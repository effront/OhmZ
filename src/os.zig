const std = @import("std");
const packet = @import("packet.zig");
const tx_mod = @import("tx.zig");

const MAX_WORKERS: usize = 32;
const PROBE_TIMEOUT_NS: u64 = 3 * std.time.ns_per_s;

pub const OsInfo = struct {
    name_buf: [64]u8 = .{0} ** 64,
    name_len: u8 = 0,
    family_buf: [32]u8 = .{0} ** 32,
    family_len: u8 = 0,
    confidence: u8 = 0,
    ttl: u8 = 0,

    pub fn name(self: *const OsInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn family(self: *const OsInfo) []const u8 {
        return self.family_buf[0..self.family_len];
    }

    fn setStr(buf: []u8, text: []const u8) u8 {
        const len: u8 = @intCast(@min(text.len, buf.len));
        @memcpy(buf[0..len], text[0..len]);
        return len;
    }
};

const TcpOptions = struct {
    mss: u16 = 0,
    wscale: u8 = 0,
    has_wscale: bool = false,
    has_sack: bool = false,
    has_timestamps: bool = false,
};

pub fn detect(ip: u32, open_port: u16) OsInfo {
    var info = OsInfo{};

    const src_ip = tx_mod.getLocalIp(ip);
    if (src_ip == 0) return info;

    const src_port: u16 = 50000 + @as(u16, @truncate(@as(u64, @bitCast(std.time.milliTimestamp())) % 10000));

    const send_fd = openRawSendSocket() catch return info;
    defer std.posix.close(send_fd);

    const recv_fd = openRawRecvSocket() catch return info;
    defer std.posix.close(recv_fd);

    setRecvTimeout(recv_fd, 3);

    var tmpl = packet.TcpTemplate.init(src_ip, src_port);
    tmpl.patch(ip, open_port, 0x12345678);

    const dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0,
        .addr = @bitCast(tmpl.buf[16..20].*),
    };

    _ = std.posix.sendto(
        send_fd,
        &tmpl.buf,
        0,
        @ptrCast(&dest),
        @sizeOf(std.posix.sockaddr.in),
    ) catch return info;

    var recv_buf: [1540]u8 = undefined;
    const deadline = std.time.nanoTimestamp() + @as(i128, PROBE_TIMEOUT_NS);

    while (std.time.nanoTimestamp() < deadline) {
        const n = std.posix.recvfrom(
            recv_fd,
            &recv_buf,
            0,
            null,
            null,
        ) catch break;

        if (n < @sizeOf(packet.Ipv4Header) + @sizeOf(packet.TcpHeader)) continue;

        const ip_hdr: *const packet.Ipv4Header = @ptrCast(@alignCast(recv_buf[0..@sizeOf(packet.Ipv4Header)]));

        if (ip_hdr.protocol != packet.IPPROTO_TCP) continue;
        if (packet.fromNet(u32, ip_hdr.src_ip) != ip) continue;

        const ihl: usize = @as(usize, ip_hdr.ver_ihl & 0x0F) * 4;
        if (ihl < 20 or n < ihl + @sizeOf(packet.TcpHeader)) continue;

        const tcp_hdr: *const packet.TcpHeader = @ptrCast(@alignCast(recv_buf[ihl .. ihl + @sizeOf(packet.TcpHeader)]));

        if (packet.fromNet(u16, tcp_hdr.src_port) != open_port) continue;
        if (packet.fromNet(u16, tcp_hdr.dst_port) != src_port) continue;

        const flags = packet.parseTcpFlags(tcp_hdr.data_off_flags);
        if (!packet.isSynAck(flags)) continue;

        const resp_ttl = ip_hdr.ttl;
        const resp_window = packet.fromNet(u16, tcp_hdr.window);

        const data_off: usize = @as(usize, (packet.fromNet(u16, tcp_hdr.data_off_flags) >> 12) & 0xF) * 4;
        var opts = TcpOptions{};
        if (data_off > 20 and n >= ihl + data_off) {
            opts = parseTcpOptions(recv_buf[ihl + 20 .. ihl + data_off]);
        }

        sendRst(send_fd, src_ip, src_port, ip, open_port, packet.fromNet(u32, tcp_hdr.ack_num));

        fingerprint(&info, resp_ttl, resp_window, opts);
        break;
    }

    return info;
}

pub fn detectAll(
    ips: []const u32,
    ports: []const u16,
    results: []OsInfo,
    num_workers: usize,
) void {
    if (ips.len == 0) return;

    if (ips.len == 1 or num_workers <= 1) {
        for (ips, 0..) |ip, i| {
            results[i] = detect(ip, ports[i]);
        }
        return;
    }

    var next_idx = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        ips: []const u32,
        ports: []const u16,
        results: []OsInfo,
        next: *std.atomic.Value(usize),
    };

    var ctx = Ctx{
        .ips = ips,
        .ports = ports,
        .results = results,
        .next = &next_idx,
    };

    const actual = @min(num_workers, @min(ips.len, MAX_WORKERS));
    var threads: [MAX_WORKERS]?std.Thread = .{null} ** MAX_WORKERS;

    for (0..actual) |w| {
        threads[w] = std.Thread.spawn(.{}, struct {
            fn run(c: *Ctx) void {
                while (true) {
                    const i = c.next.fetchAdd(1, .monotonic);
                    if (i >= c.ips.len) break;
                    c.results[i] = detect(c.ips[i], c.ports[i]);
                }
            }
        }.run, .{&ctx}) catch null;
    }

    for (&threads) |*t| {
        if (t.*) |handle| handle.join();
    }
}

fn parseTcpOptions(data: []const u8) TcpOptions {
    var opts = TcpOptions{};
    var pos: usize = 0;

    while (pos < data.len) {
        const kind = data[pos];
        switch (kind) {
            0 => break, // EOL
            1 => pos += 1, // NOP
            2 => { // MSS
                if (pos + 4 > data.len) break;
                opts.mss = @as(u16, data[pos + 2]) << 8 | @as(u16, data[pos + 3]);
                pos += 4;
            },
            3 => { // Window Scale
                if (pos + 3 > data.len) break;
                opts.has_wscale = true;
                opts.wscale = data[pos + 2];
                pos += 3;
            },
            4 => { // SACK Permitted
                opts.has_sack = true;
                if (pos + 2 > data.len) break;
                pos += 2;
            },
            8 => { // Timestamps
                opts.has_timestamps = true;
                if (pos + 2 > data.len) break;
                const opt_len = data[pos + 1];
                pos += opt_len;
            },
            else => {
                if (pos + 1 >= data.len) break;
                const opt_len = data[pos + 1];
                if (opt_len < 2) break;
                pos += opt_len;
            },
        }
    }

    return opts;
}

fn fingerprint(info: *OsInfo, ttl: u8, window: u16, opts: TcpOptions) void {
    info.ttl = ttl;

    const base_ttl: u16 = if (ttl <= 64)
        64
    else if (ttl <= 128)
        128
    else
        255;

    if (base_ttl == 255) {
        if (window == 4128 and opts.mss == 536) {
            setOs(info, "Cisco IOS", "Cisco", 90);
        } else if (opts.has_sack and opts.has_timestamps and opts.mss == 1460) {
            setOs(info, "Solaris", "Solaris", 75);
        } else {
            setOs(info, "Network Device", "Network", 60);
        }
        return;
    }

    if (base_ttl == 128) {
        if (window == 8192) {
            if (opts.has_timestamps) {
                setOs(info, "Windows 7/8", "Windows", 80);
            } else {
                setOs(info, "Windows 7", "Windows", 75);
            }
        } else if (window == 65535 or window >= 64000) {
            if (opts.has_wscale and opts.has_sack and opts.has_timestamps) {
                setOs(info, "Windows 10/11", "Windows", 85);
            } else if (opts.has_wscale and opts.has_sack) {
                setOs(info, "Windows Server", "Windows", 80);
            } else {
                setOs(info, "Windows", "Windows", 70);
            }
        } else {
            setOs(info, "Windows", "Windows", 60);
        }
        return;
    }

    // base_ttl == 64: Linux, macOS, *BSD
    if (!opts.has_wscale and opts.has_sack and window == 16384) {
        setOs(info, "OpenBSD", "BSD", 80);
        return;
    }

    const standard_mss = (opts.mss == 1460 or opts.mss == 1448 or opts.mss == 1410 or opts.mss == 65495 or opts.mss == 0);

    if (opts.has_wscale and opts.has_sack and opts.has_timestamps and standard_mss) {
        if (opts.wscale == 6 and window == 65535) {
            setOs(info, "macOS", "macOS", 80);
            return;
        }

        if (window == 65535 or window == 65495) {
            setOs(info, "Linux 5.x+", "Linux", 85);
        } else if (window >= 26000 and window <= 32000) {
            setOs(info, "Linux 4.x", "Linux", 80);
        } else if (window >= 14000 and window <= 15000) {
            setOs(info, "Linux 3.x", "Linux", 80);
        } else if (window >= 5000 and window <= 6000) {
            setOs(info, "Linux 2.6", "Linux", 80);
        } else {
            setOs(info, "Linux", "Linux", 75);
        }
        return;
    }

    if (opts.has_wscale and opts.has_sack and opts.has_timestamps) {
        if (opts.mss > 1400) {
            setOs(info, "Linux", "Linux", 70);
        } else {
            setOs(info, "FreeBSD", "BSD", 65);
        }
        return;
    }

    if (opts.has_sack and opts.has_timestamps) {
        setOs(info, "Linux", "Linux", 60);
        return;
    }

    if (opts.has_sack) {
        setOs(info, "Linux", "Linux", 55);
        return;
    }

    // TTL alone gives a hint
    if (base_ttl == 64) {
        setOs(info, "Linux/Unix", "Linux", 40);
        return;
    }

    setOs(info, "Unknown", "Unknown", 30);
}

fn setOs(info: *OsInfo, os_name: []const u8, os_family: []const u8, confidence: u8) void {
    info.name_len = OsInfo.setStr(&info.name_buf, os_name);
    info.family_len = OsInfo.setStr(&info.family_buf, os_family);
    info.confidence = confidence;
}

fn sendRst(fd: std.posix.fd_t, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, seq: u32) void {
    var tmpl = packet.TcpTemplate.initWithFlags(src_ip, src_port, packet.TcpFlags.RST);
    tmpl.patch(dst_ip, dst_port, seq);

    const dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0,
        .addr = @bitCast(tmpl.buf[16..20].*),
    };

    _ = std.posix.sendto(
        fd,
        &tmpl.buf,
        0,
        @ptrCast(&dest),
        @sizeOf(std.posix.sockaddr.in),
    ) catch {};
}

fn openRawSendSocket() !std.posix.fd_t {
    const fd = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.RAW,
    );
    errdefer std.posix.close(fd);

    const hdr_incl: c_int = 1;
    try std.posix.setsockopt(
        fd,
        std.posix.IPPROTO.IP,
        std.posix.system.IP.HDRINCL,
        std.mem.asBytes(&hdr_incl),
    );

    return fd;
}

fn openRawRecvSocket() !std.posix.fd_t {
    return try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.TCP,
    );
}

fn setRecvTimeout(fd: std.posix.fd_t, secs: isize) void {
    const SO_RCVTIMEO = 20;
    const tv = std.posix.timeval{
        .sec = secs,
        .usec = 0,
    };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_RCVTIMEO, std.mem.asBytes(&tv)) catch {};
}
