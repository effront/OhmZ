const std = @import("std");
const packet = @import("packet.zig");
const tx_mod = @import("tx.zig");

const MAX_WORKERS: usize = 32;
const PROBE_TIMEOUT_NS: u64 = 3 * std.time.ns_per_s;
const PROBE_COUNT: usize = 3;
const MAX_PROBE_PKT: usize = 80;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

const TcpOptions = struct {
    mss: u16 = 0,
    wscale: u8 = 0,
    has_wscale: bool = false,
    has_sack: bool = false,
    has_timestamps: bool = false,
};

const TcpProbeResult = struct {
    ttl: u8 = 0,
    window: u16 = 0,
    df: bool = false,
    opts: TcpOptions = .{},
};

const IcmpResult = struct {
    valid: bool = false,
    ttl: u8 = 0,
    df: bool = false,
    reply_size: u16 = 0,
};

// ---------------------------------------------------------------------------
// Probe descriptors
// ---------------------------------------------------------------------------

// Probe 1 (SEQ/OPS): standard SYN, tiny window
//   MSS=1460, WScale=10, SACK, Timestamps(0,0), NOP, EOL
const probe1_opts = [_]u8{
    0x02, 0x04, 0x05, 0xB4, // MSS = 1460
    0x03, 0x03, 0x0A, // WScale = 10
    0x04, 0x02, // SACK Permitted
    0x08, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamps
    0x01, // NOP
    0x00, // EOL
};

// Probe 2 (WIN): different MSS, specific window
//   MSS=265, NOP, NOP, Timestamps(0,0), NOP, WScale=1, SACK
const probe2_opts = [_]u8{
    0x02, 0x04, 0x01, 0x09, // MSS = 265
    0x01, // NOP
    0x01, // NOP
    0x08, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamps
    0x01, // NOP
    0x03, 0x03, 0x01, // WScale = 1
    0x04, 0x02, // SACK Permitted
};

// Probe 3 (ECN): SYN with ECE+CWR flags
//   WScale=10, NOP, MSS=1460, SACK, NOP, NOP
const probe3_opts = [_]u8{
    0x03, 0x03, 0x0A, // WScale = 10
    0x01, // NOP
    0x02, 0x04, 0x05, 0xB4, // MSS = 1460
    0x04, 0x02, // SACK Permitted
    0x01, // NOP
    0x01, // NOP
};

const ProbeDesc = struct {
    window: u16,
    flags: u16,
    opts: []const u8,
};

const probe_descs = [PROBE_COUNT]ProbeDesc{
    .{ .window = 1, .flags = packet.TcpFlags.SYN, .opts = &probe1_opts },
    .{ .window = 63, .flags = packet.TcpFlags.SYN, .opts = &probe2_opts },
    .{ .window = 4, .flags = packet.TcpFlags.SYN | packet.TcpFlags.ECE | packet.TcpFlags.CWR, .opts = &probe3_opts },
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn detect(ip: u32, open_port: u16) OsInfo {
    var info = OsInfo{};

    const src_ip = tx_mod.getLocalIp(ip);
    if (src_ip == 0) return info;

    const base_port: u16 = 50000 + @as(u16, @truncate(@as(u64, @bitCast(std.time.milliTimestamp())) % 10000));

    const send_fd = openRawSendSocket() catch return info;
    defer std.posix.close(send_fd);

    const recv_fd = openRawRecvSocket() catch return info;
    defer std.posix.close(recv_fd);

    setRecvTimeout(recv_fd, 2);

    const dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0,
        .addr = packet.toNet(u32, ip),
    };

    // Send 3 TCP probes with different options and source ports
    for (0..PROBE_COUNT) |i| {
        const src_port = base_port +% @as(u16, @intCast(i));
        var pkt_buf: [MAX_PROBE_PKT]u8 = .{0} ** MAX_PROBE_PKT;
        const pkt_len = buildSynProbe(
            &pkt_buf,
            src_ip,
            src_port,
            ip,
            open_port,
            0x12345678 +% @as(u32, @intCast(i)),
            probe_descs[i].window,
            probe_descs[i].flags,
            probe_descs[i].opts,
        );

        _ = std.posix.sendto(
            send_fd,
            pkt_buf[0..pkt_len],
            0,
            @ptrCast(&dest),
            @sizeOf(std.posix.sockaddr.in),
        ) catch continue;

        // Small delay between probes to avoid rate limiting
        std.time.sleep(50 * std.time.ns_per_ms);
    }

    // Collect TCP probe responses
    var probes: [PROBE_COUNT]?TcpProbeResult = .{null} ** PROBE_COUNT;
    var received: u8 = 0;
    var recv_buf: [1540]u8 = undefined;
    const deadline = std.time.nanoTimestamp() + @as(i128, PROBE_TIMEOUT_NS);

    while (std.time.nanoTimestamp() < deadline and received < PROBE_COUNT) {
        const n = std.posix.recvfrom(recv_fd, &recv_buf, 0, null, null) catch break;

        if (n < @sizeOf(packet.Ipv4Header) + @sizeOf(packet.TcpHeader)) continue;

        const ip_hdr: *const packet.Ipv4Header = @ptrCast(@alignCast(recv_buf[0..@sizeOf(packet.Ipv4Header)]));

        if (ip_hdr.protocol != packet.IPPROTO_TCP) continue;
        if (packet.fromNet(u32, ip_hdr.src_ip) != ip) continue;

        const ihl: usize = @as(usize, ip_hdr.ver_ihl & 0x0F) * 4;
        if (ihl < 20 or n < ihl + @sizeOf(packet.TcpHeader)) continue;

        const tcp_hdr: *const packet.TcpHeader = @ptrCast(@alignCast(recv_buf[ihl .. ihl + @sizeOf(packet.TcpHeader)]));

        if (packet.fromNet(u16, tcp_hdr.src_port) != open_port) continue;

        const dst_port = packet.fromNet(u16, tcp_hdr.dst_port);

        // Match response to probe by destination port (our source port)
        var probe_idx: ?usize = null;
        for (0..PROBE_COUNT) |i| {
            if (dst_port == base_port +% @as(u16, @intCast(i)) and probes[i] == null) {
                probe_idx = i;
                break;
            }
        }
        if (probe_idx == null) continue;

        const flags = packet.parseTcpFlags(tcp_hdr.data_off_flags);
        if (!packet.isSynAck(flags)) continue;

        const idx = probe_idx.?;

        const data_off: usize = @as(usize, (packet.fromNet(u16, tcp_hdr.data_off_flags) >> 12) & 0xF) * 4;
        var opts = TcpOptions{};
        if (data_off > 20 and n >= ihl + data_off) {
            opts = parseTcpOptions(recv_buf[ihl + 20 .. ihl + data_off]);
        }

        // Send RST to clean up half-open connection
        sendRst(send_fd, src_ip, base_port +% @as(u16, @intCast(idx)), ip, open_port, packet.fromNet(u32, tcp_hdr.ack_num));

        probes[idx] = TcpProbeResult{
            .ttl = ip_hdr.ttl,
            .window = packet.fromNet(u16, tcp_hdr.window),
            .df = (recv_buf[6] & 0x40) != 0,
            .opts = opts,
        };
        received += 1;
    }

    // ICMP probe (best effort - failure is acceptable)
    const icmp = probeIcmp(ip);

    // Fingerprint using combined probe data
    fingerprintMulti(&info, probes, icmp);

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
        for (ips, 0..) |target_ip, i| {
            results[i] = detect(target_ip, ports[i]);
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

// ---------------------------------------------------------------------------
// Packet building
// ---------------------------------------------------------------------------

fn buildSynProbe(
    buf: *[MAX_PROBE_PKT]u8,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    window: u16,
    flags: u16,
    tcp_opts: []const u8,
) usize {
    const opts_padded = (tcp_opts.len + 3) & ~@as(usize, 3);
    const tcp_total: usize = 20 + opts_padded;
    const pkt_total: usize = 20 + tcp_total;

    @memset(buf, 0);

    // IP header (20 bytes at offset 0)
    const ip: *packet.Ipv4Header = @ptrCast(@alignCast(buf[0..@sizeOf(packet.Ipv4Header)]));
    ip.ver_ihl = 0x45;
    ip.tos = 0;
    ip.total_len = packet.toNet(u16, @intCast(pkt_total));
    ip.identification = 0;
    ip.flags_frag = packet.toNet(u16, 0x4000); // DF
    ip.ttl = 64;
    ip.protocol = packet.IPPROTO_TCP;
    ip.src_ip = packet.toNet(u32, src_ip);
    ip.dst_ip = packet.toNet(u32, dst_ip);

    // TCP header (20 bytes at offset 20)
    const tcp: *packet.TcpHeader = @ptrCast(@alignCast(buf[20..][0..@sizeOf(packet.TcpHeader)]));
    tcp.src_port = packet.toNet(u16, src_port);
    tcp.dst_port = packet.toNet(u16, dst_port);
    tcp.seq_num = packet.toNet(u32, seq);
    tcp.ack_num = 0;
    const data_off_val: u16 = @intCast(tcp_total / 4);
    tcp.data_off_flags = packet.toNet(u16, (data_off_val << 12) | flags);
    tcp.window = packet.toNet(u16, window);
    tcp.urgent = 0;

    // TCP options (at offset 40, zero-padded to 4-byte boundary)
    @memcpy(buf[40 .. 40 + tcp_opts.len], tcp_opts);

    // Compute TCP checksum (field must be zero first)
    tcp.checksum = 0;
    tcp.checksum = packet.tcpChecksum(ip, buf[20 .. 20 + tcp_total]);

    // Compute IP checksum
    ip.checksum = 0;
    ip.checksum = packet.ipChecksum(buf[0..20]);

    return pkt_total;
}

// ---------------------------------------------------------------------------
// ICMP probe
// ---------------------------------------------------------------------------

fn probeIcmp(ip: u32) IcmpResult {
    var result = IcmpResult{};

    const fd = std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.ICMP,
    ) catch return result;
    defer std.posix.close(fd);

    setRecvTimeout(fd, 2);

    // Build ICMP Echo Request (8 byte header + 56 byte payload)
    var pkt: [64]u8 = .{0} ** 64;
    pkt[0] = 8; // type: Echo Request
    pkt[1] = 0; // code: 0
    // checksum at [2..4] - computed below
    pkt[4] = 0x13;
    pkt[5] = 0x37; // identifier
    pkt[6] = 0x00;
    pkt[7] = 0x01; // sequence number
    // Payload: 56 bytes of 0x41 ('A')
    for (pkt[8..]) |*b| b.* = 0x41;

    // Compute ICMP checksum
    var sum: u32 = 0;
    var ci: usize = 0;
    while (ci + 1 < pkt.len) : (ci += 2) {
        sum += @as(u32, pkt[ci]) << 8 | @as(u32, pkt[ci + 1]);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    const cksum: u16 = @intCast(~sum & 0xFFFF);
    pkt[2] = @intCast(cksum >> 8);
    pkt[3] = @intCast(cksum & 0xFF);

    const dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0,
        .addr = packet.toNet(u32, ip),
    };

    _ = std.posix.sendto(
        fd,
        &pkt,
        0,
        @ptrCast(&dest),
        @sizeOf(std.posix.sockaddr.in),
    ) catch return result;

    var recv_buf: [1540]u8 = undefined;
    const icmp_deadline = std.time.nanoTimestamp() + @as(i128, 2 * std.time.ns_per_s);

    while (std.time.nanoTimestamp() < icmp_deadline) {
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n < 28) continue; // IP header (20 min) + ICMP header (8)

        // Verify source IP matches target
        const ip_hdr: *const packet.Ipv4Header = @ptrCast(@alignCast(recv_buf[0..@sizeOf(packet.Ipv4Header)]));
        if (packet.fromNet(u32, ip_hdr.src_ip) != ip) continue;

        const ihl: usize = @as(usize, recv_buf[0] & 0x0F) * 4;
        if (n < ihl + 8) continue;

        // Must be Echo Reply (type 0)
        if (recv_buf[ihl] != 0) continue;

        // Verify our identifier
        if (recv_buf[ihl + 4] != 0x13 or recv_buf[ihl + 5] != 0x37) continue;

        result.valid = true;
        result.ttl = recv_buf[8]; // TTL from IP header
        result.df = (recv_buf[6] & 0x40) != 0; // DF flag
        result.reply_size = @intCast(n - ihl);
        break;
    }

    return result;
}

// ---------------------------------------------------------------------------
// TCP option parsing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Multi-probe fingerprinting
// ---------------------------------------------------------------------------

fn fingerprintMulti(info: *OsInfo, probes: [PROBE_COUNT]?TcpProbeResult, icmp: IcmpResult) void {
    // Determine base TTL from the first valid probe
    var valid_count: u8 = 0;
    var base_ttl: u16 = 0;

    for (probes) |mp| {
        if (mp) |p| {
            valid_count += 1;
            if (base_ttl == 0) {
                base_ttl = if (p.ttl <= 64) 64 else if (p.ttl <= 128) 128 else 255;
            }
            info.ttl = p.ttl;
        }
    }

    if (valid_count == 0 and !icmp.valid) return;

    // Fall back to ICMP TTL when no TCP probes succeeded
    if (icmp.valid and base_ttl == 0) {
        base_ttl = if (icmp.ttl <= 64) 64 else if (icmp.ttl <= 128) 128 else 255;
        info.ttl = icmp.ttl;
    }

    // ECN probe (probe 3) response: Linux responds, Windows ignores
    const has_ecn_response = probes[2] != null;

    // DF bit from ICMP echo reply
    const icmp_df = icmp.valid and icmp.df;

    // ---------------------------------------------------------------
    // TTL 128 - Windows family
    // ---------------------------------------------------------------
    if (base_ttl == 128) {
        var confidence: u8 = 70;
        if (!has_ecn_response) confidence += 10; // Windows ignores ECN
        if (icmp_df) confidence += 5;

        if (probes[0]) |p| {
            if (p.opts.has_wscale and p.opts.has_sack and p.opts.has_timestamps) {
                if (p.window >= 64000 or p.window == 65535) {
                    setOs(info, "Windows 10/11/Server 2016+", "Windows", @min(confidence + 5, 95));
                } else if (p.window == 8192) {
                    setOs(info, "Windows 7/Server 2008", "Windows", confidence);
                } else {
                    setOs(info, "Windows", "Windows", confidence);
                }
            } else if (p.opts.has_sack and !p.opts.has_timestamps) {
                setOs(info, "Windows XP/2003", "Windows", confidence);
            } else {
                setOs(info, "Windows", "Windows", @min(confidence, 75));
            }
        } else {
            setOs(info, "Windows", "Windows", 60);
        }
        return;
    }

    // ---------------------------------------------------------------
    // TTL 64 - Linux, macOS, *BSD
    // ---------------------------------------------------------------
    if (base_ttl == 64) {
        var confidence: u8 = 70;
        if (has_ecn_response) confidence += 5; // Linux responds to ECN

        if (probes[0]) |p| {
            // OpenBSD: no wscale, has SACK, window 16384
            if (!p.opts.has_wscale and p.opts.has_sack and p.window == 16384) {
                setOs(info, "OpenBSD", "BSD", 80);
                return;
            }

            // macOS: wscale=6, window=65535
            if (p.opts.has_wscale and p.opts.wscale == 6 and p.window == 65535) {
                setOs(info, "macOS", "macOS", 80);
                return;
            }

            if (p.opts.has_wscale and p.opts.has_sack and p.opts.has_timestamps) {
                const standard_mss = (p.opts.mss == 1460 or p.opts.mss == 1448 or
                    p.opts.mss == 1410 or p.opts.mss == 65495 or p.opts.mss == 0);

                if (standard_mss) {
                    // Linux version detection by window size
                    if (p.window >= 65000) {
                        setOs(info, "Linux 5.x/6.x", "Linux", @min(confidence + 10, 95));
                    } else if (p.window >= 26000 and p.window <= 32000) {
                        setOs(info, "Linux 4.x", "Linux", @min(confidence + 5, 90));
                    } else if (p.window >= 14000 and p.window <= 15000) {
                        setOs(info, "Linux 3.x", "Linux", @min(confidence + 5, 90));
                    } else if (p.window >= 5000 and p.window <= 6000) {
                        setOs(info, "Linux 2.6", "Linux", confidence);
                    } else {
                        setOs(info, "Linux", "Linux", confidence);
                    }
                } else if (p.opts.mss > 1400) {
                    setOs(info, "Linux", "Linux", 70);
                } else {
                    setOs(info, "FreeBSD", "BSD", 65);
                }
            } else if (p.opts.has_sack and p.opts.has_timestamps) {
                setOs(info, "Linux", "Linux", 60);
            } else if (p.opts.has_sack) {
                setOs(info, "Linux", "Linux", 55);
            } else {
                setOs(info, "Linux/Unix", "Linux", 55);
            }
        } else {
            setOs(info, "Linux/Unix", "Linux", 50);
        }
        return;
    }

    // ---------------------------------------------------------------
    // TTL 255 - Network devices, Solaris
    // ---------------------------------------------------------------
    if (base_ttl == 255) {
        if (probes[0]) |p| {
            if (p.window == 4128 and p.opts.mss == 536) {
                setOs(info, "Cisco IOS", "Cisco", 90);
            } else if (p.opts.has_sack and p.opts.has_timestamps and p.opts.mss == 1460) {
                setOs(info, "Solaris", "Solaris", 75);
            } else {
                setOs(info, "Network Device", "Network", 60);
            }
        } else {
            setOs(info, "Network Device", "Network", 50);
        }
        return;
    }

    setOs(info, "Unknown", "Unknown", 30);
}

// ---------------------------------------------------------------------------
// Legacy single-probe fingerprint (kept for fallback / reference)
// ---------------------------------------------------------------------------

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

    if (base_ttl == 64) {
        setOs(info, "Linux/Unix", "Linux", 40);
        return;
    }

    setOs(info, "Unknown", "Unknown", 30);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
