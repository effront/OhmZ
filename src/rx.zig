const std = @import("std");
const packet = @import("packet.zig");
const cookie_mod = @import("cookie.zig");
const stats_mod = @import("stats.zig");
const target_mod = @import("target.zig");
const cli = @import("cli.zig");

pub const ScanResult = struct {
    ip: u32,
    port: u16,
    status: PortStatus,
    rtt_us: u64,
};

pub const PortStatus = enum {
    open,
    closed,
    filtered,
};

pub const RxEngine = struct {
    sock_fd: std.posix.fd_t,
    cookie: *const cookie_mod.SynCookie,
    stats: *stats_mod.ScanStats,
    results: ResultStore,
    src_port: u16,
    scan_type: cli.ScanType,

    pub fn init(
        allocator: std.mem.Allocator,
        cookie: *const cookie_mod.SynCookie,
        stats: *stats_mod.ScanStats,
        src_port: u16,
        scan_type: cli.ScanType,
    ) !RxEngine {
        const fd = try openCaptureSocket();
        return .{
            .sock_fd = fd,
            .cookie = cookie,
            .stats = stats,
            .results = ResultStore.init(allocator),
            .src_port = src_port,
            .scan_type = scan_type,
        };
    }

    pub fn deinit(self: *RxEngine) void {
        std.posix.close(self.sock_fd);
        self.results.deinit();
    }

    pub fn run(self: *RxEngine) void {
        var recv_buf: [1540]u8 = undefined;

        while (!self.stats.isDone()) {
            const n = std.posix.recvfrom(
                self.sock_fd,
                &recv_buf,
                std.posix.MSG.DONTWAIT,
                null,
                null,
            ) catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(10_000);
                    continue;
                }
                continue;
            };

            if (n < @sizeOf(packet.Ipv4Header) + @sizeOf(packet.TcpHeader)) continue;

            self.processPacket(recv_buf[0..n]);
        }

        self.drainRemaining(&recv_buf);
    }

    fn processPacket(self: *RxEngine, data: []const u8) void {
        const ip: *const packet.Ipv4Header = @ptrCast(@alignCast(data.ptr));

        if (ip.protocol != packet.IPPROTO_TCP) return;

        const ihl: usize = @as(usize, ip.ver_ihl & 0x0F) * 4;
        if (ihl < 20 or data.len < ihl + @sizeOf(packet.TcpHeader)) return;

        const tcp: *const packet.TcpHeader = @ptrCast(@alignCast(data.ptr + ihl));

        if (packet.fromNet(u16, tcp.dst_port) != self.src_port) return;

        const src_ip = packet.fromNet(u32, ip.src_ip);
        const src_port = packet.fromNet(u16, tcp.src_port);
        const ack_num = packet.fromNet(u32, tcp.ack_num);

        const flags = packet.parseTcpFlags(tcp.data_off_flags);

        switch (self.scan_type) {
            .syn => {
                if (packet.isSynAck(flags)) {
                    if (self.cookie.validate(src_ip, src_port, packet.fromNet(u32, ip.dst_ip), self.src_port, ack_num)) {
                        self.stats.addRecv(1);
                        const key = resultKey(src_ip, src_port);
                        if (!self.results.seen(key)) {
                            self.results.mark(key, src_ip, src_port);
                            self.stats.addOpen();
                        }
                    }
                } else if (packet.isRst(flags)) {
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                }
            },
            .fin, .xmas, .null_scan => {
                if (packet.isRst(flags)) {
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                }
            },
            .ack => {
                if (packet.isRst(flags)) {
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                }
            },
            .window => {
                if (packet.isRst(flags)) {
                    self.stats.addRecv(1);
                    const win = packet.fromNet(u16, tcp.window);
                    if (win > 0) {
                        const key = resultKey(src_ip, src_port);
                        if (!self.results.seen(key)) {
                            self.results.mark(key, src_ip, src_port);
                            self.stats.addOpen();
                        }
                    } else {
                        self.stats.addClosed();
                    }
                }
            },
            else => {
                if (packet.isSynAck(flags)) {
                    self.stats.addRecv(1);
                    const key = resultKey(src_ip, src_port);
                    if (!self.results.seen(key)) {
                        self.results.mark(key, src_ip, src_port);
                        self.stats.addOpen();
                    }
                } else if (packet.isRst(flags)) {
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                }
            },
        }
    }

    fn drainRemaining(self: *RxEngine, buf: *[1540]u8) void {
        const deadline = std.time.nanoTimestamp() + 2 * std.time.ns_per_s;
        while (std.time.nanoTimestamp() < deadline) {
            const n = std.posix.recvfrom(
                self.sock_fd,
                buf,
                std.posix.MSG.DONTWAIT,
                null,
                null,
            ) catch break;

            if (n < @sizeOf(packet.Ipv4Header) + @sizeOf(packet.TcpHeader)) continue;
            self.processPacket(buf[0..n]);
        }
    }
};

pub const OpenPort = struct {
    ip: u32,
    port: u16,
};

pub const ResultStore = struct {
    dedup: std.AutoHashMap(u64, void),
    open_list: std.ArrayList(OpenPort),

    pub fn init(allocator: std.mem.Allocator) ResultStore {
        return .{
            .dedup = std.AutoHashMap(u64, void).init(allocator),
            .open_list = std.ArrayList(OpenPort).init(allocator),
        };
    }

    pub fn deinit(self: *ResultStore) void {
        self.dedup.deinit();
        self.open_list.deinit();
    }

    pub fn seen(self: *ResultStore, key: u64) bool {
        return self.dedup.contains(key);
    }

    pub fn mark(self: *ResultStore, key: u64, ip: u32, port: u16) void {
        self.dedup.put(key, {}) catch {};
        self.open_list.append(.{ .ip = ip, .port = port }) catch {};
    }
};

fn resultKey(ip: u32, port: u16) u64 {
    return @as(u64, ip) << 16 | @as(u64, port);
}

fn openCaptureSocket() !std.posix.fd_t {
    return try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.TCP,
    );
}
