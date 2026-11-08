const std = @import("std");
const packet = @import("packet.zig");
const cookie_mod = @import("cookie.zig");
const target_mod = @import("target.zig");
const blackrock = @import("blackrock.zig");
const throttle_mod = @import("throttle.zig");
const stats_mod = @import("stats.zig");

pub const TxEngine = struct {
    sock_fd: std.posix.fd_t,
    tmpl: packet.SynTemplate,
    cookie: *const cookie_mod.SynCookie,
    target_space: *const target_mod.TargetSpace,
    shuffler: blackrock.BlackRock,
    throttle: throttle_mod.Throttle,
    stats: *stats_mod.ScanStats,
    src_ip: u32,
    src_port: u16,
    shard_id: ?u16,
    shard_total: ?u16,
    start_index: u64,

    pub fn init(
        cookie: *const cookie_mod.SynCookie,
        target_space: *const target_mod.TargetSpace,
        stats: *stats_mod.ScanStats,
        src_ip: u32,
        src_port: u16,
        rate: u64,
        seed: u64,
        shard_id: ?u16,
        shard_total: ?u16,
        start_index: u64,
    ) !TxEngine {
        const fd = try openRawSocket();
        return .{
            .sock_fd = fd,
            .tmpl = packet.SynTemplate.init(src_ip, src_port),
            .cookie = cookie,
            .target_space = target_space,
            .shuffler = blackrock.BlackRock.init(target_space.total_targets, seed),
            .throttle = throttle_mod.Throttle.init(rate),
            .stats = stats,
            .src_ip = src_ip,
            .src_port = src_port,
            .shard_id = shard_id,
            .shard_total = shard_total,
            .start_index = start_index,
        };
    }

    pub fn deinit(self: *TxEngine) void {
        std.posix.close(self.sock_fd);
    }

    pub fn run(self: *TxEngine) void {
        var index: u64 = self.start_index;

        while (index < self.target_space.total_targets) {
            if (self.stats.isDone()) break;

            const batch = self.throttle.nextBatch();
            var sent_this_batch: u64 = 0;

            for (0..batch.count) |_| {
                if (index >= self.target_space.total_targets) break;

                if (self.shard_total) |total| {
                    if ((index % @as(u64, total)) != @as(u64, (self.shard_id orelse 1) - 1)) {
                        index += 1;
                        continue;
                    }
                }

                const shuffled = self.shuffler.shuffle(index);
                const t = self.target_space.targetAt(shuffled);

                const seq = self.cookie.generate(
                    self.src_ip,
                    self.src_port,
                    t.ip,
                    t.port,
                );

                self.tmpl.patch(t.ip, t.port, seq);
                self.sendPacket() catch {};

                sent_this_batch += 1;
                index += 1;
            }

            if (sent_this_batch > 0) {
                self.stats.addSent(sent_this_batch);
            }

            if (batch.sleep_ns > 0) {
                std.time.sleep(batch.sleep_ns);
            }
        }
    }

    pub fn currentIndex(self: *const TxEngine) u64 {
        _ = self;
        return 0;
    }

    fn sendPacket(self: *TxEngine) !void {
        const dest = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = 0,
            .addr = @bitCast(self.tmpl.buf[16..20].*),
        };

        _ = std.posix.sendto(
            self.sock_fd,
            &self.tmpl.buf,
            0,
            @ptrCast(&dest),
            @sizeOf(std.posix.sockaddr.in),
        ) catch |err| {
            if (err == error.NetworkUnreachable or err == error.PermissionDenied) return err;
        };
    }
};

fn openRawSocket() !std.posix.fd_t {
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

pub fn getLocalIp(dst_ip: u32) u32 {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return 0;
    defer std.posix.close(fd);

    var dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 80),
        .addr = std.mem.nativeToBig(u32, dst_ip),
    };

    std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch return 0;

    var local: std.posix.sockaddr.in = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    std.posix.getsockname(fd, @ptrCast(&local), &len) catch return 0;

    return std.mem.bigToNative(u32, local.addr);
}
