const std = @import("std");
const target_mod = @import("target.zig");
const blackrock = @import("blackrock.zig");
const stats_mod = @import("stats.zig");
const rx_mod = @import("rx.zig");

const CONNECT_TIMEOUT_MS: i64 = 3000;
const MAX_INFLIGHT: usize = 4096;
const POLL_INTERVAL_MS: i32 = 10;

pub const ConnectEngine = struct {
    target_space: *const target_mod.TargetSpace,
    shuffler: blackrock.BlackRock,
    stats: *stats_mod.ScanStats,
    results: rx_mod.ResultStore,
    rate: u64,
    shard_id: ?u16,
    shard_total: ?u16,
    start_index: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        target_space: *const target_mod.TargetSpace,
        stats: *stats_mod.ScanStats,
        rate: u64,
        seed: u64,
        shard_id: ?u16,
        shard_total: ?u16,
        start_index: u64,
    ) ConnectEngine {
        return .{
            .target_space = target_space,
            .shuffler = blackrock.BlackRock.init(target_space.total_targets, seed),
            .stats = stats,
            .results = rx_mod.ResultStore.init(allocator),
            .rate = rate,
            .shard_id = shard_id,
            .shard_total = shard_total,
            .start_index = start_index,
        };
    }

    pub fn deinit(self: *ConnectEngine) void {
        self.results.deinit();
    }

    pub fn run(self: *ConnectEngine) void {
        var fds: [MAX_INFLIGHT]std.posix.fd_t = undefined;
        var ips: [MAX_INFLIGHT]u32 = undefined;
        var ports: [MAX_INFLIGHT]u16 = undefined;
        var deadlines: [MAX_INFLIGHT]i64 = undefined;
        var pfds: [MAX_INFLIGHT]std.posix.pollfd = undefined;

        var active: usize = 0;
        var index: u64 = self.start_index;
        var tokens: f64 = 0;
        var last_refill_ns: i128 = std.time.nanoTimestamp();
        const rate_f: f64 = @floatFromInt(self.rate);

        while (index < self.target_space.total_targets or active > 0) {
            if (self.stats.isDone()) break;

            const now_ns = std.time.nanoTimestamp();

            const elapsed_ns = now_ns - last_refill_ns;
            if (elapsed_ns > 0) {
                tokens += @as(f64, @floatFromInt(elapsed_ns)) * rate_f / 1_000_000_000.0;
                tokens = @min(tokens, rate_f);
                last_refill_ns = now_ns;
            }

            const now_ms = @as(i64, @intCast(@divFloor(now_ns, 1_000_000)));

            while (tokens >= 1.0 and active < MAX_INFLIGHT and index < self.target_space.total_targets) {
                if (self.shard_total) |total| {
                    if ((index % @as(u64, total)) != @as(u64, (self.shard_id orelse 1) - 1)) {
                        index += 1;
                        continue;
                    }
                }

                const shuffled = self.shuffler.shuffle(index);
                const t = self.target_space.targetAt(shuffled);

                const fd = std.posix.socket(
                    std.posix.AF.INET,
                    std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
                    0,
                ) catch break;

                index += 1;
                tokens -= 1.0;

                var dest = std.posix.sockaddr.in{
                    .family = std.posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, t.port),
                    .addr = std.mem.nativeToBig(u32, t.ip),
                };

                std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch |err| {
                    if (err == error.WouldBlock) {
                        fds[active] = fd;
                        ips[active] = t.ip;
                        ports[active] = t.port;
                        deadlines[active] = now_ms + CONNECT_TIMEOUT_MS;
                        pfds[active] = .{
                            .fd = fd,
                            .events = std.posix.POLL.OUT,
                            .revents = 0,
                        };
                        active += 1;
                        self.stats.addSent(1);
                        continue;
                    }
                    std.posix.close(fd);
                    self.stats.addSent(1);
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                    continue;
                };

                self.stats.addSent(1);
                self.markOpen(t.ip, t.port);
                std.posix.close(fd);
            }

            if (active == 0) {
                std.time.sleep(1_000_000);
                continue;
            }

            const can_send = tokens >= 1.0 and active < MAX_INFLIGHT and index < self.target_space.total_targets;
            const poll_timeout: i32 = if (can_send) 0 else POLL_INTERVAL_MS;

            for (pfds[0..active]) |*pfd| pfd.revents = 0;
            _ = std.posix.poll(pfds[0..active], poll_timeout) catch 0;

            const check_ms = @as(i64, @intCast(@divFloor(std.time.nanoTimestamp(), 1_000_000)));
            var i: usize = 0;
            while (i < active) {
                var remove = false;

                if (pfds[i].revents != 0) {
                    if (pfds[i].revents & std.posix.POLL.OUT != 0) {
                        const is_open = blk: {
                            std.posix.getsockoptError(fds[i]) catch break :blk false;
                            break :blk true;
                        };
                        if (is_open) {
                            self.markOpen(ips[i], ports[i]);
                        } else {
                            self.stats.addRecv(1);
                            self.stats.addClosed();
                        }
                    } else {
                        self.stats.addRecv(1);
                        self.stats.addClosed();
                    }
                    remove = true;
                } else if (check_ms >= deadlines[i]) {
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                    remove = true;
                }

                if (remove) {
                    std.posix.close(fds[i]);
                    active -= 1;
                    if (i < active) {
                        fds[i] = fds[active];
                        ips[i] = ips[active];
                        ports[i] = ports[active];
                        deadlines[i] = deadlines[active];
                        pfds[i] = pfds[active];
                    }
                } else {
                    i += 1;
                }
            }
        }

        for (0..active) |i| {
            self.stats.addRecv(1);
            self.stats.addClosed();
            std.posix.close(fds[i]);
        }

        self.stats.markDone();
    }

    fn markOpen(self: *ConnectEngine, ip: u32, port: u16) void {
        self.stats.addRecv(1);
        const key = @as(u64, ip) << 16 | @as(u64, port);
        if (!self.results.seen(key)) {
            self.results.mark(key, ip, port);
            self.stats.addOpen();
        }
    }
};
