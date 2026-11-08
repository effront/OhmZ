const std = @import("std");
const target_mod = @import("target.zig");
const blackrock = @import("blackrock.zig");
const throttle_mod = @import("throttle.zig");
const stats_mod = @import("stats.zig");
const rx_mod = @import("rx.zig");

const CONNECT_TIMEOUT_MS: i64 = 3000;
const BATCH_SIZE: usize = 512;

pub const ConnectEngine = struct {
    target_space: *const target_mod.TargetSpace,
    shuffler: blackrock.BlackRock,
    throttle: throttle_mod.Throttle,
    stats: *stats_mod.ScanStats,
    results: rx_mod.ResultStore,
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
            .throttle = throttle_mod.Throttle.init(rate),
            .stats = stats,
            .results = rx_mod.ResultStore.init(allocator),
            .shard_id = shard_id,
            .shard_total = shard_total,
            .start_index = start_index,
        };
    }

    pub fn deinit(self: *ConnectEngine) void {
        self.results.deinit();
    }

    pub fn run(self: *ConnectEngine) void {
        var index: u64 = self.start_index;

        var fds: [BATCH_SIZE]std.posix.fd_t = undefined;
        var ips: [BATCH_SIZE]u32 = undefined;
        var ports: [BATCH_SIZE]u16 = undefined;
        var pending: [BATCH_SIZE]bool = undefined;

        while (index < self.target_space.total_targets) {
            if (self.stats.isDone()) break;

            const batch = self.throttle.nextBatch();
            const max_this_batch: usize = @min(batch.count, BATCH_SIZE);
            var batch_count: usize = 0;

            while (batch_count < max_this_batch and index < self.target_space.total_targets) {
                if (self.shard_total) |total| {
                    if ((index % @as(u64, total)) != @as(u64, (self.shard_id orelse 1) - 1)) {
                        index += 1;
                        continue;
                    }
                }

                const shuffled = self.shuffler.shuffle(index);
                const t = self.target_space.targetAt(shuffled);
                index += 1;

                const fd = std.posix.socket(
                    std.posix.AF.INET,
                    std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
                    0,
                ) catch continue;

                var dest = std.posix.sockaddr.in{
                    .family = std.posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, t.port),
                    .addr = std.mem.nativeToBig(u32, t.ip),
                };

                std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch |err| {
                    if (err == error.WouldBlock) {
                        fds[batch_count] = fd;
                        ips[batch_count] = t.ip;
                        ports[batch_count] = t.port;
                        pending[batch_count] = true;
                        batch_count += 1;
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

            if (batch_count == 0) {
                if (batch.sleep_ns > 0) std.time.sleep(batch.sleep_ns);
                continue;
            }

            self.stats.addSent(batch_count);

            var pfds: [BATCH_SIZE]std.posix.pollfd = undefined;
            for (0..batch_count) |i| {
                pfds[i] = .{
                    .fd = fds[i],
                    .events = std.posix.POLL.OUT,
                    .revents = 0,
                };
            }

            var remaining = batch_count;
            const deadline = std.time.milliTimestamp() + CONNECT_TIMEOUT_MS;

            while (remaining > 0) {
                const now = std.time.milliTimestamp();
                const left = deadline - now;
                if (left <= 0) break;

                const timeout: i32 = @intCast(@min(left, std.math.maxInt(i32)));
                const ready = std.posix.poll(pfds[0..batch_count], timeout) catch break;
                if (ready == 0) break;

                for (0..batch_count) |i| {
                    if (!pending[i]) continue;
                    if (pfds[i].revents == 0) continue;

                    pending[i] = false;
                    remaining -= 1;
                    pfds[i].fd = -1;

                    if (pfds[i].revents & std.posix.POLL.OUT != 0) {
                        std.posix.getsockoptError(fds[i]) catch {
                            self.stats.addRecv(1);
                            self.stats.addClosed();
                            std.posix.close(fds[i]);
                            continue;
                        };
                        self.markOpen(ips[i], ports[i]);
                    } else {
                        self.stats.addRecv(1);
                        self.stats.addClosed();
                    }
                    std.posix.close(fds[i]);
                }
            }

            for (0..batch_count) |i| {
                if (pending[i]) {
                    self.stats.addRecv(1);
                    self.stats.addClosed();
                    std.posix.close(fds[i]);
                }
            }

            if (batch.sleep_ns > 0) std.time.sleep(batch.sleep_ns);
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
