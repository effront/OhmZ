const std = @import("std");
const target_mod = @import("target.zig");
const blackrock = @import("blackrock.zig");
const throttle_mod = @import("throttle.zig");
const stats_mod = @import("stats.zig");
const rx_mod = @import("rx.zig");

const CONNECT_TIMEOUT_MS: u32 = 3000;

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

                self.tryConnect(t.ip, t.port);
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

        self.stats.markDone();
    }

    fn tryConnect(self: *ConnectEngine, ip: u32, port: u16) void {
        const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0) catch return;
        defer std.posix.close(fd);

        var dest = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, ip),
        };

        const need_poll: bool = blk: {
            std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch |err| {
                if (err == error.WouldBlock) break :blk true;
                self.stats.addRecv(1);
                self.stats.addClosed();
                return;
            };
            self.markOpen(ip, port);
            return;
        };
        _ = need_poll;

        var pfd = [1]std.posix.pollfd{.{
            .fd = fd,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};

        const ready = std.posix.poll(&pfd, CONNECT_TIMEOUT_MS) catch return;

        if (ready == 0) return;

        if (pfd[0].revents & std.posix.POLL.OUT != 0) {
            std.posix.getsockoptError(fd) catch {
                self.stats.addRecv(1);
                self.stats.addClosed();
                return;
            };
            self.markOpen(ip, port);
        } else {
            self.stats.addRecv(1);
            self.stats.addClosed();
        }
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
