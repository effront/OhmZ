const std = @import("std");

const BUCKET_COUNT = 256;
const GROWTH_FACTOR = 1.005;
const SHRINK_FACTOR = 0.999;
const SUSPEND_THRESHOLD_NS: i128 = 1_000_000_000;
const MIN_BATCH: u64 = 1;

pub const Throttle = struct {
    target_rate: u64,
    buckets: [BUCKET_COUNT]u64,
    timestamps: [BUCKET_COUNT]i128,
    head: u8,
    batch_size: f64,
    last_tick_ns: i128,

    pub fn init(target_rate: u64) Throttle {
        return .{
            .target_rate = target_rate,
            .buckets = std.mem.zeroes([BUCKET_COUNT]u64),
            .timestamps = std.mem.zeroes([BUCKET_COUNT]i128),
            .head = 0,
            .batch_size = @max(@as(f64, @floatFromInt(target_rate)) / 100.0, 1.0),
            .last_tick_ns = std.time.nanoTimestamp(),
        };
    }

    pub const BatchResult = struct {
        count: u64,
        sleep_ns: u64,
    };

    pub fn nextBatch(self: *Throttle) BatchResult {
        const now = std.time.nanoTimestamp();
        const gap = now - self.last_tick_ns;

        if (gap > SUSPEND_THRESHOLD_NS) {
            self.reset();
            self.last_tick_ns = now;
            return .{
                .count = @intFromFloat(@max(self.batch_size, 1.0)),
                .sleep_ns = self.computeSleepNs(),
            };
        }

        self.last_tick_ns = now;
        const count: u64 = @intFromFloat(@max(self.batch_size, 1.0));

        self.buckets[self.head] = count;
        self.timestamps[self.head] = now;
        self.head +%= 1;

        const actual_rate = self.measuredRate(now);
        const target_f: f64 = @floatFromInt(self.target_rate);

        if (actual_rate < target_f * 0.95) {
            self.batch_size *= GROWTH_FACTOR;
        } else if (actual_rate > target_f * 1.05) {
            self.batch_size *= SHRINK_FACTOR;
        }

        self.batch_size = @max(self.batch_size, @as(f64, @floatFromInt(MIN_BATCH)));
        const max_batch: f64 = @floatFromInt(self.target_rate / 10 + 1);
        self.batch_size = @min(self.batch_size, max_batch);

        return .{
            .count = count,
            .sleep_ns = self.computeSleepNs(),
        };
    }

    fn measuredRate(self: *const Throttle, now: i128) f64 {
        var total_packets: u64 = 0;
        var oldest_ts: i128 = now;

        for (0..BUCKET_COUNT) |i| {
            if (self.timestamps[i] == 0) continue;
            total_packets += self.buckets[i];
            if (self.timestamps[i] < oldest_ts) {
                oldest_ts = self.timestamps[i];
            }
        }

        const elapsed_ns = now - oldest_ts;
        if (elapsed_ns <= 0 or total_packets == 0) return 0;

        const elapsed_secs: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        return @as(f64, @floatFromInt(total_packets)) / elapsed_secs;
    }

    fn computeSleepNs(self: *const Throttle) u64 {
        if (self.target_rate == 0) return 10_000_000;
        const batch_f: f64 = @max(self.batch_size, 1.0);
        const target_f: f64 = @floatFromInt(self.target_rate);
        const sleep_secs = batch_f / target_f;
        const ns: f64 = sleep_secs * 1_000_000_000.0;
        return @intFromFloat(@max(ns, 1000.0));
    }

    fn reset(self: *Throttle) void {
        self.buckets = std.mem.zeroes([BUCKET_COUNT]u64);
        self.timestamps = std.mem.zeroes([BUCKET_COUNT]i128);
        self.head = 0;
    }
};

test "Throttle initial batch is reasonable" {
    var t = Throttle.init(10_000);
    const b = t.nextBatch();
    try std.testing.expect(b.count >= 1);
    try std.testing.expect(b.count <= 1001);
    try std.testing.expect(b.sleep_ns > 0);
}

test "Throttle adapts batch size" {
    var t = Throttle.init(100_000);
    const initial = t.batch_size;

    for (0..50) |_| {
        _ = t.nextBatch();
        std.time.sleep(100_000);
    }

    try std.testing.expect(t.batch_size != initial);
}

test "Throttle suspend detection resets" {
    var t = Throttle.init(1000);
    _ = t.nextBatch();

    t.last_tick_ns = std.time.nanoTimestamp() - 2_000_000_000;
    const b = t.nextBatch();
    try std.testing.expect(b.count >= 1);
}
