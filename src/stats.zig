const std = @import("std");
const Atomic = std.atomic.Value;

pub const ScanStats = struct {
    packets_sent: Atomic(u64) = Atomic(u64).init(0),
    packets_recv: Atomic(u64) = Atomic(u64).init(0),
    ports_open: Atomic(u64) = Atomic(u64).init(0),
    ports_closed: Atomic(u64) = Atomic(u64).init(0),
    total_targets: u64,
    start_time_ns: i128,
    is_done: Atomic(bool) = Atomic(bool).init(false),

    pub fn init(total_targets: u64) ScanStats {
        return .{
            .total_targets = total_targets,
            .start_time_ns = std.time.nanoTimestamp(),
        };
    }

    pub fn addSent(self: *ScanStats, n: u64) void {
        _ = self.packets_sent.fetchAdd(n, .monotonic);
    }

    pub fn addRecv(self: *ScanStats, n: u64) void {
        _ = self.packets_recv.fetchAdd(n, .monotonic);
    }

    pub fn addOpen(self: *ScanStats) void {
        _ = self.ports_open.fetchAdd(1, .monotonic);
    }

    pub fn addClosed(self: *ScanStats) void {
        _ = self.ports_closed.fetchAdd(1, .monotonic);
    }

    pub fn markDone(self: *ScanStats) void {
        self.is_done.store(true, .release);
    }

    pub fn isDone(self: *ScanStats) bool {
        return self.is_done.load(.acquire);
    }

    pub fn snapshot(self: *ScanStats) ScanSnapshot {
        const now_ns = std.time.nanoTimestamp();
        const sent = self.packets_sent.load(.monotonic);
        const recv = self.packets_recv.load(.monotonic);
        const open = self.ports_open.load(.monotonic);
        const closed = self.ports_closed.load(.monotonic);
        const elapsed_ns = now_ns - self.start_time_ns;
        const elapsed_secs: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

        const progress: f64 = if (self.total_targets > 0)
            @min(@as(f64, @floatFromInt(sent)) / @as(f64, @floatFromInt(self.total_targets)), 1.0)
        else
            0;

        return .{
            .sent = sent,
            .recv = recv,
            .open = open,
            .closed = closed,
            .total = self.total_targets,
            .progress = progress,
            .elapsed_secs = elapsed_secs,
            .timestamp_ns = now_ns,
        };
    }
};

pub const ScanSnapshot = struct {
    sent: u64,
    recv: u64,
    open: u64,
    closed: u64,
    total: u64,
    progress: f64,
    elapsed_secs: f64,
    timestamp_ns: i128,

    pub fn deltaPps(self: ScanSnapshot, prev: ScanSnapshot) f64 {
        const dt_ns = self.timestamp_ns - prev.timestamp_ns;
        if (dt_ns <= 0) return 0;
        const dt_secs: f64 = @as(f64, @floatFromInt(dt_ns)) / 1_000_000_000.0;
        if (dt_secs < 0.001) return 0;
        const d_sent: f64 = @floatFromInt(self.sent -| prev.sent);
        return d_sent / dt_secs;
    }

    pub fn eta(self: ScanSnapshot, pps: f64) f64 {
        if (pps <= 0 or self.progress >= 1.0) return 0;
        const remaining: f64 = @floatFromInt(self.total -| self.sent);
        return remaining / pps;
    }
};

test "ScanStats atomic increments" {
    var stats = ScanStats.init(100);
    stats.addSent(10);
    stats.addSent(5);
    stats.addRecv(3);
    stats.addOpen();
    stats.addOpen();
    stats.addClosed();

    const snap = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 15), snap.sent);
    try std.testing.expectEqual(@as(u64, 3), snap.recv);
    try std.testing.expectEqual(@as(u64, 2), snap.open);
    try std.testing.expectEqual(@as(u64, 1), snap.closed);
    try std.testing.expectEqual(@as(u64, 100), snap.total);
}

test "ScanStats done flag ordering" {
    var stats = ScanStats.init(1);
    try std.testing.expect(!stats.isDone());
    stats.markDone();
    try std.testing.expect(stats.isDone());
}

test "ScanSnapshot delta PPS" {
    const prev = ScanSnapshot{
        .sent = 1000,
        .recv = 900,
        .open = 10,
        .closed = 890,
        .total = 10000,
        .progress = 0.1,
        .elapsed_secs = 1.0,
        .timestamp_ns = 1_000_000_000,
    };
    const curr = ScanSnapshot{
        .sent = 2000,
        .recv = 1800,
        .open = 20,
        .closed = 1780,
        .total = 10000,
        .progress = 0.2,
        .elapsed_secs = 1.25,
        .timestamp_ns = 1_250_000_000,
    };
    const pps = curr.deltaPps(prev);
    try std.testing.expectApproxEqAbs(@as(f64, 4000.0), pps, 1.0);
}
