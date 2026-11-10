const std = @import("std");
const stats_mod = @import("stats.zig");
const ScanStats = stats_mod.ScanStats;
const ScanSnapshot = stats_mod.ScanSnapshot;

const REFRESH_NS: u64 = 50 * std.time.ns_per_ms;
const SLOW_REFRESH_NS: u64 = 250 * std.time.ns_per_ms;
const RAMP_TICKS: u32 = 20;
const EWMA_ALPHA: f64 = 0.3;
const MIN_BAR_WIDTH: usize = 8;
const FIXED_COLS: usize = 32;

const BLOCK_FULL: []const u8 = "\u{2588}";
const BLOCK_LIGHT: []const u8 = "\u{2591}";

pub const ProgressBar = struct {
    stats: *ScanStats,
    thread: ?std.Thread = null,
    show_verbose: bool = false,

    pub fn init(scan_stats: *ScanStats, verbose: bool) ProgressBar {
        return .{
            .stats = scan_stats,
            .show_verbose = verbose,
        };
    }

    pub fn start(self: *ProgressBar) !void {
        self.thread = try std.Thread.spawn(.{}, renderLoop, .{self});
    }

    pub fn join(self: *ProgressBar) void {
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn renderLoop(self: *ProgressBar) void {
        const w = std.io.getStdErr().writer();
        hideCursor(w);
        defer showCursor(w);

        var prev_snap = self.stats.snapshot();
        var smoothed_pps: f64 = 0;
        var display_progress: f64 = 0;

        renderLineSmooth(w, 0, prev_snap, 0, 0, self.show_verbose, barWidth());

        var tick: u32 = 0;
        while (!self.stats.isDone()) {
            const sleep_ns = if (tick < RAMP_TICKS) REFRESH_NS else SLOW_REFRESH_NS;
            std.time.sleep(sleep_ns);
            tick += 1;

            const snap = self.stats.snapshot();
            const raw_pps = snap.deltaPps(prev_snap);

            smoothed_pps = if (smoothed_pps == 0)
                raw_pps
            else
                EWMA_ALPHA * raw_pps + (1.0 - EWMA_ALPHA) * smoothed_pps;

            const target_progress = @min(snap.progress, 0.99);
            display_progress = smoothProgress(display_progress, target_progress);

            const eta_secs = snap.eta(smoothed_pps);
            renderLineSmooth(w, display_progress, snap, smoothed_pps, eta_secs, self.show_verbose, barWidth());
            prev_snap = snap;
        }

        const final_snap = self.stats.snapshot();
        const final_pps = final_snap.deltaPps(prev_snap);
        smoothed_pps = EWMA_ALPHA * final_pps + (1.0 - EWMA_ALPHA) * smoothed_pps;

        renderLineSmooth(w, 1.0, final_snap, smoothed_pps, 0, self.show_verbose, barWidth());
        renderComplete(w, final_snap, smoothed_pps);
    }

    fn smoothProgress(current: f64, target: f64) f64 {
        if (current >= target) return target;
        const gap = target - current;
        const step = @max(gap * 0.4, 0.01);
        return @min(current + step, target);
    }

    fn renderLineSmooth(w: anytype, progress: f64, snap: ScanSnapshot, pps: f64, eta_secs: f64, verbose: bool, bw: usize) void {
        const pct: u8 = @intFromFloat(@min(progress * 100.0, 100.0));
        const filled: usize = @intFromFloat(@min(progress * @as(f64, @floatFromInt(bw)), @as(f64, @floatFromInt(bw))));
        const empty: usize = bw - filled;

        w.print("\r\x1b[K\x1b[1;37m{d:>3}%\x1b[0m \x1b[36m", .{pct}) catch return;
        for (0..filled) |_| w.writeAll(BLOCK_FULL) catch return;
        for (0..empty) |_| w.writeAll(BLOCK_LIGHT) catch return;
        w.writeAll("\x1b[0m ") catch return;

        writePps(w, pps);
        w.writeAll(" ") catch return;
        writeEta(w, eta_secs);

        if (verbose) {
            w.print(" | sent:{d} recv:{d} open:\x1b[32m{d}\x1b[0m", .{
                snap.sent,
                snap.recv,
                snap.open,
            }) catch return;
        }
    }

    fn renderComplete(w: anytype, snap: ScanSnapshot, _: f64) void {
        const real_avg: f64 = if (snap.elapsed_secs > 0.001)
            @as(f64, @floatFromInt(snap.sent)) / snap.elapsed_secs
        else
            0;
        w.print("\r\x1b[K\x1b[1;32mScan complete\x1b[0m in ", .{}) catch return;
        writeDuration(w, snap.elapsed_secs);
        w.print(" | {d} targets | \x1b[32m{d} open\x1b[0m ports | avg ", .{
            snap.total,
            snap.open,
        }) catch return;
        writePps(w, real_avg);
        w.writeAll("\n") catch return;
    }

    fn writePps(w: anytype, pps: f64) void {
        if (pps >= 1_000_000) {
            w.print("\x1b[33m{d:.1}M pps\x1b[0m", .{pps / 1_000_000.0}) catch return;
        } else if (pps >= 1_000) {
            w.print("\x1b[33m{d:.1}K pps\x1b[0m", .{pps / 1_000.0}) catch return;
        } else {
            w.print("\x1b[33m{d:.0} pps\x1b[0m", .{pps}) catch return;
        }
    }

    fn writeEta(w: anytype, secs: f64) void {
        if (secs <= 0) {
            w.writeAll("\x1b[35mETA: --:--\x1b[0m") catch return;
            return;
        }
        const total_s: u64 = @intFromFloat(secs);
        const d = total_s / 86400;
        const h = (total_s % 86400) / 3600;
        const m = (total_s % 3600) / 60;
        const s = total_s % 60;

        w.writeAll("\x1b[35mETA: ") catch return;
        if (d > 0) {
            w.print("{d}d{d:0>2}h{d:0>2}m", .{ d, h, m }) catch return;
        } else if (h > 0) {
            w.print("{d}h{d:0>2}m{d:0>2}s", .{ h, m, s }) catch return;
        } else if (m > 0) {
            w.print("{d}m{d:0>2}s", .{ m, s }) catch return;
        } else {
            w.print("{d}s", .{s}) catch return;
        }
        w.writeAll("\x1b[0m") catch return;
    }

    fn writeDuration(w: anytype, secs: f64) void {
        const total_s: u64 = @intFromFloat(@max(secs, 0));
        const d = total_s / 86400;
        const h = (total_s % 86400) / 3600;
        const m = (total_s % 3600) / 60;
        const s = total_s % 60;

        if (d > 0) {
            w.print("{d}d{d:0>2}h{d:0>2}m", .{ d, h, m }) catch return;
        } else if (h > 0) {
            w.print("{d}h{d:0>2}m{d:0>2}s", .{ h, m, s }) catch return;
        } else if (m > 0) {
            w.print("{d}m{d:0>2}s", .{ m, s }) catch return;
        } else {
            w.print("{d:.1}s", .{secs}) catch return;
        }
    }

    fn barWidth() usize {
        const cols = getTermCols();
        if (cols <= FIXED_COLS + MIN_BAR_WIDTH) return MIN_BAR_WIDTH;
        return cols - FIXED_COLS;
    }

    fn getTermCols() usize {
        const WinSize = extern struct { row: u16, col: u16, xpix: u16, ypix: u16 };
        var ws: WinSize = std.mem.zeroes(WinSize);
        const rc = std.os.linux.ioctl(2, 0x5413, @intFromPtr(&ws));
        if (@as(isize, @bitCast(rc)) >= 0 and ws.col > 0) return ws.col;
        return 80;
    }

    fn hideCursor(w: anytype) void {
        w.writeAll("\x1b[?25l") catch {};
    }

    fn showCursor(w: anytype) void {
        w.writeAll("\x1b[?25h") catch {};
    }
};
