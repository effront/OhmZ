const std = @import("std");
const target_mod = @import("target.zig");

pub const ScanRecord = struct {
    ip: u32,
    port: u16,
    protocol: []const u8,
    status: []const u8,
    service: ?[]const u8,
    rtt_us: u64,
    timestamp: i64,
};

pub const JsonWriter = struct {
    file: std.fs.File,
    bw: std.io.BufferedWriter(4096, std.fs.File.Writer),
    first: bool,

    pub fn init(path: []const u8) !JsonWriter {
        const file = try std.fs.cwd().createFile(path, .{});
        var jw = JsonWriter{
            .file = file,
            .bw = std.io.bufferedWriter(file.writer()),
            .first = true,
        };
        jw.bw.writer().writeAll("[\n") catch {};
        return jw;
    }

    pub fn writeRecord(self: *JsonWriter, rec: ScanRecord) void {
        const w = self.bw.writer();
        if (!self.first) {
            w.writeAll(",\n") catch return;
        }
        self.first = false;

        var ip_buf: [16]u8 = undefined;
        const ip_str = target_mod.formatIp(&ip_buf, rec.ip);

        w.print(
            \\  {{"ip":"{s}","port":{d},"protocol":"{s}","status":"{s}"
        , .{ ip_str, rec.port, rec.protocol, rec.status }) catch return;

        if (rec.service) |svc| {
            w.print(",\"service\":\"{s}\"", .{svc}) catch return;
        }

        w.print(",\"rtt_us\":{d},\"timestamp\":{d}}}", .{ rec.rtt_us, rec.timestamp }) catch return;
    }

    pub fn finish(self: *JsonWriter) void {
        const w = self.bw.writer();
        w.writeAll("\n]\n") catch {};
        self.bw.flush() catch {};
        self.file.close();
    }
};

pub const GrepWriter = struct {
    file: std.fs.File,
    bw: std.io.BufferedWriter(4096, std.fs.File.Writer),

    pub fn init(path: []const u8) !GrepWriter {
        const file = try std.fs.cwd().createFile(path, .{});
        return .{
            .file = file,
            .bw = std.io.bufferedWriter(file.writer()),
        };
    }

    pub fn writeRecord(self: *GrepWriter, rec: ScanRecord) void {
        var ip_buf: [16]u8 = undefined;
        const ip_str = target_mod.formatIp(&ip_buf, rec.ip);

        self.bw.writer().print("Host: {s}\tPorts: {d}/{s}/{s}/{s}\n", .{
            ip_str,
            rec.port,
            rec.status,
            rec.protocol,
            rec.service orelse "",
        }) catch {};
    }

    pub fn finish(self: *GrepWriter) void {
        self.bw.flush() catch {};
        self.file.close();
    }
};

pub const NdjsonWriter = struct {
    file: std.fs.File,
    bw: std.io.BufferedWriter(4096, std.fs.File.Writer),

    pub fn init(path: []const u8) !NdjsonWriter {
        const file = try std.fs.cwd().createFile(path, .{});
        return .{
            .file = file,
            .bw = std.io.bufferedWriter(file.writer()),
        };
    }

    pub fn writeRecord(self: *NdjsonWriter, rec: ScanRecord) void {
        var ip_buf: [16]u8 = undefined;
        const ip_str = target_mod.formatIp(&ip_buf, rec.ip);
        const w = self.bw.writer();

        w.print("{{{s}\"ip\":\"{s}\",\"port\":{d},\"protocol\":\"{s}\",\"status\":\"{s}\"", .{
            "",
            ip_str,
            rec.port,
            rec.protocol,
            rec.status,
        }) catch return;

        if (rec.service) |svc| {
            w.print(",\"service\":\"{s}\"", .{svc}) catch return;
        }

        w.print(",\"rtt_us\":{d},\"timestamp\":{d}}}\n", .{ rec.rtt_us, rec.timestamp }) catch return;
    }

    pub fn finish(self: *NdjsonWriter) void {
        self.bw.flush() catch {};
        self.file.close();
    }
};

pub fn printResult(writer: anytype, rec: ScanRecord) void {
    var ip_buf: [16]u8 = undefined;
    const ip_str = target_mod.formatIp(&ip_buf, rec.ip);

    if (rec.service) |svc| {
        writer.print("{d}/{s}\t{s}\t{s}\t{s}\n", .{
            rec.port, rec.protocol, rec.status, ip_str, svc,
        }) catch {};
    } else {
        writer.print("{d}/{s}\t{s}\t{s}\n", .{
            rec.port, rec.protocol, rec.status, ip_str,
        }) catch {};
    }
}
