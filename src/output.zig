const std = @import("std");
const target_mod = @import("target.zig");

pub const ScanRecord = struct {
    ip: u32,
    port: u16,
    protocol: []const u8,
    status: []const u8,
    service: ?[]const u8,
    version: ?[]const u8 = null,
    extra: ?[]const u8 = null,
    tls: bool = false,
    scripts: ?[]const u8 = null,
    rtt_us: u64,
    timestamp: i64,
};

// ---------------------------------------------------------------------------
// Normal text output (-oN) - nmap-style plain text
// ---------------------------------------------------------------------------
pub const NormalWriter = struct {
    file: std.fs.File,
    bw: std.io.BufferedWriter(4096, std.fs.File.Writer),

    pub fn init(path: []const u8) !NormalWriter {
        const file = try std.fs.cwd().createFile(path, .{});
        var nw = NormalWriter{
            .file = file,
            .bw = std.io.bufferedWriter(file.writer()),
        };
        const w = nw.bw.writer();
        w.writeAll("# OhmZ scan report\n") catch {};
        const ts = std.time.timestamp();
        w.print("# Started at {d}\n", .{ts}) catch {};
        return nw;
    }

    pub fn writeHostHeader(self: *NormalWriter, ip: u32) void {
        var ip_buf: [16]u8 = undefined;
        const ip_str = target_mod.formatIp(&ip_buf, ip);
        const w = self.bw.writer();
        w.print("\nOhmZ scan report for {s}\n", .{ip_str}) catch {};
        w.writeAll("PORT      STATE   SERVICE\n") catch {};
    }

    pub fn writeRecord(self: *NormalWriter, rec: ScanRecord) void {
        const w = self.bw.writer();
        var pbuf: [12]u8 = undefined;
        const pstr = std.fmt.bufPrint(&pbuf, "{d}/{s}", .{ rec.port, rec.protocol }) catch "?/tcp";
        w.print("{s:<9} {s:<7} {s}\n", .{
            pstr,
            rec.status,
            rec.service orelse "unknown",
        }) catch {};
    }

    pub fn finish(self: *NormalWriter) void {
        const w = self.bw.writer();
        const ts = std.time.timestamp();
        w.print("\n# Completed at {d}\n", .{ts}) catch {};
        self.bw.flush() catch {};
        self.file.close();
    }
};

// ---------------------------------------------------------------------------
// JSON output (-oJ)
// ---------------------------------------------------------------------------
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
        if (rec.version) |ver| {
            w.print(",\"version\":\"{s}\"", .{ver}) catch return;
        }
        if (rec.extra) |ext| {
            w.print(",\"extra\":\"{s}\"", .{ext}) catch return;
        }
        if (rec.tls) {
            w.writeAll(",\"tls\":true") catch return;
        }
        if (rec.scripts) |scr| {
            w.writeAll(",\"scripts\":\"") catch return;
            writeJsonEscaped(w, scr);
            w.writeByte('"') catch return;
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

// ---------------------------------------------------------------------------
// Grepable output (-oG) - nmap-compatible, one line per host
// ---------------------------------------------------------------------------
pub const GrepWriter = struct {
    file: std.fs.File,
    bw: std.io.BufferedWriter(4096, std.fs.File.Writer),
    last_ip: u32,
    line_started: bool,

    pub fn init(path: []const u8) !GrepWriter {
        const file = try std.fs.cwd().createFile(path, .{});
        var gw = GrepWriter{
            .file = file,
            .bw = std.io.bufferedWriter(file.writer()),
            .last_ip = 0,
            .line_started = false,
        };
        gw.bw.writer().writeAll("# OhmZ grepable output\n") catch {};
        return gw;
    }

    pub fn writeRecord(self: *GrepWriter, rec: ScanRecord) void {
        const w = self.bw.writer();

        if (rec.ip != self.last_ip) {
            if (self.line_started) {
                w.writeAll("\n") catch {};
            }
            var ip_buf: [16]u8 = undefined;
            const ip_str = target_mod.formatIp(&ip_buf, rec.ip);
            w.print("Host: {s} ()\tPorts: ", .{ip_str}) catch {};
            self.last_ip = rec.ip;
            self.line_started = true;
        } else {
            w.writeAll(", ") catch {};
        }

        w.print("{d}/{s}/{s}//{s}///", .{
            rec.port,
            rec.status,
            rec.protocol,
            rec.service orelse "",
        }) catch {};
    }

    pub fn finish(self: *GrepWriter) void {
        const w = self.bw.writer();
        if (self.line_started) {
            w.writeAll("\n") catch {};
        }
        self.bw.flush() catch {};
        self.file.close();
    }
};

// ---------------------------------------------------------------------------
// XML output (-oX) - nmap-compatible structure
// ---------------------------------------------------------------------------
pub const XmlWriter = struct {
    file: std.fs.File,
    bw: std.io.BufferedWriter(4096, std.fs.File.Writer),
    last_ip: u32,
    host_open: bool,
    ports_open: bool,

    pub fn init(path: []const u8) !XmlWriter {
        const file = try std.fs.cwd().createFile(path, .{});
        var xw = XmlWriter{
            .file = file,
            .bw = std.io.bufferedWriter(file.writer()),
            .last_ip = 0,
            .host_open = false,
            .ports_open = false,
        };
        const w = xw.bw.writer();
        w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n") catch {};
        w.writeAll("<ohmzscan scanner=\"ohmz\" version=\"0.4.0\">\n") catch {};
        return xw;
    }

    pub fn writeRecord(self: *XmlWriter, rec: ScanRecord) void {
        const w = self.bw.writer();

        if (rec.ip != self.last_ip) {
            self.closeHost();
            var ip_buf: [16]u8 = undefined;
            const ip_str = target_mod.formatIp(&ip_buf, rec.ip);
            w.print("  <host>\n    <address addr=\"{s}\" addrtype=\"ipv4\"/>\n", .{ip_str}) catch {};
            w.writeAll("    <ports>\n") catch {};
            self.last_ip = rec.ip;
            self.host_open = true;
            self.ports_open = true;
        }

        w.print("      <port protocol=\"{s}\" portid=\"{d}\">\n", .{ rec.protocol, rec.port }) catch {};
        w.print("        <state state=\"{s}\"/>\n", .{rec.status}) catch {};
        if (rec.service) |svc| {
            if (rec.version) |ver| {
                w.print("        <service name=\"{s}\" product=\"{s}\"/>\n", .{ svc, ver }) catch {};
            } else {
                w.print("        <service name=\"{s}\"/>\n", .{svc}) catch {};
            }
        }
        w.writeAll("      </port>\n") catch {};
    }

    fn closeHost(self: *XmlWriter) void {
        const w = self.bw.writer();
        if (self.ports_open) {
            w.writeAll("    </ports>\n") catch {};
            self.ports_open = false;
        }
        if (self.host_open) {
            w.writeAll("  </host>\n") catch {};
            self.host_open = false;
        }
    }

    pub fn finish(self: *XmlWriter) void {
        self.closeHost();
        const w = self.bw.writer();
        w.writeAll("</ohmzscan>\n") catch {};
        self.bw.flush() catch {};
        self.file.close();
    }
};

// ---------------------------------------------------------------------------
// NDJSON output (internal / -oB legacy)
// ---------------------------------------------------------------------------
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

        w.print("{{\"ip\":\"{s}\",\"port\":{d},\"protocol\":\"{s}\",\"status\":\"{s}\"", .{
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

fn writeJsonEscaped(w: anytype, s: []const u8) void {
    for (s) |c| {
        switch (c) {
            '"' => w.writeAll("\\\"") catch return,
            '\\' => w.writeAll("\\\\") catch return,
            '\n' => w.writeAll("\\n") catch return,
            '\r' => w.writeAll("\\r") catch return,
            '\t' => w.writeAll("\\t") catch return,
            else => {
                if (c < 0x20) {
                    w.print("\\u{x:0>4}", .{c}) catch return;
                } else {
                    w.writeByte(c) catch return;
                }
            },
        }
    }
}

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
