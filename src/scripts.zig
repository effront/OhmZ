const std = @import("std");
const rx_mod = @import("rx.zig");

const SO_RCVTIMEO = 20;
const SO_SNDTIMEO = 21;
const IO_TIMEOUT_SECS: isize = 3;
const MAX_WORKERS: usize = 32;

pub const ScriptResult = struct {
    id_buf: [32]u8 = .{0} ** 32,
    id_len: u8 = 0,
    output_buf: [256]u8 = .{0} ** 256,
    output_len: u16 = 0,

    pub fn id(self: *const ScriptResult) []const u8 {
        return self.id_buf[0..self.id_len];
    }

    pub fn output(self: *const ScriptResult) []const u8 {
        return self.output_buf[0..self.output_len];
    }

    fn setId(self: *ScriptResult, text: []const u8) void {
        const len: u8 = @intCast(@min(text.len, self.id_buf.len));
        @memcpy(self.id_buf[0..len], text[0..len]);
        self.id_len = len;
    }

    fn setOutput(self: *ScriptResult, text: []const u8) void {
        const len: u16 = @intCast(@min(text.len, self.output_buf.len));
        @memcpy(self.output_buf[0..len], text[0..len]);
        self.output_len = len;
    }
};

pub const HostScripts = struct {
    results: [8]ScriptResult = .{ScriptResult{}} ** 8,
    count: u8 = 0,

    pub fn add(self: *HostScripts, script_id: []const u8, output_text: []const u8) void {
        if (self.count >= 8) return;
        self.results[self.count].setId(script_id);
        self.results[self.count].setOutput(output_text);
        self.count += 1;
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn runDefault(ip: u32, port: u16) HostScripts {
    var hs = HostScripts{};
    switch (port) {
        80, 8080, 8888, 3000, 5000, 8000, 9090 => {
            scriptHttpTitle(ip, port, &hs);
            scriptHttpRobots(ip, port, &hs);
        },
        22, 2222 => scriptSshHostkey(ip, port, &hs),
        25, 587 => scriptSmtpCommands(ip, port, &hs),
        3306, 33060 => scriptMysqlInfo(ip, port, &hs),
        else => {},
    }
    return hs;
}

pub fn runAll(
    ports: []const rx_mod.OpenPort,
    results: []HostScripts,
    num_workers: usize,
) void {
    if (ports.len == 0) return;

    if (ports.len == 1 or num_workers <= 1) {
        for (ports, 0..) |p, i| {
            results[i] = runDefault(p.ip, p.port);
        }
        return;
    }

    var next_idx = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        ports: []const rx_mod.OpenPort,
        results: []HostScripts,
        next: *std.atomic.Value(usize),
    };

    var ctx = Ctx{
        .ports = ports,
        .results = results,
        .next = &next_idx,
    };

    const actual = @min(num_workers, @min(ports.len, MAX_WORKERS));
    var threads: [MAX_WORKERS]?std.Thread = .{null} ** MAX_WORKERS;

    for (0..actual) |w| {
        threads[w] = std.Thread.spawn(.{}, struct {
            fn run(c: *Ctx) void {
                while (true) {
                    const i = c.next.fetchAdd(1, .monotonic);
                    if (i >= c.ports.len) break;
                    c.results[i] = runDefault(c.ports[i].ip, c.ports[i].port);
                }
            }
        }.run, .{&ctx}) catch null;
    }

    for (&threads) |*t| {
        if (t.*) |handle| {
            handle.join();
            t.* = null;
        }
    }
}

// ---------------------------------------------------------------------------
// Script: http-title
// ---------------------------------------------------------------------------

fn scriptHttpTitle(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);

    var req_buf: [128]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ip_str}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    if (total == 0) return;

    const data = buf[0..total];
    const title = findTitle(data) orelse return;
    if (title.len > 0) {
        hs.add("http-title", title);
    }
}

fn findTitle(data: []const u8) ?[]const u8 {
    const open_tag = findCaseInsensitive(data, "<title>") orelse return null;
    const after = open_tag + 7;
    if (after >= data.len) return null;
    const close_tag = findCaseInsensitive(data[after..], "</title>") orelse return null;
    const raw = data[after .. after + close_tag];
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;
    return trimmed;
}

fn findCaseInsensitive(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;
    const end = haystack.len - needle.len + 1;
    var i: usize = 0;
    while (i < end) : (i += 1) {
        var matched = true;
        for (needle, 0..) |nc, j| {
            if (toLower(haystack[i + j]) != toLower(nc)) {
                matched = false;
                break;
            }
        }
        if (matched) return i;
    }
    return null;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// ---------------------------------------------------------------------------
// Script: http-robots
// ---------------------------------------------------------------------------

fn scriptHttpRobots(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);

    var req_buf: [160]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET /robots.txt HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ip_str}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    if (total == 0) return;

    const data = buf[0..total];

    if (std.mem.indexOf(u8, data, "HTTP/1.")) |_| {
        if (data.len >= 12) {
            const status = data[9..12];
            if (std.mem.eql(u8, status, "200")) {
                var count: u16 = 0;
                var pos: usize = 0;
                while (pos < total) {
                    if (findCaseInsensitive(data[pos..], "disallow:")) |off| {
                        count += 1;
                        pos += off + 9;
                    } else break;
                }
                var out_buf: [48]u8 = undefined;
                const out = std.fmt.bufPrint(&out_buf, "{d} disallowed entries", .{count}) catch return;
                hs.add("http-robots", out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Script: ssh-hostkey
// ---------------------------------------------------------------------------

fn scriptSshHostkey(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var buf: [512]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 4) return;

    const data = buf[0..n];
    if (!std.mem.startsWith(u8, data, "SSH-")) return;

    const line_end = std.mem.indexOfAny(u8, data, "\r\n") orelse n;
    const banner = data[0..line_end];
    if (banner.len > 0) {
        hs.add("ssh-hostkey", banner);
    }
}

// ---------------------------------------------------------------------------
// Script: smtp-commands
// ---------------------------------------------------------------------------

fn scriptSmtpCommands(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var buf: [2048]u8 = undefined;
    const greeting_n = std.posix.read(fd, &buf) catch return;
    if (greeting_n < 3) return;

    if (!std.mem.startsWith(u8, buf[0..greeting_n], "220")) return;

    _ = std.posix.write(fd, "EHLO ohmz\r\n") catch return;

    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\r\n250 ") != null) break;
        if (total > 3 and buf[total - 1] == '\n') {
            const last_line_start = findLastLineStart(buf[0..total]);
            if (total - last_line_start >= 4 and buf[last_line_start + 3] == ' ') break;
        }
    }
    if (total == 0) return;

    _ = std.posix.write(fd, "QUIT\r\n") catch {};

    const data = buf[0..total];
    var out_buf: [256]u8 = undefined;
    var out_len: usize = 0;

    var line_it = std.mem.splitSequence(u8, data, "\r\n");
    while (line_it.next()) |line| {
        if (line.len < 4) continue;
        if (!std.mem.startsWith(u8, line, "250")) continue;
        if (line[3] != '-' and line[3] != ' ') continue;

        const ext = std.mem.trim(u8, line[4..], " ");
        if (ext.len == 0) continue;

        const ext_name = blk: {
            const space_idx = std.mem.indexOfScalar(u8, ext, ' ');
            break :blk if (space_idx) |si| ext[0..si] else ext;
        };
        if (ext_name.len == 0) continue;

        if (out_len > 0 and out_len + 1 < out_buf.len) {
            out_buf[out_len] = ',';
            out_len += 1;
        }
        const copy_len = @min(ext_name.len, out_buf.len - out_len);
        if (copy_len == 0) break;
        @memcpy(out_buf[out_len .. out_len + copy_len], ext_name[0..copy_len]);
        out_len += copy_len;
    }

    if (out_len > 0) {
        hs.add("smtp-commands", out_buf[0..out_len]);
    }
}

fn findLastLineStart(data: []const u8) usize {
    if (data.len < 2) return 0;
    var i: usize = data.len - 2;
    while (i > 0) : (i -= 1) {
        if (data[i] == '\n') return i + 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Script: mysql-info
// ---------------------------------------------------------------------------

fn scriptMysqlInfo(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var buf: [1024]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 5) return;

    const payload_len: usize = @as(usize, buf[0]) | (@as(usize, buf[1]) << 8) | (@as(usize, buf[2]) << 16);
    if (4 + payload_len > n) return;

    const payload = buf[4 .. 4 + payload_len];
    if (payload.len < 2) return;

    const proto_ver = payload[0];
    if (proto_ver != 10 and proto_ver != 9) return;

    const ver_end = std.mem.indexOfScalar(u8, payload[1..], 0) orelse return;
    const version_str = payload[1 .. 1 + ver_end];

    // After version: 4 bytes conn id + 8 bytes auth-plugin-data-part-1 + 1 filler
    const caps_offset = 1 + ver_end + 1 + 4 + 8 + 1;
    if (caps_offset + 2 > payload.len) {
        var out_buf: [128]u8 = undefined;
        const out = std.fmt.bufPrint(&out_buf, "MySQL {s} proto:{d}", .{ version_str, proto_ver }) catch return;
        hs.add("mysql-info", out);
        return;
    }

    const caps_lo: u16 = @as(u16, payload[caps_offset]) | (@as(u16, payload[caps_offset + 1]) << 8);

    var caps_hi: u16 = 0;
    // Extended caps are 13 bytes after caps_lo: 1 charset + 2 status + 2 caps_hi
    const ext_offset = caps_offset + 2 + 1 + 2;
    if (ext_offset + 2 <= payload.len) {
        caps_hi = @as(u16, payload[ext_offset]) | (@as(u16, payload[ext_offset + 1]) << 8);
    }

    const caps: u32 = @as(u32, caps_lo) | (@as(u32, caps_hi) << 16);

    var out_buf: [256]u8 = undefined;
    var out_len: usize = 0;

    const prefix = std.fmt.bufPrint(out_buf[0..], "MySQL {s} caps:", .{version_str}) catch return;
    out_len = prefix.len;

    const cap_names = [_]struct { flag: u32, name: []const u8 }{
        .{ .flag = 0x00000800, .name = "SSL" },
        .{ .flag = 0x00000020, .name = "COMPRESS" },
        .{ .flag = 0x00008000, .name = "SECURE_CONNECTION" },
        .{ .flag = 0x00080000, .name = "PLUGIN_AUTH" },
        .{ .flag = 0x00200000, .name = "MULTI_STATEMENTS" },
        .{ .flag = 0x00400000, .name = "MULTI_RESULTS" },
    };

    var first = true;
    for (cap_names) |c| {
        if (caps & c.flag != 0) {
            if (!first and out_len < out_buf.len) {
                out_buf[out_len] = ',';
                out_len += 1;
            }
            const copy_len = @min(c.name.len, out_buf.len - out_len);
            if (copy_len == 0) break;
            @memcpy(out_buf[out_len .. out_len + copy_len], c.name[0..copy_len]);
            out_len += copy_len;
            first = false;
        }
    }

    hs.add("mysql-info", out_buf[0..out_len]);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn openSocket(ip: u32, port: u16) ?std.posix.fd_t {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return null;
    setTimeout(fd);

    var dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, ip),
    };
    std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch {
        std.posix.close(fd);
        return null;
    };

    return fd;
}

fn setTimeout(fd: std.posix.fd_t) void {
    const Timeval = extern struct { sec: isize, usec: isize };
    const tv = Timeval{ .sec = IO_TIMEOUT_SECS, .usec = 0 };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_RCVTIMEO, bytes) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_SNDTIMEO, bytes) catch {};
}

fn formatIp(buf: []u8, ip: u32) []const u8 {
    const b = [4]u8{
        @intCast((ip >> 24) & 0xFF),
        @intCast((ip >> 16) & 0xFF),
        @intCast((ip >> 8) & 0xFF),
        @intCast(ip & 0xFF),
    };
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch "?.?.?.?";
}
