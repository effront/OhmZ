const std = @import("std");

pub const BannerInfo = struct {
    buf: [128]u8 = .{0} ** 128,
    len: u8 = 0,

    pub fn str(self: *const BannerInfo) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn empty(self: *const BannerInfo) bool {
        return self.len == 0;
    }
};

const SO_RCVTIMEO = 20;
const SO_SNDTIMEO = 21;
const TIMEOUT_SECS: isize = 3;

pub fn grab(ip: u32, port: u16) BannerInfo {
    var info = BannerInfo{};

    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return info;
    defer std.posix.close(fd);

    setTimeout(fd);

    var dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, ip),
    };
    std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch return info;

    var buf: [4096]u8 = undefined;

    if (isHttpPort(port)) {
        grabHttp(fd, &buf, &info);
    } else {
        grabGeneric(fd, &buf, &info);
    }

    return info;
}

fn isHttpPort(port: u16) bool {
    return switch (port) {
        80, 8080, 8888, 3000, 9090, 8000, 5000 => true,
        else => false,
    };
}

fn setTimeout(fd: std.posix.fd_t) void {
    const Timeval = extern struct { sec: isize, usec: isize };
    const tv = Timeval{ .sec = TIMEOUT_SECS, .usec = 0 };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_RCVTIMEO, bytes) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_SNDTIMEO, bytes) catch {};
}

fn grabGeneric(fd: std.posix.fd_t, buf: *[4096]u8, info: *BannerInfo) void {
    const n = std.posix.read(fd, buf) catch return;
    if (n == 0) return;

    const data = buf[0..n];
    const end = std.mem.indexOfAny(u8, data, "\r\n") orelse @min(n, 128);
    const line = data[0..end];

    if (std.mem.startsWith(u8, line, "SSH-")) {
        parseSsh(line, info);
        return;
    }

    if (line.len > 4 and isDigit(line[0]) and isDigit(line[1]) and isDigit(line[2]) and (line[3] == ' ' or line[3] == '-')) {
        setVersion(info, line[4..]);
        return;
    }

    setVersion(info, line);
}

fn parseSsh(line: []const u8, info: *BannerInfo) void {
    var dashes: u8 = 0;
    var start: usize = 0;
    for (line, 0..) |c, i| {
        if (c == '-') {
            dashes += 1;
            if (dashes == 2) {
                start = i + 1;
                break;
            }
        }
    }
    if (start == 0 or start >= line.len) return;

    const ver = line[start..];
    const len: u8 = @intCast(@min(ver.len, info.buf.len));
    @memcpy(info.buf[0..len], ver[0..len]);
    for (info.buf[0..len]) |*c| {
        if (c.* == '_') c.* = ' ';
    }
    info.len = len;
}

fn grabHttp(fd: std.posix.fd_t, buf: *[4096]u8, info: *BannerInfo) void {
    const request = "GET / HTTP/1.0\r\n\r\n";
    _ = std.posix.write(fd, request) catch return;

    const n = std.posix.read(fd, buf) catch return;
    if (n == 0) return;

    const data = buf[0..n];

    const needle = "Server: ";
    if (std.mem.indexOf(u8, data, needle)) |pos| {
        const start = pos + needle.len;
        const end_pos = std.mem.indexOfPos(u8, data, start, "\r\n") orelse @min(start + 64, n);
        setVersion(info, data[start..end_pos]);
    }
}

fn setVersion(info: *BannerInfo, text: []const u8) void {
    var trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len >= 2 and trimmed[0] == '(' and trimmed[trimmed.len - 1] == ')') {
        trimmed = trimmed[1 .. trimmed.len - 1];
    }
    const len: u8 = @intCast(@min(trimmed.len, info.buf.len));
    @memcpy(info.buf[0..len], trimmed[0..len]);
    info.len = len;
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}
