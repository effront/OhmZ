const std = @import("std");
const rx_mod = @import("rx.zig");
const tls_mod = @import("tls.zig");

const SO_RCVTIMEO = 20;
const SO_SNDTIMEO = 21;
const IO_TIMEOUT_SECS: isize = 3;
const MAX_WORKERS: usize = 32;

pub const ServiceInfo = struct {
    name_buf: [32]u8 = .{0} ** 32,
    name_len: u8 = 0,
    version_buf: [128]u8 = .{0} ** 128,
    version_len: u8 = 0,
    extra_buf: [256]u8 = .{0} ** 256,
    extra_len: u16 = 0,
    tls: bool = false,

    pub fn name(self: *const ServiceInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn version(self: *const ServiceInfo) []const u8 {
        return self.version_buf[0..self.version_len];
    }

    pub fn extra(self: *const ServiceInfo) []const u8 {
        return self.extra_buf[0..self.extra_len];
    }

    pub fn empty(self: *const ServiceInfo) bool {
        return self.name_len == 0 and self.version_len == 0;
    }

    pub fn str(self: *const ServiceInfo) []const u8 {
        if (self.version_len > 0) return self.version_buf[0..self.version_len];
        if (self.name_len > 0) return self.name_buf[0..self.name_len];
        return "";
    }

    fn setName(self: *ServiceInfo, text: []const u8) void {
        const len: u8 = @intCast(@min(text.len, self.name_buf.len));
        @memcpy(self.name_buf[0..len], text[0..len]);
        self.name_len = len;
    }

    fn setVersion(self: *ServiceInfo, text: []const u8) void {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        const len: u8 = @intCast(@min(trimmed.len, self.version_buf.len));
        @memcpy(self.version_buf[0..len], trimmed[0..len]);
        self.version_len = len;
    }

    fn setExtra(self: *ServiceInfo, text: []const u8) void {
        const len: u16 = @intCast(@min(text.len, self.extra_buf.len));
        @memcpy(self.extra_buf[0..len], text[0..len]);
        self.extra_len = len;
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn detect(ip: u32, port: u16) ServiceInfo {
    const protocol = classifyPort(port);
    return switch (protocol) {
        .http => probeHttp(ip, port),
        .ssh => probeSsh(ip, port),
        .ftp => probeFtp(ip, port),
        .smtp => probeSmtp(ip, port),
        .mysql => probeMysql(ip, port),
        .redis => probeRedis(ip, port),
        .postgresql => probePostgresql(ip, port),
        .tls => probeTls(ip, port),
        .generic => probeGeneric(ip, port),
    };
}

pub fn detectAll(
    ports: []const rx_mod.OpenPort,
    results: []ServiceInfo,
    num_workers: usize,
) void {
    if (ports.len == 0) return;

    if (ports.len == 1 or num_workers <= 1) {
        for (ports, 0..) |p, i| {
            results[i] = detect(p.ip, p.port);
        }
        return;
    }

    var next_idx = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        ports: []const rx_mod.OpenPort,
        results: []ServiceInfo,
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
                    c.results[i] = detect(c.ports[i].ip, c.ports[i].port);
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

// Backward-compatible alias
pub const BannerInfo = ServiceInfo;
pub const grab = detect;

// ---------------------------------------------------------------------------
// Port classification
// ---------------------------------------------------------------------------

const Protocol = enum { http, ssh, ftp, smtp, mysql, redis, postgresql, tls, generic };

fn classifyPort(port: u16) Protocol {
    return switch (port) {
        80, 8080, 8888, 3000, 5000, 8000, 9090 => .http,
        443, 8443, 993, 995, 465, 636, 990, 992 => .tls,
        22, 2222 => .ssh,
        21 => .ftp,
        25, 587 => .smtp,
        3306, 33060 => .mysql,
        6379, 6380 => .redis,
        5432, 5433, 5434 => .postgresql,
        else => .generic,
    };
}

// ---------------------------------------------------------------------------
// Protocol probes
// ---------------------------------------------------------------------------

fn probeHttp(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);

    var req_buf: [128]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ip_str}) catch return info;
    _ = std.posix.write(fd, request) catch return info;

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n == 0) return info;

    const data = buf[0..n];

    if (std.mem.indexOf(u8, data, "Server: ")) |pos| {
        const start = pos + 8;
        const end = std.mem.indexOfPos(u8, data, start, "\r\n") orelse @min(start + 80, n);
        const server = data[start..end];

        if (std.mem.indexOf(u8, server, "/")) |slash| {
            info.setName(server[0..slash]);
            if (slash + 1 < server.len) {
                info.setVersion(server[slash + 1 ..]);
            }
        } else {
            info.setName(server);
        }
    }

    if (std.mem.indexOf(u8, data, "X-Powered-By: ")) |pos| {
        const start = pos + 14;
        const end = std.mem.indexOfPos(u8, data, start, "\r\n") orelse @min(start + 80, n);
        info.setExtra(data[start..end]);
    }

    return info;
}

fn probeSsh(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var buf: [512]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 4) return info;

    const line_end = std.mem.indexOfAny(u8, buf[0..n], "\r\n") orelse n;
    const line = buf[0..line_end];

    if (!std.mem.startsWith(u8, line, "SSH-")) return info;

    var dash_count: u8 = 0;
    var soft_start: usize = 0;
    for (line, 0..) |c, i| {
        if (c == '-') {
            dash_count += 1;
            if (dash_count == 2) {
                soft_start = i + 1;
                break;
            }
        }
    }
    if (soft_start == 0 or soft_start >= line.len) {
        info.setName("SSH");
        return info;
    }

    const software = line[soft_start..];

    if (std.mem.indexOf(u8, software, "OpenSSH")) |_| {
        info.setName("OpenSSH");
        if (std.mem.indexOf(u8, software, "_")) |uscore| {
            const ver_start = uscore + 1;
            const ver_end = std.mem.indexOfAnyPos(u8, software, ver_start, " \t") orelse software.len;
            info.setVersion(software[ver_start..ver_end]);
        }
    } else if (std.mem.indexOf(u8, software, "dropbear")) |_| {
        info.setName("Dropbear");
        if (std.mem.indexOf(u8, software, "_")) |uscore| {
            info.setVersion(software[uscore + 1 ..]);
        }
    } else {
        const space = std.mem.indexOfScalar(u8, software, ' ') orelse software.len;
        if (std.mem.indexOf(u8, software[0..space], "_")) |uscore| {
            info.setName(software[0..uscore]);
            info.setVersion(software[uscore + 1 .. space]);
        } else {
            info.setVersion(software[0..space]);
        }
    }

    return info;
}

fn probeFtp(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var buf: [1024]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 4) return info;

    const line_end = std.mem.indexOfAny(u8, buf[0..n], "\r\n") orelse n;
    const line = buf[0..line_end];

    if (line.len < 4 or line[0] != '2' or line[1] != '2' or line[2] != '0') return info;

    const text = std.mem.trim(u8, line[4..], " \t");

    if (std.mem.indexOf(u8, text, "vsftpd")) |_| {
        info.setName("vsftpd");
        extractVersionNumber(text, &info);
    } else if (std.mem.indexOf(u8, text, "ProFTPD")) |_| {
        info.setName("ProFTPD");
        extractVersionNumber(text, &info);
    } else if (std.mem.indexOf(u8, text, "Pure-FTPd")) |_| {
        info.setName("Pure-FTPd");
    } else if (std.mem.indexOf(u8, text, "FileZilla")) |_| {
        info.setName("FileZilla Server");
        extractVersionNumber(text, &info);
    } else {
        info.setName("FTP");
        info.setVersion(text);
    }

    return info;
}

fn probeSmtp(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var buf: [2048]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 4) return info;

    const line_end = std.mem.indexOfAny(u8, buf[0..n], "\r\n") orelse n;
    const banner = buf[4..line_end];

    if (std.mem.indexOf(u8, banner, "Postfix")) |_| {
        info.setName("Postfix");
    } else if (std.mem.indexOf(u8, banner, "Exim")) |_| {
        info.setName("Exim");
        extractVersionNumber(banner, &info);
    } else if (std.mem.indexOf(u8, banner, "Sendmail")) |_| {
        info.setName("Sendmail");
        extractVersionNumber(banner, &info);
    } else {
        info.setName("SMTP");
        if (banner.len > 0) info.setVersion(banner);
    }

    _ = std.posix.write(fd, "EHLO ohmz.scan\r\n") catch return info;
    var ehlo_buf: [2048]u8 = undefined;
    const en = std.posix.read(fd, &ehlo_buf) catch return info;
    if (en > 0) {
        const ehlo = ehlo_buf[0..en];
        var caps_buf: [256]u8 = undefined;
        var caps_len: usize = 0;

        if (std.mem.indexOf(u8, ehlo, "STARTTLS") != null) {
            caps_len += (std.fmt.bufPrint(caps_buf[caps_len..], "STARTTLS ", .{}) catch "").len;
        }
        if (std.mem.indexOf(u8, ehlo, "AUTH") != null) {
            caps_len += (std.fmt.bufPrint(caps_buf[caps_len..], "AUTH ", .{}) catch "").len;
        }
        if (std.mem.indexOf(u8, ehlo, "PIPELINING") != null) {
            caps_len += (std.fmt.bufPrint(caps_buf[caps_len..], "PIPELINING ", .{}) catch "").len;
        }
        if (caps_len > 0) {
            info.setExtra(caps_buf[0..caps_len]);
        }
    }

    _ = std.posix.write(fd, "QUIT\r\n") catch {};
    return info;
}

fn probeMysql(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var buf: [1024]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 5) return info;

    const payload_len: usize = @as(usize, buf[0]) | (@as(usize, buf[1]) << 8) | (@as(usize, buf[2]) << 16);
    if (payload_len + 4 > n) return info;

    const proto_ver = buf[4];
    if (proto_ver != 10 and proto_ver != 9) return info;

    const ver_start: usize = 5;
    const ver_end = std.mem.indexOfScalarPos(u8, buf[0..n], ver_start, 0) orelse return info;
    const version_str = buf[ver_start..ver_end];

    if (std.mem.indexOf(u8, version_str, "MariaDB")) |_| {
        info.setName("MariaDB");
    } else {
        info.setName("MySQL");
    }
    info.setVersion(version_str);

    return info;
}

fn probeRedis(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    _ = std.posix.write(fd, "INFO server\r\n") catch return info;

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n == 0) return info;

    const data = buf[0..n];

    if (data[0] == '-') {
        info.setName("Redis");
        if (std.mem.indexOf(u8, data, "NOAUTH")) |_| {
            info.setExtra("auth required");
        }
        return info;
    }

    info.setName("Redis");

    if (std.mem.indexOf(u8, data, "redis_version:")) |pos| {
        const start = pos + 14;
        const end = std.mem.indexOfAnyPos(u8, data, start, "\r\n") orelse @min(start + 20, n);
        info.setVersion(data[start..end]);
    }

    if (std.mem.indexOf(u8, data, "redis_mode:")) |pos| {
        const start = pos + 11;
        const end = std.mem.indexOfAnyPos(u8, data, start, "\r\n") orelse @min(start + 20, n);
        const mode = std.mem.trim(u8, data[start..end], " \t\r\n");
        if (!std.mem.eql(u8, mode, "standalone")) {
            info.setExtra(mode);
        }
    }

    return info;
}

fn probePostgresql(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    // StartupMessage: Int32 length (includes self) + Int32 version 3.0 + params + \0
    const startup = [_]u8{
        0, 0, 0, 23, // length = 23 (includes self)
        0, 3, 0, 0, // protocol 3.0
        'u', 's', 'e', 'r', 0, // key: "user\0" (5)
        'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0, // val: "postgres\0" (9)
        0, // end of params (1)
    }; // total: 4+4+5+9+1 = 23
    _ = std.posix.write(fd, &startup) catch return info;

    var buf: [512]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 5) return info;

    info.setName("PostgreSQL");

    const msg_type = buf[0];
    if (msg_type == 'R') {
        if (n >= 9) {
            const auth_type: u32 = (@as(u32, buf[5]) << 24) | (@as(u32, buf[6]) << 16) |
                (@as(u32, buf[7]) << 8) | @as(u32, buf[8]);
            if (auth_type == 0) {
                // AuthenticationOk - read ParameterStatus messages
                var extra_buf: [512]u8 = undefined;
                const extra_n = std.posix.read(fd, &extra_buf) catch return info;
                parsePostgresParams(extra_buf[0..extra_n], &info);
            } else {
                const auth_name: []const u8 = switch (auth_type) {
                    3 => "cleartext",
                    5 => "md5",
                    10 => "SCRAM-SHA-256",
                    else => "auth-required",
                };
                info.setExtra(auth_name);
            }
        }
    } else if (msg_type == 'E') {
        if (n > 6) {
            const err_text = buf[6..n];
            if (std.mem.indexOf(u8, err_text, "PostgreSQL")) |_| {
                extractVersionNumber(err_text, &info);
            }
        }
    }

    return info;
}

fn parsePostgresParams(data: []const u8, info: *ServiceInfo) void {
    var pos: usize = 0;
    while (pos + 5 < data.len) {
        const t = data[pos];
        if (pos + 5 > data.len) break;
        const len: usize = (@as(usize, data[pos + 1]) << 24) |
            (@as(usize, data[pos + 2]) << 16) |
            (@as(usize, data[pos + 3]) << 8) |
            @as(usize, data[pos + 4]);
        if (len < 4 or pos + 1 + len > data.len) break;

        if (t == 'S') {
            const param_data = data[pos + 5 .. pos + 1 + len];
            if (std.mem.indexOf(u8, param_data, "server_version")) |sv| {
                const val_start = sv + 15;
                if (val_start < param_data.len) {
                    const val_end = std.mem.indexOfScalarPos(u8, param_data, val_start, 0) orelse param_data.len;
                    info.setVersion(param_data[val_start..val_end]);
                    return;
                }
            }
        }
        pos += 1 + len;
    }
}

fn probeTls(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};

    const tls_info = tls_mod.probe(ip, port);
    if (!tls_info.valid) return info;

    info.tls = true;

    const cn = tls_info.subjectCn();
    if (cn.len > 0) {
        info.setName(cn);
    }

    const ver = tls_info.versionStr();
    const cipher = tls_info.cipherStr();
    const expiry = tls_info.notAfter();

    var extra: [256]u8 = undefined;
    var elen: usize = 0;

    if (ver.len > 0) {
        const written = std.fmt.bufPrint(extra[elen..], "{s}", .{ver}) catch "";
        elen += written.len;
    }
    if (cipher.len > 0) {
        const written = std.fmt.bufPrint(extra[elen..], " {s}", .{cipher}) catch "";
        elen += written.len;
    }
    if (expiry.len > 0) {
        const written = std.fmt.bufPrint(extra[elen..], " exp:{s}", .{expiry}) catch "";
        elen += written.len;
    }

    if (elen > 0) {
        info.setExtra(extra[0..elen]);
    }

    const issuer = tls_info.issuerCn();
    if (cn.len > 0 and issuer.len > 0) {
        var vbuf: [128]u8 = undefined;
        const vstr = std.fmt.bufPrint(&vbuf, "{s} (issuer: {s})", .{ cn, issuer }) catch cn;
        info.setVersion(vstr);
    } else if (cn.len > 0) {
        info.setVersion(cn);
    } else if (ver.len > 0) {
        info.setVersion(ver);
    }

    return info;
}

fn probeGeneric(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var buf: [1024]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n == 0) return info;

    const line_end = std.mem.indexOfAny(u8, buf[0..n], "\r\n") orelse @min(n, 128);
    const line = buf[0..line_end];

    if (std.mem.startsWith(u8, line, "SSH-")) {
        return probeSshFromBanner(line);
    }

    if (line.len > 4 and isDigit(line[0]) and isDigit(line[1]) and isDigit(line[2]) and (line[3] == ' ' or line[3] == '-')) {
        info.setVersion(line[4..]);
        return info;
    }

    if (line.len > 0) {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len > 0) info.setVersion(trimmed);
    }

    return info;
}

fn probeSshFromBanner(line: []const u8) ServiceInfo {
    var info = ServiceInfo{};
    var dash_count: u8 = 0;
    var soft_start: usize = 0;
    for (line, 0..) |c, i| {
        if (c == '-') {
            dash_count += 1;
            if (dash_count == 2) {
                soft_start = i + 1;
                break;
            }
        }
    }
    if (soft_start > 0 and soft_start < line.len) {
        const software = line[soft_start..];
        if (std.mem.indexOf(u8, software, "OpenSSH")) |_| {
            info.setName("OpenSSH");
            if (std.mem.indexOf(u8, software, "_")) |uscore| {
                const ver_end = std.mem.indexOfAnyPos(u8, software, uscore + 1, " \t") orelse software.len;
                info.setVersion(software[uscore + 1 .. ver_end]);
            }
        } else {
            info.setVersion(software);
        }
    } else {
        info.setName("SSH");
    }
    return info;
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

fn extractVersionNumber(text: []const u8, info: *ServiceInfo) void {
    for (text, 0..) |c, i| {
        if (isDigit(c)) {
            const start = i;
            var end = i + 1;
            while (end < text.len and (isDigit(text[end]) or text[end] == '.')) {
                end += 1;
            }
            if (end > start + 1) {
                info.setVersion(text[start..end]);
                return;
            }
        }
    }
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
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
