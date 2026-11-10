const std = @import("std");
const rx_mod = @import("rx.zig");
const tls_mod = @import("tls.zig");
const sigs = @import("sigs.zig");

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
        .memcached => probeMemcached(ip, port),
        .mongodb => probeMongodb(ip, port),
        .mqtt => probeMqtt(ip, port),
        .amqp => probeAmqp(ip, port),
        .rdp => probeRdp(ip, port),
        .smb => probeSmb(ip, port),
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

const Protocol = enum {
    http,
    ssh,
    ftp,
    smtp,
    mysql,
    redis,
    postgresql,
    tls,
    memcached,
    mongodb,
    mqtt,
    amqp,
    rdp,
    smb,
    generic,
};

fn classifyPort(port: u16) Protocol {
    return switch (port) {
        80, 3000, 5000, 8000, 8080, 8888, 9090 => .http,
        443, 465, 636, 990, 992, 993, 995, 8443 => .tls,
        22, 2222 => .ssh,
        21 => .ftp,
        25, 587 => .smtp,
        3306, 33060 => .mysql,
        6379...6399 => .redis,
        5432...5434 => .postgresql,
        11211 => .memcached,
        27017...27019 => .mongodb,
        1883, 8883 => .mqtt,
        5672 => .amqp,
        3389 => .rdp,
        445 => .smb,
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

    if (findHeaderValue(data, "server:")) |server| {
        parseServerHeader(server, &info);
    }

    if (findHeaderValue(data, "x-powered-by:")) |val| {
        info.setExtra(val);
    }

    if (info.name_len == 0) {
        if (findHeaderValue(data, "uwebsockets:")) |val| {
            info.setName("uWebSockets");
            info.setVersion(val);
        } else {
            if (extractTitle(data)) |title| {
                info.setVersion(title);
            }
            info.setName("http");
        }
    }

    fingerprintHttp(data, &info);

    if (std.mem.eql(u8, info.name(), "uvicorn") and std.mem.eql(u8, info.extra(), "FastAPI")) {
        probeFastapiOpenapi(ip, port, &info);
    }

    if (std.mem.eql(u8, info.name(), "http")) {
        if (sigs.matchHttp(data)) |m| {
            info.setName(m.name);
            info.version_len = 0;
        }
    }

    if (info.extra_len == 0 and std.mem.eql(u8, info.name(), "http")) {
        storeHttpEvidence(data, &info);
    }

    return info;
}

fn storeHttpEvidence(data: []const u8, info: *ServiceInfo) void {
    var buf: [128]u8 = undefined;
    var len: usize = 0;

    if (data.len >= 12 and std.mem.startsWith(u8, data, "HTTP/")) {
        const written = std.fmt.bufPrint(buf[len..], "{s}", .{data[9..12]}) catch return;
        len += written.len;
    }
    if (findHeaderValue(data, "content-type:")) |ct| {
        const semi = std.mem.indexOfScalar(u8, ct, ';') orelse ct.len;
        const short = ct[0..@min(semi, 32)];
        const written = std.fmt.bufPrint(buf[len..], ", {s}", .{short}) catch return;
        len += written.len;
    }
    const body_start = if (std.mem.indexOf(u8, data, "\r\n\r\n")) |p| p + 4 else data.len;
    if (body_start < data.len) {
        const body_len = data.len - body_start;
        const written = std.fmt.bufPrint(buf[len..], ", {d}B", .{body_len}) catch return;
        len += written.len;
    }
    if (len > 0) {
        info.setExtra(buf[0..len]);
    }
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
            info.setVersion(software[uscore + 1 ..]);
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

    if (std.mem.startsWith(u8, data, "-NOAUTH") or std.mem.startsWith(u8, data, "-DENIED")) {
        info.setName("Redis");
        info.setExtra("auth required");
        return info;
    }

    if (std.mem.startsWith(u8, data, "-ERR")) {
        info.setName("Redis");
        return info;
    }

    if (data[0] != '$' or !std.mem.startsWith(u8, data, "$")) return info;
    if (std.mem.indexOf(u8, data, "redis_version:") == null) return info;

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

    const alpn_str = tls_info.alpn();

    var extra: [256]u8 = undefined;
    var elen: usize = 0;

    if (ver.len > 0) {
        const written = std.fmt.bufPrint(extra[elen..], "{s}", .{ver}) catch "";
        elen += written.len;
    }
    if (alpn_str.len > 0) {
        const written = std.fmt.bufPrint(extra[elen..], ", {s}", .{alpn_str}) catch "";
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

fn probeMemcached(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    _ = std.posix.write(fd, "version\r\n") catch return info;
    var buf: [256]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 8) return info;

    const data = buf[0..n];
    if (std.mem.startsWith(u8, data, "VERSION ")) {
        info.setName("Memcached");
        const end = std.mem.indexOfAny(u8, data[8..], "\r\n") orelse (n - 8);
        info.setVersion(data[8 .. 8 + end]);
    }
    _ = std.posix.write(fd, "quit\r\n") catch {};
    return info;
}

fn probeMongodb(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    // OP_QUERY: isMaster command on admin.$cmd
    const bson_doc = [_]u8{
        0x15, 0x00, 0x00, 0x00, // doc size = 21
        0x10, // type: int32
        'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // key
        0x01, 0x00, 0x00, 0x00, // value = 1
        0x00, // doc terminator
    };
    const coll = "admin.$cmd\x00";
    const payload_len = 4 + coll.len + 4 + 4 + bson_doc.len;
    const msg_len: u32 = @intCast(16 + payload_len);

    var msg: [128]u8 = .{0} ** 128;
    var pos: usize = 0;
    std.mem.writeInt(u32, msg[pos..][0..4], msg_len, .little);
    pos += 4;
    std.mem.writeInt(u32, msg[pos..][0..4], 1, .little);
    pos += 4; // requestID
    pos += 4; // responseTo = 0
    std.mem.writeInt(u32, msg[pos..][0..4], 2004, .little);
    pos += 4; // OP_QUERY
    pos += 4; // flags = 0
    @memcpy(msg[pos .. pos + coll.len], coll);
    pos += coll.len;
    pos += 4; // numberToSkip = 0
    std.mem.writeInt(u32, msg[pos..][0..4], @as(u32, 0xFFFFFFFF), .little);
    pos += 4; // numberToReturn
    @memcpy(msg[pos .. pos + bson_doc.len], &bson_doc);
    pos += bson_doc.len;

    _ = std.posix.write(fd, msg[0..pos]) catch return info;

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 36) return info;

    const op = std.mem.readInt(u32, buf[12..16], .little);
    if (op != 1) return info;

    info.setName("MongoDB");
    if (findBsonString(buf[36..n], "version")) |ver| {
        info.setVersion(ver);
    }
    return info;
}

fn findBsonString(data: []const u8, key: []const u8) ?[]const u8 {
    if (data.len < 5) return null;
    var pos: usize = 4;
    while (pos < data.len) {
        const btype = data[pos];
        if (btype == 0) break;
        pos += 1;
        const key_end = std.mem.indexOfScalarPos(u8, data, pos, 0) orelse break;
        const found_key = data[pos..key_end];
        pos = key_end + 1;

        if (btype == 0x02 and std.mem.eql(u8, found_key, key)) {
            if (pos + 4 > data.len) break;
            const str_len = std.mem.readInt(u32, data[pos..][0..4], .little);
            pos += 4;
            if (str_len == 0 or pos + str_len > data.len) break;
            return data[pos .. pos + str_len - 1];
        } else {
            pos = skipBsonValue(data, pos, btype) orelse break;
        }
    }
    return null;
}

fn skipBsonValue(data: []const u8, start: usize, btype: u8) ?usize {
    const pos = start;
    switch (btype) {
        0x01 => return if (pos + 8 <= data.len) pos + 8 else null, // double
        0x02, 0x0D, 0x0E => { // string, JS, symbol
            if (pos + 4 > data.len) return null;
            const len = std.mem.readInt(u32, data[pos..][0..4], .little);
            return if (pos + 4 + len <= data.len) pos + 4 + len else null;
        },
        0x03, 0x04 => { // document, array
            if (pos + 4 > data.len) return null;
            const len = std.mem.readInt(u32, data[pos..][0..4], .little);
            return if (pos + len <= data.len) pos + len else null;
        },
        0x05 => { // binary
            if (pos + 5 > data.len) return null;
            const len = std.mem.readInt(u32, data[pos..][0..4], .little);
            return if (pos + 5 + len <= data.len) pos + 5 + len else null;
        },
        0x07 => return if (pos + 12 <= data.len) pos + 12 else null, // ObjectId
        0x08 => return if (pos + 1 <= data.len) pos + 1 else null, // bool
        0x09 => return if (pos + 8 <= data.len) pos + 8 else null, // datetime
        0x0A => return pos, // null
        0x10 => return if (pos + 4 <= data.len) pos + 4 else null, // int32
        0x11, 0x12 => return if (pos + 8 <= data.len) pos + 8 else null, // timestamp, int64
        else => return null,
    }
}

fn probeMqtt(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    const connect_pkt = [_]u8{
        0x10, 0x10, // CONNECT, remaining length 16
        0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
        0x04, // protocol level 4 (MQTT 3.1.1)
        0x02, // connect flags (clean session)
        0x00, 0x3C, // keepalive 60s
        0x00, 0x04, 'o', 'h', 'm', 'z', // client ID
    };
    _ = std.posix.write(fd, &connect_pkt) catch return info;

    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 2) return info;

    if (buf[0] == 0x20) {
        info.setName("MQTT");
        if (n >= 4) {
            const rc = buf[3];
            const status: []const u8 = switch (rc) {
                0 => "connected",
                4 => "bad-credentials",
                5 => "not-authorized",
                else => "refused",
            };
            info.setExtra(status);
        }
    }
    _ = std.posix.write(fd, &[_]u8{ 0xE0, 0x00 }) catch {};
    return info;
}

fn probeAmqp(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    _ = std.posix.write(fd, "AMQP\x00\x00\x09\x01") catch return info;

    var buf: [512]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 8) return info;

    // Connection.Start: frame type=1 (method), class=10, method=10
    if (buf[0] == 1) {
        info.setName("AMQP");
        // Check for RabbitMQ in the response payload
        if (n > 20 and std.mem.indexOf(u8, buf[0..n], "RabbitMQ") != null) {
            info.setExtra("RabbitMQ");
        }
    }
    return info;
}

fn probeRdp(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    const cr_pkt = [_]u8{
        0x03, 0x00, 0x00, 0x0B, // TPKT header
        0x06, // X.224 length
        0xE0, // Connection Request
        0x00, 0x00, // dst-ref
        0x00, 0x00, // src-ref
        0x00, // class 0
    };
    _ = std.posix.write(fd, &cr_pkt) catch return info;

    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 7) return info;

    if (buf[0] == 0x03 and buf[1] == 0x00 and buf[5] == 0xD0) {
        info.setName("RDP");
        info.setExtra("Microsoft Terminal Services");
    }
    return info;
}

fn probeSmb(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    // SMB2 Negotiate: NetBIOS(4) + SMB2 header(64) + negotiate body
    var pkt: [128]u8 = .{0} ** 128;
    var pos: usize = 4; // skip NetBIOS header

    // SMB2 header
    @memcpy(pkt[pos .. pos + 4], "\xfeSMB");
    pos += 4;
    std.mem.writeInt(u16, pkt[pos..][0..2], 64, .little);
    pos += 2; // structure size
    pos += 2; // credit charge
    pos += 4; // status
    // command = NEGOTIATE (0)
    pos += 2;
    std.mem.writeInt(u16, pkt[pos..][0..2], 1, .little);
    pos += 2; // credit request
    pos += 4; // flags
    pos += 4; // next command
    pos += 8; // message ID
    pos += 4; // reserved
    pos += 4; // tree ID
    pos += 8; // session ID
    pos += 16; // signature

    // Negotiate body
    std.mem.writeInt(u16, pkt[pos..][0..2], 36, .little);
    pos += 2; // structure size
    std.mem.writeInt(u16, pkt[pos..][0..2], 2, .little);
    pos += 2; // dialect count
    pos += 2; // security mode
    pos += 2; // reserved
    pos += 4; // capabilities
    pos += 16; // client GUID
    pos += 8; // negotiate context
    // dialects
    std.mem.writeInt(u16, pkt[pos..][0..2], 0x0202, .little);
    pos += 2;
    std.mem.writeInt(u16, pkt[pos..][0..2], 0x0311, .little);
    pos += 2;

    // NetBIOS length
    const nb_len: u32 = @intCast(pos - 4);
    std.mem.writeInt(u32, pkt[0..4], nb_len, .big);
    pkt[0] = 0;

    _ = std.posix.write(fd, pkt[0..pos]) catch return info;

    var buf: [512]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n < 68) return info;

    if (n >= 8 and std.mem.eql(u8, buf[4..8], "\xfeSMB")) {
        info.setName("SMB");
        if (n >= 72) {
            const dialect = std.mem.readInt(u16, buf[68..70], .little);
            var ver_buf: [16]u8 = undefined;
            const ver_str: []const u8 = switch (dialect) {
                0x0202 => "2.0.2",
                0x0210 => "2.1",
                0x0300 => "3.0",
                0x0302 => "3.0.2",
                0x0311 => "3.1.1",
                else => std.fmt.bufPrint(&ver_buf, "dialect:0x{X:0>4}", .{dialect}) catch "unknown",
            };
            info.setVersion(ver_str);
        }
    } else if (n >= 8 and std.mem.eql(u8, buf[4..8], "\xffSMB")) {
        info.setName("SMB");
        info.setVersion("1.0");
    }
    return info;
}

fn probeGeneric(ip: u32, port: u16) ServiceInfo {
    // Phase 1: NULL probe - wait for service to speak first
    {
        const fd = openSocket(ip, port) orelse return ServiceInfo{};
        defer std.posix.close(fd);

        var buf: [1024]u8 = undefined;
        const n = readWithTimeout(fd, &buf, 1_000_000_000);
        if (n > 0) {
            const data = buf[0..n];
            const result = classifyBanner(data, ip, port);
            if (result.name_len > 0) return result;
            if (sigs.matchBanner(data)) |m| {
                var sig_info = ServiceInfo{};
                sig_info.setName(m.name);
                if (m.version.len > 0) sig_info.setVersion(m.version);
                return sig_info;
            }
            if (!result.empty()) return result;
        }
    }

    // Phase 2: HTTP GET (most common on unknown ports, fresh connection)
    if (!isKnownNonHttpPort(port)) {
        const http_info = probeHttpGeneric(ip, port);
        if (!http_info.empty()) return http_info;
    }

    // Phase 3: Protocol-specific probes (last resort, each on a fresh connection)
    {
        const redis_info = probeRedis(ip, port);
        if (!redis_info.empty()) return redis_info;
    }
    {
        const pg_info = probePostgresql(ip, port);
        if (!pg_info.empty()) return pg_info;
    }

    return ServiceInfo{};
}

fn classifyBanner(data: []const u8, ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const line_end = std.mem.indexOfAny(u8, data, "\r\n") orelse @min(data.len, 128);
    const line = data[0..line_end];

    if (std.mem.startsWith(u8, line, "SSH-")) {
        return probeSshFromBanner(line);
    }

    // FTP/SMTP-style numeric banner (e.g. "220 ...")
    if (line.len > 4 and isDigit(line[0]) and isDigit(line[1]) and isDigit(line[2]) and (line[3] == ' ' or line[3] == '-')) {
        info.setVersion(line[4..]);
        return info;
    }

    // MySQL greeting packet
    if (data.len >= 5 and data[3] == 0 and data[4] == 0x0a) {
        return probeMysql(ip, port);
    }

    // Redis RESP response
    if (std.mem.startsWith(u8, data, "-ERR") or
        std.mem.startsWith(u8, data, "-NOAUTH") or
        std.mem.startsWith(u8, data, "-DENIED") or
        std.mem.startsWith(u8, data, "+PONG") or
        (data[0] == '$' and data.len >= 4 and (isDigit(data[1]) or data[1] == '-')))
    {
        info.setName("Redis");
        if (std.mem.indexOf(u8, data, "NOAUTH")) |_| {
            info.setExtra("auth required");
        }
        return info;
    }

    // HTTP response (some servers send HTTP without a request)
    if (std.mem.startsWith(u8, data, "HTTP/")) {
        info.setName("http");
        if (findHeaderValue(data, "server:")) |server| {
            parseServerHeader(server, &info);
        }
        fingerprintHttp(data, &info);
        return info;
    }

    // Generic banner text
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len > 0) {
        info.setVersion(trimmed);
    }

    return info;
}

fn probeHttpGeneric(ip: u32, port: u16) ServiceInfo {
    var info = ServiceInfo{};
    const fd = openSocket(ip, port) orelse return info;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);
    var req_buf: [128]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{ip_str}) catch return info;
    _ = std.posix.write(fd, request) catch return info;

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return info;
    if (n == 0) return info;

    const data = buf[0..n];
    if (!std.mem.startsWith(u8, data, "HTTP/")) return info;

    if (findHeaderValue(data, "server:")) |server| {
        parseServerHeader(server, &info);
    }
    if (info.name_len == 0) {
        if (findHeaderValue(data, "uwebsockets:")) |val| {
            info.setName("uWebSockets");
            info.setVersion(val);
        } else {
            if (extractTitle(data)) |title| {
                info.setVersion(title);
            }
            info.setName("http");
        }
    }
    if (findHeaderValue(data, "x-powered-by:")) |val| {
        info.setExtra(val);
    }
    fingerprintHttp(data, &info);

    if (std.mem.eql(u8, info.name(), "uvicorn") and std.mem.eql(u8, info.extra(), "FastAPI")) {
        probeFastapiOpenapi(ip, port, &info);
    }

    if (std.mem.eql(u8, info.name(), "http")) {
        if (sigs.matchHttp(data)) |m| {
            info.setName(m.name);
            info.version_len = 0;
        }
    }

    if (info.extra_len == 0 and std.mem.eql(u8, info.name(), "http")) {
        storeHttpEvidence(data, &info);
    }

    return info;
}

fn probeFastapiOpenapi(ip: u32, port: u16, info: *ServiceInfo) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);
    var req_buf: [128]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET /openapi.json HTTP/1.0\r\nHost: {s}\r\n\r\n", .{ip_str}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n == 0) return;
    const data = buf[0..n];

    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return;
    if (std.mem.indexOf(u8, data[0..@min(data.len, 32)], " 200 ") == null) return;

    const body_start = (std.mem.indexOf(u8, data, "\r\n\r\n") orelse return) + 4;
    if (body_start >= data.len) return;
    const body = data[body_start..];

    if (findJsonValue(body, "\"title\":\"")) |title| {
        if (findJsonValue(body, "\"version\":\"")) |ver| {
            var extra_buf: [128]u8 = undefined;
            const extra = std.fmt.bufPrint(&extra_buf, "{s} {s}", .{ title, ver }) catch return;
            info.setExtra(extra);
        } else {
            info.setExtra(title);
        }
    }
}

fn isKnownNonHttpPort(port: u16) bool {
    return switch (port) {
        22, 2222 => true,
        21 => true,
        25, 587 => true,
        110 => true,
        143 => true,
        3306, 33060 => true,
        5432...5434 => true,
        6379...6399 => true,
        6660...6669, 6697 => true,
        11211 => true,
        27017...27019 => true,
        1883, 8883 => true,
        5672 => true,
        3389 => true,
        445 => true,
        else => false,
    };
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
                info.setVersion(software[uscore + 1 ..]);
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

fn readWithTimeout(fd: std.posix.fd_t, buf: []u8, timeout_ns: u64) usize {
    var pfd = [1]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ms: i32 = @intCast(timeout_ns / 1_000_000);
    const ready = std.posix.poll(&pfd, ms) catch return 0;
    if (ready == 0) return 0;
    return std.posix.read(fd, buf) catch 0;
}

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

fn findHeaderValue(data: []const u8, header: []const u8) ?[]const u8 {
    // Only match at start of a header line (pos == 0 or preceded by \n)
    var offset: usize = 0;
    while (offset < data.len) {
        const pos = findCaseTag(data[offset..], header) orelse return null;
        const abs_pos = offset + pos;
        if (abs_pos == 0 or data[abs_pos - 1] == '\n') {
            var start = abs_pos + header.len;
            while (start < data.len and (data[start] == ' ' or data[start] == '\t')) start += 1;
            if (start >= data.len) return null;
            const end = std.mem.indexOfPos(u8, data, start, "\r\n") orelse @min(start + 128, data.len);
            if (start >= end) return null;
            return data[start..end];
        }
        offset = abs_pos + 1;
    }
    return null;
}

fn parseServerHeader(server: []const u8, info: *ServiceInfo) void {
    if (std.mem.indexOf(u8, server, "/")) |slash| {
        info.setName(server[0..slash]);
        if (slash + 1 < server.len) info.setVersion(server[slash + 1 ..]);
    } else {
        info.setName(server);
    }
}

fn fingerprintHttp(data: []const u8, info: *ServiceInfo) void {
    const body_start = if (std.mem.indexOf(u8, data, "\r\n\r\n")) |pos| pos + 4 else data.len;
    const body = if (body_start < data.len) data[body_start..] else "";

    // uvicorn + {"detail":...} -> FastAPI
    if (info.name_len > 0 and std.mem.eql(u8, info.name(), "uvicorn")) {
        if (std.mem.indexOf(u8, body, "{\"detail\":")) |_| {
            info.setExtra("FastAPI");
        }
        return;
    }

    if (info.name_len == 0 or std.mem.eql(u8, info.name(), "http")) {
        // Go net/http: body "404 page not found" + X-Content-Type-Options: nosniff
        if (findHeaderValue(data, "x-content-type-options:")) |val| {
            if (findCaseTag(val, "nosniff") != null and std.mem.indexOf(u8, body, "404 page not found") != null) {
                info.setName("Go net/http");
                return;
            }
        }

        // Node.js http: Keep-Alive: timeout=N + Transfer-Encoding: chunked + no Server
        if (findHeaderValue(data, "keep-alive:")) |ka| {
            if (std.mem.startsWith(u8, ka, "timeout=") and findHeaderValue(data, "transfer-encoding:") != null) {
                info.setName("Node.js http");
                return;
            }
        }

        // Elasticsearch: JSON with "tagline":"You Know, for Search"
        if (std.mem.indexOf(u8, body, "You Know, for Search") != null) {
            info.setName("Elasticsearch");
            if (findJsonValue(body, "\"number\":\"")) |ver| {
                info.setVersion(ver);
            }
            return;
        }

        // Docker API: JSON with "ApiVersion"
        if (std.mem.indexOf(u8, body, "\"ApiVersion\"") != null) {
            info.setName("Docker API");
            if (findJsonValue(body, "\"ApiVersion\":\"")) |ver| {
                info.setVersion(ver);
            }
            return;
        }
    }
}

fn findJsonValue(data: []const u8, prefix: []const u8) ?[]const u8 {
    const pos = std.mem.indexOf(u8, data, prefix) orelse return null;
    const start = pos + prefix.len;
    if (start >= data.len) return null;
    const end = std.mem.indexOfScalarPos(u8, data, start, '"') orelse return null;
    return data[start..end];
}

fn extractTitle(data: []const u8) ?[]const u8 {
    const open = findCaseTag(data, "<title>") orelse return null;
    const after = open + 7;
    if (after >= data.len) return null;
    const close = findCaseTag(data[after..], "</title>") orelse return null;
    const raw = data[after .. after + close];
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;
    return trimmed;
}

fn findCaseTag(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;
    const end = haystack.len - needle.len + 1;
    var i: usize = 0;
    while (i < end) : (i += 1) {
        var matched = true;
        for (needle, 0..) |nc, j| {
            const hc = haystack[i + j];
            const lower_h = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
            const lower_n = if (nc >= 'A' and nc <= 'Z') nc + 32 else nc;
            if (lower_h != lower_n) {
                matched = false;
                break;
            }
        }
        if (matched) return i;
    }
    return null;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseServerHeader - nginx with version" {
    var info = ServiceInfo{};
    parseServerHeader("nginx/1.25.3", &info);
    try std.testing.expectEqualStrings("nginx", info.name());
    try std.testing.expectEqualStrings("1.25.3", info.version());
}

test "parseServerHeader - Apache complex version" {
    var info = ServiceInfo{};
    parseServerHeader("Apache/2.4.57 (Debian)", &info);
    try std.testing.expectEqualStrings("Apache", info.name());
    try std.testing.expectEqualStrings("2.4.57 (Debian)", info.version());
}

test "parseServerHeader - name only, no slash" {
    var info = ServiceInfo{};
    parseServerHeader("cloudflare", &info);
    try std.testing.expectEqualStrings("cloudflare", info.name());
    try std.testing.expectEqual(@as(u8, 0), info.version_len);
}

test "probeSshFromBanner - OpenSSH" {
    const info = probeSshFromBanner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.4");
    try std.testing.expectEqualStrings("OpenSSH", info.name());
    try std.testing.expectEqualStrings("9.6p1 Ubuntu-3ubuntu0.4", info.version());
}

test "probeSshFromBanner - unknown SSH software" {
    const info = probeSshFromBanner("SSH-2.0-libssh_0.10.5");
    try std.testing.expectEqualStrings("libssh_0.10.5", info.version());
}

test "probeSshFromBanner - bare SSH" {
    const info = probeSshFromBanner("SSH-2.0");
    try std.testing.expectEqualStrings("SSH", info.name());
}

test "findHeaderValue - case insensitive match" {
    const data = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\n\r\n";
    const val = findHeaderValue(data, "server:");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("nginx/1.25", val.?);
}

test "findHeaderValue - lowercase header" {
    const data = "HTTP/1.1 200 OK\r\nserver: uvicorn\r\ncontent-type: application/json\r\n\r\n";
    const val = findHeaderValue(data, "server:");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("uvicorn", val.?);
}

test "findHeaderValue - not found" {
    const data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    const val = findHeaderValue(data, "server:");
    try std.testing.expect(val == null);
}

test "findHeaderValue - no mid-line match" {
    const data = "HTTP/1.1 200 OK\r\nX-Server: fake\r\n\r\n";
    const val = findHeaderValue(data, "server:");
    try std.testing.expect(val == null);
}

test "fingerprintHttp - uvicorn with FastAPI body" {
    var info = ServiceInfo{};
    info.setName("uvicorn");
    const data = "HTTP/1.1 404 Not Found\r\nserver: uvicorn\r\ncontent-type: application/json\r\n\r\n{\"detail\":\"Not Found\"}";
    fingerprintHttp(data, &info);
    try std.testing.expectEqualStrings("FastAPI", info.extra());
}

test "fingerprintHttp - uvicorn without FastAPI body" {
    var info = ServiceInfo{};
    info.setName("uvicorn");
    const data = "HTTP/1.1 200 OK\r\nserver: uvicorn\r\n\r\n<html>Hello</html>";
    fingerprintHttp(data, &info);
    try std.testing.expectEqual(@as(u16, 0), info.extra_len);
}

test "fingerprintHttp - Go net/http" {
    var info = ServiceInfo{};
    info.setName("http");
    const data = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n\r\n404 page not found\n";
    fingerprintHttp(data, &info);
    try std.testing.expectEqualStrings("Go net/http", info.name());
}

test "fingerprintHttp - Node.js http" {
    var info = ServiceInfo{};
    info.setName("http");
    const data = "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\nHello";
    fingerprintHttp(data, &info);
    try std.testing.expectEqualStrings("Node.js http", info.name());
}

test "extractTitle - basic" {
    const data = "HTTP/1.1 200 OK\r\n\r\n<html><head><title>My Page</title></head></html>";
    const title = extractTitle(data);
    try std.testing.expect(title != null);
    try std.testing.expectEqualStrings("My Page", title.?);
}

test "extractTitle - case insensitive" {
    const data = "<HTML><HEAD><TITLE>Test</TITLE></HEAD></HTML>";
    const title = extractTitle(data);
    try std.testing.expect(title != null);
    try std.testing.expectEqualStrings("Test", title.?);
}

test "extractTitle - no title" {
    const data = "<html><body>No title here</body></html>";
    const title = extractTitle(data);
    try std.testing.expect(title == null);
}

test "findCaseTag - case insensitive" {
    const pos = findCaseTag("Hello World", "HELLO");
    try std.testing.expect(pos != null);
    try std.testing.expectEqual(@as(usize, 0), pos.?);
}

test "findCaseTag - not found" {
    const pos = findCaseTag("Hello World", "xyz");
    try std.testing.expect(pos == null);
}

test "extractVersionNumber - basic" {
    var info = ServiceInfo{};
    extractVersionNumber("vsftpd 3.0.5", &info);
    try std.testing.expectEqualStrings("3.0.5", info.version());
}

test "extractVersionNumber - embedded in text" {
    var info = ServiceInfo{};
    extractVersionNumber("ProFTPD 1.3.7c Server ready", &info);
    try std.testing.expectEqualStrings("1.3.7", info.version());
}

test "classifyPort - known ports" {
    try std.testing.expectEqual(Protocol.http, classifyPort(80));
    try std.testing.expectEqual(Protocol.http, classifyPort(8080));
    try std.testing.expectEqual(Protocol.tls, classifyPort(443));
    try std.testing.expectEqual(Protocol.ssh, classifyPort(22));
    try std.testing.expectEqual(Protocol.ftp, classifyPort(21));
    try std.testing.expectEqual(Protocol.smtp, classifyPort(25));
    try std.testing.expectEqual(Protocol.mysql, classifyPort(3306));
    try std.testing.expectEqual(Protocol.redis, classifyPort(6379));
    try std.testing.expectEqual(Protocol.redis, classifyPort(6382));
    try std.testing.expectEqual(Protocol.postgresql, classifyPort(5432));
    try std.testing.expectEqual(Protocol.generic, classifyPort(9999));
}

test "ServiceInfo - setName truncates at 32 bytes" {
    var info = ServiceInfo{};
    const long = "a" ** 64;
    info.setName(long);
    try std.testing.expectEqual(@as(u8, 32), info.name_len);
}

test "ServiceInfo - setVersion trims whitespace" {
    var info = ServiceInfo{};
    info.setVersion("  1.2.3  \r\n");
    try std.testing.expectEqualStrings("1.2.3", info.version());
}

test "ServiceInfo - empty checks" {
    var info = ServiceInfo{};
    try std.testing.expect(info.empty());
    info.setName("test");
    try std.testing.expect(!info.empty());
}

test "ServiceInfo - str prefers version" {
    var info = ServiceInfo{};
    info.setName("nginx");
    info.setVersion("1.25.3");
    try std.testing.expectEqualStrings("1.25.3", info.str());
}

test "ServiceInfo - str falls back to name" {
    var info = ServiceInfo{};
    info.setName("http");
    try std.testing.expectEqualStrings("http", info.str());
}

test "classifyBanner - SSH" {
    const info = classifyBanner("SSH-2.0-OpenSSH_9.6p1\r\n", 0, 0);
    try std.testing.expectEqualStrings("OpenSSH", info.name());
}

test "classifyBanner - FTP greeting" {
    const info = classifyBanner("220 (vsFTPd 3.0.5)\r\n", 0, 0);
    try std.testing.expectEqualStrings("(vsFTPd 3.0.5)", info.version());
}

test "classifyBanner - Redis RESP error" {
    const info = classifyBanner("-NOAUTH Authentication required.\r\n", 0, 0);
    try std.testing.expectEqualStrings("Redis", info.name());
    try std.testing.expectEqualStrings("auth required", info.extra());
}

test "classifyBanner - generic text" {
    const info = classifyBanner("* OK Dovecot ready.\r\n", 0, 0);
    try std.testing.expectEqualStrings("* OK Dovecot ready.", info.version());
}

test "isKnownNonHttpPort" {
    try std.testing.expect(isKnownNonHttpPort(22));
    try std.testing.expect(isKnownNonHttpPort(6379));
    try std.testing.expect(isKnownNonHttpPort(3306));
    try std.testing.expect(!isKnownNonHttpPort(80));
    try std.testing.expect(!isKnownNonHttpPort(8080));
    try std.testing.expect(!isKnownNonHttpPort(9999));
}

test "storeHttpEvidence - status, content-type, body size" {
    var info = ServiceInfo{};
    info.setName("http");
    const data = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found";
    storeHttpEvidence(data, &info);
    try std.testing.expectEqualStrings("404, text/plain, 9B", info.extra());
}

test "storeHttpEvidence - strips content-type params" {
    var info = ServiceInfo{};
    info.setName("http");
    const data = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h1>Hi</h1>";
    storeHttpEvidence(data, &info);
    try std.testing.expectEqualStrings("200, text/html, 11B", info.extra());
}

test "classifyPort - new protocols" {
    try std.testing.expectEqual(Protocol.memcached, classifyPort(11211));
    try std.testing.expectEqual(Protocol.mongodb, classifyPort(27017));
    try std.testing.expectEqual(Protocol.mqtt, classifyPort(1883));
    try std.testing.expectEqual(Protocol.amqp, classifyPort(5672));
    try std.testing.expectEqual(Protocol.rdp, classifyPort(3389));
    try std.testing.expectEqual(Protocol.smb, classifyPort(445));
}

test "isKnownNonHttpPort - new protocols" {
    try std.testing.expect(isKnownNonHttpPort(11211));
    try std.testing.expect(isKnownNonHttpPort(27017));
    try std.testing.expect(isKnownNonHttpPort(1883));
    try std.testing.expect(isKnownNonHttpPort(5672));
    try std.testing.expect(isKnownNonHttpPort(3389));
    try std.testing.expect(isKnownNonHttpPort(445));
}

test "fingerprintHttp - Elasticsearch" {
    var info = ServiceInfo{};
    info.setName("http");
    const data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"node1\",\"version\":{\"number\":\"8.12.0\"},\"tagline\":\"You Know, for Search\"}";
    fingerprintHttp(data, &info);
    try std.testing.expectEqualStrings("Elasticsearch", info.name());
    try std.testing.expectEqualStrings("8.12.0", info.version());
}

test "fingerprintHttp - Docker API" {
    var info = ServiceInfo{};
    info.setName("http");
    const data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ApiVersion\":\"1.45\",\"Version\":\"27.0.3\"}";
    fingerprintHttp(data, &info);
    try std.testing.expectEqualStrings("Docker API", info.name());
    try std.testing.expectEqualStrings("1.45", info.version());
}

test "findJsonValue" {
    const data = "{\"name\":\"test\",\"version\":\"1.2.3\"}";
    const val = findJsonValue(data, "\"version\":\"");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("1.2.3", val.?);
}

test "findBsonString - basic" {
    // BSON: {"version": "7.0.5"}
    // doc_size(4) + type(1) + key\0 + str_len(4) + val\0 + terminator(1)
    const bson = [_]u8{
        0x1C, 0x00, 0x00, 0x00, // doc size = 28
        0x02, // type: string
        'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00, // key
        0x06, 0x00, 0x00, 0x00, // string length = 6 (including null)
        '7', '.', '0', '.', '5', 0x00, // value
        0x00, // doc terminator
    };
    const result = findBsonString(&bson, "version");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("7.0.5", result.?);
}
