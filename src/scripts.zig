const std = @import("std");
const rx_mod = @import("rx.zig");
const tls_mod = @import("tls.zig");

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
    results: [12]ScriptResult = .{ScriptResult{}} ** 12,
    count: u8 = 0,

    pub fn add(self: *HostScripts, script_id: []const u8, output_text: []const u8) void {
        if (self.count >= 12) return;
        self.results[self.count].setId(script_id);
        self.results[self.count].setOutput(output_text);
        self.count += 1;
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn runDefault(ip: u32, port: u16) HostScripts {
    return runScripts(ip, port, false);
}

pub fn runScripts(ip: u32, port: u16, extended: bool) HostScripts {
    var hs = HostScripts{};
    switch (port) {
        80, 8080, 8888, 3000, 5000, 8000, 9090 => {
            scriptHttpTitle(ip, port, &hs);
            scriptHttpRobots(ip, port, &hs);
            if (extended) {
                scriptHttpOpenapi(ip, port, &hs);
                scriptHttpDocs(ip, port, &hs);
                scriptHttp404(ip, port, &hs);
                scriptHttpProxy(ip, port, &hs);
            }
        },
        22, 2222 => scriptSshHostkey(ip, port, &hs),
        25, 587 => scriptSmtpCommands(ip, port, &hs),
        3306, 33060 => scriptMysqlInfo(ip, port, &hs),
        3389 => scriptRdpNtlm(ip, port, &hs),
        443, 465, 636, 993, 995, 3269, 7443, 8443, 9091 => scriptSslCert(ip, port, &hs),
        445 => scriptSmb2Info(ip, port, &hs),
        389, 3268 => scriptLdapRootdse(ip, port, &hs),
        5222, 5269 => scriptXmppInfo(ip, port, &hs),
        1080, 7777 => scriptSocksAuth(ip, port, &hs),
        else => {
            if (extended) {
                // Try HTTP scripts on non-standard ports too
                scriptHttpTitle(ip, port, &hs);
                if (hs.count > 0) {
                    scriptHttpOpenapi(ip, port, &hs);
                    scriptHttp404(ip, port, &hs);
                }
            }
        },
    }
    return hs;
}

pub fn runAll(
    ports: []const rx_mod.OpenPort,
    results: []HostScripts,
    num_workers: usize,
) void {
    runAllEx(ports, results, num_workers, false);
}

pub fn runAllEx(
    ports: []const rx_mod.OpenPort,
    results: []HostScripts,
    num_workers: usize,
    extended: bool,
) void {
    if (ports.len == 0) return;

    if (ports.len == 1 or num_workers <= 1) {
        for (ports, 0..) |p, i| {
            results[i] = runScripts(p.ip, p.port, extended);
        }
        return;
    }

    var next_idx = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        ports: []const rx_mod.OpenPort,
        results: []HostScripts,
        next: *std.atomic.Value(usize),
        ext: bool,
    };

    var ctx = Ctx{
        .ports = ports,
        .results = results,
        .next = &next_idx,
        .ext = extended,
    };

    const actual = @min(num_workers, @min(ports.len, MAX_WORKERS));
    var threads: [MAX_WORKERS]?std.Thread = .{null} ** MAX_WORKERS;

    for (0..actual) |w| {
        threads[w] = std.Thread.spawn(.{}, struct {
            fn run(c: *Ctx) void {
                while (true) {
                    const i = c.next.fetchAdd(1, .monotonic);
                    if (i >= c.ports.len) break;
                    c.results[i] = runScripts(c.ports[i].ip, c.ports[i].port, c.ext);
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
// Script: http-openapi (extended)
// ---------------------------------------------------------------------------

fn scriptHttpOpenapi(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);
    var req_buf: [160]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET /openapi.json HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ip_str}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    if (total < 15) return;

    const data = buf[0..total];
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return;
    if (!std.mem.eql(u8, data[9..12], "200")) return;

    if (std.mem.indexOf(u8, data, "\"openapi\"") != null or std.mem.indexOf(u8, data, "\"swagger\"") != null) {
        var out_buf: [128]u8 = undefined;
        if (findJsonStringValue(data, "\"title\"")) |title| {
            const out = std.fmt.bufPrint(&out_buf, "OpenAPI: {s}", .{title}) catch "OpenAPI spec found";
            hs.add("http-openapi", out);
        } else {
            hs.add("http-openapi", "OpenAPI spec found");
        }
    }
}

fn findJsonStringValue(data: []const u8, key_with_quote: []const u8) ?[]const u8 {
    // Find "key":"value" pattern
    const key_pos = std.mem.indexOf(u8, data, key_with_quote) orelse return null;
    var pos = key_pos + key_with_quote.len;
    // Skip whitespace and colon
    while (pos < data.len and (data[pos] == ':' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
    if (pos == 0) return null;
    pos -= 1; // back to opening quote
    if (pos >= data.len or data[pos] != '"') return null;
    pos += 1;
    const end = std.mem.indexOfScalarPos(u8, data, pos, '"') orelse return null;
    if (end <= pos) return null;
    return data[pos..end];
}

// ---------------------------------------------------------------------------
// Script: http-docs (extended)
// ---------------------------------------------------------------------------

fn scriptHttpDocs(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);
    var req_buf: [160]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET /docs HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ip_str}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    if (total < 15) return;

    const data = buf[0..total];
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return;
    if (!std.mem.eql(u8, data[9..12], "200")) return;

    if (findCaseInsensitive(data, "swagger-ui") != null) {
        hs.add("http-docs", "Swagger UI");
    } else if (findCaseInsensitive(data, "redoc") != null) {
        hs.add("http-docs", "ReDoc");
    }
}

// ---------------------------------------------------------------------------
// Script: http-404 (extended) - framework fingerprinting via error page
// ---------------------------------------------------------------------------

fn scriptHttp404(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(&ip_buf, ip);
    var req_buf: [160]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET /asd404ohmz HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ip_str}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    if (total < 15) return;

    const data = buf[0..total];
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return;

    const body_start = if (std.mem.indexOf(u8, data, "\r\n\r\n")) |p| p + 4 else total;
    const body = if (body_start < total) data[body_start..] else "";

    if (std.mem.indexOf(u8, body, "Cannot GET") != null) {
        hs.add("http-404", "Express.js");
    } else if (std.mem.indexOf(u8, body, "{\"detail\":\"Not Found\"}") != null) {
        hs.add("http-404", "FastAPI");
    } else if (std.mem.indexOf(u8, body, "Whitelabel Error Page") != null) {
        hs.add("http-404", "Spring Boot");
    } else if (findCaseInsensitive(body, "<address>apache") != null) {
        hs.add("http-404", "Apache");
    } else if (findCaseInsensitive(body, "nginx") != null and std.mem.indexOf(u8, body, "404") != null) {
        hs.add("http-404", "nginx");
    }
}

// ---------------------------------------------------------------------------
// Script: http-proxy (extended) - reverse proxy detection
// ---------------------------------------------------------------------------

fn scriptHttpProxy(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    var req_buf: [128]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: invalid.ohmz.test\r\nConnection: close\r\n\r\n", .{}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [2048]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 15) return;

    const data = buf[0..n];
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return;

    // A reverse proxy often returns 404/502 with its own headers for invalid Host
    if (findCaseInsensitive(data, "traefik") != null) {
        hs.add("http-proxy", "Traefik reverse proxy");
    } else if (findCaseInsensitive(data, "haproxy") != null) {
        hs.add("http-proxy", "HAProxy");
    } else if (findCaseInsensitive(data, "envoy") != null) {
        hs.add("http-proxy", "Envoy proxy");
    } else if (findCaseInsensitive(data, "caddy") != null) {
        hs.add("http-proxy", "Caddy");
    }
}

// ---------------------------------------------------------------------------
// Script: rdp-ntlm-info - RDP negotiation protocol info
// ---------------------------------------------------------------------------

fn scriptRdpNtlm(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    // X.224 Connection Request with RDP Negotiation Request (NLA)
    const cr = [_]u8{
        0x03, 0x00, 0x00, 0x13, // TPKT header, length 19
        0x0E, // X.224 length indicator
        0xE0, // Connection Request
        0x00, 0x00, // dst-ref
        0x00, 0x00, // src-ref
        0x00, // class 0
        // RDP Negotiation Request
        0x01, // type: RDP_NEG_REQ
        0x00, // flags
        0x08, 0x00, // length (LE)
        0x03, 0x00, 0x00, 0x00, // protocols: PROTOCOL_SSL | PROTOCOL_HYBRID
    };
    _ = std.posix.write(fd, &cr) catch return;

    var buf: [256]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 11) return;
    // Check for Connection Confirm (0xD0)
    if (buf[5] != 0xD0) return;

    var out_buf: [128]u8 = undefined;
    var out_len: usize = 0;

    // Parse RDP Negotiation Response (last 8 bytes of X.224 payload)
    const x224_len: usize = buf[4];
    if (x224_len >= 14) {
        const neg_offset: usize = 5 + x224_len - 8;
        if (neg_offset + 8 <= n and neg_offset >= 5) {
            const neg_type = buf[neg_offset];
            if (neg_type == 0x02) { // RDP_NEG_RSP
                const proto = buf[neg_offset + 4];
                const proto_name: []const u8 = if (proto & 0x02 != 0)
                    "NLA (CredSSP)"
                else if (proto & 0x01 != 0)
                    "TLS"
                else
                    "Standard RDP Security";
                const written = std.fmt.bufPrint(&out_buf, "Protocol: {s}", .{proto_name}) catch return;
                out_len = written.len;
            } else if (neg_type == 0x03) { // NEG_FAILURE
                const written = std.fmt.bufPrint(&out_buf, "Negotiation failed", .{}) catch return;
                out_len = written.len;
            }
        }
    }

    if (out_len == 0) {
        const written = std.fmt.bufPrint(&out_buf, "Microsoft Terminal Services", .{}) catch return;
        out_len = written.len;
    }

    hs.add("rdp-ntlm-info", out_buf[0..out_len]);
}

// ---------------------------------------------------------------------------
// Script: ssl-cert - TLS certificate info
// ---------------------------------------------------------------------------

fn scriptSslCert(ip: u32, port: u16, hs: *HostScripts) void {
    const tls_info = tls_mod.probe(ip, port);
    if (!tls_info.valid) return;

    var out_buf: [256]u8 = undefined;
    var out_len: usize = 0;

    const cn = tls_info.subjectCn();
    if (cn.len > 0) {
        const written = std.fmt.bufPrint(out_buf[out_len..], "CN={s}", .{cn}) catch return;
        out_len += written.len;
    }

    const san = tls_info.sans();
    if (san.len > 0) {
        const san_trunc = san[0..@min(san.len, 80)];
        const written = std.fmt.bufPrint(out_buf[out_len..], " SAN={s}", .{san_trunc}) catch return;
        out_len += written.len;
    }

    const issuer = tls_info.issuerCn();
    if (issuer.len > 0) {
        const written = std.fmt.bufPrint(out_buf[out_len..], " Issuer={s}", .{issuer}) catch return;
        out_len += written.len;
    }

    const expiry = tls_info.notAfter();
    if (expiry.len > 0) {
        const written = std.fmt.bufPrint(out_buf[out_len..], " Exp={s}", .{expiry}) catch return;
        out_len += written.len;
    }

    if (out_len > 0) {
        hs.add("ssl-cert", out_buf[0..out_len]);
    }
}

// ---------------------------------------------------------------------------
// Script: smb2-security-mode - SMB2 negotiate security info
// ---------------------------------------------------------------------------

fn scriptSmb2Info(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
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

    _ = std.posix.write(fd, pkt[0..pos]) catch return;

    var buf: [512]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 72) return;
    if (!std.mem.eql(u8, buf[4..8], "\xfeSMB")) return;

    var out_buf: [128]u8 = undefined;
    var out_len: usize = 0;

    // SMB2 NEGOTIATE response: NetBIOS(4) + header(64) + body
    // SecurityMode at body offset 2 (after StructureSize)
    if (n >= 74) {
        const sec_mode = buf[70]; // 4 + 64 + 2 (skip StructureSize)
        const signing: []const u8 = if (sec_mode & 0x02 != 0)
            "signing enabled and required"
        else if (sec_mode & 0x01 != 0)
            "signing enabled"
        else
            "signing not required";

        // DialectRevision at body offset 4
        const dialect = std.mem.readInt(u16, buf[72..74], .little);
        const dialect_str: []const u8 = switch (dialect) {
            0x0202 => "2.0.2",
            0x0210 => "2.1",
            0x0300 => "3.0",
            0x0302 => "3.0.2",
            0x0311 => "3.1.1",
            else => "unknown",
        };

        const written = std.fmt.bufPrint(&out_buf, "SMBv{s}: {s}", .{ dialect_str, signing }) catch return;
        out_len = written.len;
    }

    if (out_len > 0) {
        hs.add("smb2-security-mode", out_buf[0..out_len]);
    }
}

// ---------------------------------------------------------------------------
// Script: ldap-rootdse - LDAP rootDSE search
// ---------------------------------------------------------------------------

fn scriptLdapRootdse(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    // LDAP SearchRequest for rootDSE (base scope, filter: objectClass present)
    const ldap_search = [_]u8{
        0x30, 0x25, // SEQUENCE len=37
        0x02, 0x01, 0x01, // MessageID = 1
        0x63, 0x20, // APPLICATION[3] SearchRequest len=32
        0x04, 0x00, // baseObject = ""
        0x0A, 0x01, 0x00, // scope = base
        0x0A, 0x01, 0x00, // derefAliases = never
        0x02, 0x01, 0x00, // sizeLimit = 0
        0x02, 0x01, 0x00, // timeLimit = 0
        0x01, 0x01, 0x00, // typesOnly = false
        0x87, 0x0B, // present filter (context tag 7)
        'o',  'b',
        'j',  'e',
        'c',  't',
        'C',  'l',
        'a',  's',
        's',
        0x30, 0x00, // attributes = all
    };
    _ = std.posix.write(fd, &ldap_search) catch return;

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 10) return;

    const data = buf[0..n];

    var out_buf: [256]u8 = undefined;
    var out_len: usize = 0;

    // Look for well-known LDAP attributes in the response
    if (findLdapString(data, "defaultNamingContext")) |val| {
        const written = std.fmt.bufPrint(&out_buf, "Domain: {s}", .{val}) catch return;
        out_len = written.len;
    } else if (findLdapString(data, "dnsHostName")) |val| {
        const written = std.fmt.bufPrint(&out_buf, "Host: {s}", .{val}) catch return;
        out_len = written.len;
    } else if (findLdapString(data, "domainFunctionality")) |val| {
        const written = std.fmt.bufPrint(&out_buf, "DomainFunc: {s}", .{val}) catch return;
        out_len = written.len;
    } else {
        // Fallback: check if response contains a SearchResultEntry (tag 0x64)
        for (data) |b| {
            if (b == 0x64) {
                hs.add("ldap-rootdse", "LDAP directory service");
                return;
            }
        }
        return;
    }

    if (out_len > 0) {
        hs.add("ldap-rootdse", out_buf[0..out_len]);
    }
}

/// Find a string value in an LDAP response by attribute name.
/// Searches for the attribute name (case-insensitive), then looks for the next
/// OCTET STRING (tag 0x04) containing a printable value.
fn findLdapString(data: []const u8, attr_name: []const u8) ?[]const u8 {
    const pos = findCaseInsensitive(data, attr_name) orelse return null;
    var search_start = pos + attr_name.len;

    // Skip past BER overhead to find the value OCTET STRING
    while (search_start + 2 < data.len) : (search_start += 1) {
        if (data[search_start] == 0x04) {
            const vlen: usize = data[search_start + 1];
            if (vlen > 0 and vlen < 128 and search_start + 2 + vlen <= data.len) {
                const val = data[search_start + 2 .. search_start + 2 + vlen];
                // Verify it looks like a printable string
                var printable = true;
                for (val) |c| {
                    if (c < 0x20 or c > 0x7E) {
                        printable = false;
                        break;
                    }
                }
                if (printable and val.len > 0) return val;
            }
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Script: xmpp-info - XMPP stream features
// ---------------------------------------------------------------------------

fn scriptXmppInfo(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    const ns: []const u8 = if (port == 5269) "jabber:server" else "jabber:client";
    var req_buf: [256]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "<?xml version='1.0'?><stream:stream xmlns='{s}' xmlns:stream='http://etherx.jabber.org/streams' to='unknown' version='1.0'>", .{ns}) catch return;
    _ = std.posix.write(fd, request) catch return;

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const rd = std.posix.read(fd, buf[total..]) catch break;
        if (rd == 0) break;
        total += rd;
        if (total > 50 and findCaseInsensitive(buf[0..total], "</stream:features>") != null) break;
        if (total > 50 and findCaseInsensitive(buf[0..total], "</stream:error>") != null) break;
    }
    if (total == 0) return;

    const data = buf[0..total];
    var out_buf: [256]u8 = undefined;
    var out_len: usize = 0;

    // Check for STARTTLS support
    if (findCaseInsensitive(data, "<starttls") != null) {
        const written = std.fmt.bufPrint(out_buf[out_len..], "STARTTLS ", .{}) catch return;
        out_len += written.len;
    }

    // Check for auth mechanisms
    if (findCaseInsensitive(data, "PLAIN") != null) {
        const written = std.fmt.bufPrint(out_buf[out_len..], "AUTH:PLAIN ", .{}) catch return;
        out_len += written.len;
    }
    if (findCaseInsensitive(data, "SCRAM-SHA-1") != null) {
        const written = std.fmt.bufPrint(out_buf[out_len..], "AUTH:SCRAM ", .{}) catch return;
        out_len += written.len;
    }

    // Extract server identity from from= attribute
    var from_pos = findCaseInsensitive(data, "from='");
    var delim: u8 = '\'';
    if (from_pos == null) {
        from_pos = findCaseInsensitive(data, "from=\"");
        delim = '"';
    }
    if (from_pos) |fpos| {
        const start = fpos + 6;
        if (start < data.len) {
            const end = std.mem.indexOfScalarPos(u8, data, start, delim) orelse @min(start + 64, data.len);
            if (end > start) {
                const from_val = data[start..end];
                const written = std.fmt.bufPrint(out_buf[out_len..], "server={s}", .{from_val}) catch return;
                out_len += written.len;
            }
        }
    }

    if (out_len > 0) {
        hs.add("xmpp-info", out_buf[0..out_len]);
    } else if (findCaseInsensitive(data, "<stream:stream") != null) {
        hs.add("xmpp-info", "XMPP stream");
    }

    _ = std.posix.write(fd, "</stream:stream>") catch {};
}

// ---------------------------------------------------------------------------
// Script: socks-auth-info - SOCKS5 authentication methods
// ---------------------------------------------------------------------------

fn scriptSocksAuth(ip: u32, port: u16, hs: *HostScripts) void {
    const fd = openSocket(ip, port) orelse return;
    defer std.posix.close(fd);

    // SOCKS5 greeting: version 5, 2 methods (no auth + username/password)
    const hello = [_]u8{
        0x05, // SOCKS5
        0x02, // 2 methods
        0x00, // no auth
        0x02, // username/password
    };
    _ = std.posix.write(fd, &hello) catch return;

    var buf: [4]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return;
    if (n < 2) return;

    if (buf[0] == 0x05) {
        const auth_str: []const u8 = switch (buf[1]) {
            0x00 => "No authentication",
            0x02 => "Username/password required",
            0xFF => "No acceptable methods",
            else => "Unknown method",
        };
        hs.add("socks-auth-info", auth_str);
    } else if (buf[0] == 0x04) {
        hs.add("socks-auth-info", "SOCKS4 (no SOCKS5 support)");
    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HostScripts - add and retrieve" {
    var hs = HostScripts{};
    try std.testing.expectEqual(@as(u8, 0), hs.count);

    hs.add("test-script", "test output");
    try std.testing.expectEqual(@as(u8, 1), hs.count);
    try std.testing.expectEqualStrings("test-script", hs.results[0].id());
    try std.testing.expectEqualStrings("test output", hs.results[0].output());
}

test "HostScripts - max 12 results" {
    var hs = HostScripts{};
    for (0..15) |_| {
        hs.add("s", "o");
    }
    try std.testing.expectEqual(@as(u8, 12), hs.count);
}

test "findCaseInsensitive - basic match" {
    const data = "Hello World";
    try std.testing.expectEqual(@as(?usize, 0), findCaseInsensitive(data, "hello"));
    try std.testing.expectEqual(@as(?usize, 6), findCaseInsensitive(data, "WORLD"));
    try std.testing.expectEqual(@as(?usize, null), findCaseInsensitive(data, "xyz"));
}

test "findCaseInsensitive - empty needle" {
    const data = "test";
    try std.testing.expectEqual(@as(?usize, 0), findCaseInsensitive(data, ""));
}

test "findTitle - extracts title" {
    const data = "HTTP/1.1 200 OK\r\n\r\n<html><title>My Page</title></html>";
    const title = findTitle(data);
    try std.testing.expect(title != null);
    try std.testing.expectEqualStrings("My Page", title.?);
}

test "findTitle - no title" {
    const data = "HTTP/1.1 200 OK\r\n\r\n<html><body>Hello</body></html>";
    try std.testing.expectEqual(@as(?[]const u8, null), findTitle(data));
}

test "findLdapString - finds attribute value" {
    // Simulated LDAP response fragment with attribute name followed by OCTET STRING value
    // Layout: some BER overhead, then "defaultNamingContext" as text, then 0x04 tag with value
    const data = [_]u8{
        0x30, 0x20, 0x04, 0x15,
        'd',  'e',  'f',  'a',
        'u',  'l',  't',  'N',
        'a',  'm',  'i',  'n',
        'g',  'C',  'o',  'n',
        't',  'e',  'x',  't',
        0x00, 0x31, 0x0F, 0x04,
        0x0D, 'D',  'C',  '=',
        't',  'e',  's',  't',
        ',',  'D',  'C',  '=',
        'c',  'o',
    };

    const result = findLdapString(&data, "defaultNamingContext");
    try std.testing.expect(result != null);
    try std.testing.expect(result.?.len > 0);
}

test "findLdapString - not found" {
    const data = [_]u8{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00 };
    const result = findLdapString(&data, "nonExistentAttr");
    try std.testing.expectEqual(@as(?[]const u8, null), result);
}

test "findLdapString - non-printable value skipped" {
    // Attribute name found, but next OCTET STRING contains non-printable bytes
    const data = [_]u8{
        'd',  'n',  's',  'H',  'o',  's', 't', 'N', 'a', 'm', 'e',
        0x04, 0x03, 0x01, 0x02, 0x03,
    };
    const result = findLdapString(&data, "dnsHostName");
    try std.testing.expectEqual(@as(?[]const u8, null), result);
}

test "formatIp - basic" {
    var buf: [16]u8 = undefined;
    const result = formatIp(&buf, 0xC0A80001); // 192.168.0.1
    try std.testing.expectEqualStrings("192.168.0.1", result);
}

test "toLower - letters and non-letters" {
    try std.testing.expectEqual(@as(u8, 'a'), toLower('A'));
    try std.testing.expectEqual(@as(u8, 'z'), toLower('Z'));
    try std.testing.expectEqual(@as(u8, 'a'), toLower('a'));
    try std.testing.expectEqual(@as(u8, '1'), toLower('1'));
}
