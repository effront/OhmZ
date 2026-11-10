const std = @import("std");

const probes_raw = @embedFile("data/service-probes");

const MatchKind = enum { prefix, contains };

const Sig = struct {
    name: []const u8,
    kind: MatchKind,
    pattern: []const u8,
    ver_skip: i8,
};

pub const Match = struct {
    name: []const u8,
    version: []const u8,
};

const Category = enum { null_probe, http_body, none };

const null_sigs = parseSigs(.null_probe);
const http_sigs = parseSigs(.http_body);

pub fn matchBanner(data: []const u8) ?Match {
    return matchAgainst(data, &null_sigs);
}

pub fn matchHttp(data: []const u8) ?Match {
    return matchAgainst(data, &http_sigs);
}

fn matchAgainst(data: []const u8, sigs: []const Sig) ?Match {
    for (sigs) |sig| {
        const maybe_pos: ?usize = switch (sig.kind) {
            .prefix => if (std.mem.startsWith(u8, data, sig.pattern)) @as(?usize, 0) else null,
            .contains => std.mem.indexOf(u8, data, sig.pattern),
        };
        const pos = maybe_pos orelse continue;
        var version: []const u8 = "";
        if (sig.ver_skip >= 0) {
            const start = pos + @as(usize, @intCast(sig.ver_skip));
            if (start < data.len) {
                const rest = data[start..];
                const end = std.mem.indexOfAny(u8, rest, "\r\n\x00") orelse rest.len;
                version = rest[0..end];
            }
        }
        return Match{ .name = sig.name, .version = version };
    }
    return null;
}

// ---------------------------------------------------------------------------
// Comptime parsing
// ---------------------------------------------------------------------------

fn countSigs(comptime cat: Category) comptime_int {
    @setEvalBranchQuota(4000);
    var section: Category = .none;
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, probes_raw, '\n');
    while (iter.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.eql(u8, line, "[null]")) {
            section = .null_probe;
            continue;
        }
        if (std.mem.eql(u8, line, "[http]")) {
            section = .http_body;
            continue;
        }
        if (section == cat) count += 1;
    }
    return count;
}

fn parseSigs(comptime cat: Category) [countSigs(cat)]Sig {
    @setEvalBranchQuota(50000);
    const N = countSigs(cat);
    var result: [N]Sig = undefined;
    var idx: usize = 0;
    var section: Category = .none;
    var iter = std.mem.splitScalar(u8, probes_raw, '\n');
    while (iter.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.eql(u8, line, "[null]")) {
            section = .null_probe;
            continue;
        }
        if (std.mem.eql(u8, line, "[http]")) {
            section = .http_body;
            continue;
        }
        if (section != cat) continue;
        result[idx] = parseLine(line);
        idx += 1;
    }
    return result;
}

fn parseLine(comptime line: []const u8) Sig {
    const sep1 = std.mem.indexOfScalar(u8, line, '|') orelse @compileError("bad sig: missing first |");
    const name = line[0..sep1];

    const after_name = line[sep1 + 1 ..];
    const sep2 = std.mem.indexOfScalar(u8, after_name, '|') orelse @compileError("bad sig: missing second |");
    const kind_str = after_name[0..sep2];

    const sep_last = std.mem.lastIndexOfScalar(u8, line, '|') orelse @compileError("bad sig: missing last |");
    const pattern = line[sep1 + 1 + sep2 + 1 .. sep_last];
    const ver_str = line[sep_last + 1 ..];

    return .{
        .name = name,
        .kind = if (std.mem.eql(u8, kind_str, "p")) .prefix else if (std.mem.eql(u8, kind_str, "c")) .contains else @compileError("bad match type"),
        .pattern = pattern,
        .ver_skip = parseI8(ver_str),
    };
}

fn parseI8(comptime s: []const u8) i8 {
    if (s.len == 0) return -1;
    var start: usize = 0;
    var negative = false;
    if (s[0] == '-') {
        negative = true;
        start = 1;
    }
    var val: i8 = 0;
    for (s[start..]) |c| {
        if (c < '0' or c > '9') @compileError("bad digit in version_skip");
        val = val * 10 + @as(i8, @intCast(c - '0'));
    }
    return if (negative) -val else val;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "null probe signature count" {
    try std.testing.expect(null_sigs.len == 5);
}

test "http signature count" {
    try std.testing.expect(http_sigs.len >= 30);
}

test "matchBanner - POP3" {
    const m = matchBanner("+OK Dovecot ready.\r\n") orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("POP3", m.name);
    try std.testing.expectEqualStrings("Dovecot ready.", m.version);
}

test "matchBanner - POP3 short" {
    const m = matchBanner("+OK \r\n") orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("POP3", m.name);
    try std.testing.expectEqualStrings("", m.version);
}

test "matchBanner - IMAP" {
    const m = matchBanner("* OK [CAPABILITY IMAP4rev1] ready.\r\n") orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("IMAP", m.name);
    try std.testing.expectEqualStrings("", m.version);
}

test "matchBanner - VNC" {
    const m = matchBanner("RFB 003.008\n") orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("VNC", m.name);
    try std.testing.expectEqualStrings("003.008", m.version);
}

test "matchBanner - NATS" {
    const m = matchBanner("INFO {\"server_id\":\"abc\"}\r\n") orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("NATS", m.name);
    try std.testing.expectEqualStrings("", m.version);
}

test "matchBanner - Rsync" {
    const m = matchBanner("@RSYNCD: 31.0\n") orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("Rsync", m.name);
    try std.testing.expectEqualStrings("31.0", m.version);
}

test "matchBanner - no match" {
    try std.testing.expect(matchBanner("UNKNOWN PROTOCOL\r\n") == null);
}

test "matchBanner - empty" {
    try std.testing.expect(matchBanner("") == null);
}

test "matchHttp - Grafana title" {
    const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Grafana</title></head></html>";
    const m = matchHttp(resp) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("Grafana", m.name);
}

test "matchHttp - Jenkins header" {
    const resp = "HTTP/1.1 200 OK\r\nX-Jenkins: 2.401.1\r\n\r\n<html></html>";
    const m = matchHttp(resp) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("Jenkins", m.name);
}

test "matchHttp - Kibana header" {
    const resp = "HTTP/1.1 200 OK\r\nkbn-name: kibana\r\n\r\n<html></html>";
    const m = matchHttp(resp) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("Kibana", m.name);
}

test "matchHttp - no match" {
    const resp = "HTTP/1.1 200 OK\r\n\r\n<html><head><title>My App</title></head></html>";
    try std.testing.expect(matchHttp(resp) == null);
}
