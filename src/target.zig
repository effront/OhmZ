const std = @import("std");
const cli = @import("cli.zig");

pub const Ipv4Addr = [4]u8;

pub const Target = struct {
    ip: u32,
    port: u16,
};

pub const TargetSpace = struct {
    ip_ranges: std.ArrayList(IpRange),
    port_ranges: std.ArrayList(cli.PortRange),
    total_ips: u64,
    total_ports: u64,
    total_targets: u64,

    pub fn deinit(self: *TargetSpace) void {
        self.ip_ranges.deinit();
        self.port_ranges.deinit();
    }

    pub fn targetAt(self: *const TargetSpace, index: u64) Target {
        const ip_idx = index / self.total_ports;
        const port_idx = index % self.total_ports;
        return .{
            .ip = self.ipAtIndex(ip_idx),
            .port = self.portAtIndex(port_idx),
        };
    }

    fn ipAtIndex(self: *const TargetSpace, idx: u64) u32 {
        var remaining = idx;
        for (self.ip_ranges.items) |range| {
            const count = range.count();
            if (remaining < count) {
                return range.start +| @as(u32, @intCast(remaining));
            }
            remaining -= count;
        }
        return self.ip_ranges.items[self.ip_ranges.items.len - 1].end;
    }

    fn portAtIndex(self: *const TargetSpace, idx: u64) u16 {
        var remaining = idx;
        for (self.port_ranges.items) |range| {
            const count: u64 = @as(u64, range.end - range.start) + 1;
            if (remaining < count) {
                return range.start +| @as(u16, @intCast(remaining));
            }
            remaining -= count;
        }
        return self.port_ranges.items[self.port_ranges.items.len - 1].end;
    }
};

pub const IpRange = struct {
    start: u32,
    end: u32,

    pub fn count(self: IpRange) u64 {
        return @as(u64, self.end - self.start) + 1;
    }
};

pub fn buildTargetSpace(allocator: std.mem.Allocator, config: *const cli.ScanConfig) !TargetSpace {
    var ip_ranges = std.ArrayList(IpRange).init(allocator);
    errdefer ip_ranges.deinit();

    for (config.targets.items) |t| {
        const range = try parseCidrOrIp(t);
        try ip_ranges.append(range);
    }

    if (config.target_file) |path| {
        try loadTargetFile(allocator, path, &ip_ranges);
    }

    var total_ips: u64 = 0;
    for (ip_ranges.items) |r| {
        total_ips += r.count();
    }

    var port_ranges = std.ArrayList(cli.PortRange).init(allocator);
    errdefer port_ranges.deinit();

    if (config.ports.items.len > 0) {
        try port_ranges.appendSlice(config.ports.items);
    } else {
        try port_ranges.append(.{ .start = 1, .end = 1000 });
    }

    var total_ports: u64 = 0;
    for (port_ranges.items) |r| {
        total_ports += @as(u64, r.end - r.start) + 1;
    }

    return .{
        .ip_ranges = ip_ranges,
        .port_ranges = port_ranges,
        .total_ips = total_ips,
        .total_ports = total_ports,
        .total_targets = total_ips * total_ports,
    };
}

pub fn parseCidrOrIp(input: []const u8) !IpRange {
    if (std.mem.indexOfScalar(u8, input, '/')) |slash| {
        const ip = try parseIpv4(input[0..slash]);
        const prefix_len = std.fmt.parseInt(u5, input[slash + 1 ..], 10) catch return error.InvalidCidr;
        if (prefix_len > 32) return error.InvalidCidr;

        const mask: u32 = if (prefix_len == 0) 0 else ~(@as(u32, 0)) << @intCast(32 - @as(u6, prefix_len));
        const network = ip & mask;
        const broadcast = network | ~mask;

        return .{ .start = network, .end = broadcast };
    }

    const ip = try parseIpv4(input);
    return .{ .start = ip, .end = ip };
}

pub fn parseIpv4(input: []const u8) !u32 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, input, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return error.InvalidIp;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIp;
        i += 1;
    }
    if (i != 4) return error.InvalidIp;

    return @as(u32, octets[0]) << 24 |
        @as(u32, octets[1]) << 16 |
        @as(u32, octets[2]) << 8 |
        @as(u32, octets[3]);
}

pub fn ipToBytes(ip: u32) Ipv4Addr {
    return .{
        @intCast((ip >> 24) & 0xFF),
        @intCast((ip >> 16) & 0xFF),
        @intCast((ip >> 8) & 0xFF),
        @intCast(ip & 0xFF),
    };
}

pub fn formatIp(buf: []u8, ip: u32) []const u8 {
    const b = ipToBytes(ip);
    const len = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch return "?.?.?.?";
    return len;
}

fn loadTargetFile(allocator: std.mem.Allocator, path: []const u8, ranges: *std.ArrayList(IpRange)) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();

    var line_buf: [256]u8 = undefined;
    while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch null) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const range = parseCidrOrIp(trimmed) catch |err| {
            std.log.warn("skipping invalid target: {s} ({any})", .{ trimmed, err });
            continue;
        };
        try ranges.append(range);
    }
    _ = allocator;
}

test "parseIpv4" {
    try std.testing.expectEqual(@as(u32, 0xC0A80001), try parseIpv4("192.168.0.1"));
    try std.testing.expectEqual(@as(u32, 0x0A000000), try parseIpv4("10.0.0.0"));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), try parseIpv4("255.255.255.255"));
}

test "parseCidrOrIp single" {
    const r = try parseCidrOrIp("192.168.1.100");
    try std.testing.expectEqual(r.start, r.end);
}

test "parseCidrOrIp /24" {
    const r = try parseCidrOrIp("192.168.1.0/24");
    try std.testing.expectEqual(@as(u32, 0xC0A80100), r.start);
    try std.testing.expectEqual(@as(u32, 0xC0A801FF), r.end);
    try std.testing.expectEqual(@as(u64, 256), r.count());
}

test "parseCidrOrIp /16" {
    const r = try parseCidrOrIp("10.0.0.0/16");
    try std.testing.expectEqual(@as(u64, 65536), r.count());
}

test "formatIp" {
    var buf: [16]u8 = undefined;
    const s = formatIp(&buf, 0xC0A80101);
    try std.testing.expectEqualStrings("192.168.1.1", s);
}
