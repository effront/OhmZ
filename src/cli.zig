const std = @import("std");

pub const ScanType = enum {
    syn,
    connect,
    fin,
    xmas,
    null_scan,
    ack,
    window,
    udp,
};

pub const TimingTemplate = enum(u3) {
    paranoid = 0,
    sneaky = 1,
    polite = 2,
    normal = 3,
    aggressive = 4,
    insane = 5,

    pub fn defaultRate(self: TimingTemplate) u64 {
        return switch (self) {
            .paranoid => 1,
            .sneaky => 10,
            .polite => 100,
            .normal => 1_000,
            .aggressive => 10_000,
            .insane => 100_000,
        };
    }
};

pub const OutputFormat = enum {
    json,
    xml,
    grepable,
    ndjson,
    binary,
};

pub const OutputSpec = struct {
    format: OutputFormat,
    path: []const u8,
};

pub const PortRange = struct {
    start: u16,
    end: u16,
};

pub const ScanConfig = struct {
    scan_type: ScanType = .syn,
    targets: std.ArrayList([]const u8),
    target_file: ?[]const u8 = null,
    excludes: std.ArrayList([]const u8),
    exclude_file: ?[]const u8 = null,
    ports: std.ArrayList(PortRange),
    top_ports: ?u16 = null,
    rate: ?u64 = null,
    timing: TimingTemplate = .normal,
    max_retries: u8 = 2,
    outputs: std.ArrayList(OutputSpec),
    output_all_prefix: ?[]const u8 = null,
    banner_grab: bool = false,
    script_scan: bool = false,
    os_detect: bool = false,
    skip_discovery: bool = false,
    shard_id: ?u16 = null,
    shard_total: ?u16 = null,
    resume_file: ?[]const u8 = null,
    show_stats: bool = false,
    verbosity: u8 = 0,
    ipv6: bool = false,

    pub fn effectiveRate(self: *const ScanConfig) u64 {
        return self.rate orelse self.timing.defaultRate();
    }

    pub fn totalPorts(self: *const ScanConfig) u32 {
        if (self.ports.items.len == 0) {
            if (self.top_ports) |n| return @as(u32, n);
            return 1000;
        }
        var total: u32 = 0;
        for (self.ports.items) |r| {
            total += @as(u32, r.end - r.start) + 1;
        }
        return total;
    }

    pub fn deinit(self: *ScanConfig) void {
        self.targets.deinit();
        self.excludes.deinit();
        self.ports.deinit();
        self.outputs.deinit();
    }
};

pub const ParseError = error{
    MissingTarget,
    InvalidPort,
    InvalidShard,
    InvalidTimingTemplate,
    UnknownFlag,
    MissingArgValue,
};

pub fn parse(allocator: std.mem.Allocator) (ParseError || std.mem.Allocator.Error)!ScanConfig {
    var config = ScanConfig{
        .targets = std.ArrayList([]const u8).init(allocator),
        .excludes = std.ArrayList([]const u8).init(allocator),
        .ports = std.ArrayList(PortRange).init(allocator),
        .outputs = std.ArrayList(OutputSpec).init(allocator),
    };
    errdefer config.deinit();

    var args = std.process.args();
    _ = args.skip();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-sS")) {
            config.scan_type = .syn;
        } else if (std.mem.eql(u8, arg, "-sT")) {
            config.scan_type = .connect;
        } else if (std.mem.eql(u8, arg, "-sU")) {
            config.scan_type = .udp;
        } else if (std.mem.eql(u8, arg, "-sF")) {
            config.scan_type = .fin;
        } else if (std.mem.eql(u8, arg, "-sX")) {
            config.scan_type = .xmas;
        } else if (std.mem.eql(u8, arg, "-sN")) {
            config.scan_type = .null_scan;
        } else if (std.mem.eql(u8, arg, "-sA")) {
            config.scan_type = .ack;
        } else if (std.mem.eql(u8, arg, "-sW")) {
            config.scan_type = .window;
        } else if (std.mem.eql(u8, arg, "-sV")) {
            config.banner_grab = true;
        } else if (std.mem.eql(u8, arg, "-sC")) {
            config.script_scan = true;
        } else if (std.mem.eql(u8, arg, "-O")) {
            config.os_detect = true;
        } else if (std.mem.eql(u8, arg, "-A")) {
            config.banner_grab = true;
            config.script_scan = true;
            config.os_detect = true;
        } else if (std.mem.eql(u8, arg, "-Pn")) {
            config.skip_discovery = true;
        } else if (std.mem.eql(u8, arg, "-6")) {
            config.ipv6 = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            config.show_stats = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            config.verbosity = @min(config.verbosity + 1, 3);
        } else if (std.mem.eql(u8, arg, "-vv")) {
            config.verbosity = 2;
        } else if (std.mem.eql(u8, arg, "-vvv")) {
            config.verbosity = 3;
        } else if (std.mem.eql(u8, arg, "-p")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try parsePorts(&config.ports, val);
        } else if (std.mem.startsWith(u8, arg, "-p")) {
            try parsePorts(&config.ports, arg[2..]);
        } else if (std.mem.eql(u8, arg, "--top-ports")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            config.top_ports = std.fmt.parseInt(u16, val, 10) catch return ParseError.InvalidPort;
        } else if (std.mem.eql(u8, arg, "--rate")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            config.rate = std.fmt.parseInt(u64, val, 10) catch return ParseError.InvalidPort;
        } else if (std.mem.eql(u8, arg, "--max-retries")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            config.max_retries = std.fmt.parseInt(u8, val, 10) catch return ParseError.InvalidPort;
        } else if (arg.len == 3 and arg[0] == '-' and arg[1] == 'T') {
            const level = std.fmt.parseInt(u3, arg[2..3], 10) catch return ParseError.InvalidTimingTemplate;
            config.timing = @enumFromInt(level);
        } else if (std.mem.eql(u8, arg, "-iL")) {
            config.target_file = args.next() orelse return ParseError.MissingArgValue;
        } else if (std.mem.eql(u8, arg, "--exclude")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try config.excludes.append(val);
        } else if (std.mem.eql(u8, arg, "--excludefile")) {
            config.exclude_file = args.next() orelse return ParseError.MissingArgValue;
        } else if (std.mem.eql(u8, arg, "--resume")) {
            config.resume_file = args.next() orelse return ParseError.MissingArgValue;
        } else if (std.mem.eql(u8, arg, "--shard")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            const slash = std.mem.indexOfScalar(u8, val, '/') orelse return ParseError.InvalidShard;
            config.shard_id = std.fmt.parseInt(u16, val[0..slash], 10) catch return ParseError.InvalidShard;
            config.shard_total = std.fmt.parseInt(u16, val[slash + 1 ..], 10) catch return ParseError.InvalidShard;
            if (config.shard_id.? < 1 or config.shard_id.? > config.shard_total.?) return ParseError.InvalidShard;
        } else if (std.mem.eql(u8, arg, "-oJ")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try config.outputs.append(.{ .format = .json, .path = val });
        } else if (std.mem.eql(u8, arg, "-oX")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try config.outputs.append(.{ .format = .xml, .path = val });
        } else if (std.mem.eql(u8, arg, "-oG")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try config.outputs.append(.{ .format = .grepable, .path = val });
        } else if (std.mem.eql(u8, arg, "-oN")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try config.outputs.append(.{ .format = .ndjson, .path = val });
        } else if (std.mem.eql(u8, arg, "-oB")) {
            const val = args.next() orelse return ParseError.MissingArgValue;
            try config.outputs.append(.{ .format = .binary, .path = val });
        } else if (std.mem.eql(u8, arg, "-oA")) {
            config.output_all_prefix = args.next() orelse return ParseError.MissingArgValue;
        } else if (arg[0] == '-') {
            return ParseError.UnknownFlag;
        } else {
            try config.targets.append(arg);
        }
    }

    if (config.targets.items.len == 0 and config.target_file == null and config.resume_file == null) {
        return ParseError.MissingTarget;
    }

    if (config.ports.items.len == 0 and config.top_ports == null) {
        config.top_ports = 1000;
    }

    return config;
}

fn parsePorts(ports: *std.ArrayList(PortRange), spec: []const u8) ParseError!void {
    var it = std.mem.splitScalar(u8, spec, ',');
    while (it.next()) |token| {
        if (std.mem.indexOfScalar(u8, token, '-')) |dash| {
            const start = std.fmt.parseInt(u16, token[0..dash], 10) catch return ParseError.InvalidPort;
            const end = std.fmt.parseInt(u16, token[dash + 1 ..], 10) catch return ParseError.InvalidPort;
            if (start == 0 or end == 0 or start > end) return ParseError.InvalidPort;
            ports.append(.{ .start = start, .end = end }) catch return ParseError.InvalidPort;
        } else {
            const port = std.fmt.parseInt(u16, token, 10) catch return ParseError.InvalidPort;
            if (port == 0) return ParseError.InvalidPort;
            ports.append(.{ .start = port, .end = port }) catch return ParseError.InvalidPort;
        }
    }
}

pub fn printUsage(writer: anytype) void {
    writer.writeAll(
        \\Usage: ohmz [scan_type] [options] <target(s)>
        \\
        \\SCAN TYPES:
        \\  -sS             TCP SYN (default)
        \\  -sT             TCP Connect
        \\  -sU             UDP
        \\  -sF/-sX/-sN     FIN / XMAS / NULL
        \\  -sA/-sW         ACK / Window
        \\
        \\PORTS:
        \\  -p <range>      Ports (e.g. -p 22,80,443 or -p 1-65535)
        \\  --top-ports <n> Most common N ports
        \\
        \\OUTPUT:
        \\  -oJ/-oX/-oG     JSON / XML / Grepable
        \\  -oN/-oB         NDJSON / Binary
        \\  -oA <prefix>    All formats
        \\
        \\PERFORMANCE:
        \\  --rate <pps>    Packets per second
        \\  -T0 to -T5     Timing template
        \\
        \\OPTIONS:
        \\  -sV             Banner grabbing
        \\  -Pn             Skip host discovery
        \\  -iL <file>      Target list file
        \\  --exclude <t>   Exclude target
        \\  --shard <N/M>   Distributed sharding
        \\  --resume <file> Resume scan
        \\  --stats         Show real-time stats
        \\  -v/-vv/-vvv     Verbosity
        \\  -6              IPv6 mode
        \\
    ) catch {};
}
