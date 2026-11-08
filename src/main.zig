const std = @import("std");
const cli = @import("cli.zig");
const target_mod = @import("target.zig");
const packet = @import("packet.zig");
const cookie_mod = @import("cookie.zig");
const blackrock = @import("blackrock.zig");
const tx_mod = @import("tx.zig");
const rx_mod = @import("rx.zig");
const connect_mod = @import("connect.zig");
const stats_mod = @import("stats.zig");
const progress_mod = @import("progress.zig");
const output_mod = @import("output.zig");
const banner_mod = @import("banner.zig");

const VERSION = "0.2.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) std.log.err("memory leak detected", .{});
    }
    const allocator = gpa.allocator();
    const stderr = std.io.getStdErr().writer();

    const config = cli.parse(allocator) catch |err| {
        switch (err) {
            error.MissingTarget => stderr.writeAll("error: no target specified\n\n") catch {},
            error.InvalidPort => stderr.writeAll("error: invalid port specification\n\n") catch {},
            error.InvalidShard => stderr.writeAll("error: invalid --shard (use N/M, e.g. 1/4)\n\n") catch {},
            error.InvalidTimingTemplate => stderr.writeAll("error: invalid timing template (use -T0 to -T5)\n\n") catch {},
            error.UnknownFlag => stderr.writeAll("error: unknown flag\n\n") catch {},
            error.MissingArgValue => stderr.writeAll("error: flag requires a value\n\n") catch {},
            else => stderr.writeAll("error: failed to parse arguments\n\n") catch {},
        }
        cli.printUsage(stderr);
        std.process.exit(1);
    };
    defer @constCast(&config).deinit();

    var target_space = target_mod.buildTargetSpace(allocator, &config) catch |err| {
        stderr.print("error: invalid target - {any}\n", .{err}) catch {};
        std.process.exit(1);
    };
    defer target_space.deinit();

    if (target_space.total_targets == 0) {
        try stderr.writeAll("error: target space is empty\n");
        std.process.exit(1);
    }

    const first_target = target_space.targetAt(0);
    const src_ip = tx_mod.getLocalIp(first_target.ip);
    if (src_ip == 0) {
        try stderr.writeAll("error: could not detect local IP address\n");
        std.process.exit(1);
    }

    var src_ip_buf: [16]u8 = undefined;
    const src_ip_str = target_mod.formatIp(&src_ip_buf, src_ip);
    const rate = config.effectiveRate();
    const scan_name = scanTypeName(config.scan_type);

    try stderr.print("\n  \x1b[1;36mOhmZ {s}\x1b[0m - Network Scanner\n" ++
        "  Scan: {s} | Source: {s} | Rate: {d} pps\n" ++
        "  Targets: {d} IPs x {d} ports = {d} probes\n", .{
        VERSION,
        scan_name,
        src_ip_str,
        rate,
        target_space.total_ips,
        target_space.total_ports,
        target_space.total_targets,
    });
    if (config.script_scan) try stderr.writeAll("  \x1b[33mNote\x1b[0m: -sC ignored - script scanning requires NSE engine (planned v0.3)\n");
    if (config.os_detect) try stderr.writeAll("  \x1b[33mNote\x1b[0m: -O ignored - OS fingerprinting requires probe engine (planned v0.3)\n");
    try stderr.writeAll("\n");

    const src_port: u16 = 40000 + @as(u16, @truncate(@as(u64, @bitCast(std.time.milliTimestamp())) % 20000));
    const syn_cookie = cookie_mod.SynCookie.init();

    var scan_stats = stats_mod.ScanStats.init(target_space.total_targets);

    var bar = progress_mod.ProgressBar.init(&scan_stats, config.verbosity > 0 or config.show_stats);
    try bar.start();

    var seed_bytes: u64 = 0;
    std.posix.getrandom(std.mem.asBytes(&seed_bytes)) catch {};

    var connect_engine: ?connect_mod.ConnectEngine = null;
    defer if (connect_engine) |*ce| ce.deinit();

    var rx_engine: ?rx_mod.RxEngine = null;
    defer if (rx_engine) |*re| re.deinit();

    if (config.scan_type == .connect) {
        connect_engine = connect_mod.ConnectEngine.init(
            allocator,
            &target_space,
            &scan_stats,
            rate,
            seed_bytes,
            config.shard_id,
            config.shard_total,
            0,
        );

        connect_engine.?.run();
        bar.join();
    } else {
        var tx_engine = tx_mod.TxEngine.init(
            &syn_cookie,
            &target_space,
            &scan_stats,
            src_ip,
            src_port,
            rate,
            seed_bytes,
            config.shard_id,
            config.shard_total,
            0,
            config.scan_type,
        ) catch |err| {
            try stderr.print("error: could not open raw socket - {any}\nHint: run with sudo or set CAP_NET_RAW\n", .{err});
            scan_stats.markDone();
            bar.join();
            std.process.exit(1);
        };
        defer tx_engine.deinit();

        const drain_secs = computeDrain(target_space.total_targets, rate);

        rx_engine = rx_mod.RxEngine.init(
            allocator,
            &syn_cookie,
            &scan_stats,
            src_port,
            config.scan_type,
            drain_secs,
        ) catch |err| {
            try stderr.print("error: could not open capture socket - {any}\n", .{err});
            scan_stats.markDone();
            bar.join();
            std.process.exit(1);
        };

        const tx_handle = try std.Thread.spawn(.{}, txThreadFn, .{&tx_engine});
        const rx_handle = try std.Thread.spawn(.{}, rxThreadFn, .{&rx_engine.?});

        tx_handle.join();
        std.time.sleep(drain_secs * std.time.ns_per_s);
        scan_stats.markDone();

        rx_handle.join();
        bar.join();
    }

    const open_ports = if (connect_engine) |*ce|
        ce.results.open_list.items
    else if (rx_engine) |*re|
        re.results.open_list.items
    else
        @as([]rx_mod.OpenPort, &.{});

    const snap = scan_stats.snapshot();

    std.mem.sort(rx_mod.OpenPort, open_ports, {}, struct {
        fn lessThan(_: void, a: rx_mod.OpenPort, b: rx_mod.OpenPort) bool {
            if (a.ip != b.ip) return a.ip < b.ip;
            return a.port < b.port;
        }
    }.lessThan);

    var banners: ?[]banner_mod.BannerInfo = null;
    defer if (banners) |b| allocator.free(b);

    if (open_ports.len > 0 and config.banner_grab) {
        try stderr.print("\nService detection on {d} open ports...\n", .{open_ports.len});
        const b = try allocator.alloc(banner_mod.BannerInfo, open_ports.len);
        for (open_ports, 0..) |p, i| {
            b[i] = banner_mod.grab(p.ip, p.port);
        }
        banners = b;
    }

    // Console output
    if (open_ports.len > 0) {
        const multi_host = blk: {
            if (open_ports.len <= 1) break :blk false;
            const first_ip = open_ports[0].ip;
            for (open_ports[1..]) |r| {
                if (r.ip != first_ip) break :blk true;
            }
            break :blk false;
        };

        const has_versions = banners != null;
        try stderr.writeAll("\n");

        if (!multi_host) {
            var host_buf: [16]u8 = undefined;
            const host_str = target_mod.formatIp(&host_buf, open_ports[0].ip);
            try stderr.print("OhmZ scan report for {s}\n", .{host_str});

            const not_shown = snap.sent -| snap.open;
            if (not_shown > 0) {
                try stderr.print("Not shown: {d} closed/filtered ports\n", .{not_shown});
            }

            if (has_versions) {
                try stderr.writeAll("PORT      STATE   SERVICE        VERSION\n");
            } else {
                try stderr.writeAll("PORT      STATE   SERVICE\n");
            }

            for (open_ports, 0..) |r, i| {
                var pbuf: [12]u8 = undefined;
                const pstr = std.fmt.bufPrint(&pbuf, "{d}/tcp", .{r.port}) catch "?/tcp";
                const svc = serviceName(r.port);
                if (has_versions) {
                    const ver = banners.?[i].str();
                    if (ver.len > 0) {
                        try stderr.print("{s:<9} \x1b[32mopen\x1b[0m    {s:<14} {s}\n", .{ pstr, svc, ver });
                    } else {
                        try stderr.print("{s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ pstr, svc });
                    }
                } else {
                    try stderr.print("{s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ pstr, svc });
                }
            }
        } else {
            if (has_versions) {
                try stderr.writeAll("HOST              PORT      STATE   SERVICE        VERSION\n");
            } else {
                try stderr.writeAll("HOST              PORT      STATE   SERVICE\n");
            }
            for (open_ports, 0..) |r, i| {
                var hbuf: [16]u8 = undefined;
                const hstr = target_mod.formatIp(&hbuf, r.ip);
                var pbuf: [12]u8 = undefined;
                const pstr = std.fmt.bufPrint(&pbuf, "{d}/tcp", .{r.port}) catch "?/tcp";
                const svc = serviceName(r.port);
                if (has_versions) {
                    const ver = banners.?[i].str();
                    if (ver.len > 0) {
                        try stderr.print("{s:<17} {s:<9} \x1b[32mopen\x1b[0m    {s:<14} {s}\n", .{ hstr, pstr, svc, ver });
                    } else {
                        try stderr.print("{s:<17} {s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ hstr, pstr, svc });
                    }
                } else {
                    try stderr.print("{s:<17} {s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ hstr, pstr, svc });
                }
            }
        }
    }

    // File output writers
    writeOutputFiles(&config, open_ports, banners);

    const avg_pps: f64 = if (snap.elapsed_secs > 0.001)
        @as(f64, @floatFromInt(snap.sent)) / snap.elapsed_secs
    else
        0;

    try stderr.print("\n\x1b[1;32mDone\x1b[0m: {d} probes in {d:.1}s ({d:.0} pps) | \x1b[32m{d} open\x1b[0m ports found\n", .{
        snap.sent,
        snap.elapsed_secs,
        avg_pps,
        snap.open,
    });
}

fn computeDrain(total_targets: u64, rate: u64) u64 {
    if (rate == 0) return 3;
    const tx_time = total_targets / rate;
    const drain = tx_time / 2 + 3;
    return @min(10, @max(3, drain));
}

fn writeOutputFiles(config: *const cli.ScanConfig, open_ports: []rx_mod.OpenPort, banners: ?[]banner_mod.BannerInfo) void {
    const ts = std.time.timestamp();

    for (config.outputs.items) |out| {
        writeOneOutput(out.format, out.path, open_ports, banners, ts);
    }

    if (config.output_all_prefix) |prefix| {
        var n_buf: [260]u8 = undefined;
        var x_buf: [260]u8 = undefined;
        var g_buf: [260]u8 = undefined;
        var j_buf: [260]u8 = undefined;

        const n_path = std.fmt.bufPrint(&n_buf, "{s}.nmap", .{prefix}) catch return;
        const x_path = std.fmt.bufPrint(&x_buf, "{s}.xml", .{prefix}) catch return;
        const g_path = std.fmt.bufPrint(&g_buf, "{s}.gnmap", .{prefix}) catch return;
        const j_path = std.fmt.bufPrint(&j_buf, "{s}.json", .{prefix}) catch return;

        writeOneOutput(.normal, n_path, open_ports, banners, ts);
        writeOneOutput(.xml, x_path, open_ports, banners, ts);
        writeOneOutput(.grepable, g_path, open_ports, banners, ts);
        writeOneOutput(.json, j_path, open_ports, banners, ts);
    }
}

fn writeOneOutput(
    format: cli.OutputFormat,
    path: []const u8,
    open_ports: []rx_mod.OpenPort,
    banners: ?[]banner_mod.BannerInfo,
    ts: i64,
) void {
    switch (format) {
        .json => {
            var w = output_mod.JsonWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, i, ts));
            }
            w.finish();
        },
        .xml => {
            var w = output_mod.XmlWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, i, ts));
            }
            w.finish();
        },
        .grepable => {
            var w = output_mod.GrepWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, i, ts));
            }
            w.finish();
        },
        .normal => {
            var w = output_mod.NormalWriter.init(path) catch return;
            var last_ip: u32 = 0;
            for (open_ports, 0..) |r, i| {
                if (r.ip != last_ip) {
                    w.writeHostHeader(r.ip);
                    last_ip = r.ip;
                }
                w.writeRecord(makeRecord(r, banners, i, ts));
            }
            w.finish();
        },
        .ndjson, .binary => {
            var w = output_mod.NdjsonWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, i, ts));
            }
            w.finish();
        },
    }
}

fn makeRecord(r: rx_mod.OpenPort, banners: ?[]banner_mod.BannerInfo, i: usize, ts: i64) output_mod.ScanRecord {
    return .{
        .ip = r.ip,
        .port = r.port,
        .protocol = "tcp",
        .status = "open",
        .service = svcOrNull(serviceName(r.port)),
        .version = if (banners) |b| blk: {
            const v = b[i].str();
            break :blk if (v.len > 0) v else null;
        } else null,
        .rtt_us = 0,
        .timestamp = ts,
    };
}

fn svcOrNull(svc: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, svc, "unknown")) return null;
    return svc;
}

fn txThreadFn(engine: *tx_mod.TxEngine) void {
    engine.run();
}

fn rxThreadFn(engine: *rx_mod.RxEngine) void {
    engine.run();
}

fn scanTypeName(st: cli.ScanType) []const u8 {
    return switch (st) {
        .syn => "TCP SYN (-sS)",
        .connect => "TCP Connect (-sT)",
        .fin => "TCP FIN (-sF)",
        .xmas => "TCP XMAS (-sX)",
        .null_scan => "TCP NULL (-sN)",
        .ack => "TCP ACK (-sA)",
        .window => "TCP Window (-sW)",
        .udp => "UDP (-sU)",
    };
}

fn serviceName(port: u16) []const u8 {
    return switch (port) {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67 => "dhcps",
        68 => "dhcpc",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        631 => "ipp",
        636 => "ldapssl",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        5900 => "vnc",
        5985 => "wsman",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "sun-answerbook",
        9090 => "zeus-admin",
        27017 => "mongodb",
        else => "unknown",
    };
}
