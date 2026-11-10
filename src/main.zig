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
const os_mod = @import("os.zig");
const traceroute_mod = @import("traceroute.zig");
const scripts_mod = @import("scripts.zig");

const VERSION = "0.5.2";

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
    {
        var feat_buf: [128]u8 = undefined;
        var feat_len: usize = 0;
        if (config.banner_grab) {
            const s = "sV";
            @memcpy(feat_buf[feat_len .. feat_len + s.len], s);
            feat_len += s.len;
        }
        if (config.script_scan) {
            if (feat_len > 0) {
                feat_buf[feat_len] = '+';
                feat_len += 1;
            }
            const s = "sC";
            @memcpy(feat_buf[feat_len .. feat_len + s.len], s);
            feat_len += s.len;
        }
        if (config.os_detect) {
            if (feat_len > 0) {
                feat_buf[feat_len] = '+';
                feat_len += 1;
            }
            const s = "O";
            @memcpy(feat_buf[feat_len .. feat_len + s.len], s);
            feat_len += s.len;
        }
        if (config.traceroute) {
            if (feat_len > 0) {
                feat_buf[feat_len] = '+';
                feat_len += 1;
            }
            const s = "trace";
            @memcpy(feat_buf[feat_len .. feat_len + s.len], s);
            feat_len += s.len;
        }
        if (feat_len > 0) {
            try stderr.print("  Detection: {s}\n", .{feat_buf[0..feat_len]});
        }
    }
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

    var banners: ?[]banner_mod.ServiceInfo = null;
    defer if (banners) |b| allocator.free(b);

    if (open_ports.len > 0 and config.banner_grab) {
        const workers: usize = @min(open_ports.len, 16);
        try stderr.print("\nService detection on {d} open ports ({d} workers)...\n", .{ open_ports.len, workers });
        const b = try allocator.alloc(banner_mod.ServiceInfo, open_ports.len);
        banner_mod.detectAll(open_ports, b, workers);
        banners = b;
    }

    // Script scanning (-sC)
    var script_results: ?[]scripts_mod.HostScripts = null;
    defer if (script_results) |sr| allocator.free(sr);

    if (open_ports.len > 0 and config.script_scan) {
        const workers: usize = @min(open_ports.len, 16);
        try stderr.print("Script scanning on {d} open ports ({d} workers)...\n", .{ open_ports.len, workers });
        const sr = try allocator.alloc(scripts_mod.HostScripts, open_ports.len);
        scripts_mod.runAll(open_ports, sr, workers);
        script_results = sr;
    }

    // Collect unique IPs for per-host detection
    var unique_ips_buf: [256]u32 = undefined;
    var unique_ports_buf: [256]u16 = undefined;
    var unique_ip_count: usize = 0;

    if (open_ports.len > 0 and (config.os_detect or config.traceroute)) {
        for (open_ports) |r| {
            var found = false;
            for (unique_ips_buf[0..unique_ip_count]) |ip| {
                if (ip == r.ip) {
                    found = true;
                    break;
                }
            }
            if (!found and unique_ip_count < 256) {
                unique_ips_buf[unique_ip_count] = r.ip;
                unique_ports_buf[unique_ip_count] = r.port;
                unique_ip_count += 1;
            }
        }
    }

    // OS fingerprinting (-O) and Traceroute (--traceroute) need raw sockets
    const is_root = std.os.linux.geteuid() == 0;

    var os_results_buf: [256]os_mod.OsInfo = undefined;
    var os_results: ?[]os_mod.OsInfo = null;

    if (unique_ip_count > 0 and config.os_detect) {
        if (is_root) {
            const workers: usize = @min(unique_ip_count, 8);
            try stderr.print("OS detection on {d} hosts ({d} workers)...\n", .{ unique_ip_count, workers });
            os_mod.detectAll(
                unique_ips_buf[0..unique_ip_count],
                unique_ports_buf[0..unique_ip_count],
                os_results_buf[0..unique_ip_count],
                workers,
            );
            os_results = os_results_buf[0..unique_ip_count];
        } else {
            try stderr.writeAll("  \x1b[33mNote\x1b[0m: -O requires root (raw sockets). Skipping OS detection.\n");
        }
    }

    var trace_results_buf: [256]traceroute_mod.TraceResult = undefined;
    var trace_results: ?[]traceroute_mod.TraceResult = null;

    if (unique_ip_count > 0 and config.traceroute) {
        if (is_root) {
            const workers: usize = @min(unique_ip_count, 4);
            try stderr.print("Traceroute to {d} hosts ({d} workers)...\n", .{ unique_ip_count, workers });
            traceroute_mod.traceAll(
                unique_ips_buf[0..unique_ip_count],
                trace_results_buf[0..unique_ip_count],
                workers,
            );
            trace_results = trace_results_buf[0..unique_ip_count];
        } else {
            try stderr.writeAll("  \x1b[33mNote\x1b[0m: --traceroute requires root (raw sockets). Skipping traceroute.\n");
        }
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
                const svc = if (has_versions) blk: {
                    const detected = banners.?[i].name();
                    break :blk if (detected.len > 0) detected else serviceName(r.port);
                } else serviceName(r.port);
                if (has_versions) {
                    const ver = banners.?[i].version();
                    if (ver.len > 0) {
                        try stderr.print("{s:<9} \x1b[32mopen\x1b[0m    {s:<14} {s}\n", .{ pstr, svc, ver });
                    } else {
                        try stderr.print("{s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ pstr, svc });
                    }
                } else {
                    try stderr.print("{s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ pstr, svc });
                }

                // Print script results for this port
                if (script_results) |sr| {
                    for (0..sr[i].count) |si| {
                        try stderr.print("|  \x1b[33m{s}\x1b[0m: {s}\n", .{ sr[i].results[si].id(), sr[i].results[si].output() });
                    }
                }
            }

            // OS detection result for this host
            if (os_results) |osr| {
                const host_ip = open_ports[0].ip;
                for (0..unique_ip_count) |ui| {
                    if (unique_ips_buf[ui] == host_ip and osr[ui].confidence > 0) {
                        try stderr.print("\nOS: \x1b[1;35m{s}\x1b[0m ({d}% confidence, TTL={d})\n", .{
                            osr[ui].name(), osr[ui].confidence, osr[ui].ttl,
                        });
                        break;
                    }
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
                const svc = if (has_versions) blk: {
                    const detected = banners.?[i].name();
                    break :blk if (detected.len > 0) detected else serviceName(r.port);
                } else serviceName(r.port);
                if (has_versions) {
                    const ver = banners.?[i].version();
                    if (ver.len > 0) {
                        try stderr.print("{s:<17} {s:<9} \x1b[32mopen\x1b[0m    {s:<14} {s}\n", .{ hstr, pstr, svc, ver });
                    } else {
                        try stderr.print("{s:<17} {s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ hstr, pstr, svc });
                    }
                } else {
                    try stderr.print("{s:<17} {s:<9} \x1b[32mopen\x1b[0m    {s}\n", .{ hstr, pstr, svc });
                }

                if (script_results) |sr| {
                    for (0..sr[i].count) |si| {
                        try stderr.print("                  |  \x1b[33m{s}\x1b[0m: {s}\n", .{ sr[i].results[si].id(), sr[i].results[si].output() });
                    }
                }
            }

            // OS detection per host
            if (os_results) |osr| {
                try stderr.writeAll("\n");
                for (0..unique_ip_count) |ui| {
                    if (osr[ui].confidence > 0) {
                        var hbuf2: [16]u8 = undefined;
                        const hstr2 = target_mod.formatIp(&hbuf2, unique_ips_buf[ui]);
                        try stderr.print("OS [{s}]: \x1b[1;35m{s}\x1b[0m ({d}% confidence, TTL={d})\n", .{
                            hstr2, osr[ui].name(), osr[ui].confidence, osr[ui].ttl,
                        });
                    }
                }
            }
        }

        // Traceroute output
        if (trace_results) |tr| {
            try stderr.writeAll("\n\x1b[1;36mTRACEROUTE\x1b[0m\n");
            for (0..unique_ip_count) |ui| {
                var hbuf3: [16]u8 = undefined;
                const hstr3 = target_mod.formatIp(&hbuf3, unique_ips_buf[ui]);
                try stderr.print("  Route to {s}:\n", .{hstr3});
                const trace = tr[ui];
                for (0..trace.hop_count) |hi| {
                    const hop = trace.hops[hi];
                    if (hop.reached()) {
                        var hop_buf: [16]u8 = undefined;
                        const hop_str = target_mod.formatIp(&hop_buf, hop.ip);
                        try stderr.print("    {d:>2}  {s:<16} {d:.1}ms\n", .{
                            hop.ttl, hop_str, @as(f64, @floatFromInt(hop.rtt_us)) / 1000.0,
                        });
                    } else {
                        try stderr.print("    {d:>2}  *\n", .{hop.ttl});
                    }
                }
            }
        }
    }

    // File output writers
    writeOutputFiles(&config, open_ports, banners, script_results, os_results, trace_results, unique_ips_buf[0..unique_ip_count]);

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

fn writeOutputFiles(
    config: *const cli.ScanConfig,
    open_ports: []rx_mod.OpenPort,
    banners: ?[]banner_mod.BannerInfo,
    script_results: ?[]scripts_mod.HostScripts,
    os_results: ?[]os_mod.OsInfo,
    trace_results: ?[]traceroute_mod.TraceResult,
    unique_ips: []const u32,
) void {
    const ts = std.time.timestamp();

    for (config.outputs.items) |out| {
        writeOneOutput(out.format, out.path, open_ports, banners, script_results, os_results, trace_results, unique_ips, ts);
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

        writeOneOutput(.normal, n_path, open_ports, banners, script_results, os_results, trace_results, unique_ips, ts);
        writeOneOutput(.xml, x_path, open_ports, banners, script_results, os_results, trace_results, unique_ips, ts);
        writeOneOutput(.grepable, g_path, open_ports, banners, script_results, os_results, trace_results, unique_ips, ts);
        writeOneOutput(.json, j_path, open_ports, banners, script_results, os_results, trace_results, unique_ips, ts);
    }
}

fn writeOneOutput(
    format: cli.OutputFormat,
    path: []const u8,
    open_ports: []rx_mod.OpenPort,
    banners: ?[]banner_mod.BannerInfo,
    script_results: ?[]scripts_mod.HostScripts,
    os_results: ?[]os_mod.OsInfo,
    trace_results: ?[]traceroute_mod.TraceResult,
    unique_ips: []const u32,
    ts: i64,
) void {
    switch (format) {
        .json => {
            var w = output_mod.JsonWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, script_results, i, ts));
            }
            w.finish();
        },
        .xml => {
            var w = output_mod.XmlWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, script_results, i, ts));
            }
            writeOsTraceXml(&w, os_results, trace_results, unique_ips);
            w.finish();
        },
        .grepable => {
            var w = output_mod.GrepWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, script_results, i, ts));
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
                w.writeRecord(makeRecord(r, banners, script_results, i, ts));
            }
            writeOsTraceNormal(&w, os_results, trace_results, unique_ips);
            w.finish();
        },
        .ndjson, .binary => {
            var w = output_mod.NdjsonWriter.init(path) catch return;
            for (open_ports, 0..) |r, i| {
                w.writeRecord(makeRecord(r, banners, script_results, i, ts));
            }
            w.finish();
        },
    }
}

fn makeRecord(r: rx_mod.OpenPort, banners: ?[]banner_mod.ServiceInfo, script_results: ?[]scripts_mod.HostScripts, i: usize, ts: i64) output_mod.ScanRecord {
    var scripts_str_buf: [512]u8 = undefined;
    var scripts_str: ?[]const u8 = null;
    if (script_results) |sr| {
        if (sr[i].count > 0) {
            var pos: usize = 0;
            for (0..sr[i].count) |si| {
                if (si > 0 and pos + 2 < scripts_str_buf.len) {
                    scripts_str_buf[pos] = ';';
                    scripts_str_buf[pos + 1] = ' ';
                    pos += 2;
                }
                const sid = sr[i].results[si].id();
                const sout = sr[i].results[si].output();
                const entry_len = sid.len + 2 + sout.len;
                if (pos + entry_len <= scripts_str_buf.len) {
                    @memcpy(scripts_str_buf[pos .. pos + sid.len], sid);
                    pos += sid.len;
                    scripts_str_buf[pos] = ':';
                    scripts_str_buf[pos + 1] = ' ';
                    pos += 2;
                    @memcpy(scripts_str_buf[pos .. pos + sout.len], sout);
                    pos += sout.len;
                }
            }
            if (pos > 0) scripts_str = scripts_str_buf[0..pos];
        }
    }

    return .{
        .ip = r.ip,
        .port = r.port,
        .protocol = "tcp",
        .status = "open",
        .service = if (banners) |b| blk: {
            const n = b[i].name();
            break :blk if (n.len > 0) n else svcOrNull(serviceName(r.port));
        } else svcOrNull(serviceName(r.port)),
        .version = if (banners) |b| blk: {
            const v = b[i].version();
            break :blk if (v.len > 0) v else null;
        } else null,
        .extra = if (banners) |b| blk: {
            const e = b[i].extra();
            break :blk if (e.len > 0) e else null;
        } else null,
        .tls = if (banners) |b| b[i].tls else false,
        .scripts = scripts_str,
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

fn writeOsTraceNormal(w: *output_mod.NormalWriter, os_results: ?[]os_mod.OsInfo, trace_results: ?[]traceroute_mod.TraceResult, unique_ips: []const u32) void {
    const bw = w.bw.writer();
    if (os_results) |osr| {
        for (osr, 0..) |info, ui| {
            if (info.confidence > 0) {
                var ip_buf: [16]u8 = undefined;
                const ip_str = target_mod.formatIp(&ip_buf, unique_ips[ui]);
                bw.print("OS [{s}]: {s} ({d}% confidence, TTL={d})\n", .{ ip_str, info.name(), info.confidence, info.ttl }) catch {};
            }
        }
    }
    if (trace_results) |tr| {
        for (tr, 0..) |trace, ui| {
            var ip_buf: [16]u8 = undefined;
            const ip_str = target_mod.formatIp(&ip_buf, unique_ips[ui]);
            bw.print("\nTRACEROUTE to {s}:\n", .{ip_str}) catch {};
            for (0..trace.hop_count) |hi| {
                const hop = trace.hops[hi];
                if (hop.reached()) {
                    var hop_buf: [16]u8 = undefined;
                    const hop_str = target_mod.formatIp(&hop_buf, hop.ip);
                    bw.print("  {d:>2}  {s:<16} {d:.1}ms\n", .{ hop.ttl, hop_str, @as(f64, @floatFromInt(hop.rtt_us)) / 1000.0 }) catch {};
                } else {
                    bw.print("  {d:>2}  *\n", .{hop.ttl}) catch {};
                }
            }
        }
    }
}

fn writeOsTraceXml(w: *output_mod.XmlWriter, os_results: ?[]os_mod.OsInfo, trace_results: ?[]traceroute_mod.TraceResult, unique_ips: []const u32) void {
    const bw = w.bw.writer();
    if (os_results) |osr| {
        for (osr, 0..) |info, ui| {
            if (info.confidence > 0) {
                var ip_buf: [16]u8 = undefined;
                const ip_str = target_mod.formatIp(&ip_buf, unique_ips[ui]);
                bw.print("  <os addr=\"{s}\">\n    <osmatch name=\"{s}\" accuracy=\"{d}\"/>\n  </os>\n", .{ ip_str, info.name(), info.confidence }) catch {};
            }
        }
    }
    if (trace_results) |tr| {
        for (tr, 0..) |trace, ui| {
            var ip_buf: [16]u8 = undefined;
            const ip_str = target_mod.formatIp(&ip_buf, unique_ips[ui]);
            bw.print("  <trace to=\"{s}\">\n", .{ip_str}) catch {};
            for (0..trace.hop_count) |hi| {
                const hop = trace.hops[hi];
                if (hop.reached()) {
                    var hop_buf: [16]u8 = undefined;
                    const hop_str = target_mod.formatIp(&hop_buf, hop.ip);
                    bw.print("    <hop ttl=\"{d}\" ipaddr=\"{s}\" rtt=\"{d:.1}\"/>\n", .{ hop.ttl, hop_str, @as(f64, @floatFromInt(hop.rtt_us)) / 1000.0 }) catch {};
                } else {
                    bw.print("    <hop ttl=\"{d}\"/>\n", .{hop.ttl}) catch {};
                }
            }
            bw.writeAll("  </trace>\n") catch {};
        }
    }
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
