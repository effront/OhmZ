const std = @import("std");
const packet = @import("packet.zig");
const tx_mod = @import("tx.zig");

const MAX_HOPS: u8 = 30;
const MAX_WORKERS: usize = 16;
const BASE_PORT: u16 = 33434;
const PROBE_TIMEOUT_SECS: isize = 2;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
const SO_RCVTIMEO: u32 = 20;
const IP_PACKET_SIZE: usize = 20 + 8 + 32; // IP header + UDP header + payload

pub const Hop = struct {
    ttl: u8 = 0,
    ip: u32 = 0,
    rtt_us: u32 = 0,

    pub fn reached(self: *const Hop) bool {
        return self.ip != 0;
    }
};

pub const TraceResult = struct {
    hops: [MAX_HOPS]Hop = .{Hop{}} ** MAX_HOPS,
    hop_count: u8 = 0,
    target_reached: bool = false,
};

pub fn trace(target_ip: u32) TraceResult {
    var result = TraceResult{};

    const send_fd = openSendSocket() orelse return result;
    defer std.posix.close(send_fd);

    const recv_fd = openRecvSocket() orelse return result;
    defer std.posix.close(recv_fd);

    const src_ip = tx_mod.getLocalIp(target_ip);
    if (src_ip == 0) return result;

    const src_port: u16 = 44000 + @as(u16, @truncate(@as(u64, @bitCast(std.time.milliTimestamp())) % 10000));

    var consecutive_timeouts: u8 = 0;

    for (0..MAX_HOPS) |i| {
        const ttl: u8 = @intCast(i + 1);
        const dst_port: u16 = BASE_PORT + ttl;

        var pkt = buildUdpPacket(src_ip, target_ip, src_port, dst_port, ttl);

        const dest = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, target_ip),
        };

        const send_time = std.time.microTimestamp();

        _ = std.posix.sendto(
            send_fd,
            &pkt,
            0,
            @ptrCast(&dest),
            @sizeOf(std.posix.sockaddr.in),
        ) catch {
            result.hops[i] = .{ .ttl = ttl };
            result.hop_count = ttl;
            continue;
        };

        const hop = recvIcmpResponse(recv_fd, target_ip, dst_port, send_time);
        result.hops[i] = .{
            .ttl = ttl,
            .ip = hop.ip,
            .rtt_us = hop.rtt_us,
        };
        result.hop_count = ttl;

        if (hop.ip == 0) {
            consecutive_timeouts += 1;
            if (consecutive_timeouts >= 5) break;
        } else {
            consecutive_timeouts = 0;
        }

        if (hop.ip == target_ip or hop.target_reached) {
            result.target_reached = true;
            break;
        }
    }

    return result;
}

pub fn traceAll(ips: []const u32, results: []TraceResult, num_workers: usize) void {
    var next_idx = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        targets: []const u32,
        out: []TraceResult,
        next: *std.atomic.Value(usize),
    };

    var ctx = Ctx{
        .targets = ips,
        .out = results,
        .next = &next_idx,
    };

    const actual = @min(num_workers, @min(ips.len, MAX_WORKERS));
    var threads: [MAX_WORKERS]?std.Thread = .{null} ** MAX_WORKERS;

    for (0..actual) |w| {
        threads[w] = std.Thread.spawn(.{}, struct {
            fn run(c: *Ctx) void {
                while (true) {
                    const i = c.next.fetchAdd(1, .monotonic);
                    if (i >= c.targets.len) break;
                    c.out[i] = trace(c.targets[i]);
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

const IcmpHop = struct {
    ip: u32 = 0,
    rtt_us: u32 = 0,
    target_reached: bool = false,
};

fn recvIcmpResponse(fd: std.posix.fd_t, target_ip: u32, expected_dst_port: u16, send_time: i64) IcmpHop {
    var buf: [1500]u8 = undefined;
    const deadline = send_time + PROBE_TIMEOUT_SECS * 1_000_000;

    while (std.time.microTimestamp() < deadline) {
        const n = std.posix.read(fd, &buf) catch return .{};
        if (n < 28) continue; // min: IP(20) + ICMP(8)

        const ihl: usize = @as(usize, buf[0] & 0x0F) * 4;
        if (ihl < 20 or n < ihl + 8) continue;

        const icmp_type = buf[ihl];
        const icmp_code = buf[ihl + 1];

        const resp_ip = readU32(buf[12..16]);

        // Type 11 Code 0 = Time Exceeded in Transit
        // Type 3 = Destination Unreachable
        if (icmp_type == 11 and icmp_code == 0) {
            if (verifyEmbeddedPacket(buf[ihl + 8 .. n], expected_dst_port)) {
                const rtt = @as(u32, @intCast(@max(0, std.time.microTimestamp() - send_time)));
                return .{ .ip = resp_ip, .rtt_us = rtt };
            }
        } else if (icmp_type == 3) {
            if (verifyEmbeddedPacket(buf[ihl + 8 .. n], expected_dst_port)) {
                const rtt = @as(u32, @intCast(@max(0, std.time.microTimestamp() - send_time)));
                return .{ .ip = resp_ip, .rtt_us = rtt, .target_reached = (resp_ip == target_ip) };
            }
        }
    }

    return .{};
}

fn verifyEmbeddedPacket(data: []const u8, expected_dst_port: u16) bool {
    // ICMP payload: original IP header + first 8 bytes of original UDP
    if (data.len < 28) return false;

    const inner_ihl: usize = @as(usize, data[0] & 0x0F) * 4;
    if (data.len < inner_ihl + 4) return false;

    const inner_protocol = data[9];
    if (inner_protocol != IPPROTO_UDP) return false;

    const udp_dst = (@as(u16, data[inner_ihl + 2]) << 8) | @as(u16, data[inner_ihl + 3]);
    return udp_dst == expected_dst_port;
}

fn buildUdpPacket(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, ttl: u8) [IP_PACKET_SIZE]u8 {
    var pkt: [IP_PACKET_SIZE]u8 = std.mem.zeroes([IP_PACKET_SIZE]u8);

    // IP header
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0; // TOS
    const total_len: u16 = IP_PACKET_SIZE;
    pkt[2] = @intCast(total_len >> 8);
    pkt[3] = @intCast(total_len & 0xFF);
    // identification = 0 (pkt[4..6])
    pkt[6] = 0x40; // Don't Fragment
    pkt[7] = 0;
    pkt[8] = ttl;
    pkt[9] = IPPROTO_UDP;
    // checksum = 0 initially (pkt[10..12])
    pkt[12] = @intCast((src_ip >> 24) & 0xFF);
    pkt[13] = @intCast((src_ip >> 16) & 0xFF);
    pkt[14] = @intCast((src_ip >> 8) & 0xFF);
    pkt[15] = @intCast(src_ip & 0xFF);
    pkt[16] = @intCast((dst_ip >> 24) & 0xFF);
    pkt[17] = @intCast((dst_ip >> 16) & 0xFF);
    pkt[18] = @intCast((dst_ip >> 8) & 0xFF);
    pkt[19] = @intCast(dst_ip & 0xFF);

    // IP checksum
    const ip_cksum = ipChecksum(pkt[0..20]);
    pkt[10] = @intCast((ip_cksum >> 8) & 0xFF);
    pkt[11] = @intCast(ip_cksum & 0xFF);

    // UDP header (starts at byte 20)
    pkt[20] = @intCast(src_port >> 8);
    pkt[21] = @intCast(src_port & 0xFF);
    pkt[22] = @intCast(dst_port >> 8);
    pkt[23] = @intCast(dst_port & 0xFF);
    const udp_len: u16 = IP_PACKET_SIZE - 20; // 40 bytes: 8 header + 32 payload
    pkt[24] = @intCast(udp_len >> 8);
    pkt[25] = @intCast(udp_len & 0xFF);
    // UDP checksum = 0 (optional for IPv4)

    return pkt;
}

fn ipChecksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) {
        const word: u16 = @as(u16, header[i]) << 8 | @as(u16, header[i + 1]);
        sum += word;
    }
    if (i < header.len) {
        sum += @as(u32, header[i]) << 8;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return @intCast(~@as(u16, @intCast(sum & 0xFFFF)));
}

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn openSendSocket() ?std.posix.fd_t {
    const fd = std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.RAW,
    ) catch return null;

    const hdr_incl: c_int = 1;
    std.posix.setsockopt(
        fd,
        std.posix.IPPROTO.IP,
        std.posix.system.IP.HDRINCL,
        std.mem.asBytes(&hdr_incl),
    ) catch {
        std.posix.close(fd);
        return null;
    };

    return fd;
}

fn openRecvSocket() ?std.posix.fd_t {
    const fd = std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.ICMP,
    ) catch return null;

    const Timeval = extern struct { sec: isize, usec: isize };
    const tv = Timeval{ .sec = PROBE_TIMEOUT_SECS, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_RCVTIMEO, std.mem.asBytes(&tv)) catch {};

    return fd;
}
