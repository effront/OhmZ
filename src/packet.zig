const std = @import("std");

pub const ETH_P_IP: u16 = 0x0800;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

pub const Ipv4Header = extern struct {
    ver_ihl: u8 = 0x45,
    tos: u8 = 0,
    total_len: u16 align(1) = 0,
    identification: u16 align(1) = 0,
    flags_frag: u16 align(1) = 0x4000,
    ttl: u8 = 64,
    protocol: u8 = IPPROTO_TCP,
    checksum: u16 align(1) = 0,
    src_ip: u32 align(1) = 0,
    dst_ip: u32 align(1) = 0,

    comptime {
        if (@sizeOf(Ipv4Header) != 20) @compileError("Ipv4Header must be 20 bytes");
    }
};

pub const TcpHeader = extern struct {
    src_port: u16 align(1) = 0,
    dst_port: u16 align(1) = 0,
    seq_num: u32 align(1) = 0,
    ack_num: u32 align(1) = 0,
    data_off_flags: u16 align(1) = 0,
    window: u16 align(1) = 0,
    checksum: u16 align(1) = 0,
    urgent: u16 align(1) = 0,

    comptime {
        if (@sizeOf(TcpHeader) != 20) @compileError("TcpHeader must be 20 bytes");
    }
};

pub const TcpFlags = struct {
    pub const FIN: u16 = 0x0001;
    pub const SYN: u16 = 0x0002;
    pub const RST: u16 = 0x0004;
    pub const PSH: u16 = 0x0008;
    pub const ACK: u16 = 0x0010;
    pub const URG: u16 = 0x0020;
    pub const ECE: u16 = 0x0040;
    pub const CWR: u16 = 0x0080;
};

pub const PACKET_SIZE = @sizeOf(Ipv4Header) + @sizeOf(TcpHeader);

pub const SynTemplate = TcpTemplate;

pub const TcpTemplate = struct {
    buf: [PACKET_SIZE]u8,

    pub fn init(src_ip: u32, src_port: u16) TcpTemplate {
        return initWithFlags(src_ip, src_port, TcpFlags.SYN);
    }

    pub fn initWithFlags(src_ip: u32, src_port: u16, flags: u16) TcpTemplate {
        var buf: [PACKET_SIZE]u8 = std.mem.zeroes([PACKET_SIZE]u8);

        var ip: *Ipv4Header = @ptrCast(@alignCast(&buf[0]));
        ip.ver_ihl = 0x45;
        ip.tos = 0;
        ip.total_len = toNet(u16, PACKET_SIZE);
        ip.identification = 0;
        ip.flags_frag = toNet(u16, 0x4000);
        ip.ttl = 64;
        ip.protocol = IPPROTO_TCP;
        ip.checksum = 0;
        ip.src_ip = toNet(u32, src_ip);
        ip.dst_ip = 0;

        var tcp: *TcpHeader = @ptrCast(@alignCast(&buf[@sizeOf(Ipv4Header)]));
        tcp.src_port = toNet(u16, src_port);
        tcp.dst_port = 0;
        tcp.seq_num = 0;
        tcp.ack_num = 0;
        tcp.data_off_flags = toNet(u16, (5 << 12) | flags);
        tcp.window = toNet(u16, 65535);
        tcp.checksum = 0;
        tcp.urgent = 0;

        return .{ .buf = buf };
    }

    pub fn patch(self: *TcpTemplate, dst_ip: u32, dst_port: u16, seq: u32) void {
        var ip: *Ipv4Header = @ptrCast(@alignCast(&self.buf[0]));
        ip.dst_ip = toNet(u32, dst_ip);
        ip.checksum = 0;
        ip.checksum = ipChecksum(std.mem.asBytes(ip));

        var tcp: *TcpHeader = @ptrCast(@alignCast(&self.buf[@sizeOf(Ipv4Header)]));
        tcp.dst_port = toNet(u16, dst_port);
        tcp.seq_num = toNet(u32, seq);
        tcp.checksum = 0;
        tcp.checksum = tcpChecksum(ip, std.mem.asBytes(tcp));
    }

    pub fn flagsForScanType(scan_type: @import("cli.zig").ScanType) u16 {
        return switch (scan_type) {
            .syn => TcpFlags.SYN,
            .fin => TcpFlags.FIN,
            .xmas => TcpFlags.FIN | TcpFlags.PSH | TcpFlags.URG,
            .null_scan => 0,
            .ack => TcpFlags.ACK,
            .window => TcpFlags.ACK,
            else => TcpFlags.SYN,
        };
    }
};

pub fn ipChecksum(header: []const u8) u16 {
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
    return toNet(u16, @intCast(~@as(u16, @intCast(sum & 0xFFFF))));
}

pub fn tcpChecksum(ip: *const Ipv4Header, tcp_bytes: []const u8) u16 {
    var sum: u32 = 0;

    const src = std.mem.asBytes(&ip.src_ip);
    sum += @as(u32, src[0]) << 8 | @as(u32, src[1]);
    sum += @as(u32, src[2]) << 8 | @as(u32, src[3]);

    const dst = std.mem.asBytes(&ip.dst_ip);
    sum += @as(u32, dst[0]) << 8 | @as(u32, dst[1]);
    sum += @as(u32, dst[2]) << 8 | @as(u32, dst[3]);

    sum += @as(u32, ip.protocol);
    sum += @as(u32, @intCast(tcp_bytes.len));

    var i: usize = 0;
    while (i + 1 < tcp_bytes.len) : (i += 2) {
        const word: u16 = @as(u16, tcp_bytes[i]) << 8 | @as(u16, tcp_bytes[i + 1]);
        sum += word;
    }
    if (i < tcp_bytes.len) {
        sum += @as(u32, tcp_bytes[i]) << 8;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return toNet(u16, @intCast(~@as(u16, @intCast(sum & 0xFFFF))));
}

pub fn toNet(comptime T: type, val: T) T {
    return @byteSwap(val);
}

pub fn fromNet(comptime T: type, val: T) T {
    return @byteSwap(val);
}

pub fn parseTcpFlags(raw: u16) u16 {
    return fromNet(u16, raw) & 0x3F;
}

pub fn isSynAck(flags: u16) bool {
    return (flags & (TcpFlags.SYN | TcpFlags.ACK)) == (TcpFlags.SYN | TcpFlags.ACK);
}

pub fn isRst(flags: u16) bool {
    return (flags & TcpFlags.RST) != 0;
}

test "Ipv4Header size" {
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(Ipv4Header));
}

test "TcpHeader size" {
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(TcpHeader));
}

test "TcpTemplate builds valid packet" {
    var tmpl = TcpTemplate.init(0xC0A80001, 12345);
    tmpl.patch(0xC0A80002, 80, 0xAABBCCDD);

    const ip: *const Ipv4Header = @ptrCast(@alignCast(&tmpl.buf[0]));
    try std.testing.expectEqual(@as(u8, 0x45), ip.ver_ihl);
    try std.testing.expectEqual(@as(u8, 64), ip.ttl);
    try std.testing.expectEqual(@as(u8, IPPROTO_TCP), ip.protocol);
    try std.testing.expectEqual(toNet(u32, 0xC0A80002), ip.dst_ip);

    const tcp: *const TcpHeader = @ptrCast(@alignCast(&tmpl.buf[@sizeOf(Ipv4Header)]));
    try std.testing.expectEqual(toNet(u16, 80), tcp.dst_port);
    try std.testing.expectEqual(toNet(u32, 0xAABBCCDD), tcp.seq_num);
}

test "toNet/fromNet roundtrip" {
    const val: u32 = 0x12345678;
    try std.testing.expectEqual(val, fromNet(u32, toNet(u32, val)));
}

test "isSynAck / isRst" {
    try std.testing.expect(isSynAck(TcpFlags.SYN | TcpFlags.ACK));
    try std.testing.expect(!isSynAck(TcpFlags.SYN));
    try std.testing.expect(isRst(TcpFlags.RST));
    try std.testing.expect(!isRst(TcpFlags.SYN));
}
