const std = @import("std");

pub const SynCookie = struct {
    key: [2]u64,

    pub fn init() SynCookie {
        var key: [2]u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&key)) catch {
            key = .{ 0x736F6D6570736575, 0x646F72616E646F6D };
        };
        return .{ .key = key };
    }

    pub fn initWithSeed(seed: u64) SynCookie {
        return .{ .key = .{ seed, seed ^ 0x6A09E667F3BCC908 } };
    }

    pub fn generate(self: *const SynCookie, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) u32 {
        const hash = self.sipHash(src_ip, src_port, dst_ip, dst_port);
        return @truncate(hash);
    }

    pub fn validate(self: *const SynCookie, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, ack_num: u32) bool {
        const expected = self.generate(dst_ip, dst_port, src_ip, src_port);
        return ack_num == expected +% 1;
    }

    fn sipHash(self: *const SynCookie, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) u64 {
        var v0: u64 = self.key[0] ^ 0x736F6D6570736575;
        var v1: u64 = self.key[1] ^ 0x646F72616E646F6D;
        var v2: u64 = self.key[0] ^ 0x6C7967656E657261;
        var v3: u64 = self.key[1] ^ 0x7465646279746573;

        const m0: u64 = @as(u64, src_ip) | (@as(u64, dst_ip) << 32);
        const m1: u64 = @as(u64, src_port) | (@as(u64, dst_port) << 16);

        v3 ^= m0;
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);
        v0 ^= m0;

        v3 ^= m1;
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);
        v0 ^= m1;

        v2 ^= 0xFF;
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);

        return v0 ^ v1 ^ v2 ^ v3;
    }

    fn sipRound(v0: *u64, v1: *u64, v2: *u64, v3: *u64) void {
        v0.* +%= v1.*;
        v2.* +%= v3.*;
        v1.* = std.math.rotl(u64, v1.*, 13);
        v3.* = std.math.rotl(u64, v3.*, 16);
        v1.* ^= v0.*;
        v3.* ^= v2.*;
        v0.* = std.math.rotl(u64, v0.*, 32);
        v2.* +%= v1.*;
        v0.* +%= v3.*;
        v1.* = std.math.rotl(u64, v1.*, 17);
        v3.* = std.math.rotl(u64, v3.*, 21);
        v1.* ^= v2.*;
        v3.* ^= v0.*;
        v2.* = std.math.rotl(u64, v2.*, 32);
    }
};

test "SynCookie generate is deterministic" {
    const cookie = SynCookie.initWithSeed(42);
    const a = cookie.generate(0xC0A80001, 12345, 0xC0A80002, 80);
    const b = cookie.generate(0xC0A80001, 12345, 0xC0A80002, 80);
    try std.testing.expectEqual(a, b);
}

test "SynCookie different inputs produce different cookies" {
    const cookie = SynCookie.initWithSeed(42);
    const a = cookie.generate(0xC0A80001, 12345, 0xC0A80002, 80);
    const b = cookie.generate(0xC0A80001, 12345, 0xC0A80002, 443);
    try std.testing.expect(a != b);
}

test "SynCookie validate round-trip" {
    const cookie = SynCookie.initWithSeed(99);
    const src_ip: u32 = 0xC0A80001;
    const src_port: u16 = 45678;
    const dst_ip: u32 = 0xC0A80002;
    const dst_port: u16 = 80;

    const seq = cookie.generate(src_ip, src_port, dst_ip, dst_port);
    const ack = seq +% 1;

    try std.testing.expect(cookie.validate(dst_ip, dst_port, src_ip, src_port, ack));
    try std.testing.expect(!cookie.validate(dst_ip, dst_port, src_ip, src_port, ack +% 1));
}
