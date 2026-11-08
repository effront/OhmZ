const std = @import("std");

const SO_RCVTIMEO = 20;
const SO_SNDTIMEO = 21;
const IO_TIMEOUT_SECS: isize = 4;

pub const TlsInfo = struct {
    version_buf: [16]u8 = .{0} ** 16,
    version_len: u8 = 0,
    cipher_buf: [64]u8 = .{0} ** 64,
    cipher_len: u8 = 0,
    subject_cn_buf: [128]u8 = .{0} ** 128,
    cn_len: u8 = 0,
    issuer_cn_buf: [128]u8 = .{0} ** 128,
    issuer_cn_len: u8 = 0,
    not_after_buf: [24]u8 = .{0} ** 24,
    not_after_len: u8 = 0,
    valid: bool = false,

    pub fn versionStr(self: *const TlsInfo) []const u8 {
        return self.version_buf[0..self.version_len];
    }

    pub fn cipherStr(self: *const TlsInfo) []const u8 {
        return self.cipher_buf[0..self.cipher_len];
    }

    pub fn subjectCn(self: *const TlsInfo) []const u8 {
        return self.subject_cn_buf[0..self.cn_len];
    }

    pub fn issuerCn(self: *const TlsInfo) []const u8 {
        return self.issuer_cn_buf[0..self.issuer_cn_len];
    }

    pub fn notAfter(self: *const TlsInfo) []const u8 {
        return self.not_after_buf[0..self.not_after_len];
    }

    fn setStr(buf: []u8, text: []const u8) u8 {
        const len: u8 = @intCast(@min(text.len, buf.len));
        @memcpy(buf[0..len], text[0..len]);
        return len;
    }
};

pub fn probe(ip: u32, port: u16) TlsInfo {
    var info = TlsInfo{};

    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return info;
    defer std.posix.close(fd);

    setTimeout(fd);

    var dest = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, ip),
    };
    std.posix.connect(fd, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch return info;

    const hello = buildClientHello();
    _ = std.posix.write(fd, hello.data[0..hello.len]) catch return info;

    var buf: [8192]u8 = undefined;
    var total: usize = 0;

    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
        if (total >= 5) {
            const record_len = readU16(buf[3..5]);
            if (total >= 5 + @as(usize, record_len)) {
                if (total >= 10 + @as(usize, record_len)) {
                    const next_len = readU16(buf[5 + @as(usize, record_len) + 3 .. 5 + @as(usize, record_len) + 5]);
                    if (total >= 5 + @as(usize, record_len) + 5 + @as(usize, next_len)) break;
                } else break;
            }
        }
    }

    if (total < 5) return info;

    const data = buf[0..total];
    parseServerMessages(data, &info);

    return info;
}

fn parseServerMessages(data: []const u8, info: *TlsInfo) void {
    var pos: usize = 0;
    while (pos + 5 <= data.len) {
        const content_type = data[pos];
        const record_len = readU16(data[pos + 3 .. pos + 5]);
        pos += 5;

        if (pos + record_len > data.len) break;
        const payload = data[pos .. pos + record_len];

        if (content_type == 22) {
            parseHandshakeMessages(payload, info);
        }

        pos += record_len;
    }
}

fn parseHandshakeMessages(data: []const u8, info: *TlsInfo) void {
    var pos: usize = 0;
    while (pos + 4 <= data.len) {
        const hs_type = data[pos];
        const hs_len = readU24(data[pos + 1 .. pos + 4]);
        pos += 4;

        if (pos + hs_len > data.len) break;
        const payload = data[pos .. pos + hs_len];

        switch (hs_type) {
            2 => parseServerHello(payload, info),
            11 => parseCertificateMsg(payload, info),
            else => {},
        }

        pos += hs_len;
    }
}

fn parseServerHello(data: []const u8, info: *TlsInfo) void {
    if (data.len < 38) return;

    const major = data[0];
    const minor = data[1];

    const session_id_len: usize = data[34];
    const cipher_offset = 35 + session_id_len;
    if (cipher_offset + 2 > data.len) return;

    const cipher_suite: u16 = @intCast(readU16(data[cipher_offset .. cipher_offset + 2]));

    var actual_major = major;
    var actual_minor = minor;
    const ext_offset = cipher_offset + 3;
    if (ext_offset + 2 <= data.len) {
        const ext_len = readU16(data[ext_offset .. ext_offset + 2]);
        var epos: usize = ext_offset + 2;
        const ext_end = @min(epos + ext_len, data.len);
        while (epos + 4 <= ext_end) {
            const etype = readU16(data[epos .. epos + 2]);
            const elen = readU16(data[epos + 2 .. epos + 4]);
            epos += 4;
            if (etype == 0x002B and elen >= 2) {
                actual_major = data[epos];
                actual_minor = data[epos + 1];
            }
            epos += elen;
        }
    }

    const ver_str = tlsVersionName(actual_major, actual_minor);
    info.version_len = TlsInfo.setStr(&info.version_buf, ver_str);

    const cipher_name = cipherSuiteName(cipher_suite);
    info.cipher_len = TlsInfo.setStr(&info.cipher_buf, cipher_name);

    info.valid = true;
}

fn parseCertificateMsg(data: []const u8, info: *TlsInfo) void {
    if (data.len < 3) return;
    const total_len = readU24(data[0..3]);
    _ = total_len;

    var pos: usize = 3;
    if (pos + 3 > data.len) return;
    const cert_len = readU24(data[pos .. pos + 3]);
    pos += 3;

    if (pos + cert_len > data.len) return;
    const cert_der = data[pos .. pos + cert_len];

    parseCertDer(cert_der, info);
}

fn parseCertDer(der: []const u8, info: *TlsInfo) void {
    const cert_seq = derEnter(der, 0x30) orelse return;
    const tbs = derEnter(cert_seq, 0x30) orelse return;

    var pos: usize = 0;

    if (pos < tbs.len and tbs[pos] == 0xA0) {
        const inner = derSkip(tbs, pos) orelse return;
        pos = inner;
    }

    pos = derSkip(tbs, pos) orelse return;
    pos = derSkip(tbs, pos) orelse return;
    const issuer_start = pos;
    pos = derSkip(tbs, pos) orelse return;

    const issuer_data = tbs[issuer_start..pos];
    extractCn(issuer_data, &info.issuer_cn_buf, &info.issuer_cn_len);

    if (pos >= tbs.len) return;
    const validity = derSlice(tbs, pos, 0x30) orelse return;
    pos = derSkip(tbs, pos) orelse return;
    parseValidity(validity, info);

    if (pos >= tbs.len) return;
    const subject_data_end = derSkip(tbs, pos) orelse return;
    const subject_data = tbs[pos..subject_data_end];
    extractCn(subject_data, &info.subject_cn_buf, &info.cn_len);
}

fn parseValidity(data: []const u8, info: *TlsInfo) void {
    const first_end = derSkip(data, 0) orelse return;
    if (first_end >= data.len) return;

    const tag = data[first_end];
    const content = derContent(data, first_end) orelse return;

    if (tag == 0x17 and content.len >= 12) {
        var buf: [24]u8 = undefined;
        const formatted = std.fmt.bufPrint(&buf, "20{c}{c}-{c}{c}-{c}{c} {c}{c}:{c}{c}:{c}{c}Z", .{
            content[0],  content[1],
            content[2],  content[3],
            content[4],  content[5],
            content[6],  content[7],
            content[8],  content[9],
            content[10], content[11],
        }) catch return;
        info.not_after_len = TlsInfo.setStr(&info.not_after_buf, formatted);
    } else if (tag == 0x18 and content.len >= 14) {
        var buf: [24]u8 = undefined;
        const formatted = std.fmt.bufPrint(&buf, "{c}{c}{c}{c}-{c}{c}-{c}{c} {c}{c}:{c}{c}:{c}{c}Z", .{
            content[0],  content[1],  content[2],  content[3],
            content[4],  content[5],  content[6],  content[7],
            content[8],  content[9],  content[10], content[11],
            content[12], content[13],
        }) catch return;
        info.not_after_len = TlsInfo.setStr(&info.not_after_buf, formatted);
    }
}

fn extractCn(name_data: []const u8, buf: *[128]u8, len: *u8) void {
    const cn_oid = [_]u8{ 0x55, 0x04, 0x03 };
    const seq = derEnter(name_data, 0x30) orelse return;

    var pos: usize = 0;
    while (pos < seq.len) {
        if (seq[pos] != 0x31) {
            pos = derSkip(seq, pos) orelse return;
            continue;
        }
        const set_content = derSlice(seq, pos, 0x31) orelse return;
        pos = derSkip(seq, pos) orelse return;

        const attr_seq = derEnter(set_content, 0x30) orelse continue;
        if (attr_seq.len < 5) continue;

        const oid_content = derContent(attr_seq, 0) orelse continue;
        if (oid_content.len == cn_oid.len and std.mem.eql(u8, oid_content, &cn_oid)) {
            const oid_end = derSkip(attr_seq, 0) orelse continue;
            const val = derContent(attr_seq, oid_end) orelse continue;
            len.* = TlsInfo.setStr(buf, val);
            return;
        }
    }
}

fn derEnter(data: []const u8, expected_tag: u8) ?[]const u8 {
    if (data.len < 2) return null;
    if (data[0] != expected_tag) return null;
    const len_info = derReadLen(data, 1) orelse return null;
    if (len_info.offset + len_info.length > data.len) return null;
    return data[len_info.offset .. len_info.offset + len_info.length];
}

fn derSlice(data: []const u8, pos: usize, expected_tag: u8) ?[]const u8 {
    if (pos >= data.len) return null;
    if (data[pos] != expected_tag) return null;
    const len_info = derReadLen(data, pos + 1) orelse return null;
    if (len_info.offset + len_info.length > data.len) return null;
    return data[len_info.offset .. len_info.offset + len_info.length];
}

fn derContent(data: []const u8, pos: usize) ?[]const u8 {
    if (pos + 1 >= data.len) return null;
    const len_info = derReadLen(data, pos + 1) orelse return null;
    if (len_info.offset + len_info.length > data.len) return null;
    return data[len_info.offset .. len_info.offset + len_info.length];
}

fn derSkip(data: []const u8, pos: usize) ?usize {
    if (pos + 1 >= data.len) return null;
    const len_info = derReadLen(data, pos + 1) orelse return null;
    return len_info.offset + len_info.length;
}

const LenInfo = struct { offset: usize, length: usize };

fn derReadLen(data: []const u8, pos: usize) ?LenInfo {
    if (pos >= data.len) return null;
    const first = data[pos];
    if (first < 0x80) {
        return .{ .offset = pos + 1, .length = first };
    }
    const num_bytes = first & 0x7F;
    if (num_bytes == 0 or num_bytes > 3) return null;
    if (pos + 1 + num_bytes > data.len) return null;
    var length: usize = 0;
    for (0..num_bytes) |i| {
        length = (length << 8) | data[pos + 1 + i];
    }
    return .{ .offset = pos + 1 + num_bytes, .length = length };
}

fn readU16(b: []const u8) usize {
    return (@as(usize, b[0]) << 8) | @as(usize, b[1]);
}

fn readU24(b: []const u8) usize {
    return (@as(usize, b[0]) << 16) | (@as(usize, b[1]) << 8) | @as(usize, b[2]);
}

const HelloMsg = struct { data: [256]u8, len: usize };

fn buildClientHello() HelloMsg {
    var buf: [256]u8 = .{0} ** 256;
    var pos: usize = 0;

    buf[pos] = 22;
    pos += 1;
    buf[pos] = 0x03;
    buf[pos + 1] = 0x01;
    pos += 2;
    const record_len_pos = pos;
    pos += 2;

    buf[pos] = 1;
    pos += 1;
    const hs_len_pos = pos;
    pos += 3;

    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    var ts_bytes: [4]u8 = undefined;
    const ts: u32 = @truncate(@as(u64, @bitCast(std.time.milliTimestamp())));
    std.mem.writeInt(u32, &ts_bytes, ts, .big);
    @memcpy(buf[pos .. pos + 4], &ts_bytes);
    std.posix.getrandom(buf[pos + 4 .. pos + 32]) catch {};
    pos += 32;

    buf[pos] = 0;
    pos += 1;

    const cipher_suites = [_][2]u8{
        .{ 0xC0, 0x2F }, // ECDHE_RSA_AES_128_GCM_SHA256
        .{ 0xC0, 0x30 }, // ECDHE_RSA_AES_256_GCM_SHA384
        .{ 0xC0, 0x2B }, // ECDHE_ECDSA_AES_128_GCM_SHA256
        .{ 0xC0, 0x2C }, // ECDHE_ECDSA_AES_256_GCM_SHA384
        .{ 0x00, 0x9C }, // RSA_AES_128_GCM_SHA256
        .{ 0x00, 0x9D }, // RSA_AES_256_GCM_SHA384
        .{ 0x00, 0x2F }, // RSA_AES_128_CBC_SHA
        .{ 0x00, 0x35 }, // RSA_AES_256_CBC_SHA
        .{ 0x00, 0xFF }, // RENEGOTIATION_INFO_SCSV
    };
    const suites_len: u16 = cipher_suites.len * 2;
    std.mem.writeInt(u16, buf[pos..][0..2], suites_len, .big);
    pos += 2;
    for (cipher_suites) |suite| {
        buf[pos] = suite[0];
        buf[pos + 1] = suite[1];
        pos += 2;
    }

    buf[pos] = 1;
    buf[pos + 1] = 0;
    pos += 2;

    const ext_len_pos = pos;
    pos += 2;

    // Extension: supported_groups (0x000A)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x0A;
    pos += 2;
    const ec_curves = [_][2]u8{
        .{ 0x00, 0x17 }, // secp256r1
        .{ 0x00, 0x18 }, // secp384r1
        .{ 0x00, 0x19 }, // secp521r1
    };
    const curves_total: u16 = ec_curves.len * 2 + 2;
    std.mem.writeInt(u16, buf[pos..][0..2], curves_total, .big);
    pos += 2;
    const curves_list: u16 = ec_curves.len * 2;
    std.mem.writeInt(u16, buf[pos..][0..2], curves_list, .big);
    pos += 2;
    for (ec_curves) |c| {
        buf[pos] = c[0];
        buf[pos + 1] = c[1];
        pos += 2;
    }

    // Extension: ec_point_formats (0x000B)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x0B;
    pos += 2;
    buf[pos] = 0x00;
    buf[pos + 1] = 0x02;
    pos += 2;
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;

    // Extension: signature_algorithms (0x000D)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x0D;
    pos += 2;
    const sig_algs = [_][2]u8{
        .{ 0x04, 0x01 }, // rsa_pkcs1_sha256
        .{ 0x05, 0x01 }, // rsa_pkcs1_sha384
        .{ 0x06, 0x01 }, // rsa_pkcs1_sha512
        .{ 0x04, 0x03 }, // ecdsa_secp256r1_sha256
        .{ 0x05, 0x03 }, // ecdsa_secp384r1_sha384
        .{ 0x08, 0x04 }, // rsa_pss_rsae_sha256
        .{ 0x08, 0x05 }, // rsa_pss_rsae_sha384
    };
    const sigs_total: u16 = sig_algs.len * 2 + 2;
    std.mem.writeInt(u16, buf[pos..][0..2], sigs_total, .big);
    pos += 2;
    const sigs_list: u16 = sig_algs.len * 2;
    std.mem.writeInt(u16, buf[pos..][0..2], sigs_list, .big);
    pos += 2;
    for (sig_algs) |sa| {
        buf[pos] = sa[0];
        buf[pos + 1] = sa[1];
        pos += 2;
    }

    const ext_len: u16 = @intCast(pos - ext_len_pos - 2);
    std.mem.writeInt(u16, buf[ext_len_pos..][0..2], ext_len, .big);

    const hs_payload_len: u24 = @intCast(pos - hs_len_pos - 3);
    buf[hs_len_pos] = @intCast((hs_payload_len >> 16) & 0xFF);
    buf[hs_len_pos + 1] = @intCast((hs_payload_len >> 8) & 0xFF);
    buf[hs_len_pos + 2] = @intCast(hs_payload_len & 0xFF);

    const record_payload_len: u16 = @intCast(pos - record_len_pos - 2);
    std.mem.writeInt(u16, buf[record_len_pos..][0..2], record_payload_len, .big);

    return .{ .data = buf, .len = pos };
}

fn setTimeout(fd: std.posix.fd_t) void {
    const Timeval = extern struct { sec: isize, usec: isize };
    const tv = Timeval{ .sec = IO_TIMEOUT_SECS, .usec = 0 };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_RCVTIMEO, bytes) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_SNDTIMEO, bytes) catch {};
}

fn tlsVersionName(major: u8, minor: u8) []const u8 {
    if (major == 0x03) {
        return switch (minor) {
            0x00 => "SSL 3.0",
            0x01 => "TLS 1.0",
            0x02 => "TLS 1.1",
            0x03 => "TLS 1.2",
            0x04 => "TLS 1.3",
            else => "TLS unknown",
        };
    }
    return "unknown";
}

fn cipherSuiteName(suite: u16) []const u8 {
    return switch (suite) {
        0xC02F => "ECDHE-RSA-AES128-GCM-SHA256",
        0xC030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xC02B => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xC02C => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xCCA8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xCCA9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0x009C => "AES128-GCM-SHA256",
        0x009D => "AES256-GCM-SHA384",
        0x002F => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0x1301 => "TLS-AES-128-GCM-SHA256",
        0x1302 => "TLS-AES-256-GCM-SHA384",
        0x1303 => "TLS-CHACHA20-POLY1305-SHA256",
        else => "unknown",
    };
}
