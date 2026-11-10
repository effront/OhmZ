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
    san_buf: [256]u8 = .{0} ** 256,
    san_len: u16 = 0,
    alpn_buf: [16]u8 = .{0} ** 16,
    alpn_len: u8 = 0,
    tls_minor: u8 = 0,
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

    pub fn sans(self: *const TlsInfo) []const u8 {
        return self.san_buf[0..self.san_len];
    }

    pub fn alpn(self: *const TlsInfo) []const u8 {
        return self.alpn_buf[0..self.alpn_len];
    }

    fn setStr(buf: []u8, text: []const u8) u8 {
        const len: u8 = @intCast(@min(text.len, buf.len));
        @memcpy(buf[0..len], text[0..len]);
        return len;
    }

    fn setStr16(buf: []u8, text: []const u8) u16 {
        const len: u16 = @intCast(@min(text.len, buf.len));
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
        if (hasAllRecords(buf[0..total])) break;
    }

    if (total < 5) return info;

    const data = buf[0..total];
    parseServerMessages(data, &info);

    return info;
}

fn hasAllRecords(data: []const u8) bool {
    var pos: usize = 0;
    var saw_cert = false;
    while (pos + 5 <= data.len) {
        const record_len = readU16(data[pos + 3 .. pos + 5]);
        if (pos + 5 + record_len > data.len) return false;
        if (data[pos] == 22) {
            var hpos: usize = pos + 5;
            const hend = hpos + record_len;
            while (hpos + 4 <= hend) {
                const hs_type = data[hpos];
                const hs_len = readU24(data[hpos + 1 .. hpos + 4]);
                if (hs_type == 11) saw_cert = true;
                hpos += 4 + hs_len;
            }
        }
        pos += 5 + record_len;
        if (saw_cert) return true;
    }
    return false;
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
            if (etype == 0x0010 and elen >= 4) {
                const proto_start = epos + 2;
                if (proto_start < ext_end) {
                    const proto_len: usize = data[proto_start];
                    if (proto_start + 1 + proto_len <= ext_end) {
                        info.alpn_len = TlsInfo.setStr(&info.alpn_buf, data[proto_start + 1 .. proto_start + 1 + proto_len]);
                    }
                }
            }
            epos += elen;
        }
    }

    info.tls_minor = actual_minor;

    const ver_str = tlsVersionName(actual_major, actual_minor);
    info.version_len = TlsInfo.setStr(&info.version_buf, ver_str);

    const cipher_name = cipherSuiteName(cipher_suite);
    info.cipher_len = TlsInfo.setStr(&info.cipher_buf, cipher_name);

    info.valid = true;
}

fn parseCertificateMsg(data: []const u8, info: *TlsInfo) void {
    if (data.len < 3) return;

    var pos: usize = 0;

    // TLS 1.3 (minor=4): request_context length prefix before cert list
    if (info.tls_minor >= 4) {
        if (pos >= data.len) return;
        const ctx_len: usize = data[pos];
        pos += 1 + ctx_len;
    }

    if (pos + 3 > data.len) return;
    const total_len = readU24(data[pos .. pos + 3]);
    _ = total_len;
    pos += 3;

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

    // Skip subjectPublicKeyInfo
    pos = subject_data_end;
    pos = derSkip(tbs, pos) orelse return;

    // Look for extensions (context tag [3] EXPLICIT)
    while (pos < tbs.len) {
        if (tbs[pos] == 0xA3) {
            const ext_wrapper = derContent(tbs, pos) orelse break;
            const ext_seq = derEnter(ext_wrapper, 0x30) orelse break;
            extractSans(ext_seq, &info.san_buf, &info.san_len);
            break;
        }
        pos = derSkip(tbs, pos) orelse break;
    }
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

fn extractSans(extensions: []const u8, san_buf: *[256]u8, san_len: *u16) void {
    const san_oid = [_]u8{ 0x55, 0x1D, 0x11 }; // 2.5.29.17
    var pos: usize = 0;
    while (pos < extensions.len) {
        if (extensions[pos] != 0x30) {
            pos = derSkip(extensions, pos) orelse return;
            continue;
        }
        const ext_seq = derSlice(extensions, pos, 0x30) orelse return;
        pos = derSkip(extensions, pos) orelse return;

        if (ext_seq.len < 2) continue;
        const oid_data = derContent(ext_seq, 0) orelse continue;
        if (oid_data.len != san_oid.len or !std.mem.eql(u8, oid_data, &san_oid)) continue;

        // Found SAN extension - get the OCTET STRING value
        var epos = derSkip(ext_seq, 0) orelse continue;
        // Skip optional BOOLEAN (critical flag)
        if (epos < ext_seq.len and ext_seq[epos] == 0x01) {
            epos = derSkip(ext_seq, epos) orelse continue;
        }
        const octet = derSlice(ext_seq, epos, 0x04) orelse continue;
        const names_seq = derEnter(octet, 0x30) orelse continue;

        var npos: usize = 0;
        var slen: usize = 0;
        while (npos < names_seq.len) {
            const tag = names_seq[npos];
            const li = derReadLen(names_seq, npos + 1) orelse break;
            if (li.offset + li.length > names_seq.len) break;
            const val = names_seq[li.offset .. li.offset + li.length];

            // tag 0x82 = dNSName (context [2] IMPLICIT)
            if (tag == 0x82 and val.len > 0) {
                if (slen > 0 and slen + 1 < san_buf.len) {
                    san_buf[slen] = ',';
                    slen += 1;
                }
                const copy_len = @min(val.len, san_buf.len - slen);
                @memcpy(san_buf[slen .. slen + copy_len], val[0..copy_len]);
                slen += copy_len;
            }
            npos = li.offset + li.length;
        }
        san_len.* = @intCast(@min(slen, san_buf.len));
        return;
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

const HelloMsg = struct { data: [384]u8, len: usize };

fn buildClientHello() HelloMsg {
    var buf: [384]u8 = .{0} ** 384;
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
        .{ 0x13, 0x01 }, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
        .{ 0x13, 0x02 }, // TLS_AES_256_GCM_SHA384 (TLS 1.3)
        .{ 0x13, 0x03 }, // TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
        .{ 0xC0, 0x2F }, // ECDHE_RSA_AES_128_GCM_SHA256
        .{ 0xC0, 0x30 }, // ECDHE_RSA_AES_256_GCM_SHA384
        .{ 0xC0, 0x2B }, // ECDHE_ECDSA_AES_128_GCM_SHA256
        .{ 0xC0, 0x2C }, // ECDHE_ECDSA_AES_256_GCM_SHA384
        .{ 0xCC, 0xA8 }, // ECDHE_RSA_CHACHA20_POLY1305
        .{ 0xCC, 0xA9 }, // ECDHE_ECDSA_CHACHA20_POLY1305
        .{ 0x00, 0x9C }, // RSA_AES_128_GCM_SHA256
        .{ 0x00, 0x9D }, // RSA_AES_256_GCM_SHA384
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

    // Extension: ALPN (0x0010) - advertise h2 and http/1.1
    buf[pos] = 0x00;
    buf[pos + 1] = 0x10;
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 14, .big);
    pos += 2; // extension data length
    std.mem.writeInt(u16, buf[pos..][0..2], 12, .big);
    pos += 2; // protocol list length
    buf[pos] = 2;
    pos += 1;
    @memcpy(buf[pos .. pos + 2], "h2");
    pos += 2;
    buf[pos] = 8;
    pos += 1;
    @memcpy(buf[pos .. pos + 8], "http/1.1");
    pos += 8;

    // Extension: supported_versions (0x002B) - offer TLS 1.3 + 1.2
    buf[pos] = 0x00;
    buf[pos + 1] = 0x2B;
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 5, .big);
    pos += 2; // extension data length
    buf[pos] = 4;
    pos += 1; // supported versions list length
    buf[pos] = 0x03;
    buf[pos + 1] = 0x04;
    pos += 2; // TLS 1.3
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2; // TLS 1.2

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "tlsVersionName" {
    try std.testing.expectEqualStrings("TLS 1.3", tlsVersionName(0x03, 0x04));
    try std.testing.expectEqualStrings("TLS 1.2", tlsVersionName(0x03, 0x03));
    try std.testing.expectEqualStrings("TLS 1.0", tlsVersionName(0x03, 0x01));
    try std.testing.expectEqualStrings("SSL 3.0", tlsVersionName(0x03, 0x00));
    try std.testing.expectEqualStrings("unknown", tlsVersionName(0x02, 0x00));
}

test "cipherSuiteName - known suites" {
    try std.testing.expectEqualStrings("TLS-AES-128-GCM-SHA256", cipherSuiteName(0x1301));
    try std.testing.expectEqualStrings("ECDHE-RSA-AES128-GCM-SHA256", cipherSuiteName(0xC02F));
    try std.testing.expectEqualStrings("unknown", cipherSuiteName(0xFFFF));
}

test "derReadLen - short form" {
    const data = [_]u8{ 0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const info = derReadLen(&data, 1);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(usize, 2), info.?.offset);
    try std.testing.expectEqual(@as(usize, 5), info.?.length);
}

test "derReadLen - long form 1 byte" {
    const data = [_]u8{ 0x30, 0x81, 0x80 } ++ ([_]u8{0} ** 128);
    const info = derReadLen(&data, 1);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(usize, 3), info.?.offset);
    try std.testing.expectEqual(@as(usize, 128), info.?.length);
}

test "buildClientHello - valid TLS record" {
    const hello = buildClientHello();
    try std.testing.expectEqual(@as(u8, 22), hello.data[0]); // handshake
    try std.testing.expectEqual(@as(u8, 0x03), hello.data[1]); // major
    try std.testing.expectEqual(@as(u8, 0x01), hello.data[2]); // minor (compat)
    try std.testing.expectEqual(@as(u8, 1), hello.data[5]); // ClientHello type
    try std.testing.expect(hello.len > 100);
    try std.testing.expect(hello.len < 384);
}

test "TlsInfo - setStr truncates" {
    var buf: [8]u8 = .{0} ** 8;
    const len = TlsInfo.setStr(&buf, "abcdefghijklmnop");
    try std.testing.expectEqual(@as(u8, 8), len);
    try std.testing.expectEqualStrings("abcdefgh", buf[0..len]);
}

test "TlsInfo - defaults" {
    const info = TlsInfo{};
    try std.testing.expect(!info.valid);
    try std.testing.expectEqual(@as(u8, 0), info.version_len);
    try std.testing.expectEqual(@as(u16, 0), info.san_len);
    try std.testing.expectEqual(@as(u8, 0), info.alpn_len);
}
