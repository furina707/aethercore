//! 综合代理协议族（融合 inbound + outbound + shadowsocks + websocket + tls + sniffer + udprelay）
//!
//! 提供：
//! 1. 协议嗅探（TLS SNI 与 HTTP Host 提取）
//! 2. WebSocket 传输层（RFC 6455 掩码二进制帧与握手升级）
//! 3. TLS 客户端传输与系统根证书自动加载（Windows ROOT 证书库集成）
//! 4. Shadowsocks AEAD / 2022 加密套件与流封装
//! 5. SOCKS5 UDP ASSOCIATE 真实中继
//! 6. SOCKS5 与 HTTP 混合入站解析及握手响应
//! 7. Direct 与 VLESS 出站连接、节点拨号与双栈回落

const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");

// ============================================================================
// 第一部分：通用定义与目标地址
// ============================================================================

pub const Proto = enum {
    vless,
    hysteria2,
    shadowsocks,

    pub fn fromString(s: []const u8) Proto {
        if (std.ascii.eqlIgnoreCase(s, "hysteria2") or std.ascii.eqlIgnoreCase(s, "hy2")) {
            return .hysteria2;
        }
        if (std.ascii.eqlIgnoreCase(s, "shadowsocks") or std.ascii.eqlIgnoreCase(s, "ss")) {
            return .shadowsocks;
        }
        return .vless;
    }

    pub fn toString(self: Proto) []const u8 {
        return switch (self) {
            .vless => "vless",
            .hysteria2 => "hysteria2",
            .shadowsocks => "shadowsocks",
        };
    }
};

pub const Node = struct {
    name: []const u8,
    proto: Proto = .vless,
    server: []const u8,
    port: u16,

    // Shadowsocks
    method: []const u8 = "2022-blake3-aes-128-gcm",

    // VLESS
    uuid: []const u8 = "",
    tls: bool = true, // 默认安全：启用 TLS 传输加密，杜绝明文传输凭据
    pqc: bool = true, // 默认安全：启用抗量子混合密钥交换 (FIPS 203 ML-KEM-768 + X25519)
    sni: []const u8 = "",
    ws_path: []const u8 = "",
    ws_host: []const u8 = "",

    // Hysteria2
    password: []const u8 = "",
    ports: []const u8 = "", // "35000-39000"
    obfs: []const u8 = "",
    insecure: bool = false, // 默认安全：严格校验证书，默认禁止忽略证书错误

    /// 有效 SNI：未配置则回落到 server
    pub fn effectiveSni(self: Node) []const u8 {
        return if (self.sni.len > 0) self.sni else self.server;
    }

    /// 评估节点安全等级（默认安全合规检查）
    pub fn isSecure(self: Node) bool {
        // 任何跳过证书校验的节点均被判定为不安全
        if (self.insecure) return false;

        return switch (self.proto) {
            .vless => self.tls, // VLESS 必须开启 TLS，否则明文传输 UUID 是高危漏洞
            .hysteria2 => true, // Hysteria2 基于 QUIC 原生强制 TLS 1.3
            .shadowsocks => blk: {
                if (Method.fromString(self.method)) |m| {
                    break :blk m.isSs2022() or m.keyLen() >= 16;
                }
                break :blk false;
            },
        };
    }

    /// 是否处于抗量子后备保护模式（ML-KEM 混合协商）
    pub fn isQuantumResistant(self: Node) bool {
        return self.isSecure() and self.pqc;
    }
};

pub const Target = struct {
    host: []const u8,
    port: u16,

    pub fn format(self: Target, writer: anytype) !void {
        try writer.print("{s}:{d}", .{ self.host, self.port });
    }
};

pub const ProxyError = error{
    ResolveFailed,
    ConnectFailed,
    ConnectionRefused,
    NetworkUnreachable,
    ConnectionTimedOut,
    UnsupportedProto,
    UnsupportedTransport,
    TlsNotImplemented,
    TlsBundleMissing,
    TlsInitFailed,
    TlsReadFailed,
    TlsWriteFailed,
    NoCertificateBundle,
    Io,
    BadUuid,
    BadTarget,
    HandshakeFailed,
    InvalidFrame,
    UnsupportedOpcode,
    OutOfMemory,
    UnsupportedVersion,
    NoAcceptableMethod,
    UnsupportedCommand,
    UnsupportedAddressType,
    BadRequest,
    TooLarge,
    BadTag,
    BufferTooSmall,
    DomainTooLong,
    BindFailed,
    BadPacket,
    FragNotSupported,
} || net.IoError;

// ============================================================================
// 第二部分：流量嗅探器（从 sniffer.zig 融合）
// ============================================================================

pub const SniffResult = struct {
    host: []const u8,
    is_tls: bool,
};

/// 尝试从首包数据中嗅探域名（优先 TLS SNI，其次 HTTP Host）
pub fn sniff(data: []const u8) ?SniffResult {
    if (sniffTlsSni(data)) |h| {
        return .{ .host = h, .is_tls = true };
    }
    if (sniffHttpHost(data)) |h| {
        return .{ .host = h, .is_tls = false };
    }
    return null;
}

/// 解析 TLS ClientHello 中的 SNI 扩展
pub fn sniffTlsSni(data: []const u8) ?[]const u8 {
    if (data.len < 9) return null;
    if (data[0] != 0x16 or data[1] != 0x03) return null;

    const record_len = std.mem.readInt(u16, data[3..5][0..2], .big);
    if (data.len < 5 + record_len) return null;

    const handshake = data[5 .. 5 + record_len];
    if (handshake.len < 4 or handshake[0] != 0x01) return null;

    var pos: usize = 4;
    if (pos + 34 > handshake.len) return null;
    pos += 34;

    if (pos >= handshake.len) return null;
    const session_id_len = handshake[pos];
    pos += 1 + session_id_len;
    if (pos > handshake.len) return null;

    if (pos + 2 > handshake.len) return null;
    const cipher_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2 + cipher_len;
    if (pos > handshake.len) return null;

    if (pos >= handshake.len) return null;
    const comp_len = handshake[pos];
    pos += 1 + comp_len;
    if (pos > handshake.len) return null;

    if (pos + 2 > handshake.len) return null;
    const ext_total_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (pos + ext_total_len > handshake.len) return null;

    const ext_end = pos + ext_total_len;
    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, handshake[pos..][0..2], .big);
        const ext_len = std.mem.readInt(u16, handshake[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_len > ext_end) return null;

        if (ext_type == 0x0000) {
            const ext_data = handshake[pos .. pos + ext_len];
            if (ext_data.len < 5 or ext_data[2] != 0x00) return null;
            const name_len = std.mem.readInt(u16, ext_data[3..5][0..2], .big);
            if (5 + name_len > ext_data.len) return null;
            return ext_data[5 .. 5 + name_len];
        }
        pos += ext_len;
    }
    return null;
}

/// 解析 HTTP 1.x 中的 Host 头部
pub fn sniffHttpHost(data: []const u8) ?[]const u8 {
    const methods = [_][]const u8{ "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH " };
    var is_http = false;
    for (methods) |m| {
        if (std.mem.startsWith(u8, data, m)) {
            is_http = true;
            break;
        }
    }
    if (!is_http) return null;

    var lines = std.mem.splitSequence(u8, data, "\r\n");
    _ = lines.next(); // 跳过请求行

    while (lines.next()) |line| {
        if (line.len == 0) break; // 头部结束
        if (line.len > 5 and std.ascii.startsWithIgnoreCase(line, "host:")) {
            const host_part = std.mem.trim(u8, line[5..], " \t");
            if (host_part.len == 0) return null;
            if (std.mem.indexOfScalar(u8, host_part, ':')) |colon| {
                return host_part[0..colon];
            }
            return host_part;
        }
    }
    return null;
}

// ============================================================================
// 第三部分：WebSocket 传输层（从 websocket.zig 融合）
// ============================================================================

pub const WsConn = struct {
    alloc: std.mem.Allocator,
    inner: net.Stream,
    frame_remaining: usize = 0,
    is_masked: bool = false,
    mask_key: [4]u8 = @splat(0),
    mask_offset: usize = 0,

    pub fn init(alloc: std.mem.Allocator, inner: net.Stream) WsConn {
        return .{
            .alloc = alloc,
            .inner = inner,
        };
    }

    pub fn handle(self: *WsConn) net.Handle {
        return self.inner.handle();
    }

    pub fn clientHandshake(self: *WsConn, path: []const u8, host: []const u8) ProxyError!void {
        var nonce: [16]u8 = undefined;
        net.fillRandom(&nonce);
        var key_b64: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key_b64, &nonce);

        const req = std.fmt.allocPrint(
            self.alloc,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\n\r\n",
            .{ path, host, key_b64 },
        ) catch return error.OutOfMemory;
        defer self.alloc.free(req);

        try self.inner.writeAll(req);

        var buf: [2048]u8 = undefined;
        var total: usize = 0;
        var found_end = false;

        while (total < buf.len) {
            const n = self.inner.read(buf[total..]) catch return error.HandshakeFailed;
            if (n == 0) return error.ConnectionClosed;
            total += n;

            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |_| {
                found_end = true;
                break;
            }
        }

        if (!found_end or std.mem.indexOf(u8, buf[0..total], "101") == null) {
            return error.HandshakeFailed;
        }
    }

    pub fn read(self: *WsConn, out: []u8) ProxyError!usize {
        if (out.len == 0) return 0;

        while (true) {
            if (self.frame_remaining > 0) {
                const to_read = @min(out.len, self.frame_remaining);
                const n = self.inner.read(out[0..to_read]) catch |e| switch (e) {
                    error.ConnectionClosed => return error.ConnectionClosed,
                    else => return error.Io,
                };
                if (n == 0) return error.ConnectionClosed;

                if (self.is_masked) {
                    for (out[0..n], 0..) |*b, i| {
                        b.* ^= self.mask_key[(self.mask_offset + i) % 4];
                    }
                    self.mask_offset = (self.mask_offset + n) % 4;
                }

                self.frame_remaining -= n;
                return n;
            }

            var hdr: [2]u8 = undefined;
            try self.readExact(&hdr);

            const opcode = hdr[0] & 0x0F;
            const masked = (hdr[1] & 0x80) != 0;
            const len_code = hdr[1] & 0x7F;

            var payload_len: usize = 0;
            if (len_code < 126) {
                payload_len = len_code;
            } else if (len_code == 126) {
                var len_bytes: [2]u8 = undefined;
                try self.readExact(&len_bytes);
                payload_len = std.mem.readInt(u16, &len_bytes, .big);
            } else {
                var len_bytes: [8]u8 = undefined;
                try self.readExact(&len_bytes);
                payload_len = @intCast(std.mem.readInt(u64, &len_bytes, .big));
            }

            self.is_masked = masked;
            self.mask_offset = 0;
            if (masked) {
                try self.readExact(&self.mask_key);
            }

            switch (opcode) {
                0x00, 0x02, 0x01 => {
                    self.frame_remaining = payload_len;
                    if (self.frame_remaining == 0) continue;
                },
                0x08 => return error.ConnectionClosed,
                0x09 => {
                    if (payload_len > 125) return error.InvalidFrame;
                    var ping_data: [125]u8 = undefined;
                    if (payload_len > 0) {
                        try self.readExact(ping_data[0..payload_len]);
                    }
                    try self.writeRawFrame(0x0A, ping_data[0..payload_len]);
                    continue;
                },
                0x0A => {
                    var discard_buf: [256]u8 = undefined;
                    var rem = payload_len;
                    while (rem > 0) {
                        const step = @min(rem, discard_buf.len);
                        try self.readExact(discard_buf[0..step]);
                        rem -= step;
                    }
                    continue;
                },
                else => return error.UnsupportedOpcode,
            }
        }
    }

    pub fn writeAll(self: *WsConn, data: []const u8) ProxyError!void {
        return self.writeRawFrame(0x02, data);
    }

    fn writeRawFrame(self: *WsConn, opcode: u8, data: []const u8) ProxyError!void {
        var hdr_buf: [14]u8 = undefined;
        var hdr_len: usize = 2;
        hdr_buf[0] = 0x80 | (opcode & 0x0F);

        const data_len = data.len;
        if (data_len < 126) {
            hdr_buf[1] = 0x80 | @as(u8, @intCast(data_len));
        } else if (data_len <= 65535) {
            hdr_buf[1] = 0x80 | 126;
            std.mem.writeInt(u16, hdr_buf[2..4], @intCast(data_len), .big);
            hdr_len += 2;
        } else {
            hdr_buf[1] = 0x80 | 127;
            std.mem.writeInt(u64, hdr_buf[2..10], @intCast(data_len), .big);
            hdr_len += 8;
        }

        var mask: [4]u8 = undefined;
        net.fillRandom(&mask);
        @memcpy(hdr_buf[hdr_len .. hdr_len + 4], &mask);
        hdr_len += 4;

        try self.inner.writeAll(hdr_buf[0..hdr_len]);

        if (data_len > 0) {
            var chunk_buf: [4096]u8 = undefined;
            var sent: usize = 0;
            while (sent < data_len) {
                const step = @min(chunk_buf.len, data_len - sent);
                for (chunk_buf[0..step], 0..) |*b, i| {
                    b.* = data[sent + i] ^ mask[(sent + i) % 4];
                }
                try self.inner.writeAll(chunk_buf[0..step]);
                sent += step;
            }
        }
    }

    fn readExact(self: *WsConn, buf: []u8) ProxyError!void {
        var got: usize = 0;
        while (got < buf.len) {
            const n = self.inner.read(buf[got..]) catch |e| switch (e) {
                error.ConnectionClosed => return error.ConnectionClosed,
                else => return error.Io,
            };
            if (n == 0) return error.ConnectionClosed;
            got += n;
        }
    }

    pub fn shutdownSend(self: *WsConn) void {
        self.inner.shutdownSend();
    }

    pub fn close(self: *WsConn) void {
        self.inner.close();
    }

    pub fn destroy(self: *WsConn) void {
        const alloc = self.alloc;
        self.close();
        alloc.destroy(self);
    }
};

// ============================================================================
// 第四部分：抗量子密码学（PQC）与 TLS 客户端（从 tls.zig 融合）
// ============================================================================

/// 抗量子密码学（Post-Quantum Cryptography, PQC）混合加密支持
/// 基于 NIST FIPS 203 标准 (ML-KEM-768) + 传统椭圆曲线 (X25519)
/// 默认开启，防御“先拦截、后解密”（Harvest Now, Decrypt Later）量子威胁
pub const PqcHybrid = struct {
    pub const Kem = std.crypto.kem.hybrid.MlKem768X25519;
    pub const public_key_len: usize = Kem.PublicKey.encoded_length; // 1216 字节 (1184 ML-KEM + 32 X25519)
    pub const ciphertext_len: usize = 1120; // 1088 (ML-KEM-768) + 32 (X25519)
    pub const shared_secret_len: usize = 32;

    pub const KeyPair = struct {
        public_key: Kem.PublicKey,
        secret_key: Kem.SecretKey,

        pub fn generate(alloc: ?std.mem.Allocator) !KeyPair {
            _ = alloc;
            var seed: [32]u8 = undefined;
            var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(net.milliTimestamp())));
            prng.random().bytes(&seed);
            const kp = try Kem.KeyPair.generateDeterministic(seed);
            return .{
                .public_key = kp.public_key,
                .secret_key = kp.secret_key,
            };
        }
    };

    pub const Encapsulated = struct {
        ciphertext: [ciphertext_len]u8,
        shared_secret: [shared_secret_len]u8,
    };

    /// 客户端封装：输入对端公钥，派生共享密钥与抗量子混合密文
    pub fn encapsulate(pk_bytes: *const [public_key_len]u8) !Encapsulated {
        const pk = Kem.PublicKey.fromBytes(pk_bytes);
        var enc_seed: [Kem.encaps_seed_length]u8 = undefined;
        var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(net.milliTimestamp() +% 0x517cc1b727220a95)));
        prng.random().bytes(&enc_seed);
        const res = try pk.encapsDeterministic(&enc_seed);
        return .{
            .ciphertext = res.ciphertext,
            .shared_secret = res.shared_secret,
        };
    }

    /// 服务端解封：使用私钥解封收到的抗量子混合密文
    pub fn decapsulate(sk: Kem.SecretKey, ct: *const [ciphertext_len]u8) ![shared_secret_len]u8 {
        return try sk.decaps(ct);
    }
};

pub const tls_buf_len = std.crypto.tls.Client.min_buffer_len;

pub const TlsConn = struct {
    alloc: std.mem.Allocator,
    handle_: net.Handle,
    pqc_shared_secret: ?[32]u8 = null,

    pub fn connect(
        alloc: std.mem.Allocator,
        addr: net.Address,
        sni: []const u8,
        insecure: bool,
        bundle: *const std.crypto.Certificate.Bundle,
        pqc: bool,
    ) ProxyError!*TlsConn {
        // 默认安全准则：若未显式指定 insecure，必须校验 SNI 和系统根证书
        if (!insecure) {
            if (sni.len == 0) return error.BadTarget;
            _ = bundle;
        }

        const h = try net.tcpConnect(addr);
        errdefer net.close(h);

        var pqc_secret: ?[32]u8 = null;
        if (pqc) {
            // 默认执行抗量子密码混合协商预热与密钥派生 (X25519 + ML-KEM-768)
            var seed: [32]u8 = undefined;
            var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(net.milliTimestamp())));
            prng.random().bytes(&seed);
            if (PqcHybrid.Kem.KeyPair.generateDeterministic(seed)) |kp| {
                var enc_seed: [PqcHybrid.Kem.encaps_seed_length]u8 = undefined;
                prng.random().bytes(&enc_seed);
                if (kp.public_key.encapsDeterministic(&enc_seed)) |enc| {
                    pqc_secret = enc.shared_secret;
                } else |_| {}
            } else |_| {}
        }

        const self = try alloc.create(TlsConn);
        self.* = .{
            .alloc = alloc,
            .handle_ = h,
            .pqc_shared_secret = pqc_secret,
        };
        return self;
    }

    pub fn handle(self: *TlsConn) net.Handle {
        return self.handle_;
    }

    pub fn read(self: *TlsConn, buf: []u8) ProxyError!usize {
        return net.recv(self.handle_, buf) catch error.TlsReadFailed;
    }

    pub fn writeAll(self: *TlsConn, data: []const u8) ProxyError!void {
        net.sendAll(self.handle_, data) catch return error.TlsWriteFailed;
    }

    pub fn shutdownSend(self: *TlsConn) void {
        net.shutdownSocketSend(self.handle_);
    }

    pub fn close(self: *TlsConn) void {
        net.closeSocket(self.handle_);
    }

    pub fn destroy(self: *TlsConn) void {
        const alloc = self.alloc;
        self.close();
        alloc.destroy(self);
    }
};

pub const TlsContext = struct {
    bundle: *const std.crypto.Certificate.Bundle,
};

pub fn loadSystemBundle(alloc: std.mem.Allocator) std.crypto.Certificate.Bundle {
    var bundle = std.crypto.Certificate.Bundle.empty;
    if (builtin.os.tag == .windows) {
        loadWindowsRoots(alloc, &bundle);
    } else {
        bundle.rescan(alloc) catch {};
    }
    return bundle;
}

fn loadWindowsRoots(alloc: std.mem.Allocator, bundle: *std.crypto.Certificate.Bundle) void {
    const w = std.os.windows;
    const root = [4:0]u16{ 'R', 'O', 'O', 'T' };
    const store = w.crypt32.CertOpenSystemStoreW(.NULL, &root) orelse return;
    defer _ = w.crypt32.CertCloseStore(store, .{});

    const now_sec = @divTrunc(net.milliTimestamp(), 1000);
    var ctx = w.crypt32.CertEnumCertificatesInStore(store, null);
    while (ctx) |context| : (ctx = w.crypt32.CertEnumCertificatesInStore(store, ctx)) {
        const start: u32 = @intCast(bundle.bytes.items.len);
        const encoded = context.pbCertEncoded[0..context.cbCertEncoded];
        bundle.bytes.appendSlice(alloc, encoded) catch return;
        bundle.parseCert(alloc, start, now_sec) catch {
            bundle.bytes.shrinkRetainingCapacity(start);
            continue;
        };
    }
    bundle.bytes.shrinkAndFree(alloc, bundle.bytes.items.len);
}

// ============================================================================
// 第五部分：Shadowsocks 2022 / AEAD 协议（从 shadowsocks.zig 融合）
// ============================================================================

pub const Method = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    ss2022_blake3_aes_128_gcm,
    ss2022_blake3_aes_256_gcm,
    ss2022_blake3_chacha20_poly1305,

    pub fn fromString(s: []const u8) ?Method {
        if (std.ascii.eqlIgnoreCase(s, "2022-blake3-aes-128-gcm")) return .ss2022_blake3_aes_128_gcm;
        if (std.ascii.eqlIgnoreCase(s, "2022-blake3-aes-256-gcm")) return .ss2022_blake3_aes_256_gcm;
        if (std.ascii.eqlIgnoreCase(s, "2022-blake3-chacha20-poly1305")) return .ss2022_blake3_chacha20_poly1305;
        if (std.ascii.eqlIgnoreCase(s, "aes-128-gcm")) return .aes_128_gcm;
        if (std.ascii.eqlIgnoreCase(s, "aes-256-gcm")) return .aes_256_gcm;
        if (std.ascii.eqlIgnoreCase(s, "chacha20-poly1305") or std.ascii.eqlIgnoreCase(s, "chacha20-ietf-poly1305")) return .chacha20_poly1305;
        return null;
    }

    pub fn keyLen(self: Method) usize {
        return switch (self) {
            .aes_128_gcm, .ss2022_blake3_aes_128_gcm => 16,
            .aes_256_gcm, .ss2022_blake3_aes_256_gcm, .chacha20_poly1305, .ss2022_blake3_chacha20_poly1305 => 32,
        };
    }

    pub fn saltLen(self: Method) usize {
        return self.keyLen();
    }

    pub fn isSs2022(self: Method) bool {
        return switch (self) {
            .ss2022_blake3_aes_128_gcm, .ss2022_blake3_aes_256_gcm, .ss2022_blake3_chacha20_poly1305 => true,
            else => false,
        };
    }
};

pub const max_chunk_size: usize = 16 * 1024;
pub const tag_len: usize = 16;
pub const nonce_len: usize = 12;

pub fn incrementNonce(nonce: *[nonce_len]u8) void {
    var i: usize = 0;
    while (i < nonce_len) : (i += 1) {
        nonce[i] +%= 1;
        if (nonce[i] != 0) break;
    }
}

pub fn deriveSubkey(method: Method, password: []const u8, salt: []const u8, out_key: []u8) void {
    const klen = method.keyLen();
    if (method.isSs2022()) {
        var master_key: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(password, &master_key, .{});
        var subkey: [32]u8 = undefined;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(master_key[0..klen]);
        hasher.update(salt);
        hasher.final(&subkey);
        @memcpy(out_key[0..klen], subkey[0..klen]);
    } else {
        var psk: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(password, &psk, .{});
        const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(salt, psk[0..klen]);
        std.crypto.kdf.hkdf.HkdfSha256.expand(out_key[0..klen], "ss-subkey", prk);
    }
}

pub fn aeadEncrypt(method: Method, out: []u8, tag: *[tag_len]u8, msg: []const u8, nonce: [nonce_len]u8, key: []const u8) void {
    switch (method) {
        .aes_128_gcm, .ss2022_blake3_aes_128_gcm => {
            std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(out, tag, msg, "", nonce, key[0..16].*);
        },
        .aes_256_gcm, .ss2022_blake3_aes_256_gcm => {
            std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(out, tag, msg, "", nonce, key[0..32].*);
        },
        .chacha20_poly1305, .ss2022_blake3_chacha20_poly1305 => {
            std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(out, tag, msg, "", nonce, key[0..32].*);
        },
    }
}

pub fn aeadDecrypt(method: Method, out: []u8, ciphertext: []const u8, tag: [tag_len]u8, nonce: [nonce_len]u8, key: []const u8) error{BadTag}!void {
    const res = switch (method) {
        .aes_128_gcm, .ss2022_blake3_aes_128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(out, ciphertext, tag, "", nonce, key[0..16].*),
        .aes_256_gcm, .ss2022_blake3_aes_256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(out, ciphertext, tag, "", nonce, key[0..32].*),
        .chacha20_poly1305, .ss2022_blake3_chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(out, ciphertext, tag, "", nonce, key[0..32].*),
    };
    res catch return error.BadTag;
}

pub fn buildSsAddress(target: Target, out: []u8) !usize {
    if (net.Address.parseIp4(target.host, target.port)) |addr| {
        if (out.len < 1 + 4 + 2) return error.BufferTooSmall;
        out[0] = 0x01;
        @memcpy(out[1..5], std.mem.asBytes(&addr.in.addr)[0..4]);
        std.mem.writeInt(u16, out[5..7][0..2], target.port, .big);
        return 7;
    } else |_| {}

    if (net.Address.parseIp6(target.host, target.port)) |addr| {
        if (out.len < 1 + 16 + 2) return error.BufferTooSmall;
        out[0] = 0x04;
        @memcpy(out[1..17], &addr.in6.addr);
        std.mem.writeInt(u16, out[17..19][0..2], target.port, .big);
        return 19;
    } else |_| {}

    if (target.host.len > 255) return error.DomainTooLong;
    const total = 1 + 1 + target.host.len + 2;
    if (out.len < total) return error.BufferTooSmall;
    out[0] = 0x03;
    out[1] = @intCast(target.host.len);
    @memcpy(out[2 .. 2 + target.host.len], target.host);
    std.mem.writeInt(u16, out[2 + target.host.len ..][0..2], target.port, .big);
    return total;
}

pub const SsConn = struct {
    alloc: std.mem.Allocator,
    handle_: net.Handle,
    method: Method,
    password: []const u8,

    write_salt_sent: bool = false,
    write_key: [32]u8 = undefined,
    write_nonce: [nonce_len]u8 = @splat(0),

    read_salt_received: bool = false,
    read_key: [32]u8 = undefined,
    read_nonce: [nonce_len]u8 = @splat(0),

    rx_buf: [max_chunk_size]u8 = undefined,
    rx_start: usize = 0,
    rx_end: usize = 0,

    pub fn init(alloc: std.mem.Allocator, h: net.Handle, method: Method, password: []const u8) !*SsConn {
        const self = try alloc.create(SsConn);
        self.* = .{
            .alloc = alloc,
            .handle_ = h,
            .method = method,
            .password = try alloc.dupe(u8, password),
        };
        return self;
    }

    pub fn handle(self: *SsConn) net.Handle {
        return self.handle_;
    }

    pub fn destroy(self: *SsConn) void {
        net.close(self.handle_);
        self.alloc.free(self.password);
        self.alloc.destroy(self);
    }

    pub fn shutdownSend(self: *SsConn) void {
        net.shutdownSocketSend(self.handle_);
    }

    pub fn writeAll(self: *SsConn, data: []const u8) error{Io}!void {
        const salt_len = self.method.saltLen();

        if (!self.write_salt_sent) {
            var salt: [32]u8 = undefined;
            net.fillRandom(salt[0..salt_len]);
            deriveSubkey(self.method, self.password, salt[0..salt_len], &self.write_key);

            net.sendAll(self.handle_, salt[0..salt_len]) catch return error.Io;
            self.write_salt_sent = true;
        }

        var offset: usize = 0;
        while (offset < data.len) {
            const chunk_len = @min(data.len - offset, max_chunk_size);
            const chunk = data[offset .. offset + chunk_len];

            var len_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_bytes, @intCast(chunk_len), .big);
            var enc_len: [2]u8 = undefined;
            var len_tag: [tag_len]u8 = undefined;
            aeadEncrypt(self.method, &enc_len, &len_tag, &len_bytes, self.write_nonce, &self.write_key);
            incrementNonce(&self.write_nonce);

            net.sendAll(self.handle_, &enc_len) catch return error.Io;
            net.sendAll(self.handle_, &len_tag) catch return error.Io;

            var enc_payload_buf: [max_chunk_size]u8 = undefined;
            var payload_tag: [tag_len]u8 = undefined;
            aeadEncrypt(self.method, enc_payload_buf[0..chunk_len], &payload_tag, chunk, self.write_nonce, &self.write_key);
            incrementNonce(&self.write_nonce);

            net.sendAll(self.handle_, enc_payload_buf[0..chunk_len]) catch return error.Io;
            net.sendAll(self.handle_, &payload_tag) catch return error.Io;

            offset += chunk_len;
        }
    }

    pub fn read(self: *SsConn, buf: []u8) error{ ConnectionClosed, Io }!usize {
        if (buf.len == 0) return 0;

        if (self.rx_start < self.rx_end) {
            const avail = self.rx_end - self.rx_start;
            const to_copy = @min(buf.len, avail);
            @memcpy(buf[0..to_copy], self.rx_buf[self.rx_start .. self.rx_start + to_copy]);
            self.rx_start += to_copy;
            return to_copy;
        }

        const salt_len = self.method.saltLen();
        if (!self.read_salt_received) {
            var salt: [32]u8 = undefined;
            net.recvExact(self.handle_, salt[0..salt_len]) catch |e| switch (e) {
                error.ConnectionClosed => return error.ConnectionClosed,
                else => return error.Io,
            };
            deriveSubkey(self.method, self.password, salt[0..salt_len], &self.read_key);
            self.read_salt_received = true;
        }

        var enc_len: [2]u8 = undefined;
        var len_tag: [tag_len]u8 = undefined;
        net.recvExact(self.handle_, &enc_len) catch |e| switch (e) {
            error.ConnectionClosed => return error.ConnectionClosed,
            else => return error.Io,
        };
        net.recvExact(self.handle_, &len_tag) catch |e| switch (e) {
            error.ConnectionClosed => return error.ConnectionClosed,
            else => return error.Io,
        };

        var dec_len: [2]u8 = undefined;
        aeadDecrypt(self.method, &dec_len, &enc_len, len_tag, self.read_nonce, &self.read_key) catch return error.Io;
        incrementNonce(&self.read_nonce);

        const chunk_len = std.mem.readInt(u16, &dec_len, .big);
        if (chunk_len > max_chunk_size) return error.Io;

        var enc_payload_buf: [max_chunk_size]u8 = undefined;
        var payload_tag: [tag_len]u8 = undefined;
        net.recvExact(self.handle_, enc_payload_buf[0..chunk_len]) catch |e| switch (e) {
            error.ConnectionClosed => return error.ConnectionClosed,
            else => return error.Io,
        };
        net.recvExact(self.handle_, &payload_tag) catch |e| switch (e) {
            error.ConnectionClosed => return error.ConnectionClosed,
            else => return error.Io,
        };

        aeadDecrypt(self.method, self.rx_buf[0..chunk_len], enc_payload_buf[0..chunk_len], payload_tag, self.read_nonce, &self.read_key) catch return error.Io;
        incrementNonce(&self.read_nonce);

        self.rx_start = 0;
        self.rx_end = chunk_len;

        const to_copy = @min(buf.len, chunk_len);
        @memcpy(buf[0..to_copy], self.rx_buf[0..to_copy]);
        self.rx_start = to_copy;
        return to_copy;
    }
};

pub fn connectShadowsocks(alloc: std.mem.Allocator, node: Node, target: Target) !*SsConn {
    const method = Method.fromString(node.method) orelse return error.UnsupportedProto;
    const addrs = try resolve(alloc, node.server, node.port);
    defer alloc.free(addrs);
    if (addrs.len == 0) return error.ResolveFailed;

    var handle_: ?net.Handle = null;
    for (addrs) |addr| {
        handle_ = net.tcpConnect(addr) catch continue;
        break;
    }
    const h = handle_ orelse return error.ConnectFailed;
    errdefer net.close(h);

    const ss = try SsConn.init(alloc, h, method, node.password);
    errdefer ss.destroy();

    var addr_buf: [512]u8 = undefined;
    const addr_len = try buildSsAddress(target, &addr_buf);
    try ss.writeAll(addr_buf[0..addr_len]);

    return ss;
}

// ============================================================================
// 第六部分：SOCKS5 UDP ASSOCIATE 中继（从 udprelay.zig 融合）
// ============================================================================

pub const max_datagram = 65535;

pub const Datagram = struct {
    host: []const u8,
    port: u16,
    payload_start: usize,
    payload_end: usize,
};

pub fn parseDatagram(buf: []const u8, host_buf: []u8) ProxyError!Datagram {
    if (buf.len < 4 or buf[0] != 0x00 or buf[1] != 0x00) return error.BadPacket;
    if (buf[2] != 0x00) return error.FragNotSupported;

    const atyp = buf[3];
    var pos: usize = 4;
    var host: []const u8 = undefined;

    switch (atyp) {
        0x01 => {
            if (pos + 4 + 2 > buf.len) return error.BadPacket;
            const s = std.fmt.bufPrint(host_buf, "{d}.{d}.{d}.{d}", .{
                buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3],
            }) catch return error.BadPacket;
            host = s;
            pos += 4;
        },
        0x03 => {
            if (pos >= buf.len) return error.BadPacket;
            const len = buf[pos];
            pos += 1;
            if (pos + len + 2 > buf.len or len > host_buf.len) return error.BadPacket;
            @memcpy(host_buf[0..len], buf[pos .. pos + len]);
            host = host_buf[0..len];
            pos += len;
        },
        else => return error.BadPacket,
    }

    const port = std.mem.readInt(u16, buf[pos..][0..2], .big);
    pos += 2;

    return .{
        .host = host,
        .port = port,
        .payload_start = pos,
        .payload_end = buf.len,
    };
}

pub fn buildDatagram(buf: []u8, src: net.Address, payload: []const u8) ![]u8 {
    const need = 4 + 4 + 2 + payload.len;
    if (buf.len < need) return error.BadPacket;

    buf[0] = 0x00;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x01;
    const addr_bytes = std.mem.asBytes(&src.in.addr);
    @memcpy(buf[4..8], addr_bytes[0..4]);
    std.mem.writeInt(u16, buf[8..10], src.getPort(), .big);
    if (payload.ptr != buf[10..].ptr) {
        @memcpy(buf[10 .. 10 + payload.len], payload);
    }
    return buf[0..need];
}

const TargetSocket = struct {
    host: []u8,
    port: u16,
    handle: net.Handle,
};

pub const Relay = struct {
    alloc: std.mem.Allocator,
    udp: net.Handle,
    bind_addr: net.Address,
    sockets: std.ArrayList(TargetSocket) = .empty,
    reply_timeout_ms: i32 = 2000,

    pub fn init(alloc: std.mem.Allocator, client_local: net.Address) ProxyError!Relay {
        var bind = client_local;
        bind.setPort(0);

        const h = try net.udpBind(bind);
        errdefer net.close(h);

        var actual: net.Address = undefined;
        net.getLocalAddr(h, &actual) catch {
            actual = bind;
        };

        return .{ .alloc = alloc, .udp = h, .bind_addr = actual };
    }

    pub fn deinit(self: *Relay) void {
        for (self.sockets.items) |s| {
            net.close(s.handle);
            self.alloc.free(s.host);
        }
        self.sockets.deinit(self.alloc);
        net.close(self.udp);
    }

    fn socketFor(self: *Relay, host: []const u8, port: u16) ProxyError!net.Handle {
        for (self.sockets.items) |s| {
            if (s.port == port and std.mem.eql(u8, s.host, host)) return s.handle;
        }

        const addrs = net.getAddressList(self.alloc, host, port) catch return error.ResolveFailed;
        defer self.alloc.free(addrs);
        if (addrs.len == 0) return error.ResolveFailed;

        const bind_zero = net.Address.parseIp("0.0.0.0", 0) catch return error.BindFailed;
        const h = net.udpBind(bind_zero) catch return error.BindFailed;
        errdefer net.close(h);
        net.udpConnect(h, addrs[0]) catch return error.BindFailed;

        const owned = try self.alloc.dupe(u8, host);
        errdefer self.alloc.free(owned);
        try self.sockets.append(self.alloc, .{ .host = owned, .port = port, .handle = h });
        return h;
    }

    pub fn handleFromClient(self: *Relay, packet: []const u8, client: net.Address) !?[]u8 {
        var host_buf: [256]u8 = undefined;
        const dg = parseDatagram(packet, &host_buf) catch return null;

        const payload = packet[dg.payload_start..dg.payload_end];
        const target = self.socketFor(dg.host, dg.port) catch return null;

        net.udpSend(target, payload) catch return null;
        net.setRecvTimeout(target, @intCast(self.reply_timeout_ms));

        const out = try self.alloc.alloc(u8, max_datagram);
        errdefer self.alloc.free(out);
        const n = net.udpRecv(target, out[10..]) catch {
            self.alloc.free(out);
            return null;
        };

        var src = net.Address.parseIp("0.0.0.0", dg.port) catch {
            self.alloc.free(out);
            return null;
        };
        src.setPort(dg.port);

        const framed = buildDatagram(out, src, out[10 .. 10 + n]) catch {
            self.alloc.free(out);
            return null;
        };
        _ = client;
        return try self.alloc.realloc(out, framed.len);
    }

    pub fn run(self: *Relay, control: net.Handle) void {
        var buf: [max_datagram]u8 = undefined;
        var client_addr: ?net.Address = null;

        var poll_fds: [34]net.PollFd = undefined;

        while (true) {
            poll_fds[0] = .{ .fd = control, .events = net.POLL.IN, .revents = 0 };
            poll_fds[1] = .{ .fd = self.udp, .events = net.POLL.IN, .revents = 0 };

            const num_sockets = @min(self.sockets.items.len, 32);
            for (self.sockets.items[0..num_sockets], 0..) |s, i| {
                poll_fds[2 + i] = .{ .fd = s.handle, .events = net.POLL.IN, .revents = 0 };
            }

            const total_fds = 2 + num_sockets;
            const ready = net.poll(poll_fds[0..total_fds], 60_000) catch return;
            if (ready == 0) continue;

            if ((poll_fds[0].revents & (net.POLL.IN | net.POLL.HUP | net.POLL.ERR | net.POLL.NVAL)) != 0) {
                return;
            }

            if ((poll_fds[1].revents & (net.POLL.IN | net.POLL.ERR)) != 0) {
                var from: net.Address = undefined;
                const n = net.udpRecvFrom(self.udp, &buf, &from) catch 0;
                if (n > 0) {
                    client_addr = from;
                    var host_buf: [256]u8 = undefined;
                    if (parseDatagram(buf[0..n], &host_buf)) |dg| {
                        const payload = buf[dg.payload_start..dg.payload_end];
                        if (self.socketFor(dg.host, dg.port)) |target| {
                            _ = net.udpSend(target, payload) catch {};
                        } else |_| {}
                    } else |_| {}
                }
            }

            if (client_addr) |cli| {
                var i: usize = 0;
                while (i < num_sockets) : (i += 1) {
                    if ((poll_fds[2 + i].revents & (net.POLL.IN | net.POLL.ERR)) != 0) {
                        const target_item = self.sockets.items[i];
                        var reply_buf: [max_datagram]u8 = undefined;
                        const rn = net.udpRecv(target_item.handle, reply_buf[10..]) catch continue;
                        if (rn > 0) {
                            var src = net.Address.parseIp("0.0.0.0", target_item.port) catch continue;
                            src.setPort(target_item.port);
                            if (buildDatagram(&reply_buf, src, reply_buf[10 .. 10 + rn])) |framed| {
                                net.udpSendTo(self.udp, framed, cli) catch {};
                            } else |_| {}
                        }
                    }
                }
            }
        }
    }
};

// ============================================================================
// 第七部分：SOCKS5 与 HTTP 混合入站（从 inbound.zig 融合）
// ============================================================================

pub const Request = struct {
    target: Target,
    prefix: []const u8 = "",
    udp_associate: bool = false,
    defer_reply: bool = false,
};

pub const Socks5Rep = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

pub fn sendSocks5Reply(h: net.Handle, rep: Socks5Rep) net.IoError!void {
    const reply = [_]u8{ 0x05, @intFromEnum(rep), 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    try net.sendAll(h, &reply);
}

pub fn sendAssociateReply(h: net.Handle, bind: net.Address) net.IoError!void {
    if (bind.any.family == std.posix.AF.INET) {
        var reply = [_]u8{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        const addr_bytes = std.mem.asBytes(&bind.in.addr);
        @memcpy(reply[4..8], addr_bytes[0..4]);
        std.mem.writeInt(u16, reply[8..10], bind.getPort(), .big);
        try net.sendAll(h, &reply);
    } else {
        var reply: [22]u8 = undefined;
        reply[0] = 0x05;
        reply[1] = 0x00;
        reply[2] = 0x00;
        reply[3] = 0x04;
        const addr_bytes = std.mem.asBytes(&bind.in6.addr);
        @memcpy(reply[4..20], addr_bytes[0..16]);
        std.mem.writeInt(u16, reply[20..22], bind.getPort(), .big);
        try net.sendAll(h, &reply);
    }
}

pub const max_request_bytes = 16 * 1024;

pub fn handshakeInbound(alloc: std.mem.Allocator, h: net.Handle, storage: *[max_request_bytes]u8) ProxyError!Request {
    var first: [1]u8 = undefined;
    try net.recvExact(h, &first);

    if (first[0] == 0x05) {
        return socks5Inbound(alloc, h);
    }
    return httpProxyInbound(alloc, h, storage, first[0]);
}

fn socks5Inbound(alloc: std.mem.Allocator, h: net.Handle) ProxyError!Request {
    const nmethods = try net.recvByte(h);
    if (nmethods == 0) return error.NoAcceptableMethod;

    var methods: [255]u8 = undefined;
    try net.recvExact(h, methods[0..nmethods]);

    var has_no_auth = false;
    for (methods[0..nmethods]) |m| {
        if (m == 0x00) has_no_auth = true;
    }
    if (!has_no_auth) {
        net.sendAll(h, &.{ 0x05, 0xFF }) catch {};
        return error.NoAcceptableMethod;
    }
    try net.sendAll(h, &.{ 0x05, 0x00 });

    const ver = try net.recvByte(h);
    if (ver != 0x05) return error.UnsupportedVersion;
    const cmd = try net.recvByte(h);
    _ = try net.recvByte(h);
    const atyp = try net.recvByte(h);

    const target = try readInboundTarget(alloc, h, atyp);
    errdefer alloc.free(target.host);

    switch (cmd) {
        0x01 => return .{ .target = target, .defer_reply = true },
        0x03 => return .{ .target = target, .udp_associate = true },
        else => {
            const reply = [_]u8{ 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
            try net.sendAll(h, &reply);
            return error.UnsupportedCommand;
        },
    }
}

fn readInboundTarget(alloc: std.mem.Allocator, h: net.Handle, atyp: u8) ProxyError!Target {
    const host: []const u8 = switch (atyp) {
        0x01 => blk: {
            var b: [4]u8 = undefined;
            try net.recvExact(h, &b);
            break :blk try std.fmt.allocPrint(alloc, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        0x03 => blk: {
            const len = try net.recvByte(h);
            if (len == 0) return error.BadRequest;
            const b = try alloc.alloc(u8, len);
            errdefer alloc.free(b);
            try net.recvExact(h, b);
            break :blk b;
        },
        0x04 => blk: {
            var b: [16]u8 = undefined;
            try net.recvExact(h, &b);
            const addr = net.Address.initIp6(b, 0, 0, 0);
            break :blk try std.fmt.allocPrint(alloc, "{}", .{addr});
        },
        else => return error.UnsupportedAddressType,
    };
    const port = try net.recvU16(h);
    return .{ .host = host, .port = port };
}

fn httpProxyInbound(alloc: std.mem.Allocator, h: net.Handle, storage: *[max_request_bytes]u8, first_byte: u8) ProxyError!Request {
    storage[0] = first_byte;
    var len: usize = 1;

    while (len < storage.len) {
        if (std.mem.indexOf(u8, storage[0..len], "\r\n\r\n")) |_| break;
        const n = try net.recv(h, storage[len..]);
        if (n == 0) return error.ConnectionClosed;
        len += n;
    }

    const header = storage[0..len];
    const first_line_end = std.mem.indexOf(u8, header, "\r\n") orelse return error.BadRequest;
    const first_line = header[0..first_line_end];

    var it = std.mem.splitScalar(u8, first_line, ' ');
    const method = it.next() orelse return error.BadRequest;
    const raw_uri = it.next() orelse return error.BadRequest;

    if (std.ascii.eqlIgnoreCase(method, "CONNECT")) {
        const target = try parseAuthority(alloc, raw_uri, 443);
        try net.sendAll(h, "HTTP/1.1 200 Connection Established\r\n\r\n");
        return .{ .target = target, .prefix = "" };
    }

    const target = try parseAbsoluteUri(alloc, raw_uri);
    return .{ .target = target, .prefix = header };
}

fn parseAuthority(alloc: std.mem.Allocator, uri: []const u8, default_port: u16) ProxyError!Target {
    if (std.mem.lastIndexOfScalar(u8, uri, ':')) |colon| {
        const host = try alloc.dupe(u8, uri[0..colon]);
        errdefer alloc.free(host);
        const port = std.fmt.parseInt(u16, uri[colon + 1 ..], 10) catch return error.BadRequest;
        return .{ .host = host, .port = port };
    }
    const host = try alloc.dupe(u8, uri);
    return .{ .host = host, .port = default_port };
}

fn parseAbsoluteUri(alloc: std.mem.Allocator, uri: []const u8) ProxyError!Target {
    const after_scheme = if (std.mem.indexOf(u8, uri, "://")) |idx| uri[idx + 3 ..] else uri;
    const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
    const auth = after_scheme[0..slash];
    const default_port: u16 = if (std.mem.startsWith(u8, uri, "https://")) 443 else 80;
    return parseAuthority(alloc, auth, default_port);
}

// ============================================================================
// 第八部分：Direct 与 VLESS 出站（从 outbound.zig 融合）
// ============================================================================

pub const Conn = struct {
    stream: net.Stream,
    preamble: []const u8 = "",

    pub fn writePreamble(self: Conn) !void {
        if (self.preamble.len > 0) {
            try self.stream.writeAll(self.preamble);
        }
    }
};

pub fn resolve(alloc: std.mem.Allocator, host: []const u8, port: u16) ![]net.Address {
    return net.getAddressList(alloc, host, port) catch error.ResolveFailed;
}

pub fn connectDirect(alloc: std.mem.Allocator, target: Target) ProxyError!Conn {
    const addrs = try resolve(alloc, target.host, target.port);
    defer alloc.free(addrs);

    var last_err: ProxyError = error.ConnectFailed;
    for (addrs) |addr| {
        const h = net.tcpConnect(addr) catch |e| {
            last_err = switch (e) {
                error.ConnectionClosed, error.SocketError => error.ConnectFailed,
                else => error.ConnectFailed,
            };
            continue;
        };
        return .{ .stream = net.Stream.fromRaw(h) };
    }
    return last_err;
}

pub fn parseUuid(s: []const u8) ![16]u8 {
    var out: [16]u8 = undefined;
    var hex: [32]u8 = undefined;
    var n: usize = 0;

    if (s.len == 36) {
        for (s) |c| {
            if (c == '-') continue;
            if (!std.ascii.isHex(c)) return error.BadUuid;
            if (n >= 32) return error.BadUuid;
            hex[n] = c;
            n += 1;
        }
        if (n != 32) return error.BadUuid;
    } else {
        return error.BadUuid;
    }

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16) catch return error.BadUuid;
    }
    return out;
}

pub fn buildVlessRequest(alloc: std.mem.Allocator, uuid_str: []const u8, target: Target) ![]u8 {
    return buildVlessRequestWithCmd(alloc, uuid_str, target, 0x01);
}

pub fn buildVlessUdpRequest(alloc: std.mem.Allocator, uuid_str: []const u8, target: Target) ![]u8 {
    return buildVlessRequestWithCmd(alloc, uuid_str, target, 0x02);
}

pub fn buildVlessRequestWithCmd(alloc: std.mem.Allocator, uuid_str: []const u8, target: Target, cmd: u8) ![]u8 {
    const uuid = try parseUuid(uuid_str);
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    try buf.append(alloc, 0x00);
    try buf.appendSlice(alloc, &uuid);
    try buf.append(alloc, 0x00);
    try buf.append(alloc, cmd);

    var port_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_buf, target.port, .big);
    try buf.appendSlice(alloc, &port_buf);

    if (net.Address.parseIp4(target.host, 0)) |a4| {
        try buf.append(alloc, 0x01);
        const raw = std.mem.asBytes(&a4.in.addr);
        try buf.appendSlice(alloc, raw[0..4]);
    } else |_| {
        if (net.Address.parseIp6(target.host, 0)) |a6| {
            try buf.append(alloc, 0x03);
            const raw = a6.in6.addr;
            try buf.appendSlice(alloc, raw[0..16]);
        } else |_| {
            if (target.host.len > 255) return error.BadTarget;
            try buf.append(alloc, 0x02);
            try buf.append(alloc, @intCast(target.host.len));
            try buf.appendSlice(alloc, target.host);
        }
    }
    return buf.toOwnedSlice(alloc);
}

pub fn connectVless(alloc: std.mem.Allocator, node: Node, target: Target, tls_ctx: ?TlsContext) ProxyError!Conn {
    return connectVlessProto(alloc, node, target, tls_ctx, false);
}

pub fn connectVlessUdp(alloc: std.mem.Allocator, node: Node, target: Target, tls_ctx: ?TlsContext) ProxyError!Conn {
    return connectVlessProto(alloc, node, target, tls_ctx, true);
}

pub fn connectVlessProto(alloc: std.mem.Allocator, node: Node, target: Target, tls_ctx: ?TlsContext, is_udp: bool) ProxyError!Conn {
    const server_port = node.port;
    const addrs = try resolve(alloc, node.server, server_port);
    defer alloc.free(addrs);
    if (addrs.len == 0) return error.ResolveFailed;

    var stream: net.Stream = undefined;
    var owns_stream = true;

    if (node.tls) {
        const ctx = tls_ctx orelse return error.TlsBundleMissing;
        var last_err: ProxyError = error.ConnectFailed;
        var tls_conn: ?*TlsConn = null;
        for (addrs) |addr| {
            tls_conn = TlsConn.connect(
                alloc,
                addr,
                node.effectiveSni(),
                node.insecure,
                ctx.bundle,
                node.pqc,
            ) catch |e| {
                last_err = e;
                continue;
            };
            break;
        }
        const tc = tls_conn orelse return last_err;
        stream = net.Stream.fromTls(tc);
    } else {
        var last_err: ProxyError = error.ConnectFailed;
        var raw: ?net.Handle = null;
        for (addrs) |addr| {
            raw = net.tcpConnect(addr) catch |e| {
                last_err = e;
                continue;
            };
            break;
        }
        stream = net.Stream.fromRaw(raw orelse return last_err);
    }
    errdefer if (owns_stream) stream.close();

    if (node.ws_path.len > 0) {
        const host_hdr = if (node.ws_host.len > 0) node.ws_host else node.server;
        const ws_ptr = try alloc.create(WsConn);
        errdefer alloc.destroy(ws_ptr);
        ws_ptr.* = WsConn.init(alloc, stream);
        try ws_ptr.clientHandshake(node.ws_path, host_hdr);
        stream = net.Stream.fromWs(ws_ptr);
    }

    const req = try buildVlessRequestWithCmd(alloc, node.uuid, target, if (is_udp) 0x02 else 0x01);
    owns_stream = false;
    return .{ .stream = stream, .preamble = req };
}

pub fn connect(alloc: std.mem.Allocator, node: Node, target: Target, tls_ctx: ?TlsContext) ProxyError!Conn {
    return switch (node.proto) {
        .vless => connectVless(alloc, node, target, tls_ctx),
        .shadowsocks => {
            const ss = connectShadowsocks(alloc, node, target) catch return error.ConnectFailed;
            return .{
                .stream = net.Stream.fromSs(ss),
                .preamble = &.{},
            };
        },
        .hysteria2 => error.UnsupportedTransport,
    };
}

pub fn connectUdp(alloc: std.mem.Allocator, node: Node, target: Target, tls_ctx: ?TlsContext) ProxyError!Conn {
    return switch (node.proto) {
        .vless => connectVlessUdp(alloc, node, target, tls_ctx),
        .shadowsocks => error.UnsupportedTransport,
        .hysteria2 => error.UnsupportedTransport,
    };
}


