//! DNS 报文编解码 + Fake-IP 池。
//!
//! **背景**：旧版核心完全没有 DNS 子系统，`resolve_host` 直接走
//! `tokio::net::lookup_host`（系统解析器），意味着即使流量走代理，
//! DNS 查询仍然直连泄漏 —— 这是最典型的隐私问题，也是 TUN 模式无法工作的根因。
//!
//! 本模块提供两块能力：
//! 1. **DNS 报文编解码**（RFC 1035 的最小可用子集）：解析查询、构造 A 记录应答
//! 2. **Fake-IP 池**：域名 ↔ 假地址的双向映射，供 DNS 应答与连接反查共用

const std = @import("std");
const net = @import("net.zig");
const router_mod = @import("router.zig");

// ============================================================================
// DNS 报文
// ============================================================================

pub const qtype_a: u16 = 1;
pub const qtype_aaaa: u16 = 28;
pub const qclass_in: u16 = 1;

pub const ParseError = error{
    TooShort,
    BadName,
    BadPointer,
    NameTooLong,
    Truncated,
};

/// 解析出的查询
pub const Query = struct {
    id: u16,
    flags: u16,
    /// 小写、不带末尾点
    name: []const u8,
    qtype: u16,
    qclass: u16,
    /// 问题区结束位置（构造应答时原样回填）
    question_end: usize,
    /// 问题区字节（QNAME+QTYPE+QCLASS）
    question: []const u8,
};

/// 解析 DNS 查询报文。
///
/// `name_buf` 用于存放展开后的域名（不做堆分配，避免 DNS 路径上的内存压力）。
pub fn parseQuery(buf: []const u8, name_buf: []u8) ParseError!Query {
    if (buf.len < 12) return error.TooShort;

    const id = std.mem.readInt(u16, buf[0..2], .big);
    const flags = std.mem.readInt(u16, buf[2..4], .big);
    const qdcount = std.mem.readInt(u16, buf[4..6], .big);
    if (qdcount == 0) return error.BadName;

    var pos: usize = 12;
    var n: usize = 0;

    // 解析 QNAME
    while (true) {
        if (pos >= buf.len) return error.Truncated;
        const len_byte = buf[pos];

        if (len_byte == 0) {
            pos += 1;
            break;
        }
        // 压缩指针：查询报文几乎不用，但遇到要能安全拒绝
        if ((len_byte & 0xC0) == 0xC0) return error.BadPointer;
        if (len_byte > 63) return error.BadName;

        pos += 1;
        if (pos + len_byte > buf.len) return error.Truncated;
        if (n > 0) {
            if (n >= name_buf.len) return error.NameTooLong;
            name_buf[n] = '.';
            n += 1;
        }
        if (n + len_byte >= name_buf.len) return error.NameTooLong;
        for (buf[pos .. pos + len_byte]) |c| {
            name_buf[n] = std.ascii.toLower(c);
            n += 1;
        }
        pos += len_byte;
    }

    if (pos + 4 > buf.len) return error.Truncated;
    const qtype = std.mem.readInt(u16, buf[pos..][0..2], .big);
    const qclass = std.mem.readInt(u16, buf[pos + 2 ..][0..2], .big);
    const question_end = pos + 4;

    return .{
        .id = id,
        .flags = flags,
        .name = name_buf[0..n],
        .qtype = qtype,
        .qclass = qclass,
        .question_end = question_end,
        .question = buf[12..question_end],
    };
}

/// 构造一个带单条 A 记录的应答（标准格式 + 0x0C 指向问题区的名字压缩）
pub fn buildResponseA(
    alloc: std.mem.Allocator,
    q: Query,
    ip: u32,
    ttl: u32,
) ![]u8 {
    // 头部 12 + 问题区 + 应答 16
    const total = 12 + q.question.len + 16;
    const buf = try alloc.alloc(u8, total);
    errdefer alloc.free(buf);

    std.mem.writeInt(u16, buf[0..2], q.id, .big);
    // QR=1, RD 保留, RA=1
    const resp_flags: u16 = 0x8000 | (q.flags & 0x0100) | 0x0080;
    std.mem.writeInt(u16, buf[2..4], resp_flags, .big);
    std.mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, buf[6..8], 1, .big); // ANCOUNT
    std.mem.writeInt(u16, buf[8..10], 0, .big);
    std.mem.writeInt(u16, buf[10..12], 0, .big);

    @memcpy(buf[12 .. 12 + q.question.len], q.question);
    var pos = 12 + q.question.len;

    // ANSWER: NAME(指针) TYPE CLASS TTL RDLEN RDATA
    buf[pos] = 0xC0;
    buf[pos + 1] = 0x0C;
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], qtype_a, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], qclass_in, .big);
    pos += 2;
    std.mem.writeInt(u32, buf[pos..][0..4], ttl, .big);
    pos += 4;
    std.mem.writeInt(u16, buf[pos..][0..2], 4, .big);
    pos += 2;
    // 主机字节序 -> 网络字节序
    std.mem.writeInt(u32, buf[pos..][0..4], ip, .big);
    pos += 4;

    std.debug.assert(pos == total);
    return buf;
}

/// 构造一个空应答（无记录，用于 AAAA 或过滤）
pub fn buildEmptyResponse(alloc: std.mem.Allocator, q: Query) ![]u8 {
    const total = 12 + q.question.len;
    const buf = try alloc.alloc(u8, total);
    std.mem.writeInt(u16, buf[0..2], q.id, .big);
    const resp_flags: u16 = 0x8000 | (q.flags & 0x0100) | 0x0080;
    std.mem.writeInt(u16, buf[2..4], resp_flags, .big);
    std.mem.writeInt(u16, buf[4..6], 1, .big);
    std.mem.writeInt(u16, buf[6..8], 0, .big);
    std.mem.writeInt(u16, buf[8..10], 0, .big);
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    @memcpy(buf[12..], q.question);
    return buf;
}

// ============================================================================
// Fake-IP 池
// ============================================================================

/// Fake-IP 段：198.18.0.0/15（RFC 5737 之外的 benchmark 段，业界惯例）
pub const fake_base: u32 = 0xC612_0000; // 198.18.0.0
pub const fake_count: u32 = 0x0002_0000; // /15 = 131072 个地址

pub const Pool = struct {
    alloc: std.mem.Allocator,
    mutex: net.Mutex = .{},

    by_name: std.StringHashMapUnmanaged(u32) = .empty,
    by_ip: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    /// 下一个待分配地址（相对 base 的偏移）
    cursor: u32 = 1,
    base: u32 = fake_base,
    capacity: u32 = fake_count,
    /// TTL（秒），同时用于 DNS 应答
    ttl: u32 = 60,

    pub fn init(alloc: std.mem.Allocator) Pool {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Pool) void {
        var it = self.by_name.iterator();
        while (it.next()) |kv| self.alloc.free(kv.key_ptr.*);
        self.by_ip.deinit(self.alloc);
        self.by_name.deinit(self.alloc);
    }

    /// 域名 → Fake-IP（不存在则分配）
    pub fn assign(self: *Pool, name: []const u8) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_name.get(name)) |ip| return ip;

        // 表满：整体重置（比 LRU 简单，且 Fake-IP 本身就是短生命周期）
        if (self.by_name.count() >= self.capacity - 1) {
            self.resetLocked();
        }

        // 找一个未被占用的地址
        var tries: u32 = 0;
        while (tries < self.capacity) : (tries += 1) {
            const off = self.cursor;
            self.cursor += 1;
            if (self.cursor >= self.capacity) self.cursor = 1;

            const ip = self.base + off;
            if (self.by_ip.get(ip)) |_| continue;

            const owned = try self.alloc.dupe(u8, name);
            errdefer self.alloc.free(owned);

            try self.by_name.put(self.alloc, owned, ip);
            try self.by_ip.put(self.alloc, ip, owned);
            return ip;
        }
        return error.PoolExhausted;
    }

    /// Fake-IP → 域名
    pub fn lookup(self: *Pool, ip: u32) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_ip.get(ip);
    }

    /// 该地址是否落在 Fake-IP 段
    pub fn isFakeIp(self: *Pool, ip: u32) bool {
        _ = self;
        return ip >= fake_base and ip < fake_base + fake_count;
    }

    /// 清空映射
    pub fn clear(self: *Pool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.resetLocked();
    }

    fn resetLocked(self: *Pool) void {
        var it = self.by_name.iterator();
        while (it.next()) |kv| self.alloc.free(kv.key_ptr.*);
        self.by_name.clearRetainingCapacity();
        self.by_ip.clearRetainingCapacity();
        self.cursor = 1;
    }

    pub fn count(self: *Pool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_name.count();
    }
};

/// 把 u32 主机序地址格式化成 "a.b.c.d"
pub fn formatIp(buf: []u8, ip: u32) ![]const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff,
    });
}

/// 解析 "a.b.c.d" 为主机序 u32
pub fn parseIp(s: []const u8) !u32 {
    var it = std.mem.splitScalar(u8, s, '.');
    var out: u32 = 0;
    var n: usize = 0;
    while (it.next()) |part| {
        if (n >= 4) return error.BadIp;
        const v = std.fmt.parseInt(u8, part, 10) catch return error.BadIp;
        out = (out << 8) | v;
        n += 1;
    }
    if (n != 4) return error.BadIp;
    return out;
}

// ============================ 测试 ============================

fn buildQuery(buf: []u8, id: u16, name: []const u8, qtype: u16) []u8 {
    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[2..4], 0x0100, .big); // RD=1
    std.mem.writeInt(u16, buf[4..6], 1, .big);
    std.mem.writeInt(u16, buf[6..8], 0, .big);
    std.mem.writeInt(u16, buf[8..10], 0, .big);
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    var pos: usize = 12;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }
    buf[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], qtype, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], qclass_in, .big);
    pos += 2;
    return buf[0..pos];
}








// ============================================================================
// DNS 服务端（从 dnsserver.zig 融合）
// ============================================================================

pub const max_packet = 4096;

pub const ServerConfig = struct {
    /// 监听地址（通常 127.0.0.1:53 或 0.0.0.0:5353）
    listen: net.Address,
    /// 上游 DNS（真实解析）
    upstream: net.Address = undefined,
    /// Fake-IP TTL（秒）
    ttl: u32 = 60,
    /// 上游超时（毫秒）
    upstream_timeout_ms: i32 = 2000,
};

pub const Config = ServerConfig;

pub const Server = struct {
    alloc: std.mem.Allocator,
    cfg: ServerConfig,
    pool: *Pool,
    router: *const router_mod.Router,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn serveUdp(self: *Server) !void {
        const h = try net.udpBind(self.cfg.listen);
        defer net.close(h);

        var buf: [max_packet]u8 = undefined;
        while (self.running.load(.acquire)) {
            var from: net.Address = undefined;
            const n = net.udpRecvFrom(h, &buf, &from) catch continue;
            if (n < 12) continue;

            var name_buf: [256]u8 = undefined;
            const q = parseQuery(buf[0..n], &name_buf) catch continue;

            const decision = self.router.decideByDomain(q.name, "");
            switch (decision.action) {
                .reject => {
                    const resp = buildEmptyResponse(self.alloc, q) catch continue;
                    defer self.alloc.free(resp);
                    net.udpSendTo(h, resp, from) catch {};
                },
                .proxy => {
                    if (q.qtype == qtype_a) {
                        const ip = self.pool.assign(q.name) catch continue;
                        const resp = buildResponseA(self.alloc, q, ip, self.cfg.ttl) catch continue;
                        defer self.alloc.free(resp);
                        net.udpSendTo(h, resp, from) catch {};
                    } else {
                        // AAAA 或其它记录类型（如 HTTPS/SVCB）：
                        // 返回标准 NODATA 响应（NOERROR，0 Answer），防 IPv6 泄漏且不阻塞客户端回退
                        const resp = buildEmptyResponse(self.alloc, q) catch continue;
                        defer self.alloc.free(resp);
                        net.udpSendTo(h, resp, from) catch {};
                    }
                },
                .direct => {
                    // 异步派发上游转发，消除同步超时对主 UDP 监听循环的阻塞
                    const pkt_copy = self.alloc.alloc(u8, n) catch continue;
                    @memcpy(pkt_copy, buf[0..n]);
                    const t = std.Thread.spawn(.{}, forwardWorker, .{ self, h, pkt_copy, from, q }) catch {
                        self.alloc.free(pkt_copy);
                        // 降级：同步处理
                        const resp = self.forwardUpstream(buf[0..n]) catch buildEmptyResponse(self.alloc, q) catch continue;
                        defer self.alloc.free(resp);
                        net.udpSendTo(h, resp, from) catch {};
                        continue;
                    };
                    t.detach();
                },
            }
        }
    }

    fn forwardWorker(self: *Server, sock: net.Handle, query: []u8, client: net.Address, q: Query) void {
        defer self.alloc.free(query);
        const resp = self.forwardUpstream(query) catch blk: {
            break :blk buildEmptyResponse(self.alloc, q) catch return;
        };
        defer self.alloc.free(resp);
        net.udpSendTo(sock, resp, client) catch {};
    }

    /// 处理一个 DNS 查询，返回应答报文（调用方负责 free）
    pub fn handle(self: *Server, packet: []const u8, len: usize) ![]u8 {
        var name_buf: [256]u8 = undefined;
        const q = parseQuery(packet[0..len], &name_buf) catch {
            return buildEmptyResponse(self.alloc, .{
                .id = std.mem.readInt(u16, packet[0..2], .big),
                .flags = 0,
                .name = "",
                .qtype = 0,
                .qclass = 0,
                .question_end = 12,
                .question = packet[12..12],
            });
        };

        const decision = self.router.decideByDomain(q.name, "");
        switch (decision.action) {
            .reject => return buildEmptyResponse(self.alloc, q),
            .proxy => {
                if (q.qtype == qtype_a) {
                    const ip = try self.pool.assign(q.name);
                    return buildResponseA(self.alloc, q, ip, self.cfg.ttl);
                } else {
                    return buildEmptyResponse(self.alloc, q);
                }
            },
            .direct => {
                return self.forwardUpstream(packet[0..len]) catch {
                    return buildEmptyResponse(self.alloc, q);
                };
            },
        }
    }

    fn forwardUpstream(self: *Server, query: []const u8) ![]u8 {
        const h = net.udpBind(try net.Address.parseIp("0.0.0.0", 0)) catch return error.UpstreamFailed;
        defer net.close(h);

        net.udpSendTo(h, query, self.cfg.upstream) catch return error.UpstreamFailed;
        net.setRecvTimeout(h, @intCast(self.cfg.upstream_timeout_ms));

        const out = try self.alloc.alloc(u8, max_packet);
        errdefer self.alloc.free(out);
        var from: net.Address = undefined;
        const n = net.udpRecvFrom(h, out, &from) catch return error.UpstreamFailed;
        return try self.alloc.realloc(out, n);
    }

    pub fn stop(self: *Server) void {
        self.running.store(false, .release);
    }
};
