//! 路由与规则匹配引擎（融合 router.zig + ipnet.zig + trie.zig + geoip.zig）
//!
//! 提供：
//! 1. IP 与 CIDR 结构、私网/Fake-IP 识别
//! 2. 二叉前缀树（Radix Trie / Longest Prefix Match），微秒级完成数万条 CIDR 匹配
//! 3. GeoIP 国内与私网 CIDR 库
//! 4. 域名分层最长后缀优先匹配（SuffixTable）
//! 5. 综合路由引擎（Router）与节点熔断冷却池（CooldownPool）

const std = @import("std");
const net = @import("net.zig");

pub const DomainRoute = struct {
    domain: []const u8 = "",
    pattern: []const u8 = "",
    target: []const u8 = "",
    outbound: []const u8 = "",
};

pub const CidrRoute = struct {
    cidr: []const u8 = "",
    target: []const u8 = "",
};

// ============================================================================
// 第一部分：IP 与 CIDR 匹配（从 ipnet.zig 融合）
// ============================================================================

pub const Ip = union(enum) {
    v4: u32, // 主机字节序
    v6: [16]u8,

    pub fn parse(s: []const u8) !Ip {
        const t = std.mem.trim(u8, s, " \t\r\n[]");
        if (std.mem.indexOfScalar(u8, t, ':') != null) {
            const addr = try net.Address.parseIp6(t, 0);
            return .{ .v6 = addr.in6.addr };
        }
        const a = try net.Address.parseIp4(t, 0);
        return .{ .v4 = std.mem.bigToNative(u32, a.in.addr) };
    }

    /// 是否为私有 / 保留地址（应直连，不进代理）
    pub fn isPrivate(self: Ip) bool {
        return switch (self) {
            .v4 => |x| isPrivateV4(x),
            .v6 => |b| isPrivateV6(b),
        };
    }

    pub fn format(self: Ip, writer: anytype) !void {
        switch (self) {
            .v4 => |x| {
                const bytes = std.mem.toBytes(std.mem.nativeToBig(u32, x));
                try writer.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
            },
            .v6 => |b| {
                try writer.print("[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:" ++
                    "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]", .{
                    b[0],  b[1],  b[2],  b[3],  b[4],  b[5],  b[6],  b[7],
                    b[8],  b[9],  b[10], b[11], b[12], b[13], b[14], b[15],
                });
            },
        }
    }
};

pub fn isPrivateV4(x: u32) bool {
    const a: u8 = @intCast((x >> 24) & 0xff);
    const b: u8 = @intCast((x >> 16) & 0xff);

    if (a == 0) return true; // 0.0.0.0/8
    if (a == 10) return true; // 10/8
    if (a == 127) return true; // loopback
    if (a == 169 and b == 254) return true; // link-local
    if (a == 172 and b >= 16 and b <= 31) return true; // 172.16/12
    if (a == 192 and b == 168) return true; // 192.168/16
    if (a == 100 and b >= 64 and b <= 127) return true; // CGNAT 100.64/10
    if (a == 198 and (b == 18 or b == 19)) return true; // benchmark 198.18/15 —— Fake-IP 段
    if (a == 192 and b == 0) return true; // 192.0.0/24, 192.0.2/24
    if (a >= 224) return true; // multicast + reserved + broadcast
    return false;
}

pub fn isPrivateV6(b: [16]u8) bool {
    // ::1 loopback
    var only_last = true;
    for (b[0..15]) |c| {
        if (c != 0) only_last = false;
    }
    if (only_last and b[15] == 1) return true;
    // :: unspecified
    var all_zero = true;
    for (b) |c| {
        if (c != 0) all_zero = false;
    }
    if (all_zero) return true;
    // fc00::/7 ULA
    if ((b[0] & 0xfe) == 0xfc) return true;
    // fe80::/10 link-local
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true;
    // ff00::/8 multicast
    if (b[0] == 0xff) return true;
    // fdfe:dcba:9876::/64 —— Fake-IP v6 段
    if (b[0] == 0xfd and b[1] == 0xfe and b[2] == 0xdc and b[3] == 0xba and
        b[4] == 0x98 and b[5] == 0x76)
    {
        return true;
    }
    return false;
}

/// CIDR 网段
pub const Cidr = struct {
    net: Ip,
    prefix: u8,

    pub fn parse(s: []const u8) !Cidr {
        const t = std.mem.trim(u8, s, " \t\r\n");
        if (std.mem.indexOfScalar(u8, t, '/')) |slash| {
            const net_ip = try Ip.parse(t[0..slash]);
            const p = try std.fmt.parseInt(u8, t[slash + 1 ..], 10);
            const max: u8 = switch (net_ip) {
                .v4 => 32,
                .v6 => 128,
            };
            if (p > max) return error.InvalidPrefix;
            return .{ .net = net_ip, .prefix = p };
        }
        const net_ip = try Ip.parse(t);
        return .{ .net = net_ip, .prefix = switch (net_ip) {
            .v4 => 32,
            .v6 => 128,
        } };
    }

    pub fn contains(self: Cidr, ip: Ip) bool {
        return switch (self.net) {
            .v4 => |n| switch (ip) {
                .v4 => |x| prefixMatch32(n, x, self.prefix),
                .v6 => false,
            },
            .v6 => |n| switch (ip) {
                .v6 => |x| prefixMatch128(n, x, self.prefix),
                .v4 => false,
            },
        };
    }
};

pub fn prefixMatch32(a: u32, b: u32, prefix: u8) bool {
    if (prefix == 0) return true;
    if (prefix >= 32) return a == b;
    const shift: u5 = @intCast(32 - @as(u32, prefix));
    const mask: u32 = @as(u32, 0xffffffff) << shift;
    return (a & mask) == (b & mask);
}

pub fn prefixMatch128(a: [16]u8, b: [16]u8, prefix: u8) bool {
    var remaining: u16 = prefix;
    var i: usize = 0;
    while (remaining >= 8 and i < 16) : (i += 1) {
        if (a[i] != b[i]) return false;
        remaining -= 8;
    }
    if (remaining == 0) return true;
    if (i >= 16) return true;
    const shift: u3 = @intCast(8 - remaining);
    const mask: u8 = ~(@as(u8, 0xff) >> shift);
    return (a[i] & mask) == (b[i] & mask);
}

// ============================================================================
// 第二部分：高性能 IP 前缀树（从 trie.zig 融合）
// ============================================================================

pub fn IpTrie(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Node = struct {
            children: [2]?*Node = .{ null, null },
            value: ?T = null,
        };

        alloc: std.mem.Allocator,
        root_v4: *Node,
        count: usize = 0,

        pub fn init(alloc: std.mem.Allocator) !Self {
            const r = try alloc.create(Node);
            r.* = .{};
            return .{
                .alloc = alloc,
                .root_v4 = r,
            };
        }

        pub fn deinit(self: *Self) void {
            self.freeNode(self.root_v4);
        }

        fn freeNode(self: *Self, node: *Node) void {
            if (node.children[0]) |c| self.freeNode(c);
            if (node.children[1]) |c| self.freeNode(c);
            self.alloc.destroy(node);
        }

        /// 插入 IPv4 (u32 主机字节序)
        pub fn insertV4(self: *Self, bits: u32, prefix_len: u8, val: T) !void {
            var curr = self.root_v4;
            const p = @min(prefix_len, 32);

            var i: u6 = 0;
            while (i < p) : (i += 1) {
                const shift: u5 = @intCast(31 - i);
                const bit: usize = (bits >> shift) & 1;
                if (curr.children[bit] == null) {
                    const next = try self.alloc.create(Node);
                    next.* = .{};
                    curr.children[bit] = next;
                }
                curr = curr.children[bit].?;
            }
            curr.value = val;
            self.count += 1;
        }

        pub fn insertV4Bytes(self: *Self, ip_bytes: [4]u8, prefix_len: u8, val: T) !void {
            const bits = std.mem.readInt(u32, &ip_bytes, .big);
            return self.insertV4(bits, prefix_len, val);
        }

        /// 插入 Cidr
        pub fn insertCidr(self: *Self, cidr: Cidr, val: T) !void {
            switch (cidr.net) {
                .v4 => |v4| try self.insertV4(v4, cidr.prefix, val),
                .v6 => {},
            }
        }

        /// 最长前缀查找（LPM）
        pub fn lookupV4(self: *const Self, bits: u32) ?T {
            var curr = self.root_v4;
            var best: ?T = curr.value;

            var i: u6 = 0;
            while (i < 32) : (i += 1) {
                const shift: u5 = @intCast(31 - i);
                const bit: usize = (bits >> shift) & 1;
                if (curr.children[bit]) |next| {
                    curr = next;
                    if (curr.value != null) {
                        best = curr.value;
                    }
                } else {
                    break;
                }
            }
            return best;
        }

        pub fn lookupV4Bytes(self: *const Self, ip_bytes: [4]u8) ?T {
            const bits = std.mem.readInt(u32, &ip_bytes, .big);
            return self.lookupV4(bits);
        }

        /// 查找 Ip
        pub fn lookup(self: *const Self, ip_val: Ip) ?T {
            switch (ip_val) {
                .v4 => |v4| return self.lookupV4(v4),
                .v6 => return null,
            }
        }
    };
}

// ============================================================================
// 第三部分：GeoIP 数据库与常用 CIDR（从 geoip.zig 融合）
// ============================================================================

pub const private_cidrs = [_][]const u8{
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
};

pub const cn_cidrs = [_][]const u8{
    "1.0.1.0/24",
    "1.0.2.0/23",
    "1.0.8.0/21",
    "1.0.32.0/19",
    "14.0.0.0/11",
    "27.0.0.0/10",
    "36.0.0.0/10",
    "42.0.0.0/11",
    "49.64.0.0/11",
    "58.16.0.0/12",
    "58.32.0.0/11",
    "101.0.0.0/10",
    "110.0.0.0/11",
    "111.0.0.0/10",
    "112.0.0.0/10",
    "113.0.0.0/10",
    "114.0.0.0/10",
    "115.0.0.0/10",
    "116.0.0.0/10",
    "117.0.0.0/10",
    "118.0.0.0/10",
    "119.0.0.0/10",
    "120.0.0.0/10",
    "121.0.0.0/10",
    "122.0.0.0/11",
    "123.0.0.0/11",
    "124.0.0.0/10",
    "180.96.0.0/11",
    "182.80.0.0/12",
    "183.0.0.0/10",
    "218.0.0.0/10",
    "220.160.0.0/11",
    "221.0.0.0/11",
    "222.16.0.0/12",
    "223.64.0.0/11",
    "223.166.0.0/15",
    "223.5.5.0/24",
    "114.114.114.0/24",
};

pub fn lookupGeoIp(tag: []const u8) ?[]const []const u8 {
    var s = tag;
    if (std.ascii.startsWithIgnoreCase(s, "geoip:")) {
        s = s[6..];
    } else if (std.ascii.startsWithIgnoreCase(s, "geoip/")) {
        s = s[6..];
    } else {
        return null;
    }

    if (std.ascii.eqlIgnoreCase(s, "private") or std.ascii.eqlIgnoreCase(s, "lan")) {
        return &private_cidrs;
    }
    if (std.ascii.eqlIgnoreCase(s, "cn") or std.ascii.eqlIgnoreCase(s, "china")) {
        return &cn_cidrs;
    }
    return null;
}

// ============================================================================
// 第四部分：路由引擎与后缀表
// ============================================================================

pub const Action = enum {
    direct,
    proxy,
    reject,

    pub fn toString(self: Action) []const u8 {
        return switch (self) {
            .direct => "DIRECT",
            .proxy => "PROXY",
            .reject => "REJECT",
        };
    }
};

/// 路由决策结果
pub const Decision = struct {
    action: Action,
    node: []const u8 = "",
    matched: []const u8 = "",
};

/// 域名后缀表：按标签数分层，层内用 HashMap 做 O(1) 精确后缀匹配
const SuffixTable = struct {
    levels: []std.StringHashMapUnmanaged([]const u8),

    fn init(alloc: std.mem.Allocator, max_labels: usize) !SuffixTable {
        const levels = try alloc.alloc(std.StringHashMapUnmanaged([]const u8), max_labels + 1);
        for (levels) |*l| l.* = .empty;
        return .{ .levels = levels };
    }

    fn deinit(self: *SuffixTable, alloc: std.mem.Allocator) void {
        for (self.levels) |*l| l.deinit(alloc);
        alloc.free(self.levels);
    }

    fn put(self: *SuffixTable, alloc: std.mem.Allocator, suffix: []const u8, target: []const u8) !void {
        const n = countLabels(suffix);
        if (n >= self.levels.len) return;
        try self.levels[n].put(alloc, suffix, target);
    }

    /// 最长后缀优先
    fn lookup(self: *const SuffixTable, host: []const u8) ?[]const u8 {
        const host_labels = countLabels(host);
        const max_level = self.levels.len - 1;
        var n = @min(host_labels, max_level);
        while (n >= 1) : (n -= 1) {
            const start = suffixStart(host, host_labels, n) orelse break;
            if (self.levels[n].get(host[start..])) |t| return t;
            if (n == 1) break;
        }
        return null;
    }
};

fn countLabels(d: []const u8) usize {
    if (d.len == 0) return 0;
    var n: usize = 1;
    for (d) |c| {
        if (c == '.') n += 1;
    }
    return n;
}

fn suffixStart(host: []const u8, total: usize, n: usize) ?usize {
    if (n == 0 or n > total) return null;
    const skip = total - n;
    if (skip == 0) return 0;
    var seen: usize = 0;
    for (host, 0..) |c, i| {
        if (c == '.') {
            seen += 1;
            if (seen == skip) return i + 1;
        }
    }
    return null;
}

pub const IpRoute = struct {
    action: Action,
    target: []const u8,
};

pub fn normalizeDomain(d: []const u8) []const u8 {
    var s = d;
    if (std.mem.startsWith(u8, s, "*.")) s = s[2..];
    if (std.mem.startsWith(u8, s, ".")) s = s[1..];
    return s;
}

/// 预编译的路由表
pub const Router = struct {
    alloc: std.mem.Allocator,

    route_suffix: SuffixTable,
    direct_suffix: SuffixTable,
    proxy_suffix: SuffixTable,

    route_keywords: []const DomainRoute,
    direct_keywords: []const []const u8,
    proxy_keywords: []const []const u8,

    ip_trie: IpTrie(IpRoute),

    direct_processes: []const []const u8,
    proxy_processes: []const []const u8,

    default_proxy: bool,

    pub fn compile(alloc: std.mem.Allocator, cfg: anytype) !Router {
        const max_labels = 16;
        var r = Router{
            .alloc = alloc,
            .route_suffix = try SuffixTable.init(alloc, max_labels),
            .direct_suffix = try SuffixTable.init(alloc, max_labels),
            .proxy_suffix = try SuffixTable.init(alloc, max_labels),
            .route_keywords = cfg.route_keywords,
            .direct_keywords = cfg.direct_keywords,
            .proxy_keywords = cfg.proxy_keywords,
            .ip_trie = try IpTrie(IpRoute).init(alloc),
            .direct_processes = cfg.direct_processes,
            .proxy_processes = cfg.proxy_processes,
            .default_proxy = cfg.default_proxy,
        };

        for (cfg.route_domains) |rd| {
            try r.route_suffix.put(alloc, normalizeDomain(rd.domain), rd.target);
        }
        for (cfg.direct_domains) |d| {
            try r.direct_suffix.put(alloc, normalizeDomain(d), "DIRECT");
        }
        for (cfg.proxy_domains) |d| {
            try r.proxy_suffix.put(alloc, normalizeDomain(d), "PROXY");
        }

        // CIDR 前缀树编译（支持万级规则 O(32) 最长前缀常数级查询）
        for (cfg.direct_cidrs) |s| {
            if (lookupGeoIp(s)) |cidrs| {
                for (cidrs) |cs| {
                    if (Cidr.parse(cs)) |c| {
                        try r.ip_trie.insertCidr(c, .{ .action = .direct, .target = s });
                    } else |_| {}
                }
            } else if (Cidr.parse(s)) |c| {
                try r.ip_trie.insertCidr(c, .{ .action = .direct, .target = "direct-cidrs" });
            } else |_| {}
        }

        for (cfg.route_cidrs) |s| {
            const action: Action = if (std.ascii.eqlIgnoreCase(s.target, "DIRECT"))
                .direct
            else if (std.ascii.eqlIgnoreCase(s.target, "REJECT"))
                .reject
            else
                .proxy;

            if (lookupGeoIp(s.cidr)) |cidrs| {
                for (cidrs) |cs| {
                    if (Cidr.parse(cs)) |c| {
                        try r.ip_trie.insertCidr(c, .{ .action = action, .target = s.target });
                    } else |_| {}
                }
            } else if (Cidr.parse(s.cidr)) |c| {
                try r.ip_trie.insertCidr(c, .{ .action = action, .target = s.target });
            } else |_| {}
        }

        return r;
    }

    pub fn deinit(self: *Router) void {
        self.route_suffix.deinit(self.alloc);
        self.direct_suffix.deinit(self.alloc);
        self.proxy_suffix.deinit(self.alloc);
        self.ip_trie.deinit();
    }

    pub fn decideByDomain(self: *const Router, host: []const u8, default_node: []const u8) Decision {
        if (host.len == 0) return self.defaultDecision(default_node);

        var trimmed = host;
        while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '.') {
            trimmed = trimmed[0 .. trimmed.len - 1];
        }
        var buf: [256]u8 = undefined;
        if (trimmed.len > buf.len) return self.defaultDecision(default_node);
        const h = buf[0..trimmed.len];
        for (trimmed, 0..) |c, i| h[i] = std.ascii.toLower(c);

        // 1. 专属路由（最长后缀）
        if (self.route_suffix.lookup(h)) |target| {
            if (std.ascii.eqlIgnoreCase(target, "DIRECT")) {
                return .{ .action = .direct, .matched = target };
            }
            if (std.ascii.eqlIgnoreCase(target, "REJECT")) {
                return .{ .action = .reject, .matched = target };
            }
            return .{ .action = .proxy, .node = target, .matched = target };
        }

        // 2. 直连域名
        if (self.direct_suffix.lookup(h)) |_| {
            return .{ .action = .direct, .matched = "direct-domains" };
        }

        // 3. 代理域名
        if (self.proxy_suffix.lookup(h)) |_| {
            return .{ .action = .proxy, .node = default_node, .matched = "proxy-domains" };
        }

        // 4. 关键字专属路由 (route-keywords)
        for (self.route_keywords) |rk| {
            if (std.mem.indexOf(u8, h, rk.domain) != null) {
                if (std.ascii.eqlIgnoreCase(rk.target, "DIRECT")) {
                    return .{ .action = .direct, .matched = rk.target };
                }
                if (std.ascii.eqlIgnoreCase(rk.target, "REJECT")) {
                    return .{ .action = .reject, .matched = rk.target };
                }
                return .{ .action = .proxy, .node = rk.target, .matched = rk.target };
            }
        }

        // 5. 直连关键字 (direct-keywords)
        for (self.direct_keywords) |dk| {
            if (std.mem.indexOf(u8, h, dk) != null) {
                return .{ .action = .direct, .matched = "direct-keywords" };
            }
        }

        // 6. 代理关键字 (proxy-keywords)
        for (self.proxy_keywords) |pk| {
            if (std.mem.indexOf(u8, h, pk) != null) {
                return .{ .action = .proxy, .node = default_node, .matched = "proxy-keywords" };
            }
        }

        return self.defaultDecision(default_node);
    }

    pub fn decideByIp(self: *const Router, ip_val: Ip, default_node: []const u8) Decision {
        if (ip_val.isPrivate()) {
            return .{ .action = .direct, .matched = "private" };
        }
        if (self.ip_trie.lookup(ip_val)) |rule| {
            if (rule.action == .direct) {
                return .{ .action = .direct, .matched = rule.target };
            }
            if (rule.action == .reject) {
                return .{ .action = .reject, .matched = rule.target };
            }
            return .{ .action = .proxy, .node = rule.target, .matched = rule.target };
        }
        return self.defaultDecision(default_node);
    }

    pub fn decideByProcess(self: *const Router, proc_name: []const u8) ?Decision {
        if (proc_name.len == 0) return null;
        for (self.direct_processes) |p| {
            if (std.ascii.eqlIgnoreCase(p, proc_name)) {
                return .{ .action = .direct, .matched = "direct-processes" };
            }
        }
        for (self.proxy_processes) |p| {
            if (std.ascii.eqlIgnoreCase(p, proc_name)) {
                return .{ .action = .proxy, .matched = "proxy-processes" };
            }
        }
        return null;
    }

    fn defaultDecision(self: *const Router, default_node: []const u8) Decision {
        if (self.default_proxy) {
            return .{ .action = .proxy, .node = default_node, .matched = "default" };
        }
        return .{ .action = .direct, .matched = "default" };
    }
};

// ============================================================================
// 第五部分：节点冷却池（熔断）
// ============================================================================

pub const CooldownPool = struct {
    alloc: std.mem.Allocator,
    mutex: net.Mutex = .{},
    entries: std.StringHashMapUnmanaged(Entry) = .empty,

    const Entry = struct { fails: u32, until_ms: i64 };

    pub fn init(alloc: std.mem.Allocator) CooldownPool {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *CooldownPool) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| self.alloc.free(kv.key_ptr.*);
        self.entries.deinit(self.alloc);
    }

    pub fn markFail(self: *CooldownPool, name: []const u8, cooldown_ms: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now = net.milliTimestamp();
        if (self.entries.getPtr(name)) |e| {
            e.fails +|= 1;
            const factor: i64 = @min(@as(i64, 1) << @intCast(@min(e.fails - 1, 3)), 8);
            e.until_ms = now + cooldown_ms * factor;
        } else {
            const key = self.alloc.dupe(u8, name) catch return;
            self.entries.put(self.alloc, key, .{ .fails = 1, .until_ms = now + cooldown_ms }) catch {
                self.alloc.free(key);
            };
        }
    }

    pub fn markOk(self: *CooldownPool, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.getPtr(name)) |e| {
            e.fails = 0;
            e.until_ms = 0;
        }
    }

    pub fn isCooling(self: *CooldownPool, name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = self.entries.get(name) orelse return false;
        return net.milliTimestamp() < e.until_ms;
    }

    pub fn sweep(self: *CooldownPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now = net.milliTimestamp();
        var to_remove = std.ArrayList([]const u8).empty;
        defer to_remove.deinit(self.alloc);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (now >= kv.value_ptr.until_ms and kv.value_ptr.fails == 0) {
                to_remove.append(self.alloc, kv.key_ptr.*) catch {};
            }
        }
        for (to_remove.items) |k| {
            if (self.entries.fetchRemove(k)) |kv| self.alloc.free(kv.key);
        }
    }
};

