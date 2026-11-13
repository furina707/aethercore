const std = @import("std");
const config = @import("config.zig");
const net = @import("net.zig");

pub const RouteAction = enum {
    direct,
    proxy,
    reject,
};

pub const IpCidr = struct {
    network: u32,
    mask: u32,

    pub fn init(ip_str: []const u8, prefix_len: u6) ?IpCidr {
        const ip = net.parseIp4Host(ip_str) orelse return null;
        const mask: u32 = if (prefix_len == 0)
            0
        else if (prefix_len >= 32)
            0xFFFFFFFF
        else
            ~@as(u32, 0) << @as(u5, @intCast(32 - prefix_len));
        return IpCidr{
            .network = ip & mask,
            .mask = mask,
        };
    }

    pub fn matches(self: IpCidr, ip: u32) bool {
        return (ip & self.mask) == self.network;
    }
};

pub const RouteDecision = struct {
    action: RouteAction,
    node_index: usize,
    is_per_ip_routed: bool = false,
    reason: []const u8 = "default",
};

pub const ActiveIpEntry = struct {
    target_ip: [32]u8 = undefined,
    target_ip_len: usize = 0,
    node_index: usize = 0,
    active_conns: u32 = 0,
    total_conns: u64 = 0,
};

pub const SpinLock = struct {
    state: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
    }

    pub fn unlock(self: *SpinLock) void {
        self.state.store(false, .release);
    }
};

pub const IpSessionTracker = struct {
    entries: [32]ActiveIpEntry = undefined,
    count: usize = 0,
    lock_state: SpinLock = .{},

    pub fn record(self: *IpSessionTracker, ip_str: []const u8, node_idx: usize) void {
        self.lock_state.lock();
        defer self.lock_state.unlock();

        // 查找是否已存在
        for (self.entries[0..self.count]) |*entry| {
            if (entry.target_ip_len == ip_str.len and std.mem.eql(u8, entry.target_ip[0..entry.target_ip_len], ip_str)) {
                entry.node_index = node_idx;
                entry.active_conns += 1;
                entry.total_conns += 1;
                return;
            }
        }

        // 新增条目
        if (self.count < self.entries.len) {
            var new_entry = &self.entries[self.count];
            const len = @min(ip_str.len, 31);
            @memcpy(new_entry.target_ip[0..len], ip_str[0..len]);
            new_entry.target_ip_len = len;
            new_entry.node_index = node_idx;
            new_entry.active_conns = 1;
            new_entry.total_conns = 1;
            self.count += 1;
        } else {
            // 环形覆盖最旧的条目
            var old_entry = &self.entries[0];
            const len = @min(ip_str.len, 31);
            @memcpy(old_entry.target_ip[0..len], ip_str[0..len]);
            old_entry.target_ip_len = len;
            old_entry.node_index = node_idx;
            old_entry.active_conns = 1;
            old_entry.total_conns += 1;
        }
    }

    pub fn release(self: *IpSessionTracker, ip_str: []const u8) void {
        self.lock_state.lock();
        defer self.lock_state.unlock();

        for (self.entries[0..self.count]) |*entry| {
            if (entry.target_ip_len == ip_str.len and std.mem.eql(u8, entry.target_ip[0..entry.target_ip_len], ip_str)) {
                if (entry.active_conns > 0) entry.active_conns -= 1;
                return;
            }
        }
    }
};

pub const Router = struct {
    mode: config.Mode,
    ip_tracker: *IpSessionTracker,

    // 私有与本地回环 CIDR
    const lan_cidrs = [_]IpCidr{
        IpCidr.init("127.0.0.0", 8).?,
        IpCidr.init("10.0.0.0", 8).?,
        IpCidr.init("172.16.0.0", 12).?,
        IpCidr.init("192.168.0.0", 16).?,
        IpCidr.init("100.64.0.0", 10).?,
        IpCidr.init("169.254.0.0", 16).?,
    };

    pub fn init(mode: config.Mode, tracker: *IpSessionTracker) Router {
        return Router{
            .mode = mode,
            .ip_tracker = tracker,
        };
    }

    /// 核心功能: 分 IP 代理与智能路由判定
    /// 1. 目标为 IP 时，进行 CIDR 匹配与一致性 IP 哈希分流 (Per-IP Hash Dispatch)
    /// 2. 目标为域名时，根据国内域/黑名单判定直连或分流
    /// 3. 分配的出站节点索引 node_index 直接生效，实现多节点分 IP 代理出口
    pub fn routeTarget(
        self: *const Router,
        host: []const u8,
        port: u16,
        default_node_index: usize,
        total_nodes: usize,
    ) RouteDecision {
        _ = port;

        switch (self.mode) {
            .direct => return .{
                .action = .direct,
                .node_index = 0,
                .reason = "global_direct",
            },
            .global => {
                const assigned_idx = self.assignIpNode(host, default_node_index, total_nodes);
                return .{
                    .action = .proxy,
                    .node_index = assigned_idx,
                    .is_per_ip_routed = true,
                    .reason = "global_per_ip",
                };
            },
            .rule => {
                // 1. 检查是否为 IPv4 地址
                if (net.parseIp4Host(host)) |ip_val| {
                    // 局域网 / 回环 CIDR 直连
                    for (lan_cidrs) |cidr| {
                        if (cidr.matches(ip_val)) {
                            return .{
                                .action = .direct,
                                .node_index = 0,
                                .reason = "lan_cidr_direct",
                            };
                        }
                    }

                    // 外部公网 IP: 核心功能「分 IP 代理」
                    // 通过一致性 IP 哈希将不同的公网目标 IP 均匀分配到不同的代理出口节点
                    const assigned_idx = self.assignIpNode(host, default_node_index, total_nodes);
                    return .{
                        .action = .proxy,
                        .node_index = assigned_idx,
                        .is_per_ip_routed = true,
                        .reason = "per_ip_cidr_proxy",
                    };
                }

                // 2. 域名检查
                if (std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1")) {
                    return .{ .action = .direct, .node_index = 0, .reason = "local_domain" };
                }

                if (isBlocked(host)) {
                    return .{ .action = .reject, .node_index = 0, .reason = "blocked_ad_tracker" };
                }

                if (isDomestic(host)) {
                    return .{ .action = .direct, .node_index = 0, .reason = "domestic_direct" };
                }

                // 外部域名通过哈希分配到分 IP 代理出口
                const assigned_idx = self.assignIpNode(host, default_node_index, total_nodes);
                return .{
                    .action = .proxy,
                    .node_index = assigned_idx,
                    .is_per_ip_routed = true,
                    .reason = "per_ip_domain_proxy",
                };
            },
        }
    }

    /// 分 IP 代理核心调度算法: 一致性哈希分流
    /// 将不同的目标 IP / 域名确定性映射到特定的代理出口节点，保持连接粘性同时实现并发分 IP
    fn assignIpNode(self: *const Router, host: []const u8, default_idx: usize, total_nodes: usize) usize {
        _ = self;
        if (total_nodes <= 1) return default_idx;

        // FNV-1a 32-bit 哈希算法
        var hash: u32 = 2166136261;
        for (host) |b| {
            hash ^= b;
            hash *%= 16777619;
        }

        // 可用代理节点（跳过 0 号直连节点）
        const proxy_nodes_count = total_nodes - 1;
        if (proxy_nodes_count > 0) {
            const offset = hash % @as(u32, @intCast(proxy_nodes_count));
            return @intCast(offset + 1);
        }

        return default_idx;
    }

    fn isBlocked(host: []const u8) bool {
        const blacklist = [_][]const u8{
            "doubleclick.net",
            "google-analytics.com",
            "adservice.google.com",
            "telemetry.",
            "tracker.",
            "analytics.",
        };
        for (blacklist) |item| {
            if (std.mem.indexOf(u8, host, item) != null) return true;
        }
        return false;
    }

    fn isDomestic(host: []const u8) bool {
        if (std.mem.endsWith(u8, host, ".cn")) return true;
        const domestic_domains = [_][]const u8{
            "baidu.com",
            "qq.com",
            "taobao.com",
            "jd.com",
            "bilibili.com",
            "163.com",
            "sina.com.cn",
            "aliyun.com",
            "weibo.com",
            "zhihu.com",
        };
        for (domestic_domains) |domain| {
            if (std.mem.endsWith(u8, host, domain)) return true;
        }
        return false;
    }
};
