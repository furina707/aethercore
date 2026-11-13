const std = @import("std");

pub const Mode = enum {
    rule,
    global,
    direct,

    pub fn toString(self: Mode) []const u8 {
        return switch (self) {
            .rule => "rule",
            .global => "global",
            .direct => "direct",
        };
    }

    pub fn fromString(str: []const u8) Mode {
        if (std.mem.eql(u8, str, "global")) return .global;
        if (std.mem.eql(u8, str, "direct")) return .direct;
        return .rule;
    }
};

pub const ProxyNode = struct {
    id: []const u8,
    name: []const u8,
    protocol: []const u8, // "vless", "socks5", "http", "direct"
    server: []const u8,
    port: u16,
    uuid: []const u8 = "",
    latency_ms: i32 = -1,
};

pub const AppConfig = struct {
    mode: Mode = .rule,
    socks5_port: u16 = 10808,
    http_port: u16 = 10809,
    control_port: u16 = 9097,
    allow_lan: bool = false, // 默认安全: 绝不监听局域网
    active_node_index: usize = 0,
    nodes: std.ArrayListUnmanaged(ProxyNode) = .empty,

    pub const CONFIG_PATH = "data/core.json";

    pub fn initDefault(allocator: std.mem.Allocator) !AppConfig {
        var cfg = AppConfig{
            .mode = .rule,
            .socks5_port = 10808,
            .http_port = 10809,
            .control_port = 9097,
            .allow_lan = false,
            .active_node_index = 0,
            .nodes = .empty,
        };

        // 默认预设节点
        try cfg.nodes.append(allocator, .{
            .id = try allocator.dupe(u8, "node-direct"),
            .name = try allocator.dupe(u8, "直连出站 (Direct)"),
            .protocol = try allocator.dupe(u8, "direct"),
            .server = try allocator.dupe(u8, "127.0.0.1"),
            .port = 0,
            .latency_ms = 1,
        });

        try cfg.nodes.append(allocator, .{
            .id = try allocator.dupe(u8, "node-hk-01"),
            .name = try allocator.dupe(u8, "香港专线 01 (VLESS-XTLS)"),
            .protocol = try allocator.dupe(u8, "vless"),
            .server = try allocator.dupe(u8, "hk01.aethercore.net"),
            .port = 443,
            .uuid = try allocator.dupe(u8, "a3e8c07e-1234-5678-9abc-def012345678"),
            .latency_ms = 18,
        });

        try cfg.nodes.append(allocator, .{
            .id = try allocator.dupe(u8, "node-jp-01"),
            .name = try allocator.dupe(u8, "东京专线 02 (VLESS-BGP)"),
            .protocol = try allocator.dupe(u8, "vless"),
            .server = try allocator.dupe(u8, "jp01.aethercore.net"),
            .port = 443,
            .uuid = try allocator.dupe(u8, "b4f9d18f-2345-6789-0bcd-ef0123456789"),
            .latency_ms = 42,
        });

        return cfg;
    }

    pub fn deinit(self: *AppConfig, allocator: std.mem.Allocator) void {
        for (self.nodes.items) |n| {
            allocator.free(n.id);
            allocator.free(n.name);
            allocator.free(n.protocol);
            allocator.free(n.server);
            if (n.uuid.len > 0) allocator.free(n.uuid);
        }
        self.nodes.deinit(allocator);
    }

    pub fn getActiveNode(self: *const AppConfig) ?ProxyNode {
        if (self.nodes.items.len == 0) return null;
        const idx = if (self.active_node_index < self.nodes.items.len) self.active_node_index else 0;
        return self.nodes.items[idx];
    }
};
