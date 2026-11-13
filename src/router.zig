const std = @import("std");
const config = @import("config.zig");

pub const RouteAction = enum {
    direct,
    proxy,
    reject,
};

pub const Router = struct {
    mode: config.Mode,

    pub fn init(mode: config.Mode) Router {
        return Router{
            .mode = mode,
        };
    }

    /// 决策目标地址的路由去向
    /// 默认安全原则: 在分流模式下，未显式声明为可信局域网或内网直连的外部流量，
    /// 默认经由加密代理节点转发，防止在明文链路泄露；恶意/风险域直接 Reject
    pub fn route(self: *const Router, host: []const u8, port: u16) RouteAction {
        _ = port;
        switch (self.mode) {
            .direct => return .direct,
            .global => return .proxy,
            .rule => {
                // 1. 本机与私有内网地址直连
                if (isLocalOrLan(host)) {
                    return .direct;
                }

                // 2. 已知恶意、追踪与安全黑洞域名拒斥 (Fail-closed)
                if (isBlocked(host)) {
                    return .reject;
                }

                // 3. 国内可信域直连
                if (isDomestic(host)) {
                    return .direct;
                }

                // 4. 默认安全策略: 外部流量默认安全加密代理
                return .proxy;
            },
        }
    }

    fn isLocalOrLan(host: []const u8) bool {
        if (std.mem.eql(u8, host, "localhost")) return true;
        if (std.mem.eql(u8, host, "127.0.0.1") or std.mem.startsWith(u8, host, "127.")) return true;
        if (std.mem.startsWith(u8, host, "10.")) return true;
        if (std.mem.startsWith(u8, host, "192.168.")) return true;
        if (std.mem.startsWith(u8, host, "172.16.") or
            std.mem.startsWith(u8, host, "172.17.") or
            std.mem.startsWith(u8, host, "172.18.") or
            std.mem.startsWith(u8, host, "172.19.") or
            std.mem.startsWith(u8, host, "172.2") or
            std.mem.startsWith(u8, host, "172.30.") or
            std.mem.startsWith(u8, host, "172.31.")) return true;
        if (std.mem.eql(u8, host, "::1")) return true;
        return false;
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
