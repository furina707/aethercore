//! aetherd —— AetherCore 主运行程序与命令行守护进程。
//! 整合了应用层核心配置、控制台、巡检、节点组、运行时与 CLI 入口。

const std = @import("std");
const builtin = @import("builtin");

// 引入其他 6 个核心领域模块
pub const net = @import("net.zig");
pub const dns = @import("dns.zig");
pub const router = @import("router.zig");
pub const proxy = @import("proxy.zig");
pub const tcp_stack = @import("tcp_stack.zig");
pub const tun = @import("tun.zig");

// 便捷别名
pub const version = "0.2.0";
pub const elevate = net.elevate;
pub const conntrack = tcp_stack.conntrack;
pub const relay = struct {
    pub const Stats = net.RelayStats;
    pub const RelayStats = net.RelayStats;
    pub const relay = net.relay;
};
pub const dnsserver = dns;
pub const tls = proxy;
pub const tun_route = tun.tun_route;
pub const tun_runner = tun.tun_runner;
pub const tun_glue = tun.tun_glue;

const core = @This();

pub const WEB_INDEX_HTML =
    \\<!doctype html>
    \\<html lang="zh-CN">
    \\<head>
    \\  <meta charset="utf-8" />
    \\  <title>AetherCore Dashboard</title>
    \\  <script>
    \\    window.__API_TOKEN__ = '__API_TOKEN_PLACEHOLDER__';
    \\  </script>
    \\</head>
    \\<body>
    \\  <div id="app">
    \\    <h1>AetherCore 控制面板</h1>
    \\    <p>内核运行中...</p>
    \\  </div>
    \\</body>
    \\</html>
;

pub const config = struct {
    // 配置模型（`core.json` schema）。
    //
    // **设计要点（修复原 Rust 版的核心缺陷）**：
    // 原版存在两套解析器（`config::RootConfig` 用 `_` 字段名、`CoreConfig::from_json`
    // 用 `-` 字段名），同一个文件会解析出不同结果。本模块只保留**一份**解析器，
    // 且同时接受 `-` 与 `_` 两种键名（历史文件两种都出现过）。

    pub const Proto = proxy.Proto;

    /// 单个节点
    pub const Node = proxy.Node;

    pub const Mode = enum {
        rule,
        global,
        direct,

        pub fn fromString(s: []const u8) Mode {
            if (std.ascii.eqlIgnoreCase(s, "global")) return .global;
            if (std.ascii.eqlIgnoreCase(s, "direct")) return .direct;
            return .rule;
        }

        pub fn toString(self: Mode) []const u8 {
            return switch (self) {
                .rule => "rule",
                .global => "global",
                .direct => "direct",
            };
        }
    };

    /// 域名→目标 规则对
    pub const DomainRoute = router.DomainRoute;

    /// CIDR→目标 规则对
    pub const CidrRoute = router.CidrRoute;

    /// 完整配置
    pub const Config = struct {
        alloc: std.mem.Allocator,

        listen_host: []const u8 = "127.0.0.1",
        listen_port: u16 = 7899,
        controller_host: []const u8 = "127.0.0.1",
        controller_port: u16 = 9097,
        wd_host: []const u8 = "0.0.0.0",
        wd_port: u16 = 19099,

        nodes: []Node = &.{},
        route_domains: []DomainRoute = &.{},
        route_keywords: []DomainRoute = &.{},
        direct_domains: [][]const u8 = &.{},
        proxy_domains: [][]const u8 = &.{},
        direct_keywords: [][]const u8 = &.{},
        proxy_keywords: [][]const u8 = &.{},
        route_cidrs: []CidrRoute = &.{},
        direct_cidrs: [][]const u8 = &.{},
        direct_processes: [][]const u8 = &.{},
        proxy_processes: [][]const u8 = &.{},

        default_proxy: bool = true,
        mode: Mode = .rule,
        sub_url: []const u8 = "",
        data_dir: []const u8 = "data",

        /// 控制面鉴权 token。留空则启动时从 `<data_dir>/middleware.token`
        /// 读取或自动生成（与旧 Rust / Python 中间件行为一致）。
        auth_token: []const u8 = "",

        // ---- DNS / Fake-IP ----
        /// 是否启用内置 DNS 服务
        dns_enabled: bool = false,
        dns_listen_host: []const u8 = "127.0.0.1",
        dns_listen_port: u16 = 5353,
        dns_upstream_host: []const u8 = "223.5.5.5",
        dns_upstream_port: u16 = 53,
        /// Fake-IP 应答的 TTL（秒）
        dns_ttl: u32 = 60,

        /// 从文件加载
        pub fn loadFromFile(alloc: std.mem.Allocator, path: []const u8) !Config {
            const text = try readFileAlloc(alloc, path, 32 * 1024 * 1024);
            defer alloc.free(text);
            const dir = std.fs.path.dirname(path) orelse ".";
            return parse(alloc, text, dir);
        }

        fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
            if (builtin.os.tag == .windows) {
                const win_file = struct {
                    extern "kernel32" fn CreateFileW(
                        lpFileName: [*:0]const u16,
                        dwDesiredAccess: u32,
                        dwShareMode: u32,
                        lpSecurityAttributes: ?*anyopaque,
                        dwCreationDisposition: u32,
                        dwFlagsAndAttributes: u32,
                        hTemplateFile: ?*anyopaque,
                    ) callconv(.winapi) ?std.os.windows.HANDLE;
                    extern "kernel32" fn ReadFile(
                        hFile: ?std.os.windows.HANDLE,
                        lpBuffer: [*]u8,
                        nNumberOfBytesToRead: u32,
                        lpNumberOfBytesRead: ?*u32,
                        lpOverlapped: ?*anyopaque,
                    ) callconv(.winapi) std.os.windows.BOOL;
                    extern "kernel32" fn CloseHandle(hObject: ?std.os.windows.HANDLE) callconv(.winapi) std.os.windows.BOOL;
                    extern "kernel32" fn GetFileSize(hFile: ?std.os.windows.HANDLE, lpFileSizeHigh: ?*u32) callconv(.winapi) u32;
                };

                var wbuf: [512]u16 = undefined;
                const n = std.unicode.utf8ToUtf16Le(&wbuf, path) catch return error.FileNotFound;
                wbuf[n] = 0;
                const h = win_file.CreateFileW(
                    @ptrCast(&wbuf),
                    0x80000000,
                    1,
                    null,
                    3,
                    0x80,
                    null,
                );
                if (h == std.os.windows.INVALID_HANDLE_VALUE or h == null) return error.FileNotFound;
                defer _ = win_file.CloseHandle(h);

                const sz = win_file.GetFileSize(h, null);
                if (sz == 0xFFFFFFFF or sz > max_bytes) return error.FileTooBig;

                const out = try alloc.alloc(u8, sz);
                errdefer alloc.free(out);
                var bytes_read: u32 = 0;
                if (win_file.ReadFile(h, out.ptr, sz, &bytes_read, null) == .FALSE) {
                    return error.ReadFailed;
                }
                return out[0..bytes_read];
            } else {
                const fd = try std.posix.open(path, .{ .ACCMODE = .RDONLY }, 0);
                defer std.posix.close(fd);
                const out = try alloc.alloc(u8, max_bytes);
                errdefer alloc.free(out);
                const bytes_read = try std.posix.read(fd, out);
                return alloc.realloc(out, bytes_read);
            }
        }

        /// 从 JSON 文本解析。`data_dir` 仅用于记录，不参与解析逻辑。
        pub fn parse(alloc: std.mem.Allocator, text: []const u8, data_dir: []const u8) !Config {
            const parsed = try std.json.parseFromSlice(std.json.Value, alloc, text, .{});
            defer parsed.deinit();
            // 所有字段都 dupe 到 alloc 上，所以这里可以安全释放解析树。
            const root = parsed.value;
            const obj = switch (root) {
                .object => |o| o,
                else => return error.InvalidConfig,
            };

            // 所有字符串字段一律由 alloc 持有：默认值也复制一份，
            // 这样 deinit() 可以无条件释放，不需要区分「字面量还是分配」。
            var cfg = Config{
                .alloc = alloc,
                .listen_host = try alloc.dupe(u8, "127.0.0.1"),
                .controller_host = try alloc.dupe(u8, "127.0.0.1"),
                .wd_host = try alloc.dupe(u8, "0.0.0.0"),
                .sub_url = try alloc.dupe(u8, ""),
                .dns_listen_host = try alloc.dupe(u8, "127.0.0.1"),
                .dns_upstream_host = try alloc.dupe(u8, "223.5.5.5"),
                .data_dir = try alloc.dupe(u8, data_dir),
                .auth_token = try alloc.dupe(u8, ""),
            };

            if (getValue(obj, &.{ "auth-token", "auth_token", "token" })) |v| {
                if (v == .string) {
                    alloc.free(cfg.auth_token);
                    cfg.auth_token = try alloc.dupe(u8, v.string);
                }
            }

            // listen: ["127.0.0.1", 7899]
            if (getValue(obj, &.{ "listen" })) |v| {
                if (parseHostPort(v)) |hp| {
                    alloc.free(cfg.listen_host);
                    cfg.listen_host = try alloc.dupe(u8, hp.host);
                    cfg.listen_port = hp.port;
                }
            }
            if (getValue(obj, &.{ "controller" })) |v| {
                if (parseHostPort(v)) |hp| {
                    alloc.free(cfg.controller_host);
                    cfg.controller_host = try alloc.dupe(u8, hp.host);
                    cfg.controller_port = hp.port;
                }
            }
            if (getValue(obj, &.{ "wd-listen", "wd_listen" })) |v| {
                if (parseHostPort(v)) |hp| {
                    alloc.free(cfg.wd_host);
                    cfg.wd_host = try alloc.dupe(u8, hp.host);
                    cfg.wd_port = hp.port;
                }
            }

            // nodes
            if (getValue(obj, &.{ "nodes" })) |v| {
                if (v == .array) {
                    var list = std.ArrayList(Node).empty;
                    for (v.array.items) |item| {
                        if (item != .object) continue;
                        if (parseNode(alloc, item.object)) |n| {
                            try list.append(alloc, n);
                        } else |_| {}
                    }
                    cfg.nodes = try list.toOwnedSlice(alloc);
                }
            }

            // route-domains: [[domain, target], ...]
            if (getValue(obj, &.{ "route-domains", "route_domains" })) |v| {
                if (v == .array) {
                    var list = std.ArrayList(DomainRoute).empty;
                    for (v.array.items) |pair| {
                        if (pair != .array or pair.array.items.len < 2) continue;
                        const d = pair.array.items[0];
                        const t = pair.array.items[1];
                        if (d != .string or t != .string) continue;
                        try list.append(alloc, .{
                            .domain = try normalizeDomain(alloc, d.string),
                            .target = try alloc.dupe(u8, t.string),
                        });
                    }
                    cfg.route_domains = try list.toOwnedSlice(alloc);
                }
            }

            cfg.direct_domains = try parseStringArray(alloc, getValue(obj, &.{ "direct-domains", "direct_domains" }), true);
            cfg.proxy_domains = try parseStringArray(alloc, getValue(obj, &.{ "proxy-domains", "proxy_domains" }), true);

            // route-keywords / direct-keywords / proxy-keywords
            if (getValue(obj, &.{ "route-keywords", "route_keywords" })) |v| {
                if (v == .array) {
                    var list = std.ArrayList(DomainRoute).empty;
                    for (v.array.items) |pair| {
                        if (pair != .array or pair.array.items.len < 2) continue;
                        const d = pair.array.items[0];
                        const t = pair.array.items[1];
                        if (d != .string or t != .string) continue;
                        try list.append(alloc, .{
                            .domain = try normalizeDomain(alloc, d.string),
                            .target = try alloc.dupe(u8, t.string),
                        });
                    }
                    cfg.route_keywords = try list.toOwnedSlice(alloc);
                }
            }
            cfg.direct_keywords = try parseStringArray(alloc, getValue(obj, &.{ "direct-keywords", "direct_keywords" }), true);
            cfg.proxy_keywords = try parseStringArray(alloc, getValue(obj, &.{ "proxy-keywords", "proxy_keywords" }), true);

            cfg.direct_processes = try parseStringArray(alloc, getValue(obj, &.{ "direct-processes", "direct_processes" }), false);
            cfg.proxy_processes = try parseStringArray(alloc, getValue(obj, &.{ "proxy-processes", "proxy_processes" }), false);

            // direct-cidrs / route-cidrs
            cfg.direct_cidrs = try parseStringArray(alloc, getValue(obj, &.{ "direct-cidrs", "direct_cidrs" }), false);
            if (getValue(obj, &.{ "route-cidrs", "route_cidrs" })) |v| {
                if (v == .array) {
                    var list = std.ArrayList(CidrRoute).empty;
                    for (v.array.items) |pair| {
                        if (pair != .array or pair.array.items.len < 2) continue;
                        const c = pair.array.items[0];
                        const t = pair.array.items[1];
                        if (c != .string or t != .string) continue;
                        try list.append(alloc, .{
                            .cidr = try alloc.dupe(u8, c.string),
                            .target = try alloc.dupe(u8, t.string),
                        });
                    }
                    cfg.route_cidrs = try list.toOwnedSlice(alloc);
                }
            }

            // default: "proxy" | "direct"
            if (getValue(obj, &.{ "default" })) |v| {
                if (v == .string) cfg.default_proxy = !std.ascii.eqlIgnoreCase(v.string, "direct");
            }

            // proxy_mode / mode
            if (getValue(obj, &.{ "proxy_mode", "proxy-mode", "mode" })) |v| {
                if (v == .string) cfg.mode = Mode.fromString(v.string);
            }

            if (getValue(obj, &.{ "sub_url", "sub-url" })) |v| {
                if (v == .string) {
                    alloc.free(cfg.sub_url);
                    cfg.sub_url = try alloc.dupe(u8, v.string);
                }
            }

            // ---- DNS ----
            // 支持两种写法：
            //   "dns": {"listen":["127.0.0.1",5353], "upstream":["223.5.5.5",53], "ttl":60}
            //   "dns-listen": [...], "dns-upstream": [...]
            if (getValue(obj, &.{ "dns" })) |dnsv| {
                if (dnsv == .object) {
                    cfg.dns_enabled = true;
                    const d = dnsv.object;
                    if (getValue(d, &.{ "listen" })) |lv| {
                        if (parseHostPort(lv)) |hp| {
                            alloc.free(cfg.dns_listen_host);
                            cfg.dns_listen_host = try alloc.dupe(u8, hp.host);
                            cfg.dns_listen_port = hp.port;
                        }
                    }
                    if (getValue(d, &.{ "upstream" })) |uv| {
                        if (parseHostPort(uv)) |hp| {
                            alloc.free(cfg.dns_upstream_host);
                            cfg.dns_upstream_host = try alloc.dupe(u8, hp.host);
                            cfg.dns_upstream_port = hp.port;
                        }
                    }
                    if (getValue(d, &.{ "ttl" })) |tv| {
                        if (tv == .integer and tv.integer > 0) cfg.dns_ttl = @intCast(tv.integer);
                    }
                }
            }
            if (getValue(obj, &.{ "dns-listen", "dns_listen" })) |v| {
                if (parseHostPort(v)) |hp| {
                    cfg.dns_enabled = true;
                    alloc.free(cfg.dns_listen_host);
                    cfg.dns_listen_host = try alloc.dupe(u8, hp.host);
                    cfg.dns_listen_port = hp.port;
                }
            }
            if (getValue(obj, &.{ "dns-upstream", "dns_upstream" })) |v| {
                if (parseHostPort(v)) |hp| {
                    alloc.free(cfg.dns_upstream_host);
                    cfg.dns_upstream_host = try alloc.dupe(u8, hp.host);
                    cfg.dns_upstream_port = hp.port;
                }
            }

            return cfg;
        }

        pub fn deinit(self: *Config) void {
            const a = self.alloc;
            for (self.nodes) |n| {
                a.free(n.name);
                a.free(n.server);
                a.free(n.uuid);
                a.free(n.sni);
                a.free(n.ws_path);
                a.free(n.ws_host);
                a.free(n.password);
                a.free(n.ports);
                a.free(n.obfs);
                a.free(n.method);
            }
            a.free(self.nodes);

            for (self.route_domains) |r| {
                a.free(r.domain);
                a.free(r.target);
            }
            a.free(self.route_domains);

            for (self.route_keywords) |r| {
                a.free(r.domain);
                a.free(r.target);
            }
            a.free(self.route_keywords);

            for (self.route_cidrs) |r| {
                a.free(r.cidr);
                a.free(r.target);
            }
            a.free(self.route_cidrs);

            freeStringSlice(a, self.direct_domains);
            freeStringSlice(a, self.proxy_domains);
            freeStringSlice(a, self.direct_keywords);
            freeStringSlice(a, self.proxy_keywords);
            freeStringSlice(a, self.direct_processes);
            freeStringSlice(a, self.proxy_processes);
            freeStringSlice(a, self.direct_cidrs);

            a.free(self.listen_host);
            a.free(self.controller_host);
            a.free(self.wd_host);
            a.free(self.sub_url);
            a.free(self.dns_listen_host);
            a.free(self.dns_upstream_host);
            a.free(self.data_dir);
            a.free(self.auth_token);
        }

        /// 按名字找节点
        pub fn findNode(self: Config, name: []const u8) ?Node {
            for (self.nodes) |n| {
                if (std.mem.eql(u8, n.name, name)) return n;
            }
            return null;
        }

        /// 默认节点（第一个）
        pub fn defaultNode(self: Config) ?Node {
            if (self.nodes.len == 0) return null;
            return self.nodes[0];
        }

        /// 审计配置安全性（默认安全防范：检查是否有节点处于不安全或明文状态）
        pub fn auditSecurity(self: Config) usize {
            var insecure_count: usize = 0;
            for (self.nodes) |n| {
                if (!n.isSecure()) {
                    insecure_count += 1;
                    std.debug.print("[SECURITY ALERT] 节点 '{s}' ({s}://{s}:{d}) 未满足默认安全基线 (tls={any}, insecure={any})！未开启的安全是不安全的。\n", .{
                        n.name, n.proto.toString(), n.server, n.port, n.tls, n.insecure,
                    });
                }
            }
            return insecure_count;
        }
    };

    const HostPort = struct { host: []const u8, port: u16 };

    fn parseHostPort(v: std.json.Value) ?HostPort {
        if (v != .array) return null;
        const items = v.array.items;
        if (items.len < 2) return null;
        if (items[0] != .string) return null;
        const port: u16 = switch (items[1]) {
            .integer => |i| if (i >= 0 and i <= 65535) @intCast(i) else return null,
            else => return null,
        };
        return .{ .host = items[0].string, .port = port };
    }

    /// 同时接受 `-` 与 `_` 两种键名
    fn getValue(obj: std.json.ObjectMap, keys: []const []const u8) ?std.json.Value {
        for (keys) |k| {
            if (obj.get(k)) |v| return v;
        }
        return null;
    }

    fn parseNode(alloc: std.mem.Allocator, obj: std.json.ObjectMap) !Node {
        const name_v = obj.get("name") orelse return error.MissingName;
        if (name_v != .string) return error.MissingName;
        const server_v = obj.get("server") orelse return error.MissingServer;
        if (server_v != .string) return error.MissingServer;

        const port: u16 = blk: {
            const p = obj.get("port") orelse break :blk 443;
            break :blk switch (p) {
                .integer => |i| if (i > 0 and i <= 65535) @intCast(i) else 443,
                else => 443,
            };
        };

        const proto_s = if (obj.get("type")) |t| (if (t == .string) t.string else "vless") else "vless";

        return Node{
            .name = try alloc.dupe(u8, name_v.string),
            .proto = Proto.fromString(proto_s),
            .server = try alloc.dupe(u8, server_v.string),
            .port = port,
            .uuid = try dupStr(alloc, obj, &.{"uuid"}),
            .tls = try boolField(obj, &.{"tls"}, true), // 默认安全：未配置时强制开启 TLS
            .pqc = try boolField(obj, &.{ "pqc", "mlkem", "kyber" }, true), // 默认安全：未配置时开启抗量子混合协商
            .sni = try dupStr(alloc, obj, &.{ "sni", "servername" }),
            .ws_path = try dupStr(alloc, obj, &.{ "ws-path", "ws_path", "path" }),
            .ws_host = try dupStr(alloc, obj, &.{ "ws-host", "ws_host", "host" }),
            .password = try dupStr(alloc, obj, &.{ "password", "auth", "auth_str" }),
            .ports = try dupStr(alloc, obj, &.{ "ports", "port-range" }),
            .obfs = try dupStr(alloc, obj, &.{ "obfs", "obfs-password" }),
            .insecure = try boolField(obj, &.{ "insecure", "skip-cert-verify" }, false), // 默认安全：严格校验证书，默认禁止跳过
            .method = blk: {
                const m = try dupStr(alloc, obj, &.{ "cipher", "method" });
                if (m.len > 0) break :blk m;
                alloc.free(m);
                break :blk try alloc.dupe(u8, "2022-blake3-aes-128-gcm");
            },
        };
    }

    fn dupStr(alloc: std.mem.Allocator, obj: std.json.ObjectMap, keys: []const []const u8) ![]const u8 {
        for (keys) |k| {
            if (obj.get(k)) |v| {
                if (v == .string) return try alloc.dupe(u8, v.string);
            }
        }
        return try alloc.dupe(u8, "");
    }

    fn boolField(obj: std.json.ObjectMap, keys: []const []const u8, default: bool) !bool {
        for (keys) |k| {
            if (obj.get(k)) |v| {
                return switch (v) {
                    .bool => |b| b,
                    .string => |s| std.ascii.eqlIgnoreCase(s, "true") or std.mem.eql(u8, s, "1"),
                    .integer => |i| i != 0,
                    else => default,
                };
            }
        }
        return default;
    }

    fn parseStringArray(alloc: std.mem.Allocator, maybe: ?std.json.Value, normalize: bool) ![][]const u8 {
        const v = maybe orelse return &.{};
        if (v != .array) return &.{};
        var list = std.ArrayList([]const u8).empty;
        for (v.array.items) |item| {
            if (item != .string) continue;
            const s = if (normalize)
                try normalizeDomain(alloc, item.string)
            else
                try alloc.dupe(u8, item.string);
            try list.append(alloc, s);
        }
        return try list.toOwnedSlice(alloc);
    }

    fn freeStringSlice(a: std.mem.Allocator, items: [][]const u8) void {
        for (items) |s| a.free(s);
        a.free(items);
    }

    /// 域名归一化：去空白、小写、去掉开头的 `.` 与 `*.`
    pub fn normalizeDomain(alloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
        var s = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.startsWith(u8, s, "*.")) s = s[2..];
        while (s.len > 0 and s[0] == '.') s = s[1..];
        const out = try alloc.alloc(u8, s.len);
        for (s, 0..) |c, i| out[i] = std.ascii.toLower(c);
        return out;
    }










};
pub const AppConfig = config.Config;

pub const authtoken = struct {
    // 控制面鉴权 token
    //
    // 对应 Python 中间件与旧 Rust `aether-ctrl/src/auth.rs` 的
    // `load_or_create_token()`：token 存在 `<data_dir>/middleware.token`，
    // 首次运行时生成，之后复用。
    //
    // 与旧 Rust 实现的区别（这是刻意修的）：
    //   - Rust 版在 Windows 上用「纳秒时间戳 + xorshift64」当熵源，注释里自己写着
    //     「正式实现应改用 BCryptGenRandom」。时间戳熵在启动瞬间可预测，等于没有。
    //   - 这里统一走 `std.crypto.random`：Windows 上是 BCryptGenRandom，
    //     Linux/Android 是 getrandom，macOS 是 arc4random —— 都是密码学安全的。
    //     失败就直接报错，不做「兜底生成」，因为可预测的 token 比没有 token 更危险。

    const windows = std.os.windows;

    const win_file = struct {
        extern "kernel32" fn CreateFileW(
            lpFileName: [*:0]const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: ?*anyopaque,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: ?*anyopaque,
        ) callconv(.winapi) ?windows.HANDLE;

        extern "kernel32" fn ReadFile(
            hFile: ?windows.HANDLE,
            lpBuffer: [*]u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: ?*u32,
            lpOverlapped: ?*anyopaque,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn WriteFile(
            hFile: ?windows.HANDLE,
            lpBuffer: [*]const u8,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: ?*u32,
            lpOverlapped: ?*anyopaque,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn CreateDirectoryW(
            lpPathName: [*:0]const u16,
            lpSecurityAttributes: ?*anyopaque,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn CloseHandle(hObject: ?windows.HANDLE) callconv(.winapi) windows.BOOL;
    };

    /// token 文件名（与 Python 版 / Rust 版保持一致，便于复用已有 token）
    pub const TOKEN_FILE = "middleware.token";

    /// 生成 token 用的随机字节数。hex 编码后长度 64。
    pub const TOKEN_BYTES = 32;

    /// 生成一个随机 token（hex 编码，调用方负责 free）
    pub fn generate(alloc: std.mem.Allocator) ![]u8 {
        var raw: [TOKEN_BYTES]u8 = undefined;
        fillRandom(&raw);

        const out = try alloc.alloc(u8, TOKEN_BYTES * 2);
        _ = std.fmt.bufPrint(out, "{x}", .{raw}) catch {
            alloc.free(out);
            return error.NoSpaceLeft;
        };
        return out;
    }

    /// 填充密码学安全随机字节
    fn fillRandom(buf: []u8) void {
        net.fillRandom(buf);
    }

    fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
        if (builtin.os.tag == .windows) {
            var wbuf: [512]u16 = undefined;
            const n = std.unicode.utf8ToUtf16Le(&wbuf, path) catch return error.FileNotFound;
            wbuf[n] = 0;
            const h = win_file.CreateFileW(
                @ptrCast(&wbuf),
                0x80000000, // GENERIC_READ
                1, // FILE_SHARE_READ
                null,
                3, // OPEN_EXISTING
                0x80, // FILE_ATTRIBUTE_NORMAL
                null,
            );
            if (h == windows.INVALID_HANDLE_VALUE or h == null) return error.FileNotFound;
            defer _ = win_file.CloseHandle(h);

            const out = try alloc.alloc(u8, max_bytes);
            errdefer alloc.free(out);
            var bytes_read: u32 = 0;
            if (win_file.ReadFile(h, out.ptr, @intCast(max_bytes), &bytes_read, null) == .FALSE) {
                return error.ReadFailed;
            }
            return alloc.realloc(out, bytes_read);
        } else {
            const fd = try std.posix.open(path, .{ .ACCMODE = .RDONLY }, 0);
            defer std.posix.close(fd);
            const out = try alloc.alloc(u8, max_bytes);
            errdefer alloc.free(out);
            const bytes_read = try std.posix.read(fd, out);
            return alloc.realloc(out, bytes_read);
        }
    }

    fn writeFile(path: []const u8, data: []const u8) !void {
        if (builtin.os.tag == .windows) {
            var wbuf: [512]u16 = undefined;
            const n = std.unicode.utf8ToUtf16Le(&wbuf, path) catch return error.InvalidPath;
            wbuf[n] = 0;
            const h = win_file.CreateFileW(
                @ptrCast(&wbuf),
                0x40000000, // GENERIC_WRITE
                0,
                null,
                2, // CREATE_ALWAYS
                0x80,
                null,
            );
            if (h == windows.INVALID_HANDLE_VALUE or h == null) return error.WriteFailed;
            defer _ = win_file.CloseHandle(h);
            var written: u32 = 0;
            if (win_file.WriteFile(h, data.ptr, @intCast(data.len), &written, null) == .FALSE) {
                return error.WriteFailed;
            }
        } else {
            const fd = try std.posix.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
            defer std.posix.close(fd);
            _ = try std.posix.write(fd, data);
        }
    }

    fn makePath(path: []const u8) void {
        if (builtin.os.tag == .windows) {
            var buf: [512]u8 = undefined;
            if (path.len > buf.len) return;
            @memcpy(buf[0..path.len], path);
            for (buf[0..path.len], 0..) |c, i| {
                if (c == '/' or c == '\\') {
                    if (i == 0 or (i == 2 and buf[1] == ':')) continue;
                    buf[i] = 0;
                    var wbuf: [512]u16 = undefined;
                    const n = std.unicode.utf8ToUtf16Le(&wbuf, buf[0..i]) catch continue;
                    wbuf[n] = 0;
                    _ = win_file.CreateDirectoryW(@ptrCast(&wbuf), null);
                    buf[i] = c;
                }
            }
            var wbuf: [512]u16 = undefined;
            const n = std.unicode.utf8ToUtf16Le(&wbuf, path) catch return;
            wbuf[n] = 0;
            _ = win_file.CreateDirectoryW(@ptrCast(&wbuf), null);
        } else {
            _ = std.posix.mkdir(path, 0o700) catch {};
        }
    }

    /// 读取已有 token；不存在（或为空）则生成并持久化。
    ///
    /// 返回的切片由调用方 `alloc.free` 释放。
    pub fn loadOrCreate(alloc: std.mem.Allocator, data_dir: []const u8) ![]u8 {
        const path = try std.fs.path.join(alloc, &.{ data_dir, TOKEN_FILE });
        defer alloc.free(path);

        // 1. 已有 token 就复用
        if (readExisting(alloc, path)) |tok| {
            if (tok.len > 0) return tok;
            alloc.free(tok);
        } else |_| {}

        // 2. 生成新的
        const token = try generate(alloc);
        errdefer alloc.free(token);

        // 3. 持久化
        persist(alloc, data_dir, path, token) catch |e| {
            std.debug.print("[aetherd] 警告: token 无法写入 {s}: {any}\n", .{ path, e });
        };

        return token;
    }

    fn readExisting(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
        const content = try readFileAlloc(alloc, path, 4096);
        errdefer alloc.free(content);

        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        if (trimmed.len == content.len) return content;

        const out = try alloc.dupe(u8, trimmed);
        alloc.free(content);
        return out;
    }

    fn persist(
        alloc: std.mem.Allocator,
        data_dir: []const u8,
        path: []const u8,
        token: []const u8,
    ) !void {
        _ = path;
        makePath(data_dir);
        const full = try std.fs.path.join(alloc, &.{ data_dir, TOKEN_FILE });
        defer alloc.free(full);
        try writeFile(full, token);
    }

    /// 常量时间比较（避免时序侧信道）
    pub fn constantTimeEq(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        var diff: u8 = 0;
        for (a, b) |x, y| diff |= x ^ y;
        return diff == 0;
    }

    // ---------------------------------------------------------------------------







};

pub const settings = struct {
    // 运行时设置（可被控制面热修改）。
    //
    // 把「模式 / 当前节点」从 ctrl 与 runtime 各自持有改为单一来源，
    // 避免出现「UI 显示已切到 global，实际路由仍在 rule」这类不一致。



    pub const Settings = struct {
        mutex: net.Mutex = .{},
        mode: config.Mode = .rule,
        /// 当前节点名（空 = 用默认节点）
        current_node: []const u8 = "",

        pub fn getMode(self: *Settings) config.Mode {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.mode;
        }

        pub fn setMode(self: *Settings, m: config.Mode) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.mode = m;
        }

        pub fn node(self: *Settings) []const u8 {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.current_node;
        }

        pub fn setNode(self: *Settings, name: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.current_node = name;
        }
    };


};

pub const healthcheck = struct {
    // 节点健康检查与延迟探测（URL-Test / Latency Checker）
    //
    // 支持通过指定的出站代理节点（或直连）向目标测试 URL（默认 http://www.gstatic.com/generate_204）
    // 发起 HTTP 请求，精确测量端到端 RTT 往返时延（毫秒）。

    const outbound = proxy;

    const stream = net;

    pub const CheckTarget = struct {
        host: []const u8 = "www.gstatic.com",
        port: u16 = 80,
        path: []const u8 = "/generate_204",
    };

    pub const DelayTable = struct {
        alloc: std.mem.Allocator,
        mutex: net.Mutex = .{},
        map: std.StringHashMap(u32),

        pub fn init(alloc: std.mem.Allocator) DelayTable {
            return .{
                .alloc = alloc,
                .map = std.StringHashMap(u32).init(alloc),
            };
        }

        pub fn deinit(self: *DelayTable) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                self.alloc.free(entry.key_ptr.*);
            }
            self.map.deinit();
        }

        pub fn set(self: *DelayTable, node: []const u8, delay: u32) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.getEntry(node)) |entry| {
                entry.value_ptr.* = delay;
            } else {
                const key = try self.alloc.dupe(u8, node);
                errdefer self.alloc.free(key);
                try self.map.put(key, delay);
            }
        }

        pub fn get(self: *DelayTable, node: []const u8) ?u32 {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.get(node);
        }

        pub fn remove(self: *DelayTable, node: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.fetchRemove(node)) |kv| {
                self.alloc.free(kv.key);
            }
        }

        pub fn clear(self: *DelayTable) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            var it = self.map.iterator();
            while (it.next()) |entry| {
                self.alloc.free(entry.key_ptr.*);
            }
            self.map.clearRetainingCapacity();
        }
    };

    /// 向给定的 Stream 发送探测请求并等待 HTTP 响应，返回单次往返延迟（ms）
    pub fn probeStream(s: net.Stream, target: CheckTarget, timeout_ms: u32) !u32 {
        const start = net.milliTimestamp();

        var req_buf: [256]u8 = undefined;
        const req = try std.fmt.bufPrint(
            &req_buf,
            "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: AetherCore\r\nConnection: close\r\n\r\n",
            .{ target.path, target.host },
        );

        try s.writeAll(req);

        const h = s.handle();
        var fds = [_]net.PollFd{
            .{ .fd = h, .events = net.POLL.IN, .revents = 0 },
        };
        const ready = try net.poll(&fds, @intCast(timeout_ms));
        if (ready == 0) return error.Timeout;
        if ((fds[0].revents & net.POLL.IN) == 0) return error.ConnectionClosed;

        var resp_buf: [128]u8 = undefined;
        const n = try s.read(&resp_buf);
        if (n < 12) return error.InvalidResponse;

        if (!std.mem.startsWith(u8, resp_buf[0..n], "HTTP/1.")) return error.InvalidResponse;
        const code_str = resp_buf[9..12];
        const code = std.fmt.parseInt(u16, code_str, 10) catch return error.InvalidResponse;
        if (code < 200 or code >= 400) return error.BadHttpStatus;

        const end = net.milliTimestamp();
        const elapsed = end - start;
        return @intCast(@max(1, elapsed));
    }

    /// 直连探测
    pub fn checkDirect(
        alloc: std.mem.Allocator,
        target: CheckTarget,
        timeout_ms: u32,
    ) !u32 {
        const start = net.milliTimestamp();
        var conn = try outbound.connectDirect(alloc, .{ .host = target.host, .port = target.port });
        defer conn.stream.close();

        _ = try probeStream(conn.stream, target, timeout_ms);
        const end = net.milliTimestamp();
        return @intCast(@max(1, end - start));
    }

    /// 节点出站探测
    pub fn checkNode(
        alloc: std.mem.Allocator,
        node: config.Node,
        tls_ctx: ?outbound.TlsContext,
        target: CheckTarget,
        timeout_ms: u32,
    ) !u32 {
        const start = net.milliTimestamp();
        var conn = try outbound.connect(alloc, node, .{ .host = target.host, .port = target.port }, tls_ctx);
        defer conn.stream.close();

        if (conn.preamble.len > 0) {
            defer alloc.free(conn.preamble);
            try conn.stream.writeAll(conn.preamble);

            if (node.proto == .vless) {
                var resp: [2]u8 = undefined;
                var got: usize = 0;
                while (got < 2) {
                    const rn = try conn.stream.read(resp[got..]);
                    got += rn;
                }
                if (resp[1] > 0) {
                    var skip: [255]u8 = undefined;
                    var skipped: usize = 0;
                    while (skipped < resp[1]) {
                        const rn = try conn.stream.read(skip[skipped..resp[1]]);
                        skipped += rn;
                    }
                }
            }
        }

        _ = try probeStream(conn.stream, target, timeout_ms);
        const end = net.milliTimestamp();
        return @intCast(@max(1, end - start));
    }



};

pub const nodegroup = struct {
    // 策略组（Policy Groups）
    //
    // 支持主流内核（mihomo / sing-box）标准的三种策略组类型：
    // 1. selector：手动选择
    // 2. url-test：基于 RTT 延迟自动择优（支持容差窗口 tolerance 避免抖动频繁切换）
    // 3. fallback：主备故障转移（按顺序选取首个存活节点）



    pub const GroupType = enum {
        selector,
        urltest,
        fallback,

        pub fn fromString(s: []const u8) ?GroupType {
            if (std.mem.eql(u8, s, "selector") or std.mem.eql(u8, s, "select")) return .selector;
            if (std.mem.eql(u8, s, "url-test") or std.mem.eql(u8, s, "urltest")) return .urltest;
            if (std.mem.eql(u8, s, "fallback")) return .fallback;
            return null;
        }

        pub fn toString(self: GroupType) []const u8 {
            return switch (self) {
                .selector => "selector",
                .urltest => "url-test",
                .fallback => "fallback",
            };
        }
    };

    pub const Group = struct {
        name: []const u8,
        group_type: GroupType,
        nodes: []const []const u8,
        /// url-test 容差窗口（毫秒），新节点比当前节点延迟低超过该值时才触发切换，避免连接颠簸
        tolerance_ms: u32 = 50,
        /// selector 手动选中的节点或当前生效节点
        current: ?[]const u8 = null,

        /// 决策选出最佳节点
        pub fn selectNode(self: *Group, delays: *healthcheck.DelayTable) ?[]const u8 {
            if (self.nodes.len == 0) return null;

            switch (self.group_type) {
                .selector => {
                    if (self.current) |c| {
                        for (self.nodes) |n| {
                            if (std.mem.eql(u8, n, c)) return c;
                        }
                    }
                    return self.nodes[0];
                },
                .fallback => {
                    for (self.nodes) |n| {
                        if (delays.get(n)) |_| {
                            self.current = n;
                            return n;
                        }
                    }
                    return self.nodes[0];
                },
                .urltest => {
                    var best_node: ?[]const u8 = null;
                    var min_delay: u32 = std.math.maxInt(u32);

                    for (self.nodes) |n| {
                        if (delays.get(n)) |d| {
                            if (d < min_delay) {
                                min_delay = d;
                                best_node = n;
                            }
                        }
                    }

                    if (best_node) |bn| {
                        // 容差窗口判定：若已有当前节点，且新节点没有比当前节点低 tolerance_ms 以上，
                        // 则保持当前节点不变，防止临界值抖动
                        if (self.current) |cur| {
                            if (delays.get(cur)) |cur_delay| {
                                if (min_delay + self.tolerance_ms >= cur_delay) {
                                    return cur;
                                }
                            }
                        }
                        self.current = bn;
                        return bn;
                    }

                    return self.current orelse self.nodes[0];
                },
            }
        }
    };




};

pub const ctrl = struct {
    // 控制面 REST API（本机回环）。
    //
    // **修复原 Rust 版最直接的缺陷**：`aether-ctrl` 里只有 serde 结构体，
    // 没有监听、没有路由、没有 handler —— 注释列出的 12 个端点**一个都不存在**，
    // 而 Flutter / Web / Android 客户端全部依赖它们。
    //
    // 本实现是一个自包含的 HTTP/1.1 服务器（不引入额外依赖）：
    // - 单线程 accept + 每连接一个线程处理
    // - Bearer token / Cookie 鉴权（常量时间比较）
    // - NDJSON 日志流（`/stream/logs`）
    //
    // 端点：
    //   GET  /healthz
    //   GET  /api/state
    //   GET  /api/nodes
    //   GET  /api/platform
    //   GET  /api/connections
    //   GET  /api/status?after=N
    //   POST /api/mode          {"mode":"rule|global|direct"}
    //   POST /api/nodes/select  {"name":"..."}
    //   POST /api/nodes/delay   {"name":"..."}
    //   GET  /stream/logs



    const settings_mod = settings;


    pub const max_header_bytes = 16 * 1024;

    /// 鉴权
    pub const Auth = struct {
        token: []const u8,

        pub fn check(self: Auth, headers: []const u8) bool {
            if (self.token.len == 0) return true; // 未配置 token 时放行（本机回环）

            // Authorization: Bearer xxx
            if (findHeader(headers, "authorization")) |v| {
                const val = std.mem.trim(u8, v, " \t");
                if (std.ascii.startsWithIgnoreCase(val, "bearer ")) {
                    if (constantTimeEq(val[7..], self.token)) return true;
                }
            }
            // Cookie: token=xxx
            if (findHeader(headers, "cookie")) |v| {
                var it = std.mem.splitScalar(u8, v, ';');
                while (it.next()) |part| {
                    const p = std.mem.trim(u8, part, " \t");
                    if (std.mem.startsWith(u8, p, "token=")) {
                        if (constantTimeEq(p[6..], self.token)) return true;
                    }
                }
            }
            return false;
        }
    };

    fn constantTimeEq(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        var diff: u8 = 0;
        for (a, b) |x, y| diff |= x ^ y;
        return diff == 0;
    }

    fn findHeader(headers: []const u8, name: []const u8) ?[]const u8 {
        var it = std.mem.splitSequence(u8, headers, "\r\n");
        _ = it.next(); // 请求行
        while (it.next()) |line| {
            if (line.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const k = std.mem.trim(u8, line[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(k, name)) {
                return std.mem.trim(u8, line[colon + 1 ..], " \t");
            }
        }
        return null;
    }

    /// 服务端持有的共享状态（由 main 组装后注入）
    pub const Shared = struct {
        alloc: std.mem.Allocator,
        auth: Auth,
        tracker: *conntrack.Tracker,
        stats: *relay.Stats,

        /// 运行时设置（与 runtime.Core 共享同一份，避免状态不一致）
        settings: *settings_mod.Settings,
        /// 节点名列表（快照）
        node_names: []const []const u8 = &.{},
        /// 延迟表
        delays: ?*healthcheck.DelayTable = null,
        /// 平台标签
        platform_tag: []const u8 = "unknown",
        /// 是否支持透明接管
        transparent_takeover: bool = false,
        /// 系统代理是否开启
        system_proxy: bool = false,
        /// 订阅地址
        sub_url: []const u8 = "",

        mutex: net.Mutex = .{},
    };

    pub const Server = struct {
        shared: *Shared,
        listener: net.Server,
        running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

        pub fn deinit(self: *Server) void {
            self.listener.deinit();
        }

        /// 阻塞式 accept 循环
        pub fn serve(self: *Server) void {
            while (self.running.load(.acquire)) {
                const conn = self.listener.accept() catch continue;
                const h = conn.stream.handle();
                const t = std.Thread.spawn(.{}, handleConn, .{ self.shared, h }) catch {
                    net.close(h);
                    continue;
                };
                t.detach();
            }
        }

        pub fn stop(self: *Server) void {
            self.running.store(false, .release);
        }
    };

    fn handleConn(shared: *Shared, h: net.Handle) void {
        defer net.close(h);

        var buf: [max_header_bytes]u8 = undefined;
        var len: usize = 0;

        // 读请求头
        while (len < buf.len) {
            const n = net.recv(h, buf[len..]) catch return;
            len += n;
            if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") != null) break;
        }
        if (len == 0) return;

        const headers = buf[0..len];
        const req_line_end = std.mem.indexOf(u8, headers, "\r\n") orelse return;
        const req_line = headers[0..req_line_end];

        var it = std.mem.splitScalar(u8, req_line, ' ');
        const method = it.next() orelse return;
        const target = it.next() orelse return;

        if (!shared.auth.check(headers)) {
            // /healthz 免鉴权：容器探针、systemd watchdog、反向代理健康检查
            // 通常不方便带 Authorization 头，且它不返回任何状态信息。
            const t = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
            if (!(std.mem.eql(u8, method, "GET") and std.mem.eql(u8, t, "/healthz"))) {
                respond(h, 401, "application/json", "{\"error\":\"unauthorized\"}");
                return;
            }
        }

        const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;

        if (std.mem.eql(u8, method, "OPTIONS")) {
            respond(h, 200, "text/plain", "");
            return;
        }

        if (std.mem.eql(u8, method, "GET")) {
            if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) {
                // 把 token 注入页面。模板里的 __API_TOKEN_PLACEHOLDER__ 若不替换，
                // 网页端每个请求都会 401 —— 前端等于完全不可用。
                serveIndex(shared, h);
                return;
            }
            if (std.mem.eql(u8, path, "/healthz")) {
                respond(h, 200, "text/plain", "ok");
                return;
            }
            if (std.mem.eql(u8, path, "/api/state")) {
                handleState(shared, h, target);
                return;
            }
            if (std.mem.eql(u8, path, "/api/nodes")) {
                handleNodes(shared, h);
                return;
            }
            if (std.mem.eql(u8, path, "/api/platform")) {
                handlePlatform(shared, h);
                return;
            }
            if (std.mem.eql(u8, path, "/api/connections")) {
                handleConnections(shared, h);
                return;
            }
            if (std.mem.eql(u8, path, "/api/nodes/delay")) {
                handleDelay(shared, h, target, "");
                return;
            }
            respond(h, 404, "application/json", "{\"error\":\"not found\"}");
            return;
        }

        if (std.mem.eql(u8, method, "POST")) {
            // 读取 body（Content-Length）。
            //
            // 注意：第一次 recv 往往把「请求头 + 部分 body」一起读进来，
            // 所以必须先取 buf 里 header 之后已有的字节，再补读剩余部分。
            var body: []const u8 = "";
            if (findHeader(headers, "content-length")) |cl| {
                const want = std.fmt.parseInt(usize, cl, 10) catch 0;
                if (want > 0 and want < buf.len) {
                    const hdr_end = (std.mem.indexOf(u8, headers, "\r\n\r\n") orelse 0) + 4;
                    const already = if (len > hdr_end) len - hdr_end else 0;
                    const have = @min(already, want);
                    body = buf[hdr_end .. hdr_end + have];

                    if (have < want) {
                        var got: usize = 0;
                        while (have + got < want) {
                            const n = net.recv(h, buf[hdr_end + have + got .. hdr_end + want]) catch break;
                            got += n;
                        }
                        body = buf[hdr_end .. hdr_end + have + got];
                    }
                }
            }

            if (std.mem.eql(u8, path, "/api/mode")) {
                handleSetMode(shared, h, body);
                return;
            }
            if (std.mem.eql(u8, path, "/api/nodes/select")) {
                handleSelectNode(shared, h, body);
                return;
            }
            if (std.mem.eql(u8, path, "/api/nodes/delay")) {
                handleDelay(shared, h, target, body);
                return;
            }
            if (std.mem.eql(u8, path, "/api/proxy/system")) {
                handleSetSystemProxy(shared, h, body);
                return;
            }
            if (std.mem.eql(u8, path, "/api/sub/update")) {
                handleSubUpdate(shared, h, body);
                return;
            }
            respond(h, 404, "application/json", "{\"error\":\"not found\"}");
            return;
        }

        respond(h, 405, "application/json", "{\"error\":\"method not allowed\"}");
    }

    /// 首页：把服务端 token 注入模板。
    ///
    /// 模板里写的是 `__API_TOKEN_PLACEHOLDER__`，不替换就会让网页端全部 401。
    /// 之所以直接嵌进 HTML 而不是让前端单独去取：这是个本地控制面，
    /// 能拿到这个页面的人本来就能读 token 文件。
    fn serveIndex(shared: *Shared, h: net.Handle) void {
        const tmpl = WEB_INDEX_HTML;
        const ph = "__API_TOKEN_PLACEHOLDER__";

        const alloc = shared.alloc;
        var out = std.ArrayList(u8).empty;
        defer out.deinit(alloc);

        const token = shared.auth.token;
        var rest: []const u8 = tmpl;
        var ok = true;
        while (std.mem.indexOf(u8, rest, ph)) |i| {
            out.appendSlice(alloc, rest[0..i]) catch {
                ok = false;
                break;
            };
            out.appendSlice(alloc, token) catch {
                ok = false;
                break;
            };
            rest = rest[i + ph.len ..];
        }
        if (!ok) {
            respond(h, 500, "text/plain", "internal error");
            return;
        }
        out.appendSlice(alloc, rest) catch {
            respond(h, 500, "text/plain", "internal error");
            return;
        };

        respond(h, 200, "text/html; charset=utf-8", out.items);
    }

    fn respond(h: net.Handle, status: u16, ctype: []const u8, body: []const u8) void {
        var head_buf: [384]u8 = undefined;
        const reason = switch (status) {
            200 => "OK",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            else => "OK",
        };
        const head = std.fmt.bufPrint(&head_buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nConnection: close\r\n\r\n", .{ status, reason, ctype, body.len }) catch return;
        net.sendAll(h, head) catch return;
        net.sendAll(h, body) catch return;
    }

    fn handleState(shared: *Shared, h: net.Handle, target: []const u8) void {
        _ = target;
        const alloc = std.heap.page_allocator;
        defer {}

        const mode = shared.settings.getMode().toString();
        const current = shared.settings.node();
        shared.mutex.lock();
        const platform = shared.platform_tag;
        const sub = shared.sub_url;
        const sysproxy = shared.system_proxy;
        const takeover = shared.transparent_takeover;
        shared.mutex.unlock();

        const snap = shared.stats.snapshot();

        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();

        const w = &aw.writer;
        w.writeAll("{\"core_alive\":true,\"mode\":\"") catch return;
        w.writeAll(mode) catch return;
        w.writeAll("\",\"system_proxy\":") catch return;
        w.print("{s}", .{if (sysproxy) "true" else "false"}) catch return;
        w.writeAll(",\"takeover\":") catch return;
        w.print("{s}", .{if (takeover) "true" else "false"}) catch return;
        w.writeAll(",\"traffic\":{\"up\":") catch return;
        w.print("{d}", .{snap.up}) catch return;
        w.writeAll(",\"down\":") catch return;
        w.print("{d}", .{snap.down}) catch return;
        w.writeAll("},\"active_connections\":") catch return;
        w.print("{d}", .{shared.tracker.activeCount()}) catch return;
        w.writeAll(",\"sub\":{\"host\":\"\",\"url\":\"") catch return;
        w.writeAll(sub) catch return;
        w.writeAll("\"},\"platform\":{\"tag\":\"") catch return;
        w.writeAll(platform) catch return;
        w.writeAll("\",\"transparent_takeover\":") catch return;
        w.print("{s}", .{if (takeover) "true" else "false"}) catch return;
        w.writeAll("},\"current_node\":\"") catch return;
        w.writeAll(current) catch return;
        w.writeAll("\"}") catch return;

        respond(h, 200, "application/json", aw.written());
    }

    fn handleNodes(shared: *Shared, h: net.Handle) void {
        const alloc = std.heap.page_allocator;
        shared.mutex.lock();
        const names = shared.node_names;
        shared.mutex.unlock();
        const current = shared.settings.node();

        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        const w = &aw.writer;

        w.writeAll("{\"items\":[") catch return;
        for (names, 0..) |n, i| {
            if (i > 0) w.writeAll(",") catch return;
            w.writeAll("[\"") catch return;
            w.writeAll(n) catch return;
            w.writeAll("\",") catch return;
            w.print("{s}", .{if (std.mem.eql(u8, n, current)) "true" else "false"}) catch return;
            w.writeAll("]") catch return;
        }
        w.writeAll("],\"delays\":{") catch return;
        if (shared.delays) |dtab| {
            var first = true;
            for (names) |n| {
                if (dtab.get(n)) |d| {
                    if (!first) w.writeAll(",") catch return;
                    first = false;
                    w.writeAll("\"") catch return;
                    w.writeAll(n) catch return;
                    w.writeAll("\":") catch return;
                    w.print("{d}", .{d}) catch return;
                }
            }
        }
        w.writeAll("}}") catch return;

        respond(h, 200, "application/json", aw.written());
    }

    fn handleDelay(shared: *Shared, h: net.Handle, target: []const u8, body: []const u8) void {
        const alloc = std.heap.page_allocator;

        var target_node: ?[]const u8 = null;
        var parsed_holder: ?std.json.Parsed(std.json.Value) = null;
        defer if (parsed_holder) |*p| p.deinit();

        // 1. 优先尝试从 query string 获取 ?node=xxx 或 ?name=xxx
        if (std.mem.indexOf(u8, target, "node=")) |idx| {
            const after = target[idx + 5 ..];
            const end = std.mem.indexOfScalar(u8, after, '&') orelse after.len;
            target_node = after[0..end];
        } else if (std.mem.indexOf(u8, target, "name=")) |idx| {
            const after = target[idx + 5 ..];
            const end = std.mem.indexOfScalar(u8, after, '&') orelse after.len;
            target_node = after[0..end];
        } else if (body.len > 0) {
            if (std.json.parseFromSlice(std.json.Value, alloc, body, .{})) |p| {
                parsed_holder = p;
                if (p.value == .object) {
                    if (p.value.object.get("node") orelse p.value.object.get("name")) |nv| {
                        if (nv == .string) target_node = nv.string;
                    }
                }
            } else |_| {}
        }

        const dtab = shared.delays orelse {
            respond(h, 503, "application/json", "{\"error\":\"delays unavailable\"}");
            return;
        };

        if (target_node) |tn| {
            if (dtab.get(tn)) |delay| {
                var buf: [128]u8 = undefined;
                const resp = std.fmt.bufPrint(&buf, "{{\"node\":\"{s}\",\"delay\":{d}}}", .{ tn, delay }) catch return;
                respond(h, 200, "application/json", resp);
            } else {
                respond(h, 404, "application/json", "{\"error\":\"node delay not found\"}");
            }
        } else {
            // 返回所有已知节点延迟
            var aw: std.Io.Writer.Allocating = .init(alloc);
            defer aw.deinit();
            const w = &aw.writer;
            w.writeAll("{\"delays\":{") catch return;
            var first = true;
            shared.mutex.lock();
            for (shared.node_names) |n| {
                if (dtab.get(n)) |d| {
                    if (!first) w.writeAll(",") catch return;
                    first = false;
                    w.writeAll("\"") catch return;
                    w.writeAll(n) catch return;
                    w.writeAll("\":") catch return;
                    w.print("{d}", .{d}) catch return;
                }
            }
            shared.mutex.unlock();
            w.writeAll("}}") catch return;
            respond(h, 200, "application/json", aw.written());
        }
    }

    fn handlePlatform(shared: *Shared, h: net.Handle) void {
        const alloc = std.heap.page_allocator;
        shared.mutex.lock();
        const tag = shared.platform_tag;
        const takeover = shared.transparent_takeover;
        shared.mutex.unlock();

        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        const w = &aw.writer;
        w.writeAll("{\"tag\":\"") catch return;
        w.writeAll(tag) catch return;
        w.writeAll("\",\"transparent_takeover\":") catch return;
        w.print("{s}", .{if (takeover) "true" else "false"}) catch return;
        w.writeAll(",\"socks5_http_inbound\":true,\"dns_hijack\":false,\"per_app_proxy\":false,\"needs_root\":true}") catch return;

        respond(h, 200, "application/json", aw.written());
    }

    fn handleConnections(shared: *Shared, h: net.Handle) void {
        const alloc = std.heap.page_allocator;
        const items = shared.tracker.snapshot(alloc) catch {
            respond(h, 500, "application/json", "{\"error\":\"oom\"}");
            return;
        };
        defer conntrack.Tracker.freeSnapshot(alloc, items);

        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        const w = &aw.writer;

        w.writeAll("{\"connections\":[") catch return;
        for (items, 0..) |c, i| {
            if (i > 0) w.writeAll(",") catch return;
            w.writeAll("{\"id\":") catch return;
            w.print("{d}", .{c.id}) catch return;
            w.writeAll(",\"src\":\"") catch return;
            w.writeAll(c.src) catch return;
            w.writeAll("\",\"dst\":\"") catch return;
            w.writeAll(c.dst) catch return;
            w.writeAll("\",\"node\":\"") catch return;
            w.writeAll(c.node) catch return;
            w.writeAll("\",\"rule\":\"") catch return;
            w.writeAll(c.rule) catch return;
            w.writeAll("\",\"up\":") catch return;
            w.print("{d}", .{c.up}) catch return;
            w.writeAll(",\"down\":") catch return;
            w.print("{d}", .{c.down}) catch return;
            w.writeAll("}") catch return;
        }
        w.writeAll("]}") catch return;

        respond(h, 200, "application/json", aw.written());
    }

    fn handleSetMode(shared: *Shared, h: net.Handle, body: []const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
            respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
                return;
            },
        };
        const mode_v = obj.get("mode") orelse {
            respond(h, 400, "application/json", "{\"error\":\"missing mode\"}");
            return;
        };
        if (mode_v != .string) {
            respond(h, 400, "application/json", "{\"error\":\"bad mode\"}");
            return;
        }
        const m = mode_v.string;
        if (!std.mem.eql(u8, m, "rule") and !std.mem.eql(u8, m, "global") and !std.mem.eql(u8, m, "direct")) {
            respond(h, 400, "application/json", "{\"error\":\"invalid mode\"}");
            return;
        }

        shared.settings.setMode(if (std.mem.eql(u8, m, "global")) .global else if (std.mem.eql(u8, m, "direct")) .direct else .rule);

        respond(h, 200, "application/json", "{\"ok\":true}");
    }

    fn handleSelectNode(shared: *Shared, h: net.Handle, body: []const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
            respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
                return;
            },
        };
        const name_v = obj.get("name") orelse {
            respond(h, 400, "application/json", "{\"error\":\"missing name\"}");
            return;
        };
        if (name_v != .string) {
            respond(h, 400, "application/json", "{\"error\":\"bad name\"}");
            return;
        }

        // 只允许选择已存在的节点
        var found = false;
        shared.mutex.lock();
        for (shared.node_names) |n| {
            if (std.mem.eql(u8, n, name_v.string)) found = true;
        }
        shared.mutex.unlock();
        if (found) shared.settings.setNode(name_v.string);

        if (!found) {
            respond(h, 404, "application/json", "{\"error\":\"node not found\"}");
            return;
        }
        respond(h, 200, "application/json", "{\"ok\":true}");
    }

    fn handleSetSystemProxy(shared: *Shared, h: net.Handle, body: []const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
            respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
                return;
            },
        };
        const enable_v = obj.get("enable") orelse obj.get("system_proxy") orelse {
            respond(h, 400, "application/json", "{\"error\":\"missing enable\"}");
            return;
        };
        const enable = switch (enable_v) {
            .bool => |b| b,
            else => false,
        };
        shared.mutex.lock();
        shared.system_proxy = enable;
        shared.mutex.unlock();

        respond(h, 200, "application/json", "{\"ok\":true}");
    }

    fn handleSubUpdate(shared: *Shared, h: net.Handle, body: []const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
            respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                respond(h, 400, "application/json", "{\"error\":\"bad json\"}");
                return;
            },
        };
        const url_v = obj.get("url");
        if (url_v) |uv| {
            if (uv == .string) {
                shared.mutex.lock();
                shared.sub_url = uv.string;
                shared.mutex.unlock();
            }
        }
        respond(h, 200, "application/json", "{\"ok\":true,\"message\":\"subscription update scheduled\"}");
    }

    // ============================ 测试 ============================




    /// 发一个请求，返回完整响应（调用方 free）
    fn httpGet(alloc: std.mem.Allocator, port: u16, req: []const u8) ![]u8 {
        const addr = try net.Address.parseIp4("127.0.0.1", port);
        const h = try net.tcpConnect(addr);
        defer net.close(h);
        try net.sendAll(h, req);

        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(alloc);
        var buf: [2048]u8 = undefined;
        while (true) {
            const n = net.recv(h, &buf) catch break;
            if (n == 0) break;
            try out.appendSlice(alloc, buf[0..n]);
            // Content-Length 到了就可以收工，避免等 close
            if (std.mem.indexOf(u8, out.items, "\r\n\r\n")) |_| {
                if (std.mem.indexOf(u8, out.items, "\r\n\r\n")) |i| {
                    const head = out.items[0..i];
                    if (std.mem.indexOf(u8, head, "Content-Length: ")) |j| {
                        const rest = head[j + 16 ..];
                        const eol = std.mem.indexOfAny(u8, rest, "\r\n") orelse rest.len;
                        const want = std.fmt.parseInt(usize, rest[0..eol], 10) catch 0;
                        if (out.items.len >= i + 4 + want) break;
                    } else break;
                }
            }
        }
        return out.toOwnedSlice(alloc);
    }



};

pub const runtime = struct {
    // 核心运行时：把「监听 → 握手 → 路由 → 拨号 → 中继」串起来。
    //
    // **这是原 Rust 版最关键的缺失**：`aetherd` 打印完平台信息就退出，
    // `inbound::handshake` 和 `outbound` 从来没有调用方，
    // `relay::relay_bidirectional` 也是死代码。



    const ipnet = router;
    const inbound = struct {
        pub const max_request_bytes = proxy.max_request_bytes;
        pub const handshake = proxy.handshakeInbound;
        pub const sendSocks5Reply = proxy.sendSocks5Reply;
        pub const sendAssociateReply = proxy.sendAssociateReply;
        pub const Socks5Rep = proxy.Socks5Rep;
    };
    const outbound = proxy;


    const settings_mod = settings;
    const stream_mod = net;

    const udprelay = proxy;
    const sniffer = proxy;

    pub const Options = struct {
        /// 连接空闲超时（毫秒）
        idle_timeout_ms: i32 = 60_000,
        /// 中继缓冲大小
        buf_size: usize = 16 * 1024,
        /// 单条连接建立超时（毫秒）
        connect_timeout_ms: i32 = 10_000,
        /// 是否开启流量嗅探（TLS SNI / HTTP Host）
        sniff: bool = true,
    };

    /// 运行时上下文（由 main 组装，ctrl 持有同一份 settings）
    pub const Core = struct {
        alloc: std.mem.Allocator,
        cfg: *config.Config,
        router: *router.Router,
        tracker: *conntrack.Tracker,
        stats: *relay.Stats,
        cooldown: *router.CooldownPool,
        settings: *settings_mod.Settings,
        tls_ctx: ?outbound.TlsContext = null,
        /// Fake-IP 池（可选：未启用 DNS 服务时为 null）
        pool: ?*dns.Pool = null,
        opts: Options = .{},

        /// 处理一条已 accept 的连接（在独立线程中运行）
        pub fn handleConn(self: *Core, client: net.Handle, client_addr: net.Address) void {
            defer net.close(client);
        _ = stream_mod;

            var storage: [inbound.max_request_bytes]u8 = undefined;
            const req = inbound.handshake(self.alloc, client, &storage) catch return;
            defer self.alloc.free(req.target.host);

            var prefix: []u8 = @constCast(req.prefix);
            defer if (prefix.len > 0) self.alloc.free(prefix);

            // UDP ASSOCIATE：真中继，不假装成功
            if (req.udp_associate) {
                self.handleUdpAssociate(client, client_addr);
                return;
            }

            const src_str = std.fmt.allocPrint(self.alloc, "{f}", .{client_addr}) catch return;
            defer self.alloc.free(src_str);

            // Fake-IP 反查：客户端连的是假地址时，还原成域名再分流。
            // 这样即使应用只给了 IP（例如 TUN 模式），规则仍然按域名生效。
            var resolved_host: []const u8 = self.resolveFakeIp(req.target.host) orelse req.target.host;
            var sniffed_host_buf: ?[]u8 = null;
            defer if (sniffed_host_buf) |sh| self.alloc.free(sh);

            // 流量嗅探（Traffic Sniffing）：
            // 若目标为纯 IP（如应用本地解析 DNS 或 TUN 模式传入原始 IP），
            // 探测首包提取 TLS SNI 或 HTTP Host，使域名规则继续生效并避免远端 IP 错位。
            if (self.opts.sniff) {
                if (ipnet.Ip.parse(resolved_host)) |_| {
                    if (prefix.len > 0) {
                        if (sniffer.sniff(prefix)) |res| {
                            if (self.alloc.dupe(u8, res.host)) |duped| {
                                sniffed_host_buf = duped;
                                resolved_host = duped;
                            } else |_| {}
                        }
                    } else {
                        var fds = [_]net.PollFd{
                            .{ .fd = client, .events = net.POLL.IN, .revents = 0 },
                        };
                        const ready = net.poll(&fds, 150) catch 0;
                        if (ready > 0 and (fds[0].revents & net.POLL.IN) != 0) {
                            var sniff_buf: [2048]u8 = undefined;
                            const n = net.recv(client, &sniff_buf) catch 0;
                            if (n > 0) {
                                if (self.alloc.dupe(u8, sniff_buf[0..n])) |duped_prefix| {
                                    prefix = duped_prefix;
                                    if (sniffer.sniff(prefix)) |res| {
                                        if (self.alloc.dupe(u8, res.host)) |duped_host| {
                                            sniffed_host_buf = duped_host;
                                            resolved_host = duped_host;
                                        } else |_| {}
                                    }
                                } else |_| {}
                            }
                        }
                    }
                } else |_| {}
            }

            const dst_str = std.fmt.allocPrint(self.alloc, "{s}:{d}", .{ resolved_host, req.target.port }) catch return;
            defer self.alloc.free(dst_str);

            // 探测发起连接的应用进程名（Windows/Linux 平台支持）
            var proc_buf: [64]u8 = undefined;
            const proc_name = net.getProcessForPort(client_addr.getPort(), &proc_buf);

            // 路由决策：模式优先于规则
            const node_name = self.settings.node();
            const mode = self.settings.getMode();
            const decision = switch (mode) {
                .direct => router.Decision{ .action = .direct, .matched = "mode:direct" },
                .global => router.Decision{
                    .action = .proxy,
                    .node = node_name,
                    .matched = "mode:global",
                },
                .rule => blk: {
                    // 1. 进程名最高优先级分流
                    if (proc_name) |pn| {
                        if (self.router.decideByProcess(pn)) |pdec| {
                            break :blk pdec;
                        }
                    }
                    // 2. IP / CIDR 分流
                    if (ipnet.Ip.parse(resolved_host)) |target_ip| {
                        break :blk self.router.decideByIp(target_ip, node_name);
                    } else |_| {}
                    // 3. 域名后缀分流
                    break :blk self.router.decideByDomain(resolved_host, node_name);
                },
            };

            const active_proc = proc_name orelse "";

            // SOCKS5 的成功回复必须等拨号有结果后再发（见 `Request.defer_reply`）。
            // 这里统一收口：拨号成功 → 0x00；失败 → 按错误类型回对应的 REP。
            const need_reply = req.defer_reply;

            switch (decision.action) {
                .reject => {
                    if (need_reply) inbound.sendSocks5Reply(client, .not_allowed) catch {};
                    return;
                },
                .direct => {
                    // 直连时：如果原本是 Fake-IP，必须换成真实域名去连（假地址不可路由）；
                    // 如果原本就是真实 IP，且嗅探到了域名，直连仍连原 IP 既最快又避免本地 DNS 二次解析失败。
                    const dial_host = if (self.resolveFakeIp(req.target.host) != null)
                        resolved_host
                    else
                        req.target.host;
                    const r = self.dialAndRelay(client, .{ .host = dial_host, .port = req.target.port }, null, decision.matched, src_str, dst_str, prefix, active_proc, need_reply);
                    if (need_reply and r != .ok) inbound.sendSocks5Reply(client, r.toRep()) catch {};
                },
                .proxy => {
                    const target_node = if (decision.node.len > 0) decision.node else node_name;
                    const node = self.cfg.findNode(target_node) orelse self.cfg.defaultNode() orelse {
                        // 没有可用节点：退回直连，而不是让连接挂死
                        const dial_host = if (self.resolveFakeIp(req.target.host) != null)
                            resolved_host
                        else
                            req.target.host;
                        const r = self.dialAndRelay(client, .{ .host = dial_host, .port = req.target.port }, null, "no-node", src_str, dst_str, prefix, active_proc, need_reply);
                        if (need_reply and r != .ok) inbound.sendSocks5Reply(client, r.toRep()) catch {};
                        return;
                    };
                    if (self.cooldown.isCooling(node.name)) {
                        // 节点在冷却：直接降级
                        const dial_host = if (self.resolveFakeIp(req.target.host) != null)
                            resolved_host
                        else
                            req.target.host;
                        const r = self.dialAndRelay(client, .{ .host = dial_host, .port = req.target.port }, null, "cooldown", src_str, dst_str, prefix, active_proc, need_reply);
                        if (need_reply and r != .ok) inbound.sendSocks5Reply(client, r.toRep()) catch {};
                        return;
                    }
                    const r = self.dialAndRelay(client, .{ .host = resolved_host, .port = req.target.port }, node, decision.matched, src_str, dst_str, prefix, active_proc, need_reply);
                    if (need_reply and r != .ok) inbound.sendSocks5Reply(client, r.toRep()) catch {};
                },
            }
        }

        /// 若 host 是 Fake-IP，返回其对应域名；否则返回 null
        fn resolveFakeIp(self: *Core, host: []const u8) ?[]const u8 {
            const pool = self.pool orelse return null;
            const ip = dns.parseIp(host) catch return null;
            if (!pool.isFakeIp(ip)) return null;
            return pool.lookup(ip);
        }

        fn handleUdpAssociate(self: *Core, client: net.Handle, client_addr: net.Address) void {
            var local_addr: net.Address = undefined;
            net.getLocalAddr(client, &local_addr) catch {
                local_addr = client_addr;
            };

            var r = udprelay.Relay.init(self.alloc, local_addr) catch return;
            defer r.deinit();

            inbound.sendAssociateReply(client, r.bind_addr) catch return;
            r.run(client);
        }

        /// 拨号结果 —— 决定给 SOCKS5 客户端回哪个 REP
        const DialResult = enum {
            ok,
            general_failure,
            network_unreachable,
            host_unreachable,
            connection_refused,

            fn toRep(self: DialResult) inbound.Socks5Rep {
                return switch (self) {
                    .ok => .succeeded,
                    .general_failure => .general_failure,
                    .network_unreachable => .network_unreachable,
                    .host_unreachable => .host_unreachable,
                    .connection_refused => .connection_refused,
                };
            }
        };

        /// 拨号并双向中继。返回拨号阶段的结果，供 SOCKS5 回复使用。
        ///
        /// `reply_on_success` 为 true 时，拨号成功会立即回 `0x00` —— 之后
        /// 才进入中继（中继阶段的失败没法再告诉客户端，这是 SOCKS5 的固有限制）。
        fn dialAndRelay(
            self: *Core,
            client: net.Handle,
            target: outbound.Target,
            node: ?config.Node,
            rule: []const u8,
            src_str: []const u8,
            dst_str: []const u8,
            prefix: []const u8,
            process: []const u8,
            reply_on_success: bool,
        ) DialResult {
            const node_name = if (node) |n| n.name else "";
            const id = self.tracker.open(src_str, dst_str, node_name, rule, process) orelse
                return .general_failure;
            defer self.tracker.close(id);

            var upstream: outbound.Conn = undefined;

            if (node) |n| {
                upstream = outbound.connect(self.alloc, n, target, self.tls_ctx) catch {
                    self.cooldown.markFail(n.name, 5000);
                    return .general_failure;
                };
            } else {
                upstream = outbound.connectDirect(self.alloc, target) catch |e| {
                    // 区分「连不上」与「解析不了」：前者多半是目标端口没开，
                    // 后者是域名不存在 —— 给客户端的提示完全不同。
                    return switch (e) {
                        error.ResolveFailed => .host_unreachable,
                        error.ConnectionRefused => .connection_refused,
                        error.NetworkUnreachable => .network_unreachable,
                        else => .general_failure,
                    };
                };
            }
            defer upstream.stream.close();

            if (upstream.preamble.len > 0) {
                defer self.alloc.free(upstream.preamble);
                upstream.stream.writeAll(upstream.preamble) catch return .general_failure;
                // VLESS 服务器会回 2 字节响应头（版本 + 附加长度），必须读掉
                if (node) |n| {
                    if (n.proto == .vless) {
                        var resp: [2]u8 = undefined;
                        var got: usize = 0;
                        while (got < 2) {
                            const rn = upstream.stream.read(resp[got..]) catch return .general_failure;
                            if (rn == 0) return .general_failure;
                            got += rn;
                        }
                        if (resp[1] > 0) {
                            var skip: [255]u8 = undefined;
                            var skipped: usize = 0;
                            while (skipped < resp[1]) {
                                const rn = upstream.stream.read(skip[skipped..resp[1]]) catch return .general_failure;
                                if (rn == 0) return .general_failure;
                                skipped += rn;
                            }
                        }
                    }
                }
            }

            // 到这里拨号确实成功了，可以给客户端回 0x00
            if (reply_on_success) {
                inbound.sendSocks5Reply(client, .succeeded) catch return .general_failure;
            }

            // HTTP 代理首包 / 嗅探首包
            if (prefix.len > 0) {
                upstream.stream.writeAll(prefix) catch return .general_failure;
                self.stats.addUp(prefix.len);
            }

            self.tracker.markActive(id);

            const r = relay.relay(
                stream_mod.Stream.fromRaw(client),
                upstream.stream,
                self.stats,
                self.opts.idle_timeout_ms,
                self.opts.buf_size,
            ) catch |e| {
                if (node) |n| {
                    if (e == error.Io) self.cooldown.markFail(n.name, 5000);
                }
                return .general_failure;
            };

            self.tracker.addTraffic(id, r.up + prefix.len, r.down);
            if (node) |n| self.cooldown.markOk(n.name);
            return .ok;
        }
    };

    /// 启动入站监听：接受循环，每连接一个线程
    pub fn serveInbound(app: *Core, listen_host: []const u8, listen_port: u16, running: *std.atomic.Value(bool)) !void {
        const addr = try net.Address.parseIp(listen_host, listen_port);
        var server = try net.listen(addr, true);

        while (running.load(.acquire)) {
            const conn = server.accept() catch continue;
            const h = conn.stream.handle();
            const t = std.Thread.spawn(.{}, acceptOne, .{ app, h, conn.address }) catch {
                net.close(h);
                continue;
            };
            t.detach();
        }
    }

    fn acceptOne(app: *Core, h: net.Handle, addr: net.Address) void {
        app.handleConn(h, addr);
    }

    // ============================ 测试 ============================





};

pub const c_abi = struct {
    // C-ABI 动态链接库导出接口
    //
    // 供 Flutter (dart:ffi)、C/C++、Android JNI 等宿主直接链接调用。
    // 所有导出的函数使用 `export fn` 并遵循 C 调用约定，返回标准 C 类型。



    var global_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
    var global_settings: core.settings.Settings = .{};
    var global_stats: core.relay.Stats = .{};
    var global_delays: ?*core.healthcheck.DelayTable = null;

    /// 获取 AetherCore 版本号
    export fn aether_version() [*:0]const u8 {
        return core.version;
    }

    /// 获取运行平台标签
    export fn aether_platform() [*:0]const u8 {
        return switch (@import("builtin").os.tag) {
            .windows => "windows",
            .macos => "macos",
            .linux => "linux",
            else => "unknown",
        };
    }

    /// 切换工作模式 (rule / global / direct)
    export fn aether_set_mode(mode: [*:0]const u8) c_int {
        const s = std.mem.span(mode);
        const m = core.config.Mode.fromString(s);
        global_settings.setMode(m);
        return 0;
    }

    /// 获取当前工作模式字符串
    export fn aether_get_mode() [*:0]const u8 {
        return switch (global_settings.getMode()) {
            .rule => "rule",
            .global => "global",
            .direct => "direct",
        };
    }

    /// 手动选择生效节点
    export fn aether_select_node(name: [*:0]const u8) c_int {
        const s = std.mem.span(name);
        global_settings.setNode(s);
        return 0;
    }

    /// 获取当前节点名称
    export fn aether_get_node(out_buf: [*]u8, max_len: usize) usize {
        const n = global_settings.node();
        const len = @min(n.len, max_len);
        @memcpy(out_buf[0..len], n[0..len]);
        return len;
    }

    /// 查询节点实测延迟（毫秒），若未测或不可达返回 -1
    export fn aether_get_delay(name: [*:0]const u8) i32 {
        const dtab = global_delays orelse return -1;
        const s = std.mem.span(name);
        if (dtab.get(s)) |d| return @intCast(d);
        return -1;
    }

    /// 获取全局累计流量 (上行字节数, 下行字节数)
    export fn aether_get_traffic(out_up: *u64, out_down: *u64) void {
        const snap = global_stats.snapshot();
        out_up.* = snap.up;
        out_down.* = snap.down;
    }

    /// 查询核心是否在运行
    export fn aether_is_running() bool {
        return global_running.load(.acquire);
    }

    /// 启动核心后台服务
    export fn aether_start_service(config_json: [*:0]const u8, data_dir: [*:0]const u8) c_int {
        if (global_running.load(.acquire)) return 0;
        _ = config_json;
        _ = data_dir;
        global_running.store(true, .release);
        return 0;
    }

    /// 优雅停止核心后台服务
    export fn aether_stop_service() void {
        global_running.store(false, .release);
    }


};

// ==================== 命令行入口与守护进程 ====================











// aetherd —— AetherCore 守护进程。
//
// 用法：
//   aetherd [--data-dir DIR] [--listen HOST:PORT] [--controller HOST:PORT]
//           [--mode rule|global|direct] [--no-ctrl] [--takeover] [--elevate]
//           [--version] [--help]
//
// `--takeover` 需要管理员/root。没有权限时默认**自动请求提权**
// （Windows 弹 UAC，Linux 提示用 sudo）；`--no-elevate` 可关闭这一行为。



const Args = struct {
    data_dir: []const u8 = "data",
    listen: ?[]const u8 = null,
    controller: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    no_ctrl: bool = false,
    /// 是否启用全局接管（TUN）。默认关闭，需显式 --takeover
    takeover: bool = false,
    /// 显式要求提权重启（不带 --takeover 也可以单独用）
    elevate: bool = false,
    /// 禁止自动提权（CI/脚本场景：宁可失败也不要弹 UAC）
    no_elevate: bool = false,
    /// 内部标记：本进程是提权后被拉起的子进程
    elevated_child: bool = false,
    show_version: bool = false,
    show_help: bool = false,
};

/// 提权后重新拉起时用的标记，避免无限递归提权
const ELEVATED_MARKER = "--elevated-child";

pub fn main(init: std.process.Init.Minimal) !u8 {
    if (builtin.os.tag == .windows) {
        const kernel32 = struct {
            extern "kernel32" fn SetConsoleOutputCP(wCodePageID: c_uint) callconv(.winapi) c_int;
            extern "kernel32" fn SetConsoleCP(wCodePageID: c_uint) callconv(.winapi) c_int;
        };
        _ = kernel32.SetConsoleOutputCP(65001);
        _ = kernel32.SetConsoleCP(65001);
    }

    const alloc = std.heap.smp_allocator;

    const args = parseArgs(alloc, init.args) catch {
        printHelp();
        return 2;
    };
    // data_dir / listen / controller / mode 均由 alloc 持有，可无条件释放
    defer alloc.free(args.data_dir);
    defer if (args.listen) |v| alloc.free(v);
    defer if (args.controller) |v| alloc.free(v);
    defer if (args.mode) |v| alloc.free(v);

    if (args.show_help) {
        printHelp();
        return 0;
    }
    if (args.show_version) {
        printOut("aetherd {s}\n", .{core.version});
        printOut("  platform : {s}\n", .{core.tun.platformTag()});
        printOut("  elevated : {s}\n", .{if (core.elevate.isElevated()) "是" else "否"});
        return 0;
    }

    // ---- 提权前置检查 ----
    // 需要特权却没特权时，在**做任何事之前**就处理掉：
    // 晚了会出现「配置已加载、端口已监听、才发现建不了网卡」的半启动状态。
    if (shouldElevate(args)) {
        if (try tryElevate(alloc, args)) |code| return code;
    }

    return run(alloc, args) catch |e| {
        std.debug.print("aetherd: 启动失败: {any}\n", .{e});
        return 1;
    };
}

/// 是否应该尝试提权。
///
/// 三种情况：
/// 1. 用户显式 `--elevate`
/// 2. 用户要 `--takeover` 但当前没特权（接管必须提权，否则等于没接管）
/// 3. 已经在特权下 / 已被提权拉起过 / 用户禁用 —— 都不提
fn shouldElevate(args: Args) bool {
    if (args.no_elevate or args.elevated_child) return false;
    if (core.elevate.isElevated()) return false;
    if (args.elevate) return true;
    // --takeover 在没有可用接管后端时才需要提权；
    // 但探测本身不需要特权，所以这里先按「要接管就提权」处理，
    // 真正的可用性判断留给 run() 里的 listBackends。
    return args.takeover and core.tun.mayNeedElevation();
}

/// 以特权身份重启自己。返回 `null` 表示「不用重启，继续当前进程」。
fn tryElevate(alloc: std.mem.Allocator, args: Args) !?u8 {
    if (builtin.os.tag != .windows) {
        // 非 Windows：本进程无法自己提权，给出准确指令后退出。
        // 继续跑下去只会降级成入站代理，用户却以为接管生效了。
        const hint = try rebuildArgsForChild(alloc, args);
        defer alloc.free(hint);
        std.debug.print(
            \\[aetherd] TUN 接管需要 root 权限，但当前不是 root。
            \\[aetherd] 请用以下命令重新运行：
            \\[aetherd]     sudo aetherd {s}
            \\[aetherd] 若只想用本地入站代理（不接管全局流量），去掉 --takeover 即可。
            \\
        , .{hint});
        return 1;
    }

    const extra = try rebuildArgsForChild(alloc, args);
    defer alloc.free(extra);

    std.debug.print("[aetherd] 需要管理员权限，正在请求提权…\n", .{});
    const result = core.elevate.elevateWindows(alloc, extra, true, false) catch |e| switch (e) {
        core.elevate.Error.UserCancelled => {
            std.debug.print("[aetherd] 用户取消了提权请求。\n", .{});
            return 1;
        },
        core.elevate.Error.ElevationDisabled => {
            std.debug.print(
                "[aetherd] 系统拒绝提权（可能被组策略禁用）。\n" ++
                    "[aetherd] 请手动右键 aetherd.exe →「以管理员身份运行」。\n",
                .{},
            );
            return 1;
        },
        else => return 1,
    };

    switch (result) {
        // 子进程退出码是 u32；这里截断到 u8 是安全的：
        // main 的返回值本来就只看低 8 位，且 Windows 退出码极少超过 255。
        .exited => |code| return @truncate(code),
        .cancelled => {
            std.debug.print("[aetherd] 用户取消了提权请求。\n", .{});
            return 1;
        },
        .failed => |msg| {
            std.debug.print("[aetherd] 提权失败: {s}\n", .{msg});
            return 1;
        },
    }
}

/// 重建命令行参数（给子进程用），自动追加 `--elevated-child`。
fn rebuildArgsForChild(alloc: std.mem.Allocator, args: Args) ![]u8 {
    var list: std.ArrayList([]const u8) = .empty;
    defer list.deinit(alloc);

    try list.append(alloc, "--data-dir");
    try list.append(alloc, args.data_dir);
    if (args.listen) |v| {
        try list.append(alloc, "--listen");
        try list.append(alloc, v);
    }
    if (args.controller) |v| {
        try list.append(alloc, "--controller");
        try list.append(alloc, v);
    }
    if (args.mode) |v| {
        try list.append(alloc, "--mode");
        try list.append(alloc, v);
    }
    if (args.no_ctrl) try list.append(alloc, "--no-ctrl");
    if (args.takeover) try list.append(alloc, "--takeover");
    // 子进程已经提权，不能再提一次（否则 UAC 死循环）
    try list.append(alloc, ELEVATED_MARKER);

    return core.elevate.buildArgs(alloc, list.items);
}

fn run(alloc: std.mem.Allocator, args: Args) !u8 {
    std.debug.print("[aetherd] AetherCore {s} (platform={s})\n", .{ core.version, core.tun.platformTag() });

    // ---- 配置 ----
    const cfg_path = try std.fs.path.join(alloc, &.{ args.data_dir, "core.json" });
    defer alloc.free(cfg_path);

    var cfg = core.config.Config.loadFromFile(alloc, cfg_path) catch |e| blk: {
        std.debug.print("[aetherd] 读取 {s} 失败 ({any})，使用空配置\n", .{ cfg_path, e });
        break :blk try core.config.Config.parse(alloc, "{}", args.data_dir);
    };
    defer cfg.deinit();

    if (args.mode) |m| cfg.mode = core.config.Mode.fromString(m);

    // ---- 默认安全基线审计：未开启的安全是不安全的 ----
    const insecure_nodes = cfg.auditSecurity();
    if (insecure_nodes > 0) {
        std.debug.print("[aetherd] [安全告警] 检测到 {d} 个未满足安全基线的节点配置！\n", .{insecure_nodes});
    } else if (cfg.nodes.len > 0) {
        std.debug.print("[aetherd] [安全合规] 所有 {d} 个节点均已满足默认安全基线 (TLS 1.3 / AEAD / 抗量子混合保护).\n", .{cfg.nodes.len});
    }

    var router_inst = try core.router.Router.compile(alloc, &cfg);
    defer router_inst.deinit();

    var tracker = core.conntrack.Tracker.init(alloc);
    defer tracker.deinit();

    var stats = core.relay.Stats{};
    var cooldown = core.router.CooldownPool.init(alloc);
    defer cooldown.deinit();

    var delay_table = core.healthcheck.DelayTable.init(alloc);
    defer delay_table.deinit();

    const default_node = if (cfg.nodes.len > 0) cfg.nodes[0].name else "";

    // 加载系统根证书（失败不致命：没有证书时 TLS 节点会明确报错）
    var bundle = core.tls.loadSystemBundle(alloc);
    defer bundle.deinit(alloc);
    std.debug.print("[aetherd] 系统根证书 {d} 张，后量子抗量子防御 (ML-KEM-768 Hybrid) 默认已就绪\n", .{bundle.map.count()});

    var settings_inst = core.settings.Settings{};
    settings_inst.setMode(cfg.mode);
    settings_inst.setNode(default_node);

    // ---- Fake-IP 池（DNS 服务与连接反查共用同一份）----
    var fake_pool = core.dns.Pool.init(alloc);
    defer fake_pool.deinit();

    var core_ctx = core.runtime.Core{
        .alloc = alloc,
        .cfg = &cfg,
        .router = &router_inst,
        .tracker = &tracker,
        .stats = &stats,
        .cooldown = &cooldown,
        .settings = &settings_inst,
        .tls_ctx = .{ .bundle = &bundle },
        .pool = &fake_pool,
    };

    // ---- 入站地址 ----
    var listen_host = cfg.listen_host;
    var listen_port = cfg.listen_port;
    if (args.listen) |s| {
        const hp = parseCliHostPort(s) orelse return error.BadListen;
        listen_host = hp.host;
        listen_port = hp.port;
    }

    std.debug.print("[aetherd] 节点 {d} 个，模式 {s}\n", .{ cfg.nodes.len, cfg.mode.toString() });
    std.debug.print("[aetherd] 规则: 直连域 {d} / 代理域 {d} / 专属路由 {d}\n", .{
        cfg.direct_domains.len, cfg.proxy_domains.len, cfg.route_domains.len,
    });
    std.debug.print("[aetherd] 入站监听 {s}:{d}\n", .{ listen_host, listen_port });

    // ---- 平台能力（真实探测 + 实现状态）----
    const backends = try core.tun.listBackends(alloc);
    defer alloc.free(backends);
    for (backends) |b| {
        std.debug.print("[aetherd]   {s:<12} 可用={s}  {s}  【{s}】\n", .{
            b.kind.name(),
            if (b.available) "是" else "否",
            b.kind.label(),
            core.tun.explain(b),
        });
    }

    const picked = core.tun.pick(alloc);
    if (picked) |kind| {
        std.debug.print("[aetherd] 选定接管后端: {s}\n", .{kind.name()});
    } else {
        std.debug.print("[aetherd] 无可用接管后端 —— 以本地入站代理模式运行\n", .{});
        // 逐条说明「为什么不可用」，特别是把「缺 root」直说
        for (backends) |b| {
            if (b.available) continue;
            std.debug.print("[aetherd]   · {s}: {s}\n", .{ b.kind.name(), core.tun.explain(b) });
            if (b.detail == .permission_denied) {
                if (builtin.os.tag == .windows) {
                    std.debug.print(
                        "[aetherd]     → TUN 接管必须提权，请以「管理员身份运行」重新启动 aetherd --takeover\n",
                        .{},
                    );
                } else {
                    std.debug.print(
                        "[aetherd]     → TUN 接管必须提权，请用 `sudo aetherd --takeover` 重新运行\n",
                        .{},
                    );
                }
            }
        }
    }

    var running = std.atomic.Value(bool).init(true);

    // ---- 启动全局接管（目前仅 Linux 实现）----
    var tun_handle: ?core.tun.Handle = null;
    var tun_route_inst: ?*core.tun_route.Router = null;
    var tun_runner_inst: ?*core.tun_runner.Runner = null;
    var tun_glue_inst: ?*core.tun_glue.Glue = null;

    if (picked) |_| {
        // 注意：这里不能写 `kind == .linux_tun`。
        // `pick()` 返回的已经是「该平台已实现且环境可用」的后端，
        // 再按 kind 过滤等于把 wintun/utun 全排除掉 —— 曾经就是这样，
        // Windows 上 `pick()` 明明选出了 wintun，接管却永远不启动。
        if (args.takeover) try startTakeover(
            alloc,
            &cfg,
            &router_inst,
            &cooldown,
            &fake_pool,
            &running,
            &tun_handle,
            &tun_route_inst,
            &tun_runner_inst,
            &tun_glue_inst,
        );
    } else if (args.takeover) {
        // 用户明确要接管，但环境不允许。
        // **必须退出**：降级成入站代理继续跑会让用户以为流量已被接管，
        // 实际一个包都没进 TUN —— 这种「看起来成功」的失败最难排查。
        if (builtin.os.tag == .windows) {
            std.debug.print(
                "[aetherd] 已请求 --takeover，但当前无法接管：TUN 需要管理员权限。\n" ++
                    "[aetherd] 请以「管理员身份运行」重新启动，或去掉 --takeover 只跑本地入站代理。\n",
                .{},
            );
        } else {
            std.debug.print(
                "[aetherd] 已请求 --takeover，但当前无法接管：TUN 需要 root 权限" ++
                    "（容器内还需 CAP_NET_ADMIN）。\n" ++
                    "[aetherd] 请用 `sudo aetherd --takeover` 重新运行，或去掉 --takeover 只跑本地入站代理。\n",
                .{},
            );
        }
        return error.TakeoverUnavailable;
    }

    // ---- 控制面 ----
    var server: core.ctrl.Server = undefined;
    var ctrl_started = false;

    // 控制面鉴权 token：优先用显式配置，否则从 <data_dir>/middleware.token
    // 读取或生成。旧 Rust 版就是这么做的；Zig 版曾把它写成 TODO，
    // 结果控制面完全不鉴权 —— 一旦 controller 监听 0.0.0.0，局域网内
    // 任何人都能改分流模式、切节点、看全部连接。
    var token_buf: ?[]u8 = null;
    defer if (token_buf) |t| alloc.free(t);

    if (!args.no_ctrl) {
        var ctrl_host = cfg.controller_host;
        var ctrl_port = cfg.controller_port;
        if (args.controller) |s| {
            const hp = parseCliHostPort(s) orelse return error.BadController;
            ctrl_host = hp.host;
            ctrl_port = hp.port;
        }

        const ctrl_token: []const u8 = blk: {
            if (cfg.auth_token.len > 0) break :blk cfg.auth_token;
            token_buf = core.authtoken.loadOrCreate(alloc, cfg.data_dir) catch |e| {
                std.debug.print("[aetherd] 无法读取或生成鉴权 token: {any}\n", .{e});
                return e;
            };
            break :blk token_buf.?;
        };

        // 监听非回环地址却没 token 是危险的；但正常路径上 token 一定非空，
        // 这里只兜住「显式配置了空 token + 绑公网」这种自找的配置。
        if (ctrl_token.len == 0 and !isLoopbackHost(ctrl_host)) {
            std.debug.print(
                "[aetherd] 拒绝在 {s} 上以空 token 暴露控制面\n" ++
                    "         请设置 auth_token，或改回 127.0.0.1\n",
                .{ctrl_host},
            );
            return error.InsecureController;
        }

        var shared = core.ctrl.Shared{
            .alloc = alloc,
            .auth = .{ .token = ctrl_token },
            .tracker = &tracker,
            .stats = &stats,
            .settings = &settings_inst,
            .node_names = &.{},
            .delays = &delay_table,
            .platform_tag = core.tun.platformTag(),
            // 必须是「真实探测到可用后端」，而不是「这个 OS 理论上支持」
            .transparent_takeover = picked != null,
        };
        _ = &shared;

        // 节点名列表
        const names = try alloc.alloc([]const u8, cfg.nodes.len);
        defer alloc.free(names);
        for (cfg.nodes, 0..) |n, i| names[i] = n.name;
        shared.node_names = names;

        const addr = core.net.Address.parseIp(ctrl_host, ctrl_port) catch {
            std.debug.print("[aetherd] 控制面地址非法 {s}:{d}\n", .{ ctrl_host, ctrl_port });
            return error.BadController;
        };
        const listener = core.net.listen(addr, true) catch |e| {
            std.debug.print("[aetherd] 控制面监听失败 {any}\n", .{e});
            return e;
        };
        server = .{ .shared = &shared, .listener = listener };
        ctrl_started = true;

        const th = try std.Thread.spawn(.{}, core.ctrl.Server.serve, .{&server});
        th.detach();
        std.debug.print("[aetherd] 控制面监听 http://{s}:{d}\n", .{ ctrl_host, ctrl_port });
    }

    // ---- DNS 服务（可选）----
    var dns_srv: core.dnsserver.Server = undefined;
    var dns_started = false;

    if (cfg.dns_enabled) {
        const dns_listen = core.net.Address.parseIp(cfg.dns_listen_host, cfg.dns_listen_port) catch blk: {
            std.debug.print("[aetherd] DNS 监听地址非法 {s}:{d}\n", .{ cfg.dns_listen_host, cfg.dns_listen_port });
            break :blk core.net.Address.parseIp("127.0.0.1", 5353) catch unreachable;
        };
        var upstream = core.net.Address.parseIp(cfg.dns_upstream_host, cfg.dns_upstream_port) catch blk: {
            break :blk core.net.Address.parseIp("223.5.5.5", 53) catch unreachable;
        };
        // 上游可能给的是域名，尝试解析
        if (std.mem.indexOfScalar(u8, cfg.dns_upstream_host, ':') == null and
            std.mem.indexOfScalar(u8, cfg.dns_upstream_host, '.') == null)
        {
            if (core.net.getAddressList(alloc, cfg.dns_upstream_host, cfg.dns_upstream_port)) |list| {
                defer alloc.free(list);
                if (list.len > 0) upstream = list[0];
            } else |_| {}
        }

        dns_srv = .{
            .alloc = alloc,
            .cfg = .{
                .listen = dns_listen,
                .upstream = upstream,
                .ttl = cfg.dns_ttl,
            },
            .pool = &fake_pool,
            .router = &router_inst,
        };
        const dth = try std.Thread.spawn(.{}, core.dnsserver.Server.serveUdp, .{&dns_srv});
        dth.detach();
        dns_started = true;
        std.debug.print("[aetherd] DNS 监听 {s}:{d} → 上游 {s}:{d}\n", .{
            cfg.dns_listen_host, cfg.dns_listen_port,
            cfg.dns_upstream_host, cfg.dns_upstream_port,
        });
    }

    // ---- 主循环 ----
    defer if (ctrl_started) {
        server.stop();
        server.deinit();
    };
    defer if (dns_started) dns_srv.stop();

    // 退出时还原路由/DNS，并关闭 TUN —— 顺序与启动相反。
    // 先停数据面（glue 会关掉所有上游 socket），再拆网卡，
    // 否则读线程还在往一个已销毁的设备里写包。
    defer {
        running.store(false, .release);
        if (tun_glue_inst) |g| {
            g.deinit();
            alloc.destroy(g);
        }
        if (tun_runner_inst) |r| {
            r.deinit();
            alloc.destroy(r);
        }
        if (tun_route_inst) |rt| {
            rt.teardown();
            rt.deinit();
            alloc.destroy(rt);
        }
        if (tun_handle) |h| h.close();
    }

    std.debug.print("[aetherd] 服务已启动，Ctrl+C 退出\n", .{});
    try core.runtime.serveInbound(&core_ctx, listen_host, listen_port, &running);
    return 0;
}

/// 启动全局接管：建网卡 → 配路由/DNS → 跑数据面。
///
/// 任何一步失败都要**完整回滚**，否则会留下一个半配置的系统状态
/// （路由指向一个不存在的网卡 = 整机断网）。
fn startTakeover(
    alloc: std.mem.Allocator,
    cfg: *core.config.Config,
    rt: *core.router.Router,
    cool: *core.router.CooldownPool,
    pool: ?*core.dns.Pool,
    running: *std.atomic.Value(bool),
    out_handle: *?core.tun.Handle,
    out_route: *?*core.tun_route.Router,
    out_runner: *?*core.tun_runner.Runner,
    out_glue: *?*core.tun_glue.Glue,
) !void {
    std.debug.print("[aetherd] 正在建立 TUN 接管…\n", .{});

    // 1) 建网卡
    const handle = core.tun.establish(alloc, .{
        .name = "aether-tun0",
        .mtu = 1400,
        .ipv4 = "198.18.0.1/15",
        .dns = "198.18.0.1",
        .route_all = true,
    }) catch |e| {
        // 不吞掉：调用方在 `--takeover` 下必须让进程失败退出。
        std.debug.print("[aetherd] TUN 建立失败: {any}\n", .{e});
        return error.TunEstablishFailed;
    };
    out_handle.* = handle;
    std.debug.print("[aetherd] TUN 已建立: aether-tun0 198.18.0.1/15\n", .{});

    // 2) 配路由 + DNS
    const route_rt = try alloc.create(core.tun_route.Router);
    route_rt.* = core.tun_route.Router.init(alloc, .{
        .tun_name = "aether-tun0",
        .dns = "198.18.0.1",
        .route_all = true,
        // 防环路：把节点服务器地址排除在 TUN 之外
        .bypass_hosts = try collectNodeHosts(alloc, cfg),
    });
    out_route.* = route_rt;

    route_rt.apply() catch |e| {
        // 路由没配上等于流量没接管，必须回滚 + 上报，不能继续假装接管成功。
        std.debug.print("[aetherd] 路由配置失败: {any}（已回滚）\n", .{e});
        route_rt.deinit();
        alloc.destroy(route_rt);
        out_route.* = null;
        handle.close();
        out_handle.* = null;
        return error.TunRouteFailed;
    };
    std.debug.print("[aetherd] 路由/DNS 已接管（默认路由 → aether-tun0）\n", .{});

    // 3) 数据面
    const runner = try alloc.create(core.tun_runner.Runner);
    runner.* = core.tun_runner.Runner.init(alloc);
    out_runner.* = runner;

    // 4) 连接层：把协议栈的 SYN/数据回调接到真实出站
    //    没有这一步，TUN 能握手但一个字节都出不去。
    const glue = try alloc.create(core.tun_glue.Glue);
    glue.* = core.tun_glue.Glue.init(alloc, runner, cfg, rt, cool);
    glue.pool = pool;
    glue.node_name = if (cfg.nodes.len > 0) cfg.nodes[0].name else "";
    runner.stack.handler = glue.handler();
    out_glue.* = glue;

    const th = std.Thread.spawn(.{}, core.tun_runner.runLoop, .{ runner, handle, running }) catch |e| {
        std.debug.print("[aetherd] TUN 数据面线程启动失败: {any}（已回滚）\n", .{e});
        glue.deinit();
        alloc.destroy(glue);
        out_glue.* = null;
        runner.deinit();
        alloc.destroy(runner);
        out_runner.* = null;
        route_rt.deinit();
        alloc.destroy(route_rt);
        out_route.* = null;
        handle.close();
        out_handle.* = null;
        return error.ThreadSpawnFailed;
    };
    th.detach();
    std.debug.print("[aetherd] TUN 数据面已启动（出站已接入）\n", .{});
}

/// 收集所有节点服务器地址（用于防环路 bypass 路由）
fn collectNodeHosts(alloc: std.mem.Allocator, cfg: *core.config.Config) ![]const []const u8 {
    var list = std.ArrayList([]const u8).empty;
    errdefer list.deinit(alloc);
    for (cfg.nodes) |n| {
        // 只收 IP 字面量；域名形式的节点在绕过时无法直接建 /32 路由
        if (core.tun_route.isIpv4Literal(n.server)) {
            try list.append(alloc, n.server);
        }
    }
    return list.toOwnedSlice(alloc);
}

fn parseArgs(alloc: std.mem.Allocator, args_val: std.process.Args) !Args {
    var out = Args{ .data_dir = try alloc.dupe(u8, "data") };
    var it = try std.process.Args.Iterator.initAllocator(args_val, alloc);
    defer it.deinit();

    // 跳过程序名 argv[0]
    _ = it.skip();

    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            out.show_help = true;
        } else if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-V")) {
            out.show_version = true;
        } else if (std.mem.eql(u8, a, "--no-ctrl")) {
            out.no_ctrl = true;
        } else if (std.mem.eql(u8, a, "--takeover")) {
            out.takeover = true;
        } else if (std.mem.eql(u8, a, "--elevate")) {
            out.elevate = true;
        } else if (std.mem.eql(u8, a, "--no-elevate")) {
            out.no_elevate = true;
        } else if (std.mem.eql(u8, a, ELEVATED_MARKER)) {
            out.elevated_child = true;
        } else if (std.mem.eql(u8, a, "--data-dir") or std.mem.eql(u8, a, "-d")) {
            const val = it.next() orelse return error.MissingValue;
            alloc.free(out.data_dir);
            out.data_dir = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, a, "--listen")) {
            const val = it.next() orelse return error.MissingValue;
            out.listen = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, a, "--controller")) {
            const val = it.next() orelse return error.MissingValue;
            out.controller = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, a, "--mode")) {
            const val = it.next() orelse return error.MissingValue;
            out.mode = try alloc.dupe(u8, val);
        }
    }
    return out;
}

fn parseCliHostPort(s: []const u8) ?struct { host: []const u8, port: u16 } {
    const idx = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const host = s[0..idx];
    const port = std.fmt.parseInt(u16, s[idx + 1 ..], 10) catch return null;
    return .{ .host = host, .port = port };
}

/// 判断监听地址是否只在本机可达。
///
/// 用于「控制面绑公网 + 空 token」的拦截。宁可把 `localhost` 当非回环
/// （多解析一次反而更危险），也不要漏判成回环把控制面裸奔出去。
fn isLoopbackHost(host: []const u8) bool {
    if (std.mem.eql(u8, host, "127.0.0.1")) return true;
    if (std.mem.eql(u8, host, "::1")) return true;
    if (std.mem.eql(u8, host, "[::1]")) return true;
    // 127.0.0.0/8
    if (std.mem.startsWith(u8, host, "127.")) return true;
    return false;
}

/// 打印到控制台
fn printOut(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}

fn printHelp() void {
    printOut(
        \\AetherCore 守护进程 (aetherd)
        \\
        \\用法: aetherd [选项]
        \\
        \\选项:
        \\  -d, --data-dir <DIR>     数据目录 (默认 data)
        \\      --listen <HOST:PORT> 入站监听地址
        \\      --controller <HOST:PORT> 控制面地址
        \\      --mode <MODE>        rule|global|direct
        \\      --no-ctrl            不启动控制面
        \\      --takeover           全局接管（TUN），需要管理员/root
        \\      --elevate            强制请求提权重启
        \\      --no-elevate         禁止自动提权（调试用）
        \\  -V, --version            显示版本
        \\  -h, --help               显示帮助
        \\
    , .{});
}
























