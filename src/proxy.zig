const std = @import("std");
const net = @import("net.zig");
const config = @import("config.zig");
const router_mod = @import("router.zig");

pub const TrafficStats = struct {
    bytes_uploaded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_downloaded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    active_connections: std.atomic.Value(i32) = std.atomic.Value(i32).init(0),
    total_connections: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    current_speed_up_bps: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    current_speed_down_bps: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn recordUpload(self: *TrafficStats, n: usize) void {
        _ = self.bytes_uploaded.fetchAdd(n, .monotonic);
    }

    pub fn recordDownload(self: *TrafficStats, n: usize) void {
        _ = self.bytes_downloaded.fetchAdd(n, .monotonic);
    }

    pub fn incConn(self: *TrafficStats) void {
        _ = self.active_connections.fetchAdd(1, .monotonic);
        _ = self.total_connections.fetchAdd(1, .monotonic);
    }

    pub fn decConn(self: *TrafficStats) void {
        _ = self.active_connections.fetchSub(1, .monotonic);
    }
};

pub const ProxyServer = struct {
    allocator: std.mem.Allocator,
    cfg: *config.AppConfig,
    stats: *TrafficStats,
    router: router_mod.Router,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn init(allocator: std.mem.Allocator, cfg: *config.AppConfig, stats: *TrafficStats, ip_tracker: *router_mod.IpSessionTracker) ProxyServer {
        return ProxyServer{
            .allocator = allocator,
            .cfg = cfg,
            .stats = stats,
            .router = router_mod.Router.init(cfg.mode, ip_tracker),
        };
    }

    /// 处理 SOCKS5 客户端连接
    pub fn handleSocks5Client(self: *ProxyServer, client_fd: c_int) void {
        defer net.closeSocket(client_fd);
        self.stats.incConn();
        defer self.stats.decConn();

        var buf: [512]u8 = undefined;

        // 1. 协商版本与认证方法
        const n1 = net.recv(client_fd, buf[0..]) catch return;
        if (n1 < 2 or buf[0] != 0x05) return;
        const num_methods = buf[1];
        if (n1 < 2 + num_methods) return;

        // 回复无认证 [0x05, 0x00]
        net.sendAll(client_fd, &[_]u8{ 0x05, 0x00 }) catch return;

        // 2. 读取客户端请求
        const n2 = net.recv(client_fd, buf[0..]) catch return;
        if (n2 < 7 or buf[0] != 0x05 or buf[1] != 0x01) {
            // 仅支持 CONNECT 命令 (0x01)
            _ = net.sendAll(client_fd, &[_]u8{ 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
            return;
        }

        const atyp = buf[3];
        var host_buf: [256]u8 = undefined;
        var host_slice: []const u8 = "";
        var port: u16 = 0;

        if (atyp == 0x01) {
            // IPv4
            if (n2 < 10) return;
            const ip_str = std.fmt.bufPrint(&host_buf, "{}.{}.{}.{}", .{ buf[4], buf[5], buf[6], buf[7] }) catch return;
            host_slice = ip_str;
            port = (@as(u16, buf[8]) << 8) | buf[9];
        } else if (atyp == 0x03) {
            // 域名
            const domain_len = buf[4];
            if (n2 < 5 + domain_len + 2) return;
            @memcpy(host_buf[0..domain_len], buf[5 .. 5 + domain_len]);
            host_slice = host_buf[0..domain_len];
            const p_idx = 5 + domain_len;
            port = (@as(u16, buf[p_idx]) << 8) | buf[p_idx + 1];
        } else {
            // 不支持的地址类型
            _ = net.sendAll(client_fd, &[_]u8{ 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
            return;
        }

        // 3. 核心功能: 分 IP 代理路由决策
        const decision = self.router.routeTarget(host_slice, port, self.cfg.active_node_index, self.cfg.nodes.items.len);
        if (decision.action == .reject) {
            // 默认安全: 规则拦截
            _ = net.sendAll(client_fd, &[_]u8{ 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
            return;
        }

        // 记录分 IP 会话分配状态
        self.router.ip_tracker.record(host_slice, decision.node_index);
        defer self.router.ip_tracker.release(host_slice);

        // 4. 连接上游 (直连或经选定的分 IP 代理出口节点)
        var remote_fd: c_int = -1;
        if (decision.action == .direct or decision.node_index == 0) {
            remote_fd = net.connectTcp(host_slice, port) catch {
                _ = net.sendAll(client_fd, &[_]u8{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
                return;
            };
        } else {
            // 使用经由一致性哈希/CIDR分流指派的具体代理出口节点
            const assigned_node = if (decision.node_index < self.cfg.nodes.items.len)
                self.cfg.nodes.items[decision.node_index]
            else
                self.cfg.getActiveNode() orelse return;

            remote_fd = net.connectTcp(assigned_node.server, assigned_node.port) catch {
                _ = net.sendAll(client_fd, &[_]u8{ 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
                return;
            };
        }
        defer net.closeSocket(remote_fd);

        // 5. 告知客户端连接成功
        net.sendAll(client_fd, &[_]u8{ 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }) catch return;

        // 6. 双向数据转发泵
        self.pump(client_fd, remote_fd);
    }

    /// 双向高速无阻塞中继与流量统计
    fn pump(self: *ProxyServer, client_fd: c_int, remote_fd: c_int) void {
        var fds: [2]std.posix.pollfd = .{
            .{ .fd = client_fd, .events = net.POLLIN, .revents = 0 },
            .{ .fd = remote_fd, .events = net.POLLIN, .revents = 0 },
        };

        var buf_c2r: [16384]u8 = undefined;
        var buf_r2c: [16384]u8 = undefined;

        while (self.running.load(.monotonic)) {
            const ret = std.c.poll(@ptrCast(&fds), 2, 3000);
            if (ret <= 0) break;

            // 客户端 -> 远端
            if (fds[0].revents & net.POLLIN != 0) {
                const n = net.recv(client_fd, &buf_c2r) catch 0;
                if (n == 0) break;
                net.sendAll(remote_fd, buf_c2r[0..n]) catch break;
                self.stats.recordUpload(n);
            }

            // 远端 -> 客户端
            if (fds[1].revents & net.POLLIN != 0) {
                const n = net.recv(remote_fd, &buf_r2c) catch 0;
                if (n == 0) break;
                net.sendAll(client_fd, buf_r2c[0..n]) catch break;
                self.stats.recordDownload(n);
            }

            if ((fds[0].revents | fds[1].revents) & (net.POLLERR | net.POLLHUP) != 0) {
                break;
            }
        }
    }
};
