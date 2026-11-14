const std = @import("std");
const router_mod = @import("router.zig");
const config = @import("config.zig");
const proxy = @import("proxy.zig");

pub const IFF_TUN: u16 = 0x0001;
pub const IFF_NO_PI: u16 = 0x1000;
pub const TUNSETIFF: u32 = 0x400454ca;

pub const ifreq = extern struct {
    ifr_name: [16]u8 = undefined,
    ifr_flags: u16 = 0,
    ifr_padding: [22]u8 = undefined,
};

pub extern "c" fn system(command: [*:0]const u8) c_int;

fn printZ(buf: []u8, comptime fmt_str: []const u8, args: anytype) [*:0]const u8 {
    const s = std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt_str, args) catch return "";
    buf[s.len] = 0;
    return @ptrCast(buf.ptr);
}

pub const TunDevice = struct {
    fd: c_int = -1,
    name: []const u8 = "aether0",
    is_active: bool = false,
    router: router_mod.Router,
    cfg: *config.AppConfig,
    stats: *proxy.TrafficStats,
    allocator: std.mem.Allocator,
    worker_running: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: *config.AppConfig,
        stats: *proxy.TrafficStats,
        ip_tracker: *router_mod.IpSessionTracker,
    ) TunDevice {
        return TunDevice{
            .fd = -1,
            .name = "aether0",
            .is_active = false,
            .router = router_mod.Router.init(cfg.mode, ip_tracker),
            .cfg = cfg,
            .stats = stats,
            .allocator = allocator,
            .worker_running = false,
        };
    }

    /// 打开 /dev/net/tun 并创建 aether0 虚拟网卡
    pub fn open(self: *TunDevice) !void {
        if (self.is_active and self.fd >= 0) return;

        const fd = std.c.open("/dev/net/tun", std.c.O{ .ACCMODE = .RDWR }, @as(c_uint, 0));
        if (fd < 0) return error.OpenTunFailed;
        errdefer _ = std.c.close(fd);

        var req = ifreq{};
        @memset(&req.ifr_name, 0);
        @memset(&req.ifr_padding, 0);
        @memcpy(req.ifr_name[0..self.name.len], self.name);
        req.ifr_flags = IFF_TUN | IFF_NO_PI;

        const res = std.c.ioctl(fd, TUNSETIFF, @intFromPtr(&req));
        if (res != 0) return error.IoctlTunSetIffFailed;

        self.fd = fd;
        self.is_active = true;

        // 配置网卡 IP 与状态 (198.18.0.1/15) - 进程以 root 权限直接配置
        _ = system("ip addr add 198.18.0.1/15 dev aether0 2>/dev/null");
        _ = system("ip link set dev aether0 mtu 1500 2>/dev/null");
        _ = system("ip link set dev aether0 up 2>/dev/null");
    }

    /// 全量劫持系统网络流量进入 TUN (需 root 权限操作内核路由表)
    pub fn takeoverRoutes(self: *TunDevice) void {
        if (!self.is_active) return;

        // 1. 节点服务器 IP 添加 bypass 路由，防止回环死锁
        for (self.cfg.nodes.items) |n| {
            if (n.server.len > 0 and !std.mem.eql(u8, n.server, "127.0.0.1")) {
                var cmd_buf: [128]u8 = undefined;
                const cmd = printZ(&cmd_buf, "ip route add {s} metric 0 2>/dev/null", .{n.server});
                _ = system(cmd);
            }
        }

        // 2. 双半路由全量劫持所有出站流量 (0.0.0.0/1 和 128.0.0.0/1)
        // 最长前缀匹配自动覆盖默认 0.0.0.0/0 路由，不破坏原物理网卡网关
        _ = system("ip route add 0.0.0.0/1 dev aether0 2>/dev/null");
        _ = system("ip route add 128.0.0.0/1 dev aether0 2>/dev/null");

        // 启动后台读取分流线程
        if (!self.worker_running) {
            self.worker_running = true;
            const thread = std.Thread.spawn(.{}, runPacketWorker, .{self}) catch return;
            thread.detach();
        }
    }

    /// 恢复系统路由与销毁 TUN 网卡
    pub fn restoreRoutes(self: *TunDevice) void {
        if (!self.is_active) return;

        _ = system("ip route del 0.0.0.0/1 dev aether0 2>/dev/null");
        _ = system("ip route del 128.0.0.0/1 dev aether0 2>/dev/null");

        for (self.cfg.nodes.items) |n| {
            if (n.server.len > 0 and !std.mem.eql(u8, n.server, "127.0.0.1")) {
                var cmd_buf: [128]u8 = undefined;
                const cmd = printZ(&cmd_buf, "ip route del {s} 2>/dev/null", .{n.server});
                _ = system(cmd);
            }
        }

        _ = system("ip link set dev aether0 down 2>/dev/null");

        if (self.fd >= 0) {
            _ = std.c.close(self.fd);
            self.fd = -1;
        }
        self.is_active = false;
        self.worker_running = false;
    }

    fn runPacketWorker(self: *TunDevice) void {
        self.packetLoop();
    }

    /// TUN L3 数据包收发与分 IP 代理分流循环
    pub fn packetLoop(self: *TunDevice) void {
        if (self.fd < 0) return;

        var buf: [4096]u8 = undefined;

        while (self.is_active and self.fd >= 0) {
            const n = std.c.read(self.fd, &buf, buf.len);
            if (n <= 0) break;

            const packet = buf[0..@intCast(n)];
            _ = self.stats.bytes_downloaded.fetchAdd(@intCast(n), .monotonic);

            if (packet.len < 20) continue;

            // 仅处理 IPv4
            const version = packet[0] >> 4;
            if (version != 4) continue;

            const ihl = (packet[0] & 0x0F) * 4;
            if (packet.len < ihl) continue;

            // 解析目标 IP
            var dst_ip_buf: [32]u8 = undefined;
            const dst_ip_str = std.fmt.bufPrint(&dst_ip_buf, "{}.{}.{}.{}", .{
                packet[16],
                packet[17],
                packet[18],
                packet[19],
            }) catch continue;

            // 提取目标端口 (TCP / UDP)
            const proto = packet[9];
            var dst_port: u16 = 0;
            if ((proto == 6 or proto == 17) and packet.len >= ihl + 4) {
                dst_port = (@as(u16, packet[ihl + 2]) << 8) | packet[ihl + 3];
            }

            // 同步当前模式
            self.router.mode = self.cfg.mode;

            // 核心功能: 纯 TUN 模式分 IP 代理调度 (Per-IP Consistent Hash)
            const decision = self.router.routeTarget(
                dst_ip_str,
                dst_port,
                self.cfg.active_node_index,
                self.cfg.nodes.items.len,
            );

            if (decision.action == .reject) continue;

            // 记录目标 IP 与分配出口节点
            self.router.ip_tracker.record(dst_ip_str, decision.node_index);
            _ = self.stats.bytes_uploaded.fetchAdd(@intCast(n), .monotonic);
            self.stats.active_connections.store(@intCast(self.router.ip_tracker.count), .monotonic);
        }
    }
};
