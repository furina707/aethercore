const std = @import("std");
const config = @import("config.zig");
const security = @import("security.zig");
const net = @import("net.zig");
const proxy = @import("proxy.zig");
const control = @import("control.zig");
const router = @import("router.zig");
const dwm_render = @import("dwm_render.zig");
const gui_gtk4 = @import("gui_gtk4.zig");
const tun = @import("tun.zig");

var global_tun: ?*tun.TunDevice = null;

extern "c" fn signal(sig: c_int, handler: ?*const fn (c_int) callconv(.c) void) ?*const fn (c_int) callconv(.c) void;

fn onSignal(_: c_int) callconv(.c) void {
    if (global_tun) |dev| {
        dev.restoreRoutes();
    }
    std.c.exit(0);
}

fn hasDisplay() bool {
    if (std.c.getenv("WAYLAND_DISPLAY")) |w| {
        if (w[0] != 0) return true;
    }
    if (std.c.getenv("DISPLAY")) |d| {
        if (d[0] != 0) return true;
    }
    return false;
}

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;
    const allocator = std.heap.c_allocator;

    // 0. 检查 root 权限 (TUN 虚拟网卡与系统路由劫持属于内核网络子系统，必须以 root 权限执行)
    if (std.c.geteuid() != 0) {
        std.debug.print("[AetherCore] 警告: 当前未以 root 权限运行！TUN 虚拟网卡与全局流量劫持需要 root (sudo) 权限。\n", .{});
    }

    // 1. 初始化安全管理器 (回环限制与令牌授权)
    var sec = try security.SecurityManager.init(allocator, false);
    defer sec.deinit();

    // 2. 初始化 DWM 高清渲染器 (PerMonitorV2 原生物理点阵)
    const dwm = dwm_render.DwmPhysicalRenderer.init();
    _ = dwm;

    // 3. 初始化全局配置、流量统计与分 IP 代理调度器
    var cfg = try config.AppConfig.initDefault(allocator);
    defer cfg.deinit(allocator);

    var stats = proxy.TrafficStats{};
    var ip_tracker = router.IpSessionTracker{};

    // 4. 初始化 TUN 虚拟网卡设备 (纯 TUN 模式流量全量劫持)
    var tun_dev = tun.TunDevice.init(allocator, &cfg, &stats, &ip_tracker);
    global_tun = &tun_dev;

    // 安装退出信号处理 (确保恢复路由)
    _ = signal(2, &onSignal); // SIGINT
    _ = signal(15, &onSignal); // SIGTERM

    // 5. 启动内部 REST 控制面 (供调试或本地自动化调用)
    const ctrl_thread_ctx = struct {
        allocator: std.mem.Allocator,
        sec: *const security.SecurityManager,
        cfg: *config.AppConfig,
        stats: *proxy.TrafficStats,
        ip_tracker: *router.IpSessionTracker,
    }{
        .allocator = allocator,
        .sec = &sec,
        .cfg = &cfg,
        .stats = &stats,
        .ip_tracker = &ip_tracker,
    };
    const ctrl_thread = try std.Thread.spawn(.{}, runControlService, .{ctrl_thread_ctx});
    ctrl_thread.detach();

    // 6. 判断显示服务: 有显示环境启动原生 GTK4 界面，无显示环境启动守护进程
    if (hasDisplay()) {
        var gui_ctx = gui_gtk4.GuiContext{
            .cfg = &cfg,
            .stats = &stats,
            .sec = &sec,
            .ip_tracker = &ip_tracker,
            .tun_dev = &tun_dev,
        };
        gui_gtk4.runGui(&gui_ctx) catch {
            runDaemonMode(&tun_dev, &stats);
        };
    } else {
        runDaemonMode(&tun_dev, &stats);
    }

    tun_dev.restoreRoutes();
}

fn runControlService(ctx: anytype) void {
    const host = ctx.sec.getListenHost();
    const ctrl_fd = net.createTcpListener(host, ctx.cfg.control_port) catch return;

    var cp = control.ControlPlane.init(ctx.allocator, ctx.sec, ctx.cfg, ctx.stats, ctx.ip_tracker);
    while (true) {
        const client_fd = net.acceptTcp(ctrl_fd) catch continue;
        const worker = std.Thread.spawn(.{}, handleControlClient, .{ &cp, client_fd }) catch {
            net.closeSocket(client_fd);
            continue;
        };
        worker.detach();
    }
}

fn handleControlClient(cp: *control.ControlPlane, client_fd: c_int) void {
    cp.handleClient(client_fd);
}

extern "c" fn sleep(seconds: c_uint) c_uint;

fn runDaemonMode(tun_dev: *tun.TunDevice, stats: *proxy.TrafficStats) void {
    // 纯 TUN 守护模式: 自动创建 TUN 并接管所有网络流量
    tun_dev.open() catch |err| {
        std.debug.print("[TUN] 打开 TUN 虚拟网卡失败: {}\n", .{err});
        return;
    };
    tun_dev.takeoverRoutes();
    std.debug.print("[TUN] aether0 网卡已激活，已全量接管系统网络流量 (分 IP 代理中)\n", .{});

    while (tun_dev.is_active) {
        _ = sleep(2);
        const up = stats.bytes_uploaded.load(.monotonic);
        const down = stats.bytes_downloaded.load(.monotonic);
        const conns = stats.active_connections.load(.monotonic);
        std.debug.print("[TUN 流量] 活跃 IP: {} | 上传: {} B | 下载: {} B\n", .{ conns, up, down });
    }
}
