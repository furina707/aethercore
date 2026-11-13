const std = @import("std");
const config = @import("config.zig");
const security = @import("security.zig");
const net = @import("net.zig");
const proxy = @import("proxy.zig");
const control = @import("control.zig");
const router = @import("router.zig");
const dwm_render = @import("dwm_render.zig");
const gui_gtk4 = @import("gui_gtk4.zig");

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;
    const allocator = std.heap.c_allocator;

    // 1. 初始化默认安全管理器 (强制仅回环 127.0.0.1)
    var sec = try security.SecurityManager.init(allocator, false);
    defer sec.deinit();

    // 2. 初始化 DWM 高清渲染器 (PerMonitorV2 原生点阵物理像素)
    const dwm = dwm_render.DwmPhysicalRenderer.init();
    _ = dwm;

    // 3. 初始化全局配置、流量统计与分 IP 代理调度器
    var cfg = try config.AppConfig.initDefault(allocator);
    defer cfg.deinit(allocator);

    var stats = proxy.TrafficStats{};
    var ip_tracker = router.IpSessionTracker{};

    // 4. 后台启动网络核心 (SOCKS5 / 分 IP 代理 / REST 控制面)
    const srv_thread_ctx = struct {
        sec: *const security.SecurityManager,
        cfg: *config.AppConfig,
        stats: *proxy.TrafficStats,
        ip_tracker: *router.IpSessionTracker,
        allocator: std.mem.Allocator,
    }{
        .sec = &sec,
        .cfg = &cfg,
        .stats = &stats,
        .ip_tracker = &ip_tracker,
        .allocator = allocator,
    };

    const srv_thread = try std.Thread.spawn(.{}, runCoreServices, .{srv_thread_ctx});
    srv_thread.detach();

    // 5. 自动运行: 有显示服务时直接运行图形界面，无显示环境以守护进程运行
    const has_display = std.c.getenv("DISPLAY") != null or std.c.getenv("WAYLAND_DISPLAY") != null;

    if (has_display) {
        var gui_ctx = gui_gtk4.GuiContext{
            .cfg = &cfg,
            .stats = &stats,
            .sec = &sec,
            .ip_tracker = &ip_tracker,
        };
        gui_gtk4.runGui(&gui_ctx) catch {
            runTerminalLoop(&stats);
        };
    } else {
        runTerminalLoop(&stats);
    }
}

fn runCoreServices(ctx: anytype) void {
    const host = ctx.sec.getListenHost();

    // 启动 SOCKS5 监听
    const socks_fd = net.createTcpListener(host, ctx.cfg.socks5_port) catch return;

    // 启动 REST 控制面监听
    const ctrl_fd = net.createTcpListener(host, ctx.cfg.control_port) catch return;

    // 启动控制面处理线程
    const ctrl_thread = std.Thread.spawn(.{}, runControlLoop, .{
        ctx.allocator,
        ctrl_fd,
        ctx.sec,
        ctx.cfg,
        ctx.stats,
        ctx.ip_tracker,
    }) catch return;
    ctrl_thread.detach();

    // 主代理循环 (SOCKS5 结合分 IP 代理引擎)
    var p_server = proxy.ProxyServer.init(ctx.allocator, ctx.cfg, ctx.stats, ctx.ip_tracker);
    while (true) {
        const client_fd = net.acceptTcp(socks_fd) catch continue;
        const worker = std.Thread.spawn(.{}, handleProxyClient, .{ &p_server, client_fd }) catch {
            net.closeSocket(client_fd);
            continue;
        };
        worker.detach();
    }
}

fn handleProxyClient(p_server: *proxy.ProxyServer, client_fd: c_int) void {
    p_server.handleSocks5Client(client_fd);
}

fn runControlLoop(
    allocator: std.mem.Allocator,
    listener_fd: c_int,
    sec: *const security.SecurityManager,
    cfg: *config.AppConfig,
    stats: *proxy.TrafficStats,
    ip_tracker: *router.IpSessionTracker,
) void {
    var cp = control.ControlPlane.init(allocator, sec, cfg, stats, ip_tracker);
    while (true) {
        const client_fd = net.acceptTcp(listener_fd) catch continue;
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

fn runTerminalLoop(stats: *proxy.TrafficStats) void {
    while (true) {
        _ = sleep(2);
        const up = stats.bytes_uploaded.load(.monotonic);
        const down = stats.bytes_downloaded.load(.monotonic);
        const conns = stats.active_connections.load(.monotonic);
        std.debug.print("[Live] 连接: {} | 上传: {} B | 下载: {} B\n", .{ conns, up, down });
    }
}
