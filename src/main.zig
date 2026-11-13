const std = @import("std");
const config = @import("config.zig");
const security = @import("security.zig");
const net = @import("net.zig");
const proxy = @import("proxy.zig");
const control = @import("control.zig");
const router = @import("router.zig");
const dwm_render = @import("dwm_render.zig");
const gui_gtk4 = @import("gui_gtk4.zig");

pub const VERSION = "4.0.0-pure-zig";

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.c_allocator;

    // 1. 解析命令行参数
    var it = init.args.iterate();
    _ = it.next(); // 跳过程序名

    var is_daemon_mode = false;
    var force_gui = false;
    var is_mobile = false;
    var allow_lan = false;

    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--daemon") or std.mem.eql(u8, arg, "-d")) {
            is_daemon_mode = true;
        } else if (std.mem.eql(u8, arg, "--mobile") or std.mem.eql(u8, arg, "-m")) {
            force_gui = true;
            is_mobile = true;
        } else if (std.mem.eql(u8, arg, "--gui") or std.mem.eql(u8, arg, "-g")) {
            force_gui = true;
        } else if (std.mem.eql(u8, arg, "--unsafe-lan")) {
            allow_lan = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            std.debug.print("AetherCore {s}\n", .{VERSION});
            std.debug.print("纯 Zig 完整重写架构 · 默认安全 · Linux GTK4 · DWM PerMonitorV2 高清渲染\n", .{});
            return;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printHelp();
            return;
        }
    }

    // 2. 初始化默认安全管理器
    // 默认安全原则: 未开启的安全是不安全的
    var sec = try security.SecurityManager.init(allocator, allow_lan);
    defer sec.deinit();

    std.debug.print("\n", .{});
    std.debug.print("=================================================================\n", .{});
    std.debug.print("  AetherCore 4.0 [纯 Zig 单二进制原生架构]\n", .{});
    std.debug.print("  * 默认安全状态: 已激活 (绑定 {s} | 256 位 CSPRNG 鉴权)\n", .{sec.getListenHost()});
    std.debug.print("  * 安全鉴权令牌: {s}\n", .{sec.getTokenString()});
    std.debug.print("=================================================================\n\n", .{});

    // 3. 初始化 DWM 高清渲染器 (PerMonitorV2 声明)
    const dwm = dwm_render.DwmPhysicalRenderer.init();
    _ = dwm;

    // 4. 初始化全局配置与流量统计
    var cfg = try config.AppConfig.initDefault(allocator);
    defer cfg.deinit(allocator);

    var stats = proxy.TrafficStats{};
    var ip_tracker = router.IpSessionTracker{};

    // 5. 启动后台网络代理服务与控制面服务
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

    // 6. GUI 与无头模式调度
    // 如果指定了 --daemon，或者没有显示环境，则以无头后台模式运行
    const has_display = std.c.getenv("DISPLAY") != null or std.c.getenv("WAYLAND_DISPLAY") != null;
    const should_run_gui = (force_gui or (!is_daemon_mode and has_display));

    if (should_run_gui) {
        std.debug.print("[GUI] 正在启动 Linux GTK4 原生图形界面 (MIUIX 卡片风格)...\n", .{});
        var gui_ctx = gui_gtk4.GuiContext{
            .cfg = &cfg,
            .stats = &stats,
            .sec = &sec,
            .ip_tracker = &ip_tracker,
            .is_mobile = is_mobile,
        };
        gui_gtk4.runGui(&gui_ctx) catch |err| {
            std.debug.print("[GUI] 启动失败 ({any})，自动回退到终端守护进程模式\n", .{err});
            runTerminalLoop(&stats);
        };
    } else {
        std.debug.print("[Daemon] 正在以守护进程模式运行 (Ctrl+C 退出)...\n", .{});
        runTerminalLoop(&stats);
    }
}

fn runCoreServices(ctx: anytype) void {
    const host = ctx.sec.getListenHost();

    // 启动 SOCKS5 监听
    const socks_fd = net.createTcpListener(host, ctx.cfg.socks5_port) catch |err| {
        std.debug.print("[!] SOCKS5 监听失败 (:{}): {any}\n", .{ ctx.cfg.socks5_port, err });
        return;
    };
    std.debug.print("[+] SOCKS5 监听已就绪: {s}:{}\n", .{ host, ctx.cfg.socks5_port });

    // 启动 REST 控制面监听
    const ctrl_fd = net.createTcpListener(host, ctx.cfg.control_port) catch |err| {
        std.debug.print("[!] 控制面监听失败 (:{}): {any}\n", .{ ctx.cfg.control_port, err });
        return;
    };
    std.debug.print("[+] REST 控制面已就绪: {s}:{} (默认安全鉴权开启)\n", .{ host, ctx.cfg.control_port });

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

fn printHelp() void {
    std.debug.print(
        \\AetherCore - 极简、高性能纯 Zig 网络核心
        \\
        \\用法:
        \\  aethercore [选项]
        \\
        \\选项:
        \\  -d, --daemon       以无头守护进程模式运行 (不启动 GUI)
        \\  -g, --gui          强制拉起 Linux GTK4 桌面 GUI
        \\  -m, --mobile       以手机版 MIUIX 竖屏模式 (390×820) 拉起 GUI 模拟器
        \\      --unsafe-lan   显式允许监听局域网 (默认安全关闭此项)
        \\  -v, --version      显示版本信息
        \\  -h, --help         显示此帮助页面
        \\
        \\默认安全 (Secure by Default):
        \\  - 所有端口默认仅绑定 127.0.0.1 本机回环地址。
        \\  - 控制面强制使用高熵 256 位 CSPRNG 密钥 (data/auth.token, 权限 0600)。
        \\  - DWM PerMonitorV2 高清点阵物理像素渲染，杜绝位图缩放插值模糊。
        \\
    , .{});
}
