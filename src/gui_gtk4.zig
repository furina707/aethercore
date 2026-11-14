const std = @import("std");
const config = @import("config.zig");
const proxy = @import("proxy.zig");
const security = @import("security.zig");
const router_mod = @import("router.zig");
const tun = @import("tun.zig");

pub const GtkWidget = anyopaque;
pub const GtkApplication = anyopaque;
pub const GApplication = anyopaque;
pub const GdkDisplay = anyopaque;
pub const GtkCssProvider = anyopaque;
pub const GtkStyleProvider = anyopaque;

pub extern "c" fn gtk_init() void;
pub extern "c" fn gtk_application_new(application_id: ?[*:0]const u8, flags: c_uint) ?*GtkApplication;
pub extern "c" fn gtk_application_window_new(application: ?*GtkApplication) ?*GtkWidget;
pub extern "c" fn gtk_window_set_title(window: ?*GtkWidget, title: [*:0]const u8) void;
pub extern "c" fn gtk_window_set_default_size(window: ?*GtkWidget, width: c_int, height: c_int) void;
pub extern "c" fn gtk_window_set_child(window: ?*GtkWidget, child: ?*GtkWidget) void;
pub extern "c" fn gtk_window_present(window: ?*GtkWidget) void;

pub extern "c" fn gtk_box_new(orientation: c_int, spacing: c_int) ?*GtkWidget;
pub extern "c" fn gtk_box_append(box: ?*GtkWidget, child: ?*GtkWidget) void;
pub extern "c" fn gtk_label_new(str: ?[*:0]const u8) ?*GtkWidget;
pub extern "c" fn gtk_label_set_text(label: ?*GtkWidget, str: [*:0]const u8) void;
pub extern "c" fn gtk_label_set_markup(label: ?*GtkWidget, str: [*:0]const u8) void;
pub extern "c" fn gtk_button_new_with_label(label: [*:0]const u8) ?*GtkWidget;
pub extern "c" fn gtk_switch_new() ?*GtkWidget;
pub extern "c" fn gtk_switch_set_active(sw: ?*GtkWidget, is_active: c_int) void;
pub extern "c" fn gtk_switch_get_active(sw: ?*GtkWidget) c_int;
pub extern "c" fn gtk_widget_add_css_class(widget: ?*GtkWidget, css_class: [*:0]const u8) void;
pub extern "c" fn gtk_widget_remove_css_class(widget: ?*GtkWidget, css_class: [*:0]const u8) void;

pub extern "c" fn gdk_display_get_default() ?*GdkDisplay;
pub extern "c" fn gtk_css_provider_new() ?*GtkCssProvider;
pub extern "c" fn gtk_css_provider_load_from_string(provider: ?*GtkCssProvider, string: [*:0]const u8) void;
pub extern "c" fn gtk_style_context_add_provider_for_display(display: ?*GdkDisplay, provider: ?*GtkStyleProvider, priority: c_uint) void;

pub extern "c" fn g_signal_connect_data(instance: ?*anyopaque, detailed_signal: [*:0]const u8, c_handler: ?*const anyopaque, data: ?*anyopaque, destroy_data: ?*anyopaque, connect_flags: c_uint) c_ulong;
pub extern "c" fn g_timeout_add(interval: c_uint, function: ?*const anyopaque, data: ?*anyopaque) c_uint;
pub extern "c" fn g_application_run(application: ?*GApplication, argc: c_int, argv: ?[*][*:0]u8) c_int;
pub extern "c" fn g_object_unref(object: ?*anyopaque) void;

pub const GuiContext = struct {
    cfg: *config.AppConfig,
    stats: *proxy.TrafficStats,
    sec: *const security.SecurityManager,
    ip_tracker: *router_mod.IpSessionTracker,
    tun_dev: ?*tun.TunDevice = null,
    is_mobile: bool = false,

    // UI 控件引用
    lbl_status: ?*GtkWidget = null,
    lbl_status_desc: ?*GtkWidget = null,
    sw_tun: ?*GtkWidget = null,
    lbl_traffic_up: ?*GtkWidget = null,
    lbl_traffic_down: ?*GtkWidget = null,
    lbl_conns: ?*GtkWidget = null,
    lbl_active_node: ?*GtkWidget = null,
    lbl_current_mode: ?*GtkWidget = null,
    lbl_ip_dispatch: ?*GtkWidget = null,
    lbl_ip_summary: ?*GtkWidget = null,
};

var global_ctx: ?*GuiContext = null;

const MIUIX_CSS =
    \\window {
    \\    background-color: #f4f6f9;
    \\    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
    \\}
    \\.main-container {
    \\    padding: 24px;
    \\}
    \\.miuix-card {
    \\    background-color: #ffffff;
    \\    border-radius: 20px;
    \\    padding: 18px 22px;
    \\    margin: 8px 0px;
    \\    border: 1px solid rgba(0, 0, 0, 0.05);
    \\    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.03);
    \\}
    \\.miuix-header-title {
    \\    font-size: 20px;
    \\    font-weight: 700;
    \\    color: #111111;
    \\}
    \\.miuix-header-subtitle {
    \\    font-size: 13px;
    \\    color: #888888;
    \\    margin-top: 2px;
    \\}
    \\.stat-label {
    \\    font-size: 13px;
    \\    color: #666666;
    \\}
    \\.stat-value {
    \\    font-size: 22px;
    \\    font-weight: 700;
    \\    color: #0084ff;
    \\}
    \\.stat-value-green {
    \\    font-size: 18px;
    \\    font-weight: 700;
    \\    color: #07c160;
    \\}
    \\.stat-value-gray {
    \\    font-size: 18px;
    \\    font-weight: 700;
    \\    color: #8e8e93;
    \\}
    \\.miuix-button {
    \\    background-color: #f0f3f6;
    \\    color: #222222;
    \\    border-radius: 12px;
    \\    padding: 8px 16px;
    \\    font-size: 14px;
    \\    font-weight: 500;
    \\    border: none;
    \\}
    \\.miuix-button:hover {
    \\    background-color: #e4e8ee;
    \\}
    \\.miuix-button-active {
    \\    background-color: #0084ff;
    \\    color: #ffffff;
    \\    border-radius: 12px;
    \\    padding: 8px 16px;
    \\    font-size: 14px;
    \\    font-weight: 600;
    \\    border: none;
    \\}
    \\.node-item {
    \\    background-color: #f8fafc;
    \\    border-radius: 12px;
    \\    padding: 10px 14px;
    \\    margin: 4px 0px;
    \\    border: 1px solid #edf2f7;
    \\}
    \\.ip-dispatch-box {
    \\    background-color: #f0f7ff;
    \\    border: 1px solid #cce4ff;
    \\    border-radius: 12px;
    \\    padding: 12px 14px;
    \\    color: #0066cc;
    \\    font-size: 13px;
    \\    font-weight: 500;
    \\}
;

fn applyMiuixTheme() void {
    const display = gdk_display_get_default() orelse return;
    const provider = gtk_css_provider_new() orelse return;
    defer g_object_unref(provider);

    gtk_css_provider_load_from_string(provider, MIUIX_CSS);
    gtk_style_context_add_provider_for_display(display, @ptrCast(provider), 600);
}

fn printZ(buf: []u8, comptime fmt_str: []const u8, args: anytype) [*:0]const u8 {
    const s = std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt_str, args) catch return "";
    buf[s.len] = 0;
    return @ptrCast(buf.ptr);
}

fn formatBytes(bytes: u64, buf: []u8) []const u8 {
    if (bytes < 1024) {
        return std.fmt.bufPrint(buf, "{} B", .{bytes}) catch "--";
    } else if (bytes < 1024 * 1024) {
        const kb = @as(f64, @floatFromInt(bytes)) / 1024.0;
        return std.fmt.bufPrint(buf, "{d:.1} KB", .{kb}) catch "--";
    } else if (bytes < 1024 * 1024 * 1024) {
        const mb = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
        return std.fmt.bufPrint(buf, "{d:.2} MB", .{mb}) catch "--";
    } else {
        const gb = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0 * 1024.0);
        return std.fmt.bufPrint(buf, "{d:.2} GB", .{gb}) catch "--";
    }
}

fn onUpdateTimer(user_data: ?*anyopaque) callconv(.c) c_int {
    _ = user_data;
    const ctx = global_ctx orelse return 0;

    var buf: [128]u8 = undefined;

    // 1. 更新上传
    const up_bytes = ctx.stats.bytes_uploaded.load(.monotonic);
    const up_fmt = formatBytes(up_bytes, &buf);
    var up_str: [160]u8 = undefined;
    const up_full = printZ(&up_str, "↑ 上传: {s}", .{up_fmt});
    if (ctx.lbl_traffic_up) |lbl| {
        gtk_label_set_text(lbl, up_full);
    }

    // 2. 更新下载
    const down_bytes = ctx.stats.bytes_downloaded.load(.monotonic);
    const down_fmt = formatBytes(down_bytes, &buf);
    var down_str: [160]u8 = undefined;
    const down_full = printZ(&down_str, "↓ 下载: {s}", .{down_fmt});
    if (ctx.lbl_traffic_down) |lbl| {
        gtk_label_set_text(lbl, down_full);
    }

    // 3. 更新活动连接数
    const conns = ctx.stats.active_connections.load(.monotonic);
    var conn_str: [64]u8 = undefined;
    const conn_full = printZ(&conn_str, "⚡ 活动 IP 会话: {}", .{conns});
    if (ctx.lbl_conns) |lbl| {
        gtk_label_set_text(lbl, conn_full);
    }

    // 4. 更新核心功能「分 IP 代理」实时调度动态
    ctx.ip_tracker.lock_state.lock();
    const count = ctx.ip_tracker.count;
    var latest_ip: [32]u8 = undefined;
    var latest_ip_len: usize = 0;
    var latest_node_idx: usize = 0;
    var latest_conns: u32 = 0;
    if (count > 0) {
        const item = ctx.ip_tracker.entries[count - 1];
        latest_ip_len = item.target_ip_len;
        @memcpy(latest_ip[0..latest_ip_len], item.target_ip[0..latest_ip_len]);
        latest_node_idx = item.node_index;
        latest_conns = item.active_conns;
    }
    ctx.ip_tracker.lock_state.unlock();

    if (ctx.lbl_ip_dispatch) |lbl| {
        if (count > 0) {
            const ip_str = latest_ip[0..latest_ip_len];
            const node_name = if (latest_node_idx < ctx.cfg.nodes.items.len)
                ctx.cfg.nodes.items[latest_node_idx].name
            else
                "直连出站";
            var ip_buf: [256]u8 = undefined;
            const full_ip = printZ(
                &ip_buf,
                "🎯 目标 IP: {s}  ➔  哈希出口: [{s}] (并发: {})",
                .{ ip_str, node_name, latest_conns },
            );
            gtk_label_set_text(lbl, full_ip);
        } else {
            gtk_label_set_text(lbl, "🎯 分 IP 代理引擎待命中: 出站流量按目标 IP 一致性哈希分流");
        }
    }

    if (ctx.lbl_ip_summary) |lbl| {
        var sum_buf: [128]u8 = undefined;
        const sum_str = printZ(&sum_buf, "当前跟踪活跃目标 IP 数: {} / 32", .{count});
        gtk_label_set_text(lbl, sum_str);
    }

    return 1;
}

fn onTunSwitchToggled(sw: ?*GtkWidget, _: ?*anyopaque) callconv(.c) void {
    const ctx = global_ctx orelse return;
    const is_active = gtk_switch_get_active(sw) != 0;

    if (ctx.tun_dev) |dev| {
        if (is_active and !dev.is_active) {
            dev.open() catch {
                gtk_switch_set_active(sw, 0);
                return;
            };
            dev.takeoverRoutes();
            if (ctx.lbl_status) |lbl| {
                gtk_label_set_text(lbl, "● TUN 全量接管已生效 (aether0)");
                gtk_widget_remove_css_class(lbl, "stat-value-gray");
                gtk_widget_add_css_class(lbl, "stat-value-green");
            }
            if (ctx.lbl_status_desc) |lbl| {
                gtk_label_set_text(lbl, "所有系统网络流量已被 TUN 虚拟网卡劫持 · 分 IP 代理自动调度");
            }
        } else if (!is_active and dev.is_active) {
            dev.restoreRoutes();
            if (ctx.lbl_status) |lbl| {
                gtk_label_set_text(lbl, "○ TUN 接管已暂停 (物理网络直连)");
                gtk_widget_remove_css_class(lbl, "stat-value-green");
                gtk_widget_add_css_class(lbl, "stat-value-gray");
            }
            if (ctx.lbl_status_desc) |lbl| {
                gtk_label_set_text(lbl, "流量恢复物理网卡直连 · 待命状态");
            }
        }
    }
}

fn onModeBtnClicked(_: ?*GtkWidget, user_data: ?*anyopaque) callconv(.c) void {
    const ctx = global_ctx orelse return;
    const mode_val: usize = @intCast(@intFromPtr(user_data));
    ctx.cfg.mode = switch (mode_val) {
        1 => .global,
        2 => .direct,
        else => .rule,
    };
    if (ctx.lbl_current_mode) |lbl| {
        const mode_name = switch (ctx.cfg.mode) {
            .rule => "当前分流: 智能按 IP 分流 (Rule)",
            .global => "当前分流: 全局代理 (Global)",
            .direct => "当前分流: 全局直连 (Direct)",
        };
        gtk_label_set_text(lbl, mode_name);
    }
}

fn onNodeSelectClicked(_: ?*GtkWidget, user_data: ?*anyopaque) callconv(.c) void {
    const ctx = global_ctx orelse return;
    const node_idx: usize = @intCast(@intFromPtr(user_data));
    if (node_idx < ctx.cfg.nodes.items.len) {
        ctx.cfg.active_node_index = node_idx;
        if (ctx.lbl_active_node) |lbl| {
            var buf: [128]u8 = undefined;
            const full = printZ(&buf, "默认出口节点: {s}", .{ctx.cfg.nodes.items[node_idx].name});
            gtk_label_set_text(lbl, full);
        }
    }
}

fn onWindowCloseRequest(_: ?*GtkWidget, _: ?*anyopaque) callconv(.c) c_int {
    const ctx = global_ctx orelse return 0;
    if (ctx.tun_dev) |dev| {
        dev.restoreRoutes();
    }
    return 0;
}

fn onAppActivate(app: ?*GtkApplication, _: ?*anyopaque) callconv(.c) void {
    applyMiuixTheme();

    const window = gtk_application_window_new(app);
    _ = g_signal_connect_data(window, "close-request", @ptrCast(&onWindowCloseRequest), null, null, 0);

    if (global_ctx) |ctx| {
        if (ctx.is_mobile) {
            gtk_window_set_title(window, "AetherCore 手机版 (MIUIX 竖屏 390×820)");
            gtk_window_set_default_size(window, 390, 820);
        } else {
            gtk_window_set_title(window, "AetherCore - TUN 全量网络核心与分 IP 代理");
            gtk_window_set_default_size(window, 820, 680);
        }
    } else {
        gtk_window_set_title(window, "AetherCore - TUN 全量网络核心与分 IP 代理");
        gtk_window_set_default_size(window, 820, 680);
    }

    const root_box = gtk_box_new(1, 14); // GTK_ORIENTATION_VERTICAL = 1
    gtk_widget_add_css_class(root_box, "main-container");

    // 1. 顶部 Header
    const header_box = gtk_box_new(0, 10);
    const title_box = gtk_box_new(1, 2);
    const lbl_title = gtk_label_new("AetherCore");
    gtk_widget_add_css_class(lbl_title, "miuix-header-title");
    const lbl_subtitle = gtk_label_new("TUN 全网接管模式 · 分 IP 代理引擎 · 原生点阵物理呈现");
    gtk_widget_add_css_class(lbl_subtitle, "miuix-header-subtitle");
    gtk_box_append(title_box, lbl_title);
    gtk_box_append(title_box, lbl_subtitle);
    gtk_box_append(header_box, title_box);
    gtk_box_append(root_box, header_box);

    // 2. TUN 网络接管总开关卡片 (彻底移除端口概念，纯 TUN 劫持)
    const status_card = gtk_box_new(0, 16);
    gtk_widget_add_css_class(status_card, "miuix-card");

    const status_left = gtk_box_new(1, 4);
    const lbl_status_title = gtk_label_new("TUN 虚拟网卡状态 (aether0)");
    gtk_widget_add_css_class(lbl_status_title, "stat-label");

    const is_active_now = if (global_ctx) |ctx| (if (ctx.tun_dev) |d| d.is_active else false) else false;

    const lbl_status_val = gtk_label_new(if (is_active_now)
        "● TUN 全量接管已生效 (aether0)"
    else
        "○ TUN 接管已暂停 (物理网络直连)");
    gtk_widget_add_css_class(lbl_status_val, if (is_active_now) "stat-value-green" else "stat-value-gray");

    const lbl_status_sub = gtk_label_new(if (is_active_now)
        "所有出站流量自动由 TUN 虚拟网卡捕获，无需为系统或应用配置端口"
    else
        "流量恢复物理网卡直连 · 待命状态");
    gtk_widget_add_css_class(lbl_status_sub, "miuix-header-subtitle");

    gtk_box_append(status_left, lbl_status_title);
    gtk_box_append(status_left, lbl_status_val);
    gtk_box_append(status_left, lbl_status_sub);

    const sw = gtk_switch_new();
    gtk_switch_set_active(sw, if (is_active_now) 1 else 0);
    _ = g_signal_connect_data(sw, "state-set", @ptrCast(&onTunSwitchToggled), null, null, 0);

    gtk_box_append(status_card, status_left);
    gtk_box_append(status_card, sw);
    gtk_box_append(root_box, status_card);

    if (global_ctx) |ctx| {
        ctx.lbl_status = lbl_status_val;
        ctx.lbl_status_desc = lbl_status_sub;
        ctx.sw_tun = sw;
    }

    // 3. 核心功能「分 IP 代理」监控卡片 (Per-IP Consistent Hash Engine)
    const ip_card = gtk_box_new(1, 10);
    gtk_widget_add_css_class(ip_card, "miuix-card");

    const ip_header_box = gtk_box_new(0, 8);
    const lbl_ip_header = gtk_label_new("核心功能: 分 IP 代理引擎 (Per-IP Proxy)");
    gtk_widget_add_css_class(lbl_ip_header, "miuix-header-title");
    gtk_box_append(ip_header_box, lbl_ip_header);

    const lbl_ip_summary = gtk_label_new("当前跟踪活跃目标 IP 数: 0 / 32");
    gtk_widget_add_css_class(lbl_ip_summary, "stat-label");
    gtk_box_append(ip_header_box, lbl_ip_summary);
    gtk_box_append(ip_card, ip_header_box);

    const lbl_ip_details = gtk_label_new("🎯 分 IP 代理引擎待命中: 出站流量按目标 IP 一致性哈希分流");
    gtk_widget_add_css_class(lbl_ip_details, "ip-dispatch-box");
    gtk_box_append(ip_card, lbl_ip_details);

    if (global_ctx) |ctx| {
        ctx.lbl_ip_dispatch = lbl_ip_details;
        ctx.lbl_ip_summary = lbl_ip_summary;
    }
    gtk_box_append(root_box, ip_card);

    // 4. 实时流量仪表卡片 (Traffic Stats Card)
    const traffic_card = gtk_box_new(0, 32);
    gtk_widget_add_css_class(traffic_card, "miuix-card");

    const up_box = gtk_box_new(1, 2);
    const lbl_up = gtk_label_new("↑ 上传: 0 B");
    gtk_widget_add_css_class(lbl_up, "stat-value");
    gtk_box_append(up_box, lbl_up);

    const down_box = gtk_box_new(1, 2);
    const lbl_down = gtk_label_new("↓ 下载: 0 B");
    gtk_widget_add_css_class(lbl_down, "stat-value");
    gtk_box_append(down_box, lbl_down);

    const conn_box = gtk_box_new(1, 2);
    const lbl_conn = gtk_label_new("⚡ 活动 IP 会话: 0");
    gtk_widget_add_css_class(lbl_conn, "stat-value");
    gtk_box_append(conn_box, lbl_conn);

    gtk_box_append(traffic_card, up_box);
    gtk_box_append(traffic_card, down_box);
    gtk_box_append(traffic_card, conn_box);
    gtk_box_append(root_box, traffic_card);

    if (global_ctx) |ctx| {
        ctx.lbl_traffic_up = lbl_up;
        ctx.lbl_traffic_down = lbl_down;
        ctx.lbl_conns = lbl_conn;
    }

    // 5. 分流模式选择卡片 (Routing Mode Card)
    const mode_card = gtk_box_new(1, 10);
    gtk_widget_add_css_class(mode_card, "miuix-card");

    const lbl_mode_header = gtk_label_new("分流模式");
    gtk_widget_add_css_class(lbl_mode_header, "stat-label");
    gtk_box_append(mode_card, lbl_mode_header);

    const mode_btn_box = gtk_box_new(0, 10);
    const btn_rule = gtk_button_new_with_label("智能按 IP 分流 (Rule)");
    gtk_widget_add_css_class(btn_rule, "miuix-button-active");
    _ = g_signal_connect_data(btn_rule, "clicked", @ptrCast(&onModeBtnClicked), @ptrFromInt(0), null, 0);

    const btn_global = gtk_button_new_with_label("全局代理 (Global)");
    gtk_widget_add_css_class(btn_global, "miuix-button");
    _ = g_signal_connect_data(btn_global, "clicked", @ptrCast(&onModeBtnClicked), @ptrFromInt(1), null, 0);

    const btn_direct = gtk_button_new_with_label("全局直连 (Direct)");
    gtk_widget_add_css_class(btn_direct, "miuix-button");
    _ = g_signal_connect_data(btn_direct, "clicked", @ptrCast(&onModeBtnClicked), @ptrFromInt(2), null, 0);

    gtk_box_append(mode_btn_box, btn_rule);
    gtk_box_append(mode_btn_box, btn_global);
    gtk_box_append(mode_btn_box, btn_direct);

    const lbl_cur_mode = gtk_label_new("当前分流: 智能按 IP 分流 (Rule)");
    gtk_widget_add_css_class(lbl_cur_mode, "miuix-header-subtitle");
    if (global_ctx) |ctx| {
        ctx.lbl_current_mode = lbl_cur_mode;
    }

    gtk_box_append(mode_card, mode_btn_box);
    gtk_box_append(mode_card, lbl_cur_mode);
    gtk_box_append(root_box, mode_card);

    // 6. 出站代理节点选择卡片 (Node Card)
    const node_card = gtk_box_new(1, 8);
    gtk_widget_add_css_class(node_card, "miuix-card");

    const lbl_node_header = gtk_label_new("出站节点列表 (支持按 IP 分散到不同出口)");
    gtk_widget_add_css_class(lbl_node_header, "stat-label");
    gtk_box_append(node_card, lbl_node_header);

    if (global_ctx) |ctx| {
        for (ctx.cfg.nodes.items, 0..) |n, i| {
            var node_buf: [128]u8 = undefined;
            const node_title = printZ(&node_buf, "{s} ({s}) - {}ms", .{
                n.name,
                n.server,
                n.latency_ms,
            });

            const btn_node = gtk_button_new_with_label(node_title);
            gtk_widget_add_css_class(btn_node, "node-item");
            _ = g_signal_connect_data(btn_node, "clicked", @ptrCast(&onNodeSelectClicked), @ptrFromInt(i), null, 0);
            gtk_box_append(node_card, btn_node);
        }

        const lbl_active_n = gtk_label_new("默认出口节点: 香港专线 01 (VLESS-XTLS)");
        gtk_widget_add_css_class(lbl_active_n, "miuix-header-subtitle");
        ctx.lbl_active_node = lbl_active_n;
        gtk_box_append(node_card, lbl_active_n);
    }
    gtk_box_append(root_box, node_card);

    // 启动定时刷新器 (每 500ms 刷新一次)
    _ = g_timeout_add(500, @ptrCast(&onUpdateTimer), null);

    gtk_window_set_child(window, root_box);
    gtk_window_present(window);
}

pub fn runGui(ctx: *GuiContext) !void {
    global_ctx = ctx;

    const app = gtk_application_new("com.aethercore.gui", 0);
    if (app == null) return error.GtkAppInitFailed;
    defer g_object_unref(app);

    _ = g_signal_connect_data(app, "activate", @ptrCast(&onAppActivate), null, null, 0);

    const status = g_application_run(@ptrCast(app), 0, null);
    _ = status;
}
