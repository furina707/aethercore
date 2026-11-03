//! TUN 接管层统一模块（融合 wintun, wintun_tun, wintun_netcfg, tun_linux, tun_route, tun_runner, tun_glue）
const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");
const router = @import("router.zig");
const proxy = @import("proxy.zig");
const tcp_stack = @import("tcp_stack.zig");
const dns = @import("dns.zig");
const main = @import("main.zig");

pub const wintun = if (builtin.os.tag == .windows) struct {
    // Wintun 动态绑定（Windows 11 的 TUN 实现）。
    //
    // **为什么动态加载而不是静态链接**：
    // `wintun.dll` 是要随程序分发的第三方二进制（WireGuard LLC，MIT），
    // 不能假设目标机器上已安装。用 `LoadLibrary/GetProcAddress` 加载，
    // 既能随包分发，也能在缺 DLL 时给出「缺文件」而不是「启动即崩」。
    //
    // **能力边界**：本文件只负责「拿到 wintun 的 11 个函数并安全调用」。
    // 网卡配置（IP/路由/DNS）在 `wintun_netcfg.zig`，数据面在 `wintun_tun.zig`。
    //
    // API 参考：https://git.zx2c4.com/wintun/tree/api/wintun.h

    const windows = std.os.windows;

    pub const is_windows = builtin.os.tag == .windows;

    // ============================================================================
    // wintun 的类型定义（按官方 wintun.h）
    // ============================================================================

    pub const AdapterHandle = *anyopaque;
    pub const SessionHandle = *anyopaque;

    /// `WINTUN_ADAPTER_HANDLE` 在官方头文件里是带名字的结构体指针
    pub const Guid = extern struct {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [8]u8,
    };

    /// 日志回调级别
    pub const LoggerLevel = enum(u32) {
        info = 0,
        warn = 1,
        err = 2,
        _,
    };

    pub const LoggerFn = *const fn (level: LoggerLevel, msg: [*:0]const u16) callconv(.winapi) void;

    /// ring buffer 容量：官方建议 0x400000（4MiB）用于高吞吐
    pub const ring_capacity: u32 = 0x400000;

    // ============================================================================
    // 函数指针类型
    // ============================================================================

    const FnCreateAdapter = *const fn (
        name: [*:0]const u16,
        tunnel_type: [*:0]const u16,
        requested_guid: ?*const Guid,
    ) callconv(.winapi) ?AdapterHandle;

    const FnOpenAdapter = *const fn (name: [*:0]const u16) callconv(.winapi) ?AdapterHandle;

    const FnCloseAdapter = *const fn (adapter: AdapterHandle) callconv(.winapi) void;

    const FnStartSession = *const fn (
        adapter: AdapterHandle,
        capacity: u32,
    ) callconv(.winapi) ?SessionHandle;

    const FnEndSession = *const fn (session: SessionHandle) callconv(.winapi) void;

    const FnReceivePacket = *const fn (
        session: SessionHandle,
        packet_size: *u32,
    ) callconv(.winapi) ?[*]u8;

    const FnReleaseReceivePacket = *const fn (
        session: SessionHandle,
        packet: [*]const u8,
    ) callconv(.winapi) void;

    const FnAllocateSendPacket = *const fn (
        session: SessionHandle,
        packet_size: u32,
    ) callconv(.winapi) ?[*]u8;

    const FnSendPacket = *const fn (
        session: SessionHandle,
        packet: [*]const u8,
    ) callconv(.winapi) void;

    const FnGetVersion = *const fn () callconv(.winapi) u32;

    const FnSetLogger = *const fn (logger: ?LoggerFn) callconv(.winapi) void;

    /// 读等待事件句柄。`WintunReceivePacket` 在没有数据时立刻返回 NULL
    /// 并置 `ERROR_NO_MORE_ITEMS` —— 不加等待的话调用方只能忙轮询，
    /// 一个 TUN 线程能把一个核吃满。
    const FnGetReadWaitEvent = *const fn (session: SessionHandle) callconv(.winapi) ?windows.HANDLE;

    // ============================================================================
    // 加载器
    // ============================================================================

    pub const LoadError = error{
        DllNotFound,
        SymbolMissing,
        UnsupportedPlatform,
    };

    const win_k32 = struct {
        extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?windows.HMODULE;
        extern "kernel32" fn GetProcAddress(hModule: windows.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
        extern "kernel32" fn FreeLibrary(hLibModule: windows.HMODULE) callconv(.winapi) windows.BOOL;
        extern "kernel32" fn GetModuleFileNameW(hModule: ?windows.HMODULE, lpFilename: [*]u16, nSize: u32) callconv(.winapi) u32;
    };

    pub const DynLib = struct {
        handle: windows.HMODULE,

        pub fn open(path: []const u8) !DynLib {
            var wbuf: [512]u16 = undefined;
            const len = std.unicode.utf8ToUtf16Le(&wbuf, path) catch return error.FileNotFound;
            wbuf[len] = 0;
            const h = win_k32.LoadLibraryW(@ptrCast(&wbuf)) orelse return error.FileNotFound;
            return .{ .handle = h };
        }

        pub fn lookup(self: DynLib, comptime T: type, name: [*:0]const u8) ?T {
            const proc = win_k32.GetProcAddress(self.handle, name) orelse return null;
            return @ptrCast(proc);
        }

        pub fn close(self: *DynLib) void {
            _ = win_k32.FreeLibrary(self.handle);
        }
    };

    fn getExeDir(buf: []u8) ?[]const u8 {
        var wbuf: [512]u16 = undefined;
        const len = win_k32.GetModuleFileNameW(null, &wbuf, wbuf.len);
        if (len == 0 or len >= wbuf.len) return null;
        const utf8_len = std.unicode.utf16LeToUtf8(buf, wbuf[0..len]) catch return null;
        const full = buf[0..utf8_len];
        if (std.mem.lastIndexOfScalar(u8, full, '\\')) |slash| {
            return full[0..slash];
        }
        return null;
    }

    pub const Wintun = struct {
        lib: DynLib,

        create_adapter: FnCreateAdapter,
        open_adapter: FnOpenAdapter,
        close_adapter: FnCloseAdapter,
        start_session: FnStartSession,
        end_session: FnEndSession,
        receive_packet: FnReceivePacket,
        release_receive_packet: FnReleaseReceivePacket,
        allocate_send_packet: FnAllocateSendPacket,
        send_packet: FnSendPacket,
        get_version: FnGetVersion,
        set_logger: FnSetLogger,
        get_read_wait_event: FnGetReadWaitEvent,

        /// 当前进程架构对应的子目录名。
        ///
        /// 官方 zip 按 `bin/{amd64,x86,arm64,arm}/wintun.dll` 组织，
        /// 分发时保持同样结构，加载器就能自动挑对架构 ——
        /// 混用架构的 DLL 会让 LoadLibrary 直接失败（错误码 193）。
        pub fn archDir() []const u8 {
            return switch (builtin.cpu.arch) {
                .x86_64 => "amd64",
                .x86 => "x86",
                .aarch64 => "arm64",
                .arm, .armeb, .thumb => "arm",
                else => "amd64",
            };
        }

        /// 加载 wintun.dll。
        ///
        /// 搜索顺序（先具体后通用）：
        ///   1. `<exe目录>\wintun\<arch>\wintun.dll` —— 随包分发的多架构布局
        ///   2. `<exe目录>\wintun.dll`               —— 放在 exe 同目录
        ///   3. `wintun\<arch>\wintun.dll`（CWD）    —— 从源码目录直接跑
        ///   4. `wintun.dll`（CWD）
        ///   5. 系统目录                              —— 已安装的驱动
        ///
        /// **必须以 exe 所在目录为基准**。之前只用相对路径，
        /// `LoadLibrary` 按当前工作目录解析 —— 用户从「开始菜单」或
        /// 别的目录启动时 CWD 不是 exe 目录，DLL 明明就在旁边却报
        /// `DllNotFound`，然后 `pick()` 判定无可用后端，接管静默失效。
        pub fn load() LoadError!Wintun {
            if (!is_windows) return error.UnsupportedPlatform;

            // exe 所在目录（失败则退化为 CWD）
            var exe_dir_buf: [512]u8 = undefined;
            const exe_dir: ?[]const u8 = getExeDir(&exe_dir_buf);

            var lib: ?DynLib = null;

            // 1) / 2) exe 目录优先
            if (exe_dir) |dir| {
                var path_buf: [512]u8 = undefined;
                const arch_path = std.fmt.bufPrint(
                    &path_buf,
                    "{s}\\wintun\\{s}\\wintun.dll",
                    .{ dir, archDir() },
                ) catch "";
                if (arch_path.len > 0) {
                    lib = DynLib.open(arch_path) catch null;
                }
                if (lib == null) {
                    const flat = std.fmt.bufPrint(&path_buf, "{s}\\wintun.dll", .{dir}) catch "";
                    if (flat.len > 0) lib = DynLib.open(flat) catch null;
                }
            }

            // 3) / 4) CWD 兜底（便于在源码目录直接 `zig build run`）
            if (lib == null) {
                var path_buf: [128]u8 = undefined;
                const arch_path = std.fmt.bufPrint(
                    &path_buf,
                    "wintun\\{s}\\wintun.dll",
                    .{archDir()},
                ) catch "wintun.dll";
                lib = DynLib.open(arch_path) catch null;
                if (lib == null) lib = DynLib.open("wintun.dll") catch null;
            }

            // 5) 系统目录
            if (lib == null) {
                lib = DynLib.open("C:\\Windows\\System32\\wintun.dll") catch null;
            }

            var l = lib orelse return error.DllNotFound;

            return .{
                .lib = l,
                .create_adapter = l.lookup(FnCreateAdapter, "WintunCreateAdapter") orelse return error.SymbolMissing,
                .open_adapter = l.lookup(FnOpenAdapter, "WintunOpenAdapter") orelse return error.SymbolMissing,
                .close_adapter = l.lookup(FnCloseAdapter, "WintunCloseAdapter") orelse return error.SymbolMissing,
                .start_session = l.lookup(FnStartSession, "WintunStartSession") orelse return error.SymbolMissing,
                .end_session = l.lookup(FnEndSession, "WintunEndSession") orelse return error.SymbolMissing,
                .receive_packet = l.lookup(FnReceivePacket, "WintunReceivePacket") orelse return error.SymbolMissing,
                .release_receive_packet = l.lookup(FnReleaseReceivePacket, "WintunReleaseReceivePacket") orelse return error.SymbolMissing,
                .allocate_send_packet = l.lookup(FnAllocateSendPacket, "WintunAllocateSendPacket") orelse return error.SymbolMissing,
                .send_packet = l.lookup(FnSendPacket, "WintunSendPacket") orelse return error.SymbolMissing,
                .get_version = l.lookup(FnGetVersion, "WintunGetRunningDriverVersion") orelse return error.SymbolMissing,
                .set_logger = l.lookup(FnSetLogger, "WintunSetLogger") orelse return error.SymbolMissing,
                .get_read_wait_event = l.lookup(FnGetReadWaitEvent, "WintunGetReadWaitEvent") orelse return error.SymbolMissing,
            };
        }

        pub fn deinit(self: *Wintun) void {
            self.lib.close();
        }

        /// DLL 版本号（形如 0x000e0001 = 0.14.1）
        pub fn version(self: *Wintun) u32 {
            return self.get_version();
        }

        /// 已安装驱动的版本。
        ///
        /// 注意：`WintunGetRunningDriverVersion` 读的是**已加载的驱动**，
        /// 驱动尚未安装/加载时返回值不可靠（实测未装驱动时拿到 0xE）。
        /// 因此这里只做「是否已装驱动」的判断依据，不要当成 DLL 版本。
        pub fn versionString(self: *Wintun, buf: []u8) []const u8 {
            const v = self.version();
            if (v == 0) return "driver-not-loaded";
            return std.fmt.bufPrint(buf, "0x{X}", .{v}) catch "?";
        }
    };

    // ============================================================================
    // UTF-8 → UTF-16（wintun 所有字符串参数都是宽字符）
    // ============================================================================

    /// 把 UTF-8 转成以 NUL 结尾的 UTF-16，写入调用方缓冲。
    /// 返回切片（不含结尾 NUL）。
    pub fn toWide(buf: []u16, s: []const u8) ![:0]const u16 {
        if (buf.len < s.len + 1) return error.BufferTooSmall;
        const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], s) catch return error.InvalidUtf8;
        buf[n] = 0;
        return buf[0..n :0];
    }

    // ============================ 测试 ============================







} else struct {
    pub const Wintun = struct {
        pub fn load() error{DllNotFound}!Wintun { return error.DllNotFound; }
        pub fn deinit(_: *Wintun) void {}
    };
};

pub const wintun_tun = if (builtin.os.tag == .windows) struct {
    const wintun_mod = wintun;
    // Windows TUN 设备（Wintun）：建网卡 + ring buffer 收发。
    //
    // 数据面**复用** `tun_runner.Runner`，所以 TCP 状态机、连接表、
    // ICMP 代答这些逻辑与 Linux 完全一致，只有「怎么读写包」不同：
    //
    //   Linux : read(fd) / write(fd)
    //   Windows: WintunReceivePacket / WintunAllocateSendPacket + WintunSendPacket
    //
    // **ReceivePacket 是阻塞的**（内部的 ring buffer 会等待），
    // 没有数据时返回 NULL 且 `GetLastError() == ERROR_NO_MORE_ITEMS`。
    // 所以读取循环必须自己处理这个返回值，不能当成错误。

    const windows = std.os.windows;


    const is_windows = builtin.os.tag == .windows;

    const kernel32 = struct {
        extern "kernel32" fn GetLastError() callconv(.winapi) u32;
        extern "kernel32" fn WaitForSingleObject(hHandle: windows.HANDLE, dwMilliseconds: u32) callconv(.winapi) u32;
    };

    pub const ERROR_NO_MORE_ITEMS: u32 = 259;

    pub const Error = error{
        Unsupported,
        NotElevated,
        DllNotFound,
        AdapterCreateFailed,
        SessionStartFailed,
        ReceiveFailed,
        SendFailed,
    };

    /// 一个已建立的 Wintun 网卡 + 会话
    pub const Device = struct {
        /// 持有 DLL 句柄与函数表（不能被移动，所以必须堆分配）
        api: *wintun.Wintun,
        adapter: wintun.AdapterHandle,
        session: wintun.SessionHandle,
        /// 网卡索引，供 iphlpapi 配地址用
        interface_index: u32,

        pub fn close(self: *Device) void {
            self.api.end_session(self.session);
            self.api.close_adapter(self.adapter);
            self.api.deinit();
        }

        /// 读一个 IP 包。返回 0 表示当前没有包（不代表出错）。
        pub fn readPacket(self: *Device, buf: []u8) Error!usize {
            var size: u32 = 0;
            const pkt = self.api.receive_packet(self.session, &size) orelse {
                const err = kernel32.GetLastError();
                if (err == ERROR_NO_MORE_ITEMS) return 0; // 无数据
                return error.ReceiveFailed;
            };
            defer self.api.release_receive_packet(self.session, pkt);

            if (size > buf.len) return error.ReceiveFailed;
            @memcpy(buf[0..size], pkt[0..size]);
            return size;
        }

        /// 阻塞等待「有包可读」或超时（毫秒）。
        ///
        /// 不用这个的话，`readPacket` 立刻返回 0，主循环只能 `continue` 空转，
        /// 一个核被吃满 —— 而且轮询间隔越短越费电，越长延迟越高，两难。
        pub fn waitForPacket(self: *Device, timeout_ms: u32) void {
            const ev = self.api.get_read_wait_event(self.session) orelse return;
            _ = kernel32.WaitForSingleObject(ev, timeout_ms);
        }

        /// 写一个 IP 包
        pub fn writePacket(self: *Device, pkt: []const u8) Error!void {
            const dst = self.api.allocate_send_packet(self.session, @intCast(pkt.len)) orelse
                return error.SendFailed;
            @memcpy(dst[0..pkt.len], pkt);
            self.api.send_packet(self.session, dst);
        }
    };

    /// 建立 Wintun 网卡并开会话。
    ///
    /// `adapter_name` 同时用作网卡显示名与隧道类型（wintun 要求两者一致才复用同一网卡）。
    pub fn establish(
        alloc: std.mem.Allocator,
        adapter_name: []const u8,
        interface_index: u32,
    ) Error!*Device {
        if (!is_windows) return error.Unsupported;

        // 1) 加载 DLL
        const api = alloc.create(wintun.Wintun) catch return error.DllNotFound;
        errdefer alloc.destroy(api);
        api.* = wintun.Wintun.load() catch return error.DllNotFound;

        // 2) 名字转宽字符
        var name_buf: [256]u16 = undefined;
        const wide_name = wintun.toWide(&name_buf, adapter_name) catch return error.AdapterCreateFailed;

        // 3) 创建（或复用）网卡
        const adapter = api.create_adapter(wide_name, wide_name, null) orelse {
            api.deinit();
            return error.AdapterCreateFailed;
        };
        errdefer api.close_adapter(adapter);

        // 4) 开会话（4MiB ring buffer）
        const session = api.start_session(adapter, wintun.ring_capacity) orelse {
            api.close_adapter(adapter);
            api.deinit();
            return error.SessionStartFailed;
        };

        const dev = alloc.create(Device) catch {
            api.end_session(session);
            api.close_adapter(adapter);
            api.deinit();
            return error.AdapterCreateFailed;
        };
        dev.* = .{
            .api = api,
            .adapter = adapter,
            .session = session,
            .interface_index = interface_index,
        };
        return dev;
    }

    pub fn destroy(dev: *Device, alloc: std.mem.Allocator) void {
        dev.close();
        alloc.destroy(dev);
    }

    // ============================ 测试 ============================



} else struct {
    pub const Device = struct {
        pub fn close(_: *Device) void {}
        pub fn readPacket(_: *Device, _: []u8) error{Unsupported}!usize { return error.Unsupported; }
        pub fn waitForPacket(_: *Device, _: u32) void {}
        pub fn writePacket(_: *Device, _: []const u8) error{Unsupported}!void { return error.Unsupported; }
    };
    pub fn establish(_: std.mem.Allocator, _: []const u8, _: u32) error{Unsupported}!*Device { return error.Unsupported; }
    pub fn destroy(_: *Device, _: std.mem.Allocator) void {}
};

pub const wintun_netcfg = if (builtin.os.tag == .windows) struct {
    // Windows 网卡/路由/DNS 配置 + 提权检查。
    //
    // Zig 标准库没有封装 `OpenProcessToken` / `CreateUnicastIpAddressEntry` /
    // `SetInterfaceDnsSettings`，这里自行声明。
    //
    // **三条铁律**（都是踩过的坑）：
    // 1. 所有操作都要管理员权限 —— 先检查再动手，别等 API 报 ACCESS_DENIED
    // 2. 防环路：改默认路由**之前**先给节点 IP 加物理网卡 /32 路由
    // 3. 任何一步失败都要回滚，否则会留下「路由指向不存在网卡 = 整机断网」

    const windows = std.os.windows;

    pub const is_windows = builtin.os.tag == .windows;

    // ============================================================================
    // 提权检查
    // ============================================================================

    const TOKEN_QUERY: u32 = 0x0008;
    const TokenElevation: u32 = 20;

    const TOKEN_ELEVATION = extern struct {
        TokenIsElevated: u32,
    };

    extern "advapi32" fn OpenProcessToken(
        ProcessHandle: windows.HANDLE,
        DesiredAccess: u32,
        TokenHandle: *windows.HANDLE,
    ) callconv(.winapi) windows.BOOL;

    extern "advapi32" fn GetTokenInformation(
        TokenHandle: windows.HANDLE,
        TokenInformationClass: u32,
        TokenInformation: ?*anyopaque,
        TokenInformationLength: u32,
        ReturnLength: *u32,
    ) callconv(.winapi) windows.BOOL;

    extern "kernel32" fn GetCurrentProcess() callconv(.winapi) windows.HANDLE;
    extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(.winapi) windows.BOOL;

    /// 当前进程是否以管理员身份运行。
    ///
    /// 这是 TUN 接管的**硬前提**：创建网卡、改路由、改 DNS 都需要它。
    pub fn isElevated() bool {
        if (!is_windows) return false;

        var token: windows.HANDLE = undefined;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == .FALSE) return false;
        defer _ = CloseHandle(token);

        var elevation = TOKEN_ELEVATION{ .TokenIsElevated = 0 };
        var ret_len: u32 = 0;
        const ok = GetTokenInformation(
            token,
            TokenElevation,
            @ptrCast(&elevation),
            @sizeOf(TOKEN_ELEVATION),
            &ret_len,
        );
        if (ok == .FALSE) return false;
        return elevation.TokenIsElevated != 0;
    }

    // ============================================================================
    // 网卡 IP 配置（iphlpapi）
    // ============================================================================

    /// `MIB_UNICASTIPADDRESS_ROW` 的必要前缀。
    /// 官方结构体很大（含 SOCKADDR_INET 等），我们只填需要的字段，
    /// 用 `@sizeOf` 保证缓冲区够大，其余清零即可。
    const MAX_ADAPTER_NAME = 128;

    const SOCKADDR_IN = extern struct {
        family: u16,
        port: u16,
        addr: u32,
        zero: [8]u8,
    };

    const SOCKADDR_INET = extern union {
        ipv4: SOCKADDR_IN,
        ipv6: [28]u8,
    };

    /// `MIB_UNICASTIPADDRESS_ROW` 的紧凑布局（仅用到的字段 + 保留区）
    const MIB_UNICASTIPADDRESS_ROW = extern struct {
        Address: SOCKADDR_INET,
        InterfaceLuid: u64,
        InterfaceIndex: u32,
        PrefixOrigin: u32,
        SuffixOrigin: u32,
        ValidLifetime: u32,
        PreferredLifetime: u32,
        OnLinkPrefixLength: u8,
        SkipAsSource: u8,
        DadState: u32,
        ScopeId: u32,
        CreationTimeStamp: i64,
    };

    extern "iphlpapi" fn CreateUnicastIpAddressEntry(
        Row: *const MIB_UNICASTIPADDRESS_ROW,
    ) callconv(.winapi) u32;

    extern "iphlpapi" fn InitializeUnicastIpAddressEntry(
        Row: *MIB_UNICASTIPADDRESS_ROW,
    ) callconv(.winapi) u32;

    pub const NetError = error{
        NotElevated,
        Unsupported,
        AddressFailed,
        InvalidArgument,
        InterfaceNotFound,
        MtuFailed,
    };

    /// 按网卡名查接口索引。
    ///
    /// WintunCreateAdapter 只返回 adapter 句柄，**不返回 ifIndex**，
    /// 而 `route add ... if <idx>`、`CreateUnicastIpAddressEntry`、
    /// `netsh interface ip set dns` 都需要它。这里用 PowerShell 查一次，
    /// 而不是去啃 GetAdaptersAddresses 的变长结构 —— 后者代码量三倍，
    /// 且要处理 alias 编码，收益不明显。
    pub fn findInterfaceIndex(alloc: std.mem.Allocator, name: []const u8) NetError!u32 {
        if (!is_windows) return error.Unsupported;

        const script = std.fmt.allocPrint(
            alloc,
            "(Get-NetAdapter -Name '{s}' -ErrorAction Stop).ifIndex",
            .{name},
        ) catch return error.InterfaceNotFound;
        defer alloc.free(script);

        const out = runCapture(alloc, &.{ "powershell", "-NoProfile", "-Command", script }) catch
            return error.InterfaceNotFound;
        defer alloc.free(out);

        const trimmed = std.mem.trim(u8, out, " \t\r\n");
        if (trimmed.len == 0) return error.InterfaceNotFound;
        return std.fmt.parseInt(u32, trimmed, 10) catch error.InterfaceNotFound;
    }

    /// 设置网卡 MTU（wintun 默认 65535，和我们的 1400 差太多，
    /// 不设的话大包会在 TUN 上被静默丢弃）
    pub fn setInterfaceMtu(index: u32, mtu: u32) NetError!void {
        if (!is_windows) return error.Unsupported;
        if (!isElevated()) return error.NotElevated;

        var idx_buf: [12]u8 = undefined;
        const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{index}) catch return error.MtuFailed;
        var mtu_buf: [12]u8 = undefined;
        const mtu_str = std.fmt.bufPrint(&mtu_buf, "{d}", .{mtu}) catch return error.MtuFailed;

        // 优先用 PowerShell 的 Set-NetIPInterface：`netsh interface ipv4 set subinterface`
        // 的「子接口编号」和 ifIndex 不是一回事，传错了会改到别的网卡上。
        const script = std.fmt.allocPrint(
            std.heap.page_allocator,
            "Set-NetIPInterface -InterfaceIndex {s} -NlMtuBytes {s}",
            .{ idx_str, mtu_str },
        ) catch return error.MtuFailed;
        defer std.heap.page_allocator.free(script);

        runSilent(&.{ "powershell", "-NoProfile", "-Command", script }) catch return error.MtuFailed;
    }

    /// 给指定接口索引设置 IPv4 地址（CIDR 形式 "198.18.0.1/15"）
    pub fn setInterfaceAddress(
        interface_index: u32,
        cidr: []const u8,
    ) NetError!void {
        if (!is_windows) return error.Unsupported;
        if (!isElevated()) return error.NotElevated;

        const parsed = parseCidr(cidr) orelse return error.InvalidArgument;

        var row = std.mem.zeroes(MIB_UNICASTIPADDRESS_ROW);
        _ = InitializeUnicastIpAddressEntry(&row);

        row.InterfaceIndex = interface_index;
        row.Address = .{ .ipv4 = .{
            .family = 2, // AF_INET
            .port = 0,
            .addr = parsed.addr_be,
            .zero = @splat(0),
        } };
        row.OnLinkPrefixLength = parsed.prefix;
        row.PrefixOrigin = 1; // Manual
        row.SuffixOrigin = 1; // Manual
        row.DadState = 4; // DadStatePreferred
        row.ValidLifetime = 0xFFFFFFFF;
        row.PreferredLifetime = 0xFFFFFFFF;

        const rc = CreateUnicastIpAddressEntry(&row);
        // 183 = ERROR_ALREADY_EXISTS，重复设置不算失败
        if (rc != 0 and rc != 183) return error.AddressFailed;
    }

    pub const Cidr4 = struct {
        addr_be: u32,
        prefix: u8,
    };

    pub fn parseCidr(s: []const u8) ?Cidr4 {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return null;
        const prefix = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return null;
        if (prefix > 32) return null;

        var parts: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, s[0..slash], '.');
        var i: usize = 0;
        while (it.next()) |p| {
            if (i >= 4) return null;
            parts[i] = std.fmt.parseInt(u8, p, 10) catch return null;
            i += 1;
        }
        if (i != 4) return null;

        return .{ .addr_be = std.mem.readInt(u32, &parts, .big), .prefix = prefix };
    }

    // ============================================================================
    // 路由与 DNS（走系统命令，稳定且易回滚）
    // ============================================================================

    pub const RouteError = error{
        NotElevated,
        Unsupported,
        CommandFailed,
    } || std.mem.Allocator.Error;

    pub const Config = struct {
        /// TUN 网卡名
        tun_name: []const u8 = "AetherCore",
        /// 物理出口网卡名（为空则自动探测）
        physical_iface: []const u8 = "",
        /// 物理网关
        physical_gateway: []const u8 = "",
        /// 绕过 TUN 的地址（上游节点 IP）
        bypass_hosts: []const []const u8 = &.{},
        /// TUN 网卡的网关地址（netsh 需要）
        tun_gateway: []const u8 = "198.18.0.1",
        /// 是否接管全部流量
        route_all: bool = true,
        /// DNS
        dns: []const u8 = "198.18.0.1",
    };

    /// 路由配置器，记录每一步以便回滚
    pub const Router = struct {
        alloc: std.mem.Allocator,
        cfg: Config,
        applied: std.ArrayList(Step) = .empty,

        pub const Step = union(enum) {
            bypass: []const u8,
            /// 记录 TUN 网卡的接口索引，回滚时精确删除我们加的那条
            default_via_tun: u32,
            dns_changed,
        };

        pub fn init(alloc: std.mem.Allocator, cfg: Config) Router {
            return .{ .alloc = alloc, .cfg = cfg };
        }

        pub fn deinit(self: *Router) void {
            for (self.applied.items) |s| {
                switch (s) {
                    .bypass => |ip| self.alloc.free(ip),
                    else => {},
                }
            }
            self.applied.deinit(self.alloc);
        }

        /// 探测默认路由的出口网卡与网关
        ///
        /// **两个 out 参数返回的是新分配的内存**，调用方负责 free。
        /// 曾经这里直接返回 `runCapture` 的缓冲区切片，而缓冲区在函数返回前
        /// 就被 `defer free` 掉了 —— 调用方拿到的是已释放内存，
        /// 读出来的网关是垃圾值，加出来的路由指向不存在的下一跳。
        pub fn detectPhysical(self: *Router, physical_iface: *[]const u8, physical_gateway: *[]const u8) RouteError!void {
            if (!is_windows) return error.Unsupported;

            const out = try runCapture(self.alloc, &.{ "powershell", "-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop" });
            defer self.alloc.free(out);

            const out2 = try runCapture(self.alloc, &.{ "powershell", "-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias" });
            defer self.alloc.free(out2);

            const gw = std.mem.trim(u8, out, " \t\r\n");
            const iface = std.mem.trim(u8, out2, " \t\r\n");
            if (iface.len == 0 or gw.len == 0) return error.CommandFailed;

            physical_gateway.* = try self.alloc.dupe(u8, gw);
            errdefer self.alloc.free(physical_gateway.*);
            physical_iface.* = try self.alloc.dupe(u8, iface);
        }

        /// 应用接管路由
        pub fn apply(self: *Router) RouteError!void {
            if (!is_windows) return error.Unsupported;
            if (!isElevated()) return error.NotElevated;

            // 0) 网关/网卡没探测过就先探测。
            //    之前这里直接用 cfg.physical_gateway，而 main 从不填它 ——
            //    结果 bypass 路由被加成 `route add 1.2.3.4 mask ... ""`，
            //    命令失败、防环路失效，接管一开就把自己网断掉。
            var gw_buf: []const u8 = self.cfg.physical_gateway;
            var iface_buf: []const u8 = self.cfg.physical_iface;
            var owned_gw: ?[]const u8 = null;
            var owned_iface: ?[]const u8 = null;
            defer if (owned_gw) |g| self.alloc.free(g);
            defer if (owned_iface) |i| self.alloc.free(i);

            if (gw_buf.len == 0 or iface_buf.len == 0) {
                try self.detectPhysical(&iface_buf, &gw_buf);
                owned_gw = gw_buf;
                owned_iface = iface_buf;
            }
            if (gw_buf.len == 0) return error.CommandFailed;

            // 1) 防环路（必须先做）
            for (self.cfg.bypass_hosts) |ip| {
                if (!isIpv4Literal(ip)) continue;
                // route add <ip> mask 255.255.255.255 <物理网关> metric 1
                try runSilent(&.{
                    "route", "add", ip, "mask", "255.255.255.255",
                    gw_buf,           "metric", "1",
                });
                try self.applied.append(self.alloc, .{ .bypass = try self.alloc.dupe(u8, ip) });
            }

            // 2) 默认路由指向 TUN
            if (self.cfg.route_all) {
                // 必须带上 TUN 网卡的接口索引。
                // `if 0` 不是「自动」而是「接口 0」（不存在），命令会失败，
                // 于是默认路由没变、流量根本没进 TUN，而日志却显示接管成功。
                const tun_idx = try self.interfaceIndex(self.cfg.tun_name);
                var idx_buf: [12]u8 = undefined;
                const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{tun_idx}) catch return error.CommandFailed;

                // 先删默认路由再加：Windows 的 route change 对不存在的路由会失败
                runSilent(&.{ "route", "delete", "0.0.0.0", "mask", "0.0.0.0" }) catch {};
                try runSilent(&.{
                    "route",      "add",         "0.0.0.0",
                    "mask",       "0.0.0.0",     self.cfg.tun_gateway,
                    "metric",     "1",           "if",
                    idx_str,
                });
                try self.applied.append(self.alloc, .{ .default_via_tun = tun_idx });
            }

            // 3) DNS：netsh 设到 TUN 网卡
            try runSilent(&.{
                "netsh", "interface", "ip", "set", "dns",
                "name=", self.cfg.tun_name, "static", self.cfg.dns,
            });
            try self.applied.append(self.alloc, .dns_changed);
        }

        /// 取网卡的接口索引（`route add ... if <idx>` 需要）
        fn interfaceIndex(self: *Router, name: []const u8) RouteError!u32 {
            const script = std.fmt.allocPrint(
                self.alloc,
                "(Get-NetAdapter -Name '{s}' -ErrorAction Stop).ifIndex",
                .{name},
            ) catch return error.CommandFailed;
            defer self.alloc.free(script);

            const out = try runCapture(self.alloc, &.{ "powershell", "-NoProfile", "-Command", script });
            defer self.alloc.free(out);
            const trimmed = std.mem.trim(u8, out, " \t\r\n");
            return std.fmt.parseInt(u32, trimmed, 10) catch error.CommandFailed;
        }

        /// 回滚
        pub fn teardown(self: *Router, physical_iface: []const u8, physical_gateway: []const u8) void {
            if (!is_windows) return;
            var i: usize = self.applied.items.len;
            while (i > 0) {
                i -= 1;
                switch (self.applied.items[i]) {
                    .dns_changed => {
                        runSilent(&.{
                            "netsh", "interface", "ip", "set", "dns",
                            "name=", self.cfg.tun_name, "dhcp",
                        }) catch {};
                    },
                    .default_via_tun => |idx| {
                        // 只删我们加的那条（按 ifIndex 限定），
                        // 否则可能顺手删掉用户原有的默认路由
                        var idx_buf: [12]u8 = undefined;
                        const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch return;
                        runSilent(&.{
                            "route", "delete", "0.0.0.0", "mask", "0.0.0.0", "if", idx_str,
                        }) catch {};
                        if (physical_gateway.len > 0) {
                            runSilent(&.{
                                "route", "add", "0.0.0.0", "mask", "0.0.0.0",
                                physical_gateway, "metric", "25",
                            }) catch {};
                        }
                        _ = physical_iface;
                    },
                    .bypass => |ip| {
                        runSilent(&.{ "route", "delete", ip }) catch {};
                    },
                }
            }
        }
    };

    pub fn isIpv4Literal(s: []const u8) bool {
        var dots: usize = 0;
        for (s) |c| {
            if (c == '.') {
                dots += 1;
            } else if (!std.ascii.isDigit(c)) return false;
        }
        return dots == 3;
    }

    fn toWide(buf: []u16, s: []const u8) ![:0]u16 {
        if (buf.len < s.len + 1) return error.BufferTooSmall;
        const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], s) catch return error.InvalidUtf8;
        buf[n] = 0;
        return buf[0..n :0];
    }

    const win_proc = struct {
        const STARTUPINFOW = extern struct {
            cb: u32 = @sizeOf(STARTUPINFOW),
            lpReserved: ?[*:0]u16 = null,
            lpDesktop: ?[*:0]u16 = null,
            lpTitle: ?[*:0]u16 = null,
            dwX: u32 = 0,
            dwY: u32 = 0,
            dwXSize: u32 = 0,
            dwYSize: u32 = 0,
            dwXCountChars: u32 = 0,
            dwYCountChars: u32 = 0,
            dwFillAttribute: u32 = 0,
            dwFlags: u32 = 0,
            wShowWindow: u16 = 0,
            cbReserved2: u16 = 0,
            lpReserved2: ?*u8 = null,
            hStdInput: ?windows.HANDLE = null,
            hStdOutput: ?windows.HANDLE = null,
            hStdError: ?windows.HANDLE = null,
        };

        const PROCESS_INFORMATION = extern struct {
            hProcess: windows.HANDLE = undefined,
            hThread: windows.HANDLE = undefined,
            dwProcessId: u32 = 0,
            dwThreadId: u32 = 0,
        };

        const SECURITY_ATTRIBUTES = extern struct {
            nLength: u32 = @sizeOf(SECURITY_ATTRIBUTES),
            lpSecurityDescriptor: ?*anyopaque = null,
            bInheritHandle: windows.BOOL = .FALSE,
        };

        extern "kernel32" fn CreatePipe(
            hReadPipe: *windows.HANDLE,
            hWritePipe: *windows.HANDLE,
            lpPipeAttributes: ?*const SECURITY_ATTRIBUTES,
            nSize: u32,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn SetHandleInformation(
            hObject: windows.HANDLE,
            dwMask: u32,
            dwFlags: u32,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn CreateProcessW(
            lpApplicationName: ?[*:0]const u16,
            lpCommandLine: [*:0]u16,
            lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
            lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
            bInheritHandles: windows.BOOL,
            dwCreationFlags: u32,
            lpEnvironment: ?*anyopaque,
            lpCurrentDirectory: ?[*:0]const u16,
            lpStartupInfo: *STARTUPINFOW,
            lpProcessInformation: *PROCESS_INFORMATION,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn WaitForSingleObject(
            hHandle: windows.HANDLE,
            dwMilliseconds: u32,
        ) callconv(.winapi) u32;

        extern "kernel32" fn GetExitCodeProcess(
            hProcess: windows.HANDLE,
            lpExitCode: *u32,
        ) callconv(.winapi) windows.BOOL;

        extern "kernel32" fn ReadFile(
            hFile: windows.HANDLE,
            lpBuffer: [*]u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: ?*u32,
            lpOverlapped: ?*anyopaque,
        ) callconv(.winapi) windows.BOOL;
    };

    fn buildCommandLine(buf: []u8, argv: []const []const u8) ![:0]u8 {
        var out_idx: usize = 0;
        for (argv, 0..) |arg, i| {
            if (i > 0) {
                if (out_idx >= buf.len) return error.BufferTooSmall;
                buf[out_idx] = ' ';
                out_idx += 1;
            }
            const has_space = for (arg) |c| {
                if (c == ' ' or c == '\t') break true;
            } else false;

            if (has_space) {
                if (out_idx >= buf.len) return error.BufferTooSmall;
                buf[out_idx] = '"';
                out_idx += 1;
                for (arg) |c| {
                    if (c == '"') {
                        if (out_idx + 2 > buf.len) return error.BufferTooSmall;
                        buf[out_idx] = '\\';
                        buf[out_idx + 1] = '"';
                        out_idx += 2;
                    } else {
                        if (out_idx >= buf.len) return error.BufferTooSmall;
                        buf[out_idx] = c;
                        out_idx += 1;
                    }
                }
                if (out_idx >= buf.len) return error.BufferTooSmall;
                buf[out_idx] = '"';
                out_idx += 1;
            } else {
                if (out_idx + arg.len > buf.len) return error.BufferTooSmall;
                @memcpy(buf[out_idx .. out_idx + arg.len], arg);
                out_idx += arg.len;
            }
        }
        if (out_idx >= buf.len) return error.BufferTooSmall;
        buf[out_idx] = 0;
        return buf[0..out_idx :0];
    }

    fn runCapture(alloc: std.mem.Allocator, argv: []const []const u8) RouteError![]u8 {
        if (!is_windows) return error.Unsupported;
        var cmd_buf: [1024]u8 = undefined;
        const cmd = buildCommandLine(&cmd_buf, argv) catch return error.CommandFailed;
        var wcmd_buf: [1024]u16 = undefined;
        const wcmd = toWide(&wcmd_buf, cmd) catch return error.CommandFailed;

        var sa: win_proc.SECURITY_ATTRIBUTES = .{
            .nLength = @sizeOf(win_proc.SECURITY_ATTRIBUTES),
            .bInheritHandle = .TRUE,
        };
        var hRead: windows.HANDLE = undefined;
        var hWrite: windows.HANDLE = undefined;
        if (win_proc.CreatePipe(&hRead, &hWrite, &sa, 0) == .FALSE) return error.CommandFailed;
        defer _ = CloseHandle(hRead);

        const HANDLE_FLAG_INHERIT: u32 = 1;
        _ = win_proc.SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

        var si: win_proc.STARTUPINFOW = .{};
        si.cb = @sizeOf(win_proc.STARTUPINFOW);
        const STARTF_USESTDHANDLES: u32 = 0x00000100;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;
        var pi: win_proc.PROCESS_INFORMATION = .{};

        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const ok = win_proc.CreateProcessW(
            null,
            wcmd.ptr,
            null,
            null,
            .TRUE,
            CREATE_NO_WINDOW,
            null,
            null,
            &si,
            &pi,
        );
        _ = CloseHandle(hWrite);

        if (ok == .FALSE) return error.CommandFailed;
        defer _ = CloseHandle(pi.hProcess);
        defer _ = CloseHandle(pi.hThread);

        var out_list: std.ArrayList(u8) = .empty;
        defer out_list.deinit(alloc);

        var read_buf: [1024]u8 = undefined;
        while (true) {
            var bytes_read: u32 = 0;
            const read_ok = win_proc.ReadFile(hRead, &read_buf, read_buf.len, &bytes_read, null);
            if (read_ok == .FALSE or bytes_read == 0) break;
            out_list.appendSlice(alloc, read_buf[0..bytes_read]) catch return error.OutOfMemory;
        }

        const INFINITE: u32 = 0xFFFFFFFF;
        _ = win_proc.WaitForSingleObject(pi.hProcess, INFINITE);

        var exit_code: u32 = 0;
        if (win_proc.GetExitCodeProcess(pi.hProcess, &exit_code) == .FALSE) return error.CommandFailed;
        if (exit_code != 0) return error.CommandFailed;

        return out_list.toOwnedSlice(alloc) catch return error.OutOfMemory;
    }

    fn runSilent(argv: []const []const u8) RouteError!void {
        if (!is_windows) return error.Unsupported;
        var cmd_buf: [1024]u8 = undefined;
        const cmd = buildCommandLine(&cmd_buf, argv) catch return error.CommandFailed;
        var wcmd_buf: [1024]u16 = undefined;
        const wcmd = toWide(&wcmd_buf, cmd) catch return error.CommandFailed;

        var si: win_proc.STARTUPINFOW = .{};
        si.cb = @sizeOf(win_proc.STARTUPINFOW);
        var pi: win_proc.PROCESS_INFORMATION = .{};

        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const ok = win_proc.CreateProcessW(
            null,
            wcmd.ptr,
            null,
            null,
            .FALSE,
            CREATE_NO_WINDOW,
            null,
            null,
            &si,
            &pi,
        );
        if (ok == .FALSE) return error.CommandFailed;
        defer _ = CloseHandle(pi.hProcess);
        defer _ = CloseHandle(pi.hThread);

        const INFINITE: u32 = 0xFFFFFFFF;
        _ = win_proc.WaitForSingleObject(pi.hProcess, INFINITE);

        var exit_code: u32 = 0;
        if (win_proc.GetExitCodeProcess(pi.hProcess, &exit_code) == .FALSE) return error.CommandFailed;
        if (exit_code != 0) return error.CommandFailed;
    }

    // ============================ 测试 ============================






} else struct {
    pub fn isElevated() bool { return false; }
};

pub const tun_linux = if (builtin.os.tag == .linux) struct {
    // Linux TUN 设备实现：`/dev/net/tun` + `TUNSETIFF` + 接口配置。
    //
    // 这个文件只会在 `target_os == .linux` 时被编译（见 tun.zig 的 `linux_impl`）。
    //
    // **为什么要自己声明常量**：Zig 标准库的 `std.os.linux.IFF` 是位域结构，
    // 字段名与内核 uapi 的 `IFF_*` 宏并不一一对应，`ifreq` 在非 Linux 目标上
    // 甚至是零长度。直接照 Linux uapi 定义可以避免跟着 std 内部结构变动。

    const linux = std.os.linux;
    const posix = std.posix;

    // ============================================================================
    // Linux uapi 常量（include/uapi/linux/if_tun.h 与 if.h）
    // ============================================================================

    /// 接口名长度（含结尾 NUL）
    pub const IFNAMSIZ = 16;

    /// `IFF_TUN`：三层（IP）隧道设备
    pub const IFF_TUN: u16 = 0x0001;
    /// `IFF_TAP`：二层（以太网）隧道设备
    pub const IFF_TAP: u16 = 0x0002;
    /// `IFF_NO_PI`：不附加 4 字节的 packet info 前缀
    pub const IFF_NO_PI: u16 = 0x1000;
    /// `IFF_UP`：接口已启用
    pub const IFF_UP: u16 = 0x0001;
    /// `IFF_RUNNING`
    pub const IFF_RUNNING: u16 = 0x0040;

    /// `struct ifreq`：16 字节名字 + 24 字节联合体 = 40 字节
    pub const IfReq = extern struct {
        name: [IFNAMSIZ]u8,
        /// union { ifr_addr / ifr_flags(short) / ifr_mtu(int) / ... }
        /// 统一按最大成员（sockaddr，16 字节）对齐，这里留足 24 字节
        data: [24]u8 = @splat(0),

        pub fn init(name: []const u8) !IfReq {
            if (name.len == 0 or name.len >= IFNAMSIZ) return error.InvalidName;
            var r = IfReq{ .name = @splat(0) };
            @memcpy(r.name[0..name.len], name);
            return r;
        }

        /// 写入 short 型标志（ifr_flags）
        pub fn setFlags(self: *IfReq, flags: u16) void {
            std.mem.writeInt(u16, self.data[0..2], flags, .little);
        }

        /// 读取 short 型标志
        pub fn getFlags(self: *const IfReq) u16 {
            return std.mem.readInt(u16, self.data[0..2], .little);
        }

        /// 写入 int 型值（ifr_mtu 等）
        pub fn setInt(self: *IfReq, v: i32) void {
            std.mem.writeInt(i32, self.data[0..4], v, .little);
        }

        /// 写入 sockaddr_in（IPv4 地址/掩码）
        pub fn setSockaddrIn(self: *IfReq, addr_be: u32) void {
            @memset(&self.data, 0);
            // struct sockaddr { sa_family_t(2) ; char sa_data[14] }
            // sockaddr_in { family, port(2), addr(4), ... }
            std.mem.writeInt(u16, self.data[0..2], posix.AF.INET, .little);
            std.mem.writeInt(u16, self.data[2..4], 0, .little); // port
            std.mem.writeInt(u32, self.data[4..8], addr_be, .big);
        }
    };

    // ---- ioctl 请求号（_IOC 编码，与内核一致）----
    fn ioc(dir: u32, typ: u32, nr: u32, size: u32) u32 {
        return (dir << 30) | (size << 16) | (typ << 8) | nr;
    }
    const IOC_WRITE: u32 = 1;
    const IOC_READ: u32 = 2;

    /// `TUNSETIFF` = `_IOW('T', 202, int)` = 0x400454CA
    pub const TUNSETIFF: u32 = ioc(IOC_WRITE, 'T', 202, 4);
    /// `TUNSETPERSIST` = `_IOW('T', 203, int)`
    pub const TUNSETPERSIST: u32 = ioc(IOC_WRITE, 'T', 203, 4);
    /// `TUNGETIFF` = `_IOR('T', 210, int)`
    pub const TUNGETIFF: u32 = ioc(IOC_READ, 'T', 210, 4);

    /// `SIOCSIFADDR` = `_IOW('i', 0, struct ifreq)`
    pub const SIOCSIFADDR: u32 = ioc(IOC_WRITE, 'i', 0, @sizeOf(IfReq));
    /// `SIOCSIFNETMASK` = `_IOW('i', 22, struct ifreq)`
    pub const SIOCSIFNETMASK: u32 = ioc(IOC_WRITE, 'i', 22, @sizeOf(IfReq));
    /// `SIOCSIFMTU` = `_IOW('i', 34, struct ifreq)`
    pub const SIOCSIFMTU: u32 = ioc(IOC_WRITE, 'i', 34, @sizeOf(IfReq));
    /// `SIOCGIFFLAGS` = `_IOWR('i', 17, struct ifreq)`
    pub const SIOCGIFFLAGS: u32 = ioc(3, 'i', 17, @sizeOf(IfReq));
    /// `SIOCSIFFLAGS` = `_IOW('i', 16, struct ifreq)`
    pub const SIOCSIFFLAGS: u32 = ioc(IOC_WRITE, 'i', 16, @sizeOf(IfReq));

    pub const Error = error{
        InvalidName,
        OpenFailed,
        PermissionDenied,
        IoctlFailed,
        ControlSocketFailed,
    };

    // ============================================================================
    // 建立接口
    // ============================================================================

    pub const Establisher = struct {
        /// 打开 /dev/net/tun 并用 TUNSETIFF 创建（或接管）指定名字的 TUN 接口。
        ///
        /// 返回的 fd 直接用于 read/write 收发 IP 包（因为设置了 IFF_NO_PI，
        /// 每次读写都是裸 IP 包，没有额外前缀）。
        pub fn create(cfg: anytype) Error!@import("tun.zig").Handle {
            const name = cfg.name;
            const mtu = cfg.mtu;
            const ipv4 = cfg.ipv4; // 形如 "198.18.0.1/15"，可为空

            // 1) 打开克隆设备
            const fd = posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0) catch |e| switch (e) {
                error.AccessDenied => return error.PermissionDenied,
                else => return error.OpenFailed,
            };
            errdefer posix.close(fd);

            // 2) TUNSETIFF：创建 TUN 设备，不附加 packet info
            var req = try IfReq.init(name);
            req.setFlags(IFF_TUN | IFF_NO_PI);
            ioctlOrErr(fd, TUNSETIFF, @intFromPtr(&req)) catch |e| {
                // 容器里即便是 root，也可能因为没有 CAP_NET_ADMIN 而失败；
                // EPERM 要报成「权限不足」，别让用户以为是设备坏了。
                return switch (e) {
                    error.PermissionDenied => error.PermissionDenied,
                    else => error.IoctlFailed,
                };
            };

            // 3) 配置地址 / 掩码 / MTU / 启用（需要单独的 AF_INET 控制 socket）
            if (ipv4.len > 0) {
                configureInterface(name, ipv4, mtu) catch |e| {
                    // 配置失败则回滚：关掉 fd，避免留下一个半配置的接口
                    posix.close(fd);
                    return switch (e) {
                        error.PermissionDenied => error.PermissionDenied,
                        else => error.IoctlFailed,
                    };
                };
            }

            return .{ .kind = .linux_tun, .fd = @intCast(fd), .owns_fd = true };
        }

        /// 只创建不配置（用于测试 ioctl 编码是否被内核接受）
        pub fn createRaw(name: []const u8) Error!posix.fd_t {
            const fd = posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0) catch return error.OpenFailed;
            errdefer posix.close(fd);
            var req = try IfReq.init(name);
            req.setFlags(IFF_TUN | IFF_NO_PI);
            ioctlOrErr(fd, TUNSETIFF, @intFromPtr(&req)) catch return error.IoctlFailed;
            return fd;
        }
    };

    fn ioctlOrErr(fd: posix.fd_t, request: u32, arg: usize) Error!void {
        const rc = linux.ioctl(fd, request, arg);
        switch (linux.E.init(rc)) {
            .SUCCESS => return,
            // 特权不足：TUNSETIFF / SIOCSIF* 都需要 CAP_NET_ADMIN。
            // 容器里 root 也可能没有该 capability，必须报成权限问题。
            .PERM, .ACCES => return error.PermissionDenied,
            else => return error.IoctlFailed,
        }
    }

    /// 通过 AF_INET + AF_UNSPEC 控制 socket 配置接口。
    ///
    /// 这里用 ioctl 而非 netlink：UNIX 上的 `SIOCSIFADDR` 系列足够完成
    /// 「设地址 / 设掩码 / 设 MTU / 拉 UP」这四件事，且不需要解析 netlink 消息。
    fn configureInterface(name: []const u8, cidr: []const u8, mtu: u32) Error!void {
        const parsed = parseCidr(cidr) orelse return error.InvalidName;

        const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return error.ControlSocketFailed;
        defer posix.close(sock);

        // 地址
        var req = IfReq.init(name) catch return error.InvalidName;
        req.setSockaddrIn(parsed.addr);
        ioctlOrErr(sock, SIOCSIFADDR, @intFromPtr(&req)) catch return error.IoctlFailed;

        // 掩码
        var req2 = IfReq.init(name) catch return error.InvalidName;
        req2.setSockaddrIn(parsed.mask);
        ioctlOrErr(sock, SIOCSIFNETMASK, @intFromPtr(&req2)) catch return error.IoctlFailed;

        // MTU
        if (mtu > 0) {
            var req3 = IfReq.init(name) catch return error.InvalidName;
            req3.setInt(@intCast(mtu));
            ioctlOrErr(sock, SIOCSIFMTU, @intFromPtr(&req3)) catch return error.IoctlFailed;
        }

        // 启用：先读当前 flags，加上 IFF_UP 再写回
        var req4 = IfReq.init(name) catch return error.InvalidName;
        ioctlOrErr(sock, SIOCGIFFLAGS, @intFromPtr(&req4)) catch return error.IoctlFailed;
        const flags = req4.getFlags();
        req4.setFlags(flags | IFF_UP | IFF_RUNNING);
        ioctlOrErr(sock, SIOCSIFFLAGS, @intFromPtr(&req4)) catch return error.IoctlFailed;
    }

    const Cidr4 = struct {
        addr: u32, // 网络字节序
        mask: u32, // 网络字节序
    };

    /// 解析 "a.b.c.d/prefix"，产出网络字节序的地址与掩码。
    pub fn parseCidr(s: []const u8) ?Cidr4 {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return null;
        const ip_str = s[0..slash];
        const prefix = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return null;
        if (prefix > 32) return null;

        const addr_be = parseIpv4Be(ip_str) orelse return null;
        const mask_host: u32 = if (prefix == 0) 0 else @as(u32, 0xffffffff) << @intCast(32 - prefix);
        return .{ .addr = addr_be, .mask = @byteSwap(mask_host) };
    }

    /// 把 "1.2.3.4" 解析成网络字节序 u32（内存里就是 01 02 03 04）
    pub fn parseIpv4Be(s: []const u8) ?u32 {
        var parts: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, s, '.');
        var i: usize = 0;
        while (it.next()) |p| {
            if (i >= 4) return null;
            parts[i] = std.fmt.parseInt(u8, p, 10) catch return null;
            i += 1;
        }
        if (i != 4) return null;
        return std.mem.readInt(u32, &parts, .big);
    }

    // ============================ 测试 ============================








} else struct {
    // 非 Linux 平台上的 `tun_linux` 桩。
    //
    // 只为让上层能引用 `parseCidr` / `parseIpv4Be` 等纯函数而存在 ——
    // 这些是纯计算，跨平台行为一致，保留真实实现可以让测试在各平台都跑。
    // 涉及 ioctl 的部分一律 `error.Unsupported`。

    pub const Error = error{Unsupported};

    pub const IFNAMSIZ = 16;

    // ---- 纯计算部分：与 Linux 版完全一致 ----

    pub fn parseIpv4Be(s: []const u8) ?u32 {
        var parts: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, s, '.');
        var i: usize = 0;
        while (it.next()) |p| {
            if (i >= 4) return null;
            parts[i] = std.fmt.parseInt(u8, p, 10) catch return null;
            i += 1;
        }
        if (i != 4) return null;
        return std.mem.readInt(u32, &parts, .big);
    }

    pub const Cidr4 = struct {
        addr: u32,
        mask: u32,
    };

    pub fn parseCidr(s: []const u8) ?Cidr4 {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return null;
        const ip_str = s[0..slash];
        const prefix = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return null;
        if (prefix > 32) return null;

        const addr_be = parseIpv4Be(ip_str) orelse return null;
        const mask_host: u32 = if (prefix == 0) 0 else @as(u32, 0xffffffff) << @intCast(32 - prefix);
        return .{ .addr = addr_be, .mask = @byteSwap(mask_host) };
    }

    /// 非 Linux 上不可用
    pub fn create(name: []const u8) Error!void {
        _ = name;
        return error.Unsupported;
    }


};

pub const tun_route = if (builtin.os.tag == .linux) struct {
    // Linux 路由 / DNS 配置（TUN 接管的「下半场」）。
    //
    // 网卡建起来只是第一步。要让流量真的进 TUN，还必须：
    // 1. 把默认路由指向 TUN（或按需加细分路由）
    // 2. 为直连流量保留一条「绕过 TUN」的路径（否则代理自身出不去，形成环路）
    // 3. 把系统 DNS 指到我们的 DNS 服务
    //
    // **防环路是本文件最核心的设计**：TUN 接管全部流量后，
    // 代理自己去连上游服务器的那个连接也会被路由进 TUN，
    // 于是「代理流量」→ TUN → 代理 → 死循环。
    // 解决办法是给每个上游节点地址加一条**走物理网卡**的 /32 主机路由，
    // 优先级高于 TUN 的默认路由。
    //
    // 实现方式：直接调 `ip` 命令（iproute2）。
    // 用 netlink 原生编解码更「干净」，但代码量和出错面都大得多；
    // `ip` 命令在所有主流发行版上都存在，且失败时有明确退出码。
    //
    // **Windows 走 `wintun_netcfg.Router`**（`route` / `netsh` 命令）。
    // 两个平台的步骤语义相同、回滚策略相同，但命令完全不同，
    // 所以这里只做一层分派，把具体实现留在各自文件里。

    const posix = std.posix;


    const is_windows = builtin.os.tag == .windows;

    pub const Error = error{
        Unsupported,
        /// 需要管理员/root，当前身份不够
        PermissionDenied,
        CommandFailed,
        NoTunDevice,
        ResolveFailed,
    } || std.mem.Allocator.Error;

    pub const Config = struct {
        /// TUN 网卡名
        tun_name: []const u8 = "aether-tun0",
        /// TUN 网卡上的地址（脚本配置时已设，这里只用于生成路由）
        tun_gateway: []const u8 = "198.18.0.1",
        /// 物理出口网卡名（为空则自动探测默认路由的 dev）
        physical_iface: []const u8 = "",
        /// 物理网卡的网关（为空则自动探测）
        physical_gateway: []const u8 = "",
        /// 原默认路由的 metric（用于加更高优先级的 TUN 路由）
        tun_route_metric: u32 = 1,
        /// 需要绕过 TUN 的地址（上游节点 IP）——防环路的关键
        bypass_hosts: []const []const u8 = &.{},
        /// 是否接管全部流量
        route_all: bool = true,
        /// 要写入的 DNS 服务器
        dns: []const u8 = "198.18.0.1",
        /// 备份文件路径（用于还原）
        backup_path: []const u8 = "/tmp/aethercore-route.bak",
    };

    /// 路由配置器。所有操作都记录到 `applied`，便于 teardown 精确回滚。
    pub const Router = struct {
        alloc: std.mem.Allocator,
        cfg: Config,
        applied: std.ArrayList(Applied) = .empty,

        /// Windows 平台的实际执行者。
        ///
        /// 为什么不用两套 `if (is_windows)` 内联分支：Linux 用 `ip` 命令、
        /// Windows 用 `route`/`netsh`，参数格式和回滚方式完全不同；
        /// 混在一个函数里两边都难读，也没法分别测试。
        /// 这里用组合把 Windows 实现藏在 `wintun_netcfg.Router` 后面，
        /// 本结构体只负责「平台分派 + 统一生命周期」。
        win: if (is_windows) wintun_netcfg.Router else void =
            if (is_windows) undefined else {},

        /// 探测到的物理出口
        physical_iface: []u8 = &.{},
        physical_gateway: []u8 = &.{},

        pub const Applied = union(enum) {
            default_via_tun,
            host_bypass: []const u8,
            dns_changed: void,
        };

        pub fn init(alloc: std.mem.Allocator, cfg: Config) Router {
            var r = Router{ .alloc = alloc, .cfg = cfg };
            if (is_windows) {
                // 名字对齐：wintun 网卡由 establish() 用 cfg.name 建，
                // 这里必须用同一个名字，否则 netsh/route 找不到接口。
                r.win = wintun_netcfg.Router.init(alloc, .{
                    .tun_name = cfg.tun_name,
                    .physical_iface = cfg.physical_iface,
                    .physical_gateway = cfg.physical_gateway,
                    .bypass_hosts = cfg.bypass_hosts,
                    .tun_gateway = cfg.tun_gateway,
                    .route_all = cfg.route_all,
                    .dns = cfg.dns,
                });
            }
            return r;
        }

        pub fn deinit(self: *Router) void {
            for (self.applied.items) |a| {
                switch (a) {
                    .host_bypass => |ip| self.alloc.free(ip),
                    else => {},
                }
            }
            self.applied.deinit(self.alloc);
            if (self.physical_iface.len > 0) self.alloc.free(self.physical_iface);
            if (self.physical_gateway.len > 0) self.alloc.free(self.physical_gateway);
            if (is_windows) self.win.deinit();
        }

        /// 探测当前默认路由的出口网卡与网关
        pub fn detectPhysical(self: *Router) Error!void {
            if (is_windows) {
                var iface: []const u8 = &.{};
                var gw: []const u8 = &.{};
                try self.win.detectPhysical(&iface, &gw);
                // 转存到本结构体拥有的内存里（win 内部那两份也要释放）
                if (self.physical_iface.len > 0) self.alloc.free(self.physical_iface);
                if (self.physical_gateway.len > 0) self.alloc.free(self.physical_gateway);
                self.physical_iface = try self.alloc.dupe(u8, iface);
                self.physical_gateway = try self.alloc.dupe(u8, gw);
                self.alloc.free(iface);
                self.alloc.free(gw);
                return;
            }
            if (builtin.os.tag != .linux) return error.Unsupported;

            // ip route show default  →  "default via 192.168.1.1 dev eth0 proto dhcp ..."
            const out = try runCapture(self.alloc, &.{ "ip", "route", "show", "default" });
            defer self.alloc.free(out);

            var it = std.mem.tokenizeAny(u8, out, " \t\r\n");
            var gateway: []const u8 = "";
            var dev: []const u8 = "";
            var prev: []const u8 = "";
            while (it.next()) |tok| {
                if (std.mem.eql(u8, prev, "via")) gateway = tok;
                if (std.mem.eql(u8, prev, "dev")) dev = tok;
                prev = tok;
            }
            if (dev.len == 0) return error.ResolveFailed;

            if (self.physical_iface.len > 0) self.alloc.free(self.physical_iface);
            self.physical_iface = try self.alloc.dupe(u8, dev);
            if (gateway.len > 0) {
                if (self.physical_gateway.len > 0) self.alloc.free(self.physical_gateway);
                self.physical_gateway = try self.alloc.dupe(u8, gateway);
            }
        }

        /// 应用接管路由。
        ///
        /// 顺序很重要：
        /// 1. 先给上游节点加 bypass 路由（必须在默认路由改掉之前加，
        ///    否则改动瞬间代理自己就断了）
        /// 2. 再把默认路由指向 TUN
        /// 3. 最后改 DNS
        pub fn apply(self: *Router) Error!void {
            if (is_windows) {
                self.win.apply() catch |e| return switch (e) {
                    error.NotElevated => error.PermissionDenied,
                    else => error.CommandFailed,
                };
                return;
            }
            if (builtin.os.tag != .linux) return error.Unsupported;
            if (self.physical_iface.len == 0) try self.detectPhysical();

            // 1) 防环路：每个上游节点地址走物理网卡
            for (self.cfg.bypass_hosts) |ip| {
                if (ip.len == 0) continue;
                if (!isIpv4Literal(ip)) continue; // 域名应在调用方先解析成 IP

                if (self.physical_gateway.len > 0) {
                    try runSilent(&.{ "ip", "route", "add", ip, "via", self.physical_gateway, "dev", self.physical_iface });
                } else {
                    try runSilent(&.{ "ip", "route", "add", ip, "dev", self.physical_iface });
                }
                try self.applied.append(self.alloc, .{ .host_bypass = try self.alloc.dupe(u8, ip) });
            }

            // 2) 默认路由指向 TUN
            //    replace 而非 add：重复 apply 不会因为「已存在」而失败
            if (self.cfg.route_all) {
                var metric_buf: [16]u8 = undefined;
                const metric = std.fmt.bufPrint(&metric_buf, "{d}", .{self.cfg.tun_route_metric}) catch return error.CommandFailed;
                try runSilent(&.{
                    "ip",     "route", "replace",         "default",
                    "dev",    self.cfg.tun_name, "metric", metric,
                });
                try self.applied.append(self.alloc, .default_via_tun);
            }

            // 3) DNS：把 resolv.conf 指到我们的 DNS
            //    先备份，便于 teardown 还原
            try self.setDns();
        }

        fn setDns(self: *Router) Error!void {
            // 备份原文件
            std.fs.cwd().copyFile("/etc/resolv.conf", std.fs.cwd(), self.cfg.backup_path, .{}) catch {};

            const content = std.fmt.allocPrint(self.alloc, "nameserver {s}\n", .{self.cfg.dns}) catch return error.CommandFailed;
            defer self.alloc.free(content);

            const f = std.fs.createFileAbsolute("/etc/resolv.conf", .{ .truncate = true }) catch return error.CommandFailed;
            defer f.close();
            f.writeAll(content) catch return error.CommandFailed;

            try self.applied.append(self.alloc, .{ .dns_changed = {} });
        }

        /// 还原：按相反顺序撤销
        pub fn teardown(self: *Router) void {
            if (is_windows) {
                self.win.teardown(self.physical_iface, self.physical_gateway);
                return;
            }
            if (builtin.os.tag != .linux) return;
            var i: usize = self.applied.items.len;
            while (i > 0) {
                i -= 1;
                switch (self.applied.items[i]) {
                    .dns_changed => {
                        std.fs.cwd().copyFile(self.cfg.backup_path, std.fs.cwd(), "/etc/resolv.conf", .{}) catch {};
                    },
                    .default_via_tun => {
                        // 恢复默认路由到物理网卡
                        if (self.physical_iface.len > 0) {
                            if (self.physical_gateway.len > 0) {
                                runSilent(&.{ "ip", "route", "replace", "default", "via", self.physical_gateway, "dev", self.physical_iface }) catch {};
                            } else {
                                runSilent(&.{ "ip", "route", "replace", "default", "dev", self.physical_iface }) catch {};
                            }
                        }
                    },
                    .host_bypass => |ip| {
                        runSilent(&.{ "ip", "route", "del", ip }) catch {};
                    },
                }
            }
        }
    };

    pub fn isIpv4Literal(s: []const u8) bool {
        var dots: usize = 0;
        for (s) |c| {
            if (c == '.') {
                dots += 1;
            } else if (!std.ascii.isDigit(c)) return false;
        }
        return dots == 3;
    }

    /// 执行命令并捕获 stdout
    fn runCapture(alloc: std.mem.Allocator, argv: []const []const u8) Error![]u8 {
        const res = std.process.Child.run(.{
            .allocator = alloc,
            .argv = argv,
            .max_output_bytes = 64 * 1024,
        }) catch return error.CommandFailed;
        defer alloc.free(res.stderr);

        switch (res.term) {
            .Exited => |code| if (code != 0) {
                alloc.free(res.stdout);
                return error.CommandFailed;
            },
            else => {
                alloc.free(res.stdout);
                return error.CommandFailed;
            },
        }
        return res.stdout;
    }

    /// 执行命令，不关心输出
    fn runSilent(argv: []const []const u8) Error!void {
        const la = std.heap.page_allocator;
        const res = std.process.Child.run(.{
            .allocator = la,
            .argv = argv,
            .max_output_bytes = 64 * 1024,
        }) catch return error.CommandFailed;
        defer la.free(res.stdout);
        defer la.free(res.stderr);

        switch (res.term) {
            .Exited => |code| if (code != 0) return error.CommandFailed,
            else => return error.CommandFailed,
        }
    }

    // ============================ 测试 ============================



} else struct {
    // 非 Linux 平台上的 TUN 路由桩。
    //
    // 存在的唯一目的：让上层（main.zig 等）可以无条件引用
    // `tun_route.Router` 这个类型，而不必在每个调用点写 `comptime` 分支。
    //
    // 所有操作都返回 `error.Unsupported` —— **不会假装配置成功**。

    pub const Error = error{Unsupported};

    pub const Config = struct {
        tun_name: []const u8 = "aether-tun0",
        tun_gateway: []const u8 = "198.18.0.1",
        physical_iface: []const u8 = "",
        physical_gateway: []const u8 = "",
        tun_route_metric: u32 = 1,
        bypass_hosts: []const []const u8 = &.{},
        route_all: bool = true,
        dns: []const u8 = "198.18.0.1",
        backup_path: []const u8 = "/tmp/aethercore-route.bak",
    };

    pub const Router = struct {
        cfg: Config,

        pub fn init(alloc: std.mem.Allocator, cfg: Config) Router {
            _ = alloc;
            return .{ .cfg = cfg };
        }

        pub fn deinit(self: *Router) void {
            _ = self;
        }

        pub fn detectPhysical(self: *Router) Error!void {
            _ = self;
            return error.Unsupported;
        }

        pub fn apply(self: *Router) Error!void {
            _ = self;
            return error.Unsupported;
        }

        pub fn teardown(self: *Router) void {
            _ = self;
        }
    };

    /// IPv4 字面量判定（与 Linux 版同语义，供上层无条件调用）
    pub fn isIpv4Literal(s: []const u8) bool {
        var dots: usize = 0;
        for (s) |c| {
            if (c == '.') {
                dots += 1;
            } else if (!std.ascii.isDigit(c)) return false;
        }
        return dots == 3;
    }



};

pub const tun_runner = struct {
    // TUN 数据包处理主循环。
    //
    // **相比旧版的关键变化**：旧版 `processPacket` 是**无状态**的 ——
    // 收到 SYN 就回一个 seq 写死 0x1000 的 SYN-ACK，然后就没了。
    // 客户端发来数据时，没有任何代码认领这条连接，于是连接形同虚设。
    //
    // 现在处理完整的生命周期：
    //   SYN  → 建连接表项 → 回 SYN-ACK
    //   ACK  → 标记 established
    //   数据 → 查表 → 写上游 socket
    //   FIN  → 回 FIN-ACK → 删表项
    //   RST  → 删表项
    //
    // 上游 socket 的建立/读写由调用方（执行真正代理拨号的那一层）注入，
    // 这样本模块可以脱离网络独立测试。

    const tun = @import("tun.zig");
    const tun_stack = tcp_stack.tun_stack;
    const tun_conn = tcp_stack.tun_conn;
    const stack_mod = tcp_stack.stack;
    const tcp_mod = tcp_stack.tcp_proto;
    const ip_mod = tcp_stack.ip_proto;

    const TcpFlags = tun_stack.TcpFlags;

    /// 上游连接抽象。TUN 数据面只依赖这三个操作，
    /// 具体是 TCP 还是 TLS/SS 由上层决定。
    pub const Upstream = struct {
        ctx: *anyopaque,
        /// 写数据到上游
        writeFn: *const fn (ctx: *anyopaque, data: []const u8) anyerror!usize,
        /// 读上游数据（非阻塞语义：没数据返回 0）
        readFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!usize,
        /// 关闭
        closeFn: *const fn (ctx: *anyopaque) void,

        pub fn write(self: Upstream, data: []const u8) !usize {
            return self.writeFn(self.ctx, data);
        }
        pub fn read(self: Upstream, buf: []u8) !usize {
            return self.readFn(self.ctx, buf);
        }
        pub fn close(self: Upstream) void {
            self.closeFn(self.ctx);
        }
    };

    /// 拨号回调：为一条新连接建立上游。返回 null 表示拒绝。
    pub const DialFn = *const fn (
        ctx: *anyopaque,
        dst_ip: [4]u8,
        dst_port: u16,
    ) anyerror!?Upstream;

    pub const Runner = struct {
        alloc: std.mem.Allocator,
        /// 真正的协议栈（IP 分片重组 + TCP 状态机 + UDP NAT）
        stack: stack_mod.Stack,
        /// 本端 TUN 网卡地址
        local_ip: [4]u8 = .{ 198, 18, 0, 1 },

        /// 拨号上下文（由上层注入）
        dial_ctx: ?*anyopaque = null,
        dial_fn: ?DialFn = null,

        /// 最近一次 tick 的时间
        last_tick_ms: i64 = 0,

        /// 保护协议栈 + TUN 写。TUN 主循环与每条上游连接的读线程
        /// 都会并发访问 `stack`，wintun 的 ring buffer 也不是线程安全的。
        mu: net.Mutex = .{},

        /// TUN 设备句柄（由 runLoop 注入），上游读线程据此回写
        tun_handle: ?tun.Handle = null,

        /// 回包出口。默认写 TUN；测试时替换成捕获回调，
        /// 这样不必真建网卡也能验证「上游 → 协议栈 → 回包」整条链路。
        tx_ctx: ?*anyopaque = null,
        tx_fn: ?*const fn (ctx: *anyopaque, pkt: []const u8) void = null,

        /// 回写缓冲（只在持锁时使用，避免每条连接各自 4KB 栈缓冲）
        tx_buf: [4096]u8 = undefined,

        pub fn init(alloc: std.mem.Allocator) Runner {
            return .{
                .alloc = alloc,
                .stack = stack_mod.Stack.init(alloc),
            };
        }

        pub fn deinit(self: *Runner) void {
            self.stack.deinit();
        }

        /// 连接数（供控制面展示）
        pub fn connCount(self: *Runner) usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.stack.tcpCount();
        }

        /// 处理一个入站 IP 包，把要回写 TUN 的报文写进 `out`，返回其长度。
        /// 返回 0 表示无需回包。
        pub fn handle(self: *Runner, pkt: []const u8, out: []u8) !usize {
            const now = net.milliTimestamp();
            self.mu.lock();
            defer self.mu.unlock();
            const n = try self.stack.handlePacket(pkt, out, now);

            // 每 30 秒驱动一次定时器（重传 / 超时清理）
            if (now - self.last_tick_ms > 30_000) {
                self.stack.tick(now);
                self.last_tick_ms = now;
            }
            return n;
        }

        /// 上游数据回写给客户端（只在持锁时构造报文）
        pub fn writeFromUpstream(self: *Runner, key: tcp_mod.Key, data: []const u8, out: []u8) !usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.stack.writeTcp(key, data, out, net.milliTimestamp());
        }

        /// 上游 UDP 回包
        pub fn writeUdpFromUpstream(self: *Runner, key: ip_mod.UdpKey, data: []const u8, out: []u8) !usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.stack.writeUdp(key, data, out);
        }

        pub fn sweep(self: *Runner) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.stack.tick(net.milliTimestamp());
        }

        /// 驱动定时器，并把因重传 / 零窗口探测 / FIN 产生的报文真正发出去。
        ///
        /// 只调 `stack.tick()` 是不够的：它负责把段标回「待发送」，
        /// 但构造报文并写 TUN 是这一层的事。两者分家的话，
        /// 重传逻辑看起来在工作（队列状态对），线路上却一个重传包都没有。
        pub fn tickAndFlush(self: *Runner) void {
            self.mu.lock();
            defer self.mu.unlock();

            const now = net.milliTimestamp();
            self.stack.tick(now);
            self.last_tick_ms = now;

            // 遍历所有连接，把待发段推出去。
            // 先收集 key 再发，避免发送过程中连接被回收导致迭代失效。
            var keys: [256]tcp_mod.Key = undefined;
            var count: usize = 0;
            for (self.stack.tcp_slots.items) |s| {
                if (count >= keys.len) break;
                keys[count] = s.key;
                count += 1;
            }

            for (keys[0..count]) |key| {
                var guard: usize = 0;
                while (guard < 64) : (guard += 1) {
                    const n = self.stack.tickAndEmit(key, &self.tx_buf, now) catch break;
                    if (n == 0) break;
                    self.emit(self.tx_buf[0..n]);
                }
            }
        }

        // ------------------------------------------------------------------
        // 供上游读线程调用（线程安全，内部持锁）
        // ------------------------------------------------------------------

        /// 把上游收到的数据推进协议栈并立即写回 TUN。
        ///
        /// 一次最多写 `tx_buf` 一个段；剩余数据留在发送队列里，
        /// 由后续 ACK 或 `tick` 驱动继续发（受拥塞窗口限制）。
        pub fn pushUpstream(self: *Runner, key: tcp_mod.Key, data: []const u8) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.flushLocked(key, data);
        }

        fn flushLocked(self: *Runner, key: tcp_mod.Key, data: []const u8) void {
            const now = net.milliTimestamp();

            var first = true;
            // 循环把队列里能发的段都发出去（受拥塞窗口/对端窗口限制）
            while (true) {
                const n = if (first and data.len > 0)
                    self.stack.writeTcp(key, data, &self.tx_buf, now) catch return
                else
                    self.stack.flushTcp(key, &self.tx_buf, now) catch return;
                first = false;
                if (n == 0) break;
                self.emit(self.tx_buf[0..n]);
            }
        }

        /// 把构造好的报文送出去：优先用注入的回调，否则写 TUN 设备
        fn emit(self: *Runner, pkt: []const u8) void {
            if (self.tx_fn) |f| {
                f(self.tx_ctx.?, pkt);
                return;
            }
            const h = self.tun_handle orelse return;
            _ = tun.writePacket(h, pkt) catch {};
        }

        /// 上游关闭：给客户端发 FIN
        pub fn closeTcpFromUpstream(self: *Runner, key: tcp_mod.Key) void {
            self.mu.lock();
            defer self.mu.unlock();
            const slot = self.stack.findTcpPub(key) orelse return;
            slot.conn.close();
            self.flushLocked(key, "");
        }

        /// 立即给客户端回 RST（目标被规则拒绝 / 拨号失败时用）
        pub fn resetTcp(self: *Runner, key: tcp_mod.Key) void {
            self.mu.lock();
            defer self.mu.unlock();
            const n = self.stack.buildRst(key, &self.tx_buf) catch return;
            if (n > 0) self.emit(self.tx_buf[0..n]);
            self.stack.closeTcp(key);
        }

        /// UDP 回包写回 TUN
        pub fn pushUdp(self: *Runner, key: ip_mod.UdpKey, data: []const u8) void {
            self.mu.lock();
            defer self.mu.unlock();
            const n = self.stack.writeUdp(key, data, &self.tx_buf) catch return;
            if (n > 0) self.emit(self.tx_buf[0..n]);
        }
    };

    /// 主循环：从 TUN 读包，处理，回写。
    ///
    /// 三个关键点（早先都缺）：
    /// 1. **阻塞等包**。`readPacket` 在无包时立刻返回 0，直接 `continue`
    ///    会变成忙轮询，把 CPU 吃满。现在用 `waitReadable` 等事件。
    /// 2. **定时器每秒驱动**。早先是「收到包才检查、且 30 秒一次」，
    ///    没流量时重传/超时/清理全部停摆，连接僵死、TIME_WAIT 堆积。
    /// 3. **重传要真的发出去**。`tick` 把段标回未发送，但没人构造报文，
    ///    等于重传队列空转 —— 弱网下表现为「连上了但永远卡住」。
    pub fn runLoop(r: *Runner, h: tun.Handle, running: *std.atomic.Value(bool)) void {
        var rx: [4096]u8 = undefined;
        var out: [4096]u8 = undefined;
        var last_tick: i64 = 0;

        // 上游读线程需要句柄才能回写
        r.mu.lock();
        r.tun_handle = h;
        r.mu.unlock();

        while (running.load(.acquire)) {
            // 等包，最多 100ms —— 兼顾延迟与 CPU
            _ = tun.waitReadable(h, 100);

            const n = tun.readPacket(h, &rx) catch {
                // 读失败（设备缺失 / 未实现 / 被关闭）都意味着接管不可继续
                return;
            };
            if (n >= 20) {
                const rep_len = r.handle(rx[0..n], &out) catch 0;
                if (rep_len > 0) {
                    _ = tun.writePacket(h, out[0..rep_len]) catch {};
                }
            }

            // 定时器：每秒驱动一次，与有没有流量无关
            const now = net.milliTimestamp();
            if (now - last_tick >= 1000) {
                r.tickAndFlush();
                last_tick = now;
            }
        }
    }

    // ============================ 测试 ============================

    fn mkSyn(dst_ip: [4]u8, dst_port: u16, src_port: u16, seq: u32, buf: []u8) []u8 {
        const n = tun_conn.buildTcpSegment(
            buf,
            .{ 10, 0, 0, 2 }, // 客户端
            dst_ip,
            src_port,
            dst_port,
            0,
            0,
            TcpFlags.SYN,
            "",
        ) catch return buf[0..0];
        // 修正 seq 字段（buildTcpSegment 里固定写了传入值，这里重新写一次）
        std.mem.writeInt(u32, buf[24..28][0..4], seq, .big);
        // 重算校验和
        std.mem.writeInt(u16, buf[36..38][0..2], 0, .big);
        const seg = buf[20..n];
        const csum = tun_stack.computeTcpChecksum(.{ 10, 0, 0, 2 }, dst_ip, seg);
        std.mem.writeInt(u16, buf[36..38][0..2], csum, .big);
        return buf[0..n];
    }







};

pub const tun_glue = struct {
    // TUN 数据面 ↔ 真实出站 的连接层。
    //
    // **这是此前最大的缺口**：`stack.zig` 的 `Handler` 回调从来没有被实现过，
    // `tun_runner.Runner.dial_fn` 也永远是 null。结果是 —— TUN 能收到客户端的
    // SYN，也能回 SYN-ACK，但客户端把数据发上来之后就没有下文了：
    // 没有代码去建立真实的出站连接，也没有代码把上游的响应送回 TUN。
    // 也就是说 `--takeover` 模式下**一次网页都打不开**。
    //
    // 本模块补上这一段：
    //
    //   客户端 ──SYN──→ stack ──onTcpOpen──→ 拨号线程（直连 / VLESS / SS）
    //                                       └→ 读线程：上游 → stack → TUN
    //   客户端 ──data─→ stack ──onTcpData──→ 待发队列 → 写线程 → 上游
    //   客户端 ──FIN──→ stack ──onTcpClose─→ 关闭上游
    //
    // **为什么所有 IO 都必须离开协议栈线程**：
    // `Handler` 回调是在 `Runner.mu` 持锁、`handlePacket` 内部同步调用的。
    // 如果在回调里直接 `connect()`（DNS 解析 + TCP 握手，最坏十几秒）
    // 或 `write()`（上游缓冲满时阻塞），整个 TUN 数据面会卡死 ——
    // 所有连接一起掉线。所以回调只做「入队 + 唤醒」，真正的 IO 在独立线程。
    //
    // 同理，回调里也**不能**调用 `runner.resetTcp` 这类要拿 `Runner.mu` 的方法，
    // 那会自锁死（std 的 Mutex 不可重入）。

    const tcp = tcp_stack.tcp_proto;
    const ip = tcp_stack.ip_proto;
    const stack_mod = tcp_stack.stack;

    const outbound = proxy;
    const config = main.config;

    const ipnet = router;


    /// 一条 TUN 侧 TCP 连接对应的上游
    pub const TcpUpstream = struct {
        key: tcp.Key,
        /// 拨号完成后填入；拨号期间为 null
        conn: ?outbound.Conn = null,
        /// 待写往上游的字节（协议栈线程追加，写线程消费）
        pending: std.ArrayList(u8) = .empty,
        /// 连接是否还活着（false 时写线程退出）
        alive: bool = true,
        /// 客户端已发 FIN：写完剩余数据后 shutdown
        want_close: bool = false,
        /// 拨号失败标记（写线程据此退出，不再等待）
        failed: bool = false,
        /// 引用计数（tcp_ups 占 1，各运行线程各占 1）
        ref_count: usize = 2,
    };

    /// 一条 UDP 映射
    pub const UdpMapping = struct {
        key: ip.UdpKey,
        /// 拨号完成前为 null
        fd: ?net.Handle = null,
        pending: std.ArrayList(u8) = .empty,
        alive: bool = true,
        failed: bool = false,
    };

    pub const Glue = struct {
        alloc: std.mem.Allocator,
        runner: *tun_runner.Runner,
        /// 与 runtime.Core 共用的路由/配置（只读）
        cfg: *config.Config,
        router: *router.Router,
        cooldown: *router.CooldownPool,
        tls_ctx: ?outbound.TlsContext = null,
        pool: ?*dns.Pool = null,

        /// 当前节点名（settings 里可热切换）
        node_name: []const u8 = "",

        mu: net.Mutex = .{},
        /// 有待写数据 / 状态变化时唤醒写线程
        cond: net.Condition = .{},

        tcp_ups: std.ArrayList(*TcpUpstream) = .empty,
        udp_maps: std.ArrayList(*UdpMapping) = .empty,

        /// 已启动的连接线程数（读 + 写各算一个）。
        ///
        /// **为什么需要它**：`deinit()` 直接 `destroy(u)` 时，读/写线程可能
        /// 还在 `u` 上跑 —— 它们下一秒就会访问已释放内存（测试里表现为
        /// 随机 "memory leaked" 或段错误，生产里就是随机崩溃）。
        /// 光把 `alive = false` 不够：线程要**真的退出**才算安全。
        /// 这里用计数器 + 条件变量做一次「等所有线程退出」的栅栏。
        live_threads: usize = 0,
        /// 线程退出时唤醒等待者
        exit_cond: net.Condition = .{},

        pub fn init(
            alloc: std.mem.Allocator,
            runner: *tun_runner.Runner,
            cfg: *config.Config,
            rt: *router.Router,
            cool: *router.CooldownPool,
        ) Glue {
            return .{
                .alloc = alloc,
                .runner = runner,
                .cfg = cfg,
                .router = rt,
                .cooldown = cool,
            };
        }

        /// 关闭所有上游。调用方必须保证此后没有新的回调进来
        /// （即 TUN 主循环已经停止）。
        ///
        /// **会阻塞等待后台线程退出**。顺序是：
        /// 1. 置 `alive = false` 并关闭 socket —— 让阻塞在 read/write 上的线程
        ///    立刻拿到错误返回
        /// 2. 广播条件变量，唤醒阻塞在 `cond.wait` 的写线程
        /// 3. 等 `live_threads` 归零 —— 此时线程已全部离开 `u`
        /// 4. 才真正 `destroy(u)` / 释放队列
        ///
        /// 少了第 3 步就是 use-after-free：线程仍在用 `u->pending`，
        /// 主线程已经把它 deinit 掉了。
        pub fn deinit(self: *Glue) void {
            self.mu.lock();
            for (self.tcp_ups.items) |u| {
                u.alive = false;
                if (u.conn) |c| c.stream.close();
            }
            for (self.udp_maps.items) |m| {
                m.alive = false;
                if (m.fd) |fd| net.close(fd);
            }
            self.cond.broadcast();
            self.mu.unlock();

            // 等所有后台线程退出。加超时是为了不在测试/退出路径上永久挂死：
            // 5 秒还没退完说明有线程卡在不可中断的 IO 上，
            // 这时继续释放会崩，不如先返回、让进程退出时由 OS 回收。
            self.mu.lock();
            var waited_ms: u64 = 0;
            while (self.live_threads > 0 and waited_ms < 5000) {
                self.exit_cond.timedWait(&self.mu, 50 * std.time.ns_per_ms) catch {};
                waited_ms += 50;
            }
            const leftover = self.live_threads;
            self.mu.unlock();

            if (leftover > 0) {
                std.debug.print(
                    "[glue] 警告: {d} 个后台线程未在 5s 内退出，跳过资源释放以免崩溃\n",
                    .{leftover},
                );
                return;
            }

            // 到这里所有线程都已退出，可以安全释放
            for (self.tcp_ups.items) |u| {
                self.releaseTcp(u);
            }
            for (self.udp_maps.items) |m| {
                m.pending.deinit(self.alloc);
                self.alloc.destroy(m);
            }
            self.tcp_ups.deinit(self.alloc);
            self.udp_maps.deinit(self.alloc);
        }

        fn releaseTcp(self: *Glue, up: *TcpUpstream) void {
            self.mu.lock();
            up.ref_count -= 1;
            const destroy_now = (up.ref_count == 0);
            self.mu.unlock();
            if (destroy_now) {
                up.pending.deinit(self.alloc);
                self.alloc.destroy(up);
            }
        }

        /// 后台线程登记/注销。成对调用，注销时唤醒 `deinit` 的等待。
        fn threadEnter(self: *Glue) void {
            self.mu.lock();
            self.live_threads += 1;
            self.mu.unlock();
        }

        fn threadExit(self: *Glue) void {
            self.mu.lock();
            self.live_threads -= 1;
            const done = self.live_threads == 0;
            self.mu.unlock();
            if (done) self.exit_cond.broadcast();
        }

        pub fn handler(self: *Glue) stack_mod.Handler {
            return .{
                .ctx = self,
                .onTcpOpen = onTcpOpen,
                .onTcpData = onTcpData,
                .onTcpClose = onTcpClose,
                .onUdpData = onUdpData,
            };
        }

        pub fn tcpCount(self: *Glue) usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.tcp_ups.items.len;
        }

        // ------------------------------------------------------------------
        // 路由决策
        // ------------------------------------------------------------------

        /// Fake-IP 反查：TUN 侧只有 IP，但规则需要域名
        fn lookupFakeIp(self: *Glue, dst_ip: [4]u8) ?[]const u8 {
            const p = self.pool orelse return null;
            const v4 = ipToU32(dst_ip);
            if (!p.isFakeIp(v4)) return null;
            return p.lookup(v4);
        }

        fn decide(self: *Glue, dst_ip: [4]u8, host: ?[]const u8) router.Decision {
            return switch (self.cfg.mode) {
                .direct => .{ .action = .direct, .matched = "mode:direct" },
                .global => .{ .action = .proxy, .node = self.node_name, .matched = "mode:global" },
                .rule => blk: {
                    if (host) |h| break :blk self.router.decideByDomain(h, self.node_name);
                    break :blk self.router.decideByIp(.{ .v4 = ipToU32(dst_ip) }, self.node_name);
                },
            };
        }

        // ------------------------------------------------------------------
        // TCP 回调（协议栈线程内，只入队不阻塞）
        // ------------------------------------------------------------------

        fn onTcpOpen(ctx: *anyopaque, key: tcp.Key) anyerror!void {
            const self: *Glue = @ptrCast(@alignCast(ctx));
            try self.openTcp(key);
        }

        fn openTcp(self: *Glue, key: tcp.Key) !void {
            const up = try self.alloc.create(TcpUpstream);
            up.* = .{ .key = key };

            self.mu.lock();
            try self.tcp_ups.append(self.alloc, up);
            self.mu.unlock();

            // 拨号必须离开协议栈线程，否则 DNS/握手期间整条 TUN 停摆
            self.threadEnter();
            const th = std.Thread.spawn(.{}, connThread, .{ self, up }) catch {
                self.threadExit();
                self.removeTcp(up, true);
                return;
            };
            th.detach();
        }

        /// 拨号 + 写循环（独立线程）
        fn connThread(self: *Glue, up: *TcpUpstream) void {
            defer {
                self.releaseTcp(up);
                self.threadExit();
            }
            self.connThreadInner(up);
        }

        fn connThreadInner(self: *Glue, up: *TcpUpstream) void {
            const fake_host = self.lookupFakeIp(up.key.dst_ip);
            const decision = self.decide(up.key.dst_ip, fake_host);

            if (decision.action == .reject) {
                self.failTcp(up, true);
                return;
            }

            var ip_buf: [16]u8 = undefined;
            const host = fake_host orelse std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                up.key.dst_ip[0], up.key.dst_ip[1], up.key.dst_ip[2], up.key.dst_ip[3],
            }) catch {
                self.failTcp(up, true);
                return;
            };
            const target = outbound.Target{ .host = host, .port = up.key.dst_port };

            var conn: outbound.Conn = undefined;
            if (decision.action == .direct) {
                conn = outbound.connectDirect(self.alloc, target) catch {
                    self.failTcp(up, true);
                    return;
                };
            } else {
                const node_name = if (decision.node.len > 0) decision.node else self.node_name;
                if (self.cfg.findNode(node_name) orelse self.cfg.defaultNode()) |node| {
                    if (self.cooldown.isCooling(node.name)) {
                        conn = outbound.connectDirect(self.alloc, target) catch {
                            self.failTcp(up, true);
                            return;
                        };
                    } else {
                        conn = outbound.connect(self.alloc, node, target, self.tls_ctx) catch {
                            self.cooldown.markFail(node.name, 5000);
                            self.failTcp(up, true);
                            return;
                        };
                    }
                } else {
                    // 没有节点：降级直连，而不是让连接挂死
                    conn = outbound.connectDirect(self.alloc, target) catch {
                        self.failTcp(up, true);
                        return;
                    };
                }
            }

            // 发送协议握手字节（VLESS 请求头 / WS 升级）
            if (conn.preamble.len > 0) {
                conn.stream.writeAll(conn.preamble) catch {
                    conn.stream.close();
                    self.failTcp(up, true);
                    return;
                };
                self.alloc.free(conn.preamble);
                conn.preamble = "";
            }

            self.mu.lock();
            if (!up.alive) {
                self.mu.unlock();
                conn.stream.close();
                return;
            }
            up.conn = conn;
            self.mu.unlock();

            // 读线程：上游 → 协议栈 → TUN
            self.mu.lock();
            up.ref_count += 1;
            self.mu.unlock();
            self.threadEnter();
            const rt = std.Thread.spawn(.{}, readThread, .{ self, up }) catch {
                self.mu.lock();
                up.ref_count -= 1;
                self.mu.unlock();
                self.threadExit();
                conn.stream.close();
                self.failTcp(up, false);
                return;
            };
            rt.detach();

            self.writeLoop(up);
        }

        /// 把待发队列写到上游
        fn writeLoop(self: *Glue, up: *TcpUpstream) void {
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(self.alloc);

            while (true) {
                self.mu.lock();
                while (up.alive and up.pending.items.len == 0 and !up.want_close) {
                    self.cond.wait(&self.mu);
                }
                if (!up.alive) {
                    self.mu.unlock();
                    break;
                }
                buf.clearRetainingCapacity();
                buf.appendSlice(self.alloc, up.pending.items) catch {
                    self.mu.unlock();
                    break;
                };
                up.pending.clearRetainingCapacity();
                const closing = up.want_close;
                const conn = up.conn orelse {
                    self.mu.unlock();
                    break;
                };
                self.mu.unlock();

                if (buf.items.len > 0) {
                    conn.stream.writeAll(buf.items) catch {
                        up.alive = false;
                        break;
                    };
                }
                if (closing) {
                    conn.stream.shutdownSend();
                    break;
                }
            }

            self.mu.lock();
            const c = up.conn;
            up.alive = false;
            self.mu.unlock();
            if (c) |conn| conn.stream.shutdownSend();
        }

        fn readThread(self: *Glue, up: *TcpUpstream) void {
            defer {
                self.releaseTcp(up);
                self.threadExit();
            }
            var buf: [16 * 1024]u8 = undefined;

            while (true) {
                self.mu.lock();
                const conn = up.conn orelse {
                    self.mu.unlock();
                    break;
                };
                const alive = up.alive;
                self.mu.unlock();
                if (!alive) break;

                const n = conn.stream.read(&buf) catch break;
                if (n == 0) break; // 上游正常关闭
                self.runner.pushUpstream(up.key, buf[0..n]);
            }

            // 上游结束：给客户端发 FIN，并回收表项
            self.runner.closeTcpFromUpstream(up.key);
            self.removeTcp(up, false);
        }

        fn failTcp(self: *Glue, up: *TcpUpstream, send_rst: bool) void {
            if (send_rst) self.runner.resetTcp(up.key);
            self.removeTcp(up, true);
        }

        /// 从表中移除并释放。`close_stream` 表示需要关掉上游 socket
        /// （读线程自己退出时不必重复关）。
        fn removeTcp(self: *Glue, up: *TcpUpstream, close_stream: bool) void {
            var removed = false;
            self.mu.lock();
            var i: usize = 0;
            while (i < self.tcp_ups.items.len) : (i += 1) {
                if (self.tcp_ups.items[i] == up) {
                    _ = self.tcp_ups.orderedRemove(i);
                    removed = true;
                    break;
                }
            }
            up.alive = false;
            const conn = up.conn;
            self.mu.unlock();
            self.cond.broadcast();

            if (close_stream) {
                if (conn) |c| c.stream.close();
            }
            if (removed) {
                self.releaseTcp(up);
            }
        }

        fn onTcpData(ctx: *anyopaque, key: tcp.Key, data: []const u8) anyerror!void {
            const self: *Glue = @ptrCast(@alignCast(ctx));
            self.mu.lock();
            defer self.mu.unlock();
            for (self.tcp_ups.items) |up| {
                if (tcp.Key.eql(up.key, key)) {
                    // 只入队：这里在协议栈线程里，不能做 IO
                    up.pending.appendSlice(self.alloc, data) catch return error.OutOfMemory;
                    self.cond.signal();
                    return;
                }
            }
        }

        fn onTcpClose(ctx: *anyopaque, key: tcp.Key) void {
            const self: *Glue = @ptrCast(@alignCast(ctx));
            self.mu.lock();
            defer self.mu.unlock();
            for (self.tcp_ups.items) |up| {
                if (tcp.Key.eql(up.key, key)) {
                    up.want_close = true;
                    self.cond.signal();
                    return;
                }
            }
        }

        // ------------------------------------------------------------------
        // UDP 回调
        // ------------------------------------------------------------------

        fn onUdpData(ctx: *anyopaque, key: ip.UdpKey, data: []const u8) anyerror!void {
            const self: *Glue = @ptrCast(@alignCast(ctx));
            self.mu.lock();
            for (self.udp_maps.items) |m| {
                if (ip.UdpKey.eql(m.key, key)) {
                    m.pending.appendSlice(self.alloc, data) catch {
                        self.mu.unlock();
                        return error.OutOfMemory;
                    };
                    self.mu.unlock();
                    self.cond.signal();
                    return;
                }
            }

            const m = self.alloc.create(UdpMapping) catch {
                self.mu.unlock();
                return error.OutOfMemory;
            };
            m.* = .{ .key = key };
            m.pending.appendSlice(self.alloc, data) catch {
                self.alloc.destroy(m);
                self.mu.unlock();
                return error.OutOfMemory;
            };
            self.udp_maps.append(self.alloc, m) catch {
                m.pending.deinit(self.alloc);
                self.alloc.destroy(m);
                self.mu.unlock();
                return error.OutOfMemory;
            };
            self.mu.unlock();

            self.threadEnter();
            const th = std.Thread.spawn(.{}, udpThread, .{ self, m }) catch {
                self.threadExit();
                self.removeUdp(m);
                return;
            };
            th.detach();
        }

        fn udpThread(self: *Glue, m: *UdpMapping) void {
            defer self.threadExit();
            const dst = net.Address.initIp4(m.key.dst_ip, m.key.dst_port);
            const bind_addr = net.Address.parseIp4("0.0.0.0", 0) catch {
                self.removeUdp(m);
                return;
            };
            const fd = net.udpBind(bind_addr) catch {
                self.removeUdp(m);
                return;
            };
            net.udpConnect(fd, dst) catch {
                net.close(fd);
                self.removeUdp(m);
                return;
            };

            self.mu.lock();
            if (!m.alive) {
                self.mu.unlock();
                net.close(fd);
                return;
            }
            m.fd = fd;
            self.mu.unlock();

            // 收线程：上游 UDP → 客户端
            const rt = std.Thread.spawn(.{}, udpReadThread, .{ self, m, fd }) catch {
                net.close(fd);
                self.removeUdp(m);
                return;
            };
            rt.detach();

            // 发：把队列里的数据报按序发出
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(self.alloc);
            while (true) {
                self.mu.lock();
                while (m.alive and m.pending.items.len == 0) self.cond.wait(&self.mu);
                if (!m.alive) {
                    self.mu.unlock();
                    break;
                }
                buf.clearRetainingCapacity();
                buf.appendSlice(self.alloc, m.pending.items) catch {
                    self.mu.unlock();
                    break;
                };
                m.pending.clearRetainingCapacity();
                self.mu.unlock();

                if (buf.items.len > 0) _ = net.udpSend(fd, buf.items) catch {};
            }
        }

        fn udpReadThread(self: *Glue, m: *UdpMapping, fd: net.Handle) void {
            var buf: [8 * 1024]u8 = undefined;
            while (true) {
                const n = net.udpRecv(fd, &buf) catch break;
                if (n == 0) continue;
                self.runner.pushUdp(m.key, buf[0..n]);
            }
            self.removeUdp(m);
        }

        fn removeUdp(self: *Glue, m: *UdpMapping) void {
            self.mu.lock();
            var i: usize = 0;
            while (i < self.udp_maps.items.len) : (i += 1) {
                if (self.udp_maps.items[i] == m) {
                    _ = self.udp_maps.orderedRemove(i);
                    break;
                }
            }
            m.alive = false;
            const fd = m.fd;
            self.mu.unlock();
            self.cond.broadcast();

            if (fd) |h| net.close(h);
            m.pending.deinit(self.alloc);
            self.alloc.destroy(m);
        }
    };

    fn ipToU32(ip4: [4]u8) u32 {
        return (@as(u32, ip4[0]) << 24) |
            (@as(u32, ip4[1]) << 16) |
            (@as(u32, ip4[2]) << 8) |
            @as(u32, ip4[3]);
    }

    // ============================ 测试 ============================

    const tun_stack = tcp_stack.tun_stack;
    const tun_conn = tcp_stack.tun_conn;

    /// 捕获回写 TUN 的报文
    const Capture = struct {
        pkts: std.ArrayList([64]u8) = .empty,
        lens: std.ArrayList(usize) = .empty,
        mu: net.Mutex = .{},
        cond: net.Condition = .{},
        alloc: std.mem.Allocator,

        fn onTx(ctx: *anyopaque, pkt: []const u8) void {
            const self: *Capture = @ptrCast(@alignCast(ctx));
            self.mu.lock();
            defer self.mu.unlock();
            if (pkt.len <= 64) {
                var b: [64]u8 = undefined;
                @memcpy(b[0..pkt.len], pkt);
                self.pkts.append(self.alloc, b) catch return;
                self.lens.append(self.alloc, pkt.len) catch return;
            }
            self.cond.broadcast();
        }

        /// 等待包含指定子串的 TCP 载荷
        fn waitForPayload(self: *Capture, needle: []const u8, timeout_ms: u64) ?[]const u8 {
            const deadline = net.milliTimestamp() + @as(i64, @intCast(timeout_ms));
            self.mu.lock();
            defer self.mu.unlock();
            while (true) {
                for (self.pkts.items, 0..) |*p, i| {
                    const pkt = p[0..self.lens.items[i]];
                    const iph = tun_stack.parseIpv4(pkt) orelse continue;
                    if (iph.proto != tun_stack.IPPROTO_TCP) continue;
                    const payload = tun_conn.tcpPayload(pkt) orelse continue;
                    if (std.mem.indexOf(u8, payload, needle) != null) return payload;
                }
                const now = net.milliTimestamp();
                if (now >= deadline) return null;
                self.cond.timedWait(&self.mu, 100 * std.time.ns_per_ms) catch {};
            }
        }
    };



};

// ==================== 主 TUN 抽象实现 ====================







// 接管层：平台抽象 + 后端探测。
//
// **修复原 Rust 版的问题**：`available()` 在 Windows 上恒返回 `true`，
// 即使 `wintun.dll` 不存在也会声称「可用」，导致 `pick_backend()`
// 返回一个根本建不出网卡的后端，用户看到「接管可用但启动失败」。
//
// 本实现：
// - `available()` 做**真实探测**（文件存在性 / 设备可打开性 / 权限）
// - 未实现的后端明确返回 `error.NotImplemented`，不再假装成功
// - 提供 fd 直通（Android VpnService / 鸿蒙 vpnExtension）

/// Linux 专属实现只在 Linux 目标上参与编译，
/// 否则 `std.posix.socket` / `linux.ioctl` 等符号在 Windows 上会编译失败。
const linux_impl = tun_linux;
const wintun_tun_mod = wintun_tun;
const wintun_netcfg_mod = wintun_netcfg;
const wintun_mod = wintun;

pub const BackendKind = enum {
    wintun,
    linux_tun,
    utun,
    vpn_fd,

    pub fn name(self: BackendKind) []const u8 {
        return switch (self) {
            .wintun => "wintun",
            .linux_tun => "linux-tun",
            .utun => "utun",
            .vpn_fd => "vpnfd",
        };
    }

    pub fn label(self: BackendKind) []const u8 {
        return switch (self) {
            .wintun => "WinTun 虚拟网卡（Windows 11）",
            .linux_tun => "Linux TUN + 路由",
            .utun => "macOS utun + pf",
            .vpn_fd => "移动端 VPN fd",
        };
    }
};

pub const TunError = error{
    NotImplemented,
    PermissionDenied,
    DeviceMissing,
    CreateFailed,
    ConfigureFailed,
    NoBackend,
    // Linux 实现可能返回的细粒度错误
    InvalidName,
    OpenFailed,
    IoctlFailed,
    ControlSocketFailed,
};

pub const TunConfig = struct {
    name: []const u8 = "aether-tun0",
    mtu: u32 = 1400,
    /// TUN 网卡自身的 IPv4 地址（CIDR），例："198.18.0.1/15"
    ipv4: []const u8 = "198.18.0.1/15",
    /// Fake-IP 段
    fake_ip_range: []const u8 = "198.18.0.0/15",
    /// DNS
    dns: []const u8 = "198.18.0.1",
    /// 接管全部流量
    route_all: bool = true,
};

/// 平台标签（供 UI 展示与能力矩阵）
pub fn platformTag() []const u8 {
    return switch (builtin.os.tag) {
        .windows => "windows",
        .macos => "macos",
        .linux => if (builtin.abi == .android) "android" else "linux",
        else => "unknown",
    };
}

/// 本平台是否支持透明接管
pub fn supportsTakeover() bool {
    return switch (builtin.os.tag) {
        .windows, .macos, .linux => true,
        else => false,
    };
}

/// 真实探测某个后端是否可用。
///
/// Windows：检查 wintun.dll 是否在可执行文件目录/系统目录；
/// Linux：检查 /dev/net/tun 是否存在且可打开；
/// macOS：检查是否以 root 运行（utun 需要 root）。
pub fn probe(kind: BackendKind) bool {
    return switch (kind) {
        .wintun => probeWintun(),
        .linux_tun => probeLinuxTun(),
        .utun => probeUtun(),
        .vpn_fd => false, // 只有原生侧显式传 fd 时才可用
    };
}

/// 该后端是否**真的实现**了（能建立网卡并收发包）。
///
/// 这是与 `probe()` 分开的两个概念：
/// - `probe()` = 运行环境是否具备条件（驱动文件在不在、设备能不能打开）
/// - `implemented()` = 这段代码有没有真的实现
///
/// **为什么要分开**：曾经 `available()` 只看驱动文件是否存在，
/// 于是仓库里放着的 `WinDivert.dll` 让 `available` 变成 true，
/// 上层据此显示「全局接管可用」，而代码里根本没有一行 WinDivert 调用 ——
/// 用户看到的是「接管已启用」，实际一点流量都没接管。
/// 现在 `pick()` 只返回 `implemented()` 为真且 `probe()` 通过的后端。
pub fn implemented(kind: BackendKind) bool {
    return switch (kind) {
        // Linux：/dev/net/tun + TUNSETIFF + SIOCSIF* 已实现（见 tun_linux.zig）
        .linux_tun => builtin.os.tag == .linux,
        // Windows：wintun 动态加载 + ring buffer + 网卡配置已实现（见 wintun*.zig）
        .wintun => builtin.os.tag == .windows,
        // macOS：utun 还没接入
        .utun => false,
        // vpn_fd 由原生侧传 fd，属于「已实现」的直通路径
        .vpn_fd => true,
    };
}

/// 探测 wintun 是否真的可用：**实际 LoadLibrary 一遍**。
///
/// 只检查文件是否存在不够：架构不匹配的 DLL（例如 32 位版）文件在，
/// 但 `LoadLibrary` 会失败。提前加载能把问题暴露在启动时而不是接管时。
fn probeWintun() bool {
    if (builtin.os.tag != .windows) return false;
    var api = wintun_mod.Wintun.load() catch return false;
    api.deinit();
    return true;
}

/// 探测结果的细分状态。
///
/// **为什么要分这么细**：TUN 接管天然需要特权。如果只返回一个 bool，
/// 「没装 TUN 驱动」和「忘了 sudo」会得到同一个结果 false，
/// 用户看到的提示就会是「本平台无可用接管后端」——而实际上
/// 只要 `sudo` 重跑一次就好了。这两件事必须分开告诉用户。
pub const Probe = enum {
    /// 设备存在且当前身份可访问
    ready,
    /// 设备文件存在，但当前身份没有权限（需要 root / CAP_NET_ADMIN）
    permission_denied,
    /// 设备文件不存在（内核模块没加载，或不是 Linux）
    device_missing,
    /// 该平台没有这个后端
    unsupported,

    pub fn ok(self: Probe) bool {
        return self == .ready;
    }

    pub fn reason(self: Probe) []const u8 {
        return switch (self) {
            .ready => "可用",
            .permission_denied => if (builtin.os.tag == .windows)
                "需要管理员权限（右键「以管理员身份运行」）"
            else
                "需要 root 权限（请用 sudo 运行）",
            .device_missing => "设备不存在（检查内核模块，如 modprobe tun）",
            .unsupported => "当前平台不支持",
        };
    }
};

fn probeLinuxTun() bool {
    if (builtin.os.tag != .linux) return false;
    const f = std.fs.openFileAbsolute("/dev/net/tun", .{ .mode = .read_write }) catch return false;
    f.close();
    return true;
}

/// Linux TUN 的细粒度探测
fn probeLinuxTunDetail() Probe {
    if (builtin.os.tag != .linux) return .unsupported;
    const f = std.fs.openFileAbsolute("/dev/net/tun", .{ .mode = .read_write }) catch |e| {
        return switch (e) {
            error.AccessDenied => .permission_denied,
            error.FileNotFound, error.NotDir => .device_missing,
            else => .device_missing,
        };
    };
    f.close();
    return .ready;
}

fn probeUtun() bool {
    if (builtin.os.tag != .macos) return false;
    // utun 需要 root
    return std.posix.geteuid() == 0;
}

/// 列出本平台的后端及可用性（真实探测结果）
pub fn listBackends(alloc: std.mem.Allocator) ![]BackendInfo {
    var list = std.ArrayList(BackendInfo).empty;
    errdefer list.deinit(alloc);

    switch (builtin.os.tag) {
        .windows => {
            try list.append(alloc, info(.wintun, true));
        },
        .linux => {
            if (builtin.abi == .android) {
                try list.append(alloc, info(.vpn_fd, false));
            } else {
                try list.append(alloc, info(.linux_tun, true));
            }
        },
        .macos => {
            try list.append(alloc, info(.utun, true));
        },
        else => {},
    }
    return list.toOwnedSlice(alloc);
}

fn info(kind: BackendKind, needs_root: bool) BackendInfo {
    const detail = probeDetail(kind);
    const impl = implemented(kind);
    return .{
        .kind = kind,
        // 「可用」= 环境具备 **且** 代码实现了。
        // 只有其一不能叫可用，否则 UI 会显示一个点了没反应的开关。
        .available = detail.ok() and impl,
        .env_ready = detail.ok(),
        .implemented = impl,
        .needs_root = needs_root,
        .detail = detail,
    };
}

/// 当前平台做 TUN 接管是否**可能**需要提权。
///
/// 用于启动早期判断「要不要先提权再说」：这个判断必须**廉价且无副作用**，
/// 不能去建网卡、不能弹窗。真正能不能接管由 `listBackends()` 决定。
///
/// 返回 true 只代表「值得先提权试一次」，不代表提权后一定成功
/// （比如 Windows 上根本没放 wintun.dll，提权也没用）。
pub fn mayNeedElevation() bool {
    return switch (builtin.os.tag) {
        .windows, .linux, .macos => true,
        else => false,
    };
}

/// 各后端的细粒度探测
///
/// **顺序很关键**：先判断「DLL/设备在不在」，再判断「有没有权限」。
/// 反过来的话，没装 DLL 的非管理员用户会被告知「请提权」，
/// 提权后仍然失败 —— 又是一种误导。
fn probeDetail(kind: BackendKind) Probe {    return switch (kind) {
        .linux_tun => probeLinuxTunDetail(),
        .utun => if (builtin.os.tag == .macos)
            (if (std.posix.geteuid() == 0) .ready else .permission_denied)
        else
            .unsupported,
        .wintun => blk: {
            if (builtin.os.tag != .windows) break :blk .unsupported;
            // 1) DLL 能否真正加载（含架构匹配）
            if (!probe(.wintun)) break :blk .device_missing;
            // 2) 建网卡要管理员
            if (!wintun_netcfg_mod.isElevated()) break :blk .permission_denied;
            break :blk .ready;
        },
        .vpn_fd => .unsupported,
    };
}

pub const BackendInfo = struct {
    kind: BackendKind,
    /// 真正可用（环境具备 + 已实现）
    available: bool,
    /// 运行环境是否具备条件（驱动在、设备可打开）
    env_ready: bool = false,
    /// 代码是否实现了该后端
    implemented: bool = false,
    needs_root: bool,
    /// 细分状态，便于把「没权限」和「没设备」分开告诉用户
    detail: Probe = .unsupported,
};

/// 给用户看的一句话解释：为什么不可用
pub fn explain(b: BackendInfo) []const u8 {
    if (b.available) return "可用";
    if (!b.implemented) return "本平台尚未实现";
    return b.detail.reason();
}

/// 选一个真正可用的后端
pub fn pick(alloc: std.mem.Allocator) ?BackendKind {
    const list = listBackends(alloc) catch return null;
    defer alloc.free(list);
    for (list) |b| {
        if (b.available) return b.kind;
    }
    return null;
}

/// TUN 句柄
pub const Handle = struct {
    kind: BackendKind,
    /// POSIX 上的文件描述符；Windows wintun 不用它（填 0）
    fd: i64,
    owns_fd: bool = true,
    /// Windows wintun 设备（Linux/macOS 为 null）
    wintun_dev: ?*wintun_tun_mod.Device = null,

    /// 从原生侧传入的 fd 构造（Android VpnService / 鸿蒙 vpnExtension）
    /// 所有权约定：fd 由原生侧创建，Zig 侧只借不关。
    pub fn fromRawFd(fd: i64) Handle {
        return .{ .kind = .vpn_fd, .fd = fd, .owns_fd = false };
    }

    pub fn close(self: Handle) void {
        if (self.wintun_dev) |dev| {
            wintun_tun_mod.destroy(dev, std.heap.page_allocator);
            return;
        }
        if (self.owns_fd and builtin.os.tag != .windows) {
            std.posix.close(@intCast(self.fd));
        }
    }
};

/// 建立 TUN 设备。
///
/// Linux：`/dev/net/tun` → `TUNSETIFF` → 配置 IP/掩码/MTU → 启用
/// Windows：`wintun.dll` 动态加载 → `WintunCreateAdapter` → `WintunStartSession`
/// macOS：未接入
pub fn establish(alloc: std.mem.Allocator, cfg: TunConfig) TunError!Handle {
    switch (builtin.os.tag) {
        .linux => {
            // 按探测细节返回准确错误：没权限 ≠ 没设备
            switch (probeLinuxTunDetail()) {
                .ready => {},
                .permission_denied => return error.PermissionDenied,
                .device_missing => return error.DeviceMissing,
                .unsupported => return error.NoBackend,
            }
            return linux_impl.Establisher.create(cfg);
        },
        .windows => {
            // Windows 上没有「设备文件」，缺的是 DLL
            if (!probe(.wintun)) return error.DeviceMissing;

            const dev = wintun_tun_mod.establish(alloc, cfg.name, 0) catch |e| {
                return switch (e) {
                    error.DllNotFound => error.DeviceMissing,
                    error.AdapterCreateFailed, error.SessionStartFailed => error.CreateFailed,
                    else => error.CreateFailed,
                };
            };
            errdefer wintun_tun_mod.destroy(dev, alloc);

            // **必须给网卡配 IP**：WintunCreateAdapter 只建一块「空网卡」，
            // 没有地址。不配地址的话：
            //   - 协议栈回的包找不到出口
            //   - `route add ... if <idx>` 指向一块无地址网卡，路由不生效
            // 之前这段缺失，导致 Windows 接管「建立了网卡、配好了路由、
            // 却一个包都不通」，且没有任何报错。
            const idx = wintun_netcfg_mod.findInterfaceIndex(alloc, cfg.name) catch |e| {
                std.debug.print("[tun] 查网卡接口索引失败: {any}\n", .{e});
                return error.CreateFailed;
            };
            wintun_netcfg_mod.setInterfaceAddress(idx, cfg.ipv4) catch |e| {
                std.debug.print("[tun] 配置网卡地址 {s} 失败: {any}\n", .{ cfg.ipv4, e });
                return error.CreateFailed;
            };
            wintun_netcfg_mod.setInterfaceMtu(idx, cfg.mtu) catch |e| {
                std.debug.print("[tun] 配置 MTU {d} 失败: {any}\n", .{ cfg.mtu, e });
                return error.CreateFailed;
            };

            // 句柄不能放进 fd（i64），存指针
            return .{ .kind = .wintun, .fd = 0, .owns_fd = false, .wintun_dev = dev };
        },
        .macos => {
            if (!probe(.utun)) return error.PermissionDenied;
            return error.NotImplemented;
        },
        else => return error.NoBackend,
    }
}

/// 读一个 IP 包。Windows 走 wintun ring buffer，其余走 fd。
pub fn readPacket(h: Handle, buf: []u8) !usize {
    if (h.wintun_dev) |dev| {
        return dev.readPacket(buf) catch return error.DeviceMissing;
    }
    if (builtin.os.tag == .windows) return error.NotImplemented;
    return std.posix.read(@intCast(h.fd), buf) catch return error.DeviceMissing;
}

/// 阻塞等待「有包可读」或超时（毫秒）。返回 false 表示可以读，true 表示超时。
///
/// Linux 走 `poll`，Windows 走 wintun 的读等待事件。
/// 没有这一步，主循环在「暂时没包」时会立刻返回 0 然后空转，
/// 一个 TUN 线程能把一个 CPU 核吃满（实测任务管理器 25% 常驻）。
pub fn waitReadable(h: Handle, timeout_ms: u32) bool {
    if (h.wintun_dev) |dev| {
        dev.waitForPacket(timeout_ms);
        return false;
    }
    if (builtin.os.tag == .windows) return false;
    var fds = [1]std.posix.pollfd{.{
        .fd = @intCast(h.fd),
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, @intCast(timeout_ms)) catch return false;
    return n == 0;
}

/// 写一个 IP 包。Windows 走 wintun ring buffer，其余走 fd。
pub fn writePacket(h: Handle, pkt: []const u8) !usize {
    if (h.wintun_dev) |dev| {
        dev.writePacket(pkt) catch return error.DeviceMissing;
        return pkt.len;
    }
    if (builtin.os.tag == .windows) return error.NotImplemented;
    return std.posix.write(@intCast(h.fd), pkt) catch return error.DeviceMissing;
}

// ============================ 测试 ============================















pub const route = tun_route;


















