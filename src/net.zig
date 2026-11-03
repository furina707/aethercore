//! 跨平台网络抽象层（TCP / UDP / Stream / Relay / BufferPool / 提权）
//!
//! 整合了原 net.zig / stream.zig / relay.zig / elevate.zig / bufferpool.zig：
//! 1. 跨平台 socket IO 原生封装（Windows ws2_32 / POSIX）
//! 2. 独立 Address 抽象（跨平台 IP 地址与端口）
//! 3. 原生同步锁 Mutex（Windows SRWLock / POSIX 原子自旋）与安全随机数生成
//! 4. 统一流 Stream 抽象与单线程 Poll 双向流中继（Relay）
//! 5. 跨平台提权辅助（Windows ShellExecuteExW runas / Linux sudo）

const std = @import("std");
const builtin = @import("builtin");

pub const is_windows = builtin.os.tag == .windows;
pub const is_posix = builtin.os.tag != .windows;

/// 平台原生 socket 句柄
pub const Handle = if (is_windows) usize else std.posix.fd_t;
pub const INVALID_HANDLE: Handle = if (is_windows) std.math.maxInt(usize) else -1;

pub const win_ws2 = struct {
    pub const AF = std.os.windows.ws2_32.AF;
    pub const SOCK = std.os.windows.ws2_32.SOCK;
    pub const SOL = std.os.windows.ws2_32.SOL;
    pub const SO = std.os.windows.ws2_32.SO;
    pub const IPPROTO = std.os.windows.ws2_32.IPPROTO;
    pub const TCP = std.os.windows.ws2_32.TCP;
    pub const timeval = std.os.windows.ws2_32.timeval;
    pub const sockaddr = std.os.windows.ws2_32.sockaddr;

    pub const INVALID_SOCKET: Handle = std.math.maxInt(usize);
    pub const SOCKET_ERROR: c_int = -1;

    pub const addrinfo = extern struct {
        flags: c_int = 0,
        family: c_int = 0,
        socktype: c_int = 0,
        protocol: c_int = 0,
        addrlen: usize = 0,
        canonname: ?[*:0]u8 = null,
        addr: ?*sockaddr = null,
        next: ?*addrinfo = null,
    };

    pub extern "ws2_32" fn socket(af: c_int, @"type": c_int, protocol: c_int) callconv(.winapi) Handle;
    pub extern "ws2_32" fn bind(s: Handle, name: *const sockaddr, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn connect(s: Handle, name: *const sockaddr, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn listen(s: Handle, backlog: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn accept(s: Handle, addr: ?*sockaddr, addrlen: ?*c_int) callconv(.winapi) Handle;
    pub extern "ws2_32" fn recv(s: Handle, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn send(s: Handle, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn recvfrom(s: Handle, buf: [*]u8, len: c_int, flags: c_int, from: ?*sockaddr, fromlen: ?*c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn sendto(s: Handle, buf: [*]const u8, len: c_int, flags: c_int, to: *const sockaddr, tolen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn closesocket(s: Handle) callconv(.winapi) c_int;
    pub extern "ws2_32" fn shutdown(s: Handle, how: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn setsockopt(s: Handle, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockname(s: Handle, name: *sockaddr, namelen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getaddrinfo(nodename: ?[*:0]const u8, servname: ?[*:0]const u8, hints: ?*const addrinfo, res: *?*addrinfo) callconv(.winapi) c_int;
    pub extern "ws2_32" fn freeaddrinfo(res: ?*addrinfo) callconv(.winapi) void;
    pub extern "ws2_32" fn WSAStartup(wVersionRequired: u16, lpWSAData: [*]u8) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSACleanup() callconv(.winapi) c_int;
};
pub const ws2 = if (is_windows) win_ws2 else struct {};

var wsa_initialized: bool = false;
pub fn ensureWinsock() void {
    if (is_windows and !wsa_initialized) {
        var data: [512]u8 = undefined;
        _ = win_ws2.WSAStartup(0x0202, &data);
        wsa_initialized = true;
    }
}

pub const IoError = error{
    RecvFailed,
    SendFailed,
    ConnectionClosed,
    SocketError,
} || std.mem.Allocator.Error;

pub const UdpError = error{
    BindFailed,
    RecvFailed,
    SendFailed,
};

// ============================================================================
// 原生锁与安全随机数（解耦 Zig 0.17 std.Io 依赖）
// ============================================================================

/// 跨平台轻量互斥锁
pub const Mutex = struct {
    srw: if (is_windows) std.os.windows.SRWLOCK else void = if (is_windows) std.os.windows.SRWLOCK_INIT else {},
    atomic_lock: if (!is_windows) std.atomic.Value(u32) else void = if (!is_windows) std.atomic.Value(u32).init(0) else {},

    pub fn lock(self: *Mutex) void {
        if (is_windows) {
            std.os.windows.ntdll.RtlAcquireSRWLockExclusive(&self.srw);
        } else {
            while (self.atomic_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
                std.Thread.yield() catch {};
            }
        }
    }

    pub fn tryLock(self: *Mutex) bool {
        if (is_windows) {
            return std.os.windows.ntdll.RtlTryAcquireSRWLockExclusive(&self.srw) != .FALSE;
        } else {
            return self.atomic_lock.cmpxchgStrong(0, 1, .acquire, .monotonic) == null;
        }
    }

    pub fn unlock(self: *Mutex) void {
        if (is_windows) {
            std.os.windows.ntdll.RtlReleaseSRWLockExclusive(&self.srw);
        } else {
            self.atomic_lock.store(0, .release);
        }
    }
};

const win_cv = struct {
    extern "kernel32" fn SleepConditionVariableSRW(
        ConditionVariable: *?*anyopaque,
        SRWLock: *std.os.windows.SRWLOCK,
        dwMilliseconds: u32,
        Flags: u32,
    ) callconv(.winapi) std.os.windows.BOOL;
    extern "kernel32" fn WakeConditionVariable(
        ConditionVariable: *?*anyopaque,
    ) callconv(.winapi) void;
    extern "kernel32" fn WakeAllConditionVariable(
        ConditionVariable: *?*anyopaque,
    ) callconv(.winapi) void;
};

/// 跨平台条件变量
pub const Condition = struct {
    cv: if (is_windows) ?*anyopaque else std.atomic.Value(u32) = if (is_windows) null else std.atomic.Value(u32).init(0),

    pub fn wait(self: *Condition, mutex: *Mutex) void {
        self.timedWait(mutex, std.math.maxInt(u64)) catch {};
    }

    pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) !void {
        if (is_windows) {
            const timeout_ms: u32 = if (timeout_ns >= std.math.maxInt(u32) * std.time.ns_per_ms)
                0xFFFFFFFF
            else
                @intCast(timeout_ns / std.time.ns_per_ms);
            const ok = win_cv.SleepConditionVariableSRW(&self.cv, &mutex.srw, timeout_ms, 0);
            if (ok == .FALSE) return error.Timeout;
        } else {
            mutex.unlock();
            const start = milliTimestamp();
            const timeout_ms = timeout_ns / std.time.ns_per_ms;
            while (milliTimestamp() - start < timeout_ms) {
                std.Thread.sleep(10 * std.time.ns_per_ms);
            }
            mutex.lock();
        }
    }

    pub fn signal(self: *Condition) void {
        if (is_windows) {
            win_cv.WakeConditionVariable(&self.cv);
        }
    }

    pub fn broadcast(self: *Condition) void {
        if (is_windows) {
            win_cv.WakeAllConditionVariable(&self.cv);
        }
    }
};

/// 填充加密级安全随机字节
pub fn fillRandom(buf: []u8) void {
    if (buf.len == 0) return;
    if (is_windows) {
        const advapi32 = struct {
            extern "advapi32" fn SystemFunction036(pbBuffer: [*]u8, dwLen: u32) callconv(.winapi) u8;
        };
        _ = advapi32.SystemFunction036(buf.ptr, @intCast(buf.len));
    } else {
        std.posix.getrandom(buf) catch {
            for (buf) |*b| b.* = 0x42;
        };
    }
}

/// 获取系统单调毫秒时间戳
pub fn milliTimestamp() i64 {
    if (is_windows) {
        const kernel32 = struct {
            extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
        };
        return @intCast(kernel32.GetTickCount64());
    } else {
        var ts: std.posix.timespec = undefined;
        std.posix.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) catch return 0;
        return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, 1_000_000);
    }
}

// ============================================================================
// 通用 IP 地址抽象
// ============================================================================

pub const Address = extern union {
    any: std.posix.sockaddr,
    in: std.posix.sockaddr.in,
    in6: std.posix.sockaddr.in6,

    pub fn initIp4(bytes: [4]u8, port: u16) Address {
        var addr: Address = undefined;
        addr.in = .{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(*align(1) const u32, @ptrCast(&bytes)).*,
        };
        return addr;
    }

    pub fn initIp6(bytes: [16]u8, port: u16, flow: u32, scope: u32) Address {
        var addr: Address = undefined;
        addr.in6 = .{
            .family = std.posix.AF.INET6,
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = flow,
            .addr = bytes,
            .scope_id = scope,
        };
        return addr;
    }

    pub fn parseIp(text: []const u8, port: u16) !Address {
        if (parseIp4(text, port)) |a| return a else |_| {}
        return parseIp6(text, port);
    }

    pub fn parseIp4(text: []const u8, port: u16) !Address {
        const ip = try std.Io.net.Ip4Address.parse(text, port);
        return initIp4(ip.bytes, ip.port);
    }

    pub fn parseIp6(text: []const u8, port: u16) !Address {
        const ip = try std.Io.net.Ip6Address.parse(text, port);
        return initIp6(ip.bytes, ip.port, ip.flow, ip.interface.index);
    }

    pub fn resolveIp(host: []const u8, port: u16) !Address {
        return parseIp(host, port);
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            std.posix.AF.INET => std.mem.bigToNative(u16, self.in.port),
            std.posix.AF.INET6 => std.mem.bigToNative(u16, self.in6.port),
            else => 0,
        };
    }

    pub fn setPort(self: *Address, port: u16) void {
        switch (self.any.family) {
            std.posix.AF.INET => self.in.port = std.mem.nativeToBig(u16, port),
            std.posix.AF.INET6 => self.in6.port = std.mem.nativeToBig(u16, port),
            else => {},
        }
    }

    pub fn getOsSockLen(self: Address) std.posix.socklen_t {
        return switch (self.any.family) {
            std.posix.AF.INET => @sizeOf(std.posix.sockaddr.in),
            std.posix.AF.INET6 => @sizeOf(std.posix.sockaddr.in6),
            else => @sizeOf(std.posix.sockaddr),
        };
    }

    pub fn format(self: Address, writer: anytype) !void {
        switch (self.any.family) {
            std.posix.AF.INET => {
                const b: *const [4]u8 = @ptrCast(&self.in.addr);
                try writer.print("{d}.{d}.{d}.{d}:{d}", .{ b[0], b[1], b[2], b[3], self.getPort() });
            },
            std.posix.AF.INET6 => {
                const b = self.in6.addr;
                try writer.print("[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{d}", .{
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
                    self.getPort(),
                });
            },
            else => try writer.writeAll("unknown_address"),
        }
    }
};

// ============================================================================
// TCP 收发与连接操作
// ============================================================================

pub fn recv(h: Handle, buf: []u8) IoError!usize {
    if (buf.len == 0) return 0;
    if (is_windows) {
        const n = ws2.recv(h, buf.ptr, @intCast(buf.len), 0);
        if (n < 0) return error.RecvFailed;
        if (n == 0) return error.ConnectionClosed;
        return @intCast(n);
    } else {
        const n = std.posix.recv(h, buf, 0) catch return error.RecvFailed;
        if (n == 0) return error.ConnectionClosed;
        return n;
    }
}

pub fn send(h: Handle, buf: []const u8) IoError!usize {
    if (buf.len == 0) return 0;
    if (is_windows) {
        const n = ws2.send(h, buf.ptr, @intCast(buf.len), 0);
        if (n < 0) return error.SendFailed;
        return @intCast(n);
    } else {
        const n = std.posix.send(h, buf, 0) catch return error.SendFailed;
        return n;
    }
}

pub fn recvAll(h: Handle, buf: []u8) IoError!usize {
    var off: usize = 0;
    while (off < buf.len) {
        const n = recv(h, buf[off..]) catch |e| switch (e) {
            error.ConnectionClosed => break,
            else => return e,
        };
        if (n == 0) break;
        off += n;
    }
    return off;
}

pub fn recvExact(h: Handle, buf: []u8) IoError!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = recv(h, buf[off..]) catch |e| switch (e) {
            error.ConnectionClosed => return error.ConnectionClosed,
            else => return e,
        };
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

pub fn sendAll(h: Handle, buf: []const u8) IoError!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try send(h, buf[off..]);
        if (n == 0) return error.SendFailed;
        off += n;
    }
}

pub fn closeSocket(h: Handle) void {
    if (is_windows) {
        _ = ws2.closesocket(h);
    } else {
        std.posix.close(h);
    }
}
pub const close = closeSocket;

pub fn shutdownSocketSend(h: Handle) void {
    if (is_windows) {
        _ = ws2.shutdown(h, 1);
    } else {
        std.posix.shutdown(h, .send) catch {};
    }
}
pub const shutdownSend = shutdownSocketSend;

pub fn shutdownRecv(h: Handle) void {
    if (is_windows) {
        _ = ws2.shutdown(h, 0);
    } else {
        std.posix.shutdown(h, .recv) catch {};
    }
}

pub fn setRecvTimeout(h: Handle, ms: u32) void {
    if (is_windows) {
        var tv = ws2.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, ws2.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(ws2.timeval));
    } else {
        const tv = std.posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        std.posix.setsockopt(h, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }
}

pub fn setNoDelay(h: Handle) void {
    if (is_windows) {
        var one: c_int = 1;
        _ = ws2.setsockopt(h, ws2.IPPROTO.TCP, ws2.TCP.NODELAY, @ptrCast(&one), @sizeOf(c_int));
    } else {
        std.posix.setsockopt(h, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1))) catch {};
    }
}

pub fn tcpConnect(addr: Address) IoError!Handle {
    ensureWinsock();
    if (is_windows) {
        const h = ws2.socket(addr.any.family, ws2.SOCK.STREAM, ws2.IPPROTO.TCP);
        if (h == ws2.INVALID_SOCKET) return error.SocketError;
        errdefer _ = ws2.closesocket(h);

        if (ws2.connect(h, &addr.any, @intCast(addr.getOsSockLen())) != 0) {
            return error.SocketError;
        }
        setNoDelay(h);
        return h;
    } else {
        const h = std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP) catch return error.SocketError;
        errdefer std.posix.close(h);

        std.posix.connect(h, &addr.any, addr.getOsSockLen()) catch return error.SocketError;
        setNoDelay(h);
        return h;
    }
}

pub const Server = struct {
    listen_address: Address,
    stream: Stream,

    pub fn accept(self: *Server) !Connection {
        if (is_windows) {
            var client_addr: Address = undefined;
            var client_len: i32 = @sizeOf(Address);
            const client_sock = ws2.accept(self.stream.handle(), &client_addr.any, &client_len);
            if (client_sock == ws2.INVALID_SOCKET) return error.SocketError;
            setNoDelay(client_sock);
            return .{
                .stream = Stream.fromRaw(client_sock),
                .address = client_addr,
            };
        } else {
            var client_addr: Address = undefined;
            var client_len: std.posix.socklen_t = @sizeOf(Address);
            const client_sock = try std.posix.accept(self.stream.handle(), &client_addr.any, &client_len, 0);
            setNoDelay(client_sock);
            return .{
                .stream = Stream.fromRaw(client_sock),
                .address = client_addr,
            };
        }
    }

    pub fn deinit(self: *Server) void {
        self.stream.close();
    }
};

pub const Connection = struct {
    stream: Stream,
    address: Address,
};

pub fn listen(addr: Address, reuse: bool) !Server {
    ensureWinsock();
    if (is_windows) {
        const h = ws2.socket(addr.any.family, ws2.SOCK.STREAM, ws2.IPPROTO.TCP);
        if (h == ws2.INVALID_SOCKET) return error.SocketError;
        errdefer _ = ws2.closesocket(h);

        if (reuse) {
            var one: c_int = 1;
            _ = ws2.setsockopt(h, ws2.SOL.SOCKET, ws2.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int));
        }

        if (ws2.bind(h, &addr.any, @intCast(addr.getOsSockLen())) != 0) {
            return error.SocketError;
        }
        if (ws2.listen(h, 128) != 0) {
            return error.SocketError;
        }

        var real_addr = addr;
        if (addr.getPort() == 0) {
            var len: i32 = @sizeOf(Address);
            _ = ws2.getsockname(h, &real_addr.any, &len);
        }

        return .{
            .listen_address = real_addr,
            .stream = Stream.fromRaw(h),
        };
    } else {
        const h = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
        errdefer std.posix.close(h);

        if (reuse) {
            try std.posix.setsockopt(h, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        }

        try std.posix.bind(h, &addr.any, addr.getOsSockLen());
        try std.posix.listen(h, 128);

        var real_addr = addr;
        if (addr.getPort() == 0) {
            var len: std.posix.socklen_t = @sizeOf(Address);
            try std.posix.getsockname(h, &real_addr.any, &len);
        }

        return .{
            .listen_address = real_addr,
            .stream = Stream.fromRaw(h),
        };
    }
}

pub fn recvByte(h: Handle) IoError!u8 {
    var b: [1]u8 = undefined;
    try recvExact(h, &b);
    return b[0];
}

pub fn recvU16(h: Handle) IoError!u16 {
    var b: [2]u8 = undefined;
    try recvExact(h, &b);
    return std.mem.readInt(u16, &b, .big);
}

pub fn sendU16(h: Handle, v: u16) IoError!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    try sendAll(h, &b);
}

// ============================================================================
// UDP 操作
// ============================================================================

pub fn udpBind(addr: Address) UdpError!Handle {
    ensureWinsock();
    if (is_windows) {
        const h = ws2.socket(addr.any.family, ws2.SOCK.DGRAM, ws2.IPPROTO.UDP);
        if (h == ws2.INVALID_SOCKET) return error.BindFailed;
        if (ws2.bind(h, &addr.any, @intCast(addr.getOsSockLen())) != 0) {
            _ = ws2.closesocket(h);
            return error.BindFailed;
        }
        return h;
    } else {
        const h = std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP) catch return error.BindFailed;
        std.posix.bind(h, &addr.any, addr.getOsSockLen()) catch {
            std.posix.close(h);
            return error.BindFailed;
        };
        return h;
    }
}

pub fn udpRecvFrom(h: Handle, buf: []u8, from: *Address) UdpError!usize {
    if (is_windows) {
        var addr_len: i32 = @sizeOf(Address);
        const n = ws2.recvfrom(h, buf.ptr, @intCast(buf.len), 0, &from.any, &addr_len);
        if (n < 0) return error.RecvFailed;
        return @intCast(n);
    } else {
        var addr_len: std.posix.socklen_t = @sizeOf(Address);
        return std.posix.recvfrom(h, buf, 0, &from.any, &addr_len) catch return error.RecvFailed;
    }
}

pub fn udpSendTo(h: Handle, buf: []const u8, to: Address) UdpError!void {
    if (is_windows) {
        const n = ws2.sendto(h, buf.ptr, @intCast(buf.len), 0, &to.any, @intCast(to.getOsSockLen()));
        if (n < 0) return error.SendFailed;
    } else {
        const len: std.posix.socklen_t = to.getOsSockLen();
        _ = std.posix.sendto(h, buf, 0, &to.any, len) catch return error.SendFailed;
    }
}

pub fn getLocalAddr(h: Handle, out: *Address) UdpError!void {
    if (is_windows) {
        var len: i32 = @sizeOf(Address);
        if (ws2.getsockname(h, &out.any, &len) != 0) return error.BindFailed;
    } else {
        var len: std.posix.socklen_t = @sizeOf(Address);
        std.posix.getsockname(h, &out.any, &len) catch return error.BindFailed;
    }
}

pub fn udpConnect(h: Handle, addr: Address) UdpError!void {
    if (is_windows) {
        if (ws2.connect(h, &addr.any, @intCast(addr.getOsSockLen())) != 0) {
            return error.BindFailed;
        }
    } else {
        std.posix.connect(h, &addr.any, addr.getOsSockLen()) catch return error.BindFailed;
    }
}

pub fn udpSend(h: Handle, buf: []const u8) UdpError!void {
    if (is_windows) {
        const n = ws2.send(h, buf.ptr, @intCast(buf.len), 0);
        if (n < 0) return error.SendFailed;
    } else {
        _ = std.posix.send(h, buf, 0) catch return error.SendFailed;
    }
}

pub fn udpRecv(h: Handle, buf: []u8) UdpError!usize {
    if (is_windows) {
        const n = ws2.recv(h, buf.ptr, @intCast(buf.len), 0);
        if (n < 0) return error.RecvFailed;
        return @intCast(n);
    } else {
        return std.posix.recv(h, buf, 0) catch return error.RecvFailed;
    }
}

pub const PollFd = extern struct {
    fd: Handle,
    events: i16,
    revents: i16 = 0,
};

pub const POLL = struct {
    pub const IN: i16 = if (is_windows) 0x0100 | 0x0200 else std.posix.POLL.IN;
    pub const OUT: i16 = if (is_windows) 0x0010 else std.posix.POLL.OUT;
    pub const ERR: i16 = if (is_windows) 0x0001 else std.posix.POLL.ERR;
    pub const HUP: i16 = if (is_windows) 0x0002 else std.posix.POLL.HUP;
    pub const NVAL: i16 = if (is_windows) 0x0004 else std.posix.POLL.NVAL;
};

pub fn poll(fds: []PollFd, timeout_ms: i32) !usize {
    if (is_windows) {
        ensureWinsock();
        const win_poll = struct {
            extern "ws2_32" fn WSAPoll(fdArray: [*]PollFd, fds: u32, timeout: i32) callconv(.winapi) c_int;
        };
        const res = win_poll.WSAPoll(fds.ptr, @intCast(fds.len), timeout_ms);
        if (res < 0) return error.PollFailed;
        return @intCast(res);
    } else {
        var pfds: [64]std.posix.pollfd = undefined;
        const count = @min(fds.len, 64);
        for (0..count) |i| {
            pfds[i] = .{ .fd = fds[i].fd, .events = fds[i].events, .revents = 0 };
        }
        const res = try std.posix.poll(pfds[0..count], timeout_ms);
        for (0..count) |i| {
            fds[i].revents = pfds[i].revents;
        }
        return res;
    }
}

/// 解析域名为 IP 地址列表
pub fn getAddressList(alloc: std.mem.Allocator, host: []const u8, port: u16) ![]Address {
    if (Address.parseIp(host, port)) |a| {
        const list = try alloc.alloc(Address, 1);
        list[0] = a;
        return list;
    } else |_| {}

    if (is_windows) {
        ensureWinsock();
        const host_z = try alloc.alloc(u8, host.len + 1);
        defer alloc.free(host_z);
        @memcpy(host_z[0..host.len], host);
        host_z[host.len] = 0;
        const host_z_ptr: [*:0]const u8 = host_z[0..host.len :0].ptr;

        var port_buf: [16]u8 = undefined;
        const port_s = try std.fmt.bufPrint(port_buf[0 .. port_buf.len - 1], "{d}", .{port});
        port_buf[port_s.len] = 0;
        const port_z: [*:0]const u8 = port_buf[0..port_s.len :0].ptr;

        var hints: ws2.addrinfo = std.mem.zeroes(ws2.addrinfo);
        hints.family = ws2.AF.UNSPEC;
        hints.socktype = ws2.SOCK.STREAM;

        var res: ?*ws2.addrinfo = null;
        if (ws2.getaddrinfo(host_z_ptr, port_z, &hints, &res) != 0) {
            return error.UnknownHostName;
        }
        defer ws2.freeaddrinfo(res);

        var count: usize = 0;
        var cur = res;
        while (cur) |info| : (cur = info.next) {
            if (info.family == ws2.AF.INET or info.family == ws2.AF.INET6) count += 1;
        }
        if (count == 0) return error.UnknownHostName;

        const result = try alloc.alloc(Address, count);
        var idx: usize = 0;
        cur = res;
        while (cur) |info| : (cur = info.next) {
            if ((info.family == ws2.AF.INET or info.family == ws2.AF.INET6) and info.addr != null) {
                var a: Address = undefined;
                const src_bytes: [*]const u8 = @ptrCast(info.addr.?);
                const copy_len = @min(@as(usize, @intCast(info.addrlen)), @sizeOf(Address));
                @memcpy(std.mem.asBytes(&a)[0..copy_len], src_bytes[0..copy_len]);
                result[idx] = a;
                idx += 1;
            }
        }
        return result;
    } else {
        const host_z = try alloc.alloc(u8, host.len + 1);
        defer alloc.free(host_z);
        @memcpy(host_z[0..host.len], host);
        host_z[host.len] = 0;
        const host_z_ptr: [*:0]const u8 = host_z[0..host.len :0].ptr;

        var port_buf: [16]u8 = undefined;
        const port_s = try std.fmt.bufPrint(port_buf[0 .. port_buf.len - 1], "{d}", .{port});
        port_buf[port_s.len] = 0;
        const port_z: [*:0]const u8 = port_buf[0..port_s.len :0].ptr;

        const hints = std.posix.addrinfo{
            .flags = .{},
            .family = std.posix.AF.UNSPEC,
            .socktype = std.posix.SOCK.STREAM,
            .protocol = std.posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .next = null,
        };
        const res = try std.posix.getaddrinfo(host_z_ptr, port_z, &hints);
        defer std.posix.freeaddrinfo(res);

        var count: usize = 0;
        var cur: ?*std.posix.addrinfo = res;
        while (cur) |info| : (cur = info.next) {
            if (info.family == std.posix.AF.INET or info.family == std.posix.AF.INET6) count += 1;
        }
        if (count == 0) return error.UnknownHostName;

        const result = try alloc.alloc(Address, count);
        var idx: usize = 0;
        cur = res;
        while (cur) |info| : (cur = info.next) {
            if (info.family == std.posix.AF.INET or info.family == std.posix.AF.INET6) {
                var a: Address = undefined;
                const copy_len = @min(@as(usize, info.addrlen), @sizeOf(Address));
                const src_bytes: [*]const u8 = @ptrCast(info.addr.?);
                @memcpy(std.mem.asBytes(&a)[0..copy_len], src_bytes[0..copy_len]);
                result[idx] = a;
                idx += 1;
            }
        }
        return result;
    }
}

pub fn getProcessForPort(port: u16, out_buf: []u8) ?[]const u8 {
    if (!is_windows) return null;
    const win = std.os.windows;

    const k32 = struct {
        extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?win.HMODULE;
        extern "kernel32" fn FreeLibrary(hLibModule: win.HMODULE) callconv(.winapi) win.BOOL;
        extern "kernel32" fn GetProcAddress(hModule: win.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?win.FARPROC;
        extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(.winapi) ?win.HMODULE;
    };

    const iphlp = k32.LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("iphlpapi.dll")) orelse return null;
    defer _ = k32.FreeLibrary(iphlp);

    const GetExtendedTcpTableFn = *const fn (
        pTcpTable: ?*anyopaque,
        pdwSize: *u32,
        bOrder: win.BOOL,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) callconv(.winapi) u32;

    const get_table_proc = k32.GetProcAddress(iphlp, "GetExtendedTcpTable") orelse return null;
    const getExtendedTcpTable: GetExtendedTcpTableFn = @ptrCast(get_table_proc);

    var size: u32 = 0;
    _ = getExtendedTcpTable(null, &size, .FALSE, 2, 5, 0);
    if (size == 0) return null;

    var stack_buf: [32768]u8 = undefined;
    if (size > stack_buf.len) return null;
    const status = getExtendedTcpTable(&stack_buf, &size, .FALSE, 2, 5, 0);
    if (status != 0) return null;

    const num_entries = std.mem.readInt(u32, stack_buf[0..4], .little);
    var target_pid: ?u32 = null;

    const port_be = std.mem.nativeToBig(u16, port);
    var offset: usize = 4;
    var i: usize = 0;
    while (i < num_entries and offset + 24 <= stack_buf.len) : (i += 1) {
        const local_port_raw = std.mem.readInt(u32, stack_buf[offset + 8 .. offset + 12][0..4], .little);
        const entry_port: u16 = @truncate(local_port_raw);
        if (entry_port == port_be or entry_port == port) {
            target_pid = std.mem.readInt(u32, stack_buf[offset + 20 .. offset + 24][0..4], .little);
            break;
        }
        offset += 24;
    }

    const pid = target_pid orelse return null;
    if (pid == 0 or pid == 4) return null;

    const k32_mod = k32.GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")) orelse return null;

    const OpenProcessFn = *const fn (dwDesiredAccess: u32, bInheritHandle: win.BOOL, dwProcessId: u32) callconv(.winapi) ?win.HANDLE;
    const open_proc = k32.GetProcAddress(k32_mod, "OpenProcess") orelse return null;
    const openProcess: OpenProcessFn = @ptrCast(open_proc);

    const QueryFullProcessImageNameAFn = *const fn (
        hProcess: win.HANDLE,
        dwFlags: u32,
        lpExeName: [*]u8,
        lpdwSize: *u32,
    ) callconv(.winapi) win.BOOL;

    const query_proc = k32.GetProcAddress(k32_mod, "QueryFullProcessImageNameA") orelse return null;
    const queryFullProcessImageNameA: QueryFullProcessImageNameAFn = @ptrCast(query_proc);

    const hProcess = openProcess(0x1000, .FALSE, pid) orelse return null;
    defer _ = CloseHandle(hProcess);

    var name_buf: [260]u8 = undefined;
    var name_len: u32 = name_buf.len;
    if (queryFullProcessImageNameA(hProcess, 0, &name_buf, &name_len) == .FALSE) return null;

    const full_path = name_buf[0..name_len];
    var base_name = full_path;
    if (std.mem.lastIndexOfScalar(u8, full_path, '\\')) |idx| {
        base_name = full_path[idx + 1 ..];
    } else if (std.mem.lastIndexOfScalar(u8, full_path, '/')) |idx| {
        base_name = full_path[idx + 1 ..];
    }

    if (base_name.len > out_buf.len) return null;
    @memcpy(out_buf[0..base_name.len], base_name);
    return out_buf[0..base_name.len];
}

// ============================================================================
// 统一 Stream 抽象（从 stream.zig 融合）
// ============================================================================

pub const Stream = struct {
    ptr: *anyopaque,
    raw_handle: Handle,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ptr: *anyopaque, buf: []u8) error{ ConnectionClosed, Io }!usize,
        writeAll: *const fn (ptr: *anyopaque, data: []const u8) error{Io}!void,
        shutdownSend: *const fn (ptr: *anyopaque) void,
        close: *const fn (ptr: *anyopaque) void,
    };

    pub fn fromRaw(h: Handle) Stream {
        return .{
            .ptr = @ptrFromInt(@as(usize, @intCast(h))),
            .raw_handle = h,
            .vtable = &raw_vtable,
        };
    }

    pub fn fromTls(conn: anytype) Stream {
        const Gen = struct {
            fn doRead(ptr: *anyopaque, buf: []u8) error{ ConnectionClosed, Io }!usize {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                return c.read(buf) catch |e| switch (e) {
                    error.ConnectionClosed => error.ConnectionClosed,
                    else => error.Io,
                };
            }
            fn doWriteAll(ptr: *anyopaque, data: []const u8) error{Io}!void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.writeAll(data) catch return error.Io;
            }
            fn doShutdownSend(ptr: *anyopaque) void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.shutdownSend();
            }
            fn doClose(ptr: *anyopaque) void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.destroy();
            }
            const vtable = VTable{
                .read = doRead,
                .writeAll = doWriteAll,
                .shutdownSend = doShutdownSend,
                .close = doClose,
            };
        };
        return .{
            .ptr = conn,
            .raw_handle = conn.handle(),
            .vtable = &Gen.vtable,
        };
    }

    pub fn fromWs(conn: anytype) Stream {
        const Gen = struct {
            fn doRead(ptr: *anyopaque, buf: []u8) error{ ConnectionClosed, Io }!usize {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                return c.read(buf) catch |e| switch (e) {
                    error.ConnectionClosed => error.ConnectionClosed,
                    else => error.Io,
                };
            }
            fn doWriteAll(ptr: *anyopaque, data: []const u8) error{Io}!void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.writeAll(data) catch return error.Io;
            }
            fn doShutdownSend(ptr: *anyopaque) void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.inner.shutdownSend();
            }
            fn doClose(ptr: *anyopaque) void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                const alloc = c.alloc;
                c.inner.close();
                alloc.destroy(c);
            }
            const vtable = VTable{
                .read = doRead,
                .writeAll = doWriteAll,
                .shutdownSend = doShutdownSend,
                .close = doClose,
            };
        };
        return .{
            .ptr = conn,
            .raw_handle = conn.handle(),
            .vtable = &Gen.vtable,
        };
    }

    pub fn fromSs(conn: anytype) Stream {
        const Gen = struct {
            fn doRead(ptr: *anyopaque, buf: []u8) error{ ConnectionClosed, Io }!usize {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                return c.read(buf) catch |e| switch (e) {
                    error.ConnectionClosed => error.ConnectionClosed,
                    else => error.Io,
                };
            }
            fn doWriteAll(ptr: *anyopaque, data: []const u8) error{Io}!void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.writeAll(data) catch return error.Io;
            }
            fn doShutdownSend(ptr: *anyopaque) void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.shutdownSend();
            }
            fn doClose(ptr: *anyopaque) void {
                const c: @TypeOf(conn) = @ptrCast(@alignCast(ptr));
                c.destroy();
            }
            const vtable = VTable{
                .read = doRead,
                .writeAll = doWriteAll,
                .shutdownSend = doShutdownSend,
                .close = doClose,
            };
        };
        return .{
            .ptr = conn,
            .raw_handle = conn.handle(),
            .vtable = &Gen.vtable,
        };
    }

    pub fn handle(self: Stream) Handle {
        return self.raw_handle;
    }

    pub fn read(self: Stream, buf: []u8) error{ ConnectionClosed, Io }!usize {
        return self.vtable.read(self.ptr, buf);
    }

    pub fn writeAll(self: Stream, data: []const u8) error{Io}!void {
        return self.vtable.writeAll(self.ptr, data);
    }

    pub fn shutdownSend(self: Stream) void {
        self.vtable.shutdownSend(self.ptr);
    }

    pub fn close(self: Stream) void {
        self.vtable.close(self.ptr);
    }

    const raw_vtable = VTable{
        .read = rawRead,
        .writeAll = rawWriteAll,
        .shutdownSend = rawShutdownSend,
        .close = rawClose,
    };

    fn rawRead(ptr: *anyopaque, buf: []u8) error{ ConnectionClosed, Io }!usize {
        const h: Handle = @intCast(@intFromPtr(ptr));
        return recv(h, buf) catch |e| switch (e) {
            error.ConnectionClosed => error.ConnectionClosed,
            else => error.Io,
        };
    }

    fn rawWriteAll(ptr: *anyopaque, data: []const u8) error{Io}!void {
        const h: Handle = @intCast(@intFromPtr(ptr));
        sendAll(h, data) catch return error.Io;
    }

    fn rawShutdownSend(ptr: *anyopaque) void {
        const h: Handle = @intCast(@intFromPtr(ptr));
        shutdownSocketSend(h);
    }

    fn rawClose(ptr: *anyopaque) void {
        const h: Handle = @intCast(@intFromPtr(ptr));
        closeSocket(h);
    }
};

// ============================================================================
// 高性能定长缓冲区池（从 bufferpool.zig 融合）
// ============================================================================

pub const default_chunk_size: usize = 16 * 1024;
pub const max_cached_chunks: usize = 128;

pub const BufferPool = struct {
    alloc: std.mem.Allocator,
    mutex: Mutex = .{},
    chunk_size: usize,
    max_cached: usize,
    free_list: std.ArrayList([]u8),

    pub fn init(alloc: std.mem.Allocator, chunk_size: usize, max_cached: usize) BufferPool {
        return .{
            .alloc = alloc,
            .chunk_size = chunk_size,
            .max_cached = max_cached,
            .free_list = std.ArrayList([]u8).empty,
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.free_list.items) |buf| {
            self.alloc.free(buf);
        }
        self.free_list.deinit(self.alloc);
    }

    pub fn acquire(self: *BufferPool) ![]u8 {
        self.mutex.lock();
        if (self.free_list.items.len > 0) {
            const buf = self.free_list.pop().?;
            self.mutex.unlock();
            return buf;
        }
        self.mutex.unlock();

        return self.alloc.alloc(u8, self.chunk_size);
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        if (buf.len != self.chunk_size) {
            self.alloc.free(buf);
            return;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len < self.max_cached) {
            self.free_list.append(self.alloc, buf) catch {
                self.alloc.free(buf);
            };
        } else {
            self.alloc.free(buf);
        }
    }

    pub fn availableCount(self: *BufferPool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.free_list.items.len;
    }
};

var default_pool_storage: ?BufferPool = null;
var default_pool_mutex: Mutex = .{};

pub fn getGlobalBufferPool() *BufferPool {
    default_pool_mutex.lock();
    defer default_pool_mutex.unlock();
    if (default_pool_storage == null) {
        default_pool_storage = BufferPool.init(std.heap.page_allocator, default_chunk_size, max_cached_chunks);
    }
    return &default_pool_storage.?;
}

// ============================================================================
// 单线程 Poll 双向流中继（从 relay.zig 融合）
// ============================================================================

pub const RelayStats = struct {
    up: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    down: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn addUp(self: *RelayStats, n: u64) void {
        _ = self.up.fetchAdd(n, .monotonic);
    }

    pub fn addDown(self: *RelayStats, n: u64) void {
        _ = self.down.fetchAdd(n, .monotonic);
    }

    pub fn snapshot(self: *const RelayStats) struct { up: u64, down: u64 } {
        return .{
            .up = self.up.load(.monotonic),
            .down = self.down.load(.monotonic),
        };
    }

    pub fn reset(self: *RelayStats) void {
        self.up.store(0, .monotonic);
        self.down.store(0, .monotonic);
    }
};

pub const Stats = RelayStats;

pub const RelayResult = struct {
    up: u64 = 0,
    down: u64 = 0,
};

pub const RelayError = error{
    PeerClosed,
    IdleTimeout,
    Io,
};

pub fn relay(
    a: Stream,
    b: Stream,
    stats: ?*RelayStats,
    idle_timeout_ms: i32,
    buf_size: usize,
) RelayError!RelayResult {
    _ = buf_size;
    const pool = getGlobalBufferPool();
    const buf = pool.acquire() catch return error.Io;
    defer pool.release(buf);

    var a_open = true;
    var b_open = true;
    var res = RelayResult{};

    while (a_open or b_open) {
        var fds = [2]PollFd{
            .{ .fd = a.handle(), .events = if (a_open) POLL.IN else 0, .revents = 0 },
            .{ .fd = b.handle(), .events = if (b_open) POLL.IN else 0, .revents = 0 },
        };

        const n = poll(&fds, idle_timeout_ms) catch return error.Io;
        if (n == 0) return error.IdleTimeout;

        const any_event = POLL.IN | POLL.HUP | POLL.ERR | POLL.NVAL;

        if (a_open and (fds[0].revents & any_event) != 0) {
            const got = a.read(buf) catch blk: {
                a_open = false;
                b.shutdownSend();
                break :blk 0;
            };
            if (got > 0) {
                b.writeAll(buf[0..got]) catch {
                    a_open = false;
                    b_open = false;
                    break;
                };
                res.up += got;
                if (stats) |s| s.addUp(got);
            }
        }

        if (b_open and (fds[1].revents & any_event) != 0) {
            const got = b.read(buf) catch blk: {
                b_open = false;
                a.shutdownSend();
                break :blk 0;
            };
            if (got > 0) {
                a.writeAll(buf[0..got]) catch {
                    a_open = false;
                    b_open = false;
                    break;
                };
                res.down += got;
                if (stats) |s| s.addDown(got);
            }
        }
    }

    return res;
}

// ============================================================================
// 提权助手（从 elevate.zig 融合）
// ============================================================================

pub const ElevateError = error{
    UserCancelled,
    ElevationDisabled,
    AlreadyElevated,
    Unsupported,
    OutOfMemory,
};

pub const ElevateResult = union(enum) {
    exited: u32,
    cancelled,
    failed: []const u8,
};

pub fn isElevated() bool {
    if (is_windows) return isElevatedWindows();
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        return std.posix.geteuid() == 0;
    }
    return false;
}

const TOKEN_QUERY: u32 = 0x0008;
const TokenElevation: u32 = 20;

const TOKEN_ELEVATION = extern struct {
    TokenIsElevated: u32,
};

const SHELLEXECUTEINFOW = extern struct {
    cbSize: u32,
    fMask: u32,
    hwnd: ?*anyopaque,
    lpVerb: ?[*:0]const u16,
    lpFile: ?[*:0]const u16,
    lpParameters: ?[*:0]const u16,
    lpDirectory: ?[*:0]const u16,
    nShow: c_int,
    hInstApp: ?*anyopaque,
    lpIDList: ?*anyopaque,
    lpClass: ?[*:0]const u16,
    hkeyClass: ?*anyopaque,
    dwHotKey: u32,
    hIcon: ?*anyopaque,
    hProcess: ?std.os.windows.HANDLE,
};

const SEE_MASK_NOCLOSEPROCESS: u32 = 0x00000040;
const SEE_MASK_FLAG_NO_UI: u32 = 0x00000400;
const SW_SHOWNORMAL: c_int = 1;
const SW_HIDE: c_int = 0;
const INFINITE: u32 = 0xFFFFFFFF;

extern "advapi32" fn OpenProcessToken(
    ProcessHandle: std.os.windows.HANDLE,
    DesiredAccess: u32,
    TokenHandle: *std.os.windows.HANDLE,
) callconv(.winapi) std.os.windows.BOOL;

extern "advapi32" fn GetTokenInformation(
    TokenHandle: std.os.windows.HANDLE,
    TokenInformationClass: u32,
    TokenInformation: ?*anyopaque,
    TokenInformationLength: u32,
    ReturnLength: *u32,
) callconv(.winapi) std.os.windows.BOOL;

extern "kernel32" fn WaitForSingleObject(hHandle: std.os.windows.HANDLE, dwMilliseconds: u32) callconv(.winapi) u32;
extern "kernel32" fn GetExitCodeProcess(hProcess: std.os.windows.HANDLE, lpExitCode: *u32) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn CloseHandle(hObject: std.os.windows.HANDLE) callconv(.winapi) std.os.windows.BOOL;

fn isElevatedWindows() bool {
    var token: std.os.windows.HANDLE = undefined;
    const current_process_handle: std.os.windows.HANDLE = @ptrFromInt(std.math.maxInt(usize));
    if (OpenProcessToken(current_process_handle, TOKEN_QUERY, &token) == .FALSE) return false;
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

pub fn getSelfExePath(alloc: std.mem.Allocator) ![:0]u8 {
    if (is_windows) {
        const w = std.os.windows;
        const slice = w.peb().ProcessParameters.ImagePathName.slice();
        return std.unicode.utf16LeToUtf8AllocZ(alloc, slice);
    } else {
        var buf: [std.posix.PATH_MAX]u8 = undefined;
        const p = try std.posix.readlink("/proc/self/exe", &buf);
        return alloc.dupeZ(u8, p);
    }
}

pub fn elevateWindows(
    alloc: std.mem.Allocator,
    extra_args: []const u8,
    wait: bool,
    hide: bool,
) ElevateError!ElevateResult {
    const exe_path = getSelfExePath(alloc) catch return ElevateError.OutOfMemory;
    defer alloc.free(exe_path);

    const exe_w = std.unicode.utf8ToUtf16LeAllocZ(alloc, exe_path) catch return ElevateError.OutOfMemory;
    defer alloc.free(exe_w);

    const runas = std.unicode.utf8ToUtf16LeAllocZ(alloc, "runas") catch return ElevateError.OutOfMemory;
    defer alloc.free(runas);

    var params_w: ?[:0]u16 = null;
    defer if (params_w) |p| alloc.free(p);
    if (extra_args.len > 0) {
        params_w = std.unicode.utf8ToUtf16LeAllocZ(alloc, extra_args) catch return ElevateError.OutOfMemory;
    }

    var sei = SHELLEXECUTEINFOW{
        .cbSize = @sizeOf(SHELLEXECUTEINFOW),
        .fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
        .hwnd = null,
        .lpVerb = runas.ptr,
        .lpFile = exe_w.ptr,
        .lpParameters = if (params_w) |p| p.ptr else null,
        .lpDirectory = null,
        .nShow = if (hide) SW_HIDE else SW_SHOWNORMAL,
        .hInstApp = null,
        .lpIDList = null,
        .lpClass = null,
        .hkeyClass = null,
        .dwHotKey = 0,
        .hIcon = null,
        .hProcess = null,
    };

    const k32 = struct {
        extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?std.os.windows.HMODULE;
        extern "kernel32" fn FreeLibrary(hLibModule: std.os.windows.HMODULE) callconv(.winapi) std.os.windows.BOOL;
        extern "kernel32" fn GetProcAddress(hModule: std.os.windows.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?std.os.windows.FARPROC;
    };
    const s32 = k32.LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("shell32.dll")) orelse return ElevateError.ElevationDisabled;
    defer _ = k32.FreeLibrary(s32);

    const ShellExecuteExWFn = *const fn (pExecInfo: *SHELLEXECUTEINFOW) callconv(.winapi) std.os.windows.BOOL;
    const proc = k32.GetProcAddress(s32, "ShellExecuteExW") orelse return ElevateError.ElevationDisabled;
    const shellExecuteExW: ShellExecuteExWFn = @ptrCast(proc);

    if (shellExecuteExW(&sei) == .FALSE) {
        return ElevateError.ElevationDisabled;
    }
    if (sei.hProcess == null) return ElevateError.ElevationDisabled;
    defer _ = CloseHandle(sei.hProcess.?);

    if (!wait) return ElevateResult{ .exited = 0 };

    _ = WaitForSingleObject(sei.hProcess.?, INFINITE);
    var code: u32 = 0;
    if (GetExitCodeProcess(sei.hProcess.?, &code) == .FALSE) {
        return ElevateResult{ .failed = "GetExitCodeProcess failed" };
    }
    return ElevateResult{ .exited = code };
}

pub fn checkPosixElevation() ElevateError!void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return ElevateError.Unsupported;
    if (std.posix.geteuid() == 0) return ElevateError.AlreadyElevated;
    return ElevateError.ElevationDisabled;
}

pub fn restartElevated(alloc: std.mem.Allocator, extra_args: []const u8, wait: bool) ElevateError!?ElevateResult {
    if (isElevated()) return null;
    if (!is_windows) return ElevateError.Unsupported;
    return try elevateWindows(alloc, extra_args, wait, false);
}

pub fn buildArgs(alloc: std.mem.Allocator, args: []const []const u8) ElevateError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    for (args, 0..) |arg, i| {
        if (i > 0) out.append(alloc, ' ') catch return ElevateError.OutOfMemory;
        appendQuoted(alloc, &out, arg) catch return ElevateError.OutOfMemory;
    }
    return out.toOwnedSlice(alloc) catch ElevateError.OutOfMemory;
}

fn appendQuoted(alloc: std.mem.Allocator, out: *std.ArrayList(u8), arg: []const u8) !void {
    const needs_quote = arg.len == 0 or std.mem.indexOfAny(u8, arg, " \t\"") != null;
    if (!needs_quote) {
        try out.appendSlice(alloc, arg);
        return;
    }
    try out.append(alloc, '"');
    var backslashes: usize = 0;
    for (arg) |c| {
        switch (c) {
            '\\' => backslashes += 1,
            '"' => {
                try out.appendNTimes(alloc, '\\', backslashes + 1);
                try out.append(alloc, '"');
                backslashes = 0;
            },
            else => {
                try out.appendNTimes(alloc, '\\', backslashes);
                try out.append(alloc, c);
                backslashes = 0;
            },
        }
    }
    try out.appendNTimes(alloc, '\\', backslashes * 2);
    try out.append(alloc, '"');
}

const Net = @This();

pub const elevate = struct {
    pub const Error = ElevateError;
    pub const Result = ElevateResult;
    pub const isElevated = Net.isElevated;
    pub const elevateWindows = Net.elevateWindows;
    pub const checkPosixElevation = Net.checkPosixElevation;
    pub const restartElevated = Net.restartElevated;
    pub const buildArgs = Net.buildArgs;
};




