const std = @import("std");

pub const sockaddr_in = extern struct {
    sin_family: u16 = 2, // AF_INET
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [8]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

pub const POLLIN: i16 = 0x0001;
pub const POLLPRI: i16 = 0x0002;
pub const POLLOUT: i16 = 0x0004;
pub const POLLERR: i16 = 0x0008;
pub const POLLHUP: i16 = 0x0010;
pub const POLLNVAL: i16 = 0x0020;

pub fn parseIp4(str: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var idx: usize = 0;
    var current: u32 = 0;
    var has_digit = false;

    for (str) |c| {
        if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            if (current > 255) return null;
            has_digit = true;
        } else if (c == '.') {
            if (!has_digit or idx >= 3) return null;
            parts[idx] = @intCast(current);
            idx += 1;
            current = 0;
            has_digit = false;
        } else {
            return null;
        }
    }
    if (!has_digit or idx != 3) return null;
    parts[3] = @intCast(current);

    // 返回网络字节序 (Big Endian)
    return (@as(u32, parts[0])) |
        (@as(u32, parts[1]) << 8) |
        (@as(u32, parts[2]) << 16) |
        (@as(u32, parts[3]) << 24);
}

pub fn createTcpListener(host: []const u8, port: u16) !c_int {
    const fd = std.c.socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if (fd < 0) return error.SocketCreateFailed;
    errdefer _ = std.c.close(fd);

    var opt: c_int = 1;
    _ = std.c.setsockopt(fd, 1, 2, &opt, @sizeOf(c_int)); // SOL_SOCKET, SO_REUSEADDR

    const ip = parseIp4(host) orelse 0x0100007f; // 默认 127.0.0.1
    var addr = sockaddr_in{
        .sin_family = 2,
        .sin_port = std.mem.nativeToBig(u16, port),
        .sin_addr = ip,
    };

    const bind_res = std.c.bind(fd, @ptrCast(&addr), @sizeOf(sockaddr_in));
    if (bind_res != 0) return error.SocketBindFailed;

    const listen_res = std.c.listen(fd, 128);
    if (listen_res != 0) return error.SocketListenFailed;

    return fd;
}

pub fn acceptTcp(listener_fd: c_int) !c_int {
    var client_addr: sockaddr_in = undefined;
    var addr_len: c_uint = @sizeOf(sockaddr_in);
    const client_fd = std.c.accept(listener_fd, @ptrCast(&client_addr), &addr_len);
    if (client_fd < 0) return error.AcceptFailed;
    return client_fd;
}

pub fn connectTcp(host: []const u8, port: u16) !c_int {
    const fd = std.c.socket(2, 1, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer _ = std.c.close(fd);

    const ip = parseIp4(host) orelse return error.InvalidAddress;
    var addr = sockaddr_in{
        .sin_family = 2,
        .sin_port = std.mem.nativeToBig(u16, port),
        .sin_addr = ip,
    };

    const res = std.c.connect(fd, @ptrCast(&addr), @sizeOf(sockaddr_in));
    if (res != 0) return error.ConnectFailed;

    return fd;
}

pub fn closeSocket(fd: c_int) void {
    if (fd >= 0) {
        _ = std.c.close(fd);
    }
}

pub fn sendAll(fd: c_int, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = std.c.send(fd, data[sent..].ptr, data.len - sent, 0);
        if (n <= 0) return error.SendFailed;
        sent += @intCast(n);
    }
}

pub fn recv(fd: c_int, buf: []u8) !usize {
    const n = std.c.recv(fd, buf.ptr, buf.len, 0);
    if (n < 0) return error.RecvFailed;
    return @intCast(n);
}
