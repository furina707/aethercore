const std = @import("std");
const net = @import("net.zig");
const security = @import("security.zig");
const config = @import("config.zig");
const proxy = @import("proxy.zig");

pub const ControlPlane = struct {
    allocator: std.mem.Allocator,
    sec: *const security.SecurityManager,
    cfg: *config.AppConfig,
    stats: *proxy.TrafficStats,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn init(
        allocator: std.mem.Allocator,
        sec: *const security.SecurityManager,
        cfg: *config.AppConfig,
        stats: *proxy.TrafficStats,
    ) ControlPlane {
        return ControlPlane{
            .allocator = allocator,
            .sec = sec,
            .cfg = cfg,
            .stats = stats,
        };
    }

    pub fn handleClient(self: *ControlPlane, client_fd: c_int) void {
        defer net.closeSocket(client_fd);

        var buf: [4096]u8 = undefined;
        const n = net.recv(client_fd, buf[0..]) catch return;
        if (n == 0) return;
        const req = buf[0..n];

        // 默认安全: 强制鉴权校验
        if (!self.isAuthorized(req)) {
            const unauthorized_resp =
                "HTTP/1.1 401 Unauthorized\r\n" ++
                "Content-Type: application/json; charset=utf-8\r\n" ++
                "Connection: close\r\n\r\n" ++
                "{\"error\":\"Unauthorized: Default-secure token authentication required\"}\n";
            _ = net.sendAll(client_fd, unauthorized_resp) catch {};
            return;
        }

        // 解析请求行
        const line_end = std.mem.indexOf(u8, req, "\r\n") orelse req.len;
        const req_line = req[0..line_end];
        var parts = std.mem.splitScalar(u8, req_line, ' ');
        const method = parts.next() orelse "";
        const path = parts.next() orelse "";

        if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/api/state")) {
            self.respondState(client_fd);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/api/nodes")) {
            self.respondNodes(client_fd);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/api/health")) {
            self.respondJson(client_fd, "{\"status\":\"healthy\",\"secure\":true,\"loopback_only\":true}\n");
        } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/mode")) {
            self.handleSetMode(client_fd, req);
        } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/node")) {
            self.handleSetNode(client_fd, req);
        } else {
            self.respondNotFound(client_fd);
        }
    }

    fn isAuthorized(self: *ControlPlane, req: []const u8) bool {
        const auth_header = "Authorization: Bearer ";
        if (std.mem.indexOf(u8, req, auth_header)) |idx| {
            const token_start = idx + auth_header.len;
            var token_end = token_start;
            while (token_end < req.len and req[token_end] != '\r' and req[token_end] != '\n' and req[token_end] != ' ') {
                token_end += 1;
            }
            const provided_token = req[token_start..token_end];
            return self.sec.verifyToken(provided_token);
        }
        return false;
    }

    fn respondState(self: *ControlPlane, client_fd: c_int) void {
        var resp_buf: [1024]u8 = undefined;
        const active_node = self.cfg.getActiveNode();
        const active_name = if (active_node) |node| node.name else "无可用节点";

        const json_body = std.fmt.bufPrint(&resp_buf,
            \\{{"status":"running","mode":"{s}","active_node":"{s}","active_connections":{},"total_connections":{},"bytes_uploaded":{},"bytes_downloaded":{},"secure_default":true}}
            \\
        , .{
            self.cfg.mode.toString(),
            active_name,
            self.stats.active_connections.load(.monotonic),
            self.stats.total_connections.load(.monotonic),
            self.stats.bytes_uploaded.load(.monotonic),
            self.stats.bytes_downloaded.load(.monotonic),
        }) catch return;

        self.respondJson(client_fd, json_body);
    }

    fn respondNodes(self: *ControlPlane, client_fd: c_int) void {
        var buf: [4096]u8 = undefined;
        var pos: usize = 0;

        const h = std.fmt.bufPrint(buf[pos..], "{{\"active_index\":{},\"nodes\":[", .{self.cfg.active_node_index}) catch return;
        pos += h.len;

        for (self.cfg.nodes.items, 0..) |n, i| {
            if (i > 0) {
                buf[pos] = ',';
                pos += 1;
            }
            const item = std.fmt.bufPrint(buf[pos..], "{{\"id\":\"{s}\",\"name\":\"{s}\",\"protocol\":\"{s}\",\"server\":\"{s}\",\"port\":{},\"latency_ms\":{}}}", .{
                n.id,
                n.name,
                n.protocol,
                n.server,
                n.port,
                n.latency_ms,
            }) catch return;
            pos += item.len;
        }

        const tail = std.fmt.bufPrint(buf[pos..], "]}}\n", .{}) catch return;
        pos += tail.len;

        self.respondJson(client_fd, buf[0..pos]);
    }

    fn handleSetMode(self: *ControlPlane, client_fd: c_int, req: []const u8) void {
        if (std.mem.indexOf(u8, req, "\"global\"") != null) {
            self.cfg.mode = .global;
        } else if (std.mem.indexOf(u8, req, "\"direct\"") != null) {
            self.cfg.mode = .direct;
        } else if (std.mem.indexOf(u8, req, "\"rule\"") != null) {
            self.cfg.mode = .rule;
        }
        self.respondJson(client_fd, "{\"success\":true}\n");
    }

    fn handleSetNode(self: *ControlPlane, client_fd: c_int, req: []const u8) void {
        if (std.mem.indexOf(u8, req, "\"index\":")) |idx| {
            const start = idx + 8;
            var end = start;
            while (end < req.len and req[end] >= '0' and req[end] <= '9') {
                end += 1;
            }
            if (end > start) {
                const num = std.fmt.parseInt(usize, req[start..end], 10) catch 0;
                if (num < self.cfg.nodes.items.len) {
                    self.cfg.active_node_index = num;
                }
            }
        }
        self.respondJson(client_fd, "{\"success\":true}\n");
    }

    fn respondJson(self: *ControlPlane, client_fd: c_int, json_content: []const u8) void {
        _ = self;
        var header_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf,
            "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: application/json; charset=utf-8\r\n" ++
            "Content-Length: {}\r\n" ++
            "Connection: close\r\n\r\n",
            .{json_content.len},
        ) catch return;

        _ = net.sendAll(client_fd, header) catch {};
        _ = net.sendAll(client_fd, json_content) catch {};
    }

    fn respondNotFound(self: *ControlPlane, client_fd: c_int) void {
        _ = self;
        const not_found =
            "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Type: application/json; charset=utf-8\r\n" ++
            "Connection: close\r\n\r\n" ++
            "{\"error\":\"Endpoint not found\"}\n";
        _ = net.sendAll(client_fd, not_found) catch {};
    }
};
