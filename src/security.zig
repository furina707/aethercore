const std = @import("std");

/// 默认安全架构 (Secure by Default)
/// 哲学原则: "未开启的安全是不安全的"
/// 1. 强随机 256 位令牌，自动生成且限制 POSIX 0600 严格文件权限
/// 2. 默认所有监听套接字仅绑定回环地址 (127.0.0.1 / ::1)，杜绝暴露公网
/// 3. 控制面恒常时间 (Constant-Time) 鉴权比对，抵御时序侧信道攻击
/// 4. 退出或销毁时内存安全擦除 (Zero-out memory)
pub const SecurityManager = struct {
    allocator: std.mem.Allocator,
    token: [64]u8,
    token_len: usize,
    loopback_only: bool,
    secure_routing_strict: bool,

    pub const TOKEN_PATH: [*:0]const u8 = "data/auth.token";

    pub fn init(allocator: std.mem.Allocator, allow_lan: bool) !SecurityManager {
        var sm = SecurityManager{
            .allocator = allocator,
            .token = undefined,
            .token_len = 0,
            .loopback_only = !allow_lan,
            .secure_routing_strict = true,
        };

        try sm.loadOrCreateToken();
        return sm;
    }

    pub fn deinit(self: *SecurityManager) void {
        // 安全擦除内存中的密钥敏感数据
        @memset(&self.token, 0);
        self.token_len = 0;
    }

    /// 获取或自动生成高熵强随机令牌
    fn loadOrCreateToken(self: *SecurityManager) !void {
        // 创建安全受限目录
        _ = std.c.mkdir("data", 0o700);

        // 尝试读取现有令牌
        if (std.c.fopen(TOKEN_PATH, "r")) |f| {
            defer _ = std.c.fclose(f);
            const bytes_read = std.c.fread(&self.token, 1, self.token.len, f);
            if (bytes_read >= 32) {
                var valid_len = bytes_read;
                while (valid_len > 0 and (self.token[valid_len - 1] == '\r' or self.token[valid_len - 1] == '\n' or self.token[valid_len - 1] == ' ')) {
                    valid_len -= 1;
                }
                self.token_len = valid_len;
                return;
            }
        }

        // 生成 32 字节 (256 位) 强加密随机数，并编码为 64 字节十六进制
        var rand_bytes: [32]u8 = undefined;
        _ = std.c.getrandom(&rand_bytes, rand_bytes.len, 0);
        defer @memset(&rand_bytes, 0);

        const hex_charset = "0123456789abcdef";
        for (rand_bytes, 0..) |b, i| {
            self.token[i * 2] = hex_charset[b >> 4];
            self.token[i * 2 + 1] = hex_charset[b & 0x0f];
        }
        self.token_len = 64;

        // 默认安全: 写入文件并严格设为 0600 (仅所有者可读写)
        const f = std.c.fopen(TOKEN_PATH, "w") orelse return error.CreateTokenFailed;
        defer _ = std.c.fclose(f);
        _ = std.c.fwrite(&self.token, 1, self.token_len, f);
        _ = std.c.fwrite("\n", 1, 1, f);
        _ = std.c.chmod(TOKEN_PATH, 0o600);
    }

    /// 常量时间验证 Bearer 令牌，杜绝时序攻击
    pub fn verifyToken(self: *const SecurityManager, provided_token: []const u8) bool {
        if (provided_token.len != self.token_len) return false;
        var diff: u8 = 0;
        const my_token = self.token[0..self.token_len];
        for (my_token, provided_token) |a, b| {
            diff |= (a ^ b);
        }
        return diff == 0;
    }

    /// 获取绑定的监听 IP: 默认安全返回 127.0.0.1
    pub fn getListenHost(self: *const SecurityManager) []const u8 {
        if (self.loopback_only) {
            return "127.0.0.1";
        } else {
            return "0.0.0.0";
        }
    }

    pub fn getTokenString(self: *const SecurityManager) []const u8 {
        return self.token[0..self.token_len];
    }
};
