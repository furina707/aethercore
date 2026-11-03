//! 用户态 TCP/IP 协议栈统一模块
const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");

pub const tun_stack = struct {
    //! 用户态 L3/L4 网络协议栈（TUN 数据包解析与分流）
    //!
    //! 在 TUN 模式下接管网卡原始 IP 数据包：
    //! 1. IPv4 报头校验与协议分发 (TCP: 6, UDP: 17, ICMP: 1)
    //! 2. ICMP Echo 请求自动代答（使用户 ping Fake-IP / 网关 198.18.0.1 能正常获得回显）
    //! 3. TCP 报头与标志位解析 (SYN/ACK/FIN/RST) 及检验和计算

    pub const IPPROTO_ICMP: u8 = 1;
    pub const IPPROTO_TCP: u8 = 6;
    pub const IPPROTO_UDP: u8 = 17;

    pub const Ipv4Header = struct {
        version: u4,
        ihl: u4,
        tos: u8,
        total_len: u16,
        id: u16,
        flags: u3,
        frag_offset: u13,
        ttl: u8,
        proto: u8,
        checksum: u16,
        src: [4]u8,
        dst: [4]u8,
        payload_start: usize,
        payload_end: usize,
    };

    pub const TcpHeader = struct {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        data_offset: u4,
        flags: u9,
        window: u16,
        checksum: u16,
        payload_start: usize,
        payload_end: usize,
    };

    pub const TcpFlags = struct {
        pub const FIN: u16 = 0x01;
        pub const SYN: u16 = 0x02;
        pub const RST: u16 = 0x04;
        pub const PSH: u16 = 0x08;
        pub const ACK: u16 = 0x10;
        pub const URG: u16 = 0x20;
    };

    /// 计算网络层校验和（16 位累加取反）
    pub fn computeChecksum(data: []const u8) u16 {
        var sum: u32 = 0;
        var i: usize = 0;
        while (i + 1 < data.len) : (i += 2) {
            sum += std.mem.readInt(u16, data[i..][0..2], .big);
        }
        if (i < data.len) {
            sum += @as(u32, data[i]) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~@as(u16, @intCast(sum & 0xFFFF));
    }

    /// 解析 IPv4 报头
    pub fn parseIpv4(packet: []const u8) ?Ipv4Header {
        if (packet.len < 20) return null;
        const v_ihl = packet[0];
        const version: u4 = @truncate(v_ihl >> 4);
        if (version != 4) return null;

        const ihl: u4 = @truncate(v_ihl & 0x0F);
        const header_len: usize = @as(usize, ihl) * 4;
        if (header_len < 20 or header_len > packet.len) return null;

        const total_len = std.mem.readInt(u16, packet[2..4][0..2], .big);
        if (total_len > packet.len) return null;

        var src: [4]u8 = undefined;
        @memcpy(&src, packet[12..16]);
        var dst: [4]u8 = undefined;
        @memcpy(&dst, packet[16..20]);

        const flags_frag = std.mem.readInt(u16, packet[6..8][0..2], .big);

        return .{
            .version = version,
            .ihl = ihl,
            .tos = packet[1],
            .total_len = total_len,
            .id = std.mem.readInt(u16, packet[4..6][0..2], .big),
            .flags = @truncate(flags_frag >> 13),
            .frag_offset = @truncate(flags_frag & 0x1FFF),
            .ttl = packet[8],
            .proto = packet[9],
            .checksum = std.mem.readInt(u16, packet[10..12][0..2], .big),
            .src = src,
            .dst = dst,
            .payload_start = header_len,
            .payload_end = total_len,
        };
    }

    /// 处理 ICMP 报文：若是 Echo Request (Type=8)，直接在原地修改为 Echo Reply (Type=0) 并调换源/目的 IP
    pub fn handleIcmpEcho(packet: []u8) ?[]u8 {
        const ip = parseIpv4(packet) orelse return null;
        if (ip.proto != IPPROTO_ICMP) return null;

        const icmp_data = packet[ip.payload_start..ip.payload_end];
        if (icmp_data.len < 8) return null;

        // Type 8 == Echo Request
        if (icmp_data[0] != 8 or icmp_data[1] != 0) return null;

        // 1. 改为 Type 0 (Echo Reply)
        icmp_data[0] = 0;
        icmp_data[1] = 0;

        // 2. 重新计算 ICMP 校验和 (清零后计算)
        icmp_data[2] = 0;
        icmp_data[3] = 0;
        const icmp_csum = computeChecksum(icmp_data);
        std.mem.writeInt(u16, icmp_data[2..4][0..2], icmp_csum, .big);

        // 3. 交换 IPv4 源地址与目的地址
        for (0..4) |i| {
            const tmp = packet[12 + i];
            packet[12 + i] = packet[16 + i];
            packet[16 + i] = tmp;
        }

        // 4. 重算 IP 头校验和
        packet[10] = 0;
        packet[11] = 0;
        const ip_hdr_len: usize = @as(usize, ip.ihl) * 4;
        const ip_csum = computeChecksum(packet[0..ip_hdr_len]);
        std.mem.writeInt(u16, packet[10..12][0..2], ip_csum, .big);

        return packet[0..ip.total_len];
    }

    /// 解析 TCP 报头
    pub fn parseTcp(payload: []const u8) ?TcpHeader {
        if (payload.len < 20) return null;

        const data_offset_byte = payload[12];
        const data_offset: u4 = @truncate(data_offset_byte >> 4);
        const header_len: usize = @as(usize, data_offset) * 4;
        if (header_len < 20 or header_len > payload.len) return null;

        const flags = std.mem.readInt(u16, payload[12..14][0..2], .big) & 0x01FF;

        return .{
            .src_port = std.mem.readInt(u16, payload[0..2][0..2], .big),
            .dst_port = std.mem.readInt(u16, payload[2..4][0..2], .big),
            .seq = std.mem.readInt(u32, payload[4..8][0..4], .big),
            .ack = std.mem.readInt(u32, payload[8..12][0..4], .big),
            .data_offset = data_offset,
            .flags = @truncate(flags),
            .window = std.mem.readInt(u16, payload[14..16][0..2], .big),
            .checksum = std.mem.readInt(u16, payload[16..18][0..2], .big),
            .payload_start = header_len,
            .payload_end = payload.len,
        };
    }

    /// 计算 TCP 伪头部校验和
    pub fn computeTcpChecksum(src_ip: [4]u8, dst_ip: [4]u8, tcp_segment: []const u8) u16 {
        var sum: u32 = 0;

        // 伪头部：源 IP(4) + 目的 IP(4) + 0(1) + 协议(1) + TCP长度(2)
        sum += std.mem.readInt(u16, src_ip[0..2][0..2], .big);
        sum += std.mem.readInt(u16, src_ip[2..4][0..2], .big);
        sum += std.mem.readInt(u16, dst_ip[0..2][0..2], .big);
        sum += std.mem.readInt(u16, dst_ip[2..4][0..2], .big);
        sum += @as(u32, IPPROTO_TCP);
        sum += @as(u32, @intCast(tcp_segment.len));

        var i: usize = 0;
        while (i + 1 < tcp_segment.len) : (i += 2) {
            sum += std.mem.readInt(u16, tcp_segment[i..][0..2], .big);
        }
        if (i < tcp_segment.len) {
            sum += @as(u32, tcp_segment[i]) << 8;
        }

        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~@as(u16, @intCast(sum & 0xFFFF));
    }

    pub const UdpHeader = struct {
        src_port: u16,
        dst_port: u16,
        length: u16,
        checksum: u16,
        payload_start: usize,
        payload_end: usize,
    };

    /// 解析 UDP 头部
    pub fn parseUdp(payload: []const u8) ?UdpHeader {
        if (payload.len < 8) return null;
        const len = std.mem.readInt(u16, payload[4..6][0..2], .big);
        if (len < 8 or len > payload.len) return null;
        return .{
            .src_port = std.mem.readInt(u16, payload[0..2][0..2], .big),
            .dst_port = std.mem.readInt(u16, payload[2..4][0..2], .big),
            .length = len,
            .checksum = std.mem.readInt(u16, payload[6..8][0..2], .big),
            .payload_start = 8,
            .payload_end = len,
        };
    }

    /// 构造 IPv4 UDP 数据报（写回 TUN）
    pub fn buildUdpPacket(
        src_ip: [4]u8,
        src_port: u16,
        dst_ip: [4]u8,
        dst_port: u16,
        payload: []const u8,
        out: []u8,
    ) !usize {
        const total_len = 20 + 8 + payload.len;
        if (out.len < total_len) return error.BufferTooSmall;

        // 1. IPv4 报头 (20 字节)
        out[0] = 0x45; // Ver=4, IHL=5
        out[1] = 0x00; // TOS
        std.mem.writeInt(u16, out[2..4][0..2], @intCast(total_len), .big);
        std.mem.writeInt(u16, out[4..6][0..2], 0, .big); // ID
        std.mem.writeInt(u16, out[6..8][0..2], 0, .big); // Flags + Frag
        out[8] = 64; // TTL
        out[9] = IPPROTO_UDP;
        std.mem.writeInt(u16, out[10..12][0..2], 0, .big); // Checksum 置零
        @memcpy(out[12..16], &src_ip);
        @memcpy(out[16..20], &dst_ip);
        const ip_csum = computeChecksum(out[0..20]);
        std.mem.writeInt(u16, out[10..12][0..2], ip_csum, .big);

        // 2. UDP 报头 (8 字节)
        std.mem.writeInt(u16, out[20..22][0..2], src_port, .big);
        std.mem.writeInt(u16, out[22..24][0..2], dst_port, .big);
        std.mem.writeInt(u16, out[24..26][0..2], @intCast(8 + payload.len), .big);
        std.mem.writeInt(u16, out[26..28][0..2], 0, .big); // UDP Checksum 可选 (0 表示不校验)

        // 3. 载荷
        @memcpy(out[28..total_len], payload);

        return total_len;
    }

    /// 对 incoming TCP SYN 报文构造 SYN-ACK 应答包（用于 TUN 用户态 TCP 握手代答）
    pub fn buildTcpSynAck(pkt: []const u8, out: []u8) !usize {
        const ip = parseIpv4(pkt) orelse return error.InvalidPacket;
        if (ip.proto != IPPROTO_TCP) return error.NotTcp;
        const tcp = parseTcp(pkt[ip.payload_start..ip.payload_end]) orelse return error.InvalidPacket;

        const total_len: usize = 20 + 20; // IPv4(20) + TCP(20)
        if (out.len < total_len) return error.BufferTooSmall;

        // IPv4 报头
        out[0] = 0x45;
        out[1] = 0x00;
        std.mem.writeInt(u16, out[2..4][0..2], @intCast(total_len), .big);
        std.mem.writeInt(u16, out[4..6][0..2], 0, .big);
        std.mem.writeInt(u16, out[6..8][0..2], 0, .big);
        out[8] = 64;
        out[9] = IPPROTO_TCP;
        std.mem.writeInt(u16, out[10..12][0..2], 0, .big);
        @memcpy(out[12..16], &ip.dst); // Swap: Src = 原 Dst
        @memcpy(out[16..20], &ip.src); // Swap: Dst = 原 Src
        std.mem.writeInt(u16, out[10..12][0..2], computeChecksum(out[0..20]), .big);

        // TCP 报头
        std.mem.writeInt(u16, out[20..22][0..2], tcp.dst_port, .big); // Swap ports
        std.mem.writeInt(u16, out[22..24][0..2], tcp.src_port, .big);
        std.mem.writeInt(u32, out[24..28][0..4], 0x1000, .big); // Local Seq = 0x1000
        std.mem.writeInt(u32, out[28..32][0..4], tcp.seq +% 1, .big); // Ack = incoming Seq + 1
        out[32] = 0x50; // DataOffset = 5 (20 bytes)
        out[33] = @truncate(TcpFlags.SYN | TcpFlags.ACK); // Flags: SYN + ACK
        std.mem.writeInt(u16, out[34..36][0..2], 64240, .big); // Window
        std.mem.writeInt(u16, out[36..38][0..2], 0, .big); // Checksum 预先置零
        std.mem.writeInt(u16, out[38..40][0..2], 0, .big); // Urgent

        const tcp_csum = computeTcpChecksum(ip.dst, ip.src, out[20..40]);
        std.mem.writeInt(u16, out[36..38][0..2], tcp_csum, .big);

        return total_len;
    }

    // ============================ 测试 ============================






};

pub const tcpopt = struct {
    //! TCP 选项编解码与协商（RFC 793 / 7323 / 2018）。
    //!
    //! 支持的选项：
    //! - **MSS**（Kind 2）：最大段长度，握手时协商
    //! - **窗口缩放**（Kind 3）：把 16 位窗口左移到最多 30 位
    //! - **SACK Permitted**（Kind 4）：允许选择性确认
    //! - **SACK 块**（Kind 5）：报告乱序区间，用于精准重传
    //! - **时间戳**（Kind 8）：精确的 RTT 测量 + PAWS（防序号回绕）
    //! - EOL / NOP（填充）
    //!
    //! 为什么需要：没有这些选项，TCP 在高带宽或长肥管道下性能会很差
    //! （窗口最大 64KB），且 RTT 测量会因重传而产生歧义。

    pub const Kind = enum(u8) {
        eol = 0,
        nop = 1,
        mss = 2,
        window_scale = 3,
        sack_permitted = 4,
        sack = 5,
        timestamp = 8,
        _,
    };

    /// 窗口缩放最大移位（RFC 7323 规定 ≤14）
    pub const max_window_shift: u8 = 14;

    pub const Error = error{
        BufferTooSmall,
        MalformedOption,
        InvalidShift,
    };

    /// 解析出的选项集合
    pub const Options = struct {
        /// MSS（未出现则为 536，RFC 1122 默认值）
        mss: u16 = 536,
        /// 窗口缩放移位（0-14），None 表示不缩放
        window_shift: ?u8 = null,
        /// 是否允许 SACK
        sack_permitted: bool = false,
        /// SACK 块（左闭右开区间的序号）
        sack_blocks: [4]?SackBlock = @splat(null),
        /// 时间戳值
        ts_val: ?u32 = null,
        ts_ecr: ?u32 = null,

        pub const SackBlock = struct {
            /// 已收到的连续区间起点
            left: u32,
            /// 终点（不含）
            right: u32,
        };

        /// 把 16 位窗口按缩放移位还原成真实窗口
        pub fn scaleWindow(self: *const Options, window: u16) u32 {
            const shift = self.window_shift orelse 0;
            return @as(u32, window) << @intCast(shift);
        }

        /// 把真实窗口按缩放移位压回 16 位（发送时用）
        pub fn unscaleWindow(self: *const Options, window: u32) u16 {
            const shift = self.window_shift orelse 0;
            const shifted = window >> @intCast(shift);
            return @truncate(@min(shifted, 0xFFFF));
        }

        pub fn sackCount(self: *const Options) usize {
            var n: usize = 0;
            for (self.sack_blocks) |b| {
                if (b != null) n += 1;
            }
            return n;
        }
    };

    /// 解析 TCP 选项区
    pub fn parse(opts: []const u8) Error!Options {
        var out = Options{};
        var i: usize = 0;

        while (i < opts.len) {
            const kind: u8 = opts[i];
            switch (kind) {
                0 => break, // EOL
                1 => {
                    i += 1; // NOP
                    continue;
                },
                2 => { // MSS
                    if (i + 4 > opts.len) return error.MalformedOption;
                    if (opts[i + 1] != 4) return error.MalformedOption;
                    out.mss = std.mem.readInt(u16, opts[i + 2 ..][0..2], .big);
                    i += 4;
                },
                3 => { // Window Scale
                    if (i + 3 > opts.len) return error.MalformedOption;
                    if (opts[i + 1] != 3) return error.MalformedOption;
                    const shift = opts[i + 2];
                    if (shift > max_window_shift) return error.InvalidShift;
                    out.window_shift = shift;
                    i += 3;
                },
                4 => { // SACK Permitted
                    if (i + 2 > opts.len) return error.MalformedOption;
                    if (opts[i + 1] != 2) return error.MalformedOption;
                    out.sack_permitted = true;
                    i += 2;
                },
                5 => { // SACK blocks
                    if (i + 2 > opts.len) return error.MalformedOption;
                    const len = opts[i + 1];
                    if (len < 2 or len > 34) return error.MalformedOption;
                    if (i + len > opts.len) return error.MalformedOption;
                    const nblocks = (len - 2) / 8;
                    if (nblocks > 4) return error.MalformedOption;

                    var b: usize = 0;
                    while (b < nblocks) : (b += 1) {
                        const off = i + 2 + b * 8;
                        out.sack_blocks[b] = .{
                            .left = std.mem.readInt(u32, opts[off..][0..4], .big),
                            .right = std.mem.readInt(u32, opts[off + 4 ..][0..4], .big),
                        };
                    }
                    i += len;
                },
                8 => { // Timestamps
                    if (i + 10 > opts.len) return error.MalformedOption;
                    if (opts[i + 1] != 10) return error.MalformedOption;
                    out.ts_val = std.mem.readInt(u32, opts[i + 2 ..][0..4], .big);
                    out.ts_ecr = std.mem.readInt(u32, opts[i + 6 ..][0..4], .big);
                    i += 10;
                },
                else => {
                    // 未知选项：按 length 字段跳过
                    if (i + 2 > opts.len) return error.MalformedOption;
                    const len = opts[i + 1];
                    if (len < 2) return error.MalformedOption;
                    if (i + len > opts.len) return error.MalformedOption;
                    i += len;
                },
            }
        }
        return out;
    }

    /// 写入 MSS 选项
    pub fn writeMss(buf: []u8, mss: u16) !usize {
        if (buf.len < 4) return error.BufferTooSmall;
        buf[0] = 2;
        buf[1] = 4;
        std.mem.writeInt(u16, buf[2..4], mss, .big);
        return 4;
    }

    /// 写入窗口缩放选项
    pub fn writeWindowScale(buf: []u8, shift: u8) !usize {
        if (shift > max_window_shift) return error.InvalidShift;
        if (buf.len < 3) return error.BufferTooSmall;
        buf[0] = 3;
        buf[1] = 3;
        buf[2] = shift;
        return 3;
    }

    /// 写入 SACK Permitted 选项
    pub fn writeSackPermitted(buf: []u8) !usize {
        if (buf.len < 2) return error.BufferTooSmall;
        buf[0] = 4;
        buf[1] = 2;
        return 2;
    }

    /// 写入时间戳选项
    pub fn writeTimestamp(buf: []u8, ts_val: u32, ts_ecr: u32) !usize {
        if (buf.len < 10) return error.BufferTooSmall;
        buf[0] = 8;
        buf[1] = 10;
        std.mem.writeInt(u32, buf[2..6], ts_val, .big);
        std.mem.writeInt(u32, buf[6..10], ts_ecr, .big);
        return 10;
    }

    /// 写入 SACK 块选项（最多 4 块）
    pub fn writeSack(buf: []u8, blocks: []const Options.SackBlock) !usize {
        if (blocks.len == 0 or blocks.len > 4) return error.MalformedOption;
        const len: usize = 2 + blocks.len * 8;
        if (buf.len < len) return error.BufferTooSmall;
        buf[0] = 5;
        buf[1] = @intCast(len);
        var i: usize = 0;
        while (i < blocks.len) : (i += 1) {
            const off = 2 + i * 8;
            std.mem.writeInt(u32, buf[off..][0..4], blocks[i].left, .big);
            std.mem.writeInt(u32, buf[off + 4 ..][0..4], blocks[i].right, .big);
        }
        return len;
    }

    /// 构造 SYN 段携带的选项（MSS + WS + SACK Permitted + Timestamp）
    ///
    /// `ts_ecr` 在纯 SYN 里为 0；**SYN-ACK 必须回显对端的 `ts_val`**，
    /// 否则对端会认为时间戳协商失败而丢弃后续所有带时间戳的段
    /// （RFC 7323 §3.2）。早期版本硬编码 0，握手能过、一发数据就断。
    pub fn buildSynOptions(
        buf: []u8,
        mss: u16,
        window_shift: u8,
        enable_sack: bool,
        ts_val: ?u32,
    ) !usize {
        return buildSynOptionsEx(buf, mss, window_shift, enable_sack, ts_val, 0);
    }

    pub fn buildSynOptionsEx(
        buf: []u8,
        mss: u16,
        window_shift: u8,
        enable_sack: bool,
        ts_val: ?u32,
        ts_ecr: u32,
    ) !usize {
        var n: usize = 0;
        n += try writeMss(buf[n..], mss);
        n += try writeWindowScale(buf[n..], window_shift);
        if (enable_sack) {
            n += try writeSackPermitted(buf[n..]);
        }
        if (ts_val) |ts| {
            n += try writeTimestamp(buf[n..], ts, ts_ecr);
        }
        // 4 字节对齐
        while (n % 4 != 0) {
            if (n >= buf.len) break;
            buf[n] = 1; // NOP
            n += 1;
        }
        return n;
    }

    /// 协商：把本端请求与对端提供的选项求交集
    pub fn negotiate(local: Options, remote: Options) Options {
        return .{
            // MSS 取较小值
            .mss = @min(local.mss, remote.mss),
            // 窗口缩放：双方都支持才生效
            .window_shift = if (local.window_shift != null and remote.window_shift != null)
                @min(local.window_shift.?, remote.window_shift.?)
            else
                null,
            // SACK 需双方都允许
            .sack_permitted = local.sack_permitted and remote.sack_permitted,
            .ts_val = local.ts_val,
            .ts_ecr = remote.ts_val,
        };
    }

    // ============================ 测试 ============================



















};

pub const timers = struct {
    //! TCP 定时器集合（RFC 6298 / RFC 1122）。
    //!
    //! **为什么单独成模块**：TCP 有 4 个独立定时器，各自超时语义不同，
    //! 混在状态机里极易写错。这里把「什么时候该干什么」抽出来，
    //! 状态机只负责响应事件。
    //!
    //! 四个定时器：
    //! 1. **重传定时器（RTO）**：最早未确认段超时 → 重传
    //! 2. **坚持定时器（Persist）**：对端窗口为 0 → 周期性发探测包
    //! 3. **保活定时器（Keepalive）**：长时间空闲 → 探测对端是否存活
    //! 4. **TIME_WAIT 定时器**：2MSL 后关闭连接
    //!
    //! 坚持定时器是本文件的核心 —— 它解决「对端窗口归零后双方互相干等」的死锁：
    //! 发送方不再发数据、接收方等数据才能开窗，连接就僵死在那里。

    pub const Config = struct {
        /// 初始 RTO（毫秒）
        initial_rto_ms: u32 = 1000,
        /// 最小 RTO
        min_rto_ms: u32 = 200,
        /// 最大 RTO
        max_rto_ms: u32 = 60_000,
        /// 坚持定时器初始间隔（毫秒）
        persist_min_ms: u32 = 500,
        /// 坚持定时器最大间隔（毫秒）
        persist_max_ms: u32 = 60_000,
        /// 保活空闲时间（毫秒）
        keepalive_idle_ms: i64 = 7_200_000, // 2 小时
        /// 保活探测间隔
        keepalive_interval_ms: i64 = 75_000,
        /// 保活最大探测次数
        keepalive_probes: u8 = 9,
        /// TIME_WAIT 停留（2MSL）
        time_wait_ms: i64 = 60_000,
    };

    /// 定时器事件：调用方据此决定动作
    pub const Event = enum {
        /// 无需动作
        none,
        /// 重传最早未确认段
        retransmit,
        /// 发送零窗口探测（1 字节或空段）
        persist_probe,
        /// 发送保活探测
        keepalive_probe,
        /// 保活失败，连接应关闭
        keepalive_failed,
        /// TIME_WAIT 结束，连接可关闭
        time_wait_expired,
    };

    /// 连接定时器状态
    pub const Timers = struct {
        cfg: Config,

        // ---- RTO 定时器 ----
        /// 重传定时器的截止时间（0 表示未启动）
        rto_deadline: i64 = 0,
        /// 当前 RTO 值
        rto_ms: u32,
        /// 已连续重传次数
        retransmits: u8 = 0,

        // ---- 坚持定时器 ----
        /// 是否处于零窗口状态
        persist_active: bool = false,
        persist_deadline: i64 = 0,
        persist_interval_ms: u32 = 500,
        persist_probes: u32 = 0,

        // ---- 保活定时器 ----
        keepalive_deadline: i64 = 0,
        keepalive_probes_sent: u8 = 0,

        // ---- TIME_WAIT ----
        time_wait_deadline: i64 = 0,

        pub fn init(cfg: Config) Timers {
            return .{
                .cfg = cfg,
                .rto_ms = cfg.initial_rto_ms,
                .persist_interval_ms = cfg.persist_min_ms,
            };
        }

        // ------------------------------------------------------------------------
        // RTO
        // ------------------------------------------------------------------------

        /// 有数据发出时启动（若未启动）
        pub fn startRto(self: *Timers, now_ms: i64) void {
            if (self.rto_deadline == 0) {
                self.rto_deadline = now_ms + self.rto_ms;
            }
        }

        /// 所有数据被确认后停止
        pub fn stopRto(self: *Timers) void {
            self.rto_deadline = 0;
            self.retransmits = 0;
            self.rto_ms = self.cfg.initial_rto_ms;
        }

        /// 用新的 RTT 估计更新 RTO
        pub fn updateRto(self: *Timers, srtt_ms: f32, rttvar_ms: f32) void {
            const computed = srtt_ms + @max(10.0, 4.0 * rttvar_ms);
            self.rto_ms = @intFromFloat(@max(
                @as(f32, @floatFromInt(self.cfg.min_rto_ms)),
                @min(@as(f32, @floatFromInt(self.cfg.max_rto_ms)), computed),
            ));
        }

        /// 重传发生后指数退避
        pub fn onRetransmit(self: *Timers, now_ms: i64) void {
            self.retransmits +|= 1;
            const shift: u5 = @intCast(@min(self.retransmits - 1, 6));
            const backoff = std.math.shl(u32, self.rto_ms, shift);
            const next = @min(backoff, self.cfg.max_rto_ms);
            self.rto_deadline = now_ms + next;
        }

        pub fn rtoExpired(self: *Timers, now_ms: i64) bool {
            return self.rto_deadline != 0 and now_ms >= self.rto_deadline;
        }

        pub fn tooManyRetransmits(self: *const Timers) bool {
            return self.retransmits >= 8;
        }

        // ------------------------------------------------------------------------
        // 坚持定时器（零窗口探测）
        // ------------------------------------------------------------------------

        /// 是否处于零窗口探测状态
        pub fn persistActive(self: *const Timers) bool {
            return self.persist_active;
        }

        /// 对端窗口归零且有数据要发 → 启动坚持定时器
        pub fn startPersist(self: *Timers, now_ms: i64) void {
            if (self.persist_active) return;
            self.persist_active = true;
            self.persist_interval_ms = self.cfg.persist_min_ms;
            self.persist_deadline = now_ms + self.persist_interval_ms;
            self.persist_probes = 0;
        }

        /// 窗口重新打开 → 停止探测
        pub fn stopPersist(self: *Timers) void {
            self.persist_active = false;
            self.persist_deadline = 0;
            self.persist_interval_ms = self.cfg.persist_min_ms;
            self.persist_probes = 0;
        }

        /// 探测发出后：间隔指数退避，封顶到 persist_max
        pub fn onPersistProbe(self: *Timers, now_ms: i64) void {
            self.persist_probes +%= 1;
            const shift: u5 = @intCast(@min(self.persist_probes - 1, 6));
            const next = std.math.shl(u32, self.cfg.persist_min_ms, shift);
            self.persist_interval_ms = @min(next, self.cfg.persist_max_ms);
            self.persist_deadline = now_ms + self.persist_interval_ms;
        }

        pub fn persistExpired(self: *Timers, now_ms: i64) bool {
            return self.persist_active and now_ms >= self.persist_deadline;
        }

        // ------------------------------------------------------------------------
        // 保活
        // ------------------------------------------------------------------------

        pub fn startKeepalive(self: *Timers, now_ms: i64) void {
            self.keepalive_deadline = now_ms + self.cfg.keepalive_idle_ms;
            self.keepalive_probes_sent = 0;
        }

        pub fn resetKeepalive(self: *Timers, now_ms: i64) void {
            self.keepalive_deadline = now_ms + self.cfg.keepalive_idle_ms;
            self.keepalive_probes_sent = 0;
        }

        pub fn keepaliveExpired(self: *Timers, now_ms: i64) bool {
            return self.keepalive_deadline != 0 and now_ms >= self.keepalive_deadline;
        }

        pub fn onKeepaliveProbe(self: *Timers, now_ms: i64) void {
            self.keepalive_probes_sent +|= 1;
            self.keepalive_deadline = now_ms + self.cfg.keepalive_interval_ms;
        }

        pub fn keepaliveFailed(self: *const Timers) bool {
            return self.keepalive_probes_sent >= self.cfg.keepalive_probes;
        }

        // ------------------------------------------------------------------------
        // TIME_WAIT
        // ------------------------------------------------------------------------

        pub fn startTimeWait(self: *Timers, now_ms: i64) void {
            self.time_wait_deadline = now_ms + self.cfg.time_wait_ms;
        }

        pub fn timeWaitExpired(self: *Timers, now_ms: i64) bool {
            return self.time_wait_deadline != 0 and now_ms >= self.time_wait_deadline;
        }

        // ------------------------------------------------------------------------
        // 统一驱动
        // ------------------------------------------------------------------------

        /// 检查所有定时器，返回应该执行的动作。
        ///
        /// `has_unsent_data`：是否有数据因窗口为 0 而发不出去
        /// `in_time_wait`：连接是否处于 TIME_WAIT
        pub fn tick(
            self: *Timers,
            now_ms: i64,
            has_unsent_data: bool,
            in_time_wait: bool,
        ) Event {
            // TIME_WAIT 优先级最高：结束后直接关闭
            if (in_time_wait) {
                if (self.timeWaitExpired(now_ms)) return .time_wait_expired;
                return .none;
            }

            // 零窗口探测优先于普通重传：
            // 窗口为 0 时重传数据没有意义（对端收不下）
            if (self.persist_active) {
                if (self.persistExpired(now_ms)) {
                    self.onPersistProbe(now_ms);
                    return .persist_probe;
                }
            } else if (has_unsent_data and self.persist_active == false) {
                // 有数据但窗口为 0（由调用方判断），启动探测
                // 注意：这里不自动启动，由调用方在发现窗口为 0 时调 startPersist
            }

            // RTO 重传
            if (self.rtoExpired(now_ms)) {
                if (self.tooManyRetransmits()) return .keepalive_failed; // 视为连接已死
                self.onRetransmit(now_ms);
                return .retransmit;
            }

            // 保活
            if (self.keepaliveExpired(now_ms)) {
                if (self.keepaliveFailed()) return .keepalive_failed;
                self.onKeepaliveProbe(now_ms);
                return .keepalive_probe;
            }

            return .none;
        }
    };

    // ============================ 测试 ============================















    fn dummyPersistAccessor(t: *const Timers) bool {
        return t.persist_active;
    }


};

pub const cc = struct {
    //! TCP 拥塞控制（RFC 5681 + NewReno 快重传/快恢复）。
    //!
    //! **为什么单独成模块**：拥塞控制是一组与连接状态机正交的算法 ——
    //! 它只关心「什么事件发生 → cwnd/ssthresh 怎么变」，
    //! 状态机关心「收到什么包 → 发什么包」。分开后两者都能独立测试。
    //!
    //! 实现的算法：
    //! - 慢启动（Slow Start）：cwnd < ssthresh 时每 ACK 增 1 MSS（指数增长）
    //! - 拥塞避免（Congestion Avoidance）：cwnd >= ssthresh 时每 RTT 增 1 MSS
    //! - 快速重传（Fast Retransmit）：收到 3 个重复 ACK 立即重传
    //! - 快速恢复（Fast Recovery，NewReno）：不回到慢启动，而是 cwnd = ssthresh + 3*MSS
    //! - RTO 超时：ssthresh = max(FlightSize/2, 2*MSS)，cwnd 回到 1 MSS（回到慢启动）
    //!
    //! 不做的：
    //! - CUBIC / BBR（TUN 场景对端是本机，RTT 恒定且极低，收益不明显）
    //! - ECN（对端支持率低）

    pub const Mss = u16;

    /// 拥塞控制状态
    pub const Phase = enum {
        /// 慢启动
        slow_start,
        /// 拥塞避免
        congestion_avoidance,
        /// 快速恢复
        fast_recovery,

        pub fn name(self: Phase) []const u8 {
            return switch (self) {
                .slow_start => "slow-start",
                .congestion_avoidance => "congestion-avoidance",
                .fast_recovery => "fast-recovery",
            };
        }
    };

    pub const Config = struct {
        /// 初始拥塞窗口（RFC 6928 建议 10 MSS）
        initial_cwnd: u32 = 10,
        /// 初始慢启动阈值（设得很大，让慢启动先跑）
        initial_ssthresh: u32 = 0xFFFF_FFFF,
        /// 最小 MSS
        mss: u16 = 1460,
        /// 快速重传阈值（通常 3）
        dup_ack_threshold: u8 = 3,
        /// 最大 cwnd（防止无限增长）
        max_cwnd: u32 = 0xFFFF,
    };

    /// 拥塞控制器
    pub const Controller = struct {
        cfg: Config,

        /// 拥塞窗口（以 MSS 为单位）
        cwnd: u32,
        /// 慢启动阈值（以 MSS 为单位）
        ssthresh: u32,
        /// 当前阶段
        phase: Phase = .slow_start,

        /// 已确认字节数（用于拥塞避免的增量式增长）
        bytes_acked: u32 = 0,
        /// 重复 ACK 计数
        dup_acks: u8 = 0,
        /// 在途字节（用于判断是否受限）
        flight_size: u32 = 0,

        /// 统计
        stat_fast_retransmit: u32 = 0,
        stat_rto_timeout: u32 = 0,
        stat_cwnd_reductions: u32 = 0,

        pub fn init(cfg: Config) Controller {
            return .{
                .cfg = cfg,
                .cwnd = cfg.initial_cwnd,
                .ssthresh = cfg.initial_ssthresh,
            };
        }

        /// 当前 cwnd 对应的字节数
        pub fn windowBytes(self: *const Controller) u32 {
            return self.cwnd * self.cfg.mss;
        }

        /// 是否能再发一个 MSS
        pub fn canSend(self: *const Controller) bool {
            return self.flight_size + self.cfg.mss <= self.windowBytes();
        }

        /// 记录已发送（增加在途字节）
        pub fn onSend(self: *Controller, bytes: u32) void {
            self.flight_size += bytes;
        }

        // ------------------------------------------------------------------------
        // 事件
        // ------------------------------------------------------------------------

        /// 收到新数据的 ACK（推进了 snd_una）
        pub fn onAck(self: *Controller, acked_bytes: u32) void {
            if (acked_bytes == 0) return;

            // 在途字节减少
            self.flight_size = if (self.flight_size > acked_bytes)
                self.flight_size - acked_bytes
            else
                0;

            // 任何推进性 ACK 都清零 dup-ack 计数
            self.dup_acks = 0;

            switch (self.phase) {
                .slow_start => {
                    // 每收到一个 ACK，cwnd += 1 MSS（指数增长）
                    // 用累计字节数近似「每 ACK 增 1 MSS」
                    self.bytes_acked += acked_bytes;
                    while (self.bytes_acked >= self.cfg.mss) {
                        self.bytes_acked -= self.cfg.mss;
                        self.cwnd = @min(self.cwnd + 1, self.cfg.max_cwnd);
                        if (self.cwnd >= self.ssthresh) {
                            self.phase = .congestion_avoidance;
                            break;
                        }
                    }
                },
                .congestion_avoidance => {
                    // 每 RTT 增 1 MSS：累积 acked_bytes 到 cwnd*MSS 后 cwnd += 1
                    self.bytes_acked += acked_bytes;
                    const threshold = self.cwnd * self.cfg.mss;
                    if (self.bytes_acked >= threshold) {
                        self.bytes_acked -= threshold;
                        self.cwnd = @min(self.cwnd + 1, self.cfg.max_cwnd);
                    }
                },
                .fast_recovery => {
                    // 快速恢复期间：收到新 ACK 说明恢复完成，退出到拥塞避免
                    self.phase = .congestion_avoidance;
                    self.cwnd = self.ssthresh;
                    self.bytes_acked = 0;
                },
            }
        }

        /// 收到重复 ACK
        ///
        /// 返回 true 表示达到了快速重传阈值，调用方应立即重传最早的未确认段。
        pub fn onDupAck(self: *Controller) bool {
            self.dup_acks +|= 1;

            if (self.phase == .fast_recovery) {
                // 快速恢复期间每多一个 dup-ACK，cwnd += 1 MSS（允许继续发新数据）
                self.cwnd = @min(self.cwnd + 1, self.cfg.max_cwnd);
                return false;
            }

            if (self.dup_acks == self.cfg.dup_ack_threshold) {
                // 进入快速恢复
                self.enterFastRecovery();
                self.stat_fast_retransmit += 1;
                return true;
            }
            return false;
        }

        fn enterFastRecovery(self: *Controller) void {
            // RFC 5681：ssthresh = max(FlightSize/2, 2*MSS)
            const half_flight = self.flight_size / 2;
            const min_window = 2 * @as(u32, self.cfg.mss);
            self.ssthresh = @max(half_flight / self.cfg.mss, 2);

            // cwnd = ssthresh + 3*MSS（NewReno）
            self.cwnd = self.ssthresh + self.cfg.dup_ack_threshold;
            self.phase = .fast_recovery;
            self.stat_cwnd_reductions += 1;
            _ = min_window;
        }

        /// RTO 超时：最严重的拥塞信号
        pub fn onTimeout(self: *Controller) void {
            self.stat_rto_timeout += 1;
            self.stat_cwnd_reductions += 1;

            // ssthresh = max(FlightSize/2, 2*MSS)
            const half = self.flight_size / 2 / self.cfg.mss;
            self.ssthresh = @max(half, 2);

            // cwnd 回到 1 MSS，重新慢启动
            self.cwnd = 1;
            self.phase = .slow_start;
            self.dup_acks = 0;
            self.bytes_acked = 0;
            self.flight_size = 0; // 所有在途数据都被认为丢失
        }

        /// 重传超时后恢复发送（cwnd 逐步恢复）
        pub fn onRetransmitSent(self: *Controller, bytes: u32) void {
            self.flight_size += bytes;
        }
    };

    // ============================ 测试 ============================













};

pub const tun_conn = struct {
    //! TUN 侧的连接表与数据包构造。
    //!
    //! 现有 `tun_stack.buildTcpSynAck` 只能回一个 SYN-ACK（本端 seq 写死 0x1000），
    //! 既没有连接状态也没有数据通路 —— 客户端完成三次握手后发数据，
    //! 这里没有任何代码处理，连接就是死的。
    //!
    //! 本模块补上数据面所需的两件事：
    //! 1. **连接表**：以 (src_ip, src_port, dst_ip, dst_port) 为键，
    //!    记录双方 seq/ack、状态、以及对应的上游 socket。
    //! 2. **报文构造**：能按给定 seq/ack/flags 生成任意 TCP 段（含数据），
    //!    以及 UDP 报文，供回写 TUN 使用。
    //!
    //! 说明：这里做的是「逐连接字节流转发」而非完整 TCP 状态机。
    //! 对代理场景已经够用：客户端与服务端各自看到的都是一条正常 TCP 连接，
    //! 我们只负责按序转发并维护 seq 窗口。重传/拥塞控制交给两端内核。


    pub const TcpFlags = tun_stack.TcpFlags;

    /// 连接键
    pub const Key = struct {
        src_ip: [4]u8,
        src_port: u16,
        dst_ip: [4]u8,
        dst_port: u16,

        pub fn hash(self: Key) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(&self.src_ip);
            h.update(std.mem.asBytes(&self.src_port));
            h.update(&self.dst_ip);
            h.update(std.mem.asBytes(&self.dst_port));
            return h.final();
        }

        pub fn eql(a: Key, b: Key) bool {
            return std.mem.eql(u8, &a.src_ip, &b.src_ip) and
                a.src_port == b.src_port and
                std.mem.eql(u8, &a.dst_ip, &b.dst_ip) and
                a.dst_port == b.dst_port;
        }
    };

    pub const State = enum {
        /// 已回 SYN-ACK，等客户端 ACK
        syn_received,
        /// 三次握手完成，可转发数据
        established,
        /// 已发 FIN
        closing,
        closed,
    };

    /// 一条 TUN 连接
    pub const Conn = struct {
        key: Key,
        state: State = .syn_received,

        /// 本端（面向客户端）的序号
        local_seq: u32,
        local_ack: u32,
        /// 对端（客户端）序号
        remote_seq: u32,

        /// 上游连接句柄（由调用方填入；-1 表示尚未建立）
        upstream_fd: i64 = -1,

        /// 最近活跃时间（毫秒），用于回收
        last_active_ms: i64 = 0,
    };

    /// 简易连接表。
    ///
    /// 不做 LRU：TUN 场景下并发连接数受客户端限制，且每条连接都有存活时间，
    /// 直接线性扫描 + 上限淘汰足够，且没有哈希冲突的边界问题。
    pub const Table = struct {
        alloc: std.mem.Allocator,
        conns: std.ArrayList(Conn) = .empty,
        max_conns: usize = 1024,
        /// 生成 local_seq 的计数器，保证不同连接起始序号不同
        seq_seed: u32 = 0x1000_0000,

        pub fn init(alloc: std.mem.Allocator) Table {
            return .{ .alloc = alloc };
        }

        pub fn deinit(self: *Table) void {
            self.conns.deinit(self.alloc);
        }

        pub fn count(self: *Table) usize {
            return self.conns.items.len;
        }

        pub fn find(self: *Table, key: Key) ?*Conn {
            for (self.conns.items) |*c| {
                if (Key.eql(c.key, key)) return c;
            }
            return null;
        }

        /// 新建连接（SYN 到达时调用），返回分配到的本端初始序号
        pub fn open(self: *Table, key: Key, client_seq: u32, now_ms: i64) !*Conn {
            if (self.conns.items.len >= self.max_conns) {
                try self.evictOldest();
            }

            self.seq_seed +%= 0x9E37_79B9;
            const local_seq = self.seq_seed;

            try self.conns.append(self.alloc, .{
                .key = key,
                .state = .syn_received,
                .local_seq = local_seq,
                .local_ack = client_seq +% 1,
                .remote_seq = client_seq,
                .last_active_ms = now_ms,
            });
            return &self.conns.items[self.conns.items.len - 1];
        }

        pub fn remove(self: *Table, key: Key) void {
            var i: usize = 0;
            while (i < self.conns.items.len) : (i += 1) {
                if (Key.eql(self.conns.items[i].key, key)) {
                    _ = self.conns.orderedRemove(i);
                    return;
                }
            }
        }

        /// 回收空闲超过 timeout_ms 的连接
        pub fn sweep(self: *Table, now_ms: i64, timeout_ms: i64) usize {
            var removed: usize = 0;
            var i: usize = 0;
            while (i < self.conns.items.len) {
                if (now_ms - self.conns.items[i].last_active_ms > timeout_ms) {
                    _ = self.conns.orderedRemove(i);
                    removed += 1;
                } else {
                    i += 1;
                }
            }
            return removed;
        }

        fn evictOldest(self: *Table) !void {
            if (self.conns.items.len == 0) return;
            var oldest: usize = 0;
            for (self.conns.items, 0..) |c, i| {
                if (c.last_active_ms < self.conns.items[oldest].last_active_ms) oldest = i;
            }
            _ = self.conns.orderedRemove(oldest);
        }
    };

    // ============================================================================
    // 报文构造
    // ============================================================================

    /// 段的额外属性：通告窗口与 TCP 选项。
    ///
    /// 早先这两样都写死（窗口恒 64240、选项区恒空），后果是：
    /// - 接收缓冲快满时仍通告 64KB，对端继续猛发，我们只能静默丢弃 → 数据损坏；
    /// - SYN-ACK 不带 MSS/窗口缩放/SACK/时间戳，等于协商结果只存在于内存里，
    ///   线路上完全没有生效。
    pub const SegmentOpts = struct {
        /// 通告窗口（未缩放值，调用方负责按 window_shift 压缩）
        window: u16 = 64240,
        /// TCP 选项字节（长度须为 4 的倍数，或由本函数补零对齐）
        options: []const u8 = "",
    };

    /// 构造一个 TCP 段（可带 payload），源/目的按**回给客户端**的方向：
    /// src = 原目标（服务端侧），dst = 原客户端。
    pub fn buildTcpSegment(
        out: []u8,
        src_ip: [4]u8,
        dst_ip: [4]u8,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u9,
        payload: []const u8,
    ) !usize {
        return buildTcpSegmentEx(out, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, .{}, payload);
    }

    /// 带选项与窗口的版本。
    pub fn buildTcpSegmentEx(
        out: []u8,
        src_ip: [4]u8,
        dst_ip: [4]u8,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u9,
        opts: SegmentOpts,
        payload: []const u8,
    ) !usize {
        // 选项区按 4 字节对齐；TCP 头最长 60 字节，即选项最多 40 字节
        const opt_len: usize = (opts.options.len + 3) / 4 * 4;
        if (opt_len > 40) return error.InvalidOptions;
        const tcp_hdr_len: usize = 20 + opt_len;
        const total = 20 + tcp_hdr_len + payload.len;
        if (out.len < total) return error.BufferTooSmall;

        // ---- IPv4 ----
        out[0] = 0x45;
        out[1] = 0x00;
        std.mem.writeInt(u16, out[2..4][0..2], @intCast(total), .big);
        std.mem.writeInt(u16, out[4..6][0..2], 0, .big);
        std.mem.writeInt(u16, out[6..8][0..2], 0x4000, .big); // DF
        out[8] = 64;
        out[9] = tun_stack.IPPROTO_TCP;
        std.mem.writeInt(u16, out[10..12][0..2], 0, .big);
        @memcpy(out[12..16], &src_ip);
        @memcpy(out[16..20], &dst_ip);
        std.mem.writeInt(u16, out[10..12][0..2], tun_stack.computeChecksum(out[0..20]), .big);

        // ---- TCP ----
        const t = out[20..];
        std.mem.writeInt(u16, t[0..2][0..2], src_port, .big);
        std.mem.writeInt(u16, t[2..4][0..2], dst_port, .big);
        std.mem.writeInt(u32, t[4..8][0..4], seq, .big);
        std.mem.writeInt(u32, t[8..12][0..4], ack, .big);
        t[12] = @intCast(tcp_hdr_len / 4 << 4); // data offset
        t[13] = @truncate(flags);
        std.mem.writeInt(u16, t[14..16][0..2], opts.window, .big);
        std.mem.writeInt(u16, t[16..18][0..2], 0, .big); // checksum 待填
        std.mem.writeInt(u16, t[18..20][0..2], 0, .big); // urgent

        // 选项区：先清零（对齐填充位必须是 NOP=1 才合法，见下）
        if (opt_len > 0) {
            @memset(t[20..tcp_hdr_len], 1); // 填充用 NOP，避免对端把 0 当 EOL 提前结束
            @memcpy(t[20 .. 20 + opts.options.len], opts.options);
        }

        if (payload.len > 0) @memcpy(t[tcp_hdr_len .. tcp_hdr_len + payload.len], payload);

        const seg = out[20..total];
        const csum = tun_stack.computeTcpChecksum(src_ip, dst_ip, seg);
        std.mem.writeInt(u16, seg[16..18][0..2], csum, .big);

        return total;
    }

    /// 构造 UDP 报文（回给客户端）
    pub fn buildUdpPacket(
        out: []u8,
        src_ip: [4]u8,
        dst_ip: [4]u8,
        src_port: u16,
        dst_port: u16,
        payload: []const u8,
    ) !usize {
        const total = 20 + 8 + payload.len;
        if (out.len < total) return error.BufferTooSmall;

        out[0] = 0x45;
        out[1] = 0x00;
        std.mem.writeInt(u16, out[2..4][0..2], @intCast(total), .big);
        std.mem.writeInt(u16, out[4..6][0..2], 0, .big);
        std.mem.writeInt(u16, out[6..8][0..2], 0x4000, .big);
        out[8] = 64;
        out[9] = tun_stack.IPPROTO_UDP;
        std.mem.writeInt(u16, out[10..12][0..2], 0, .big);
        @memcpy(out[12..16], &src_ip);
        @memcpy(out[16..20], &dst_ip);
        std.mem.writeInt(u16, out[10..12][0..2], tun_stack.computeChecksum(out[0..20]), .big);

        const u = out[20..];
        std.mem.writeInt(u16, u[0..2][0..2], src_port, .big);
        std.mem.writeInt(u16, u[2..4][0..2], dst_port, .big);
        std.mem.writeInt(u16, u[4..6][0..2], @intCast(8 + payload.len), .big);
        std.mem.writeInt(u16, u[6..8][0..2], 0, .big); // UDP 校验和可选，填 0

        if (payload.len > 0) @memcpy(u[8 .. 8 + payload.len], payload);
        return total;
    }

    /// 从 TCP 段里取出 payload 切片
    pub fn tcpPayload(pkt: []const u8) ?[]const u8 {
        const ip = tun_stack.parseIpv4(pkt) orelse return null;
        if (ip.proto != tun_stack.IPPROTO_TCP) return null;
        const seg = pkt[ip.payload_start..ip.payload_end];
        const tcp = tun_stack.parseTcp(seg) orelse return null;
        // parseTcp 已经算好 payload 的起止（相对于 seg）
        if (tcp.payload_start > tcp.payload_end or tcp.payload_end > seg.len) return null;
        return seg[tcp.payload_start..tcp.payload_end];
    }

    // ============================ 测试 ============================








};

pub const tcp_proto = struct {
    //! 用户态 TCP 协议栈 —— 生产级实现（RFC 793 / 9293）。
    //!
    //! **为什么需要它**：TUN 接管后拿到的是原始 IP 包，必须自己实现传输层。
    //! 现有的 `tun_runner` 只回 SYN-ACK，没有数据通路，连接建立后即死。
    //!
    //! 本模块实现完整的 TCP 状态机，并把三类算法外置到独立模块：
    //! - `cc.zig`      —— 拥塞控制（慢启动 / 拥塞避免 / 快重传 / 快恢复）
    //! - `timers.zig`  —— 四个定时器（RTO / 坚持 / 保活 / TIME_WAIT）
    //! - `tcpopt.zig`  —— 选项协商（MSS / 窗口缩放 / SACK / 时间戳）
    //!
    //! 状态机自身负责：
    //! - 三次握手 / 四次挥手
    //! - 滑动窗口 + 发送/接收缓冲
    //! - 乱序段重组
    //! - 序号回绕（modulo 2^32 运算）
    //!
    //! 设计取向：
    //! - 单线程模型：所有时间推进由外部 `tick()` 驱动，便于测试
    //! - 拥塞控制用 NewReno（TUN 对端是本机，RTT 恒定；CUBIC/BBR 收益有限）
    //! - 支持 SACK/时间戳，但只在双方都启用时生效


    pub const Flags = tun_stack.TcpFlags;

    /// 序号空间大小
    pub const seq_mod: u32 = 0x1_0000_0000;

    /// 收到的 TCP 段
    pub const Incoming = struct {
        seq: u32,
        ack: u32,
        flags: u9,
        window: u16,
        payload: []const u8,
    };

    /// 连接键（四元组）
    pub const Key = struct {
        src_ip: [4]u8,
        src_port: u16,
        dst_ip: [4]u8,
        dst_port: u16,

        pub fn eql(a: Key, b: Key) bool {
            return std.mem.eql(u8, &a.src_ip, &b.src_ip) and
                a.src_port == b.src_port and
                std.mem.eql(u8, &a.dst_ip, &b.dst_ip) and
                a.dst_port == b.dst_port;
        }

        pub fn hash(self: Key) u64 {
            var h = std.Hash.Wyhash.init(0);
            h.update(&self.src_ip);
            h.update(std.mem.asBytes(&self.src_port));
            h.update(&self.dst_ip);
            h.update(std.mem.asBytes(&self.dst_port));
            return h.final();
        }
    };

    // ============================================================================
    // 序号运算（必须处理回绕）
    // ============================================================================

    /// a < b ？
    pub fn seqLt(a: u32, b: u32) bool {
        return @as(i32, @bitCast(a -% b)) < 0;
    }

    /// a <= b ？
    pub fn seqLe(a: u32, b: u32) bool {
        return @as(i32, @bitCast(a -% b)) <= 0;
    }

    /// a > b ？
    pub fn seqGt(a: u32, b: u32) bool {
        return @as(i32, @bitCast(a -% b)) > 0;
    }

    /// 两个序号的距离（a 到 b 有多少字节）
    pub fn seqDiff(a: u32, b: u32) u32 {
        return b -% a;
    }

    // ============================================================================
    // 状态机
    // ============================================================================

    pub const State = enum {
        closed,
        listen,
        syn_sent,
        syn_received,
        established,
        fin_wait_1,
        fin_wait_2,
        close_wait,
        closing,
        last_ack,
        time_wait,

        pub fn name(self: State) []const u8 {
            return @tagName(self);
        }
    };

    // ============================================================================
    // 配置与常量
    // ============================================================================

    pub const Config = struct {
        /// 初始 RTO（毫秒），RFC 6298 建议 1 秒
        initial_rto_ms: u32 = 1000,
        /// 最小 RTO（RFC 6298 建议 1 秒；本地回环可降到 200ms 提升体验）
        min_rto_ms: u32 = 200,
        /// 最大 RTO
        max_rto_ms: u32 = 60_000,
        /// MSS（不含 IP/TCP 头）
        mss: u16 = 1460,
        /// 接收窗口大小
        recv_window: u16 = 65535,
        /// 最大重传次数
        max_retries: u8 = 8,
        /// 2*MSL（TIME_WAIT 停留时间）
        time_wait_ms: i64 = 60_000,
        /// 接收缓冲上限
        recv_buf_size: usize = 256 * 1024,
        /// 发送缓冲上限
        send_buf_size: usize = 256 * 1024,

        // ---- 选项协商 ----
        /// 本端请求的窗口缩放移位（0 = 不缩放，14 = 最大）
        request_window_shift: u8 = 0,
        /// 是否启用 SACK
        enable_sack: bool = true,
        /// 是否启用时间戳选项
        enable_timestamps: bool = true,
        /// 是否启用保活
        enable_keepalive: bool = false,

        // ---- 定时器 ----
        /// 坚持定时器最小间隔
        persist_min_ms: u32 = 500,
        /// 坚持定时器最大间隔
        persist_max_ms: u32 = 60_000,
    };

    /// 由 Config 派生出各子模块的配置
    fn ccConfig(c: Config) cc.Config {
        return .{
            .initial_cwnd = 10,
            .initial_ssthresh = 0xFFFF_FFFF,
            .mss = c.mss,
            .dup_ack_threshold = 3,
            .max_cwnd = 0xFFFF,
        };
    }

    fn timersConfig(c: Config) timers.Config {
        return .{
            .initial_rto_ms = c.initial_rto_ms,
            .min_rto_ms = c.min_rto_ms,
            .max_rto_ms = c.max_rto_ms,
            .persist_min_ms = c.persist_min_ms,
            .persist_max_ms = c.persist_max_ms,
            .keepalive_idle_ms = 7_200_000,
            .keepalive_interval_ms = 75_000,
            .keepalive_probes = 9,
            .time_wait_ms = c.time_wait_ms,
        };
    }

    /// 重传队列里的一个段
    pub const OutSegment = struct {
        /// 该段第一个字节的序号
        seq: u32,
        /// 数据（在 send_buf 中的位置由 start/len 表示）
        start: usize,
        len: u32,
        /// 是否包含 SYN / FIN（各占一个序号）
        syn: bool = false,
        fin: bool = false,
        /// 已发送次数
        retries: u8 = 0,
        /// 下次重传的绝对时间
        next_send_ms: i64 = 0,
        /// 实际发出该段的时间（用于 RTT 采样；0 表示尚未发出）
        sent_at_ms: i64 = 0,
        /// 是否已发出至少一次
        sent: bool = false,
    };

    /// 乱序段
    pub const InSegment = struct {
        seq: u32,
        len: u32,
        start: usize,
    };

    pub const Error = error{
        OutOfMemory,
        ConnectionReset,
        BufferFull,
    };

    // ============================================================================
    // 连接
    // ============================================================================

    pub const Conn = struct {
        alloc: std.mem.Allocator,
        cfg: Config,

        state: State = .closed,

        // ---- 序号 ----
        /// 本端发送的下一个序号
        snd_una: u32 = 0, // 最早未被确认的序号
        snd_nxt: u32 = 0, // 下一个要发送的序号
        iss: u32 = 0, // 初始发送序号

        /// 对端发送的下一个序号（即我们期望收到的）
        rcv_nxt: u32 = 0,
        irs: u32 = 0, // 初始接收序号

        /// 对端通告的窗口
        snd_wnd: u16 = 0,
        /// 本端通告的窗口
        rcv_wnd: u16 = 0,

        // ---- 缓冲 ----
        /// 发送缓冲：已发送但未确认的数据保留在这里以便重传
        send_buf: std.ArrayList(u8) = .empty,
        /// 发送队列（按 seq 排序）
        out_queue: std.ArrayList(OutSegment) = .empty,
        /// 接收缓冲：按序到达的数据
        recv_buf: std.ArrayList(u8) = .empty,
        /// 乱序段（按 seq 排序）
        in_queue: std.ArrayList(InSegment) = .empty,
        /// 乱序数据本体
        in_data: std.ArrayList(u8) = .empty,

        // ---- 时间 ----
        now_ms: i64 = 0,
        rto_ms: u32 = 1000,
        srtt_ms: f32 = 0,
        rttvar_ms: f32 = 0,
        rtt_measured: bool = false,

        /// 是否有待发送的 FIN（close() 置位）
        fin_queued: bool = false,
        /// FIN 是否已被对端确认
        fin_acked: bool = false,
        /// 是否有待发出的零窗口探测
        persist_probe_pending: bool = false,
        /// 连续收到的重复 ACK 数（3 个触发快速重传）
        dup_acks: u8 = 0,

        /// 待发给对端的标志（由外部读取）
        pending_flags: u9 = 0,

        // ---- 外置算法模块 ----
        /// 拥塞控制器（cwnd / ssthresh / 快重传）
        cc: cc.Controller,
        /// 四个定时器（RTO / 坚持 / 保活 / TIME_WAIT）
        tm: timers.Timers,
        /// 协商后的选项（MSS / 窗口缩放 / SACK / 时间戳）
        opts: tcpopt.Options = .{},
        /// 最近收到的时间戳回显值（用于下次发送时填 ts_ecr）
        last_ts_ecr: ?u32 = null,

        pub fn init(alloc: std.mem.Allocator, cfg: Config) Conn {
            return .{
                .alloc = alloc,
                .cfg = cfg,
                .rto_ms = cfg.initial_rto_ms,
                .rcv_wnd = cfg.recv_window,
                .cc = cc.Controller.init(ccConfig(cfg)),
                .tm = timers.Timers.init(timersConfig(cfg)),
            };
        }

        /// 实际 MSS（含 IP/TCP 头后的段大小）
        pub fn segMss(self: *const Conn) u16 {
            return self.opts.mss;
        }

        /// 构造本端 SYN / SYN-ACK 要携带的选项字节。
        ///
        /// 不把协商结果发出去的话，对端就按默认值（MSS 536、无窗口缩放、
        /// 无 SACK、无时间戳）工作，内存里那份 `opts` 只是自娱自乐。
        pub fn synOptions(self: *const Conn, buf: []u8) []const u8 {
            const shift = self.cfg.request_window_shift;
            const n = tcpopt.buildSynOptionsEx(
                buf,
                self.cfg.mss,
                shift,
                self.cfg.enable_sack,
                if (self.cfg.enable_timestamps) self.tsNow() else null,
                self.last_ts_ecr orelse 0,
            ) catch return "";
            return buf[0..n];
        }

        /// 当前要通告给对端的窗口（已按协商的缩放移位压缩成 16 位）
        pub fn advertisedWindow(self: *const Conn) u16 {
            return self.opts.unscaleWindow(self.rcv_wnd);
        }

        /// 本端时间戳时钟（毫秒低 32 位，RFC 7323 允许任意单调时钟）
        fn tsNow(self: *const Conn) u32 {
            return @truncate(@as(u64, @bitCast(self.now_ms)));
        }

        /// 构造数据段要携带的选项：时间戳（若协商）+ SACK 块（若协商）
        ///
        /// SACK 块来自乱序队列 —— 告诉对端「这些段我收到了，别再重传」。
        /// 没有它的话，一个包丢了之后对端会把后面所有在途数据全部重传，
        /// 弱网下吞吐直接掉一个数量级。
        pub fn dataOptions(self: *const Conn, buf: []u8) []const u8 {
            var n: usize = 0;

            if (self.opts.window_shift != null and self.opts.ts_val != null) {
                n += tcpopt.writeTimestamp(
                    buf[n..],
                    self.tsNow(),
                    self.last_ts_ecr orelse 0,
                ) catch return buf[0..n];
            }

            if (self.opts.sack_permitted and self.in_queue.items.len > 0) {
                var blocks: [4]tcpopt.Options.SackBlock = undefined;
                var count: usize = 0;
                for (self.in_queue.items) |s| {
                    if (count >= 4) break;
                    blocks[count] = .{ .left = s.seq, .right = s.seq +% s.len };
                    count += 1;
                }
                if (count > 0) {
                    n += tcpopt.writeSack(buf[n..], blocks[0..count]) catch return buf[0..n];
                }
            }

            // 补齐到 4 字节边界（NOP 填充）
            while (n % 4 != 0 and n < buf.len) : (n += 1) buf[n] = 1;
            return buf[0..n];
        }

        /// 当前可发送窗口（取拥塞窗口与对端通告窗口的较小值）
        pub fn sendWindow(self: *const Conn) u32 {
            const peer = self.opts.scaleWindow(self.snd_wnd);
            return @min(self.cc.windowBytes(), peer);
        }

        /// 是否还能再发一个 MSS
        pub fn canSendMore(self: *const Conn) bool {
            return @min(self.cfg.mss, self.opts.mss) > 0 and
                self.cc.flight_size + self.opts.mss <= self.sendWindow();
        }

        pub fn deinit(self: *Conn) void {
            self.send_buf.deinit(self.alloc);
            self.out_queue.deinit(self.alloc);
            self.recv_buf.deinit(self.alloc);
            self.in_queue.deinit(self.alloc);
            self.in_data.deinit(self.alloc);
        }

        /// 被动打开：收到 SYN 时调用。
        ///
        /// `their_opts` 是对端 SYN 里携带的选项；若不提供则用默认值（536 MSS、无扩展）。
        pub fn accept(
            self: *Conn,
            their_seq: u32,
            their_window: u16,
            their_opts: ?tcpopt.Options,
            now_ms: i64,
        ) void {
            self.irs = their_seq;
            self.rcv_nxt = their_seq +% 1;
            self.iss = self.generateIss(now_ms);
            self.snd_una = self.iss;
            self.snd_nxt = self.iss +% 1;
            self.snd_wnd = their_window;
            self.state = .syn_received;
            self.now_ms = now_ms;

            // 选项协商：本端能力 ∩ 对端能力
            const local = tcpopt.Options{
                .mss = self.cfg.mss,
                .window_shift = if (self.cfg.request_window_shift > 0)
                    self.cfg.request_window_shift
                else
                    null,
                .sack_permitted = self.cfg.enable_sack,
                .ts_val = if (self.cfg.enable_timestamps) @truncate(@as(u64, @intCast(now_ms))) else null,
            };
            self.opts = tcpopt.negotiate(local, their_opts orelse tcpopt.Options{});

            // 时间戳：记下对端的 ts_val 以便回显
            if (their_opts) |ro| {
                self.last_ts_ecr = ro.ts_val;
            }
        }

        /// 主动打开
        pub fn connect(self: *Conn, now_ms: i64) void {
            self.iss = self.generateIss(now_ms);
            self.snd_una = self.iss;
            self.snd_nxt = self.iss +% 1;
            self.state = .syn_sent;
            self.now_ms = now_ms;
        }

        fn generateIss(self: *Conn, now_ms: i64) u32 {
            // RFC 6528：ISS 应随时间变化，防止序号预测攻击
            var h = std.hash.Wyhash.init(@intCast(@max(0, now_ms)));
            h.update(std.mem.asBytes(&self.alloc));
            return @truncate(h.final());
        }

        // ------------------------------------------------------------------------
        // 收发
        // ------------------------------------------------------------------------

        /// 应用层写入数据，返回写入字节数
        pub fn write(self: *Conn, data: []const u8) !usize {
            // syn_received 也允许排队：TUN 代理里上游往往在三次握手完成前
            // 就已经把响应送回来了（尤其本地 DNS / 内网服务），
            // 此时 snd_nxt 已越过 SYN，序号是有效的。
            if (self.state != .established and
                self.state != .close_wait and
                self.state != .syn_received)
            {
                return 0;
            }
            const space = self.cfg.send_buf_size - self.send_buf.items.len;
            const n = @min(space, data.len);
            if (n == 0) return 0;

            const start = self.send_buf.items.len;
            try self.send_buf.appendSlice(self.alloc, data[0..n]);

            // 按 MSS 切段：整块塞进一个段会让单包远超 MTU，TUN 写不进去或对端丢弃。
            const mss: usize = @max(1, @as(usize, self.opts.mss));
            var off: usize = 0;
            while (off < n) {
                const chunk = @min(mss, n - off);
                try self.out_queue.append(self.alloc, .{
                    // 序号相对本次写入的偏移，而非 send_buf 的绝对位置
                    // ——否则发送缓冲已有数据时序号会整体前移，对端收到乱序。
                    .seq = self.snd_nxt +% @as(u32, @intCast(off)),
                    .start = start + off,
                    .len = @intCast(chunk),
                });
                off += chunk;
            }
            self.snd_nxt +%= @intCast(n);
            return n;
        }

        /// 应用层读取已按序到达的数据
        pub fn read(self: *Conn, buf: []u8) usize {
            if (self.recv_buf.items.len == 0) return 0;
            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            // 移除已读部分
            const remaining = self.recv_buf.items.len - n;
            std.mem.copyForwards(u8, self.recv_buf.items[0..remaining], self.recv_buf.items[n..]);
            self.recv_buf.shrinkRetainingCapacity(remaining);
            self.updateRecvWindow();
            return n;
        }

        /// 关闭：排队一个 FIN
        ///
        /// 早先这里只置 `fin_queued = true`，却**从不把 FIN 段放进发送队列**，
        /// 于是 `flushLocked` 发完数据就返回，客户端永远收不到 FIN，
        /// 连接要等到它自己的超时（几十秒）才断 —— 表现为「网页加载完了但不结束」。
        pub fn close(self: *Conn) void {
            if (self.state != .established and self.state != .close_wait) return;
            if (self.fin_queued) return;

            // FIN 排在所有已排队数据之后，占一个序号
            self.out_queue.append(self.alloc, .{
                .seq = self.snd_nxt,
                .start = 0,
                .len = 0,
                .fin = true,
            }) catch return;
            self.snd_nxt +%= 1;
            self.fin_queued = true;

            self.state = if (self.state == .established) .fin_wait_1 else .last_ack;
        }

        fn updateRecvWindow(self: *Conn) void {
            const used = self.recv_buf.items.len;
            const free = if (used >= self.cfg.recv_buf_size) 0 else self.cfg.recv_buf_size - used;
            self.rcv_wnd = @intCast(@min(free, self.cfg.recv_window));
        }

        // ------------------------------------------------------------------------
        // 收包
        // ------------------------------------------------------------------------

        /// 处理收到的 TCP 段。返回需要立即发送的响应标志。
        pub fn onSegment(self: *Conn, seg: Incoming, now_ms: i64) !u9 {
            self.now_ms = now_ms;
            var reply: u9 = 0;

            switch (self.state) {
                .syn_received => {
                    if ((seg.flags & Flags.ACK) != 0 and seg.ack == self.snd_nxt) {
                        self.state = .established;
                        self.snd_una = seg.ack;
                        self.snd_wnd = seg.window;
                        self.removeAckedSyn();
                    }
                    // 握手的第三个包也可能捎带数据或 FIN（RFC 9293 允许）。
                    // 只处理 ACK 会丢掉这些数据/FIN，导致连接状态卡住。
                    if ((seg.flags & Flags.FIN) != 0 or
                        seg.payload.len > 0 or
                        (seg.flags & Flags.RST) != 0)
                    {
                        reply |= try self.handleDataSegment(seg, now_ms);
                    }
                },
                .established, .fin_wait_1, .fin_wait_2, .close_wait, .closing, .last_ack => {
                    reply |= try self.handleDataSegment(seg, now_ms);
                },
                .time_wait => {
                    // 收到重传的 FIN 要重新回 ACK
                    if ((seg.flags & Flags.FIN) != 0) reply |= Flags.ACK;
                },
                else => {},
            }

            // 统一处理 ACK（确认我们的发送）
            if ((seg.flags & Flags.ACK) != 0 and
                (self.state == .established or self.state == .fin_wait_1 or
                    self.state == .fin_wait_2 or self.state == .closing or
                    self.state == .last_ack))
            {
                try self.handleAck(seg.ack, seg.window, now_ms);
            }

            return reply;
        }

        fn removeAckedSyn(self: *Conn) void {
            _ = self;
            // SYN 不占发送缓冲，只需要 snd_una 前进（上面已做）
        }

        fn handleDataSegment(self: *Conn, seg: Incoming, now_ms: i64) !u9 {
            var reply: u9 = 0;

            // ---- RST ----
            if ((seg.flags & Flags.RST) != 0) {
                self.state = .closed;
                return 0;
            }

            // ---- 数据 ----
            if (seg.payload.len > 0) {
                if (seg.seq == self.rcv_nxt) {
                    // 按序到达
                    try self.deliverInOrder(seg.payload);
                    self.rcv_nxt +%= @intCast(seg.payload.len);
                    reply |= Flags.ACK;
                    // 尝试从乱序队列里接续
                    try self.drainOutOfOrder();
                } else if (seqGt(seg.seq, self.rcv_nxt)) {
                    // 乱序（前面有空洞）：缓存起来
                    try self.bufferOutOfOrder(seg);
                    reply |= Flags.ACK;
                } else {
                    // 重复数据：丢弃但回 ACK
                    reply |= Flags.ACK;
                }
            }

            // ---- FIN ----
            if ((seg.flags & Flags.FIN) != 0) {
                self.rcv_nxt +%= 1;
                reply |= Flags.ACK;
                switch (self.state) {
                    .established => {
                        self.state = .close_wait;
                    },
                    .fin_wait_1 => {
                        self.state = .closing;
                    },
                    .fin_wait_2 => {
                        self.state = .time_wait;
                        // 2MSL 由 timers 模块管理，状态机不再自己记账
                        self.tm.startTimeWait(now_ms);
                    },
                    else => {},
                }
            }

            return reply;
        }

        fn deliverInOrder(self: *Conn, data: []const u8) !void {
            const space = self.cfg.recv_buf_size - self.recv_buf.items.len;
            const n = @min(space, data.len);
            try self.recv_buf.appendSlice(self.alloc, data[0..n]);
            self.updateRecvWindow();
        }

        fn bufferOutOfOrder(self: *Conn, seg: Incoming) !void {
            // 已在队列中则不重复
            for (self.in_queue.items) |s| {
                if (s.seq == seg.seq and s.len == seg.payload.len) return;
            }
            const start = self.in_data.items.len;
            try self.in_data.appendSlice(self.alloc, seg.payload);
            try self.in_queue.append(self.alloc, .{
                .seq = seg.seq,
                .len = @intCast(seg.payload.len),
                .start = start,
            });
            std.mem.sort(InSegment, self.in_queue.items, {}, struct {
                fn lt(_: void, a: InSegment, b: InSegment) bool {
                    return seqLt(a.seq, b.seq);
                }
            }.lt);
        }

        /// 把乱序队列中已经连续的段搬到接收缓冲
        fn drainOutOfOrder(self: *Conn) !void {
            var i: usize = 0;
            while (i < self.in_queue.items.len) {
                const s = self.in_queue.items[i];
                if (s.seq == self.rcv_nxt) {
                    try self.deliverInOrder(self.in_data.items[s.start .. s.start + s.len]);
                    self.rcv_nxt +%= s.len;
                    _ = self.in_queue.orderedRemove(i);
                    i = 0; // 重新从头扫描（可能有新的连续段）
                } else if (seqLt(s.seq, self.rcv_nxt)) {
                    // 已被后续数据覆盖，丢弃
                    _ = self.in_queue.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        fn handleAck(self: *Conn, ack: u32, window: u16, now_ms: i64) !void {
            if (seqGt(ack, self.snd_nxt)) {
                // 确认了还没发的数据 —— 非法，忽略
                return;
            }
            if (seqLe(ack, self.snd_una)) {
                // 零窗口通告是这一支里的特例，必须先处理。
                //
                // 对端缓冲满时发来的 ACK **不会推进 snd_una**（它没收到新数据），
                // 于是落到「重复 ACK」分支。早先这里直接 return，窗口更新和
                // 坚持定时器全被跳过 —— 我方以为对端窗口还是大的，继续猛发，
                // 对端全丢；对端等着我们探测，我们等着对端开窗。双方僵死。
                if (window == 0) {
                    self.snd_wnd = 0;
                    if (self.out_queue.items.len > 0) self.tm.startPersist(now_ms);
                } else if (self.tm.persistActive()) {
                    self.snd_wnd = window;
                    self.tm.stopPersist();
                    // 窗口重新打开，把卡住的段全部标回待发
                    for (self.out_queue.items) |*s| {
                        if (seqLe(s.seq +% s.len, self.snd_una)) continue;
                        s.sent = false;
                    }
                    return;
                }

                // 重复 ACK：对端在催我们重发。累计到 3 个就快速重传，
                // 不必等 RTO —— 这是弱网下吞吐差一个数量级的主要原因。
                if (ack == self.snd_una and self.out_queue.items.len > 0) {
                    self.dup_acks +|= 1;
                    if (self.cc.onDupAck()) {
                        for (self.out_queue.items) |*s| {
                            if (seqLe(s.seq +% s.len, self.snd_una)) continue;
                            s.sent = false;
                            s.retries +|= 1;
                            break;
                        }
                    }
                }
                return;
            }

            // 真正推进了 snd_una：重置重复计数
            self.dup_acks = 0;

            // RTT 测量（简化版：只测量非重传段）
            self.measureRtt(ack, now_ms);

            const acked = seqDiff(self.snd_una, ack);
            self.snd_una = ack;
            self.snd_wnd = window;

            // 零窗口 → 启动坚持定时器；窗口重新打开 → 停掉
            if (window == 0) {
                if (self.out_queue.items.len > 0) self.tm.startPersist(now_ms);
            } else if (self.tm.persistActive()) {
                self.tm.stopPersist();
            }

            // 从发送队列里移除已确认的段
            var i: usize = 0;
            while (i < self.out_queue.items.len) {
                const s = &self.out_queue.items[i];
                const seg_end = s.seq +% s.len +% @as(u32, if (s.syn or s.fin) 1 else 0);
                if (seqLe(seg_end, ack)) {
                    if (s.fin) self.fin_acked = true;
                    _ = self.out_queue.orderedRemove(i);
                } else if (seqLt(s.seq, ack)) {
                    // 部分确认：调整 start 与 seq
                    const adv = seqDiff(s.seq, ack);
                    s.start += adv;
                    s.len -= adv;
                    s.seq = ack;
                    i += 1;
                } else {
                    i += 1;
                }
            }

            // 拥塞窗口随 ACK 增长（慢启动 / 拥塞避免由 cc 模块决定）
            self.cc.onAck(acked);
            // 在途字节数直接从发送队列重算，避免累加漂移把窗口算死
            self.recomputeFlight();

            if (self.out_queue.items.len == 0) self.tm.stopRto();

            // 状态推进
            if (self.state == .fin_wait_1 and self.fin_acked) {
                self.state = .fin_wait_2;
            }
        }

        /// 在途字节数 = 发送队列里尚未被确认的字节总数
        fn recomputeFlight(self: *Conn) void {
            var total: u32 = 0;
            for (self.out_queue.items) |s| {
                if (seqLe(s.seq +% s.len, self.snd_una)) continue;
                total +%= s.len;
            }
            self.cc.flight_size = total;
        }

        /// RTT 测量（RFC 6298）。
        ///
        /// 只在「非重传段被确认」时采样，避免 Karn 算法指出的重传歧义。
        /// 没有采样时保持当前 RTO —— 宁可保守，也不要用错误样本把 RTO 拉崩。
        fn measureRtt(self: *Conn, ack: u32, now_ms: i64) void {
            for (self.out_queue.items) |s| {
                if (!s.sent) continue;
                // 只看「整段被确认」且「没重传过」的样本
                if (s.retries != 0) continue;
                if (!seqLe(s.seq +% s.len, ack)) continue;

                // 发送时刻 = 下次重传时刻 - 当时的 RTO。
                // 注意 `markSent` 用的是 `self.rto_ms`，而这里读的是「现在」的
                // `rto_ms` —— RTT 样本本身会改动它，于是同一段的「发送时刻」
                // 每次算出来都不一样，样本越测越偏。用 `sent_at_ms` 直接记录。
                const sent_at = if (s.sent_at_ms != 0) s.sent_at_ms else s.next_send_ms - @as(i64, self.rto_ms);
                const sample: f32 = @floatFromInt(@max(0, now_ms - sent_at));
                if (!self.rtt_measured) {
                    self.srtt_ms = sample;
                    self.rttvar_ms = sample / 2;
                    self.rtt_measured = true;
                } else {
                    const diff = @abs(self.srtt_ms - sample);
                    self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * diff;
                    self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample;
                }
                self.rto_ms = @intFromFloat(@max(
                    @as(f32, @floatFromInt(self.cfg.min_rto_ms)),
                    @min(
                        @as(f32, @floatFromInt(self.cfg.max_rto_ms)),
                        self.srtt_ms + @max(10.0, 4.0 * self.rttvar_ms),
                    ),
                ));
                return;
            }
        }

        // ------------------------------------------------------------------------
        // 定时器
        // ------------------------------------------------------------------------

        /// 由外部周期性调用，驱动重传与超时
        pub fn tick(self: *Conn, now_ms: i64) !void {
            self.now_ms = now_ms;

            // ---- TIME_WAIT 超时 ----
            if (self.state == .time_wait) {
                if (self.tm.timeWaitExpired(now_ms)) self.state = .closed;
                return;
            }

            // ---- 零窗口探测 ----
            //
            // 对端窗口为 0 时重传数据毫无意义（对端根本收不下），必须改发探测包，
            // 让对端回一个带最新窗口的 ACK。否则双方互相干等，连接僵死。
            if (self.tm.persistActive()) {
                if (self.tm.persistExpired(now_ms)) {
                    self.tm.onPersistProbe(now_ms);
                    self.persist_probe_pending = true;
                }
                return;
            }

            // ---- 重传 ----
            //
            // 注意：这里要把 `sent` 复位，让 `hasPendingSend()` / `nextSendSegment()`
            // 能重新取到这个段。只更新 next_send_ms 而不复位 sent，
            // 会导致「重传计时器空转，数据永远发不出去」—— 弱网下连接直接挂死。
            if (self.tm.rtoExpired(now_ms)) {
                if (self.tm.tooManyRetransmits()) {
                    self.state = .closed;
                    return;
                }
                self.tm.onRetransmit(now_ms);
                self.cc.onTimeout();

                for (self.out_queue.items) |*s| {
                    if (!s.sent) continue;
                    if (seqLe(s.seq +% s.len, self.snd_una)) continue; // 已确认
                    s.retries +|= 1;
                    if (s.retries > self.cfg.max_retries) {
                        self.state = .closed;
                        return;
                    }
                    // 指数退避
                    const shift: u5 = @intCast(@min(s.retries - 1, 6));
                    const backoff = std.math.shl(u32, self.rto_ms, shift);
                    s.next_send_ms = now_ms + @min(backoff, self.cfg.max_rto_ms);
                    // 关键：标记为待发送，下一轮会重新取出
                    s.sent = false;
                }
            }

            // ---- 保活 ----
            if (self.tm.keepaliveExpired(now_ms)) {
                if (self.tm.keepaliveFailed()) {
                    self.state = .closed;
                    return;
                }
                self.tm.onKeepaliveProbe(now_ms);
            }
        }

        /// 取走待发的零窗口探测（发出后由调用方置回 false）
        pub fn takePersistProbe(self: *Conn) bool {
            const p = self.persist_probe_pending;
            self.persist_probe_pending = false;
            return p;
        }

        /// 是否有待发送的数据（外部据此构造报文）
        pub fn hasPendingSend(self: *Conn) bool {
            for (self.out_queue.items) |s| {
                if (!s.sent) return true;
                if (seqLe(s.seq +% s.len, self.snd_una)) continue;
                if (self.now_ms >= s.next_send_ms) return true;
            }
            return false;
        }

        /// 取下一个待发送段
        pub fn nextSendSegment(self: *Conn) ?OutSegment {
            for (self.out_queue.items) |*s| {
                if (!s.sent) return s.*;
                if (seqLe(s.seq +% s.len, self.snd_una)) continue;
                if (self.now_ms >= s.next_send_ms) return s.*;
            }
            return null;
        }

        /// 发送队列里第一个尚未被确认的段（零窗口探测用）
        pub fn firstUnacked(self: *Conn) ?OutSegment {
            for (self.out_queue.items) |s| {
                if (seqLe(s.seq +% s.len, self.snd_una)) continue;
                return s;
            }
            return null;
        }

        pub fn markSent(self: *Conn, seg: OutSegment) void {
            for (self.out_queue.items) |*s| {
                if (s.seq == seg.seq and s.len == seg.len) {
                    s.sent = true;
                    s.sent_at_ms = self.now_ms;
                    s.next_send_ms = self.now_ms + self.rto_ms;
                    // 有数据在途 → 启动重传定时器（已在跑则不动）
                    self.tm.startRto(self.now_ms);
                    return;
                }
            }
        }
    };

    // ============================ 测试 ============================


    fn seqDist(a: u32, b: u32) u32 {
        return b -% a;
    }











};

pub const ip_proto = struct {
    //! 用户态 IP 层 + UDP NAT（配合 `tcp.zig` 组成完整协议栈）。
    //!
    //! 职责：
    //! 1. **IP 层**：解析/构造 IPv4 包，处理分片重组
    //! 2. **UDP NAT**：把 TUN 侧 UDP 会话映射到上游 socket，维持双向转发
    //! 3. **ICMP**：Echo 代答 + 必要的差错报文
    //!
    //! 与 `tcp.zig` 的分工：
    //!   tcp.zig  —— 传输层状态机（序号、重传、窗口）
    //!   本文件    —— 网络层（IP 头、分片）+ UDP（无连接，只需 NAT 映射）
    //!
    //! 分片重组的必要性：虽然本机应用通常不会发分片包，但 UDP over DNS
    //! 与某些游戏会发；不处理会导致偶发失败且极难排查。


    pub const IPPROTO_ICMP = tun_stack.IPPROTO_ICMP;
    pub const IPPROTO_TCP = tun_stack.IPPROTO_TCP;
    pub const IPPROTO_UDP = tun_stack.IPPROTO_UDP;

    /// IPv4 标志位
    pub const IP_FLAG_MF: u16 = 0x2000; // more fragments
    pub const IP_FLAG_DF: u16 = 0x4000; // don't fragment

    pub const Error = error{
        OutOfMemory,
        InvalidPacket,
        BufferTooSmall,
    };

    // ============================================================================
    // IP 分片重组
    // ============================================================================

    pub const FragmentKey = struct {
        src: [4]u8,
        dst: [4]u8,
        id: u16,
        proto: u8,

        pub fn eql(a: FragmentKey, b: FragmentKey) bool {
            return std.mem.eql(u8, &a.src, &b.src) and
                std.mem.eql(u8, &a.dst, &b.dst) and
                a.id == b.id and a.proto == b.proto;
        }
    };

    pub const FragmentBuffer = struct {
        key: FragmentKey,
        /// 已收到的数据（按偏移写入）
        data: []u8,
        /// 各字节是否已收到
        received: []bool,
        /// 总长度（收到最后一个分片后确定）
        total_len: ?usize = null,
        /// 最后活动时间，用于超时清理
        last_ms: i64 = 0,

        pub fn deinit(self: *FragmentBuffer, alloc: std.mem.Allocator) void {
            alloc.free(self.data);
            alloc.free(self.received);
        }

        /// 是否已收齐
        pub fn complete(self: *const FragmentBuffer) bool {
            const total = self.total_len orelse return false;
            for (self.received[0..total]) |r| {
                if (!r) return false;
            }
            return true;
        }
    };

    /// 分片重组器
    pub const Reassembler = struct {
        alloc: std.mem.Allocator,
        buffers: std.ArrayList(FragmentBuffer) = .empty,
        /// 单个重组缓冲上限
        max_size: usize = 65535,
        /// 超时（毫秒）
        timeout_ms: i64 = 30_000,

        pub fn init(alloc: std.mem.Allocator) Reassembler {
            return .{ .alloc = alloc };
        }

        pub fn deinit(self: *Reassembler) void {
            for (self.buffers.items) |*b| b.deinit(self.alloc);
            self.buffers.deinit(self.alloc);
        }

        /// 喂入一个分片。收齐时把完整包写进 `out`，返回其长度。
        ///
        /// **所有权说明**：输出缓冲由调用方提供，本函数不分配内存。
        /// 早期版本返回内部缓冲并自行 alloc，导致所有权混乱和泄漏；
        /// 改成 caller-provided buffer 后语义清晰，也避免了每包一次分配。
        pub fn feed(
            self: *Reassembler,
            pkt: []const u8,
            out: []u8,
            now_ms: i64,
        ) Error!?usize {
            const ip = tun_stack.parseIpv4(pkt) orelse return error.InvalidPacket;
            if (ip.total_len < 20) return error.InvalidPacket;

            // tun_stack 把标志位与偏移拆成了两个字段：flags(u3) / frag_offset(u13)
            const frag_off: u16 = @as(u16, ip.frag_offset) * 8;
            // flags 的第 0 位 = MF（more fragments）
            const mf = (ip.flags & 0x1) != 0;

            // 不分片：直接拷贝出去
            if (frag_off == 0 and !mf) {
                const n = ip.total_len;
                if (out.len < n) return error.BufferTooSmall;
                @memcpy(out[0..n], pkt[0..n]);
                return n;
            }

            const key = FragmentKey{
                .src = ip.src,
                .dst = ip.dst,
                .id = ip.id,
                .proto = ip.proto,
            };

            // 找现有的缓冲
            var idx: ?usize = null;
            for (self.buffers.items, 0..) |b, i| {
                if (FragmentKey.eql(b.key, key)) {
                    idx = i;
                    break;
                }
            }

            var buf: *FragmentBuffer = undefined;
            if (idx) |i| {
                buf = &self.buffers.items[i];
            } else {
                const data = try self.alloc.alloc(u8, self.max_size);
                errdefer self.alloc.free(data);
                const received = try self.alloc.alloc(bool, self.max_size);
                errdefer self.alloc.free(received);
                @memset(received, false);
                try self.buffers.append(self.alloc, .{
                    .key = key,
                    .data = data,
                    .received = received,
                    .last_ms = now_ms,
                });
                buf = &self.buffers.items[self.buffers.items.len - 1];
            }
            buf.last_ms = now_ms;

            // 写入本分片的载荷
            const payload = pkt[ip.payload_start..ip.total_len];
            const end = frag_off + payload.len;
            if (end > self.max_size) return error.BufferTooSmall;
            @memcpy(buf.data[frag_off..end], payload);
            @memset(buf.received[frag_off..end], true);

            // 最后一个分片 → 确定总长
            if (!mf) buf.total_len = end;

            if (buf.complete()) {
                const total = buf.total_len.?;
                const need = ip.payload_start + total;
                if (out.len < need) return error.BufferTooSmall;

                // 用当前分片的 IP 头 + 重组后的载荷
                @memcpy(out[0..ip.payload_start], pkt[0..ip.payload_start]);
                @memcpy(out[ip.payload_start..need], buf.data[0..total]);
                // 修正总长度与校验和（原分片的头里长度是分片长度）
                std.mem.writeInt(u16, out[2..4][0..2], @intCast(need), .big);
                std.mem.writeInt(u16, out[10..12][0..2], 0, .big);
                const csum = tun_stack.computeChecksum(out[0..ip.payload_start]);
                std.mem.writeInt(u16, out[10..12][0..2], csum, .big);

                buf.deinit(self.alloc);
                _ = self.buffers.orderedRemove(idx.?);
                return need;
            }
            return null;
        }

        /// 清理超时的重组缓冲
        pub fn sweep(self: *Reassembler, now_ms: i64) usize {
            var removed: usize = 0;
            var i: usize = 0;
            while (i < self.buffers.items.len) {
                if (now_ms - self.buffers.items[i].last_ms > self.timeout_ms) {
                    self.buffers.items[i].deinit(self.alloc);
                    _ = self.buffers.orderedRemove(i);
                    removed += 1;
                } else {
                    i += 1;
                }
            }
            return removed;
        }
    };

    // ============================================================================
    // UDP NAT
    // ============================================================================

    pub const UdpKey = struct {
        src_ip: [4]u8,
        src_port: u16,
        dst_ip: [4]u8,
        dst_port: u16,

        pub fn eql(a: UdpKey, b: UdpKey) bool {
            return std.mem.eql(u8, &a.src_ip, &b.src_ip) and
                a.src_port == b.src_port and
                std.mem.eql(u8, &a.dst_ip, &b.dst_ip) and
                a.dst_port == b.dst_port;
        }

        pub fn hash(self: UdpKey) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(&self.src_ip);
            h.update(std.mem.asBytes(&self.src_port));
            h.update(&self.dst_ip);
            h.update(std.mem.asBytes(&self.dst_port));
            return h.final();
        }
    };

    pub const NatEntry = struct {
        key: UdpKey,
        /// 上游 socket（由外部管理，这里是句柄值）
        upstream: i64 = -1,
        /// 最后活动时间
        last_ms: i64 = 0,
        /// 统计
        packets_in: u64 = 0,
        packets_out: u64 = 0,
    };

    /// UDP NAT 表
    pub const UdpNat = struct {
        alloc: std.mem.Allocator,
        entries: std.ArrayList(NatEntry) = .empty,
        /// 最大条目数
        max_entries: usize = 1024,
        /// 空闲超时（RFC 4787 建议 ≥ 2 分钟）
        timeout_ms: i64 = 120_000,

        pub fn init(alloc: std.mem.Allocator) UdpNat {
            return .{ .alloc = alloc };
        }

        pub fn deinit(self: *UdpNat) void {
            self.entries.deinit(self.alloc);
        }

        pub fn find(self: *UdpNat, key: UdpKey) ?*NatEntry {
            for (self.entries.items) |*e| {
                if (UdpKey.eql(e.key, key)) return e;
            }
            return null;
        }

        /// 建立（或复用）一个映射
        pub fn map(self: *UdpNat, key: UdpKey, now_ms: i64) !*NatEntry {
            if (self.find(key)) |e| {
                e.last_ms = now_ms;
                return e;
            }
            if (self.entries.items.len >= self.max_entries) {
                try self.evictOldest();
            }
            try self.entries.append(self.alloc, .{
                .key = key,
                .last_ms = now_ms,
            });
            return &self.entries.items[self.entries.items.len - 1];
        }

        pub fn remove(self: *UdpNat, key: UdpKey) void {
            var i: usize = 0;
            while (i < self.entries.items.len) : (i += 1) {
                if (UdpKey.eql(self.entries.items[i].key, key)) {
                    _ = self.entries.orderedRemove(i);
                    return;
                }
            }
        }

        fn evictOldest(self: *UdpNat) !void {
            if (self.entries.items.len == 0) return;
            var oldest: usize = 0;
            for (self.entries.items, 0..) |e, i| {
                if (e.last_ms < self.entries.items[oldest].last_ms) oldest = i;
            }
            _ = self.entries.orderedRemove(oldest);
        }

        pub fn sweep(self: *UdpNat, now_ms: i64) usize {
            var removed: usize = 0;
            var i: usize = 0;
            while (i < self.entries.items.len) {
                if (now_ms - self.entries.items[i].last_ms > self.timeout_ms) {
                    _ = self.entries.orderedRemove(i);
                    removed += 1;
                } else {
                    i += 1;
                }
            }
            return removed;
        }

        pub fn count(self: *UdpNat) usize {
            return self.entries.items.len;
        }
    };

    // ============================================================================
    // 报文构造
    // ============================================================================

    /// 构造 IPv4 + UDP 报文
    pub fn buildUdpPacket(
        out: []u8,
        src_ip: [4]u8,
        dst_ip: [4]u8,
        src_port: u16,
        dst_port: u16,
        payload: []const u8,
    ) Error!usize {
        const total = 20 + 8 + payload.len;
        if (out.len < total) return error.BufferTooSmall;

        out[0] = 0x45;
        out[1] = 0x00;
        std.mem.writeInt(u16, out[2..4][0..2], @intCast(total), .big);
        std.mem.writeInt(u16, out[4..6][0..2], 0, .big);
        std.mem.writeInt(u16, out[6..8][0..2], IP_FLAG_DF, .big);
        out[8] = 64;
        out[9] = IPPROTO_UDP;
        std.mem.writeInt(u16, out[10..12][0..2], 0, .big);
        @memcpy(out[12..16], &src_ip);
        @memcpy(out[16..20], &dst_ip);
        std.mem.writeInt(u16, out[10..12][0..2], tun_stack.computeChecksum(out[0..20]), .big);

        const u = out[20..];
        std.mem.writeInt(u16, u[0..2][0..2], src_port, .big);
        std.mem.writeInt(u16, u[2..4][0..2], dst_port, .big);
        std.mem.writeInt(u16, u[4..6][0..2], @intCast(8 + payload.len), .big);
        // UDP 校验和：IPv4 下可选，填 0 表示不校验
        std.mem.writeInt(u16, u[6..8][0..2], 0, .big);

        @memcpy(u[8 .. 8 + payload.len], payload);
        return total;
    }

    /// 计算带伪首部的 UDP 校验和（需要时使用）
    pub fn udpChecksum(
        src_ip: [4]u8,
        dst_ip: [4]u8,
        udp_segment: []const u8,
    ) u16 {
        var sum: u32 = 0;
        // 伪首部：src(4) dst(4) zero(1) proto(1) len(2)
        sum += @as(u16, @intCast(src_ip[0])) << 8 | src_ip[1];
        sum += @as(u16, @intCast(src_ip[2])) << 8 | src_ip[3];
        sum += @as(u16, @intCast(dst_ip[0])) << 8 | dst_ip[1];
        sum += @as(u16, @intCast(dst_ip[2])) << 8 | dst_ip[3];
        sum += IPPROTO_UDP;
        sum += @intCast(udp_segment.len);

        var i: usize = 0;
        while (i + 1 < udp_segment.len) : (i += 2) {
            sum += @as(u16, udp_segment[i]) << 8 | udp_segment[i + 1];
        }
        if (i < udp_segment.len) {
            sum += @as(u16, udp_segment[i]) << 8;
        }
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return @truncate(~sum);
    }

    // ============================ 测试 ============================

    /// 构造一个分片包
    fn mkFragment(
        buf: []u8,
        src: [4]u8,
        dst: [4]u8,
        id: u16,
        frag_off_bytes: u16,
        mf: bool,
        payload: []const u8,
    ) []u8 {
        const total = 20 + payload.len;
        buf[0] = 0x45;
        std.mem.writeInt(u16, buf[2..4][0..2], @intCast(total), .big);
        std.mem.writeInt(u16, buf[4..6][0..2], id, .big);
        var flags: u16 = @intCast(frag_off_bytes / 8);
        if (mf) flags |= IP_FLAG_MF;
        std.mem.writeInt(u16, buf[6..8][0..2], flags, .big);
        buf[8] = 64;
        buf[9] = IPPROTO_UDP;
        std.mem.writeInt(u16, buf[10..12][0..2], 0, .big);
        @memcpy(buf[12..16], &src);
        @memcpy(buf[16..20], &dst);
        std.mem.writeInt(u16, buf[10..12][0..2], tun_stack.computeChecksum(buf[0..20]), .big);
        @memcpy(buf[20..total], payload);
        return buf[0..total];
    }









};

pub const stack = struct {
    //! 协议栈总装：把 IP 层、TCP、UDP NAT 组装成一个可用的用户态栈。
    //!
    //! 这是 `tun_runner` 真正需要的“引擎”：给一个 IP 包，产出要回写的 IP 包，
    //! 同时把应用数据通过回调交给上层（去建立真实出站连接）。
    //!
    //! 数据流：
    //!
    //!   TUN → IP 包 ──┬─ 分片？→ 重组 → 继续
    //!                 ├─ TCP → 查连接表 → tcp.Conn.onSegment
    //!                 │         └→ 应用数据 → onTcpData 回调 → 出站
    //!                 └─ UDP → UdpNat 查表 → onUdpData 回调 → 出站
    //!
    //!   出站回包 → writeTcp / writeUdp → 构造 IP 包 → TUN

        const tcp = tcp_proto;
        const ip = ip_proto;

    pub const IPPROTO_TCP = tun_stack.IPPROTO_TCP;
    pub const IPPROTO_UDP = tun_stack.IPPROTO_UDP;
    pub const IPPROTO_ICMP = tun_stack.IPPROTO_ICMP;

    /// 交给上层的回调：有新数据要送往真实世界
    pub const Handler = struct {
        ctx: *anyopaque,

        /// TCP 连接建立时调用（上层据此拨号出站）
        onTcpOpen: *const fn (ctx: *anyopaque, key: tcp.Key) anyerror!void,
        /// TCP 收到应用数据
        onTcpData: *const fn (ctx: *anyopaque, key: tcp.Key, data: []const u8) anyerror!void,
        /// TCP 连接关闭
        onTcpClose: *const fn (ctx: *anyopaque, key: tcp.Key) void,
        /// UDP 数据报（含新建映射）
        onUdpData: *const fn (ctx: *anyopaque, key: ip.UdpKey, data: []const u8) anyerror!void,

        pub fn tcpOpen(self: Handler, key: tcp.Key) !void {
            return self.onTcpOpen(self.ctx, key);
        }
        pub fn tcpData(self: Handler, key: tcp.Key, data: []const u8) !void {
            return self.onTcpData(self.ctx, key, data);
        }
        pub fn tcpClose(self: Handler, key: tcp.Key) void {
            self.onTcpClose(self.ctx, key);
        }
        pub fn udpData(self: Handler, key: ip.UdpKey, data: []const u8) !void {
            return self.onUdpData(self.ctx, key, data);
        }
    };

    /// TCP 连接:运行时组合 tcp.Conn 与它的键
    pub const TcpSlot = struct {
        key: tcp.Key,
        conn: tcp.Conn,

        pub fn deinit(self: *TcpSlot) void {
            self.conn.deinit();
        }
    };

    pub const Stack = struct {
        alloc: std.mem.Allocator,
        handler: ?Handler = null,

        /// 本端 TUN 地址（回包源地址）
        local_ip: [4]u8 = .{ 198, 18, 0, 1 },

        /// TCP 连接表
        tcp_slots: std.ArrayList(TcpSlot) = .empty,
        /// UDP NAT
        nat: ip.UdpNat,
        /// 分片重组
        reassembler: ip.Reassembler,

        /// 统计
        stat_tcp_in: u64 = 0,
        stat_tcp_out: u64 = 0,
        stat_udp_in: u64 = 0,
        stat_udp_out: u64 = 0,
        stat_frag_dropped: u64 = 0,

        /// 配置
        tcp_cfg: tcp.Config = .{},

        pub fn init(alloc: std.mem.Allocator) Stack {
            return .{
                .alloc = alloc,
                .nat = ip.UdpNat.init(alloc),
                .reassembler = ip.Reassembler.init(alloc),
            };
        }

        pub fn deinit(self: *Stack) void {
            for (self.tcp_slots.items) |*s| s.deinit();
            self.tcp_slots.deinit(self.alloc);
            self.nat.deinit();
            self.reassembler.deinit();
        }

        pub fn tcpCount(self: *Stack) usize {
            return self.tcp_slots.items.len;
        }

        fn findTcp(self: *Stack, key: tcp.Key) ?*TcpSlot {
            for (self.tcp_slots.items) |*s| {
                if (tcp.Key.eql(s.key, key)) return s;
            }
            return null;
        }

        /// 供外部模块（tun_runner / tun_glue）查连接
        pub fn findTcpPub(self: *Stack, key: tcp.Key) ?*TcpSlot {
            return self.findTcp(key);
        }

        /// 构造一个 RST 回给客户端（目标被拒 / 拨号失败时用）。
        ///
        /// 没有 RST 的话客户端会一直重传到超时（几秒到几十秒），
        /// 表现为「网页卡住」而不是「立刻失败」。
        pub fn buildRst(self: *Stack, key: tcp.Key, out: []u8) !usize {
            const slot = self.findTcp(key) orelse return 0;
            const seq = slot.conn.snd_nxt;
            const ack = slot.conn.rcv_nxt;
            return tun_conn.buildTcpSegment(
                out,
                self.local_ip,
                key.src_ip,
                key.dst_port,
                key.src_port,
                seq,
                ack,
                tun_stack.TcpFlags.RST | tun_stack.TcpFlags.ACK,
                "",
            ) catch 0;
        }

        // ------------------------------------------------------------------------
        // 入口：处理一个来自 TUN 的 IP 包
        // ------------------------------------------------------------------------

        /// 处理一个 IP 包。需要回写的包写进 `out`，返回其长度（0 表示无需回包）。
        ///
        /// `now_ms` 由调用方提供，便于测试时控时。
        pub fn handlePacket(self: *Stack, pkt: []const u8, out: []u8, now_ms: i64) !usize {
            // 1) 分片重组
            var reassembled: [4096]u8 = undefined;
            const n = (try self.reassembler.feed(pkt, &reassembled, now_ms)) orelse return 0;
            const full = reassembled[0..n];

            const iph = tun_stack.parseIpv4(full) orelse return 0;

            return switch (iph.proto) {
                IPPROTO_TCP => self.handleTcp(iph, full, out, now_ms),
                IPPROTO_UDP => self.handleUdp(iph, full, out, now_ms),
                IPPROTO_ICMP => self.handleIcmp(full, out),
                else => 0,
            };
        }

        fn handleIcmp(self: *Stack, pkt: []const u8, out: []u8) !usize {
            _ = self;
            const need = pkt.len;
            if (out.len < need) return 0;
            @memcpy(out[0..need], pkt[0..need]);
            const rep = tun_stack.handleIcmpEcho(out[0..need]) orelse return 0;
            return rep.len;
        }

        fn handleTcp(self: *Stack, iph: tun_stack.Ipv4Header, pkt: []const u8, out: []u8, now_ms: i64) !usize {
            const seg = pkt[iph.payload_start..iph.payload_end];
            const th = tun_stack.parseTcp(seg) orelse return 0;

            const key = tcp.Key{
                .src_ip = iph.src,
                .src_port = th.src_port,
                .dst_ip = iph.dst,
                .dst_port = th.dst_port,
            };

            const payload = seg[th.payload_start..th.payload_end];
            const incoming = tcp.Incoming{
                .seq = th.seq,
                .ack = th.ack,
                .flags = th.flags,
                .window = th.window,
                .payload = payload,
            };

            // ---- SYN：新建连接 ----
            if ((th.flags & tun_stack.TcpFlags.SYN) != 0 and (th.flags & tun_stack.TcpFlags.ACK) == 0) {
                if (self.findTcp(key)) |existing| {
                    // 重复 SYN：重发 SYN-ACK（不新建）
                    return try self.buildTcpReply(iph, th, existing.conn.snd_nxt, existing.conn.rcv_nxt -% 1, tun_stack.TcpFlags.SYN | tun_stack.TcpFlags.ACK, "", out);
                }
                if (self.tcp_slots.items.len >= 1024) return 0;

                var slot = TcpSlot{
                    .key = key,
                    .conn = tcp.Conn.init(self.alloc, self.tcp_cfg),
                };
                // parse SYN options for MSS / window scale / SACK / timestamps
                const opt_len = @as(usize, th.data_offset) * 4;
                const syn_opts: ?tcpopt.Options = if (opt_len > 20 and opt_len <= seg.len)
                    tcpopt.parse(seg[20..opt_len]) catch null
                else
                    null;
                slot.conn.accept(th.seq, th.window, syn_opts, now_ms);

                const iss = slot.conn.iss;
                const rcv = slot.conn.rcv_nxt;

                try self.tcp_slots.append(self.alloc, slot);
                self.stat_tcp_in +%= 1;

                // 通知上层拨号
                if (self.handler) |h| h.tcpOpen(key) catch {};

                // SYN-ACK 必须带上协商好的选项，否则对端按默认值工作：
                // MSS 536（大包被无谓切碎）、无窗口缩放（64KB 封顶）、
                // 无 SACK（一丢包就全量重传）、无时间戳。
                var optbuf: [40]u8 = undefined;
                const out_opts = slot.conn.synOptions(&optbuf);
                return try self.buildTcpReplyEx(
                    key,
                    iss +% 1,
                    rcv,
                    tun_stack.TcpFlags.SYN | tun_stack.TcpFlags.ACK,
                    .{ .window = slot.conn.advertisedWindow(), .options = out_opts },
                    "",
                    out,
                );
            }

            const slot = self.findTcp(key) orelse {
                // 未知连接：回 RST
                return try self.buildTcpReply(
                    iph,
                    th,
                    0,
                    th.seq +% @as(u32, @intCast(payload.len)) +% @as(u32, if ((th.flags & tun_stack.TcpFlags.SYN) != 0) 1 else 0),
                    tun_stack.TcpFlags.RST | tun_stack.TcpFlags.ACK,
                    "",
                    out,
                );
            };

            const reply_flags = try slot.conn.onSegment(incoming, now_ms);

            // 数据交给上层
            if (payload.len > 0 and self.handler != null) {
                self.stat_tcp_in +%= payload.len;
                if (self.handler) |h| h.tcpData(key, payload) catch {};
            }

            // 连接结束
            if (slot.conn.state == .closed or slot.conn.state == .time_wait) {
                if (self.handler) |h| h.tcpClose(key);
            }

            if (reply_flags == 0) return 0;

            // 纯 ACK 也要带上真实窗口与选项：窗口写死 64240 时，
            // 接收缓冲将满的告警根本传不出去，对端会继续猛发然后被我们丢弃。
            var ackbuf: [40]u8 = undefined;
            const aopts = slot.conn.dataOptions(&ackbuf);
            return try self.buildTcpReplyEx(
                key,
                slot.conn.snd_nxt,
                slot.conn.rcv_nxt,
                reply_flags,
                .{ .window = slot.conn.advertisedWindow(), .options = aopts },
                "",
                out,
            );
        }

        fn handleUdp(self: *Stack, iph: tun_stack.Ipv4Header, pkt: []const u8, out: []u8, now_ms: i64) !usize {
            _ = out;
            const seg = pkt[iph.payload_start..iph.payload_end];
            const uh = tun_stack.parseUdp(seg) orelse return 0;
            const payload = seg[uh.payload_start..uh.payload_end];

            const key = ip.UdpKey{
                .src_ip = iph.src,
                .src_port = uh.src_port,
                .dst_ip = iph.dst,
                .dst_port = uh.dst_port,
            };

            _ = try self.nat.map(key, now_ms);
            self.stat_udp_in +%= payload.len;

            if (self.handler) |h| {
                h.udpData(key, payload) catch {};
            }
            // UDP 的回包由上层调用 writeUdp 主动发出，这里不需要立即回包
            return 0;
        }

        /// 构造回给客户端的 TCP 段。
        ///
        /// **源地址必须是本端 TUN 地址**，不能用原包的目的地址：
        /// TUN 场景下「远端」是本机模拟的，客户端认为自己在跟 1.1.1.1 说话，
        /// 但回包的以太层/IP 层来源必须是与客户端同网段的 TUN 网关，
        /// 否则客户端会因为源地址与目标地址相同而丢弃（实测表现为连接卡死）。
        fn buildTcpReply(
            self: *Stack,
            iph: tun_stack.Ipv4Header,
            th: tun_stack.TcpHeader,
            seq: u32,
            ack: u32,
            flags: u9,
            payload: []const u8,
            out: []u8,
        ) !usize {
            return tun_conn.buildTcpSegment(
                out,
                self.local_ip, // 源 = 本端 TUN 地址
                iph.src, // 目的 = 原客户端
                th.dst_port,
                th.src_port,
                seq,
                ack,
                flags,
                payload,
            ) catch 0;
        }

        /// 带选项/窗口的回复构造（SYN-ACK 与数据段走这条）
        fn buildTcpReplyEx(
            self: *Stack,
            key: tcp.Key,
            seq: u32,
            ack: u32,
            flags: u9,
            opts: tun_conn.SegmentOpts,
            payload: []const u8,
            out: []u8,
        ) !usize {
            return tun_conn.buildTcpSegmentEx(
                out,
                self.local_ip,
                key.src_ip,
                key.dst_port,
                key.src_port,
                seq,
                ack,
                flags,
                opts,
                payload,
            ) catch 0;
        }

        // ------------------------------------------------------------------------
        // 出站 → TUN
        // ------------------------------------------------------------------------

        /// 上游数据回写给客户端（构造 TCP 段）
        ///
        /// **不再绕过发送队列**：旧实现直接拼包并推进 `snd_nxt`，
        /// 导致数据既不重传、也不按 MSS 切分、还不看拥塞窗口 ——
        /// 丢一个包连接就永久卡死。现在数据先进队列，再从队列取段发送。
        pub fn writeTcp(self: *Stack, key: tcp.Key, data: []const u8, out: []u8, now_ms: i64) !usize {
            const slot = self.findTcp(key) orelse return 0;
            slot.conn.now_ms = now_ms;
            if (data.len > 0) _ = try slot.conn.write(data);
            return try self.emitOne(slot, out);
        }

        /// 继续把队列里剩余的段发出去（调用方循环调用直到返回 0）
        pub fn flushTcp(self: *Stack, key: tcp.Key, out: []u8, now_ms: i64) !usize {
            const slot = self.findTcp(key) orelse return 0;
            slot.conn.now_ms = now_ms;
            return try self.emitOne(slot, out);
        }

        /// 从发送队列取一个可发段并构造报文；返回 0 表示当前没有可发段
        fn emitOne(self: *Stack, slot: *TcpSlot, out: []u8) !usize {
            const conn = &slot.conn;
            // 纯 FIN 段不占窗口，窗口满时也必须能发出去，否则连接关不掉
            const seg = conn.nextSendSegment() orelse return 0;
            if (seg.len > 0 and !conn.canSendMore()) return 0; // 拥塞窗口 / 对端窗口已满
            const payload = conn.send_buf.items[seg.start .. seg.start + seg.len];

            // 数据段也要带窗口与选项：接收窗口动态变化、时间戳用于 RTT 与
            // 回绕检测、SACK 块告诉对端哪些乱序段已收到（避免全量重传）。
            var optbuf: [40]u8 = undefined;
            const dopts = conn.dataOptions(&optbuf);

            var flags: u9 = tun_stack.TcpFlags.ACK;
            if (seg.len > 0) flags |= tun_stack.TcpFlags.PSH;
            if (seg.fin) flags |= tun_stack.TcpFlags.FIN;

            const n = try tun_conn.buildTcpSegmentEx(
                out,
                self.local_ip,
                slot.key.src_ip,
                slot.key.dst_port,
                slot.key.src_port,
                seg.seq,
                conn.rcv_nxt,
                flags,
                .{ .window = conn.advertisedWindow(), .options = dopts },
                payload,
            );
            conn.markSent(seg);
            conn.cc.onSend(seg.len);
            self.stat_tcp_out +%= seg.len;
            return n;
        }

        /// 上游 UDP 回包
        pub fn writeUdp(self: *Stack, key: ip.UdpKey, data: []const u8, out: []u8) !usize {
            self.stat_udp_out +%= data.len;
            return ip.buildUdpPacket(
                out,
                self.local_ip,
                key.src_ip,
                key.dst_port,
                key.src_port,
                data,
            ) catch 0;
        }

        // ------------------------------------------------------------------------
        // 定时驱动
        // ------------------------------------------------------------------------

        /// 驱动定时器；返回一个需要立即发出的报文长度（0 表示没有）
        ///
        /// 重传、零窗口探测、FIN 重发都要在这里落成真实报文。
        /// 早先 `tick` 只是把段标回 `sent = false`，没人去取、没人去发 ——
        /// 弱网下连接会静默挂死，测试却全绿（因为测试直接查队列状态）。
        pub fn tickAndEmit(self: *Stack, key: tcp.Key, out: []u8, now_ms: i64) !usize {
            const slot = self.findTcp(key) orelse return 0;
            slot.conn.now_ms = now_ms;

            // 零窗口探测：发 1 字节「探针」，序号是 snd_una - 1（RFC 9293 §3.8.6.1）。
            // 对端会回 ACK 并带上最新窗口，窗口若已打开就恢复正常发送。
            if (slot.conn.takePersistProbe()) {
                const probe_seq = slot.conn.snd_una -% 1;
                const probe = [_]u8{0};
                return tun_conn.buildTcpSegmentEx(
                    out,
                    self.local_ip,
                    key.src_ip,
                    key.dst_port,
                    key.src_port,
                    probe_seq,
                    slot.conn.rcv_nxt,
                    tun_stack.TcpFlags.ACK,
                    .{ .window = slot.conn.advertisedWindow() },
                    &probe,
                ) catch 0;
            }

            return try self.emitOne(slot, out);
        }

        /// 是否有待发出的数据（含重传与 FIN）
        pub fn hasPendingTcp(self: *Stack, key: tcp.Key) bool {
            const slot = self.findTcp(key) orelse return false;
            return slot.conn.hasPendingSend();
        }

        /// 周期性调用：重传、超时清理
        pub fn tick(self: *Stack, now_ms: i64) void {
            for (self.tcp_slots.items) |*s| {
                s.conn.tick(now_ms) catch {};
            }
            // 清理已关闭的连接
            var i: usize = 0;
            while (i < self.tcp_slots.items.len) {
                if (self.tcp_slots.items[i].conn.state == .closed) {
                    self.tcp_slots.items[i].deinit();
                    _ = self.tcp_slots.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
            _ = self.nat.sweep(now_ms);
            _ = self.reassembler.sweep(now_ms);
        }

        /// 删除一条 TCP 连接（上游断开时调用）
        pub fn closeTcp(self: *Stack, key: tcp.Key) void {
            var i: usize = 0;
            while (i < self.tcp_slots.items.len) : (i += 1) {
                if (tcp.Key.eql(self.tcp_slots.items[i].key, key)) {
                    self.tcp_slots.items[i].deinit();
                    _ = self.tcp_slots.orderedRemove(i);
                    return;
                }
            }
        }
    };










    // ============================================================================
    // 线路上真实生效的验证
    //
    // 下面这批测试检查的是**实际构造出来的报文**，而不是内存里的状态。
    // 起因：`opts` / `rcv_wnd` / `fin_queued` 这些字段此前都算对了，
    // 但一个都没写进包里，207 个测试全绿而真实链路不可用。
    // ============================================================================





    fn seq_lt(a: u32, b: u32) bool {
        return @as(i32, @bitCast(a -% b)) < 0;
    }
    fn seq_ge(a: u32, b: u32) bool {
        return !seq_lt(a, b);
    }


};

pub const conntrack = struct {
    //! 连接跟踪表（解决原版「没有任何连接级可观测性」的问题）。
    //!
    //! 原 Rust 版只有两个全局 `AtomicU64`，无法回答「当前有几个连接、
    //! 各自连去哪、走了哪个节点」。这里维护一张有界连接表，
    //! 供 `/api/connections` 与 UI 使用。

    pub const ConnState = enum { connecting, active, closed };

    pub const ConnInfo = struct {
        id: u64,
        /// 客户端地址（字符串，stable 存储）
        src: []const u8,
        /// 目标 host:port
        dst: []const u8,
        /// 命中的节点名（空表示直连）
        node: []const u8 = "",
        /// 命中的规则说明
        rule: []const u8 = "",
        /// 进程名（TUN 模式）
        process: []const u8 = "",
        state: ConnState = .connecting,
        up: u64 = 0,
        down: u64 = 0,
        started_ms: i64 = 0,
    };

    pub const Tracker = struct {
        alloc: std.mem.Allocator,
        mutex: net.Mutex = .{},
        next_id: u64 = 1,
        /// 活跃连接（只保留未关闭的）
        conns: std.AutoHashMapUnmanaged(u64, ConnInfo) = .empty,
        /// 最大保留条数（防内存无限增长）
        max_entries: usize = 512,
        /// 累计统计（关连接后仍保留总数）
        total_up: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        total_down: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub fn init(alloc: std.mem.Allocator) Tracker {
            return .{ .alloc = alloc };
        }

        pub fn deinit(self: *Tracker) void {
            var it = self.conns.iterator();
            while (it.next()) |kv| self.freeInfo(kv.value_ptr.*);
            self.conns.deinit(self.alloc);
        }

        fn freeInfo(self: *Tracker, info: ConnInfo) void {
            self.alloc.free(info.src);
            self.alloc.free(info.dst);
            self.alloc.free(info.node);
            self.alloc.free(info.rule);
            self.alloc.free(info.process);
        }

        /// 登记一条新连接
        pub fn open(
            self: *Tracker,
            src: []const u8,
            dst: []const u8,
            node: []const u8,
            rule: []const u8,
            process: []const u8,
        ) ?u64 {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.conns.count() >= self.max_entries) {
                // 满了就挤掉最早的一条（简单 LRU 语义足够）
                var oldest_id: u64 = 0;
                var oldest_time: i64 = std.math.maxInt(i64);
                var it = self.conns.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.started_ms < oldest_time) {
                        oldest_time = kv.value_ptr.started_ms;
                        oldest_id = kv.key_ptr.*;
                    }
                }
                if (oldest_id != 0) {
                    if (self.conns.fetchRemove(oldest_id)) |kv| self.freeInfo(kv.value);
                }
            }

            const id = self.next_id;
            self.next_id += 1;

            const info = ConnInfo{
                .id = id,
                .src = self.alloc.dupe(u8, src) catch return null,
                .dst = self.alloc.dupe(u8, dst) catch return null,
                .node = self.alloc.dupe(u8, node) catch return null,
                .rule = self.alloc.dupe(u8, rule) catch return null,
                .process = self.alloc.dupe(u8, process) catch return null,
                .started_ms = net.milliTimestamp(),
            };
            self.conns.put(self.alloc, id, info) catch {
                self.freeInfo(info);
                return null;
            };
            return id;
        }

        pub fn markActive(self: *Tracker, id: u64) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.conns.getPtr(id)) |c| c.state = .active;
        }

        /// 累加流量并记录
        pub fn addTraffic(self: *Tracker, id: u64, up: u64, down: u64) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.conns.getPtr(id)) |c| {
                c.up += up;
                c.down += down;
            }
            _ = self.total_up.fetchAdd(up, .monotonic);
            _ = self.total_down.fetchAdd(down, .monotonic);
        }

        pub fn close(self: *Tracker, id: u64) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.conns.fetchRemove(id)) |kv| self.freeInfo(kv.value);
        }

        /// 快照（调用方负责 free）
        pub fn snapshot(self: *Tracker, alloc: std.mem.Allocator) ![]ConnInfo {
            self.mutex.lock();
            defer self.mutex.unlock();

            var list = std.ArrayList(ConnInfo).empty;
            errdefer list.deinit(alloc);
            var it = self.conns.iterator();
            while (it.next()) |kv| {
                const c = kv.value_ptr.*;
                try list.append(alloc, .{
                    .id = c.id,
                    .src = try alloc.dupe(u8, c.src),
                    .dst = try alloc.dupe(u8, c.dst),
                    .node = try alloc.dupe(u8, c.node),
                    .rule = try alloc.dupe(u8, c.rule),
                    .process = try alloc.dupe(u8, c.process),
                    .state = c.state,
                    .up = c.up,
                    .down = c.down,
                    .started_ms = c.started_ms,
                });
            }
            return list.toOwnedSlice(alloc);
        }

        pub fn freeSnapshot(alloc: std.mem.Allocator, items: []ConnInfo) void {
            for (items) |c| {
                alloc.free(c.src);
                alloc.free(c.dst);
                alloc.free(c.node);
                alloc.free(c.rule);
                alloc.free(c.process);
            }
            alloc.free(items);
        }

        pub fn activeCount(self: *Tracker) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.conns.count();
        }
    };

    // ============================ 测试 ============================




};

