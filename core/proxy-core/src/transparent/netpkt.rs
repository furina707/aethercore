//! 纯逻辑网络包工具：IPv4 / TCP / UDP 解析、Internet 校验和、构造回包。
//!
//! 该模块完全不依赖 Windows 或 wintun，全部为纯函数，便于单元测试
//! （`cargo test` 可实跑；本环境仅能 `cargo check`）。
//! 透明代理的 Wintun 引擎（`wintun_tun.rs`）依赖此处的解析与构造能力，
//! 在 TUN 线程里完成「捕获原始 IP 包 → 解析五元组 → 伪造 SYN/ACK/FIN/数据回包」。
use std::net::Ipv4Addr;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// 解析后的 IPv4 报文（仅取 L4 负载切片，零拷贝）。
#[derive(Debug, Clone, Copy)]
pub struct IpPacket<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    /// L4 段：TCP/UDP 头 + 数据
    pub payload: &'a [u8],
}

/// 解析后的 TCP 段。
#[derive(Debug, Clone)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: u8,
    pub data: &'a [u8],
    /// 从 SYN 选项的 MSS 中解析；无则为 None
    pub mss: Option<u16>,
}

/// 解析后的 UDP 数据报。
#[derive(Debug, Clone)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub data: &'a [u8],
}

/// 解析 IPv4 报文，返回源/目的 IP、协议号与 L4 负载切片。
/// 仅做最小校验（版本=4、IHL≥5、总长度、协议号）；不校验 IP 头_checksum。
pub fn parse_ipv4(pkt: &[u8]) -> Option<IpPacket<'_>> {
    if pkt.len() < 20 {
        return None;
    }
    let version_ihl = pkt[0];
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let total_len = total_len.min(pkt.len());
    let proto = pkt[9];
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    let payload = &pkt[ihl..total_len];
    Some(IpPacket {
        src,
        dst,
        proto,
        payload,
    })
}

/// 解析 TCP 段（输入为 IPv4 负载）。
pub fn parse_tcp(seg: &[u8]) -> Option<TcpSegment<'_>> {
    if seg.len() < 20 {
        return None;
    }
    let data_off = (seg[12] >> 4) as usize * 4;
    if data_off < 20 || seg.len() < data_off {
        return None;
    }
    let src_port = u16::from_be_bytes([seg[0], seg[1]]);
    let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
    let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
    let ack = u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]);
    let window = u16::from_be_bytes([seg[14], seg[15]]);
    let flags = seg[13];
    let data = &seg[data_off..];
    let mss = parse_tcp_mss(&seg[20..data_off]);
    Some(TcpSegment {
        src_port,
        dst_port,
        seq,
        ack,
        window,
        flags,
        data,
        mss,
    })
}

/// 解析 TCP 选项里的 MSS（用于限制我们发出的段大小，避免分片）。
fn parse_tcp_mss(options: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i + 1 < options.len() {
        let kind = options[i];
        if kind == 0 {
            break; // End of options
        }
        if kind == 1 {
            i += 1; // NOP
            continue;
        }
        let len = options[i + 1] as usize;
        if len < 2 || i + len > options.len() {
            break;
        }
        if kind == 2 && len == 4 {
            return Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
        }
        i += len;
    }
    None
}

/// 解析 UDP 数据报（输入为 IPv4 负载）。
pub fn parse_udp(seg: &[u8]) -> Option<UdpDatagram<'_>> {
    if seg.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([seg[0], seg[1]]);
    let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
    let data = &seg[8..];
    Some(UdpDatagram {
        src_port,
        dst_port,
        data,
    })
}

/// Internet 校验和（RFC 1071，ones' complement）。
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 头校验和（输入为 20 字节头，校验和字段应已置零）。
pub fn ipv4_header_checksum(header: &[u8; 20]) -> u16 {
    internet_checksum(header)
}

/// TCP/UDP 校验和：伪头（源IP+目的IP+0+协议+长度）+ 段（校验和字段置零）。
pub fn transport_checksum(src: &[u8; 4], dst: &[u8; 4], proto: u8, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len() + 1);
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
    buf.push(0);
    buf.push(proto);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    // 保证偶数长度
    if buf.len() % 2 != 0 {
        buf.push(0);
    }
    internet_checksum(&buf)
}

/// 构造完整的 IPv4 + TCP 回包。
///
/// 调用方负责按方向传入 `src`/`dst`（透明代理里：src=真实服务器、dst=客户端）。
pub fn build_ipv4_tcp(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total = 20 + tcp_len;
    let mut buf = vec![0u8; total];

    // ---- IPv4 头 ----
    buf[0] = 0x45; // version 4, IHL 5
    buf[1] = 0; // DSCP/ECN
    buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF=1, fragment offset 0
    buf[8] = 64; // TTL
    buf[9] = IPPROTO_TCP;
    buf[12..16].copy_from_slice(src_ip);
    buf[16..20].copy_from_slice(dst_ip);
    let mut ip_header = [0u8; 20];
    ip_header.copy_from_slice(&buf[0..20]);
    let ip_csum = ipv4_header_checksum(&ip_header);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ---- TCP 头 ----
    buf[20..22].copy_from_slice(&src_port.to_be_bytes());
    buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
    buf[24..28].copy_from_slice(&seq.to_be_bytes());
    buf[28..32].copy_from_slice(&ack.to_be_bytes());
    buf[32] = 0x50; // data offset 5, reserved 0
    buf[33] = flags;
    buf[34..36].copy_from_slice(&window.to_be_bytes());
    buf[36..38].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buf[38..40].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer
    buf[40..].copy_from_slice(payload);
    let tcp_csum = transport_checksum(src_ip, dst_ip, IPPROTO_TCP, &buf[20..]);
    buf[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

    buf
}

/// 构造完整的 IPv4 + UDP 回包（UDP 校验和置 0，IPv4 下合法）。
pub fn build_ipv4_udp(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut buf = vec![0u8; total];

    // ---- IPv4 头 ----
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = IPPROTO_UDP;
    buf[12..16].copy_from_slice(src_ip);
    buf[16..20].copy_from_slice(dst_ip);
    let mut ip_header = [0u8; 20];
    ip_header.copy_from_slice(&buf[0..20]);
    let ip_csum = ipv4_header_checksum(&ip_header);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ---- UDP 头 ----
    buf[20..22].copy_from_slice(&src_port.to_be_bytes());
    buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
    buf[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[26..28].copy_from_slice(&0u16.to_be_bytes()); // checksum = 0
    buf[28..].copy_from_slice(payload);

    buf
}

/// 从 IPv4 地址生成 4 字节数组。
pub fn ipv4_to_octets(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        build_ipv4_tcp(&src, &dst, sport, dport, seq, ack, flags, 65535, payload)
    }

    #[test]
    fn checksum_of_zero_buffer_is_0xffff() {
        // 全零的偶数长度缓冲，取反后应为 0xffff
        assert_eq!(internet_checksum(&[0u8; 4]), 0xffff);
    }

    #[test]
    fn ipv4_parse_roundtrip() {
        let src = [10, 0, 0, 1];
        let dst = [93, 184, 216, 34];
        let pkt = mk_tcp_packet(src, dst, 12345, 443, 100, 0, TCP_SYN, &[]);
        let ip = parse_ipv4(&pkt).expect("parse");
        assert_eq!(ip.src, src);
        assert_eq!(ip.dst, dst);
        assert_eq!(ip.proto, IPPROTO_TCP);
        let tcp = parse_tcp(ip.payload).expect("parse tcp");
        assert_eq!(tcp.src_port, 12345);
        assert_eq!(tcp.dst_port, 443);
        assert_eq!(tcp.seq, 100);
        assert_eq!(tcp.flags, TCP_SYN);
        assert!(tcp.data.is_empty());
    }

    #[test]
    fn tcp_checksum_is_self_consistent() {
        // 构造包后重新解析，用「零校验和」的段重算应等于包中存储的校验和
        let src = [192, 168, 1, 10];
        let dst = [1, 1, 1, 1];
        let payload = b"GET / HTTP/1.1\r\n";
        let pkt = mk_tcp_packet(src, dst, 5000, 80, 7, 99, TCP_PSH | TCP_ACK, payload);
        let ip = parse_ipv4(&pkt).unwrap();
        let tcp = parse_tcp(ip.payload).unwrap();
        assert_eq!(tcp.data, payload);
        // 复制段并将校验和字段清零后重算
        let mut seg = ip.payload.to_vec();
        seg[16..18].copy_from_slice(&0u16.to_be_bytes()); // TCP 校验和在偏移 16
        let recomputed = transport_checksum(&src, &dst, IPPROTO_TCP, &seg);
        // 包中存储的校验和位于 TCP 头偏移 16
        let stored = u16::from_be_bytes([ip.payload[16], ip.payload[17]]);
        assert_eq!(recomputed, stored, "重建的 TCP 校验和应与包中一致");
    }

    #[test]
    fn ip_header_checksum_valid() {
        let src = [10, 0, 0, 1];
        let dst = [8, 8, 8, 8];
        let pkt = mk_tcp_packet(src, dst, 1, 2, 0, 0, TCP_SYN, &[]);
        let mut header = [0u8; 20];
        header.copy_from_slice(&pkt[0..20]);
        // 校验和字段已填，再算一次应为 0
        assert_eq!(internet_checksum(&header), 0, "合法 IP 头校验和重算应为 0");
    }

    #[test]
    fn mss_option_parsed() {
        // 手工造一个带 MSS=1460 选项的 SYN 段
        let mut seg = vec![0u8; 20 + 4];
        seg[12] = 0x50; // data offset 5
        seg[13] = TCP_SYN;
        // 选项：kind=2 len=4 mss=1460
        seg[20] = 2;
        seg[21] = 4;
        seg[22..24].copy_from_slice(&1460u16.to_be_bytes());
        let tcp = parse_tcp(&seg).unwrap();
        assert_eq!(tcp.mss, Some(1460));
    }

    #[test]
    fn udp_build_and_parse() {
        let src = [10, 0, 0, 2];
        let dst = [10, 0, 0, 3];
        let pkt = build_ipv4_udp(&src, &dst, 5353, 53, b"hello");
        let ip = parse_ipv4(&pkt).unwrap();
        assert_eq!(ip.proto, IPPROTO_UDP);
        let udp = parse_udp(ip.payload).unwrap();
        assert_eq!(udp.src_port, 5353);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.data, b"hello");
    }

    #[test]
    fn malformed_packets_rejected() {
        assert!(parse_ipv4(&[0u8; 10]).is_none());
        assert!(parse_ipv4(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]).is_some());
        assert!(parse_tcp(&[0u8; 10]).is_none());
        assert!(parse_udp(&[0u8; 4]).is_none());
    }
}
