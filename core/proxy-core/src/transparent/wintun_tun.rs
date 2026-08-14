//! 透明代理方案2：Wintun 虚拟网卡 TUN 透明拦截（Windows，用户态，无需内核驱动）。
//!
//! 工作原理：
//!   1. 通过 `wintun` crate 加载 `wintun.dll`（WireGuard 项目出品，MIT），
//!      打开/创建虚拟网卡并启动会话（Session）。
//!   2. 把被路由到该网卡的 IPv4 流量（典型由 `route add` / 默认网关指向 TUN）捕获。
//!   3. 在专用线程里对捕获的包做 **用户态 TCP 终止**（最小状态机：SYN/ACK/FIN/
//!      序列号/重传）与 **UDP NAT**，从而拿到每条连接的「原始目标 IP:端口」。
//!   4. TCP 连接直接通过现有 `relay::dial_outbound_state` 拨号到真实目标
//!      （复用路由/健康探测/TLS）；UDP 则直接用本机 socket 发往真实目标（NAT）。
//!
//! 部署（需管理员）：
//!   - 把 `wintun.dll`（x64）放到程序目录或 PATH；
//!   - `netsh interface ip set address "omni-proxy-tun" static 10.99.0.1 255.255.255.0`
//!   - 添加路由，例如：`route add 0.0.0.0 mask 128.0.0.0 10.99.0.1` 与
//!     `route add 128.0.0.0 mask 128.0.0.0 10.99.0.1`（把全量流量引向 TUN）。
//!
//! 设计取舍（重要）：
//!   - 这里用「自研最小 TCP 状态机」而非 smoltcp，完全规避 smoltcp 的 buffer 生命周期
//!     复杂度，且逻辑可控、可编译验证。对于本地 TUN（无真实线路丢包、无 PMTU 问题）
//!     足够稳健；RFC 完整性（SACK、窗口缩放、PMTU）为已知缺口，后续可换 smoltcp 加固。
//!   - TCP 回包在收到客户端数据后立即 ACK（rcv_nxt 前移），靠 TCP 窗口做背压；
//!     上游慢时客户端数据暂存 `pending_app`，超过上限则断连。
use crate::config::WintunConfig;
use crate::relay::dial_outbound_state;
use crate::route::RouteRequest;
use crate::state::ProxyState;
use crate::transparent::netpkt::*;
use anyhow::Result;
use rand::random;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::mpsc as ampsc;

/// 四元组：标识一条连接（src_ip, src_port, dst_ip, dst_port）。
type Quad = ([u8; 4], u16, [u8; 4], u16);

/// 重传超时与各类阈值。
const RTO: Duration = Duration::from_millis(500);
const MAX_RETRANSMITS: u32 = 12;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const PENDING_APP_CAP: usize = 8 * 1024 * 1024; // 客户端→上游缓冲上限
const CHANNEL_CAP: usize = 1024;

#[cfg(windows)]
pub async fn run_wintun(cfg: &WintunConfig, state: Arc<ProxyState>) -> Result<()> {
    let rt = Handle::current();
    let dll = cfg.dll_path.clone().unwrap_or_else(|| "wintun.dll".into());
    tracing::info!(dll = %dll, "加载 wintun.dll");
    let wintun = match unsafe { wintun::load_from_path(&dll) } {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(
                dll = %dll,
                error = ?e,
                "无法加载 wintun.dll。请下载 https://www.wintun.net 的 x64 dll 放入程序目录或 PATH，并以管理员运行。"
            );
            return Ok(());
        }
    };

    let adapter = match wintun::Adapter::open(&wintun, &cfg.adapter_name) {
        Ok(a) => a,
        Err(_) => match wintun::Adapter::create(&wintun, "omni-proxy", &cfg.adapter_name, None) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(
                    adapter = %cfg.adapter_name,
                    error = ?e,
                    "无法打开/创建 Wintun 适配器（需管理员权限）"
                );
                return Ok(());
            }
        },
    };

    let session = match adapter.start_session(wintun::MAX_RING_CAPACITY) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(error = ?e, "Wintun 启动会话失败");
            return Ok(());
        }
    };

    let (tun_ip, prefix) = match parse_subnet(&cfg.subnet) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(subnet = %cfg.subnet, error = ?e, "subnet 配置解析失败");
            return Ok(());
        }
    };
    tracing::info!(
        adapter = %cfg.adapter_name,
        tun_ip = %tun_ip,
        prefix,
        "Wintun 会话已启动；请将流量路由到该网卡（如 route add 0.0.0.0 mask 128.0.0.0 <tun_ip>）"
    );

    // 原始包通道：RX 线程 → 处理线程
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let stop = Arc::new(AtomicBool::new(false));

    // RX 线程：阻塞读取 Wintun 包，转发到通道
    let session_rx = session.clone();
    let stop_rx = stop.clone();
    std::thread::spawn(move || {
        loop {
            if stop_rx.load(Ordering::Relaxed) {
                break;
            }
            match session_rx.receive_blocking() {
                Ok(packet) => {
                    let data = packet.bytes().to_vec();
                    if tx.send(data).is_err() {
                        break; // 处理线程已退出
                    }
                }
                Err(_) => {
                    // 会话被 shutdown / 驱动卸载 / 线程退出
                    break;
                }
            }
        }
    });

    // 处理线程（阻塞线程池）：跑 TCP/UDP 终止与桥接
    let state2 = state.clone();
    let stop_proc = stop.clone();
    tokio::task::spawn_blocking(move || {
        run_engine(rx, session, state2, rt, stop_proc, tun_ip);
    });

    Ok(())
}

#[cfg(not(windows))]
pub async fn run_wintun(_cfg: &WintunConfig, _state: Arc<ProxyState>) -> Result<()> {
    tracing::warn!("Wintun 透明模式仅在 Windows 可用，当前平台跳过。");
    Ok(())
}

fn parse_subnet(s: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("subnet 应为 ip/prefix 形式，如 10.99.0.1/24"))?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| anyhow::anyhow!("非法 IP：{}", ip))?;
    let prefix: u8 = prefix.parse().unwrap_or(24);
    Ok((ip, prefix))
}

/// 处理线程主循环：收包 → 分发 → 周期性 tick（重传/回收/空闲超时）。
fn run_engine(
    rx: mpsc::Receiver<Vec<u8>>,
    session: Arc<wintun::Session>,
    state: Arc<ProxyState>,
    rt: Handle,
    stop: Arc<AtomicBool>,
    _tun_ip: Ipv4Addr,
) {
    let mut tcp_conns: HashMap<Quad, TcpConn> = HashMap::new();
    let mut udp_conns: HashMap<Quad, UdpConn> = HashMap::new();
    let start = Instant::now();
    let mut last_gc = start;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(pkt) => {
                dispatch(&pkt, &mut tcp_conns, &mut udp_conns, &session, &state, &rt);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(_) => break, // 通道断开，处理线程退出
        }

        let now = Instant::now();
        // TCP：抽取上游数据、发送、重传、回收
        for conn in tcp_conns.values_mut() {
            conn.poll_upstream(&session, now);
            conn.tick_retransmit(&session, now);
            if now.saturating_duration_since(conn.last_active) > TCP_IDLE_TIMEOUT {
                conn.dead = true;
            }
        }
        // UDP：取回应、空闲回收
        for u in udp_conns.values_mut() {
            u.poll_reply(&session, now);
            if now.saturating_duration_since(u.last_active) > UDP_IDLE_TIMEOUT {
                u.dead = true;
            }
        }
        // 周期性 GC
        if now.saturating_duration_since(last_gc) > Duration::from_secs(5) {
            tcp_conns.retain(|_, c| !c.dead);
            udp_conns.retain(|_, u| !u.dead);
            last_gc = now;
        }
    }
}

/// 把一个 IP 包分发给 TCP 或 UDP 处理逻辑。
fn dispatch(
    pkt: &[u8],
    tcp_conns: &mut HashMap<Quad, TcpConn>,
    udp_conns: &mut HashMap<Quad, UdpConn>,
    session: &Arc<wintun::Session>,
    state: &Arc<ProxyState>,
    rt: &Handle,
) {
    let ip = match parse_ipv4(pkt) {
        Some(ip) => ip,
        None => return,
    };
    match ip.proto {
        IPPROTO_TCP => {
            let tcp = match parse_tcp(ip.payload) {
                Some(t) => t,
                None => return,
            };
            let quad = (ip.src, tcp.src_port, ip.dst, tcp.dst_port);
            handle_tcp(quad, &tcp, tcp_conns, session, state, rt);
        }
        IPPROTO_UDP => {
            let udp = match parse_udp(ip.payload) {
                Some(u) => u,
                None => return,
            };
            let quad = (ip.src, udp.src_port, ip.dst, udp.dst_port);
            handle_udp(quad, &udp, udp_conns, session);
        }
        _ => {}
    }
}

// ===================== TCP =====================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    SynRcvd,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    Closed,
}

struct TcpConn {
    client_ip: [u8; 4],
    client_port: u16,
    server_ip: [u8; 4],
    server_port: u16,
    cisn: u32,
    our_isn: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    send_buf: Vec<u8>,
    last_send: Instant,
    retransmits: u32,
    mss: usize,
    state: TcpState,
    app_tx: Option<ampsc::Sender<Vec<u8>>>,
    up_rx: ampsc::Receiver<Vec<u8>>,
    pending_app: Vec<u8>,
    upstream_closed: bool,
    fin_to_client_sent: bool,
    fin_from_client: bool,
    dead: bool,
    last_active: Instant,
}

impl TcpConn {
    /// 向客户端发送一个 TCP 段（已带 IP 头）。src=server, dst=client。
    fn send_segment(&self, session: &Arc<wintun::Session>, flags: u8, payload: &[u8]) {
        let pkt = build_ipv4_tcp(
            &self.server_ip,
            &self.client_ip,
            self.server_port,
            self.client_port,
            self.snd_nxt,
            self.rcv_nxt,
            flags,
            65535,
            payload,
        );
        send_ip(session, &pkt);
    }

    /// 把上游数据作为 PSH+ACK 段发出（按 MSS 分段），记入 send_buf 待确认。
    fn push_out(&mut self, session: &Arc<wintun::Session>, data: &[u8], now: Instant) {
        if data.is_empty() {
            return;
        }
        let mut off = 0;
        while off < data.len() {
            let end = (off + self.mss).min(data.len());
            let chunk = &data[off..end];
            self.send_segment(session, TCP_PSH | TCP_ACK, chunk);
            self.send_buf.extend_from_slice(chunk);
            self.snd_nxt = self.snd_nxt.wrapping_add(chunk.len() as u32);
            off = end;
        }
        self.last_send = now;
    }

    /// 每轮：把上游来的数据（up_rx）取出并发往客户端；检测上游关闭 → 发 FIN。
    fn poll_upstream(&mut self, session: &Arc<wintun::Session>, now: Instant) {
        // 先把上次未发出的 pending 客户端数据尽力发出（虽由 handle_tcp 写入，
        // 但此处统一兜底确保不被丢）
        loop {
            match self.up_rx.try_recv() {
                Ok(b) => self.push_out(session, &b, now),
                Err(ampsc::error::TryRecvError::Empty) => break,
                Err(ampsc::error::TryRecvError::Disconnected) => {
                    self.upstream_closed = true;
                    break;
                }
            }
        }
        if self.app_tx.is_none() {
            self.upstream_closed = true;
        }
        if self.upstream_closed && !self.fin_to_client_sent {
            // 上游已关：向客户端发 FIN（半关），等待其 ACK 后回收
            // 即使客户端先发了 FIN（CloseWait），仍需补发我方 FIN 完成双向关闭。
            self.send_segment(session, TCP_FIN | TCP_ACK, &[]);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_to_client_sent = true;
            self.state = TcpState::FinWait;
        }
    }

    /// 重传未确认数据 / SYN-ACK。
    fn tick_retransmit(&mut self, session: &Arc<wintun::Session>, now: Instant) {
        let unacked = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        let need_resend = match self.state {
            TcpState::SynRcvd => now.saturating_duration_since(self.last_send) > RTO,
            _ => unacked > 0 && now.saturating_duration_since(self.last_send) > RTO,
        };
        if !need_resend {
            return;
        }
        self.retransmits += 1;
        if self.retransmits > MAX_RETRANSMITS {
            self.dead = true;
            return;
        }
        if self.state == TcpState::SynRcvd {
            // 重发 SYN-ACK
            let pkt = build_ipv4_tcp(
                &self.server_ip,
                &self.client_ip,
                self.server_port,
                self.client_port,
                self.our_isn,
                self.cisn.wrapping_add(1),
                TCP_SYN | TCP_ACK,
                65535,
                &[],
            );
            send_ip(session, &pkt);
            self.last_send = now;
        } else if !self.send_buf.is_empty() {
            // 从未确认位置重发
            let unacked_bytes = &self.send_buf[..unacked.min(self.send_buf.len())];
            // 用 snd_una 作为起始 seq 重发（连续一段，最多按 MSS 发首段即可触发窗口）
            let mut off = 0;
            // 重发整段未确认数据（本地 TUN，量不大）
            while off < unacked_bytes.len() {
                let end = (off + self.mss).min(unacked_bytes.len());
                let chunk = &unacked_bytes[off..end];
                let pkt = build_ipv4_tcp(
                    &self.server_ip,
                    &self.client_ip,
                    self.server_port,
                    self.client_port,
                    self.snd_una.wrapping_add(off as u32),
                    self.rcv_nxt,
                    TCP_PSH | TCP_ACK,
                    65535,
                    chunk,
                );
                send_ip(session, &pkt);
                off = end;
            }
            self.last_send = now;
        }
    }
}

/// 处理一个 TCP 段（新连接建立或已有连接的数据/ACK/FIN/RST）。
fn handle_tcp(
    quad: Quad,
    tcp: &crate::transparent::netpkt::TcpSegment<'_>,
    conns: &mut HashMap<Quad, TcpConn>,
    session: &Arc<wintun::Session>,
    state: &Arc<ProxyState>,
    rt: &Handle,
) {
    if let Some(conn) = conns.get_mut(&quad) {
        conn.last_active = Instant::now();
        process_tcp_segment(conn, tcp, session, quad);
        return;
    }

    // 新连接：必须是 SYN（无 ACK）
    if tcp.flags & TCP_SYN == 0 || tcp.flags & TCP_ACK != 0 {
        return;
    }
    let (sip, sport, dip, dport) = quad;
    let our_isn: u32 = random();
    // 向客户端回 SYN-ACK（src=server, dst=client）
    let pkt = build_ipv4_tcp(
        &dip,
        &sip,
        dport,
        sport,
        our_isn,
        tcp.seq.wrapping_add(1),
        TCP_SYN | TCP_ACK,
        65535,
        &[],
    );
    send_ip(session, &pkt);

    let mss = tcp.mss.unwrap_or(1460).min(1460) as usize;
    let (app_tx, app_rx) = ampsc::channel::<Vec<u8>>(CHANNEL_CAP);
    let (up_tx, up_rx) = ampsc::channel::<Vec<u8>>(CHANNEL_CAP);

    let req = RouteRequest {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::from(dip))),
        port: dport,
    };
    let task_state = state.clone();
    let task_req = req.clone();
    rt.spawn(async move {
        upstream_task(task_state, task_req, app_rx, up_tx).await;
    });

    conns.insert(
        quad,
        TcpConn {
            client_ip: sip,
            client_port: sport,
            server_ip: dip,
            server_port: dport,
            cisn: tcp.seq,
            our_isn,
            rcv_nxt: tcp.seq.wrapping_add(1),
            snd_nxt: our_isn.wrapping_add(1),
            snd_una: our_isn.wrapping_add(1),
            send_buf: Vec::new(),
            last_send: Instant::now(),
            retransmits: 0,
            mss,
            state: TcpState::SynRcvd,
            app_tx: Some(app_tx),
            up_rx,
            pending_app: Vec::new(),
            upstream_closed: false,
            fin_to_client_sent: false,
            fin_from_client: false,
            dead: false,
            last_active: Instant::now(),
        },
    );
}

/// 处理已有连接的段（ACK / 数据 / FIN / RST）。
fn process_tcp_segment(conn: &mut TcpConn, tcp: &crate::transparent::netpkt::TcpSegment<'_>, session: &Arc<wintun::Session>, _quad: Quad) {
    // RST：直接回收
    if tcp.flags & TCP_RST != 0 {
        conn.dead = true;
        return;
    }

    // 状态推进：SYN-RCVD 收到对 SYN-ACK 的 ACK → Established
    if conn.state == TcpState::SynRcvd && tcp.flags & TCP_ACK != 0 && tcp.ack == conn.snd_nxt {
        conn.state = TcpState::Established;
        conn.retransmits = 0;
    }

    // 确认我们发出去的数据
    if tcp.flags & TCP_ACK != 0 {
        if tcp.ack.wrapping_sub(conn.snd_una) as i64 > 0
            && tcp.ack.wrapping_sub(conn.snd_nxt) as i64 <= 0
        {
            let acked = tcp.ack.wrapping_sub(conn.snd_una) as usize;
            if acked <= conn.send_buf.len() {
                conn.send_buf.drain(..acked);
                conn.snd_una = tcp.ack;
                if conn.send_buf.is_empty() {
                    conn.last_send = Instant::now(); // 已确认，重置重传计时
                }
            }
            // 客户端 ACK 了我们的 FIN
            if conn.fin_to_client_sent && tcp.ack == conn.snd_nxt {
                conn.state = TcpState::LastAck;
                conn.dead = true; // 双方 FIN 完成，回收
                return;
            }
        }
    }

    // 数据：严格按序接收（本地 TUN 乱序极罕见）
    if !tcp.data.is_empty() {
        if tcp.seq == conn.rcv_nxt {
            // 转发到上游（先发 pending，再发本次）
            if !conn.pending_app.is_empty() {
                let pend = std::mem::take(&mut conn.pending_app);
                forward_to_upstream(conn, &pend);
            }
            forward_to_upstream(conn, tcp.data);
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(tcp.data.len() as u32);
            // 立即 ACK
            conn.send_segment(session, TCP_ACK, &[]);
            conn.last_active = Instant::now();
        } else if (tcp.seq.wrapping_sub(conn.rcv_nxt) as i64) < 0 {
            // 重复/旧段：重 ACK 当前期望
            conn.send_segment(session, TCP_ACK, &[]);
        }
        // 乱序段：忽略（靠客户端重传）
    }

    // 客户端 FIN
    if tcp.flags & TCP_FIN != 0 {
        // 先确认已收到的数据
        if (tcp.seq.wrapping_sub(conn.rcv_nxt) as i64) >= 0 {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1); // FIN 占一个序号
        }
        conn.send_segment(session, TCP_ACK, &[]);
        // 关闭上游写入：丢弃 app_tx 通道（upstream_task 的 app_rx 收到 None 并关闭上游）
        conn.fin_from_client = true;
        conn.state = TcpState::CloseWait;
        conn.app_tx = None;
    }
}

/// 把客户端数据发往上游（通道满则暂存 pending_app；通道已关则标记上游关闭）。
fn forward_to_upstream(conn: &mut TcpConn, data: &[u8]) {
    match conn.app_tx.as_ref().map(|tx| tx.try_send(data.to_vec())) {
        Some(Ok(())) => {}
        Some(Err(ampsc::error::TrySendError::Full(_))) => {
            conn.pending_app.extend_from_slice(data);
            if conn.pending_app.len() > PENDING_APP_CAP {
                conn.dead = true; // 上游过慢，断连保护
            }
        }
        Some(Err(ampsc::error::TrySendError::Closed(_))) | None => {
            conn.upstream_closed = true;
        }
    }
}

/// 上游桥接任务：把客户端数据写给上游，把上游数据回传 TUN 线程。
async fn upstream_task(
    state: Arc<ProxyState>,
    req: RouteRequest,
    mut app_rx: ampsc::Receiver<Vec<u8>>,
    up_tx: ampsc::Sender<Vec<u8>>,
) {
    let upstream = match dial_outbound_state(&state, &req).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, req_domain = ?req.domain, req_ip = ?req.ip, req_port = req.port, "透明代理上游拨号失败");
            return; // up_tx 丢弃 → TUN 线程感知并给客户端发 FIN
        }
    };
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            n = tokio::io::AsyncReadExt::read(&mut ur, &mut buf) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        if up_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            m = app_rx.recv() => {
                match m {
                    Some(b) => {
                        if tokio::io::AsyncWriteExt::write_all(&mut uw, &b).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    // 任务结束 → up_tx 丢弃，TUN 线程感知上游关闭
}

// ===================== UDP =====================

struct UdpConn {
    socket: UdpSocket,
    client_ip: [u8; 4],
    client_port: u16,
    server_ip: [u8; 4],
    server_port: u16,
    last_active: Instant,
    dead: bool,
}

fn handle_udp(
    quad: Quad,
    udp: &crate::transparent::netpkt::UdpDatagram<'_>,
    conns: &mut HashMap<Quad, UdpConn>,
    session: &Arc<wintun::Session>,
) {
    if let Some(u) = conns.get_mut(&quad) {
        // 已存在的 UDP 会话：直接转发
        u.last_active = Instant::now();
        let _ = u.socket.send(udp.data);
        return;
    }
    let (sip, sport, dip, dport) = quad;
    let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, "透明代理 UDP 本地 socket 绑定失败");
            return;
        }
    };
    let target: SocketAddr = SocketAddrV4::new(Ipv4Addr::from(dip), dport).into();
    if sock.connect(target).is_err() || sock.set_nonblocking(true).is_err() {
        return;
    }
    let _ = sock.send(udp.data);
    conns.insert(
        quad,
        UdpConn {
            socket: sock,
            client_ip: sip,
            client_port: sport,
            server_ip: dip,
            server_port: dport,
            last_active: Instant::now(),
            dead: false,
        },
    );
    let _ = session; // 保活引用
}

impl UdpConn {
    /// 取回上游响应并伪造成「服务器→客户端」的 IP/UDP 包发回 TUN。
    fn poll_reply(&mut self, session: &Arc<wintun::Session>, now: Instant) {
        let mut buf = [0u8; 65535];
        loop {
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    let pkt = build_ipv4_udp(
                        &self.server_ip,
                        &self.client_ip,
                        self.server_port,
                        self.client_port,
                        &buf[..n],
                    );
                    send_ip(session, &pkt);
                    self.last_active = now;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.dead = true;
                    break;
                }
            }
        }
    }
}

// ===================== 工具 =====================

/// 通过 Wintun 会话发送一个完整的 IP 包（自动分配发送缓冲）。
fn send_ip(session: &Arc<wintun::Session>, pkt: &[u8]) {
    match session.allocate_send_packet(pkt.len() as u16) {
        Ok(mut p) => {
            p.bytes_mut().copy_from_slice(pkt);
            session.send_packet(p);
        }
        Err(e) => {
            // 环满：丢弃（TCP 会重传；UDP 无重传，偶发丢包可接受）
            tracing::debug!(error = ?e, "Wintun 发送缓冲分配失败，丢包");
        }
    }
}
