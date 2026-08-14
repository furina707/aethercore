//! 转发核心：建立出站连接、TLS 包装、双向数据拷贝。共享于所有协议。
use crate::config::{Config, Outbound};
use crate::observe::Stats;
use crate::route::{RouteRequest, select_outbound};
use crate::state::ProxyState;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 默认空闲超时（秒）：双向 pipe 在此时间内无任何数据流动则关闭连接，
/// 避免僵死连接长期占用资源。可由 `observability.idle_timeout_secs` 覆盖。
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// 慢出站连接阈值：单次连接尝试（含协议握手）超过此时长则额外打印 warn 告警，
/// 便于在网络抖动或上游响应缓慢时快速定位。默认 1000ms，可按需调整。
pub const SLOW_DIAL_THRESHOLD: Duration = Duration::from_millis(1000);

/// 暴露默认空闲超时秒数，供 ProxyState 等模块引用。
pub fn default_idle_timeout_secs() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

/// 根据路由决策解析目标地址（域名或 IP）。
/// 使用 tokio::net::lookup_host 异步解析，避免阻塞 Tokio 运行时线程。
async fn resolve_target(addr: &str) -> Result<std::net::SocketAddr> {
    match tokio::net::lookup_host(addr).await {
        Ok(mut iter) => iter.next().context("DNS 返回空结果"),
        Err(e) => anyhow::bail!("无法解析目标地址: {} ({})", addr, e),
    }
}

/// 取出站链路的超时配置：优先 outbound.timeout_secs，否则 10s 兜底。
fn outbound_timeout(ob: &Outbound) -> Duration {
    Duration::from_secs(ob.timeout_secs.max(1))
}

/// 取出站链路的重试次数：retries 表示 *额外* 重试次数，总尝试 = retries + 1。
fn outbound_attempts(ob: &Outbound) -> u32 {
    ob.retries.saturating_add(1)
}

/// 按选定 outbound 建立到目标的连接，并对每次尝试施加超时；
/// 失败时按 `retries` 重试，每次重试之间做线性退避（500ms / 1s / 1.5s ...）。
async fn connect_via(cfg: &Config, ob_name: &str, req: &RouteRequest) -> Result<TcpStream> {
    let ob = cfg
        .outbounds
        .iter()
        .find(|o| o.name == ob_name)
        .context("出站链路未找到")?;

    let attempts = outbound_attempts(ob);
    let per_attempt_timeout = outbound_timeout(ob);
    tracing::info!(
        outbound = %ob.name,
        protocol = ?ob.protocol,
        target = %ob.target,
        req_domain = ?req.domain,
        req_ip = ?req.ip,
        req_port = req.port,
        attempts,
        timeout_secs = per_attempt_timeout.as_secs(),
        "开始建立出站连接"
    );
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..attempts {
        if attempt > 0 {
            // 线性退避：500ms * attempt
            let backoff = Duration::from_millis(500 * attempt as u64);
            tracing::info!(outbound = %ob.name, attempt, backoff_ms = backoff.as_millis(), "出站重试前退避");
            tokio::time::sleep(backoff).await;
        }
        let started = std::time::Instant::now();
        match timeout(per_attempt_timeout, connect_once(ob, req)).await {
            Ok(Ok(stream)) => {
                let elapsed = started.elapsed();
                tracing::info!(
                    outbound = %ob.name,
                    attempt,
                    attempts_total = attempts,
                    attempts_used = attempt + 1,
                    final_status = "succeeded",
                    elapsed_ms = elapsed.as_millis(),
                    "出站连接建立成功"
                );
                if elapsed > SLOW_DIAL_THRESHOLD {
                    tracing::warn!(
                        outbound = %ob.name,
                        protocol = ?ob.protocol,
                        target = %ob.target,
                        attempt,
                        elapsed_ms = elapsed.as_millis(),
                        threshold_ms = SLOW_DIAL_THRESHOLD.as_millis(),
                        "出站连接耗时超过慢阈值，可能存在网络抖动或上游响应缓慢"
                    );
                }
                return Ok(stream);
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    outbound = %ob.name,
                    attempt,
                    attempts_total = attempts,
                    remaining_retries = attempts.saturating_sub(attempt + 1),
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %e,
                    "出站连接失败"
                );
                last_err = Some(e);
            }
            Err(_) => {
                tracing::warn!(
                    outbound = %ob.name,
                    attempt,
                    attempts_total = attempts,
                    remaining_retries = attempts.saturating_sub(attempt + 1),
                    timeout_secs = per_attempt_timeout.as_secs(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "出站连接超时"
                );
                last_err = Some(anyhow::anyhow!(
                    "连接超时（{}s）",
                    per_attempt_timeout.as_secs()
                ));
            }
        }
    }
    tracing::error!(
        outbound = %ob.name,
        attempts_total = attempts,
        retries_used = attempts.saturating_sub(1),
        final_status = "failed",
        last_error = ?last_err,
        "出站连接全部失败，已用尽重试次数"
    );
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("出站连接失败：未知原因")))
}

/// 单次出站连接尝试（无重试、无超时，由 connect_via 包装）。
/// 按协议分支记录各阶段耗时（resolve / tcp_connect / handshake），便于定位慢点。
async fn connect_once(ob: &Outbound, req: &RouteRequest) -> Result<TcpStream> {
    let total = std::time::Instant::now();
    match ob.protocol {
        crate::config::OutboundProtocol::Direct => {
            // 注意：to_socket_addrs() 要求 "host:port" 格式，裸域名会瞬间失败。
            // 因此无论来源是 IP 还是域名，都必须拼接端口。
            let host = if let Some(ip) = req.ip {
                ip.to_string()
            } else {
                req.domain.clone().unwrap_or_else(|| ob.target.clone())
            };
            let target = format!("{}:{}", host, req.port);
            let resolve_started = std::time::Instant::now();
            let sa = resolve_target(&target).await?;
            let resolve_ms = resolve_started.elapsed().as_millis();

            let connect_started = std::time::Instant::now();
            let stream = TcpStream::connect(sa)
                .await
                .with_context(|| format!("直连失败: {}", target))?;
            tracing::info!(
                protocol = "direct",
                target = %target,
                resolve_ms,
                connect_ms = connect_started.elapsed().as_millis(),
                total_ms = total.elapsed().as_millis(),
                "Direct 出站连接建立完成"
            );
            Ok(stream)
        }
        crate::config::OutboundProtocol::Socks5 => {
            let connect_started = std::time::Instant::now();
            let mut stream = TcpStream::connect(&ob.target)
                .await
                .with_context(|| format!("连接上游 SOCKS5 失败: {}", ob.target))?;
            let tcp_connect_ms = connect_started.elapsed().as_millis();

            let target_host = req
                .domain
                .clone()
                .or_else(|| req.ip.map(|ip| ip.to_string()))
                .unwrap_or_else(|| ob.target.clone());
            let hs_started = std::time::Instant::now();
            crate::socks::socks5_handshake_client(&mut stream, &target_host, req.port).await?;
            tracing::info!(
                protocol = "socks5",
                upstream = %ob.target,
                target = %target_host,
                port = req.port,
                tcp_connect_ms,
                handshake_ms = hs_started.elapsed().as_millis(),
                total_ms = total.elapsed().as_millis(),
                "SOCKS5 出站连接建立完成"
            );
            Ok(stream)
        }
        crate::config::OutboundProtocol::HttpProxy => {
            let connect_started = std::time::Instant::now();
            let mut stream = TcpStream::connect(&ob.target)
                .await
                .with_context(|| format!("连接上游 HTTP 代理失败: {}", ob.target))?;
            let tcp_connect_ms = connect_started.elapsed().as_millis();

            let target_host = req
                .domain
                .clone()
                .or_else(|| req.ip.map(|ip| ip.to_string()))
                .unwrap_or_else(|| ob.target.clone());
            let tunnel_started = std::time::Instant::now();
            crate::http::http_connect_tunnel(&mut stream, &target_host, req.port).await?;
            tracing::info!(
                protocol = "http_proxy",
                upstream = %ob.target,
                target = %target_host,
                port = req.port,
                tcp_connect_ms,
                tunnel_ms = tunnel_started.elapsed().as_millis(),
                total_ms = total.elapsed().as_millis(),
                "HTTP 代理出站连接建立完成"
            );
            Ok(stream)
        }
        crate::config::OutboundProtocol::Shadowsocks => {
            // TODO: 实现 Shadowsocks 协议栈
            tracing::warn!("Shadowsocks 出站链路暂未实现，回退到直连");
            let host = if let Some(ip) = req.ip {
                ip.to_string()
            } else {
                req.domain.clone().unwrap_or_else(|| ob.target.clone())
            };
            let target = format!("{}:{}", host, req.port);
            let resolve_started = std::time::Instant::now();
            let sa = resolve_target(&target).await?;
            let resolve_ms = resolve_started.elapsed().as_millis();
            let connect_started = std::time::Instant::now();
            let stream = TcpStream::connect(sa)
                .await
                .with_context(|| format!("Shadowsocks 回退直连失败: {}", target))?;
            tracing::info!(
                protocol = "shadowsocks(fallback)",
                target = %target,
                resolve_ms,
                connect_ms = connect_started.elapsed().as_millis(),
                total_ms = total.elapsed().as_millis(),
                "Shadowsocks 回退直连完成"
            );
            Ok(stream)
        }
        crate::config::OutboundProtocol::Vmess => {
            // TODO: 实现 Vmess 协议栈
            tracing::warn!("Vmess 出站链路暂未实现，回退到直连");
            let host = if let Some(ip) = req.ip {
                ip.to_string()
            } else {
                req.domain.clone().unwrap_or_else(|| ob.target.clone())
            };
            let target = format!("{}:{}", host, req.port);
            let resolve_started = std::time::Instant::now();
            let sa = resolve_target(&target).await?;
            let resolve_ms = resolve_started.elapsed().as_millis();
            let connect_started = std::time::Instant::now();
            let stream = TcpStream::connect(sa)
                .await
                .with_context(|| format!("Vmess 回退直连失败: {}", target))?;
            tracing::info!(
                protocol = "vmess(fallback)",
                target = %target,
                resolve_ms,
                connect_ms = connect_started.elapsed().as_millis(),
                total_ms = total.elapsed().as_millis(),
                "Vmess 回退直连完成"
            );
            Ok(stream)
        }
    }
}

/// 无状态版本：直接按路由规则选择出站（不做健康故障转移）。
pub async fn dial_outbound(cfg: &Config, req: &RouteRequest) -> Result<TcpStream> {
    let ob_name = select_outbound(cfg, req);
    connect_via(cfg, &ob_name, req).await
}

/// 带运行时状态的版本：经 ProxyState 选择出站（含健康故障转移），并复用其配置。
pub async fn dial_outbound_state(state: &Arc<ProxyState>, req: &RouteRequest) -> Result<TcpStream> {
    let (stream, _name) = dial_outbound_tracked(state, req).await?;
    Ok(stream)
}

/// 与 dial_outbound_state 相同，但额外返回选中的 outbound name，
/// 供调用方按 outbound 累计统计。
pub async fn dial_outbound_tracked(
    state: &Arc<ProxyState>,
    req: &RouteRequest,
) -> Result<(TcpStream, String)> {
    let ob_name = state.select_outbound(req).await;
    tracing::info!(
        selected_outbound = %ob_name,
        req_domain = ?req.domain,
        req_ip = ?req.ip,
        req_port = req.port,
        "路由决策：已选择出站链路"
    );
    let cfg = state.config();
    let stream = connect_via(&cfg, &ob_name, req).await?;
    Ok((stream, ob_name))
}

/// 建立出站连接，并按需用 TLS 包装（返回装箱的读写流）。
pub async fn dial_outbound_tls(
    cfg: &Config,
    req: &RouteRequest,
) -> Result<Box<dyn Tunnel>> {
    let ob_name = select_outbound(cfg, req);
    let ob = cfg
        .outbounds
        .iter()
        .find(|o| o.name == ob_name)
        .context("出站链路未找到")?;

    let stream = dial_outbound(cfg, req).await?;
    if ob.tls {
        let sni = ob.sni.clone().unwrap_or_else(|| {
            req.domain
                .clone()
                .unwrap_or_else(|| req.ip.map(|ip| ip.to_string()).unwrap_or_default())
        });
        let client_cfg = crate::tls::build_client_config(&sni)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let server_name = rustls::pki_types::ServerName::try_from(sni.as_str())?.to_owned();
        let tls_stream = connector.connect(server_name, stream).await?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

/// 统一的双向隧道抽象，支持裸 TCP 与 TLS。
pub trait Tunnel: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Tunnel for T {}

/// 在两个隧道/流之间双向拷贝，并记录统计。
/// 使用默认空闲超时（300s）。若需要自定义，使用 `pipe_with_idle_timeout`。
pub async fn pipe<A, B>(a: A, b: B, stats: &Stats) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    pipe_with_idle_timeout(a, b, stats, Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)).await
}

/// 带空闲超时的双向拷贝：在 `idle_timeout` 时间内任一方向无数据流动则关闭连接。
/// 这避免了僵死连接（对端不响应也不关闭）长期占用资源。
pub async fn pipe_with_idle_timeout<A, B>(
    a: A,
    b: B,
    stats: &Stats,
    idle_timeout: Duration,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    stats.record_conn_start();
    // 用 tokio::select! 同时监视双向拷贝与空闲超时。copy_bidirectional
    // 在内部会循环，因此我们通过定时器+通道模式中断：当定时器先触发则提前返回。
    let result = run_pipe_with_idle(a, b, idle_timeout).await;
    match result {
        Ok((inb, outb)) => {
            stats.record_bytes(inb, outb);
            stats.record_conn_end();
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            stats.record_conn_end();
            Err(e)
        }
    }
}

/// 与 pipe_with_idle_timeout 相同，但额外按 outbound name 累计 per-outbound 统计。
/// `bytes_ab` = a→b（客户端→上游 = 上传），`bytes_ba` = b→a（上游→客户端 = 下载）。
pub async fn pipe_tracked<A, B>(
    a: A,
    b: B,
    stats: &Stats,
    idle_timeout: Duration,
    outbound: &str,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();
    stats.record_conn_start();
    stats.outbound_conn_start(outbound);
    tracing::info!(outbound = %outbound, idle_secs = idle_timeout.as_secs(), "pipe 双向转发开始");
    let result = run_pipe_with_idle(a, b, idle_timeout).await;
    let elapsed = started.elapsed();
    match result {
        Ok((ab, ba)) => {
            stats.record_bytes(ab, ba);
            stats.outbound_bytes(outbound, ab, ba);
            stats.record_conn_end();
            stats.outbound_conn_end(outbound);
            tracing::info!(
                outbound = %outbound,
                bytes_up = ab,
                bytes_down = ba,
                elapsed_ms = elapsed.as_millis(),
                "pipe 正常结束"
            );
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            stats.outbound_error(outbound);
            stats.record_conn_end();
            stats.outbound_conn_end(outbound);
            tracing::warn!(
                outbound = %outbound,
                elapsed_ms = elapsed.as_millis(),
                error = ?e,
                "pipe 异常结束"
            );
            Err(e)
        }
    }
}

/// 内部：手动双向拷贝，每次 select 同时等待 a/b 的读事件与空闲超时。
/// 任一方向有数据流动即重置空闲计时器；若 idle_timeout 内两侧均无数据则关闭。
async fn run_pipe_with_idle<A, B>(
    a: A,
    b: B,
    idle_timeout: Duration,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut a = a;
    let mut b = b;
    let mut bytes_ab: u64 = 0; // a -> b（原 copy_bidirectional 第一返回值）
    let mut bytes_ba: u64 = 0; // b -> a（原 copy_bidirectional 第二返回值）
    let mut buf_a = vec![0u8; 16 * 1024];
    let mut buf_b = vec![0u8; 16 * 1024];

    loop {
        tokio::select! {
            // 从 a 读，向 b 写
            n = a.read(&mut buf_a) => {
                match n {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        bytes_ab += n as u64;
                        b.write_all(&buf_a[..n]).await?;
                    }
                    Err(e) => return Err(anyhow::Error::from(e)),
                }
            }
            // 从 b 读，向 a 写
            n = b.read(&mut buf_b) => {
                match n {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        bytes_ba += n as u64;
                        a.write_all(&buf_b[..n]).await?;
                    }
                    Err(e) => return Err(anyhow::Error::from(e)),
                }
            }
            // 空闲超时：本轮 select 重置计时器，因此仅当两侧均无数据时触发
            _ = tokio::time::sleep(idle_timeout) => {
                tracing::debug!(?idle_timeout, "连接空闲超时，关闭");
                return Ok((bytes_ab, bytes_ba));
            }
        }
    }
    Ok((bytes_ab, bytes_ba))
}