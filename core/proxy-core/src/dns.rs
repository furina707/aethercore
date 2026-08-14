//! DNS 代理转发：接收 UDP DNS 查询，转发到上游解析器，回传响应。
use crate::config::Config;
use crate::observe::Stats;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// 慢 DNS 转发阈值：单次查询往返超过此时长则额外打印 warn 告警。
/// DNS 通常在百毫秒内完成，超过 500ms 视为上游解析器响应缓慢。
const SLOW_DNS_THRESHOLD: Duration = Duration::from_millis(500);

/// 启动 DNS 代理监听器。
pub async fn run_dns(cfg: &Config, bind: &str, stats: Arc<Stats>) -> Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    let socket = Arc::new(socket);
    let upstream = pick_upstream(cfg);
    tracing::info!(
        bind = %bind,
        upstream = %upstream,
        "DNS 代理监听器就绪，等待查询"
    );
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        tracing::info!(peer = %peer, len, upstream = %upstream, "收到 DNS 查询");
        let pkt = buf[..len].to_vec();
        let upstream = upstream.clone();
        let stats = stats.clone();
        let sock = socket.clone();
        tokio::spawn(async move {
            match forward(&upstream, &pkt).await {
                Ok(resp) => {
                    let _ = sock.send_to(&resp, peer).await;
                    stats.record_bytes(pkt.len() as u64, resp.len() as u64);
                    tracing::info!(peer = %peer, q_len = pkt.len(), r_len = resp.len(), "DNS 响应已回送");
                }
                Err(e) => {
                    tracing::warn!(peer = %peer, upstream = %upstream, error = ?e, "DNS 转发失败");
                    stats.record_error();
                }
            }
        });
    }
}

fn pick_upstream(cfg: &Config) -> String {
    // 若有名为 dns 的出站则复用其 target，否则默认公共 DNS
    cfg.outbounds
        .iter()
        .find(|o| o.name == "dns")
        .map(|o| {
            tracing::info!(upstream = %o.target, "DNS 上游：使用出站链路 'dns' 的 target");
            o.target.clone()
        })
        .unwrap_or_else(|| {
            tracing::info!(upstream = "8.8.8.8:53", "DNS 上游：未配置 'dns' 出站，使用默认 8.8.8.8:53");
            "8.8.8.8:53".into()
        })
}

async fn forward(upstream: &str, pkt: &[u8]) -> Result<Vec<u8>> {
    let started = std::time::Instant::now();
    let client = UdpSocket::bind("0.0.0.0:0").await?;
    let bind_ms = started.elapsed().as_millis();

    let send_started = std::time::Instant::now();
    client.send_to(pkt, upstream).await?;
    let send_ms = send_started.elapsed().as_millis();

    tracing::info!(
        upstream = %upstream,
        q_len = pkt.len(),
        bind_ms,
        send_ms,
        "DNS 查询已发送到上游，等待响应"
    );

    let recv_started = std::time::Instant::now();
    let mut resp = vec![0u8; 65535];
    let (n, _) = client.recv_from(&mut resp).await?;
    let recv_ms = recv_started.elapsed().as_millis();
    resp.truncate(n);

    let total = started.elapsed();
    tracing::info!(
        upstream = %upstream,
        r_len = n,
        bind_ms,
        send_ms,
        recv_ms,
        total_ms = total.as_millis(),
        "DNS 转发往返完成"
    );
    if total > SLOW_DNS_THRESHOLD {
        tracing::warn!(
            upstream = %upstream,
            recv_ms,
            total_ms = total.as_millis(),
            threshold_ms = SLOW_DNS_THRESHOLD.as_millis(),
            "DNS 转发耗时超过慢阈值，上游解析器响应缓慢"
        );
    }
    Ok(resp)
}
