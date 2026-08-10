//! DNS 代理转发：接收 UDP DNS 查询，转发到上游解析器，回传响应。
use crate::config::Config;
use crate::observe::Stats;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// 启动 DNS 代理监听器。
pub async fn run_dns(cfg: &Config, bind: &str, stats: Arc<Stats>) -> Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    let socket = Arc::new(socket);
    tracing::info!("DNS 代理监听: {}", bind);
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..len].to_vec();
        let upstream = pick_upstream(cfg);
        let stats = stats.clone();
        let sock = socket.clone();
        tokio::spawn(async move {
            match forward(&upstream, &pkt).await {
                Ok(resp) => {
                    let _ = sock.send_to(&resp, peer).await;
                    stats.record_bytes(pkt.len() as u64, resp.len() as u64);
                }
                Err(e) => {
                    tracing::warn!("DNS 转发失败: {:?}", e);
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
        .map(|o| o.target.clone())
        .unwrap_or_else(|| "8.8.8.8:53".into())
}

async fn forward(upstream: &str, pkt: &[u8]) -> Result<Vec<u8>> {
    let client = UdpSocket::bind("0.0.0.0:0").await?;
    client.send_to(pkt, upstream).await?;
    let mut resp = vec![0u8; 65535];
    let (n, _) = client.recv_from(&mut resp).await?;
    resp.truncate(n);
    Ok(resp)
}
