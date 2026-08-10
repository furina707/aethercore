//! 转发核心：建立出站连接、TLS 包装、双向数据拷贝。共享于所有协议。
use crate::config::Config;
use crate::observe::Stats;
use crate::route::{RouteRequest, select_outbound};
use crate::state::ProxyState;
use anyhow::{Context, Result};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// 根据路由决策解析目标地址（域名或 IP）。
fn resolve_target(addr: &str) -> Result<std::net::SocketAddr> {
    if let Ok(sa) = addr.to_socket_addrs() {
        if let Some(s) = sa.into_iter().next() {
            return Ok(s);
        }
    }
    anyhow::bail!("无法解析目标地址: {}", addr)
}

/// 实际按选定 outbound 建立到目标的连接。
async fn connect_via(cfg: &Config, ob_name: &str, req: &RouteRequest) -> Result<TcpStream> {
    let ob = cfg
        .outbounds
        .iter()
        .find(|o| o.name == ob_name)
        .context("出站链路未找到")?;

    match ob.protocol {
        crate::config::OutboundProtocol::Direct => {
            let target = if let Some(ip) = req.ip {
                format!("{}:{}", ip, req.port)
            } else {
                req.domain
                    .clone()
                    .map(|d| format!("{}:{}", d, req.port))
                    .unwrap_or_else(|| ob.target.clone())
            };
            let sa = resolve_target(&target)?;
            TcpStream::connect(sa)
                .await
                .with_context(|| format!("直连失败: {}", target))
        }
        crate::config::OutboundProtocol::Socks5 => {
            let mut stream = TcpStream::connect(&ob.target)
                .await
                .with_context(|| format!("连接上游 SOCKS5 失败: {}", ob.target))?;
            let target_host = req
                .domain
                .clone()
                .or_else(|| req.ip.map(|ip| ip.to_string()))
                .unwrap_or_else(|| ob.target.clone());
            crate::socks::socks5_handshake_client(&mut stream, &target_host, req.port).await?;
            Ok(stream)
        }
        crate::config::OutboundProtocol::HttpProxy => {
            let mut stream = TcpStream::connect(&ob.target)
                .await
                .with_context(|| format!("连接上游 HTTP 代理失败: {}", ob.target))?;
            let target_host = req
                .domain
                .clone()
                .or_else(|| req.ip.map(|ip| ip.to_string()))
                .unwrap_or_else(|| ob.target.clone());
            crate::http::http_connect_tunnel(&mut stream, &target_host, req.port).await?;
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
    let ob_name = state.select_outbound(req).await;
    let cfg = state.config();
    connect_via(&cfg, &ob_name, req).await
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
pub async fn pipe<A, B>(a: A, b: B, stats: &Stats) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    stats.record_conn_start();
    match copy_bidirectional(&mut { a }, &mut { b }).await {
        Ok((inb, outb)) => {
            stats.record_bytes(inb, outb);
            stats.record_conn_end();
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            stats.record_conn_end();
            Err(e.into())
        }
    }
}
