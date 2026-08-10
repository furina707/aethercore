//! 服务编排：根据配置启动各类监听器（TCP/HTTP/SOCKS/DNS/UDP 透明）。
use crate::config::{Config, ListenerProtocol};
use crate::observe::{Stats, init_logging, spawn_stats_reporter};
use crate::relay::{dial_outbound_state, pipe};
use crate::route::RouteRequest;
use crate::state::ProxyState;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// 加载配置并启动全部监听器。
pub async fn run(config_path: &str) -> Result<()> {
    let cfg = Config::load(Path::new(config_path))?;
    init_logging(&cfg.observability);
    let stats = Stats::new();
    spawn_stats_reporter(&cfg.observability, stats.clone());

    // 运行时共享状态（配置可热重载、含健康状态）
    let state = ProxyState::new(cfg);
    spawn_hot_reload(state.clone(), PathBuf::from(config_path));
    spawn_health_check(state.clone());

    // 透明代理：Windows 三种方案（PAC / WFP / Wintun）按配置启动
    {
        let cfg = state.config();
        if let Some(t) = &cfg.transparent {
            if let Err(e) = crate::transparent::run_transparent(t, state.clone()).await {
                tracing::error!("透明代理启动失败: {:?}", e);
            }
        }
    }

    // 预构建 TLS 服务端配置（基于当前配置）
    let tls_acceptor = {
        let cfg = state.config();
        if let Some(t) = &cfg.tls {
            let sc = crate::tls::build_server_config(&t.cert, &t.key, t.client_ca.as_deref())?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        } else {
            None
        }
    };

    let mut handles = Vec::new();
    let listeners = state.config().server.listeners.clone();
    for listener in &listeners {
        let state = state.clone();
        let stats = stats.clone();
        let tls = tls_acceptor.clone();
        let bind = listener.bind.clone();
        let proto = listener.protocol;
        let use_tls = listener.tls;

        let bind_info = bind.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = start_listener(proto, &bind, use_tls, tls, state, stats).await {
                tracing::error!("监听器 {:?} {} 异常: {:?}", proto, bind, e);
            }
        });
        handles.push(handle);
        tracing::info!("已启动 {:?} 监听器: {}", proto, bind_info);
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

/// 启动配置热重载后台任务。
fn spawn_hot_reload(state: Arc<ProxyState>, path: PathBuf) {
    tokio::spawn(async move {
        let cfg = state.config();
        let interval = match cfg.hot_reload_secs {
            Some(s) if s > 0 => s,
            _ => return, // 未启用
        };
        let mut last_mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
            if mtime == last_mtime {
                continue;
            }
            last_mtime = mtime;
            match Config::load(&path) {
                Ok(new_cfg) => {
                    state.reload(new_cfg);
                    tracing::info!("配置已热重载: {:?}", path);
                }
                Err(e) => tracing::warn!("配置热重载失败（保留旧配置）: {:?}", e),
            }
        }
    });
}

/// 启动健康探测后台任务。
fn spawn_health_check(state: Arc<ProxyState>) {
    tokio::spawn(async move {
        state.run_health_check().await;
    });
}

async fn start_listener(
    proto: ListenerProtocol,
    bind: &str,
    use_tls: bool,
    tls: Option<Arc<TlsAcceptor>>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    match proto {
        ListenerProtocol::Tcp => run_tcp_transparent(bind, state, stats).await,
        ListenerProtocol::Udp => run_udp_transparent(bind, state, stats).await,
        ListenerProtocol::Http | ListenerProtocol::Https => {
            run_http(bind, use_tls, tls, state, stats).await
        }
        ListenerProtocol::Socks => run_socks(bind, use_tls, tls, state, stats).await,
        ListenerProtocol::Dns => {
            let cfg = state.config();
            crate::dns::run_dns(&cfg, bind, stats).await
        }
    }
}

/// TCP 透明转发：以入站连接的初始目标作为路由依据（此处由对端告知目标，
/// 实际透明模式需要 NF/IPTABLES 配合；这里以直连对等形式处理）。
async fn run_tcp_transparent(bind: &str, state: Arc<ProxyState>, stats: Arc<Stats>) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    loop {
        let (mut client, _) = listener.accept().await?;
        let state = state.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let req = RouteRequest::default();
            if let Ok(upstream) = dial_outbound_state(&state, &req).await {
                if let Err(e) = pipe(&mut client, upstream, &stats).await {
                    tracing::debug!("TCP 转发结束: {:?}", e);
                }
            } else {
                stats.record_error();
            }
        });
    }
}

/// UDP 透明转发：简单回显式转发到默认出站。
async fn run_udp_transparent(bind: &str, state: Arc<ProxyState>, stats: Arc<Stats>) -> Result<()> {
    use std::sync::Arc as StdArc;
    use tokio::net::UdpSocket;
    let socket = UdpSocket::bind(bind).await?;
    let socket = StdArc::new(socket);
    tracing::info!("UDP 透明监听: {}", bind);
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..len].to_vec();
        let state = state.clone();
        let stats = stats.clone();
        let sock = socket.clone();
        tokio::spawn(async move {
            let req = RouteRequest::default();
            if let Ok(mut upstream) = dial_outbound_state(&state, &req).await {
                use tokio::io::AsyncWriteExt;
                if upstream.write_all(&pkt).await.is_ok() {
                    let mut resp = vec![0u8; 65535];
                    if let Ok(n) = tokio::io::AsyncReadExt::read(&mut upstream, &mut resp).await {
                        resp.truncate(n);
                        let _ = sock.send_to(&resp, peer).await;
                    }
                }
            } else {
                stats.record_error();
            }
        });
    }
}

/// HTTP/HTTPS 代理监听器。
async fn run_http(
    bind: &str,
    use_tls: bool,
    tls: Option<Arc<TlsAcceptor>>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let tls = if use_tls { tls } else { None };
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let stats = stats.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            match handle_http_conn(stream, tls, state, stats).await {
                Ok(()) => {}
                Err(e) => tracing::debug!("HTTP 连接结束: {:?}", e),
            }
        });
    }
}

async fn handle_http_conn(
    stream: tokio::net::TcpStream,
    tls: Option<Arc<TlsAcceptor>>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut client: Box<dyn crate::relay::Tunnel> = if let Some(tls) = tls {
        let tls_stream = tls.accept(stream).await?;
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    let (method, host, port) = crate::http::http_parse_request(&mut client).await?;
    if method.eq_ignore_ascii_case("CONNECT") {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    } else {
        client
            .write_all(b"HTTP/1.1 405 Method Not Supported\r\n\r\n")
            .await?;
        return Ok(());
    }

    let req = RouteRequest {
        domain: Some(host.clone()),
        ip: host.parse().ok(),
        port,
    };
    let upstream = dial_outbound_state(&state, &req).await?;
    pipe(client, upstream, &stats).await?;
    Ok(())
}

/// SOCKS 代理监听器（支持 SOCKS4/4a/5，可选 TLS 包装）。
async fn run_socks(
    bind: &str,
    use_tls: bool,
    tls: Option<Arc<TlsAcceptor>>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let tls = if use_tls { tls } else { None };
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let stats = stats.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_conn(stream, tls, state, stats).await {
                tracing::debug!("SOCKS 连接结束: {:?}", e);
            }
        });
    }
}

async fn handle_socks_conn(
    stream: tokio::net::TcpStream,
    tls: Option<Arc<TlsAcceptor>>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut client: Box<dyn crate::relay::Tunnel> = if let Some(tls) = tls {
        Box::new(tls.accept(stream).await?)
    } else {
        Box::new(stream)
    };
    let (host, port) = crate::socks::socks_handshake_server(&mut client).await?;
    let req = RouteRequest {
        domain: Some(host.clone()),
        ip: host.parse().ok(),
        port,
    };
    let upstream = dial_outbound_state(&state, &req).await?;
    pipe(client, upstream, &stats).await?;
    Ok(())
}
