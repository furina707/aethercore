//! 服务编排：根据配置启动各类监听器（TCP/HTTP/SOCKS/DNS/UDP 透明）。
use crate::config::{AuthConfig, Config, ListenerProtocol};
use crate::observe::{Stats, init_logging, spawn_stats_reporter};
use crate::relay::{dial_outbound_state, dial_outbound_tracked, pipe_tracked};
use crate::route::RouteRequest;
use crate::state::ProxyState;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// 加载配置并启动全部监听器。
/// `log_level_override`：命令行 -v/-q 提供的日志级别覆盖，优先于配置文件。
pub async fn run(config_path: &str, log_level_override: Option<&str>) -> Result<()> {
    let cfg = Config::load(Path::new(config_path))?;
    init_logging(&cfg.observability, log_level_override);
    tracing::info!(
        config = config_path,
        listeners = cfg.server.listeners.len(),
        outbounds = cfg.outbounds.len(),
        routes = cfg.routing.len(),
        hot_reload_secs = ?cfg.hot_reload_secs,
        health_check = ?cfg.health_check.is_some(),
        tls = cfg.tls.is_some(),
        "配置已加载，准备启动服务"
    );
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
            tracing::info!(
                pac = t.pac.is_some(),
                wintun = t.wintun.is_some(),
                wfp = t.wfp.is_some(),
                "透明代理配置检测到，开始启动启用的方案"
            );
            if let Err(e) = crate::transparent::run_transparent(t, state.clone()).await {
                tracing::error!(error = ?e, "透明代理启动失败");
            }
        } else {
            tracing::info!("透明代理：未配置，跳过");
        }
    }

    // 预构建 TLS 服务端配置（基于当前配置）
    let tls_acceptor = {
        let cfg = state.config();
        if let Some(t) = &cfg.tls {
            tracing::info!(
                cert = %t.cert,
                key = %t.key,
                mtls = t.client_ca.is_some(),
                "TLS 服务端配置已构建"
            );
            let sc = crate::tls::build_server_config(&t.cert, &t.key, t.client_ca.as_deref())?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        } else {
            tracing::info!("TLS：未配置，HTTPS/TLS 监听器将无法握手");
            None
        }
    };

    let mut handles = Vec::new();
    let listeners = state.config().server.listeners.clone();
    tracing::info!(count = listeners.len(), "开始启动监听器");
    for listener in &listeners {
        let state = state.clone();
        let stats = stats.clone();
        let tls = tls_acceptor.clone();
        let bind = listener.bind.clone();
        let proto = listener.protocol;
        let use_tls = listener.tls;
        let auth = listener.auth.clone();
        let auth_enabled = auth.is_some();

        let bind_info = bind.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = start_listener(proto, &bind, use_tls, tls, auth, state, stats).await {
                tracing::error!(protocol = ?proto, bind = %bind, error = ?e, "监听器异常退出");
            }
        });
        handles.push(handle);
        tracing::info!(protocol = ?proto, bind = %bind_info, tls = use_tls, auth = auth_enabled, "监听器已启动");
    }

    tracing::info!("所有监听器已启动，进入服务循环");
    for h in handles {
        let _ = h.await;
    }
    tracing::info!("所有监听器已结束，服务退出");
    Ok(())
}

/// 启动配置热重载后台任务。
fn spawn_hot_reload(state: Arc<ProxyState>, path: PathBuf) {
    tokio::spawn(async move {
        let cfg = state.config();
        let interval = match cfg.hot_reload_secs {
            Some(s) if s > 0 => s,
            _ => {
                tracing::info!(path = ?path, "热重载：未启用（hot_reload_secs 未配置或为 0）");
                return;
            }
        };
        tracing::info!(path = ?path, interval_secs = interval, "热重载后台任务已启动");
        let mut last_mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
            if mtime == last_mtime {
                continue;
            }
            tracing::info!(path = ?path, "检测到配置文件变更，开始热重载");
            last_mtime = mtime;
            match Config::load(&path) {
                Ok(new_cfg) => {
                    state.reload(new_cfg);
                    tracing::info!(path = ?path, "配置已热重载生效");
                }
                Err(e) => tracing::warn!(path = ?path, error = ?e, "配置热重载失败（保留旧配置）"),
            }
        }
    });
}

/// 启动健康探测后台任务。
fn spawn_health_check(state: Arc<ProxyState>) {
    tokio::spawn(async move {
        let cfg = state.config();
        match &cfg.health_check {
            Some(hc) => {
                tracing::info!(
                    interval_secs = hc.interval_secs,
                    timeout_secs = hc.timeout_secs,
                    max_failures = hc.max_failures,
                    "健康检查后台任务已启动"
                );
            }
            None => {
                tracing::info!("健康检查：未启用（health_check 未配置）");
            }
        }
        state.run_health_check().await;
    });
}

async fn start_listener(
    proto: ListenerProtocol,
    bind: &str,
    use_tls: bool,
    tls: Option<Arc<TlsAcceptor>>,
    auth: Option<AuthConfig>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    match proto {
        ListenerProtocol::Tcp => run_tcp_transparent(bind, state, stats).await,
        ListenerProtocol::Udp => run_udp_transparent(bind, state, stats).await,
        ListenerProtocol::Http | ListenerProtocol::Https => {
            run_http(bind, use_tls, tls, auth, state, stats).await
        }
        ListenerProtocol::Socks => run_socks(bind, use_tls, tls, auth, state, stats).await,
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
    tracing::info!(protocol = "tcp", bind = %bind, "TCP 透明监听器就绪，等待连接");
    loop {
        let (mut client, peer) = listener.accept().await?;
        tracing::info!(protocol = "tcp", peer = %peer, "接受新 TCP 连接");
        let state = state.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let total_started = std::time::Instant::now();
            let req = RouteRequest::default();
            match dial_outbound_tracked(&state, &req).await {
                Ok((upstream, ob)) => {
                    let idle = state.idle_timeout();
                    if let Err(e) = pipe_tracked(&mut client, upstream, &stats, idle, &ob).await {
                        tracing::warn!(protocol = "tcp", peer = %peer, outbound = %ob, error = ?e, total_elapsed_ms = total_started.elapsed().as_millis(), "TCP 转发异常结束");
                    } else {
                        tracing::info!(protocol = "tcp", peer = %peer, outbound = %ob, total_elapsed_ms = total_started.elapsed().as_millis(), "TCP 转发结束");
                    }
                }
                Err(e) => {
                    tracing::warn!(protocol = "tcp", peer = %peer, error = ?e, dial_ms = total_started.elapsed().as_millis(), "TCP 出站连接失败");
                    stats.record_error();
                }
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
    tracing::info!(protocol = "udp", bind = %bind, "UDP 透明监听器就绪，等待数据包");
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        tracing::info!(protocol = "udp", peer = %peer, len, "收到 UDP 数据包");
        let pkt = buf[..len].to_vec();
        let state = state.clone();
        let stats = stats.clone();
        let sock = socket.clone();
        tokio::spawn(async move {
            let req = RouteRequest::default();
            match dial_outbound_tracked(&state, &req).await {
                Ok((mut upstream, ob)) => {
                    use tokio::io::AsyncWriteExt;
                    stats.outbound_conn_start(&ob);
                    let ok = upstream.write_all(&pkt).await.is_ok();
                    if ok {
                        let mut resp = vec![0u8; 65535];
                        if let Ok(n) = tokio::io::AsyncReadExt::read(&mut upstream, &mut resp).await {
                            resp.truncate(n);
                            let _ = sock.send_to(&resp, peer).await;
                            stats.outbound_bytes(&ob, pkt.len() as u64, n as u64);
                            tracing::info!(protocol = "udp", peer = %peer, outbound = %ob, sent = n, "UDP 响应已转发");
                        } else {
                            tracing::warn!(protocol = "udp", peer = %peer, outbound = %ob, "UDP 上游无响应");
                        }
                    } else {
                        stats.outbound_error(&ob);
                        tracing::warn!(protocol = "udp", peer = %peer, outbound = %ob, "UDP 写入上游失败");
                    }
                    stats.outbound_conn_end(&ob);
                }
                Err(e) => {
                    tracing::warn!(protocol = "udp", peer = %peer, error = ?e, "UDP 出站连接失败");
                    stats.record_error();
                }
            }
        });
    }
}

/// HTTP/HTTPS 代理监听器。
async fn run_http(
    bind: &str,
    use_tls: bool,
    tls: Option<Arc<TlsAcceptor>>,
    auth: Option<AuthConfig>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let tls = if use_tls { tls } else { None };
    tracing::info!(
        protocol = if use_tls { "https" } else { "http" },
        bind = %bind,
        tls = use_tls,
        auth = auth.is_some(),
        "HTTP/HTTPS 代理监听器就绪，等待连接"
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(protocol = if use_tls { "https" } else { "http" }, peer = %peer, "接受新 HTTP 连接");
        let state = state.clone();
        let stats = stats.clone();
        let tls = tls.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            match handle_http_conn(stream, tls, auth, state, stats).await {
                Ok(()) => {}
                Err(e) => tracing::warn!(protocol = "http", peer = %peer, error = ?e, "HTTP 连接处理失败"),
            }
        });
    }
}

async fn handle_http_conn(
    stream: tokio::net::TcpStream,
    tls: Option<Arc<TlsAcceptor>>,
    auth: Option<AuthConfig>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let peer = stream.peer_addr().ok();
    let total_started = std::time::Instant::now();
    let mut client: Box<dyn crate::relay::Tunnel> = if let Some(tls) = tls {
        tracing::debug!(peer = ?peer, "开始 TLS 服务端握手");
        let tls_started = std::time::Instant::now();
        let tls_stream = tls.accept(stream).await?;
        tracing::info!(peer = ?peer, elapsed_ms = tls_started.elapsed().as_millis(), "TLS 握手成功");
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    let parse_started = std::time::Instant::now();
    let (method, host, port, headers) = crate::http::http_parse_request(&mut client).await?;
    tracing::info!(
        peer = ?peer,
        method = %method,
        host = %host,
        port,
        connect = method.eq_ignore_ascii_case("CONNECT"),
        elapsed_ms = parse_started.elapsed().as_millis(),
        "HTTP 请求解析完成"
    );

    // 验证认证
    if let Some(auth_config) = &auth {
        let auth_header = headers.get("proxy-authorization").cloned().unwrap_or_default();
        let http_auth = crate::http::HttpAuth {
            username: auth_config.username.clone(),
            password: auth_config.password.clone(),
        };

        if !http_auth.verify(&auth_header) {
            tracing::warn!(peer = ?peer, host = %host, "HTTP 代理认证失败");
            crate::http::send_http_error(
                &mut client,
                407,
                "Proxy Authentication Required",
            ).await?;
            tracing::info!(peer = ?peer, total_elapsed_ms = total_started.elapsed().as_millis(), "HTTP 连接处理结束（认证失败）");
            return Ok(());
        }
        tracing::info!(peer = ?peer, host = %host, "HTTP 代理认证通过");
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        tracing::info!(peer = ?peer, host = %host, port, "HTTP CONNECT 隧道建立，回送 200");
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    } else {
        // 支持完整的 HTTP 请求转发
        let req = RouteRequest {
            domain: Some(host.clone()),
            ip: host.parse().ok(),
            port,
        };
        let dial_started = std::time::Instant::now();
        let mut upstream = dial_outbound_state(&state, &req).await?;
        tracing::info!(peer = ?peer, host = %host, port, method = %method, dial_ms = dial_started.elapsed().as_millis(), "HTTP 非CONNECT 请求，出站已就绪，转发到上游");

        // 转发请求到上游
        let fwd_req_started = std::time::Instant::now();
        crate::http::http_forward_request(
            &mut client,
            &mut upstream,
            &method,
            &host,
            port,
            &headers,
        ).await?;
        tracing::info!(peer = ?peer, host = %host, elapsed_ms = fwd_req_started.elapsed().as_millis(), "HTTP 请求已转发到上游");

        // 转发响应回客户端
        let fwd_resp_started = std::time::Instant::now();
        crate::http::http_forward_response(&mut upstream, &mut client).await?;
        tracing::info!(
            peer = ?peer,
            host = %host,
            resp_elapsed_ms = fwd_resp_started.elapsed().as_millis(),
            total_elapsed_ms = total_started.elapsed().as_millis(),
            "HTTP 响应已转发回客户端，请求处理完成"
        );
        return Ok(());
    }

    let req = RouteRequest {
        domain: Some(host.clone()),
        ip: host.parse().ok(),
        port,
    };
    let dial_started = std::time::Instant::now();
    let (upstream, ob) = dial_outbound_tracked(&state, &req).await?;
    let idle = state.idle_timeout();
    tracing::info!(peer = ?peer, host = %host, port, outbound = %ob, dial_ms = dial_started.elapsed().as_millis(), "HTTP CONNECT 出站已就绪，开始双向转发");
    pipe_tracked(client, upstream, &stats, idle, &ob).await?;
    tracing::info!(peer = ?peer, host = %host, outbound = %ob, total_elapsed_ms = total_started.elapsed().as_millis(), "HTTP CONNECT 连接处理结束");
    Ok(())
}

/// SOCKS 代理监听器（支持 SOCKS4/4a/5，可选 TLS 包装，支持认证）。
async fn run_socks(
    bind: &str,
    use_tls: bool,
    tls: Option<Arc<TlsAcceptor>>,
    auth: Option<AuthConfig>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let tls = if use_tls { tls } else { None };
    tracing::info!(
        protocol = "socks",
        bind = %bind,
        tls = use_tls,
        auth = auth.is_some(),
        "SOCKS 代理监听器就绪，等待连接"
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(protocol = "socks", peer = %peer, "接受新 SOCKS 连接");
        let state = state.clone();
        let stats = stats.clone();
        let tls = tls.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_conn(stream, tls, auth, state, stats).await {
                tracing::warn!(protocol = "socks", error = ?e, "SOCKS 连接处理失败");
            }
        });
    }
}

async fn handle_socks_conn(
    stream: tokio::net::TcpStream,
    tls: Option<Arc<TlsAcceptor>>,
    auth: Option<AuthConfig>,
    state: Arc<ProxyState>,
    stats: Arc<Stats>,
) -> Result<()> {
    let peer = stream.peer_addr().ok();
    let total_started = std::time::Instant::now();
    let mut client: Box<dyn crate::relay::Tunnel> = if let Some(tls) = tls {
        tracing::debug!(peer = ?peer, "开始 TLS 服务端握手");
        let tls_started = std::time::Instant::now();
        let s = tls.accept(stream).await?;
        tracing::info!(peer = ?peer, elapsed_ms = tls_started.elapsed().as_millis(), "TLS 握手成功");
        Box::new(s)
    } else {
        Box::new(stream)
    };

    // 带认证的 SOCKS 握手
    let socks_auth_config = auth.map(|a| crate::socks::SocksAuth {
        username: a.username,
        password: a.password,
    });

    let handshake_started = std::time::Instant::now();
    let (host, port) = crate::socks::socks_handshake_server_with_auth(
        &mut client,
        socks_auth_config.as_ref(),
    ).await?;
    tracing::info!(peer = ?peer, host = %host, port, elapsed_ms = handshake_started.elapsed().as_millis(), "SOCKS 握手完成，目标已解析");

    let req = RouteRequest {
        domain: Some(host.clone()),
        ip: host.parse().ok(),
        port,
    };
    let dial_started = std::time::Instant::now();
    let (upstream, ob) = dial_outbound_tracked(&state, &req).await?;
    let idle = state.idle_timeout();
    tracing::info!(peer = ?peer, host = %host, port, outbound = %ob, dial_ms = dial_started.elapsed().as_millis(), idle_secs = idle.as_secs(), "SOCKS 出站已就绪，开始双向转发");
    pipe_tracked(client, upstream, &stats, idle, &ob).await?;
    tracing::info!(peer = ?peer, host = %host, outbound = %ob, total_elapsed_ms = total_started.elapsed().as_millis(), "SOCKS 连接处理结束");
    Ok(())
}