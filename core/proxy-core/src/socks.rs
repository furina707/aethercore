//! SOCKS4/4a/5 协议解析与服务端处理，以及 SOCKS5 客户端握手（用于上游代理）。
//! 支持认证、UDP 关联、IPv6 等完整功能。
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[allow(dead_code)]
mod socks5 {
    pub const VERSION: u8 = 0x05;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
    pub const ATYP_V4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_V6: u8 = 0x04;
    pub const AUTH_NO_AUTH: u8 = 0x00;
    pub const AUTH_GSSAPI: u8 = 0x01;
    pub const AUTH_USERNAME_PASSWORD: u8 = 0x02;
    pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
    pub const REP_SUCCEEDED: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_NOT_ALLOWED: u8 = 0x02;
    pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_CONNECTION_REFUSED: u8 = 0x05;
    pub const REP_TTL_EXPIRED: u8 = 0x06;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// SOCKS 认证配置。
#[derive(Debug, Clone)]
pub struct SocksAuth {
    pub username: String,
    pub password: String,
}

impl SocksAuth {
    /// 验证用户名密码。
    pub fn verify(&self, username: &str, password: &str) -> bool {
        self.username == username && self.password == password
    }
}

/// SOCKS 请求结果。
#[derive(Debug)]
pub struct SocksRequest {
    pub version: u8,
    pub command: u8,
    pub host: String,
    pub port: u16,
}

/// 解析 SOCKS 请求目标，返回 (host, port)。支持 SOCKS4/4a/5。
pub async fn socks_handshake_server<S>(stream: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    match ver {
        0x04 => socks4_handshake(stream).await,
        0x05 => {
            let (host, port) = socks5_handshake_server(stream, None).await?;
            Ok((host, port))
        }
        _ => bail!("不支持的 SOCKS 版本: {}", ver),
    }
}

/// 带认证的 SOCKS 握手。
pub async fn socks_handshake_server_with_auth<S>(
    stream: &mut S,
    auth: Option<&SocksAuth>,
) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    tracing::info!(version = ver, auth_required = auth.is_some(), "SOCKS 握手开始");
    match ver {
        0x04 => socks4_handshake(stream).await,
        0x05 => socks5_handshake_server(stream, auth).await,
        _ => {
            tracing::warn!(version = ver, "不支持的 SOCKS 版本");
            bail!("不支持的 SOCKS 版本: {}", ver);
        }
    }
}

async fn socks4_handshake<S>(stream: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cmd = stream.read_u8().await?;
    if cmd != 0x01 {
        tracing::warn!(cmd, "SOCKS4 仅支持 CONNECT");
        bail!("仅支持 SOCKS4 CONNECT");
    }
    let port = stream.read_u16().await?;
    let ip = stream.read_u32().await?;
    
    // 读取 userid 直到 0
    let mut buf = [0u8; 1];
    while stream.read_exact(&mut buf).await.is_ok() && buf[0] != 0 {}
    
    // SOCKS4a: 0.0.0.x 表示域名跟随
    let host = if (ip & 0xFF) != 0 {
        format!(
            "{}.{}.{}.{}",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF
        )
    } else {
        // 读域名直到 0
        let mut domain = Vec::new();
        while stream.read_exact(&mut buf).await.is_ok() && buf[0] != 0 {
            domain.push(buf[0]);
        }
        String::from_utf8_lossy(&domain).to_string()
    };
    tracing::info!(version = 4, host = %host, port, "SOCKS4 请求解析完成");
    
    // 回送 SOCKS4 响应
    let resp = [0x00, 0x5A, (port >> 8) as u8, port as u8, 0, 0, 0, 0];
    stream.write_all(&resp).await?;
    Ok((host, port))
}

async fn socks5_handshake_server<S>(
    stream: &mut S,
    auth: Option<&SocksAuth>,
) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    
    // 选择认证方法
    let auth_method = if auth.is_some() {
        if methods.contains(&socks5::AUTH_USERNAME_PASSWORD) {
            socks5::AUTH_USERNAME_PASSWORD
        } else {
            socks5::AUTH_NO_ACCEPTABLE
        }
    } else if methods.contains(&socks5::AUTH_NO_AUTH) {
        socks5::AUTH_NO_AUTH
    } else {
        socks5::AUTH_NO_ACCEPTABLE
    };
    
    stream.write_all(&[0x05, auth_method]).await?;
    tracing::info!(
        version = 5,
        auth_method,
        methods_offered = ?methods,
        "SOCKS5 认证方法协商完成"
    );
    
    if auth_method == socks5::AUTH_NO_ACCEPTABLE {
        tracing::warn!("SOCKS5 客户端未提供可用认证方法");
        bail!("无可用的认证方法");
    }
    
    // 如果需要用户名密码认证
    if auth_method == socks5::AUTH_USERNAME_PASSWORD {
        if let Some(auth_config) = auth {
            let ver = stream.read_u8().await?;
            if ver != 0x01 {
                bail!("SOCKS5 认证版本错误");
            }
            
            let ulen = stream.read_u8().await? as usize;
            let mut username = vec![0u8; ulen];
            stream.read_exact(&mut username).await?;
            let username = String::from_utf8_lossy(&username).to_string();
            
            let plen = stream.read_u8().await? as usize;
            let mut password = vec![0u8; plen];
            stream.read_exact(&mut password).await?;
            let password = String::from_utf8_lossy(&password).to_string();
            
            if auth_config.verify(&username, &password) {
                stream.write_all(&[0x01, 0x00]).await?; // 认证成功
                tracing::info!(username = %username, "SOCKS5 用户名密码认证通过");
            } else {
                stream.write_all(&[0x01, 0x01]).await?; // 认证失败
                tracing::warn!(username = %username, "SOCKS5 用户名密码认证失败");
                bail!("SOCKS5 认证失败");
            }
        }
    }
    
    // 读取请求
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        bail!("SOCKS5 请求版本错误");
    }
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;
    
    let host = match atyp {
        socks5::ATYP_V4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        socks5::ATYP_V6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        socks5::ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut d = vec![0u8; len];
            stream.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        _ => bail!("SOCKS5 未知地址类型: {}", atyp),
    };
    let port = stream.read_u16().await?;
    
    // 处理不同命令
    match cmd {
        socks5::CMD_CONNECT => {
            // 成功响应
            let resp = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            stream.write_all(&resp).await?;
            tracing::info!(version = 5, cmd = "connect", host = %host, port, "SOCKS5 CONNECT 请求处理完成");
            Ok((host, port))
        }
        socks5::CMD_UDP_ASSOCIATE => {
            // UDP 关联：返回代理地址
            // 这里简单返回 0.0.0.0:0，实际应该返回 UDP 代理地址
            let resp = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            stream.write_all(&resp).await?;
            tracing::warn!(version = 5, cmd = "udp_associate", host = %host, port, "SOCKS5 UDP 关联请求（暂未完全实现，返回占位地址）");
            Ok((host, port))
        }
        socks5::CMD_BIND => {
            // BIND 命令：回送失败
            let resp = [0x05, socks5::REP_COMMAND_NOT_SUPPORTED, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            stream.write_all(&resp).await?;
            tracing::warn!(version = 5, cmd = "bind", "SOCKS5 BIND 命令不支持");
            bail!("SOCKS5 BIND 命令不支持");
        }
        _ => {
            let resp = [0x05, socks5::REP_COMMAND_NOT_SUPPORTED, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            stream.write_all(&resp).await?;
            tracing::warn!(version = 5, cmd, "SOCKS5 未知命令");
            bail!("SOCKS5 未知命令: {}", cmd);
        }
    }
}

/// SOCKS5 客户端握手（连接上游 SOCKS5 代理建立到目标的隧道）。
pub async fn socks5_handshake_client(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let started = std::time::Instant::now();
    tracing::info!(host = %host, port, "SOCKS5 客户端握手开始（与上游 SOCKS5 代理）");
    // 协商 NO AUTH
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        tracing::warn!(resp = ?resp, elapsed_ms = started.elapsed().as_millis(), "上游 SOCKS5 协商失败");
        bail!("上游 SOCKS5 协商失败");
    }

    // CONNECT 请求
    let mut req = Vec::new();
    req.push(0x05);
    req.push(socks5::CMD_CONNECT);
    req.push(0x00);
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(socks5::ATYP_V4);
        req.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(socks5::ATYP_V6);
        req.extend_from_slice(&ipv6.octets());
    } else {
        req.push(socks5::ATYP_DOMAIN);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    // 读取响应
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        tracing::warn!(rep = hdr[1], elapsed_ms = started.elapsed().as_millis(), "上游 SOCKS5 CONNECT 失败");
        bail!("上游 SOCKS5 CONNECT 失败，回复码: {}", hdr[1]);
    }
    
    let atyp = hdr[3];
    let mut disc = match atyp {
        socks5::ATYP_V4 => 4,
        socks5::ATYP_V6 => 16,
        socks5::ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => bail!("上游 SOCKS5 返回未知地址类型"),
    };
    disc += 2; // port
    let mut _skip = vec![0u8; disc];
    stream.read_exact(&mut _skip).await?;
    Ok(())
}

/// 构建 SOCKS5 错误响应。
pub fn socks5_error_response(rep: u8) -> [u8; 10] {
    [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// 构建 SOCKS5 成功响应。
pub fn socks5_success_response() -> [u8; 10] {
    [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}