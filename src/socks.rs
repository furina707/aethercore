//! SOCKS4/5 协议解析与服务端处理，以及 SOCKS5 客户端握手（用于上游代理）。
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[allow(dead_code)]
mod socks5 {
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
    pub const ATYP_V4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_V6: u8 = 0x04;
}

/// 解析 SOCKS 请求目标，返回 (host, port)。支持 SOCKS4/4a/5。
pub async fn socks_handshake_server<S>(stream: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    match ver {
        0x04 => socks4_handshake(stream).await,
        0x05 => socks5_handshake_server(stream).await,
        _ => bail!("不支持的 SOCKS 版本: {}", ver),
    }
}

async fn socks4_handshake<S>(stream: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cmd = stream.read_u8().await?;
    if cmd != 0x01 {
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
    // 回送 SOCKS4 响应
    let resp = [0x00, 0x5A, (port >> 8) as u8, port as u8, 0, 0, 0, 0];
    stream.write_all(&resp).await?;
    Ok((host, port))
}

async fn socks5_handshake_server<S>(stream: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    // 选 NO AUTH
    stream.write_all(&[0x05, 0x00]).await?;

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

    if cmd != socks5::CMD_CONNECT {
        // 仅实现 CONNECT，其它回送失败
        let resp = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream.write_all(&resp).await?;
        bail!("仅支持 SOCKS5 CONNECT");
    }

    // 成功响应
    let resp = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&resp).await?;
    Ok((host, port))
}

/// SOCKS5 客户端握手（连接上游 SOCKS5 代理建立到目标的隧道）。
pub async fn socks5_handshake_client(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    // 协商 NO AUTH
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
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

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
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
