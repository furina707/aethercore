//! HTTP/HTTPS 代理：CONNECT 隧道 + 普通代理请求。上游 HTTP 代理隧道客户端。
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// 解析 HTTP 请求行与首部，返回方法、目标 (host, port)。
/// 支持 GET http://... 形式与 CONNECT host:port 形式。
pub async fn http_parse_request<S>(stream: &mut S) -> Result<(String, String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    // 读取到 \r\n\r\n
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("HTTP 连接提前关闭");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("HTTP 头部过大");
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first_line = text.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target, 443)?;
        return Ok((method, host, port));
    }

    // 绝对形式 http://host:port/path
    if let Some(rest) = target.strip_prefix("http://") {
        if let Some(slash) = rest.find('/') {
            let (hp, _) = rest.split_at(slash);
            let (host, port) = parse_host_port(hp, 80)?;
            return Ok((method, host, port));
        } else {
            let (host, port) = parse_host_port(rest, 80)?;
            return Ok((method, host, port));
        }
    }

    // 相对形式：依赖 Host 头
    let host_line = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
        .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let (host, port) = parse_host_port(&host_line, 80)?;
    Ok((method, host, port))
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(default_port);
        Ok((h.to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// 向上游 HTTP 代理发起 CONNECT 建立隧道。
pub async fn http_connect_tunnel(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        host, port, host, port
    );
    stream.write_all(req.as_bytes()).await?;
    // 读取响应行
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("上游 HTTP 代理无响应");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        bail!("上游 HTTP 代理拒绝 CONNECT: {}", text.lines().next().unwrap_or(""));
    }
    Ok(())
}
