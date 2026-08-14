//! HTTP/HTTPS 代理：CONNECT 隧道 + 完整 HTTP 请求转发 + 认证支持。
use anyhow::{bail, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// HTTP 代理认证配置。
#[derive(Debug, Clone)]
pub struct HttpAuth {
    pub username: String,
    pub password: String,
}

impl HttpAuth {
    /// 生成 Basic Auth 头部值。
    pub fn basic_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.username, self.password);
        STANDARD.encode(credentials)
    }

    /// 验证 Proxy-Authorization 头部。
    pub fn verify(&self, auth_header: &str) -> bool {
        if let Some(credentials) = auth_header.strip_prefix("Basic ") {
            let expected = self.basic_auth_header();
            credentials == expected
        } else {
            false
        }
    }
}

/// 解析 HTTP 请求，返回 (方法, 目标主机, 目标端口, 请求头)。
pub async fn http_parse_request<S>(stream: &mut S) -> Result<(String, String, u16, HashMap<String, String>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut byte = [0u8; 1];
    
    // 读取 HTTP 头部
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("HTTP 连接提前关闭");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("HTTP 头部过大");
        }
    }
    
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    
    // 解析请求行
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    
    // 解析请求头
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }
    
    // 根据方法类型解析目标
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target, 443)?;
        return Ok((method, host, port, headers));
    }
    
    // 绝对形式 http://host:port/path 或 https://host:port/path
    if let Some(rest) = target.strip_prefix("http://") {
        if let Some(slash) = rest.find('/') {
            let (hp, _) = rest.split_at(slash);
            let (host, port) = parse_host_port(hp, 80)?;
            return Ok((method, host, port, headers));
        } else {
            let (host, port) = parse_host_port(rest, 80)?;
            return Ok((method, host, port, headers));
        }
    }
    
    if let Some(rest) = target.strip_prefix("https://") {
        if let Some(slash) = rest.find('/') {
            let (hp, _) = rest.split_at(slash);
            let (host, port) = parse_host_port(hp, 443)?;
            return Ok((method, host, port, headers));
        } else {
            let (host, port) = parse_host_port(rest, 443)?;
            return Ok((method, host, port, headers));
        }
    }
    
    // 相对形式：依赖 Host 头
    let host_line = headers
        .get("host")
        .cloned()
        .unwrap_or_default();
    let (host, port) = parse_host_port(&host_line, 80)?;
    Ok((method, host, port, headers))
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    if s.is_empty() {
        bail!("空的主机地址");
    }
    
    // 处理 IPv6 [::1]:8080
    if let Some(start) = s.find('[') {
        if let Some(end) = s.find(']') {
            let host = &s[start + 1..end];
            let port = if end + 1 < s.len() && &s[end + 1..end + 2] == ":" {
                s[end + 2..].parse::<u16>().unwrap_or(default_port)
            } else {
                default_port
            };
            return Ok((host.to_string(), port));
        }
    }
    
    if let Some((h, p)) = s.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(default_port);
        Ok((h.to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// 发送 HTTP 错误响应。
pub async fn send_http_error<S>(stream: &mut S, status: u16, message: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Error",
    };
    
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, status_text, message.len(), message
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// 发送 HTTP 成功响应（用于 CONNECT）。
pub async fn send_http_success<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// 向上游 HTTP 代理发起 CONNECT 建立隧道。
pub async fn http_connect_tunnel(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let started = std::time::Instant::now();
    tracing::info!(host = %host, port, "向上游 HTTP 代理发起 CONNECT 隧道");
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
            tracing::warn!(host = %host, port, elapsed_ms = started.elapsed().as_millis(), "上游 HTTP 代理无响应");
            bail!("上游 HTTP 代理无响应");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            bail!("上游 HTTP 代理响应过大");
        }
    }

    let text = String::from_utf8_lossy(&buf);
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        tracing::warn!(
            host = %host,
            port,
            status_line = text.lines().next().unwrap_or(""),
            elapsed_ms = started.elapsed().as_millis(),
            "上游 HTTP 代理拒绝 CONNECT"
        );
        bail!("上游 HTTP 代理拒绝 CONNECT: {}", text.lines().next().unwrap_or(""));
    }
    tracing::info!(host = %host, port, elapsed_ms = started.elapsed().as_millis(), "上游 HTTP 代理 CONNECT 隧道建立成功");
    Ok(())
}

/// 完整的 HTTP 代理转发：解析请求、修改头部、转发到上游。
pub async fn http_forward_request<S>(
    client: &mut S,
    upstream: &mut TcpStream,
    method: &str,
    host: &str,
    port: u16,
    original_headers: &HashMap<String, String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();
    // 构建转发请求
    let request_line = if method.eq_ignore_ascii_case("CONNECT") {
        format!("CONNECT {}:{} HTTP/1.1\r\n", host, port)
    } else {
        format!("{} http://{}:{} HTTP/1.1\r\n", method, host, port)
    };

    let mut headers = original_headers.clone();
    // 更新 Host 头部
    headers.insert("host".to_string(), format!("{}:{}", host, port));
    // 移除 Connection 和 Proxy- 相关头部
    headers.retain(|k, _| !k.starts_with("proxy-") && k != "connection");
    // 添加 Via 头部标识代理
    headers.entry("via".to_string())
        .or_insert_with(|| "1.1 omni-proxy".to_string());

    let header_str = headers
        .iter()
        .map(|(k, v)| format!("{}: {}\r\n", k, v))
        .collect::<String>();

    let full_request = format!("{}\r\n{}\r\n", request_line, header_str);
    upstream.write_all(full_request.as_bytes()).await?;

    // 如果有请求体（POST/PUT 等），需要转发
    if method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH")
    {
        if let Some(content_length) = headers.get("content-length") {
            let length: usize = content_length.parse().unwrap_or(0);
            if length > 0 {
                let mut body = vec![0u8; length];
                client.read_exact(&mut body).await?;
                upstream.write_all(&body).await?;
            }
        }
    }

    tracing::debug!(method = %method, host = %host, port, elapsed_ms = started.elapsed().as_millis(), "HTTP 请求已转发到上游");
    Ok(())
}

/// 读取上游 HTTP 响应并转发给客户端。
pub async fn http_forward_response<S>(
    upstream: &mut TcpStream,
    client: &mut S,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();
    let mut buf = Vec::with_capacity(8192);
    let mut byte = [0u8; 1];

    // 读取响应头部
    loop {
        let n = upstream.read(&mut byte).await?;
        if n == 0 {
            bail!("上游连接提前关闭");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("HTTP 响应头部过大");
        }
    }

    // 转发响应头部
    client.write_all(&buf).await?;

    // 解析 Content-Length 和 Transfer-Encoding
    let text = String::from_utf8_lossy(&buf);
    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;

    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            is_chunked = true;
        }
        if lower.starts_with("content-length:") {
            if let Ok(len) = line.splitn(2, ':').nth(1).unwrap_or("").trim().parse::<usize>() {
                content_length = Some(len);
            }
        }
    }

    // 转发响应体
    if is_chunked {
        // Chunked 编码：逐块转发直到结束
        loop {
            let mut chunk_size_line = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                upstream.read(&mut byte).await?;
                chunk_size_line.push(byte[0]);
                if chunk_size_line.len() >= 2 && chunk_size_line.ends_with(b"\r\n") {
                    break;
                }
            }

            let size_str = String::from_utf8_lossy(&chunk_size_line);
            let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);

            if size == 0 {
                // 最后一个 chunk，转发并结束
                client.write_all(&chunk_size_line).await?;
                // 读取尾部 headers 和最终 \r\n
                let mut trailer = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    upstream.read(&mut byte).await?;
                    trailer.push(byte[0]);
                    if trailer.len() >= 2 && trailer.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                client.write_all(&trailer).await?;
                break;
            }
            
            // 读取 chunk 数据
            let mut chunk = vec![0u8; size + 2]; // +2 for \r\n
            upstream.read_exact(&mut chunk).await?;
            client.write_all(&chunk).await?;
        }
    } else if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        upstream.read_exact(&mut body).await?;
        client.write_all(&body).await?;
    }
    // 如果没有 Content-Length 也不是 chunked，则保持连接直到上游关闭

    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis(),
        chunked = is_chunked,
        content_length = ?content_length,
        "HTTP 响应已转发回客户端"
    );
    Ok(())
}