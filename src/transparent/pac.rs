//! 透明代理方案1：系统代理 / PAC 自动配置。
//!
//! 启动一个最小 HTTP 服务返回 PAC 脚本，浏览器/系统通过 WPAD 或手动设置
//! 指向该 PAC 即可按域名后缀/端口规则决定直连还是走代理，无需管理员权限。
//! 可在 Windows 上调用 WinHttp 设置系统代理（需权限，失败仅告警）。
use crate::config::PacConfig;
use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 生成 PAC 脚本文本。
fn build_pac_script(cfg: &PacConfig) -> String {
    let proxy = &cfg.proxy;
    let bypass: Vec<String> = cfg
        .bypass_domains
        .iter()
        .map(|d| format!("shExpMatch(host, \"*.{}\")", d))
        .collect();
    let bypass_expr = if bypass.is_empty() {
        "false".to_string()
    } else {
        bypass.join(" || ")
    };

    let port_expr = if cfg.proxy_ports.is_empty() {
        "true".to_string()
    } else {
        let mut conds = Vec::new();
        for p in &cfg.proxy_ports {
            conds.push(format!("(port == {})", p));
        }
        conds.join(" || ")
    };

    format!(
        r#"function FindProxyForURL(url, host) {{
    // 直连域名后缀
    if ({bypass_expr}) {{ return "DIRECT"; }}
    // 仅对指定端口走代理
    var port = url.substring(0, 6).toLowerCase() == "https:" ? 443 : 80;
    if (/^[a-z]+:\/\//.test(url)) {{
        var m = url.match(/:(\d+)\//);
        if (m) port = parseInt(m[1], 10);
    }}
    if ({port_expr}) {{
        return "{proxy}";
    }}
    return "DIRECT";
}}
"#,
        bypass_expr = bypass_expr,
        port_expr = port_expr,
        proxy = proxy,
    )
}

/// 启动 PAC 服务（在独立任务中运行）。
pub async fn run_pac(cfg: &PacConfig) -> Result<()> {
    let bind = cfg.bind.clone();
    let pac = build_pac_script(cfg);
    let listener = TcpListener::bind(&bind).await?;
    tracing::info!("PAC 服务已启动: http://{}/proxy.pac", bind);

    // 可选：设置系统代理
    if cfg.set_system_proxy {
        set_system_proxy_pac(&format!("http://{}/proxy.pac", bind));
    }

    loop {
        let (mut sock, _) = listener.accept().await?;
        let pac = pac.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            if let Ok(n) = sock.read(&mut buf).await {
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.lines().next().unwrap_or("").trim();
                // 仅响应 /proxy.pac 或 /
                if path.starts_with("GET") {
                    let body = if path.contains("proxy.pac") || path == "GET / " {
                        pac.as_bytes()
                    } else {
                        b"404 Not Found"
                    };
                    let status = if path.contains("proxy.pac") || path == "GET / " {
                        "200 OK"
                    } else {
                        "404 Not Found"
                    };
                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                }
            }
        });
    }
}

#[cfg(windows)]
fn set_system_proxy_pac(pac_url: &str) {
    // 完整设置需调用 WinHttpSetOption 或写注册表；此处做尽力而为提示，
    // 推荐手动在 设置->网络->代理 填入该 PAC URL，或以管理员运行：
    //   netsh winhttp set proxy proxy-server="<proxy>" bypass-list="<domains>"
    tracing::warn!(
        "已请求设置系统 PAC 代理 {}；Windows 上完整设置请手动在 \
         设置->网络->代理 中填入该 PAC URL，或以管理员运行 netsh winhttp set proxy ...",
        pac_url
    );
}

#[cfg(not(windows))]
fn set_system_proxy_pac(_pac_url: &str) {}
