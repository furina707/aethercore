//! 透明代理方案1：系统代理 / PAC 自动配置。
//!
//! 启动一个最小 HTTP 服务返回 PAC 脚本，浏览器/系统通过 WPAD 或手动设置
//! 指向该 PAC 即可按域名后缀/端口规则决定直连还是走代理，无需管理员权限。
//! 可在 Windows 上调用 WinHttp 设置系统代理（需权限，失败仅告警）。
use crate::config::PacConfig;
use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ,
};

/// 保存设置前的原 AutoConfigURL 值，供退出时还原。
/// 外层 Option=是否已记录过原值；内层 Option=原值是否存在（None=原本未配置）。
#[cfg(windows)]
static ORIGINAL_AUTOCONFIG_URL: std::sync::Mutex<Option<Option<String>>> =
    std::sync::Mutex::new(None);

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
    match apply_autoconfig_url(Some(pac_url), true) {
        Ok(()) => tracing::info!(
            pac_url = %pac_url,
            "系统代理 PAC 已设置（AutoConfigURL），浏览器/系统将走该 PAC"
        ),
        Err(e) => tracing::warn!(
            error = ?e,
            pac_url = %pac_url,
            "设置系统代理 PAC 失败；可手动在 设置→网络→代理 中填入该 PAC URL"
        ),
    }
}

#[cfg(not(windows))]
fn set_system_proxy_pac(_pac_url: &str) {
    tracing::debug!("非 Windows 平台，跳过系统代理自动设置");
}

/// 还原系统代理设置（仅在曾设置过时生效）。
/// 在进程退出前显式调用（因 `std::process::exit` 不会执行 Drop）。
#[cfg(windows)]
pub fn restore_system_proxy() {
    let original = ORIGINAL_AUTOCONFIG_URL.lock().unwrap().take();
    match original {
        Some(Some(prev)) => match apply_autoconfig_url(Some(&prev), false) {
            Ok(()) => tracing::info!(restored = %prev, "系统代理已还原（写回原 AutoConfigURL）"),
            Err(e) => tracing::warn!(error = ?e, "还原系统代理失败"),
        },
        Some(None) => match apply_autoconfig_url(None, false) {
            Ok(()) => tracing::info!("系统代理已还原（删除 AutoConfigURL，恢复未配置状态）"),
            Err(e) => tracing::warn!(error = ?e, "还原系统代理失败"),
        },
        None => tracing::debug!("系统代理无需还原（从未设置过）"),
    }
}

#[cfg(not(windows))]
pub fn restore_system_proxy() {}

// ===== Windows 注册表实现细节 =====

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn open_internet_settings() -> Result<HKEY> {
    let path = to_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    let mut hkey = HKEY::default();
    unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            0,
            KEY_READ | KEY_SET_VALUE,
            &mut hkey,
        )
    }
    .map_err(|e| anyhow::anyhow!("RegOpenKeyExW 失败: {}", e))?;
    Ok(hkey)
}

/// 读取当前 AutoConfigURL；Ok(None) 表示该值不存在（未配置）。
#[cfg(windows)]
fn query_autoconfig_url(hkey: HKEY) -> Result<Option<String>> {
    let name = to_wide("AutoConfigURL");
    let mut len: u32 = 0;
    // 第一次仅查询大小（lpdata=None）。值不存在时返回 Err，视为未配置。
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name.as_ptr()),
            None,
            None,
            None,
            Some(&mut len as *mut u32),
        )
    };
    if res.is_err() {
        return Ok(None);
    }
    if len == 0 {
        return Ok(Some(String::new()));
    }
    let mut buf = vec![0u8; len as usize];
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name.as_ptr()),
            None,
            None,
            Some(buf.as_mut_ptr()),
            Some(&mut len as *mut u32),
        )
    };
    if let Err(e) = res {
        anyhow::bail!("RegQueryValueExW 读取失败: {}", e);
    }
    // REG_SZ 为 UTF-16，len 是字节数
    let utf16: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed: Vec<u16> = utf16.into_iter().take_while(|&c| c != 0).collect();
    Ok(Some(String::from_utf16_lossy(&trimmed)))
}

#[cfg(windows)]
fn set_autoconfig_url_value(hkey: HKEY, value: &str) -> Result<()> {
    let name = to_wide("AutoConfigURL");
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = wide.iter().flat_map(|&c| c.to_le_bytes()).collect();
    unsafe { RegSetValueExW(hkey, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(bytes.as_slice())) }
        .map_err(|e| anyhow::anyhow!("RegSetValueExW 失败: {}", e))?;
    Ok(())
}

#[cfg(windows)]
fn delete_autoconfig_url(hkey: HKEY) -> Result<()> {
    let name = to_wide("AutoConfigURL");
    // 值不存在视为已删除成功，忽略所有错误
    let _ = unsafe { RegDeleteValueW(hkey, PCWSTR(name.as_ptr())) };
    Ok(())
}

/// 通知系统代理设置已变更，让正在运行的浏览器/WinINet 立即感知。
#[cfg(windows)]
fn notify_settings_changed() {
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

/// 统一入口：写入或删除 AutoConfigURL，可选保存原值用于后续还原。
#[cfg(windows)]
fn apply_autoconfig_url(new_value: Option<&str>, save_original: bool) -> Result<()> {
    let hkey = open_internet_settings()?;
    if save_original {
        let mut guard = ORIGINAL_AUTOCONFIG_URL.lock().unwrap();
        if guard.is_none() {
            // 首次设置：记录原值（查询失败也视为无原值）
            *guard = Some(query_autoconfig_url(hkey).unwrap_or(None));
        }
    }
    let res = match new_value {
        Some(v) => set_autoconfig_url_value(hkey, v),
        None => delete_autoconfig_url(hkey),
    };
    let _ = unsafe { RegCloseKey(hkey) };
    res?;
    notify_settings_changed();
    Ok(())
}
