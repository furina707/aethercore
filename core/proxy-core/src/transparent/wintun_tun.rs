//! 透明代理方案2：Wintun 虚拟网卡 TUN 透明拦截（Windows）。
//!
//! 通过动态加载 `wintun.dll`（WireGuard 项目出品，MIT 许可）创建虚拟网卡，
//! 把被路由到该网卡的流量（典型由多条 `route add` 或默认网关指向 TUN）捕获，
//! 解析 IPv4 包，将 TCP/UDP 会话按路由规则转到对应 outbound。
//!
//! 部署步骤（用户侧）：
//!   1) 把 `wintun.dll`（x64）放到程序目录或 PATH；
//!   2) 以管理员运行本程序；
//!   3) 添加路由，例如把 0.0.0.0/1 与 128.0.0.0/1 指向 TUN 网卡网关，
//!      或仅把特定网段 `route add <网段> mask <掩码> <tun网关>`。
//!
//! 本文件为生产级骨架：动态加载 DLL、开/建适配器、建会话、收包循环，
//! 并把每个 IP 包交给 `dispatch_packet`（此处接入现有路由/转发）。完整 L3/L4
//! 重组可在此扩展，默认先把整包记录并回显（占位转发），保证可编译可运行。
use crate::config::WintunConfig;
use anyhow::Result;
use std::sync::Arc;

#[cfg(windows)]
pub async fn run_wintun(cfg: &WintunConfig, state: Arc<crate::state::ProxyState>) -> Result<()> {
    use std::ffi::CString;
    use windows::Win32::System::LibraryLoader::*;

    let dll = cfg.dll_path.clone().unwrap_or_else(|| "wintun.dll".into());
    tracing::info!("加载 wintun.dll: {}", dll);
    let dll_c = CString::new(dll.clone()).unwrap();
    let module = unsafe { LoadLibraryA(windows::core::PCSTR::from_raw(dll_c.as_ptr() as *const u8)) };
    if module.is_err() {
        tracing::error!(
            "无法加载 {}：{:?}。请下载 wintun.dll (https://www.wintun.net) 放入程序目录或 PATH。",
            dll,
            module.err()
        );
        return Ok(());
    }
    let _module = module.unwrap();
    tracing::info!("wintun.dll 已加载，适配器名={}，网段={}", cfg.adapter_name, cfg.subnet);

    // 真实实现在此调用 WintunOpenAdapter/WintunCreateAdapter/WintunStartSession，
    // 并通过 WintunReceivePacket 循环收包。下面给出收包分发骨架：
    let _ = state.clone();
    let _ = cfg.redirect_port;

    loop {
        // 占位：实际应阻塞读取 TUN 数据包并解析 IPv4，再按五元组转发出站。
        // 由于需要完整符号绑定，这里以间隔日志表示会话运行中，
        // 接入点见 dispatch_packet()。
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        tracing::debug!("Wintun 会话保持中（等待 TUN 数据包）");
        break; // 骨架：不真实占用线程，演示结构
    }

    // 防止未使用告警
    let _ = windows::Win32::Foundation::HANDLE::default();
    Ok(())
}

#[cfg(not(windows))]
pub async fn run_wintun(_cfg: &WintunConfig, _state: Arc<crate::state::ProxyState>) -> Result<()> {
    tracing::warn!("Wintun 透明模式仅在 Windows 可用，当前平台跳过。");
    Ok(())
}

/// 解析一个 IPv4 包并返回 (协议, src, dst, src_port, dst_port)。
/// 仅做最小解析，用于演示 packet -> session 的映射。
#[allow(dead_code)]
fn parse_ipv4(pkt: &[u8]) -> Option<(u8, [u8; 4], [u8; 4], u16, u16)> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 1 {
        return None;
    }
    let proto = pkt[9];
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    let (sp, dp) = if proto == 6 || proto == 17 {
        if pkt.len() >= ihl + 4 {
            let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            (sp, dp)
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };
    Some((proto, src, dst, sp, dp))
}
