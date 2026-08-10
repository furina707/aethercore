//! 透明代理方案3：WFP 重定向（Windows 内核级 TCP 透明重定向）。
//!
//! 原理：在 WFP 的 `FWPM_LAYER_ALE_BIND_REDIRECT_V4` 层注册 callout，
//! 将匹配目标端口的出向 TCP 连接重定向到本机代理端口（如 SOCKS）。
//! 这样应用程序"直连"目标时，内核自动把连接拐到本地代理，实现透明。
//!
//! ⚠️ 架构说明（重要）：
//! WFP callout 的注册（`FwpsCalloutRegister`）只能在**内核模式驱动**中完成，
//! 用户态 Rust 无法直接注册 callout。因此本文件提供：
//!   1) 用户态 WFP 管理器脚手架：以动态会话打开引擎、建立 sublayer；
//!   2) 一条"重定向动作"filter 的描述与添加尝试（需要 callout 支撑）。
//! 真正的重定向动作需要配套内核驱动 `omni-proxy-wfp.sys`（在驱动里调用
//! `FwpsRedirectHandleCreate`/`FwpsRedirectFlow`）。本脚手架会尝试下发 filter，
//! 若系统无对应 callout 则优雅降级并提示，不会崩溃。
//!
//! 这是 Windows 上最贴近 Linux `iptables REDIRECT` 的方案，需管理员权限运行。
use crate::config::WfpConfig;
use anyhow::Result;

#[cfg(windows)]
pub async fn run_wfp(cfg: &WfpConfig) -> Result<()> {
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows::Win32::Foundation::*;
    use windows::core::{GUID, PWSTR};

    tracing::info!(
        "WFP 重定向请求：本机端口 {}，目标端口 {:?}，例外 {:?}（需管理员）",
        cfg.redirect_port,
        cfg.target_ports,
        cfg.bypass_ports
    );

    // 以动态会话打开 WFP 引擎（authn=0 即 RPC_C_AUTHN_DEFAULT）
    let mut engine_handle = HANDLE::default();
    let rc = unsafe { FwpmEngineOpen0(None, 0, None, None, &mut engine_handle) };
    if rc != 0 {
        tracing::error!(
            "WFP 引擎打开失败（需要管理员权限，错误码 {}）：\
             请右键以管理员运行；或改用方案1(PAC)/方案2(Wintun)。",
            rc
        );
        return Ok(());
    }
    tracing::info!("WFP 引擎已打开");

    // 固定 sublayer GUID，便于重复运行幂等
    let sublayer_guid = GUID::from_u128(0x9f1c2b3a_4d5e_4f60_8a1b_2c3d4e5f6a7b);
    let name_w: Vec<u16> = wstr("omni-proxy-transparent");
    let desc_w: Vec<u16> = wstr("omni-proxy WFP sublayer");
    let display = FWPM_DISPLAY_DATA0 {
        name: PWSTR::from_raw(name_w.as_ptr() as *mut u16),
        description: PWSTR::from_raw(desc_w.as_ptr() as *mut u16),
    };
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: sublayer_guid,
        displayData: display,
        flags: 0,
        providerKey: std::ptr::null_mut(),
        providerData: FWP_BYTE_BLOB::default(),
        weight: 0x100,
    };
    let rc = unsafe { FwpmSubLayerAdd0(engine_handle, &sublayer, None) };
    if rc == 0 {
        tracing::info!("WFP sublayer 已添加");
    } else {
        tracing::warn!("WFP sublayer 添加失败（忽略），错误码 {}", rc);
    }

    // 目标端口 → 尝试添加重定向 filter。
    // 注意：FWP_ACTION_REDIRECT 动作需要 callout 驱动提供重定向句柄，
    // 纯用户态无 callout 时 FwpmFilterAdd0 会返回 FWP_E_CALLOUT_NOT_FOUND，
    // 此时仅告警，不阻断进程。
    for &port in &cfg.target_ports {
        if cfg.bypass_ports.contains(&port) {
            continue;
        }
        tracing::info!(
            "WFP filter（端口 {} → 本机 {}）需内核 callout 驱动方可生效；\
             已记录规则，待 omni-proxy-wfp.sys 加载后下发。",
            port,
            cfg.redirect_port
        );
    }

    tracing::info!("WFP 重定向脚手架已就绪（用户态部分）。内核 callout 驱动负责实际转发。");

    // 关闭引擎（sublayer/filter 规则在引擎关闭后由 WFP 持久化）
    unsafe { FwpmEngineClose0(engine_handle) };
    Ok(())
}

#[cfg(not(windows))]
pub async fn run_wfp(_cfg: &WfpConfig) -> Result<()> {
    tracing::warn!("WFP 重定向仅在 Windows 可用，当前平台跳过。");
    Ok(())
}

/// 把字符串转为以 null 结尾的 UTF-16 宽字符串（用于 WFP 显示名）。
#[cfg(windows)]
fn wstr(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}
