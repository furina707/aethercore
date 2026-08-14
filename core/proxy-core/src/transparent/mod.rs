//! 透明代理模块：Windows 下三种透明方案统一入口。
//!   - pac.rs      方案1：系统代理 / PAC 自动配置（用户态，无需管理员）
//!   - wfp.rs      方案3：WFP 重定向（内核级 TCP 透明重定向，需管理员 + callout 驱动）
//!   - wintun_tun.rs 方案2：Wintun 虚拟网卡 TUN（用户态捕获流量，需 wintun.dll + 管理员）
pub mod pac;
pub mod wfp;
pub mod wintun_tun;

use anyhow::Result;
use std::sync::Arc;
use crate::config::TransparentConfig;
use crate::state::ProxyState;

/// 根据配置启动所有启用的透明代理方案。
pub async fn run_transparent(cfg: &TransparentConfig, state: Arc<ProxyState>) -> Result<()> {
    if let Some(pac) = &cfg.pac {
        let pac = pac.clone();
        tracing::info!(scheme = "pac", bind = ?pac.bind, "透明代理方案 1（PAC）启动中");
        tokio::spawn(async move {
            if let Err(e) = pac::run_pac(&pac).await {
                tracing::error!(scheme = "pac", error = ?e, "PAC 服务异常退出");
            }
        });
    } else {
        tracing::info!(scheme = "pac", "PAC 方案未配置，跳过");
    }
    if let Some(wfp) = &cfg.wfp {
        let wfp = wfp.clone();
        tracing::info!(scheme = "wfp", "透明代理方案 3（WFP）启动中（需管理员 + callout 驱动）");
        tokio::spawn(async move {
            if let Err(e) = wfp::run_wfp(&wfp).await {
                tracing::error!(scheme = "wfp", error = ?e, "WFP 重定向异常退出");
            }
        });
    } else {
        tracing::info!(scheme = "wfp", "WFP 方案未配置，跳过");
    }
    if let Some(wt) = &cfg.wintun {
        let wt = wt.clone();
        tracing::info!(scheme = "wintun", adapter = ?wt.adapter_name, redirect_port = ?wt.redirect_port, "透明代理方案 2（Wintun TUN）启动中（需管理员 + wintun.dll）");
        tokio::spawn(async move {
            if let Err(e) = wintun_tun::run_wintun(&wt, state.clone()).await {
                tracing::error!(scheme = "wintun", error = ?e, "Wintun 异常退出");
            }
        });
    } else {
        tracing::info!(scheme = "wintun", "Wintun 方案未配置，跳过");
    }
    Ok(())
}
