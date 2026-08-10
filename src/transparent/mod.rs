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
        tokio::spawn(async move {
            if let Err(e) = pac::run_pac(&pac).await {
                tracing::error!("PAC 服务异常: {:?}", e);
            }
        });
    }
    if let Some(wfp) = &cfg.wfp {
        let wfp = wfp.clone();
        tokio::spawn(async move {
            if let Err(e) = wfp::run_wfp(&wfp).await {
                tracing::error!("WFP 重定向异常: {:?}", e);
            }
        });
    }
    if let Some(wt) = &cfg.wintun {
        let wt = wt.clone();
        tokio::spawn(async move {
            if let Err(e) = wintun_tun::run_wintun(&wt, state.clone()).await {
                tracing::error!("Wintun 异常: {:?}", e);
            }
        });
    }
    Ok(())
}
