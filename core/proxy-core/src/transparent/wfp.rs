//! 透明代理方案3：WFP 重定向（Windows 内核级 TCP 透明重定向）。
//!
//! ⚠️ 注意：WFP callout 需要内核驱动支撑，当前仅提供用户态脚手架。
//! 需要配套内核驱动 `omni-proxy-wfp.sys` 才能实现真正的重定向。
use crate::config::WfpConfig;
use anyhow::Result;

#[cfg(windows)]
pub async fn run_wfp(cfg: &WfpConfig) -> Result<()> {
    tracing::warn!(
        "WFP 重定向请求：本机端口 {}，目标端口 {:?}，例外 {:?}（需管理员 + 内核驱动）\
         当前版本暂未实现完整 WFP 功能，请改用方案1(PAC)或方案2(Wintun)。",
        cfg.redirect_port,
        cfg.target_ports,
        cfg.bypass_ports
    );
    Ok(())
}

#[cfg(not(windows))]
pub async fn run_wfp(_cfg: &WfpConfig) -> Result<()> {
    anyhow::bail!("WFP 仅支持 Windows 平台");
}