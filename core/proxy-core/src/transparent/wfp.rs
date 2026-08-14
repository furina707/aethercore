//! 透明代理方案3：WFP 重定向（Windows 内核级 TCP 透明重定向）。
//!
//! # 两种落地方式
//! 1. **WFP 内建 ALE Redirect（推荐，纯用户态，无需自研驱动）**
//!    借助 WFP 的 `FWPM_LAYER_ALE_REDIRECT_V{4,6}` 层，把命中的出站 TCP
//!    连接重定向到本机代理监听端口。该能力自 Windows 8 起内置于 WFP，
//!    只需用户态管理 API（fwpuclnt.dll，经 `windows` crate 的
//!    `Windows.Win32.NetworkManagement.WindowsFilteringPlatform` 调用），
//!    **不需要自研内核驱动**。
//! 2. **自定义 Callout 驱动 `omni-proxy-wfp.sys`（完全控制）**
//!    若需要更精细的 TCP 流重写（保留原始目标、做 TLS 拦截等），需编写
//!    内核 Callout 驱动并配套用户态管理程序。本仓库当前**未提供**该 sys
//!    文件，故方案2（Wintun）才是真正可用的内核旁路透明方案。
//!
//! # 当前状态
//! 本文件仅提供**用户态管理引擎骨架**与清晰的实现路线；两种方式的代码
//! 均**尚未完整实现**（缺 WFP 管理 API 调用 + 内核驱动）。在 WFP 就绪前，
//! 生产可用请优先采用方案1（PAC，已可用）或方案2（Wintun，已实现）。
//!
//! # 用户态 WFP 引擎骨架（方式1 的轮廓）
//! - `open_engine()`          打开 FWPM 引擎（FwpmEngineOpen0）
//! - `install_redirect()`     在 ALE_REDIRECT 层注册重定向过滤器（FwpmFilterAdd0），
//!                            把命中 `target_ports` 的连接改向本机 `redirect_port`
//! - `uninstall()`            卸载过滤器并关闭引擎
//!
//! 这些步骤依赖 `windows` crate 的 WFP 特性；为避免误编译，本骨架只声明
//! 结构并输出明确 TODO 日志，待 WFP 管理 API 接入后再填充真实调用。
use crate::config::WfpConfig;
use anyhow::Result;

/// WFP 用户态管理引擎（骨架）。
///
/// 真实实现需要在 `open_engine()` 中调用 WFP 管理 API，在
/// `install_redirect()` 中于 `FWPM_LAYER_ALE_REDIRECT_V4` 注册过滤器。
/// 这些调用依赖 `windows` crate 的 WFP 特性，本骨架暂不展开调用，
/// 仅记录日志与实现路线，避免误编译。
#[cfg(windows)]
pub struct WfpEngine {
    cfg: WfpConfig,
}

#[cfg(windows)]
impl WfpEngine {
    pub fn new(cfg: WfpConfig) -> Self {
        Self { cfg }
    }

    /// 打开 FWPM 引擎（FwpmEngineOpen0）。TODO: 调用真实 WFP 管理 API。
    pub fn open_engine(&self) -> Result<()> {
        tracing::warn!(
            redirect_port = self.cfg.redirect_port,
            "WFP: open_engine 待实现（需 FwpmEngineOpen0 / WFP 管理 API）"
        );
        Ok(())
    }

    /// 在 ALE_REDIRECT 层添加重定向过滤器，把命中 `target_ports` 的
    /// 出站 TCP 连接改向本机 `redirect_port`。
    /// TODO: FwpmFilterAdd0 + FWPM_LAYER_ALE_REDIRECT_V4。
    pub fn install_redirect(&self) -> Result<()> {
        tracing::warn!(
            target_ports = ?self.cfg.target_ports,
            bypass_ports = ?self.cfg.bypass_ports,
            "WFP: install_redirect 待实现（需 FwpmFilterAdd0 + ALE_REDIRECT 层）"
        );
        Ok(())
    }

    /// 卸载过滤器并关闭引擎。TODO: FwpmFilterDeleteByKey0 / FwpmEngineClose0。
    pub fn uninstall(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
pub async fn run_wfp(cfg: &WfpConfig) -> Result<()> {
    tracing::warn!(
        redirect_port = cfg.redirect_port,
        target_ports = ?cfg.target_ports,
        bypass_ports = ?cfg.bypass_ports,
        "WFP 重定向请求（需管理员）。当前版本尚未实现完整 WFP 功能：\
         方式1 需调用 WFP 管理 API 注册 ALE_REDIRECT 过滤器（纯用户态）；\
         方式2 需配套内核驱动 omni-proxy-wfp.sys。请改用方案1(PAC) 或方案2(Wintun)。"
    );
    // 骨架流程：打开引擎 → 安装重定向过滤器 → 待关闭信号卸载。
    let engine = WfpEngine::new(cfg.clone());
    engine.open_engine()?;
    engine.install_redirect()?;
    // TODO: 等待关闭信号后 engine.uninstall()。
    Ok(())
}

#[cfg(not(windows))]
pub async fn run_wfp(_cfg: &WfpConfig) -> Result<()> {
    anyhow::bail!("WFP 仅支持 Windows 平台");
}
