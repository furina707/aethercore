//! 全协议代理核心入口。
mod cli;
mod config;
mod dns;
mod http;
mod observe;
mod relay;
mod route;
mod server;
mod socks;
mod state;
mod tls;
mod transparent;

use anyhow::Result;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    // 安装 rustls 默认 crypto provider（用于 TLS）
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args = cli::parse();

    // --check 模式：仅校验配置文件，不启动服务
    if args.check_only {
        tracing::info!(
            mode = "check",
            config = %args.config,
            "进入配置校验模式（不启动服务）"
        );
        return run_check(&args.config);
    }

    // 安装 Ctrl+C / SIGTERM 信号处理，触发优雅退出
    install_signal_handlers();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %args.config,
        log_level_override = ?args.log_level_override,
        "全协议代理核心启动"
    );
    server::run(&args.config, args.log_level_override.as_deref()).await
}

/// 配置校验模式：加载 + validate，打印结果后退出。
fn run_check(config_path: &str) -> Result<()> {
    match config::Config::load(Path::new(config_path)) {
        Ok(cfg) => {
            println!("✓ 配置文件合法: {}", config_path);
            println!("  - 监听器: {} 个", cfg.server.listeners.len());
            println!("  - 出站链路: {} 个", cfg.outbounds.len());
            println!("  - 路由规则: {} 条", cfg.routing.len());
            println!(
                "  - 热重载: {}",
                cfg.hot_reload_secs
                    .map(|s| format!("{}s", s))
                    .unwrap_or_else(|| "未启用".into())
            );
            println!(
                "  - 健康检查: {}",
                cfg.health_check
                    .as_ref()
                    .map(|_| "启用".to_string())
                    .unwrap_or_else(|| "未启用".into())
            );
            tracing::info!(
                mode = "check",
                config = config_path,
                listeners = cfg.server.listeners.len(),
                outbounds = cfg.outbounds.len(),
                routes = cfg.routing.len(),
                "配置校验通过"
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                mode = "check",
                config = config_path,
                error = ?e,
                "配置校验失败"
            );
            eprintln!("✗ 配置文件校验失败: {}", config_path);
            eprintln!("  错误: {:?}", e);
            std::process::exit(1);
        }
    }
}

/// 安装 Ctrl+C（Windows/Linux）与 SIGTERM（Linux）信号处理。
/// 收到信号后打印日志并设置全局退出标志。各监听器 select 该标志后会优雅退出。
fn install_signal_handlers() {
    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::warn!(error = ?e, "注册 ctrl_c 失败");
                return;
            }
        };

        #[cfg(unix)]
        let term = async {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "注册 SIGTERM 失败");
                    // 永远挂起，不触发
                    std::future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let term = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!(signal = "ctrl_c", "收到退出信号，开始优雅退出");
            }
            _ = term => {
                tracing::info!(signal = "sigterm", "收到退出信号，开始优雅退出");
            }
        }

        // 给监听器一点时间优雅收尾，然后强制退出
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // 还原系统代理设置（PAC 模式）：因 process::exit 不会执行 Drop，必须显式调用
        crate::transparent::pac::restore_system_proxy();
        tracing::info!(signal = "exit", "进程退出");
        std::process::exit(0);
    });
}
