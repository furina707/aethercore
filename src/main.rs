//! 全协议代理核心入口。
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

#[tokio::main]
async fn main() -> Result<()> {
    // 安装 rustls 默认 crypto provider（用于 TLS）
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).map(String::as_str).unwrap_or("config.yaml");
    tracing::info!("全协议代理核心启动，配置: {}", config_path);
    server::run(config_path).await
}
