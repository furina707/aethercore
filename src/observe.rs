//! 可观测性：日志初始化 + 连接统计。
use crate::config::ObservabilityConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// 连接统计计数器内部数据（原子量，跨线程共享）。
#[derive(Default)]
struct StatsInner {
    connections: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    active: AtomicU64,
    errors: AtomicU64,
}

/// 全局连接统计句柄，内部用 Arc 共享，可廉价 clone。
#[derive(Clone, Default)]
pub struct Stats {
    inner: Arc<StatsInner>,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_conn_start(&self) {
        self.inner.connections.fetch_add(1, Ordering::Relaxed);
        self.inner.active.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_conn_end(&self) {
        self.inner.active.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn record_bytes(&self, inb: u64, outb: u64) {
        self.inner.bytes_in.fetch_add(inb, Ordering::Relaxed);
        self.inner.bytes_out.fetch_add(outb, Ordering::Relaxed);
    }
    pub fn record_error(&self) {
        self.inner.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// 初始化 tracing 日志。
pub fn init_logging(cfg: &ObservabilityConfig) {
    let filter = cfg.log_level.as_str();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();
}

/// 启动周期性统计打印任务。
pub fn spawn_stats_reporter(cfg: &ObservabilityConfig, stats: Arc<Stats>) -> Option<JoinHandle<()>> {
    if !cfg.stats {
        return None;
    }
    let interval = Duration::from_secs(cfg.stats_interval_secs.max(1));
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            tracing::info!(
                total = stats.inner.connections.load(Ordering::Relaxed),
                active = stats.inner.active.load(Ordering::Relaxed),
                in_mb = stats.inner.bytes_in.load(Ordering::Relaxed) / (1024 * 1024),
                out_mb = stats.inner.bytes_out.load(Ordering::Relaxed) / (1024 * 1024),
                errors = stats.inner.errors.load(Ordering::Relaxed),
                "proxy stats"
            );
        }
    }))
}
