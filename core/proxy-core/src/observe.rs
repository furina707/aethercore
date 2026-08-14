//! 可观测性：日志初始化 + 连接统计 + UI 数据导出。
use crate::config::ObservabilityConfig;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing_appender::rolling;
use tracing_subscriber::prelude::*;

/// 连接统计计数器内部数据（原子量，跨线程共享）。
pub struct StatsInner {
    pub connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active: AtomicU64,
    pub errors: AtomicU64,
    pub start_time: std::time::Instant,
}

/// 统计快照（用于 JSON 序列化）。
#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
    pub uptime_secs: u64,
    pub bytes_in_human: String,
    pub bytes_out_human: String,
}

/// 全局连接统计句柄，内部用 Arc 共享，可廉价 clone。
#[derive(Clone)]
pub struct Stats {
    pub inner: Arc<StatsInner>,
    /// 每条出站链路的累计统计，按 outbound name 索引
    pub per_outbound: Arc<std::sync::RwLock<HashMap<String, OutboundCounters>>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            inner: Arc::new(StatsInner {
                connections: AtomicU64::new(0),
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                active: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                start_time: std::time::Instant::now(),
            }),
            per_outbound: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
}

/// 单条出站链路的累计计数器。
#[derive(Debug, Clone, Default, Serialize)]
pub struct OutboundCounters {
    /// 累计连接数（含已结束）
    pub connections: u64,
    /// 当前活跃连接数
    pub active: u64,
    /// 累计失败/错误数
    pub errors: u64,
    /// 客户端 -> 上游 累计字节数（上传）
    pub bytes_up: u64,
    /// 上游 -> 客户端 累计字节数（下载）
    pub bytes_down: u64,
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

    /// 获取统计快照（用于 UI/API）。
    pub fn snapshot(&self) -> StatsSnapshot {
        let uptime = self.inner.start_time.elapsed().as_secs();
        let bytes_in = self.inner.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.inner.bytes_out.load(Ordering::Relaxed);
        StatsSnapshot {
            total_connections: self.inner.connections.load(Ordering::Relaxed),
            active_connections: self.inner.active.load(Ordering::Relaxed),
            bytes_in,
            bytes_out,
            errors: self.inner.errors.load(Ordering::Relaxed),
            uptime_secs: uptime,
            bytes_in_human: format_bytes(bytes_in),
            bytes_out_human: format_bytes(bytes_out),
        }
    }

    /// 记录一次出站连接开始（按 outbound name 计数）。
    pub fn outbound_conn_start(&self, name: &str) {
        if let Ok(mut m) = self.per_outbound.write() {
            let c = m.entry(name.to_string()).or_default();
            c.connections += 1;
            c.active += 1;
        }
    }

    /// 记录一次出站连接结束。
    pub fn outbound_conn_end(&self, name: &str) {
        if let Ok(mut m) = self.per_outbound.write() {
            if let Some(c) = m.get_mut(name) {
                if c.active > 0 {
                    c.active -= 1;
                }
            }
        }
    }

    /// 记录一次出站连接错误。
    pub fn outbound_error(&self, name: &str) {
        if let Ok(mut m) = self.per_outbound.write() {
            let c = m.entry(name.to_string()).or_default();
            c.errors += 1;
        }
    }

    /// 记录一次出站连接的字节流量。
    /// `bytes_up` = 客户端 -> 上游，`bytes_down` = 上游 -> 客户端
    pub fn outbound_bytes(&self, name: &str, bytes_up: u64, bytes_down: u64) {
        if let Ok(mut m) = self.per_outbound.write() {
            let c = m.entry(name.to_string()).or_default();
            c.bytes_up += bytes_up;
            c.bytes_down += bytes_down;
        }
    }

    /// 取所有出站链路的累计统计快照（用于 UI/API）。
    pub fn outbound_snapshot(&self) -> Vec<(String, OutboundCounters)> {
        if let Ok(m) = self.per_outbound.read() {
            let mut list: Vec<_> = m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            list.sort_by(|a, b| a.0.cmp(&b.0));
            list
        } else {
            Vec::new()
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// 初始化 tracing 日志。
/// `override_level`：命令行 -v/-q 提供的日志级别，优先于配置文件。
/// 优先级：RUST_LOG 环境变量 > 命令行 -v/-q > 配置文件 log_level。
///
/// 日志同时写入：
/// 1. 控制台（stdout），便于实时观察；
/// 2. 文件：`<log_dir>/omni-proxy-YYYY-MM-DD.log`，按天滚动（默认目录 "log"）。
pub fn init_logging(cfg: &ObservabilityConfig, override_level: Option<&str>) {
    let filter = override_level.unwrap_or(cfg.log_level.as_str());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    // 控制台 layer（带颜色、文件/行号）
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(true)
        .with_file(true)
        .with_line_number(true)
        .with_writer(std::io::stdout);

    // 文件 layer：按天滚动到 <log_dir>/omni-proxy-YYYY-MM-DD.log（无颜色）
    let log_dir = if cfg.log_dir.is_empty() {
        "log".to_string()
    } else {
        cfg.log_dir.clone()
    };
    let file_appender = rolling::daily(&log_dir, "omni-proxy");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    // 全局持有 guard 直到进程结束，否则缓冲中的日志可能丢失
    FILE_GUARD.get_or_init(|| guard);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_file(true)
        .with_line_number(true)
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_counters() {
        let stats = Stats::new();
        stats.record_conn_start();
        stats.record_bytes(100, 50);
        let s = stats.snapshot();
        assert_eq!(s.total_connections, 1);
        assert_eq!(s.active_connections, 1);
        assert_eq!(s.bytes_in, 100);
        assert_eq!(s.bytes_out, 50);
        stats.record_conn_end();
        assert_eq!(stats.snapshot().active_connections, 0);
        stats.record_error();
        assert_eq!(stats.snapshot().errors, 1);
    }

    #[test]
    fn per_outbound_counters() {
        let stats = Stats::new();
        stats.outbound_conn_start("socks5");
        stats.outbound_bytes("socks5", 10, 20);
        let mut list = stats.outbound_snapshot();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "socks5");
        assert_eq!(list[0].1.connections, 1);
        assert_eq!(list[0].1.bytes_up, 10);
        assert_eq!(list[0].1.bytes_down, 20);
        stats.outbound_conn_end("socks5");
        list = stats.outbound_snapshot();
        assert_eq!(list[0].1.active, 0);
        stats.outbound_error("socks5");
        assert_eq!(stats.outbound_snapshot()[0].1.errors, 1);
    }

    #[test]
    fn format_bytes_human() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }
}

/// 持有文件日志 worker guard，确保缓冲日志在进程退出前被刷盘。
static FILE_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

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