//! 共享运行时状态：原子热更新的配置 + 出站链路健康状态。
//! 监听器持有一个 Arc<ProxyState>，所有路由/出站决策实时读取，
//! 支持配置热重载与健康探测故障转移。
use crate::config::{Config, HealthCheckConfig, Outbound, OutboundProtocol};
use crate::route::RouteRequest;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// 单条出站链路的健康记录。
#[derive(Debug, Default, Clone, Copy)]
pub struct Health {
    pub alive: bool,
    pub consecutive_failures: u32,
    pub last_checked: Option<Instant>,
}

/// 代理运行时共享状态。
pub struct ProxyState {
    /// 当前生效配置（可原子替换）
    config: ArcSwap<Config>,
    /// 各 outbound 健康状态，按 name 索引
    health: RwLock<HashMap<String, Health>>,
}

impl ProxyState {
    pub fn new(config: Config) -> Arc<Self> {
        let mut h = HashMap::new();
        for ob in &config.outbounds {
            h.insert(ob.name.clone(), Health { alive: true, ..Default::default() });
        }
        Arc::new(Self {
            config: ArcSwap::from_pointee(config),
            health: RwLock::new(h),
        })
    }

    /// 当前配置快照。
    pub fn config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// 原子热替换配置（外部热重载任务调用）。
    pub fn reload(&self, cfg: Config) {
        // 合并健康状态：保留既有记录，新增链路默认存活
        tokio::task::block_in_place(|| {
            let mut map = self.health.blocking_write();
            for ob in &cfg.outbounds {
                map.entry(ob.name.clone()).or_insert(Health { alive: true, ..Default::default() });
            }
        });
        self.config.store(Arc::new(cfg));
    }

    /// 上报一次出站探测结果。
    pub async fn report_health(&self, name: &str, ok: bool) {
        let mut map = self.health.write().await;
        let e = map.entry(name.to_string()).or_default();
        if ok {
            e.alive = true;
            e.consecutive_failures = 0;
        } else {
            e.consecutive_failures += 1;
            if e.consecutive_failures >= 3 {
                e.alive = false;
            }
        }
        e.last_checked = Some(Instant::now());
    }

    /// 选择出站链路名：先按路由规则，命中死链则回退到任意存活链路，
    /// 全部不可用时回退到 "direct"。
    pub async fn select_outbound(&self, req: &RouteRequest) -> String {
        let cfg = self.config();
        let chosen = crate::route::select_outbound(&cfg, req);
        let health = self.health.read().await;
        if health.get(&chosen).map(|h| h.alive).unwrap_or(true) {
            return chosen;
        }
        // 故障转移：在同协议出站中挑一个存活的
        if let Some(ob) = cfg.outbounds.iter().find(|o| o.name == chosen) {
            let proto = ob.protocol;
            if let Some(fb) = cfg
                .outbounds
                .iter()
                .find(|o| o.protocol == proto && health.get(&o.name).map(|h| h.alive).unwrap_or(true))
            {
                return fb.name.clone();
            }
        }
        "direct".to_string()
    }

    /// 后台健康探测任务：对每个 outbound 做 TCP 连通性探测。
    pub async fn run_health_check(self: Arc<Self>) {
        let cfg = self.config();
        let hc: HealthCheckConfig = match &cfg.health_check {
            Some(h) => h.clone(),
            None => return, // 未启用健康探测
        };
        let interval = Duration::from_secs(hc.interval_secs.max(1));
        let timeout = Duration::from_secs(hc.timeout_secs.max(1));
        loop {
            let cfg = self.config();
            for ob in &cfg.outbounds {
                if ob.name == "direct" {
                    continue; // 直连无需探测
                }
                let ok = probe(ob, timeout).await;
                self.report_health(&ob.name, ok).await;
                tracing::debug!("健康探测 {} -> {}", ob.name, if ok { "alive" } else { "dead" });
            }
            tokio::time::sleep(interval).await;
        }
    }
}

/// 对单条出链路做 TCP 探测。relay/direct 探测其 target；
/// 上游代理类探测到上游地址的连通性。
async fn probe(ob: &Outbound, timeout: Duration) -> bool {
    let target = match ob.protocol {
        OutboundProtocol::Direct => {
            // direct 无明确 target（0.0.0.0:0），跳过
            if ob.target == "0.0.0.0:0" {
                return true;
            }
            ob.target.clone()
        }
        _ => ob.target.clone(),
    };
    if let Ok(addrs) = target.to_socket_addrs() {
        if let Some(addr) = addrs.into_iter().next() {
            return tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
                .await
                .is_ok();
        }
    }
    false
}
