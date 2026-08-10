//! 规则路由/分流引擎。根据目标域名、IP、端口选择出站链路。
use crate::config::{Config, RouteRule};
use std::net::IpAddr;

/// 一次连接请求的路由上下文。
#[derive(Debug, Clone, Default)]
pub struct RouteRequest {
    pub domain: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: u16,
}

/// 路由决策结果：返回出站链路名。
pub fn select_outbound(cfg: &Config, req: &RouteRequest) -> String {
    for rule in &cfg.routing {
        if matches(rule, req) {
            return rule.outbound.clone();
        }
    }
    "direct".to_string()
}

fn matches(rule: &RouteRule, req: &RouteRequest) -> bool {
    let mut hit = false;
    let mut any_checked = false;

    if !rule.domain_suffix.is_empty() {
        any_checked = true;
        if let Some(d) = &req.domain {
            let d_lower = d.to_lowercase();
            if rule
                .domain_suffix
                .iter()
                .any(|s| d_lower == s.to_lowercase() || d_lower.ends_with(&format!(".{}", s)))
            {
                hit = true;
            }
        }
    }

    if !rule.ip_cidr.is_empty() {
        any_checked = true;
        if let Some(ip) = req.ip {
            if rule.ip_cidr.iter().any(|c| cidr_contains(c, ip)) {
                hit = true;
            }
        }
    }

    if !rule.port.is_empty() {
        any_checked = true;
        if rule.port.contains(&req.port) {
            hit = true;
        }
    }

    if !any_checked {
        return false;
    }
    match rule.match_mode {
        crate::config::MatchMode::Any => hit,
        crate::config::MatchMode::All => {
            // all 模式下，所有已配置的维度都必须命中
            let domain_ok = rule.domain_suffix.is_empty()
                || req
                    .domain
                    .as_ref()
                    .map(|d| {
                        let d = d.to_lowercase();
                        rule.domain_suffix
                            .iter()
                            .any(|s| d == s.to_lowercase() || d.ends_with(&format!(".{}", s)))
                    })
                    .unwrap_or(false);
            let ip_ok = rule.ip_cidr.is_empty()
                || req.ip.map(|ip| rule.ip_cidr.iter().any(|c| cidr_contains(c, ip))).unwrap_or(false);
            let port_ok = rule.port.is_empty() || rule.port.contains(&req.port);
            domain_ok && ip_ok && port_ok
        }
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, b.parse::<u8>().unwrap_or(32)),
        None => (cidr, if ip.is_ipv4() { 32 } else { 128 }),
    };
    let net: IpAddr = match net.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(ip)) => {
            let mask = if bits == 0 { 0u32 } else { u32::MAX << (32 - bits) };
            let n = u32::from(n);
            let ip = u32::from(ip);
            (n & mask) == (ip & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(ip)) => {
            let n = u128::from(n);
            let ip = u128::from(ip);
            let mask = if bits == 0 { 0u128 } else { u128::MAX << (128 - bits) };
            (n & mask) == (ip & mask)
        }
        _ => false,
    }
}
