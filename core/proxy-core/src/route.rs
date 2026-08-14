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
    for (idx, rule) in cfg.routing.iter().enumerate() {
        if matches(rule, req) {
            tracing::info!(
                rule_index = idx,
                rule_name = ?rule.name,
                match_mode = ?rule.match_mode,
                outbound = %rule.outbound,
                req_domain = ?req.domain,
                req_ip = ?req.ip,
                req_port = req.port,
                "路由命中规则"
            );
            return rule.outbound.clone();
        }
    }
    tracing::info!(
        req_domain = ?req.domain,
        req_ip = ?req.ip,
        req_port = req.port,
        "路由未命中任何规则，回退 direct"
    );
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
                .any(|s| {
                    let s_lower = s.to_lowercase();
                    d_lower == s_lower || d_lower.ends_with(&format!(".{}", s_lower))
                })
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
                        rule.domain_suffix.iter().any(|s| {
                            let s = s.to_lowercase();
                            d == s || d.ends_with(&format!(".{}", s))
                        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Listener, ListenerProtocol, MatchMode, Outbound, OutboundProtocol, RouteRule, ServerConfig};

    /// 构造一个最小可用配置：direct + 一个名为 "proxy" 的出站，
    /// 以及一组传入的路由规则。便于规则匹配测试。
    fn cfg_with_rules(rules: Vec<RouteRule>) -> Config {
        Config {
            server: ServerConfig {
                listeners: vec![Listener {
                    protocol: ListenerProtocol::Http,
                    bind: "0.0.0.0:8080".into(),
                    tls: false,
                    transparent: false,
                    auth: None,
                }],
            },
            tls: None,
            outbounds: vec![
                Outbound {
                    name: "direct".into(),
                    protocol: OutboundProtocol::Direct,
                    target: "0.0.0.0:0".into(),
                    tls: false,
                    sni: None,
                    auth: None,
                    pool_size: 0,
                    retries: 0,
                    timeout_secs: 10,
                },
                Outbound {
                    name: "proxy".into(),
                    protocol: OutboundProtocol::Socks5,
                    target: "127.0.0.1:1080".into(),
                    tls: false,
                    sni: None,
                    auth: None,
                    pool_size: 0,
                    retries: 0,
                    timeout_secs: 10,
                },
            ],
            routing: rules,
            observability: Default::default(),
            hot_reload_secs: None,
            health_check: None,
            transparent: None,
        }
    }

    fn req_domain(domain: &str, port: u16) -> RouteRequest {
        RouteRequest {
            domain: Some(domain.into()),
            ip: None,
            port,
        }
    }

    fn req_ip(ip: &str, port: u16) -> RouteRequest {
        RouteRequest {
            domain: None,
            ip: ip.parse().ok(),
            port,
        }
    }

    // ===== select_outbound 默认行为 =====

    #[test]
    fn no_rules_falls_back_to_direct() {
        let cfg = cfg_with_rules(vec![]);
        assert_eq!(select_outbound(&cfg, &req_domain("example.com", 80)), "direct");
    }

    #[test]
    fn unmatched_rule_falls_back_to_direct() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec![],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        // 不匹配的域名应回退 direct
        assert_eq!(select_outbound(&cfg, &req_domain("other.com", 80)), "direct");
    }

    // ===== 域名后缀匹配 =====

    #[test]
    fn domain_suffix_exact_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: Some("t".into()),
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec![],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_domain("example.com", 80)), "proxy");
    }

    #[test]
    fn domain_suffix_subdomain_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec![],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_domain("www.example.com", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_domain("a.b.example.com", 80)), "proxy");
    }

    #[test]
    fn domain_suffix_case_insensitive() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec!["Example.COM".into()],
            ip_cidr: vec![],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_domain("WWW.example.com", 80)), "proxy");
    }

    #[test]
    fn domain_suffix_not_prefix_match() {
        // "evilexample.com" 不应匹配 "example.com" 后缀（必须是 .example.com 或精确）
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec![],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_domain("evilexample.com", 80)), "direct");
    }

    // ===== CIDR 匹配 =====

    #[test]
    fn cidr_v4_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec![],
            ip_cidr: vec!["10.0.0.0/8".into()],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_ip("10.1.2.3", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("10.255.255.255", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("11.0.0.1", 80)), "direct");
    }

    #[test]
    fn cidr_v6_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec![],
            ip_cidr: vec!["2001:db8::/32".into()],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_ip("2001:db8::1", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("2001:db8:abcd::1", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("2001:db9::1", 80)), "direct");
    }

    #[test]
    fn cidr_32_host_route() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec![],
            ip_cidr: vec!["1.2.3.4/32".into()],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_ip("1.2.3.4", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("1.2.3.5", 80)), "direct");
    }

    #[test]
    fn cidr_0_catch_all_v4() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec![],
            ip_cidr: vec!["0.0.0.0/0".into()],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_ip("8.8.8.8", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("127.0.0.1", 80)), "proxy");
    }

    #[test]
    fn cidr_invalid_returns_false() {
        // 非法 CIDR 不应 panic，应返回 false（不匹配）
        assert!(!cidr_contains("not-an-ip", "10.0.0.1".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/8", "2001:db8::1".parse().unwrap())); // v4 vs v6
    }

    // ===== 端口匹配 =====

    #[test]
    fn port_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec![],
            ip_cidr: vec![],
            port: vec![22, 3389],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_domain("any.com", 22)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_domain("any.com", 3389)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_domain("any.com", 80)), "direct");
    }

    // ===== MatchMode::All =====

    #[test]
    fn match_mode_all_requires_all_dimensions() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec!["10.0.0.0/8".into()],
            port: vec![443],
            match_mode: MatchMode::All,
            outbound: "proxy".into(),
        }]);
        // 三个维度都命中
        let req_all = RouteRequest {
            domain: Some("www.example.com".into()),
            ip: Some("10.1.1.1".parse().unwrap()),
            port: 443,
        };
        assert_eq!(select_outbound(&cfg, &req_all), "proxy");

        // 缺一个端口不命中
        let req_no_port = RouteRequest {
            domain: Some("www.example.com".into()),
            ip: Some("10.1.1.1".parse().unwrap()),
            port: 80,
        };
        assert_eq!(select_outbound(&cfg, &req_no_port), "direct");

        // 缺 IP 不命中
        let req_no_ip = RouteRequest {
            domain: Some("www.example.com".into()),
            ip: None,
            port: 443,
        };
        assert_eq!(select_outbound(&cfg, &req_no_ip), "direct");
    }

    #[test]
    fn match_mode_any_any_dimension_suffices() {
        let cfg = cfg_with_rules(vec![RouteRule {
            name: None,
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec!["10.0.0.0/8".into()],
            port: vec![443],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        // 任一命中即可
        assert_eq!(select_outbound(&cfg, &req_domain("example.com", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_ip("10.1.1.1", 80)), "proxy");
        assert_eq!(select_outbound(&cfg, &req_domain("other.com", 443)), "proxy");
    }

    // ===== 规则顺序 =====

    #[test]
    fn first_matching_rule_wins() {
        let cfg = cfg_with_rules(vec![
            RouteRule {
                name: Some("first".into()),
                domain_suffix: vec!["example.com".into()],
                ip_cidr: vec![],
                port: vec![],
                match_mode: MatchMode::Any,
                outbound: "proxy".into(),
            },
            RouteRule {
                name: Some("second".into()),
                domain_suffix: vec!["example.com".into()],
                ip_cidr: vec![],
                port: vec![],
                match_mode: MatchMode::Any,
                outbound: "direct".into(),
            },
        ]);
        // 第一条命中即采用 proxy，第二条不会再覆盖
        assert_eq!(select_outbound(&cfg, &req_domain("example.com", 80)), "proxy");
    }

    // ===== 空规则 =====

    #[test]
    fn empty_rule_does_not_match() {
        // 所有维度都为空的规则不应匹配任何请求（避免误命中"默认代理"）
        let cfg = cfg_with_rules(vec![RouteRule {
            name: Some("empty".into()),
            domain_suffix: vec![],
            ip_cidr: vec![],
            port: vec![],
            match_mode: MatchMode::Any,
            outbound: "proxy".into(),
        }]);
        assert_eq!(select_outbound(&cfg, &req_domain("anything.com", 80)), "direct");
    }
}
