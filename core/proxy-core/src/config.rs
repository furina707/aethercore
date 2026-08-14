//! 配置加载：多协议监听、路由规则、TLS、可观测性。
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// 完整代理配置。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// 全局监听/转发参数
    pub server: ServerConfig,
    /// TLS 配置（服务端证书 + 可选双向认证）
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// 出站链路定义，路由规则引用其 name
    pub outbounds: Vec<Outbound>,
    /// 路由规则，按顺序匹配，命中即采用对应 outbound
    #[serde(default)]
    pub routing: Vec<RouteRule>,
    /// 可观测性
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// 热重载：定时重新读取配置文件并原子替换（秒）
    #[serde(default)]
    pub hot_reload_secs: Option<u64>,
    /// 健康探测：对 outbounds 做周期性存活检测，死链从路由中剔除
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// 透明代理配置（Windows 三种方案：PAC / Wintun TUN / WFP 重定向）
    #[serde(default)]
    pub transparent: Option<TransparentConfig>,
}

/// 透明代理总开关与各方案子配置。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TransparentConfig {
    /// 方案1：系统代理 / PAC 自动配置
    #[serde(default)]
    pub pac: Option<PacConfig>,
    /// 方案2：Wintun 虚拟网卡 TUN 透明拦截（需 wintun.dll）
    #[serde(default)]
    pub wintun: Option<WintunConfig>,
    /// 方案3：WFP 重定向（内核级 TCP 透明重定向到本地代理端口）
    #[serde(default)]
    pub wfp: Option<WfpConfig>,
}

/// 方案1：PAC 自动配置服务。
/// 进程内起一个最小 HTTP 服务，返回 PAC 脚本，并把系统代理指向它。
#[derive(Debug, Clone, Deserialize)]
pub struct PacConfig {
    /// PAC 服务监听地址，如 "127.0.0.1:15080"
    pub bind: String,
    /// 实际要使用的代理（HTTP/SOCKS），如 "PROXY 127.0.0.1:18080"
    pub proxy: String,
    /// 是否自动设置系统代理（需要管理员/足够权限，失败仅告警）
    #[serde(default)]
    pub set_system_proxy: bool,
    /// PAC 脚本可代理的目标端口（空=全部）
    #[serde(default)]
    pub proxy_ports: Vec<u16>,
    /// 直连域名后缀（不走代理）
    #[serde(default)]
    pub bypass_domains: Vec<String>,
}

/// 方案2：Wintun TUN 虚拟网卡。
#[derive(Debug, Clone, Deserialize)]
pub struct WintunConfig {
    /// wintun.dll 路径（默认从程序目录/系统 PATH 查找）
    #[serde(default)]
    pub dll_path: Option<String>,
    /// 虚拟网卡名
    #[serde(default = "default_wintun_adapter")]
    pub adapter_name: String,
    /// TUN 网段，如 "10.99.0.1/24"
    pub subnet: String,
    /// 本地透明代理监听（TUN 数据包的目标端口，如 SOCKS 端口）
    pub redirect_port: u16,
}

fn default_wintun_adapter() -> String {
    "omni-proxy-tun".into()
}

/// 方案3：WFP 重定向。
/// 把本机出向 TCP（指定端口）透明重定向到本地代理端口。
#[derive(Debug, Clone, Deserialize)]
pub struct WfpConfig {
    /// 本地代理监听端口（被重定向到的端口，如 SOCKS 端口）
    pub redirect_port: u16,
    /// 需要透明重定向的目标端口（如 80/443/53 等），空=全部
    #[serde(default)]
    pub target_ports: Vec<u16>,
    /// 例外目标端口（典型：代理自身端口，避免回环）
    #[serde(default)]
    pub bypass_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// 探测间隔（秒）
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,
    /// 探测超时（秒）
    #[serde(default = "default_hc_timeout")]
    pub timeout_secs: u64,
    /// 连续失败多少次判定为不可用
    #[serde(default = "default_hc_fails")]
    pub max_failures: u32,
}

fn default_hc_interval() -> u64 { 10 }
fn default_hc_timeout() -> u64 { 3 }
fn default_hc_fails() -> u32 { 3 }

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// 入站监听器列表
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    /// 监听协议类型
    pub protocol: ListenerProtocol,
    /// 监听地址，如 "0.0.0.0:1080"
    pub bind: String,
    /// 若该监听器走 TLS（如 HTTPS 代理 / TLS 包装的 SOCKS），指定 tls 配置名
    #[serde(default)]
    pub tls: bool,
    /// 透明代理模式需要的真实目标获取方式（仅 TCP/UDP 透明）
    #[serde(default)]
    pub transparent: bool,
    /// 认证配置（HTTP/SOCKS 代理用）
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

/// 认证配置。
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// 认证类型：basic（HTTP）/ password（SOCKS）
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// 用户名
    pub username: String,
    /// 密码
    pub password: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Basic,
    Password,
}

fn default_auth_type() -> AuthType {
    AuthType::Basic
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Tcp,
    Udp,
    Http,
    Https,
    Socks,
    Dns,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// 证书链 (PEM)
    pub cert: String,
    /// 私钥 (PEM)
    pub key: String,
    /// 可选的客户端 CA，用于 mTLS
    #[serde(default)]
    pub client_ca: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Outbound {
    /// 链路唯一名，路由规则引用
    pub name: String,
    /// 出站协议
    pub protocol: OutboundProtocol,
    /// 目标地址（直连用 host:port；relay 用上游代理）
    pub target: String,
    /// 该出站链路是否用 TLS 包装
    #[serde(default)]
    pub tls: bool,
    /// TLS 主机名（SNI）
    #[serde(default)]
    pub sni: Option<String>,
    /// 认证信息（上游代理需要认证时）
    #[serde(default)]
    pub auth: Option<OutboundAuth>,
    /// 连接池大小（0=禁用）
    #[serde(default)]
    pub pool_size: usize,
    /// 重试次数
    #[serde(default = "default_retries")]
    pub retries: u32,
    /// 超时时间（秒）
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// 出站认证配置。
#[derive(Debug, Clone, Deserialize)]
pub struct OutboundAuth {
    /// 用户名
    pub username: String,
    /// 密码
    pub password: String,
}

fn default_retries() -> u32 { 0 }
fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutboundProtocol {
    /// 直连转发
    Direct,
    /// 经上游 SOCKS5 代理
    Socks5,
    /// 经上游 HTTP(S) 代理
    HttpProxy,
    /// 经上游 Shadowsocks 代理
    Shadowsocks,
    /// 经上游 Vmess 代理
    Vmess,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteRule {
    /// 规则名称（便于排查）
    #[serde(default)]
    pub name: Option<String>,
    /// 匹配域名后缀，如 "example.com"
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// 匹配 IP CIDR，如 "10.0.0.0/8"
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    /// 匹配端口列表
    #[serde(default)]
    pub port: Vec<u16>,
    /// 以上条件的关系：any=任一命中，all=全部命中
    #[serde(default)]
    pub match_mode: MatchMode,
    /// 命中后使用的出站链路名
    pub outbound: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    #[default]
    Any,
    All,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ObservabilityConfig {
    /// 日志级别：trace/debug/info/warn/error
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 是否启用连接统计
    #[serde(default = "default_true")]
    pub stats: bool,
    /// 统计采样间隔（秒）
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,
    /// 连接空闲超时（秒）：双向无数据流动超过该值则关闭连接，0 = 使用默认 300s
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// 日志文件目录（相对 cwd 或绝对路径），默认 "log"。
    /// 同时写入控制台与该目录下的滚动日志文件（按天滚动，omni-proxy-YYYY-MM-DD.log）。
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_true() -> bool {
    true
}
fn default_stats_interval() -> u64 {
    10
}
fn default_log_dir() -> String {
    "log".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: Config = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("JSON 配置解析失败 ({}): {}", path.display(), e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        let names: std::collections::HashSet<&str> =
            self.outbounds.iter().map(|o| o.name.as_str()).collect();
        if !names.contains("direct") {
            anyhow::bail!("必须定义名为 'direct' 的默认出站链路");
        }
        for r in &self.routing {
            if !names.contains(r.outbound.as_str()) {
                anyhow::bail!("路由规则引用了未定义的 outbound: {}", r.outbound);
            }
        }
        Ok(())
    }
}