# omni-proxy

> 全协议代理核心 — TCP / UDP / HTTP / HTTPS / SOCKS4/5 / DNS + TLS + 规则路由 + 透明代理

一个用 Rust 编写的多协议、可观测、可热重载的代理服务核心。所有协议共享同一套路由引擎与出站链路池，支持配置热重载、健康检查故障转移、按出站链路的流量统计。

## 特性一览

### 入站协议（Listeners）
- **HTTP / HTTPS 代理**：CONNECT 隧道 + 完整 HTTP 请求转发；支持 Basic 认证
- **SOCKS4 / SOCKS4a / SOCKS5**：CONNECT、用户名/密码认证、IPv4/IPv6/域名
- **TCP / UDP 透明转发**：可作 TUN/WFP 重定向的接驳点
- **DNS 代理**：UDP DNS 查询转发到上游解析器

### 出站协议（Outbounds）
- **direct**：直连目标
- **socks5**：经上游 SOCKS5 代理
- **httpproxy**：经上游 HTTP 代理（CONNECT 隧道）
- **shadowsocks / vmess**：协议栈预留（当前回退直连并告警）

每条出站链路支持：
- `timeout_secs` — 单次连接超时
- `retries` — 失败重试次数（线性退避 500ms × n）
- `tls` — 是否对出站连接做 TLS 包装
- `sni` — 自定义 SNI
- `auth` — 上游代理认证
- `pool_size` — 连接池大小（预留）

### 路由引擎
按顺序匹配，命中即采用对应 outbound；全部不命中则回退 `direct`。
匹配维度：
- `domain_suffix` — 域名后缀（大小写不敏感，支持子域）
- `ip_cidr` — IPv4 / IPv6 CIDR
- `port` — 目标端口列表
- `match_mode` — `any`（任一命中）/ `all`（全部命中）

### 可观测性
- 全局连接/字节/错误计数
- **按 outbound 累计**的连接数、活跃数、错误数、上传/下载字节
- 周期性日志采样
- 连接空闲超时（`observability.idle_timeout_secs`，默认 300s）

### 可靠性
- **配置热重载**：`hot_reload_secs` 指定周期，进程内原子替换
- **健康检查**：周期性 TCP 探测 outbounds，连续失败自动剔除并故障转移到同协议存活链路
- **优雅退出**：收到 Ctrl+C / SIGTERM 后打印日志并退出
- **空闲超时**：双向无数据流动超过阈值自动关闭，防止僵死连接

### 透明代理（Windows）
三种方案可单独启用：
- **方案 1 — PAC**：用户态 HTTP 服务返回 PAC 脚本，浏览器/系统按脚本分流，无需管理员
- **方案 2 — Wintun TUN**：动态加载 `wintun.dll` 创建虚拟网卡捕获流量，用户态自研最小 TCP 状态机 + UDP NAT 做 L3/L4 终止，桥接出站链路（需管理员 + DLL）
- **方案 3 — WFP**：内核级 TCP 透明重定向（需管理员 + callout 驱动，当前为脚手架）

## 快速开始

### 编译

```bash
cargo build --release
# 产物：target/release/omni-proxy.exe（Windows）或 target/release/omni-proxy（Linux/macOS）
```

### 生成自签名证书（HTTPS 代理需要）

```bash
cargo run --example gen_cert
# 写出 certs/server.crt 与 certs/server.key
```

### 启动

```bash
# 默认读取 ./proxy-config.json
omni-proxy

# 指定配置
omni-proxy /etc/omni/proxy.json
omni-proxy --config /etc/omni/proxy.json

# 启用 debug 日志
omni-proxy -v

# 仅校验配置不启动
omni-proxy --check proxy-config.json
```

日志写入 `log/` 目录（按天滚动的 `omni-proxy-YYYY-MM-DD.log`），同时输出到控制台。

### 命令行参数

```
omni-proxy — 全协议代理核心 (TCP/UDP/HTTP/SOCKS/DNS + TLS + 规则路由)

用法:
    omni-proxy [OPTIONS] [CONFIG_PATH]

参数:
    [CONFIG_PATH]            配置文件路径（位置参数，等价于 --config）

选项:
    -c, --config <PATH>      配置文件路径（默认: proxy-config.json）
        --check <PATH>       仅校验配置文件合法性，不启动服务
    -v, --verbose            提升日志级别到 debug（覆盖配置）
    -q, --quiet              降低日志级别到 warn（覆盖配置）
    -h, --help               显示此帮助信息
    -V, --version            显示版本号
```

日志级别优先级：`RUST_LOG` 环境变量 > 命令行 `-v/-q` > 配置文件 `log_level`。

## 配置示例

> 配置文件为 **JSON** 格式（omni-proxy 仅通过 `serde_json` 解析，默认读取 `./proxy-config.json`）。

```json
{
  "server": {
    "listeners": [
      { "protocol": "http",  "bind": "0.0.0.0:8080" },
      { "protocol": "https", "bind": "0.0.0.0:8443", "tls": true,
        "auth": { "auth_type": "basic", "username": "admin", "password": "secret" } },
      { "protocol": "socks", "bind": "0.0.0.0:1080" },
      { "protocol": "dns",   "bind": "0.0.0.0:53" }
    ]
  },
  "tls": {
    "cert": "certs/server.crt",
    "key":  "certs/server.key"
  },
  "outbounds": [
    { "name": "direct",     "protocol": "direct",     "target": "0.0.0.0:0" },
    { "name": "via-socks5", "protocol": "socks5",     "target": "127.0.0.1:1088", "retries": 3, "timeout_secs": 10 },
    { "name": "dns",        "protocol": "direct",     "target": "8.8.8.8:53" }
  ],
  "routing": [
    { "name": "内网直连",          "domain_suffix": ["internal.example.com", "corp.local"], "outbound": "direct" },
    { "name": "SSH/RDP 走 SOCKS5", "port": [22, 3389],                                      "outbound": "via-socks5" },
    { "name": "内网网段",          "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],           "outbound": "direct" }
  ],
  "observability": {
    "log_level": "info", "stats": true, "stats_interval_secs": 10,
    "idle_timeout_secs": 300, "log_dir": "log"
  },
  "hot_reload_secs": 5,
  "health_check": { "interval_secs": 10, "timeout_secs": 3, "max_failures": 3 }
}
```

完整示例见 [proxy-config.json](../../proxy-config.json)（位于仓库根目录 `net/proxy-config.json`）。

## 项目结构

```
src/
├── main.rs              入口：CLI 解析、信号处理
├── cli.rs               命令行参数解析（自实现，无 clap 依赖）
├── config.rs            配置 schema 与加载/校验
├── server.rs            服务编排：启动各类监听器、热重载、健康检查
├── relay.rs             转发核心：出站连接（带超时/重试）、双向 pipe（带空闲超时）
├── route.rs             规则路由引擎（domain_suffix / ip_cidr / port / match_mode）
├── state.rs             共享运行时状态：原子热更新配置 + 健康状态
├── http.rs              HTTP 代理协议：CONNECT + 完整请求转发 + Basic 认证
├── socks.rs             SOCKS4/4a/5 协议：服务端握手 + 客户端握手（用于上游）
├── dns.rs               DNS 代理：UDP 查询转发
├── tls.rs               rustls 服务端/客户端配置，支持 mTLS
├── observe.rs           可观测性：日志、全局统计、per-outbound 统计
└── transparent/         Windows 透明代理
    ├── mod.rs           统一入口
    ├── pac.rs           方案 1：PAC 自动配置
    ├── wintun_tun.rs    方案 2：Wintun 虚拟网卡 TUN
    └── wfp.rs           方案 3：WFP 重定向（脚手架）
examples/
└── gen_cert.rs          生成自签名证书
```

## 测试

```bash
cargo test --bin omni-proxy
```

覆盖：
- 路由引擎：域名后缀（精确/子域/大小写/前缀混淆）、CIDR（v4/v6/32 位主机/0.0.0.0/0 全捕获/非法输入）、端口匹配、`any`/`all` 模式、规则顺序、空规则
- CLI 参数解析：位置参数、`-c`/`--config`/`--config=`、`--check`、`-v`/`-q`、优先级
- 配置加载/校验：合法与非法 schema、默认值、可选字段（config.rs）
- 可观测性统计：计数/字节累计/每出站聚合（observe.rs）
- 透明代理包逻辑：IPv4/TCP/UDP 解析、Internet 校验和、MSS 解析、回包构造与畸形包拒收（transparent/netpkt.rs）

## 已知限制 / TODO

- **Shadowsocks / Vmess 出站**：协议栈未实现，当前回退直连并告警
- **SOCKS5 UDP_ASSOCIATE**：服务端仅回送占位响应，未真正中转 UDP
- **Wintun TUN**：已实现用户态 L3/L4 终止（自研最小 TCP 状态机 + UDP NAT），桥接到 `relay::dial_outbound_state` 复用路由/健康探测/TLS；`cargo check --tests` 编译通过。**运行时**仍需 `wintun.dll`（x64）+ 管理员权限 + 路由引流（如 `route add`），尚未做端到端实测；RFC 完整性（SACK/窗口缩放/PMTU）为已知缺口，必要时可换 smoltcp 加固
- **WFP 重定向**：两种落地方式——(1) WFP 内建 ALE_REDIRECT（纯用户态，无需自研驱动，推荐）；(2) 自定义 Callout 驱动 `omni-proxy-wfp.sys`（完全控制）。当前 `wfp.rs` 仅提供用户态管理引擎骨架，两种方式均未完整实现，需配套 WFP 管理 API 调用；生产可用请优先选方案1(PAC) 或方案2(Wintun)
- **连接池**：`outbound.pool_size` 字段已定义但未启用（每次新建连接）
- **HTTP 转发**：响应体仅处理 `Content-Length` 与 `Transfer-Encoding: chunked`，`Connection: close` 模式按读到 EOF 处理

## 依赖

- tokio 1（异步运行时）
- rustls 0.23 + tokio-rustls 0.26（TLS）
- hickory-proto / hickory-resolver 0.24（DNS）
- serde / serde_json（配置与 API）
- tracing / tracing-subscriber（日志）
- arc-swap（原子热更新配置）
- windows 0.52（Windows 透明代理，feature gated）

## 许可

MIT
