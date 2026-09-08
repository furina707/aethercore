# AetherCore: Windows Pure Python Proxy Core

AetherCore 是专为 Windows 打造的**纯 Python 代理核心**（替代 mihomo / sing-box）：
全部模块（内核、订阅生成、分应用规则）均为 Python 实现，零编译、零外部依赖。

---

## 1. 架构总览

```text
aethercore/
├── launcher.py                      # 入口/调度/TUN引擎驱动/TUI监控
├── test_tun.py                      # 单元/状态机/GeoIP/热重载完整测试套件
├── core/                            # 全部 Python 核心模块
│   ├── __init__.py
│   ├── aether_core.py               # 代理核心（SOCKS5/HTTP + VLESS + IPv6 + 控制器配置热重载）
│   ├── aether_gen.py                # 订阅解析 + core.conf 生成
│   ├── aether_rules.py              # 分应用规则存储（app_rules.json）
│   ├── aether_geoip.py              # 纯 Python 零依赖 MaxMind MMDB 解析器 (Country.mmdb)
│   ├── aether_tun.py                # WinTun 虚拟网卡管理与物理路由探测/双向绕过
│   ├── tun_dns.py                   # Fake-IP DNS / 双向映射池 (198.18.0.0/15 + fdfe::/64)
│   ├── tun_stack.py                 # IP/TCP/UDP 分发器与 UDP NAT (含 Fake-IP QUIC 秒回退)
│   └── tun_tcp.py                   # 用户态 TCP 协议栈 (32位回绕/零窗口探测/SOCKS5桥接/真实进程映射)
├── data/                            # 运行时生成：配置/日志/缓存
│   ├── core.conf                    # 内核配置（节点 + 分流规则）
│   ├── config.yaml                  # 订阅节点缓存
│   ├── sub.b64                      # 订阅原始 base64 缓存
│   ├── app_rules.json               # 分应用代理规则
│   ├── core.log / traffic.log       # 运行日志
│   └── cache.db
├── geo/                             # 地理数据（MaxMind 格式 GeoIP）
│   └── Country.mmdb
├── wintun/                          # Wintun 驱动二进制 (wintun.dll x64/arm64)
├── README.md                        # 项目说明文档
└── LICENSE                          # 许可证
```

---

## 2. 核心特性

- **纯 Python 代理核心（替代 mihomo/sing-box）**：`aether_core.py` 纯 Python 实现——混合入站（SOCKS5 + HTTP 代理 @7899）、分流决策（域名后缀匹配、私网/环回 CIDR、纯 Python GeoIP CN 直连、分进程路由）、VLESS(TCP/TLS/WS) 出站（支持 IPv4/IPv6 双栈与物理出口绑定）、内置 RESTful 控制器 API（`/version`、`/logs`、`/traffic`、`/proxies`、`/configs` 配置原子热重载）。
- **零外部依赖与零编译**：全 Python 栈实现，内置标准库网络协议栈与 MMDB 二进制解析，无需 MSVC/MinGW 编译，直接 `python launcher.py` 启动。
- **🚀 完整 TUN 透明网卡接管**：
  - 基于官方 **WinTun** 驱动，自动探测物理出口并注入防回环 /32 主机路由与物理网卡强绑定。
  - **Fake-IP DNS 池**：双栈 Fake-IP（IPv4 `198.18.0.0/15`，IPv6 `fdfe:dcba:9876::/64`），支持并发安全的双向域名/IP 反查。
  - **RFC 793 用户态 TCP 协议栈**：完整 TCP 状态机、严格 32 位序号回绕算术（Modulo 2^32）、零窗口探测（Zero-Window Probe）防死锁、MSS 协商、乱序段重组与指数退避重传。
  - **真实客户端进程名穿透**：TUN 模式下自动探测真实发起连接的应用进程名，穿透到 SOCKS5 并映射至分流控制器与 TUI 监控面板。
  - **Fake-IP UDP / QUIC 快速回退**：拦截并静默丢弃目标为 Fake-IP 的 UDP 流量，促使 Chromium/Firefox 浏览器秒级回退至 TCP TLS，杜绝 UDP 代理黑洞。
- **纯 Python GeoIP 引擎 (`aether_geoip.py`)**：自研零依赖 MaxMind MMDB 2.0 格式解析器，极速读取 `Country.mmdb` 二进制树与数据段，支持中国大陆 IP 与私网地址极速直连分流。
- **📱 分应用代理**：按进程名强制路由（`app_rules.json`，最高优先级）——控制台按 `3` 进入分应用面板（`j/k` 选择、`1` 直连、`2` 走代理、`3` 自动优选、`x` 删除规则）；修改后通过 `PUT /configs` 自动热重载，无需中断现有连接。
- **配置秒开与后台订阅热更新**：启动时检测到本地配置直接秒级拉起，后台异步拉取最新订阅；**每 6 小时自动定时拉取**；TUI 界面按 `U` 键可随时手动触发异步更新与热重载。
- **零依赖控制台 TUI 实时仪表盘**：内核实时推送每个连接的协议、进程名、目标域名/IP 与命中节点；控制台以全屏 TUI 展示（标题栏 + 连接汇总表 + 状态栏 + 底部流量/提示栏 + 键盘操作），同一目标重复连接只更新计数 ×N、逐行差异重绘不滚动不折行，自动适配窗口缩放（中文/Emoji 按双宽截断），`/traffic` 接口实时显示上行/下行速率（EMA 平滑）；**键盘：`Tab/2` 切换实时日志流/连接汇总表、`3` 分应用代理面板、`4/N` 切换节点、`U` 更新订阅、`f` 协议筛选、`s` 排序、`q` 退出**；支持 `--no-tui` 或 `--logs` 纯文本流式输出；完整明细全量写入 `traffic.log` 与 `core.log`。
- **开机自动启动与单实例守护**：通过 HKCU Run 键设置。单实例互斥锁避免并发冲突；运行中实时监控内核健康，异常退出自动拉起自愈；始终保证提权安全。

---

## 3. 启动方式

### 方式 A：使用嵌入式 Python（推荐）

```powershell
& ".\python-3.15.0rc1-embed-amd64\python.exe" launcher.py
```

### 方式 B：使用系统 Python

```powershell
python launcher.py
```

### 方式 C：纯文本日志模式（终端无 TUI 刷新）

```powershell
python launcher.py --logs
```

### 方式 D：轻量级验证（推荐先跑）

```powershell
python -c "import core.aether_core, core.aether_gen, core.aether_rules, core.aether_tun; print('imports ok')"
python test_tun.py
```

> **注意**：程序启动时会自动检测管理员权限，若非管理员运行将请求 UAC 提权。拒绝提权则直接退出。

---

## 4. 验证与维护

建议按以下顺序执行，便于在改动后快速判断是否引入回归：

- 语法/导入检查：`python -m compileall core launcher.py test_tun.py`
- 单元级验证：`python test_tun.py`
- 仅确认核心模块能导入：`python -c "import core.aether_core, core.aether_gen, core.aether_rules, core.aether_tun; print('imports ok')"`
- 若需要在 Windows shell 中直接做一轮最小检查：`python -c "import core.aether_core; print('ok')"`

> 该仓库默认在 Windows 环境下运行，因为入口依赖 `winreg`、`msvcrt`、Wintun 相关能力；`test_tun.py` 也会验证 TUN/TCP 状态机、Fake-IP DNS、校验和和生成配置等关键行为。

---

## 5. 模块说明

| 模块 | 文件 | 功能 |
|------|------|------|
| 调度器 | `launcher.py` | 入口调度、单实例锁、UAC提权、TUN引擎驱动、TUI控制台、定时与手动订阅更新 |
| 代理核心 | `core/aether_core.py` | SOCKS5/HTTP入站、VLESS出站(IPv4/IPv6)、分流决策、GeoIP集成、TUN进程穿透、RESTful控制器及配置热重载 (`PUT /configs`) |
| 订阅生成 | `core/aether_gen.py` | 订阅解析、VLESS节点提取、`core.conf`生成及分应用规则附加 |
| 规则管理 | `core/aether_rules.py` | 读写 `app_rules.json`，分应用代理规则增删改查 |
| GeoIP引擎 | `core/aether_geoip.py` | 纯 Python 零依赖 MaxMind MMDB 2.0 解析器，提供中国大陆 IP 与私网直连判定 |
| TUN网卡驱动 | `core/aether_tun.py` | WinTun 虚拟网卡初始化、物理出口探测、强绑定物理出口防回环、物理网关 /32 绕过路由与接管默认路由安装/卸载 |
| Fake-IP DNS | `core/tun_dns.py` | Fake-IP DNS 服务器、双栈 Fake-IP 池（IPv4 `198.18.0.0/15`、IPv6 `fdfe:dcba:9876::/64`）、反向查询映射 |
| 用户态TCP栈 | `core/tun_tcp.py` | 用户态 TCP 协议栈、RFC 793 状态机、32 位序号回绕运算、零窗口探测防死锁、SOCKS5 透明桥接、TUN 客户端进程映射穿透 |
| TUN分发引擎 | `core/tun_stack.py` | 数据面分发器（IPv4/IPv6/TCP/UDP/ICMP）、Fake-IP UDP/QUIC 快速回退丢弃、UDP NAT 出口直连、TUN 全局生命周期驱动 |