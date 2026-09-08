# AetherCore: Windows Native C Proxy Core

AetherCore 是专为 Windows (amd64 / arm64) 打造的**纯 C 语言代理核心**（替代 mihomo / sing-box）：
除 `launcher.py` 启动器外，内核、托盘、订阅生成、分应用规则全部为 C 实现。

---

## 1. 架构总览

```text
aethercore/
├── launcher.py                      # 唯一的 Python 文件：入口/调度/系统代理/监控（其余全部 C）
├── core/                            # 全部 C 源码 + 单一二进制 + 构建脚本
│   ├── aether_main.c                # 统一入口（子命令分发）
│   ├── aether_core.c                # 代理核心（SOCKS5/HTTP + VLESS + 控制器）
│   ├── aether_tray.c                # 系统托盘（Win32 常驻菜单）
│   ├── aether_gen.c                 # 订阅解析 + core.conf 生成
│   ├── aether_rules.c               # 分应用规则存储
│   ├── aether_core.exe              # 单一可执行文件（core/tray/gen/rules 子命令）
│   └── build.bat                    # 一键编译（MSVC vcvars64 自动探测）
├── data/                            # 运行时生成：配置/日志/缓存
│   ├── core.conf                    # C 内核配置（节点 + 分流规则）
│   ├── config.yaml                  # 订阅节点缓存（core.conf 由它离线重建）
│   ├── app_rules.json               # 分应用代理规则
│   ├── nodes_cache.json             # 订阅原始缓存
│   ├── core.log / traffic.log       # 运行日志
│   └── cache.db
├── geo/                             # 地理数据（GeoIP，供二期 GEOIP 分流）
│   ├── geoip.dat / geosite.dat / Country.mmdb
├── legacy/                          # 不再使用的旧代码归档（mihomo/sing-box/Wintun 演示）
└── README.md                        # 项目说明文档
```

---

## 2. 核心特性

- **C 原生代理核心（替代 mihomo/sing-box）**：`aether_core.exe` 纯 C 实现——混合入站（SOCKS5 + HTTP 代理 @7899）、域名/私网分流（直连域名白名单、代理域名、CIDR 直连）、VLESS(TCP) 节点出站、控制器 API（`/version`、`/logs`、`/traffic`、`/proxies`，与 launcher/TUI/托盘兼容）；二期规划 TUN + lwIP 透明接管、UDP、VLESS WS/TLS(Reality)。
- **统一单可执行文件**：`aether_core.exe` 通过子命令提供全部能力——`core`（代理内核）、`tray`（托盘）、`gen`（订阅解析 + 生成 `data/core.conf`）、`rules`（读写 `data/app_rules.json`）。
- **默认全量代理 + 国内直连分流**：国内音视频/系统更新域名直连白名单保持本地高速直连，其余默认走代理节点；私网/环回 CIDR 永远直连。
- **C 原生系统托盘（零外部依赖）**：`aether_tray.exe` 纯 Win32 C 实现系统托盘常驻，支持左键一键隐藏/唤出控制台窗口、气泡通知、右键菜单（更新订阅、查看实时日志、手动切换节点、分应用代理、一键安全退出）；与 launcher 通过本地 TCP 控制通道通信，C 托盘不可用时自动回退 Python 托盘。
- **启动即托盘模式**：默认启动后隐藏窗口直接常驻系统托盘，全程不弹出控制台窗口；随时双击托盘图标或右键菜单唤出控制台，异常错误会自动弹出窗口提示。
- **默认全量代理 + 手动换节点**：未分类流量默认走代理节点，托盘"🌐 手动切换节点"子菜单可随时锁定任意节点；国内常见域名直连白名单保持本地高速直连。
- **📱 分应用代理**：按进程名强制路由（`app_rules.json`，最高优先级）——控制台按 `p` 进入分应用面板（`j/k` 选择、`1` 直连、`2` 走代理、`3` 自动优选、`x` 删除规则）；托盘"📱 分应用代理"子菜单可循环切换；规则持久化进 `core.conf`，进程级生效将在 C 内核二期实现（v0 先存储规则）。
- **内核守护自愈**：内核异常退出自动重启并热重载配置、托盘通知；配置原子写入（临时文件 + 替换）防止半截配置；`traffic.log` 超 5MB 自动轮转保留历史一份。
- **订阅异步更新不阻塞启动**：启动时优先使用本地已有配置立即拉起内核，订阅拉取与分流生成转入后台线程异步执行，更新完成后通过内置控制器 API 热重载生效，无需重启；托盘"立即更新订阅"同样异步完成，并**每 6 小时自动定时更新**。
- **零依赖控制台 TUI 实时仪表盘**：内核实时推送每个连接的协议、进程名、目标域名/IP 与命中节点；控制台以全屏 TUI 展示（标题栏 + 连接汇总表 + 状态栏 + 底部流量/提示栏 + 键盘操作），同一目标重复连接只更新计数 ×N、逐行差异重绘不滚动不折行，自动适配窗口缩放（中文/Emoji 按双宽截断），`/traffic` 接口实时显示上行/下行速率（EMA 平滑）；**键盘：`t`/`u`/`a` 协议筛选、`s` 按次数排序、`q` 退出**；完整明细仍全量写入 `traffic.log`。
- **开机自动启动**：托盘"🔄 开机自动启动"开关（HKCU Run 键）一键设置。**单实例锁**：重复启动弹窗提示并自动退出，避免两个网关抢占用同一张虚拟网卡。
- **系统代理模式（v0）**：launcher 启动 C 内核后自动设置 Windows 系统代理 `127.0.0.1:7899`，退出时自动复原；TUN 透明接管（Wintun + lwIP）为二期计划。

---

## 3. 一键启动命令

```powershell
& "C:\Users\cytFu\Desktop\aethercore\python-3.15.0rc1-embed-amd64\python.exe" launcher.py
```

### 方式 B：手动编译与运行 C 语言原生内核

#### 一键编译（MSVC）:
```powershell
cd core
.\build.bat
```

#### 手动编译 (MSVC / MinGW-w64):
```powershell
cd core
cl.exe /nologo /utf-8 /O2 /W3 aether_main.c aether_core.c aether_tray.c aether_gen.c aether_rules.c /Fe:aether_core.exe /link user32.lib shell32.lib ws2_32.lib advapi32.lib
```

#### 运行二进制 (需管理员权限):
```powershell
.\core\aether_core.exe core -f .\data\core.conf
.\core\aether_core.exe gen  -d .\data --rebuild
.\core\aether_core.exe rules -d .\data list
```
