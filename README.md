# AetherCore 4.0

采用**纯 Zig**完整重写的极简、超高性能原生网络引擎与控制台。以单一原生二进制提供全平台核心能力、Linux GTK4 桌面端 GUI、DWM PerMonitorV2 高清渲染架构以及 MIUIX 风格的 Mobile Compose 规范。

---

## 核心设计契约

### 1. 默认安全 (Secure by Default)
> **“未开启的安全是不安全的”**
- **回环强制隔离**：所有端口（SOCKS5 `:10808`、HTTP `:10809`、REST API `:9097`）默认仅绑定 `127.0.0.1` 回环地址，杜绝局域网或公网未授权暴露。
- **高熵密钥鉴权**：首次启动由操作系统 CSPRNG 自动生成 256 位安全令牌（`data/auth.token`），文件权限强制设为 POSIX `0600`（仅所有者可读写）。
- **侧信道防御**：控制面 API 校验全面采用恒常时间（Constant-Time）比对算法，杜绝时序攻击。
- **闭合式故障安全 (Fail-Closed)**：智能分流模式下，未显式声明为内网的外部流量默认经由安全加密代理转发，拦截风险追踪域，防止明文泄露。
- **内存零化安全**：密钥与敏感缓冲区销毁时强制内存安全擦除。

### 2. DWM 位图高清渲染方案 (Windows / Win32)
- **显式声明 PerMonitorV2**：向桌面窗口管理器 (DWM) 声明 `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2`，通知 DWM 绝不进行系统级位图拉伸（No Bitmap Stretching）。
- **响应跨屏与 DPI 动态变动**：拦截 `WM_DPICHANGED` 消息，根据屏幕实时物理点阵重新换算尺寸。
- **点对点原生点阵重绘**：从系统获取物理缩放比（`scale = dpi / 96.0f`），按屏幕原生点阵物理分辨率渲染文字与几何体，彻底避免任何双线性/双三次插值产生的发虚、模糊与边缘锯齿。

### 3. Linux 原生 GTK4 图形界面
- 采用纯 Zig 直接调用 GTK4 C ABI，零中间绑定层开销，毫秒级启动。
- 融入现代 MIUIX 卡片化视觉风格：流体圆角卡片、实时流量双向动态仪表盘、一键分流模式切换（Rule / Global / Direct）与出站节点状态管理。

### 4. 手机 App 界面风格 (MIUIX + Compose 预览)
- 遵循小米澎湃 OS / MIUIX 视觉规范（位于 `mobile/AetherMiuixPreview.kt`）。
- 22dp 超椭圆大圆角卡片、高对比度状态指示胶囊、极简分段选择器与实时数据监控。
- 包含完整 Jetpack Compose `@Preview` 定义，支持在 Android Studio 及 Compose Multiplatform 工具链中即时预览。

### 5. 核心主要功能：分 IP 代理调度 (Per-IP Proxy Dispatch)
- **目标 IP 精确 CIDR 匹配**：内核支持 IPv4 掩码级路由判决，私有网段（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `100.64.0.0/10`）自动直连。
- **一致性 IP 哈希出口分流 (Consistent IP-Hash)**：外部公网目标访问采用确定性哈希算法，自动均衡映射到各个代理出口节点（实现不同目标分配独立代理出口 IP，防同一 IP 集中高频访问导致风控封禁）。
- **目标会话粘性保持 (Session Affinity)**：同一目标 IP 始终绑定固定代理出口节点，保证登录凭证与会话状态不漂移。
- **实时监控与控制面 API**：提供 `GET /api/ips` 接口实时查询活跃目标 IP 分流路由、出口节点分配与并发连接。
- **全端可视化呈现**：桌面端 GTK4 与手机端 MIUIX 界面均集成“分 IP 代理调度”实时监控卡片。

### 6. 极简构建与拉起 (`run.py`)
- `run.py` 仅保留构建与拉起 Zig 单二进制的极简逻辑，不保留任何其他语言业务代码。
- 不引入自动化校验冗余，不进行冗余的语法检查扫描与深层依赖审计，纯靠 Zig 编译器瞬时原生构建。

---

## 快速上手

### 构建与运行单二进制

```bash
# 极简脚本拉起 (自动编译并运行单一二进制)
python3 run.py

# 以 ReleaseFast 优化模式运行
python3 run.py --release

# 以守护进程模式运行 (无头服务器环境)
python3 run.py -- --daemon

# 强制拉起 Linux GTK4 桌面 GUI
python3 run.py -- --gui
```

### 直接使用 Zig 编译

```bash
# 编译
zig build

# 运行产物
./zig-out/bin/aethercore -h
```

---

## 项目架构一览

```
.
├── build.zig                 # 纯 Zig 单二进制极简构建定义 (GTK4 / Win32)
├── build.zig.zon             # 极简依赖清单
├── run.py                    # 极简构建与拉起脚本 (无业务逻辑)
├── mobile/
│   └── AetherMiuixPreview.kt # 手机端 MIUIX 风格 Compose 预览规范
└── src/
    ├── main.zig              # 单二进制统合入口 (CLI / 调度 / 信号管理)
    ├── security.zig          # 默认安全保障 (256位 CSPRNG 鉴权 / 0600 权限 / 恒常时间比对)
    ├── config.zig            # 配置管理与出站节点状态模型
    ├── net.zig               # 纯 Zig 套接字抽象与非阻塞网络 I/O
    ├── router.zig            # 默认安全分流与域名规则引擎
    ├── proxy.zig             # 高性能 SOCKS5 服务端与双向流量转发泵
    ├── control.zig           # 默认安全 REST 控制面 HTTP API
    ├── dwm_render.zig        # DWM PerMonitorV2 物理像素高清渲染模块
    └── gui_gtk4.zig          # Linux 原生 GTK4 图形界面 (MIUIX 风格)
```
