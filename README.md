# net — 代理工具集（双核心）

本仓库包含两套**相互独立**、可按场景任选其一使用的代理核心：

- **omni-proxy**：自研 Rust 代理核心（源码在 `core/proxy-core/`）
- **sing-box**：第三方预编译代理（二进制在 `core/singbox-core/`）

两者**互不调用、互不依赖**，只需根据需求选用其一即可。

---

## 1. omni-proxy（自研 · Rust）

- 源码：`core/proxy-core/`（Cargo 项目，详见 `core/proxy-core/README.md`）
- 配置：`proxy-config.json`（**JSON** 格式；二进制默认读取 `./proxy-config.json`）
- 启动方式：
  - 开发调试：`cd core/proxy-core && cargo run -- proxy-config.json`
  - 生产（零参数）：`python launcher.py`（自动定位编译产物并传入配置）
- 当前能力：HTTP/HTTPS/SOCKS4-5/DNS + TLS + 规则路由 + 配置热重载 + 健康检查故障转移 + PAC/Wintun 透明代理 + 内置 UAC 提权 + 内置 Web 控制台（`http://127.0.0.1:9090`）。
- 状态：v0.1.0，MVP 完成度较高；WFP 透明代理、SOCKS5 UDP、Shadowsocks/Vmess 出站仍处部分/待实现。

## 2. sing-box（预编译二进制）

- 二进制：`core/singbox-core/sing-box.exe`（含 `libcronet.dll`）
- 配置：`singbox-config.json`（由订阅地址 `sub` 生成，含节点清单与凭证，**不入库**）
- 启动：`core/singbox-core/sing-box.exe run -c singbox-config.json`
- 说明：成熟的第三方代理实现，按需选用，与 omni-proxy 无代码耦合。

---

## 3. 工具脚本

| 脚本 | 作用 | 用法 |
|---|---|---|
| `launcher.py` | omni-proxy 零参数启动器 | `python launcher.py` |
| `update_singbox.py` | 自动从 GitHub 下载适配当前平台的最新 sing-box 并更新 `core/singbox-core/`（自动备份旧版本；API 限流时回退直链） | `python update_singbox.py --check` 仅查询 / `python update_singbox.py` 更新 |
| `update_subscription.py` | **订阅更新器**：从 `sub` 中的订阅 URL 拉取节点（自动识别 base64/明文分享链接：vmess/vless/trojan/ss/hy2 或 sing-box JSON），去重后生成 `singbox-config.json`（保留旧配置的 log/dns/路由/入站，重建出站：DIRECT/REJECT + 节点 + `♻️自动选择` + `🚀节点选择`），写前自动备份 | `python update_subscription.py` 更新 / `--check` 仅统计 / `--dry-run` 预览节点 / `--url URL` 临时指定订阅 |
| `singbox_docs.py` | 抓取 sing-box 官方配置要求，生成独立界面 `singbox-docs.html`（支持明暗主题；离线降级为内置快照） | `python singbox_docs.py` / `--offline` 强制离线 |
| `proxy_gui.py` | **代理工具桌面 GUI**（PySide6/Qt）：一个窗口管理 omni-proxy（启停/实时统计/出站/路由）、sing-box（**订阅更新**/节点清单/启停/版本更新）与工具链（日志尾随/文档入口）。**单实例锁（重复启动自动唤醒原窗口）+ 系统托盘（最小化/气泡/菜单）+ 明暗主题切换（偏好记忆）+ Ctrl+1/2/3 切换页面 + 退出确认清理子进程 + 高 DPI 适配** | `pip install PySide6` 后 `python proxy_gui.py`；`--shot` 无头渲染截图，`--light` 强制浅色，`--dpi 1.5` 强制缩放调试；**打包独立 exe**：`python -m PyInstaller --onefile --windowed --name omni-proxy-gui proxy_gui.py`（产物 `dist/omni-proxy-gui.exe`，双击即用，无需 Python 环境） |

---

## 说明

- 两套核心各自独立运行，按场景选择其一。
- 证书/私钥、构建产物、订阅凭证、日志、`.workbuddy/` 等已通过 `.gitignore` 排除，不进入版本库。
