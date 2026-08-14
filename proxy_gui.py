#!/usr/bin/env python3
"""proxy_gui.py — 代理工具桌面 GUI（PySide6/Qt）。

一个窗口管理整个代理工具链：
  · omni-proxy（自研核心）：启停、实时统计（对接 /api/status）、出站/监听器/路由查看
  · sing-box（节点代理）：节点列表解析展示、启停进程、一键更新到最新版
  · 工具链：日志尾随、官方配置文档入口、进度报告、关于

运行：
  pip install PySide6
  python proxy_gui.py

截图模式（无头渲染，用于预览/验证）：
  python proxy_gui.py --shot [输出.png]
"""
import json
import os
import re
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QFont, QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

ROOT = Path(__file__).resolve().parent
OMNI_CONFIG = ROOT / "proxy-config.json"
SINGBOX_DIR = ROOT / "core" / "singbox-core"
SINGBOX_CONFIG = ROOT / "singbox-config.json"
LOG_DIR = ROOT / "log"
WEBUI_URL = "http://127.0.0.1:9090/api/status"

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ---------- 工具函数 ----------

def find_binary(subdir: str, name: str) -> Path | None:
    base = ROOT / "core" / subdir
    for profile in ("release", "debug"):
        cand = base / "target" / profile / name
        if cand.is_file():
            return cand
    return None


def find_singbox_exe() -> Path | None:
    exe = SINGBOX_DIR / ("sing-box.exe" if os.name == "nt" else "sing-box")
    return exe if exe.is_file() else None


def fetch_status(url: str, timeout: float = 2.0):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "proxy-gui/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def parse_singbox_nodes(cfg_path: Path):
    """从 sing-box 配置提取节点清单（tag/type/server/server_port）。"""
    if not cfg_path.is_file():
        return []
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    nodes = []
    for ob in data.get("outbounds", []):
        typ = ob.get("type", "")
        tag = ob.get("tag", "")
        if not tag:
            continue
        nodes.append({
            "tag": tag,
            "type": typ,
            "server": ob.get("server", ""),
            "port": ob.get("server_port", ""),
        })
    return nodes


def fmt_bytes(b):
    b = int(b or 0)
    if b < 1024:
        return f"{b} B"
    for u in ("KB", "MB", "GB", "TB"):
        b /= 1024.0
        if b < 1024:
            return f"{b:.2f} {u}"
    return f"{b:.2f} PB"


def fmt_uptime(s):
    s = int(s or 0)
    h, m, x = s // 3600, s % 3600 // 60, s % 60
    return f"{h:02d}:{m:02d}:{x:02d}"


def tail_lines(path: Path, n: int = 300) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    lines = data.splitlines()
    return "\n".join(lines[-n:])


def latest_log_file() -> Path | None:
    if not LOG_DIR.is_dir():
        return None
    files = sorted(LOG_DIR.glob("omni-proxy-*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None

# ---------- 主题 ----------

QSS = """
QMainWindow, QWidget#root {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #0c1019, stop:1 #131b2e);
  color: #e9edf7;
  font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
  font-size: 13px;
}
QFrame#card {
  background: rgba(255,255,255,0.045);
  border: 1px solid rgba(255,255,255,0.09);
  border-radius: 12px;
}
QFrame#card:hover { border-color: rgba(255,255,255,0.16); }
QLabel#kpiV {
  font-size: 22px; font-weight: 800; color: #8f9bff;
}
QLabel#kpiL { font-size: 11px; color: #8b96ad; }
QLabel#secTitle {
  font-size: 15px; font-weight: 700; color: #e9edf7;
  padding-left: 10px;
  border-left: 3px solid qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #818cf8, stop:1 #22d3ee);
}
QPushButton {
  background: rgba(129,140,248,0.16);
  border: 1px solid rgba(129,140,248,0.35);
  color: #cfd6ff; border-radius: 9px; padding: 7px 16px; font-weight: 600;
}
QPushButton:hover { background: rgba(129,140,248,0.28); }
QPushButton:pressed { background: rgba(129,140,248,0.4); }
QPushButton#danger {
  background: rgba(248,113,113,0.14);
  border-color: rgba(248,113,113,0.4); color: #fda4af;
}
QPushButton#danger:hover { background: rgba(248,113,113,0.26); }
QPushButton#ghost {
  background: transparent; border-color: rgba(255,255,255,0.15); color: #c3cadb;
}
QPushButton#ghost:hover { background: rgba(255,255,255,0.06); }
QPushButton:disabled { color: #5c6678; border-color: rgba(255,255,255,0.06); background: transparent; }
QTableWidget {
  background: transparent; alternate-background-color: rgba(255,255,255,0.02);
  border: 1px solid rgba(255,255,255,0.09); border-radius: 10px;
  gridline-color: rgba(255,255,255,0.06); color: #dde3f0;
  selection-background-color: rgba(129,140,248,0.3);
}
QHeaderView::section {
  background: rgba(255,255,255,0.05); color: #8b96ad;
  border: none; border-bottom: 1px solid rgba(255,255,255,0.09);
  padding: 6px 8px; font-weight: 600;
}
QListWidget#nav {
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.09); border-radius: 12px;
  padding: 6px;
}
QListWidget#nav::item {
  border-radius: 9px; padding: 9px 12px; margin: 2px 0; color: #b9c1d4;
}
QListWidget#nav::item:selected {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  color: #ffffff; font-weight: 600;
}
QListWidget#nav::item:hover:!selected { background: rgba(255,255,255,0.06); }
QPlainTextEdit, QTextEdit {
  background: rgba(8,12,22,0.8); border: 1px solid rgba(255,255,255,0.09);
  border-radius: 10px; color: #c9d3e8; font-family: "Cascadia Mono", Consolas, monospace;
  font-size: 12px; selection-background-color: rgba(129,140,248,0.3);
}
QStatusBar { color: #8b96ad; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: rgba(255,255,255,0.14); border-radius: 5px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
"""

# ---------- 演示数据（截图模式） ----------

DEMO_STATUS = {
    "version": "0.1.0",
    "stats": {"total_connections": 1284, "active_connections": 7,
              "bytes_in": 523_000_000, "bytes_out": 1_204_000_000,
              "bytes_in_human": "498.78 MB", "bytes_out_human": "1.12 GB",
              "errors": 3, "uptime_secs": 90042},
    "outbounds": [
        {"name": "direct", "protocol": "direct", "target": "0.0.0.0:0", "alive": True,
         "failures": 0, "connections": 820, "active": 2, "errors": 0,
         "bytes_up": 210_000_000, "bytes_down": 640_000_000},
        {"name": "via-socks5", "protocol": "socks5", "target": "127.0.0.1:1088", "alive": True,
         "failures": 0, "connections": 410, "active": 5, "errors": 1,
         "bytes_up": 300_000_000, "bytes_down": 550_000_000},
        {"name": "dns", "protocol": "direct", "target": "8.8.8.8:53", "alive": False,
         "failures": 3, "connections": 54, "active": 0, "errors": 2,
         "bytes_up": 13_000_000, "bytes_down": 14_000_000},
    ],
    "listeners": [
        {"protocol": "http", "bind": "0.0.0.0:8080"},
        {"protocol": "https", "bind": "0.0.0.0:8443"},
        {"protocol": "socks", "bind": "0.0.0.0:1080"},
        {"protocol": "dns", "bind": "0.0.0.0:53"},
    ],
    "routes": [
        {"name": "内网直连", "domain_suffix": ["internal.example.com", "corp.local"],
         "ip_cidr": [], "port": [], "match_mode": "any", "outbound": "direct"},
        {"name": "SSH/RDP 走 SOCKS5", "domain_suffix": [], "ip_cidr": [],
         "port": [22, 3389], "match_mode": "any", "outbound": "via-socks5"},
        {"name": "内网网段", "domain_suffix": [], "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
         "port": [], "match_mode": "any", "outbound": "direct"},
    ],
    "config": {"hot_reload_secs": 5, "health_check_enabled": True, "log_level": "info",
               "stats_interval_secs": 10, "idle_timeout_secs": 300},
}

DEMO_NODES = [
    {"tag": "HK-HK1", "type": "vless", "server": "hkg1.example.com", "port": 443},
    {"tag": "JP-Tokyo", "type": "hysteria2", "server": "jp1.example.com", "port": 8443},
    {"tag": "US-LA", "type": "vless", "server": "us1.example.com", "port": 443},
    {"tag": "SG-Azure", "type": "shadowsocks", "server": "sg1.example.com", "port": 8388},
]

# ---------- 通用小组件 ----------

def section_title(text: str) -> QLabel:
    lb = QLabel(text)
    lb.setObjectName("secTitle")
    return lb


def kpi_card(label: str) -> tuple[QFrame, QLabel]:
    frame = QFrame()
    frame.setObjectName("card")
    v = QLabel("—")
    v.setObjectName("kpiV")
    l = QLabel(label)
    l.setObjectName("kpiL")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(2)
    lay.addWidget(v)
    lay.addWidget(l)
    return frame, v


def make_table(headers: list[str], rows: int = 0) -> QTableWidget:
    t = QTableWidget(rows, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectRows)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def table_set(t: QTableWidget, data: list[list[str]]) -> None:
    t.setRowCount(len(data))
    for r, row in enumerate(data):
        for c, val in enumerate(row):
            t.setItem(r, c, QTableWidgetItem(val))
    for c in range(t.columnCount()):
        t.resizeColumnToContents(c)
    if t.columnCount():
        t.horizontalHeader().setStretchLastSection(True)


# ---------- omni-proxy 页 ----------

class OmniPage(QWidget):
    def __init__(self, demo: bool = False, parent=None):
        super().__init__(parent)
        self.demo = demo
        self.proc = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        # 顶部控制条
        top = QHBoxLayout()
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet("color:#34d399;font-size:16px;")
        self.status_lb = QLabel("未连接（omni-proxy 未运行）")
        self.btn_start = QPushButton("启动 omni-proxy")
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setObjectName("danger")
        self.btn_stop.setEnabled(False)
        self.btn_refresh = QPushButton("立即刷新")
        self.btn_refresh.setObjectName("ghost")
        top.addWidget(self.status_dot)
        top.addWidget(self.status_lb)
        top.addStretch(1)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_stop)
        top.addWidget(self.btn_start)
        lay.addLayout(top)

        # KPI
        self.kpis = [kpi_card(n) for n in
                     ("总连接", "活跃连接", "上传", "下载", "错误", "运行时长")]
        kg = QGridLayout()
        kg.setSpacing(12)
        for i, (frame, _v) in enumerate(self.kpis):
            kg.addWidget(frame, i // 3, i % 3)
        lay.addLayout(kg)

        # 出站 + 监听器
        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(section_title("出站链路"))
        self.table_ob = make_table(["名称", "协议", "目标", "健康", "连接", "活跃", "错误", "↑", "↓"])
        lv.addWidget(self.table_ob)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(section_title("监听器"))
        self.table_ls = make_table(["协议", "绑定地址"])
        rv.addWidget(self.table_ls)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([700, 300])
        lay.addWidget(split, 1)

        # 路由
        lay.addWidget(section_title("路由规则"))
        self.table_rt = make_table(["名称", "匹配", "模式", "出口"])
        lay.addWidget(self.table_rt)

        self.btn_start.clicked.connect(self.start_omni)
        self.btn_stop.clicked.connect(self.stop_omni)
        self.btn_refresh.clicked.connect(self.poll)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(2000)

        if demo:
            self.render(DEMO_STATUS, True)

    def start_omni(self):
        exe = find_binary("proxy-core", "omni-proxy.exe" if os.name == "nt" else "omni-proxy")
        if not exe:
            QMessageBox.warning(self, "omni-proxy", "未找到编译产物，请先：cd core/proxy-core && cargo build --release")
            return
        if not OMNI_CONFIG.is_file():
            QMessageBox.warning(self, "omni-proxy", f"缺少配置文件：{OMNI_CONFIG}")
            return
        try:
            self.proc = subprocess.Popen(
                [str(exe), str(OMNI_CONFIG)], cwd=str(ROOT),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            QMessageBox.critical(self, "omni-proxy", f"启动失败：{e}")
            return
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_lb.setText("启动中…（等待 Web 控制台就绪）")

    def stop_omni(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.set_offline()

    def set_offline(self):
        self.status_dot.setStyleSheet("color:#f87171;font-size:16px;")
        self.status_lb.setText("未连接（omni-proxy 未运行）")
        for _f, v in self.kpis:
            v.setText("—")

    def poll(self):
        data = fetch_status(WEBUI_URL) if not self.demo else DEMO_STATUS
        if data is None:
            self.set_offline()
            return
        self.render(data, False)

    def render(self, d: dict, demo: bool):
        self.status_dot.setStyleSheet("color:#34d399;font-size:16px;")
        self.status_lb.setText(
            f"已连接 · v{d.get('version','?')} · 热重载 "
            f"{d['config'].get('hot_reload_secs') or '关'}s · 健康检查 "
            f"{'开' if d['config'].get('health_check_enabled') else '关'}"
            + ("  · [演示数据]" if demo else ""))
        st = d["stats"]
        vals = [str(st["total_connections"]), str(st["active_connections"]),
                st["bytes_in_human"], st["bytes_out_human"], str(st["errors"]),
                fmt_uptime(st["uptime_secs"])]
        for (_f, v), x in zip(self.kpis, vals):
            v.setText(x)

        rows = []
        for o in d["outbounds"]:
            health = "● 正常" if o["alive"] else f"● 失效×{o['failures']}"
            rows.append([o["name"], o["protocol"], o["target"], health,
                         str(o["connections"]), str(o["active"]), str(o["errors"]),
                         fmt_bytes(o["bytes_up"]), fmt_bytes(o["bytes_down"])])
        table_set(self.table_ob, rows)

        table_set(self.table_ls, [[l["protocol"], l["bind"]] for l in d["listeners"]])

        rrows = []
        for r in d["routes"]:
            parts = []
            if r["domain_suffix"]:
                parts.append("域名: " + ", ".join(r["domain_suffix"]))
            if r["ip_cidr"]:
                parts.append("CIDR: " + ", ".join(r["ip_cidr"]))
            if r["port"]:
                parts.append("端口: " + ", ".join(map(str, r["port"])))
            rrows.append([r["name"], " / ".join(parts) or "全量", r["match_mode"], r["outbound"]])
        table_set(self.table_rt, rrows)

    def closeEvent(self, ev):
        self.timer.stop()
        super().closeEvent(ev)


# ---------- sing-box 页 ----------

class SingboxPage(QWidget):
    def __init__(self, demo: bool = False, parent=None):
        super().__init__(parent)
        self.demo = demo
        self.proc = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        top = QHBoxLayout()
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet("color:#64748b;font-size:16px;")
        self.status_lb = QLabel("未运行")
        self.btn_start = QPushButton("启动 sing-box")
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setObjectName("danger")
        self.btn_stop.setEnabled(False)
        self.btn_update = QPushButton("检查/更新版本")
        self.btn_update.setObjectName("ghost")
        top.addWidget(self.status_dot)
        top.addWidget(self.status_lb)
        top.addStretch(1)
        top.addWidget(self.btn_update)
        top.addWidget(self.btn_stop)
        top.addWidget(self.btn_start)
        lay.addLayout(top)

        lay.addWidget(section_title("节点清单（singbox-config.json）"))
        self.table = make_table(["节点", "协议", "服务器", "端口"])
        lay.addWidget(self.table, 1)

        lay.addWidget(section_title("更新输出"))
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumHeight(150)
        lay.addWidget(self.out)

        self.btn_start.clicked.connect(self.start_singbox)
        self.btn_stop.clicked.connect(self.stop_singbox)
        self.btn_update.clicked.connect(self.check_update)
        self.refresh_nodes()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_nodes)
        self.timer.start(10000)

        if demo:
            table_set(self.table, [[n["tag"], n["type"], n["server"], str(n["port"])] for n in DEMO_NODES])
            self.status_lb.setText("未运行  ·  [演示数据]")

    def refresh_nodes(self):
        nodes = DEMO_NODES if self.demo else parse_singbox_nodes(SINGBOX_CONFIG)
        table_set(self.table, [[n["tag"], n["type"], n["server"], str(n["port"])] for n in nodes])
        if not nodes:
            self.status_lb.setText("未找到节点（singbox-config.json 缺失或为空）")

    def start_singbox(self):
        exe = find_singbox_exe()
        if not exe:
            QMessageBox.warning(self, "sing-box", "未找到 core/singbox-core/sing-box.exe，可先运行 python update_singbox.py")
            return
        if not SINGBOX_CONFIG.is_file():
            QMessageBox.warning(self, "sing-box", f"缺少配置文件：{SINGBOX_CONFIG}")
            return
        try:
            self.proc = subprocess.Popen(
                [str(exe), "run", "-c", str(SINGBOX_CONFIG)], cwd=str(ROOT),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            QMessageBox.critical(self, "sing-box", f"启动失败：{e}")
            return
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_dot.setStyleSheet("color:#34d399;font-size:16px;")
        self.status_lb.setText(f"运行中（PID {self.proc.pid}）")

    def stop_singbox(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_dot.setStyleSheet("color:#64748b;font-size:16px;")
        self.status_lb.setText("未运行")

    def _run_script(self, args: list[str]):
        self.out.clear()
        self.out.appendPlainText("$ python " + " ".join(args))
        script = ROOT / args[0]

        def worker():
            try:
                p = subprocess.run([sys.executable, str(script)] + args[1:],
                                   capture_output=True, text=True, timeout=120, cwd=str(ROOT))
                text = (p.stdout or "") + (p.stderr or "")
            except Exception as e:
                text = str(e)
            self.out.appendPlainText(text)

        threading.Thread(target=worker, daemon=True).start()

    def check_update(self):
        self._run_script(["update_singbox.py", "--check"])

    def closeEvent(self, ev):
        self.timer.stop()
        super().closeEvent(ev)


# ---------- 工具链页 ----------

class ToolsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        lay.addWidget(section_title("入口"))
        row = QHBoxLayout()
        btn_docs = QPushButton("sing-box 官方配置要求（本地界面）")
        btn_off = QPushButton("官方文档（在线）")
        btn_report = QPushButton("开发进度报告")
        btn_open = QPushButton("打开日志目录")
        for b in (btn_docs, btn_off, btn_report, btn_open):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        lay.addWidget(section_title("omni-proxy 日志（自动尾随）"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        lay.addWidget(self.log, 1)

        btn_docs.clicked.connect(lambda: self._open_file(ROOT / "singbox-docs.html"))
        btn_off.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://sing-box.sagernet.org/configuration/")))
        btn_report.clicked.connect(lambda: self._open_file(ROOT / "dev-progress-report.html"))
        btn_open.clicked.connect(lambda: self._open_dir(LOG_DIR))

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tail_log)
        self.timer.start(1500)
        self.tail_log()

    def _open_file(self, path: Path):
        if path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        else:
            QMessageBox.information(self, "提示", f"文件不存在：{path}")

    def _open_dir(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def tail_log(self):
        f = latest_log_file()
        if f:
            self.log.setPlainText(tail_lines(f))
        elif not self.log.toPlainText():
            self.log.setPlainText("（暂无日志）")

    def closeEvent(self, ev):
        self.timer.stop()
        super().closeEvent(ev)


# ---------- 主窗口 ----------

class MainWindow(QMainWindow):
    def __init__(self, demo: bool = False):
        super().__init__()
        self.setWindowTitle("代理工具控制台 · omni-proxy / sing-box")
        self.resize(1180, 760)
        self.setObjectName("root")

        central = QWidget()
        self.setCentralWidget(central)
        root_lay = QHBoxLayout(central)
        root_lay.setContentsMargins(14, 14, 14, 14)
        root_lay.setSpacing(14)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(180)
        for name in ("omni-proxy 核心", "sing-box 节点", "工具链"):
            item = QListWidgetItem(name)
            item.setSizeHint(item.sizeHint())
            self.nav.addItem(item)

        self.stack = QStackedWidget()
        self.pages = [OmniPage(demo=demo), SingboxPage(demo=demo), ToolsPage()]
        for p in self.pages:
            self.stack.addWidget(p)

        root_lay.addWidget(self.nav)
        root_lay.addWidget(self.stack, 1)

        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        self.statusBar().showMessage(
            f"工作目录：{ROOT} · Web 控制台：http://127.0.0.1:9090"
            + (" · [演示数据模式]" if demo else ""))

    def closeEvent(self, ev):
        for p in self.pages:
            p.closeEvent(ev)
        super().closeEvent(ev)


# ---------- 入口 ----------

def main() -> int:
    args = sys.argv[1:]
    shot = None
    if "--shot" in args:
        i = args.index("--shot")
        shot = args[i + 1] if i + 1 < len(args) else "gui-shot.png"
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    app = QApplication(sys.argv[:1])
    app.setStyleSheet(QSS)

    # offscreen 模式下注入系统中文字体（真实桌面运行无需此步）
    if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
        fonts_dir = os.path.join(os.environ.get("WINDIR", "C:/Windows"), "Fonts")
        for fname in ("msyh.ttc", "simhei.ttf", "simsun.ttc", "simfang.ttf"):
            p = os.path.join(fonts_dir, fname)
            if os.path.isfile(p):
                fid = QFontDatabase.addApplicationFont(p)
                if fid >= 0:
                    fams = QFontDatabase.applicationFontFamilies(fid)
                    if fams:
                        app.setFont(QFont(fams[0], 10))
                        break

    win = MainWindow(demo=bool(shot))
    win.show()
    app.processEvents()

    if shot:
        # 渲染稳定后截图
        QTimer.singleShot(800, lambda: (app.processEvents(), win.grab().save(shot), app.quit()))
        return app.exec()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
