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

from PySide6.QtCore import Qt, QTimer, QUrl, QSettings
from PySide6.QtGui import (
    QAction, QColor, QDesktopServices, QFont, QFontDatabase, QGuiApplication,
    QIcon, QKeySequence, QLinearGradient, QPainter, QPixmap, QShortcut,
)
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFrame, QGraphicsDropShadowEffect, QGridLayout,
    QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QStackedWidget,
    QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
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

DARK_QSS = """
QMainWindow, QWidget#root {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #080b14, stop:1 #0e1424);
  color: #e8edf8;
  font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
  font-size: 13px;
}
QFrame#card {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 rgba(255,255,255,0.075), stop:1 rgba(255,255,255,0.035));
  border: 1px solid rgba(255,255,255,0.10);
  border-radius: 13px;
}
QFrame#card:hover { border-color: rgba(125,140,255,0.35); }
QLabel#kpiV {
  font-size: 23px; font-weight: 800; color: #8fa3ff;
}
QLabel#kpiL { font-size: 11px; color: #94a0ba; letter-spacing: .3px; }
QLabel#secTitle {
  font-size: 15px; font-weight: 700; color: #e8edf8;
  padding-left: 11px;
  border-left: 3px solid qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #7d8cff, stop:1 #2dd4bf);
}
QPushButton {
  background: rgba(125,140,255,0.13);
  border: 1px solid rgba(125,140,255,0.32);
  color: #d4dbff; border-radius: 9px; padding: 7px 16px; font-weight: 600;
}
QPushButton:hover { background: rgba(125,140,255,0.22); border-color: rgba(125,140,255,0.45); }
QPushButton:pressed { background: rgba(125,140,255,0.32); }
QPushButton#primary {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  border: 1px solid rgba(255,255,255,0.18); color: #ffffff;
  border-radius: 9px; padding: 7px 18px; font-weight: 700; letter-spacing: .3px;
}
QPushButton#primary:hover {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #7578f5, stop:1 #9a6cf8);
  border-color: rgba(255,255,255,0.30);
}
QPushButton#primary:pressed {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #5659e8, stop:1 #7d4fe8);
}
QPushButton#danger {
  background: rgba(251,113,133,0.12);
  border-color: rgba(251,113,133,0.38); color: #fda4af;
}
QPushButton#danger:hover { background: rgba(251,113,133,0.22); }
QPushButton#ghost {
  background: transparent; border-color: rgba(255,255,255,0.14); color: #b6c0d6;
}
QPushButton#ghost:hover { background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.24); }
QPushButton:disabled {
  color: #4d5870; border-color: rgba(255,255,255,0.06); background: transparent;
}
QTableWidget {
  background: rgba(10,14,26,0.55); alternate-background-color: rgba(255,255,255,0.02);
  border: 1px solid rgba(255,255,255,0.09); border-radius: 11px;
  gridline-color: rgba(255,255,255,0.05); color: #dde3f1;
  selection-background-color: rgba(125,140,255,0.24);
}
QHeaderView::section {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 rgba(255,255,255,0.07), stop:1 rgba(255,255,255,0.03));
  color: #8f9bb6; border: none;
  border-bottom: 1px solid rgba(255,255,255,0.08);
  padding: 7px 10px; font-weight: 600; letter-spacing: .3px;
}
QListWidget#nav {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 rgba(255,255,255,0.05), stop:1 rgba(255,255,255,0.02));
  border: 1px solid rgba(255,255,255,0.09); border-radius: 13px;
  padding: 6px;
}
QListWidget#nav::item {
  border-radius: 9px; padding: 9px 12px; margin: 2px 0; color: #a9b4cd;
}
QListWidget#nav::item:selected {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  color: #ffffff; font-weight: 700;
}
QListWidget#nav::item:hover:!selected { background: rgba(255,255,255,0.06); }
QPlainTextEdit, QTextEdit {
  background: rgba(7,11,22,0.9); border: 1px solid rgba(255,255,255,0.09);
  border-radius: 11px; color: #c9d4ec; font-family: "Cascadia Mono", Consolas, monospace;
  font-size: 12px; selection-background-color: rgba(125,140,255,0.3);
}
QStatusBar { color: #8f9bb6; background: transparent; }
QStatusBar::item { border: none; }
QScrollBar:vertical { background: transparent; width: 6px; margin: 2px; }
QScrollBar::handle:vertical { background: rgba(255,255,255,0.14); border-radius: 3px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: rgba(255,255,255,0.24); }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QCheckBox { color: #b6c0d6; spacing: 7px; }
QCheckBox::indicator {
  width: 16px; height: 16px; border-radius: 5px;
  border: 1.5px solid rgba(255,255,255,0.28); background: transparent;
}
QCheckBox::indicator:checked {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  border: 1.5px solid #6366f1;
}
QCheckBox::indicator:hover { border-color: rgba(125,140,255,0.7); }
QMenu {
  background: #111827; color: #dde3f1;
  border: 1px solid rgba(255,255,255,0.12); border-radius: 10px; padding: 5px;
}
QMenu::item { padding: 7px 24px; border-radius: 7px; }
QMenu::item:selected { background: rgba(125,140,255,0.25); }
QMenu::separator { height: 1px; background: rgba(255,255,255,0.08); margin: 4px 10px; }
QToolTip {
  background: #161e33; color: #e8edf8;
  border: 1px solid rgba(255,255,255,0.16); border-radius: 7px; padding: 4px 9px;
}
QSplitter::handle { background: transparent; }
"""

# 亮色主题（QSS 语法，切换时整表替换）
LIGHT_QSS = """
QMainWindow, QWidget#root {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #f5f7fc, stop:1 #e9eef9);
  color: #171d2e;
  font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
  font-size: 13px;
}
QFrame#card {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 rgba(255,255,255,0.95), stop:1 rgba(255,255,255,0.78));
  border: 1px solid rgba(23,29,58,0.10);
  border-radius: 13px;
}
QFrame#card:hover { border-color: rgba(99,102,241,0.45); }
QLabel#kpiV { font-size: 23px; font-weight: 800; color: #4f5de0; }
QLabel#kpiL { font-size: 11px; color: #5f6c88; letter-spacing: .3px; }
QLabel#secTitle {
  font-size: 15px; font-weight: 700; color: #171d2e;
  padding-left: 11px;
  border-left: 3px solid qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6366f1, stop:1 #0ea5b7);
}
QPushButton {
  background: rgba(99,102,241,0.10);
  border: 1px solid rgba(99,102,241,0.38);
  color: #4f5de0; border-radius: 9px; padding: 7px 16px; font-weight: 600;
}
QPushButton:hover { background: rgba(99,102,241,0.18); border-color: rgba(99,102,241,0.55); }
QPushButton:pressed { background: rgba(99,102,241,0.28); }
QPushButton#primary {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  border: 1px solid rgba(255,255,255,0.35); color: #ffffff;
  border-radius: 9px; padding: 7px 18px; font-weight: 700; letter-spacing: .3px;
}
QPushButton#primary:hover {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #7578f5, stop:1 #9a6cf8);
}
QPushButton#primary:pressed {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #5659e8, stop:1 #7d4fe8);
}
QPushButton#danger {
  background: rgba(220,38,38,0.07);
  border-color: rgba(220,38,38,0.4); color: #c62828;
}
QPushButton#danger:hover { background: rgba(220,38,38,0.14); }
QPushButton#ghost {
  background: transparent; border-color: rgba(23,29,58,0.16); color: #3d4a66;
}
QPushButton#ghost:hover { background: rgba(23,29,58,0.05); border-color: rgba(23,29,58,0.28); }
QPushButton:disabled {
  color: #a3adc2; border-color: rgba(23,29,58,0.08); background: transparent;
}
QTableWidget {
  background: rgba(255,255,255,0.72); alternate-background-color: rgba(23,29,58,0.02);
  border: 1px solid rgba(23,29,58,0.11); border-radius: 11px;
  gridline-color: rgba(23,29,58,0.06); color: #171d2e;
  selection-background-color: rgba(99,102,241,0.20);
}
QHeaderView::section {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 rgba(23,29,58,0.05), stop:1 rgba(23,29,58,0.02));
  color: #5f6c88; border: none;
  border-bottom: 1px solid rgba(23,29,58,0.10);
  padding: 7px 10px; font-weight: 600; letter-spacing: .3px;
}
QListWidget#nav {
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 rgba(255,255,255,0.75), stop:1 rgba(255,255,255,0.55));
  border: 1px solid rgba(23,29,58,0.11); border-radius: 13px;
  padding: 6px;
}
QListWidget#nav::item {
  border-radius: 9px; padding: 9px 12px; margin: 2px 0; color: #3d4a66;
}
QListWidget#nav::item:selected {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  color: #ffffff; font-weight: 700;
}
QListWidget#nav::item:hover:!selected { background: rgba(23,29,58,0.06); }
QPlainTextEdit, QTextEdit {
  background: rgba(255,255,255,0.92); border: 1px solid rgba(23,29,58,0.11);
  border-radius: 11px; color: #28324e; font-family: "Cascadia Mono", Consolas, monospace;
  font-size: 12px; selection-background-color: rgba(99,102,241,0.22);
}
QStatusBar { color: #5f6c88; background: transparent; }
QStatusBar::item { border: none; }
QScrollBar:vertical { background: transparent; width: 6px; margin: 2px; }
QScrollBar::handle:vertical { background: rgba(23,29,58,0.18); border-radius: 3px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: rgba(23,29,58,0.32); }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QCheckBox { color: #3d4a66; spacing: 7px; }
QCheckBox::indicator {
  width: 16px; height: 16px; border-radius: 5px;
  border: 1.5px solid rgba(23,29,58,0.30); background: rgba(255,255,255,0.7);
}
QCheckBox::indicator:checked {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
  border: 1.5px solid #6366f1;
}
QCheckBox::indicator:hover { border-color: rgba(99,102,241,0.7); }
QMenu {
  background: #ffffff; color: #171d2e;
  border: 1px solid rgba(23,29,58,0.14); border-radius: 10px; padding: 5px;
}
QMenu::item { padding: 7px 24px; border-radius: 7px; }
QMenu::item:selected { background: rgba(99,102,241,0.14); }
QMenu::separator { height: 1px; background: rgba(23,29,58,0.10); margin: 4px 10px; }
QToolTip {
  background: #ffffff; color: #171d2e;
  border: 1px solid rgba(23,29,58,0.16); border-radius: 7px; padding: 4px 9px;
}
QSplitter::handle { background: transparent; }
"""


def apply_theme(app: QApplication, light: bool) -> None:
    """切换全局主题并返回当前是否浅色。"""
    app.setStyleSheet(LIGHT_QSS if light else DARK_QSS)


def tray_notify(title: str, msg: str, timeout: int = 3000) -> None:
    """托盘气泡通知（托盘不可用时静默忽略）。"""
    app = QApplication.instance()
    tray = getattr(app, "_tray", None)
    if tray is not None and QSystemTrayIcon.isSystemTrayAvailable():
        tray.showMessage(title, msg, QSystemTrayIcon.Information, timeout)

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


def soften(w: QWidget, blur: int = 40, dy: int = 10, alpha: int = 70) -> QWidget:
    """给组件加柔和投影，增强层次感。"""
    effect = QGraphicsDropShadowEffect(w)
    effect.setBlurRadius(blur)
    effect.setOffset(0, dy)
    effect.setColor(QColor(0, 0, 0, alpha))
    w.setGraphicsEffect(effect)
    return w


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
    soften(frame, blur=26, dy=6, alpha=45)
    return frame, v


def make_table(headers: list[str], rows: int = 0) -> QTableWidget:
    t = QTableWidget(rows, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectRows)
    t.horizontalHeader().setStretchLastSection(True)
    soften(t, blur=30, dy=7, alpha=45)
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
        self.btn_start.setObjectName("primary")
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
        self.btn_start.setText("启动中…")
        self.btn_stop.setEnabled(True)
        self.status_lb.setText("启动中…（等待 Web 控制台就绪）")
        tray_notify("omni-proxy", "正在启动…")

    def stop_omni(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None
        self.btn_start.setEnabled(True)
        self.btn_start.setText("启动 omni-proxy")
        self.btn_stop.setEnabled(False)
        self.set_offline()
        tray_notify("omni-proxy", "已停止")

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
        # 启动中 → 就绪 状态迁移
        if self.btn_start.text() == "启动中…":
            self.btn_start.setText("启动 omni-proxy")
            tray_notify("omni-proxy", "Web 控制台已就绪")
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
        self.btn_start.setObjectName("primary")
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
        soften(self.out, blur=26, dy=6, alpha=40)
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
        tray_notify("sing-box", f"已启动（PID {self.proc.pid}）")

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
        tray_notify("sing-box", "已停止")

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
        head = QHBoxLayout()
        self.chk_follow = QCheckBox("自动滚动到底部")
        self.chk_follow.setChecked(True)
        head.addWidget(self.chk_follow)
        head.addStretch(1)
        lay.addLayout(head)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        soften(self.log, blur=30, dy=7, alpha=45)
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
            if self.chk_follow.isChecked():
                sb = self.log.verticalScrollBar()
                sb.setValue(sb.maximum())
        elif not self.log.toPlainText():
            self.log.setPlainText("（暂无日志）")

    def closeEvent(self, ev):
        self.timer.stop()
        super().closeEvent(ev)


# ---------- 主窗口 ----------

class MainWindow(QMainWindow):
    def __init__(self, demo: bool = False, settings: QSettings | None = None, light: bool = False):
        super().__init__()
        self._demo = demo
        self._settings = settings or QSettings("omni-proxy", "proxy-gui")
        self._light = light
        self._tray = None
        self._quit_requested = False
        self.setWindowTitle("代理工具控制台 · omni-proxy / sing-box")
        self.resize(1180, 760)
        self.setObjectName("root")

        # 恢复上次窗口几何
        geo = self._settings.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)

        central = QWidget()
        self.setCentralWidget(central)
        root_lay = QHBoxLayout(central)
        root_lay.setContentsMargins(14, 14, 14, 14)
        root_lay.setSpacing(14)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(180)
        soften(self.nav, blur=34, dy=8, alpha=50)
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
        # 恢复上次浏览的页面
        self.nav.setCurrentRow(int(self._settings.value("page", 0)))

        # 状态栏：主题切换按钮（常驻）
        self.btn_theme = QPushButton("浅色" if self._light else "深色")
        self.btn_theme.setObjectName("ghost")
        self.btn_theme.setFixedWidth(64)
        self.btn_theme.setToolTip("切换明暗主题")
        self.btn_theme.clicked.connect(self.toggle_theme)
        self.statusBar().addPermanentWidget(self.btn_theme)
        self.statusBar().showMessage(f"工作目录：{ROOT} · 初始化…")

        # 快捷键：Ctrl+1/2/3 切换页面
        for i, key in enumerate(("1", "2", "3")):
            QShortcut(QKeySequence(f"Ctrl+{key}"), self,
                      lambda i=i: self.nav.setCurrentRow(i))

        self._init_tray()

    # ---------- 托盘 ----------

    def _init_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self._tray = QSystemTrayIcon(self._make_icon(), self)
        menu = QMenu(self)
        act_toggle = QAction("显示 / 隐藏", menu)
        act_toggle.triggered.connect(self._toggle_visible)
        act_theme = QAction("切换主题", menu)
        act_theme.triggered.connect(self.toggle_theme)
        act_quit = QAction("退出", menu)
        act_quit.triggered.connect(self.quit_app)
        menu.addAction(act_toggle)
        menu.addAction(act_theme)
        menu.addSeparator()
        menu.addAction(act_quit)
        self._tray.setContextMenu(menu)
        self._tray.setToolTip("代理工具控制台 · omni-proxy / sing-box")
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()
        QApplication.instance()._tray = self._tray
        if not self._demo:
            self._tray.showMessage(
                "代理工具控制台", "已最小化到系统托盘，双击图标可恢复窗口",
                QSystemTrayIcon.Information, 2500)

    @staticmethod
    def _make_icon() -> QIcon:
        pm = QPixmap(64, 64)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        grad = QLinearGradient(0, 0, 64, 64)
        grad.setColorAt(0, QColor("#6366f1"))
        grad.setColorAt(1, QColor("#8b5cf6"))
        p.setBrush(grad)
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(2, 2, 60, 60, 14, 14)
        p.setPen(QColor("#ffffff"))
        f = p.font()
        f.setBold(True)
        f.setPointSize(16)
        p.setFont(f)
        p.drawText(pm.rect(), Qt.AlignCenter, "om")
        p.end()
        return QIcon(pm)

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self._toggle_visible()

    def _toggle_visible(self):
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    # ---------- 主题 ----------

    def toggle_theme(self):
        self._light = not self._light
        apply_theme(QApplication.instance(), self._light)
        self.btn_theme.setText("浅色" if self._light else "深色")
        self._settings.setValue("theme", "light" if self._light else "dark")

    # ---------- 生命周期 ----------

    def showEvent(self, ev):
        """显示时按屏幕可用区与 DPI 校正窗口尺寸，并展示缩放信息。"""
        super().showEvent(ev)
        scr = self.screen()
        if scr is not None:
            # 逻辑像素窗口尺寸超出屏幕可用区时收缩到 92%（高 DPI 屏幕常见）
            avail = scr.availableGeometry()
            if self.width() > avail.width() or self.height() > avail.height():
                self.resize(int(avail.width() * 0.92), int(avail.height() * 0.92))
        dpr = self.devicePixelRatioF()
        self.statusBar().showMessage(
            f"工作目录：{ROOT} · Web 控制台：http://127.0.0.1:9090 · 显示缩放 {dpr:.2f}×"
            + (" · [演示数据模式]" if self._demo else ""))

    def closeEvent(self, ev):
        # 有关闭按钮 = 最小化到托盘（托盘可用且非主动退出时）
        if self._tray is not None and not self._quit_requested:
            ev.ignore()
            self.hide()
            return
        for p in self.pages:
            p.closeEvent(ev)
        self._save_state()
        super().closeEvent(ev)

    def _save_state(self):
        s = self._settings
        s.setValue("geometry", self.saveGeometry())
        s.setValue("page", self.nav.currentRow())
        s.setValue("theme", "light" if self._light else "dark")
        s.sync()

    def quit_app(self):
        """退出前确认子进程处理并保存偏好。"""
        running = [(n, p) for n, p in
                   (("omni-proxy", self.pages[0].proc), ("sing-box", self.pages[1].proc))
                   if p is not None and p.poll() is None]
        if running and not self._demo:
            box = QMessageBox(self)
            box.setWindowTitle("退出代理工具控制台")
            box.setText("以下进程仍在运行：\n\n" + "\n".join(
                f"  · {n}（PID {p.pid}）" for n, p in running) + "\n\n是否先停止它们？")
            btn_stop = box.addButton("停止并退出", QMessageBox.AcceptRole)
            btn_keep = box.addButton("保留进程退出", QMessageBox.DestructiveRole)
            btn_cancel = box.addButton("取消", QMessageBox.RejectRole)
            box.setDefaultButton(btn_stop)
            box.exec()
            clicked = box.clickedButton()
            if clicked is btn_cancel or clicked is None:
                return
            if clicked is btn_stop:
                self.pages[0].stop_omni()
                self.pages[1].stop_singbox()
        self._quit_requested = True
        self._save_state()
        QApplication.instance().quit()


# ---------- 入口 ----------

def main() -> int:
    args = sys.argv[1:]
    shot = None
    if "--shot" in args:
        i = args.index("--shot")
        shot = args[i + 1] if i + 1 < len(args) else "gui-shot.png"
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    # ---- 高 DPI 适配（必须在 QApplication 创建前生效）----
    # 精确缩放策略：允许 125%/150% 等任意比例，避免默认取整导致的模糊/错位
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
    # --dpi 调试参数：用 QT_SCALE_FACTOR 强制缩放因子（如 --dpi 1.5）
    if "--dpi" in args:
        i = args.index("--dpi")
        if i + 1 < len(args):
            try:
                float(args[i + 1])
                os.environ["QT_SCALE_FACTOR"] = args[i + 1]
            except ValueError:
                print(f"忽略无效 --dpi 值：{args[i + 1]}")

    app = QApplication(sys.argv[:1])
    settings = QSettings("omni-proxy", "proxy-gui")
    # 截图模式由 --light 显式决定；正常模式记忆偏好
    if shot:
        light = "--light" in args
    else:
        light = ("--light" in args) or (settings.value("theme", "dark") == "light")
    apply_theme(app, light)

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

    win = MainWindow(demo=bool(shot), settings=settings, light=light)
    win.show()
    app.processEvents()

    if shot:
        # 渲染稳定后截图
        QTimer.singleShot(800, lambda: (app.processEvents(), win.grab().save(shot), app.quit()))
        return app.exec()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
