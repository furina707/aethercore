#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AetherCore - 全自动透明代理与单进程独占分流管理器
自动更新订阅 -> 生成单进程分流配置 -> 启动高性能内核 -> 实时监控每个应用的出口节点与带宽
"""

import os
import sys

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import io
import time
import json
import socket
import struct
import re
import ctypes
import signal
import queue
import threading
import collections
import urllib.request
import urllib.parse
import subprocess
import winreg
import msvcrt
from ctypes import wintypes

def get_process_for_port(port: int) -> str:
    """Windows 获取指定本地 TCP 端口的进程名 (支持 IPv4 与 IPv6)"""
    if sys.platform != "win32" or port <= 0:
        return "App"
    try:
        TCP_TABLE_OWNER_PID_ALL = 5
        AF_INET = 2
        AF_INET6 = 23
        pid = 0

        # 1. 优先查 IPv4 TCP 表
        size = wintypes.DWORD(0)
        ctypes.windll.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        if size.value > 0:
            buf = ctypes.create_string_buffer(size.value)
            if ctypes.windll.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
                num = struct.unpack_from("I", buf, 0)[0]
                offset = 4
                for _ in range(num):
                    state, laddr, lport, raddr, rport, owning_pid = struct.unpack_from("6I", buf, offset)
                    if socket.ntohs(lport & 0xFFFF) == port:
                        pid = owning_pid
                        break
                    offset += 24

        # 2. 若 IPv4 未查到，查询 IPv6 TCP 表 (MIB_TCP6ROW_OWNER_PID, 56 字节/项)
        if pid <= 0:
            size = wintypes.DWORD(0)
            ctypes.windll.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
            if size.value > 0:
                buf = ctypes.create_string_buffer(size.value)
                if ctypes.windll.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
                    num = struct.unpack_from("I", buf, 0)[0]
                    offset = 4
                    for _ in range(num):
                        lport = struct.unpack_from("I", buf, offset + 20)[0]
                        if socket.ntohs(lport & 0xFFFF) == port:
                            pid = struct.unpack_from("I", buf, offset + 52)[0]
                            break
                        offset += 56

        if pid <= 0:
            return "App"

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return "App"
        try:
            name_buf = ctypes.create_unicode_buffer(512)
            name_size = wintypes.DWORD(512)
            if ctypes.windll.kernel32.QueryFullProcessImageNameW(h, 0, name_buf, ctypes.byref(name_size)):
                return os.path.basename(name_buf.value)
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
    except Exception:
        pass
    return "App"

# 纯 Python 核心模块（替代 C 原生二进制）
from core.aether_rules import rules_list as py_rules_list, rules_set as py_rules_set, \
    rules_del as py_rules_del, get_rules_path as py_rules_path
from core.aether_gen import generate as py_gen_generate
from core.aether_core import aether_core_main as py_core_main

WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, WORKSPACE_DIR)
CORE_DIR = os.path.join(WORKSPACE_DIR, "core")
DATA_DIR = os.path.join(WORKSPACE_DIR, "data")
LEGACY_DIR = os.path.join(WORKSPACE_DIR, "legacy")

EMBEDDED_PYTHON = os.path.join(WORKSPACE_DIR, "python-3.15.0rc1-embed-amd64", "python.exe")
if not os.path.exists(EMBEDDED_PYTHON):
    alt_py = r"C:\Users\cytFu\Desktop\bin\python-3.15.0rc1-embed-amd64\python.exe"
    if os.path.exists(alt_py):
        EMBEDDED_PYTHON = alt_py

CONFIG_FILE = os.path.join(DATA_DIR, "config.yaml")
CORE_CONF = os.path.join(DATA_DIR, "core.conf")
LOG_FILE = os.path.join(DATA_DIR, "traffic.log")

MANUAL_GROUP = "手动节点 (MANUAL)"
AUTOSTART_NAME = "AetherCoreGateway"
AUTOSTART_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
SINGLE_INSTANCE_MUTEX = "Local\\AetherCoreTransparentGateway"
LOG_MAX_BYTES = 5 * 1024 * 1024
AUTO_UPDATE_INTERVAL = 6 * 3600
CONTROLLER = "http://127.0.0.1:9097"

# ---- 订阅剩余流量缓存 ----
_SUB_TRAFFIC = {
    "upload": 0,      # 已用上行 (bytes)
    "download": 0,    # 已用下行 (bytes)
    "total": 0,       # 总流量 (bytes)
    "expire": "",     # 到期时间字符串
    "fetched_at": 0.0,  # 上次成功拉取时间戳
}
_SUB_TRAFFIC_LOCK = threading.Lock()
_SUB_TRAFFIC_INTERVAL = 300  # 每 5 分钟刷新一次

def _parse_sub_userinfo(header_val: str) -> dict:
    """解析 subscription-userinfo 头，返回字段字典"""
    result = {}
    for part in header_val.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
    return result

def _refresh_sub_traffic():
    """后台拉取订阅头，更新剩余流量缓存"""
    from core.aether_gen import SUB_URL
    try:
        req = urllib.request.Request(
            SUB_URL,
            headers={"User-Agent": "ClashMeta; AetherCore"},
            method="HEAD",
        )
        res = urllib.request.urlopen(req, timeout=10)
        info_hdr = res.headers.get("subscription-userinfo", "")
        if not info_hdr:
            # HEAD 不返回时改用 GET 但只读头
            req2 = urllib.request.Request(SUB_URL, headers={"User-Agent": "ClashMeta; AetherCore"})
            res2 = urllib.request.urlopen(req2, timeout=10)
            info_hdr = res2.headers.get("subscription-userinfo", "")
            res2.close()
        if info_hdr:
            parsed = _parse_sub_userinfo(info_hdr)
            with _SUB_TRAFFIC_LOCK:
                _SUB_TRAFFIC["upload"]   = int(parsed.get("upload", 0) or 0)
                _SUB_TRAFFIC["download"] = int(parsed.get("download", 0) or 0)
                _SUB_TRAFFIC["total"]    = int(parsed.get("total", 0) or 0)
                _SUB_TRAFFIC["expire"]   = parsed.get("expire", "")
                _SUB_TRAFFIC["fetched_at"] = time.time()
    except Exception:
        pass

def _sub_traffic_loop(stopping):
    """后台循环：启动立即拉一次，之后每 5 分钟刷新"""
    _refresh_sub_traffic()
    while not stopping.is_set():
        stopping.wait(timeout=_SUB_TRAFFIC_INTERVAL)
        if not stopping.is_set():
            _refresh_sub_traffic()

class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UNDERLINE = "\033[4m"
    REVERSE = "\033[7m"

    # 前景色
    BLACK   = "\033[30m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    # 背景与暗调强调色
    BG_DARK    = "\033[48;5;236m"
    BG_BLUE    = "\033[48;5;24m"
    BG_CYAN    = "\033[48;5;30m"
    BG_GREEN   = "\033[48;5;28m"
    BG_MAGENTA = "\033[48;5;53m"
    BG_GRAY    = "\033[48;5;238m"

APP_RULES_FILE = os.path.join(DATA_DIR, "app_rules.json")

def target_label(target):
    t = str(target or "").strip()
    return {"direct": "本地直连", "proxy": "走代理(手动节点)", "auto": "自动优选"}.get(t.lower(), f"节点:{t}")

def rules_list():
    return py_rules_list(DATA_DIR)

def rules_set(proc, target):
    py_rules_set(proc, target, DATA_DIR)

def rules_del(proc):
    py_rules_del(proc, DATA_DIR)

def run_gen(fetch=False, echo=True):
    mode = "fetch" if fetch else "rebuild"
    try:
        out_lines = []
        ok = py_gen_generate(DATA_DIR, mode)
        if ok:
            msg = "[ok] 已生成内核配置: core.conf"
            out_lines.append(msg)
            push_status(msg)
            if echo:
                print(msg)
        else:
            msg = "[x] 配置生成失败（无订阅且无历史缓存）"
            out_lines.append(msg)
            push_status(msg)
            if echo:
                print(msg)
        return ok, "\n".join(out_lines)
    except Exception as e:
        msg = f"[x] 配置生成异常: {e}"
        push_status(msg)
        if echo:
            print(msg)
        return False, str(e)


# ---- 工具函数 ----
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate_admin():
    if not is_admin():
        print(f"{Color.YELLOW}[*] 检测到当前非管理员权限，正在请求 UAC 提权...{Color.RESET}")
        py_exe = EMBEDDED_PYTHON if os.path.exists(EMBEDDED_PYTHON) else sys.executable
        script_args = [f'"{arg}"' for arg in sys.argv]
        params = f"-W ignore {' '.join(script_args)}"
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", py_exe, params, WORKSPACE_DIR, 1)
        if ret > 32:
            sys.exit(0)
        else:
            show_console_window()
            print(f"{Color.RED}[x] 提权请求被用户拒绝或失败 (Error Code: {ret}){Color.RESET}")
            input("\n按回车键退出...")
            sys.exit(1)

def kill_conflicting_proxies():
    try:
        subprocess.run(["powershell", "-Command",
            "Get-Process -Name '*clash*', '*mihomo*', '*verge*', 'sing-box*', 'xray*', 'v2ray*' -ErrorAction SilentlyContinue | Stop-Process -Force"],
            capture_output=True)
    except Exception:
        pass
    try:
        subprocess.run(["taskkill", "/F", "/IM", "clash-verge.exe", "/IM", "verge-mihomo.exe", "/IM", "verge-mihomo-alpha.exe", "/IM", "clash.exe", "/IM", "mihomo.exe", "/IM", "sing-box.exe"],
            capture_output=True)
    except Exception:
        pass
    for exe_path in (os.path.join(LEGACY_DIR, "core.exe"),):
        name = os.path.splitext(os.path.basename(exe_path))[0]
        try:
            exe_path = os.path.abspath(exe_path).replace("'", "''")
            ps = (f"Get-Process -Name '{name}' -ErrorAction SilentlyContinue | "
                  f"Where-Object {{ $_.Path -eq '{exe_path}' }} | Stop-Process -Force")
            subprocess.run(["powershell", "-Command", ps], capture_output=True)
        except Exception:
            pass

def get_pids_for_ports(*ports: int) -> set:
    """获取正在使用指定本地 TCP 端口的所有进程 PID"""
    if sys.platform != "win32":
        return set()
    pids = set()
    try:
        TCP_TABLE_OWNER_PID_ALL = 5
        AF_INET = 2
        size = wintypes.DWORD(0)
        ctypes.windll.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        buf = ctypes.create_string_buffer(size.value)
        if ctypes.windll.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            num = struct.unpack_from("I", buf, 0)[0]
            offset = 4
            for _ in range(num):
                state, laddr, lport, raddr, rport, owning_pid = struct.unpack_from("6I", buf, offset)
                net_port = socket.ntohs(lport & 0xFFFF)
                if net_port in ports and owning_pid > 0:
                    pids.add(owning_pid)
                offset += 24
    except Exception:
        pass
    return pids

def _terminate_pid(pid: int) -> bool:
    """强制结束指定 PID 进程"""
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        PROCESS_TERMINATE = 0x0001
        SYNCHRONIZE = 0x00100000
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
        if h:
            ctypes.windll.kernel32.TerminateProcess(h, 0)
            ctypes.windll.kernel32.WaitForSingleObject(h, 1000)
            ctypes.windll.kernel32.CloseHandle(h)
            return True
    except Exception:
        pass
    return False

def kill_old_instances() -> bool:
    """自动查找并强制关闭所有运行中的旧实例及占用代理端口的旧进程"""
    my_pid = os.getpid()
    killed = False

    # 1. 终止占用 7899 (代理) 或 9097 (控制器) 的所有其他进程
    for port in (7899, 9097):
        pids = get_pids_for_ports(port)
        for pid in pids:
            if pid != my_pid:
                if _terminate_pid(pid):
                    killed = True

    # 2. 终止其他正在运行 launcher.py 或 aether_core 的 Python 实例
    try:
        ps_cmd = (
            f"$curr = {my_pid}; "
            "Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction SilentlyContinue | "
            "Where-Object { "
            f"$_.ProcessId -ne $curr -and ($_.CommandLine -like '*launcher.py*' -or $_.CommandLine -like '*aether_core*') "
            "} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
        )
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                             capture_output=True, timeout=5)
        if res.returncode == 0 and res.stdout:
            killed = True
    except Exception:
        pass

    if killed:
        time.sleep(0.5)

    return killed

def core_already_running() -> bool:
    try:
        req = urllib.request.Request(CONTROLLER + "/version",
            headers={"Authorization": "Bearer aethercore"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False

def hide_console_window():
    try:
        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        if whnd:
            ctypes.windll.user32.ShowWindow(whnd, 0)
    except Exception:
        pass

def show_console_window():
    try:
        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        if whnd:
            ctypes.windll.user32.ShowWindow(whnd, 5)
            ctypes.windll.user32.ShowWindow(whnd, 9)
            ctypes.windll.user32.SetForegroundWindow(whnd)
    except Exception:
        pass

def toggle_console_window():
    try:
        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        if not whnd:
            return False
        if ctypes.windll.user32.IsWindowVisible(whnd):
            ctypes.windll.user32.ShowWindow(whnd, 0)
            return False
        show_console_window()
        return True
    except Exception:
        return False

def console_visible():
    try:
        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        return bool(whnd) and bool(ctypes.windll.user32.IsWindowVisible(whnd))
    except Exception:
        return False

def open_logs_file():
    if os.path.exists(LOG_FILE):
        os.system(f'start "" "{LOG_FILE}"')

# AetherCore 专为 TUN 透明接管设计（始终以管理员权限运行，通过 WinTun 驱动直接在 L3 网络层接管全流量，无需且不修改 Windows 系统代理）

_CORE_THREAD = None
_CORE_STOP_EVENT = threading.Event()
_MONITOR_THREADS = []

# ---- TUN 全局接管 ----
_TUN_MODE = {"active": False, "error": None}
_TUN_ENGINE = None


def parse_tun_enabled(conf_path: str) -> bool:
    """解析 core.conf 中的 tun 开关 (缺省视为开启)"""
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("\t")
                if parts and parts[0] == "tun" and len(parts) >= 2:
                    return parts[1].strip().lower() in ("on", "1", "true", "yes")
    except Exception:
        pass
    return True


def parse_listen_addr(conf_path: str):
    """解析 core.conf 的 listen 行，返回 (ip, port)"""
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("\t")
                if parts and parts[0] == "listen" and len(parts) >= 3:
                    return parts[1].strip(), int(parts[2].strip())
    except Exception:
        pass
    return "127.0.0.1", 7899


def wait_core_listen(host: str, port: int, timeout: float = 8.0) -> bool:
    """等待内核 SOCKS5/HTTP 入站就绪 (TUN 桥接依赖它)"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            time.sleep(0.2)
    return False


def start_tun_engine():
    """启动 TUN 引擎 (需管理员权限)"""
    global _TUN_ENGINE
    from core.tun_stack import TunEngine
    host, port = parse_listen_addr(CORE_CONF)

    def tun_log(msg):
        try:
            import core.aether_core as ac
            ac.core_log(f"{msg}")
        except Exception:
            pass
        print(f"{Color.CYAN}{msg}{Color.RESET}", flush=True)

    eng = TunEngine(socks_addr=(host, port), conf_path=CORE_CONF, log=tun_log)
    eng.start()
    _TUN_ENGINE = eng


def stop_tun_engine():
    global _TUN_ENGINE
    if _TUN_ENGINE is not None:
        try:
            _TUN_ENGINE.stop()
        except Exception:
            pass
        _TUN_ENGINE = None
    _TUN_MODE["active"] = False


def start_core():
    core_log_path = os.path.join(DATA_DIR, "core.log")
    try:
        if os.path.exists(core_log_path) and os.path.getsize(core_log_path) > 1024 * 1024:
            os.remove(core_log_path)
    except Exception:
        pass
    try:
        with open(core_log_path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"\n--- [core start {time.strftime('%Y-%m-%d %H:%M:%S')}] ---\n")
    except Exception:
        pass
    _CORE_STOP_EVENT.clear()
    t = threading.Thread(target=_run_core_thread, daemon=True, name="py-core")
    t.start()
    return _CoreProc(t)

class _CoreProc:
    def __init__(self, thread):
        self._thread = thread
        self._poll = None
    def poll(self):
        if self._thread and not self._thread.is_alive():
            self._poll = 0
        return self._poll
    def terminate(self):
        _CORE_STOP_EVENT.set()
        import core.aether_core
        core.aether_core.CORE_STOP_EVENT.set()
    def kill(self):
        _CORE_STOP_EVENT.set()
        import core.aether_core
        core.aether_core.CORE_STOP_EVENT.set()
    def wait(self, timeout=None):
        if self._thread:
            self._thread.join(timeout=timeout)

def _run_core_thread():
    try:
        py_core_main(DATA_DIR, CORE_CONF)
    except Exception as e:
        core_log_path = os.path.join(DATA_DIR, "core.log")
        try:
            with open(core_log_path, "a", encoding="utf-8", errors="ignore") as f:
                f.write(f"[x] Python core thread exited: {e}\n")
        except Exception:
            pass

def ensure_single_instance(create=True) -> bool:
    try:
        kernel32 = ctypes.windll.kernel32
        if not create:
            kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
            kernel32.OpenMutexW.restype = wintypes.HANDLE
            h = kernel32.OpenMutexW(0x001F0001, False, SINGLE_INSTANCE_MUTEX)
            if h:
                kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel32.CloseHandle.restype = wintypes.BOOL
                kernel32.CloseHandle(h)
                return False
            return True
        kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.GetLastError.restype = wintypes.DWORD
        kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)
        if kernel32.GetLastError() == 183:
            time.sleep(0.3)
            kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)
        return True
    except Exception:
        return True

def autostart_is_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_KEY) as key:
            winreg.QueryValueEx(key, AUTOSTART_NAME)
            return True
    except Exception:
        return False

def autostart_set(enable: bool):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                py = EMBEDDED_PYTHON if os.path.exists(EMBEDDED_PYTHON) else sys.executable
                cmd = f'"{py}" -W ignore "{os.path.abspath(__file__)}"'
                winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
        return autostart_is_enabled() == enable
    except Exception:
        return False

def rotate_log(log_fp):
    try:
        log_fp.close()
    except Exception:
        pass
    try:
        if os.path.exists(LOG_FILE + ".1"):
            os.remove(LOG_FILE + ".1")
        if os.path.exists(LOG_FILE):
            os.replace(LOG_FILE, LOG_FILE + ".1")
    except Exception:
        pass
    return open(LOG_FILE, "a", encoding="utf-8", buffering=1)
STD_OUTPUT_HANDLE = -11

class _COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

class _SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

class _CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [("dwSize", _COORD), ("dwCursorPosition", _COORD),
                ("wAttributes", wintypes.WORD), ("srWindow", _SMALL_RECT),
                ("dwMaximumWindowSize", _COORD)]

def _is_wide(cp):
    if 0x1F1E6 <= cp <= 0x1F1FF:
        return False  # 国旗 Emoji 由两个区域指示符构成，每个占1格，合并共2格
    return (0x1100 <= cp <= 0x115F or 0x2E80 <= cp <= 0xA4CF or 0xAC00 <= cp <= 0xD7A3
            or 0xF900 <= cp <= 0xFAFF or 0xFE30 <= cp <= 0xFE4F or 0xFF00 <= cp <= 0xFF60
            or 0xFFE0 <= cp <= 0xFFE6 or 0x1F000 <= cp <= 0x1FAFF or 0x20000 <= cp <= 0x3FFFD
            or 0x2600 <= cp <= 0x27BF or 0x2B00 <= cp <= 0x2BFF)

def _disp_width(text):
    return sum(2 if _is_wide(ord(ch)) else 1 for ch in text)

def _truncate(text, width):
    if width <= 0:
        return ""
    out, used = [], 0
    for ch in text:
        cw = 2 if _is_wide(ord(ch)) else 1
        if used + cw > width:
            break
        out.append(ch)
        used += cw
    return "".join(out)

def _pad_disp(text: str, target_width: int, align: str = "left", fill: str = " ") -> str:
    """按终端显示宽度填充字符串，精准支持双宽中文字符与 Emoji"""
    text = str(text or "")
    cur_w = _disp_width(text)
    if cur_w > target_width:
        text = _truncate(text, target_width)
        cur_w = _disp_width(text)
    diff = max(target_width - cur_w, 0)
    if align == "right":
        return (fill * diff) + text
    elif align == "center":
        l_pad = diff // 2
        return (fill * l_pad) + text + (fill * (diff - l_pad))
    else:
        return text + (fill * diff)

def disable_quick_edit():
    """禁用 Windows 控制台快速编辑模式，防止鼠标点击终端窗口时触发选择暂停导致程序卡死"""
    if sys.platform != "win32":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        h_conin = kernel32.CreateFileW(
            "CONIN$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if h_conin and h_conin != -1:
            mode = wintypes.DWORD()
            if kernel32.GetConsoleMode(h_conin, ctypes.byref(mode)):
                ENABLE_QUICK_EDIT_MODE = 0x0040
                ENABLE_EXTENDED_FLAGS = 0x0080
                new_mode = (mode.value & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS
                kernel32.SetConsoleMode(h_conin, new_mode)
            kernel32.CloseHandle(h_conin)
    except Exception:
        pass

class Tui:
    def __init__(self):
        disable_quick_edit()
        self.hOut = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        self.csbi = _CONSOLE_SCREEN_BUFFER_INFO()
        if not ctypes.windll.kernel32.GetConsoleScreenBufferInfo(
                self.hOut, ctypes.byref(self.csbi)):
            # 尝试通过 CONOUT$ 获取真实的控制台缓冲区句柄 (解决 PowerShell/Windows Terminal 下句柄重定向问题)
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            self.hOut = ctypes.windll.kernel32.CreateFileW(
                "CONOUT$",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if not self.hOut or self.hOut == -1:
                self.hOut = None

        # 尝试开启 Windows 终端 ANSI 虚拟终端序列支持 (VT Processing)
        if self.hOut and self.hOut != -1:
            try:
                mode = ctypes.c_ulong()
                if ctypes.windll.kernel32.GetConsoleMode(self.hOut, ctypes.byref(mode)):
                    ctypes.windll.kernel32.SetConsoleMode(self.hOut, mode.value | 0x0004)
            except Exception:
                pass

        self._prev = None
        self._started = False
        self._prev_size = (0, 0)
        self._hwnd = None
        self._was_focused = True  # 假设启动时有焦点
        self._original_buffer_size = None
        try:
            self._hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        except Exception:
            self._hwnd = None

    def _is_focused(self):
        """检测控制台窗口是否是当前前台窗口"""
        try:
            if self._hwnd:
                fg = ctypes.windll.user32.GetForegroundWindow()
                return fg == self._hwnd
        except Exception:
            pass
        return True  # 无法判断时默认有焦点

    def size(self):
        if self.hOut and self.hOut != -1:
            try:
                if ctypes.windll.kernel32.GetConsoleScreenBufferInfo(self.hOut, ctypes.byref(self.csbi)):
                    w = self.csbi.srWindow.Right - self.csbi.srWindow.Left + 1
                    h = self.csbi.srWindow.Bottom - self.csbi.srWindow.Top + 1
                    if w > 10 and h > 5:
                        return max(w, 1), max(h, 1)
            except Exception:
                pass
        import shutil
        ts = shutil.get_terminal_size((100, 30))
        return max(ts.columns, 20), max(ts.lines, 10)

    def start(self):
        disable_quick_edit()
        if not self._started:
            if self.hOut and self.hOut != -1:
                try:
                    if ctypes.windll.kernel32.GetConsoleScreenBufferInfo(
                            self.hOut, ctypes.byref(self.csbi)):
                        self._original_buffer_size = _COORD(
                            self.csbi.dwSize.X, self.csbi.dwSize.Y)
                        height = self.csbi.srWindow.Bottom - self.csbi.srWindow.Top + 1
                        size = _COORD(self.csbi.dwSize.X, height)
                        ctypes.windll.kernel32.SetConsoleScreenBufferSize(
                            self.hOut, size)
                except Exception:
                    self._original_buffer_size = None
            sys.stdout.write("\033[2J\033[3J\033[H\033[?25l")
            sys.stdout.flush()
            self._started = True

    def close(self):
        if self._started:
            sys.stdout.write("\033[?25h\033[0m\033[H")
            sys.stdout.flush()
            if self.hOut and self._original_buffer_size is not None:
                try:
                    ctypes.windll.kernel32.SetConsoleScreenBufferSize(
                        self.hOut, self._original_buffer_size)
                except Exception:
                    pass
            self._original_buffer_size = None
            self._started = False

    def invalidate(self):
        """强制下一帧全量重绘（清掉 diff 缓存）"""
        self._prev = None

    @staticmethod
    def _compose(segments, width):
        out, sig, used = [], [], 0
        for text, prefix in segments:
            if used >= width:
                break
            keep = _truncate(text, width - used)
            if not keep:
                continue
            out.append(prefix or "")
            out.append(keep)
            if prefix:
                out.append("\033[0m")
            sig.append(keep)
            used += _disp_width(keep)
        line = "".join(out)
        pad = max(width - used, 0)
        return "".join(sig), line + (" " * pad) + "\033[0m"

    def render(self, segment_rows):
        if not segment_rows:
            return
        w, h = self.size()
        self.start()

        # 尺寸变化 → 强制全量重绘
        cur_size = (w, h)
        if cur_size != self._prev_size:
            self._prev = None
            self._prev_size = cur_size
            # 清屏确保旧内容不残留
            sys.stdout.write("\033[2J\033[3J\033[H")

        # 焦点恢复 → 强制全量重绘（终端失焦后内容可能被其他窗口覆盖）
        focused = self._is_focused()
        if focused and not self._was_focused:
            self._prev = None
        self._was_focused = focused

        nxt = []
        eff_w = max(w - 1, 20)
        for i in range(h):
            segs = segment_rows[i] if i < len(segment_rows) else []
            _sig, line = self._compose(segs, eff_w)
            prev = self._prev[i] if self._prev is not None and i < len(self._prev) else None
            if prev == line:
                nxt.append(line)
                continue
            if line:
                sys.stdout.write(f"\033[{i + 1};1H\033[2K{line}")
            else:
                sys.stdout.write(f"\033[{i + 1};1H\033[2K")
            nxt.append(line)
        self._prev = nxt
        sys.stdout.flush()

# ---- 内核控制器通信 ----
def _controller_request(method, path, payload=None, timeout=4):
    try:
        req = urllib.request.Request(
            CONTROLLER + path,
            data=payload,
            method=method,
            headers={"Authorization": "Bearer aethercore", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status, resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return False, 0, ""

_NODE_CACHE = {"t": 0.0, "items": [], "loading": False}
_NODE_TTL = 30.0
SEEN_PROCESSES = {}

def _refresh_nodes_async():
    if _NODE_CACHE.get("loading"):
        return
    _NODE_CACHE["loading"] = True
    def work():
        try:
            ok, _, text = _controller_request("GET", "/proxies", timeout=3)
            if ok and text:
                data = json.loads(text)
                group = data.get("proxies", {}).get(MANUAL_GROUP, {})
                now = group.get("now", "")
                items = [(n, n == now) for n in group.get("all", [])]
                if items:
                    _NODE_CACHE["items"] = items
                    _NODE_CACHE["t"] = time.time()
        except Exception:
            pass
        finally:
            _NODE_CACHE["loading"] = False
    threading.Thread(target=work, daemon=True, name="node-refresh").start()

def list_manual_nodes():
    if not _NODE_CACHE["items"] or (time.time() - _NODE_CACHE["t"] >= _NODE_TTL):
        ok, _, text = _controller_request("GET", "/proxies", timeout=1.5)
        if ok and text:
            try:
                data = json.loads(text)
                proxies = data.get("proxies", {})
                group = None
                for k, v in proxies.items():
                    if "MANUAL" in k or "手动" in k:
                        group = v
                        break
                if not group and proxies:
                    group = next(iter(proxies.values()))
                if group:
                    now = group.get("now", "")
                    items = [(n, n == now) for n in group.get("all", [])]
                    if items:
                        _NODE_CACHE["items"] = items
                        _NODE_CACHE["t"] = time.time()
                        return items
            except Exception:
                pass
        _refresh_nodes_async()
    return _NODE_CACHE["items"]

def select_manual_node(name: str) -> bool:
    payload = json.dumps({"name": name}).encode("utf-8")
    for grp in ("🎮 手动节点 (MANUAL)", MANUAL_GROUP):
        ok, status, _ = _controller_request("PUT", "/proxies/" + urllib.parse.quote(grp), payload)
        if ok and (status in (200, 204)):
            return True
    return False

# ---- 分应用代理与配置热重载 ----
def apply_app_rules_async():
    def worker():
        try:
            push_status("[i] 正在应用分应用代理规则...")
            ok, _ = run_gen(fetch=False, echo=False)
            if ok:
                # 优先使用控制器热重载 PUT /configs
                payload = json.dumps({"path": CORE_CONF}).encode("utf-8")
                hot_ok, status, _ = _controller_request("PUT", "/configs", payload, timeout=5)
                if hot_ok and status in (200, 204):
                    push_status("[ok] 分应用代理规则已热重载生效")
                    return
                # 回退到完整重启内核
                if restart_core():
                    push_status("[ok] 分应用代理规则已生效（重启内核）")
                else:
                    push_status("[x] 分应用规则应用失败（内核未就绪?）")
            else:
                push_status("[x] 分应用规则配置生成失败")
        except Exception as e:
            push_status(f"[x] 分应用规则应用异常: {e}")
    threading.Thread(target=worker, daemon=True, name="app-rules").start()

def update_subscription_async(trigger_name="自动更新"):
    """异步拉取最新订阅，生成配置并通过控制器热重载 (PUT /configs)"""
    def worker():
        try:
            push_status(f"[i] 正在{trigger_name}拉取订阅...")
            ok, _ = run_gen(fetch=True, echo=False)
            if ok:
                payload = json.dumps({"path": CORE_CONF}).encode("utf-8")
                hot_ok, status, _ = _controller_request("PUT", "/configs", payload, timeout=5)
                if hot_ok and status in (200, 204):
                    push_status(f"[ok] 订阅已更新并热重载生效 ({trigger_name})")
                    _refresh_nodes_async()
                    _refresh_sub_traffic()
                else:
                    if restart_core():
                        push_status(f"[ok] 订阅已更新，内核已重载 ({trigger_name})")
                    else:
                        push_status(f"[x] 订阅更新完成但重载内核失败")
            else:
                push_status(f"[!] 订阅拉取失败，保留当前配置 ({trigger_name})")
        except Exception as e:
            push_status(f"[x] 订阅更新异常: {e}")
    threading.Thread(target=worker, daemon=True, name="sub-updater").start()

def _auto_update_loop(stopping):
    """后台循环：每 6 小时自动拉取订阅并热重载配置"""
    while not stopping.is_set():
        stopping.wait(timeout=AUTO_UPDATE_INTERVAL)
        if not stopping.is_set():
            update_subscription_async("定时任务")

def set_app_target(proc, target):
    rules_set(proc, target)
    apply_app_rules_async()

def remove_app_target(proc):
    rules_del(proc)
    apply_app_rules_async()

def format_bytes(b) -> str:
    try:
        val = float(b or 0)
    except Exception:
        return "0 B"
    if val < 1:
        return "0 B"
    elif val < 1024:
        return f"{val:.0f} B"
    elif val < 1024 * 1024:
        return f"{val / 1024:.1f} KB"
    elif val < 1024 ** 3:
        return f"{val / (1024 * 1024):.2f} MB"
    elif val < 1024 ** 4:
        return f"{val / (1024 ** 3):.2f} GB"
    else:
        return f"{val / (1024 ** 4):.2f} TB"

# ---- 状态消息队列 ----
console_status_queue = queue.Queue()

def push_status(msg=""):
    try:
        console_status_queue.put(str(msg))
    except Exception:
        pass

class ConnectionTable:
    def __init__(self, max_rows=25):
        self.max_rows = max_rows
        self.rows = collections.OrderedDict()

    def upsert(self, key, entry):
        if key in self.rows:
            r = self.rows[key]
            r["count"] += 1
            r["time"] = entry["time"]
            r["proc"] = entry["proc"]
            r["node_plain"] = entry["node_plain"]
            r["node_prefix"] = entry["node_prefix"]
            r["target"] = entry["target"]
            r["proto"] = entry["proto"]
            if "status" in entry:
                r["status"] = entry["status"]
            return False
        e = dict(entry)
        e["count"] = 1
        e["status"] = entry.get("status", "ACTIVE")
        self.rows[key] = e
        if len(self.rows) > self.max_rows:
            self.rows.popitem(last=False)
        return True

    def update_status(self, target, status, node_override=None):
        target_clean = target.split(":")[0].strip().lower()
        matched = False
        for k, r in self.rows.items():
            r_target = r["target"].split(":")[0].strip().lower()
            if r_target == target_clean or r["target"] == target:
                r["status"] = status
                if node_override:
                    r["node_plain"] = node_override
                matched = True
        return matched

TRAFFIC = {"up": 0, "down": 0}
RECENT_LOGS = collections.deque(maxlen=300)

def _traffic_stream():
    while not _CORE_STOP_EVENT.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(('127.0.0.1', 9097))
            req = 'GET /traffic HTTP/1.1\r\nHost: 127.0.0.1:9097\r\nAuthorization: Bearer aethercore\r\nConnection: keep-alive\r\n\r\n'
            s.sendall(req.encode('ascii'))
            buffer = ""
            while not _CORE_STOP_EVENT.is_set():
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk.decode('utf-8', errors='ignore')
                    while '\n' in buffer:
                        ln, buffer = buffer.split('\n', 1)
                        ln = ln.strip()
                        if ln.startswith('{'):
                            try:
                                d = json.loads(ln)
                                TRAFFIC["up"] = int(d.get("up", 0))
                                TRAFFIC["down"] = int(d.get("down", 0))
                            except Exception:
                                pass
                except socket.timeout:
                    continue
        except Exception:
            if _CORE_STOP_EVENT.is_set():
                break
            time.sleep(1.0)
        finally:
            try:
                s.close()
            except Exception:
                pass

def _log_stream(table, seen_procs, log_fp, stopping, tui_active_fn):
    re_conn = re.compile(
        r'\[(?P<proto>[A-Za-z0-9_-]+)\]\s+(?P<src>[^\s]+)\s+-->\s+(?P<target>[^\s]+)\s+(?:match\s+(?P<rule>[^\s]+)\s+)?using\s+(?P<node>.+)'
    )
    re_proc_paren = re.compile(r'\(([^)]+)\)')
    re_closed = re.compile(r'\[CLOSED\]\s+(?:\((?P<proc>[^)]+)\)\s+)?(?P<target>[^\s]+)')
    re_timeout = re.compile(r'\[TIMEOUT\]\s+(?:\((?P<proc>[^)]+)\)\s+)?(?P<target>[^\s]+)')
    re_fallback = re.compile(r'\[FALLBACK\]\s+(?:\((?P<proc>[^)]+)\)\s+)?(?P<target>[^\s]+)')
    re_fail = re.compile(r'\[FAIL\]\s+(?:\((?P<proc>[^)]+)\)\s+)?(?P<target>[^\s]+)')
    re_success = re.compile(r'\[SUCCESS\]\s+(?:\((?P<proc>[^)]+)\)\s+)?(?P<target>[^\s]+)')

    while not stopping.is_set() and not _CORE_STOP_EVENT.is_set():
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(('127.0.0.1', 9097))
            req = 'GET /logs HTTP/1.1\r\nHost: 127.0.0.1:9097\r\nAuthorization: Bearer aethercore\r\nConnection: keep-alive\r\n\r\n'
            s.sendall(req.encode('ascii'))
            buffer = ""
            while not stopping.is_set() and not _CORE_STOP_EVENT.is_set():
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk.decode('utf-8', errors='replace')
                    while '\n' in buffer:
                        ln, buffer = buffer.split('\n', 1)
                        ln = ln.strip()
                        if not ln or not ln.startswith('{'):
                            continue
                        try:
                            d = json.loads(ln)
                        except Exception:
                            continue
                        payload = d.get("payload", "").strip()
                        if not payload:
                            continue

                        now_str = time.strftime("%H:%M:%S")
                        RECENT_LOGS.append((now_str, payload))

                        # 写入 traffic.log 文件
                        try:
                            if log_fp:
                                log_fp.write(f"[{now_str}] {payload}\n")
                                log_fp.flush()
                        except Exception:
                            pass

                        # 捕获异常断开 / 超时 / 降级直连 / 成功状态
                        m_closed = re_closed.search(payload)
                        if m_closed:
                            t_target = m_closed.group("target")
                            t_proc = m_closed.group("proc") or "App"
                            table.update_status(t_target, "CLOSED")
                            push_status(f"⚠️ [{t_proc}] {t_target} 网页访问被远端服务器掐断(ERR_CONNECTION_CLOSED)，已自动切换直连自愈！")

                        m_timeout = re_timeout.search(payload)
                        if m_timeout:
                            t_target = m_timeout.group("target")
                            t_proc = m_timeout.group("proc") or "App"
                            table.update_status(t_target, "TIMEOUT")
                            push_status(f"⏱️ [{t_proc}] {t_target} 响应超时(ERR_TIMED_OUT)，已自动切换直连自愈！")

                        m_fallback = re_fallback.search(payload)
                        if m_fallback:
                            t_target = m_fallback.group("target")
                            t_proc = m_fallback.group("proc") or "App"
                            table.update_status(t_target, "FALLBACK", "⚡ 自动直连 (自愈)")
                            push_status(f"⚡ [{t_proc}] {t_target} 已切换为直连白名单，重试即可正常打开！")

                        m_fail = re_fail.search(payload)
                        if m_fail:
                            t_target = m_fail.group("target")
                            table.update_status(t_target, "FAIL")

                        m_succ = re_success.search(payload)
                        if m_succ:
                            t_target = m_succ.group("target")
                            table.update_status(t_target, "OK")

                        # 尝试匹配连接日志并存入 ConnectionTable
                        m = re_conn.search(payload)
                        if m:
                            proto = m.group("proto").upper()
                            src = m.group("src")
                            target = m.group("target")
                            node_raw = m.group("node").strip().strip("'\"")

                            proc = "App"
                            m_proc = re_proc_paren.search(src)
                            if m_proc:
                                proc = m_proc.group(1)
                            elif ":" in src:
                                try:
                                    sport = int(src.rsplit(":", 1)[1])
                                    proc = get_process_for_port(sport) or "App"
                                except Exception:
                                    proc = "App"

                            node_prefix = Color.YELLOW if "DIRECT" in node_raw.upper() else Color.CYAN
                            entry = {
                                "time": now_str,
                                "proc": proc,
                                "node_plain": node_raw,
                                "node_prefix": node_prefix,
                                "target": target,
                                "proto": proto,
                                "status": "ACTIVE",
                            }
                            key = (proc, target, proto)
                            table.upsert(key, entry)
                            seen_procs[proc] = seen_procs.get(proc, 0) + 1

                            if not tui_active_fn():
                                node_color = Color.YELLOW if "DIRECT" in node_raw.upper() else Color.CYAN
                                print(f"{Color.WHITE}[{now_str}]{Color.RESET} "
                                      f"{Color.MAGENTA}[{proto}]{Color.RESET} "
                                      f"{Color.GREEN}[{proc}]{Color.RESET} ➔ "
                                      f"{node_color}[{node_raw}]{Color.RESET} ➔ "
                                      f"🎯 {Color.WHITE}{target}{Color.RESET}")
                        else:
                            if not (m_closed or m_fallback or m_fail or m_succ):
                                push_status(payload)
                            if not tui_active_fn():
                                if "[x]" in payload or "error" in payload.lower() or "[closed]" in payload.lower():
                                    c = Color.RED
                                elif "[i]" in payload:
                                    c = Color.CYAN
                                elif "[fallback]" in payload.lower():
                                    c = Color.YELLOW
                                else:
                                    c = Color.WHITE
                                print(f"{Color.WHITE}[{now_str}]{Color.RESET} {c}{payload}{Color.RESET}")
                except socket.timeout:
                    continue
        except Exception:
            if stopping.is_set() or _CORE_STOP_EVENT.is_set():
                break
            time.sleep(1.0)
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

def _make_col_divider(start: str, sep: str, end: str, col_widths: list, total_width: int) -> str:
    """生成精确等宽的表格行分隔线"""
    parts = []
    for i, cw in enumerate(col_widths):
        if i == 0:
            parts.append(start + ("─" * cw))
        else:
            parts.append(sep + ("─" * cw))
    parts.append(end)
    res = "".join(parts)
    diff = total_width - _disp_width(res)
    if diff > 0:
        res = res[:-len(end)] + ("─" * diff) + end
    elif diff < 0:
        res = res[:total_width - len(end)] + end
    return res


def _build_header_card(width: int, height: int, active_tab: int, up: int, down: int,
                       up_spd: float, down_spd: float, extra_badge: str = "") -> list:
    """构建统一的顶栏监控仪表盘与选项卡"""
    colors = Color()
    rows = []

    # 1. 顶边框 + 运行状态胶囊 + 时间戳
    t_now = time.strftime("%H:%M:%S")
    b_left = "╭─[ "
    title_parts = [
        ("[运行正常]", colors.GREEN + colors.BOLD),
        (" ]──[ ", colors.GRAY),
        ("AetherCore 代理网关", colors.CYAN + colors.BOLD),
        (" ]", colors.GRAY),
    ]
    if width < 85:
        b_right = f"──[ {t_now} ]─╮"
    else:
        b_right = f"──[ 127.0.0.1:7899 ]──[ {t_now} ]─╮"
    w_title = sum(_disp_width(p[0]) for p in title_parts)
    rem = max(width - _disp_width(b_left) - _disp_width(b_right) - w_title, 0)

    row1 = [(b_left, colors.GRAY)] + title_parts + [("─" * rem, colors.GRAY), (b_right, colors.GRAY)]
    rows.append(row1)

    # 2. 统计速率栏 (出口节点、实时上行/下行速率与总量)
    node_name = "默认节点"
    node_count = 0
    try:
        import core.aether_core as ac
        if ac.g_cfg and ac.g_cfg.nodes:
            node_name = ac.g_cfg.nodes[ac.g_cfg.current_node].name
            node_count = ac.g_cfg.node_count
    except Exception:
        pass

    node_disp = _truncate(node_name, 14 if width < 90 else 22)
    s_node = f" 节点: {node_disp} " if width < 90 else f" 节点: {node_disp} ({node_count}个) "
    s_up = f" 上行: {format_bytes(up_spd)}/s " if width < 90 else f" 上行: {format_bytes(up_spd)}/s ({format_bytes(up)}) "
    s_down = f" 下行: {format_bytes(down_spd)}/s " if width < 90 else f" 下行: {format_bytes(down_spd)}/s ({format_bytes(down)}) "
    if _TUN_MODE["active"]:
        s_mode = " 模式: TUN全局接管 "
        c_mode = colors.GREEN + colors.BOLD
    elif _TUN_MODE.get("error"):
        err_b = _truncate(_TUN_MODE["error"], 16)
        s_mode = f" 模式: TUN异常({err_b}) "
        c_mode = colors.RED + colors.BOLD
    elif not parse_tun_enabled(CORE_CONF):
        s_mode = " 模式: 仅内核代理 "
        c_mode = colors.YELLOW
    else:
        s_mode = " 模式: 全量代理 "
        c_mode = colors.YELLOW

    div = "│"
    w_content = _disp_width(s_node) + 1 + _disp_width(s_up) + 1 + _disp_width(s_down)
    if w_content + 1 + _disp_width(s_mode) <= width - 2:
        w_content += 1 + _disp_width(s_mode)
        include_mode = True
    else:
        include_mode = False

    rem_spaces = max(width - 2 - w_content, 0)

    row2 = [
        ("│", colors.GRAY),
        (s_node, colors.CYAN),
        (div, colors.GRAY),
        (s_up, colors.GREEN),
        (div, colors.GRAY),
        (s_down, colors.BLUE + colors.BOLD),
    ]
    if include_mode:
        row2.extend([
            (div, colors.GRAY),
            (s_mode, c_mode),
        ])
    row2.extend([
        (" " * rem_spaces, ""),
        ("│", colors.GRAY),
    ])
    rows.append(row2)

    # 2b. 订阅剩余流量栏 (醒目文字展示，无需图标)
    with _SUB_TRAFFIC_LOCK:
        st_up    = _SUB_TRAFFIC["upload"]
        st_down  = _SUB_TRAFFIC["download"]
        st_total = _SUB_TRAFFIC["total"]
        st_exp   = _SUB_TRAFFIC["expire"]
        st_at    = _SUB_TRAFFIC["fetched_at"]

    if st_total > 0:
        used = st_up + st_down
        remain = max(st_total - used, 0)
        pct = (used / st_total) * 100

        tag_text = "【剩余流量】"
        val_text = f" {format_bytes(remain)} "
        val_color = colors.GREEN + colors.BOLD if pct < 80 else (colors.YELLOW + colors.BOLD if pct < 95 else colors.RED + colors.BOLD)

        if width < 85:
            s_used = f" 已用: {format_bytes(used)} "
            s_total = f" 总量: {format_bytes(st_total)} "
            s_ratio = f" 占比: {pct:.1f}% "
        else:
            s_used = f" 已用流量: {format_bytes(used)} "
            s_total = f" 总额度: {format_bytes(st_total)} "
            s_ratio = f" 已用占比: {pct:.1f}% "

        row_tr = [
            ("│", colors.GRAY),
            (" ", ""),
            (tag_text, colors.CYAN + colors.BOLD),
            (val_text, val_color),
            ("│", colors.GRAY),
            (s_used, colors.WHITE),
            ("│", colors.GRAY),
            (s_total, colors.WHITE),
            ("│", colors.GRAY),
            (s_ratio, colors.YELLOW if pct >= 80 else colors.GRAY),
        ]

        if st_exp:
            try:
                exp_ts = int(st_exp)
                if exp_ts > 0:
                    exp_text = f" 到期时间: {time.strftime('%Y-%m-%d', time.localtime(exp_ts))} "
                else:
                    exp_text = ""
            except Exception:
                exp_text = f" 到期时间: {st_exp} "
            if exp_text:
                curr_w = sum(_disp_width(x[0]) for x in row_tr)
                if curr_w + 1 + _disp_width(exp_text) <= width - 2:
                    row_tr.extend([
                        ("│", colors.GRAY),
                        (exp_text, colors.CYAN),
                    ])

        curr_w = sum(_disp_width(x[0]) for x in row_tr)
        rem_tr = max(width - 1 - curr_w, 0)
        row_tr.extend([
            (" " * rem_tr, ""),
            ("│", colors.GRAY),
        ])
        rows.append(row_tr)
    else:
        status_tip = " 订阅剩余流量: 正在同步额度信息... " if st_at == 0.0 else " 订阅剩余流量: 暂未获取到额度数据 "
        rem_f = max(width - 2 - _disp_width(status_tip), 0)
        rows.append([
            ("│", colors.GRAY),
            (status_tip, colors.YELLOW if st_at == 0.0 else colors.GRAY),
            (" " * rem_f, ""),
            ("│", colors.GRAY),
        ])

    # 3. 选项卡分隔线
    rows.append([
        ("├─┬", colors.GRAY),
        ("─" * (width - 4), colors.GRAY),
        ("┤", colors.GRAY),
    ])

    # 4. 选项卡栏
    t1_style = (colors.CYAN + colors.BOLD + colors.REVERSE) if active_tab == 1 else (colors.WHITE)
    t2_style = (colors.CYAN + colors.BOLD + colors.REVERSE) if active_tab == 2 else (colors.WHITE)
    t3_style = (colors.CYAN + colors.BOLD + colors.REVERSE) if active_tab == 3 else (colors.WHITE)
    t4_style = (colors.CYAN + colors.BOLD + colors.REVERSE) if active_tab == 4 else (colors.WHITE)

    if width < 95:
        t1_txt = "[1]活动" if active_tab == 1 else " 1 活动"
        t2_txt = "[2]日志" if active_tab == 2 else " 2 日志"
        t3_txt = "[3]分流" if active_tab == 3 else " 3 分流"
        t4_txt = "[4]节点" if active_tab == 4 else " 4 节点"
    else:
        t1_txt = " [1] 活动连接 " if active_tab == 1 else "  1  活动连接  "
        t2_txt = " [2] 实时日志 " if active_tab == 2 else "  2  实时日志  "
        t3_txt = " [3] 进程分流 " if active_tab == 3 else "  3  进程分流  "
        t4_txt = " [4] 节点选择 " if active_tab == 4 else "  4  节点选择  "

    tabs_w = _disp_width(t1_txt) + 1 + _disp_width(t2_txt) + 1 + _disp_width(t3_txt) + 1 + _disp_width(t4_txt)
    badge_w = (_disp_width(extra_badge) + 1) if extra_badge else 0
    if tabs_w + badge_w > width - 2:
        extra_badge = ""
        badge_w = 0
    rem_tab_spaces = max(width - 2 - tabs_w - badge_w, 0)

    row4 = [
        ("│", colors.GRAY),
        (t1_txt, t1_style),
        ("│", colors.GRAY),
        (t2_txt, t2_style),
        ("│", colors.GRAY),
        (t3_txt, t3_style),
        ("│", colors.GRAY),
        (t4_txt, t4_style),
        (" " * rem_tab_spaces, ""),
    ]
    if extra_badge:
        row4.append((extra_badge + " ", colors.GRAY))
    row4.append(("│", colors.GRAY))
    rows.append(row4)

    return rows


def _build_frame(table, last_status, width, height, up, down, up_spd, down_spd,
                 proto_filter=None, sort_mode="time", keys_hint="", seen_procs_cnt=0):
    colors = Color()
    filter_txt = f"筛选:{proto_filter}" if proto_filter else "筛选:全部"
    sort_txt = "排序:频次" if sort_mode == "count" else "排序:时间"
    badge = f"[{filter_txt} │ {sort_txt}]"

    rows = _build_header_card(width, height, active_tab=1, up=up, down=down,
                              up_spd=up_spd, down_spd=down_spd, extra_badge=badge)

    # 列宽计算 (根据终端宽度自适应各列，支持窄屏模式)
    if width < 90:
        w_time = 8
        w_proc = 10
        w_node = 12
        w_proto = 5
        w_status = 9
        w_count = 4
    elif width < 110:
        w_time = 8
        w_proc = 12
        w_node = 16
        w_proto = 6
        w_status = 10
        w_count = 4
    else:
        w_time = 8
        w_proc = 14
        w_node = 18
        w_proto = 6
        w_status = 11
        w_count = 5

    overhead = 2 + (3 * 6) + 2  # 22
    w_fixed = w_time + w_proc + w_node + w_proto + w_status + w_count + overhead
    w_target = max(width - w_fixed, 6)
    diff = width - (w_time + w_proc + w_node + w_target + w_proto + w_status + w_count + overhead)
    w_target += diff

    cols = [w_time, w_proc, w_node, w_target, w_proto, w_status, w_count]
    col_div = _make_col_divider("├─┴─", "─┬─", "─┤", cols, width)
    rows.append([(col_div, colors.GRAY)])

    # 表头
    rows.append([
        ("│ ", colors.GRAY),
        (_pad_disp("时间", w_time, "center"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("进程名称", w_proc, "left"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("出口节点", w_node, "left"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("目标地址 (域名:端口)", w_target, "left"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("协议", w_proto, "center"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("状态", w_status, "center"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("频次", w_count, "right"), colors.WHITE + colors.BOLD),
        (" │", colors.GRAY),
    ])

    head_div = _make_col_divider("├─", "─┼─", "─┤", cols, width)
    rows.append([(head_div, colors.GRAY)])

    max_data = max(height - 11, 1)
    items = list(table.rows.items())
    if sort_mode == "count":
        items = sorted(items, key=lambda kv: -kv[1]["count"])
    else:
        items = list(reversed(items))

    if proto_filter:
        items = [it for it in items if it[1]["proto"].upper() == proto_filter]

    added = 0
    if not items:
        empty_row = (
            "│ " + _pad_disp("⚡ 暂无活动连接，打开浏览器或应用程序访问网络即可在此捕获...", width - 4, "center") + " │"
        )
        rows.append([(empty_row, colors.GRAY)])
        added = 1
    else:
        for key, r in items:
            if added >= max_data:
                break
            proto = r["proto"].upper()
            proto_c = colors.CYAN if "HTTP" in proto else (colors.MAGENTA if "TCP" in proto else colors.YELLOW)
            cnt = r["count"]
            if cnt >= 50:
                cnt_c = colors.RED + colors.BOLD
            elif cnt >= 10:
                cnt_c = colors.YELLOW + colors.BOLD
            elif cnt >= 2:
                cnt_c = colors.GREEN + colors.BOLD
            else:
                cnt_c = colors.GRAY

            node_disp = r["node_plain"]
            node_c = colors.YELLOW if "DIRECT" in node_disp.upper() else colors.CYAN

            # 状态判定
            st = r.get("status", "ACTIVE")
            if st == "CLOSED":
                st_text = "❌ 断开" if w_status <= 10 else "❌ 异常断开"
                st_color = colors.RED + colors.BOLD
            elif st == "TIMEOUT":
                st_text = "⏱ 超时" if w_status <= 10 else "⏱ 响应超时"
                st_color = colors.MAGENTA + colors.BOLD
            elif st == "FAIL":
                st_text = "❌ 失败" if w_status <= 10 else "❌ 节点失败"
                st_color = colors.RED + colors.BOLD
            elif st == "FALLBACK":
                st_text = "⚠️ 直连" if w_status <= 10 else "⚠️ 自动直连"
                st_color = colors.YELLOW + colors.BOLD
            elif st == "OK":
                st_text = "✔ 正常" if w_status <= 10 else "✔ 正常连通"
                st_color = colors.GREEN
            else:
                st_text = "⚡ 活跃" if w_status <= 10 else "⚡ 传输中"
                st_color = colors.CYAN

            row = [
                ("│ ", colors.GRAY),
                (_pad_disp(r["time"], w_time, "center"), colors.GRAY),
                (" │ ", colors.GRAY),
                (_pad_disp(f"[{r['proc']}]", w_proc, "left"), colors.GREEN),
                (" │ ", colors.GRAY),
                (_pad_disp(node_disp, w_node, "left"), node_c),
                (" │ ", colors.GRAY),
                (_pad_disp(r["target"], w_target, "left"), colors.WHITE),
                (" │ ", colors.GRAY),
                (_pad_disp(proto, w_proto, "center"), proto_c),
                (" │ ", colors.GRAY),
                (_pad_disp(st_text, w_status, "center"), st_color),
                (" │ ", colors.GRAY),
                (_pad_disp(f"x{cnt}", w_count, "right"), cnt_c),
                (" │", colors.GRAY),
            ]
            rows.append(row)
            added += 1

    while added < max_data:
        blank_line = "│" + (" " * (width - 2)) + "│"
        rows.append([(blank_line, colors.GRAY)])
        added += 1

    # 底部通知与快捷键栏
    status_div = "├─" + ("─" * (width - 4)) + "─┤"
    rows.append([(status_div, colors.GRAY)])

    if _TUN_MODE["active"]:
        default_status = "🔔 状态: 服务正常运转中 (TUN 全局网络接管)"
    else:
        default_status = "🔔 状态: 服务正常运转中"
    status_txt = last_status or default_status
    status_line = "│ " + _pad_disp(status_txt, width - 4, "left") + " │"
    rows.append([(status_line, colors.YELLOW)])

    total_ev = sum(r["count"] for r in table.rows.values())
    if width < 90:
        left_keys = "╰─ [Q]退出 [Tab]视图 [4]节点 [S]排序 [F]过滤"
        right_info = f"──[{len(table.rows)}条]─╯"
    else:
        left_keys = "╰─ [Q]退出  [Tab/2]日志  [3]分流  [4/N]选节点  [U]更新订阅  [S]排序  [F]过滤  [D]清空"
        right_info = f"──[ 活动:{len(table.rows)} 总计:{total_ev} ]─╯"
    rem_foot = max(width - _disp_width(left_keys) - _disp_width(right_info), 0)
    rows.append([
        (left_keys, colors.CYAN),
        ("─" * rem_foot, colors.GRAY),
        (right_info, colors.GRAY),
    ])

    return rows


def _build_log_frame(recent_logs, last_status, width, height, up, down, up_spd, down_spd, conn_cnt=0, proc_cnt=0):
    colors = Color()
    badge = f"[共 {len(recent_logs)} 条日志]"
    rows = _build_header_card(width, height, active_tab=2, up=up, down=down,
                              up_spd=up_spd, down_spd=down_spd, extra_badge=badge)

    rows.append([
        ("├─┴", colors.GRAY),
        ("─" * (width - 4), colors.GRAY),
        ("┤", colors.GRAY),
    ])

    max_data = max(height - 9, 1)
    lines = list(recent_logs)[-max_data:] if max_data > 0 else []

    added = 0
    if not lines:
        empty_row = "│ " + _pad_disp("📜 暂无内核日志输出...", width - 4, "center") + " │"
        rows.append([(empty_row, colors.GRAY)])
        added = 1
    else:
        for t_str, line in lines:
            c = colors.WHITE
            if "[closed]" in line.lower():
                c = colors.RED + colors.BOLD
                tag = "CLOSED"
            elif "[timeout]" in line.lower():
                c = colors.MAGENTA + colors.BOLD
                tag = "TIMEO "
                tag_c = colors.MAGENTA + colors.REVERSE
            elif "[fallback]" in line.lower():
                c = colors.YELLOW + colors.BOLD
                tag = "FALLBK"
                tag_c = colors.YELLOW + colors.REVERSE
            elif "[fail]" in line.lower() or "[x]" in line or "error" in line.lower():
                c = colors.RED + colors.BOLD
                tag = " FAIL "
                tag_c = colors.RED + colors.REVERSE
            elif "[success]" in line.lower():
                c = colors.GREEN
                tag = "  OK  "
                tag_c = colors.GREEN + colors.REVERSE
            elif "[i]" in line:
                c = colors.CYAN
                tag = " INFO "
                tag_c = colors.CYAN + colors.REVERSE
            elif "-->" in line:
                c = colors.GREEN
                tag = "ROUTE "
                tag_c = colors.GREEN + colors.REVERSE
            else:
                tag = " LOG  "
                tag_c = colors.GRAY + colors.REVERSE

            w_prefix = len(f"│ {t_str} [{tag}] ")
            w_line_max = max(width - 4 - w_prefix, 10)
            disp_payload = _truncate(line, w_line_max)
            rem = max(width - 2 - _disp_width(f" {t_str} [{tag}] {disp_payload} "), 0)

            row = [
                ("│ ", colors.GRAY),
                (f"{t_str} ", colors.GRAY),
                (f"[{tag}]", tag_c),
                (f" {disp_payload}", c),
                (" " * rem, ""),
                ("│", colors.GRAY),
            ]
            rows.append(row)
            added += 1

    while added < max_data:
        rows.append([("│" + (" " * (width - 2)) + "│", colors.GRAY)])
        added += 1

    rows.append([("├─" + ("─" * (width - 4)) + "─┤", colors.GRAY)])
    status_txt = last_status or "🔔 提示: 按 [Tab] 或 [1] 返回表格视图，按 [D] 清空当前日志"
    status_line = "│ " + _pad_disp(status_txt, width - 4, "left") + " │"
    rows.append([(status_line, colors.YELLOW)])

    left_keys = "╰─ [1/Tab]返回表格  [3/Enter]分流管理  [D]清空日志  [Q]退出"
    right_info = f"──[ 日志总数: {len(recent_logs)} ]─╯"
    rem_foot = max(width - _disp_width(left_keys) - _disp_width(right_info), 0)
    rows.append([
        (left_keys, colors.CYAN),
        ("─" * rem_foot, colors.GRAY),
        (right_info, colors.GRAY),
    ])

    return rows


def _build_app_panel_frame(seen_procs, panel_idx, width, height, last_status,
                           up=0, down=0, up_spd=0.0, down_spd=0.0):
    colors = Color()
    rules = rules_list()
    procs = sorted(set(rules) | set(seen_procs),
                   key=lambda p: (-seen_procs.get(p, 0), p))
    badge = f"[已捕获 {len(procs)} 个进程 │ 定制 {len(rules)} 条]"
    rows = _build_header_card(width, height, active_tab=3, up=up, down=down,
                              up_spd=up_spd, down_spd=down_spd, extra_badge=badge)

    w_idx = 6
    w_proc = 20
    w_rule = 24
    w_cnt = 12
    overhead = 2 + (3 * 4) + 2  # 16
    w_status = max(width - (w_idx + w_proc + w_rule + w_cnt + overhead), 10)
    w_status += (width - (overhead + w_idx + w_proc + w_rule + w_cnt + w_status))

    cols = [w_idx, w_proc, w_rule, w_cnt, w_status]
    col_div = _make_col_divider("├─┴─", "─┬─", "─┤", cols, width)
    rows.append([(col_div, colors.GRAY)])

    rows.append([
        ("│ ", colors.GRAY),
        (_pad_disp("序号", w_idx, "center"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("进程名称 (EXE)", w_proc, "left"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("当前分流策略", w_rule, "left"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("历史捕获连接", w_cnt, "right"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("规则状态", w_status, "center"), colors.WHITE + colors.BOLD),
        (" │", colors.GRAY),
    ])

    head_div = _make_col_divider("├─", "─┼─", "─┤", cols, width)
    rows.append([(head_div, colors.GRAY)])

    max_data = max(height - 11, 1)
    added = 0
    if not procs:
        empty_row = "│ " + _pad_disp("⚡ 暂无检测到的活动进程，请打开网络应用...", width - 4, "center") + " │"
        rows.append([(empty_row, colors.GRAY)])
        added = 1
    else:
        for i, p in enumerate(procs[:max_data]):
            is_sel = (i == panel_idx)
            mark = "❯ " if is_sel else "  "
            idx_str = f"{mark}{i + 1:02d}"

            r_rule = rules.get(p, "")
            if r_rule.lower() == "direct":
                rule_str = "⚡ 本地直连 (DIRECT)"
                rule_c = colors.GREEN + colors.BOLD
                status_badge = "已指定直连"
            elif r_rule.lower() == "proxy":
                rule_str = "🌐 节点代理 (PROXY)"
                rule_c = colors.CYAN + colors.BOLD
                status_badge = "已指定代理"
            elif r_rule.lower() == "auto":
                rule_str = "🚀 自动优选 (AUTO)"
                rule_c = colors.MAGENTA + colors.BOLD
                status_badge = "已指定优选"
            elif r_rule:
                rule_str = f"🎯 {r_rule}"
                rule_c = colors.YELLOW + colors.BOLD
                status_badge = "指定节点"
            else:
                rule_str = "跟随全局 (默认)"
                rule_c = colors.GRAY
                status_badge = "默认规则"

            cnt = seen_procs.get(p, 0)

            row = [
                ("│ ", colors.GRAY),
                (_pad_disp(idx_str, w_idx, "left"), colors.YELLOW + colors.BOLD if is_sel else colors.GRAY),
                (" │ ", colors.GRAY),
                (_pad_disp(f"[{p}]", w_proc, "left"), colors.GREEN + colors.BOLD if is_sel else colors.GREEN),
                (" │ ", colors.GRAY),
                (_pad_disp(rule_str, w_rule, "left"), rule_c),
                (" │ ", colors.GRAY),
                (_pad_disp(f"{cnt} 次", w_cnt, "right"), colors.WHITE),
                (" │ ", colors.GRAY),
                (_pad_disp(status_badge, w_status, "center"), colors.YELLOW if r_rule else colors.GRAY),
                (" │", colors.GRAY),
            ]
            rows.append(row)
            added += 1

    while added < max_data:
        rows.append([("│" + (" " * (width - 2)) + "│", colors.GRAY)])
        added += 1

    rows.append([("├─" + ("─" * (width - 4)) + "─┤", colors.GRAY)])
    status_txt = last_status or "💡 操作指引: 使用 [↑/↓ 或 J/K] 选中进程，按数字键即时下发规则"
    status_line = "│ " + _pad_disp(status_txt, width - 4, "left") + " │"
    rows.append([(status_line, colors.YELLOW)])

    if width < 96:
        left_keys = "╰─ [↑/↓]选 [1]直连 [2]代理 [3]优选 [X]清 [Esc]返"
        right_info = f"──[{len(rules)}/{len(procs)}]─╯"
    else:
        left_keys = "╰─ [↑/↓/J/K]移动  [1]直连  [2]走代理  [3]自动优选  [X]清除规则  [Esc/Enter]返回"
        right_info = f"──[ 定制: {len(rules)}/{len(procs)} ]─╯"
    rem_foot = max(width - _disp_width(left_keys) - _disp_width(right_info), 0)
    rows.append([
        (left_keys, colors.CYAN),
        ("─" * rem_foot, colors.GRAY),
        (right_info, colors.GRAY),
    ])

    return rows

def _build_node_panel_frame(node_items, panel_idx, width, height, last_status,
                            up=0, down=0, up_spd=0.0, down_spd=0.0):
    colors = Color()
    cur_name = ""
    for n, is_cur in node_items:
        if is_cur:
            cur_name = n
            break
    badge = f"[共 {len(node_items)} 个节点 │ 当前: {cur_name[:14]}]" if cur_name else f"[共 {len(node_items)} 个节点]"
    rows = _build_header_card(width, height, active_tab=4, up=up, down=down,
                              up_spd=up_spd, down_spd=down_spd, extra_badge=badge)

    w_idx = 6
    w_status = 16
    overhead = 2 + (2 * 3) + 2  # 10
    w_name = max(width - (w_idx + w_status + overhead), 20)
    w_name += (width - (overhead + w_idx + w_name + w_status))

    cols = [w_idx, w_name, w_status]
    col_div = _make_col_divider("├─", "─┬─", "─┤", cols, width)
    rows.append([(col_div, colors.GRAY)])

    rows.append([
        ("│ ", colors.GRAY),
        (_pad_disp("序号", w_idx, "center"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("出站节点名称 (地区 / 线路特征)", w_name, "left"), colors.WHITE + colors.BOLD),
        (" │ ", colors.GRAY),
        (_pad_disp("运行状态", w_status, "center"), colors.WHITE + colors.BOLD),
        (" │", colors.GRAY),
    ])

    head_div = _make_col_divider("├─", "─┼─", "─┤", cols, width)
    rows.append([(head_div, colors.GRAY)])

    max_data = max(height - 11, 1)
    added = 0
    if not node_items:
        empty_row = "│ " + _pad_disp("⚡ 正在加载节点列表，请稍候...", width - 4, "center") + " │"
        rows.append([(empty_row, colors.GRAY)])
        added = 1
    else:
        start_idx = 0
        if panel_idx >= max_data:
            start_idx = min(panel_idx - max_data + 1, len(node_items) - max_data)
            start_idx = max(0, start_idx)

        visible_nodes = node_items[start_idx:start_idx + max_data]
        for i_rel, (name, is_cur) in enumerate(visible_nodes):
            i_abs = start_idx + i_rel
            is_sel = (i_abs == panel_idx)
            mark = "❯ " if is_sel else "  "
            idx_str = f"{mark}{i_abs + 1:02d}"

            if is_cur:
                status_str = "● 当前使用中"
                status_c = colors.GREEN + colors.BOLD
                name_c = colors.GREEN + colors.BOLD if not is_sel else colors.YELLOW + colors.BOLD
            else:
                status_str = "回车立即切换" if is_sel else "○ 就绪"
                status_c = colors.YELLOW + colors.BOLD if is_sel else colors.GRAY
                name_c = colors.YELLOW + colors.BOLD if is_sel else colors.WHITE

            row = [
                ("│ ", colors.GRAY),
                (_pad_disp(idx_str, w_idx, "left"), colors.YELLOW + colors.BOLD if is_sel else colors.GRAY),
                (" │ ", colors.GRAY),
                (_pad_disp(name, w_name, "left"), name_c),
                (" │ ", colors.GRAY),
                (_pad_disp(status_str, w_status, "center"), status_c),
                (" │", colors.GRAY),
            ]
            rows.append(row)
            added += 1

    while added < max_data:
        rows.append([("│" + (" " * (width - 2)) + "│", colors.GRAY)])
        added += 1

    rows.append([("├─" + ("─" * (width - 4)) + "─┤", colors.GRAY)])
    status_txt = last_status or "💡 操作指引: 使用 [↑/↓ 或 J/K] 挑选目标节点，按 [Enter] 即可瞬间切换出站出口！"
    status_line = "│ " + _pad_disp(status_txt, width - 4, "left") + " │"
    rows.append([(status_line, colors.YELLOW)])

    cur_pos = panel_idx + 1 if node_items else 0
    if width < 95:
        left_keys = "╰─ [↑/↓]选节点 [Enter]应用 [1]连接 [2]日志 [Esc]返"
        right_info = f"──[{cur_pos}/{len(node_items)}]─╯"
    else:
        left_keys = "╰─ [↑/↓/J/K]挑选节点  [Enter]应用切换  [1]连接  [2]日志  [3]分流  [Esc]返回"
        right_info = f"──[ 节点: {cur_pos}/{len(node_items)} ]─╯"
    rem_foot = max(width - _disp_width(left_keys) - _disp_width(right_info), 0)
    rows.append([
        (left_keys, colors.CYAN),
        ("─" * rem_foot, colors.GRAY),
        (right_info, colors.GRAY),
    ])

    return rows


def _poll_keys():
    keys = []
    try:
        while msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):
                if msvcrt.kbhit():
                    ch2 = msvcrt.getwch()
                    if ch2 == "H":
                        keys.append("UP")
                    elif ch2 == "P":
                        keys.append("DOWN")
                    elif ch2 == "K":
                        keys.append("LEFT")
                    elif ch2 == "M":
                        keys.append("RIGHT")
            elif ch == "\x1b":
                keys.append("ESC")
            elif ch == "\t":
                keys.append("TAB")
            elif ch == "\x03":
                keys.append("CTRL_C")
            else:
                keys.append(ch)
    except Exception:
        pass
    return keys


def restart_core():
    global _CORE_PROC
    _CORE_STOP_EVENT.set()
    import core.aether_core
    core.aether_core.CORE_STOP_EVENT.set()
    if _CORE_PROC:
        _CORE_PROC.wait(timeout=5)
    time.sleep(0.5)
    _CORE_STOP_EVENT.clear()
    core.aether_core.CORE_STOP_EVENT.clear()
    _CORE_PROC = start_core()
    time.sleep(0.5)
    return True

_CORE_PROC = None


def monitor_connections_loop(core_holder, stopping, log_fp):
    global _CORE_PROC, _MONITOR_THREADS
    previous_sigint_handler = signal.getsignal(signal.SIGINT)
    tui = None
    worker_threads = []
    _MONITOR_THREADS = worker_threads

    def handle_sigint(signum, frame):
        if not stopping.is_set():
            if tui is None:
                print(f"\n{Color.YELLOW}[*] 收到 Ctrl+C，正在退出...{Color.RESET}", flush=True)
            else:
                push_status("[*] 收到 Ctrl+C，正在退出...")
            stopping.set()

    signal.signal(signal.SIGINT, handle_sigint)
    use_tui = "--no-tui" not in sys.argv and "--log" not in sys.argv
    if use_tui:
        try:
            tui = Tui()
        except Exception:
            tui = None

    mode_txt = "TUN 全局网络接管" if _TUN_MODE["active"] else "内核入站已就绪"
    if tui is not None:
        print(f"{Color.GREEN}[ok] Python 内核代理服务已就绪（{mode_txt}）！{Color.RESET}")
        print(f"{Color.CYAN}[*] 实时监控各进程出口节点与连接（重复连接自动聚合计数 xN）...{Color.RESET}\n")
        traffic_thread = threading.Thread(target=_traffic_stream, daemon=True, name="traffic")
        traffic_thread.start()
        worker_threads.append(traffic_thread)
    else:
        print(f"{Color.GREEN}[ok] Python 内核代理服务已就绪（{mode_txt}）！{Color.RESET}")
        print(f"{Color.CYAN}[*] 实时日志滚动监听中（所有连接与内核事件自然向下滚动，按 Ctrl+C 退出）...{Color.RESET}\n")

    table = ConnectionTable()
    last_status = ""
    last_render = 0.0
    prev_up = prev_down = 0
    prev_t = time.time()
    ema_up = ema_down = 0.0
    proto_filter = None
    sort_mode = "time"
    view_mode = "table"
    seen_procs = {}
    panel_active = False
    panel_idx = 0
    node_panel_active = False
    node_panel_idx = 0

    # 启动内核日志流监听线程
    log_thread = threading.Thread(
        target=_log_stream,
        args=(table, seen_procs, log_fp, stopping, lambda: tui is not None),
        daemon=True,
        name="log-stream"
    )
    log_thread.start()
    worker_threads.append(log_thread)

    # 启动订阅剩余流量后台刷新线程
    sub_traffic_thread = threading.Thread(
        target=_sub_traffic_loop,
        args=(stopping,),
        daemon=True,
        name="sub-traffic"
    )
    sub_traffic_thread.start()
    worker_threads.append(sub_traffic_thread)

    # 启动 6 小时定时拉取订阅后台刷新线程
    auto_update_thread = threading.Thread(
        target=_auto_update_loop,
        args=(stopping,),
        daemon=True,
        name="sub-auto-update"
    )
    auto_update_thread.start()
    worker_threads.append(auto_update_thread)

    while not stopping.is_set():
        time.sleep(0.05)
        if tui is None:
            # 滚动日志模式：检测键盘按键 q 或 Ctrl+C 退出，u 手动更新订阅
            if msvcrt.kbhit():
                try:
                    ch = msvcrt.getwch()
                    if ch.lower() == "q" or ch == "\x03":
                        stopping.set()
                        break
                    elif ch.lower() == "u":
                        update_subscription_async("手动快捷键")
                except Exception:
                    pass
            if core_holder.poll() is not None:
                if tui is None:
                    print(f"{Color.RED}[x] 内核进程已退出，正在重启...{Color.RESET}")
                else:
                    push_status("[x] 内核进程已退出，正在重启...")
                _CORE_PROC = start_core()
                time.sleep(0.5)
            continue
        if tui is not None:
            now = time.time()
            up = TRAFFIC.get("up", 0)
            down = TRAFFIC.get("down", 0)
            dt = max(now - prev_t, 0.001)
            up_spd = (up - prev_up) / dt
            down_spd = (down - prev_down) / dt
            alpha = 0.3
            ema_up = alpha * up_spd + (1 - alpha) * ema_up if ema_up else up_spd
            ema_down = alpha * down_spd + (1 - alpha) * ema_down if ema_down else down_spd
            prev_up, prev_down = up, down
            prev_t = now

            try:
                while not console_status_queue.empty():
                    last_status = console_status_queue.get_nowait()
            except queue.Empty:
                pass

            keys = _poll_keys()
            keys_hint = ""
            for k in keys:
                if k == "CTRL_C":
                    push_status("[*] 收到 Ctrl+C，正在退出...")
                    stopping.set()
                    break
                elif k in ("4", "n", "N"):
                    node_panel_active = not node_panel_active
                    panel_active = False
                    if node_panel_active:
                        nodes = list_manual_nodes()
                        for i, (nm, is_c) in enumerate(nodes):
                            if is_c:
                                node_panel_idx = i
                                break
                elif k == "TAB":
                    if node_panel_active:
                        node_panel_active = False
                        view_mode = "table"
                    elif panel_active:
                        panel_active = False
                        view_mode = "table"
                    elif view_mode == "table":
                        view_mode = "logs"
                    else:
                        view_mode = "table"
                elif k == "1":
                    node_panel_active = False
                    if panel_active:
                        procs = sorted(set(rules_list()) | set(seen_procs), key=lambda p: (-seen_procs.get(p, 0), p))
                        if 0 <= panel_idx < len(procs):
                            set_app_target(procs[panel_idx], "direct")
                            push_status(f"[ok] 已设置 {procs[panel_idx]} 为 本地直连")
                    else:
                        panel_active = False
                        view_mode = "table"
                elif k == "2":
                    node_panel_active = False
                    if panel_active:
                        procs = sorted(set(rules_list()) | set(seen_procs), key=lambda p: (-seen_procs.get(p, 0), p))
                        if 0 <= panel_idx < len(procs):
                            set_app_target(procs[panel_idx], "proxy")
                            push_status(f"[ok] 已设置 {procs[panel_idx]} 为 走代理")
                    else:
                        panel_active = False
                        view_mode = "logs"
                elif k == "3":
                    node_panel_active = False
                    if panel_active:
                        procs = sorted(set(rules_list()) | set(seen_procs), key=lambda p: (-seen_procs.get(p, 0), p))
                        if 0 <= panel_idx < len(procs):
                            set_app_target(procs[panel_idx], "auto")
                            push_status(f"[ok] 已设置 {procs[panel_idx]} 为 自动优选")
                    else:
                        panel_active = True
                        panel_idx = 0
                elif k.lower() == "l":
                    node_panel_active = False
                    panel_active = False
                    view_mode = "logs" if view_mode == "table" else "table"
                elif k.lower() == "t":
                    node_panel_active = False
                    panel_active = False
                    view_mode = "table"
                elif k in ("p", "ESC", "\x08"):
                    if node_panel_active:
                        node_panel_active = False
                    elif panel_active:
                        panel_active = False
                    elif view_mode == "logs":
                        view_mode = "table"
                elif k == "q":
                    if node_panel_active:
                        node_panel_active = False
                    elif panel_active:
                        panel_active = False
                    elif view_mode == "logs":
                        view_mode = "table"
                    else:
                        stopping.set()
                elif k in ("j", "DOWN"):
                    if node_panel_active:
                        nodes = list_manual_nodes()
                        node_panel_idx = min(max(len(nodes) - 1, 0), node_panel_idx + 1)
                    elif panel_active:
                        procs_len = len(set(rules_list()) | set(seen_procs))
                        panel_idx = min(max(procs_len - 1, 0), panel_idx + 1)
                elif k in ("k", "UP"):
                    if node_panel_active:
                        node_panel_idx = max(0, node_panel_idx - 1)
                    elif panel_active:
                        panel_idx = max(0, panel_idx - 1)
                elif k.lower() == "x" and panel_active:
                    procs = sorted(set(rules_list()) | set(seen_procs), key=lambda p: (-seen_procs.get(p, 0), p))
                    if 0 <= panel_idx < len(procs):
                        remove_app_target(procs[panel_idx])
                        push_status(f"[ok] 已清除 {procs[panel_idx]} 的自定义规则")
                elif k.lower() == "d":
                    if view_mode == "logs":
                        RECENT_LOGS.clear()
                        push_status("[ok] 已清空实时内核日志")
                    else:
                        table.rows.clear()
                        push_status("[ok] 已清空活动连接表")
                elif k.lower() == "f":
                    if proto_filter is None:
                        proto_filter = "TCP"
                    elif proto_filter == "TCP":
                        proto_filter = "UDP"
                    else:
                        proto_filter = None
                elif k.lower() == "s":
                    sort_mode = "count" if sort_mode == "time" else "time"
                elif k.lower() == "u":
                    update_subscription_async("手动快捷键")
                elif k == "\r":
                    if node_panel_active:
                        nodes = list_manual_nodes()
                        if 0 <= node_panel_idx < len(nodes):
                            tgt_name = nodes[node_panel_idx][0]
                            if select_manual_node(tgt_name):
                                push_status(f"🌐 [ok] 已成功切换出站出口为: {tgt_name}")
                                _NODE_CACHE["t"] = 0.0
                            else:
                                push_status(f"❌ [x] 切换节点失败: {tgt_name}")
                        node_panel_active = False
                    else:
                        panel_active = not panel_active
                        panel_idx = 0
                keys_hint += repr(k).strip("'")

            if stopping.is_set():
                break

            w, h = tui.size()
            eff_w = max(w - 1, 20)
            if node_panel_active:
                rows = _build_node_panel_frame(list_manual_nodes(), node_panel_idx, eff_w, h, last_status,
                                              up, down, ema_up, ema_down)
            elif panel_active:
                rows = _build_app_panel_frame(seen_procs, panel_idx, eff_w, h, last_status,
                                             up, down, ema_up, ema_down)
            elif view_mode == "logs":
                rows = _build_log_frame(RECENT_LOGS, last_status, eff_w, h, up, down, ema_up, ema_down,
                                        len(table.rows), len(seen_procs))
            else:
                rows = _build_frame(table, last_status, eff_w, h, up, down, ema_up, ema_down,
                                    proto_filter, sort_mode, keys_hint, len(seen_procs))
            tui.render(rows)
            last_render = now

        if _CORE_PROC and _CORE_PROC.poll() is not None:
            push_status("[x] 内核进程已退出，正在重启...")
            _CORE_PROC = start_core()
            time.sleep(0.5)

    if tui is not None:
        tui.close()
    stopping.set()
    _CORE_STOP_EVENT.set()
    _join_monitor_threads()
    signal.signal(signal.SIGINT, previous_sigint_handler)


def _join_monitor_threads(timeout=3):
    for worker_thread in list(_MONITOR_THREADS):
        if worker_thread.is_alive():
            worker_thread.join(timeout=timeout)
    _MONITOR_THREADS.clear()


def shutdown_runtime(stopping=None):
    """统一停止核心和所有监控线程，保证退出路径幂等。"""
    stop_tun_engine()
    _CORE_STOP_EVENT.set()
    if stopping is not None:
        stopping.set()
    import core.aether_core
    core.aether_core.CORE_STOP_EVENT.set()
    if _CORE_PROC:
        _CORE_PROC.wait(timeout=5)
    _join_monitor_threads()


def main():
    global _CORE_PROC
    disable_quick_edit()
    print(f"{Color.CYAN}{Color.BOLD}AetherCore - 纯 Python 透明代理网关{Color.RESET}")
    print(f"{Color.YELLOW}[*] 工作目录: {WORKSPACE_DIR}{Color.RESET}")
    print(f"{Color.YELLOW}[*] 数据目录: {DATA_DIR}{Color.RESET}")

    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)

    if not is_admin():
        elevate_admin()
        return 0

    # 自动关闭正在运行的旧实例 / 内核残留进程，直接接管服务（无需用户手动退出旧实例）
    killed = kill_old_instances()
    if killed:
        print(f"{Color.YELLOW}[*] 检测到已有旧实例正在运行，已自动关闭旧实例并接管服务{Color.RESET}")

    ensure_single_instance(create=True)
    kill_conflicting_proxies()

    # 生成配置：若已有本地 core.conf 则秒起，后台异步更新订阅；若不存在则同步生成
    if os.path.exists(CORE_CONF) and os.path.getsize(CORE_CONF) > 0:
        print(f"{Color.GREEN}[ok] 检测到已有内核配置，正在快速启动...{Color.RESET}")
        update_subscription_async("启动后台")
    else:
        print(f"{Color.YELLOW}[*] 未检测到有效内核配置，正在拉取订阅...{Color.RESET}")
        ok, _ = run_gen(fetch=True, echo=True)
        if not ok:
            print(f"{Color.YELLOW}[!] 首次配置生成失败，尝试从缓存生成...{Color.RESET}")
            run_gen(fetch=False, echo=True)

    # 启动内核
    _CORE_PROC = start_core()
    time.sleep(0.5)

    # TUN 全局网络接管
    if parse_tun_enabled(CORE_CONF):
        host, port = parse_listen_addr(CORE_CONF)
        if not wait_core_listen(host, port):
            err_msg = f"[x] 内核监听 ({host}:{port}) 未就绪，无法启动 TUN"
            try:
                import core.aether_core as ac
                ac.core_log(f"[tun] {err_msg}")
            except Exception:
                pass
            print(f"{Color.RED}{err_msg}{Color.RESET}")
        else:
            try:
                start_tun_engine()
                _TUN_MODE["active"] = True
                msg = "[ok] TUN 全局接管已开启 (IPv4+IPv6, Fake-IP DNS)"
                try:
                    import core.aether_core as ac
                    ac.core_log(f"[tun] {msg}")
                except Exception:
                    pass
                print(f"{Color.GREEN}{msg}{Color.RESET}")
            except Exception as e:
                _TUN_MODE["error"] = str(e)
                err_msg = f"[x] TUN 模式启动失败: {e}"
                try:
                    import core.aether_core as ac
                    ac.core_log(f"[tun] {err_msg}")
                except Exception:
                    pass
                print(f"{Color.RED}{err_msg}{Color.RESET}")
    else:
        print(f"{Color.YELLOW}[!] TUN 模式已在 core.conf 中关闭 (tun off){Color.RESET}")

    # 打开日志文件
    log_fp = open(LOG_FILE, "a", encoding="utf-8", buffering=1) if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) < LOG_MAX_BYTES else rotate_log(open(LOG_FILE, "a", encoding="utf-8", buffering=1))

    # 进入监控循环
    stopping = threading.Event()
    try:
        monitor_connections_loop(_CORE_PROC, stopping, log_fp)
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[*] 收到 Ctrl+C，正在退出...{Color.RESET}", flush=True)
    finally:
        print(f"\n{Color.YELLOW}[*] 正在关闭...{Color.RESET}")
        shutdown_runtime(stopping)
        try:
            log_fp.close()
        except Exception:
            pass
        print(f"{Color.GREEN}[ok] 已安全退出{Color.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        try:
            core_log_path = os.path.join(DATA_DIR, "core.log")
            with open(core_log_path, "a", encoding="utf-8", errors="ignore") as f:
                f.write(f"\n[CRASH] Launcher unhandled exception:\n{tb}\n")
        except Exception:
            pass
        print(f"\n{Color.RED}[x] 未捕获异常: {e}{Color.RESET}")
        traceback.print_exc()
        input("\n按回车退出...")
