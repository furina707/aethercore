#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AetherCore - 全自动透明代理与单进程独占分流管理器
自动更新订阅 -> 生成单进程分流配置 -> 启动高性能内核 -> 实时监控每个应用的出口节点与带宽
"""

import os
import sys
import io
import time
import json
import socket
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

# 纯 Python 核心模块（替代 C 原生二进制）
from core.aether_rules import rules_list as py_rules_list, rules_set as py_rules_set, \
    rules_del as py_rules_del, get_rules_path as py_rules_path
from core.aether_gen import generate as py_gen_generate
from core.aether_core import aether_core_main as py_core_main
from core.aether_tray import AetherTray as PyAetherTray

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

class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

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
            "Get-Process -Name 'clash-verge', 'verge-mihomo', 'clash' -ErrorAction SilentlyContinue | Stop-Process -Force"],
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

class _InternetProxyInfo(ctypes.Structure):
    _fields_ = [
        ("dwAccessType", wintypes.DWORD),
        ("lpszProxy", wintypes.LPCWSTR),
        ("lpszProxyBypass", wintypes.LPCWSTR),
    ]

def set_system_proxy(enable: bool):
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
        wininet.InternetSetOptionW.restype = wintypes.BOOL
        if enable:
            info = _InternetProxyInfo(3, "127.0.0.1:7899", "<local>")
        else:
            info = _InternetProxyInfo(1, None, None)
        wininet.InternetSetOptionW(None, 38, ctypes.byref(info), ctypes.sizeof(info))
        wininet.InternetSetOptionW(None, 39, None, 0)
        wininet.InternetSetOptionW(None, 37, None, 0)
    except Exception:
        pass

_CORE_THREAD = None
_CORE_STOP_EVENT = threading.Event()

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
        return kernel32.GetLastError() != 183
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

class Tui:
    def __init__(self):
        self.hOut = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        self.csbi = _CONSOLE_SCREEN_BUFFER_INFO()
        if not ctypes.windll.kernel32.GetConsoleScreenBufferInfo(
                self.hOut, ctypes.byref(self.csbi)):
            raise OSError("no console")
        self._prev = None
        self._started = False

    def size(self):
        ctypes.windll.kernel32.GetConsoleScreenBufferInfo(self.hOut, ctypes.byref(self.csbi))
        w = self.csbi.srWindow.Right - self.csbi.srWindow.Left + 1
        h = self.csbi.srWindow.Bottom - self.csbi.srWindow.Top + 1
        return max(w, 1), max(h, 1)

    def start(self):
        if not self._started:
            sys.stdout.write("\033[2J\033[H\033[?25l")
            sys.stdout.flush()
            self._started = True

    def close(self):
        if self._started:
            sys.stdout.write("\033[?25h\033[0m\033[H")
            sys.stdout.flush()
            self._started = False

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
            sig.append(keep)
            used += _disp_width(keep)
        line = "".join(out)
        pad = max(width - used, 0)
        return "".join(sig), line + "\033[0m" + (" " * pad)

    def render(self, segment_rows):
        w, h = self.size()
        self.start()
        nxt = []
        for i in range(h):
            segs = segment_rows[i] if i < len(segment_rows) else []
            _sig, line = self._compose(segs, w)
            prev = self._prev[i] if self._prev is not None and i < len(self._prev) else None
            if prev == line:
                nxt.append(line)
                continue
            if line:
                sys.stdout.write(f"\033[{i + 1};1H{line}\033[K")
            else:
                sys.stdout.write(f"\033[{i + 1};1H\033[K")
            nxt.append(line)
        self._prev = nxt
        sys.stdout.flush()

# ---- TrayBridge ----
TRAY_CONNECT_TIMEOUT = 8.0

def _enc(s):
    return urllib.parse.quote(str(s), safe="")

def _dec(s):
    return urllib.parse.unquote(str(s))

class TrayBridge:
    def __init__(self, title="AetherCore 代理网关", on_exit_callback=None,
                 on_reload_callback=None, on_autostart_callback=None,
                 on_list_nodes_callback=None, on_node_select_callback=None,
                 on_list_app_rules_callback=None, on_app_toggle_callback=None,
                 on_open_app_rules_callback=None, on_reload_app_rules_callback=None,
                 on_console_callback=None, console_visible_fn=None,
                 on_open_logs_callback=None, autostart_enabled_fn=None,
                 autostart_enabled=False, start_hidden=True):
        self.title = title
        self.on_exit_callback = on_exit_callback
        self.on_reload_callback = on_reload_callback
        self.on_autostart_callback = on_autostart_callback
        self.on_list_nodes_callback = on_list_nodes_callback
        self.on_node_select_callback = on_node_select_callback
        self.on_list_app_rules_callback = on_list_app_rules_callback
        self.on_app_toggle_callback = on_app_toggle_callback
        self.on_open_app_rules_callback = on_open_app_rules_callback
        self.on_reload_app_rules_callback = on_reload_app_rules_callback
        self.on_console_callback = on_console_callback
        self.console_visible_fn = console_visible_fn
        self.on_open_logs_callback = on_open_logs_callback
        self.autostart_enabled_fn = autostart_enabled_fn
        self.autostart_enabled = autostart_enabled
        self.start_hidden = start_hidden
        self._srv = None
        self._port = 0
        self._proc = None
        self._conn = None
        self._stop = False
        self._tray_ready = False
        self._conn_lock = threading.Lock()
        self._pending = []
        self._pending_lock = threading.Lock()

    def start(self):
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind(("127.0.0.1", 0))
            self._srv.listen(4)
            self._srv.settimeout(0.5)
            self._port = self._srv.getsockname()[1]
        except Exception:
            return False
        threading.Thread(target=self._accept_loop, daemon=True, name="tray-srv").start()
        try:
            self._py_tray = PyAetherTray(self._port)
            self._tray_thread = threading.Thread(target=self._py_tray.run, daemon=True, name="py-tray")
            self._tray_thread.start()
        except Exception:
            return False
        deadline = time.time() + TRAY_CONNECT_TIMEOUT
        while time.time() < deadline:
            with self._conn_lock:
                if self._tray_ready:
                    return True
            time.sleep(0.2)
        self.stop()
        return False

    def stop(self):
        self._stop = True
        conn = self._conn
        if conn is not None:
            try:
                with self._conn_lock:
                    conn.sendall(b"QUIT\n")
            except Exception:
                pass
        if hasattr(self, '_py_tray') and self._py_tray is not None:
            try:
                self._py_tray.stop()
            except Exception:
                pass
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass

    def show_notification(self, title, msg):
        payload = f"NOTIFY {_enc(title)}|{_enc(msg)}\n".encode("utf-8")
        with self._conn_lock:
            conn = self._conn
            if conn is not None and self._tray_ready:
                try:
                    conn.sendall(payload)
                    return
                except Exception:
                    pass
        with self._pending_lock:
            self._pending.append((str(title), str(msg)))
            if len(self._pending) > 8:
                self._pending.pop(0)

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True, name="tray-conn").start()

    def _handle(self, conn):
        buf = b""
        conn.settimeout(1.0)
        with self._conn_lock:
            self._conn = conn
        with self._pending_lock:
            pending = list(self._pending)
            self._pending.clear()
        for title, msg in pending:
            try:
                conn.sendall(f"NOTIFY {_enc(title)}|{_enc(msg)}\n".encode("utf-8"))
            except Exception:
                break
        try:
            while not self._stop:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.decode("utf-8", errors="replace").strip()
                    if line:
                        self._dispatch(conn, line)
        finally:
            with self._conn_lock:
                if self._conn is conn:
                    self._conn = None
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _reply(conn, rid, ok, payload=""):
        status = "OK" if ok else "ERR"
        line = f"{rid} {status} {payload}\n" if payload else f"{rid} {status}\n"
        try:
            conn.sendall(line.encode("utf-8"))
        except Exception:
            pass

    def _dispatch(self, conn, line):
        parts = line.split(" ", 2)
        if len(parts) < 2:
            return
        rid, cmd = parts[0], parts[1].upper()
        arg = _dec(parts[2].strip()) if len(parts) > 2 else ""
        try:
            if cmd == "PING":
                with self._conn_lock:
                    self._tray_ready = True
                self._reply(conn, rid, True, "PONG")
            elif cmd == "STATUS":
                vis = 1 if (self.console_visible_fn and self.console_visible_fn()) else 0
                auto = 1 if (self.autostart_enabled_fn and self.autostart_enabled_fn()) else 0
                self._reply(conn, rid, True, f"autostart={auto} console={vis}")
            elif cmd == "NODES":
                items = self.on_list_nodes_callback() or []
                parts = [f"{_enc(n)}={1 if sel else 0}" for n, sel in items]
                self._reply(conn, rid, True, f"{len(parts)};" + ";".join(parts))
            elif cmd == "APPS":
                items = self.on_list_app_rules_callback() or []
                parts = [f"{_enc(p)}={_enc(t)}={_enc(l)}" for p, t, l in items]
                self._reply(conn, rid, True, f"{len(parts)};" + ";".join(parts))
            elif cmd == "SELECT":
                if self.on_node_select_callback:
                    self.on_node_select_callback(arg)
                self._reply(conn, rid, True)
            elif cmd == "APPSET":
                if self.on_app_toggle_callback:
                    self.on_app_toggle_callback(arg)
                self._reply(conn, rid, True)
            elif cmd == "APPRELOAD":
                if self.on_reload_app_rules_callback:
                    self.on_reload_app_rules_callback()
                self._reply(conn, rid, True)
            elif cmd == "CONSOLE":
                vis = 1
                if self.on_console_callback:
                    vis = 1 if self.on_console_callback() else 0
                self._reply(conn, rid, True, f"console={vis}")
            elif cmd == "LOG":
                if self.on_open_logs_callback:
                    self.on_open_logs_callback()
                self._reply(conn, rid, True)
            elif cmd == "OPENAPPS":
                if self.on_open_app_rules_callback:
                    self.on_open_app_rules_callback()
                self._reply(conn, rid, True)
            elif cmd == "AUTOSTART":
                if self.on_autostart_callback:
                    self.on_autostart_callback()
                auto = 1 if (self.autostart_enabled_fn and self.autostart_enabled_fn()) else 0
                self._reply(conn, rid, True, f"enabled={auto}")
            elif cmd == "UPDATE":
                if self.on_reload_callback:
                    self.on_reload_callback()
                self._reply(conn, rid, True)
            elif cmd == "EXIT":
                self._reply(conn, rid, True)
                if self.on_exit_callback:
                    threading.Thread(target=self._run_exit, daemon=True, name="tray-exit").start()
            else:
                self._reply(conn, rid, False, "unknown command")
        except Exception as e:
            self._reply(conn, rid, False, str(e))

    def _run_exit(self):
        try:
            if self.on_exit_callback:
                self.on_exit_callback()
        except Exception:
            pass


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
    if time.time() - _NODE_CACHE["t"] < _NODE_TTL:
        return _NODE_CACHE["items"]
    _refresh_nodes_async()
    return _NODE_CACHE["items"]

def select_manual_node(name: str) -> bool:
    payload = json.dumps({"name": name}).encode("utf-8")
    ok, _, _ = _controller_request("PUT", "/proxies/" + urllib.parse.quote(MANUAL_GROUP), payload)
    return ok

# ---- 分应用代理 ----
def apply_app_rules_async():
    def worker():
        try:
            push_status("[i] 正在应用分应用代理规则...")
            ok, _ = run_gen(fetch=False, echo=False)
            if ok and restart_core():
                push_status("[ok] 分应用代理规则已生效")
            else:
                push_status("[x] 分应用规则应用失败（内核未就绪?）")
        except Exception as e:
            push_status(f"[x] 分应用规则应用异常: {e}")
    threading.Thread(target=worker, daemon=True, name="app-rules").start()

def set_app_target(proc, target):
    rules_set(proc, target)
    apply_app_rules_async()

def remove_app_target(proc):
    rules_del(proc)
    apply_app_rules_async()

def _build_app_panel_frame(seen_procs, panel_idx, width, height, last_status):
    rules = rules_list()
    procs = sorted(set(rules) | set(seen_procs),
                   key=lambda p: (-seen_procs.get(p, 0), p))
    max_data = max(height - 4, 0)
    colors = Color()
    rows = [[(f" 分应用代理 | {time.strftime('%H:%M:%S')} | 共 {len(procs)} 个进程", f"{colors.CYAN}{colors.BOLD}")]]
    rows.append([("进程名                           目标                    最近连接", f"{colors.WHITE}{colors.BOLD}")])
    for i, p in enumerate(procs[:max_data]):
        mark = ">" if i == panel_idx else " "
        label = target_label(rules.get(p, "")) if p in rules else "未设置(跟随全局)"
        rows.append([
            (f"{mark} {p}", f"{colors.GREEN}" if i == panel_idx else ""),
            (" ", ""),
            (label, f"{colors.YELLOW}" if p in rules else ""),
            (" ", ""),
            (f"x{seen_procs.get(p, 0)}", ""),
        ])
    rows.append([(last_status or "选择进程后按 1/2/3 设置，x 删除规则", f"{colors.YELLOW}")])
    rows.append([("j/k 选择  1 本地直连  2 走代理(手动节点)  3 自动优选  x 删除  p/q 返回", "")])
    return rows

def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    else:
        return f"{b / (1024 * 1024):.2f} MB"

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
            return False
        e = dict(entry)
        e["count"] = 1
        self.rows[key] = e
        if len(self.rows) > self.max_rows:
            self.rows.popitem(last=False)
        return True

TRAFFIC = {"up": 0, "down": 0}

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

def _build_frame(table, last_status, width, height, up, down, up_spd, down_spd,
                 proto_filter=None, sort_mode="time", keys_hint=""):
    colors = Color()
    rows = []
    title = (f"AetherCore Python 内核 | {time.strftime('%H:%M:%S')} | 默认全量代理"
             f" | up {format_bytes(up)}  down {format_bytes(down)}")
    rows.append([(title, f"{colors.CYAN}{colors.BOLD}")])
    colh = "时间    进程            节点                       目标                           协议    次数"
    rows.append([(colh, f"{colors.WHITE}{colors.BOLD}")])
    if sort_mode == "count":
        items = sorted(table.rows.items(), key=lambda kv: -kv[1]["count"])
    else:
        items = reversed(list(table.rows.items()))
    max_data = max(height - 4, 0)
    added = 0
    for key, r in items:
        if added >= max_data:
            break
        if proto_filter is not None and r["proto"].upper() != proto_filter:
            continue
        rows.append([
            (f"{r['time']}", ""),
            ("  ", ""),
            (f"[{r['proc']}]", f"{colors.GREEN}"),
            (" ", ""),
            (r["node_plain"], r["node_prefix"]),
            (" ", ""),
            (r["target"], f"{colors.WHITE}"),
            ("  ", ""),
            (f"({r['proto']})", f"{colors.MAGENTA}"),
            (" ", ""),
            (f"x{r['count']}", f"{colors.GREEN}{colors.BOLD}"),
        ])
        added += 1
    rows.append([(last_status or "状态栏：等待活动连接...", f"{colors.YELLOW}")])
    total = sum(r["count"] for r in table.rows.values())
    filter_txt = f"筛选:{proto_filter}" if proto_filter else "筛选:全部"
    sort_txt = "排序:次数" if sort_mode == "count" else "排序:时间"
    foot = (f"{keys_hint}"
            f" | {filter_txt} {sort_txt}"
            f" | 事件 {total} 行 {len(table.rows)}"
            f" | up {format_bytes(up_spd)}/s down {format_bytes(down_spd)}/s")
    rows.append([(foot, "")])
    return rows

def _poll_keys():
    keys = []
    try:
        while msvcrt.kbhit():
            keys.append(msvcrt.getwch())
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
    _CORE_PROC = start_core()
    time.sleep(0.5)
    set_system_proxy(True)
    return True

_CORE_PROC = None


def monitor_connections_loop(core_holder, stopping, log_fp, tray=None):
    print(f"{Color.GREEN}[ok] Python 内核代理服务已就绪（系统代理 127.0.0.1:7899）！{Color.RESET}")
    print(f"{Color.CYAN}[*] 实时监控各进程出口节点与连接（重复连接自动聚合计数 xN）...{Color.RESET}\n")
    tui = None
    try:
        tui = Tui()
    except Exception:
        tui = None
    if tui is not None:
        threading.Thread(target=_traffic_stream, daemon=True, name="traffic").start()
    else:
        print(f"{Color.YELLOW}[i] 控制台 TUI 不可用，回退为普通文本输出。{Color.RESET}")
    table = ConnectionTable()
    last_status = ""
    last_render = 0.0
    prev_up = prev_down = 0
    prev_t = time.time()
    ema_up = ema_down = 0.0
    proto_filter = None
    sort_mode = "time"
    log_events = 0
    seen_procs = {}
    panel_active = False
    panel_idx = 0
    log_fp_write = log_fp

    while not stopping.is_set():
        time.sleep(0.05)
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
                if k == "p" and panel_active:
                    panel_active = False
                elif k == "q":
                    if panel_active:
                        panel_active = False
                    else:
                        stopping.set()
                elif k == "j":
                    if panel_active:
                        panel_idx = max(0, panel_idx - 1)
                elif k == "k":
                    if panel_active:
                        panel_idx = min(len(seen_procs) - 1, panel_idx + 1)
                elif k == "1" and panel_active:
                    procs = sorted(seen_procs, key=lambda p: -seen_procs[p])
                    if 0 <= panel_idx < len(procs):
                        set_app_target(procs[panel_idx], "direct")
                elif k == "2" and panel_active:
                    procs = sorted(seen_procs, key=lambda p: -seen_procs[p])
                    if 0 <= panel_idx < len(procs):
                        set_app_target(procs[panel_idx], "proxy")
                elif k == "3" and panel_active:
                    procs = sorted(seen_procs, key=lambda p: -seen_procs[p])
                    if 0 <= panel_idx < len(procs):
                        set_app_target(procs[panel_idx], "auto")
                elif k == "x" and panel_active:
                    procs = sorted(seen_procs, key=lambda p: -seen_procs[p])
                    if 0 <= panel_idx < len(procs):
                        remove_app_target(procs[panel_idx])
                elif k == "f":
                    if proto_filter is None:
                        proto_filter = "TCP"
                    elif proto_filter == "TCP":
                        proto_filter = "UDP"
                    else:
                        proto_filter = None
                elif k == "s":
                    sort_mode = "count" if sort_mode == "time" else "time"
                elif k == "\r":
                    panel_active = not panel_active
                    panel_idx = 0
                keys_hint += repr(k).strip("'")

            w, h = tui.size()
            if panel_active:
                rows = _build_app_panel_frame(seen_procs, panel_idx, w, h, last_status)
            else:
                rows = _build_frame(table, last_status, w, h, up, down, ema_up, ema_down,
                                    proto_filter, sort_mode, keys_hint)
            tui.render(rows)
            last_render = now

        if core_holder.poll() is not None:
            print(f"{Color.RED}[x] 内核进程已退出，正在重启...{Color.RESET}")
            start_core()
            time.sleep(0.5)

    if tui is not None:
        tui.close()


def main():
    global _CORE_PROC
    print(f"{Color.CYAN}{Color.BOLD}AetherCore - 纯 Python 透明代理网关{Color.RESET}")
    print(f"{Color.YELLOW}[*] 工作目录: {WORKSPACE_DIR}{Color.RESET}")
    print(f"{Color.YELLOW}[*] 数据目录: {DATA_DIR}{Color.RESET}")

    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)

    if not ensure_single_instance(create=False):
        print(f"{Color.RED}[x] 已有实例在运行，请先退出旧实例！{Color.RESET}")
        return 1

    if not is_admin():
        if not sys.argv[0].endswith(".py"):
            elevate_admin()
            return 0
        else:
            print(f"{Color.YELLOW}[!] 以非管理员权限运行，部分功能可能受限{Color.RESET}")

    ensure_single_instance(create=True)

    kill_conflicting_proxies()

    if core_already_running():
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                "检测到环境中已有一个 AetherCore 内核在运行\n"
                "（通常是旧版本实例残留，正占用 TUN 网卡与端口，会导致新实例空转、无流量）。\n\n"
                "请先在任务管理器结束旧的 python.exe / Python 内核进程，\n"
                "或右键旧实例托盘图标选择【退出 AetherCore】，再重新启动。",
                "AetherCore - 内核端口被占用", 0x10 | 0x40000)
        except Exception:
            show_console_window()
            print(f"{Color.RED}[x] 端口已被旧内核占用，请先退出旧实例再启动！{Color.RESET}")
        return 1

    # 生成配置
    ok, _ = run_gen(fetch=True, echo=True)
    if not ok:
        print(f"{Color.YELLOW}[!] 首次配置生成失败，使用缓存（如有）...{Color.RESET}")

    # 启动内核
    _CORE_PROC = start_core()
    time.sleep(0.5)
    set_system_proxy(True)

    # 启动托盘
    tray = TrayBridge(
        title="AetherCore 代理网关",
        on_exit_callback=lambda: (
            set_system_proxy(False),
            _CORE_STOP_EVENT.set(),
            setattr(__import__('core.aether_core'), 'CORE_STOP_EVENT', threading.Event()),
            os._exit(0)
        ),
        on_reload_callback=lambda: (
            run_gen(fetch=True, echo=False),
            restart_core()
        ),
        on_autostart_callback=lambda: autostart_set(not autostart_is_enabled()),
        on_list_nodes_callback=list_manual_nodes,
        on_node_select_callback=select_manual_node,
        on_list_app_rules_callback=lambda: [
            (p, target_label(t), t) for p, t in rules_list().items()
        ],
        on_app_toggle_callback=lambda arg: (
            set_app_target(*arg.split("=", 1)) if "=" in arg else remove_app_target(arg)
        ),
        on_reload_app_rules_callback=apply_app_rules_async,
        on_console_callback=toggle_console_window,
        console_visible_fn=console_visible,
        on_open_logs_callback=open_logs_file,
        autostart_enabled_fn=autostart_is_enabled,
        autostart_enabled=autostart_is_enabled(),
        start_hidden=False,
    )
    tray.start()

    # 打开日志文件
    log_fp = open(LOG_FILE, "a", encoding="utf-8", buffering=1) if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) < LOG_MAX_BYTES else rotate_log(open(LOG_FILE, "a", encoding="utf-8", buffering=1))

    # 进入监控循环
    stopping = threading.Event()
    try:
        monitor_connections_loop(_CORE_PROC, stopping, log_fp, tray)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{Color.YELLOW}[*] 正在关闭...{Color.RESET}")
        _CORE_STOP_EVENT.set()
        import core.aether_core
        core.aether_core.CORE_STOP_EVENT.set()
        set_system_proxy(False)
        tray.stop()
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
        print(f"\n{Color.RED}[x] 未捕获异常: {e}{Color.RESET}")
        import traceback
        traceback.print_exc()
        input("\n按回车键退出...")