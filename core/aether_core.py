# SPDX-License-Identifier: MIT
# AetherCore - 纯 Python 代理核心 (替代 aether_core.c)
#
# 功能：
#   - 混合入站：SOCKS5 (CONNECT) + HTTP 代理 (CONNECT/绝对URI) @ 7899
#   - 规则分流：直连域名 / 代理域名 / 直连 IP (CIDR) / 默认动作
#   - 出站：DIRECT 直连 + VLESS (TCP 原始传输) 节点
#   - 控制器 API：/version /logs /traffic /proxies (与 mihomo 兼容子集)
#
# 配置 (core.conf，制表符分隔，UTF-8)：
#   listen\t<ip>\t<port>
#   controller\t<ip>\t<port>
#   node\t<名称>\t<uuid>\t<server>\t<port>
#   direct-domain\t.qq.com
#   proxy-domain\t.google.com
#   direct-ip\t198.18.0.0/15
#   default\tdirect|proxy

import os
import sys

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import socket
import struct
import threading
import json
import time
import base64
import hashlib
import ipaddress
import re
import random
import ssl
import uuid as uuid_mod
from urllib.parse import urlparse, unquote
from collections import OrderedDict

# 停止事件（由 launcher 设置）
CORE_STOP_EVENT = threading.Event()

# ---- 常量 ----
MAX_NODES = 128
MAX_DOMAINS = 1024
MAX_CIDRS = 256
MAX_TARGET_LEN = 512
LOG_RING_CAP = 4096
LOG_LINE_MAX = 512
HANDSHAKE_TIMEOUT = 15.0
CONTROLLER_TIMEOUT = 5.0

# ---- 配置结构 ----
class Node:
    __slots__ = ("name", "uuid", "server", "port", "tls", "sni", "ws", "ws_path", "ws_host")

    def __init__(self):
        self.name = ""
        self.uuid = ""
        self.server = ""
        self.port = 0
        self.tls = False
        self.sni = ""
        self.ws = False
        self.ws_path = ""
        self.ws_host = ""


class Config:
    __slots__ = ("listen_ip", "listen_port", "ctrl_ip", "ctrl_port",
                 "nodes", "node_count", "current_node",
                 "direct_domains", "proxy_domains", "route_domains", "route_cidrs",
                 "direct_cidrs", "default_proxy",
                 "direct_processes", "proxy_processes")

    def __init__(self):
        self.listen_ip = "127.0.0.1"
        self.listen_port = 7899
        self.ctrl_ip = "127.0.0.1"
        self.ctrl_port = 9097
        self.nodes = []
        self.node_count = 0
        self.current_node = 0
        self.direct_domains = []
        self.proxy_domains = []
        self.route_domains = []  # [(domain_pattern, target), ...]
        self.route_cidrs = []    # [(IPv4Network, target), ...]
        self.direct_cidrs = []
        self.default_proxy = True  # True=proxy, False=direct
        self.direct_processes = []
        self.proxy_processes = []


# ---- 全局状态 ----
g_cfg = Config()
g_running = True
g_up_bytes = 0
g_down_bytes = 0
g_log_ring = []
g_log_seq = 0
g_log_lock = threading.Lock()
g_data_dir = ""
g_config_file = ""

# TUN 模式客户端源端口到真实进程名映射
_TUN_PORT_MAP = {}
_TUN_PORT_LOCK = threading.Lock()


def register_tun_client_port(local_port: int, proc_name: str):
    """供 tun_tcp 桥接时登记发起程序的真实进程名"""
    if not local_port or not proc_name or proc_name == "App":
        return
    with _TUN_PORT_LOCK:
        _TUN_PORT_MAP[local_port] = (proc_name, time.time())
        now = time.time()
        stale = [p for p, (_, t) in _TUN_PORT_MAP.items() if now - t > 60]
        for p in stale:
            del _TUN_PORT_MAP[p]


def get_tun_client_process(local_port: int) -> str:
    """提取并移除指定端口关联的真实进程名"""
    with _TUN_PORT_LOCK:
        entry = _TUN_PORT_MAP.pop(local_port, None)
        if entry:
            return entry[0]
    return ""


def core_log(fmt: str, *args):
    """记录日志到环形缓冲区与 core.log"""
    global g_log_seq
    msg = fmt % args if args else fmt
    with g_log_lock:
        g_log_seq += 1
        g_log_ring.append({"seq": g_log_seq, "line": msg})
        if len(g_log_ring) > LOG_RING_CAP:
            g_log_ring[:LOG_RING_CAP // 2] = []
    if os.environ.get("AETHER_CORE_STDOUT", "0") == "1":
        try:
            print(f"[core] {msg}", flush=True)
        except Exception:
            pass

    if g_data_dir:
        try:
            core_log_path = os.path.join(g_data_dir, "core.log")
            with open(core_log_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [core] {msg}\n")
        except Exception:
            pass


def get_process_for_port(port: int) -> str:
    """Windows 获取指定本地 TCP 端口的进程名 (支持 IPv4 与 IPv6)"""
    if sys.platform != "win32" or port <= 0:
        return "App"
    try:
        import ctypes
        from ctypes import wintypes
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


def traffic_add(is_up: bool, n: int):
    """增加流量计数"""
    global g_up_bytes, g_down_bytes
    if is_up:
        g_up_bytes += n
    else:
        g_down_bytes += n


# 常见 Google 官方 IPv4 网段 (ASN 15169 与 Google Cloud/AI 常见端点，保证 IP 拨号不走偏)
GOOGLE_DEFAULT_CIDRS = [
    "172.217.0.0/16",
    "142.250.0.0/15",
    "173.194.0.0/16",
    "216.58.192.0/19",
    "74.125.0.0/16",
    "64.233.160.0/19",
    "66.102.0.0/20",
    "66.249.64.0/19",
    "108.177.0.0/17",
    "209.85.128.0/17",
    "216.239.32.0/19",
    "172.253.0.0/16",
    "8.8.4.0/24",
    "8.8.8.0/24",
    "34.0.0.0/9",
    "34.128.0.0/10",
    "35.184.0.0/13",
    "35.192.0.0/12",
    "35.208.0.0/12",
    "35.224.0.0/12",
    "35.240.0.0/13",
]


# ---- 自定义覆盖配置与节点匹配 ----
def load_override_rules(base_dir: str = None) -> tuple:
    """
    加载 Override-Configuration.json 中的自定义配置
    返回 ([(domain_pattern, target), ...], [(IPv4Network, target), ...])
    """
    candidates = []
    if base_dir:
        candidates.append(os.path.join(base_dir, "Override-Configuration.json"))
    if g_data_dir and g_data_dir != base_dir:
        candidates.append(os.path.join(g_data_dir, "Override-Configuration.json"))
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(os.path.dirname(script_dir), "data", "Override-Configuration.json"))

    target_file = None
    for c in candidates:
        if c and os.path.exists(c):
            target_file = c
            break

    if not target_file:
        return [], []

    dom_rules = []
    cidr_rules = []
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            # 格式 1: {"rules": [{"target": "...", "domains": [...], "cidrs": [...]}, ...]}
            if "rules" in data and isinstance(data["rules"], list):
                for item in data["rules"]:
                    if isinstance(item, dict):
                        tgt = str(item.get("target", "")).strip()
                        doms = item.get("domains", [])
                        raw_cidrs = list(item.get("cidrs", item.get("ips", [])))
                        name = str(item.get("name", "")).strip()
                        is_google = (
                            "google" in name.lower() or
                            "google" in tgt.lower() or
                            any("google" in str(d).lower() for d in doms)
                        )
                        if is_google:
                            for gc in GOOGLE_DEFAULT_CIDRS:
                                if gc not in raw_cidrs:
                                    raw_cidrs.append(gc)

                        if tgt and doms:
                            for d in doms:
                                d_str = str(d).strip()
                                if d_str and (d_str, tgt) not in dom_rules:
                                    dom_rules.append((d_str, tgt))

                        if tgt and raw_cidrs:
                            for c in raw_cidrs:
                                try:
                                    net = ipaddress.ip_network(str(c).strip(), strict=False)
                                    if (net, tgt) not in cidr_rules:
                                        cidr_rules.append((net, tgt))
                                except Exception:
                                    pass

            # 格式 2: {"rules": {"domain_or_cidr": "target", ...}}
            elif "rules" in data and isinstance(data["rules"], dict):
                for k, tgt in data["rules"].items():
                    k_str = str(k).strip()
                    t_str = str(tgt).strip()
                    if k_str and t_str:
                        try:
                            net = ipaddress.ip_network(k_str, strict=False)
                            if (net, t_str) not in cidr_rules:
                                cidr_rules.append((net, t_str))
                        except ValueError:
                            if (k_str, t_str) not in dom_rules:
                                dom_rules.append((k_str, t_str))
            # 格式 3: {"domain_or_cidr": "target", ...}
            else:
                for k, tgt in data.items():
                    if isinstance(tgt, str):
                        k_str = str(k).strip()
                        t_str = str(tgt).strip()
                        if k_str and t_str:
                            try:
                                net = ipaddress.ip_network(k_str, strict=False)
                                if (net, t_str) not in cidr_rules:
                                    cidr_rules.append((net, t_str))
                            except ValueError:
                                if (k_str, t_str) not in dom_rules:
                                    dom_rules.append((k_str, t_str))
    except Exception as e:
        core_log(f"[!] 读取 Override-Configuration.json 异常: {e}")

    return dom_rules, cidr_rules


def resolve_node_by_target(target: str, nodes: list, default_name: str = None) -> str:
    """
    根据目标（具体节点全名、关键词如'新加坡'/'美国06'/'SG'等）解析最匹配的节点名称。
    """
    if not nodes or not target:
        return default_name

    target_clean = str(target).strip()
    target_lower = target_clean.lower()

    # 0. 支持逗号分隔的多目标/节点容灾池定义 (如 "节点A, 节点B")，依次寻找首个未冷却的有效节点
    # 注意：不能使用 '|' 作为候选分隔符，因为许多节点名称本身包含 '|' 属性说明
    if "," in target_clean:
        sub_targets = [st.strip() for st in target_clean.split(",") if st.strip()]
        first_valid = None
        for st in sub_targets:
            res = resolve_node_by_target(st, nodes, None)
            if res:
                if not first_valid:
                    first_valid = res
                if not is_node_in_cooldown(res):
                    return res
        if first_valid:
            return first_valid

    # 1. 精确完全匹配节点名称
    for n in nodes:
        if n.name.strip().lower() == target_lower:
            return n.name

    # 2. 地区常见关键词字典
    REGION_KEYWORDS = {
        "新加坡": ["新加坡", "singapore", "sg", "🇸🇬"],
        "香港": ["香港", "hong kong", "hongkong", "hk", "🇭🇰"],
        "日本": ["日本", "japan", "jp", "🇯🇵", "东京", "大阪"],
        "美国": ["美国", "united states", "usa", "us", "🇺🇸"],
        "台湾": ["台湾", "taiwan", "tw", "🇹🇼"],
        "韩国": ["韩国", "korea", "kr", "🇰🇷", "首尔"],
        "英国": ["英国", "uk", "united kingdom", "🇬🇧", "伦敦"],
        "德国": ["德国", "germany", "de", "🇩🇪", "法兰克福"],
    }

    # 3. 关键词特征加权评分匹配
    tokens = [t.lower() for t in re.findall(r'[\u4e00-\u9fa5]+|[a-zA-Z]+|\d+(?:\.\d+)?(?:倍)?', target_clean)]
    SHORT_CODES = {"us", "de", "jp", "hk", "tw", "kr", "uk", "sg"}

    def _match_kw(kw: str, text: str) -> bool:
        if kw in SHORT_CODES:
            return bool(re.search(rf"(^|[^a-z0-9]){re.escape(kw)}([^a-z0-9]|$)", text))
        return kw in text

    extra_kws = []
    for reg, kws in REGION_KEYWORDS.items():
        if reg in target_clean or any(_match_kw(k.lower(), target_lower) for k in kws):
            extra_kws.extend(kws)
            break

    best_score = -1
    best_node = None
    for n in nodes:
        n_low = n.name.lower()
        score = 0
        for tok in tokens:
            if _match_kw(tok, n_low):
                if any(char.isdigit() for char in tok):
                    score += 5  # 数字编号（如 01, 06）高权重
                elif tok in ("0.1倍", "0.01倍", "倍"):
                    score += 2
                else:
                    score += 3
        for ek in extra_kws:
            if _match_kw(ek.lower(), n_low):
                score += 4
                break
        if score > best_score:
            best_score = score
            best_node = n.name

    if best_score > 0 and best_node:
        return best_node

    # 4. 降级：模糊子串包含 (仅对非 2 字母短代码允许降级)
    if len(target_lower) > 2:
        for n in nodes:
            if target_lower in n.name.lower() or n.name.lower() in target_lower:
                return n.name

    return default_name


# ---- 节点故障临时熔断冷却池 (内存级) ----
_NODE_FAIL_COOLDOWN = {}   # {node_name: (fail_timestamp, fail_count)}
_NODE_FAIL_LOCK = threading.Lock()
NODE_COOLDOWN_SECONDS = 30.0    # 首次失败冷却 30 秒，期间自动降权后移
NODE_COOLDOWN_MAX_SECONDS = 600.0  # 连续失败指数升级，封顶 10 分钟

def mark_node_failed(node_name: str):
    """标记节点故障，进入短暂冷却；冷却窗口内连续失败则指数升级冷却时长 (快速熔断区域性故障)"""
    if not node_name:
        return
    with _NODE_FAIL_LOCK:
        ts, cnt = _NODE_FAIL_COOLDOWN.get(node_name, (0.0, 0))
        cnt = cnt + 1 if (time.time() - ts) < NODE_COOLDOWN_SECONDS else 1
        _NODE_FAIL_COOLDOWN[node_name] = (time.time(), cnt)

def mark_node_ok(node_name: str):
    """节点连接成功，清除冷却标记与失败计数"""
    if not node_name:
        return
    with _NODE_FAIL_LOCK:
        _NODE_FAIL_COOLDOWN.pop(node_name, None)

def _node_cooldown_seconds(cnt: int) -> float:
    return min(NODE_COOLDOWN_SECONDS * (2 ** max(0, cnt - 1)), NODE_COOLDOWN_MAX_SECONDS)

def is_node_in_cooldown(node_name: str) -> bool:
    """检查节点是否在冷却期内"""
    if not node_name:
        return False
    with _NODE_FAIL_LOCK:
        item = _NODE_FAIL_COOLDOWN.get(node_name)
        if not item:
            return False
        ts, cnt = item
        if time.time() - ts < _node_cooldown_seconds(cnt):
            return True
        del _NODE_FAIL_COOLDOWN[node_name]
        return False


def _match_node_region(name: str) -> str:
    """从节点名提取地区。短代码仅按词边界匹配，避免 node/plus 等误伤。"""
    if not name:
        return ""
    n = name.lower()
    # (地区, 可安全子串, 需词边界的短代码)
    rules = [
        ("美国", ["美国", "usa", "🇺🇸"], ["us"]),
        ("新加坡", ["新加坡", "singapore", "🇸🇬"], ["sg"]),
        ("日本", ["日本", "japan", "🇯🇵"], ["jp"]),
        ("香港", ["香港", "hong kong", "🇭🇰"], ["hk"]),
        ("台湾", ["台湾", "taiwan", "🇹🇼"], ["tw"]),
        ("韩国", ["韩国", "korea", "🇰🇷"], ["kr"]),
        ("英国", ["英国", "🇬🇧"], ["uk"]),
        ("德国", ["德国", "germany", "🇩🇪"], ["de"]),
    ]
    for region, tokens, codes in rules:
        for t in tokens:
            if t.lower() in n:
                return region
        for code in codes:
            if re.search(rf"(^|[^a-z0-9]){re.escape(code)}([^a-z0-9]|$)", n):
                return region
    return ""


def get_backup_candidates(failed_node_names: set or list) -> list:
    """
    根据已失败的节点集合，按智能优先级返回所有健康的备选代理节点列表。
    优先级排序策略：
    1. 同地区未冷却的稳定节点（优先 0.01倍/0.1倍）
    2. 同地区其他未冷却节点
    3. 同地区冷却中的节点（若无其它可选）
    4. 全局其它地区未冷却节点
    5. 全局其它地区冷却节点
    """
    if not g_cfg or not g_cfg.nodes:
        return []

    if isinstance(failed_node_names, str):
        failed_set = {failed_node_names.strip().lower()}
    else:
        failed_set = {str(n).strip().lower() for n in failed_node_names if n}

    failed_regions = {r for r in (_match_node_region(fname) for fname in failed_set) if r}

    same_reg_active_hi = []
    same_reg_active_lo = []
    same_reg_cooldown = []
    other_active_hi = []
    other_active_lo = []
    other_cooldown = []

    for n in g_cfg.nodes:
        n_low = n.name.lower().strip()
        if n_low in failed_set:
            continue
        is_same_reg = bool(failed_regions) and _match_node_region(n.name) in failed_regions
        in_cool = is_node_in_cooldown(n.name)
        is_hi = bool(n.ws and ("0.01倍" in n.name or "0.1倍" in n.name))

        if is_same_reg:
            if in_cool:
                same_reg_cooldown.append(n.name)
            elif is_hi:
                same_reg_active_hi.append(n.name)
            else:
                same_reg_active_lo.append(n.name)
        else:
            if in_cool:
                other_cooldown.append(n.name)
            elif is_hi:
                other_active_hi.append(n.name)
            else:
                other_active_lo.append(n.name)

    # 健康节点优先；冷却节点仅作为最后手段。
    # 否则区域性故障 (如整区 503) 会把 max_backup_tries 全部耗在同区死节点上，
    # 永远轮不到其它健康地区的节点。
    active = same_reg_active_hi + same_reg_active_lo + other_active_hi + other_active_lo
    cooldown = same_reg_cooldown + other_cooldown
    return active + cooldown if active else cooldown


def find_backup_proxy_node(failed_node_name: str) -> str:
    """寻找单个最佳备选节点（保持向后兼容）"""
    cands = get_backup_candidates([failed_node_name])
    return cands[0] if cands else None



# ---- 配置加载 ----
def load_config(path: str) -> bool:
    """加载 core.conf 配置 (支持原子热重载)"""
    global g_cfg, g_config_file
    if not os.path.exists(path):
        return False

    new_cfg = Config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("\t")
                if not parts:
                    continue

                cmd = parts[0].strip()

                if cmd == "listen" and len(parts) >= 3:
                    new_cfg.listen_ip = parts[1].strip()
                    new_cfg.listen_port = int(parts[2].strip())
                elif cmd == "controller" and len(parts) >= 3:
                    new_cfg.ctrl_ip = parts[1].strip()
                    new_cfg.ctrl_port = int(parts[2].strip())
                elif cmd == "node" and len(parts) >= 5 and new_cfg.node_count < MAX_NODES:
                    n = Node()
                    n.name = parts[1].strip()
                    n.uuid = parts[2].strip()
                    n.server = parts[3].strip()
                    n.port = int(parts[4].strip())
                    if len(parts) >= 6:
                        n.tls = parts[5].strip().lower() in ("tls", "1")
                    if len(parts) >= 7:
                        n.sni = parts[6].strip() or n.server
                    else:
                        n.sni = n.server
                    if len(parts) >= 8 and parts[7].strip():
                        n.ws = True
                        n.ws_path = parts[7].strip().rstrip("}, \t\r\n")
                        n.ws_host = parts[8].strip().rstrip("}, \t\r\n") if len(parts) >= 9 else n.sni
                    new_cfg.nodes.append(n)
                    new_cfg.node_count += 1
                elif cmd in ("route-domain", "node-domain") and len(parts) >= 3:
                    d = parts[1].strip()
                    target = parts[2].strip()
                    new_cfg.route_domains.append((d, target))
                elif cmd == "direct-domain" and len(parts) >= 2:
                    d = parts[1].strip()
                    if d not in new_cfg.direct_domains:
                        new_cfg.direct_domains.append(d)
                elif cmd == "proxy-domain" and len(parts) >= 3:
                    d = parts[1].strip()
                    target = parts[2].strip()
                    new_cfg.route_domains.append((d, target))
                elif cmd == "proxy-domain" and len(parts) >= 2:
                    d = parts[1].strip()
                    if d not in new_cfg.proxy_domains:
                        new_cfg.proxy_domains.append(d)
                elif cmd in ("route-ip", "route-cidr") and len(parts) >= 3:
                    ip_str = parts[1].strip()
                    target = parts[2].strip()
                    try:
                        cidr = ipaddress.ip_network(ip_str, strict=False)
                        new_cfg.route_cidrs.append((cidr, target))
                    except ValueError:
                        pass
                elif cmd == "direct-ip" and len(parts) >= 2:
                    try:
                        cidr = ipaddress.ip_network(parts[1].strip(), strict=False)
                        new_cfg.direct_cidrs.append(cidr)
                    except ValueError:
                        pass
                elif cmd == "default" and len(parts) >= 2:
                    new_cfg.default_proxy = parts[1].strip().lower() == "proxy"
                elif cmd == "direct-process" and len(parts) >= 2:
                    p = parts[1].strip().lower()
                    if p not in new_cfg.direct_processes:
                        new_cfg.direct_processes.append(p)
                elif cmd == "proxy-process" and len(parts) >= 2:
                    p = parts[1].strip().lower()
                    if p not in new_cfg.proxy_processes:
                        new_cfg.proxy_processes.append(p)
    except (OSError, ValueError) as e:
        core_log(f"[x] 配置加载失败: {e}")
        return False

    if new_cfg.node_count == 0 and new_cfg.default_proxy:
        return False

    # 加载 Override-Configuration.json 自定义配置（作为未在 core.conf 中显式覆盖时的补充规则）
    override_dir = os.path.dirname(os.path.abspath(path)) if path else g_data_dir
    dom_overrides, cidr_overrides = load_override_rules(override_dir)
    if dom_overrides:
        new_cfg.route_domains = new_cfg.route_domains + dom_overrides
    if cidr_overrides:
        new_cfg.route_cidrs = new_cfg.route_cidrs + cidr_overrides

    # 尽量保留旧配置选中的节点
    if g_cfg and g_cfg.nodes and 0 <= g_cfg.current_node < len(g_cfg.nodes):
        old_name = g_cfg.nodes[g_cfg.current_node].name
        for i, n in enumerate(new_cfg.nodes):
            if n.name == old_name:
                new_cfg.current_node = i
                break

    g_cfg = new_cfg
    g_config_file = os.path.abspath(path)
    return True


# ---- 域名匹配 ----
def domain_suffix_match(host: str, suffix: str) -> bool:
    """域名后缀匹配"""
    host = host.lower()
    suffix = suffix.lower().lstrip(".")
    if not suffix:
        return False
    if host == suffix:
        return True
    if host.endswith("." + suffix):
        return True
    return False


def match_domains(host: str, domain_list: list) -> bool:
    """匹配域名列表"""
    if not host or not domain_list:
        return False
    for d in domain_list:
        if domain_suffix_match(host, d):
            return True
    return False


def match_cidrs(host: str) -> bool:
    """匹配 CIDR 列表"""
    try:
        clean = host.strip("[]").split("%")[0]
        ip = ipaddress.ip_address(clean)
        for cidr in g_cfg.direct_cidrs:
            if ip in cidr:
                return True
    except (ValueError, TypeError):
        pass
    return False


def is_ip_str(host: str) -> bool:
    """判断是否为 IP 地址"""
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        pass
    return False


def clean_host(host: str) -> str:
    """提取规范主机名或 IP（正确处理 IPv6 [addr]:port 及无括号 IPv6）"""
    h = host.strip()
    if h.startswith("["):
        idx = h.find("]")
        if idx != -1:
            return h[1:idx].strip().lower()
    if h.count(":") > 1:
        # 裸 IPv6 地址 (如 2001:4860:...)
        return h.lower()
    return h.split(":")[0].strip().lower()


# ---- 动态直连自愈缓存 ----
g_dynamic_direct = set()
g_dynamic_lock = threading.Lock()

NEVER_DIRECT_DOMAINS = (
    "google.com", "googleapis.com", "gstatic.com", "google.dev", "google",
    "googleusercontent.com", "googlevideo.com", "youtube.com", "ytimg.com",
    "github.com", "githubusercontent.com", "openai.com", "anthropic.com",
    "claude.ai", "chatgpt.com", "twitter.com", "x.com", "telegram.org",
    "wikipedia.org", "wikimedia.org", "asterdex.com", "binance.com"
)

def add_dynamic_direct(host: str):
    """动态记录异常断开的域名，自动加入直连自愈列表（阻断/AI域名除外，避免泄漏国内IP）"""
    h = clean_host(host)
    if not h:
        return
    # 纯 IP 地址 (IPv4 / IPv6) 绝不加入自愈直连白名单，防止海外 IP 污染直连导致死循环与超时
    if is_ip_str(h):
        return
    for blk in NEVER_DIRECT_DOMAINS:
        if h == blk or h.endswith("." + blk):
            return
    with g_dynamic_lock:
        if h not in g_dynamic_direct:
            g_dynamic_direct.add(h)
            core_log(f"[FALLBACK] host {h} added to dynamic direct whitelist")


# ---- Fake-IP 识别与反查 ----
FAKE_V4_NET_STR = "198.18.0.0/15"   # TUN Fake-IPv4 网段 (与 aether_tun.py 一致)
FAKE_V6_NET_STR = "fdfe:dcba:9877::/48"


def _is_fake_ip(host: str) -> bool:
    """判断地址是否落在 TUN Fake-IP 网段 (回流防护)"""
    try:
        clean = host.strip("[]").split("%")[0]
        if ":" not in clean:
            return ipaddress.IPv4Address(clean) in ipaddress.IPv4Network(FAKE_V4_NET_STR)
        return ipaddress.IPv6Address(clean) in ipaddress.IPv6Network(FAKE_V6_NET_STR)
    except Exception:
        return False


def unwrap_fake_ip(host: str) -> str:
    """若目标为 Fake-IP (IPv4 198.18.0.0/15 或 IPv6 fdfe:dcba:9877::/48)，反查恢复为真实域名"""
    if not host:
        return host
    clean = clean_host(host)
    if _is_fake_ip(clean):
        pool = getattr(sys, "_aether_fake_ip_pool", None)
        if pool is not None:
            dom = pool.reverse(clean)
            if dom:
                return dom
        try:
            try:
                from core.tun_dns import reverse_fake_ip
            except ImportError:
                from tun_dns import reverse_fake_ip
            real_dom = reverse_fake_ip(clean)
            if real_dom:
                return real_dom
        except Exception:
            pass
    return host


# ---- 规则决策 ----
def decide_route(host: str, port: int, proc_name: str = None) -> tuple:
    """
    路由决策
    返回 (is_proxy: bool, node_name: str or None)
    """
    host = unwrap_fake_ip(host)
    h_clean = clean_host(host)
    default_node = g_cfg.nodes[g_cfg.current_node].name if (g_cfg.nodes and 0 <= g_cfg.current_node < len(g_cfg.nodes)) else None

    # 1. 进程规则检测（仅在明确要求直连时拦截；auto/proxy 或特定节点均允许域名覆盖规则生效）
    proc_forced_node = None
    if proc_name:
        p_low = proc_name.lower().strip()
        # 1.1 优先查 app_rules.json
        if g_data_dir:
            try:
                from core.aether_rules import rules_get
                app_rule = rules_get(p_low, g_data_dir)
                if app_rule:
                    app_rule = app_rule.lower().strip()
                    if app_rule == "direct":
                        return False, None
                    elif app_rule == "auto":
                        # 自动优选：完全跟随分流规则
                        pass
                    elif app_rule == "proxy":
                        proc_forced_node = default_node
                    else:
                        for n in g_cfg.nodes:
                            if n.name.lower() == app_rule:
                                proc_forced_node = n.name
                                break
                        if not proc_forced_node:
                            proc_forced_node = default_node
            except Exception:
                pass

        # 1.2 检查 core.conf 中定义的 direct-process / proxy-process
        if p_low in g_cfg.direct_processes:
            return False, None
        if p_low in g_cfg.proxy_processes and not proc_forced_node:
            proc_forced_node = default_node

    # 2. 最高优先级：自定义覆盖配置规则 (Override-Configuration.json) 与专有路由
    if is_ip_str(host):
        try:
            ip_obj = ipaddress.ip_address(h_clean.strip("[]").split("%")[0])
            for net, target in g_cfg.route_cidrs:
                if ip_obj in net:
                    matched_node = resolve_node_by_target(target, g_cfg.nodes, default_node)
                    return True, matched_node
        except Exception:
            pass

    if g_cfg.route_domains:
        for d, target in g_cfg.route_domains:
            if domain_suffix_match(h_clean, d) or (host and domain_suffix_match(host.lower(), d)):
                matched_node = resolve_node_by_target(target, g_cfg.nodes, default_node)
                return True, matched_node

    # 3. 进程强制指定节点（未命中自定义域名规则时的降级）
    if proc_forced_node:
        return True, proc_forced_node

    # 5. 域名分流规则
    if match_domains(host, g_cfg.direct_domains):
        return False, None
    if match_domains(host, g_cfg.proxy_domains):
        return True, default_node

    # 6. IP / CIDR / GeoIP 分流规则
    if is_ip_str(host):
        if match_cidrs(host):
            return False, None
        try:
            try:
                from core.aether_geoip import is_cn
            except ImportError:
                from aether_geoip import is_cn
            if is_cn(host, g_data_dir):
                return False, None
        except Exception:
            pass

    # 7. 默认动作
    if g_cfg.default_proxy and g_cfg.node_count > 0:
        return True, default_node
    return False, None



# ---- VLESS 协议 ----
def uuid_parse(uuid_str: str) -> bytes:
    """解析 UUID 字符串为 16 字节"""
    return uuid_mod.UUID(uuid_str).bytes


def vless_build_header(node: Node, host: str, port: int) -> bytes:
    """构建 VLESS 请求头"""
    buf = bytearray()
    buf.append(0)  # version
    buf.extend(uuid_parse(node.uuid))  # UUID (16 bytes)
    buf.append(0)  # addon length
    buf.append(1)  # command: TCP
    buf.append((port >> 8) & 0xFF)
    buf.append(port & 0xFF)

    # Address type
    h_clean = host.strip("[]").split("%")[0]
    try:
        ip = ipaddress.IPv4Address(h_clean)
        buf.append(1)  # IPv4
        buf.extend(ip.packed)
    except ValueError:
        try:
            ip = ipaddress.IPv6Address(h_clean)
            buf.append(3)  # IPv6
            buf.extend(ip.packed)
        except ValueError:
            # Domain name
            encoded = host.encode("utf-8")
            if len(encoded) > 255:
                raise ValueError("host too long")
            buf.append(2)  # Domain
            buf.append(len(encoded))
            buf.extend(encoded)

    return bytes(buf)


# ---- 出站连接 ----
def _tun_dns_resolve(host: str) -> str:
    """TUN 模式下的直连域名解析: 经物理网卡向上游 UDP DNS 查询 A 记录。

    绕过系统解析器——TUN 模式下系统 DNS 已被 Fake-IP 劫持，getaddrinfo 会
    返回 198.18.x.x 导致直连目标回流 TUN 形成循环。失败返回 None。
    """
    bind_ip = os.environ.get("AETHER_BIND_IP")
    if not bind_ip:
        try:
            try:
                from core.aether_tun import detect_physical_network
            except ImportError:
                from aether_tun import detect_physical_network
            phys = detect_physical_network()
            bind_ip = phys.get("v4_ip")
        except Exception:
            pass

    upstreams = [os.environ.get("AETHER_DNS_UPSTREAM", "223.5.5.5"), "119.29.29.29", "114.114.114.114"]
    for upstream in upstreams:
        s = None
        try:
            txid = random.getrandbits(16)
            qname = b"".join(bytes([len(l)]) + (l.encode("idna") if not l.isascii() else l.encode()) for l in host.split(".")) + b"\x00"
            query = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            if bind_ip:
                try:
                    s.bind((bind_ip, 0))
                except OSError:
                    pass
            s.sendto(query, (upstream, 53))
            data, _ = s.recvfrom(4096)
            if len(data) < 12 or struct.unpack(">H", data[:2])[0] != txid:
                continue
            ancount = struct.unpack(">H", data[6:8])[0]
            try:
                from tun_dns import skip_dns_question, _decode_qname
            except ImportError:
                from core.tun_dns import skip_dns_question, _decode_qname
            off = skip_dns_question(data, 12)
            if off < 0:
                continue
            # 解析 Answer 中的 A 记录
            for _ in range(ancount):
                if off >= len(data):
                    break
                _, off = _decode_qname(data, off)
                if off + 10 > len(data):
                    break
                atype, _aclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                if off + rdlen > len(data):
                    break
                if atype == 1 and rdlen == 4:
                    res_ip = socket.inet_ntoa(data[off:off + 4])
                    if not _is_fake_ip(res_ip):
                        return res_ip
                off += rdlen
        except Exception:
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return None


def dial_host(host: str, port: int, timeout: float = HANDSHAKE_TIMEOUT) -> socket.socket:
    """建立 TCP 出站连接 (支持 IPv4/IPv6，含 TUN 物理出口绑定防回环)"""
    if _is_fake_ip(host):
        raise ConnectionError(f"refusing to dial Fake-IP {host} (TUN 回流防护)")

    bind_ip = os.environ.get("AETHER_BIND_IP")
    bind_ip6 = os.environ.get("AETHER_BIND_IP6")
    tun_mode = os.environ.get("AETHER_TUN") == "1"

    if tun_mode and not _is_ip_literal(host):
        resolved = _tun_dns_resolve(host)
        if resolved and not _is_fake_ip(resolved):
            host = resolved
        else:
            raise ConnectionError(f"TUN DNS resolve failed for {host}")

    is_v6 = ":" in host
    fam = socket.AF_INET6 if is_v6 else socket.AF_INET

    s = None
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if tun_mode:
            if is_v6:
                if bind_ip6:
                    try:
                        s.bind((bind_ip6, 0))
                    except OSError:
                        pass
                else:
                    import errno
                    raise OSError(errno.ENETUNREACH, f"IPv6 unreachable: physical uplink has no IPv6 for {host}")
            elif bind_ip:
                try:
                    s.bind((bind_ip, 0))
                except OSError:
                    pass
        s.connect((host, port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s
    except Exception:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        raise


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]").split("%")[0])
        return True
    except Exception:
        return False


# ---- WebSocket 帧 ----
def _ws_build_frame(data: bytes, opcode: int = 0x02) -> bytes:
    """构建 WebSocket 帧（客户端掩码）"""
    frame = bytearray()
    frame.append(0x80 | opcode)  # FIN + opcode

    mask_key = bytes([random.randint(0, 255) for _ in range(4)])
    length = len(data)

    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", length))

    frame.extend(mask_key)
    masked = bytes(data[i] ^ mask_key[i % 4] for i in range(length))
    frame.extend(masked)

    return bytes(frame)


def _ws_read_frame(sock: socket.socket) -> tuple:
    """读取 WebSocket 帧，返回 (opcode, payload)"""
    # 读取头部
    header = _recv_all(sock, 2)
    if not header:
        return None, None

    b0, b1 = header[0], header[1]
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) != 0
    length = b1 & 0x7F

    if length == 126:
        ext = _recv_all(sock, 2)
        if not ext:
            return None, None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = _recv_all(sock, 8)
        if not ext:
            return None, None
        length = struct.unpack(">Q", ext)[0]

    # 控制帧 (Close, Ping, Pong) 读取载荷
    if opcode in (0x8, 0x9, 0xA):
        payload = _recv_all(sock, length) if length > 0 else b""
        return opcode, payload

    if masked:
        mask_key = _recv_all(sock, 4)
        if not mask_key:
            return None, None
        payload = _recv_all(sock, length)
        if not payload:
            return None, None
        payload = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))
    else:
        payload = _recv_all(sock, length) if length > 0 else b""

    return opcode, payload


# ---- 通道封装 ----
class Chan:
    """出站通道：支持裸 TCP / TLS / WebSocket / VLESS"""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.tls = False
        self.ws = False
        self.ws_buffer = b""
        self.in_buffer = bytearray()
        self.vless = False
        self.vless_resp_read = False
        self.lock = threading.Lock()

    def send(self, data: bytes):
        """发送数据"""
        with self.lock:
            if self.ws:
                self.sock.sendall(_ws_build_frame(data))
            else:
                self.sock.sendall(data)

    def _recv_raw(self, max_size: int = 65536) -> bytes:
        if self.ws:
            while True:
                if self.ws_buffer:
                    chunk = self.ws_buffer[:max_size]
                    self.ws_buffer = self.ws_buffer[max_size:]
                    return chunk
                opcode, payload = _ws_read_frame(self.sock)
                if opcode is None or opcode == 0x8:  # Error or Close
                    return b""
                if opcode == 0x9:  # Ping
                    # 回复 Pong (RFC 6455 规范：Pong 载荷必须与 Ping 一致)
                    pong = _ws_build_frame(payload or b"", 0x0A)
                    with self.lock:
                        try:
                            self.sock.sendall(pong)
                        except Exception:
                            pass
                    continue
                if opcode == 0x0A:  # Pong
                    continue
                if payload:
                    self.ws_buffer = payload
                    chunk = self.ws_buffer[:max_size]
                    self.ws_buffer = self.ws_buffer[max_size:]
                    return chunk
                return b""
        else:
            return self.sock.recv(max_size)

    def recv(self, max_size: int = 65536) -> bytes:
        """接收数据（自动剥离 VLESS 协议响应头）"""
        if self.vless and not self.vless_resp_read:
            # VLESS 服务端响应头规范：version (1B) + addon_length (1B) + addons (addon_length B)
            while len(self.in_buffer) < 2:
                chunk = self._recv_raw(max_size)
                if not chunk:
                    return b""
                self.in_buffer.extend(chunk)
            addon_len = self.in_buffer[1]
            hdr_len = 2 + addon_len
            while len(self.in_buffer) < hdr_len:
                chunk = self._recv_raw(max_size)
                if not chunk:
                    return b""
                self.in_buffer.extend(chunk)
            # 剥离 VLESS 响应头
            del self.in_buffer[:hdr_len]
            self.vless_resp_read = True

        if self.in_buffer:
            chunk = bytes(self.in_buffer[:max_size])
            del self.in_buffer[:max_size]
            return chunk

        return self._recv_raw(max_size)

    def close(self):
        """关闭通道"""
        try:
            if self.ws:
                try:
                    self.sock.sendall(_ws_build_frame(b"", 0x08))
                except Exception:
                    pass
            self.sock.close()
        except Exception:
            pass


def _recv_all(sock: socket.socket, size: int) -> bytes:
    """可靠接收指定字节数"""
    buf = b""
    while len(buf) < size:
        try:
            chunk = sock.recv(size - len(buf))
            if not chunk:
                return None
            buf += chunk
        except socket.timeout:
            return None
        except Exception:
            return None
    return buf


# ---- TLS 握手 ----
def _tls_handshake(sock: socket.socket, sni: str) -> ssl.SSLContext:
    """建立 TLS 连接"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    # TLS 1.2
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssock = context.wrap_socket(sock, server_hostname=sni)
    return ssock


# ---- WebSocket 握手 ----
def _ws_handshake(sock: socket.socket, path: str, host: str) -> tuple:
    """WebSocket 握手，返回 (success: bool, leftover_bytes: bytes)"""
    key = base64.b64encode(bytes(random.randint(0, 255) for _ in range(16))).decode()
    h = host.strip().rstrip("}, \t\r\n")
    p = path.strip().rstrip("}, \t\r\n") or "/"
    request = (
        f"GET {p} HTTP/1.1\r\n"
        f"Host: {h}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(request)

    # 读取响应
    resp = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except Exception:
            chunk = None
        if not chunk:
            return False, b""
        resp += chunk
        if b"\r\n\r\n" in resp:
            break

    idx = resp.find(b"\r\n\r\n")
    headers = resp[:idx]
    leftover = resp[idx + 4:]

    status_line = headers.split(b"\r\n")[0].strip() if headers else b""
    if re.match(rb"^HTTP/1\.[01]\s+101(\s|$)", status_line):
        return True, leftover
    else:
        first_line = headers.split(b"\r\n")[0].decode("ascii", errors="replace") if headers else "empty"
        core_log(f"[x] WebSocket rejected: {first_line}")
        return False, b""


# ---- 节点连接 ----
def node_open(host: str, port: int, node_name: str = None) -> Chan:
    """建立到 VLESS 节点的通道"""
    host = unwrap_fake_ip(host)
    idx = g_cfg.current_node
    if node_name:
        for i, n in enumerate(g_cfg.nodes):
            if n.name == node_name:
                idx = i
                break

    if idx < 0 or idx >= g_cfg.node_count:
        raise ValueError("no node configured")

    node = g_cfg.nodes[idx]
    server_target = node.server
    if not _is_ip_literal(server_target):
        real_server = _tun_dns_resolve(server_target)
        if real_server and not _is_fake_ip(real_server):
            server_target = real_server
        elif os.environ.get("AETHER_TUN") == "1":
            raise ConnectionError(f"TUN DNS resolve failed for node server {server_target}")
    sock = None
    ch = None
    try:
        sock = dial_host(server_target, node.port)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        ch = Chan(sock)

        if node.tls:
            ssock = _tls_handshake(sock, node.sni)
            ch = Chan(ssock)
            ch.tls = True

        if node.ws:
            ok, leftover = _ws_handshake(ch.sock, node.ws_path, node.ws_host)
            if not ok:
                ch.close()
                raise ConnectionError("WebSocket handshake failed")
            ch.ws = True
            if leftover:
                ch.in_buffer.extend(leftover)

        # 标记为 VLESS 节点，启用 2 字节响应头自动剥离
        ch.vless = True

        # 发送 VLESS 头
        vh = vless_build_header(node, host, port)
        ch.send(vh)

        # 握手完成，将 socket 切换为长连接保活模式
        try:
            ch.sock.settimeout(120.0)
        except Exception:
            pass

        return ch
    except Exception:
        if ch is not None:
            ch.close()
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        raise


def connect_proxy_with_failover(host: str, port: int, primary_node: str = None, proc_name: str = "", max_backup_tries: int = 2) -> tuple:
    """
    多节点容灾连接池：
    先连接指定的 primary_node（支持重试 1 次），若失败则自动打上短暂熔断冷却标记，
    并自动从候选容灾池中提取健康的同地区备选节点依次尝试切换连接。
    返回 (ch: Chan, used_node_name: str)
    若所有备选节点全部失败，则向上层抛出异常，绝不降级直连。
    """
    tried_nodes = set()
    first_err = None

    # 1. 尝试主节点 (冷却期内直接跳过，避免每个连接都先白等一次已知故障节点)
    if primary_node:
        tried_nodes.add(primary_node.strip().lower())
        if is_node_in_cooldown(primary_node):
            core_log(f"[FAILOVER] ({proc_name}) {host}:{port} primary node [{primary_node}] in cooldown, skip to backup pool")
        else:
            try:
                ch = node_open_retry(host, port, primary_node, attempts=1)
                mark_node_ok(primary_node)
                return ch, primary_node
            except Exception as e:
                first_err = e
                mark_node_failed(primary_node)
                core_log(f"[FAIL] ({proc_name}) {host}:{port} primary node [{primary_node}] failed: {e}")

    # 2. 从多节点容灾池依次尝试健康备选节点
    candidates = get_backup_candidates(tried_nodes)
    if not candidates and not primary_node:
        # 如果未指定 primary_node，直接取第一个候选
        candidates = get_backup_candidates([])

    backup_tries = 0
    last_err = first_err
    for cand in candidates:
        if backup_tries >= max_backup_tries:
            break
        tried_nodes.add(cand.strip().lower())
        backup_tries += 1
        core_log(f"[FAILOVER] ({proc_name}) {host}:{port} failover to backup node [{cand}] (attempt {backup_tries}/{max_backup_tries})")
        try:
            ch = node_open_retry(host, port, cand, attempts=1)
            mark_node_ok(cand)
            return ch, cand
        except Exception as e_cand:
            last_err = e_cand
            mark_node_failed(cand)
            core_log(f"[FAIL] ({proc_name}) {host}:{port} backup node [{cand}] failed: {e_cand}")

    if last_err:
        raise last_err
    raise ConnectionError(f"all proxy nodes failed for {host}:{port}")


def node_open_retry(host: str, port: int, node_name: str = None, attempts: int = 2) -> Chan:
    """建立代理通道，失败后快速重连，最后将错误交给上层降级处理。"""
    last_error = None
    for attempt in range(max(1, attempts)):
        try:
            return node_open(host, port, node_name)
        except Exception as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.1)
    raise last_error


# ---- 直连通道 ----
def chan_outbound(host: str, port: int) -> Chan:
    """建立直连通道"""
    host = unwrap_fake_ip(host)
    sock = dial_host(host, port)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return Chan(sock)


def chan_outbound_retry(host: str, port: int, attempts: int = 2) -> Chan:
    """建立直连通道，失败后快速重连。"""
    last_error = None
    for attempt in range(max(1, attempts)):
        try:
            return chan_outbound(host, port)
        except Exception as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.1)
    raise last_error


# ---- 通道中继 ----
def relay_tunnel(client: socket.socket, ch: Chan, is_up: bool = True, timeout: float = 20.0):
    """双向中继客户端 ↔ 节点通道，支持防死锁双向掐断与超时检测，返回 (bytes_up, bytes_down, err_msg)"""
    bytes_up = 0
    bytes_down = 0
    err_up = None
    err_down = None
    done_event = threading.Event()

    # 针对双端设置合理的数据流超时（20 秒），防止节点假死时浏览器提前报错 ERR_TIMED_OUT
    try:
        client.settimeout(timeout)
        ch.sock.settimeout(timeout)
    except Exception:
        pass

    def upstream():
        nonlocal bytes_up, err_up
        try:
            while g_running and not CORE_STOP_EVENT.is_set() and not done_event.is_set():
                try:
                    data = client.recv(16384)
                except socket.timeout:
                    if bytes_up == 0 and bytes_down == 0:
                        err_up = "timed out"
                    break
                except Exception as e:
                    err_up = str(e)
                    break
                if not data:
                    break
                ch.send(data)
                bytes_up += len(data)
                traffic_add(is_up, len(data))
        except Exception as e:
            err_up = str(e)
        finally:
            done_event.set()
            try:
                ch.close()
            except Exception:
                pass

    def downstream():
        nonlocal bytes_down, err_down
        try:
            while g_running and not CORE_STOP_EVENT.is_set() and not done_event.is_set():
                try:
                    data = ch.recv(16384)
                except socket.timeout:
                    err_down = "timed out"
                    break
                except Exception as e:
                    err_down = str(e)
                    break
                if not data:
                    break
                try:
                    client.sendall(data)
                except Exception as e:
                    err_down = str(e)
                    break
                bytes_down += len(data)
                traffic_add(not is_up, len(data))
                # 收到服务端首包响应后，放宽空闲超时至 300 秒，支持长连接 (WebSocket / SSE / 大文件流式下载)
                if bytes_down > 0:
                    try:
                        ch.sock.settimeout(300.0)
                        client.settimeout(300.0)
                    except Exception:
                        pass
        except Exception as e:
            err_down = str(e)
        finally:
            done_event.set()
            try:
                client.close()
            except Exception:
                pass

    up = threading.Thread(target=upstream, daemon=True)
    down = threading.Thread(target=downstream, daemon=True)
    up.start()
    down.start()
    up.join()
    down.join()

    return bytes_up, bytes_down, err_down or err_up


def _report_relay_result(proc_name: str, host: str, port: int, use_proxy: bool, bytes_up: int, bytes_down: int, err: str = None):
    """统一分析并汇报中继结果，准确记录超时与断开日志（取消降级直连）"""
    is_timeout = bool(err and "timed out" in str(err).lower())

    if is_timeout:
        if use_proxy:
            core_log(f"[TIMEOUT] ({proc_name}) {host}:{port} proxy response timed out (ERR_TIMED_OUT)")
        else:
            core_log(f"[TIMEOUT] ({proc_name}) {host}:{port} direct connection timed out (ERR_TIMED_OUT)")
    elif bytes_up > 0 and bytes_down == 0:
        if use_proxy:
            core_log(f"[CLOSED] ({proc_name}) {host}:{port} proxy terminated by remote (ERR_CONNECTION_CLOSED)")
        else:
            core_log(f"[CLOSED] ({proc_name}) {host}:{port} direct terminated by remote")
    elif bytes_up == 0 and bytes_down == 0:
        # 空连接提前掐断或等待首包超时
        if use_proxy:
            core_log(f"[TIMEOUT] ({proc_name}) {host}:{port} connection closed with 0B (ERR_TIMED_OUT)")
        else:
            core_log(f"[CLOSED] ({proc_name}) {host}:{port} direct closed with 0B")
    else:
        core_log(f"[SUCCESS] ({proc_name}) {host}:{port} up={bytes_up}B down={bytes_down}B")


# ---- SOCKS5 处理 ----
def handle_socks5(client: socket.socket, client_ip: str, client_port: int = 0):
    """处理 SOCKS5 代理请求"""
    try:
        # 读取 methods
        # 读取 methods 数量 (版本字节 0x05 已在 handle_client 中读取)
        nm_b = _recv_all(client, 1)
        if not nm_b:
            return
        nm = nm_b[0]
        if nm > 60:
            return
        methods = _recv_all(client, nm)
        if not methods:
            return
        client.sendall(b"\x05\x00")

        # 读取请求
        req = _recv_all(client, 4)
        if not req or len(req) < 4 or req[1] != 0x01:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        atyp = req[3]

        if atyp == 0x01:  # IPv4
            ip = _recv_all(client, 4)
            if not ip:
                return
            host = ".".join(str(b) for b in ip)
        elif atyp == 0x03:  # Domain
            lenb = _recv_all(client, 1)
            if not lenb:
                return
            dl = lenb[0]
            if dl <= 0 or dl > 255:
                return
            domain = _recv_all(client, dl)
            if not domain:
                return
            host = domain.decode("utf-8", errors="replace")
        elif atyp == 0x04:  # IPv6
            ip = _recv_all(client, 16)
            if not ip:
                return
            host = str(ipaddress.IPv6Address(ip))
        else:
            return

        portb = _recv_all(client, 2)
        if not portb:
            return
        port = (portb[0] << 8) | portb[1]

        host = unwrap_fake_ip(host)
        tun_proc = get_tun_client_process(client_port) if client_port else ""
        proc_name = tun_proc or (get_process_for_port(client_port) if client_port else "")
        use_proxy, node_name = decide_route(host, port, proc_name)
        log_conn("TCP", client_ip, client_port, host, port, use_proxy, node_name, proc_name)

        ch = None
        if use_proxy and g_cfg.node_count > 0:
            try:
                ch, used_node = connect_proxy_with_failover(host, port, primary_node=node_name, proc_name=proc_name)
                node_name = used_node
            except Exception as e:
                core_log(f"[FAIL] ({proc_name}) {host}:{port} all proxy failovers exhausted: {e}")
                try:
                    client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                except Exception:
                    pass
                raise e
        else:
            try:
                ch = chan_outbound_retry(host, port)
            except Exception as e:
                core_log(f"[FAIL] ({proc_name}) {host}:{port} direct connect failed: {e}")
                try:
                    client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                except Exception:
                    pass
                raise e

        # 回复成功
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        bytes_up, bytes_down, err = relay_tunnel(client, ch)
        ch.close()
        _report_relay_result(proc_name, host, port, use_proxy, bytes_up, bytes_down, err)
    except Exception as e:
        import traceback
        core_log(f"[x] SOCKS5 error: {e} | {traceback.format_exc(limit=6)}")
    finally:
        if ch is not None:
            try:
                ch.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass


# ---- HTTP 代理处理 ----
def handle_http(client: socket.socket, client_ip: str, first_byte: bytes, client_port: int = 0):
    """处理 HTTP 代理请求"""
    try:
        # 读取请求头
        buf = first_byte
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = client.recv(16384)
            if not chunk:
                return
            buf += chunk

        # 解析请求行
        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = buf.find(b"\n\n")
        if header_end == -1:
            return

        head = buf[:header_end].decode("utf-8", errors="replace")
        first_line = head.split("\r\n")[0].split("\n")[0]
        parts = first_line.split()
        if len(parts) < 2:
            return

        method = parts[0].upper()
        target = parts[1]

        tun_proc = get_tun_client_process(client_port) if client_port else ""
        proc_name = tun_proc or (get_process_for_port(client_port) if client_port else "")

        if method == "CONNECT":
            # HTTPS 隧道
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            else:
                host = target
                port = 443

            host = unwrap_fake_ip(host)
            use_proxy, node_name = decide_route(host, port, proc_name)
            log_conn("TCP", client_ip, client_port, host, port, use_proxy, node_name, proc_name)

            ch = None
            if use_proxy and g_cfg.node_count > 0:
                try:
                    ch, used_node = connect_proxy_with_failover(host, port, primary_node=node_name, proc_name=proc_name)
                    node_name = used_node
                except Exception as e:
                    core_log(f"[FAIL] ({proc_name}) {host}:{port} all proxy failovers exhausted: {e}")
                    try:
                        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    except Exception:
                        pass
                    raise e
            else:
                try:
                    ch = chan_outbound_retry(host, port)
                except Exception as e:
                    core_log(f"[FAIL] ({proc_name}) {host}:{port} direct connect failed: {e}")
                    try:
                        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    except Exception:
                        pass
                    raise e

            try:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except Exception:
                ch.close()
                return

            bytes_up, bytes_down, err = relay_tunnel(client, ch)
            ch.close()
            _report_relay_result(proc_name, host, port, use_proxy, bytes_up, bytes_down, err)
        else:
            # 普通 HTTP
            host, port, path = parse_http_target(target, head)

            if not host:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return

            host = unwrap_fake_ip(host)
            use_proxy, node_name = decide_route(host, port, proc_name)
            log_conn(method, client_ip, client_port, host, port, use_proxy, node_name, proc_name)

            ch = None
            if use_proxy and g_cfg.node_count > 0:
                try:
                    ch, used_node = connect_proxy_with_failover(host, port, primary_node=node_name, proc_name=proc_name)
                    node_name = used_node
                except Exception as e:
                    core_log(f"[FAIL] ({proc_name}) {host}:{port} all proxy failovers exhausted: {e}")
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    return
            else:
                try:
                    ch = chan_outbound_retry(host, port)
                except Exception as e:
                    core_log(f"[FAIL] ({proc_name}) {host}:{port} direct connect failed: {e}")
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    return

            # 重写请求行
            body_start = buf[header_end:]
            if method in ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"):
                new_line = f"{method} {path} HTTP/1.1\r\n".encode()
                rest = head.split("\r\n", 1)[1] if "\r\n" in head else ""
                new_head = new_line + rest.encode("utf-8", errors="replace")
                ch.send(new_head + body_start)
            else:
                ch.send(buf[:header_end] + body_start)

            bytes_up, bytes_down, err = relay_tunnel(client, ch)
            ch.close()
            _report_relay_result(proc_name, host, port, use_proxy, bytes_up, bytes_down, err)
    except Exception as e:
        core_log(f"[x] HTTP error: {e}")
    finally:
        if ch is not None:
            try:
                ch.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass


def parse_http_target(target: str, head: str) -> tuple:
    """解析 HTTP 目标，返回 (host, port, path)"""
    host = ""
    port = 80
    path = "/"

    if target.startswith("http://"):
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    elif target.startswith("/"):
        # origin-form
        path = target
        # 从 Host 头获取
        for line in head.split("\r\n"):
            if line.lower().startswith("host:"):
                h = line[5:].strip()
                if ":" in h:
                    host, port_str = h.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        pass
                else:
                    host = h
                break

    return host, port, path


def log_conn(proto: str, client_ip: str, client_port: int, host: str, port: int, use_proxy: bool, node_name: str = None, proc_name: str = None):
    """记录连接日志"""
    proc_str = f"({proc_name})" if proc_name else ""
    src_str = f"{client_ip}:{client_port}{proc_str}" if client_port else f"{client_ip}{proc_str}"
    if use_proxy and node_name:
        core_log(f"[{proto}] {src_str} --> {host}:{port} match proxy using {node_name}")
    else:
        core_log(f"[{proto}] {src_str} --> {host}:{port} match DIRECT using DIRECT")


# ---- 客户端线程 ----
def handle_client(client: socket.socket, client_ip: str, client_port: int = 0):
    """处理客户端连接"""
    try:
        client.settimeout(HANDSHAKE_TIMEOUT)
        first = _recv_all(client, 1)
        if not first:
            return

        if first[0] == 0x05:
            handle_socks5(client, client_ip, client_port)
        else:
            handle_http(client, client_ip, first, client_port)
    except Exception as e:
        core_log(f"[x] client error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---- 控制器 API ----
def ctrl_handle_version(client: socket.socket):
    """处理 /version"""
    body = json.dumps({"version": "AetherCore Python Core v0.1.0"})
    ctrl_send(client, "200 OK", "application/json", body)


def ctrl_handle_proxies(client: socket.socket):
    """处理 /proxies"""
    if g_cfg.node_count == 0:
        ctrl_send(client, "200 OK", "application/json", json.dumps({"proxies": {}}))
        return

    current = g_cfg.nodes[g_cfg.current_node].name
    all_names = [n.name for n in g_cfg.nodes]
    body = json.dumps({
        "proxies": {
            "🎮 手动节点 (MANUAL)": {
                "type": "select",
                "now": current,
                "all": all_names,
            }
        }
    })
    ctrl_send(client, "200 OK", "application/json", body)


def ctrl_handle_logs(client: socket.socket):
    """处理 /logs - 流式日志"""
    hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n"
    client.sendall(hdr.encode())

    last_seq = 0
    while g_running and not CORE_STOP_EVENT.is_set():
        with g_log_lock:
            entries = [e for e in g_log_ring if e["seq"] > last_seq]
            for e in entries:
                if e["seq"] > last_seq:
                    last_seq = e["seq"]
                line = json.dumps({"type": "log", "payload": e["line"]}) + "\n"
                try:
                    client.sendall(line.encode())
                except Exception:
                    return
        time.sleep(0.2)


def ctrl_handle_traffic(client: socket.socket):
    """处理 /traffic - 流式流量"""
    hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n"
    client.sendall(hdr.encode())

    while g_running and not CORE_STOP_EVENT.is_set():
        data = json.dumps({"up": g_up_bytes, "down": g_down_bytes}) + "\n"
        try:
            client.sendall(data.encode())
        except Exception:
            return
        time.sleep(1.0)


def ctrl_set_node(name: str) -> bool:
    """切换当前节点"""
    for i, n in enumerate(g_cfg.nodes):
        if n.name == name:
            g_cfg.current_node = i
            core_log(f"[i] manual node switched to {name}")
            return True
    return False


def ctrl_send(client: socket.socket, status: str, ctype: str, body: str):
    """发送控制器响应"""
    resp = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        f"Connection: close\r\n\r\n"
        f"{body}"
    )
    try:
        client.sendall(resp.encode())
    except Exception:
        pass


def handle_controller(client: socket.socket):
    """处理控制器请求"""
    try:
        client.settimeout(CONTROLLER_TIMEOUT)
        buf = b""
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = client.recv(8192)
            if not chunk:
                return
            buf += chunk

        req = buf.decode("utf-8", errors="replace")
        first_line = req.split("\r\n")[0].split("\n")[0]
        parts = first_line.split()
        if len(parts) < 2:
            ctrl_send(client, "400 Bad Request", "application/json",
                      json.dumps({"error": "bad request"}))
            return

        method = parts[0]
        path = parts[1]

        # 读取完整请求体 (Content-Length)
        body_bytes = b""
        try:
            sep = b"\r\n\r\n"
            sep_len = 4
            header_end = buf.find(sep)
            if header_end == -1:
                sep = b"\n\n"
                sep_len = 2
                header_end = buf.find(sep)
            if header_end >= 0:
                body_bytes = buf[header_end + sep_len:]
                content_length = 0
                for line in req.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            pass
                remaining = content_length - len(body_bytes)
                while remaining > 0:
                    chunk = client.recv(min(remaining, 4096))
                    if not chunk:
                        break
                    body_bytes += chunk
                    remaining -= len(chunk)
        except Exception:
            pass

        body = body_bytes.decode("utf-8", errors="replace")

        if method == "GET" and path == "/version":
            ctrl_handle_version(client)
        elif method == "GET" and path.startswith("/logs"):
            ctrl_handle_logs(client)
        elif method == "GET" and path.startswith("/traffic"):
            ctrl_handle_traffic(client)
        elif method == "GET" and path == "/proxies":
            ctrl_handle_proxies(client)
        elif method == "PUT" and path.startswith("/configs"):
            conf_path = g_config_file
            if body.strip():
                try:
                    cdata = json.loads(body)
                    if isinstance(cdata, dict) and cdata.get("path"):
                        conf_path = cdata["path"]
                except Exception:
                    pass
            if not conf_path and g_data_dir:
                conf_path = os.path.join(g_data_dir, "core.conf")
            if conf_path and os.path.exists(conf_path) and load_config(conf_path):
                core_log(f"[i] configuration reloaded successfully from {conf_path}")
                ctrl_send(client, "204 No Content", "application/json", "")
            else:
                core_log(f"[x] configuration reload failed (path={conf_path})")
                ctrl_send(client, "500 Internal Server Error", "application/json",
                          json.dumps({"error": "failed to reload config"}))
        elif method == "PUT" and path.startswith("/proxies/"):
            # 解析 body 中的 {"name": "..."}
            body_text = body.strip() or (req.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in req else "")
            try:
                data = json.loads(body_text)
                name = data.get("name", "")
                if name and ctrl_set_node(name):
                    ctrl_send(client, "204 No Content", "application/json", "")
                else:
                    ctrl_send(client, "404 Not Found", "application/json",
                              json.dumps({"error": "node not found"}))
            except json.JSONDecodeError:
                ctrl_send(client, "400 Bad Request", "application/json",
                          json.dumps({"error": "invalid json"}))
        else:
            ctrl_send(client, "404 Not Found", "application/json",
                      json.dumps({"error": "not found"}))
    except Exception as e:
        core_log(f"[x] controller error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---- 主流程 ----
def aether_core_main(data_dir: str = None, config_file: str = None):
    """启动代理核心"""
    global g_running, g_data_dir, g_config_file
    CORE_STOP_EVENT.clear()
    g_running = True

    if data_dir:
        g_data_dir = data_dir
    elif config_file:
        g_data_dir = os.path.dirname(config_file)

    if config_file is None:
        if data_dir:
            config_file = os.path.join(data_dir, "core.conf")
        else:
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "..", "data", "core.conf")

    if not load_config(config_file):
        print(f"[x] 加载配置失败: {config_file}", file=sys.stderr)
        return 1

    # 启动代理监听
    try:
        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_sock.bind((g_cfg.listen_ip, g_cfg.listen_port))
        proxy_sock.listen(128)
        proxy_sock.settimeout(1.0)
    except OSError as e:
        print(f"[x] 监听 {g_cfg.listen_ip}:{g_cfg.listen_port} 失败: {e}", file=sys.stderr)
        return 1

    # 启动控制器监听
    try:
        ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ctrl_sock.bind((g_cfg.ctrl_ip, g_cfg.ctrl_port))
        ctrl_sock.listen(16)
        ctrl_sock.settimeout(1.0)
    except OSError as e:
        print(f"[x] 控制器监听 {g_cfg.ctrl_ip}:{g_cfg.ctrl_port} 失败: {e}", file=sys.stderr)
        proxy_sock.close()
        return 1

    core_log(f"[i] AetherCore Python core started: listen {g_cfg.listen_ip}:{g_cfg.listen_port}, "
             f"controller {g_cfg.ctrl_ip}:{g_cfg.ctrl_port}, nodes {g_cfg.node_count}")

    # 控制器线程
    def ctrl_loop():
        while g_running and not CORE_STOP_EVENT.is_set():
            try:
                client, _ = ctrl_sock.accept()
                threading.Thread(target=handle_controller, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    threading.Thread(target=ctrl_loop, daemon=True).start()

    # 主代理循环
    try:
        while g_running and not CORE_STOP_EVENT.is_set():
            try:
                client, addr = proxy_sock.accept()
                client_ip = addr[0]
                client_port = addr[1] if len(addr) > 1 else 0
                threading.Thread(target=handle_client, args=(client, client_ip, client_port), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
    finally:
        g_running = False
        proxy_sock.close()
        ctrl_sock.close()

    return 0


def main():
    """CLI 入口，兼容 C 版本 aether_core.exe 的参数格式"""
    import argparse

    parser = argparse.ArgumentParser(description="AetherCore 代理核心")
    parser.add_argument("core", nargs="?", default="core", help="子命令")
    parser.add_argument("-f", "--config", default=None, help="配置文件路径")
    parser.add_argument("-d", "--data-dir", default=None, help="数据目录路径")

    args = sys.argv[1:]

    config_file = None
    data_dir = None

    i = 0
    while i < len(args):
        if args[i] == "core":
            i += 1
        elif args[i] == "-f" and i + 1 < len(args):
            config_file = args[i + 1]
            i += 2
        elif args[i] == "-d" and i + 1 < len(args):
            data_dir = args[i + 1]
            i += 2
        elif args[i] in ("--help", "-h"):
            print("用法: aether_core.py core -f <core.conf>")
            return 0
        else:
            i += 1

    return aether_core_main(data_dir, config_file)


if __name__ == "__main__":
    sys.exit(main())