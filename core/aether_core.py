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
                 "direct_domains", "proxy_domains",
                 "direct_cidrs", "default_proxy")

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
        self.direct_cidrs = []
        self.default_proxy = True  # True=proxy, False=direct


# ---- 全局状态 ----
g_cfg = Config()
g_running = True
g_up_bytes = 0
g_down_bytes = 0
g_log_ring = []
g_log_seq = 0
g_log_lock = threading.Lock()


def core_log(fmt: str, *args):
    """记录日志到环形缓冲区"""
    global g_log_seq
    msg = fmt % args if args else fmt
    with g_log_lock:
        g_log_seq += 1
        g_log_ring.append({"seq": g_log_seq, "line": msg})
        if len(g_log_ring) > LOG_RING_CAP:
            g_log_ring[:LOG_RING_CAP // 2] = []
    print(f"[core] {msg}", flush=True)


def traffic_add(is_up: bool, n: int):
    """增加流量计数"""
    global g_up_bytes, g_down_bytes
    if is_up:
        g_up_bytes += n
    else:
        g_down_bytes += n


# ---- 配置加载 ----
def load_config(path: str) -> bool:
    """加载 core.conf 配置"""
    global g_cfg
    if not os.path.exists(path):
        return False

    g_cfg = Config()

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
                    g_cfg.listen_ip = parts[1].strip()
                    g_cfg.listen_port = int(parts[2].strip())
                elif cmd == "controller" and len(parts) >= 3:
                    g_cfg.ctrl_ip = parts[1].strip()
                    g_cfg.ctrl_port = int(parts[2].strip())
                elif cmd == "node" and len(parts) >= 5 and g_cfg.node_count < MAX_NODES:
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
                        n.ws_path = parts[7].strip()
                        n.ws_host = parts[8].strip() if len(parts) >= 9 else n.sni
                    g_cfg.nodes.append(n)
                    g_cfg.node_count += 1
                elif cmd == "direct-domain" and len(parts) >= 2:
                    d = parts[1].strip()
                    if d not in g_cfg.direct_domains:
                        g_cfg.direct_domains.append(d)
                elif cmd == "proxy-domain" and len(parts) >= 2:
                    d = parts[1].strip()
                    if d not in g_cfg.proxy_domains:
                        g_cfg.proxy_domains.append(d)
                elif cmd == "direct-ip" and len(parts) >= 2:
                    try:
                        cidr = ipaddress.IPv4Network(parts[1].strip(), strict=False)
                        g_cfg.direct_cidrs.append(cidr)
                    except ValueError:
                        pass
                elif cmd == "default" and len(parts) >= 2:
                    g_cfg.default_proxy = parts[1].strip().lower() == "proxy"
                elif cmd in ("direct-process", "proxy-process") and len(parts) >= 2:
                    pass  # 分应用规则由 launcher 管理，内核仅做域名/IP 分流
    except (OSError, ValueError) as e:
        core_log(f"[x] 配置加载失败: {e}")
        return False

    return g_cfg.node_count > 0 or not g_cfg.default_proxy


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
        ip = ipaddress.IPv4Address(host)
        for cidr in g_cfg.direct_cidrs:
            if ip in cidr:
                return True
    except ValueError:
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


# ---- 规则决策 ----
def decide_route(host: str, port: int) -> tuple:
    """
    路由决策
    返回 (is_proxy: bool, node_name: str or None)
    """
    if match_domains(host, g_cfg.direct_domains):
        return False, None
    if match_domains(host, g_cfg.proxy_domains):
        return True, g_cfg.nodes[g_cfg.current_node].name if g_cfg.nodes else None
    if is_ip_str(host) and match_cidrs(host):
        return False, None
    if g_cfg.default_proxy and g_cfg.node_count > 0:
        return True, g_cfg.nodes[g_cfg.current_node].name
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
    try:
        ip = ipaddress.IPv4Address(host)
        buf.append(1)  # IPv4
        buf.extend(ip.packed)
    except ValueError:
        try:
            ip = ipaddress.IPv6Address(host)
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
def dial_host(host: str, port: int, timeout: float = HANDSHAKE_TIMEOUT) -> socket.socket:
    """建立 TCP 出站连接"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s
    except Exception:
        raise


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

    if opcode == 0x8:  # Close
        return opcode, None
    if opcode == 0x9:  # Ping
        return opcode, None
    if opcode == 0xA:  # Pong
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
        self.lock = threading.Lock()

    def send(self, data: bytes):
        """发送数据"""
        with self.lock:
            if self.ws:
                self.sock.sendall(_ws_build_frame(data))
            else:
                self.sock.sendall(data)

    def recv(self, max_size: int = 65536) -> bytes:
        """接收数据"""
        if self.ws:
            while True:
                if self.ws_buffer:
                    chunk = self.ws_buffer[:max_size]
                    self.ws_buffer = self.ws_buffer[max_size:]
                    return chunk
                opcode, payload = _ws_read_frame(self.sock)
                if opcode == 0x8:  # Close
                    return b""
                if opcode == 0x9:  # Ping
                    # 回复 Pong
                    pong = _ws_build_frame(b"", 0x0A)
                    with self.lock:
                        self.sock.sendall(pong)
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
def _ws_handshake(sock: socket.socket, path: str, host: str) -> bool:
    """WebSocket 握手"""
    key = base64.b64encode(bytes(random.randint(0, 255) for _ in range(16))).decode()
    request = (
        f"GET {path or '/'} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(request)

    # 读取响应
    resp = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return False
        resp += chunk
        if b"\r\n\r\n" in resp:
            break

    return b"101" in resp


# ---- 节点连接 ----
def node_open(host: str, port: int, node_name: str = None) -> Chan:
    """建立到 VLESS 节点的通道"""
    idx = g_cfg.current_node
    if node_name:
        for i, n in enumerate(g_cfg.nodes):
            if n.name == node_name:
                idx = i
                break

    if idx < 0 or idx >= g_cfg.node_count:
        raise ValueError("no node configured")

    node = g_cfg.nodes[idx]
    sock = dial_host(node.server, node.port)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    ch = Chan(sock)

    if node.tls:
        ssock = _tls_handshake(sock, node.sni)
        ch = Chan(ssock)
        ch.tls = True

    if node.ws:
        if not _ws_handshake(ch.sock, node.ws_path, node.ws_host):
            ch.close()
            raise ConnectionError("WebSocket handshake failed")
        ch.ws = True

    # 发送 VLESS 头
    vh = vless_build_header(node, host, port)
    ch.send(vh)

    return ch


# ---- 直连通道 ----
def chan_outbound(host: str, port: int) -> Chan:
    """建立直连通道"""
    sock = dial_host(host, port)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return Chan(sock)


# ---- 通道中继 ----
def relay_tunnel(client: socket.socket, ch: Chan, is_up: bool = True):
    """双向中继客户端 ↔ 节点通道"""

    def upstream():
        """客户端 -> 节点"""
        try:
            while g_running and not CORE_STOP_EVENT.is_set():
                data = client.recv(16384)
                if not data:
                    break
                ch.send(data)
                traffic_add(is_up, len(data))
        except Exception:
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def downstream():
        """节点 -> 客户端"""
        try:
            while g_running and not CORE_STOP_EVENT.is_set():
                data = ch.recv(16384)
                if not data:
                    break
                client.sendall(data)
                traffic_add(not is_up, len(data))
        except Exception:
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    up = threading.Thread(target=upstream, daemon=True)
    down = threading.Thread(target=downstream, daemon=True)
    up.start()
    down.start()
    up.join()
    down.join()


# ---- SOCKS5 处理 ----
def handle_socks5(client: socket.socket, client_ip: str):
    """处理 SOCKS5 代理请求"""
    try:
        # 读取 methods
        data = _recv_all(client, 2)
        if not data or data[0] != 0x05:
            return
        nm = data[1]
        if nm > 60:
            return
        methods = _recv_all(client, nm)
        if not methods:
            return

        # 回复无认证
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

        # 回复成功
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        use_proxy, node_name = decide_route(host, port)
        log_conn("TCP", client_ip, host, port, use_proxy, node_name)

        if use_proxy and g_cfg.node_count > 0:
            ch = node_open(host, port, node_name)
        else:
            ch = chan_outbound(host, port)

        relay_tunnel(client, ch)
        ch.close()
    except Exception as e:
        core_log(f"[x] SOCKS5 error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---- HTTP 代理处理 ----
def handle_http(client: socket.socket, client_ip: str, first_byte: bytes):
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

            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            use_proxy, node_name = decide_route(host, port)
            log_conn("TCP", client_ip, host, port, use_proxy, node_name)

            if use_proxy and g_cfg.node_count > 0:
                ch = node_open(host, port, node_name)
            else:
                ch = chan_outbound(host, port)

            relay_tunnel(client, ch)
            ch.close()
        else:
            # 普通 HTTP
            host, port, path = parse_http_target(target, head)

            if not host:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return

            use_proxy, node_name = decide_route(host, port)
            log_conn(method, client_ip, host, port, use_proxy, node_name)

            if use_proxy and g_cfg.node_count > 0:
                ch = node_open(host, port, node_name)
            else:
                ch = chan_outbound(host, port)

            # 重写请求行
            body_start = buf[header_end:]
            if method == "GET":
                # 对于 GET 请求，重写为 origin-form
                new_line = f"{method} {path} HTTP/1.1\r\n".encode()
                rest = head.split("\r\n", 1)[1] if "\r\n" in head else ""
                new_head = new_line + rest.encode("utf-8", errors="replace")
                ch.send(new_head + body_start)
            else:
                # 其他方法，转发原始请求
                ch.send(buf[:header_end] + body_start)

            relay_tunnel(client, ch)
            ch.close()
    except Exception as e:
        core_log(f"[x] HTTP error: {e}")
    finally:
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


def log_conn(proto: str, client_ip: str, host: str, port: int, use_proxy: bool, node_name: str = None):
    """记录连接日志"""
    if use_proxy and node_name:
        core_log(f"[{proto}] {client_ip} --> {host}:{port} match proxy using {node_name}")
    else:
        core_log(f"[{proto}] {client_ip} --> {host}:{port} match DIRECT using DIRECT")


# ---- 客户端线程 ----
def handle_client(client: socket.socket, client_ip: str):
    """处理客户端连接"""
    try:
        client.settimeout(HANDSHAKE_TIMEOUT)
        first = _recv_all(client, 1)
        if not first:
            return

        if first[0] == 0x05:
            handle_socks5(client, client_ip)
        else:
            handle_http(client, client_ip, first)
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

        # 读取并丢弃请求体
        try:
            header_end = buf.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = buf.find(b"\n\n")
            if header_end >= 0:
                content_length = 0
                for line in req.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            pass
                remaining = content_length - (len(buf) - header_end - 4)
                while remaining > 0:
                    chunk = client.recv(min(remaining, 4096))
                    if not chunk:
                        break
                    remaining -= len(chunk)
        except Exception:
            pass

        if method == "GET" and path == "/version":
            ctrl_handle_version(client)
        elif method == "GET" and path.startswith("/logs"):
            ctrl_handle_logs(client)
        elif method == "GET" and path.startswith("/traffic"):
            ctrl_handle_traffic(client)
        elif method == "GET" and path == "/proxies":
            ctrl_handle_proxies(client)
        elif method == "PUT" and path.startswith("/configs"):
            ctrl_send(client, "204 No Content", "application/json", "")
        elif method == "PUT" and path.startswith("/proxies/"):
            # 解析 body 中的 {"name": "..."}
            body = req.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in req else ""
            try:
                data = json.loads(body)
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
    global g_running
    CORE_STOP_EVENT.clear()
    g_running = True

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
                threading.Thread(target=handle_client, args=(client, client_ip), daemon=True).start()
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