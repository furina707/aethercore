# SPDX-License-Identifier: MIT
# AetherCore - TUN 模式 Fake-IP DNS 引擎
#
# 劫持进入 TUN 的所有 UDP/53 查询:
#   - A   -> 198.18.0.0/15  Fake-IPv4
#   - AAAA-> fdfe:dcba:9876::/48 Fake-IPv6
#   - HTTPS(65) -> 空应答 (避免浏览器等待 ECH 记录)
#   - PTR -> 反查映射表，查不到则转发上游
#   - 其它类型 -> 转发上游 (源绑定物理网卡 IP，防回环)
#
# 域名 -> Fake-IP 的双向映射供 tun_tcp.py 在发起 SOCKS5 CONNECT 时
# 还原域名，使内核的 proxy-domain/direct-domain 分流规则在 TUN 模式下继续生效。

import os
import socket
import struct
import threading
import time
import random
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aether_tun import FAKE_V4_NET, FAKE_V6_NET, is_fake_v4

DEFAULT_UPSTREAMS = ["223.5.5.5", "119.29.29.29", "8.8.8.8"]
DNS_PORT = 53
QTYPES = {"A": 1, "PTR": 12, "AAAA": 28, "HTTPS": 65}

# 最低分配地址，避开网段头几个保留地址 (如 198.18.0.1 是 TUN 网关)
V4_ALLOC_BASE = int(ipaddress.IPv4Address("198.18.0.10"))
V4_ALLOC_END = int(ipaddress.IPv4Address("198.19.255.254"))
V6_ALLOC_BASE = int(ipaddress.IPv6Address("fdfe:dcba:9876::10"))
V6_ALLOC_END = int(ipaddress.IPv6Address("fdfe:dcba:9876:0:ffff:ffff:ffff:fffe"))


class FakeIPPool:
    """Fake-IP 分配器: 域名 -> 固定 Fake-IP (LRU 复用)"""

    def __init__(self, cap=65536):
        self._lock = threading.Lock()
        self._cap = cap
        self._domain2v4 = {}
        self._domain2v6 = {}
        self._v4_2domain = {}
        self._v6_2domain = {}
        self._v4_next = V4_ALLOC_BASE
        self._v6_next = V6_ALLOC_BASE

    def _alloc_v4(self):
        # 线性递增，耗尽后从最低处回收
        while self._v4_next <= V4_ALLOC_END:
            ip = str(ipaddress.IPv4Address(self._v4_next))
            self._v4_next += 1
            if ip not in self._v4_2domain:
                return ip
        # 池满: 淘汰最早分配的一半
        victims = list(self._v4_2domain.items())[:self._cap // 4]
        for ip, dom in victims:
            del self._v4_2domain[ip]
            self._domain2v4.pop(dom, None)
        self._v4_next = V4_ALLOC_BASE
        return self._alloc_v4()

    def _alloc_v6(self):
        while self._v6_next <= V6_ALLOC_END:
            ip = str(ipaddress.IPv6Address(self._v6_next))
            self._v6_next += 1
            if ip not in self._v6_2domain:
                return ip
        victims = list(self._v6_2domain.items())[:self._cap // 4]
        for ip, dom in victims:
            del self._v6_2domain[ip]
            self._domain2v6.pop(dom, None)
        self._v6_next = V6_ALLOC_BASE
        return self._alloc_v6()

    def get_v4(self, domain):
        with self._lock:
            ip = self._domain2v4.get(domain)
            if not ip:
                ip = self._alloc_v4()
                self._domain2v4[domain] = ip
                self._v4_2domain[ip] = domain
            return ip

    def get_v6(self, domain):
        with self._lock:
            ip = self._domain2v6.get(domain)
            if not ip:
                ip = self._alloc_v6()
                self._domain2v6[domain] = ip
                self._v6_2domain[ip] = domain
            return ip

    def reverse_v4(self, ip):
        with self._lock:
            return self._v4_2domain.get(ip)

    def reverse_v6(self, ip):
        with self._lock:
            return self._v6_2domain.get(ip)

    def reverse(self, ip):
        return self.reverse_v4(ip) or self.reverse_v6(ip)

    def lookup_domain(self, domain):
        with self._lock:
            return self._domain2v4.get(domain), self._domain2v6.get(domain)


def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _decode_qname(msg: bytes, off: int):
    """解析 (可含压缩指针的) 域名，返回 (name, next_off)；失败返回 ("", len)"""
    labels = []
    jumped = False
    end = off
    seen = 0
    while True:
        if off >= len(msg) or seen > 32:
            return "", len(msg)
        ln = msg[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                return "", len(msg)
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            seen += 1
            continue
        labels.append(msg[off + 1:off + 1 + ln].decode("ascii", errors="replace"))
        off += 1 + ln
        seen += 1
    return ".".join(labels), end


def _parse_query(msg: bytes):
    """解析 DNS 查询，返回 (txid, qname, qtype) 或 None"""
    if len(msg) < 12:
        return None
    txid, flags, qdcount = struct.unpack(">HHH", msg[:6])
    if flags & 0x8000 or qdcount < 1:  # 0x8000 = Response 位，查询报文必须为 0
        return None
    name, off = _decode_qname(msg, 12)
    if not name or off + 4 > len(msg):
        return None
    qtype, _qclass = struct.unpack(">HH", msg[off:off + 4])
    return txid, name, qtype


def _build_response(txid: int, qname: str, qtype: int, answers: list) -> bytes:
    """构造应答; answers = [(qtype, ttl, rdata_bytes)]"""
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, len(answers), 0, 0)
    body = _encode_qname(qname) + struct.pack(">HH", qtype, 1)
    for atype, ttl, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", atype, 1, ttl, len(rdata)) + rdata
    return header + body


class FakeIPDNS:
    """Fake-IP DNS 处理器"""

    def __init__(self, bind_ip=None, bind_ip6=None, upstreams=None, log=None):
        self.pool = FakeIPPool()
        self.bind_ip = bind_ip      # 物理网卡 IPv4 (转发上游查询时绑定)
        self.bind_ip6 = bind_ip6
        self.upstreams = upstreams or list(DEFAULT_UPSTREAMS)
        self._log = log or (lambda msg: None)

    # ---- 主入口 ----
    def handle_query(self, payload: bytes):
        """处理进入 TUN 的 DNS 查询报文，返回应答 bytes (无需再包 IP 头) 或 None"""
        parsed = _parse_query(payload)
        if not parsed:
            return None
        txid, qname, qtype = parsed
        lname = qname.lower().rstrip(".")

        if qtype == QTYPES["A"]:
            return _build_response(txid, qname, qtype,
                                   [(1, 60, socket.inet_aton(self.pool.get_v4(lname)))])
        if qtype == QTYPES["AAAA"]:
            if not self.bind_ip6:
                # 物理网络无 IPv6 出口，直接返回空应答 (NOERROR, 0 answers)
                # 促使客户端/浏览器/Antigravity 立即使用 IPv4 Fake-IP，彻底避免 IPv6 直连超时
                return _build_response(txid, qname, qtype, [])
            fake6 = self.pool.get_v6(lname)
            return _build_response(txid, qname, qtype,
                                   [(28, 60, socket.inet_pton(socket.AF_INET6, fake6))])
        if qtype == QTYPES["HTTPS"]:
            # 空应答: NOERROR + 0 answers，浏览器会回退到 A/AAAA
            return _build_response(txid, qname, qtype, [])
        if qtype == QTYPES["PTR"]:
            dom = self._reverse_ptr(lname)
            if dom:
                return _build_response(txid, qname, qtype,
                                       [(12, 60, _encode_qname(dom))])
            return self._forward(payload)
        return self._forward(payload)

    def _reverse_ptr(self, lname: str):
        parts = lname.split(".")
        if parts[-1:] == ["arpa"]:
            # v4 PTR: 4 段逆序 IP + "in-addr" + "arpa" = 6 个 label
            if parts[-2:-1] == ["in-addr"] and len(parts) == 6:
                ip = ".".join(reversed(parts[:4]))
                return self.pool.reverse_v4(ip)
            if parts[-2:-1] == ["ip6"] and len(parts) == 34:
                hexdigits = "".join(reversed(parts[1:33]))
                try:
                    packed = bytes.fromhex(hexdigits)
                    ip = str(ipaddress.IPv6Address(packed))
                    return self.pool.reverse_v6(ip)
                except Exception:
                    return None
        return None

    # ---- 上游转发 ----
    def _forward(self, payload: bytes, timeout=3.0):
        for upstream in self.upstreams:
            try:
                fam = socket.AF_INET6 if ":" in upstream else socket.AF_INET
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                bind = self.bind_ip6 if fam == socket.AF_INET6 else self.bind_ip
                if bind:
                    try:
                        s.bind((bind, 0))
                    except OSError:
                        pass
                s.sendto(payload, (upstream, DNS_PORT))
                data, _ = s.recvfrom(4096)
                s.close()
                return data
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
                continue
        self._log("[tun-dns] 上游转发失败")
        return None
