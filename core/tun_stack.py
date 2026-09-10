# SPDX-License-Identifier: MIT
# AetherCore - TUN 数据面分发器 + UDP NAT + 引擎生命周期
#
# 读包循环: Wintun -> IPv4/IPv6 解析 -> 分发
#   TCP        -> tun_tcp.TcpStack (用户态 TCP 栈 -> SOCKS5 桥接)
#   UDP :53    -> tun_dns.FakeIPDNS (Fake-IP 应答)
#   UDP 其它   -> UDP NAT 中继 (socket 绑定物理网卡 IP，直连出口)
#   ICMP Echo  -> 本栈回显 (其余丢弃)
#
# 已知限制: IP 分片 / 转发的 ICMP 错误 / 转发其它 ICMPv6 (NDP) 不处理

import os
import sys
import socket
import struct
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aether_tun import (
    WintunDevice, detect_physical_network, is_fake_v4, is_fake_v6, is_fake_ip,
    TUN_V6_IP,
)
from tun_dns import FakeIPDNS
from tun_tcp import TcpStack

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58
IPPROTO_FRAG = 44

# IPv6 可跳过的扩展头: Hop-by-Hop / Routing / Destination Options / AH
_V6_EXT_SKIP = {0, 43, 60, 51}


def _cksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _pseudo_cksum(src, dst, proto, seg: bytes) -> int:
    if ":" in src:
        pseudo = (socket.inet_pton(socket.AF_INET6, src) +
                  socket.inet_pton(socket.AF_INET6, dst) +
                  struct.pack(">I", len(seg)) + b"\x00\x00\x00" + bytes([proto]))
    else:
        pseudo = (socket.inet_aton(src) + socket.inet_aton(dst) +
                  b"\x00" + bytes([proto]) + struct.pack(">H", len(seg)))
    return _cksum(pseudo + seg)


def build_ip4_packet(src, dst, proto, payload, ident=1):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64,
                      proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ck = _cksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    return hdr + payload


def build_ip6_packet(src, dst, next_header, payload):
    hdr = struct.pack(">IHBB16s16s", 0x60000000, len(payload), next_header, 64,
                      socket.inet_pton(socket.AF_INET6, src),
                      socket.inet_pton(socket.AF_INET6, dst))
    return hdr + payload


def build_udp_segment(src, dst, sport, dport, payload):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ck = _pseudo_cksum(src, dst, 17, seg)
    if ck == 0:
        ck = 0xFFFF
    return seg[:6] + struct.pack(">H", ck) + seg[8:]


def parse_ip_packet(pkt: bytes):
    """解析 IPv4/IPv6 头，返回 dict 或 None。
    v6 会跳过扩展头；分片包返回 None (不支持)。
    """
    if not pkt:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        total = (pkt[2] << 8) | pkt[3]
        flags_frag = struct.unpack(">H", pkt[6:8])[0]
        if flags_frag & 0x1FFF:      # 非首片
            return None
        if flags_frag & 0x2000:      # MF: 后续分片，不重组
            return None
        proto = pkt[9]
        src = socket.inet_ntoa(pkt[12:16])
        dst = socket.inet_ntoa(pkt[16:20])
        end = min(total, len(pkt))
        return {"family": 4, "proto": proto, "src": src, "dst": dst,
                "payload": pkt[ihl:end]}
    if ver == 6:
        if len(pkt) < 40:
            return None
        payload_len = struct.unpack(">H", pkt[4:6])[0]
        nh = pkt[6]
        src = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        off = 40
        end = min(40 + payload_len, len(pkt))
        for _ in range(5):
            if nh == IPPROTO_FRAG:
                return None
            if nh in _V6_EXT_SKIP:
                if off + 2 > end:
                    return None
                ext_len = (pkt[off + 1] + 1) * 8
                if nh == 51:  # AH: len 以 4 字节为单位
                    ext_len = (pkt[off + 1] + 2) * 4
                nh = pkt[off]
                off += ext_len
                continue
            break
        if nh not in (6, 17, 58):
            return None
        return {"family": 6, "proto": nh, "src": src, "dst": dst,
                "payload": pkt[off:end]}
    return None


def build_icmp_echo_reply(family, src, dst, payload):
    """构造 ICMP/ICMPv6 Echo 应答"""
    if family == 4:
        if len(payload) < 8 or payload[0] != 8:   # 仅回显 Echo Request
            return None
        rep = b"\x00\x00\x00\x00" + payload[4:]
        ck = _cksum(rep)
        rep = rep[:2] + struct.pack(">H", ck) + rep[4:]
        return build_ip4_packet(dst, src, 1, rep)
    else:
        if len(payload) < 8 or payload[0] != 128:
            return None
        rep = b"\x81\x00\x00\x00" + payload[4:]
        ck = _pseudo_cksum(dst, src, 58, rep)
        rep = rep[:2] + struct.pack(">H", ck) + rep[4:]
        return build_ip6_packet(dst, src, 58, rep)


class UdpNat:
    """UDP NAT 中继: 客户端流 <-> 绑定物理网卡的上游 socket"""

    FLOW_TTL = 60.0
    MAX_FLOWS = 4096

    def __init__(self, device, phys, log=None):
        self.device = device
        self.phys = phys
        self.log = log or (lambda m: None)
        self.flows = {}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True)

    def start(self):
        self._sweeper.start()

    def stop(self):
        self._stop.set()
        with self.lock:
            flows = list(self.flows.values())
        for f in flows:
            try:
                f["sock"].close()
            except Exception:
                pass

    def handle(self, family, src, dst, sport, dport, payload):
        key = (family, src, sport, dst, dport)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                if len(self.flows) >= self.MAX_FLOWS:
                    return
                flow = self._create_flow(family, src, dst, sport, dport)
                if flow is None:
                    return
                self.flows[key] = flow
            flow["last"] = time.time()
        try:
            flow["sock"].sendto(payload, (dst, dport))
        except Exception as e:
            self.log(f"[tun-udp] 发送失败 {dst}:{dport}: {e}")

    def _create_flow(self, family, src, dst, sport, dport):
        try:
            if family == 4:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                bind = self.phys.get("v4_ip")
            else:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                bind = self.phys.get("v6_ip")
            if bind:
                try:
                    s.bind((bind, 0))
                except OSError:
                    pass
            s.settimeout(5.0)
        except Exception as e:
            self.log(f"[tun-udp] 创建上游 socket 失败: {e}")
            return None
        flow = {"sock": s, "last": time.time()}
        threading.Thread(target=self._relay, args=(flow, family, src, dst, sport, dport),
                         daemon=True).start()
        return flow

    def _relay(self, flow, family, src, dst, sport, dport):
        s = flow["sock"]
        ident = 1
        while not self._stop.is_set():
            try:
                data, _addr = s.recvfrom(65535)
            except socket.timeout:
                with self.lock:
                    if time.time() - flow["last"] > self.FLOW_TTL:
                        break
                continue
            except OSError:
                break
            seg = build_udp_segment(dst, src, dport, sport, data)
            if family == 4:
                pkt = build_ip4_packet(dst, src, 17, seg, ident)
                ident = (ident + 1) & 0xFFFF
            else:
                pkt = build_ip6_packet(dst, src, 17, seg)
            self.device.write_packet(pkt)
        try:
            s.close()
        except Exception:
            pass
        with self.lock:
            key = (family, src, sport, dst, dport)
            if self.flows.get(key) is flow:
                del self.flows[key]

    def _sweep_loop(self):
        while not self._stop.wait(15.0):
            now = time.time()
            with self.lock:
                stale = [f for f in self.flows.values() if now - f["last"] > self.FLOW_TTL]
            for f in stale:
                try:
                    f["sock"].close()
                except Exception:
                    pass


class TunEngine:
    """TUN 模式总引擎: 网卡生命周期 + 路由接管 + 数据面分发"""

    def __init__(self, socks_addr=("127.0.0.1", 7899), conf_path=None,
                 node_servers=None, log=None):
        self.socks_addr = socks_addr
        self.conf_path = conf_path
        self.log = log or (lambda m: print(m, flush=True))
        self.device = WintunDevice()
        self.phys = {"v4_ip": None, "v6_ip": None, "gw_v4": None, "if_index_v4": 0}
        self.dns = None
        self.tcp = None
        self.udp = None
        self._reader = None
        self._stop = threading.Event()

    def start(self):
        """启动引擎 (需管理员权限)。物理探测必须在安装接管路由之前完成。"""
        self.phys = detect_physical_network()
        self.log(f"[tun] 物理出口: v4={self.phys['v4_ip']} v6={self.phys['v6_ip']} "
                 f"gw={self.phys['gw_v4']}")
        if not self.phys["v4_ip"]:
            raise RuntimeError("未探测到物理网卡 IPv4，无法防回环")

        # 供内核 dial_host 绑定物理出口 (强主机模型保证不回流 TUN)
        os.environ["AETHER_BIND_IP"] = self.phys["v4_ip"]
        if self.phys["v6_ip"]:
            os.environ["AETHER_BIND_IP6"] = self.phys["v6_ip"]
        os.environ["AETHER_TUN"] = "1"

        self.device.physical = self.phys
        self.device.open()
        has_v6 = bool(self.phys.get("v6_ip"))
        self.device.configure_network(ipv6_str=TUN_V6_IP if has_v6 else None)

        # 节点服务器 /32 主机路由 (双保险: 即使绑定失效也直走物理网关)
        for server in self._node_servers():
            if ":" not in server:
                try:
                    self.device.install_bypass_route_v4(server)
                except Exception:
                    pass

        if not self.device.install_capture_routes(with_v4=True, with_v6=has_v6):
            raise RuntimeError("接管路由安装失败")
        if has_v6:
            self.log("[tun] 已接管 v4 (0.0.0.0/1+128.0.0.0/1) 与 v6 (::/1+8000::/1) 默认路由")
        else:
            self.log("[tun] 已接管 v4 (0.0.0.0/1+128.0.0.0/1) 默认路由 (物理出口无 IPv6，已跳过 v6 接管)")

        self.dns = FakeIPDNS(bind_ip=self.phys["v4_ip"], bind_ip6=self.phys.get("v6_ip"),
                             log=self.log)
        self.tcp = TcpStack(self.device, self.dns, self.socks_addr, log=self.log)
        self.tcp.start()
        self.udp = UdpNat(self.device, self.phys, log=self.log)
        self.udp.start()

        self._stop.clear()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.log("[tun] TUN 引擎已启动，开始接管全局流量")

    def stop(self):
        self._stop.set()
        if self.tcp:
            self.tcp.stop()
        if self.udp:
            self.udp.stop()
        for k in ("AETHER_BIND_IP", "AETHER_BIND_IP6", "AETHER_TUN"):
            os.environ.pop(k, None)
        try:
            self.device.close()   # 含路由清理
        except Exception:
            pass
        self.log("[tun] TUN 引擎已停止，路由已还原")

    def _node_servers(self):
        """从 core.conf 提取节点服务器地址 (防回环 /32 路由用)"""
        servers = set()
        if self.conf_path and os.path.exists(self.conf_path):
            try:
                with open(self.conf_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split("\t")
                        if parts and parts[0] == "node" and len(parts) >= 5:
                            servers.add(parts[3].strip())
            except Exception:
                pass
        return servers

    def _read_loop(self):
        while not self._stop.is_set():
            try:
                pkt, _size = self.device.read_packet(timeout_ms=300)
            except Exception as e:
                if not self._stop.is_set():
                    self.log(f"[tun] 读包异常: {e}")
                    time.sleep(0.5)
                continue
            if not pkt:
                continue
            try:
                self._dispatch(pkt)
            except Exception as e:
                self.log(f"[tun] 分发异常: {e}")

    def _dispatch(self, pkt):
        ip = parse_ip_packet(pkt)
        if not ip:
            return
        family, proto = ip["family"], ip["proto"]
        src, dst = ip["src"], ip["dst"]
        payload = ip["payload"]

        if proto == IPPROTO_TCP:
            self.tcp.handle_packet(family, src, dst, payload)
        elif proto == IPPROTO_UDP:
            self._handle_udp(family, src, dst, payload)
        elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            reply = build_icmp_echo_reply(family, src, dst, payload)
            if reply:
                self.device.write_packet(reply)
        # 其余协议丢弃

    def _handle_udp(self, family, src, dst, payload):
        if len(payload) < 8:
            return
        sport, dport, ulen = struct.unpack(">HHH", payload[:6])
        data = payload[8:ulen] if ulen >= 8 else payload[8:]
        if dport == 53:
            resp = self.dns.handle_query(data)
            if resp:
                seg = build_udp_segment(dst, src, dport, sport, resp)
                if family == 4:
                    pkt = build_ip4_packet(dst, src, 17, seg)
                else:
                    pkt = build_ip6_packet(dst, src, 17, seg)
                self.device.write_packet(pkt)
                return
        if is_fake_ip(dst):
            # 浏览器通过 Fake-IP 解析后尝试 QUIC (UDP 443)，直接丢弃促使浏览器立即回退到 TCP HTTPS
            return
        self.udp.handle(family, src, dst, sport, dport, data)
