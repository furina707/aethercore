# SPDX-License-Identifier: MIT
# AetherCore - TUN 模式用户态 TCP 栈
#
# 终止经 TUN 进入的 TCP 会话 (三次握手 / 序号与窗口管理 / 重传 / FIN-RST 状态机)，
# 把每条流桥接到内核的 SOCKS5 入站 (127.0.0.1:7899)。
# Fake-IP 目标会被还原为域名 (ATYP=domain)，使内核域名分流规则继续生效。
#
# 简化点 (相对完整 RFC):
#   - 不做 SACK / 窗口缩放协商 (SYN-ACK 只通告 MSS) / 时间戳选项
#   - 重传为固定 RTO 指数退避，无拥塞控制 (RTT 为本机回环级)
#   - 乱序数据小缓冲 (32KB)，超出则丢弃等待对端重传
#   - 半关闭: 客户端 FIN 后继续读上游直到 EOF，再发自身 FIN (与内核 relay 语义对齐)

import os
import sys
import socket
import struct
import threading
import time
import random
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aether_tun import is_fake_ip

# TCP 标志位
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

MSS_V4 = 1460   # 1500 - 20(IP) - 20(TCP)
MSS_V6 = 1440   # 1500 - 40(IP) - 20(TCP)
RCV_BUF_CAP = 256 * 1024       # 本栈接收缓冲上限 (通告窗口依据)
INFLIGHT_CAP = 512 * 1024      # 在途数据上限 (对端窗口之外的本栈发送上限)
MAX_RETRIES = 8
IDLE_TIMEOUT = 300.0


# ---- 校验和与 IP 包构造 ----
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


def build_ip4_packet(src, dst, proto, payload, ident=0):
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


# RFC 793 32 位序号模运算比较
def seq_lt(a: int, b: int) -> bool:
    """a < b"""
    return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF

def seq_lte(a: int, b: int) -> bool:
    """a <= b"""
    return ((a - b) & 0xFFFFFFFF) >= 0x7FFFFFFF or a == b

def seq_gt(a: int, b: int) -> bool:
    """a > b"""
    return ((b - a) & 0xFFFFFFFF) > 0x7FFFFFFF

def seq_gte(a: int, b: int) -> bool:
    """a >= b"""
    return ((b - a) & 0xFFFFFFFF) >= 0x7FFFFFFF or a == b

def seq_diff(a: int, b: int) -> int:
    """a - b (有符号模差)"""
    d = (a - b) & 0xFFFFFFFF
    return d if d < 0x80000000 else d - 0x100000000


def build_tcp_segment(src, dst, sport, dport, seq, ackn, flags, window,
                      payload=b"", mss=None):
    """构造完整 TCP 段 (含伪头校验和，IP 头由调用方决定)"""
    opts = b""
    if mss:
        opts = struct.pack(">BBH", 2, 4, mss)
    doff = (20 + len(opts)) // 4
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ackn & 0xFFFFFFFF,
                      doff << 4, flags, window & 0xFFFF, 0, 0)
    seg = hdr + opts + payload
    ck = _pseudo_cksum(src, dst, 6, seg)
    seg = seg[:16] + struct.pack(">H", ck) + seg[18:]
    return seg


def parse_tcp_segment(data: bytes):
    """解析 TCP 段，返回 dict 或 None"""
    if len(data) < 20:
        return None
    sport, dport, seq, ackn, off_flags, window = struct.unpack(">HHIIHH", data[:16])
    doff = (off_flags >> 12) * 4
    if doff < 20 or doff > len(data):
        return None
    flags = off_flags & 0x01FF
    opts = data[20:doff]
    payload = data[doff:]
    mss = None
    i = 0
    while i + 1 < len(opts):  # 解析 SYN 中的 MSS 选项
        kind = opts[i]
        if kind == 0:
            break
        ln = opts[i + 1] if i + 1 < len(opts) else 0
        if ln < 2:
            break
        if kind == 2 and ln == 4:
            mss = struct.unpack(">H", opts[i + 2:i + 4])[0]
        i += ln
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ackn,
        "flags": flags, "window": window, "mss": mss, "payload": payload,
    }


# ---- SOCKS5 客户端 ----
def socks5_connect(socks_addr, dest, port, timeout=10.0, client_port: int = 0):
    """连接内核 SOCKS5 入站。dest 可为域名或 IP (域名 ATYP=domain 保留分流语义)。

    本地代理端口在未监听/已绑定但未 accept 的情况下，可能不会立即返回 ECONNREFUSED，
    因而会长时间卡在 connect timeout；这里收紧本地连接超时 (0.5s)，
    让 TUN TCP 状态机在本地内核未就绪时可以尽快发出 RST。
    本地 TCP 建立成功后，SOCKS5 握手及远端拨号阶段使用完整 timeout (默认 10.0s)。
    """
    local_timeout = min(timeout, 0.5)
    s = socket.create_connection(socks_addr, timeout=local_timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout)

    # 登记 TUN 模式原客户端的真实进程名，使内核分应用规则和日志能准确关联
    if client_port:
        try:
            import aether_core
            real_proc = aether_core.get_process_for_port(client_port)
            if real_proc and real_proc != "App":
                aether_core.register_tun_client_port(s.getsockname()[1], real_proc)
        except Exception:
            pass

    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 0x05 or r[1] != 0x00:
        s.close()
        raise ConnectionError("SOCKS5 握手失败")
    try:
        addr = socket.inet_aton(dest)
        if dest.count(".") == 3:
            atyp = 0x01
        else:
            raise OSError
    except OSError:
        try:
            addr = socket.inet_pton(socket.AF_INET6, dest)
            atyp = 0x04
        except OSError:
            atyp = 0x03
            addr = dest.encode("idna") if not dest.isascii() else dest.encode()
    req = b"\x05\x01\x00" + bytes([atyp]) + (
        bytes([len(addr)]) if atyp == 0x03 else b"") + addr + struct.pack(">H", port)
    s.sendall(req)
    r = s.recv(4)
    if len(r) < 4 or r[1] != 0x00:
        s.close()
        raise ConnectionError(f"SOCKS5 CONNECT 失败: code={r[1] if len(r) > 1 else '?'}")
    if r[3] == 0x01:
        s.recv(6)
    elif r[3] == 0x04:
        s.recv(18)
    elif r[3] == 0x03:
        dl = s.recv(1)
        if dl:
            s.recv(dl[0] + 2)
    s.settimeout(None)
    return s


class TCB:
    """一条 TCP 连接的控制块"""

    def __init__(self, stack, family, src, dst, sport, dport):
        self.stack = stack
        self.family = family          # 4 / 6
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.state = "SYN_RCVD"
        self.lock = threading.RLock()

        # 接收侧 (client -> tun -> socks)
        self.rcv_irs = 0
        self.rcv_nxt = 0
        self.rcv_q = collections.deque()
        self.rcv_cond = threading.Condition(self.lock)
        self.ooo = {}                 # seq -> bytes
        self.ooo_bytes = 0
        self.client_fin = False
        self.client_fin_seq = None

        # 发送侧 (socks -> tun -> client)
        self.snd_iss = random.getrandbits(32)
        self.snd_nxt = (self.snd_iss + 1) & 0xFFFFFFFF
        self.snd_una = self.snd_iss
        self.snd_q = collections.deque()
        self.unacked = []             # [seq, data, send_time, retries, is_fin]
        self.client_win = 0
        self.client_mss = MSS_V4 if family == 4 else MSS_V6
        self.fin_sent = False
        self.server_eof = False

        # 桥接
        self.socks = None
        self.dead = False
        self.last_activity = time.time()
        self.bridge_started = False

    # ---- 包处理 (由 TcpStack 在读线程中调用) ----
    def on_segment(self, seg):
        flags = seg["flags"]
        with self.lock:
            if self.dead:
                return
            self.last_activity = time.time()

            if flags & RST:
                self._teardown_locked()
                return

            if flags & ACK:
                self._process_ack_locked(seg["ack"])
                self.client_win = seg["window"]
                if self.client_win > 0:
                    self._zwp_retries = 0
                if self.state == "SYN_RCVD":
                    self.state = "ESTABLISHED"
                    self._start_bridge_locked()

            if seg["payload"]:
                self._accept_data_locked(seg["seq"], seg["payload"])

            if flags & FIN:
                # FIN 的序号位置 = 段起始 seq + 数据长度 (FIN 常与末段数据同包)
                self._note_fin_locked((seg["seq"] + len(seg["payload"])) & 0xFFFFFFFF)

        self._try_send()

    def _accept_data_locked(self, seq, payload):
        if seq == self.rcv_nxt:
            self.rcv_q.append(payload)
            self.rcv_nxt = (self.rcv_nxt + len(payload)) & 0xFFFFFFFF
            # 收割乱序缓存
            while self.rcv_nxt in self.ooo:
                data = self.ooo.pop(self.rcv_nxt)
                self.ooo_bytes -= len(data)
                self.rcv_q.append(data)
                self.rcv_nxt = (self.rcv_nxt + len(data)) & 0xFFFFFFFF
            with self.rcv_cond:
                self.rcv_cond.notify_all()
            self._send_ack_locked()
        elif seq_gt(seq, self.rcv_nxt) and self.ooo_bytes < 32768:
            self.ooo[seq] = payload
            self.ooo_bytes += len(payload)
            self._send_ack_locked()   # dup-ack
        else:
            self._send_ack_locked()   # 旧段重复确认

    def _note_fin_locked(self, seq):
        if self.client_fin_seq is None:
            self.client_fin_seq = seq
        self._check_fin_locked()

    def _check_fin_locked(self):
        if (not self.client_fin and self.client_fin_seq is not None
                and seq_lte(self.client_fin_seq, self.rcv_nxt)):
            self.client_fin = True
            self.rcv_nxt = (self.client_fin_seq + 1) & 0xFFFFFFFF   # FIN 占一个序号
            if self.state == "ESTABLISHED":
                self.state = "CLOSE_WAIT"
            elif self.state == "FIN_WAIT2":
                self.state = "TIME_WAIT"
                self._teardown_locked()
                return
            self._send_ack_locked()
            with self.rcv_cond:
                self.rcv_cond.notify_all()

    def _process_ack_locked(self, ackn):
        if seq_lte(ackn, self.snd_una) or seq_gt(ackn, self.snd_nxt):
            return
        self.snd_una = ackn
        while self.unacked:
            e = self.unacked[0]
            end = (e[0] + len(e[1]) + (1 if e[4] else 0)) & 0xFFFFFFFF
            if seq_lte(end, ackn):
                self.unacked.pop(0)
            else:
                break
        # 我方 FIN 已被确认
        if self.fin_sent and self.snd_una == self.snd_nxt:
            if self.client_fin:
                self.state = "CLOSED"
                self._teardown_locked()
            elif self.state != "CLOSED":
                self.state = "FIN_WAIT2"

    # ---- 发送 ----
    def _try_send(self):
        """把 snd_q 中窗口允许的数据切分为 MSS 段发出；上游 EOF 且排空后发 FIN"""
        with self.lock:
            if self.dead or self.state == "SYN_RCVD":
                return
            win = min(self.client_win, INFLIGHT_CAP)
            while self.snd_q:
                inflight = seq_diff(self.snd_nxt, self.snd_una)
                if inflight >= win:
                    break           # 零/满窗口: 靠重传定时器充当窗口探测
                mss = min(self.client_mss, MSS_V4 if self.family == 4 else MSS_V6)
                data = self.snd_q.popleft()
                while data and inflight < win:
                    chunk = data[:mss]
                    data = data[mss:]
                    self._emit_locked(chunk, False)
                    inflight += len(chunk)
                if data:
                    self.snd_q.appendleft(data)
                    break
            # 对端已 EOF 且数据发完 -> 发 FIN
            if self.server_eof and not self.snd_q and not self.fin_sent:
                self._emit_locked(b"", True)
                self.fin_sent = True
            self.last_activity = time.time()

    def _emit_locked(self, data, is_fin):
        flags = ACK | (FIN if is_fin else (PSH if data else 0))
        seq = self.snd_nxt
        seg = build_tcp_segment(self.dst, self.src, self.dport, self.sport,
                                seq, self.rcv_nxt, flags, self._adv_window_locked(), data)
        self.stack.send_tcp(self.family, self.dst, self.src, seg)
        self.unacked.append([seq, data, time.time(), 0, is_fin])
        self.snd_nxt = (self.snd_nxt + len(data) + (1 if is_fin else 0)) & 0xFFFFFFFF

    def _adv_window_locked(self):
        used = sum(len(d) for d in self.rcv_q) + self.ooo_bytes
        return max(1, min(RCV_BUF_CAP - used, 0xFFFF))

    def _send_ack_locked(self):
        seg = build_tcp_segment(self.dst, self.src, self.dport, self.sport,
                                self.snd_nxt, self.rcv_nxt, ACK,
                                self._adv_window_locked())
        self.stack.send_tcp(self.family, self.dst, self.src, seg)

    def _send_rst_locked(self):
        seg = build_tcp_segment(self.dst, self.src, self.dport, self.sport,
                                self.snd_nxt, self.rcv_nxt, RST | ACK, 0)
        self.stack.send_tcp(self.family, self.dst, self.src, seg)

    def send_synack(self, syn_seg):
        with self.lock:
            self.rcv_irs = syn_seg["seq"]
            self.rcv_nxt = (syn_seg["seq"] + 1) & 0xFFFFFFFF
            self.client_win = syn_seg["window"]
            if syn_seg["mss"]:
                self.client_mss = min(syn_seg["mss"], self.client_mss)
            mss = MSS_V4 if self.family == 4 else MSS_V6
            seg = build_tcp_segment(self.dst, self.src, self.dport, self.sport,
                                    self.snd_iss, self.rcv_nxt, SYN | ACK,
                                    self._adv_window_locked(), mss=mss)
            self.stack.send_tcp(self.family, self.dst, self.src, seg)

    # ---- 桥接 ----
    def _start_bridge_locked(self):
        if self.bridge_started or self.dead:
            return
        self.bridge_started = True
        domain = self.stack.dns.pool.reverse(self.dst) if is_fake_ip(self.dst) else None
        dest = domain or self.dst
        threading.Thread(target=self._bridge_connect, args=(dest,), daemon=True).start()

    def _bridge_connect(self, dest):
        try:
            s = socks5_connect(self.stack.socks_addr, dest, self.dport, client_port=self.sport)
        except Exception as e:
            self.stack.log(f"[tun-tcp] {self.src}:{self.sport} -> {dest}:{self.dport} SOCKS5 失败: {e}")
            self.rst()
            return
        with self.lock:
            if self.dead:
                s.close()
                return
            self.socks = s
        threading.Thread(target=self._pump_t2s, args=(s,), daemon=True).start()
        self._pump_s2t(s)

    def _pump_t2s(self, s):
        """TUN 接收队列 -> SOCKS5 上行"""
        while True:
            with self.lock:
                while not self.rcv_q and not self.dead and not self.client_fin:
                    self.rcv_cond.wait(1.0)
                if self.dead:
                    return
                if not self.rcv_q and self.client_fin:
                    break               # 上行方向结束 (继续保留下行)
                data = b"".join(self.rcv_q)
                self.rcv_q.clear()
            try:
                s.sendall(data)
            except Exception:
                self.rst()
                return

    def _pump_s2t(self, s):
        """SOCKS5 下行 -> TUN 发送缓冲"""
        try:
            while True:
                data = s.recv(65536)
                if not data:
                    break
                with self.lock:
                    if self.dead:
                        return
                    self.snd_q.append(data)
                self._try_send()
        except Exception:
            pass
        finally:
            with self.lock:
                self.server_eof = True
            self._try_send()          # 触发 FIN

    # ---- 关闭 ----
    def rst(self):
        with self.lock:
            if not self.dead:
                self._send_rst_locked()
            self._teardown_locked()

    def _teardown_locked(self):
        if self.dead:
            return
        self.dead = True
        self.state = "CLOSED"
        if self.socks:
            try:
                self.socks.close()
            except Exception:
                pass
            self.socks = None
        with self.rcv_cond:
            self.rcv_cond.notify_all()
        self.stack.remove_flow(self.src, self.sport, self.dst, self.dport)

    def on_timer(self, now):
        with self.lock:
            if self.dead:
                return
            if now - self.last_activity > IDLE_TIMEOUT:
                self._teardown_locked()
                return
            for entry in self.unacked:
                seq, data, sent, retries, is_fin = entry
                rto = 0.3 * (1.5 ** retries)
                if now - sent > rto:
                    if retries >= MAX_RETRIES:
                        self._teardown_locked()
                        return
                    seg = build_tcp_segment(
                        self.dst, self.src, self.dport, self.sport,
                        seq, self.rcv_nxt,
                        ACK | (FIN if is_fin else (PSH if data else 0)),
                        self._adv_window_locked(), data)
                    self.stack.send_tcp(self.family, self.dst, self.src, seg)
                    entry[2] = now
                    entry[3] = retries + 1

            # Zero-window probe (零窗口探测): 客户端窗口为 0 且有待发数据时定期探测，防止死锁
            if self.snd_q and not self.unacked and self.client_win == 0:
                if not hasattr(self, "_last_zwp"):
                    self._last_zwp = now
                    self._zwp_retries = 0
                zwp_rto = min(5.0, 0.5 * (1.5 ** self._zwp_retries))
                if now - self._last_zwp > zwp_rto:
                    if self._zwp_retries >= MAX_RETRIES:
                        self._teardown_locked()
                        return
                    # 发送 ACK 探测包诱导对端重新通告窗口
                    probe_seq = (self.snd_nxt - 1) & 0xFFFFFFFF
                    seg = build_tcp_segment(
                        self.dst, self.src, self.dport, self.sport,
                        probe_seq, self.rcv_nxt,
                        ACK, self._adv_window_locked())
                    self.stack.send_tcp(self.family, self.dst, self.src, seg)
                    self._last_zwp = now
                    self._zwp_retries += 1


class TcpStack:
    """用户态 TCP 栈: 流表 + 分发 + 定时器"""

    def __init__(self, device, dns, socks_addr, log=None):
        self.device = device
        self.dns = dns
        self.socks_addr = socks_addr
        self.log = log or (lambda m: None)
        self.flows = {}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._ip_id = random.getrandbits(16)
        self._timer = threading.Thread(target=self._timer_loop, daemon=True)

    def start(self):
        self._timer.start()

    def stop(self):
        self._stop.set()
        with self.lock:
            tcbs = list(self.flows.values())
        for t in tcbs:
            t.rst()

    def send_tcp(self, family, src_ip, dst_ip, seg):
        if family == 4:
            self._ip_id = (self._ip_id + 1) & 0xFFFF
            pkt = build_ip4_packet(src_ip, dst_ip, 6, seg, self._ip_id)
        else:
            pkt = build_ip6_packet(src_ip, dst_ip, 6, seg)
        self.device.write_packet(pkt)

    def handle_packet(self, family, src, dst, seg_bytes):
        seg = parse_tcp_segment(seg_bytes)
        if not seg:
            return
        key = (src, seg["sport"], dst, seg["dport"])
        flags = seg["flags"]

        with self.lock:
            tcb = self.flows.get(key)

        if flags & SYN and not flags & ACK:
            if tcb and tcb.state == "SYN_RCVD" and seg["seq"] == tcb.rcv_irs:
                tcb.send_synack(seg)          # SYN 重传
                return
            if tcb:
                tcb.rst()                      # 冲突，重置旧流
            with self.lock:
                tcb = TCB(self, family, src, dst, seg["sport"], seg["dport"])
                self.flows[key] = tcb
            tcb.send_synack(seg)
            return

        if not tcb:
            if not flags & RST:
                r = build_tcp_segment(dst, src, seg["dport"], seg["sport"],
                                      0, (seg["seq"] + max(1, len(seg["payload"]))) & 0xFFFFFFFF, RST | ACK, 0)
                self.send_tcp(family, dst, src, r)
            return

        tcb.on_segment(seg)

    def remove_flow(self, src, sport, dst, dport):
        with self.lock:
            self.flows.pop((src, sport, dst, dport), None)

    def _timer_loop(self):
        while not self._stop.wait(0.2):
            now = time.time()
            with self.lock:
                tcbs = list(self.flows.values())
            for t in tcbs:
                try:
                    t.on_timer(now)
                except Exception:
                    pass
