# SPDX-License-Identifier: MIT
"""TUN 模块单元测试 (无需管理员/wintun): 校验和、IP/TCP 构造解析、Fake-IP DNS、TCP 状态机"""
import os
import sys
import socket
import struct
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))

import tun_tcp as tt
import tun_stack as ts
import tun_dns as td
import aether_tun as at

PASS = 0
FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


# ---- 1. 校验和已知向量 (RFC 1071 例) ----
print("== checksum ==")
data = bytes([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])
check("cksum rfc1071", tt._cksum(data) == 0x220d, hex(tt._cksum(data)))

# ---- 2. IP/TCP 构造 -> 解析 roundtrip ----
print("== ip/tcp build & parse ==")
seg = tt.build_tcp_segment("10.0.0.1", "10.0.0.2", 12345, 443, 1000, 2000,
                           tt.ACK | tt.PSH, 65535, b"hello world")
p = tt.parse_tcp_segment(seg)
check("tcp parse fields",
      p and p["sport"] == 12345 and p["dport"] == 443 and p["seq"] == 1000
      and p["ack"] == 2000 and p["flags"] == (tt.ACK | tt.PSH)
      and p["window"] == 65535 and p["payload"] == b"hello world", str(p))

pkt = ts.build_ip4_packet("10.0.0.1", "10.0.0.2", 6, seg)
ip = ts.parse_ip_packet(pkt)
check("ip4 roundtrip",
      ip and ip["family"] == 4 and ip["proto"] == 6 and ip["src"] == "10.0.0.1"
      and ip["dst"] == "10.0.0.2" and ip["payload"] == seg, str(ip))

seg6 = tt.build_tcp_segment("fd00::1", "fd00::2", 1, 2, 3, 4, tt.SYN, 100, mss=1440)
pkt6 = ts.build_ip6_packet("fd00::1", "fd00::2", 6, seg6)
ip6 = ts.parse_ip_packet(pkt6)
check("ip6 roundtrip",
      ip6 and ip6["family"] == 6 and ip6["proto"] == 6 and ip6["src"] == "fd00::1"
      and ip6["dst"] == "fd00::2" and ip6["payload"] == seg6, str(ip6))

# 分片包应被拒绝
frag = bytearray(pkt)
frag[6:8] = struct.pack(">H", 0x2003)  # MF + offset=3
check("frag dropped", ts.parse_ip_packet(bytes(frag)) is None)

# ---- 3. UDP 构造 ----
print("== udp ==")
useg = ts.build_udp_segment("10.0.0.2", "10.0.0.1", 53, 50000, b"\x01\x02\x03")
sp, dp, ulen = struct.unpack(">HHH", useg[:6])
ck = struct.unpack(">H", useg[6:8])[0]
check("udp header", sp == 53 and dp == 50000 and ulen == 11 and ck != 0,
      f"{sp},{dp},{ulen},{ck}")
rx_ck = tt._pseudo_cksum("10.0.0.2", "10.0.0.1", 17, useg)
check("udp checksum valid", rx_ck == 0, hex(rx_ck))

# ---- 4. Fake-IP DNS ----
print("== fake-ip dns ==")
dns = td.FakeIPDNS(bind_ip=None)
ip4 = dns.pool.get_v4("example.com")
ip6 = dns.pool.get_v6("example.com")
check("fake v4 in range", at.is_fake_v4(ip4), ip4)
check("fake v6 in range", at.is_fake_v6(ip6), ip6)
check("stable mapping", dns.pool.get_v4("example.com") == ip4)
check("reverse lookup", dns.pool.reverse(ip4) == "example.com")

qname = td._encode_qname("example.com")
query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
resp = dns.handle_query(query)
check("A query answered", resp is not None)
rflags = struct.unpack(">H", resp[2:4])[0]
check("resp is response", rflags & 0x8000 != 0, hex(rflags))
# 解析应答里的 A 记录
ans_ip = socket.inet_ntoa(resp[-4:])
check("A record = fake ip", ans_ip == dns.pool.get_v4("example.com"), ans_ip)

query6 = struct.pack(">HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 28, 1)
# 1) 无 IPv6 上行时返回空应答 (0 answers)，防止 IPv6 直连挂起
resp6_no_v6 = dns.handle_query(query6)
check("AAAA empty NOERROR when no v6", resp6_no_v6 is not None and len(resp6_no_v6) == 12 + len(qname) + 4)

# 2) 有 IPv6 上行时返回 Fake-IP IPv6
dns_v6 = td.FakeIPDNS(bind_ip="10.0.0.2", bind_ip6="2001:db8::1")
resp6 = dns_v6.handle_query(query6)
rdlen6 = struct.unpack(">H", resp6[-18:-16])[0] if resp6 else 0
check("AAAA answered with v6", resp6 is not None and len(resp6) > len(query6))
check("AAAA rdata 16B", rdlen6 == 16 and len(resp6[-16:]) == 16, str(rdlen6))

# HTTPS(65) 空应答
q65 = struct.pack(">HHHHHH", 0x9999, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 65, 1)
r65 = dns.handle_query(q65)
check("HTTPS empty NOERROR", r65 is not None and len(r65) == 12 + len(qname) + 4)

# PTR
arpa_name = ".".join(reversed(ip4.split("."))) + ".in-addr.arpa"
ptr_name = td._encode_qname(arpa_name)
qptr = struct.pack(">HHHHHH", 0xabcd, 0x0100, 1, 0, 0, 0) + ptr_name + struct.pack(">HH", 12, 1)
rptr = dns.handle_query(qptr)
check("PTR answered", rptr is not None and b"example" in rptr, str(rptr))

# ---- 5. TCP 状态机 (假 device 收包) ----
print("== tcp state machine ==")
class FakeDevice:
    def __init__(self):
        self.sent = []
    def write_packet(self, pkt):
        self.sent.append(pkt)
    def pop(self):
        """取出下一个发往客户端的 (src,dst,tcp段)"""
        while self.sent:
            pkt = self.sent.pop(0)
            ip = ts.parse_ip_packet(pkt)
            if ip and ip["proto"] == 6:
                return ip
        return None

log_lines = []
dev = FakeDevice()
dns = td.FakeIPDNS(bind_ip=None, upstreams=["127.0.0.1"])  # 转发类查询指向必失败上游

# 两个测试端口: refused (bind 不 listen, connect 收 RST) / hang (listen 不 accept, 桥接挂起)
refused_sock = socket.socket()
refused_sock.bind(("127.0.0.1", 0))
refused_port = refused_sock.getsockname()[1]
hang_sock = socket.socket()
hang_sock.bind(("127.0.0.1", 0))
hang_sock.listen(4)
hang_port = hang_sock.getsockname()[1]

stack = tt.TcpStack(dev, dns, ("127.0.0.1", refused_port), log=log_lines.append)

C = "198.18.7.100"   # 客户端 (TUN 内)
S = "198.18.9.1"     # Fake-IP 服务端
dns.pool._domain2v4["test.example"] = S
dns.pool._v4_2domain[S] = "test.example"

# 客户端 SYN
syn = tt.build_tcp_segment(C, S, 40000, 443, 1000, 0, tt.SYN, 64240, mss=1460)
dev.sent.clear()
stack.handle_packet(4, C, S, syn)
ipr = dev.pop()
check("SYN-ACK emitted", ipr is not None and ipr["src"] == S and ipr["dst"] == C, str(ipr))
pr = tt.parse_tcp_segment(ipr["payload"])
check("SYN-ACK flags", pr and pr["flags"] & (tt.SYN | tt.ACK) == (tt.SYN | tt.ACK))
check("SYN-ACK sport=443", pr and pr["sport"] == 443 and pr["dport"] == 40000)
check("SYN-ACK mss opt", pr and pr["mss"] == tt.MSS_V4, str(pr and pr["mss"]))

# 客户端 ACK 完成握手 -> 桥接连 refused 端口失败 -> RST
ack = tt.build_tcp_segment(C, S, 40000, 443, 1001, pr["seq"] + 1, tt.ACK, 64240)
dev.sent.clear()
stack.handle_packet(4, C, S, ack)
time.sleep(0.8)
ipr = dev.pop()
pr2 = tt.parse_tcp_segment(ipr["payload"]) if ipr else None
check("socks fail -> RST", pr2 and pr2["flags"] & tt.RST, str(pr2 and pr2["flags"]))
check("flow removed after RST", (C, 40000, S, 443) not in stack.flows)
refused_sock.close()

# 手动建立一条桥接挂起的流 (上游不响应，隔离状态机测试)
stack2 = tt.TcpStack(dev, dns, ("127.0.0.1", hang_port), log=log_lines.append)
tcb = tt.TCB(stack2, 4, C, S, 41000, 80)
stack2.flows[(C, 41000, S, 80)] = tcb
syn2 = tt.build_tcp_segment(C, S, 41000, 80, 5000, 0, tt.SYN, 64240, mss=1460)
tcb.send_synack(tt.parse_tcp_segment(syn2))
# 客户端 ACK
tcb.on_segment(tt.parse_tcp_segment(
    tt.build_tcp_segment(C, S, 41000, 80, 5001, tcb.snd_nxt, tt.ACK, 64240)))
time.sleep(0.2)  # 等桥接线程进入挂起的 socks recv
check("established", tcb.state == "ESTABLISHED" and not tcb.dead, tcb.state)
# 下行数据 + 客户端确认
tcb.snd_q.append(b"HTTP RESPONSE BODY " * 20)
tcb._try_send()
check("data segments sent", len(tcb.unacked) > 0 and tcb.snd_nxt > tcb.snd_iss + 1)
tcb.on_segment(tt.parse_tcp_segment(
    tt.build_tcp_segment(C, S, 41000, 80, 5001, tcb.snd_nxt, tt.ACK, 64240)))
check("all acked", not tcb.unacked)
# 上游 EOF -> FIN -> 客户端 ACK FIN -> 客户端 FIN
tcb.server_eof = True
tcb._try_send()
check("fin sent", tcb.fin_sent)
fin_seq = tcb.snd_nxt - 1
tcb.on_segment(tt.parse_tcp_segment(
    tt.build_tcp_segment(C, S, 41000, 80, 5001, fin_seq + 1, tt.ACK, 64240)))
check("fin_wait2", tcb.state == "FIN_WAIT2", tcb.state)
tcb.on_segment(tt.parse_tcp_segment(
    tt.build_tcp_segment(C, S, 41000, 80, 5001, fin_seq + 1, tt.FIN | tt.ACK, 64240)))
check("flow closed & removed", (C, 41000, S, 80) not in stack2.flows, tcb.state)
stack2.stop()
hang_sock.close()

# ---- 6. dial_host 防护 ----
print("== dial_host guards ==")
import aether_core as ac
check("fake v4 guard", ac._is_fake_ip("198.18.5.5"))
check("fake v4 198.19 guard", ac._is_fake_ip("198.19.0.10"))
check("fake v6 guard", ac._is_fake_ip("fdfe:dcba:9877::1234"))
check("real ip pass", not ac._is_fake_ip("1.2.3.4"))
try:
    ac.dial_host("198.18.5.5", 80)
    check("dial fake refused", False)
except ConnectionError:
    check("dial fake refused", True)
except Exception as e:
    check("dial fake refused", False, str(e))

# ---- 7. gen 配置 ----
print("== gen tun line ==")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))
import aether_gen as ag
import tempfile
tmp = os.path.join(tempfile.gettempdir(), "aether_test_core.conf")
nodes = ag.Node() if hasattr(ag, "Node") else None
class N: pass
n = N(); n.type="vless"; n.uuid="u"; n.server="1.2.3.4"; n.port=443; n.name="t"; n.tls=True; n.sni="s"; n.ws=False; n.ws_path="/"; n.ws_host=""
ok = ag.generate_core_conf([n], tmp, None)
content = open(tmp, encoding="utf-8").read()
check("gen has tun on", ok and "tun\ton" in content)

# ---- 8. 32 位 TCP 序号回绕运算测试 ----
print("== tcp 32-bit sequence wrap-around ==")
check("seq_lt wrap", tt.seq_lt(0xFFFFFFFF, 10))
check("seq_gt wrap", tt.seq_gt(10, 0xFFFFFFFF))
check("seq_diff wrap", tt.seq_diff(10, 0xFFFFFFFF) == 11, str(tt.seq_diff(10, 0xFFFFFFFF)))
check("seq_lte equal", tt.seq_lte(0xFFFFFFFF, 0xFFFFFFFF))
check("seq_gte equal", tt.seq_gte(0xFFFFFFFF, 0xFFFFFFFF))
check("seq_lte wrap", tt.seq_lte(0xFFFFFFFF, 5))
check("seq_gte wrap", tt.seq_gte(5, 0xFFFFFFFF))
check("seq_lt regular", not tt.seq_lt(10, 0xFFFFFFFF))
check("seq_diff regular", tt.seq_diff(100, 50) == 50)

# ---- 9. 纯 Python GeoIP MMDB 解析测试 ----
print("== geoip mmdb ==")
import aether_geoip as agip
check("geoip cn alidns", agip.is_cn("223.5.5.5") is True)
check("geoip cn 114dns", agip.is_cn("114.114.114.114") is True)
check("geoip non-cn google", agip.is_cn("8.8.8.8") is False)
check("geoip non-cn cloudflare", agip.is_cn("1.1.1.1") is False)
check("geoip private loopback code", agip.country_code("127.0.0.1") == "PRIVATE")
check("geoip private loopback is_cn", agip.is_cn("127.0.0.1") is True)
check("geoip invalid ip", agip.is_cn("not-an-ip") is False)

# ---- 10. TUN 客户端进程映射测试 ----
print("== tun client process map ==")
ac.register_tun_client_port(54321, "chrome.exe")
check("tun port registered", ac.get_tun_client_process(54321) == "chrome.exe")
check("tun unknown port", ac.get_tun_client_process(12345) == "")

# ---- 11. 路由决策与控制器 PUT /configs 热重载 ----
print("== route decision & controller hot-reload ==")
conf_file_1 = os.path.join(tempfile.gettempdir(), "aether_test_hotreload_1.conf")
with open(conf_file_1, "w", encoding="utf-8") as f:
    f.write(
        "listen\t127.0.0.1\t7899\n"
        "controller\t127.0.0.1\t9099\n"
        "secret\taethercore\n"
        "node\tvless\ttest-node\t1.2.3.4\t443\tuuid\ttls\t\t\n"
        "direct-domain\t.cn\n"
        "direct-domain\t.baidu.com\n"
        "direct-process\tcurl.exe\n"
        "proxy-process\tgit.exe\n"
        "default\tproxy\n"
    )

ac.load_config(conf_file_1)

def route_target(host, port=80, proc=None):
    use_proxy, _ = ac.decide_route(host, port, proc)
    return "PROXY" if use_proxy else "DIRECT"

check("route process direct", route_target("example.com", proc="curl.exe") == "DIRECT")
check("route process proxy", route_target("example.com", proc="git.exe") == "PROXY")
check("route domain direct", route_target("baidu.com") == "DIRECT")
check("route domain proxy", route_target("google.com") == "PROXY")
check("route geoip cn", route_target("223.5.5.5") == "DIRECT")

# 启动微型控制器测试服务器
import socketserver
import json
import urllib.request

class ControllerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ac.handle_controller(self.request)

ctrl_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ControllerHandler)
ctrl_port = ctrl_server.server_address[1]
threading.Thread(target=ctrl_server.serve_forever, daemon=True).start()

# 生成新配置 2: 把 git.exe 改为 direct-process
conf_file_2 = os.path.join(tempfile.gettempdir(), "aether_test_hotreload_2.conf")
with open(conf_file_2, "w", encoding="utf-8") as f:
    f.write(
        "listen\t127.0.0.1\t7899\n"
        "controller\t127.0.0.1\t9099\n"
        "secret\taethercore\n"
        "node\tvless\ttest-node\t1.2.3.4\t443\tuuid\ttls\t\t\n"
        "direct-domain\t.cn\n"
        "direct-process\tgit.exe\n"
        "default\tproxy\n"
    )

# 发起 PUT /configs 请求进行热重载
put_req = urllib.request.Request(
    f"http://127.0.0.1:{ctrl_port}/configs",
    data=json.dumps({"path": conf_file_2}).encode("utf-8"),
    headers={"Authorization": "Bearer aethercore", "Content-Type": "application/json"},
    method="PUT"
)
try:
    with urllib.request.urlopen(put_req, timeout=3) as resp:
        check("controller put status", resp.status == 204, str(resp.status))
except Exception as e:
    check("controller put status", False, str(e))

# 验证热重载后生效: git.exe 变成了 DIRECT
time.sleep(0.1)
check("hot-reload route changed", route_target("example.com", proc="git.exe") == "DIRECT", f"got {route_target('example.com', proc='git.exe')}")
ctrl_server.shutdown()

# ---- 11.1 自定义覆盖路由配置 (route-domain & Override-Configuration) 测试 ----
print("== custom route-domain & override configuration ==")
conf_file_override = os.path.join(tempfile.gettempdir(), "aether_test_override.conf")
with open(conf_file_override, "w", encoding="utf-8") as f:
    f.write(
        "listen\t127.0.0.1\t7899\n"
        "controller\t127.0.0.1\t9099\n"
        "node\t🇸🇬新加坡01 | 电信联通推荐\t3a3405dc-9576-4854-83f4-ceb1d47d57a4\tsg1.example.com\t443\ttls\n"
        "node\t🇺🇸美国圣何塞06-0.1倍\t3a3405dc-9576-4854-83f4-ceb1d47d57a4\tus6.example.com\t443\ttls\n"
        "node\t🇺🇸美国圣何塞01-0.1倍\t3a3405dc-9576-4854-83f4-ceb1d47d57a4\tus1.example.com\t443\ttls\n"
        "route-domain\t.binance.com\t🇸🇬新加坡01 | 电信联通推荐\n"
        "route-domain\t.asterdex.com\t🇸🇬新加坡01 | 电信联通推荐\n"
        "route-domain\t.google.com\t🇺🇸美国06-0.1倍 | 电信联通移动推荐\n"
        "route-ip\t172.217.0.0/16\t🇺🇸美国06-0.1倍 | 电信联通移动推荐\n"
        "route-ip\t34.0.0.0/9\t🇺🇸美国06-0.1倍 | 电信联通移动推荐\n"
        "direct-domain\t.cn\n"
        "direct-domain\t.baidu.com\n"
        "default\tproxy\n"
    )

ac.load_config(conf_file_override)
# 将当前默认主节点设为美国01
ac.g_cfg.current_node = 2

r_binance = ac.decide_route("binance.com", 443)
check("route binance to sg", r_binance[0] is True and "新加坡01" in r_binance[1], str(r_binance))

r_asterdex = ac.decide_route("www.asterdex.com", 443)
check("route www.asterdex.com to sg", r_asterdex[0] is True and "新加坡01" in r_asterdex[1], str(r_asterdex))

r_asterdex_sub = ac.decide_route("api.asterdex.com", 443)
check("route api.asterdex.com to sg", r_asterdex_sub[0] is True and "新加坡01" in r_asterdex_sub[1], str(r_asterdex_sub))

r_google = ac.decide_route("google.com", 443)
check("route google to us06", r_google[0] is True and "06" in r_google[1], str(r_google))

r_google_ip = ac.decide_route("172.217.115.4", 443)
check("route google ip to us06", r_google_ip[0] is True and "06" in r_google_ip[1], str(r_google_ip))

r_google_cloud_ip = ac.decide_route("34.54.84.110", 443)
check("route google cloud ip to us06", r_google_cloud_ip[0] is True and "06" in r_google_cloud_ip[1], str(r_google_cloud_ip))

r_other = ac.decide_route("other-site.org", 443)
check("route other to default us01", r_other[0] is True and "01" in r_other[1], str(r_other))


# ---- 12. TUN 底层 Ctypes 内存布局与物理网卡探测 ----
print("== tun ctypes & physical network ==")
import core.aether_tun as at
phys = at.detect_physical_network()
check("phys v4 detected", phys["v4_ip"] is not None, str(phys))
check("phys gw detected", phys["gw_v4"] is not None, str(phys))
check("phys ifindex detected", phys["if_index_v4"] > 0, str(phys))

sa4 = at.sockaddr_inet_v4("198.19.0.1")
raw_bytes = bytes(sa4)
check("sockaddr_inet_v4 family", raw_bytes[0:2] == b"\x02\x00")
check("sockaddr_inet_v4 port", raw_bytes[2:4] == b"\x00\x00")
check("sockaddr_inet_v4 addr", raw_bytes[4:8] == socket.inet_aton("198.19.0.1"))

sa6 = at.sockaddr_inet_v6("fdfe:dcba:9877::1")
raw6 = bytes(sa6)
check("sockaddr_inet_v6 family", raw6[0:2] == struct.pack("<H", at.AF_INET6_WIN))
check("sockaddr_inet_v6 addr", raw6[8:24] == socket.inet_pton(socket.AF_INET6, "fdfe:dcba:9877::1"))

check("unicast row address at offset 0", at.MIB_UNICASTIPADDRESS_ROW.Address.offset == 0)
fwd_row = at.MIB_IPFORWARDROW()
check("ipforwardrow has named fields", hasattr(fwd_row, "dwForwardNextHop") and hasattr(fwd_row, "dwForwardIfIndex"))

# ---- 13. SOCKS5 入站服务端握手与连通测试 ----
print("== socks5 server inbound handshake ==")
# 目标 echo 服务
echo_s = socket.socket()
echo_s.bind(("127.0.0.1", 0))
echo_s.listen(1)
echo_p = echo_s.getsockname()[1]

def _echo_runner():
    try:
        conn, _ = echo_s.accept()
        data = conn.recv(1024)
        conn.sendall(data)
        conn.close()
    except Exception:
        pass

threading.Thread(target=_echo_runner, daemon=True).start()

# AetherCore handle_client 服务端
core_s = socket.socket()
core_s.bind(("127.0.0.1", 0))
core_s.listen(2)
core_p = core_s.getsockname()[1]

def _core_runner():
    try:
        conn, addr = core_s.accept()
        ac.handle_client(conn, addr[0], addr[1])
    except Exception:
        pass

threading.Thread(target=_core_runner, daemon=True).start()

try:
    c_sock = tt.socks5_connect(("127.0.0.1", core_p), "127.0.0.1", echo_p, timeout=2.0)
    check("socks5 handshake success", c_sock is not None)
    c_sock.sendall(b"hello-socks5")
    echo_resp = c_sock.recv(1024)
    check("socks5 relay data", echo_resp == b"hello-socks5")
    c_sock.close()
except Exception as e:
    check("socks5 handshake success", False, str(e))
    check("socks5 relay data", False, str(e))
finally:
    core_s.close()
    echo_s.close()

# ---- 15. clean_host & dynamic direct 防污染测试 ----
print("== clean_host & anti-poisoning ==")
check("clean_host domain", ac.clean_host("google.com:443") == "google.com")
check("clean_host bracketed v6", ac.clean_host("[2001:4860::1]:443") == "2001:4860::1")
check("clean_host raw v6", ac.clean_host("2001:4860:4846:400::") == "2001:4860:4846:400::")
check("clean_host ipv4", ac.clean_host("1.2.3.4:80") == "1.2.3.4")

# 测试防污染: IP 地址不应被写入直连白名单
ac.g_dynamic_direct.clear()
ac.add_dynamic_direct("2001:4860:4846:400::")
ac.add_dynamic_direct("142.250.190.46")
check("dynamic direct rejects raw v6", "2001:4860:4846:400::" not in ac.g_dynamic_direct)
check("dynamic direct rejects raw v4", "142.250.190.46" not in ac.g_dynamic_direct)

ac.add_dynamic_direct("example.cn")
check("dynamic direct accepts domestic domain", "example.cn" in ac.g_dynamic_direct)

# 测试 TUN 模式下无 IPv6 出口时 dial_host 立即抛出网络不可达
os.environ["AETHER_TUN"] = "1"
os.environ.pop("AETHER_BIND_IP6", None)
try:
    ac.dial_host("2001:4860:4846:400::", 443, timeout=0.1)
    check("dial_host v6 without uplink raises immediately", False, "no exception raised")
except OSError as e:
    check("dial_host v6 without uplink raises immediately", "unreachable" in str(e).lower())
finally:
    os.environ.pop("AETHER_TUN", None)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
