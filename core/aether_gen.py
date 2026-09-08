        # SPDX-License-Identifier: MIT
# AetherCore - 订阅解析与内核配置生成器 (纯 Python 实现)
#
# 从订阅拉取/缓存解析 VLESS 节点，生成 data/core.conf。
# 用法:
#   aether_gen.py -d <数据目录> --rebuild   离线：复用 data/config.yaml 节点缓存
#   aether_gen.py -d <数据目录> --fetch     联网：拉取订阅并刷新缓存
#   aether_gen.py -d <数据目录>             有缓存则 rebuild，否则 fetch

import os
import sys
import json
import base64
import urllib.request
import urllib.parse
import subprocess
import re
import struct
import ipaddress

SUB_URL = "https://dasho.xn--cp3a08l.com/api/v1/pq/a238fdf4660b8a4ee19242b2adf655d9"
MAX_NODES = 128

# ---- 域名分流规则（与旧 subscription.py 保持一致） ----
DIRECT_DOMAINS = [
    "qq.com", "tencent.com", "music.tc.qq.com", "y.qq.com", "gtimg.com", "qpic.cn",
    "weixin.qq.com", "163.com", "126.net", "music.163.com", "netease.com", "126.com",
    "kugou.com", "kuwo.cn", "migu.cn", "bilibili.com", "bilivideo.com", "biliapi.net",
    "hdslb.com", "baidu.com", "alipay.com", "taobao.com", "tmall.com", "jd.com",
    "aliyun.com", "ubuntu.com", "canonical.com", "debian.org", "archlinux.org",
    "centos.org", "alpinelinux.org", "fedoraproject.org", "opensuse.org", "kernel.org",
    "gnu.org", "tsinghua.edu.cn", "ustc.edu.cn", "cn",
]

PROXY_DOMAINS = [
    "daily-cloudcode-pa.googleapis.com", "cloudaicompanion.googleapis.com",
    "generativelanguage.googleapis.com", "gemini.google.com",
    "alkalimakersuite-pa.clients6.google.com", "googleapis.com", "google.com",
    "gstatic.com", "deepmind.google", "aiplatform.googleapis.com",
    "cloudcode.googleapis.com", "binance.com", "binance.org", "binance.me",
    "binance.charity", "binance.cloud", "binancezh.com", "binancezh.top",
    "binancezh.info", "binancezh.biz", "binancezh.be", "bnbstatic.com",
    "bntrace.com", "saasexch.com", "binance.vision", "bblivestream.com",
    "nftstatic.com", "bscdnweb.com", "bnw3w.com", "okx.com", "bybit.com", "gate.io",
]

PRIVATE_CIDRS = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
]


class Node:
    """VLESS 节点信息"""
    __slots__ = ("name", "type", "server", "uuid", "port", "tls", "sni", "ws", "ws_path", "ws_host")

    def __init__(self):
        self.name = ""
        self.type = ""
        self.server = ""
        self.uuid = ""
        self.port = 0
        self.tls = False
        self.sni = ""
        self.ws = False
        self.ws_path = ""
        self.ws_host = ""


def read_file(path: str) -> str:
    """读取文件内容，失败返回 None"""
    try:
        with open(path, "rb") as f:
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def write_file(path: str, content: str) -> bool:
    """写入文件"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except OSError:
        return False


def _kv_get(entry: str, key: str) -> str:
    """提取 YAML 行中 'key: value' 的值"""
    pattern = r'(?<![a-zA-Z0-9_\-])' + re.escape(key) + r'\s*:\s*(.*?)(?:\s*$|,|(?=\s+[a-zA-Z_]))'
    m = re.search(pattern, entry, re.MULTILINE)
    if m:
        val = m.group(1).strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        return val
    return ""


def _kv_value(val: str) -> str:
    """清理提取的值"""
    val = val.strip()
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]
    return val


def parse_proxies(content: str) -> list:
    """解析 YAML 格式 proxies: 块，返回 Node 列表"""
    nodes = []
    # 找到 proxies: 块
    m = re.search(r'^proxies:\s*$', content, re.MULTILINE)
    if not m:
        return nodes

    block = content[m.end():]
    # 逐行解析 proxies 条目（以 "- " 开头的行）
    entries = re.split(r'\n\s*-\s+', block)
    for entry in entries[1:]:  # 第一个是空白
        if not entry.strip():
            continue
        name = _kv_get(entry, "name")
        type_ = _kv_get(entry, "type")
        server = _kv_get(entry, "server")
        port_str = _kv_get(entry, "port")
        uuid = _kv_get(entry, "uuid")

        if not (name and type_ and server and port_str):
            continue

        try:
            port = int(port_str)
        except ValueError:
            continue

        n = Node()
        n.name = _kv_value(name)
        n.type = _kv_value(type_)
        n.server = _kv_value(server)
        n.port = port
        if uuid:
            n.uuid = _kv_value(uuid)

        net = _kv_get(entry, "network")
        if net and _kv_value(net).lower() == "ws":
            n.ws = True

        tls = _kv_get(entry, "tls")
        if tls and _kv_value(tls).lower() == "true":
            n.tls = True

        sni = _kv_get(entry, "servername")
        if sni:
            n.sni = _kv_value(sni)

        if n.ws:
            path = _kv_get(entry, "path")
            host = _kv_get(entry, "Host")
            if path:
                n.ws_path = _kv_value(path)
            if host:
                n.ws_host = _kv_value(host)

        nodes.append(n)
    return nodes


def b64_decode(text: str) -> str:
    """解码 base64 文本"""
    try:
        # 标准 base64
        padding = 4 - len(text) % 4
        if padding != 4:
            text += "=" * padding
        decoded = base64.b64decode(text)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        try:
            # 标准 base64（无填充）
            decoded = base64.b64decode(text + "===")
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return ""


def urldecode(s: str) -> str:
    """URL 解码"""
    return urllib.parse.unquote(s)


def _qs_get(qs: str, key: str) -> str:
    """从 query string 中获取 key 的值"""
    pattern = r'(?:^|&)' + re.escape(key) + r'=([^&]+)'
    m = re.search(pattern, qs)
    if m:
        return urllib.parse.unquote(m.group(1))
    return ""


def parse_vless_links(text: str) -> list:
    """解析 vless:// 链接文本，返回 Node 列表"""
    nodes = []
    pattern = r'vless://([^@]+)@([^?#]+)(?:\?([^#]*))?(?:#(.+))?'
    for m in re.finditer(pattern, text):
        uuid = urllib.parse.unquote(m.group(1))
        host_port = m.group(2)
        query = m.group(3) or ""
        name = urllib.parse.unquote(m.group(4)) if m.group(4) else ""

        # 过滤无效节点
        if name and ("剩余流量" in name or "套餐到期" in name):
            continue

        # 解析 server:port
        server = host_port
        port = 443
        if ":" in host_port:
            # IPv6 处理
            if host_port.startswith("["):
                rb = host_port.rfind("]")
                if rb > 0:
                    server = host_port[1:rb]
                    if rb + 1 < len(host_port) and host_port[rb + 1] == ":":
                        try:
                            port = int(host_port[rb + 2:])
                        except ValueError:
                            pass
            else:
                parts = host_port.rsplit(":", 1)
                if len(parts) == 2:
                    try:
                        port = int(parts[1])
                        server = parts[0]
                    except ValueError:
                        pass

        # 过滤本地地址
        if server.startswith("127.") or server.lower() == "localhost":
            continue

        n = Node()
        n.uuid = uuid
        n.server = server
        n.port = port
        n.name = name if name else f"node-{len(nodes) + 1}"

        # 解析 query 参数
        sec = _qs_get(query, "security")
        if sec.lower() == "reality":
            continue  # 核心暂不支持 reality
        n.tls = sec.lower() == "tls"

        sni = _qs_get(query, "sni")
        if sni:
            n.sni = sni

        type_ = _qs_get(query, "type")
        if type_.lower() == "ws":
            n.ws = True
            path = _qs_get(query, "path")
            if path:
                n.ws_path = path
            host = _qs_get(query, "host")
            if host:
                n.ws_host = host
        elif type_ and type_.lower() not in ("tcp", ""):
            continue  # grpc/h2 等不支持

        n.type = "vless"
        nodes.append(n)

    return nodes


def write_process_rules(f, rules_path: str):
    """读取 app_rules.json，注入 process 规则到 core.conf"""
    try:
        if os.path.exists(rules_path):
            with open(rules_path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            if isinstance(data, dict):
                for proc, target in data.items():
                    if target.lower() == "direct":
                        f.write(f"direct-process\t{proc}\n")
                    else:
                        f.write(f"proxy-process\t{proc}\n")
    except Exception:
        pass


def fetch_subscription(cache_path: str) -> bool:
    """拉取订阅到缓存文件"""
    cmd = [
        "curl.exe", "-s", "-L",
        "--connect-timeout", "3",
        "-m", "20",
        "-A", "ClashMeta; AetherCore",
        "-o", cache_path,
        SUB_URL,
    ]
    try:
        rc = subprocess.run(cmd, capture_output=True, timeout=30)
        if rc.returncode == 0:
            return True
    except Exception:
        pass

    # 带代理重试
    cmd[1:1] = ["-x", "http://127.0.0.1:7899"]
    try:
        rc = subprocess.run(cmd, capture_output=True, timeout=30)
        return rc.returncode == 0
    except Exception:
        return False


def generate_core_conf(nodes: list, conf_path: str, rules_path: str) -> bool:
    """生成 core.conf 配置文件"""
    used = 0
    lines = []
    lines.append("# AetherCore C core config (generated by aether_gen.py)")
    lines.append("listen\t127.0.0.1\t7899")
    lines.append("controller\t127.0.0.1\t9097")

    for n in nodes:
        if used >= MAX_NODES:
            break
        if n.type.lower() != "vless" or not n.uuid or not n.server or n.port <= 0:
            continue
        name = n.name.replace("\t", " ").replace("\n", " ").replace("\r", " ")
        if n.ws:
            line = (f"node\t{name}\t{n.uuid}\t{n.server}\t{n.port}\t"
                    f"{'tls' if n.tls else 'none'}\t"
                    f"{n.sni if n.sni else n.server}\t"
                    f"{n.ws_path}\t"
                    f"{n.ws_host if n.ws_host else (n.sni if n.sni else n.server)}")
        else:
            line = (f"node\t{name}\t{n.uuid}\t{n.server}\t{n.port}\t"
                    f"{'tls' if n.tls else 'none'}\t"
                    f"{n.sni if n.sni else n.server}")
        lines.append(line)
        used += 1

    if used == 0:
        return False

    for d in DIRECT_DOMAINS:
        d = d[1:] if d.startswith(".") else d
        lines.append(f"direct-domain\t.{d}")
    for d in PROXY_DOMAINS:
        d = d[1:] if d.startswith(".") else d
        lines.append(f"proxy-domain\t.{d}")
    for cidr in PRIVATE_CIDRS:
        lines.append(f"direct-ip\t{cidr}")

    # 写入分应用规则
    if rules_path:
        # 临时写入，后面用 write_process_rules 追加
        pass

    lines.append("default\tproxy")

    content = "\n".join(lines) + "\n"

    # 追加分应用规则
    if rules_path:
        rule_lines = []
        try:
            if os.path.exists(rules_path):
                with open(rules_path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                if isinstance(data, dict):
                    for proc, target in data.items():
                        if target.lower() == "direct":
                            rule_lines.append(f"direct-process\t{proc}")
                        else:
                            rule_lines.append(f"proxy-process\t{proc}")
        except Exception:
            pass
        if rule_lines:
            content += "\n".join(rule_lines) + "\n"

    try:
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] 成功解析 {len(nodes)} 个节点，生成 core.conf（{used} 个 VLESS 节点）")
        print(f"[✔] 已生成内核配置: {conf_path}")
        return True
    except OSError as e:
        print(f"[x] 写入 core.conf 失败: {e}")
        return False


def generate(data_dir: str, mode: str = "auto") -> bool:
    """
    生成 core.conf
    mode: "auto" - 有缓存则 rebuild，否则 fetch
          "rebuild" - 离线复用缓存
          "fetch" - 联网拉取
    """
    cache_path = os.path.join(data_dir, "sub.b64")
    conf_path = os.path.join(data_dir, "core.conf")
    rules_path = os.path.join(data_dir, "app_rules.json")

    os.makedirs(data_dir, exist_ok=True)

    content = None
    if mode != "rebuild":
        print("[*] 正在拉取订阅...")
        if fetch_subscription(cache_path):
            print("[*] 订阅拉取成功")
        elif mode == "fetch":
            print("[x] 订阅拉取失败")
            return False

    # 读取缓存
    content = read_file(cache_path)
    if not content:
        # 兼容旧的 clash yaml 缓存
        alt_path = os.path.join(data_dir, "config.yaml")
        content = read_file(alt_path)

    if not content:
        print("[x] 无订阅缓存且拉取失败")
        return False

    # 尝试 base64 解码
    nodes = []
    text = b64_decode(content)
    if text and "vless://" in text:
        nodes = parse_vless_links(text)
    else:
        nodes = parse_proxies(content)

    if not nodes:
        print("[x] 订阅内容中未解析到节点")
        return False

    if not generate_core_conf(nodes, conf_path, rules_path):
        print("[x] 没有可用的 VLESS 节点")
        return False

    return True


def main():
    """CLI 入口，兼容 C 版本 aether_gen.exe 的参数格式"""
    import argparse

    parser = argparse.ArgumentParser(description="AetherCore 订阅解析与配置生成器")
    parser.add_argument("-d", "--data-dir", default=None, help="数据目录路径")
    parser.add_argument("--rebuild", action="store_true", help="离线重建配置")
    parser.add_argument("--fetch", action="store_true", help="联网拉取订阅")

    args = sys.argv[1:]

    data_dir = None
    mode = "auto"

    i = 0
    while i < len(args):
        if args[i] == "-d" and i + 1 < len(args):
            data_dir = args[i + 1]
            i += 2
        elif args[i] == "--rebuild":
            mode = "rebuild"
            i += 1
        elif args[i] == "--fetch":
            mode = "fetch"
            i += 1
        else:
            i += 1

    if not data_dir:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(script_dir), "data")

    return 0 if generate(data_dir, mode) else 1


if __name__ == "__main__":
    sys.exit(main())