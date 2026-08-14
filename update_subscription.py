#!/usr/bin/env python3
"""update_subscription.py — 订阅更新器：从订阅 URL 拉取节点并生成 sing-box 配置。

流程：
  1. 读取 `sub` 文件中的订阅 URL（支持多行多个，自动合并去重）
  2. 下载订阅内容，自动识别格式：
     - sing-box JSON（含 outbounds）→ 直接提取节点
     - base64 / 明文 v2rayN 分享链接（vmess:// vless:// trojan:// ss:// hy2://）
       → 解析并转换为 sing-box outbounds
  3. 生成 singbox-config.json：
     - 保留旧配置的 log / dns / inbounds / route / experimental
     - 重建 outbounds：[DIRECT, REJECT] + 解析节点 + urltest「♻️自动选择」
       + selector「🚀节点选择」（与 route 的 download_detour 引用一致）
     - 按 (type, server, server_port) 去重；重名节点自动加序号
  4. 写文件前自动备份旧配置为 singbox-config.json.bak-时间戳

用法：
  python update_subscription.py            # 更新订阅并生成配置
  python update_subscription.py --check    # 仅下载解析并统计节点数，不写文件
  python update_subscription.py --url URL  # 临时指定订阅 URL（覆盖 sub 文件）
  python update_subscription.py --out P    # 指定输出路径（默认 singbox-config.json）
  python update_subscription.py --dry-run  # 打印将生成的节点清单，不写文件

仅依赖 Python 标准库。
"""
import argparse
import base64
import binascii
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUB_FILE = ROOT / "sub"
OUT_FILE = ROOT / "singbox-config.json"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 proxy-sub-updater/1.0")

# 分享链接协议前缀
PROTO_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "hy2://", "hysteria://")
# sing-box 中忽略的特殊 outbound 类型（非节点）
SPECIAL_TYPES = {"direct", "block", "selector", "urltest", "dns", "http", "socks"}
# 合法 shadowsocks 加密（过滤非法）
SS_METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
              "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none"}


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


# ---------- 订阅获取 ----------

def read_sub_urls(path: Path) -> list[str]:
    if not path.is_file():
        raise RuntimeError(f"找不到订阅文件：{path}（请把订阅 URL 写入该文件，每行一个）")
    urls = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and line.startswith(("http://", "https://")):
            urls.append(line)
    if not urls:
        raise RuntimeError(f"订阅文件 {path} 中没有有效的 http(s) URL")
    return urls


def download(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def try_b64_decode(text: str) -> str | None:
    """尝试 base64 解码（容忍换行/空白）。返回解码后的 UTF-8 文本或 None。"""
    s = re.sub(r"\s+", "", text)
    if not s:
        return None
    for pad in ("", "=", "==", "==="):
        try:
            raw = base64.b64decode(s + pad, validate=False)
            dec = raw.decode("utf-8", errors="ignore")
            if dec and any(c.isalpha() for c in dec):
                return dec
        except (binascii.Error, ValueError):
            continue
    return None


def looks_like_shares(text: str) -> bool:
    return any(p in text for p in PROTO_PREFIXES) or any(
        re.match(rf"^{re.escape(p)}", line.strip()) for p in PROTO_PREFIXES
        for line in text.splitlines())


def load_subscription_text(url: str) -> str:
    """下载订阅并返回可解析的文本（自动 base64 解码）。"""
    raw = download(url).decode("utf-8", errors="replace")
    if looks_like_shares(raw):
        return raw
    dec = try_b64_decode(raw)
    if dec is not None and looks_like_shares(dec):
        return dec
    if looks_like_shares(raw):
        return raw
    return raw  # 交给上层判断（JSON 或无法识别）


# ---------- 分享链接解析 ----------

def parse_query(q: str) -> dict:
    return urllib.parse.parse_qs(q) if q else {}


def q1(d: dict, key: str, default=""):
    v = d.get(key)
    return v[0] if isinstance(v, list) and v else default


def parse_vmess(line: str) -> dict | None:
    try:
        raw = line[len("vmess://"):]
        if raw.startswith("vmess://"):  # 兼容嵌套
            raw = raw[len("vmess://"):]
        # 可能是 base64(JSON) 或 #name 后缀
        name = ""
        if "#" in raw:
            raw, _, name = raw.partition("#")
            name = urllib.parse.unquote(name)
        dec = try_b64_decode(raw)
        if not dec:
            return None
        j = json.loads(dec)
    except Exception:
        return None
    tag = name or j.get("ps") or j.get("add") or "vmess"
    ob = {
        "type": "vmess", "tag": tag,
        "server": j.get("add", ""), "server_port": int(j.get("port") or 0),
        "uuid": j.get("id", ""), "alter_id": int(j.get("aid") or 0),
        "security": j.get("scy") or "auto",
    }
    tls = False
    if j.get("tls") in ("tls", "1", "true") or j.get("security") in ("tls", "reality"):
        tls = True
    sni = j.get("sni") or j.get("host") or ""
    if tls:
        ob["tls"] = {"enabled": True, "server_name": sni, "insecure": False}
    net = j.get("net") or "tcp"
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": j.get("path") or "/",
                           "headers": {"Host": [j.get("host") or ""]} if j.get("host") else {}}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": j.get("path") or ""}
    return ob


def parse_vless(line: str) -> dict | None:
    try:
        rest = line[len("vless://"):]
        userinfo, _, after = rest.partition("@")
        if not after:
            return None
        hostport, _, frag = after.partition("#")
        if "?" in hostport:
            hostport, _, qs = hostport.partition("?")
        else:
            qs = ""
        host, _, port = hostport.rpartition(":")
        name = urllib.parse.unquote(frag) if frag else host or "vless"
    except Exception:
        return None
    q = parse_query(qs)
    ob = {"type": "vless", "tag": name, "server": host, "server_port": int(port or 0),
          "uuid": urllib.parse.unquote(userinfo), "packet_encoding": "xudp"}
    flow = q1(q, "flow")
    if flow:
        ob["flow"] = flow
    sec = q1(q, "security")
    sni = q1(q, "sni")
    if sec == "reality":
        ob["tls"] = {"enabled": True, "server_name": sni,
                     "utls": {"enabled": True, "fingerprint": q1(q, "fp") or "chrome"},
                     "reality": {"enabled": True, "public_key": q1(q, "pbk"),
                                 "short_id": q1(q, "sid")}}
    elif sec == "tls":
        ob["tls"] = {"enabled": True, "server_name": sni,
                     "utls": {"enabled": True, "fingerprint": q1(q, "fp") or "chrome"},
                     "insecure": q1(q, "allowInsecure") in ("1", "true")}
    # 传输层
    tp = q1(q, "type") or "tcp"
    if tp == "ws":
        ob["transport"] = {"type": "ws", "path": q1(q, "path") or "/",
                           "headers": {"Host": [q1(q, "host")]} if q1(q, "host") else {}}
    elif tp == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q1(q, "serviceName")}
    elif tp == "http":
        ob["transport"] = {"type": "http", "host": [q1(q, "host")] if q1(q, "host") else [],
                           "path": q1(q, "path") or "/"}
    return ob


def parse_trojan(line: str) -> dict | None:
    try:
        rest = line[len("trojan://"):]
        passwd, _, after = rest.partition("@")
        hostport, _, frag = after.partition("#")
        if "?" in hostport:
            hostport, _, qs = hostport.partition("?")
        else:
            qs = ""
        host, _, port = hostport.rpartition(":")
        name = urllib.parse.unquote(frag) if frag else host or "trojan"
    except Exception:
        return None
    q = parse_query(qs)
    ob = {"type": "trojan", "tag": name, "server": host, "server_port": int(port or 0),
          "password": urllib.parse.unquote(passwd)}
    sni = q1(q, "sni") or q1(q, "peer")
    if sni:
        ob["tls"] = {"enabled": True, "server_name": sni,
                     "insecure": q1(q, "allowInsecure") in ("1", "true")}
    tp = q1(q, "type")
    if tp == "ws":
        ob["transport"] = {"type": "ws", "path": q1(q, "path") or "/",
                           "headers": {"Host": [q1(q, "host")]} if q1(q, "host") else {}}
    return ob


def parse_ss(line: str) -> dict | None:
    """兼容 v2rayN 三种 ss:// 格式。"""
    raw = line[len("ss://"):]
    name = ""
    if "#" in raw:
        raw, _, name = raw.partition("#")
        name = urllib.parse.unquote(name)
    # 格式1：ss://base64(method:pass)@host:port
    if "@" in raw:
        head, _, hostport = raw.partition("@")
        host, _, port = hostport.rpartition(":")
        dec = try_b64_decode(head)
        if dec and ":" in dec:
            method, _, pwd = dec.partition(":")
            pwd = urllib.parse.unquote(pwd)
        else:
            # 明文 method:pass@host:port
            method, _, pwd = head.partition(":")
    else:
        # 格式2：ss://base64(method:pass@host:port)
        dec = try_b64_decode(raw)
        if not dec or "@" not in dec:
            return None
        head, _, hostport = dec.partition("@")
        method, _, pwd = head.partition(":")
        host, _, port = hostport.rpartition(":")
        pwd = urllib.parse.unquote(pwd)
    if method not in SS_METHODS:
        return None
    return {"type": "shadowsocks", "tag": name or host or "ss",
            "server": host, "server_port": int(port or 0),
            "method": method, "password": pwd}


def parse_hy2(line: str) -> dict | None:
    try:
        rest = line[len("hy2://"):]
        passwd, _, after = rest.partition("@")
        hostport, _, frag = after.partition("#")
        if "?" in hostport:
            hostport, _, qs = hostport.partition("?")
        else:
            qs = ""
        host, _, port = hostport.rpartition(":")
        name = urllib.parse.unquote(frag) if frag else host or "hysteria2"
    except Exception:
        return None
    q = parse_query(qs)
    ob = {"type": "hysteria2", "tag": name, "server": host, "server_port": int(port or 0),
          "password": urllib.parse.unquote(passwd)}
    sni = q1(q, "sni") or q1(q, "peer")
    ob["tls"] = {"enabled": True, "server_name": sni or host,
                 "insecure": q1(q, "insecure") in ("1", "true")}
    return ob


def parse_share_line(line: str) -> dict | None:
    line = line.strip()
    if line.startswith("vmess://"):
        return parse_vmess(line)
    if line.startswith("vless://"):
        return parse_vless(line)
    if line.startswith("trojan://"):
        return parse_trojan(line)
    if line.startswith("ss://"):
        return parse_ss(line)
    if line.startswith("hy2://"):
        return parse_hy2(line)
    return None


# ---------- 节点提取 ----------

def extract_nodes_from_json(data: dict) -> list[dict]:
    """从 sing-box JSON（订阅直出）提取节点 outbounds。"""
    nodes = []
    for ob in data.get("outbounds", []):
        if ob.get("type") in SPECIAL_TYPES or not ob.get("server"):
            continue
        nodes.append(ob)
    return nodes


def parse_shares(text: str) -> list[dict]:
    nodes = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        ob = parse_share_line(line)
        if ob is None or not ob.get("server"):
            continue
        key = (ob["type"], ob.get("server"), ob.get("server_port"))
        if key in seen:
            continue
        seen.add(key)
        nodes.append(ob)
    return nodes


def dedup_and_name(nodes: list[dict]) -> list[dict]:
    """按 (type, server, port) 去重；重名 tag 自动追加序号。"""
    seen_key, seen_tag, out = set(), {}, []
    for ob in nodes:
        key = (ob["type"], ob.get("server"), ob.get("server_port"))
        if key in seen_key:
            continue
        seen_key.add(key)
        tag = ob.get("tag") or ob["type"]
        n = seen_tag.get(tag, 0)
        seen_tag[tag] = n + 1
        if n > 0:
            tag = f"{tag} #{n + 1}"
        ob["tag"] = tag
        out.append(ob)
    return out


# ---------- 配置生成 ----------

def build_config(nodes: list[dict], old: dict | None) -> dict:
    """以旧配置为基础（保留 log/dns/inbounds/route/experimental），重建 outbounds。"""
    base = json.loads(json.dumps(old)) if old else {}
    node_tags = [n["tag"] for n in nodes]
    outbounds = [
        {"type": "direct", "tag": "DIRECT"},
        {"type": "block", "tag": "REJECT"},
        *nodes,
        {"type": "urltest", "tag": "♻️自动选择", "url": "http://cp.cloudflare.com/generate_204",
         "interrupt_exist_connections": False, "outbounds": node_tags},
        {"type": "selector", "tag": "🚀节点选择", "interrupt_exist_connections": True,
         "outbounds": ["♻️自动选择", *node_tags]},
    ]
    cfg = {
        "log": base.get("log", {"level": "info", "timestamp": True}),
        "dns": base.get("dns") or {
            "servers": [{"tag": "dns-remote", "address": "https://1.1.1.1/dns-query",
                         "detour": "🚀节点选择"}],
            "final": "dns-remote",
        },
        "inbounds": base.get("inbounds") or [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 9090}],
        "outbounds": outbounds,
        "route": base.get("route") or {
            "rules": [
                {"inbound": "mixed-in", "action": "sniff"},
                {"ip_is_private": True, "outbound": "direct"},
                {"protocol": "dns", "outbound": "dns-out"},
            ],
            "final": "🚀节点选择",
        },
        "experimental": base.get("experimental") or {
            "cache_file": {"enabled": True},
            "clash_api": {"external_controller": "127.0.0.1:9091"},
        },
    }
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser(description="订阅更新器：拉取订阅并生成 sing-box 配置")
    ap.add_argument("--check", action="store_true", help="仅下载解析并统计，不写文件")
    ap.add_argument("--url", type=str, default=None, help="临时指定订阅 URL（覆盖 sub 文件）")
    ap.add_argument("--out", type=Path, default=None, help="输出路径（默认 singbox-config.json）")
    ap.add_argument("--dry-run", action="store_true", help="打印节点清单，不写文件")
    ap.add_argument("--quiet", action="store_true", help="减少输出")
    args = ap.parse_args()

    out_path = args.out or OUT_FILE
    try:
        urls = [args.url] if args.url else read_sub_urls(SUB_FILE)
        all_nodes: list[dict] = []
        per_url = []
        for url in urls:
            if not args.quiet:
                print(f"[sub] 下载订阅：{url}")
            text = load_subscription_text(url)
            # 识别 sing-box JSON
            if text.lstrip().startswith("{"):
                try:
                    data = json.loads(text)
                    nodes = extract_nodes_from_json(data)
                    src = "json"
                except json.JSONDecodeError:
                    nodes, src = parse_shares(text), "shares"
            else:
                nodes, src = parse_shares(text), "shares"
            if not nodes:
                print(f"[sub] ⚠️ {url} 未解析出节点（格式：{src}）")
            per_url.append((url, src, len(nodes)))
            all_nodes.extend(nodes)

        nodes = dedup_and_name(all_nodes)
        type_stat: dict[str, int] = {}
        for n in nodes:
            type_stat[n["type"]] = type_stat.get(n["type"], 0) + 1

        print(f"[sub] 解析完成：{len(nodes)} 个节点（去重后）")
        print("[sub] 类型分布: " + ", ".join(f"{k}×{v}" for k, v in sorted(type_stat.items())))
        for url, src, n in per_url:
            print(f"[sub]   {url}  -> {n} 个（{src}）" if not args.quiet else "")

        if args.check or args.dry_run:
            if args.dry_run:
                print("\n[sub] 节点清单（--dry-run，未写文件）：")
                for n in nodes:
                    print(f"  · [{n['type']}] {n['tag']}  {n['server']}:{n['server_port']}")
            return 0

        # 读取旧配置做基础
        old = None
        if out_path.is_file():
            try:
                old = json.loads(out_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                eprint(f"[sub] 警告：旧配置 {out_path} 解析失败，将以默认结构生成")

        cfg = build_config(nodes, old)
        # 备份旧文件
        if out_path.is_file():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            bak = out_path.with_name(out_path.name + f".bak-{ts}")
            import shutil
            shutil.copy2(out_path, bak)
            print(f"[sub] 已备份旧配置 -> {bak.name}")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[sub] 完成：{out_path}（{len(nodes)} 个节点 + 自动选择/节点选择）")
        return 0
    except Exception as e:
        eprint(f"[sub] 错误：{e}")
        return 1
    except KeyboardInterrupt:
        eprint("[sub] 已取消")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
