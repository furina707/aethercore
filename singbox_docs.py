#!/usr/bin/env python3
"""singbox_docs.py — 抓取 sing-box 官方配置要求，生成独立的 HTML 界面（singbox-docs.html）。

特性：
  - 在线抓取官方文档站（https://sing-box.sagernet.org/configuration/）的
    配置总览 / Log / DNS / Inbound / Outbound / Route / Experimental 页面
  - 用 HTMLParser 白名单提取 <article> 正文（保留标题/表格/代码块/链接），
    组装成带目录、来源标注与抓取时间的独立界面
  - 网络不可达 / 单页失败时自动降级：整站失败则展示内置的官方配置结构快照，
    单页失败则在该页给出官方链接占位
  - 界面 CSS 支持明/暗主题（跟随系统 prefers-color-scheme）

用法：
  python singbox_docs.py                # 在线抓取生成界面（失败自动降级）
  python singbox_docs.py --offline      # 强制离线，仅用内置快照
  python singbox_docs.py --out out.html # 指定输出路径（默认 ./singbox-docs.html）

仅依赖 Python 标准库，无第三方包。
"""
import argparse
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from html import escape
from html.parser import HTMLParser
from pathlib import Path

SITE = "https://sing-box.sagernet.org"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) singbox-docs/1.0"

# (id, 标题, 官方页面路径)
PAGES = [
    ("configuration", "配置总览 Configuration", "/configuration/"),
    ("log", "Log 日志", "/configuration/log/"),
    ("dns", "DNS 域名解析", "/configuration/dns/"),
    ("inbound", "Inbound 入站", "/configuration/inbound/"),
    ("outbound", "Outbound 出站", "/configuration/outbound/"),
    ("route", "Route 路由", "/configuration/route/"),
    ("experimental", "Experimental 实验性", "/configuration/experimental/"),
]

# 内置快照：官方配置结构（离线/整站抓取失败时兜底）
SNAPSHOT_STRUCTURE = {
    "json": """{
  "$schema": "https://sing-box.sagernet.org/schema.json",
  "log": {},
  "dns": {},
  "ntp": {},
  "certificate": {},
  "certificate_providers": [],
  "http_clients": [],
  "network_namespaces": [],
  "endpoints": [],
  "inbounds": [],
  "outbounds": [],
  "route": {},
  "services": [],
  "experimental": {}
}""",
    "fields": [
        ("$schema", "JSON Schema", "https://sing-box.sagernet.org/configuration/schema/"),
        ("log", "日志设置", "https://sing-box.sagernet.org/configuration/log/"),
        ("dns", "DNS 解析设置", "https://sing-box.sagernet.org/configuration/dns/"),
        ("ntp", "NTP 时间同步", "https://sing-box.sagernet.org/configuration/ntp/"),
        ("certificate", "证书配置", "https://sing-box.sagernet.org/configuration/certificate/"),
        ("certificate_providers", "证书提供方", "https://sing-box.sagernet.org/configuration/shared/certificate-provider/"),
        ("http_clients", "HTTP 客户端", "https://sing-box.sagernet.org/configuration/shared/http-client/"),
        ("network_namespaces", "网络命名空间", "https://sing-box.sagernet.org/configuration/network-namespace/"),
        ("endpoints", "端点（TUN 等）", "https://sing-box.sagernet.org/configuration/endpoint/"),
        ("inbounds", "入站协议", "https://sing-box.sagernet.org/configuration/inbound/"),
        ("outbounds", "出站协议", "https://sing-box.sagernet.org/configuration/outbound/"),
        ("route", "路由规则", "https://sing-box.sagernet.org/configuration/route/"),
        ("services", "服务", "https://sing-box.sagernet.org/configuration/service/"),
        ("experimental", "实验性功能", "https://sing-box.sagernet.org/configuration/experimental/"),
    ],
    "commands": [
        ("校验配置", "sing-box check -c config.json"),
        ("格式化配置", "sing-box format -w -c config.json -D config_directory"),
        ("合并配置", "sing-box merge output.json -c config.json -D config_directory"),
    ],
}


def now_beijing() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")


# ---------- 正文提取（HTMLParser 白名单） ----------

_IGNORE_TAGS = {
    "script", "style", "nav", "header", "footer", "form", "input", "button",
    "select", "option", "template", "iframe", "noscript", "svg", "img", "video",
}
_ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li", "pre", "code",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "blockquote",
    "strong", "b", "em", "i", "a", "br", "hr", "div", "span", "dl", "dt", "dd",
}
_BLOCK_TAGS = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "ul", "ol",
               "table", "blockquote", "hr", "div", "dl"}


class ArticleExtractor(HTMLParser):
    """从 <article> 片段中提取白名单 HTML。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip = 0          # 忽略标签深度
        self.out: list[str] = []
        self.heading = ""      # 页面首个 h1（作为页面标题）
        self._in_h1 = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.skip:
            self.skip += 1
            return
        if tag in _IGNORE_TAGS:
            self.skip = 1
            return
        if tag not in _ALLOWED_TAGS:
            return
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            href = attrs["href"]
            if href.startswith("/"):
                href = SITE + href
            self.out.append(f'<a href="{escape(href, quote=True)}">')
        elif tag == "code" and attrs.get("class"):
            self.out.append(f'<code class="{escape(attrs["class"], quote=True)}">')
        else:
            self.out.append(f"<{tag}>")
        if tag == "h1":
            self._in_h1 = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip:
            self.skip -= 1
            return
        if tag in _IGNORE_TAGS or tag not in _ALLOWED_TAGS:
            return
        self.out.append(f"</{tag}>")
        if tag in _BLOCK_TAGS:
            self.out.append("\n")
        if tag == "h1":
            self._in_h1 = False

    def handle_data(self, data):
        if self.skip:
            return
        if self._in_h1:
            self.heading = re.sub(r"\s+", " ", data).strip()
            # 首标题不作为正文输出
            return
        if data.strip():
            self.out.append(escape(data))

    def result(self) -> tuple[str, str]:
        html = "".join(self.out)
        html = re.sub(r"[ \t]+", " ", html)
        html = re.sub(r"\n{3,}", "\n\n", html)
        return self.heading, html.strip()


def extract_article(html: str) -> tuple[str, str]:
    m = re.search(r"<article[^>]*>(.*?)</article>", html, re.S)
    if not m:
        raise RuntimeError("页面中未找到 <article> 正文容器")
    p = ArticleExtractor()
    p.feed(m.group(1))
    return p.result()


def fetch_page(path: str) -> str:
    req = urllib.request.Request(SITE + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read().decode("utf-8", "ignore")


# ---------- 组装 HTML ----------

_CSS = """
:root{
  --bg:#f7f8fa; --card:#ffffff; --ink:#1f2430; --sub:#5b6472;
  --line:#e6e9ef; --green:#1a9e6f; --amber:#d98a00; --red:#d2433a;
  --blue:#2f6fed; --codebg:#eef1f6; --bar:#eef1f6;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#14161c; --card:#1e222b; --ink:#e6e9f0; --sub:#9aa3b2;
    --line:#2d333f; --green:#3ecf8e; --amber:#e8a33d; --red:#ef6b60;
    --blue:#6f9dff; --codebg:#262c37; --bar:#262c37;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  line-height:1.65;padding:28px 16px}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}
.sub{color:var(--sub);font-size:13.5px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
  padding:18px 20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(20,30,50,.05)}
h2{font-size:17px;margin:0 0 12px;padding-left:10px;border-left:4px solid var(--blue)}
h3{font-size:15px;margin:16px 0 8px}
h4{font-size:14px;margin:12px 0 6px}
.toc{display:flex;flex-wrap:wrap;gap:8px}
.toc a{display:inline-block;padding:4px 12px;border:1px solid var(--line);
  border-radius:20px;font-size:13px;color:var(--ink);text-decoration:none;background:var(--bg)}
.toc a:hover{border-color:var(--blue);color:var(--blue)}
.body{font-size:14px}
.body pre{background:var(--codebg);border:1px solid var(--line);border-radius:8px;
  padding:12px 14px;overflow-x:auto;font-size:12.5px}
.body code{background:var(--codebg);padding:1px 6px;border-radius:5px;font-size:12.5px}
.body pre code{background:none;padding:0}
.body table{width:100%;border-collapse:collapse;font-size:13px;margin:10px 0}
.body th,.body td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.body th{color:var(--sub);font-size:12px;background:var(--bg)}
.body a{color:var(--blue)}
.warn{background:rgba(217,138,0,.12);border-left:4px solid var(--amber);
  padding:10px 14px;border-radius:8px;margin:8px 0;font-size:13.5px}
.ok{background:rgba(26,158,111,.12);border-left:4px solid var(--green);
  padding:10px 14px;border-radius:8px;margin:8px 0;font-size:13.5px}
.muted{color:var(--sub);font-size:12.5px}
"""


def build_html(sections: list[dict], fetched: bool, offline: bool, generated: str) -> str:
    toc = "\n".join(
        f'<a href="#sec-{s["id"]}">{escape(s["title"])}</a>' for s in sections
    )
    body = []
    for s in sections:
        inner = s["content"]
        if s.get("failed"):
            inner = (
                f'<div class="warn"><b>该页在线抓取失败</b>（网络不可达或页面结构变化）。'
                f'请访问官方文档：<a href="{s["url"]}">{s["url"]}</a></div>'
            )
        body.append(
            f'<section class="card" id="sec-{s["id"]}">\n'
            f'  <h2>{escape(s["title"])}</h2>\n'
            f'  <div class="body">{inner}</div>\n'
            f'  <div class="muted" style="margin-top:10px">来源：<a href="{s["url"]}">{s["url"]}</a></div>\n'
            f"</section>"
        )

    status = []
    if offline:
        status.append('<span class="tag" style="color:var(--amber)">离线快照</span>')
    elif fetched:
        status.append('<span style="color:var(--green)">已在线抓取官方文档</span>')
    else:
        status.append('<span style="color:var(--amber)">在线抓取失败，展示内置结构快照</span>')

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>sing-box 官方配置要求</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>sing-box 官方配置要求</h1>
    <div class="sub">
      抓取自 <a href="{SITE}/configuration/">{SITE}/configuration/</a> · 生成时间 {generated} ·
      {" ".join(status)}
    </div>
    <div class="toc">{toc}</div>
  </div>
  {"\n".join(body)}
  <div class="muted" style="text-align:center;margin-top:8px">
    本界面由 singbox_docs.py 抓取官方文档生成；以官方站点为准，必要时运行
    <code>python singbox_docs.py</code> 重新抓取。
  </div>
</div>
</body>
</html>
"""


def snapshot_section() -> dict:
    """内置的官方配置结构快照。"""
    rows = "\n".join(
        f"<tr><td><code>{escape(k)}</code></td><td>{escape(d)}</td>"
        f'<td><a href="{u}">文档</a></td></tr>'
        for k, d, u in SNAPSHOT_STRUCTURE["fields"]
    )
    cmds = "\n".join(
        f"<li><b>{escape(n)}</b>：<code>{escape(c)}</code></li>"
        for n, c in SNAPSHOT_STRUCTURE["commands"]
    )
    content = (
        "<p>sing-box 使用 <b>JSON</b> 格式配置文件。以下为官方顶层结构：</p>"
        f"<pre><code>{escape(SNAPSHOT_STRUCTURE['json'])}</code></pre>"
        "<table><tr><th>顶层字段</th><th>说明</th><th>官方文档</th></tr>"
        f"{rows}</table>"
        "<h3>配置相关命令</h3>"
        f"<ul>{cmds}</ul>"
    )
    return {"id": "configuration", "title": "配置总览 Configuration（内置快照）",
            "url": SITE + "/configuration/", "content": content, "failed": False}


def main() -> int:
    ap = argparse.ArgumentParser(description="抓取 sing-box 官方配置要求并生成独立 HTML 界面")
    ap.add_argument("--offline", action="store_true", help="强制离线：仅用内置快照")
    ap.add_argument("--out", type=Path, default=None, help="输出路径（默认 ./singbox-docs.html）")
    ap.add_argument("--quiet", action="store_true", help="减少输出")
    args = ap.parse_args()

    out_path = args.out or (Path(__file__).resolve().parent / "singbox-docs.html")
    generated = now_beijing()

    if args.offline:
        sections = [snapshot_section()]
        out_html = build_html(sections, fetched=False, offline=True, generated=generated)
        out_path.write_text(out_html, encoding="utf-8")
        if not args.quiet:
            print(f"[docs] 已生成离线快照界面：{out_path}")
        return 0

    sections = []
    fetched_any = False
    for pid, title, path in PAGES:
        url = SITE + path
        try:
            heading, content = extract_article(fetch_page(path))
            if not content.strip():
                raise RuntimeError("正文为空")
            fetched_any = True
            if not args.quiet:
                print(f"[docs] ✓ {title}（{len(content)} 字符）")
            sections.append({"id": pid, "title": title, "url": url,
                             "content": content, "failed": False})
        except Exception as e:
            if not args.quiet:
                print(f"[docs] ✗ {title}：{e}")
            sections.append({"id": pid, "title": title, "url": url,
                             "content": "", "failed": True})

    if not fetched_any:
        # 整站抓取失败 → 内置快照兜底
        sections = [snapshot_section()]

    out_html = build_html(sections, fetched=fetched_any, offline=False, generated=generated)
    out_path.write_text(out_html, encoding="utf-8")
    if not args.quiet:
        print(f"[docs] 完成：{out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
