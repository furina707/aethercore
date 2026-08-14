//! 内置 Web 控制台（程序 UI）：极简 HTTP 服务，零第三方 Web 框架依赖。
//!
//! 提供：
//!   - `GET /`            内嵌的现代 HTML 控制台（玻璃拟态 UI，含明暗主题）
//!   - `GET /api/status`  实时 JSON：统计快照 / 出站链路统计与健康 / 监听器 /
//!                        路由规则 / 配置概览
//!
//! 端口默认 `127.0.0.1:9090`，可用环境变量 `OMNI_WEBUI_PORT` 覆盖。
//! 控制台前端每 2 秒轮询一次 `/api/status` 刷新数据。
use crate::config::{ListenerProtocol, MatchMode, OutboundProtocol};
use crate::observe::{OutboundCounters, Stats};
use crate::state::ProxyState;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_PORT: u16 = 9090;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// 启动 Web 控制台服务（后台任务，不阻塞）。
pub fn spawn(state: Arc<ProxyState>, stats: Arc<Stats>) {
    tokio::spawn(async move {
        let port = std::env::var("OMNI_WEBUI_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);
        let bind = format!("127.0.0.1:{}", port);
        let listener = match TcpListener::bind(&bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(bind = %bind, error = ?e, "Web 控制台启动失败（端口被占用或不可用）");
                return;
            }
        };
        tracing::info!(bind = %bind, "Web 控制台已启动，浏览器打开 http://{bind}");
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let state = state.clone();
            let stats = stats.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(sock, &state, &stats).await {
                    tracing::debug!(error = ?e, "webui 连接处理失败");
                }
            });
        }
    });
}

/// 处理单个 HTTP 连接：读请求行 + 头，按路径返回 HTML 或 JSON。
async fn handle_conn(mut sock: TcpStream, state: &Arc<ProxyState>, stats: &Arc<Stats>) -> Result<()> {
    let mut reader = BufReader::new(sock);

    let mut request_line = String::new();
    tokio::time::timeout(REQUEST_TIMEOUT, reader.read_line(&mut request_line)).await??;
    let request_line = request_line.trim();
    if request_line.is_empty() {
        return Ok(());
    }

    // 读完请求头直到空行（GET 无请求体）
    loop {
        let mut line = String::new();
        tokio::time::timeout(REQUEST_TIMEOUT, reader.read_line(&mut line)).await??;
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");

    let (code, reason, ctype, body) = match path {
        "/api/status" => {
            ("200", "OK", "application/json; charset=utf-8", build_status_json(state, stats).await)
        }
        "/" | "/index.html" => ("200", "OK", "text/html; charset=utf-8", INDEX_HTML.to_string()),
        _ => ("404", "Not Found", "text/plain; charset=utf-8", "404 Not Found".to_string()),
    };

    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let mut writer = reader.into_inner();
    writer.write_all(resp.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// 组装 /api/status 的 JSON。
async fn build_status_json(state: &Arc<ProxyState>, stats: &Arc<Stats>) -> String {
    let cfg = state.config();
    let snap = stats.snapshot();
    let health = state.get_health().await;
    let per: HashMap<String, OutboundCounters> = stats.outbound_snapshot().into_iter().collect();

    let outbounds: Vec<serde_json::Value> = cfg
        .outbounds
        .iter()
        .map(|ob| {
            let h = health.get(&ob.name).copied().unwrap_or_default();
            let c = per.get(&ob.name).cloned().unwrap_or_default();
            json!({
                "name": ob.name,
                "protocol": outbound_protocol_str(&ob.protocol),
                "target": ob.target,
                "alive": h.alive,
                "failures": h.consecutive_failures,
                "last_checked_secs": h.last_checked.map(|i| i.elapsed().as_secs()),
                "connections": c.connections,
                "active": c.active,
                "errors": c.errors,
                "bytes_up": c.bytes_up,
                "bytes_down": c.bytes_down,
            })
        })
        .collect();

    let listeners: Vec<serde_json::Value> = cfg
        .server
        .listeners
        .iter()
        .map(|l| {
            json!({
                "protocol": listener_protocol_str(&l.protocol),
                "bind": l.bind,
            })
        })
        .collect();

    let routes: Vec<serde_json::Value> = cfg
        .routing
        .iter()
        .map(|r| {
            json!({
                "name": r.name.clone().unwrap_or_else(|| "(未命名)".into()),
                "domain_suffix": r.domain_suffix,
                "ip_cidr": r.ip_cidr,
                "port": r.port,
                "match_mode": match_mode_str(&r.match_mode),
                "outbound": r.outbound,
            })
        })
        .collect();

    let payload = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "stats": {
            "total_connections": snap.total_connections,
            "active_connections": snap.active_connections,
            "bytes_in": snap.bytes_in,
            "bytes_out": snap.bytes_out,
            "bytes_in_human": snap.bytes_in_human,
            "bytes_out_human": snap.bytes_out_human,
            "errors": snap.errors,
            "uptime_secs": snap.uptime_secs,
        },
        "outbounds": outbounds,
        "listeners": listeners,
        "routes": routes,
        "config": {
            "hot_reload_secs": cfg.hot_reload_secs,
            "health_check_enabled": cfg.health_check.is_some(),
            "log_level": cfg.observability.log_level,
            "stats_interval_secs": cfg.observability.stats_interval_secs,
            "idle_timeout_secs": cfg.observability.idle_timeout_secs,
        },
    });
    payload.to_string()
}

// ---------- enum → 展示字符串 ----------

pub fn listener_protocol_str(p: &ListenerProtocol) -> &'static str {
    match p {
        ListenerProtocol::Tcp => "tcp",
        ListenerProtocol::Udp => "udp",
        ListenerProtocol::Http => "http",
        ListenerProtocol::Https => "https",
        ListenerProtocol::Socks => "socks",
        ListenerProtocol::Dns => "dns",
    }
}

pub fn outbound_protocol_str(p: &OutboundProtocol) -> &'static str {
    match p {
        OutboundProtocol::Direct => "direct",
        OutboundProtocol::Socks5 => "socks5",
        OutboundProtocol::HttpProxy => "httpproxy",
        OutboundProtocol::Shadowsocks => "shadowsocks",
        OutboundProtocol::Vmess => "vmess",
    }
}

pub fn match_mode_str(m: &MatchMode) -> &'static str {
    match m {
        MatchMode::Any => "any",
        MatchMode::All => "all",
    }
}

// ---------- 内嵌控制台 HTML ----------

const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>omni-proxy 控制台</title>
<style>
:root{
  --bg0:#0a0e16; --bg1:#10182a; --ink:#e9edf7; --sub:#94a1bb;
  --line:rgba(255,255,255,.09); --card:rgba(255,255,255,.045);
  --card-strong:rgba(255,255,255,.08); --codebg:#0c1220;
  --indigo:#818cf8; --violet:#a78bfa; --cyan:#22d3ee;
  --green:#34d399; --amber:#fbbf24; --red:#f87171;
  --glow-a:rgba(99,102,241,.20); --glow-b:rgba(34,211,238,.12);
  --shadow:0 10px 34px rgba(2,6,18,.45);
}
@media (prefers-color-scheme: light){
  :root{
    --bg0:#f3f5fb; --bg1:#e9edf8; --ink:#151a28; --sub:#5a6784;
    --line:rgba(20,30,60,.10); --card:rgba(255,255,255,.72);
    --card-strong:rgba(255,255,255,.95); --codebg:#10162a;
    --indigo:#4f5de0; --violet:#7c5cf0; --cyan:#0891b2;
    --green:#059669; --amber:#b45309; --red:#dc2626;
    --glow-a:rgba(99,102,241,.14); --glow-b:rgba(8,145,178,.10);
    --shadow:0 10px 30px rgba(30,45,90,.12);
  }
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;color:var(--ink);
  font-family:Inter,"Segoe UI",-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
  line-height:1.65;min-height:100vh;
  background:
    radial-gradient(900px 480px at 12% -8%, var(--glow-a), transparent 60%),
    radial-gradient(820px 460px at 95% 0%, var(--glow-b), transparent 55%),
    linear-gradient(168deg, var(--bg0), var(--bg1));
  background-attachment:fixed;padding:26px 18px}
.wrap{max-width:1060px;margin:0 auto}
.hero{padding:22px 24px;margin-bottom:20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.logo{width:42px;height:42px;border-radius:12px;flex:none;
  background:linear-gradient(135deg,var(--indigo),var(--violet));
  display:flex;align-items:center;justify-content:center;font-weight:800;font-size:17px;color:#fff;
  box-shadow:0 8px 22px var(--glow-a)}
h1{font-size:21px;margin:0;letter-spacing:.3px}
.sub{color:var(--sub);font-size:12.5px;margin-top:2px}
.badge{margin-left:auto;display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:999px;
  font-size:13px;font-weight:600;border:1px solid var(--line);background:var(--card)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);
  animation:pulse 1.6s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;
  margin-bottom:16px;box-shadow:var(--shadow);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  animation:rise .5s ease both;transition:transform .2s ease,border-color .2s ease}
.card:hover{transform:translateY(-2px);border-color:var(--card-strong)}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
h2{font-size:15.5px;margin:0 0 14px;padding:0 0 10px 12px;position:relative;letter-spacing:.2px}
h2::before{content:"";position:absolute;left:0;top:2px;bottom:12px;width:4px;border-radius:4px;
  background:linear-gradient(180deg,var(--indigo),var(--cyan))}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 15px;
  transition:transform .18s ease,border-color .18s ease}
.kpi:hover{transform:translateY(-2px);border-color:var(--card-strong)}
.kpi .v{font-size:22px;font-weight:800;letter-spacing:.2px;
  background:linear-gradient(92deg,var(--indigo),var(--cyan));
  -webkit-background-clip:text;background-clip:text;color:transparent}
.kpi .l{font-size:11.5px;color:var(--sub);margin-top:2px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media (max-width:760px){.two{grid-template-columns:1fr}}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;
  border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:8px 11px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:none}
th{color:var(--sub);font-weight:600;font-size:11.5px;
  background:linear-gradient(180deg,var(--card-strong),transparent)}
tbody tr{transition:background .15s ease}
tbody tr:hover{background:var(--card-strong)}
.hl{display:inline-flex;align-items:center;gap:6px}
.hl .dot{width:8px;height:8px;animation:none}
.ok{color:var(--green);font-weight:600}
.bad{color:var(--red);font-weight:600}
code{background:var(--codebg);padding:1px 7px;border-radius:6px;font-size:12px;border:1px solid var(--line)}
.muted{color:var(--sub);font-size:12px}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;
  border:1px solid var(--line);background:var(--card);margin:1px 3px 1px 0}
.empty{color:var(--sub);font-size:13px;padding:6px 2px}
::selection{background:rgba(129,140,248,.35)}
</style>
</head>
<body>
<div class="wrap">
  <header class="card hero">
    <div class="logo">om</div>
    <div>
      <h1>omni-proxy 控制台</h1>
      <div class="sub" id="sub">加载中…</div>
    </div>
    <div class="badge"><span class="dot"></span><span id="statusText">运行中</span></div>
  </header>

  <section class="card" style="animation-delay:60ms">
    <h2>实时统计</h2>
    <div class="grid" id="kpis"></div>
  </section>

  <section class="card" style="animation-delay:120ms">
    <h2>出站链路</h2>
    <table><thead><tr>
      <th>名称</th><th>协议</th><th>目标</th><th>健康</th>
      <th>连接</th><th>活跃</th><th>错误</th><th>↑ 上传</th><th>↓ 下载</th>
    </tr></thead><tbody id="outbounds"></tbody></table>
  </section>

  <div class="two">
    <section class="card" style="animation-delay:180ms">
      <h2>监听器</h2>
      <table><thead><tr><th>协议</th><th>绑定地址</th></tr></thead>
      <tbody id="listeners"></tbody></table>
    </section>
    <section class="card" style="animation-delay:240ms">
      <h2>配置</h2>
      <div id="config"></div>
    </section>
  </div>

  <section class="card" style="animation-delay:300ms">
    <h2>路由规则</h2>
    <table><thead><tr>
      <th>名称</th><th>匹配</th><th>模式</th><th>出口</th>
    </tr></thead><tbody id="routes"></tbody></table>
  </section>
</div>

<script>
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
function fmtBytes(b){b=Number(b)||0;
  if(b<1024)return b+" B";
  var u=["KB","MB","GB","TB"],i=-1;
  do{b/=1024;i++;}while(b>=1024&&i<u.length-1);
  return b.toFixed(2)+" "+u[i];}
function fmtUptime(s){s=Number(s)||0;var h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;
  return (h<10?"0":"")+h+":"+(m<10?"0":"")+m+":"+(x<10?"0":"")+x;}
function kpi(label,value){return '<div class="kpi"><div class="v">'+value+'</div><div class="l">'+esc(label)+'</div></div>';}

function render(d){
  document.getElementById("sub").textContent =
    "v"+d.version+" · 轮询刷新（2s）· 配置热重载 "+(d.config.hot_reload_secs? d.config.hot_reload_secs+"s":"关闭")+
    " · 健康检查 "+(d.config.health_check_enabled?"开启":"关闭")+" · 日志级别 "+esc(d.config.log_level);
  var st=d.stats;
  document.getElementById("kpis").innerHTML=
    kpi("总连接",st.total_connections)+
    kpi("活跃连接",st.active_connections)+
    kpi("上传",st.bytes_in_human)+
    kpi("下载",st.bytes_out_human)+
    kpi("错误",st.errors)+
    kpi("运行时长",fmtUptime(st.uptime_secs));

  document.getElementById("outbounds").innerHTML=d.outbounds.map(function(o){
    var h='<span class="hl"><span class="dot" style="background:'+(o.alive?"var(--green)":"var(--red)")+
      ';box-shadow:none"></span>'+(o.alive?'<span class="ok">正常</span>':'<span class="bad">失效×'+o.failures+"</span>")+"</span>";
    return "<tr><td><b>"+esc(o.name)+"</b></td><td><code>"+esc(o.protocol)+"</code></td><td>"+esc(o.target)+
      "</td><td>"+h+"</td><td>"+o.connections+"</td><td>"+o.active+"</td><td>"+o.errors+
      "</td><td>"+fmtBytes(o.bytes_up)+"</td><td>"+fmtBytes(o.bytes_down)+"</td></tr>";
  }).join("") || '<tr><td colspan="9" class="empty">暂无出站链路</td></tr>';

  document.getElementById("listeners").innerHTML=d.listeners.map(function(l){
    return "<tr><td><code>"+esc(l.protocol)+"</code></td><td>"+esc(l.bind)+"</td></tr>";
  }).join("") || '<tr><td colspan="2" class="empty">暂无监听器</td></tr>';

  var c=d.config;
  document.getElementById("config").innerHTML=
    '<div class="muted">统计周期</div><div style="margin:2px 0 10px">'+(c.stats_interval_secs||"—")+"s</div>"+
    '<div class="muted">空闲超时</div><div style="margin:2px 0 10px">'+(c.idle_timeout_secs||"—")+"s</div>"+
    '<div class="muted">出站链路</div><div style="margin-top:2px">'+d.outbounds.length+" 条</div>";

  document.getElementById("routes").innerHTML=d.routes.map(function(r){
    var parts=[];
    if(r.domain_suffix&&r.domain_suffix.length)parts.push(r.domain_suffix.map(function(x){return '<span class="chip">'+esc(x)+"</span>";}).join(""));
    if(r.ip_cidr&&r.ip_cidr.length)parts.push(r.ip_cidr.map(function(x){return '<span class="chip">'+esc(x)+"</span>";}).join(""));
    if(r.port&&r.port.length)parts.push('<span class="chip">端口 '+esc(r.port.join(","))+"</span>");
    return "<tr><td><b>"+esc(r.name)+"</b></td><td>"+(parts.join(" ")||'<span class="empty">全量</span>')+
      "</td><td><code>"+esc(r.match_mode)+"</code></td><td>"+esc(r.outbound)+"</td></tr>";
  }).join("") || '<tr><td colspan="4" class="empty">暂无路由规则</td></tr>';
}

async function tick(){
  try{
    var r=await fetch("/api/status");
    var d=await r.json();
    render(d);
    document.getElementById("statusText").textContent="运行中";
  }catch(e){
    document.getElementById("statusText").textContent="连接中断";
  }
}
tick();
setInterval(tick,2000);
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_str_mapping() {
        assert_eq!(listener_protocol_str(&ListenerProtocol::Http), "http");
        assert_eq!(listener_protocol_str(&ListenerProtocol::Socks), "socks");
        assert_eq!(outbound_protocol_str(&OutboundProtocol::Direct), "direct");
        assert_eq!(outbound_protocol_str(&OutboundProtocol::Shadowsocks), "shadowsocks");
        assert_eq!(match_mode_str(&MatchMode::All), "all");
    }

    #[test]
    fn index_html_contains_key_sections() {
        assert!(INDEX_HTML.contains("omni-proxy 控制台"));
        assert!(INDEX_HTML.contains("/api/status"));
        assert!(INDEX_HTML.contains("id=\"outbounds\""));
        assert!(INDEX_HTML.contains("setInterval"));
    }
}
