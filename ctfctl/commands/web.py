"""web —— WebUI 工作台（纯标准库，键盘驱动）。

    ctfctl            # 默认就是它：起本地服务 + 开浏览器
    ctfctl web [--port 8778] [--host 127.0.0.1] [--no-open] [--token T]
    ctfctl web --host 0.0.0.0     # 想给别的设备看（Tailscale 等）：必须带 token，会打印带 token 的地址

设计：浏览器只负责画，逻辑全在 core/workbench.py（与 TUI 同一个引擎）。
默认只监听回环地址；一旦监听非回环就强制 token 校验，并且每个请求都要带对。
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import __version__
from ..core import browse as browse_mod
from ..core import workbench as wb

LOOPBACK = ("127.0.0.1", "::1", "localhost")
LOG: list[str] = []
LOCK = threading.Lock()
STATE = {"target": "", "actions": [], "kind": ""}

PAGE = r"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>ctfctl 工作台</title>
<style>
 :root{--bg:#0f1115;--fg:#e6e6e6;--dim:#8b93a1;--acc:#4ea1ff;--ok:#3ddc84;--warn:#ffb454;--pane:#171a21}
 *{box-sizing:border-box}
 body{margin:0;font:14px/1.5 -apple-system,"Noto Sans CJK SC","Microsoft YaHei",system-ui,sans-serif;background:var(--bg);color:var(--fg);height:100vh;display:flex;flex-direction:column}
 header{display:flex;gap:8px;align-items:center;padding:8px 12px;background:var(--pane);border-bottom:1px solid #232833}
 header .title{color:var(--acc);font-weight:600;white-space:nowrap}
 input,button,select{font:inherit;background:#0d1017;color:var(--fg);border:1px solid #2a3040;border-radius:6px;padding:6px 10px}
 input#target{flex:1;min-width:220px}
 button{cursor:pointer}button:hover{border-color:var(--acc)}
 button.primary{background:#123054;border-color:#2b6cb0}
 main{flex:1;display:grid;grid-template-columns:1fr 1fr;gap:0;min-height:0}
 section{display:flex;flex-direction:column;min-width:0;border-right:1px solid #232833}
 section:last-child{border-right:none}
 .panehead{padding:6px 10px;background:#141821;color:var(--dim);border-bottom:1px solid #232833;display:flex;gap:10px;align-items:center}
 .pane{flex:1;overflow:auto;padding:8px 10px;margin:0}
 pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,"JetBrains Mono",Menlo,monospace}
 .act{border-bottom:1px solid #1e2330;padding:6px 8px;cursor:pointer}
 .act:hover{background:#1b2130}
 .act.sel{background:#1d2b3f;outline:1px solid var(--acc)}
 .act .k{display:inline-block;min-width:18px;text-align:center;background:#243149;border-radius:4px;padding:0 4px;margin-right:6px;color:var(--acc)}
 .act .why{color:var(--dim);font-size:12px}
 .act code{color:var(--warn);font-size:12px;word-break:break-all}
 .row{display:flex;gap:8px;align-items:center}
 .row input{flex:1}
 footer{padding:6px 12px;background:var(--pane);border-top:1px solid #232833;color:var(--dim);font-size:12.5px;display:flex;gap:14px;flex-wrap:wrap}
 .tag{color:var(--ok)}.bad{color:#ff6b6b}
 .tabs button{padding:4px 10px;font-size:13px}
 .tabs button.on{border-color:var(--acc);color:var(--acc)}
 #browseDetail{flex:1;overflow:auto;padding:8px 10px}
</style></head><body>
<header>
  <span class="title">ctfctl 工作台</span>
  <input id="target" placeholder="目标：http://靶机/ 或 /path/附件.zip  （回车分析）" autocomplete="off">
  <button class="primary" onclick="analyze()">分析 (Enter)</button>
  <label style="color:var(--dim)"><input type="checkbox" id="full"> 完整清单</label>
  <span id="status" style="color:var(--dim)"></span>
</header>
<main>
  <section>
    <div class="panehead">输出 <span id="kind"></span></div>
    <pre class="pane" id="out">按 t 或点输入框填目标 → 回车分析。</pre>
  </section>
  <section>
    <div class="panehead tabs" id="tabs"></div>
    <div class="pane" id="work">
      <div id="actions" style="color:var(--dim)">分析后这里出现可执行动作（键盘 1-9 直接跑）</div>
    </div>
    <div id="browse" style="display:none;flex-direction:column;flex:1;min-height:0">
      <div class="row" style="padding:6px 10px"><input id="filter" placeholder="/ 过滤条目" oninput="renderBrowse()"></div>
      <div style="display:grid;grid-template-columns:1fr 1.2fr;flex:1;min-height:0">
        <div class="pane" id="browseList" style="border-right:1px solid #232833"></div>
        <div id="browseDetail"><pre id="browseBody"></pre></div>
      </div>
    </div>
  </section>
</main>
<footer>
  <span><b>1-9</b> 跑第 N 条动作</span><span><b>a</b> 目标框</span><span><b>r</b> 分析</span>
  <span><b>i</b> 自定义子命令</span><span><b>k/o/u/h/c</b> 知识库/工具/规则/历史/速查</span>
  <span><b>Esc</b> 回动作栏</span><span class="tag" id="ver">__VERSION__</span>
</footer>
<script>
const TOKEN="__TOKEN__";
let STATE={actions:[]},SEL=0,BROWSE=null,BITEMS=[],BSEL=0;
async function api(path, body){
  const r=await fetch(path,{method:body?"POST":"GET",headers:{"Content-Type":"application/json","X-Token":TOKEN},
    body:body?JSON.stringify(body):undefined});
  if(!r.ok) throw new Error(r.status+" "+r.statusText);
  return await r.json();
}
function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function show(out){document.getElementById("out").textContent=out||"";}
function append(out){const e=document.getElementById("out");e.textContent+=(out||"");}
function status(s,cls){const e=document.getElementById("status");e.textContent=s||"";e.className=cls||"";}
async function analyze(){
  const t=document.getElementById("target").value.trim();
  if(!t){status("先填目标：URL（http://…）或题目附件路径","bad");document.getElementById("target").focus();return;}
  localStorage.setItem("ctfctl.target",t);
  const t0=Date.now();
  status("分析中…（发真请求/读真文件，靶机侦察可能要几十秒）");
  const tick=setInterval(()=>status("分析中… "+((Date.now()-t0)/1000).toFixed(0)+"s（靶机侦察可能要几十秒）"),500);
  try{
    const d=await api("/api/analyze",{target:t,full:document.getElementById("full").checked});
    show(d.output); STATE.actions=d.actions||[]; SEL=0;
    document.getElementById("kind").textContent=d.kind?("["+d.kind+"]"):"";
    renderActions();
    status("完成："+STATE.actions.length+" 条可执行动作（"+((Date.now()-t0)/1000).toFixed(1)+"s）","tag");
  }catch(e){status("分析失败："+e.message,"bad");}
  finally{clearInterval(tick);}
}
function renderActions(){
  const box=document.getElementById("actions");
  if(!STATE.actions.length){box.innerHTML='<span style="color:var(--dim)">没有动作命中。换个目标，或看右侧栏目里的知识库/工具目录。</span>';return;}
  box.innerHTML=STATE.actions.map((a,i)=>`<div class="act ${i===SEL?'sel':''}" onclick="runAction(${i})">
     <div><span class="k">${i+1}</span>${esc(a.label)}</div>
     <div class="why">${esc(a.rule_name||"")} ${a.why?"· "+esc(a.why):""}</div>
     <code>${esc(a.render||"")}</code></div>`).join("");
  box.className="pane";
}
async function runAction(i){
  if(i<0||i>=STATE.actions.length)return;
  SEL=i; renderActions();
  const a=STATE.actions[i]; status("跑第 "+(i+1)+" 条…");
  try{
    const d=await api("/api/action",{index:i});
    append("\n$ "+a.render+"\n"+(d.output||"(无输出)")+(d.rc?"\n[rc="+d.rc+"]":""));
    status("完成 rc="+d.rc, d.rc?"bad":"tag");
  }catch(e){status("失败："+e.message,"bad");}
}
async function runCmd(v){
  if(!v.trim())return; append("\n$ ctfctl "+v+"\n");
  try{const d=await api("/api/run",{argv:v.split(/\s+/)});append(d.output||"(无输出)");status("rc="+d.rc,d.rc?"bad":"tag");}
  catch(e){status("失败："+e.message,"bad");}
}
async function openBrowse(sec){
  try{
    const d=await api("/api/browse?section="+sec);
    BROWSE=sec; BITEMS=d.items; BSEL=0;
    document.getElementById("work").style.display="none";
    const b=document.getElementById("browse"); b.style.display="flex";
    renderTabs(sec); renderBrowse(); pick(0);
    document.getElementById("filter").focus();
  }catch(e){status("栏目加载失败："+e.message,"bad");}
}
function closeBrowse(){BROWSE=null;document.getElementById("browse").style.display="none";
  document.getElementById("work").style.display="block";renderTabs("");document.getElementById("out").focus();}
function renderTabs(active){
  const tabs=[["kb","知识库"],["tools","工具目录"],["rules","规则"],["history","历史"],["cheat","速查"]];
  document.getElementById("tabs").innerHTML=tabs.map(([k,n])=>
    `<button class="${k===active?'on':''}" onclick="openBrowse('${k}')">${n}</button>`).join("")
    +(active?`<button onclick="closeBrowse()">回到动作</button>`:"");
}
function renderBrowse(){
  const f=(document.getElementById("filter").value||"").toLowerCase();
  BITEMS=BITEMS||[];
  const shown=BITEMS.filter(it=>!f||(it.title+it.key).toLowerCase().includes(f));
  document.getElementById("browseList").innerHTML=shown.map((it,i)=>
    `<div class="act ${i===BSEL?'sel':''}" onclick="pick(${i})">${esc(it.title)}</div>`).join("")
    ||'<span style="color:var(--dim)">（没有匹配）</span>';
  window.__shown=shown;
}
async function pick(i){
  const shown=window.__shown||BITEMS; if(!shown.length)return;
  BSEL=Math.max(0,Math.min(i,shown.length-1)); renderBrowse();
  try{
    const d=await api("/api/browse?section="+BROWSE+"&key="+encodeURIComponent(shown[BSEL].key));
    document.getElementById("browseBody").textContent=(d.body||[]).join("\n");
  }catch(e){document.getElementById("browseBody").textContent="加载失败："+e.message;}
}
document.getElementById("target").addEventListener("keydown",e=>{if(e.key==="Enter")analyze();});
document.getElementById("filter").addEventListener("keydown",e=>{
  if(e.key==="ArrowDown"){e.preventDefault();pick(BSEL+1);}
  if(e.key==="ArrowUp"){e.preventDefault();pick(BSEL-1);}
  if(e.key==="Escape"){closeBrowse();}
});
document.addEventListener("keydown",e=>{
  const typing=["INPUT","TEXTAREA"].includes(document.activeElement.tagName);
  if(e.key==="Escape"){document.activeElement.blur();return;}
  if(typing)return;
  if(e.key>="1"&&e.key<="9"){runAction(parseInt(e.key)-1);e.preventDefault();}
  else if(e.key==="a"){document.getElementById("target").focus();}
  else if(e.key==="r"){analyze();}
  else if(e.key==="i"){const v=prompt("ctfctl 子命令（不带 ctfctl）：");if(v)runCmd(v);}
  else if(e.key==="k"){openBrowse("kb");} else if(e.key==="o"){openBrowse("tools");}
  else if(e.key==="u"){openBrowse("rules");} else if(e.key==="h"){openBrowse("history");}
  else if(e.key==="c"){openBrowse("cheat");}
  else if(e.key==="/"){if(BROWSE){document.getElementById("filter").focus();e.preventDefault();}}
});
renderTabs("");
api("/api/state").then(d=>{
  const last=d.target||localStorage.getItem("ctfctl.target")||"";
  if(last)document.getElementById("target").value=last;
}).catch(()=>{const l=localStorage.getItem("ctfctl.target");if(l)document.getElementById("target").value=l;});
document.getElementById("target").focus();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ctfctl/" + __version__
    token_needed = False
    token = ""

    # ------------------------------------------------------------ 工具
    def log_message(self, fmt, *args):          # 静音（别把访问日志打到工作台终端）
        pass

    def _ok(self, obj, ctype="application/json; charset=utf-8"):
        data = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _err(self, code, msg):
        data = json.dumps({"error": msg}, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self, q: dict) -> bool:
        if not self.token_needed:
            return True
        return (self.headers.get("X-Token") or q.get("token", [""])[0]) == self.token

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------ 路由
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            if not self._authed(q):
                return self._err(403, "需要 token：用启动时打印的带 token 地址打开")
            html = PAGE.replace("__VERSION__", "v" + __version__).replace("__TOKEN__", self.token)
            return self._ok(html.encode("utf-8"), "text/html; charset=utf-8")
        if not self._authed(q):
            return self._err(403, "token 不对")
        if u.path == "/api/state":
            with LOCK:
                return self._ok({"target": STATE["target"], "actions": STATE["actions"],
                                 "kind": STATE["kind"], "version": __version__})
        if u.path == "/api/browse":
            sec = (q.get("section") or ["kb"])[0]
            builder = browse_mod.BUILDERS.get(sec)
            if not builder:
                return self._err(404, f"没有这个栏目：{sec}")
            items = builder()
            key = (q.get("key") or [""])[0]
            if key:
                hit = next((it for it in items if str(it["key"]) == key), None)
                if not hit:
                    return self._err(404, "没有这个条目")
                return self._ok({"title": hit["title"], "body": hit["body"]})
            return self._ok({"section": sec, "items": [{"title": it["title"], "key": it["key"]} for it in items],
                             "sections": browse_mod.SECTIONS})
        return self._err(404, "no such endpoint")

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if not self._authed({}):
            return self._err(403, "token 不对")
        body = self._body()
        if u.path == "/api/target":
            with LOCK:
                STATE["target"] = str(body.get("target", "")).strip()
                return self._ok({"target": STATE["target"]})
        if u.path == "/api/analyze":
            with LOCK:
                target = str(body.get("target") or STATE["target"]).strip()
                STATE["target"] = target
                full = bool(body.get("full"))
            try:
                res = wb.analyze(target, full=full)
            except Exception as e:                      # 任何内部异常都变成可读文本，别把界面打死
                return self._err(500, f"{type(e).__name__}: {e}")
            with LOCK:
                STATE["actions"] = res.get("actions", [])
                STATE["kind"] = res.get("kind", "")
            return self._ok(res)
        if u.path == "/api/action":
            idx = int(body.get("index", -1))
            with LOCK:
                acts = list(STATE["actions"])
            if not (0 <= idx < len(acts)):
                return self._err(400, "动作下标越界（先分析）")
            try:
                rc, out = wb.run_action(acts[idx])
            except Exception as e:
                return self._err(500, f"{type(e).__name__}: {e}")
            return self._ok({"rc": rc, "output": out, "label": acts[idx].get("label", ""),
                             "render": acts[idx].get("render", "")})
        if u.path == "/api/run":
            argv = body.get("argv") or []
            if not argv:
                return self._err(400, "空命令")
            rc, out = wb.run_argv([str(a) for a in argv])
            return self._ok({"rc": rc, "output": out})
        return self._err(404, "no such endpoint")


# ------------------------------------------------------------------ 启动

def _free_port(preferred: int) -> int:
    for p in [preferred] + list(range(preferred + 1, preferred + 20)):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return 0


def serve(port: int, host: str, token: str, open_browser: bool) -> int:
    Handler.token_needed = bool(token)
    Handler.token = token or ""
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        print(f"[!] 起不来 {host}:{port} —— {e}", file=sys.stderr)
        return 2
    real_port = httpd.server_address[1]
    shown_host = "127.0.0.1" if host in LOOPBACK else host
    url = f"http://{shown_host}:{real_port}/"
    if token:
        url += "?token=" + token
    print(f"[web] 工作台已启动：{url}")
    if host not in LOOPBACK:
        print("[web] 注意：监听在非回环地址（别的设备也能访问）。已强制 token 校验；"
              "用完关掉进程/或别在不可信网络里开。")
    print("[web] Ctrl-C 结束。命令行界面仍在：ctfctl tui / ctfctl go <目标>")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] 已停止")
    finally:
        httpd.server_close()
    return 0


def run(args) -> int:
    host = args.host
    token = args.token or ""
    if host not in LOOPBACK and not token:
        token = secrets.token_urlsafe(12)
        print("[web] 非回环监听：已自动生成 token（地址里会带上）")
    port = args.port if args.port else _free_port(8778)
    return serve(port, host, token, not args.no_open)


def register(sub) -> None:
    p = sub.add_parser("web", help="WebUI 工作台（默认入口：本地服务 + 浏览器，键盘驱动）")
    p.add_argument("--port", type=int, default=8778, help="端口（默认 8778，占了就往后找）")
    p.add_argument("--host", default="127.0.0.1", help="监听地址（默认只有本机能访问；填 0.0.0.0 会强制 token）")
    p.add_argument("--token", help="自定义 token（监听非回环时必需，不给就自动生成）")
    p.add_argument("--no-open", action="store_true", help="不自动开浏览器（只打印地址）")
    p.set_defaults(func=run)
