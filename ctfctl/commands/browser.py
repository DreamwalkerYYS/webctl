"""browser —— 借真浏览器发一次请求（第二条出口 + 真 UA + 真 cookie 名单）。

为什么需要它：跑在容器里的命令行出口 IP 和浏览器不是一个，靶机/平台常常只放行其中一个
（症状：全程 403 且响应体为空）。这条通道走 CDP，把请求交给浏览器发，再把原始响应取回来。

    ctfctl browser "http://靶机/"                    # 借已开着的调试端口（默认 回环地址:9222）
    ctfctl browser "http://靶机/" --launch           # 自己起一个 headless 浏览器（临时 profile）
    ctfctl browser "http://靶机/" --discover         # 列出可用的调试目标
    ctfctl browser "$U/api" -X POST -d 'a=b' -H 'X-Forwarded-For: 回环地址'
    ctfctl browser "$U/" --cdp http://回环地址:9333   # 指向你自己的 Edge/Chrome（带登录态）

实现：CDP Fetch 域两段拦截 —— 请求阶段改方法/头/体，响应阶段取状态、响应头与**原始 body**
（不走 fetch()，所以没有跨域限制，也不受页面 CSP 影响）。
"""
from __future__ import annotations

import base64
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

from ..core.cdp import CDP, http_json, list_targets
from ..core.response import Resp
from ..core.session import emit

BROWSER_CANDIDATES = ["chromium", "chromium-browser", "google-chrome-stable", "google-chrome",
                      "microsoft-edge-stable", "microsoft-edge", "brave", "chrome"]


def find_browser() -> str | None:
    for name in BROWSER_CANDIDATES:
        p = shutil.which(name)
        if p:
            return p
    for pat in ("~/.hermes/tools/chromium-*/chrome-linux/chrome",
                "~/.hermes/tools/chromium-*/*/chrome",
                "~/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
                "/opt/microsoft/msedge/msedge"):
        hits = sorted(glob.glob(os.path.expanduser(pat)))
        if hits:
            return hits[-1]
    return None


def launch_browser(cdp_base: str, headless: bool = True) -> subprocess.Popen:
    exe = find_browser()
    if not exe:
        raise SystemExit("[!] 找不到浏览器可执行文件。要么装 chromium/chrome，要么 --cdp 指向已开的调试端口")
    port = cdp_base.rsplit(":", 1)[-1].strip("/").split("/")[0]
    profile = tempfile.mkdtemp(prefix="ctfctl-chrome-")
    args = [exe, f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check", "--disable-gpu",
            "--remote-allow-origins=*", "about:blank"]
    if headless:
        args.insert(1, "--headless=new")
    print(f"[browser] 起 {exe} (port {port}, profile {profile})", file=sys.stderr)
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):                       # 等调试端口起来
        try:
            http_json(cdp_base, "/json/version", timeout=1)
            return proc
        except Exception:
            time.sleep(0.25)
    proc.terminate()
    raise SystemExit("[!] 浏览器起来了但调试端口没响应（试试换 --cdp http://…:9333）")


def fetch_via_browser(cdp_base: str, url: str, method: str = "GET", headers: dict | None = None,
                      body: str | None = None, timeout: float = 30, tab_origin: bool = True) -> Resp:
    """借浏览器发一次请求：先导航到目标同源站点，再在页面里注入 fetch 取回原始响应。

    为什么不用 Fetch 域拦截：Page.navigate 的回复要等导航提交，边等回复边处理拦截事件会死锁
    （实测在 Chrome 145 上必卡）。同源 fetch 更简单也更稳：
      * 同源 → 没有跨域限制，能拿到状态码/响应头/原始字节
      * UA 走 Network.setUserAgentOverride、Cookie 走 Network.setCookie（这两个是 fetch 的禁止改名单头）
      * 出口 IP、TLS 指纹、代理设置都来自浏览器本身 —— 这就是这条通道存在的意义

    副作用：会先对站点的 "/" 发一次 GET（导航用）。对 CTF 靶机无影响。
    """
    u = urllib.parse.urlsplit(url)
    origin = f"{u.scheme}://{u.netloc}"
    headers = dict(headers or {})
    cdp = CDP(cdp_base, timeout=timeout)
    try:
        cdp.call("Network.enable")
        cdp.call("Page.enable")
        # 禁止改名单头：交给 CDP 设置
        ua = None
        for k in list(headers):
            if k.lower() == "user-agent":
                ua = headers.pop(k)
            elif k.lower() == "cookie":
                for pair in headers.pop(k).split(";"):
                    n, _, v = pair.strip().partition("=")
                    if n:
                        cdp.call("Network.setCookie", {"name": n, "value": v, "url": origin})
        if ua:
            cdp.call("Network.setUserAgentOverride", {"userAgent": ua})
        if tab_origin:
            cdp.ws.send_text(json.dumps({"id": 9001, "method": "Page.navigate",
                                         "params": {"url": origin + "/"}}))
            try:                                     # 等加载事件；超时也继续（有的站首页就卡）
                cdp.next_event("Page.loadEventFired", timeout=min(10.0, timeout))
            except Exception:
                pass
        js = """(async () => {
  const init = {method: %s, headers: %s, credentials: 'include', redirect: 'follow'};
  %s
  const r = await fetch(%s, init);
  const buf = new Uint8Array(await r.arrayBuffer());
  let s = ''; const chunk = 0x8000;
  for (let i = 0; i < buf.length; i += chunk) s += String.fromCharCode.apply(null, buf.subarray(i, i + chunk));
  return {status: r.status, url: r.url, ok: r.ok,
          headers: Array.from(r.headers.entries()),
          b64: btoa(s), size: buf.length};
})()""" % (json.dumps(method.upper()), json.dumps(headers),
           f"init.body = {json.dumps(body)};" if body is not None else "",
           json.dumps(url))
        try:
            out = cdp.evaluate(js)
        except RuntimeError as e:                     # 页面内异常（多为网络层失败）
            raise RuntimeError(f"页面内 fetch 失败：{e}")
        if not isinstance(out, dict) or "b64" not in out:
            raise RuntimeError(f"浏览器没返回数据：{str(out)[:200]}")
        return Resp(out.get("status", 0), dict(out.get("headers") or []),
                    base64.b64decode(out["b64"]), url, out.get("url"))
    finally:
        try:
            cdp.close()
        except Exception:
            pass


def run(args) -> int:
    if args.discover:
        try:
            ts = list_targets(args.cdp, timeout=3)
        except Exception as e:
            print(f"[!] 连不上 {args.cdp}：{e}", file=sys.stderr)
            return 2
        print(f"{args.cdp} 上有 {len(ts)} 个目标：")
        for t in ts:
            print(f"  [{t.get('type')}] {t.get('title')}  {t.get('url')[:90]}")
            print(f"        {t.get('webSocketDebuggerUrl')}")
        return 0

    headers = {}
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    if args.ua:
        headers["User-Agent"] = args.ua
    ctype = args.ctype or ("application/x-www-form-urlencoded" if args.data and not args.raw else None)
    if ctype:
        headers.setdefault("Content-Type", ctype)
    body = args.data if args.data is not None else None

    proc = None
    if args.launch:
        proc = launch_browser(args.cdp, headless=not args.no_headless)
    try:
        resp = fetch_via_browser(args.cdp, args.url, args.method, headers, body, args.timeout)
    except Exception as e:
        print(f"[!] 浏览器通道失败：{type(e).__name__}: {e}", file=sys.stderr)
        print("    排查：① 浏览器是不是带 --remote-debugging-port 起的 ② --discover 看有没有可用目标 "
              "③ 换 --cdp http://回环地址:其它端口", file=sys.stderr)
        return 2
    finally:
        if proc is not None:
            proc.terminate()
    emit(resp, args)
    print(f"[via] 浏览器通道（CDP {args.cdp}）—— 出口 IP 与 UA 都来自浏览器，不是本机命令行", file=sys.stderr)
    return 0


def register(sub) -> None:
    p = sub.add_parser("browser", help="借真浏览器发请求（第二条出口，绕开 403/空响应）")
    p.add_argument("url", nargs="?", help="目标 URL（--discover 时可不填）")
    p.add_argument("-X", "--method", default="GET")
    p.add_argument("-H", "--header", action="append", help="额外请求头（请求阶段注入）")
    p.add_argument("-d", "--data", help="请求体")
    p.add_argument("--ctype", help="Content-Type（默认表单；--raw 时不猜）")
    p.add_argument("--raw", action="store_true", help="body 原样发，不自动加表单 Content-Type")
    p.add_argument("--ua", help="伪造 UA（默认用浏览器自己的）")
    p.add_argument("--cdp", default="http://127.0.0.1:9222", help="CDP 调试端口（默认 9222）")
    p.add_argument("--launch", action="store_true", help="自己起一个 headless 浏览器（临时 profile）")
    p.add_argument("--no-headless", action="store_true", help="配 --launch：起带界面的浏览器")
    p.add_argument("--discover", action="store_true", help="列出该调试端口上的目标")
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("-v", "--verbose", action="store_true", help="打印响应头 + 终端提示")
    p.add_argument("--grep")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-o", "--out")
    p.add_argument("--max", type=int, default=3000)
    p.set_defaults(func=run)
