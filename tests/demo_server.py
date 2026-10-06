"""本地演示靶机：专门用来测 ctfctl 的判定逻辑（不联网、可重复）。

它刻意复刻了你踩过的几类坑：
  * nginx try_files 式**假 200**：未知非 .php 路径回退首页（字节数与首页一致）
  * .php 结尾走"PHP 层"给**真 404**
  * 真存在的备份文件 index.php.bak（text/plain，字节数不同）
  * 首页带：注释线索、隐藏 input、data-* 属性、表单、带参链接、JWT 字符串、"你不是管理员"话术
  * 响应头带 Werkzeug + 三段式 session cookie（触发客户端 session 规则）

用法：python3 tests/demo_server.py [port]
"""
from __future__ import annotations

import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INDEX_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>Demo 靶机</title><script src="/static/js/app.js" defer></script></head>
<body>
<!-- 出题人忘了删的注释：flag 在 /flag.php 里（但那个路径要先通过校验） -->
<h1>Demo 靶机</h1>
<div id="next" hidden data-next="/stage2-abc" data-answer-format="binary"></div>
<input type="hidden" name="csrf_tok" value="deadbeef">
<p>你不是管理员，无法查看凭证。</p>
<pre id="tok">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciJ9.aaaa</pre>
<form method="post" action="/submit"><input name="q"><button>提交</button></form>
<a href="/api/v1/user?id=1&file=readme.txt">用户信息</a>
<a href="/search?keyword=test">搜索</a>
<script>window.setTimeout(()=>{},0)</script>
</body></html>"""

BAK_PHP = """<?php
// index.php.bak —— 备份文件泄露（真实存在，text/plain）
if (md5($_GET['a']) == md5($_GET['b'])) { echo $flag; }
system($_GET['cmd']);
"""

APP_JS = """// /static/js/app.js
fetch('/api/v1/user?id=1');
const debug = '/admin/debug?cmd=ls';
"""

ROBOTS = "User-agent: *\nDisallow: /admin\n"

# 一个真的三段式 session cookie（内容是假的，只为触发规则）
SESSION_COOKIE = ".".join([
    base64.urlsafe_b64encode(b'{"name":"guest"}').rstrip(b"=").decode(),
    base64.urlsafe_b64encode(b"\x00\x00\x00\x01").rstrip(b"=").decode(),
    base64.urlsafe_b64encode(b"x" * 20).rstrip(b"=").decode(),
])


class Handler(BaseHTTPRequestHandler):
    server_version = "Werkzeug/3.0.1"
    sys_version = "Python/3.11.9"

    def _send(self, code: int, body: bytes | str, ctype: str, extra: dict | None = None) -> None:
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                                    # noqa: N802
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)
        if path == "/":
            self._send(200, INDEX_HTML, "text/html; charset=utf-8",
                       {"Set-Cookie": f"session={SESSION_COOKIE}; Path=/"})
        elif path == "/index.php.bak":
            self._send(200, BAK_PHP, "text/plain; charset=utf-8")
        elif path == "/static/js/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif path == "/robots.txt":
            self._send(200, ROBOTS, "text/plain")
        elif path == "/echo-ua":
            self._send(200, "UA=" + (self.headers.get("User-Agent") or ""), "text/plain")
        elif path == "/api/v1/user":
            self._send(200, json.dumps({"id": q.get("id", [""])[0], "role": "user"}), "application/json")
        elif path == "/login":
            self._send(200, INDEX_HTML.replace("Demo 靶机", "登录").replace("<pre id=\"tok\">",
                       "<p>登录页</p><pre style=\"display:none\">"), "text/html; charset=utf-8")
        elif path.endswith(".php"):
            self._send(404, "404 Not Found", "text/plain")          # 真 404：走 PHP 层
        else:
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")  # 假 200：回退首页

    def do_POST(self):                                   # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            form = dict(parse_qs(body))
            self._send(200, f"ok form={json.dumps(form, ensure_ascii=False)}", "text/plain")
        else:
            self._send(200, "ok raw", "text/plain")

    def log_message(self, *a):                           # 静音
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8848
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"demo 靶机：http://127.0.0.1:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
