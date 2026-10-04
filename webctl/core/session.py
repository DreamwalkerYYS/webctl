"""会话层：cookie jar 按 host 持久化 + 统一请求 + 统一输出。

这是"手写 curl 最烦"的部分：多步流程里 sid/credential 等 cookie 要一直带着，
还要能随手改方法/头/体。所有命令共用这里的 Session 和 add_http_args()。
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import CACHE, DEFAULT_UA, ensure_dirs
from .response import Resp


# ---------------------------------------------------------------- 会话
class Session:
    def __init__(self, base: str = "", jar_name: str | None = None, new: bool = False,
                 proxy: str | None = None, timeout: float = 20, ua: str | None = None,
                 verbose: bool = False):
        self.base = base.rstrip("/")
        self.verbose = verbose
        self.timeout = timeout
        self.ua = ua or DEFAULT_UA
        self.proxy = proxy
        self.history: list[tuple[str, str, int, int]] = []
        ensure_dirs()
        key = jar_name
        if not key:
            key = urllib.parse.urlsplit(self.base).hostname or "default"
        self.jar_path = os.path.join(CACHE, f"{key}.jar")
        self.jar = http.cookiejar.MozillaCookieJar(self.jar_path)
        if not new and os.path.exists(self.jar_path):
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)
        # 请求历史（replay/diff 的数据源）
        self.host_key = key
        self.hist_dir = os.path.join(CACHE, "history", key)
        self.hist_index = os.path.join(self.hist_dir, "index.jsonl")
        self.tag = "req"          # 记录来源：req/recon/fuzz/diff/replay（导出时可过滤）

    def _record(self, method: str, url: str, headers: dict, body, resp: Resp) -> None:
        """落一条历史：请求要素 + 响应摘要 + 响应体文件（失败也不影响主流程）。"""
        try:
            import hashlib
            os.makedirs(self.hist_dir, exist_ok=True)
            sha = hashlib.sha256(resp.body).hexdigest()
            ts = time.time()
            bpath = os.path.join(self.hist_dir, f"{int(ts*1000)}-{sha[:8]}.body")
            with open(bpath, "wb") as f:
                f.write(resp.body)
            rec = {"ts": ts, "method": method.upper(), "url": url,
                   "req_headers": {k: v for k, v in headers.items()},
                   "req_body": (body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")),
                   "status": resp.status, "size": resp.size, "ctype": resp.ctype,
                   "sha": sha, "body_file": bpath,
                   "tag": getattr(self, "tag", "req"),
                   "cookies": self._cookies_for(url)}
            with open(self.hist_index, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:                 # 历史只是副产品，任何异常都不能影响主流程
            pass

    # ---- 内部 ----
    def _cookies_for(self, url: str) -> str:
        """当前 jar 里对该 URL 生效的 cookie（导出脚本时要用它复现会话）。"""
        host = urllib.parse.urlsplit(url).hostname or ""
        out = []
        for c in self.jar:
            d = (c.domain or "").lstrip(".")
            if d and (host == d or host.endswith("." + d)):
                out.append(f"{c.name}={c.value}")
        return "; ".join(out)

    def _full(self, url_or_path: str) -> str:
        if url_or_path.startswith(("http://", "https://")):
            return url_or_path
        if not self.base:
            raise SystemExit("[!] 需要完整 URL（或先给 base）")
        return self.base + (url_or_path if url_or_path.startswith("/") else "/" + url_or_path)

    def _no_redirect_opener(self):
        class NoRedir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        handlers = [urllib.request.HTTPCookieProcessor(self.jar), NoRedir()]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        return urllib.request.build_opener(*handlers)

    # ---- 公开 ----
    def set_cookie(self, name: str, value: str, domain: str | None = None) -> None:
        host = domain or urllib.parse.urlsplit(self.base or "http://local").hostname or "local"
        self.jar.set_cookie(http.cookiejar.Cookie(
            0, name, value, None, False, host, False, False, "/", True, False, None, True, None, None, {}))

    def request(self, method: str = "GET", url: str = "/", data: bytes | str | None = None,
                ctype: str | None = None, headers: dict | None = None,
                cookies: dict | None = None, follow: bool = True) -> Resp:
        target = self._full(url)
        hdrs = {"User-Agent": self.ua}
        if ctype:
            hdrs["Content-Type"] = ctype
        hdrs.update(headers or {})
        if cookies:
            old = self.jar._cookies.get(urllib.parse.urlsplit(target).hostname, {})
            for k, v in cookies.items():
                self.set_cookie(k, v)
        if isinstance(data, str):
            data = data.encode()
        if data is not None and method.upper() == "GET":
            method = "POST"
        req = urllib.request.Request(target, data=data, method=method.upper(), headers=hdrs)
        opener = self._opener if follow else self._no_redirect_opener()
        t0 = time.time()
        try:
            r = opener.open(req, timeout=self.timeout)
            resp = Resp(r.status, dict(r.headers), r.read(), target, r.geturl())
        except urllib.error.HTTPError as e:
            resp = Resp(e.code, dict(e.headers), e.read(), target)
        except Exception as e:                                     # 出口/连接类问题
            resp = Resp(0, {}, f"webctl: {type(e).__name__}: {e}".encode(), target)
        try:
            self.jar.save(ignore_discard=True, ignore_expires=True)
        except OSError:
            pass
        self.history.append((method.upper(), target, resp.status, resp.size))
        self._record(method, target, hdrs, data, resp)
        if self.verbose:
            print(f"  [{time.time()-t0:.2f}s] {method.upper()} {target}", file=sys.stderr)
        return resp


# ---------------------------------------------------------------- 命令行公共参数
def add_http_args(p) -> None:
    p.add_argument("url", help="完整 URL 或路径（配合 --base）")
    p.add_argument("--base", default="", help="站点根，例如 http://host:8080（给相对路径时用）")
    p.add_argument("-H", "--header", action="append", help="额外请求头 'K: V'")
    p.add_argument("-b", "--cookie", action="append", help="本次请求附加 cookie k=v")
    p.add_argument("--ua", help="User-Agent")
    p.add_argument("--proxy", help="走代理（Burp 等），如 本地回环地址:8080")
    p.add_argument("-v", "--verbose", action="store_true", help="打印响应头 + 当前 cookie + 计时")
    p.add_argument("--head", action="store_true", help="只看响应头")
    p.add_argument("--no-follow", action="store_true", help="不跟随重定向（看 302/303 的 Location）")
    p.add_argument("--grep", help="只打印正则匹配到的内容")
    p.add_argument("-q", "--quiet", action="store_true", help="只留正文/grep 结果，不打印状态行与存盘信息")
    p.add_argument("-o", "--out", help="把响应体另存到该路径")
    p.add_argument("--max", type=int, default=3000, help="正文打印上限（默认 3000 字符）")
    p.add_argument("--jar", help="用另一份 cookie jar（多会话并行）")
    p.add_argument("--new", action="store_true", help="清空该 host 的 jar，开新会话")
    p.add_argument("--timeout", type=float, default=20)


def session_from_args(args) -> Session:
    base = getattr(args, "base", "") or ""
    if not base and getattr(args, "url", "").startswith(("http://", "https://")):
        u = urllib.parse.urlsplit(args.url)
        base = f"{u.scheme}://{u.netloc}"
    return Session(base=base, jar_name=getattr(args, "jar", None), new=getattr(args, "new", False),
                   proxy=getattr(args, "proxy", None), timeout=getattr(args, "timeout", 20),
                   ua=getattr(args, "ua", None), verbose=getattr(args, "verbose", False))


def emit(resp: Resp, args, jar_path: str | None = None) -> str:
    """统一输出：状态行 + （可选）头 + 正文/grep + 自动捞 flag。"""
    grep = getattr(args, "grep", None)
    quiet = getattr(args, "quiet", False)

    def info(*a, **k):
        """状态行/头/存盘/FLAG 提示：-q 时不打，--grep 时打到 stderr（stdout 只留匹配）。"""
        if quiet:
            return
        print(*a, **k, file=sys.stderr if grep else sys.stdout)

    info(resp.summary())
    if getattr(args, "verbose", False) or getattr(args, "head", False):
        for k, v in resp.raw_headers.items():
            info(f"  {k}: {v}")
    if getattr(args, "head", False):
        return ""
    text = resp.text
    if grep:
        for m in resp.grep(grep):
            print(m)
    else:
        limit = getattr(args, "max", 3000)
        print(text[:limit] + (f"\n...[{len(text)-limit} more chars]" if len(text) > limit else ""))
    path = resp.save(getattr(args, "out", None))
    flags = resp.flags()
    if flags:
        info("\n[FLAG?] " + "  ".join(flags))
    info(f"[saved] body={path}" + (f" jar={jar_path}" if jar_path else ""))
    if resp.status == 0:
        info("[!] 连接失败：先确认靶机在跑 / 网络出口（403+空响应也可能是出口问题，换网络或 --proxy）")
    elif resp.status in (403, 401) and resp.size == 0:
        info("[!] 403/401 且空响应：优先怀疑出口 IP，而不是题目 —— 换网络/代理，或改用浏览器 fetch")
    return text
