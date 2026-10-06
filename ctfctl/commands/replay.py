"""replay —— 从请求历史里挑一条重放、改包，或和现在的响应对比。

每一次 `ctfctl req/recon/fuzz/...` 的请求都已经落在
`~/.cache/ctfctl/history/<host>/index.jsonl`（含请求头/体与响应体文件），所以"我刚才那条是怎么发的"
不用靠回忆。

    ctfctl replay list                 # 最近 20 条（含序号/方法/状态/大小/地址）
    ctfctl replay show 7               # 看第 7 条的完整请求 + 响应头 + 正文开头
    ctfctl replay resend 7 -d 'a=b'    # 重放第 7 条，顺便改 body/头/方法
    ctfctl replay resend --last -H 'X-Forwarded-For: 回环地址' --diff
序号是 `replay list` 里显示的编号（1 起，越新越大）。
"""
from __future__ import annotations

import difflib
import sys

from ..core import history
from ..core.config import FLAG_RE
from ..core.session import Session, emit


def _rows(args) -> list[dict]:
    host = args.host or (args.jar or None)
    return history.load(host_key=host, limit=args.limit if args.cmd == "replay" and args.rlist else None)


def _pick(args, recs: list[dict]) -> dict:
    if getattr(args, "last", False):
        return recs[-1]
    idx = args.index
    if idx is None or idx < 1 or idx > len(recs):
        raise SystemExit(f"[!] 序号要在 1..{len(recs)} 之间（ctfctl replay list 看列表）")
    return recs[idx - 1]


def run_list(args) -> int:
    recs = history.load(host_key=args.host, limit=args.count)
    if not recs:
        print("还没有历史。先随便发一条：ctfctl req get \"$U/\"")
        return 0
    print(f"{'#':>4}  {'时间':8} {'方法':6} {'状态':>4} {'大小':>9}  {'地址'}")
    import datetime as dt
    for i, r in enumerate(recs, 1):
        t = dt.datetime.fromtimestamp(r.get("ts", 0)).strftime("%H:%M:%S")
        url = r.get("url", "")
        print(f"{i:>4}  {t:8} {r.get('method',''):6} {r.get('status',0):>4} {r.get('size',0):>9}  {url[:110]}")
    if args.host:
        print(f"[host] {args.host}")
    return 0


def run_show(args) -> int:
    recs = history.load(host_key=args.host)
    rec = _pick(args, recs)
    print(f"[{rec['method']}] {rec['url']}")
    print(f"响应：{rec.get('status')} {rec.get('size')}B {rec.get('ctype','?')} sha={rec.get('sha','')[:12]}")
    print("\n请求头：")
    for k, v in (rec.get("req_headers") or {}).items():
        print(f"  {k}: {v}")
    if rec.get("req_body"):
        print("\n请求体：")
        print("  " + str(rec["req_body"])[:2000])
    body = history.body_of(rec).decode("utf-8", "replace")
    print(f"\n响应体（前 {args.max} 字符）：")
    print(body[:args.max])
    import re
    flags = sorted(set(re.findall(FLAG_RE, body)))
    if flags:
        print("\n[FLAG?] " + "  ".join(flags))
    return 0


def run_resend(args) -> int:
    recs = history.load(host_key=args.host)
    rec = _pick(args, recs)
    headers = dict(rec.get("req_headers") or {})
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    headers.pop("Content-Length", None)
    headers.pop("Host", None)
    method = (args.method or rec["method"]).upper()
    body = args.data if args.data is not None else (rec.get("req_body") or None)
    import urllib.parse
    if body is not None and not args.raw and method in ("POST", "PUT", "PATCH") and "=" in body:
        pairs = [kv.partition("=")[::2] for kv in body.split("&")]
        body = urllib.parse.urlencode(pairs)
    sess = Session(base="", jar_name=args.jar, proxy=args.proxy, timeout=args.timeout, ua=args.ua)
    sess.tag = "replay"
    resp = sess.request(method, rec["url"], data=body, headers=headers, follow=not args.no_follow)
    old = history.body_of(rec)
    print(f"[原] {rec.get('status')} {len(old)}B sha={rec.get('sha','')[:12]}")
    print(f"[新] {resp.summary()} sha={__import__('hashlib').sha256(resp.body).hexdigest()[:12]}")
    if args.diff:
        _print_diff(old, resp.body, args.max_diff)
    emit(resp, args, jar_path=sess.jar_path)
    return 0


def _print_diff(a: bytes, b: bytes, max_lines: int) -> None:
    if a == b:
        print("[diff] 完全一致")
        return
    ta = a.decode("utf-8", "replace").splitlines()
    tb = b.decode("utf-8", "replace").splitlines()
    d = list(difflib.unified_diff(ta, tb, "原", "新", lineterm="", n=1))
    print(f"[diff] 长度 {len(a)}B → {len(b)}B，差异 {max(0, len(d)-3)} 行：")
    for line in d[:max_lines]:
        print("   " + line[:200])
    if len(d) > max_lines:
        print(f"   …（还有 {len(d)-max_lines} 行，用 --max-diff 放大）")


def register(sub) -> None:
    p = sub.add_parser("replay", help="请求历史：list / show / resend（可改包再发 + diff）")
    v = p.add_subparsers(dest="rlist", required=True)

    l = v.add_parser("list", help="列出历史")
    l.add_argument("-n", "--count", type=int, default=20)
    l.add_argument("--host", help="只看某个 host（jar 名，通常是 hostname）")
    l.set_defaults(func=run_list, cmd="replay")

    s = v.add_parser("show", help="看某一条的完整请求与响应")
    s.add_argument("index", type=int, nargs="?")
    s.add_argument("--last", action="store_true")
    s.add_argument("--host")
    s.add_argument("--max", type=int, default=2000)
    s.set_defaults(func=run_show, cmd="replay")

    r = v.add_parser("resend", help="重放并改包（-H/-d/-X）")
    r.add_argument("index", type=int, nargs="?")
    r.add_argument("--last", action="store_true")
    r.add_argument("--host")
    r.add_argument("-H", "--header", action="append")
    r.add_argument("-d", "--data", help="替换请求体（表单串；--raw 则原样发）")
    r.add_argument("--raw", action="store_true", help="--data 原样发，不重新 urlencode")
    r.add_argument("-X", "--method")
    r.add_argument("--diff", action="store_true", help="和原始响应逐行对比")
    r.add_argument("--max-diff", type=int, default=40)
    r.add_argument("--no-follow", action="store_true")
    r.add_argument("--grep")
    r.add_argument("-q", "--quiet", action="store_true")
    r.add_argument("-o", "--out")
    r.add_argument("--max", type=int, default=3000)
    r.add_argument("--jar")
    r.add_argument("--proxy")
    r.add_argument("--ua")
    r.add_argument("--timeout", type=float, default=20)
    r.set_defaults(func=run_resend, cmd="replay")
