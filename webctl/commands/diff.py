"""diff —— 两次响应的对比，专治盲注/布尔判断/权限差异这类"只有细微不同"的题。

三种比法：
    webctl diff live URL --a 'id=1'  --b "id=1'"      # 现场发两条，比响应
    webctl diff live URL --field id --a 1 --b "1'-- -"  # 更省事：直接给某字段的两个取值
    webctl diff files A.html B.html                    # 比两个本地文件
    webctl diff history 7 8                            # 比历史里的第 7、8 条响应

输出：状态/长度/Content-Type/sha 的对照表 + 正文的行级差异（difflib）。
退出码：一致 0，不一致 1 —— 可以塞进 for 循环里当布尔探针用。
"""
from __future__ import annotations

import difflib
import hashlib
import os
import sys
import urllib.parse

from ..core import history
from ..core.session import Session


def _brief(kind: str, status, body: bytes, ctype: str) -> None:
    print(f"  {kind:8s} {status} {len(body):>8}B {ctype or '?':26s} sha={hashlib.sha256(body).hexdigest()[:12]}")


def _compare(a: bytes, b: bytes, ctype_a: str, ctype_b: str, status_a, status_b, args) -> int:
    print("对比：")
    _brief("A", status_a, a, ctype_a)
    _brief("B", status_b, b, ctype_b)
    same_len = len(a) == len(b)
    same_sha = hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()
    print(f"  长度{'相同' if same_len else f'不同（Δ{len(a)-len(b):+d}）'}"
          f" · sha{'相同' if same_sha else '不同'}"
          f" · 状态{'相同' if status_a == status_b else f'不同（{status_a} vs {status_b}）'}")
    if same_sha:
        print("  → 响应完全一致：这个位置可能没有注入点/没有权限差异")
        return 0
    ta = a.decode("utf-8", "replace").splitlines()
    tb = b.decode("utf-8", "replace").splitlines()
    d = list(difflib.unified_diff(ta, tb, "A", "B", lineterm="", n=args.context))
    print(f"\n  行级差异（{max(0, len(d)-3)} 行，展示前 {args.max_diff} 行）：")
    for line in d[:args.max_diff]:
        print("   " + line[:220])
    if len(d) > args.max_diff:
        print(f"   …（还有 {len(d)-args.max_diff} 行，--max-diff 放大）")
    return 1


def run_live(args) -> int:
    if args.a is None or args.b is None:
        raise SystemExit("[!] 要给 --a 和 --b 两个取值（或用 --field 简写）")
    a_val, b_val = args.a, args.b
    if args.field:
        a_val, b_val = f"{args.field}={a_val}", f"{args.field}={b_val}"
    sess = Session(base=args.url.split("?")[0] if args.url.startswith("http") else "",
                   jar_name=args.jar, proxy=args.proxy, timeout=args.timeout, ua=args.ua)
    sess.tag = "diff"
    headers = {}
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    method = (args.method or ("POST" if args.in_body else "GET")).upper()

    def send(payload: str):
        if not args.in_body:                       # 默认：拼进查询串（id=1 / id=1' 这类探针）
            sep = "&" if "?" in args.url else "?"
            return sess.request("GET", args.url + sep + payload, headers=headers)
        pairs = [kv.partition("=")[::2] for kv in payload.split("&")]
        return sess.request(method, args.url, data=urllib.parse.urlencode(pairs),
                            ctype=args.ctype, headers=headers)

    ra, rb = send(a_val), send(b_val)
    rc = _compare(ra.body, rb.body, ra.ctype, rb.ctype, ra.status, rb.status, args)
    if getattr(args, "save", None):
        os.makedirs(args.save, exist_ok=True)
        open(os.path.join(args.save, "A.body"), "wb").write(ra.body)
        open(os.path.join(args.save, "B.body"), "wb").write(rb.body)
        print(f"  [saved] {args.save}/A.body  {args.save}/B.body")
    return rc


def run_files(args) -> int:
    a = open(args.file_a, "rb").read()
    b = open(args.file_b, "rb").read()
    return _compare(a, b, "", "", "-", "-", args)


def run_history(args) -> int:
    recs = history.load(host_key=args.host)
    try:
        ra, rb = recs[args.a - 1], recs[args.b - 1]
    except IndexError:
        raise SystemExit(f"[!] 序号超范围（历史共 {len(recs)} 条）")
    for r in (ra, rb):
        if isinstance(r, dict) and r not in (ra, rb):
            pass
    ba, bb = history.body_of(ra), history.body_of(rb)
    print(f"A: {ra['method']} {ra['url']}  @{ra.get('status')}")
    print(f"B: {rb['method']} {rb['url']}  @{rb.get('status')}")
    return _compare(ba, bb, ra.get("ctype", ""), rb.get("ctype", ""), ra.get("status"), rb.get("status"), args)


def _common(p):
    p.add_argument("--max-diff", type=int, default=60)
    p.add_argument("--context", type=int, default=1, help="差异上下文行数")
    p.add_argument("--jar")
    p.add_argument("--proxy")
    p.add_argument("--ua")
    p.add_argument("--timeout", type=float, default=20)


def register(sub) -> None:
    p = sub.add_parser("diff", help="两次响应对比（盲注/布尔/权限差异）")
    v = p.add_subparsers(dest="dmode", required=True)

    li = v.add_parser("live", help="现场发两条请求再比")
    li.add_argument("url")
    li.add_argument("--a", required=True, help="A 的取值")
    li.add_argument("--b", required=True, help="B 的取值")
    li.add_argument("--field", help="简写：字段名（自动拼成 field=A / field=B）")
    li.add_argument("--in-body", action="store_true", help="作为 POST 表单体发（默认拼在查询串上）")
    li.add_argument("--method", help="显式指定方法")
    li.add_argument("--ctype", default="application/x-www-form-urlencoded")
    li.add_argument("-H", "--header", action="append")
    li.add_argument("--save", help="把 A/B 响应体存到该目录")
    _common(li)
    li.set_defaults(func=run_live)

    fi = v.add_parser("files", help="比两个本地文件")
    fi.add_argument("file_a"); fi.add_argument("file_b")
    _common(fi)
    fi.set_defaults(func=run_files)

    hi = v.add_parser("history", help="比历史里的两条响应")
    hi.add_argument("a", type=int); hi.add_argument("b", type=int)
    hi.add_argument("--host")
    _common(hi)
    hi.set_defaults(func=run_history)
