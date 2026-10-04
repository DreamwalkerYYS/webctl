"""req —— 会话化发请求：`webctl req get|post|req`

这一层替代手写 curl：cookie 按 host 自动持久化，随时换方法/头/body，
响应统一打印（状态/长度/类型 + 正文），并自动把 flag 捞出来。
"""
from __future__ import annotations

import urllib.parse

from ..core.session import add_http_args, emit, session_from_args


def _run(args) -> int:
    sess = session_from_args(args)
    headers = {}
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    cookies = {}
    for c in args.cookie or []:
        k, _, v = c.partition("=")
        cookies[k.strip()] = v
    verb = args.verb
    if verb == "get":
        resp = sess.request("GET", args.url, headers=headers, cookies=cookies,
                            follow=not args.no_follow)
    elif verb == "post":
        if args.json is not None:
            body, ctype = args.json, (args.ctype or "application/json")
        else:
            pairs = [kv.partition("=")[::2] for kv in (args.data or [])]
            body, ctype = urllib.parse.urlencode(pairs), (args.ctype or "application/x-www-form-urlencoded")
        resp = sess.request("POST", args.url, data=body, ctype=ctype, headers=headers,
                            cookies=cookies, follow=not args.no_follow)
    else:  # req：任意方法 + 原始 body
        resp = sess.request(args.method, args.url, data=args.data or None, ctype=args.ctype,
                            headers=headers, cookies=cookies, follow=not args.no_follow)
    emit(resp, args, jar_path=sess.jar_path)
    return 0


def register(sub) -> None:
    p = sub.add_parser("req", help="发 HTTP 请求（会话 cookie 自动带）")
    v = p.add_subparsers(dest="verb", required=True)

    g = v.add_parser("get", help="GET")
    add_http_args(g)
    g.set_defaults(func=_run)

    po = v.add_parser("post", help="POST（表单或 JSON）")
    add_http_args(po)
    po.add_argument("-d", "--data", action="append", help="表单字段 k=v（可多次）")
    po.add_argument("--json", help="JSON 请求体（自动设 Content-Type）")
    po.add_argument("--ctype", help="显式指定 Content-Type（配合 --json 可覆盖）")
    po.set_defaults(func=_run)

    rq = v.add_parser("req", help="任意方法 + 原始 body（PUT/DELETE/…）")
    add_http_args(rq)
    rq.add_argument("-X", "--method", default="POST")
    rq.add_argument("--data", default="", help="原始 body（字符串）")
    rq.add_argument("--ctype", default="application/x-www-form-urlencoded")
    rq.set_defaults(func=_run)
