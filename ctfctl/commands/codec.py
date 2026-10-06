"""codec —— 编解码小工具（省得每次开 CyberChef / 记 base64 参数）。

    ctfctl codec b64  "hello"      → aGVsbG8=
    ctfctl codec b64d "aGVsbG8="   → hello
    ctfctl codec url  "a b&c"      → a%20b%26c
    ctfctl codec urld "a%20b"      → a b
    ctfctl codec hex  "AB"         → 4142
    ctfctl codec hexd "4142"       → AB
    ctfctl codec guess "aGVsbG8="  → 猜它是什么编码
不给文本时从 stdin 读（方便管道）。
"""
from __future__ import annotations

import base64
import binascii
import sys
import urllib.parse


def _input(args) -> str:
    if args.text:
        return " ".join(args.text) if isinstance(args.text, list) else args.text
    return sys.stdin.read().strip()


def _b64e(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _b64d(s: str) -> str:
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad).decode("utf-8", "replace")
    except binascii.Error:
        return "[!] 不是合法 base64"


def _guess(s: str) -> str:
    import re

    out = []
    if re.fullmatch(r"[A-Za-z0-9+/=\s]{8,}", s):
        try:
            raw = base64.b64decode(s)
            out.append(f"可能是 base64 → {raw.decode('utf-8', 'replace')[:200]!r}")
        except Exception:
            pass
    if re.fullmatch(r"[A-Za-z0-9_\-=]{8,}", s):
        try:
            raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
            out.append(f"可能是 base64url → {raw.decode('utf-8', 'replace')[:200]!r}")
        except Exception:
            pass
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try:
            out.append(f"可能是 hex → {bytes.fromhex(s).decode('utf-8', 'replace')[:200]!r}")
        except Exception:
            pass
    if "%" in s:
        out.append(f"可能是 URL 编码 → {urllib.parse.unquote(s)[:200]!r}")
    if s.count(".") == 2 and all(len(x) > 3 for x in s.split(".")):
        out.append("看起来是 JWT：ctfctl jwt decode <token>")
    if not out:
        out.append("猜不出来，试试 gzip/zlib（file / zlib.decompress）或直接 hexdump")
    return "\n".join(out)


def run(args) -> int:
    s = _input(args)
    cmd = args.codec
    if cmd == "b64":
        print(_b64e(s))
    elif cmd == "b64d":
        print(_b64d(s))
    elif cmd == "url":
        print(urllib.parse.quote(s, safe=""))
    elif cmd == "urld":
        print(urllib.parse.unquote(s))
    elif cmd == "hex":
        print(s.encode().hex())
    elif cmd == "hexd":
        try:
            print(bytes.fromhex(s).decode("utf-8", "replace"))
        except ValueError:
            print("[!] 不是合法 hex")
    else:
        print(_guess(s))
    return 0


def register(sub) -> None:
    p = sub.add_parser("codec", help="编码/解码：b64 / b64d / url / urld / hex / hexd / guess")
    v = p.add_subparsers(dest="codec", required=True)
    for name, help_ in (("b64", "→ base64"), ("b64d", "base64 →"), ("url", "→ URL 编码"),
                        ("urld", "URL 解码 →"), ("hex", "→ hex"), ("hexd", "hex →"),
                        ("guess", "猜编码")):
        sp = v.add_parser(name, help=help_)
        sp.add_argument("text", nargs="*", help="文本（不给则读 stdin）")
        sp.set_defaults(func=run)
