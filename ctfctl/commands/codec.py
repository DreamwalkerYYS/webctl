"""codec —— 编解码 / 古典密码 / 哈希 / 提取（省得每次开 CyberChef）。

    ctfctl codec b64 "hello" | b64d | b32 | b32d | b58 | b58d | b85 | b85d | a85 | a85d
    ctfctl codec hex | hexd | uu | uud | url | urld | rot13 | rot47 | binary | binaryd
    ctfctl codec morse | morsed | brainfuck | unicode | htmld | guess
    ctfctl codec cipher caesar   "KHOOR" --brute          # 凯撒（--shift N 指定位移）
    ctfctl codec cipher atbash   "SVOOL"
    ctfctl codec cipher vigenere "LXFOPVEFRNHR" --key LEMON        # --decrypt 反向
    ctfctl codec cipher beaufort "AKWWAC" --key FORT
    ctfctl codec cipher railfence "WEAREDISCOVERED" --rails 3 [--decrypt]
    ctfctl codec cipher affine   "..." --a 5 --b 8 [--decrypt]
    ctfctl codec cipher bacon    "AABAB..." [--decrypt]
    ctfctl codec cipher polybius "..." [--decrypt]
    ctfctl codec cipher playfair "..." --key MONARCHY [--decrypt]
    ctfctl codec cipher xor      "明文" --key K          # → hex
    ctfctl codec cipher xor      "6162" --key K --decrypt  # hex → 明文
    ctfctl codec cipher rc4      "明文" --key Key [--hex-out] | --decrypt --hex-in
    ctfctl codec hash md5|sha1|sha256|sha512|hmac-sha256 --key K|pbkdf2 --salt S --iters N
    ctfctl codec extract --flags --urls --emails --b64 --regex 'RE'

不给文本时从 stdin 读（方便管道）。只做能在标准库里几行写完的东西；
AES/DES/更复杂的分组密码请用 CyberChef 或 CTFCrackTools（见 ctfctl tools show cyberchef）。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import string
import sys
import urllib.parse

# ---------------------------------------------------------------- 输入

def _input(args) -> str:
    t = getattr(args, "text", None)
    if t:
        return " ".join(t) if isinstance(t, list) else t
    return sys.stdin.read().strip()


# ---------------------------------------------------------------- 编码族

def _b64e(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _b64d(s: str) -> str:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return "[!] 不是合法 base64"


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58e(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + (out or "")


def _b58d(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58:
            raise ValueError(f"base58 里没有这个字符：{c!r}")
        n = n * 58 + _B58.index(c)
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")


MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.",
    "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.",
    "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-",
    "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
    "6": "-....", "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--",
    "?": "..--..", "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-",
    "&": ".-...", ":": "---...", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-",
    '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}
_MORSE_REV = {v: k for k, v in MORSE.items()}

def _brainfuck(code: str, limit: int = 20000) -> str:
    cells = [0] * 30000
    p, i, out, steps = 0, 0, [], 0
    depth = 0
    while i < len(code) and steps < limit:
        steps += 1
        c = code[i]
        if c == ">":
            p += 1
        elif c == "<":
            p -= 1
        elif c == "+":
            cells[p] = (cells[p] + 1) % 256
        elif c == "-":
            cells[p] = (cells[p] - 1) % 256
        elif c == ".":
            out.append(chr(cells[p]))
        elif c == "[" and cells[p] == 0:
            depth = 1
            while i < len(code) - 1 and depth:
                i += 1
                depth += {"[": 1, "]": -1}.get(code[i], 0)
        elif c == "]" and cells[p] != 0:
            depth = 1
            while i > 0 and depth:
                i -= 1
                depth += {"]": 1, "[": -1}.get(code[i], 0)
        i += 1
    return "".join(out)


def _rot47(s: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)


def _uu(s: str) -> str:
    return binascii.b2a_uu(s.encode()).decode().strip()


def _uud(s: str) -> str:
    out = []
    for line in s.splitlines():
        line = line.strip()
        if not line or line == "`":
            continue
        try:
            out.append(binascii.a2b_uu(line.encode()).decode("utf-8", "replace"))
        except binascii.Error:
            continue
    return "".join(out)


# ---------------------------------------------------------------- 古典密码

def caesar(s: str, shift: int) -> str:
    out = []
    for c in s:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            out.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def atbash(s: str) -> str:
    """Atbash：字母镜像（a↔z）。**非字母原样保留** —— 旧实现按任意字符算，遇到 CJK/emoji 直接
    `chr() arg not in range` 崩掉（喂整个文件文本时会炸）。"""
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z":
            out.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else:
            out.append(c)
    return "".join(out)



def _vig(s: str, key: str, decrypt: bool) -> str:
    key = re.sub(r"[^a-z]", "", key.lower())
    if not key:
        return "[!] vigenere 需要 --key"
    out, k = [], 0
    for c in s:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key[k % len(key)]) - 97
            out.append(chr((ord(c) - base + (-shift if decrypt else shift)) % 26 + base))
            k += 1
        else:
            out.append(c)
    return "".join(out)


def beaufort(s: str, key: str) -> str:
    key = re.sub(r"[^a-z]", "", key.lower())
    out, k = [], 0
    for c in s:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            out.append(chr((ord(key[k % len(key)]) - 97 - (ord(c) - base)) % 26 + base))
            k += 1
        else:
            out.append(c)
    return "".join(out)


def railfence(s: str, rails: int) -> str:
    """栅栏加密（按锯齿把字符分行拼起来）。解密用 _railfence_decrypt。"""
    if rails < 2:
        return "[!] --rails 至少 2"
    rows = [""] * rails
    r, d = 0, 1
    for c in s:
        rows[r] += c
        if r == 0:
            d = 1
        elif r == rails - 1:
            d = -1
        r += d
    return "".join(rows)


def _railfence_decrypt(s: str, rails: int) -> str:
    """栅栏解密（显式实现，别用上面那个炫技写法）。"""
    n = len(s)
    pattern, r, d = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            d = 1
        elif r == rails - 1:
            d = -1
        r += d
    counts = [pattern.count(i) for i in range(rails)]
    rows, idx = [], 0
    for c in counts:
        rows.append(list(s[idx:idx + c]))
        idx += c
    pos = [0] * rails
    out = []
    for row in pattern:
        out.append(rows[row][pos[row]])
        pos[row] += 1
    return "".join(out)


def affine(s: str, a: int, b: int, decrypt: bool) -> str:
    inv = {1: 1, 3: 9, 5: 21, 7: 15, 9: 3, 11: 19, 15: 7, 17: 23, 19: 11, 21: 5, 23: 17, 25: 25}
    if decrypt and a % 26 not in inv:
        return f"[!] a={a} 与 26 不互素，无法解密"
    out = []
    for c in s:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            x = ord(c) - base
            y = (inv[a % 26] * (x - b)) % 26 if decrypt else (a * x + b) % 26
            out.append(chr(y + base))
        else:
            out.append(c)
    return "".join(out)


_BACON = {"a": "0", "b": "1"}


def bacon(s: str, decrypt: bool) -> str:
    if decrypt:
        s = re.sub(r"[^aab]", "", s.lower())
        letters = [_BACON[c] for c in s]
        out = ""
        for i in range(0, len(letters) - 4, 5):
            idx = int("".join(letters[i:i + 5]), 2)
        # 5 位组的取值范围是 0..31，而字母表只有 26 个 —— 直接索引会 IndexError
        # （实测：任意二进制/乱码文本喂进来就崩）。超范围的组用 '?' 占位，不影响合法密文。
        out += string.ascii_uppercase[idx] if idx < 26 else "?"
        return out
    s = re.sub(r"[^A-Za-z]", "", s).upper()
    return "".join("".join("ab"[int(b)] for b in f"{ord(c) - 65:05b}") for c in s)


POLYBIUS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"     # 5x5，I/J 合并


def polybius(s: str, decrypt: bool) -> str:
    if decrypt:
        digits = re.sub(r"[^1-5]", "", s)
        out = ""
        for i in range(0, len(digits) - 1, 2):
            r, c = int(digits[i]) - 1, int(digits[i + 1]) - 1
            out += POLYBIUS[r * 5 + c]
        return out
    s = re.sub(r"[^A-Za-z]", "", s).upper().replace("J", "I")
    return " ".join(f"{POLYBIUS.index(c)//5+1}{POLYBIUS.index(c)%5+1}" for c in s)


def _playfair_square(key: str) -> list[str]:
    seen, sq = set(), []
    for c in re.sub(r"[^A-Za-z]", "", key).upper().replace("J", "I") + string.ascii_uppercase:
        if c == "J":
            continue
        if c not in seen:
            seen.add(c)
            sq.append(c)
    return sq


def playfair(s: str, key: str, decrypt: bool) -> str:
    sq = _playfair_square(key)
    pos = {c: divmod(i, 5) for i, c in enumerate(sq)}
    txt = re.sub(r"[^A-Za-z]", "", s).upper().replace("J", "I")
    if not decrypt:
        pairs, i = [], 0
        while i < len(txt):
            a = txt[i]
            b = txt[i + 1] if i + 1 < len(txt) else "X"
            if a == b:
                b = "X"
                i += 1
            else:
                i += 2
            pairs.append((a, b))
    else:
        pairs = [(txt[i], txt[i + 1]) for i in range(0, len(txt) - 1, 2)]
    out = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(sq[ra * 5 + (ca + (-1 if decrypt else 1)) % 5])
            out.append(sq[rb * 5 + (cb + (-1 if decrypt else 1)) % 5])
        elif ca == cb:
            out.append(sq[((ra + (-1 if decrypt else 1)) % 5) * 5 + ca])
            out.append(sq[((rb + (-1 if decrypt else 1)) % 5) * 5 + cb])
        else:
            out.append(sq[ra * 5 + cb])
            out.append(sq[rb * 5 + ca])
    return "".join(out)


def xor_brute(data: bytes, top: int = 5) -> str:
    scored = []
    for k in range(256):
        t = bytes(b ^ k for b in data)
        printable = sum(1 for c in t if 32 <= c < 127 or c in (9, 10, 13))
        score = printable / max(1, len(t))
        scored.append((score, k, t))
    scored.sort(key=lambda x: -x[0])
    out = []
    for score, k, t in scored[:top]:
        out.append(f"  key=0x{k:02x} ({score*100:.0f}% 可打印) {t[:60]!r}")
    return "\n".join(out)


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out, i, j = bytearray(), 0, 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


# ---------------------------------------------------------------- hash / 提取

def run_hash(args) -> int:
    data = _input(args).encode()
    algo = args.algo
    if algo == "hmac-sha256":
        if not args.key:
            print("[!] hmac-sha256 需要 --key", file=sys.stderr)
            return 2
        print(hmac.new(args.key.encode(), data, hashlib.sha256).hexdigest())
        return 0
    if algo == "pbkdf2":
        it = args.iters or 1000
        print(hashlib.pbkdf2_hmac("sha256", data, (args.salt or "").encode(), it).hex())
        print(f"  # pbkdf2-sha256 salt={args.salt or ''!r} iters={it}")
        return 0
    try:
        print(hashlib.new(algo, data).hexdigest())
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    return 0


EXTRACT_PATS = {
    "flags": r"[A-Za-z0-9_?]{1,24}\{[^}\n]{2,200}\}",
    "urls": r"https?://[^\s\"'<>)]+",
    "emails": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "b64": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])",
    "hex64": r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])",
}


def run_extract(args) -> int:
    s = _input(args)
    kinds = [k for k in ("flags", "urls", "emails", "ipv4", "b64", "hex64") if getattr(args, k)]
    if args.regex:
        kinds.append("regex")
    if not kinds:
        kinds = ["flags"]
    for k in kinds:
        pat = args.regex if k == "regex" else EXTRACT_PATS[k]
        hits = list(dict.fromkeys(m.group(0) for m in re.finditer(pat, s)))
        print(f"== {k}（{len(hits)}）")
        for h in hits[:40]:
            print(f"  {h}")
    return 0


# ---------------------------------------------------------------- 调度

def run(args) -> int:
    cmd = args.codec
    if cmd == "hash":
        return run_hash(args)
    if cmd == "extract":
        return run_extract(args)
    s = _input(args)
    if cmd == "cipher":
        return _run_cipher(args, s)
    simple = {
        "b64": _b64e, "b64d": _b64d,
        "b32": lambda x: base64.b32encode(x.encode()).decode(),
        "b32d": lambda x: base64.b32decode(x + "=" * (-len(x) % 8)).decode("utf-8", "replace"),
        "b85": lambda x: base64.b85encode(x.encode()).decode(),
        "b85d": lambda x: base64.b85decode(x).decode("utf-8", "replace"),
        "a85": lambda x: base64.a85encode(x.encode()).decode(),
        "a85d": lambda x: base64.a85decode(x).decode("utf-8", "replace"),
        "b58": lambda x: _b58e(x.encode()),
        "b58d": lambda x: _b58d(x).decode("utf-8", "replace"),
        "rot13": lambda x: caesar(x, 13),
        "rot47": _rot47, "uu": _uu, "uud": _uud,
        "morse": lambda x: " / ".join(" ".join(MORSE.get(c.upper(), "?") for c in w) for w in x.split()),
        "morsed": lambda x: "".join(_MORSE_REV.get(t, "?") for t in x.replace("/", " / ").split(" ") if t)
                             .replace("??", " ").replace("?", ""),
        "brainfuck": _brainfuck,
        "unicode": lambda x: x.encode("unicode_escape").decode(),
        "unicoded": lambda x: x.encode().decode("unicode_escape"),
        "htmld": lambda x: __import__("html").unescape(x),
        "binary": lambda x: " ".join(f"{b:08b}" for b in x.encode()),
        "guess": _guess,
    }
    if cmd in ("hex",):
        print(s.encode().hex())
    elif cmd in ("hexd",):
        try:
            print(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s)).decode("utf-8", "replace"))
        except ValueError:
            print("[!] 不是合法 hex")
    elif cmd == "url":
        print(urllib.parse.quote(s, safe=""))
    elif cmd == "urld":
        print(urllib.parse.unquote(s))
    elif cmd == "binaryd":
        bits = re.sub(r"[^01]", "", s)
        print("".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)))
    elif cmd in simple:
        try:
            print(simple[cmd](s))
        except Exception as e:
            print(f"[!] {type(e).__name__}: {e}")
            return 1
    return 0


def _run_cipher(args, s: str) -> int:
    algo = args.algo
    if algo == "caesar":
        if args.brute or args.shift is None:
            print("凯撒 26 个位移（看哪个像人话）：")
            for n in range(26):
                print(f"  shift={n:2}  {caesar(s, -n)[:100]}")
            return 0
        print(caesar(s, -args.shift if args.decrypt else args.shift))
    elif algo == "atbash":
        print(atbash(s))
    elif algo == "vigenere":
        print(_vig(s, args.key or "", args.decrypt))
    elif algo == "beaufort":
        print(beaufort(s, args.key or ""))
    elif algo == "railfence":
        if args.decrypt:
            print(_railfence_decrypt(s, args.rails or 3))
        else:
            print(railfence(s, args.rails or 3))
    elif algo == "affine":
        print(affine(s, args.a if args.a is not None else 5, args.b or 0, args.decrypt))
    elif algo == "bacon":
        print(bacon(s, args.decrypt))
    elif algo == "polybius":
        print(polybius(s, args.decrypt))
    elif algo == "playfair":
        if not args.key:
            print("[!] playfair 需要 --key", file=sys.stderr)
            return 2
        print(playfair(s, args.key, args.decrypt))
    elif algo == "xor":
        if args.brute:
            print(xor_brute(s.encode()))
        else:
            if not args.key:
                print("[!] xor 需要 --key 或 --brute", file=sys.stderr)
                return 2
            key = args.key.encode()
            if args.decrypt:                      # 解密：输入是 hex，输出是可读文本
                try:
                    data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s))
                except ValueError:
                    print("[!] --decrypt 时输入应是 hex", file=sys.stderr)
                    return 2
                print(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode("utf-8", "replace"))
            else:                                 # 加密：输入是文本，输出 hex
                print(bytes(b ^ key[i % len(key)] for i, b in enumerate(s.encode())).hex())
    elif algo == "rc4":
        if not args.key:
            print("[!] rc4 需要 --key", file=sys.stderr)
            return 2
        if args.decrypt:
            try:
                data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s))
            except ValueError:
                print("[!] --decrypt 时输入应是 hex（密文）", file=sys.stderr)
                return 2
            print(rc4(args.key.encode(), data).decode("utf-8", "replace"))
        else:
            print(rc4(args.key.encode(), s.encode()).hex())
    return 0


def _guess(s: str) -> str:
    out = []
    tried = []
    for name, fn in (("base64", _b64d), ("base32", simple_b32d), ("base58", lambda x: _b58d(x).decode("utf-8", "replace")),
                     ("base85", lambda x: base64.b85decode(x).decode("utf-8", "replace"))):
        try:
            r = fn(s)
            if r and all(32 <= ord(c) < 127 or c in "\n\t" for c in r[:60]) and len(r) >= 3:
                out.append(f"可能是 {name} → {r[:160]!r}")
        except Exception:
            pass
    if re.fullmatch(r"[0-9a-fA-F\s]+", s) and len(re.sub(r"\s", "", s)) % 2 == 0:
        tried.append("hex")
    if re.fullmatch(r"[01\s]{16,}", s):
        bits = re.sub(r"[^01]", "", s)
        txt = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))
        out.append(f"可能是二进制 → {txt[:160]!r}")
    if re.fullmatch(r"[.\-/\s]+", s) and ("." in s or "-" in s):
        out.append(f"可能是摩斯 → {simple_morse(s)[:160]!r}")
    if set(re.sub(r"[^a-zA-Z]", "", s).lower()) <= {"a", "b"} and len(re.sub(r"[^a-zA-Z]", "", s)) >= 20:
        out.append(f"可能是培根 → {bacon(s, True)[:120]}")
    if "a/b" and re.fullmatch(r"[aAbB]{20,}", s.replace(" ", "")):
        pass
    bf_chars = set("+-<>[].,")
    if (len(s) > 20 and set(s) <= bf_chars and set(s) & set("+<>[]")
            and not re.fullmatch(r"[.\-/\s]+", s)):      # 只由 . - / 组成的是摩斯，不是 brainfuck
        out.append(f"可能是 brainfuck → {_brainfuck(s)[:120]!r}")
    if "%" in s:
        out.append(f"可能是 URL 编码 → {urllib.parse.unquote(s)[:160]!r}")
    if s.count(".") == 2 and all(len(x) > 3 for x in s.split(".")):
        out.append("看起来是 JWT：ctfctl jwt decode <token>")
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", s):
        n = {32: "MD5", 40: "SHA1", 64: "SHA256"}[len(s)]
        out.append(f"是 {n} 哈希：ctfctl codec hash {n.lower()} … / hashcat -m " +
                   {"MD5": "0", "SHA1": "100", "SHA256": "1400"}[n])
    if not out:
        out.append("猜不出来：试 ctfctl codec cipher caesar --brute，或 CyberChef 的魔法棒")
    return "\n".join(out)


def simple_b32d(x: str) -> str:
    return base64.b32decode(x + "=" * (-len(x) % 8)).decode("utf-8", "replace")


def simple_morse(x: str) -> str:
    return "".join(_MORSE_REV.get(t, "?") for t in x.replace("/", " / ").split(" ") if t)


def register(sub) -> None:
    p = sub.add_parser("codec", help="编码/古典密码/哈希/提取（b64/b32/b58/b85/hex/url/rot/morse/"
                                     "cipher/hash/extract/guess）")
    v = p.add_subparsers(dest="codec", required=True)

    for name, help_ in (("b64", "→ base64"), ("b64d", "base64 →"), ("b32", "→ base32"),
                        ("b32d", "base32 →"), ("b85", "→ base85"), ("b85d", "base85 →"),
                        ("a85", "→ ascii85"), ("a85d", "ascii85 →"), ("b58", "→ base58"),
                        ("b58d", "base58 →"), ("hex", "→ hex"), ("hexd", "hex →"),
                        ("uu", "→ uuencode"), ("uud", "uuencode →"), ("url", "→ URL 编码"),
                        ("urld", "URL 解码 →"), ("rot13", "ROT13"), ("rot47", "ROT47"),
                        ("binary", "→ 二进制"), ("binaryd", "二进制 →"), ("morse", "→ 摩斯"),
                        ("morsed", "摩斯 →"), ("brainfuck", "跑 brainfuck"),
                        ("unicode", "→ \\uXXXX"), ("unicoded", "\\uXXXX →"),
                        ("htmld", "HTML 实体 →"), ("guess", "猜编码（多候选）")):
        sp = v.add_parser(name, help=help_)
        sp.add_argument("text", nargs="*", help="文本（不给则读 stdin）")
        sp.set_defaults(func=run)

    c = v.add_parser("cipher", help="古典密码/流密码：caesar/atbash/vigenere/beaufort/railfence/"
                                    "affine/bacon/polybius/playfair/xor/rc4")
    c.add_argument("algo", choices=["caesar", "atbash", "vigenere", "beaufort", "railfence",
                                    "affine", "bacon", "polybius", "playfair", "xor", "rc4"])
    c.add_argument("text", nargs="*", help="文本（不给则读 stdin）")
    c.add_argument("--key", help="密钥（vigenere/beaufort/playfair/xor/rc4）")
    c.add_argument("--shift", type=int, help="caesar 位移")
    c.add_argument("--rails", type=int, default=3, help="railfence 栏数（默认 3）")
    c.add_argument("--a", type=int, help="affine 的 a")
    c.add_argument("--b", type=int, default=0, help="affine 的 b")
    c.add_argument("--brute", action="store_true", help="穷举（caesar 全部位移 / xor 256 个单字节）")
    c.add_argument("--decrypt", action="store_true", help="反向（解密）")
    c.set_defaults(func=run)

    h = v.add_parser("hash", help="哈希：md5/sha1/sha256/sha512/hmac-sha256/pbkdf2")
    h.add_argument("algo", choices=["md5", "sha1", "sha256", "sha512", "hmac-sha256", "pbkdf2"])
    h.add_argument("text", nargs="*", help="文本（不给则读 stdin）")
    h.add_argument("--key", help="hmac 密钥")
    h.add_argument("--salt", help="pbkdf2 盐")
    h.add_argument("--iters", type=int, help="pbkdf2 迭代次数（默认 1000）")
    h.set_defaults(func=run)

    e = v.add_parser("extract", help="从文本里批量捞：--flags --urls --emails --ipv4 --b64 --hex64 --regex")
    e.add_argument("text", nargs="*", help="文本（不给则读 stdin）")
    for k in ("flags", "urls", "emails", "ipv4", "b64", "hex64"):
        e.add_argument(f"--{k}", action="store_true")
    e.add_argument("--regex", help="自定义正则")
    e.set_defaults(func=run)
