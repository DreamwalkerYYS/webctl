"""autosolve —— 部分题型的**自动推进闭环**（非 AI）：候选生成 + 现成工具 + 判定器裁决。

闭环类型（都有确定性判定器）：
  · 编码套娃   text → DFS 解码（深度≤4，节点/时间有预算），判定 text_readable/flag/file_magic
  · 古典密码   凯撒 26 / 阿特巴什 / 仿射 312 / 栅栏 2..10 / 培根 / 波利比奥斯，判定同上
  · 单字节 XOR 256 个密钥，按可打印率 + 判定器排序
  · 压缩包     弱口令 + 文件名/目录词汇 + 数字（有预算），zip 走 stdlib；7z/rar 有 CLI 才试；
              成功后**递归**分析里面的文件（深度≤2）
  · 图片 LSB   Pillow 在位时按位平面抽 ASCII（无 Pillow 则明确说 UNKNOWN，不瞎猜）
  · 元数据/夹带 exiftool / binwalk / foremost（在位才跑）
  · 哈希       长度+字符集识别；john + 字典在位才真跑
  · RSA        从文本里解析 n/e/c：小 e 整数根、Fermat 因数分解；RsaCtfTool 在位则端到端

红线（沿用）：不对靶机自动发利用流量、不写远端；本模块只读本地文件 + 写自己的缓存目录。
"""
from __future__ import annotations

import binascii
import gzip
import html
import json
import math
import os
import re
import shutil
import subprocess
import time
import unicodedata
import zlib

from . import oracles as O
from .config import CACHE, ensure_dirs

MAX_NODES = 400            # 编码链搜索上限
MAX_TRIALS = 6000          # 各类穷举的总试探上限
DIGIT_LIMIT = 10000        # 压缩包口令数字部分上限

WEAK_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
    "dragon", "123123", "abc123", "000000", "iloveyou", "letmein", "monkey", "admin", "root", "toor",
    "pass", "passwd", "test", "guest", "changeme", "secret", "flag", "ctf", "nssctf", "buuctf",
    "hitcon", "iscc", "flag{", "1qaz2wsx", "qwerty123", "a123456", "123qwe", "1q2w3e4r", "zaq12wsx",
    "P@ssw0rd", "p@ssword", "root123", "admin123", "666666", "888888", "5201314", "woaini",
]


# ---------------------------------------------------------------- 小工具

def _have(cmd: str) -> str:
    return shutil.which(cmd) or ""


def _run(cmd: list[str], timeout: int = 60, cwd: str | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd)
        out = (p.stdout or b"") + (p.stderr or b"")
        return p.returncode, out.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, f"{type(e).__name__}: {e}"


def _conf_of(results: list[dict]) -> int:
    """从判定结果里取置信：有硬证据→3；只有中/强中→2；否则 1。"""
    if any(r["verdict"] == "HIT" and r["conf"] >= 3 for r in results):
        return 3
    if any(r["verdict"] == "HIT" and r["conf"] == 2 for r in results):
        return 2
    return 1


def _step(sid: str, label: str, verdict: str = "MISS", conf: int = 1, reason: str = "",
          result: str = "", cmds: list[str] | None = None) -> dict:
    return {"id": sid, "label": label, "verdict": verdict, "conf": conf,
            "reason": reason, "result": result, "cmds": cmds or []}


# ---------------------------------------------------------------- 编码链

def _ops() -> list[tuple[str, callable]]:
    """可用解码算子。全部 stdlib；失败返回 None（不是异常）。"""
    from ..commands import codec as C

    def wrap(fn):
        def inner(s):
            try:
                v = fn(s)
            except Exception:
                return None
            if isinstance(v, (bytes, bytearray)):
                try:
                    v = bytes(v).decode("utf-8")
                except UnicodeDecodeError:
                    return None
            v = str(v)
            return v if v and v != s else None
        return inner

    def uud(s):
        return C._uud(s)

    def b58d(s):
        return C._b58d(s).decode("utf-8", "replace")

    def hexd(s):
        return binascii.unhexlify(re.sub(r"\s", "", s))

    def a85d(s):
        return binascii.a85decode(s.encode(), ignorechars=b" \n\r\t")

    def urld(s):
        import urllib.parse
        return urllib.parse.unquote(s)

    def unicoded(s):
        if "\\u" not in s and "\\x" not in s:
            return None
        return s.encode().decode("unicode_escape")

    def htmld(s):
        return html.unescape(s) if ("&" in s and ";" in s) else None

    def rev(s):
        return s[::-1] if len(s) > 8 else None

    def bin8(s):
        t = re.sub(r"[^01]", "", s)
        if len(t) < 8 or len(t) % 8:
            return None
        return "".join(chr(int(t[i:i + 8], 2)) for i in range(0, len(t), 8))

    def morse(s):
        return C.simple_morse(s) if re.fullmatch(r"[.\-/\s]+", s.strip()) and s.strip() else None

    return [
        ("base64", wrap(lambda s: __import__("base64").b64decode(s + "=" * ((4 - len(s) % 4) % 4), validate=False).decode("utf-8"))),
        ("base32", wrap(lambda s: __import__("base64").b32decode(s + "=" * ((8 - len(s) % 8) % 8), casefold=True).decode("utf-8"))),
        ("base58", wrap(b58d)),
        ("base85", wrap(lambda s: a85d(s).decode("utf-8"))),
        ("hex", wrap(hexd)),
        ("url", wrap(urld)),
        ("rot13", wrap(lambda s: __import__("codecs").decode(s, "rot13"))),
        ("rot47", wrap(C._rot47)),
        ("morse", wrap(morse)),
        ("binary8", wrap(bin8)),
        ("uuencode", wrap(uud)),
        ("html", wrap(htmld)),
        ("unicode-esc", wrap(unicoded)),
        ("reverse", wrap(rev)),
        ("gzip-hex", wrap(lambda s: gzip.decompress(bytes.fromhex(s)).decode("utf-8"))),
    ]


def decode_chain(text: str, max_depth: int = 4, budget_s: float = 20.0) -> dict:
    """在编码算子上做有界 DFS，用判定器挑最好的那条路（拿到硬命中立刻停）。"""
    t0 = time.time()
    text = (text or "").strip()
    if not text:
        return _step("decode-chain", "编码链", "ERROR", 1, "输入为空")
    ops = _ops()
    seen: set[int] = set()
    best = {"score": -1.0, "path": [], "value": text, "results": []}
    frontier = [([], text)]
    nodes = 0
    while frontier and nodes < MAX_NODES and time.time() - t0 < budget_s:
        path, cur = frontier.pop(0)
        h = hash(cur[:4000])
        if h in seen:
            continue
        seen.add(h)
        nodes += 1
        if path:                                   # 起点不判（原文本来就可读）
            results = O.judge_all(cur)
            hit, why = O.is_hit(results)
            sc = O.score(results) + (1000 if hit else 0) - len(path) * 0.1
            if sc > best["score"]:
                best = {"score": sc, "path": path, "value": cur, "results": results}
            if hit and any(r["oracle"] == "flag_regex" and r["verdict"] == "HIT" for r in results):
                break
        if len(path) >= max_depth:
            continue
        for name, fn in ops:
            v = fn(cur)
            if v and len(v) <= 200_000:
                frontier.append((path + [name], v))
    hit, why = O.is_hit(best["results"])
    return _step("decode-chain", f"编码链（试了 {nodes} 个节点，深度≤{max_depth}）",
                 "HIT" if hit else "UNKNOWN",
                 _conf_of(best["results"]) if hit else 1,
                 (f"{'→'.join(best['path'])}：{why}" if hit
                  else f"最像的路径 {'→'.join(best['path']) or '（无）'}：" +
                       (best["results"][0]["reason"] if best["results"] else "没有可用结果")),
                 best["value"][:2000],
                 [f"ctfctl codec {p}" for p in best["path"][:4]])


# ---------------------------------------------------------------- 古典密码

def classical_sweep(text: str, budget_s: float = 25.0) -> list[dict]:
    """凯撒/阿特巴什/仿射/栅栏/培根/波利比奥斯的全候选评分排序（返回前几名）。"""
    from ..commands import codec as C
    t0 = time.time()
    s = (text or "").strip()
    if len(s) < 4:
        return [_step("classical", "古典密码", "ERROR", 1, "文本太短")]
    cands: list[tuple[str, str]] = []
    for k in range(1, 26):
        cands.append((f"caesar-{k}", C.caesar(s, k)))
        if time.time() - t0 > budget_s:
            break
    cands.append(("atbash", C.atbash(s)))
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        for b in range(26):
            cands.append((f"affine-{a}-{b}", C.affine(s, a, b, True)))
            if time.time() - t0 > budget_s:
                break
    for r in range(2, 11):
        cands.append((f"railfence-{r}", C._railfence_decrypt(s, r)))
    if re.fullmatch(r"[abAB\s]{4,}", s):
        cands.append(("bacon", C.bacon(s, True)))
    if re.fullmatch(r"[1-5\s]{4,}", s):
        cands.append(("polybius", C.polybius(s, True)))

    out = []
    for name, val in cands:
        if not val or val == s:            # 没变过的不算（"原文可读"不是答案）
            continue
        results = O.judge_all(val)
        hit, why = O.is_hit(results)
        sc = O.score(results) + (500 if hit else 0)
        out.append(_step("classical", f"古典密码 {name}", "HIT" if hit else "MISS",
                         _conf_of(results) if hit else 1,
                         why or (results[0]["reason"] if results else ""),
                         val[:2000], [f"ctfctl codec cipher {name.split('-')[0]} ..."]))
    out.sort(key=lambda d: (-(100 if d["conf"] == 3 else 10 if d["conf"] == 2 else 0),
                            -len(d["result"])))
    seen_val, uniq = set(), []
    for d in out:                                   # 同一结果只留第一个名字（affine-1-7 == caesar-19）
        key = d["result"][:200]
        if key in seen_val:
            continue
        seen_val.add(key)
        uniq.append(d)
    return uniq[:5]


# ---------------------------------------------------------------- 单字节 XOR

def xor_sweep(data: bytes, budget_s: float = 20.0) -> list[dict]:
    t0 = time.time()
    raw = bytes(data or b"")
    if len(raw) < 8:
        return [_step("xor", "单字节 XOR", "ERROR", 1, "数据太短")]
    scored = []
    for k in range(256):
        if time.time() - t0 > budget_s:
            break
        x = bytes(b ^ k for b in raw)
        pr = sum(1 for b in x if 32 <= b < 127 or b in (9, 10, 13)) / len(x)
        if pr < 0.80:
            continue
        results = O.judge_all(x, as_bytes=True)
        hit, why = O.is_hit(results)
        scored.append((O.score(results) + pr * 20 + (500 if hit else 0), k, x, results, hit, why))
    scored.sort(key=lambda t: -t[0])
    out = []
    for sc, k, x, results, hit, why in scored[:5]:
        out.append(_step("xor", f"单字节 XOR key=0x{k:02x}", "HIT" if hit else "UNKNOWN",
                         _conf_of(results) if hit else 1,
                         why or f"可打印率 {(sum(1 for b in x if 32 <= b < 127) / len(x)):.2f}",
                         x.decode("utf-8", "replace")[:2000], [f"ctfctl codec cipher xor <hex> --key 0x{k:02x} --decrypt"]))
    return out or [_step("xor", "单字节 XOR", "UNKNOWN", 1, "256 个密钥都没给出可读结果")]


# ---------------------------------------------------------------- 压缩包

def _pwd_candidates(path: str) -> list[str]:
    words = list(WEAK_PASSWORDS)
    stem = os.path.splitext(os.path.basename(path))[0]
    if stem and len(stem) <= 20:
        words += [stem, stem.lower(), stem.upper()]
    d = os.path.dirname(os.path.abspath(path))
    for name in (os.path.basename(d), os.path.basename(os.path.dirname(d))):
        if name and 2 <= len(name) <= 20:
            words += [name, name.lower()]
    seen, out = set(), []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def archive_auto(path: str, depth: int = 2, budget_s: float = 90.0) -> list[dict]:
    """压缩包闭环：zip 用 stdlib 试口令；7z/rar 有 CLI 才试。成功则递归分析内层文件。"""
    import zipfile
    steps: list[dict] = []
    t0 = time.time()
    if not os.path.exists(path):
        return [_step("archive", "压缩包", "ERROR", 1, f"文件不存在：{path}")]
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                encrypted = any(i.flag_bits & 0x1 for i in infos)
                if not encrypted:
                    steps.append(_step("archive", f"ZIP（{len(infos)} 条目，未加密）", "HIT", 3,
                                       "不需要口令，直接可读", "",
                                       [f"ctfctl file {path}"]))
                    target_dir = _unzip_here(path, None, steps)
                else:
                    target_dir = None
                    cands = _pwd_candidates(path)
                    tried = 0
                    for pwd in cands + [str(i) for i in range(0, DIGIT_LIMIT)]:
                        if time.time() - t0 > budget_s or tried > MAX_TRIALS:
                            break
                        tried += 1
                        if z.read(infos[0].filename, pwd=pwd.encode()) is not None:
                            steps.append(_step("archive", f"ZIP 口令命中（试了 {tried} 个）", "HIT", 3,
                                               f"口令 = {pwd}（ZipCrypto 可读）", pwd))
                            target_dir = _unzip_here(path, pwd, steps)
                            break
                    if target_dir is None:
                        steps.append(_step("archive", f"ZIP 需要口令（试了 {tried} 个候选）", "UNKNOWN", 1,
                                           "弱口令/文件名/数字都没中：字典不够或口令有语义，需人工/更大字典",
                                           "", [f"zip2john {path} > h.txt && john --wordlist=字典 h.txt"]))
        except Exception as e:
            steps.append(_step("archive", "ZIP 处理出错", "ERROR", 1, f"{type(e).__name__}: {e}"))
    else:
        sz = _have("7z") or _have("7za")
        ur = _have("unrar")
        if sz and path.lower().endswith((".7z", ".zip")):
            for pwd in _pwd_candidates(path)[:200]:
                rc, out = _run([sz, "t", f"-p{pwd}", "-y", path], timeout=30)
                if rc == 0:
                    steps.append(_step("archive", f"7z 口令命中", "HIT", 3, f"口令 = {pwd}", pwd))
                    steps.append(_step("archive", "7z 解包", "HIT", 2, "已解到缓存目录",
                                       _unzip7z(path, pwd)))
                    break
            else:
                steps.append(_step("archive", "7z 需要口令/未知", "UNKNOWN", 1, "候选没命中"))
        elif ur and path.lower().endswith(".rar"):
            steps.append(_step("archive", "RAR", "UNKNOWN", 1, "有 unrar：先看是否需要口令",
                               "", [f"unrar l {path}"]))
        else:
            steps.append(_step("archive", "压缩包", "UNKNOWN", 1,
                               "不是 zip/tar，且没装 7z/unrar（主机上有 7z 与 unrar）"))

    # 递归：把解出来的内层文件也走一遍自动闭环
    if depth > 0:
        for d in [s.get("result") for s in steps if s["result"] and os.path.isdir(str(s.get("result", "")))]:
            for root, _, files in os.walk(d):
                for f in files[:20]:
                    p = os.path.join(root, f)
                    if os.path.getsize(p) > 20 * 1024 * 1024:
                        continue
                    inner = auto_file(p, depth=depth - 1, budget_s=min(30.0, budget_s))
                    for st in inner:
                        st["label"] = f"[内层 {f}] " + st["label"]
                    steps += inner
    return steps


def _unzip_here(path: str, pwd: str | None, steps: list[dict]) -> str | None:
    import zipfile
    ensure_dirs()
    out = os.path.join(CACHE, "auto", os.path.basename(path) + ".d")
    try:
        os.makedirs(out, exist_ok=True)
        with zipfile.ZipFile(path) as z:
            z.extractall(out, pwd=pwd.encode() if pwd else None)
        steps.append(_step("archive", "ZIP 解包", "HIT", 2, f"已解到 {out}", out))
        return out
    except Exception as e:
        steps.append(_step("archive", "ZIP 解包失败", "ERROR", 1, f"{type(e).__name__}: {e}"))
        return None


def _unzip7z(path: str, pwd: str) -> str:
    sz = _have("7z") or _have("7za")
    out = os.path.join(CACHE, "auto", os.path.basename(path) + ".d")
    os.makedirs(out, exist_ok=True)
    _run([sz, "x", f"-p{pwd}", "-y", f"-o{out}", path], timeout=60)
    return out


# ---------------------------------------------------------------- 图片 / 元数据

def image_auto(path: str) -> list[dict]:
    steps: list[dict] = []
    try:
        from PIL import Image                                     # 主机有；容器没有
    except ImportError:
        return [_step("image", "图片 LSB", "UNKNOWN", 1,
                      "没有 Pillow（主机的 python3 有，容器没有）：在主机上跑能得到 LSB 结果")]
    try:
        im = Image.open(path).convert("RGB")
        px, w, h = im.load(), im.size[0], im.size[1]
        for mode_name, pick in (("R 通道低位", lambda p: p[0]),
                                ("RGB 交错低位", None)):
            bits = []
            if pick:
                for y in range(h):
                    for x in range(w):
                        bits.append(pick(px[x, y]) & 1)
            else:
                for y in range(h):
                    for x in range(w):
                        for c in range(3):
                            bits.append(px[x, y][c] & 1)
            text = "".join(chr(int("".join(str(b) for b in bits[i:i + 8]), 2))
                           for i in range(0, len(bits) - 7, 8))
            runs = [r for r in re.findall(r"[\x20-\x7e\n\r\t]{6,}", text)]
            joined = "\n".join(runs)
            if not joined.strip():
                steps.append(_step("image", f"图片 LSB（{mode_name}）", "MISS", 1, "没抽出可打印串"))
                continue
            results = O.judge_all(joined)
            hit, why = O.is_hit(results)
            steps.append(_step("image", f"图片 LSB（{mode_name}）", "HIT" if hit else "UNKNOWN",
                               3 if hit else 1, why or f"抽出 {len(runs)} 段可打印串（像噪声）",
                               joined[:2000]))
    except Exception as e:
        steps.append(_step("image", "图片解析失败", "ERROR", 1, f"{type(e).__name__}: {e}"))
    return steps


def meta_auto(path: str, extract: bool = False) -> list[dict]:
    steps: list[dict] = []
    ex, bw, fm = _have("exiftool"), _have("binwalk"), _have("foremost")
    if ex:
        rc, out = _run([ex, "-a", "-u", "-g1", path], timeout=60)
        results = O.judge_all(out)
        hit, why = O.is_hit(results)
        steps.append(_step("meta", "exiftool 全字段", "HIT" if hit else "UNKNOWN",
                           3 if hit else 1, why or "字段里没有 flag 样式", out[:1500] if hit else ""))
    if bw:
        rc, out = _run([bw, path], timeout=120)
        sigs = re.findall(r"^\s*\d+\s+0x[0-9A-F]+.*$", out, re.M)[:12]
        results = O.judge_all(out)
        hit, why = O.is_hit(results)
        steps.append(_step("meta", f"binwalk（{len(sigs)} 个签名）", "HIT" if hit else "UNKNOWN",
                           3 if hit else 1, why or "签名里有嵌东西的迹象（见结果）",
                           "\n".join(sigs)[:1200]))
        if extract:
            out_dir = os.path.join(CACHE, "auto", os.path.basename(path) + ".binwalk")
            os.makedirs(out_dir, exist_ok=True)
            _run([bw, "-e", "-C", out_dir, path], timeout=180)
            steps.append(_step("meta", "binwalk 递归解包", "UNKNOWN", 1, f"已解到 {out_dir}", out_dir))
    if fm and extract:
        out_dir = os.path.join(CACHE, "auto", os.path.basename(path) + ".foremost")
        os.makedirs(out_dir, exist_ok=True)
        _run([fm, "-i", path, "-o", out_dir], timeout=180)
        steps.append(_step("meta", "foremost 雕刻", "UNKNOWN", 1, f"已雕刻到 {out_dir}", out_dir))
    if not steps:
        steps.append(_step("meta", "元数据/夹带", "UNKNOWN", 1,
                           "没有 exiftool/binwalk/foremost（主机上都有）"))
    return steps


# ---------------------------------------------------------------- 哈希 / RSA

def hash_auto(text: str) -> list[dict]:
    s = (text or "").strip()
    kinds = []
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        kinds = ["MD5", "NTLM"]
    elif re.fullmatch(r"[0-9a-fA-F]{40}", s):
        kinds = ["SHA1", "MySQL5"]
    elif re.fullmatch(r"[0-9a-fA-F]{64}", s):
        kinds = ["SHA256", "SHA3-256"]
    elif re.fullmatch(r"[0-9a-fA-F]{128}", s):
        kinds = ["SHA512"]
    elif s.startswith("$2"):
        kinds = ["bcrypt"]
    elif s.startswith("$pbkdf2"):
        kinds = ["PBKDF2"]
    if not kinds:
        return []
    steps = [_step("hash", f"哈希识别：{len(s)} 位 → {'/'.join(kinds)}", "UNKNOWN", 2,
                   "算法已定，下一步查库或爆破", s[:80])]
    john = _have("john")
    wl = next((w for w in ("/usr/share/wordlists/rockyou.txt", "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
                           os.path.expanduser("~/wordlists/rockyou.txt")) if os.path.exists(w)), "")
    if john and wl:
        hf = os.path.join(CACHE, "auto", "hash.txt")
        os.makedirs(os.path.dirname(hf), exist_ok=True)
        open(hf, "w").write(s + "\n" + (s + "\n") * 0)
        rc, out = _run([john, f"--wordlist={wl}", f"--format={kinds[0].lower()}", hf], timeout=300)
        if rc == 0 and "password" in out.lower():
            steps.append(_step("hash", "john 爆破", "HIT", 3, "字典命中", out[-400:]))
        else:
            steps.append(_step("hash", "john 爆破", "UNKNOWN", 1, "字典没命中（换更大字典/规则）",
                               "", [f"john --wordlist={wl} --format={kinds[0].lower()} {hf}"]))
    else:
        steps.append(_step("hash", "爆破", "UNKNOWN", 1,
                           "没装 john 或找不到字典，给出命令让你自己跑",
                           "", [f"hashcat -m 0 h.txt 字典" if not john else "john: 需要有字典文件"]))
    return steps


def rsa_auto(text: str) -> list[dict]:
    """从文本里解析 n/c/e，试**确定性**攻击族：小 e 整数根、Fermat 分解。"""
    steps: list[dict] = []
    nums = {k: [] for k in ("n", "e", "c", "p", "q")}
    for key, val in re.findall(r"\b([ncepq])\s*[=:]\s*(0x[0-9a-fA-F]+|\d{3,})", text or ""):
        try:
            nums[key].append(int(val, 16) if val.lower().startswith("0x") else int(val))
        except ValueError:
            pass
    n = nums["n"][0] if nums["n"] else None
    e = nums["e"][0] if nums["e"] else (65537 if n and not nums["e"] else None)
    c = nums["c"][0] if nums["c"] else None
    if not n:
        return steps
    steps.append(_step("rsa", f"RSA 参数：n={n.bit_length()} 位 e={e}", "UNKNOWN", 2,
                       "已解析出参数，试确定性攻击族"))
    if c and e and e < 20:                                     # 小 e：直接开整数根
        m, exact = _iroot(c, e)
        if exact:
            b = m.to_bytes((m.bit_length() + 7) // 8, "big")
            results = O.judge_all(b, as_bytes=True)
            hit, why = O.is_hit(results)
            steps.append(_step("rsa", f"小 e 整数根（e={e}）", "HIT" if hit else "UNKNOWN",
                               3 if hit else 1, why or "开得出整数根但内容不可读", b.decode("utf-8", "replace")[:500]))
    f = _fermat(n)
    if f:
        p, q = f
        steps.append(_step("rsa", "Fermat 分解成功", "HIT", 3, f"p={p}\nq={q}", f"{p}\n{q}"))
    if not [s for s in steps if s["verdict"] == "HIT"]:
        tool = _have("RsaCtfTool") or _have("rsactftool")
        if tool:
            steps.append(_step("rsa", "RsaCtfTool 端到端", "UNKNOWN", 1,
                               "已装：给出命令自己跑（避免长时间占用）",
                               "", [f"{tool} --publickey key.pub --private",
                                    f"{tool} --publickey key.pub --decryptfile ciphertext"]))
        else:
            steps.append(_step("rsa", "攻击族未命中", "UNKNOWN", 1,
                               "没装 RsaCtfTool：可试 Wiener / 共模 / 已知 p,q / 大数分解",
                               "", ["pipx install RsaCtfTool   # 或 yafu/cado-nfs 分解 n"]))
    return steps


def _iroot(x: int, k: int) -> tuple[int, bool]:
    if x < 0:
        return 0, False
    lo, hi = 0, 1 << ((x.bit_length() // k) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** k == x


def _fermat(n: int, rounds: int = 100000) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


# ---------------------------------------------------------------- 调度

def auto_text(text: str, budget_s: float = 30.0) -> list[dict]:
    steps: list[dict] = []
    # ① 先判"原文"：很多题的附件里 flag 就是明文（少了这一步会白跑一圈）
    base_results = O.judge_all(text)
    # 原文判定**只认硬证据**：flag / 容器格式 / 可读压缩包 / 合法填充。
    # 「文本可读」不能算（源码、题面、提示串都是可读文本 —— 实测把 .asm 源码判成"闭合"）
    HARD = ("flag_regex", "file_magic", "archive_readable", "pkcs7_valid")
    hard = [r for r in base_results if r["verdict"] == "HIT" and r["conf"] >= 3 and r["oracle"] in HARD]
    if hard:
        steps.append(_step("as-is", "原文判定", "HIT", 3, hard[0]["reason"], text[:2000]))
        return steps
    steps.append(_step("as-is", "原文判定", "MISS", 1,
                       "原文里没有硬证据（flag/容器）：进入解码与逆变换"))
    steps.append(decode_chain(text, budget_s=min(20.0, budget_s)))
    if not any(s["verdict"] == "HIT" and s["conf"] >= 3 for s in steps):
        steps += classical_sweep(text, budget_s=min(15.0, budget_s))[:3]
        raw = None
        t = text.strip()
        if re.fullmatch(r"[0-9a-fA-F\s]{16,}", t):
            try:
                raw = bytes.fromhex(re.sub(r"\s", "", t))
            except ValueError:
                raw = None
        if raw is None and re.fullmatch(r"[A-Za-z0-9+/=]{16,}", t):
            import base64
            try:
                raw = base64.b64decode(t + "=" * ((4 - len(t) % 4) % 4), validate=False)
            except Exception:
                raw = None
        if raw:
            steps += xor_sweep(raw, budget_s=min(10.0, budget_s))[:2]
        steps += hash_auto(text)
        steps += rsa_auto(text)
    return steps


def auto_file(path: str, depth: int = 2, budget_s: float = 90.0, extract: bool = False) -> list[dict]:
    """按类型走对应闭环；文本类再补编码/古典/XOR/哈希/RSA。"""
    from ..commands import file as file_cmd
    steps: list[dict] = []
    if not os.path.exists(path):
        return [_step("auto", "自动闭环", "ERROR", 1, f"文件不存在：{path}")]
    t = file_cmd.triage(path, 20)
    kind = t.get("kind") or t.get("magic") or "未知类型"
    findings = t.get("findings", [])
    steps.append(_step("auto", f"类型：{kind}（{', '.join(findings[:4]) or '无标签'}）", "UNKNOWN", 2,
                       "初筛结论（结构/内嵌/保护/熵）"))
    try:
        data = open(path, "rb").read(4 * 1024 * 1024)
    except OSError as e:
        return steps + [_step("auto", "读文件失败", "ERROR", 1, str(e))]

    # 汇编源码型（.asm/.s 或含 db + 汇编助记符）：先走 rev 的变换链重放
    head = data[:4096]
    looks_asm = bool(re.search(rb"^\s*\.(8086|model|data|code)\b", head, re.M)) or \
        (b"db " in head and re.search(rb"\b(mov|lea|xor|cmp|jne|loop|int)\b", head, re.I))
    if looks_asm:
        from . import revauto as R
        steps += R.rev_asm_source(path, budget_s=min(30.0, budget_s))
        if O.flags_in("\n".join(x.get("result", "") for x in steps)):
            return steps
    if kind == "text" or t.get("text"):
        try:
            dec = file_cmd.decode_text(data)            # 多编码回退（UTF-8→GB18030→BIG5）
            text = dec.get("text", "")
            if dec.get("encoding") not in ("utf-8", "ascii"):
                steps.append(_step("auto", f"文本编码：{dec.get('encoding')}", "UNKNOWN", 2,
                                   "按该编码解码后再做后续闭环"))
        except Exception:
            text = data.decode("utf-8", "replace")
        steps += auto_text(text[:200000], budget_s=budget_s)
    if re.search(r"\.(zip|7z|rar|tar|gz|tgz|bz2|xz)$", path, re.I) or data[:2] == b"PK":
        steps += archive_auto(path, depth=depth, budget_s=budget_s)
    if data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff" or data[:4] == b"GIF8":
        steps += image_auto(path)
    if data[:4] == b"\x7fELF" or data[:2] == b"MZ":
        from . import revauto as R          # rev（逆向）有它自己的分档闭环
        steps += R.rev_auto(path, budget_s=budget_s)
    if findings or kind in ("file", "?", "binary"):
        steps += meta_auto(path, extract=extract)
    return steps


def run_auto(target: str, depth: int = 2, budget_s: float = 120.0, extract: bool = False) -> list[dict]:
    if target.startswith(("http://", "https://")):
        from .solve import SolveState
        st = SolveState(target)
        for _ in st.advance(limit=3, budget_s=budget_s):
            pass
        return [_step("auto", "Web：交互推进 3 步（只读探针）",
                      "HIT" if st.flags else "UNKNOWN", 3 if st.flags else 1,
                      (f"拿到 flag 候选：{st.flags[-1]}" if st.flags else "见 solve 状态（下一步清单）"),
                      st.report())]
    return auto_file(target, depth=depth, budget_s=budget_s, extract=extract)


def flags_of(steps: list[dict]) -> list[str]:
    """把**所有**步骤结果里的可信 flag 收齐（去重，保序）—— 口令与 flag 往往在不同步骤里。"""
    out: list[str] = []
    for s in steps:
        for f in O.flags_in(s.get("result", "") or ""):
            if f not in out:
                out.append(f)
    return out


def summarize(steps: list[dict]) -> tuple[bool, str]:
    """是否闭合：硬证据或中证据（中证据要人工扫一眼确认）+ 一句话结论。"""
    hard = [s for s in steps if s["verdict"] == "HIT" and s["conf"] >= 3]
    mid = [s for s in steps if s["verdict"] == "HIT" and s["conf"] == 2]
    flags = flags_of(steps)
    if hard:
        return True, (f"闭合（硬证据）：{hard[0]['label']} —— {hard[0]['reason']}" +
                      (f"；flag 候选 {flags[0]}" if flags else ""))
    if mid:
        return True, (f"闭合（中证据，扫一眼确认）：{mid[0]['label']} —— {mid[0]['reason']}" +
                      (f"；flag 候选 {flags[0]}" if flags else ""))
    unk = [s for s in steps if s["verdict"] == "UNKNOWN"]
    return False, f"未闭合（{len(unk)} 条需人工判断，见上面逐条依据）"
