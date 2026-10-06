"""file —— 文件/二进制初筛（misc · rev · pwn · crypto 的第一步）。

    ctfctl file chal.zip              # 类型 + 哈希 + 结构 + 发现 + 建议
    ctfctl file ./pwn --strings 40    # 多打些字符串
    ctfctl file ./p.png --json        # 给脚本/别的工具用

它自己不做利用，只做「看得见」的事：识别类型、拆结构（PNG 块 / ZIP 条目 / ELF 头）、
找附加数据与内嵌文件、看熵、捞可疑字符串，然后把发现喂给建议引擎（core/advise.py）
给出下一步方向 + 推荐工具。全部标准库，不联网、不改文件。
"""
from __future__ import annotations

import binascii
import hashlib
import json
import math
import os
import re
import struct
import sys
import zipfile

from ..core import advise as advise_mod

# ------------------------------------------------------------------ 常量

#: (偏移, 签名, 名字) —— 只看开头几个字节就够用的那些
MAGICS = [
    (0, b"\x89PNG\r\n\x1a\n", "PNG 图片"),
    (0, b"\xff\xd8\xff", "JPEG 图片"),
    (0, b"GIF87a", "GIF 图片"), (0, b"GIF89a", "GIF 图片"),
    (0, b"BM", "BMP 图片"),
    (0, b"RIFF", "RIFF 容器(WAV/AVI)"),
    (0, b"ID3", "MP3 音频"),
    (0, b"fLaC", "FLAC 无损音频"),
    (0, b"OggS", "OGG 音频"),
    (0, b"%PDF-", "PDF 文档"),
    (0, b"PK\x03\x04", "ZIP 压缩包"), (0, b"PK\x05\x06", "ZIP 压缩包(空)"),
    (0, b"Rar!\x1a\x07", "RAR 压缩包"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z 压缩包"),
    (0, b"\x1f\x8b", "gzip 压缩流"),
    (0, b"BZh", "bzip2 压缩流"),
    (0, b"\xfd7zXZ", "xz 压缩流"),
    (0, b"ustar", "tar 归档"),
    (0, b"\x7fELF", "ELF 可执行/目标文件"),
    (0, b"MZ", "PE/DOS 可执行(Windows)"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (0, b"SQLite format 3\x00", "SQLite 数据库"),
    (0, b"\xd4\xc3\xb2\xa1", "PCAP 抓包"), (0, b"\xa1\xb2\xc3\xd4", "PCAP 抓包"),
    (0, b"\x0a\x0d\x0d\x0a", "PCAPNG 抓包"),
    (0, b"-----BEGIN", "PEM 密钥/证书"),
    (0, b"\\documentclass", "LaTeX 源码"),
]

#: 用来找「内嵌在别处的文件」的签名（binwalk 风格）
EMBED = [
    (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff\xe0", "JPEG"), (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP"), (b"Rar!\x1a\x07", "RAR"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"), (b"%PDF-", "PDF"), (b"\x7fELF", "ELF"),
    (b"SQLite format 3\x00", "SQLite"), (b"BZh", "bzip2"),
]

FLAG_RE = re.compile(rb"[A-Za-z0-9_?]{1,24}\{[^}\n]{2,200\}")
#: 只在一段可打印串里找 flag，且要求前缀从词边界开始 —— 否则随机二进制里的 `{` 会满屏假命中
FLAG_IN_STR = re.compile(r"(?<![A-Za-z0-9_.])([A-Za-z0-9_?]{1,24}\{[^}\n]{2,200}\})")
STR_RE = re.compile(rb"[\x20-\x7e]{6,}")
INTERESTING = re.compile(r"(flag|ctf|key|pass|secret|token|admin|/bin/|/flag|http://|https://|\.php|system|exec|/etc/|root:|BEGIN )", re.I)


# ------------------------------------------------------------------ 小工具

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def magic_name(head: bytes, path: str) -> str:
    for off, sig, name in MAGICS:
        if off + len(sig) <= len(head) and head[off:off + len(sig)] == sig:
            return name
    if path.lower().endswith((".tar", ".tar.gz", ".tgz")) and b"ustar" in head[:300]:
        return "tar 归档"
    return "未知/纯文本" if _looks_text(head) else "未知二进制"


def _looks_text(b: bytes) -> bool:
    if not b:
        return False
    sample = b[:4096]
    printable = sum(1 for x in sample if 9 <= x <= 13 or 32 <= x <= 126 or x >= 0x80)
    return printable / len(sample) > 0.92


def find_embedded(data: bytes, limit: int = 20) -> list[dict]:
    hits = []
    for sig, name in EMBED:
        start = 1
        while True:
            i = data.find(sig, start)
            if i < 0 or len(hits) >= limit:
                break
            hits.append({"offset": i, "type": name})
            start = i + 1
    return sorted(hits, key=lambda h: h["offset"])


def appended_tail(data: bytes, kind: str) -> dict | None:
    """结构末尾之后还挂着东西？PNG(IEND) / JPEG(FFD9) / ZIP(EOCD) / GIF(3B) / PDF(%%EOF)。"""
    end = None
    if kind == "PNG 图片":
        i = data.rfind(b"IEND")
        if i >= 0:
            end = i + 8                      # IEND + CRC
    elif kind == "JPEG 图片":
        i = data.rfind(b"\xff\xd9")
        end = i + 2 if i >= 0 else None
    elif kind == "GIF 图片":
        i = data.rfind(b"\x3b")
        end = i + 1 if i >= 0 else None
    elif kind.startswith("ZIP"):
        i = data.rfind(b"PK\x05\x06")
        if i >= 0 and i + 22 <= len(data):
            cdsize, _, n = struct.unpack("<IHH", data[i + 12:i + 20])
            end = i + 22 + cdsize + n
    elif kind == "PDF 文档":
        i = data.rfind(b"%%EOF")
        end = i + 5 if i >= 0 else None
    if end is None or end >= len(data):
        return None
    tail = len(data) - end
    if tail < 8:
        return None
    return {"offset": end, "bytes": tail, "preview": data[end:end + 16]}


def png_report(data: bytes) -> dict:
    out: dict = {"chunks": [], "bad_crc": [], "dims": None, "chunk_after_iend": False}
    if not data.startswith(b"\x89PNG"):
        return out
    i, seen_iend = 8, False
    while i + 8 <= len(data):
        (ln,) = struct.unpack(">I", data[i:i + 4])
        typ = data[i + 4:i + 8]
        if not re.fullmatch(rb"[A-Za-z]{4}", typ):
            break
        body = data[i + 8:i + 8 + ln]
        crc = data[i + 8 + ln:i + 12 + ln]
        out["chunks"].append({"type": typ.decode("latin1"), "len": ln})
        if len(crc) == 4 and binascii.crc32(typ + body) & 0xffffffff != struct.unpack(">I", crc)[0]:
            out["bad_crc"].append(typ.decode("latin1"))
        if typ == b"IHDR" and len(body) >= 8:
            w, h = struct.unpack(">II", body[:8])
            out["dims"] = [w, h]
            out["ihdr"] = {"depth": body[8], "color": body[9], "interlace": body[12]} if len(body) >= 13 else {}
        if seen_iend:
            out["chunk_after_iend"] = True
            break
        if typ == b"IEND":
            seen_iend = True
        i += 12 + ln
    return out


def jpeg_dims(data: bytes) -> list[int] | None:
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        (ln,) = struct.unpack(">H", data[i + 2:i + 4])
        if m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return [w, h]
        i += 2 + ln
    return None


def elf_report(data: bytes) -> dict:
    out: dict = {"class": None, "endian": None, "type": None, "machine": None,
                 "nx": None, "pie": None, "relro": None, "canary": None, "notes": []}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return out
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    out["class"] = "64-bit" if is64 else "32-bit"
    out["endian"] = "little" if data[5] == 1 else "big"
    et = struct.unpack(e + "H", data[16:18])[0]
    out["type"] = {1: "REL(目标文件)", 2: "EXEC(可执行)", 3: "DYN(共享库/PIE)", 4: "CORE"}.get(et, str(et))
    em = struct.unpack(e + "H", data[18:20])[0]
    out["machine"] = {3: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0x08: "MIPS"}.get(em, f"machine={em}")
    out["pie"] = "on" if et == 3 else "off"
    # 程序头：GNU_STACK 的 flags 给 NX，GNU_RELRO 段给 RELRO
    if is64:
        phoff, phentsize, phnum = struct.unpack(e + "Q", data[32:40])[0], struct.unpack(e + "H", data[54:56])[0], struct.unpack(e + "H", data[56:58])[0]
    else:
        phoff, phentsize, phnum = struct.unpack(e + "I", data[28:32])[0], struct.unpack(e + "H", data[42:44])[0], struct.unpack(e + "H", data[44:46])[0]
    for k in range(phnum):
        off = phoff + k * phentsize
        if off + phentsize > len(data):
            break
        if is64:
            p_type, p_flags = struct.unpack(e + "II", data[off:off + 8])
        else:
            p_type, _, p_flags = struct.unpack(e + "III", data[off:off + 12])
        if p_type == 0x6474e551:                     # PT_GNU_STACK
            out["nx"] = "off" if p_flags & 0x1 else "on"
        if p_type == 0x6474e552:                     # PT_GNU_RELRO
            out["relro"] = "on（未验证 BIND_NOW）"
    for tok, label in ((b"__stack_chk_fail", "canary"), (b"__libc_start_main", "libc"),
                       (b"/bin/sh", "有 /bin/sh 字符串")):
        if tok in data:
            if label == "canary":
                out["canary"] = "on"
            else:
                out["notes"].append(label)
    if out["canary"] is None:
        out["canary"] = "off"
    if out["relro"] is None:
        out["relro"] = "off"
    return out


def zip_local_flags(path: str) -> dict:
    """读本地文件头里的 flag 位（zipfile 只暴露中央目录那一份）。两份不一致 = 伪加密。"""
    out: dict = {}
    try:
        d = open(path, "rb").read()
    except OSError:
        return out
    i = 0
    while True:
        j = d.find(b"PK\x03\x04", i)
        if j < 0 or j + 30 > len(d):
            break
        (flags,) = struct.unpack("<H", d[j + 6:j + 8])
        (csize,) = struct.unpack("<I", d[j + 18:j + 22])
        namelen, extralen = struct.unpack("<HH", d[j + 26:j + 30])
        name = d[j + 30:j + 30 + namelen].decode("utf-8", "replace")
        out[name] = flags
        i = j + 30 + namelen + extralen + (csize or 0)
    return out


def zip_report(path: str) -> dict:
    out: dict = {"entries": [], "encrypted": [], "comment": "", "nested": [], "pseudo": []}
    local = zip_local_flags(path)
    try:
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                out["entries"].append({"name": i.filename, "size": i.file_size,
                                       "comp": i.compress_size, "crc": f"{i.CRC:08x}"})
                lf = local.get(i.filename)
                if lf is not None and (lf & 0x1) != (i.flag_bits & 0x1):
                    out["pseudo"].append(i.filename)       # 本地头说加密、中央目录说不加密（或反之）
                if i.flag_bits & 0x1:
                    out["encrypted"].append(i.filename)
                if i.filename.lower().endswith((".zip", ".rar", ".7z", ".tar", ".gz")):
                    out["nested"].append(i.filename)
            out["comment"] = z.comment.decode("utf-8", "replace")[:200]
    except (zipfile.BadZipFile, OSError) as e:
        out["error"] = str(e)
    return out


def strings_report(data: bytes, want: int) -> dict:
    all_s = [m.group(0).decode("latin1") for m in STR_RE.finditer(data)]
    interesting = [s for s in all_s if INTERESTING.search(s)]
    flags: list[str] = []
    for s in all_s:                                     # 只在可打印串里找，避免二进制假命中
        for m in FLAG_IN_STR.finditer(s):
            if m.group(1) not in flags:
                flags.append(m.group(1))
    return {"total": len(all_s), "interesting": interesting[:want], "flags": flags[:10]}


def text_report(text: str) -> dict:
    out: dict = {"rsa_vars": {}, "hashes": [], "b64_lines": 0, "lines": text.count("\n") + 1}
    for var in ("n", "e", "c", "p", "q", "d", "phi"):
        m = re.search(rf"^\s*{var}\s*=\s*([0-9]+|0x[0-9a-fA-F]+)", text, re.M)
        if m:
            out["rsa_vars"][var] = m.group(1)
    for m in re.finditer(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b", text):
        out["hashes"].append(m.group(0))
        if len(out["hashes"]) >= 5:
            break
    for line in text.splitlines():
        line = line.strip()
        if len(line) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]{16,}", line):
            out["b64_lines"] += 1
    return out


# ------------------------------------------------------------------ 主流程

def triage(path: str, want_strings: int = 12) -> dict:
    if not os.path.exists(path):
        return {"error": f"文件不存在：{path}"}
    if os.path.isdir(path):
        return {"error": f"{path} 是目录（本命令只吃单个文件）"}
    data = open(path, "rb").read(64 * 1024 * 1024)
    head = data[:64]
    t: dict = {
        "path": os.path.abspath(path),
        "name": os.path.basename(path),
        "ext": os.path.splitext(path)[1].lower(),
        "size": len(data),
        "sha256": sha256(data),
        "magic": magic_name(head, path),
        "entropy": round(entropy(data[:65536]), 3),
        "findings": [],
    }
    t["embedded"] = find_embedded(data)[:8]
    tail = appended_tail(data, t["magic"])
    if tail:
        t["appended"] = tail
        t["findings"].append("appended")
    if t["magic"] == "PNG 图片":
        t["png"] = png_report(data)
        if t["png"].get("bad_crc"):
            t["findings"].append("png:crc-bad")
        if t["png"].get("chunk_after_iend"):
            t["findings"].append("appended")
    elif t["magic"] == "JPEG 图片":
        d = jpeg_dims(data)
        if d:
            t["dims"] = d
    elif t["magic"] == "GIF 图片":
        if len(data) >= 10:
            t["dims"] = list(struct.unpack("<HH", data[6:10]))
    elif t["magic"] == "ELF 可执行/目标文件":
        t["elf"] = elf_report(data)
        t["findings"].append("elf")
        for k, v in (("nx", "nx-off"), ("canary", "canary-off"), ("pie", "pie-off")):
            if t["elf"].get(k) == "off":
                t["findings"].append(f"elf:{v}")
    elif t["magic"] == "PE/DOS 可执行(Windows)":
        t["findings"].append("pe")
    elif t["magic"].startswith("ZIP"):
        t["zip"] = zip_report(path)
        if t["zip"].get("pseudo"):
            t["findings"].append("zip:pseudo-encrypt")
        if t["zip"].get("encrypted"):
            t["findings"].append("zip:encrypted")
        if t["zip"].get("nested"):
            t["findings"].append("zip:nested")
    if t["magic"] in ("PCAP 抓包", "PCAPNG 抓包"):
        t["findings"].append("pcap")
    if t["entropy"] > 7.5 and t["size"] > 4096:
        t["findings"].append("entropy-high")
    sr = strings_report(data, want_strings)
    t["strings"] = sr
    if sr["flags"]:
        t["findings"].append("strings:flag")
    if _looks_text(data[:8192]):
        t["text"] = text_report(data.decode("utf-8", "replace")[:200000])
        if t["text"]["rsa_vars"]:
            t["findings"].append("text:rsa")
        if t["text"]["b64_lines"] > 3:
            t["findings"].append("text:base64")
        if t["text"]["hashes"]:
            t["findings"].append("text:hash")
        if t.get("appended"):
            t["findings"].append("appended")
    if t.get("appended") or any(e["offset"] for e in t["embedded"]):
        t["findings"].append("embedded")
    seen: set[str] = set()
    t["findings"] = [f for f in t["findings"] if not (f in seen or seen.add(f))]   # 去重保序
    return t


def evidence_of(t: dict) -> dict:
    """给建议引擎的证据。文本类文件报 kind=text（好让「先归类」那套规则命中），其余报 kind=file。"""
    is_text = bool(t.get("text")) or (t.get("magic") or "").endswith("纯文本")
    return {"kind": "text" if is_text else "file",
            "magic": t.get("magic", ""), "ext": t.get("ext", ""),
            "name": t.get("name", ""), "size": t.get("size"), "findings": t.get("findings", []),
            "body": (t.get("strings", {}).get("interesting") or [""])[0]}


def render(t: dict, want_strings: int = 12) -> str:
    if t.get("error"):
        return f"[!] {t['error']}"
    L = [f"=== 文件初筛 {t['name']} ===",
         f"  类型   {t['magic']}   大小 {t['size']} 字节   熵 {t['entropy']}",
         f"  sha256 {t['sha256']}"]
    if t.get("dims"):
        L.append(f"  尺寸   {t['dims'][0]} x {t['dims'][1]}")
    if t.get("png"):
        ch = ", ".join(c["type"] for c in t["png"]["chunks"][:12])
        L.append(f"  PNG 块 {ch}")
        if t["png"].get("bad_crc"):
            L.append(f"  [!] CRC 对不上的块：{', '.join(t['png']['bad_crc'])}（块内容被改过 → 尺寸/数据可能被动手脚）")
    if t.get("elf"):
        e = t["elf"]
        L.append(f"  ELF    {e['class']} {e['endian']} {e['machine']} {e['type']}")
        L.append(f"  保护   NX={e['nx'] or '?'}  PIE={e['pie']}  canary={e['canary']}  RELRO={e['relro']}")
    if t.get("zip"):
        z = t["zip"]
        L.append(f"  ZIP    {len(z['entries'])} 个条目" + (f"，加密：{', '.join(z['encrypted'])}" if z["encrypted"] else ""))
        for i in z["entries"][:10]:
            L.append(f"         {i['name']}  {i['size']}B → {i['comp']}B  crc={i['crc']}")
        if z.get("nested"):
            L.append(f"         嵌套压缩包：{', '.join(z['nested'])}（解完还有一层）")
    if t.get("text"):
        tx = t["text"]
        L.append(f"  文本   {tx['lines']} 行" + (f"，疑似 RSA 变量：{'/'.join(tx['rsa_vars'])}" if tx["rsa_vars"] else "")
                 + (f"，{tx['b64_lines']} 行像 base64" if tx["b64_lines"] else "")
                 + (f"，{len(tx['hashes'])} 个长哈希串" if tx["hashes"] else ""))
    if t.get("embedded"):
        L.append("  内嵌文件（binwalk 风格）：")
        for e in t["embedded"]:
            L.append(f"         偏移 {e['offset']:#x}  {e['type']}")
    if t.get("appended"):
        a = t["appended"]
        L.append(f"  [!] 结构末尾之后还有 {a['bytes']} 字节附加数据（偏移 {a['offset']:#x}，开头 {a['preview']!r}）")
    if t.get("strings", {}).get("flags"):
        L.append(f"  [!] 命中 flag 样式串：{', '.join(t['strings']['flags'])}")
    if t.get("strings", {}).get("interesting"):
        L.append(f"  可疑字符串（共 {t['strings']['total']} 条）：")
        for s in t["strings"]["interesting"][:want_strings]:
            L.append(f"         {s[:110]}")
    L.append(f"  发现标签 {', '.join(t['findings']) or '（无）'}")
    return "\n".join(L)


def run(args) -> int:
    t = triage(args.path, args.strings)
    if t.get("error"):
        print(f"[!] {t['error']}", file=sys.stderr)
        return 1
    print(render(t, args.strings))
    if not args.no_advice:
        ev = evidence_of(t)
        ranked = advise_mod.rank(advise_mod.match(ev), ev)
        print()
        for line in advise_mod.render_text(ranked, ev, {"{path}": t["path"]}, limit=args.limit):
            print(line)
    if args.json:
        json.dump(t, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"\n[json] {args.json}")
    return 0


def register(sub) -> None:
    p = sub.add_parser("file", help="文件/二进制初筛：类型·结构·内嵌·字符串·保护机制 + 下一步建议")
    p.add_argument("path", help="要看的文件（misc/rev/pwn/crypto 的附件）")
    p.add_argument("--strings", type=int, default=12, help="打多少条可疑字符串（默认 12）")
    p.add_argument("--limit", type=int, default=3, help="最多给几条建议（默认 3）")
    p.add_argument("--no-advice", action="store_true", help="只要事实，不要建议")
    p.add_argument("--json", help="把结果写成 JSON")
    p.set_defaults(func=run)
