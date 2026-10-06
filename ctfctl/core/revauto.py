"""revauto —— rev（逆向）类题目的**自动推进**：能自动的自动掉，不能的给出可执行下一步。

诚实分档（越往下越依赖人/工具）：
  ① 明文捷径：flag 直接躺在文件里 / 字符串里 / 一层 XOR 后 —— 全自动，成功率高
  ② 常量数组：.rodata/.data 里的字节数组，试单字节 XOR 与编码链 —— 全自动（有判定器裁决）
  ③ 黑盒逐字符爆破：程序对输入的**逐字符信号**（退出码 / 输出 / 长度）可观测时，
     直接枚举可打印字符把它问出来 —— 全自动，且不需要看懂算法
     （典型：`if (in[i] != f[i]) return 10+i;` 这类短路比较）
  ④ 反汇编级提取：objdump/radare2/rizin 在位时，抓立即数序列与提示串，给候选与锚点 —— 半自动
  ⑤ 符号执行（angr）：能全自动但有前提（明确 find/avoid 地址 + 预算）；本机 angr 目前装不起来，
     给模板与 z3 备用
  ⑥ 自定义算法/VM/混淆：**不能自动** —— 需要人读代码，这是判定器帮不上忙的部分

本模块只做①–③（④视工具在位），全部确定性；不联网、不改题目文件、只写自己的缓存目录。
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import time

from . import autosolve as AS
from . import oracles as O
from .config import CACHE, ensure_dirs

PRINTABLE = [chr(c) for c in range(0x20, 0x7F)]
PROMPT_ANCHORS = re.compile(
    r"(correct|wrong|incorrect|nope|nice|good|success|fail|invalid|try again|flag|"
    r"congrat|密码|错误|正确|成功|失败)", re.I)


def _have(cmd: str) -> str:
    return shutil.which(cmd) or ""


# ---------------------------------------------------------------- ① 结构 + 明文捷径

def elf_info(path: str) -> dict:
    """自解析 ELF（不依赖 binutils，任何环境都能给出结构事实）。"""
    data = open(path, "rb").read()
    info: dict = {"magic": data[:4].hex(), "size": len(data)}
    if data[:4] != b"\x7fELF":
        if data[:2] == b"MZ":
            info["type"] = "PE"
            # PE：先只给事实，深度解析交给 objdump/r2
            info["note"] = "PE 文件（用 objdump -x / r2 看结构）"
        elif data[:2] == b"UPX!" or b"UPX!" in data[:4096]:
            info["type"] = "UPX 加壳（先 upx -d 脱壳）"
        else:
            info["type"] = "非 ELF/PE"
        return info
    is64 = data[4] == 2
    little = data[5] == 1
    end = "<" if little else ">"
    info.update({"type": "ELF64" if is64 else "ELF32", "arch": {3: "x86", 62: "x86-64", 183: "aarch64", 40: "arm"}.get(struct.unpack_from(end + "H", data, 18)[0], "?")})
    if is64:
        e_entry, e_shoff = struct.unpack_from(end + "Q", data, 24)[0], struct.unpack_from(end + "Q", data, 40)[0]
        e_shnum, e_shentsize = struct.unpack_from(end + "H", data, 60)[0], struct.unpack_from(end + "H", data, 58)[0]
        e_shstrndx = struct.unpack_from(end + "H", data, 62)[0]
        e_type = struct.unpack_from(end + "H", data, 16)[0]
    else:
        e_entry = struct.unpack_from(end + "I", data, 24)[0]
        e_shoff = struct.unpack_from(end + "I", data, 32)[0]
        e_shnum = struct.unpack_from(end + "H", data, 48)[0]
        e_shentsize = struct.unpack_from(end + "H", data, 46)[0]
        e_shstrndx = struct.unpack_from(end + "H", data, 50)[0]
        e_type = struct.unpack_from(end + "H", data, 16)[0]
    info["entry"] = hex(e_entry)
    info["pie"] = e_type == 3
    sections = []
    for i in range(min(e_shnum, 64)):
        off = e_shoff + i * e_shentsize
        if off + 64 > len(data):
            break
        if is64:
            name_off, sh_type = struct.unpack_from(end + "I", data, off)[0], struct.unpack_from(end + "I", data, off + 4)[0]
            sh_addr = struct.unpack_from(end + "Q", data, off + 16)[0]
            sh_off = struct.unpack_from(end + "Q", data, off + 24)[0]
            sh_size = struct.unpack_from(end + "Q", data, off + 32)[0]
        else:
            name_off, sh_type = struct.unpack_from(end + "I", data, off)[0], struct.unpack_from(end + "I", data, off + 4)[0]
            sh_addr = struct.unpack_from(end + "I", data, off + 12)[0]
            sh_off = struct.unpack_from(end + "I", data, off + 16)[0]
            sh_size = struct.unpack_from(end + "I", data, off + 20)[0]
        sections.append({"name_off": name_off, "type": sh_type, "off": sh_off, "size": sh_size,
                         "addr": sh_addr})
    # 节名表：必须用 e_shstrndx 指向的 .shstrtab —— 用"第一个 STRTAB"会拿到 .dynstr，
    # 于是节名全变成动态符号（实测把 .rodata 认成 "fgets"，导致后面的常量数组扫描全空）
    strtab = sections[e_shstrndx] if 0 <= e_shstrndx < len(sections) else None
    if strtab is None or strtab["type"] != 3:
        strtab = next((x for x in sections if x["type"] == 3), None)
    if strtab:
        raw = data[strtab["off"]:strtab["off"] + strtab["size"]]
        for s in sections:
            # 节名按**字节偏移**在 .shstrtab 里取到下一个 NUL —— 之前拿 split() 后的列表下标当偏移，
            # 结果节名全是另一个字符串（实测 .rodata 被认成 "fgets"，常量数组扫描直接空转）
            o = s["name_off"]
            if o < len(raw):
                e = raw.find(b"\x00", o)
                s["name"] = raw[o:(e if e >= 0 else len(raw))].decode("utf-8", "replace")
    info["sections"] = [(s.get("name", ""), s["size"]) for s in sections if s.get("name")]
    info["_sections"] = sections
    info["_data"] = data
    return info


def pe_sections(path: str) -> list[dict]:
    """PE 节区表（.text/.rdata/.data）—— meow.exe 这类 mingw PE 的常量数组都在 .rdata。"""
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        return []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return []
        coff = e_lfanew + 4
        nsec, opt_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        sec_off = opt + opt_size
        out = []
        for i in range(min(nsec, 32)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b"\x00").decode("utf-8", "replace")
            vsize, vaddr = struct.unpack_from("<I", data, o + 8)[0], struct.unpack_from("<I", data, o + 12)[0]
            raw_size, raw_off = struct.unpack_from("<I", data, o + 16)[0], struct.unpack_from("<I", data, o + 20)[0]
            flags = struct.unpack_from("<I", data, o + 36)[0]
            out.append({"name": name, "off": raw_off, "size": raw_size, "vaddr": vaddr,
                        "vsize": vsize, "exec": bool(flags & 0x20000000), "magic": magic})
        return out
    except Exception:
        return []


#: 经典对称算法指纹（常量）：命中就说明这道 rev 用了它，可以自动试解密
ALGO_SIGNS = [
    ("TEA/XTEA/XXTEA", [b"\xb9\x79\x37\x9e", b"\x9e\x37\x79\xb9", b"\x47\x86\xc8\x61"]),
    ("RC4", [bytes(range(0, 64))]),                    # S-box 初始化序列 0..255
    ("AES", [b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"]),
    ("ChaCha/Salsa20", [b"expand 32-byte k", b"expand 16-byte k"]),
    ("MD5/SHA 常量", [b"\x01\x23\x45\x67\x89\xab\xcd\xef"]),
]


def algo_fingerprint(path: str) -> list[str]:
    data = open(path, "rb").read()
    hits = []
    for name, sigs in ALGO_SIGNS:
        for sig in sigs:
            if sig and sig in data:
                hits.append(name)
                break
    return hits


def va_to_off(path: str, va: int) -> int | None:
    """把反汇编里的地址（VA）换成文件偏移：PE 用节区表，ELF 用节区。"""
    data = open(path, "rb").read()
    if data[:2] == b"MZ":
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            coff = e_lfanew + 4
            nsec, opt_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
            opt = coff + 20
            img_base = struct.unpack_from("<Q", data, opt + 24)[0] if struct.unpack_from("<H", data, opt)[0] == 0x20b \
                else struct.unpack_from("<I", data, opt + 28)[0]
            rva = va - img_base
            sec_off = opt + opt_size
            for i in range(min(nsec, 32)):
                o = sec_off + i * 40
                vsize, vaddr = struct.unpack_from("<I", data, o + 8)[0], struct.unpack_from("<I", data, o + 12)[0]
                raw_size, raw_off = struct.unpack_from("<I", data, o + 16)[0], struct.unpack_from("<I", data, o + 20)[0]
                if vaddr <= rva < vaddr + max(vsize, raw_size):
                    return raw_off + (rva - vaddr)
        except Exception:
            return None
        return None
    if data[:4] == b"\x7fELF":                               # ELF：用节区 VA 匹配
        info = elf_info(path)
        for sec in info.get("_sections", []):
            if sec.get("addr") is None:
                continue
            if sec["addr"] <= va < sec["addr"] + sec["size"]:
                return sec["off"] + (va - sec["addr"])
    return None


#: objdump 对 PE/PIE 常写成 rip 相对，绝对地址只出现在行尾注释 `# 0x...`
COMMENT_ADDR_RE = re.compile(r"#\s*(?:0x)?([0-9a-f]{4,16})\b", re.I)  # objdump 注释不带 0x；地址可能只有 4 位
BRACKET_ADDR_RE = re.compile(r"\[(0x[0-9a-f]{4,16})\]", re.I)
LEN_IMM_RE = re.compile(r"mov(?:abs)?\s+(?:e|r)\w+,\s*0x([0-9a-f]{1,4})\b", re.I)
XREF_CALLS = ("memcmp", "strcmp", "strncmp", "memcpy", "memcmp@", "strcmp@", "bcmp")


def _line_va(line: str) -> int | None:
    """从一条反汇编指令里取绝对地址：优先行尾注释放的，其次方括号里的。"""
    m = COMMENT_ADDR_RE.search(line)
    if not m:
        m = BRACKET_ADDR_RE.search(line)
    if m:
        try:
            v = int(m.group(1), 16)
            return v if v >= 0x1000 else None          # 太小的数值多半是立即数/偏移，不是地址
        except ValueError:
            return None
    return None


def const_arrays_by_xref(path: str) -> list[dict]:
    """精确提取「程序拿去比较的常量数组」：① 反汇编里 memcmp/strcmp 附近的地址+长度
    ② 兜底：反汇编里出现过的所有 VA × 常见长度（8/16/24/32/48/64）都当候选。

    比"盲扫高熵块"准得多：meow.exe 的密文就是 memcmp 前的 lea 指向的那 24 字节。
    """
    od = _have("objdump")
    if not od:
        return []
    rc, out = _run([od, "-d", "-M", "intel", path], timeout=180)
    if rc != 0:
        return []
    lines = out.splitlines()
    found: list[dict] = []
    seen_va: list[int] = []
    for i, line in enumerate(lines):
        va = _line_va(line)
        if va and va not in seen_va:
            seen_va.append(va)
        if not any(c in line for c in XREF_CALLS):
            continue
        tgt, ln = None, None
        for back in range(max(0, i - 10), i):
            v = _line_va(lines[back])
            if v and ("lea" in lines[back].lower() or "mov" in lines[back].lower()):
                tgt = v
            m2 = LEN_IMM_RE.search(lines[back])
            if m2:
                cand = int(m2.group(1), 16)
                if 4 <= cand <= 4096:
                    ln = cand
        if tgt and ln:
            found.append({"va": tgt, "len": ln, "call": line.strip()[-70:], "exact": True})
    # 规则②：**内联字节比较循环**（没有 memcmp 调用）——
    #   lea rcx,[0x2010]  ...  cmp rdx, 0x41（循环上界即数组长度）... cmp dil, byte [rdx+rcx]
    for i, line in enumerate(lines):
        m = re.search(r"lea\s+(\w+),\s*\[?(?:rip[^#]*#\s*)?(?:0x)?([0-9a-f]{4,16})", line, re.I)
        if not m:
            continue
        reg, va = m.group(1), int(m.group(2), 16)
        if va_to_off(path, va) is None:
            continue
        for ahead in range(i + 1, min(len(lines), i + 14)):
            mm = re.search(r"\bcmp\s+(?:e|r)\w+,\s*0x([0-9a-f]{1,4})\b", lines[ahead], re.I)
            if mm:
                ln = int(mm.group(1), 16)
                if 8 <= ln <= 4096 and not any(f["va"] == va and f["len"] == ln for f in found):
                    found.append({"va": va, "len": ln, "exact": True,
                                  "call": f"内联比较循环（lea {reg} + cmp 上界 0x{ln:x}）"})
                break
    # 兜底：比较调用附近没解析出长度时，用常见长度把出现过的地址都试一遍
    data = open(path, "rb").read()
    for va in seen_va[:120]:
        off = va_to_off(path, va)
        if off is None or off >= len(data):
            continue
        for L in (8, 16, 24, 32, 48, 64):
            if off + L <= len(data) and not any(f["va"] == va and f["len"] == L for f in found):
                found.append({"va": va, "len": L, "call": "（兜底：地址 × 常见长度）", "exact": False})
    # 精确的排前面
    found.sort(key=lambda f: (not f["exact"], f["len"]))
    return found[:80]


def _entropy(b: bytes) -> float:
    import collections
    import math as _m
    if not b:
        return 0.0
    c = collections.Counter(b)
    return -sum((n / len(b)) * _m.log2(n / len(b)) for n in c.values())


def _ct_candidates(path: str, min_len: int = 8, max_len: int = 256, cap: int = 24) -> list[bytes]:
    """候选密文数组：高熵、长度是 8 的倍数（TEA 分组）的连续段。"""
    data = open(path, "rb").read()
    spans = [(s["off"], s["size"], s["name"]) for s in pe_sections(path) if not s["exec"]]
    if not spans:                                     # ELF：用节区
        info = elf_info(path)
        spans = [(s["off"], s["size"], s.get("name", "")) for s in info.get("_sections", [])
                 if s.get("name") in (".rodata", ".data", ".data.rel.ro", ".rdata")]
    out: list[bytes] = []
    for off, size, _name in spans:
        blob = data[off:off + size]
        # ① 整段连续非零 run 本身也要当候选（实测：65 字节的常量数组正好卡在固定长度之间被漏掉）
        for run in re.findall(rb"[^\x00]{8,256}", blob):
            printable = sum(1 for b in run if 32 <= b < 127 or b in (9, 10, 13))
            if printable != len(run) and len(set(run)) >= max(6, len(run) // 4):
                out.append(run)
        # ② 固定长度滑窗（覆盖数组被前后数据粘连的情况）
        for L in (8, 12, 16, 21, 24, 32, 40, 48, 64, 96, 128, 192, 256):
            for m in re.finditer(rb"[^\x00]{%d}" % L, blob):
                cand = m.group(0)
                printable = sum(1 for b in cand if 32 <= b < 127 or b in (9, 10, 13))
                if printable == len(cand):             # 纯可打印 = 字符串，跳过
                    continue
                if len(set(cand)) < max(6, len(cand) // 4):
                    continue
                if cand in out:
                    continue
                out.append(cand)
                if len(out) >= cap:
                    return out
    return out


def _key_candidates(path: str, ctx_text: str = "") -> list[bytes]:
    """密钥候选：字符串里长度合适的可见串（尤其 16/32 字节，正好是 TEA/AES 的密钥长度）。"""
    cands: list[bytes] = []
    pools = rev_strings(path, 4) + re.findall(r"[A-Za-z0-9_!@#\$%\^&\*\.\-]{6,64}", ctx_text)
    for t in pools:
        raw = t.encode("utf-8", "replace")
        if 6 <= len(raw) <= 64 and not raw.count(b" ") == len(raw):
            cands.append(raw)
    # 长度优先 16/32（TEA/AES），其次其它
    cands.sort(key=lambda b: (len(b) not in (16, 32, 8, 24), len(b)))
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:60]


def _tea_decrypt_block(v: list[int], key: bytes, rounds: int = 32, delta: int = 0x9E3779B9,
                       big_endian: bool = False) -> list[int]:
    order = "big" if big_endian else "little"
    k = [int.from_bytes(key[i:i + 4].ljust(4, b"\x00"), order) for i in (0, 4, 8, 12)]
    s = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v[1] = (v[1] - (((v[0] << 4) + k[2] & 0xFFFFFFFF) ^ (v[0] + s & 0xFFFFFFFF)
                        ^ ((v[0] >> 5) + k[3] & 0xFFFFFFFF))) & 0xFFFFFFFF
        v[0] = (v[0] - (((v[1] << 4) + k[0] & 0xFFFFFFFF) ^ (v[1] + s & 0xFFFFFFFF)
                        ^ ((v[1] >> 5) + k[1] & 0xFFFFFFFF))) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    return v


def _xxtea_decrypt(data: bytes, key: bytes, big_endian: bool = False) -> bytes | None:
    order = "big" if big_endian else "little"
    try:
        k = [int.from_bytes(key[i:i + 4].ljust(4, b"\x00"), order) for i in range(0, 16, 4)]
    except Exception:
        return None
    if len(data) < 8 or len(data) % 4:
        return None
    v = [int.from_bytes(data[i:i + 4], order) for i in range(0, len(data), 4)]
    n = len(v)
    delta, rounds = 0x9E3779B9, 6 + 52 // n
    total = (rounds * delta) & 0xFFFFFFFF
    y = v[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[(p - 1) % n]
            mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        total = (total - delta) & 0xFFFFFFFF
    try:
        return b"".join(int(x).to_bytes(4, order) for x in v)
    except OverflowError:
        return None


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out, i, j = bytearray(), 0, 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def verify_by_running(path: str, candidate: bytes, timeout: float = 8.0) -> tuple[bool, str]:
    """把候选当输入真的跑一遍程序，看它自己的成功提示 —— 这是最硬的判定器（比启发式可靠）。

    PE 用 wine（主机有）；ELF 直接跑。判据：退出码 0 且输出里出现 correct/success/flag 之类锚点。
    """
    runner = [path]
    if open(path, "rb").read(2) == b"MZ":
        wine = _have("wine")
        if not wine:
            return False, "PE 且没装 wine，无法运行验证"
        runner = [wine, path]
    try:
        p = subprocess.run(runner, input=candidate + b"\n", capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"运行失败：{type(e).__name__}"
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    # 成功必须**显式**：出现 correct/congrat/success/well done 之类，且**没有** wrong/fail 之类。
    # （曾经把提示语 "Input your flag:" 里的 "flag" 当成功锚点 → 程序打印 Wrong 也报"验证通过"）
    ok_re = re.compile(r"(correct|congrat|success|well done|you win|accepted|nice\b)", re.I)
    bad_re = re.compile(r"(wrong|incorrect|invalid|fail|nope|try again|denied)", re.I)
    ok = bool(ok_re.search(out)) and not bad_re.search(out)
    if not ok and O.flags_in(out) and not bad_re.search(out):
        ok = True                                   # 程序自己回显了 flag 也算过
    return ok, out.strip()[:160]


def rev_crypto(path: str, budget_s: float = 60.0) -> list[dict]:
    """**经典对称算法自动解密**：算法指纹 + 密钥候选（字符串里）+ 密文候选（高熵数组）→ 试解 → 判定器裁决。

    这是 rev+crypto 混合题里最常见的一类（TEA/XTEA/XXTEA/RC4），全部确定性、可复核。
    """
    t0 = time.time()
    steps: list[dict] = []
    algos = algo_fingerprint(path)
    if algos:
        steps.append(_step("rev-crypto", f"算法指纹：{'、'.join(algos)}", "UNKNOWN", 2,
                           "二进制里出现了该算法的常量（delta / S-box / 初始化向量）"))
    # 精确路径：反汇编里的常量数组（VA + 长度），比盲扫高熵块靠谱
    xrefs = const_arrays_by_xref(path)
    cts: list[bytes] = []
    data_all = open(path, "rb").read()
    exact_hits = 0
    for x in xrefs:
        off = va_to_off(path, x["va"])
        if off is None:
            continue
        ct = data_all[off:off + x["len"]]
        if ct and ct not in cts:
            cts.append(ct)
            if x["exact"] and exact_hits < 3:
                exact_hits += 1
                steps.append(_step("rev-crypto",
                                   f"交叉引用取到常量数组（VA {hex(x['va'])}，{x['len']}B，{x['call'][:40]}）",
                                   "UNKNOWN", 2,
                                   "程序把它与计算结果做了比较 → 它就是待解密的密文/待比对的明文"))
    cts += [c for c in _ct_candidates(path) if c not in cts]
    try:                                              # 再补一批：常量数组扫描的候选（含任意长度）
        info2 = elf_info(path)
        cts += [c for _, c in _rodata_blobs(info2, max_blobs=24, path=path) if c not in cts]
    except Exception:
        pass
    keys = _key_candidates(path)
    if not cts:
        return steps + [_step("rev-crypto", "自动解密", "UNKNOWN", 1, "没找到高熵常量数组（不像有硬编码密文）")]
    if algos and "TEA/XTEA/XXTEA" not in algos and "RC4" not in algos:
        pass
    tried = 0
    best: dict | None = None
    for key in keys[:40]:
        if time.time() - t0 > budget_s:
            break
        for ct in cts[:16]:
            if time.time() - t0 > budget_s:
                break
            for big in (False, True):
                tried += 1
                out = None
                if "TEA/XTEA/XXTEA" in algos or True:          # 指纹缺失也照样试（成本低）
                    # TEA 分组解密
                    if len(key) >= 16 and len(ct) % 8 == 0:
                        order = "big" if big else "little"
                        res = bytearray()
                        for i in range(0, len(ct), 8):
                            v = [int.from_bytes(ct[i:i + 4], order), int.from_bytes(ct[i + 4:i + 8], order)]
                            v = _tea_decrypt_block(v, key, big_endian=big)
                            res += int(v[0]).to_bytes(4, order) + int(v[1]).to_bytes(4, order)
                        out = bytes(res)
                    if out and (O.is_hit(O.judge_all(out, as_bytes=True))[0] or O.flags_in(out.decode("utf-8", "replace"))):
                        best = {"algo": "TEA", "key": key, "ct": ct, "pt": out, "big": big, "tried": tried}
                        break
                    # XXTEA 整体解密
                    if len(key) >= 16:
                        x = _xxtea_decrypt(ct, key, big_endian=big)
                        if x and (O.is_hit(O.judge_all(x, as_bytes=True))[0] or O.flags_in(x.decode("utf-8", "replace").strip("\x00"))):
                            best = {"algo": "XXTEA", "key": key, "ct": ct, "pt": x, "big": big, "tried": tried}
                            break
                    # RC4（流密码）
                    r = _rc4(key, ct)
                    if O.is_hit(O.judge_all(r, as_bytes=True))[0] or O.flags_in(r.decode("utf-8", "replace")):
                        best = {"algo": "RC4", "key": key, "ct": ct, "pt": r, "big": big, "tried": tried}
                        break
                if best:
                    break
            if best:
                break
        if best:
            break
    # ── 重复密钥 XOR·**crib-drag + 字符集剪枝**：前缀给前几字节密钥，剩余字节用"明文必须可打印"剪出来 ──
    if not best:
        for ct in cts[:24]:
            for pfx in ("flag{", "FLAG{", "ctf{", "CTF{", "QCTF{", "NSSCTF{"):
                if time.time() - t0 > budget_s or best:
                    break
                pb = pfx.encode()
                for period in range(len(pb), 33):
                    if period > len(ct):
                        break
                    # 前缀给出前几个密钥字节；剩下的用"明文必须可打印"逐位剪枝，
                    # 剪不唯一就**枚举组合**（组合数有上限，超过就跳过）
                    fixed = {i: ct[i] ^ pb[i] for i in range(min(period, len(pb)))}
                    opts: list[set] = []
                    positions: list[int] = []
                    bad = False
                    for i in range(period):
                        if i in fixed:
                            continue
                        cands = set(range(32, 127))
                        for j in range(i, len(ct), period):
                            cands = {c for c in cands if 32 <= (ct[j] ^ c) < 127}
                            if not cands:
                                bad = True
                                break
                        if bad or not cands:
                            break
                        positions.append(i)
                        opts.append(cands)
                    if bad:
                        continue
                    import itertools
                    total = 1
                    for o in opts:
                        total *= len(o)
                    if total > 4096:
                        continue
                    for combo in itertools.product(*opts):
                        key = [fixed.get(i) for i in range(period)]
                        for pos, c in zip(positions, combo):
                            key[pos] = c
                        if any(k is None for k in key):
                            continue
                        tried += 1
                        kb = bytes(key)
                        pt = bytes(c ^ kb[i % period] for i, c in enumerate(ct))
                        txt = pt.decode("utf-8", "replace").rstrip("\x00\n")
                        if O.is_hit(O.judge_all(txt))[0] or O.flags_in(txt):
                            best = {"algo": f"重复密钥 XOR（crib-drag 周期 {period}，密钥 {kb!r}）",
                                    "key": kb, "ct": ct, "pt": pt, "big": False, "tried": tried}
                            break
                    if best:
                        break

    # ── 重复密钥 XOR·**已知前缀推密钥**（最有效的一招：flag 前缀 ⊕ 密文 = 密钥片段） ──
    KNOWN_PREFIXES = ("flag{", "FLAG{", "ctf{", "CTF{", "QCTF{", "NSSCTF{", "flag", "key{", "iscc{")
    if not best:
        for ct in cts[:24]:
            if time.time() - t0 > budget_s:
                break
            for pfx in KNOWN_PREFIXES:
                pfx_b = pfx.encode()
                if len(ct) < len(pfx_b) + 4:
                    continue
                key = bytes(ct[i] ^ pfx_b[i] for i in range(len(pfx_b)))
                if not all(32 <= b < 127 for b in key):        # 密钥片段应是可见字符
                    continue
                tried += 1
                pt = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
                txt = pt.decode("utf-8", "replace").rstrip("\x00\n")
                if O.is_hit(O.judge_all(txt))[0] or O.flags_in(txt):
                    best = {"algo": f"重复密钥 XOR（由前缀 {pfx} 推出密钥 {key[:8]!r}）",
                            "key": key, "ct": ct, "pt": pt, "big": False, "tried": tried}
                    break
            if best:
                break
        if best and len(best["key"]) < 8:                       # 密钥可能比前缀长：按周期补齐再解
            pass

    # ── 重复密钥 XOR（极常见的 rev 形态：短密钥存在 .rodata 字符串里，与常量数组逐字节异或） ──
    if not best:
        for key in keys[:40]:
            if time.time() - t0 > budget_s:
                break
            for ct in cts[:24]:
                if len(key) < 2 or len(ct) < 8:
                    continue
                tried += 1
                pt = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
                txt = pt.decode("utf-8", "replace").rstrip("\x00\n")
                if O.is_hit(O.judge_all(txt))[0] or O.flags_in(txt):
                    best = {"algo": "重复密钥 XOR", "key": key, "ct": ct, "pt": pt, "big": False,
                            "tried": tried}
                    break
            if best:
                break
    if best:
        pt = best["pt"].decode("utf-8", "replace").rstrip("\x00")
        # 程序自己跑一遍 = 最硬验证（跑不动/跑失败要如实反映，不能假装通过）
        ok, detail = verify_by_running(path, pt.encode("utf-8", "replace"))
        ran_and_failed = bool(detail) and bool(re.search(r"(wrong|incorrect|invalid|fail|nope)", detail, re.I))
        if ran_and_failed:
            steps.append(_step("rev-crypto", f"候选被程序否掉（{best['algo']}，试了 {best['tried']} 组）",
                               "MISS", 1, f"真跑一遍得到否定输出：{detail}"))
        else:
            steps.append(_step("rev-crypto",
                               f"{best['algo']} 解出明文（试了 {best['tried']} 组）"
                               + ("，运行验证通过 ✔" if ok else "（没能运行验证）"),
                               "HIT", 3 if ok else 2,
                               f"key={best['key'][:24]!r}（{len(best['key'])}B） + {best['algo']} 解密"
                               + ("（大端）" if best["big"] else "（小端）")
                               + (f"；真跑一遍：{detail}" if detail else "；没跑起来，未验证"),
                               pt, [f"# 复现：{best['algo']} 解密，key={best['key']!r}，密文来自常量数组"]))
    else:
        steps.append(_step("rev-crypto", f"自动解密（{tried} 组尝试）", "UNKNOWN", 1,
                           "密钥/密文候选或算法组合没对上：可能是自定义变体或需要从代码里取常量"))
    return steps


def rev_strings(path: str, min_len: int = 5) -> list[str]:
    """抽可打印串（含 UTF-16），找 flag 与提示锚点。"""
    data = open(path, "rb").read()
    out = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    txt = [s.decode("ascii", "replace") for s in out[:4000]]
    # UTF-16LE
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % max(4, min_len - 1), data):
        txt.append(m.group(0)[:400].decode("utf-16-le", "replace"))
    return txt


# ---------------------------------------------------------------- ② 常量数组扫描

def _rodata_blobs(info: dict, min_len: int = 12, max_blobs: int = 40, path: str = "") -> list[tuple[str, bytes]]:
    """从非执行节区里挑"被处理过的常量数组"。

    判据（实测调过）：① 长度 ≥ min_len ② **原样不是纯可打印**（纯可打印的是字符串，原文判定已覆盖）
    ③ 去重后的字节数够多（不像零块/重复块）④ 至少有一个字节落在非常见可打印区间。
    不要求"像可打印"——XOR 过的 flag 数组里会夹 0x05 这类字节，之前按可打印筛会把数组切断。
    """
    data = info.get("_data", b"")
    secs = [s for s in info.get("_sections", [])
            if s.get("name") in (".rodata", ".data", ".data.rel.ro", ".rdata")]
    if not secs and path:                              # PE：节区表另一套解析
        secs = [{"name": x["name"], "off": x["off"], "size": x["size"]}
                for x in pe_sections(path) if not x["exec"]]
    cands: list[bytes] = []
    for s in secs:
        blob = data[s["off"]:s["off"] + s["size"]]
        for m in re.finditer(rb"[^\x00]{%d,256}" % min_len, blob):
            run = m.group(0)
            # 只取"旗数组量级"的固定长度集 + run 自身长度：全枚举会被上限截断，
            # 结果只生成出短窗口（实测漏掉整条数组）
            lens = [L for L in (8, 12, 16, 20, 21, 24, 28, 32, 40, 48, 56, 64, 96, 128) if L <= len(run)]
            if len(run) <= 128 and len(run) not in lens:
                lens.append(len(run))
            for L in lens:
                for st in range(0, len(run) - L + 1):
                    w = run[st:st + L]
                    printable = sum(1 for b in w if 32 <= b < 127 or b in (9, 10, 13))
                    if printable == len(w):
                        continue                              # 纯字符串，跳过
                    if len(set(w)) < max(6, len(w) // 3):
                        continue
                    cands.append(w)
    # 只留"旗数组量级"的长度（≤64），短的优先 —— 长窗口多半是把邻接字符串合进来的产物，
    # 排前面会把真正的数组挤出候选（实测 A 就是这样漏掉的）
    cands = [w for w in cands if len(w) <= 128]
    cands.sort(key=lambda w: len(w))
    out, seen = [], set()
    for w in cands:
        if w in seen:
            continue
        seen.add(w)
        out.append(("常量数组", w))
        if len(out) >= max_blobs:
            break
    return out


def rev_blobs(path: str, budget_s: float = 25.0) -> list[dict]:
    """对常量数组试单字节 XOR / 常见变换 / 编码链（复用 autosolve 的判定器裁决）。"""
    t0 = time.time()
    info = elf_info(path)
    steps: list[dict] = []
    blobs = _rodata_blobs(info)
    if not blobs:
        return [_step("rev-blobs", "常量数组扫描", "MISS", 1, "没找到合适的常量数组")]
    hit_any = False
    for _, cand in blobs:
        if time.time() - t0 > budget_s or hit_any:
            break
        for st in AS.xor_sweep(cand, budget_s=2.0)[:1]:
            if st["verdict"] == "HIT":
                steps.append(_step("rev-blobs", "常量数组 → 单字节 XOR", "HIT", st["conf"],
                                   st["reason"], st["result"]))
                hit_any = True
                break
        if not hit_any:
            chain = AS.decode_chain(cand.decode("utf-8", "replace"), max_depth=2, budget_s=2.0)
            if chain["verdict"] == "HIT":
                steps.append(_step("rev-blobs", "常量数组 → 编码链", "HIT", chain["conf"],
                                   chain["reason"], chain["result"]))
                hit_any = True
    if not steps:
        steps.append(_step("rev-blobs", f"常量数组扫描（{len(blobs)} 个）", "UNKNOWN", 1,
                           "数组存在但 XOR/编码链都没解出可读内容：可能是自定义变换（需读代码）"))
    return steps


# ---------------------------------------------------------------- ③ 黑盒逐字符爆破

def _signal(prog: str, arg_in: bytes, timeout: float = 5.0) -> dict | None:
    """跑一次程序，取可观测信号：退出码 / 输出哈希 / 输出长度 / 耗时。"""
    t0 = time.time()
    try:
        p = subprocess.run([prog], input=arg_in, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = p.stdout + p.stderr
    return {"rc": p.returncode, "hash": hashlib.sha256(out).hexdigest()[:16],
            "len": len(out), "ms": int((time.time() - t0) * 1000)}


def rev_brute(path: str, max_len: int = 64, budget_s: float = 90.0, timeout: float = 5.0) -> list[dict]:
    """**逐字符信号爆破**：只依赖"每多对一个字符，信号就前进一格"这一性质。

    三步：① 先探**期望长度**（长度错时信号往往一致，正确的长度会跳出来）
          ② 逐字符问：退出码型取"信号最大者"（越对越往后），哈希/长度型取"与基线不同者"
          ③ 收尾**真跑一遍验证**（rc==0 或输出里出现 correct/flag 之类锚点才算命中）
    对 `if (in[i]!=f[i]) return 10+i;` 这类逐字符短路比较非常有效，且不需要看懂算法。
    """
    steps: list[dict] = []
    if not os.access(path, os.X_OK):
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
    if not os.access(path, os.X_OK):
        return [_step("rev-brute", "黑盒爆破", "UNKNOWN", 1, "文件不可执行（先 chmod +x）")]
    t0 = time.time()

    # ① 探长度：多数长度给出同一信号，异常那个就是期望长度
    probes = []
    for L in range(4, min(max_len, 64) + 1):
        if time.time() - t0 > budget_s / 4:
            break
        sig = _signal(path, b"A" * L, timeout)
        if sig is None:
            return [_step("rev-brute", "黑盒爆破", "UNKNOWN", 1, "程序跑不起来（缺库/要参数/要网络）")]
        probes.append((L, sig))
    if not probes:
        return [_step("rev-brute", "黑盒爆破", "UNKNOWN", 1, "探长度失败")]
    from collections import Counter
    modal = Counter((p[1]["rc"], p[1]["hash"], p[1]["len"]) for p in probes).most_common(1)[0][0]
    odd = [(L, sig) for L, sig in probes if (sig["rc"], sig["hash"], sig["len"]) != modal]
    if not odd:
        return [_step("rev-brute", "黑盒爆破", "UNKNOWN", 1,
                      f"所有长度信号都一样（rc={modal[0]}，输出 {modal[2]}B）——不是逐字符可观测型，跳过")]
    length = odd[0][0]
    use = "rc" if odd[0][1]["rc"] != modal[0] else ("hash" if odd[0][1]["hash"] != modal[1] else "len")
    steps.append(_step("rev-brute", f"黑盒爆破：期望长度 {length}，信号 = {use}", "UNKNOWN", 2,
                       f"{len(odd)} 个长度给出不同信号（其余 {len(probes) - len(odd)} 个相同）→ 逐字符可问"))

    # ② 逐字符问
    known = ""
    ambiguous = False
    for pos in range(length):
        if time.time() - t0 > budget_s:
            steps.append(_step("rev-brute", "黑盒爆破", "UNKNOWN", 1,
                               f"超预算（已问出 {len(known)}/{length}：{known[:40]}）"))
            break
        base_sig = _signal(path, (known + "A" * (length - len(known))).encode(), timeout)
        best_ch, best_key, diff_count = None, None, 0
        for ch in PRINTABLE:
            if time.time() - t0 > budget_s:
                break
            sig = _signal(path, (known + ch + "A" * (length - len(known) - 1)).encode(), timeout)
            if sig is None:
                continue
            key = sig["rc"] if use == "rc" else (sig["hash"] if use == "hash" else sig["len"])
            if key != (base_sig["rc"] if use == "rc" else (base_sig["hash"] if use == "hash" else base_sig["len"])):
                diff_count += 1
                if use == "rc":                     # 退出码型：越对越往后（取最大）
                    if best_key is None or key > best_key:
                        best_ch, best_key = ch, key
                elif best_ch is None:               # 哈希型：第一个不同的作候选
                    best_ch, best_key = ch, key
        if best_ch is None:
            break
        if use != "rc" and diff_count > 1:          # 哈希型多个候选 → 判不了，别硬猜
            ambiguous = True
            steps.append(_step("rev-brute", f"黑盒爆破：第 {pos + 1} 位有 {diff_count} 个候选",
                               "UNKNOWN", 1, f"前缀 {known!r} 之后信号无法唯一确定，停在这里"))
            break
        known += best_ch

    # ③ 收尾验证（必须真跑一遍）
    if known:
        sig = _signal(path, (known + "\n").encode(), timeout)
        ok = False
        if sig is not None:
            detail = ""
            try:
                p = subprocess.run([path], input=(known + "\n").encode(), capture_output=True, timeout=timeout)
                out = (p.stdout + p.stderr).decode("utf-8", "replace")
                ok = (p.returncode == 0 and bool(PROMPT_ANCHORS.search(out))) or bool(O.flags_in(out))
                detail = out.strip()[:120]
            except Exception:
                detail = ""
            steps.append(_step("rev-brute", f"黑盒爆破{'命中' if ok else '未验证通过'}（{len(known)} 字符）",
                               "HIT" if ok else "UNKNOWN", 3 if ok else 2,
                               (f"真跑一遍：{detail}" if detail else f"rc={sig['rc']}（没能确认成功态）"),
                               known))
        if ok:
            return steps
    if not any(s["verdict"] == "HIT" for s in steps):
        steps.append(_step("rev-brute", "黑盒爆破未命中", "UNKNOWN", 1,
                           "信号可观测但没问出答案：可能不是逐字符比较，或需要特定输入格式"))
    return steps


# ---------------------------------------------------------------- ③.5 汇编源码：变换链重放

ASM_HINT = re.compile(r"\b(mov|lea|xor|add|sub|cmp|jne|je|loop|int|push|pop|db|equ)\b", re.I)
DB_BYTES_RE = re.compile(r"\bdb\b\s*(.+)$", re.I)


def _parse_db_values(expr: str) -> list[int]:
    """解析 `db 01Ch, 029h, 'Hello', 13, 10` 这类数据定义。"""
    out: list[int] = []
    for tok in re.split(r",", expr):
        tok = tok.strip()
        if not tok:
            continue
        m = re.match(r"^'(.*)'$", tok) or re.match(r'^"(.*)"$', tok)
        if m:
            out += list(m.group(1).encode("latin-1", "replace"))
            continue
        m = re.match(r"^([0-9][0-9a-f]*)h$", tok, re.I)       # NASM 风格 01Ch（含字母的十六进制）
        if m:
            out.append(int(m.group(1), 16))
            continue
        m = re.match(r"^0x([0-9a-f]+)$", tok, re.I)
        if m:
            out.append(int(m.group(1), 16))
            continue
        if re.fullmatch(r"\d+", tok):
            out.append(int(tok))
    return out


def rev_asm_source(path: str, budget_s: float = 30.0) -> list[dict]:
    """汇编**源码**型 rev：解析常量数组与逐字节变换链，逆变换 + **正变换回验**（自洽即硬证据）。

    覆盖常见形态：`xor al, key[bx]` / `add al, 3` / `sub al, 1` / `rol|ror al, n` / `not al` /
    `inc|dec al` 组成的循环，配上 `db` 常量数组（'Hello'、01Ch、0x1C 都认）。
    """
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return [_step("rev-asm", "汇编源码解析", "ERROR", 1, str(e))]
    if not ASM_HINT.search(text):
        return []
    labels: dict[str, list[int]] = {}
    cur = ""
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z_][\w]*)\s+db\s+(.+)$", line, re.I) or \
            re.match(r"^\s*([A-Za-z_][\w]*)\s+db\s*$", line, re.I)
        if m:
            cur = m.group(1).lower()
            labels.setdefault(cur, [])
            if m.lastindex == 2:
                labels[cur] += _parse_db_values(m.group(2))
            continue
        if cur and re.match(r"^\s*db\s+(.+)$", line, re.I):     # 续行
            labels[cur] += _parse_db_values(re.match(r"^\s*db\s+(.+)$", line, re.I).group(1))
    # 密文数组 = 最长且元素都在 0..255 的数组；key = 短的字符串数组
    arrays = [(k, v) for k, v in labels.items() if v and all(0 <= x <= 255 for x in v)]
    if not arrays:
        return [_step("rev-asm", "汇编源码", "UNKNOWN", 2, "是汇编源码但没找到 db 常量数组")]
    arrays.sort(key=lambda kv: -len(kv[1]))
    ct_name, ct = arrays[0]
    # 密钥数组的选法：**优先 xor/sub/add 行里真正出现的那个数组名**（否则会把提示字符串当密钥，
    # 结果回验不一致）；其次取最短的可打印数组
    used_names = [n.lower() for n in re.findall(r"(?:xor|sub|add)\s+(?:al|ax|eax)\s*,\s*([A-Za-z_]\w*)\s*(?:\[|\b)", text, re.I)]
    key_name, key = None, [0]
    for n in used_names:
        for k, v in arrays[1:]:
            if k == n and 1 <= len(v) <= 32:
                key_name, key = k, v
                break
        if key_name:
            break
    if key_name is None:
        printable = [(k, v) for k, v in arrays[1:]
                     if 1 <= len(v) <= 16 and all(32 <= b < 127 for b in v)]
        printable.sort(key=lambda kv: len(kv[1]))
        if printable:
            key_name, key = printable[0]
    keys = [(key_name, key)] if key_name else []
    steps = [_step("rev-asm", f"汇编源码：密文数组 {ct_name}（{len(ct)}B）"
                               + (f" + 密钥 {keys[0][0]}={key!r}" if keys else "（无密钥数组）"),
                               "UNKNOWN", 2, "从 db 定义里取到的常量数组")]

    # 变换链：按出现顺序收 al/ax 上的立即数与操作
    ops: list[tuple] = []
    for line in text.splitlines():
        m = re.search(r"\b(xor|add|sub|rol|ror|not|inc|dec)\s+(al|eax|ax|byte ptr \[[^\]]+\]|\w+)\s*(?:,\s*(0x[0-9a-f]+|\d+h|\d+))?", line, re.I)
        if not m:
            continue
        op, operand, imm = m.group(1).lower(), m.group(2).lower(), m.group(3)
        if "key[" in line.lower() or (keys and keys[0][0] in line.lower()):
            ops.append(("xor-key", None))                     # 与密钥逐字节异或（循环使用）
        elif imm is not None:
            v = int(imm, 16) if (imm.lower().startswith("0x") or imm.lower().endswith("h")) else int(imm)
            if op in ("xor", "add", "sub", "rol", "ror", "not", "inc", "dec"):
                ops.append((op, v))
    if not ops:
        return steps + [_step("rev-asm", "变换链", "UNKNOWN", 1, "没解析出逐字节变换（可能是寄存器/查表型）")]
    steps.append(_step("rev-asm", f"变换链：{' → '.join(str(o[0]) for o in ops)}", "UNKNOWN", 2,
                       f"{len(ops)} 步（作用在 al 上）"))

    def inv_ops(byte: int, idx: int) -> int:
        b = byte
        for op, v in reversed(ops):                            # 逆序逆变换
            if op == "xor-key":
                b ^= (key[idx % len(key)] if key else 0)
            elif op == "xor":
                b ^= v
            elif op == "add":
                b = (b - v) & 0xFF
            elif op == "sub":
                b = (b + v) & 0xFF
            elif op == "rol":
                n = v % 8
                b = ((b >> n) | (b << (8 - n))) & 0xFF          # 逆 rol = ror
            elif op == "ror":
                n = v % 8
                b = ((b << n) | (b >> (8 - n))) & 0xFF
            elif op == "not":
                b = (~b) & 0xFF
            elif op == "inc":
                b = (b - 1) & 0xFF
            elif op == "dec":
                b = (b + 1) & 0xFF
        return b & 0xFF

    def fwd_ops(byte: int, idx: int) -> int:                    # 正变换（回验用）
        b = byte
        for op, v in ops:
            if op == "xor-key":
                b ^= (key[idx % len(key)] if key else 0)
            elif op == "xor":
                b ^= v
            elif op == "add":
                b = (b + v) & 0xFF
            elif op == "sub":
                b = (b - v) & 0xFF
            elif op == "rol":
                n = v % 8
                b = ((b << n) | (b >> (8 - n))) & 0xFF
            elif op == "ror":
                n = v % 8
                b = ((b >> n) | (b << (8 - n))) & 0xFF
            elif op == "not":
                b = (~b) & 0xFF
            elif op == "inc":
                b = (b + 1) & 0xFF
            elif op == "dec":
                b = (b - 1) & 0xFF
        return b & 0xFF

    cand = bytes(inv_ops(c, i) for i, c in enumerate(ct))
    re_enc = bytes(fwd_ops(b, i) for i, b in enumerate(cand))
    consistent = re_enc == bytes(ct)                             # 回验：必须是原密文
    flagish = O.is_hit(O.judge_all(cand.decode("latin-1")))[0] or bool(O.flags_in(cand.decode("latin-1", "replace")))
    txt = cand.decode("latin-1")
    steps.append(_step("rev-asm", f"逆变换结果（正变换回验{'一致 ✔' if consistent else '不一致 ✘'}）",
                       "HIT" if (consistent and (flagish or all(32 <= b < 127 for b in cand))) else "UNKNOWN",
                       3 if consistent and flagish else (2 if consistent else 1),
                       ("逆变换后再正变换 == 原密文（自洽），且内容像 flag/明文" if consistent
                        else "自洽性不成立，说明变换链没解析全（需人工）"),
                       txt, [f"# 复现：按 {' → '.join(str(o[0]) for o in ops)} 的逆序逆变换密文数组即可"]))
    return steps


# ---------------------------------------------------------------- ④ 反汇编级提取

def rev_disasm(path: str, budget_s: float = 40.0) -> list[dict]:
    """有 objdump/r2 时：抓立即数序列与提示串（半自动，给候选与锚点）。"""
    steps: list[dict] = []
    od, r2 = _have("objdump"), _have("r2") or _have("rizin")
    if od:
        rc, out = _run([od, "-d", "-M", "intel", path], timeout=120)
        if rc == 0:
            imms = re.findall(r"(cmp|xor|add|sub)\s+(?:[a-z]{2,3}\s*,\s*)?0x([0-9a-f]{2,4})\b", out)
            seq = [int(v, 16) for op, v in imms if 1 <= int(v, 16) <= 0xFF]
            interesting = [v for v in seq if 0x20 <= v <= 0x7E]
            steps.append(_step("rev-disasm", f"objdump 立即数（cmp/xor/add/sub，{len(seq)} 条，可打印 {len(interesting)} 条）",
                               "UNKNOWN", 2,
                               "立即数序列是可打印字符的嫌疑很大（逐字节比较/变换）",
                               " ".join(f"{v:02x}" for v in seq[:64])))
            if interesting:
                cand = "".join(chr(v) for v in interesting[:80])
                if O.is_hit(O.judge_all(cand))[0] or O.flags_in(cand):
                    steps.append(_step("rev-disasm", "用立即数序列拼出的候选", "HIT", 3, "拼出的内容像答案", cand))
                else:
                    # 立即数序列本身常是"被变换过的字符"（如逐字节 ^k）→ 直接拿它跑 XOR 扫描
                    xh = [b for b in bytes((v & 0xFF) for v in interesting[:120])]
                    for st in AS.xor_sweep(bytes(xh), budget_s=6.0)[:1]:
                        if st["verdict"] == "HIT":
                            steps.append(_step("rev-disasm", "立即数序列 → 单字节 XOR", "HIT", st["conf"],
                                               st["reason"], st["result"]))
                            break
                    else:
                        steps.append(_step("rev-disasm", "立即数拼候选（未成形）", "UNKNOWN", 1,
                                           "序列看着像字符但拼不出 flag：可能被自定义变换（需读代码）", cand[:120]))
            anchors = [l.strip() for l in out.splitlines() if PROMPT_ANCHORS.search(l)][:8]
            if anchors:
                steps.append(_step("rev-disasm", f"提示串锚点（{len(anchors)} 处）", "UNKNOWN", 2,
                                   "这些串就是判定分岔点（correct/wrong 的引用处）", "\n".join(anchors)[:800]))
    if r2:
        rc, out = _run([r2, "-q", "-e", "scr.color=0", "-c", "aaa; afl~main; izz~flag,correct,wrong", "-c", "q", path],
                       timeout=180)
        if rc == 0 and out.strip():
            steps.append(_step("rev-disasm", "radare2（函数/字符串摘要）", "UNKNOWN", 2,
                               "r2 的摘要可供人工接力", out[:900]))
    if not steps:
        steps.append(_step("rev-disasm", "反汇编", "UNKNOWN", 1,
                           "没装 objdump/r2（主机上有）：给出命令自己看",
                           "", [f"objdump -d -M intel {path} | less", f"r2 -A {path}"]))
    return steps


# ---------------------------------------------------------------- 调度 + 工具

def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, f"{type(e).__name__}: {e}"


def _step(sid, label, verdict="MISS", conf=1, reason="", result="", cmds=None) -> dict:
    return {"id": sid, "label": label, "verdict": verdict, "conf": conf,
            "reason": reason, "result": result, "cmds": cmds or []}


def rev_auto(path: str, budget_s: float = 120.0, brute: bool = True) -> list[dict]:
    """rev 自动推进：① 结构+明文 → ② 常量数组 → ③ 对称算法解密 → ③.5 汇编源码变换链 → ④ 反汇编 → ④.5 黑盒爆破。"""
    steps: list[dict] = []
    # 汇编**源码**（.asm/.s 或长得像汇编的文本）先走变换链重放
    head = open(path, "rb").read(4096)
    if re.search(rb"\.(asm|s|S)$|^\s*\.(8086|model|data|code)\b", head[:400], re.M) or \
            (b"db " in head and ASM_HINT.search(head.decode("latin-1", "replace"))):
        steps += rev_asm_source(path, budget_s=budget_s)
        if O.flags_in("\n".join(x.get("result", "") for x in steps)):
            return steps
    info = elf_info(path)
    steps.append(_step("rev-info", f"结构：{info.get('type')} {info.get('arch', '')} "
                                   f"入口 {info.get('entry', '?')} PIE={info.get('pie', '?')}", "UNKNOWN", 2,
                       f"{len(info.get('sections', []))} 个节区", ", ".join(n for n, _ in info.get("sections", [])[:12])))
    strings = rev_strings(path)
    flags = []
    for s in strings:
        flags += O.flags_in(s)
    anchors = [s for s in strings if PROMPT_ANCHORS.search(s) and len(s) < 120][:6]
    if flags:
        steps.append(_step("rev-strings", "字符串里的 flag（明文捷径）", "HIT", 3,
                           f"{len(flags)} 个可疑 flag", "\n".join(dict.fromkeys(flags))[:400]))
        return steps
    if anchors:
        steps.append(_step("rev-strings", f"提示串锚点（{len(anchors)} 条）", "UNKNOWN", 2,
                           "这些是判定分岔点（谁打印 correct/wrong 谁就是校验函数）", "\n".join(anchors)[:400]))
    steps += rev_crypto(path, budget_s=min(45.0, budget_s))
    if O.flags_in("\n".join(x.get("result", "") for x in steps)):
        return steps
    steps += rev_blobs(path, budget_s=min(25.0, budget_s))
    if not O.flags_in("\n".join(x.get("result", "") for x in steps)):
        steps += rev_disasm(path, budget_s=min(40.0, budget_s))
        if brute:
            steps += rev_brute(path, budget_s=min(budget_s, 90.0))
    return steps
