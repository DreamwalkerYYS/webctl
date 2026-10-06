"""oracles —— 确定性判定器（**非 AI**）：把「这一步成功了没有」变成可复核的三态结论。

设计原则（路线文档 `~/文档/Brain/项目/ctfctl/` 里的第 1 节）：
  · 三态：HIT / MISS / UNKNOWN / ERROR —— UNKNOWN 表示"判定器说不清，该人上"，不是失败。
  · 置信三档：硬(3) / 中(2) / 弱(1)。**HIT 需要 ≥1 条硬证据，或 ≥2 条不重复的中证据**；
    弱证据（如"响应长度变了"）永远不能单独判 HIT。
  · 判定器必须**无副作用**（只读、不发送、不改文件），且必须给出依据（可复核的短句）。
  · 不许引入任何模型/统计学习判定（明文可读性用可打印率 + 字母频率卡方 + 常用字表，
    明文/Ciphey 那套 BERT 判定器按约束不采用）。
"""
from __future__ import annotations

import math
import re
import unicodedata

#: 形似 flag 的完整样式（前缀 + 内容），先宽后严：命中后还要过"前缀可信 / 内容合理"两道
FLAG_SHAPE_RE = re.compile(r"(?<![A-Za-z0-9_.\-])([A-Za-z][A-Za-z0-9_]{1,23})\{([^}\n]{2,400})\}")
FLAG_LOOSE_RE = re.compile(r"([A-Za-z][A-Za-z0-9_]{2,23}\{[^}\n]{2,400})")   # 半截（可能被截断）

#: 常见赛事/平台前缀（不穷举，只用来"提高可信度"，不是必需条件）
KNOWN_FLAG_PREFIXES = {
    "flag", "ctf", "key", "pass", "pwd", "nssctf", "buuctf", "hitcon", "iscc", "qwb", "moectf",
    "swpuctf", "dest", "n1ctf", "de1ctf", "hgame", "geek", "guess", "sctf", "starctf", "ACTF",
    "NSS", "flag2", "FLAG", "CTF", "KEY", "flag_", "ctfshow", "moe",
}

#: 形似 flag 的**内容**要有起码的"像人写的"：字母数字占比高、标点不能占主导
def _flag_content_ok(content: str) -> bool:
    if not content or len(content) < 3:
        return False
    if any(ch in content for ch in "{}<>`"):        # 不允许嵌套/反引号
        return False
    ok = sum(1 for ch in content if ch.isalnum() or ch in "_-@.!#$%^&*()+=:, " )
    return ok / len(content) >= 0.75


def _flag_prefix_ok(prefix: str, content: str, text: str) -> tuple[bool, str]:
    """前缀是否可信：常见前缀 > 命中常用词 > 同文本可读。返回 (可信, 理由)。"""
    low = prefix.lower()
    # 内容门槛对**所有**前缀都适用：`key{as#}` 这种 4 字内容即使前缀眼熟也不算（实测假阳性）
    tight = sum(1 for ch in content if ch.isalnum() or ch in "_-!@") / len(content)
    if len(content) < 6 or tight < 0.85:
        return False, f"内容太短/太杂（{len(content)} 字符，紧凑度 {tight:.2f}）"
    if any(ch in content for ch in "[]{}<>`~^|\\"):        # 这些字符几乎不出现在真 flag 里
        return False, "内容含非常见字符"
    if low in KNOWN_FLAG_PREFIXES or prefix in KNOWN_FLAG_PREFIXES:
        return True, "前缀在常见清单里"
    if low in COMMON_WORDS or low.rstrip("_") in COMMON_WORDS:
        return True, "前缀是常用词"
    if _chi2_en(text) < 60 or _cjk_ratio(text) >= 0.3:
        return True, "同文本整体可读（英文卡方/中文占比达标）"
    # 通用旗样式：短前缀（2–10 位，常全大写）+ 花括号内容紧凑（≥6 位、无空格、字符集干净）
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,9}", prefix) and len(content) >= 6 and " " not in content:
        tight = sum(1 for ch in content if ch.isalnum() or ch in "_-!@#" ) / len(content)
        if tight >= 0.9:
            return True, "短前缀 + 内容紧凑（通用旗样式）"
    return False, "前缀不像 flag 名（可能是错密钥/错变换的另一种可读路径）"

MAGICS = [
    ("PNG", 0, b"\x89PNG\r\n\x1a\n"), ("JPEG", 0, b"\xff\xd8\xff"), ("GIF", 0, b"GIF8"),
    ("ZIP", 0, b"PK\x03\x04"), ("GZIP", 0, b"\x1f\x8b"), ("BZIP2", 0, b"BZh"),
    ("XZ", 0, b"\xfd7zXZ"), ("7Z", 0, b"7z\xbc\xaf\x27\x1c"), ("RAR", 0, b"Rar!\x1a\x07"),
    ("PDF", 0, b"%PDF"), ("ELF", 0, b"\x7fELF"), ("PE", 0, b"MZ"), ("SQLITE", 0, b"SQLite format 3"),
    ("PCAP", 0, b"\xd4\xc3\xb2\xa1"), ("PCAPNG", 0, b"\x0a\x0d\x0d\x0a"), ("TAR", 257, b"ustar"),
    ("CLASS", 0, b"\xca\xfe\xba\xbe"), ("WAV", 0, b"RIFF"), ("MP3", 0, b"ID3"),
]

#: 英文 26 字母频率（百分比），用于卡方检验
EN_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
           2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
           1.974, 0.074]

#: 常用英文词（判定"这段是不是人话"的辅助，不用外部字典）
COMMON_WORDS = {
    "the", "and", "you", "that", "this", "with", "have", "from", "not", "are", "was", "for",
    "his", "her", "one", "all", "but", "they", "will", "would", "there", "their", "what", "about",
    "flag", "key", "secret", "password", "pass", "user", "admin", "hello", "world", "test", "ctf",
    "congratulations", "congrats", "well", "done", "success", "correct", "wrong", "welcome", "token",
    "encode", "decode", "cipher", "base64", "xor", "easy", "baby", "level", "stage", "submit",
}


def _ratio_printable(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def _chi2_en(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha() and c.isascii()]
    n = len(letters)
    if n < 20:
        return 1e9
    counts = {c: 0 for c in "abcdefghijklmnopqrstuvwxyz"}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    total = 0.0
    for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
        exp = EN_FREQ[i] / 100 * n
        total += (counts[c] - exp) ** 2 / exp
    return total


def _cjk_ratio(text: str) -> float:
    if not text:
        return 0.0
    cjk = sum(1 for c in text if 0x4E00 <= ord(c) <= 0x9FFF)
    return cjk / len(text)


def _word_hits(text: str) -> int:
    toks = set(re.findall(r"[A-Za-z]{2,20}", text.lower()))
    return len(toks & COMMON_WORDS)


def _res(oracle: str, verdict: str, conf: int, reason: str, extracted=None) -> dict:
    return {"oracle": oracle, "verdict": verdict, "conf": conf, "reason": reason,
            "extracted": list(extracted or [])}


# ---------------------------------------------------------------- 各判定器

def flags_in(text: str) -> list[str]:
    """从一段文本里取出**可信**的完整 flag（形状 + 前缀 + 内容三关）。"""
    out = []
    for prefix, content in FLAG_SHAPE_RE.findall(text or ""):
        if _flag_content_ok(content) and _flag_prefix_ok(prefix, content, text)[0]:
            out.append(f"{prefix}{{{content}}}")
    return out


def flag_oracle(text: str) -> dict:
    """flag 判定：**形状 + 前缀可信 + 内容合理**三关都过才算硬证据。

    只用"形似 `xxx{...}`"会让错密钥/错变换的乱码也命中（实测：rot47 能把字母变成 `{|}`，
    XOR 错密钥也能把整句变可打印）——所以必须加后缀两道。
    """
    text = text or ""
    good, weak = [], []
    for prefix, content in FLAG_SHAPE_RE.findall(text):
        tok = f"{prefix}{{{content}}}"
        if not _flag_content_ok(content):
            weak.append(tok)
            continue
        ok, why = _flag_prefix_ok(prefix, content, text)
        (good if ok else weak).append(tok if ok else f"{tok}（{why}）")
    if good:
        return _res("flag_regex", "HIT", 3, f"完整 flag：{good[0][:60]}", good[:5])
    if weak:
        return _res("flag_regex", "UNKNOWN", 2, f"形似 flag 但不可信：{weak[0][:80]}", weak[:3])
    loose = FLAG_LOOSE_RE.findall(text)
    if loose:
        return _res("flag_regex", "UNKNOWN", 1, f"疑似半截 flag：{loose[0][:60]}", loose[:3])
    return _res("flag_regex", "MISS", 1, "没有 flag 样式")


def _magic_verified(data: bytes) -> tuple[str | None, bool, str]:
    """魔数 + **结构自洽**校验。只看 2–4 字节魔数会产生大量假阳性
    （实测：随机窗口 XOR 后撞上 `MZ`，就被当成"PE 文件"判硬证据）。"""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        ok = data[12:16] == b"IHDR" and b"IEND" in data[-64:]
        return "PNG", ok, ("IHDR + IEND 齐备" if ok else "只有魔数，缺 IHDR/IEND")
    if data[:4] == b"PK\x03\x04":
        ok = b"PK\x01\x02" in data or b"PK\x05\x06" in data
        return "ZIP", ok, ("有中央目录" if ok else "只有本地头，没有中央目录（可能是残片）")
    if data[:3] == b"\xff\xd8\xff":
        ok = data[-2:] == b"\xff\xd9"
        return "JPEG", ok, ("有 EOI 结束标记" if ok else "缺 EOI 结束标记")
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF", data[-1:] == b"\x3b", "有 trailer" if data[-1:] == b"\x3b" else "缺 trailer"
    if data[:4] == b"\x7fELF":
        ok = len(data) > 64 and data[4] in (1, 2) and data[5] in (1, 2)
        return "ELF", ok, ("header 自洽" if ok else "header 不合法")
    if data[:2] == b"MZ":
        try:
            import struct as _st
            lfanew = _st.unpack_from("<I", data, 0x3C)[0]
            ok = 0 < lfanew < len(data) - 24 and data[lfanew:lfanew + 4] == b"PE\x00\x00"
        except Exception:
            ok = False
        return "PE", ok, ("有合法 PE 头" if ok else "只有 MZ，没有 PE 头")
    if data[:2] == b"\x1f\x8b":
        try:
            import gzip as _gz
            _gz.decompress(data)
            return "GZIP", True, "能解压"
        except Exception:
            return "GZIP", False, "解压失败"
    if data[:5] == b"%PDF":
        return "PDF", b"%%EOF" in data[-1024:], "%%EOF" if b"%%EOF" in data[-1024:] else "缺 %%EOF"
    if data[257:262] == b"ustar":
        return "TAR", True, "ustar 头"
    if data[:16] == b"SQLite format 3\x00":
        return "SQLITE", True, "header"
    return None, False, ""


def file_magic(data: bytes, name: str = "") -> dict:
    fmt, ok, why = _magic_verified(bytes(data or b""))
    if fmt and ok:
        return _res("file_magic", "HIT", 3, f"{fmt}：{why}", [fmt])
    if fmt:
        return _res("file_magic", "UNKNOWN", 2, f"疑似 {fmt} 但结构不自洽（{why}）")
    hits = [n for n, off, sig in MAGICS if len(sig) >= 4 and data[off:off + len(sig)] == sig]
    if hits:
        return _res("file_magic", "UNKNOWN", 1, f"命中魔数 {hits[0]}（≤4 字节，不足以判定）")
    if not data:
        return _res("file_magic", "MISS", 1, "空数据")
    return _res("file_magic", "MISS", 1, "不是已知容器格式")


def text_readable(data) -> dict:
    """可读性判定（确定性）：可打印率 + 英文卡方 + 中文常用字占比 + 常用词命中。

    短串（<16 字节）不判可读 —— 否则随机字节也会"可读"（同类工具的常见假阳性）。
    """
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data or b"")
    if len(raw) < 16:
        return _res("text_readable", "UNKNOWN", 1, f"太短（{len(raw)}B），不判定")
    text = raw.decode("utf-8", "replace")
    pr = _ratio_printable(raw)
    cjk = _cjk_ratio(text)
    chi2 = _chi2_en(text)
    words = _word_hits(text)
    if pr < 0.85:
        return _res("text_readable", "MISS", 1, f"可打印率 {pr:.2f} < 0.85（更像二进制）")
    if cjk >= 0.30:
        return _res("text_readable", "HIT", 2, f"可打印率 {pr:.2f}，中文占比 {cjk:.2f}", [text[:200]])
    if chi2 < 60 or words >= 2:
        strong = chi2 < 45 or words >= 3
        detail = f"可打印率 {pr:.2f}，英文卡方 {chi2:.0f}，常用词 {words} 个"
        if strong:
            return _res("text_readable_strong", "HIT", 2, detail + "（强）", [text[:200]])
        return _res("text_readable", "HIT", 2, detail, [text[:200]])
    return _res("text_readable", "UNKNOWN", 1,
                f"可打印率 {pr:.2f} 但卡方 {chi2:.0f}、常用词 {words} —— 像乱码，需人工看")


def pkcs7_valid(data: bytes) -> dict:
    b = bytes(data or b"")
    if not b or len(b) % 8:
        return _res("pkcs7_valid", "MISS", 1, "长度不是 8 的倍数（不符合分组填充）")
    n = b[-1]
    if not (1 <= n <= 16) or n > len(b):
        return _res("pkcs7_valid", "MISS", 1, f"末字节 {n} 不是合法填充长度")
    if b[-n:] != bytes([n]) * n:
        return _res("pkcs7_valid", "MISS", 1, "末尾填充字节不一致")
    # 注意：填充合法**不能单独当硬证据**（随机数据末尾是 0x01 的概率 ~1/256，实测刷出过假命中）。
    # 它只在"解出明文/带 flag"等其他证据同时成立时才有意义 → 定为中证据。
    return _res("pkcs7_valid", "HIT", 2, f"PKCS#7 填充合法（{n} 字节，需与明文/flag 同时成立）")


def archive_readable(path: str) -> dict:
    """压缩包能正常读/解出条目 = 口令对（zip 用 stdlib 试，7z/rar 交给 CLI）。"""
    import os
    import tarfile
    import zipfile
    if not os.path.exists(path):
        return _res("archive_readable", "ERROR", 1, f"文件不存在：{path}")
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                bad = z.testzip()
                names = z.namelist()
            if bad:
                return _res("archive_readable", "MISS", 2, f"CRC 校验失败于 {bad}")
            return _res("archive_readable", "HIT", 3, f"ZIP 可读，{len(names)} 个条目", names[:5])
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                names = t.getnames()
            return _res("archive_readable", "HIT", 3, f"TAR 可读，{len(names)} 个条目", names[:5])
    except Exception as e:
        return _res("archive_readable", "MISS", 1, f"读不了：{type(e).__name__}: {e}")
    return _res("archive_readable", "UNKNOWN", 1, "不是 zip/tar（交给 7z/unrar）")


def structure_parity(text: str) -> dict:
    import json
    s = (text or "").strip()
    if not s:
        return _res("structure_parity", "MISS", 1, "空")
    try:
        json.loads(s)
        return _res("structure_parity", "HIT", 2, "是合法 JSON", [s[:200]])
    except Exception:
        pass
    # base64/hex 判定**不允许空格**：英文句子（"THE FLAG IS …"）会被宽松版误判成 base64
    one = re.sub(r"\s+", "", s)
    if len(one) >= 24 and " " not in s and re.fullmatch(r"[A-Za-z0-9+/=]+", one) and len(one) % 4 == 0:
        return _res("structure_parity", "HIT", 2, "符合 base64 字符集与长度", [one[:80]])
    if " " not in s and re.fullmatch(r"[0-9a-fA-F]{16,}", s):
        return _res("structure_parity", "HIT", 2, "符合十六进制字符集", [s[:80]])
    return _res("structure_parity", "MISS", 1, "不是已知结构")


def judge_tool_output(out: str) -> list[dict]:
    """判定**外部工具的输出**（binwalk/exiftool/tshark 等）。

    这类输出本来就是可读文本 → `text_readable` 必然命中，绝不能拿它当证据
    （实测：binwalk 打一行 "0 signatures" 就被判成"闭合"）。只保留硬证据类判定器。
    """
    keep = []
    for r in judge_all(out or ""):
        if r["oracle"].startswith("text_readable") or r["oracle"] == "structure_parity":
            continue
        keep.append(r)
    return keep


def judge_all(data, as_bytes: bool = False) -> list[dict]:
    """对一块数据跑全部适用判定器，按置信降序返回。"""
    out = []
    if as_bytes or isinstance(data, (bytes, bytearray)):
        raw = bytes(data or b"")
        out.append(file_magic(raw))
        out.append(text_readable(raw))
        try:
            out.append(flag_oracle(raw.decode("utf-8", "replace")))
        except Exception:
            pass
        if len(raw) % 8 == 0:
            out.append(pkcs7_valid(raw))
    else:
        text = str(data or "")
        out.append(flag_oracle(text))
        out.append(text_readable(text))
        out.append(structure_parity(text))
    return sorted(out, key=lambda r: -r["conf"])


def is_hit(results: list[dict]) -> tuple[bool, str]:
    """裁决：① 硬证据 1 条 ② 中证据 2 条（不同判定器）③ **强中证据 1 条**。

    第 ③ 条是给"可读明文"用的（古典密码/编码链解出人话，但未必带 flag 格式）：
    它算闭合但标注为中证据，报告里要写清楚，让人一眼扫过确认。
    """
    hard = [r for r in results if r["verdict"] == "HIT" and r["conf"] >= 3]
    mid = {r["oracle"]: r for r in results if r["verdict"] == "HIT" and r["conf"] == 2}
    if hard:
        return True, f"硬证据：{hard[0]['oracle']}（{hard[0]['reason']}）"
    strong = [r for r in mid.values() if r["oracle"].endswith("_strong")]
    if len(mid) >= 2:
        return True, f"中证据 {len(mid)} 条：{'、'.join(mid)}"
    if strong:
        return True, f"强中证据：{strong[0]['oracle']}（{strong[0]['reason']}）"
    return False, ""


def score(results: list[dict]) -> float:
    """给候选打分（用于在多个候选里排序；不单独当 HIT 依据）。"""
    s = 0.0
    for r in results:
        if r["verdict"] == "HIT":
            s += {3: 100.0, 2: 10.0, 1: 1.0}.get(r["conf"], 0.0)
            if r["oracle"].endswith("_strong"):
                s += 5.0
        elif r["verdict"] == "UNKNOWN":
            s += 0.5
    return s
