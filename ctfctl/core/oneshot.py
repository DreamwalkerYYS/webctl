"""oneshot —— 「一把梭」层：某些题型用**现成工具**一次跑完，判定器只做裁决。

设计原则（沿用全项目）：
  · 能调现成工具就调，不重写；本层只负责「认类型 → 选工具 → 跑 → 用判定器验」。**
  · 工具不在位时**不假装能解**：给出一条可复制的安装命令，并标 UNKNOWN。
  · 每个 runner 返回 _step 结构（id/label/verdict/conf/reason/result/cmds）。
  · 只读为主；会写盘的（binwalk -e / git-dumper / foremost）写进缓存目录。
  · 绝不联网打靶、不执行远端代码。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

from . import oracles as O
from .config import CACHE
from .revauto import _step

#: 一把梭题型 → 工具 / 装法（工具不在位时把装法原样报出来）
TOOLKIT = {
    "qr":        {"tool": "zbarimg", "install": "pacman -S zbar", "how": "zbarimg -q --raw <图片>"},
    "stego_png": {"tool": "zsteg", "install": "paru -S zsteg  # 或 gem install zsteg",
                  "how": "zsteg -a <图片>"},
    "stego_jpg": {"tool": "stegseek", "install": "paru -S stegseek",
                  "how": "stegseek <图片> <字典>"},
    "stego_any": {"tool": "steghide", "install": "pacman -S steghide", "how": "steghide extract -sf <文件>"},
    "zip_crack": {"tool": "zip2john", "install": "pacman -S john", "how": "zip2john a.zip > h; john --wordlist=… h"},
    "zip_fast":  {"tool": "fcrackzip", "install": "pacman -S fcrackzip", "how": "fcrackzip -u -D -p 字典 a.zip"},
    "pyc":       {"tool": "pycdc", "install": "paru -S pycdc-git  # 或 pip install decompyle3",
                  "how": "pycdc a.pyc  # 反编译出源码直接看逻辑"},
    "git":       {"tool": "git-dumper", "install": "pacman -S git-dumper", "how": "git-dumper <站点/.git> 目录"},
    "pcap":      {"tool": "tshark", "install": "pacman -S wireshark-cli", "how": "tshark -r a.pcap -Y http"},
    "sqlcipher": {"tool": "sqlcipher", "install": "pacman -S sqlcipher",
                  "how": "sqlcipher db 'PRAGMA key=\"…\"; .dump'"},
    "audio":     {"tool": "sox", "install": "pacman -S sox multimon-ng", "how": "sox a.wav -n spectrogram"},
    "rsa":       {"tool": "RsaCtfTool", "install": "pipx install RsaCtfTool",
                  "how": "RsaCtfTool --publickey k.pub --private"},
}


def _have(cmd: str) -> str:
    return shutil.which(cmd) or ""


def _run(cmd: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, f"{type(e).__name__}: {e}"


def _verdict_of(out: str, extra: str = "") -> tuple[str, int, str, str]:
    """统一裁决：先看 flag 样式，再看是否解出可读明文/文件（不看"输出可读"本身）。"""
    flags = O.flags_in(out)
    if flags:
        return "HIT", 3, f"解出 flag：{flags[0]}", "\n".join(l for l in out.splitlines() if flags[0] in l)[:400]
    fm = O.file_magic(out.encode("utf-8", "replace"))
    if fm["verdict"] == "HIT":
        return "HIT", 3, fm["reason"], out[:300]
    hits = [r for r in O.judge_all(out) if r["verdict"] == "HIT" and r["conf"] >= 2
            and not r["oracle"].startswith("text_readable")]
    if len(hits) >= 2:
        return "HIT", 2, "中证据 " + "、".join(r["oracle"] for r in hits), out[:300]
    if extra:
        return "UNKNOWN", 1, extra, out[:200]
    return "UNKNOWN", 1, "工具跑完了但没有硬证据（见输出）", out[:200]


def _missing(kind: str) -> dict:
    t = TOOLKIT[kind]
    return _step(f"oneshot-{kind}", f"{kind}：缺 {t['tool']}（未安装，不假装能解）", "UNKNOWN", 1,
                 f"装：{t['install']}", "", [t["how"]])


# ---------------------------------------------------------------- 各 runner

def qr(path: str) -> list[dict]:
    """二维码/条码：zbarimg 一把梭（图片里藏 QR 是常见 misc 送分题）。"""
    if not _have("zbarimg"):
        return [_missing("qr")]
    rc, out = _run(["zbarimg", "-q", "--raw", path], timeout=60)
    v, c, reason, res = _verdict_of(out, "" if rc == 0 else f"zbarimg rc={rc}")
    return [_step("oneshot-qr", "二维码/条码（zbarimg）", v, c, reason, res, [f"zbarimg -q --raw {path}"])]


def git_leak(path_or_dir: str) -> list[dict]:
    """`.git` 泄露：先看本地目录里有没有 .git，再看工作站目录（站点 .git 用 git-dumper 需要 URL）。"""
    if not _have("git-dumper"):
        return [_missing("git")]
    d = path_or_dir if os.path.isdir(path_or_dir) else os.path.dirname(os.path.abspath(path_or_dir))
    if not os.path.isdir(os.path.join(d, ".git")):
        return [_step("oneshot-git", ".git 泄露", "UNKNOWN", 1,
                      "本地没有 .git/ 目录（站点上的 .git 需要 URL，用下面的命令抓）",
                      "", [f"git-dumper <站点>/.git {CACHE}/gitdump"])]
    outdir = os.path.join(CACHE, "oneshot", "gitdump")
    os.makedirs(outdir, exist_ok=True)
    rc, out = _run(["bash", "-lc", f"cd {d} && git log --all --oneline | head -20; git stash list; "
                                   f"git fsck --lost-found 2>&1 | head -10"], timeout=120)
    v, c, reason, res = _verdict_of(out, "有 .git/：先 git log --all / stash / fsck 找历史里的 flag")
    return [_step("oneshot-git", "本地 .git 历史（log/stash/fsck）", v, c, reason, res,
                  [f"cd {d} && git log --all -p | grep -i flag", f"cd {d} && git fsck --lost-found"])]


def pcap(path: str) -> list[dict]:
    """流量包：tshark 导出 http 对象 + 打印明文凭据（US/pw 之类）。"""
    if not _have("tshark"):
        return [_missing("pcap")]
    rc, out = _run(["bash", "-lc",
                    f"tshark -r {path!r} -q -z follow,tcp,ascii 2>/dev/null | head -c 400000"], timeout=180)
    v, c, reason, res = _verdict_of(out)
    steps = [_step("oneshot-pcap", "pcap 会话重组（tshark follow tcp）", v, c, reason, res,
                   [f"tshark -r {path} -Y 'http.request' -T fields -e http.request.uri",
                    f"tshark -r {path} --export-objects http,{CACHE}/pcap"])]
    if v != "HIT":     # 再试导出 http 对象（文件里常有 flag）
        outdir = os.path.join(CACHE, "oneshot", "pcap")
        os.makedirs(outdir, exist_ok=True)
        _run(["bash", "-lc", f"tshark -r {path!r} --export-objects http,{outdir} 2>/dev/null"], timeout=180)
        found = []
        for root, _, files in os.walk(outdir):
            for f in files:
                p = os.path.join(root, f)
                try:
                    data = open(p, "rb").read(2_000_000)
                except OSError:
                    continue
                fl = O.flags_in(data.decode("utf-8", "replace"))
                if fl:
                    found += fl
        if found:
            steps.append(_step("oneshot-pcap", "pcap 导出的对象里找到 flag", "HIT", 3,
                               f"{found[0]}", "\n".join(found[:3]), [os.path.join(outdir, "*")]))
    return steps


def sqlcipher_db(path: str, keys: list[str] | None = None) -> list[dict]:
    """SQLCipher 数据库：用候选密钥尝试 dump（密钥常来自题面/元数据/文件名）。"""
    if not _have("sqlcipher"):
        return [_missing("sqlcipher")]
    cand_keys = list(keys or [])
    stem = os.path.splitext(os.path.basename(path))[0]
    cand_keys += [stem, "123456", "password", "ctf", "flag"]
    steps: list[dict] = []
    for k in cand_keys[:8]:
        out_db = os.path.join(CACHE, "oneshot", "dump.sqlite")
        os.makedirs(os.path.dirname(out_db), exist_ok=True)
        if os.path.exists(out_db):
            os.remove(out_db)
        script = (f"PRAGMA key='{k}'; PRAGMA cipher_migrate;\n"
                  f"ATTACH DATABASE '{out_db}' AS plaintext KEY '';\n"
                  f"SELECT sqlcipher_export('plaintext');\nDETACH DATABASE plaintext;\n")
        rc, out = _run(["sqlcipher", path], timeout=60)
        rc2, out2 = _run(["bash", "-lc", f"printf %s {script!r} | sqlcipher {path!r} 2>&1 | head -20"], timeout=60)
        blob = ""
        if os.path.exists(out_db):
            rc3, blob = _run(["sqlite3", out_db, ".dump"], timeout=60)
        v, c, reason, res = _verdict_of(blob + out2, "")
        if v == "HIT":
            return steps + [_step("oneshot-sqlcipher", f"SQLCipher 解密成功（密钥 {k!r}）", "HIT", 3,
                                  reason, res, [f"sqlcipher {path}  # PRAGMA key='{k}'; .dump"])]
        steps.append(_step("oneshot-sqlcipher", f"SQLCipher 试密钥 {k!r}", "MISS", 1, out2[:120] or "无输出"))
        # WAL/journal 检查（未提交数据常藏 flag）
    wal = path + "-wal"
    if os.path.exists(wal):
        out = "".join(x for x in re.findall(r"[\x20-\x7e]{6,}", open(wal, "rb").read().decode("latin-1", "ignore"))[:2000])
        v, c, reason, res = _verdict_of(out, "有 -wal 文件：文件里可能有未提交的事务数据")
        steps.append(_step("oneshot-sqlcipher", "SQLite WAL 里的可读串", v, c, reason, res, [f"strings {wal}"]))
    if not steps:
        steps.append(_step("oneshot-sqlcipher", "SQLCipher", "UNKNOWN", 1, "候选密钥都不对，需要题面/元数据里的密钥"))
    return steps


def pyc_decompile(path: str) -> list[dict]:
    """Python 字节码：反编译回源码（一把梭，逻辑直接可读）。"""
    tool = _have("pycdc") or _have("decompyle3") or _have("uncompyle6")
    if not tool:
        return [_missing("pyc")]
    base = os.path.basename(tool)
    if base == "pycdc":
        rc, out = _run([tool, path], timeout=90)
    else:
        rc, out = _run([tool, path], timeout=90)
    v, c, reason, res = _verdict_of(out, "反编译输出里有嫌疑字符串（自己 grep 一下常量/比较）")
    return [_step("oneshot-pyc", f"pyc 反编译（{base}）", v, c, reason, res, [f"{base} {path}"])]


def dispatch(path: str) -> list[dict]:
    """按文件特征挑 runner（只跑"认出来的类型"，认不出就返回空）。"""
    steps: list[dict] = []
    if not os.path.exists(path) or os.path.isdir(path):
        return steps
    try:
        head = open(path, "rb").read(4096)
    except OSError:
        return steps
    ext = os.path.splitext(path)[1].lower()
    # 二维码/条码：图片就试（zbarimg 很快）
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:4] == b"GIF8":
        steps += qr(path)
    if head[:4] == b"\x7fELF" and b"python" in head.lower():
        steps += pyc_decompile(path)
    if ext in (".pyc", ".pyo") or head[:4] in (b"\x42\x0d\x0d\x0a", b"\x55\x0d\x0d\x0a"):
        steps += pyc_decompile(path)
    if head[:2] == b"MZ" and b"pyinstaller" in head.lower():
        steps += [_step("oneshot-pyc", "疑似 PyInstaller 打包", "UNKNOWN", 2,
                        "先用 pyinstxtractor 拆包再反编译 entry .pyc",
                        "", ["pip install pyinstxtractor", "python pyinstxtractor.py <exe>"])]
    if head[:4] == b"\xd4\xc3\xb2\xa1" or head[:4] == b"\x0a\x0d\x0d\x0a":
        steps += pcap(path)
    if head[:16] == b"SQLite format 3\x00":
        # 未加密的 SQLite 也能直接 dump（加密的交给 sqlcipher 分支）
        rc, out = _run(["sqlite3", path, ".dump"], timeout=90)
        v, c, reason, res = _verdict_of(out, "SQLite 能直接读（未加密）")
        steps.append(_step("oneshot-sqlite", "SQLite 直接 dump", v, c, reason, res, [f"sqlite3 {path} .dump"]))
        if v != "HIT":
            steps += sqlcipher_db(path)
    return steps
