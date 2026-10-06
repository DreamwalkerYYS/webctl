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
#: 「一把梭」工具注册表（2026-10 调研，按"本地文件→输出"无交互可调用性取舍）
#: 字段：tool=可执行名 / install=装法 / how=无交互调用式 / net=是否需要联网 / ai=是否依赖模型
#: 说明：GPL 一律**子进程调用**，不链接不嵌入（避免传染）；带 ai=True 的默认不自动跑。
TOOLKIT = {
    # —— 图片/音频隐写 ——
    "png_lsb":   {"tool": "zsteg", "install": "paru -S zsteg  # 或 gem install zsteg", "net": False, "ai": False,
                  "how": "zsteg -a <图.png>"},
    "jpg_stego": {"tool": "stegseek", "install": "paru -S stegseek", "net": False, "ai": False,
                  "how": "stegseek --seed <图.jpg>   # 免字典检测；有词表则 stegseek <图.jpg> 词表"},
    "audio":     {"tool": "minimodem", "install": "pacman -S minimodem", "net": False, "ai": False,
                  "how": "minimodem -f a.wav --rx 1200 -a   # FSK/DTMF 自适应"},
    # —— 编码/密码 ——
    "basecrack": {"tool": "basecrack", "install": "pipx install basecrack", "net": False, "ai": False,
                  "how": "basecrack --magic -t '<串>'   # base 家族多层自动"},
    "hash_id":   {"tool": "nth", "install": "pipx install name-that-hash", "net": False, "ai": False,
                  "how": "nth -t '<hash>' --json"},
    "zip_known": {"tool": "bkcrack", "install": "paru -S bkcrack  # 或 cmake 构建", "net": False, "ai": False,
                  "how": "bkcrack -C enc.zip -c 条目 -P 明文.zip -p 条目   # 需 ≥12B 已知明文"},
    "ciphey":    {"tool": "ciphey", "install": "cargo install ciphey  # Rust 版", "net": False, "ai": True,
                  "how": "⚠️ 新版明文判定用 BERT（gibberish-or-not）→ 按「不带 AI」约束默认不自动跑；"
                         "要接入须把判定器换成我们自己的 oracles"},
    # —— 反编译 ——
    "java":      {"tool": "jadx", "install": "pacman -S jadx", "net": False, "ai": False,
                  "how": "jadx -d 输出目录 app.apk"},
    "dotnet":    {"tool": "ilspycmd", "install": "pacman -S ilspycmd  # 或 dotnet tool install ilspycmd",
                  "net": False, "ai": False, "how": "ilspycmd -o 输出目录 a.dll   # 混淆样本先过 de4dot"},
    "pyc":       {"tool": "pycdc", "install": "paru -S pycdc-git", "net": False, "ai": False,
                  "how": "pycdc a.pyc"},
    "pyinst":    {"tool": "pyinstxtractor", "install": "pipx install pyinstxtractor", "net": False, "ai": False,
                  "how": "python pyinstxtractor.py a.exe   # 拆出 pyc 再喂 pycdc"},
    # —— 文档 / 流量 / 取证 ——
    "pdf":       {"tool": "pdf-parser.py", "install": "git clone DidierStevensSuite（或单下 pdfid.py/pdf-parser.py）",
                  "net": False, "ai": False, "how": "python pdf-parser.py f.pdf   # 纯 stdlib"},
    "office":    {"tool": "olevba", "install": "pipx install oletools", "net": False, "ai": False,
                  "how": "olevba f.doc   # 提取 VBA 宏"},
    "pcap_cred": {"tool": "Pcredz", "install": "git clone lgandx/PCredz", "net": False, "ai": False,
                  "how": "Pcredz -f f.pcap"},
    "browser":   {"tool": "hindsight.py", "install": "pipx install pyhindsight", "net": False, "ai": False,
                  "how": "hindsight.py -i profile目录 -o out -f jsonl"},
    "mem":       {"tool": "vol", "install": "pipx install volatility3", "net": True, "ai": False,
                  "how": "vol -f dump.raw windows.info   # ⚠️ Windows 符号表默认联网，离线需预置"},
    # —— pwn / rev ——
    "onegadget": {"tool": "one_gadget", "install": "gem install one_gadget", "net": True, "ai": False,
                  "how": "one_gadget -f libc.so.6   # -f 强制本地，避免按 BuildID 联网"},
    "libc_match":{"tool": "libc-database", "install": "git clone niklasb/libc-database && ./get all",
                  "net": True, "ai": False, "how": "./find <符号> <地址>   # 建库需联网，匹配离线"},
    "rsa":       {"tool": "RsaCtfTool", "install": "pipx install RsaCtfTool", "net": True, "ai": False,
                  "how": "RsaCtfTool --publickey k.pub --private   # 在线攻击可用 --attack 指定，离线只走本地算法"},
    "angr":      {"tool": "python3", "install": "pipx install angr", "net": False, "ai": False,
                  "how": "⚠️ 无 CLI：需自写 find/avoid 模板；本机 py3.14 下 angr 装不起来（CLexer 报错）"},
    "qr":        {"tool": "zbarimg", "install": "pacman -S zbar", "net": False, "ai": False,
                  "how": "zbarimg -q --raw <图片>"},
    "steghide": {"tool": "steghide", "install": "pacman -S steghide", "net": False, "ai": False,
                  "how": "steghide extract -sf <文件>   # 无口令时回车空密码试一次"},
    "zip_crack": {"tool": "zip2john", "install": "pacman -S john", "net": False, "ai": False,
                  "how": "zip2john a.zip > h; john --wordlist=… h"},
    "zip_fast":  {"tool": "fcrackzip", "install": "pacman -S fcrackzip", "net": False, "ai": False,
                  "how": "fcrackzip -u -D -p 字典 a.zip"},
    "git":       {"tool": "git-dumper", "install": "pacman -S git-dumper", "net": True, "ai": False,
                  "how": "git-dumper <站点>/.git 目录"},
    "pcap":      {"tool": "tshark", "install": "pacman -S wireshark-cli", "net": False, "ai": False,
                  "how": "tshark -r a.pcap -Y http"},
    "sqlcipher": {"tool": "sqlcipher", "install": "pacman -S sqlcipher", "net": False, "ai": False,
                  "how": "sqlcipher db   # PRAGMA key='…'; .dump"},
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


def zsteg_png(path: str) -> list[dict]:
    """PNG/BMP 隐写：zsteg -a 一把梭（LSB/位平面/多通道全试）。"""
    if not _have("zsteg"):
        return [_missing("png_lsb")]
    rc, out = _run(["zsteg", "-a", path], timeout=180)
    v, c, reason, res = _verdict_of(out, "" if rc == 0 else f"zsteg rc={rc}")
    return [_step("oneshot-zsteg", "PNG/BMP 隐写（zsteg -a）", v, c, reason, res, [f"zsteg -a {path}"])]


def stegseek_jpg(path: str) -> list[dict]:
    """JPEG 隐写：stegseek --seed 免字典检测（有词表时再上词表）。"""
    if not _have("stegseek"):
        return [_missing("jpg_stego")]
    rc, out = _run(["stegseek", "--seed", path], timeout=240)
    v, c, reason, res = _verdict_of(out, "")
    steps = [_step("oneshot-stegseek", "JPEG 隐写（stegseek --seed）", v, c, reason, res,
                   [f"stegseek --seed {path}", f"stegseek {path} /usr/share/wordlists/rockyou.txt"])]
    if not _have("steghide") and v != "HIT":
        return steps
    if v != "HIT" and _have("steghide"):        # 空口令再试一发（很常见）
        rc2, out2 = _run(["bash", "-lc", f"printf '\\n' | steghide extract -sf {path!r} -p '' -f 2>&1 | head -20"], timeout=60)
        v2, c2, reason2, res2 = _verdict_of(out2, "空口令没解出")
        steps.append(_step("oneshot-steghide", "steghide 空口令", v2, c2, reason2, res2,
                           [f"steghide extract -sf {path} -p '' -f"]))
    return steps


def jadx_dex(path: str) -> list[dict]:
    """APK/DEX：jadx 反编译成 Java 源码（一把梭看逻辑与硬编码值）。"""
    if not _have("jadx"):
        return [_missing("java")]
    outdir = os.path.join(CACHE, "oneshot", os.path.basename(path) + ".jadx")
    os.makedirs(outdir, exist_ok=True)
    rc, out = _run(["jadx", "-d", outdir, "--quiet", path], timeout=600)
    flags, hits = [], []
    for root, _, files in os.walk(outdir):
        for f in files:
            if not f.endswith(".java"):
                continue
            try:
                txt = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            fl = O.flags_in(txt)
            if fl:
                flags += fl
            if "flag" in txt.lower() and len(hits) < 5:
                hits.append(os.path.join(root, f))
    if flags:
        return [_step("oneshot-jadx", f"APK/DEX 反编译（jadx，{len(hits)} 个相关文件）", "HIT", 3,
                      f"源码里找到 flag：{flags[0]}", "\n".join(flags[:3]), [f"jadx -d {outdir} {path}"])]
    names = ", ".join(os.path.basename(h) for h in hits[:4])
    return [_step("oneshot-jadx", f"APK/DEX 反编译（jadx）→ {outdir}", "UNKNOWN", 2,
                  f"出现 'flag' 的文件（人工看一眼）：{names or '无'}", outdir, [f"grep -rn flag {outdir}"])]


def doc_probe(path: str) -> list[dict]:
    """PDF / Office：pdfid·pdf-parser 或 olevba（在位才跑，纯本地）。"""
    head = open(path, "rb").read(8)
    ext = os.path.splitext(path)[1].lower()
    if head[:5] == b"%PDF":
        tool = _have("pdf-parser.py") or _have("pdf-parser")
        if not tool:
            return [_missing("pdf")]
        rc, out = _run(["python3", tool, path], timeout=120)
        v, c, reason, res = _verdict_of(out, "PDF 结构已列出（看 /JS /EmbeddedFile /OpenAction）")
        return [_step("oneshot-pdf", "PDF 结构（pdf-parser）", v, c, reason, res, [f"pdf-parser.py {path}"])]
    if ext in (".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"):
        tool = _have("olevba")
        if not tool:
            return [_missing("office")]
        rc, out = _run([tool, path], timeout=120)
        v, c, reason, res = _verdict_of(out, "宏源码已提取（看 AutoOpen / Shell / 编码串）")
        return [_step("oneshot-office", "Office 宏（olevba）", v, c, reason, res, [f"olevba {path}"])]
    return []


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
        steps += qr(path)                     # 二维码/条码
    if head[:8] == b"\x89PNG\r\n\x1a\n" or ext in (".bmp",):
        steps += zsteg_png(path)              # PNG/BMP 隐写
    if head[:3] == b"\xff\xd8\xff":
        steps += stegseek_jpg(path)           # JPEG 隐写（含 steghide 空口令）
    if ext in (".apk", ".dex") or head[:4] == b"dex\n":
        steps += jadx_dex(path)               # Android 反编译
    if head[:5] == b"%PDF" or ext in (".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"):
        steps += doc_probe(path)              # PDF / Office 宏
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
