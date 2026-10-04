"""fuzz —— 目录/参数爆破，两条引擎，规矩一样：**自动过滤假 200**。

    --engine auto    有 ffuf 就调 ffuf（并把命令原文打出来，方便你学它的 flag），没有就用内置引擎
    --engine builtin 内置引擎（纯标准库，容器里也能跑；默认只放 4 并发，别把靶机打挂）
    --engine ffuf    强制 ffuf（没装就报错并给安装提示）

过滤假 200 的原理（你自己踩过的坑）：
    nginx `try_files` 会把不存在的路径回退成 **200 + 首页**。
    所以判据是「字节数 == 首页字节数 且 Content-Type == 首页」→ 丢掉，不看状态码。
    ffuf 对应的开关是 `-fs <首页字节数>`；本工具默认自动探测首页字节数并注入。

例子
    webctl fuzz "http://靶机/FUZZ"
    webctl fuzz "http://靶机/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,html,bak
    webctl fuzz "http://靶机/api/FUZZ" -mc 200,301,302,403 -t 30 --save /tmp/hit
    webctl fuzz "http://靶机/" -X POST -d "user=FUZZ" -H "Content-Type: application/x-www-form-urlencoded"
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..core.config import CACHE
from ..core.detect import classify
from ..core.session import Session

DEFAULT_WL = ["/usr/share/seclists/Discovery/Web-Content/common.txt",
              "/usr/share/wordlists/dirb/common.txt",
              "/usr/share/dirb/wordlists/common.txt",
              "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"]
BUILTIN_FALLBACK = ["admin", "login", "api", "api/v1", "backup", "src", "source", "test", "debug",
                    "flag", "flag.php", "config.php", "robots.txt", ".git/HEAD", "www.zip", "index.php.bak"]


def _pick_wordlist(arg: str | None) -> str | None:
    if arg:
        return arg
    for p in DEFAULT_WL:
        if os.path.exists(p):
            return p
    return None


def _expand(wordlist: str, exts: str) -> list[str]:
    words = []
    ext_list = [e.strip().lstrip(".") for e in (exts or "").split(",") if e.strip()]
    with open(wordlist, encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            words.append(w)
            for e in ext_list:
                words.append(f"{w}.{e}")
    return words


def _baseline(sess: Session, url: str) -> tuple[int, str]:
    """探测首页字节数/Content-Type：这是过滤假 200 的依据。

    首页都连不上时（status 0）不做假 200 过滤 —— 否则会把 64 字节的连接错误当成"首页大小"，
    把所有真实命中全过滤掉。
    """
    probe = url.split("FUZZ")[0] or "/"
    r = sess.request("GET", probe)
    if r.status == 0:
        print(f"[!] 首页探测失败（{r.text[:80]}）：本次不做假 200 过滤，先查靶机/出口", file=sys.stderr)
        return -1, ""
    return r.size, r.ctype


# ------------------------------------------------------------------ ffuf 通道
def run_ffuf(args, wordlist: str, base_size: int) -> int:
    exe = shutil.which("ffuf")
    if not exe:
        print("[!] 没装 ffuf。装法：pacman -S ffuf（或 go install github.com/ffuf/ffuf/v2@latest）"
              "；也可以 --engine builtin 直接用内置引擎", file=sys.stderr)
        return 2
    out_json = os.path.join(CACHE, "ffuf-out.json")
    os.makedirs(CACHE, exist_ok=True)
    cmd = [exe, "-u", args.url, "-w", wordlist, "-mc", args.mc, "-t", str(args.threads),
           "-o", out_json, "-of", "json", "-s"]
    if args.fs is not None:
        cmd += ["-fs", str(args.fs)]
    elif base_size >= 0 and not args.show_fake:
        cmd += ["-fs", str(base_size)]
    if args.method and args.method.upper() != "GET":
        cmd += ["-X", args.method.upper()]
    if args.data:
        cmd += ["-d", args.data]
    for h in args.header or []:
        cmd += ["-H", h]
    if args.ext:
        cmd += ["-e", ",".join(e.strip().lstrip(".") for e in args.ext.split(","))]
    if args.delay:
        cmd += ["-p", str(args.delay)]
    print(f"[引擎] ffuf：{' '.join(cmd)}", file=sys.stderr if args.json else sys.stdout)
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode not in (0, 1):        # ffuf 无命中返回 1
        print(p.stdout[-2000:] + p.stderr[-2000:], file=sys.stderr)
    rows = []
    if os.path.exists(out_json):
        try:
            data = json.load(open(out_json, encoding="utf-8"))
            for r in data.get("results", []):
                rows.append({"input": "/" + str(r.get("input", {}).get("FUZZ", "")),
                             "status": r.get("status"), "size": r.get("length"),
                             "ctype": r.get("content-type", ""), "url": r.get("url", "")})
        except (OSError, json.JSONDecodeError):
            pass
    _report(rows, args, time.time() - t0, engine="ffuf")
    return 0


# ------------------------------------------------------------------ 内置通道
def run_builtin(args, words: list[str], base_size: int, base_ctype: str) -> int:
    sess = Session(base=args.url.split("FUZZ")[0], jar_name=args.jar, proxy=args.proxy,
                   timeout=args.timeout, ua=args.ua)
    sess.tag = "fuzz"
    codes = {int(c) for c in args.mc.split(",") if c.strip().isdigit()}
    print(f"[引擎] 内置（{len(words)} 个词，{args.threads} 并发）"
          f"{'  [自动过滤假 200：字节数==' + str(base_size) + ']' if base_size >= 0 and not args.show_fake else ''}")
    t0 = time.time()
    locked = __import__("threading").Lock()

    def one(w: str):
        url = args.url.replace("FUZZ", urllib.parse.quote(w, safe="/?=&%"))
        if args.delay:
            time.sleep(args.delay)
        headers = {}
        for h in args.header or []:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip().replace("FUZZ", w)
        data = args.data.replace("FUZZ", w) if args.data else None
        r = sess.request(args.method.upper(), url, data=data, headers=headers)
        cls = classify(r, base_size, base_ctype)
        keep = r.status in codes and (cls != "FAKE" or args.show_fake)
        if keep:
            with locked:
                print(f"   {r.status} {r.size:>8}B {r.ctype or '?':26s} /{w}" + ("   [FAKE]" if cls == "FAKE" else ""))
            if args.save:
                os.makedirs(args.save, exist_ok=True)
                fn = re.sub(r"[^A-Za-z0-9._-]+", "_", w) or "root"
                r.save(os.path.join(args.save, fn))
        return {"input": "/" + w, "status": r.status, "size": r.size, "ctype": r.ctype,
                "cls": cls, "kept": keep}

    with ThreadPoolExecutor(max(1, args.threads)) as ex:
        rows = list(ex.map(one, words))
    _report([r for r in rows if r["kept"]], args, time.time() - t0, engine="builtin", all_rows=rows)
    return 0


def _report(rows: list[dict], args, secs: float, engine: str, all_rows: list[dict] | None = None) -> None:
    print(f"\n[结果] {len(rows)} 条命中，用时 {secs:.1f}s（引擎 {engine}）")
    for r in sorted(rows, key=lambda x: (x.get("status") or 0, -(x.get("size") or 0))):
        print(f"   {r.get('status')} {r.get('size'):>8}B {r.get('ctype') or '?':26s} {r.get('input')}")
    if not rows:
        print("   （空 —— 要么真没有，要么被假 200 过滤吃掉了；加 --show-fake 看看被丢的那些）")
    if all_rows and not args.show_fake:
        fake = sum(1 for r in all_rows if r.get("cls") == "FAKE")
        if fake:
            print(f"   [注] 另有 {fake} 条是假 200，已按「字节数==首页」过滤（--show-fake 可显示）")
    if args.json:
        out = os.path.join(CACHE, "fuzz-result.json")
        json.dump({"engine": engine, "url": args.url, "hits": rows}, open(out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print(f"[json] {out}")


def run(args) -> int:
    if "FUZZ" not in args.url and not (args.data and "FUZZ" in args.data):
        print("[!] 得有个 FUZZ 占位符，告诉工具往哪儿塞词：webctl fuzz \"http://host/FUZZ\"", file=sys.stderr)
        return 2
    wordlist = _pick_wordlist(args.wordlist)
    if not wordlist and args.engine != "builtin":
        print("[!] 没找到字典（给 -w，或 --engine builtin 用内置小清单）", file=sys.stderr)
        return 2
    base_size, base_ctype = -1, ""
    if not args.show_fake:
        sess = Session(base=args.url.split("FUZZ")[0], jar_name=args.jar, proxy=args.proxy,
                       timeout=args.timeout, ua=args.ua)
        base_size, base_ctype = _baseline(sess, args.url)
        print(f"[基线] 首页 {base_size}B {base_ctype}  ← 假 200 过滤依据（可用 --fs 覆盖）", file=sys.stderr)

    engine = args.engine
    if engine == "auto":
        engine = "ffuf" if shutil.which("ffuf") else "builtin"
    if engine == "ffuf":
        if not wordlist:
            print("[!] ffuf 需要字典：-w path", file=sys.stderr)
            return 2
        return run_ffuf(args, wordlist, args.fs if args.fs is not None else base_size)
    words = _expand(wordlist, args.ext) if wordlist else BUILTIN_FALLBACK
    return run_builtin(args, words, args.fs if args.fs is not None else base_size, base_ctype)


def register(sub) -> None:
    p = sub.add_parser("fuzz", help="目录/参数爆破（ffuf 或内置引擎，自动过滤假 200）")
    p.add_argument("url", help="带 FUZZ 的地址，如 http://host/FUZZ")
    p.add_argument("-w", "--wordlist", help="字典（不给就找常用路径）")
    p.add_argument("-e", "--ext", help="额外后缀，如 php,html,bak")
    p.add_argument("-X", "--method", default="GET")
    p.add_argument("-d", "--data", help="请求体模板（含 FUZZ），配 -X POST 用")
    p.add_argument("-H", "--header", action="append", help="额外请求头（值里可含 FUZZ）")
    p.add_argument("-mc", "--mc", default="200,301,302,401,403", help="要保留的状态码（默认 200,301,302,401,403）")
    p.add_argument("--fs", type=int, help="手动指定要过滤的响应字节数（默认自动探测首页）")
    p.add_argument("--show-fake", action="store_true", help="连假 200 一起显示（排查用）")
    p.add_argument("--engine", choices=["auto", "ffuf", "builtin"], default="auto")
    p.add_argument("-t", "--threads", type=int, default=20, help="并发（默认 20；共享靶机别拉满）")
    p.add_argument("--delay", type=float, default=0, help="每个请求间隔（秒）")
    p.add_argument("--save", help="把命中的响应体存到这个目录")
    p.add_argument("--json", action="store_true", help="结果另存 JSON")
    p.add_argument("--jar", help="用哪份 cookie jar")
    p.add_argument("--proxy", help="走代理（Burp 等）")
    p.add_argument("--ua", help="User-Agent")
    p.add_argument("--timeout", type=float, default=10)
    p.set_defaults(func=run)
