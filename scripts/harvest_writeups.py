#!/usr/bin/env python3
"""harvest_writeups —— 公开 writeup 语料抓取 + 手法词频统计（纯标准库）。

它不产生「观点」，只产生**可核对的数字**：每个手法在多少个 writeup 文件里出现过、
命中示例是哪一个文件。kb.json 里每张卡的 corpus 字段就该拿这里的输出填。

    # 1) 抓一个仓库（走 codeload tarball；国内直连 raw 常被掐，tarball 反而通）
    python3 scripts/harvest_writeups.py fetch sajjadium/ctf-writeups
    # GitHub 直连不通时走加速前缀（实测 ghfast.top / ghproxy.net 可用）
    python3 scripts/harvest_writeups.py fetch owner/repo --mirror https://ghfast.top/

    # 2) 统计本地语料目录（可给多个）
    python3 scripts/harvest_writeups.py count --corpus ~/.cache/ctfctl/corpus/xxx \
        --json /tmp/kb_evidence.json --top 40

统计口径（写进报告时照抄，别含糊）：
  · 单位是**文件**不是题：一个文件里出现 5 次算 1；
  · 只扫文本类扩展名（--ext 可改）；二进制/图片跳过；
  · 关键词是**大小写不敏感的子串/正则**（见 data/techniques.json 的 aliases）；
  · 语料是「某个仓库的全部 md」，不是全站随机抽样 —— 只能说明这套语料里的分布。
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEF_TECH = os.path.join(ROOT, "ctfctl", "data", "techniques.json")
CORPUS_DIR = os.path.expanduser(os.environ.get("CTFCTL_CORPUS", "~/.cache/ctfctl/corpus"))
UA = "ctfctl-harvest/1.0 (+ctf writeup corpus stats)"
TEXT_EXT = (".md", ".markdown", ".txt", ".rst", ".html", ".htm")


# ------------------------------------------------------------------ 抓

def _download(url: str, dest: str, timeout: int = 300) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    n = 0
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            n += len(chunk)
            f.write(chunk)
    return n


def cmd_fetch(args) -> int:
    os.makedirs(CORPUS_DIR, exist_ok=True)
    rc = 0
    for spec in args.repo:
        repo = spec
        branch = None
        if "@" in spec:
            repo, branch = spec.rsplit("@", 1)
        repo = repo.rstrip("/").replace("https://github.com/", "")
        slug = repo.replace("/", "__")
        outdir = os.path.join(CORPUS_DIR, slug)
        tarpath = os.path.join(CORPUS_DIR, slug + ".tar.gz")
        base = (args.mirror or "") + "https://codeload.github.com"
        urls = ([f"{base}/{repo}/tar.gz/refs/heads/{branch}"] if branch else
                [f"{base}/{repo}/tar.gz/refs/heads/{b}" for b in ("main", "master")])
        got = False
        for u in urls:
            try:
                t0 = time.time()
                n = _download(u, tarpath, timeout=args.timeout)
                print(f"[fetch] {u} -> {n} 字节（{time.time()-t0:.1f}s）")
                got = True
                break
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                print(f"[fetch] 失败 {u}: {e}", file=sys.stderr)
        if not got:
            print(f"[!] {repo} 没下下来（试试 --mirror https://ghfast.top/）", file=sys.stderr)
            rc = 1
            continue
        if os.path.isdir(outdir):
            shutil.rmtree(outdir)
        os.makedirs(outdir)
        with tarfile.open(tarpath, "r:gz") as tf:
            members = tf.getmembers()
            total = sum(m.size for m in members if m.isfile())
            print(f"[unpack] {len(members)} 个成员 / {total/1e6:.1f} MB 解压中…")
            for m in members:
                if m.issym() or m.islnk():
                    continue
                try:
                    tf.extract(m, outdir, filter="data")
                except TypeError:                      # py<3.12 没有 filter 参数
                    tf.extract(m, outdir)
        os.remove(tarpath)
        print(f"[ok] {repo} -> {outdir}")
    return rc


# ------------------------------------------------------------------ 统计

def _load_techniques(path: str) -> dict:
    d = json.load(open(path, encoding="utf-8"))
    return d.get("techniques", d)


#: 索引/说明类文件不计入（它们的主题词频会把统计带偏：README 什么都提一句）
SKIP_BASENAMES = {"readme.md", "index.md", "summary.md", "discussion.md", "resources.md",
                  "contributing.md", "changelog.md", "license", "license.md", "toc.md"}


def _iter_files(dirs: list[str], exts: tuple[str, ...], max_files: int):
    seen_hashes: set[str] = set()
    n = 0
    for d in dirs:
        for dp, dn, fn in os.walk(os.path.expanduser(d)):
            dn[:] = [x for x in dn if x not in (".git", "node_modules", ".github", "assets", "images")]
            for f in sorted(fn):
                if not f.lower().endswith(exts):
                    continue
                p = os.path.join(dp, f)
                # 只跳过「语料根目录/一层」的索引文件：仓库把每道题的 writeup 也叫 README.md
                if f.lower() in SKIP_BASENAMES and os.path.relpath(p, d).count(os.sep) <= 1:
                    continue
                try:
                    if os.path.getsize(p) > 4_000_000:
                        continue
                    data = open(p, "rb").read()
                except OSError:
                    continue
                h = hashlib.sha1(data).hexdigest()
                if h in seen_hashes:                   # 同一份 writeup 在多个仓库里重复
                    continue
                seen_hashes.add(h)
                yield p, data.decode("utf-8", "replace")
                n += 1
                if max_files and n >= max_files:
                    return


def cmd_count(args) -> int:
    techs = _load_techniques(args.techniques)
    pats = {k: re.compile(v.get("re", ""), re.I) if v.get("re") else
            re.compile("|".join(re.escape(a) for a in v.get("aliases", [])), re.I)
            for k, v in techs.items()}
    per: dict[str, dict] = {}          # 来源 → {files, bytes, counts{tech:{files,examples}}}
    for d in args.corpus:
        d = os.path.expanduser(d)
        key = os.path.basename(d.rstrip("/"))
        agg = {"dir": d, "files": 0, "bytes": 0,
               "counts": {k: {"files": 0, "examples": []} for k in techs}}
        for p_, text in _iter_files([d], tuple(args.ext), args.max_files):
            agg["files"] += 1
            agg["bytes"] += len(text.encode("utf-8", "replace"))
            for k, rx in pats.items():
                if rx.search(text):
                    c = agg["counts"][k]
                    c["files"] += 1
                    if len(c["examples"]) < 3:
                        c["examples"].append(os.path.relpath(p_, d))
        per[key] = agg

    nfiles = sum(a["files"] for a in per.values())
    nbytes = sum(a["bytes"] for a in per.values())
    print(f"语料：{nfiles} 个文本文件 / {nbytes} 字节（每个来源内部去重；口径见脚本 docstring）")
    print("来源：")
    for k, a in per.items():
        print(f"  {k:<34} {a['files']:>5} 文件 / {a['bytes']/1e6:>7.1f} MB")
    keys = list(per)
    hdr = f"{'手法':<26}" + "".join(f"{k[:18]:>20}" for k in keys) + f"{'合计命中':>10}"
    print("\n" + hdr)
    rows = sorted(techs, key=lambda k: -sum(a["counts"][k]["files"] for a in per.values()))
    shown = 0
    for k in rows:
        tot = sum(a["counts"][k]["files"] for a in per.values())
        if tot == 0 and args.top:
            continue
        if args.top and shown >= args.top:
            break
        line = f"{techs[k].get('name', k):<26}"
        for kk in keys:
            a = per[kk]
            c = a["counts"][k]["files"]
            pct = (c / a["files"] * 100) if a["files"] else 0
            line += f"{f'{c} ({pct:.0f}%)':>20}"
        print(line + f"{tot:>10}")
        shown += 1
    if args.json:
        out = {"corpus": per, "files": nfiles, "bytes": nbytes,
               "fetched": time.strftime("%Y-%m-%d"), "ext": list(args.ext),
               "counts": {k: {"files": sum(a["counts"][k]["files"] for a in per.values()),
                              "per_source": {kk: per[kk]["counts"][k]["files"] for kk in keys},
                              "examples": next((a["counts"][k]["examples"] for a in per.values()
                                                if a["counts"][k]["examples"]), [])}
                          for k in techs}}
        json.dump(out, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"[json] {args.json}")
    return 0


def cmd_sources(args) -> int:
    if not os.path.isdir(CORPUS_DIR):
        print("（还没抓过东西）")
        return 0
    for d in sorted(os.listdir(CORPUS_DIR)):
        p = os.path.join(CORPUS_DIR, d)
        if not os.path.isdir(p):
            continue
        n, sz = 0, 0
        for dp, dn, fn in os.walk(p):
            for f in fn:
                n += 1
                try:
                    sz += os.path.getsize(os.path.join(dp, f))
                except OSError:
                    pass
        print(f"  {d:<40} {n:>6} 文件 / {sz/1e6:.1f} MB   {p}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="公开 writeup 语料抓取 + 手法词频统计")
    sp = ap.add_subparsers(dest="cmd", required=True)

    f = sp.add_parser("fetch", help="下载并解压 GitHub 仓库（codeload tarball，可加加速前缀）")
    f.add_argument("repo", nargs="+", help="owner/repo 或 owner/repo@branch")
    f.add_argument("--mirror", help="加速前缀，如 https://ghfast.top/")
    f.add_argument("--timeout", type=int, default=300)
    f.set_defaults(func=cmd_fetch)

    c = sp.add_parser("count", help="统计本地语料里的手法分布")
    c.add_argument("--corpus", action="append", required=True, help="语料目录（可多次）")
    c.add_argument("--techniques", default=DEF_TECH, help="手法关键词表（默认 ctfctl/data/techniques.json）")
    c.add_argument("--ext", action="append", default=[], help="只扫这些扩展名（默认 md/txt/rst/html）")
    c.add_argument("--max-files", type=int, default=0, help="抽样上限（0=不限）")
    c.add_argument("--top", type=int, default=0, help="0=全部命中都打印")
    c.add_argument("--json", help="把结果写成 JSON（填进 kb.json 的 corpus 字段）")
    c.set_defaults(func=cmd_count)

    s = sp.add_parser("sources", help="看看本地抓了哪些语料")
    s.set_defaults(func=cmd_sources)

    args = ap.parse_args()
    if getattr(args, "func", None) is cmd_count and not args.ext:
        args.ext = list(TEXT_EXT)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
