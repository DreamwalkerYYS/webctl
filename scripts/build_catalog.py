#!/usr/bin/env python3
"""build_catalog —— 把 Kali / BlackArch 的官方工具目录变成 ctfctl 的 data/tools.json。

数据来源（都可以重新抓）：
  · BlackArch: https://blackarch.org/tools.html  —— 一张大表：名称/版本/说明/分类/主页（48 类）
  · Kali:      https://www.kali.org/tools/all-tools/ —— 工具全表 + kali-meta 的官方分类元包

做法：
  ① 解析两份快照 → 每个工具 {name, desc, cats(映射到 CTF 方向), url, 包名, 来源}
  ② 叠加人工维护的 data/ctf-tools.json（中文说明 / 安装方式 / 用法 / 踩坑），人工字段优先
  ③ 写出 data/tools.json（分类表 + 工具表），并把统计打出来（数字要能复核）

    python3 scripts/build_catalog.py                       # 用 research/ 下的快照
    python3 scripts/build_catalog.py --fetch               # 现场重抓（Kali 直连；BlackArch 被墙就用 --mirror）
    python3 scripts/build_catalog.py --research DIR --out ctfctl/data/tools.json
"""
from __future__ import annotations

import argparse
import collections
import html
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UA = "ctfctl-build/1.0 (+catalog)"
BLACKARCH_URL = "https://blackarch.org/tools.html"
KALI_URL = "https://www.kali.org/tools/all-tools/"
#: 权威来源（比抓 HTML 靠谱）：Kali 的分类元包定义 + BlackArch 的 pacman 库
KALI_META_URL = "https://gitlab.com/kalilinux/packages/kali-meta/-/raw/kali/master/debian/control"
KALI_PAGES_URL = "https://www.kali.org/tools/pages.json"
BLACKARCH_DB_URL = "https://blackarch.org/blackarch/blackarch/os/x86_64/blackarch.db"

# ---------------------------------------------------------------- CTF 方向（本工具的顶层分类）

CATEGORIES = [
    ("web", "Web 应用"),
    ("recon", "信息收集/侦察"),
    ("osint", "OSINT/情报"),
    ("pwn", "二进制利用 (pwn)"),
    ("rev", "逆向工程"),
    ("crypto", "密码学"),
    ("misc", "杂项/隐写/编码"),
    ("forensics", "取证（磁盘·内存·流量）"),
    ("hash", "口令与哈希"),
    ("net", "网络/嗅探/代理/隧道"),
    ("wireless", "无线/射频/SDR"),
    ("mobile", "移动端（Android/iOS）"),
    ("hardware", "硬件/IoT/固件"),
    ("post", "后渗透/权限维持"),
    ("data", "数据处理与编解码"),
    ("online", "在线工具（不在本机跑）"),
]

#: BlackArch 的分类 → 本工具的 CTF 方向
BA_MAP = {
    "webapp": ["web"], "scanner": ["recon", "web"], "recon": ["recon", "osint"],
    "exploitation": ["pwn"], "cracker": ["hash"], "windows": ["rev", "pwn"],
    "networking": ["net"], "misc": ["misc"], "forensic": ["forensics"], "automation": ["data"],
    "fuzzer": ["web", "recon"], "crypto": ["crypto"], "wireless": ["wireless"],
    "binary": ["rev", "pwn"], "social": ["osint"], "backdoor": ["post"], "mobile": ["mobile"],
    "defensive": ["forensics"], "sniffer": ["net"], "proxy": ["net"], "radio": ["wireless"],
    "reversing": ["rev"], "malware": ["rev"], "fingerprint": ["recon"], "code-audit": ["web", "rev"],
    "dos": ["net"], "bluetooth": ["wireless"], "voip": ["net"], "decompiler": ["rev"],
    "spoof": ["net"], "tunnel": ["net"], "disassembler": ["rev"], "honeypot": ["net"],
    "stego": ["misc"], "debugger": ["rev", "pwn"], "ai": ["misc"], "wordlist": ["hash"],
    "database": ["web"], "hardware": ["hardware"], "automobile": ["hardware"], "drone": ["hardware"],
    "firmware": ["hardware"], "keylogger": ["post"], "anti-forensic": ["forensics"],
    "packer": ["rev"], "nfc": ["hardware"], "ids": ["forensics"], "threat-model": ["forensics"],
}

#: Kali 官方分类元包（kali-tools-*）→ 本工具的 CTF 方向
KALI_MAP = {
    "information-gathering": ["recon", "osint"], "vulnerability-analysis": ["recon", "web"],
    "web-applications": ["web"], "password-attacks": ["hash"], "passwords": ["hash"],
    "wireless-attacks": ["wireless"], "bluetooth-tools": ["wireless"], "rfid": ["hardware"],
    "sdr": ["wireless"], "exploitation-tools": ["pwn"], "sniffing-spoofing": ["net"],
    "post-exploitation": ["post"], "forensics": ["forensics"], "reporting-tools": ["misc"],
    "reverse-engineering": ["rev"], "hardware-hacking": ["hardware"], "database-assessment": ["web"],
    "windows-resources": ["rev", "pwn"], "identify": ["forensics", "misc"], "respond": ["forensics"],
    "crypto-stego": ["crypto", "misc"], "mobile": ["mobile"], "cloud": ["web"],
    # 伞形元包（装了等于装一堆）不参与 CTF 分类映射，否则 wireshark 会被塞进十几个类
    "top10": [], "default": [], "everything": [], "large": [], "headless": [],
    "identify": ["forensics", "misc"],
}

#: Kali 页面里是「元包」不是工具，别当工具收进来
NOT_A_TOOL = re.compile(r"^(kali-|meta|linux-|python3?$|ruby$|perl$|gcc|make$|git$)")


# ---------------------------------------------------------------- 解析

def _get(url: str, path: str) -> str:
    if os.path.exists(path):
        return open(path, encoding="utf-8", errors="replace").read()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read().decode("utf-8", "replace")
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return data


def parse_blackarch(h: str) -> list[dict]:
    out = []
    for row in re.split(r"<tr>", h):
        m = re.search(r'class=tbl-name itemprop="name">([^<]+)</td>', row)
        if not m:
            continue
        name = html.unescape(m.group(1)).strip()
        d = re.search(r'class="tbl-description dcat" itemprop="description">(.*?)</td>', row, re.S)
        c = re.search(r'title="\s*blackarch-([a-z0-9\-]+)\s*"', row)
        u = re.search(r'class=tbl-homepage itemprop="mainEntityOfPage"><a href="([^"]+)"', row)
        cats = BA_MAP.get(c.group(1), []) if c else []
        out.append({"name": name,
                    "desc_en": html.unescape(re.sub(r"\s+", " ", d.group(1)).strip()) if d else "",
                    "cats": cats,
                    "url": u.group(1) if u else "",
                    "blackarch": name,
                    "src": ["blackarch"]})
    return out


def parse_kali_meta(control: str) -> tuple[dict[str, list[str]], list[str]]:
    """解析 kali-meta 的 debian/control：kali-tools-<类> 的 Depends 就是该类工具全集。

    返回 ({分类名: [包名…]}, [分类名…])。分类名 = 元包名去掉 kali-tools- 前缀。
    """
    cats: dict[str, list[str]] = {}
    for stanza in control.split("\n\n"):
        m = re.search(r"^Package:\s*(kali-tools-([a-z0-9\-]+))\s*$", stanza, re.M)
        if not m:
            continue
        d = re.search(r"^Depends:\s*(.+?)(?=\n[A-Z][A-Za-z\-]*:|\Z)", stanza, re.M | re.S)
        pkgs = []
        if d:
            for item in d.group(1).replace("\n", " ").split(","):
                name = re.sub(r"\(.*?\)", "", item).strip().split(" ")[0].strip()
                if name and name != "kali-tools-" + m.group(2):
                    pkgs.append(name)
        cats[m.group(2)] = pkgs
    return cats, sorted(cats)


def parse_blackarch_db(path: str) -> dict[str, dict]:
    """读 blackarch.db（gzip tar）：每包的 desc 里有 %GROUPS%（blackarch-* 即分类，权威）。"""
    out: dict[str, dict] = {}
    if not os.path.exists(path):
        return out
    import tarfile
    try:
        with tarfile.open(path, "r:gz") as t:
            for m in t:
                if not m.name.endswith("/desc"):
                    continue
                txt = t.extractfile(m).read().decode("utf-8", "replace")
                def field(tag):
                    mm = re.search(rf"%{tag}%\n(.*?)(?=\n%|\Z)", txt, re.S)
                    return mm.group(1).strip() if mm else ""
                name = field("NAME")
                if not name:
                    continue
                groups = [g.strip() for g in field("GROUPS").splitlines() if g.strip()]
                out[name.lower()] = {"desc": field("DESC"), "url": field("URL"),
                                     "groups": groups, "version": field("VERSION")}
    except (OSError, tarfile.TarError):
        return out
    return out


def parse_kali(h: str) -> tuple[list[str], set[str]]:
    """返回（官方分类元包名, 页面上出现的工具名集合）。"""
    metas = sorted(set(re.findall(r"#(kali-tools-[a-z0-9\-]+)", h)))
    names = set()
    for m in re.finditer(r'href=https://www\.kali\.org/tools/([a-zA-Z0-9\.\-\+_]+)/', h):
        n = m.group(1)
        if not NOT_A_TOOL.match(n):
            names.add(n)
    for m in re.finditer(r'title="([^"]+) command"', h):        # 子命令名也算
        names.add(html.unescape(m.group(1)))
    return metas, names


# ---------------------------------------------------------------- 组装

def build(research: str, out_path: str) -> int:
    ba = _get(BLACKARCH_URL, os.path.join(research, "blackarch-tools.html"))
    ka = _get(KALI_URL, os.path.join(research, "kali-all-tools.html"))
    ba_tools = parse_blackarch(ba)
    kali_metas, kali_names = parse_kali(ka)
    # 权威来源：Kali 分类元包（分类→工具全集）+ BlackArch pacman 库（每包的 groups）
    meta_cats = {}
    try:
        meta_cats, _ = parse_kali_meta(_get(KALI_META_URL, os.path.join(research, "control")))
    except Exception as e:
        print(f"[!] kali-meta 读不了：{e}", file=sys.stderr)
    ba_db = parse_blackarch_db(os.path.join(research, "blackarch.db"))
    # 反查：工具 → 它属于哪些 kali 分类 / blackarch 组
    tool_kali_cats: dict[str, list[str]] = {}
    for cat, pkgs in meta_cats.items():
        for pkg in pkgs:
            tool_kali_cats.setdefault(pkg.lower(), []).append(cat)

    overlay_path = os.path.join(ROOT, "ctfctl", "data", "ctf-tools.json")
    overlay = {}
    if os.path.exists(overlay_path):
        overlay = {t["name"]: t for t in json.load(open(overlay_path, encoding="utf-8")).get("tools", [])}

    by_name: dict[str, dict] = {}
    for t in ba_tools:
        by_name.setdefault(t["name"].lower(), t)
        if t["name"].lower() in {k.lower() for k in kali_names}:
            t["src"].append("kali")

    # 用 kali-meta 的分类把工具补进来（Depends 里的包名就是权威分类）
    for cat, pkgs in meta_cats.items():
        for pkg in pkgs:
            key = pkg.lower()
            t = by_name.get(key)
            if t:
                continue
            if not overlay.get(pkg):
                continue                          # 同上：只有人工点过名的才收，避免噪音
            db = ba_db.get(key, {})
            by_name[key] = {"name": pkg, "desc_en": db.get("desc", ""),
                            "cats": KALI_MAP.get(cat, []), "url": db.get("url", ""), "src": ["kali-meta"]}

    # 只出现在 Kali 表里、BlackArch 没有的工具（挑有名气的一批，避免把 Kali 元包/杂包全收）
    for n in sorted(kali_names):
        if n.lower() in by_name:
            continue
        if not overlay.get(n):
            continue                                     # 只有人工点过名的才收，否则库会变成噪音
        by_name[n.lower()] = {"name": n, "desc_en": "", "cats": [], "url": "", "src": ["kali"]}

    # 叠加人工字段（覆盖 desc/cats/安装方式/用法…）
    added_curated = 0
    for name, ov in overlay.items():
        key = name.lower()
        t = by_name.get(key)
        if not t:
            t = {"name": name, "src": ["curated"]}
            by_name[key] = t
            added_curated += 1
        for k, v in ov.items():
            t[k] = v
        t["curated"] = True
        if "cats" not in t or not t["cats"]:
            t["cats"] = ov.get("cats", [])

    tools = []
    for t in by_name.values():
        # 权威分类挂上去：blackarch_groups（来自 .db）+ kali_cats（来自 kali-meta）
        db = ba_db.get(t["name"].lower())
        if db:
            t["blackarch_groups"] = db["groups"]
            if not t.get("desc_en"):
                t["desc_en"] = db.get("desc", "")
            if not t.get("url"):
                t["url"] = db.get("url", "")
            mapped = [c for g in db["groups"] for c in BA_MAP.get(g.replace("blackarch-", ""), [])]
            if mapped:
                t["cats"] = list(dict.fromkeys((t.get("cats") or []) + mapped))
        kc = tool_kali_cats.get(t["name"].lower())
        if kc:
            t["kali_cats"] = kc
            mapped = [c for x in kc for c in KALI_MAP.get(x, [])]
            if mapped:
                t["cats"] = list(dict.fromkeys((t.get("cats") or []) + mapped))
        t.setdefault("cats", [])
        if not t["cats"]:
            t["cats"] = ["misc"]
        t["cats"] = [c for c in t["cats"] if any(c == cid for cid, _ in CATEGORIES)] or ["misc"]
        t.setdefault("desc", t.get("desc_en", ""))
        t["desc"] = (t["desc"] or "")[:200]
        t["desc_en"] = (t.get("desc_en") or "")[:200]
        tools.append(t)
    tools.sort(key=lambda t: (not t.get("curated"), t["cats"][0], t["name"].lower()))

    cat_counts = collections.Counter(c for t in tools for c in t["cats"])
    doc = {
        "_comment": "工具目录：BlackArch 官方表 + Kali 官方工具表（分类元包 kali-tools-*）机器生成，人工字段（desc/install/usage/ctf_use）来自 ctf-tools.json 覆盖。重新生成：python3 scripts/build_catalog.py",
        "sources": [
            {"id": "blackarch", "name": "BlackArch 工具表 + pacman 库 blackarch.db", "url": BLACKARCH_URL,
             "snapshot": "research/blackarch-tools.html + research/blackarch.db",
             "tools": len(ba_tools), "cats": 48, "db_pkgs": len(ba_db)},
            {"id": "kali", "name": "Kali 官方工具表 + kali-meta 分类元包（Depends 即分类全集）", "url": KALI_META_URL,
             "snapshot": "research/kali-all-tools.html + research/control", "tools": len(kali_names),
             "cats": len(kali_metas), "metas": kali_metas, "meta_cats": len(meta_cats)},
            {"id": "curated", "name": "人工维护的 CTF 常用工具（中文说明/安装/用法）",
             "file": "ctfctl/data/ctf-tools.json", "tools": len(overlay)},
        ],
        "categories": [{"id": cid, "name": name, "count": cat_counts.get(cid, 0)} for cid, name in CATEGORIES],
        "kali_metas": kali_metas,
        "tools": tools,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    size = os.path.getsize(out_path)
    print(f"工具 {len(tools)} 个（人工 {len(overlay)}，其中新增 {added_curated}）"
          f" · BlackArch 行 {len(ba_tools)} · Kali 名字 {len(kali_names)} · Kali 分类元包 {len(kali_metas)}")
    print(f"分类构成：" + "  ".join(f"{cid}={cat_counts.get(cid,0)}" for cid, _ in CATEGORIES))
    print(f"写出 {out_path}（{size/1024:.0f} KB）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 ctfctl 的工具目录（Kali/BlackArch 官方表 → data/tools.json）")
    ap.add_argument("--research", default=os.path.join(ROOT, "research"), help="快照目录（没有就现抓）")
    ap.add_argument("--out", default=os.path.join(ROOT, "ctfctl", "data", "tools.json"))
    ap.add_argument("--fetch", action="store_true", help="强制重抓（默认有快照就用快照）")
    args = ap.parse_args()
    if args.fetch:
        for p in ("blackarch-tools.html", "kali-all-tools.html"):
            fp = os.path.join(args.research, p)
            if os.path.exists(fp):
                os.remove(fp)
    os.makedirs(args.research, exist_ok=True)
    return build(args.research, args.out)


if __name__ == "__main__":
    sys.exit(main())
