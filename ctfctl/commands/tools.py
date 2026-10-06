"""tools —— CTF 工具目录。

分类体系取 Kali / BlackArch 的官方分类（快照落 data/tools.json，来源与抓取
日期写在 sources 里），每条工具带：类别、一句话说明、安装方式、装没装、几条用法。

    ctfctl tools                        # 分类概览（每类几个、本机装了几个）
    ctfctl tools list --cat web         # 列某类
    ctfctl tools list --installed       # 只列本机装了的
    ctfctl tools search jwt             # 名称/别名/说明/标签全字段检索
    ctfctl tools show ffuf              # 详情 + 安装命令 + 用法
    ctfctl tools check [--missing]      # 扫本机：pacman -Qq + PATH
    ctfctl tools install <name>         # 只打印安装命令；--run 才真跑

设计：这里只做「索引 + 打印命令」，不代跑利用、不下载工具（`install --run` 是显式
选择）。判断权留给人。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

from ..core.config import CONFIG, DATA

USER_TOOLS = os.path.join(CONFIG, "tools.json")      # 个人补充（同 schema，追加）


# ------------------------------------------------------------------ 数据

def load_catalog() -> dict:
    cat = {"sources": [], "categories": [], "tools": []}
    for path in (os.path.join(DATA, "tools.json"), USER_TOOLS):
        if not os.path.exists(path):
            continue
        try:
            d = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] 工具目录读不了 {path}: {e}", file=sys.stderr)
            continue
        cat["sources"].extend(d.get("sources", []))
        cat["categories"].extend(d.get("categories", []))
        cat["tools"].extend(d.get("tools", []))
    return cat


def _all_tools(cat: dict) -> list[dict]:
    return cat.get("tools", [])


def by_name(cat: dict, name: str) -> dict | None:
    n = name.strip().lower()
    for t in _all_tools(cat):
        if t.get("name", "").lower() == n or n in [a.lower() for a in t.get("aliases", [])]:
            return t
    return None


def cat_name(cat: dict, cid: str) -> str:
    for c in cat.get("categories", []):
        if c.get("id") == cid:
            return c.get("name", cid)
    return cid


def cat_ids(cat: dict) -> list[str]:
    ids = [c["id"] for c in cat.get("categories", [])]
    for t in _all_tools(cat):
        for c in t.get("cats", []):
            if c not in ids:
                ids.append(c)
    return ids


# ------------------------------------------------------------------ 本机装了没

def _pacman_installed() -> set[str]:
    if not shutil.which("pacman"):
        return set()
    try:
        r = subprocess.run(["pacman", "-Qq"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return set()
    return {l.strip() for l in r.stdout.decode("utf-8", "replace").splitlines() if l.strip()}


def installed_state(tool: dict, pacman_pkgs: set[str] | None = None) -> str:
    """返回 'path'（PATH 里有可执行）/ 'pkg'（包管理器装了）/ 'pip'（python 模块在）/ 'no'。"""
    exe = tool.get("check") or tool.get("name")
    if exe and shutil.which(exe):
        return "path"
    inst = tool.get("install", {}) or {}
    if pacman_pkgs:
        for key in ("pacman", "blackarch"):
            pkg = inst.get(key)
            if pkg and pkg in pacman_pkgs:
                return "pkg"
    mod = tool.get("check_module")
    if mod:
        try:
            __import__(mod)
            return "pip"
        except ImportError:
            pass
    return "no"


def _pkgs(tool: dict) -> list[tuple[str, str]]:
    """(管理器, 包名) 列表，用于打印安装命令。"""
    inst = tool.get("install", {}) or {}
    out = []
    for key, mgr in (("pacman", "pacman"), ("blackarch", "paru"), ("pip", "pip"),
                     ("pipx", "pipx"), ("go", "go"), ("git", "git"), ("cargo", "cargo"),
                     ("gem", "gem"), ("npm", "npm")):
        v = inst.get(key)
        if v:
            out.append((mgr, v))
    return out


def install_cmd(mgr: str, pkg: str) -> str:
    # 主机是 Arch：系统 Python 受 PEP 668 管，pip 要 --break-system-packages
    return {
        "pacman": f"sudo pacman -S {pkg}",
        "paru": f"paru -S {pkg}",
        "pip": f"pip install --break-system-packages {pkg}",
        "pipx": f"pipx install {pkg}",
        "go": f"go install {pkg}",
        "git": f"git clone {pkg}",
        "cargo": f"cargo install {pkg}",
        "gem": f"gem install --user-install {pkg}",
        "npm": f"npm i -g {pkg}",
    }.get(mgr, f"# {mgr}: {pkg}")


# ------------------------------------------------------------------ 子命令

def run_overview(args) -> int:
    cat = load_catalog()
    pacman = _pacman_installed()
    tools = _all_tools(cat)
    print(f"=== ctfctl 工具目录（{len(tools)} 个 · {len(cat_ids(cat))} 类）===")
    print(f"来源：" + "；".join(s.get("name", "?") for s in cat.get("sources", [])) or "来源：-")
    print()
    for cid in cat_ids(cat):
        items = [t for t in tools if cid in t.get("cats", [])]
        if not items:
            continue
        have = sum(1 for t in items if installed_state(t, pacman) != "no")
        print(f"  {cid:<10} {cat_name(cat, cid):<16} {len(items):>4} 个   本机已装 {have}")
    print()
    print("下一步：ctfctl tools list --cat web | ctfctl tools search <kw> | ctfctl tools check --missing")
    return 0


def run_list(args) -> int:
    cat = load_catalog()
    pacman = _pacman_installed()
    tools = _all_tools(cat)
    if args.cat:
        want = args.cat.lower()
        ids = [c for c in cat_ids(cat) if want in c.lower() or want == cat_name(cat, c).lower()]
        if not ids:
            print(f"[!] 没有这个分类：{args.cat}（有：{', '.join(cat_ids(cat))}）")
            return 2
        tools = [t for t in tools if any(c in t.get("cats", []) for c in ids)]
    if args.installed:
        tools = [t for t in tools if installed_state(t, pacman) != "no"]
    if args.missing:
        tools = [t for t in tools if installed_state(t, pacman) == "no"]
    tools = sorted(tools, key=lambda t: (t.get("cats", [""])[0], t.get("name", "")))
    if not tools:
        print("（空）")
        return 0
    width = max(len(t.get("name", "")) for t in tools)
    for t in tools:
        mark = "✓" if installed_state(t, pacman) != "no" else " "
        catstr = ",".join(t.get("cats", []))
        print(f" {mark} {t.get('name',''):<{width}}  {catstr:<12} {t.get('desc','')}")
    print(f"\n共 {len(tools)} 个（✓ = 本机已装；install 命令见 ctfctl tools show <name>）")
    return 0


def run_search(args) -> int:
    cat = load_catalog()
    pacman = _pacman_installed()
    kw = args.keyword.lower()
    hits = []
    for t in _all_tools(cat):
        blob = " ".join([t.get("name", ""), t.get("desc", ""), t.get("url", ""),
                         " ".join(t.get("aliases", [])), " ".join(t.get("tags", [])),
                         t.get("ctf_use", "")]).lower()
        if kw in blob:
            hits.append(t)
    if not hits:
        print(f"[!] 没搜到 {args.keyword}；试试 ctfctl tools（看分类）或 ctfctl kb search {args.keyword}")
        return 1
    for t in hits:
        mark = "✓" if installed_state(t, pacman) != "no" else " "
        print(f" {mark} {t.get('name',''):<20} [{','.join(t.get('cats',[]))}] {t.get('desc','')}")
    print(f"\n{len(hits)} 条命中")
    return 0


def run_show(args) -> int:
    cat = load_catalog()
    t = by_name(cat, args.name)
    if not t:
        print(f"[!] 目录里没有 {args.name}（ctfctl tools search 试试）", file=sys.stderr)
        return 1
    state = installed_state(t, _pacman_installed())
    print(f"# {t.get('name')}   [{'/'.join(t.get('cats', []))}]")
    if t.get("aliases"):
        print(f"别名：{', '.join(t['aliases'])}")
    print(f"状态：{'已装（PATH 里能找到）' if state == 'path' else '已装（包管理器）' if state == 'pkg' else '未装'}")
    print(f"说明：{t.get('desc','')}")
    if t.get("ctf_use"):
        print(f"CTF 里：{t['ctf_use']}")
    if t.get("url"):
        print(f"主页：{t['url']}")
    print("\n安装：")
    if not _pkgs(t):
        print("  （无安装方式记录）")
    for mgr, pkg in _pkgs(t):
        print(f"  {install_cmd(mgr, pkg)}")
    if t.get("usage"):
        print("\n用法（照抄改参数）：")
        for u in t["usage"]:
            print(f"  {u}")
    if t.get("note"):
        print(f"\n坑：{t['note']}")
    return 0


def run_check(args) -> int:
    cat = load_catalog()
    pacman = _pacman_installed()
    have, miss = [], []
    for t in _all_tools(cat):
        (have if installed_state(t, pacman) != "no" else miss).append(t)
    if args.missing:
        print(f"未装 {len(miss)} 个：")
        for t in sorted(miss, key=lambda x: x.get("name", "")):
            mgr, pkg = (_pkgs(t) or [("-", "-")])[0]
            print(f"  {t.get('name',''):<20} {install_cmd(mgr, pkg)}")
        return 0
    print(f"已装 {len(have)} / {len(have) + len(miss)}")
    for t in sorted(have, key=lambda x: x.get("name", "")):
        print(f"  ✓ {t.get('name',''):<20} [{','.join(t.get('cats',[]))}]")
    print(f"\n缺 {len(miss)} 个：ctfctl tools check --missing")
    return 0


def run_install(args) -> int:
    cat = load_catalog()
    t = by_name(cat, args.name)
    if not t:
        print(f"[!] 目录里没有 {args.name}", file=sys.stderr)
        return 1
    pkgs = _pkgs(t)
    if not pkgs:
        print(f"[!] {args.name} 没有记录的安装方式（主页：{t.get('url','-')}）", file=sys.stderr)
        return 2
    if args.manager:
        pkgs = [p for p in pkgs if p[0] == args.manager] or pkgs
    for mgr, pkg in pkgs:
        cmd = install_cmd(mgr, pkg)
        print(cmd)
        if args.run:
            print(f"[run] {cmd}")
            rc = subprocess.call(cmd, shell=True)
            if rc != 0:
                print(f"[!] 退出码 {rc}", file=sys.stderr)
                return rc
            break
    if not args.run:
        print("\n（只打印命令；要真装加 --run）")
    return 0


def register(sub) -> None:
    p = sub.add_parser("tools", help="CTF 工具目录（Kali/BlackArch 分类 + 本机装没装 + 安装命令）")
    sp = p.add_subparsers(dest="sub")

    q = sp.add_parser("list", help="列工具")
    q.add_argument("--cat", help="只看某类（web/pwn/crypto/rev/misc/net/osint/hash/wireless…）")
    q.add_argument("--installed", action="store_true", help="只列本机已装")
    q.add_argument("--missing", action="store_true", help="只列本机没装")
    q.set_defaults(func=run_list)

    q = sp.add_parser("search", help="全字段检索")
    q.add_argument("keyword")
    q.set_defaults(func=run_search)

    q = sp.add_parser("show", help="详情 + 安装命令 + 用法")
    q.add_argument("name")
    q.set_defaults(func=run_show)

    q = sp.add_parser("check", help="扫本机：装了哪些、缺哪些")
    q.add_argument("--missing", action="store_true", help="只列缺的（带安装命令）")
    q.set_defaults(func=run_check)

    q = sp.add_parser("install", help="打印安装命令（--run 才执行）")
    q.add_argument("name")
    q.add_argument("--manager", help="指定管理器：pacman/paru/pip/pipx/go/git/cargo/npm")
    q.add_argument("--run", action="store_true", help="真的执行（默认只打印）")
    q.set_defaults(func=run_install)

    p.set_defaults(func=run_overview)
