"""kb —— 知识库：把公开 writeup 里的手法固化成卡片。

数据在 data/kb.json：sources（语料来源 + 抽取口径 + 统计）与 cards（手法卡片）。
每张卡：信号（看到什么）→ 机制（为什么成立）→ 步骤 → 可粘贴命令 → 工具 → 出处。
卡片的 `corpus` 字段是「这条手法在语料里命中多少文件」的实测数字，不是感觉。

    ctfctl kb                       # 按阶段概览 + 语料统计
    ctfctl kb list [--phase 注入]    # 列卡片
    ctfctl kb search <关键词>        # 全字段检索
    ctfctl kb show <id>             # 详情（机制 / 步骤 / 命令 / 出处 / 语料证据）
    ctfctl kb signals               # 信号总表：看到 X → 查哪张卡
    ctfctl kb sources               # 语料来源与统计口径（样本怎么来的、多大）
"""
from __future__ import annotations

import json
import os
import sys

from ..core.config import CONFIG, DATA

USER_KB = os.path.join(CONFIG, "kb.json")


def load_kb() -> dict:
    kb = {"sources": [], "phases": [], "cards": []}
    for path in (os.path.join(DATA, "kb.json"), USER_KB):
        if not os.path.exists(path):
            continue
        try:
            d = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] 知识库读不了 {path}: {e}", file=sys.stderr)
            continue
        for k in kb:
            kb[k].extend(d.get(k, []))
    return kb


def by_id(kb: dict, cid: str) -> dict | None:
    c = cid.strip().lower()
    for card in kb.get("cards", []):
        if card.get("id", "").lower() == c:
            return card
    return None


def phase_name(kb: dict, pid: str) -> str:
    for p in kb.get("phases", []):
        if p.get("id") == pid:
            return p.get("name", pid)
    return pid


def _match(card: dict, kw: str) -> bool:
    blob = " ".join([card.get("id", ""), card.get("title", ""), card.get("mechanism", ""),
                     " ".join(card.get("signals", [])), " ".join(card.get("steps", [])),
                     " ".join(card.get("cmds", [])), " ".join(card.get("tools", [])),
                     " ".join(card.get("tags", []))]).lower()
    return kw.lower() in blob


def run_overview(args) -> int:
    kb = load_kb()
    cards = kb.get("cards", [])
    print(f"=== ctfctl 知识库（{len(cards)} 张卡）===")
    for p in kb.get("phases", []):
        n = [c for c in cards if c.get("phase") == p.get("id")]
        if not n:
            continue
        print(f"  {p.get('name', p.get('id')):<10} {len(n):>2} 张   " +
              "、".join(c.get("title", "")[:18] for c in n[:4]) + (" …" if len(n) > 4 else ""))
    other = [c for c in cards if not any(c.get("phase") == p.get("id") for p in kb.get("phases", []))]
    if other:
        print(f"  (未归类)   {len(other)} 张")
    print()
    for s in kb.get("sources", []):
        print(f"语料 {s.get('name','?')}：{s.get('files','?')} 个文件 / {s.get('bytes','?')} 字节"
              f"（{s.get('fetched','?')} 抓取）")
    print()
    print("下一步：ctfctl kb signals（信号总表）| ctfctl kb search <kw> | ctfctl kb show <id>")
    return 0


def run_list(args) -> int:
    kb = load_kb()
    cards = kb.get("cards", [])
    if args.phase:
        cards = [c for c in cards if args.phase.lower() in (c.get("phase", "") + phase_name(kb, c.get("phase", ""))).lower()]
    if args.tag:
        cards = [c for c in cards if args.tag.lower() in [t.lower() for t in c.get("tags", [])]]
    if not cards:
        print("（空）")
        return 0
    cur = None
    for c in sorted(cards, key=lambda x: (x.get("phase", ""), x.get("id", ""))):
        if c.get("phase") != cur:
            cur = c.get("phase")
            print(f"\n[{phase_name(kb, cur)}]")
        corpus = c.get("corpus") or {}
        ev = f"  语料 {corpus['files']} 文件" if corpus.get("files") else ""
        print(f"  {c.get('id',''):<26} {c.get('title','')}{ev}")
    print(f"\n共 {len(cards)} 张；详情 ctfctl kb show <id>")
    return 0


def run_search(args) -> int:
    kb = load_kb()
    hits = [c for c in kb.get("cards", []) if _match(c, args.keyword)]
    if not hits:
        print(f"[!] 知识库里没搜到 {args.keyword}（ctfctl kb 看全部；工具 ctfctl tools search）")
        return 1
    for c in hits:
        print(f"  {c.get('id',''):<26} [{phase_name(kb, c.get('phase',''))}] {c.get('title','')}")
        for s in c.get("signals", [])[:2]:
            print(f"        信号：{s}")
    print(f"\n{len(hits)} 张命中")
    return 0


def run_show(args) -> int:
    kb = load_kb()
    c = by_id(kb, args.id)
    if not c:
        print(f"[!] 没有这张卡：{args.id}（ctfctl kb search 试试）", file=sys.stderr)
        return 1
    print(f"# {c.get('title')}    [{phase_name(kb, c.get('phase',''))}]   id={c.get('id')}")
    print("\n信号（看到这些就来查这张卡）：")
    for s in c.get("signals", []):
        print(f"  · {s}")
    if c.get("mechanism"):
        print(f"\n机制（为什么成立）：\n  {c['mechanism']}")
    if c.get("steps"):
        print("\n步骤：")
        for i, s in enumerate(c["steps"], 1):
            print(f"  {i}. {s}")
    if c.get("cmds"):
        print("\n可粘贴命令：")
        for x in c["cmds"]:
            print(f"  {x}")
    if c.get("tools"):
        print(f"\n相关工具：{', '.join(c['tools'])}（详情 ctfctl tools show <name>）")
    if c.get("related_rules"):
        print(f"对应规则：{', '.join(c['related_rules'])}（ctfctl rules show <id>）")
    corpus = c.get("corpus") or {}
    if corpus.get("files"):
        print(f"\n语料证据：{corpus['files']} 个 writeup 文件命中" +
              (f"，例：{corpus['example']}" if corpus.get("example") else ""))
        if corpus.get("counts"):
            print("  " + "  ".join(f"{k}={v}" for k, v in corpus["counts"].items()))
    if c.get("refs"):
        print("\n出处：")
        for r in c["refs"]:
            print(f"  {r.get('title','')} {r.get('url','')}")
    return 0


def run_signals(args) -> int:
    kb = load_kb()
    rows = []
    for c in kb.get("cards", []):
        for s in c.get("signals", []):
            rows.append((s, c.get("id", ""), c.get("title", "")))
    if not rows:
        print("（知识库为空）")
        return 0
    w = max(len(r[0]) for r in rows)
    for s, cid, title in sorted(rows):
        print(f"  {s:<{w}}  →  {cid}  ({title})")
    print(f"\n{len(rows)} 条信号 → {len(kb.get('cards', []))} 张卡")
    return 0


def run_sources(args) -> int:
    kb = load_kb()
    for s in kb.get("sources", []):
        print(f"# {s.get('name','?')}")
        print(f"  URL：{s.get('url','-')}")
        print(f"  许可：{s.get('license','-')}   抓取：{s.get('fetched','-')}")
        print(f"  规模：{s.get('files','-')} 个文件 / {s.get('bytes','-')} 字节" +
              (f" / {s.get('repos','-')} 个仓库" if s.get("repos") else ""))
        if s.get("scope"):
            print(f"  口径：{s['scope']}")
        if s.get("stages"):
            print("  阶段：")
            for k, v in s["stages"].items():
                print(f"    {k:<12} {v}")
        print()
    return 0


def register(sub) -> None:
    p = sub.add_parser("kb", help="知识库：writeup 归纳出的手法卡片（信号→机制→命令）")
    sp = p.add_subparsers(dest="sub")

    q = sp.add_parser("list", help="列卡片")
    q.add_argument("--phase", help="只列某个阶段（recon/auth/injection/rce/file/session/misc…）")
    q.add_argument("--tag", help="只列带某个标签")
    q.set_defaults(func=run_list)

    q = sp.add_parser("search", help="全字段检索")
    q.add_argument("keyword")
    q.set_defaults(func=run_search)

    q = sp.add_parser("show", help="看一张卡的全文")
    q.add_argument("id")
    q.set_defaults(func=run_show)

    q = sp.add_parser("signals", help="信号总表：看到 X → 查哪张卡")
    q.set_defaults(func=run_signals)

    q = sp.add_parser("sources", help="语料来源与统计口径")
    q.set_defaults(func=run_sources)

    p.set_defaults(func=run_overview)
