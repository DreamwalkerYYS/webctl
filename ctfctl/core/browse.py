"""browse —— 浏览栏目的数据（知识库/工具目录/规则/历史/速查）。

TUI 与 WebUI 共用：都拿到 [{"title": 列表显示, "key": 定位用, "body": [行…]}]。
"""
from __future__ import annotations

import os
import unicodedata

from . import history as hist_mod
from . import rules as rules_mod


def dwidth(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def dtrunc(s: str, n: int) -> str:
    out, w = [], 0
    for c in s:
        cw = 2 if unicodedata.east_asian_width(c) in "WF" else 1
        if w + cw > n:
            return "".join(out)
        out.append(c)
        w += cw
    return s


def dpad(s: str, n: int) -> str:
    s = dtrunc(s, n)
    return s + " " * max(0, n - dwidth(s))


def wrap(s: str, n: int) -> list[str]:
    out, cur, w = [], "", 0
    for c in s:
        cw = 2 if unicodedata.east_asian_width(c) in "WF" else 1
        if w + cw > n:
            out.append(cur)
            cur, w = "", 0
        cur += c
        w += cw
    out.append(cur)
    return out


SECTIONS = [("kb", "知识库"), ("tools", "工具目录"), ("rules", "规则"),
            ("history", "历史"), ("cheat", "速查")]


def items_kb() -> list[dict]:
    from ..commands import kb as kb_mod
    kb = kb_mod.load_kb()
    out = []
    for c in kb.get("cards", []):
        body = [f"# {c.get('title','')}   [{kb_mod.phase_name(kb, c.get('phase',''))}]",
                f"id: {c.get('id','')}"]
        body += ["", "信号："] + [f"  · {s}" for s in c.get("signals", [])]
        if c.get("mechanism"):
            body += ["", "机制："] + [f"  {l}" for l in wrap(c["mechanism"], 84)]
        if c.get("steps"):
            body += ["", "步骤："] + [f"  {i}. {l}" for i, s in enumerate(c["steps"], 1) for l in wrap(s, 80)]
        if c.get("cmds"):
            body += ["", "命令："] + [f"  {x}" for x in c["cmds"]]
        if c.get("tools"):
            body += ["", f"工具：{', '.join(c['tools'])}"]
        corpus = c.get("corpus") or {}
        if corpus.get("files"):
            body += ["", f"语料证据：{corpus['files']} 个文件命中"
                         f"（{corpus.get('technique','')}；{'/'.join(f'{k}={v}' for k, v in (corpus.get('per_source') or {}).items())}）"]
        if c.get("refs"):
            body += ["", "出处："] + [f"  {r.get('title','')} {r.get('url','')}" for r in c["refs"]]
        out.append({"title": c.get("title", ""), "key": c.get("id", ""), "body": body})
    return out


def items_tools() -> list[dict]:
    from ..commands import tools as tools_mod
    cat = tools_mod.load_catalog()
    pacman = tools_mod._pacman_installed()
    out = []
    for cid in tools_mod.cat_ids(cat):
        ts = sorted([t for t in cat.get("tools", []) if cid in t.get("cats", [])],
                    key=lambda t: (not t.get("curated"), t.get("name", "")))
        if not ts:
            continue
        have = sum(1 for t in ts if tools_mod.installed_state(t, pacman) != "no")
        lines = [f"# {tools_mod.cat_name(cat, cid)}（{len(ts)} 个 · 本机已装 {have}）", ""]
        for t in ts:
            mark = "✓" if tools_mod.installed_state(t, pacman) != "no" else "·"
            tag = "★" if t.get("curated") else " "
            lines.append(f" {mark}{tag} {dpad(t.get('name',''), 18)} {t.get('desc','')}")
        out.append({"title": f"{tools_mod.cat_name(cat, cid)}（{len(ts)}）", "key": cid, "body": lines})
    return out


def items_rules() -> list[dict]:
    out = []
    for r in rules_mod.load_rules():
        body = [f"# {r.get('name','')}   id={r.get('id','')}", "", f"触发：{r.get('hint','')}", ""]
        for k in ("header_re", "body_re", "param_re", "file_re"):
            if (r.get("when") or {}).get(k):
                body.append(f"{k}: " + " | ".join(r["when"][k]))
        body.append("")
        body += [f"  {c}" for c in r.get("cmds", [])]
        out.append({"title": f"{r.get('id','')} — {r.get('name','')}", "key": r.get("id", ""), "body": body})
    return out


def items_history() -> list[dict]:
    recs = hist_mod.load(limit=200)
    out = []
    for r in recs[-100:]:
        body = [f"# {r.get('method','')} {r.get('url','')}",
                f"host: {r.get('host','')}   tag: {r.get('tag','')}",
                f"状态: {r.get('status','')}  {r.get('size','')}B  {r.get('ctype','')}",
                f"body: {r.get('body_file','')}"]
        out.append({"title": f"[{r.get('tag','') or '-'}] {r.get('method','')} {r.get('url','')}",
                    "key": str(r.get("ts", "")), "body": body})
    return out


def items_cheat() -> list[dict]:
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cheatsheet.md")
    if not os.path.exists(p):
        return [{"title": "（没有 cheatsheet.md）", "key": "-", "body": []}]
    blocks, cur = [], None
    for line in open(p, encoding="utf-8").read().splitlines():
        if line.startswith("#"):
            cur = {"title": line.lstrip("# ").strip(), "key": line.strip("# ").strip(), "body": []}
            blocks.append(cur)
        elif cur is not None:
            cur["body"].append(line)
    return [b for b in blocks if b["title"]] or [{"title": "速查", "key": "-", "body": []}]


BUILDERS = {"kb": items_kb, "tools": items_tools, "rules": items_rules,
            "history": items_history, "cheat": items_cheat}
