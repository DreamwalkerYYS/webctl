"""建议引擎：把「证据」变成「下一步做什么」。

和 rules.json 同构（when 里各类条件是 AND、同类内多个正则是 OR），但多了三层：
    why    为什么这么怀疑 —— 给人读的推理，不是命令
    next   可执行动作：[{"label","kind":"cmd|shell|kb|tool","argv"/"cmd"/"id"/"name","why"}]
    tools  推荐工具名（对应 data/tools.json）· kb 知识卡 id（对应 data/kb.json）

证据（evidence）字段：
    kind       "web" / "file" / "text"
    headers, body, params, files, status            —— web 面（与 rules.json 共用）
    magic, name, ext, size, entropy                 —— 文件面
    findings   高信号标签列表（file 初筛产出），如 "elf"、"elf:nx-off"、"embedded"、
               "appended"、"zip:encrypted"、"png:crc-bad"、"entropy-high"、"strings:flag"

规则文件：data/advice.json（随包）+ ~/.config/ctfctl/advice.json（个人补充，追加）
"""
from __future__ import annotations

import json
import os
import re
import sys

from .config import CONFIG, DATA

USER_ADVICE = os.path.join(CONFIG, "advice.json")
FIELDS = ("kind_re", "magic_re", "ext_re", "findings_re", "body_re", "header_re", "param_re", "name_re")

#: 能直接利用的入口 > 泛泛的特征（与 rules.py 保持同一套直觉）
HIGH_SIGNAL = {"file", "path", "url", "src", "include", "page", "cmd", "exec", "system",
               "do", "run", "shell", "code", "eval", "id", "search", "q", "keyword", "name"}


def load() -> list[dict]:
    rules: list[dict] = []
    for path in (os.path.join(DATA, "advice.json"), USER_ADVICE):
        if not os.path.exists(path):
            continue
        try:
            d = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] 建议表读不了 {path}: {e}", file=sys.stderr)
            continue
        rules.extend(d.get("rules", d if isinstance(d, list) else []))
    return rules


def _any(patterns, *haystacks) -> bool:
    if not patterns:
        return True
    for p in patterns:
        for h in haystacks:
            if h and re.search(p, str(h), re.I | re.S):
                return True
    return False


def _blob(ev: dict, key: str) -> str:
    v = ev.get(key, "")
    return " ".join(v) if isinstance(v, (list, tuple)) else str(v or "")


def match(ev: dict, rules: list[dict] | None = None) -> list[dict]:
    rules = load() if rules is None else rules
    ctx = {
        "kind_re": _blob(ev, "kind"),
        "magic_re": _blob(ev, "magic"),
        "ext_re": _blob(ev, "ext"),
        "findings_re": " ".join(ev.get("findings", []) or []),
        "body_re": _blob(ev, "body"),
        "header_re": _blob(ev, "headers"),
        "param_re": " ".join(ev.get("params", []) or []),
        "name_re": _blob(ev, "name"),
    }
    out = []
    for r in rules:
        w = r.get("when", {})
        conds = {k: w.get(k) for k in FIELDS}
        if not any(conds.values()):
            continue
        if all(_any(w.get(k), ctx.get(k, "")) for k in FIELDS):
            out.append(r)
    return out


def score(rule: dict, ev: dict) -> int:
    s = int(rule.get("weight", 1))
    w = rule.get("when", {})
    s += 2 * sum(1 for k in FIELDS if w.get(k))                       # 证据类型越多越可信
    for p in ev.get("params", []) or []:
        if p.lower() in HIGH_SIGNAL:
            s += 2
    for f in ev.get("findings", []) or []:
        if re.search(r"(crc-bad|encrypted|nx-off|canary-off|pie-off|appended|embedded|strings:flag|entropy-high)", f, re.I):
            s += 3                                                    # 硬证据
    return s


def rank(hits: list[dict], ev: dict) -> list[tuple[int, dict]]:
    return sorted(((score(r, ev), r) for r in hits), key=lambda t: -t[0])


def render_next(item: dict, subs: dict | None = None) -> str:
    """把一条 next 动作渲染成可粘贴的命令行文本。"""
    subs = subs or {}
    kind = item.get("kind", "cmd")
    if kind == "cmd":
        argv = [str(x) for x in item.get("argv", [])]
        argv = [subs.get(a, a) for a in argv]
        return "ctfctl " + " ".join(_q(a) for a in argv)
    if kind == "shell":
        cmd = item.get("cmd", "")
        for k, v in subs.items():
            cmd = cmd.replace(k, v)
        return cmd
    if kind == "kb":
        return f"ctfctl kb show {item.get('id', '')}"
    if kind == "tool":
        return f"ctfctl tools show {item.get('name', '')}"
    return ""


def _q(s: str) -> str:
    return f'"{s}"' if (s == "" or any(c in s for c in ' "$\'&|;<>()*')) else s


def render_text(ranked: list[tuple[int, dict]], ev: dict, subs: dict | None = None,
                limit: int = 3, title: str = "下一步建议") -> list[str]:
    """给 CLI（recon/go/file）与 TUI 共用的纯文本建议块。"""
    lines: list[str] = []
    if not ranked:
        lines.append("（没有踩中任何建议规则；把这次侦察的特征补进 data/advice.json 或 rules.json）")
        return lines
    top = ranked[:limit]
    lines.append(f"=== {title}：按证据打分排序（{len(ranked)} 条命中）===")
    for i, (sc, r) in enumerate(top, 1):
        lines.append(f"\n[{i}] {sc} 分 · {r.get('name', r.get('id'))}")
        if r.get("why"):
            lines.append(f"    为什么：{r['why']}")
        for n in r.get("next", []):
            cmd = render_next(n, subs)
            lines.append(f"    → {n.get('label', '')}")
            if cmd:
                lines.append(f"        {cmd}")
            if n.get("why"):
                lines.append(f"        （{n['why']}）")
        if r.get("tools"):
            lines.append(f"    工具：{', '.join(r['tools'])}   （详情 ctfctl tools show <name>）")
        if r.get("kb"):
            lines.append(f"    知识卡：{'、'.join(r['kb'])}   （ctfctl kb show <id>）")
    if len(ranked) > limit:
        rest = "、".join(f"{r.get('name')}({s})" for s, r in ranked[limit:])
        lines.append(f"\n其余命中：{rest}")
    return lines


def actions_flat(ranked: list[tuple[int, dict]], subs: dict | None = None) -> list[dict]:
    """摊平成「一条动作一行」，给 TUI 当可按键执行的清单。"""
    out = []
    for sc, r in ranked:
        for n in r.get("next", []):
            out.append({"score": sc, "rule": r.get("id"), "rule_name": r.get("name", ""),
                        "label": n.get("label", ""), "kind": n.get("kind", "cmd"),
                        "argv": n.get("argv", []), "cmd": n.get("cmd", ""), "id": n.get("id", ""),
                        "name": n.get("name", ""), "why": n.get("why", ""),
                        "render": render_next(n, subs), "kb": r.get("kb", []), "tools": r.get("tools", [])})
    return out
