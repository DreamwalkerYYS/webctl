"""规则层：把笔记里的「看到 X → 想 Y」变成数据，代码只负责匹配。

规则文件：webctl/data/rules.json
  {"id","name","when":{"header_re":[...],"body_re":[...],"param_re":[...],"file_re":[...]},
   "hint":"...","cmds":["webctl ...","curl ..."]}
when 里的各类条件是 AND；同一类里多个正则是 OR。留空表示不限制。

以后加方向：只动 rules.json，不用碰代码。
"""
from __future__ import annotations

import json
import os
import re

from .config import CONFIG, DATA

USER_RULES = os.path.join(CONFIG, "rules.json")     # 个人规则（覆盖/追加），可选


def load_rules() -> list[dict]:
    rules: list[dict] = []
    for path in (os.path.join(DATA, "rules.json"), USER_RULES):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] 规则文件读不了 {path}: {e}")
            continue
        rules.extend(data.get("rules", data if isinstance(data, list) else []))
    return rules


def _any(patterns, *haystacks) -> bool:
    if not patterns:
        return True
    for p in patterns:
        for h in haystacks:
            if h and re.search(p, h, re.I | re.S):
                return True
    return False


def match(ctx: dict, rules: list[dict] | None = None) -> list[dict]:
    """ctx 形如 {"headers": str, "body": str, "params": [str], "files": [str]}。

    条件全为空的规则不会自动命中（例如"403 出口问题"那条属于按需触发），
    需要时把它放进 ctx["_force"] 的 id 集合里。
    """
    rules = rules if rules is not None else load_rules()
    params = " ".join(ctx.get("params", []))
    files = " ".join(ctx.get("files", []))
    forced = set(ctx.get("_force", ()))
    out = []
    for r in rules:
        w = r.get("when", {})
        conds = {k: w.get(k) for k in ("header_re", "body_re", "param_re", "file_re")}
        if not any(conds.values()) and r.get("id") not in forced:
            continue
        if r.get("id") in forced or (
                _any(w.get("header_re"), ctx.get("headers", ""))
                and _any(w.get("body_re"), ctx.get("body", ""))
                and _any(w.get("param_re"), params)
                and _any(w.get("file_re"), files)):
            out.append(r)
    return out


# ---------------------------------------------------------------- 排序与命令渲染
#: 命中即高信号的证据（权重越高越"看得见"）：能直接利用的入口 > 泛泛的特征
HIGH_SIGNAL_PARAMS = {"file", "path", "url", "src", "include", "page", "cmd", "exec", "system",
                      "do", "run", "shell", "code", "eval", "id", "search", "q", "keyword", "name"}


def _matched_condition_types(rule: dict, ctx: dict, params: str) -> set[str]:
    """这条规则是靠哪几类证据命中的（证据越多越可信）。"""
    w = rule.get("when", {})
    hit = set()
    if w.get("header_re") and _any(w.get("header_re"), ctx.get("headers", "")):
        hit.add("header")
    if w.get("body_re") and _any(w.get("body_re"), ctx.get("body", "")):
        hit.add("body")
    if w.get("param_re") and _any(w.get("param_re"), params):
        hit.add("param")
    if w.get("file_re") and _any(w.get("file_re"), " ".join(ctx.get("files", []))):
        hit.add("file")
    return hit


def score(rule: dict, ctx: dict) -> int:
    """给规则打分：证据类型数 + 高信号参数 + 真实文件命中 + 规则自带 weight。"""
    params = " ".join(ctx.get("params", []))
    files = ctx.get("files", [])
    s = int(rule.get("weight", 1))
    hit = _matched_condition_types(rule, ctx, params)
    s += 2 * len(hit)
    if "param" in hit:
        low = params.lower()
        s += sum(2 for p in HIGH_SIGNAL_PARAMS if re.search(rf"(^|[^\w]){re.escape(p)}([^\w]|$)", low))
    if "file" in hit:
        s += 3 + sum(1 for f in files if f not in ("FAKE",))
    if "body" in hit:
        s += 1
    return s


def rank(rules: list[dict], ctx: dict) -> list[tuple[int, dict]]:
    """按可能性排序，返回 [(分数, 规则)]。"""
    return sorted(((score(r, ctx), r) for r in rules), key=lambda t: -t[0])


def render_cmds(rule: dict, base: str, subs: dict | None = None) -> list[str]:
    """把规则里的命令模板变成**可直接粘贴**的版本：替换 $U / <host> / 令牌占位符。"""
    subs = dict(subs or {})
    host = base.split("://", 1)[-1].rstrip("/")
    out = []
    for cmd in rule.get("cmds", []):
        c = cmd.replace("$U", base).replace("<host>", host).replace("<target>", host)
        for k, v in subs.items():
            c = c.replace(k, v)
        out.append(c)
    return out
