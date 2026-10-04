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
        if (_any(w.get("header_re"), ctx.get("headers", ""))
                and _any(w.get("body_re"), ctx.get("body", ""))
                and _any(w.get("param_re"), params)
                and _any(w.get("file_re"), files)
                or r.get("id") in forced):
            out.append(r)
    return out
