"""rules —— 规则表操作：看有哪些规则、单独试一条、检查 JSON 是否写对。

规则表 = 你笔记里的「看到 X → 想 Y」。加规则只改
    ctfctl/data/rules.json        （随包走，upgrade 会被覆盖）
    ~/.config/ctfctl/rules.json   （个人补充，优先级靠后、只增不改）
"""
from __future__ import annotations

import json
import sys

from ..core import rules as rules_mod


def run_list(args) -> int:
    rules = rules_mod.load_rules()
    print(f"{len(rules)} 条规则")
    for r in rules:
        w = r.get("when", {})
        conds = " ".join(f"{k.replace('_re', '')}={len(v)}" for k, v in w.items() if v)
        print(f"  {r['id']:16s} {r['name']:22s} [{conds}]")
    if args.verbose:
        for r in rules:
            print(f"\n▸ {r['id']}: {r['name']}\n  {r['hint']}")
            for c in r.get("cmds", []):
                print(f"    {c}")
    return 0


def run_test(args) -> int:
    ctx = {"headers": args.headers or "", "body": args.body or "",
           "params": (args.param or []), "files": (args.file or [])}
    hits = rules_mod.match(ctx)
    if not hits:
        print("没有命中任何规则（换个特征试试，或 ctfctl rules list 看条件）")
        return 1
    for r in hits:
        print(f"▸ {r['name']}\n  {r['hint']}")
        for c in r.get("cmds", []):
            print(f"    {c}")
    return 0


def run_check(args) -> int:
    """给自定义规则做体检：JSON 能否解析、字段是否齐全、正则能否编译。"""
    import re

    rules = rules_mod.load_rules()
    bad = 0
    for r in rules:
        for field in ("id", "name", "when", "hint"):
            if field not in r:
                print(f"[!] 规则缺字段 {field}: {r}"); bad += 1
        for k, pats in (r.get("when") or {}).items():
            if not isinstance(pats, list):
                print(f"[!] {r.get('id')}.{k} 应该是列表"); bad += 1; continue
            for p in pats:
                try:
                    re.compile(p)
                except re.error as e:
                    print(f"[!] {r.get('id')}.{k} 正则坏了：{p} ({e})"); bad += 1
    print(f"[规则] {len(rules)} 条，问题 {bad} 处")
    return 1 if bad else 0


def register(sub) -> None:
    p = sub.add_parser("rules", help="规则表：list / test / check")
    v = p.add_subparsers(dest="rulescmd", required=True)

    l = v.add_parser("list", help="列出所有规则")
    l.add_argument("-v", "--verbose", action="store_true", help="连 hint 和命令一起打印")
    l.set_defaults(func=run_list)

    t = v.add_parser("test", help="用给定特征试匹配（不联网）")
    t.add_argument("--headers", help="响应头文本")
    t.add_argument("--body", help="正文/源码片段")
    t.add_argument("--param", action="append", help="参数名（可多次）")
    t.add_argument("--file", action="append", help="扫到的文件/路径（可多次）")
    t.set_defaults(func=run_test)

    c = v.add_parser("check", help="检查规则 JSON 与正则")
    c.set_defaults(func=run_check)
