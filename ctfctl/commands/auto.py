"""auto —— 部分题型的**自动推进闭环**（非 AI，判定器裁决）。

    ctfctl auto ./chal.txt          # 文本：编码链 → 古典密码 → XOR → 哈希/RSA 识别
    ctfctl auto ./chal.zip          # 压缩包：口令候选 → 解包 → 内层文件再走一遍
    ctfctl auto ./a.png             # 图片：LSB 位平面 + 元数据/夹带（有工具才跑）
    ctfctl auto "$U"                # URL：走 solve 的只读探针推进 3 步
    ctfctl auto ./x.bin --deep      # 额外做 binwalk 递归解包 / foremost 雕刻（写缓存目录）
    ctfctl auto ./x.txt --json      # 机器可读（给脚本/后续流程用）

退出码：0 = 闭合（有硬命中，通常是拿到 flag/明文/解开的口令）；3 = 未闭合（列出具依据的未决项）。
每条结果都带**判定依据**（哪个判定器、为什么），可人工复核；判定器全部确定性，不含模型。
"""
from __future__ import annotations

import json as _json
import sys

from ..core import autosolve as AS
from ..core import oracles as O


def _print_steps(steps: list[dict], verbose: bool = True) -> None:
    for i, s in enumerate(steps, 1):
        mark = {"HIT": "✔", "MISS": "·", "UNKNOWN": "?", "ERROR": "!"}.get(s["verdict"], "·")
        conf = {3: "硬", 2: "中", 1: "弱"}.get(s["conf"], "-")
        print(f"  {mark} [{i:>2}] {s['label']}")
        print(f"        判定 {s['verdict']}（{conf}）：{s['reason']}")
        if verbose and s["result"] and s["verdict"] == "HIT":
            body = s["result"].strip()
            lines = body.splitlines()[:8]
            print("        结果：" + "\n              ".join(lines))
        if verbose and s["cmds"]:
            for c in s["cmds"][:3]:
                print(f"        命令：{c}")


def run(args) -> int:
    target = args.target
    budget = float(args.budget)
    print(f"[auto] {target}   （确定性判定器裁决，不含模型）")
    steps = AS.run_auto(target, depth=2, budget_s=budget, extract=bool(args.deep))
    closed, note = AS.summarize(steps)

    if args.json:
        print(_json.dumps({"target": target, "closed": closed, "note": note, "steps": steps},
                          ensure_ascii=False, indent=1))
        return 0 if closed else 3

    _print_steps(steps, verbose=not args.quiet)
    print()
    hits = [s for s in steps if s["verdict"] == "HIT"]
    if closed:
        flags = AS.flags_of(steps)
        print(f"[auto] 闭合 ✅ {note}")
        for f in flags[:3]:
            print(f"[auto] flag 候选：{f}")
        for s in hits[:4]:
            if s.get("result") and not O.flags_in(s["result"]):
                print(f"[auto] 产出（{s['label']}）：{s['result'].strip().splitlines()[0][:120]}")
        print("[auto] 提醒：flag 回平台验一次；口令类产出记进 writeup")
        return 0
    print(f"[auto] 未闭合 ⚠ {note}")
    print("[auto] 下一步（人工）：按上面 `?` 的条目核对依据；缺工具的按提示装（主机上 exiftool/binwalk/7z/john 已有）")
    return 3


def register(sub) -> None:
    p = sub.add_parser("auto", help="部分题型自动推进（编码链/古典密码/XOR/压缩包/图片/元数据，判定器裁决）")
    p.add_argument("target", help="附件路径 或 URL")
    p.add_argument("--budget", type=float, default=120.0, help="总时间预算（秒，默认 120）")
    p.add_argument("--deep", action="store_true", help="额外做 binwalk 递归解包 / foremost 雕刻（写缓存目录）")
    p.add_argument("--json", action="store_true", help="输出 JSON（脚本用）")
    p.add_argument("--quiet", action="store_true", help="只打判定，不打印结果正文")
    p.set_defaults(func=run)
