"""go —— 一条命令搞定「这是什么 + 下一步做什么」。

    ctfctl go "http://靶机/"        # URL → 侦察 + 建议
    ctfctl go ./chal.zip            # 文件 → 初筛 + 建议
    ctfctl go "http://靶机/" --full  # 侦察跑全量小清单

不认识的东西也照打：先判是 URL 还是路径，再决定走 recon 还是 file。
要更细的控制就去用各自的命令（recon / file / fuzz / kb / tools）。
"""
from __future__ import annotations

import argparse
import os
import sys

from . import file as file_cmd
from . import recon as recon_cmd


def _is_url(s: str) -> bool:
    return s.startswith(("http://", "https://")) or ("." in s.split("/")[0] and "/" not in s.split(".")[0]
                                                      and not os.path.exists(s) and " " not in s)


def run(args) -> int:
    t = args.target
    if _is_url(t):
        print(f"[go] 看起来是 URL → 走 Web 侦察（ctfctl recon）\n")
        # recon 需要的字段显式给全（以前用 **vars(args) 糊过去，go 没有 jar 之类就炸）
        ns = argparse.Namespace(url=t, cmd="recon", func=None, jar=None, new=False, proxy=None,
                                ua=None, timeout=15.0, full=bool(getattr(args, "full", False)),
                                threads=4, delay=0.05, report=None, note=False, no_suggest=False,
                                json=False, verbose=False)
        rc = recon_cmd.run(ns)
        print(f"\n[go] 下一步：ctfctl solve \"{t}\"（交互式推进整题）"
              f" / ctfctl fuzz \"{t}/FUZZ\" -e php,bak,zip --safe")
        return rc
    if os.path.isdir(t):
        items = sorted(os.listdir(t))
        print(f"[go] {t} 是目录，{len(items)} 项：")
        for i in items[:40]:
            p = os.path.join(t, i)
            mark = "d" if os.path.isdir(p) else f"{os.path.getsize(p)}B"
            print(f"  {mark:>10}  {i}")
        print("\n提示：对单个文件跑 ctfctl go <文件>；目录整体最后再打包看结构")
        return 0
    if not os.path.exists(t):
        print(f"[!] 既不是 URL 也不是存在的文件：{t}", file=sys.stderr)
        print("    用法：ctfctl go \"http://靶机/\"  或  ctfctl go ./附件.zip", file=sys.stderr)
        return 2
    print(f"[go] 看起来是文件 → 走文件初筛（ctfctl file）\n")
    ns = argparse.Namespace(path=t, strings=getattr(args, "strings", 12),
                            limit=getattr(args, "limit", 3), no_advice=False,
                            json=getattr(args, "json", None))
    return file_cmd.run(ns)


def register(sub) -> None:
    p = sub.add_parser("go", help="一条命令：URL→侦察+建议 / 文件→初筛+建议（不确定就先打这个）")
    p.add_argument("target", help="URL 或文件路径")
    p.add_argument("--full", action="store_true", help="URL：侦察跑全量小清单")
    p.add_argument("--strings", type=int, default=12, help="文件：打多少条可疑字符串")
    p.add_argument("--limit", type=int, default=3, help="最多给几条建议")
    p.add_argument("--json", help="文件：结果写 JSON")
    p.set_defaults(func=run)
