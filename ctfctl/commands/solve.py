"""solve —— 交互式整题推进（状态机在 core/solve.py）。

    ctfctl solve "$U"              # 看当前状态 + 下一步能做什么（不跑任何东西）
    ctfctl solve "$U" --step [N]   # 推进 N 步（默认 1）：跑一步 → 抠新证据 → 重算下一步
    ctfctl solve "$U" --auto [N]   # 自动滚 N 步（默认 3，--budget 限时；拿到 flag 候选就停）
    ctfctl solve "$U" --run 3      # 跑清单里的第 3 条
    ctfctl solve "$U" --reset      # 清掉状态重来

和 WebUI/TUI 共用同一份状态（存 ~/.cache/ctfctl/solve/<目标>.json），所以界面里点过的步骤，
命令行这里接着走，不会重复。
"""
from __future__ import annotations

import sys

from ..core.solve import SolveState


def _state(args) -> SolveState:
    st = SolveState(args.target)
    if args.reset:
        try:
            import os
            os.remove(st.path())
        except OSError:
            pass
        st = SolveState(args.target, load=False)
    return st


def run(args) -> int:
    st = _state(args)
    if args.reset:
        print(f"[solve] 已重置状态（{st.path()}）")

    if args.auto:
        n = args.auto if args.auto > 0 else 3
        print(f"[solve] 自动推进最多 {n} 步（预算 {args.budget}s；拿到 flag 候选即停）")
        for i, r in enumerate(st.advance(limit=n, budget_s=args.budget), 1):
            a = r.get("action")
            if a:
                print(f"\n── 第 {i} 步：{a.get('label')}")
                print(f"   $ {a.get('render')}")
                out = (r.get("output") or "").strip()
                if out:
                    print("   " + "\n   ".join(out.splitlines()[:12]))
                for nw in r.get("new") or []:
                    print(f"   [+] {nw}")
                if r.get("rc"):
                    print(f"   [rc={r['rc']}]")
            for nw in r.get("new") or []:
                if not a:
                    print(f"   [!] {nw}")
            if r.get("note"):
                print(f"   → {r['note']}")

    elif args.run:
        st.refresh_actions()
        idx = args.run - 1
        if not (0 <= idx < len(st.actions)):
            print(f"[!] 序号超范围（现在有 {len(st.actions)} 条）", file=sys.stderr)
            return 2
        a = st.actions[idx]
        print(f"$ {a.get('render')}")
        r = st.step(a)
        print((r.get("output") or "").rstrip())
        for nw in r.get("new") or []:
            print(f"[+] {nw}")

    elif args.step:
        for i in range(max(1, args.step)):
            r = st.step()
            if r.get("action") is None:
                print("（没有可自动推进的动作了）")
                break
            a = r["action"]
            print(f"\n── 第 {st.steps} 步：{a.get('label')}\n   $ {a.get('render')}")
            out = (r.get("output") or "").strip()
            if out:
                print("   " + "\n   ".join(out.splitlines()[:12]))
            for nw in r.get("new") or []:
                print(f"   [+] {nw}")

    print()
    print(st.report())
    if st.flags:
        print(f"\n[solve] 拿到 flag 候选：{st.flags[-1]}   （记得回平台验证）")
    else:
        print(f"\n[solve] 状态已存 {st.path()}；界面里也能接着推（WebUI 的「解题」页）")
    return 0


def register(sub) -> None:
    p = sub.add_parser("solve", help="交互式整题推进：跑一步 → 抠新证据 → 重算下一步（状态可续）")
    p.add_argument("target", help="URL 或附件路径")
    p.add_argument("--step", type=int, nargs="?", const=1, default=0, metavar="N",
                   help="推进 N 步（默认 1）")
    p.add_argument("--auto", type=int, nargs="?", const=3, default=0, metavar="N",
                   help="自动滚 N 步（默认 3；拿到 flag 候选或无新证据就停）")
    p.add_argument("--run", type=int, metavar="N", help="跑清单里的第 N 条")
    p.add_argument("--budget", type=float, default=90.0, help="自动推进的时间预算（秒）")
    p.add_argument("--reset", action="store_true", help="清掉这个目标的状态重来")
    p.set_defaults(func=run)
