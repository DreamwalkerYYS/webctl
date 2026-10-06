"""workbench —— 工作台的「引擎」，与界面无关。

TUI 与 WebUI 都调这里，保证两个界面行为一致（分析、执行动作、跑命令、浏览栏目）。

    analyze(target)        → {"output": str, "actions": [...], "kind": "web|file|dir|bad"}
    run_action(action)     → (rc, output)
    run_argv(argv)         → (rc, output)（进程内跑 ctfctl 子命令）
    run_shell(cmd)         → (rc, output)（真在机器上跑外部工具）
"""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import subprocess

from . import advise as advise_mod
from .config import CACHE, ensure_dirs


# ------------------------------------------------------------------ 跑东西

def run_argv(argv: list[str]) -> tuple[int, str]:
    """把一条 ctfctl 子命令当函数跑，stdout/stderr 全抓回字符串（不污染调用方的终端）。"""
    from ..cli import build_parser
    buf = io.StringIO()
    rc = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            ap = build_parser()
            args = ap.parse_args([str(a) for a in argv])
            if getattr(args, "func", None) is None:
                rc = 2
            else:
                rc = int(args.func(args) or 0)
        except SystemExit as e:
            try:
                rc = int(e.code or 0)
            except (TypeError, ValueError):          # SystemExit("消息") 这种，退出码按 2
                print(str(e.code))
                rc = 2
        except Exception as e:                      # 子命令炸了也别把工作台带崩
            print(f"[!] {type(e).__name__}: {e}")
            rc = 1
    return rc, buf.getvalue()


def run_shell(cmd: str, timeout: int = 900) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"[!] {e}"
    return r.returncode, (r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace"))


# ------------------------------------------------------------------ 分析

def _subs(target: str) -> dict:
    return {"{url}": target, "{path}": target}


def analyze(target: str, full: bool = False) -> dict:
    """判类型 → 侦察或初筛 → 给证据与可执行动作。返回的 actions 可直接喂给 run_action。"""
    ensure_dirs()
    target = (target or "").strip()
    if not target:
        return {"kind": "bad", "output": "先给个目标：URL（http://…）或题目附件路径。", "actions": []}
    subs = _subs(target)

    if target.startswith(("http://", "https://")):
        from ..commands import recon as recon_cmd
        ns = argparse.Namespace(url=target, cmd="recon", func=None, jar=None, new=False, proxy=None,
                                ua=None, timeout=15.0, full=bool(full), threads=4, delay=0.05,
                                report=None, note=False, no_suggest=False, json=False, verbose=False)
        rc, out = run_argv(["recon", target] + (["--full"] if full else []))
        last = getattr(recon_cmd, "LAST", None) or {}
        ctx = dict(last.get("ctx") or {})
        ev = {"kind": "web", "headers": ctx.get("headers", ""), "body": ctx.get("body", ""),
              "params": ctx.get("params", []), "files": ctx.get("files", []), "status": ctx.get("status")}
        ranked = advise_mod.rank(advise_mod.match(ev), ev)
        out += "\n" + "\n".join(advise_mod.render_text(ranked, ev, subs, limit=4, title="Web 下一步建议"))
        return {"kind": "web", "output": out, "actions": advise_mod.actions_flat(ranked, subs),
                "rc": rc, "report": last.get("base", target)}

    if os.path.isdir(target):
        items = sorted(os.listdir(target))
        lines = [f"{target} 是目录，{len(items)} 项："]
        for i in items[:60]:
            p = os.path.join(target, i)
            lines.append(f"  {'d' if os.path.isdir(p) else str(os.path.getsize(p)) + 'B':>10}  {i}")
        lines.append("\n提示：对单个文件分析；目录先看命名与结构")
        return {"kind": "dir", "output": "\n".join(lines), "actions": []}

    if not os.path.exists(target):
        return {"kind": "bad", "output": f"既不是 http(s) URL，也不是存在的文件/目录：{target}", "actions": []}

    from ..commands import file as file_cmd
    t = file_cmd.triage(target, 20)
    ev = file_cmd.evidence_of(t)
    ranked = advise_mod.rank(advise_mod.match(ev), ev)
    out = file_cmd.render(t, 20) + "\n" + \
        "\n".join(advise_mod.render_text(ranked, ev, {"{path}": t.get("path", target)},
                                         limit=4, title="文件类下一步建议"))
    return {"kind": "text" if ev["kind"] == "text" else "file", "output": out,
            "actions": advise_mod.actions_flat(ranked, {"{path}": t.get("path", target)}),
            "findings": t.get("findings", []), "path": t.get("path", target)}


# ------------------------------------------------------------------ 执行动作

def run_action(action: dict) -> tuple[int, str]:
    """执行一条建议动作。cmd 类走子命令；shell 类真跑外部工具；kb/tool 类只反馈入口。"""
    kind = action.get("kind", "cmd")
    if kind == "cmd":
        return run_argv(list(action.get("argv", [])))
    if kind == "shell":
        return run_shell(action.get("cmd", ""))
    if kind == "kb":
        return 0, f"知识卡：{action.get('id', '')}（ctfctl kb show {action.get('id','')}）"
    if kind == "tool":
        return 0, f"工具条目：{action.get('name', '')}（ctfctl tools show {action.get('name','')}）"
    return 2, f"不认识的动作类型：{kind}"
