"""统一入口：自动发现 ctfctl/commands/ 下的子命令模块并注册。

每个命令模块只需要：
    def register(sub):  # sub = argparse 的 subparsers 对象
        p = sub.add_parser("xxx", help="...")
        ...
        p.set_defaults(func=run)
    def run(args) -> int:  # 返回退出码
        ...
"""
from __future__ import annotations

import argparse
import importlib
import os
import pkgutil
import sys

from . import __version__


def load_commands(sub) -> list[str]:
    import ctfctl.commands as pkg

    names = []
    for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"ctfctl.commands.{info.name}")
        if hasattr(mod, "register"):
            mod.register(sub)
            names.append(info.name)
    return names


def _alias_notice() -> None:
    """老命令名 webctl 仍可用，但提醒一次（启动器是同一份脚本）。"""
    name = os.path.basename(sys.argv[0] or "")
    if name.startswith("webctl"):
        print("[i] webctl 已改名 ctfctl（本别名继续可用，建议改用 ctfctl）", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ctfctl",
        description="CTF 工具箱（会话化请求 / 侦察 / 爆破 / JWT / 编码 / Cookie / 工具目录 / 知识库 / TUI）",
        epilog="加功能：往 ctfctl/commands/ 丢一个模块 · 规则与知识：ctfctl rules list / ctfctl kb",
    )
    ap.add_argument("--version", action="version", version=f"ctfctl {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    load_commands(sub)
    return ap


def main(argv: list[str] | None = None) -> int:
    _alias_notice()
    # 裸跑 ctfctl 直接进 WebUI 工作台（他要的：不用记命令；TUI 仍在 `ctfctl tui`）
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["web"]
    ap = build_parser()
    args = ap.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:                      # 只给分组、没给子命令时打印帮助
        ap.parse_args([args.cmd, "-h"])
        return 2
    try:
        return int(func(args) or 0)
    except KeyboardInterrupt:
        print("\n[中断]", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
