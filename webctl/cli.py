"""统一入口：自动发现 webctl/commands/ 下的子命令模块并注册。

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
import pkgutil
import sys

from . import __version__


def load_commands(sub) -> list[str]:
    import webctl.commands as pkg

    names = []
    for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"webctl.commands.{info.name}")
        if hasattr(mod, "register"):
            mod.register(sub)
            names.append(info.name)
    return names


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="webctl",
        description="Web 题通用工具（会话化请求 / 侦察 / JWT / 编码 / Cookie / 笔记）",
        epilog="规则表：webctl rules list  ·  加功能：往 webctl/commands/ 丢一个模块",
    )
    ap.add_argument("--version", action="version", version=f"webctl {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    load_commands(sub)
    return ap


def main(argv: list[str] | None = None) -> int:
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
