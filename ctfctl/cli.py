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
import contextlib
import importlib
import io
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
        description="CTF 工具箱（会话化请求 / 侦察 / 爆破 / JWT / 编解码 / 古典密码 / Cookie / "
                    "工具目录 / 知识库 / WebUI 工作台）",
        epilog="加功能：往 ctfctl/commands/ 丢一个模块 · 规则与知识：ctfctl rules list / ctfctl kb",
    )
    ap.add_argument("--version", action="version", version=f"ctfctl {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    load_commands(sub)
    return ap


def _bare_first(ap: argparse.ArgumentParser, argv: list[str]) -> list[str]:
    """把「裸 token（子命令/参数值）」放前面、选项放后面。

    argparse 不支持 intermixed（子解析器会 TypeError），而 `codec cipher caesar --shift 3 KHOOR`
    这种写法会因为 nargs="*" 的位置参数写在选项后面而报 unrecognized arguments。
    这里只在第一次解析失败时兜底重排：保持裸 token 的相对顺序，把选项（连同它的值）挪到最后。
    """
    takes_value: set[str] = set()

    def walk(p):
        for act in getattr(p, "_actions", []):
            if isinstance(act, argparse._SubParsersAction):
                for sub in act.choices.values():
                    walk(sub)
            elif act.option_strings and not isinstance(act, (argparse._StoreTrueAction,
                                                             argparse._StoreFalseAction,
                                                             argparse._CountAction,
                                                             argparse._HelpAction,
                                                             argparse._VersionAction)):
                takes_value.update(act.option_strings)
    walk(ap)
    bare, opts, i = [], [], 0
    while i < len(argv):
        t = argv[i]
        if t.startswith("-") and t != "-":
            opts.append(t)
            if t in takes_value and i + 1 < len(argv):
                i += 1
                opts.append(argv[i])
        else:
            bare.append(t)
        i += 1
    return bare + opts


def main(argv: list[str] | None = None) -> int:
    _alias_notice()
    # 裸跑 ctfctl 直接进 WebUI 工作台（他要的：不用记命令；TUI 仍在 `ctfctl tui`）
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["web"]
    ap = build_parser()
    noise = io.StringIO()
    try:
        with contextlib.redirect_stderr(noise):     # 首次尝试的 argparse 报错先别吓用户
            args = ap.parse_args(argv)
    except SystemExit as e:
        if e.code != 2:
            raise
        try:
            args = ap.parse_args(_bare_first(ap, argv))
        except SystemExit:
            sys.stderr.write(noise.getvalue())
            if _bare_first(ap, argv) != argv:        # 只在「重排能改变什么」时才提顺序
                print("[i] 参数顺序不对时可以这样写：把文本/路径放前面，选项放后面"
                      "（例：ctfctl codec cipher caesar KHOOR --shift 3），或从 stdin 喂进去",
                      file=sys.stderr)
            raise
    func = getattr(args, "func", None)
    if func is None:                      # 只给分组、没给子命令时打印帮助
        ap.parse_args([args.cmd, "-h"])
        return 2
    try:
        return int(func(args) or 0)
    except KeyboardInterrupt:
        print("\n[中断]", file=sys.stderr)
        return 130
    except BrokenPipeError:                 # `ctfctl tools list | head` 这类用法，正常结束即可
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
