"""shell —— 交互式终端（默认入口）：一个提示符干完全部。

    ctfctl                    # 进交互式终端（裸跑就是它）
    ctfctl shell "$U"         # 带目标直接进，并自动做一轮分析

为什么不用 curses / WebUI：curses 要处理绘制与按键（崩过：常量名、写满角落、按键被抢），
WebUI 要端口 + 浏览器 + token，且都多一层渲染。交互式终端没有渲染层、没有端口，
SSH/mosh 下一样用，还能被管道驱动（可测试）。

一屏记法（不用记命令）：
    回车            → 推进一步（跑一步 → 抠新证据 → 重算下一步）
    1..9            → 跑清单里的第 N 条动作
    t <目标>        → 设目标并自动做一轮分析（URL 或附件路径）
    r               → 重新分析当前目标
    s [N]           → 推进 N 步（默认 1）
    a [N]           → 自动推进 N 步（默认 3，拿到 flag 候选/无新证据即停）
    o               → 状态总览（阶段/证据/已试/下一步）
    k [词] o=tools  → 知识库 / 工具目录（同 tools [词]）/ rules / hist / cheat
    !<命令>         → 直接跑系统命令（明确标出，结果也会进证据）
    其它任何一行     → 当作 ctfctl 子命令执行（req get / codec b64d / fuzz …），
                      输出同样会被喂给解题状态
    q / quit / Ctrl-D → 退出（打印状态摘要与存盘路径）
"""
from __future__ import annotations

import os
import shlex
import sys

from ..core import workbench as wb
from ..core.config import CACHE, ensure_dirs
from ..core.solve import SolveState

HIST = os.path.join(CACHE, "shell_history")
MAX_OUT = 200          # 单条输出打印上限（行），超出截断（原文仍在历史/缓存里）
LIST_N = 9


def _readline_setup(names: list[str]) -> None:
    """有 readline 就开历史与补全；没有也不影响（比如某些精简环境）。"""
    try:
        import atexit
        import readline
    except ImportError:
        return

    def completer(text: str, state: int):
        buf = readline.get_line_buffer()
        pool = []
        if not buf.strip():                                  # 空行：补子命令
            pool = [n for n in names if n.startswith(text)]
        else:
            pool = [w for w in ("target", "step", "auto", "status", "help", "quit") if w.startswith(text)]
            try:                                             # 也补文件路径
                pool += [f for f in os.listdir(".") if f.startswith(text)][:50]
            except OSError:
                pass
        return pool[state] if state < len(pool) else None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    ensure_dirs()
    try:
        readline.read_history_file(HIST)
    except OSError:
        pass
    readline.set_history_length(500)
    atexit.register(lambda: _save_hist(readline))


def _save_hist(rl) -> None:
    try:
        ensure_dirs()
        rl.write_history_file(HIST)
    except OSError:
        pass


def _print_out(out: str) -> None:
    lines = (out or "").rstrip("\n").splitlines()
    if len(lines) > MAX_OUT:
        print("\n".join(lines[:MAX_OUT]))
        print(f"...（还有 {len(lines) - MAX_OUT} 行，已截断；完整输出见缓存/历史）")
    elif lines:
        print("\n".join(lines))


class Shell:
    def __init__(self, target: str = "", names: list[str] | None = None):
        self.target = target.strip()
        self.names = names or []
        self.st: SolveState | None = None
        self.actions: list[dict] = []
        self.full = False

    # ---------------------------------------------------------------- 状态
    def _state(self, create: bool = False) -> SolveState | None:
        if not self.target:
            print("[i] 先设目标：t <URL 或 附件路径>（例：t ./chal.zip）")
            return None
        if self.st is None or self.st.target != self.target:
            if not create and not os.path.exists(SolveState(self.target).path()):
                self.st = SolveState(self.target, load=False)
            else:
                self.st = SolveState(self.target)
        return self.st

    def _refresh(self) -> None:
        st = self._state()
        if st is not None:
            self.actions = st.refresh_actions()

    def _show_actions(self) -> None:
        if not self.actions:
            print("  （没有可自动推进的动作了：要么该换方向，要么该人工介入）")
            return
        for i, a in enumerate(self.actions[:LIST_N], 1):
            why = a.get("rule_name") or a.get("why") or ""
            print(f"  {i}) {a.get('label', '')}" + (f"   [{why}]" if why else ""))
            print(f"     $ {a.get('render', '')}")
        if len(self.actions) > LIST_N:
            print(f"  …还有 {len(self.actions) - LIST_N} 条（o 看全量，或用子命令自己来）")

    @staticmethod
    def _evidence_summary(st: SolveState | None) -> str:
        if st is None:
            return "-"
        ev = st.evidence
        bits = [f"{k} {len(ev[k])}" for k in ("params", "paths", "files", "tokens", "errors") if ev.get(k)]
        return "、".join(bits) if bits else "（暂无）"

    def _wrap(self, rc: int, out: str, new: list[str] | None = None) -> None:
        _print_out(out)
        if rc:
            print(f"  [rc={rc}]")
        for nw in (new or []):
            print(f"  [+] {nw}")

    # ---------------------------------------------------------------- 动作
    def analyze(self) -> None:
        if not self.target:
            return
        base = os.path.basename(self.target)
        print(f"[分析] {self.target}")
        res = wb.analyze(self.target, full=self.full)
        text = res.get("output", "") or ""
        _print_out(text)                       # 先看事实（侦察/初筛的原始输出）
        st = self._state(create=True)
        if st is not None:
            st.ingest(text)                    # 输出立刻变成证据（不需要手抄）
            if res.get("findings"):
                st.ingest(" ".join(str(v) for v in res["findings"]))
            st.save()
        self._refresh()
        print(f"\n[i] 阶段 {st.stage if st else '-'} · 证据 {self._evidence_summary(st)} · 下一步：")
        self._show_actions()

    def advance(self, n: int = 1) -> None:
        st = self._state(create=True)
        if st is None:
            return
        for i in range(max(1, n)):
            r = st.step()
            a = r.get("action")
            if a is None:
                print("[i] （没有可自动推进的动作了）")
                break
            print(f"\n── 第 {st.steps} 步：{a.get('label', '')}\n   $ {a.get('render', '')}")
            self._wrap(r.get("rc", 0), r.get("output", ""), r.get("new"))
            if st.flags:
                print(f"  ★ 拿到 flag 候选：{st.flags[-1]}（回平台验证）")
                break
        self._refresh()
        self._show_actions()

    def auto(self, n: int = 3) -> None:
        st = self._state(create=True)
        if st is None:
            return
        print(f"[自动推进] 最多 {n} 步（拿到 flag 候选 / 无新证据 / 无新动作即停）")
        for r in st.advance(limit=n, budget_s=120.0):
            a = r.get("action")
            if a is not None:
                print(f"\n── 第 {st.steps} 步：{a.get('label', '')}\n   $ {a.get('render', '')}")
                self._wrap(r.get("rc", 0), r.get("output", ""), r.get("new"))
            if r.get("note"):
                print(f"  → {r['note']}")
        self._refresh()
        self._show_actions()

    def run_index(self, idx: int) -> None:
        st = self._state(create=True)
        if st is None:
            return
        if not self.actions:
            self._refresh()
        if not (1 <= idx <= len(self.actions)):
            print(f"[!] 序号超范围（现在有 {len(self.actions)} 条）")
            return
        a = self.actions[idx - 1]
        print(f"$ {a.get('render', '')}")
        r = st.step(a)
        self._wrap(r.get("rc", 0), r.get("output", ""), r.get("new"))
        self._refresh()
        self._show_actions()

    def status(self) -> None:
        st = self._state()
        if st is None:
            return
        print(st.report())
        self._refresh()
        self._show_actions()

    # ---------------------------------------------------------------- 主循环
    HELP = """可用输入（不用记命令）：
  回车            推进一步（跑一步 → 抠新证据 → 重算下一步）
  1..9            跑清单里的第 N 条
  t <目标>        设目标并自动分析（URL 或附件路径）
  r               重新分析当前目标
  s [N] / a [N]   推进 N 步 / 自动推进 N 步（默认 1 / 3）
  o               状态总览（阶段/证据/已试/下一步）
  k [词]          知识库    tools [词]  工具目录    rules  规则    hist  历史    cheat  速查
  !<命令>         直接跑系统命令（结果也会进证据）
  <任意子命令>    当成 ctfctl 子命令跑（req get / codec b64d / fuzz / jwt decode …）
  q / quit        退出（状态自动存盘）"""

    def cmd(self, line: str) -> bool:
        """处理一行输入；返回 False 表示要退出。"""
        line = line.strip()
        low = line.lower()

        if not line:                                   # 回车 = 推进
            if not self.target:
                print("[i] 先设目标：t <URL 或 附件路径>")
            else:
                self.advance(1)
            return True

        if low in ("q", "quit", "exit", ":q"):
            return False
        if low in ("?", "help", "h", "**"):
            print(self.HELP)
            return True
        if low in ("o", "status", "st"):
            self.status()
            return True
        if low == "r":
            self.analyze()
            return True

        head, _, rest = line.partition(" ")
        hl, rest = head.lower(), rest.strip()

        if hl in ("t", "target"):
            if not rest:
                print(f"[i] 当前目标：{self.target or '（未设）'}")
                return True
            self.target = rest.strip().strip("'\"")
            self.st = None
            self.analyze()
            return True
        if hl in ("s", "step"):
            self.advance(int(rest) if rest.isdigit() else 1)
            return True
        if hl in ("a", "auto"):
            self.auto(int(rest) if rest.isdigit() else 3)
            return True
        if hl in ("full",):
            self.full = not self.full
            print(f"[i] 完整清单：{'开' if self.full else '关'}")
            return True
        if hl in ("k", "kb", "tools", "rules", "hist", "history", "cheat", "cheatsheet"):
            sub = {"k": "kb", "history": "hist", "cheatsheet": "cheat"}.get(hl, hl)
            argv = [sub] + (shlex.split(rest) if rest else [])
            if sub == "cheat":
                argv = ["kb", "cheat"]
            if sub == "hist":
                argv = ["replay", "list"]
            rc, out = wb.run_argv(argv)
            self._wrap(rc, out)
            return True
        if line.startswith("!"):
            cmd = line[1:].strip()
            if not cmd:
                print("[i] 用法：!ls -la（直接跑系统命令）")
                return True
            print(f"$ {cmd}")
            rc, out = wb.run_shell(cmd)
            self._wrap(rc, out)
            st = self._state()
            if st is not None and out:
                new = st.ingest(out)
                st.save()
                for nw in new:
                    print(f"  [+] {nw}")
            return True
        if line.isdigit():                              # 数字 = 跑第 N 条
            self.run_index(int(line))
            return True

        # 其它任何一行：当成 ctfctl 子命令
        try:
            argv = shlex.split(line)
        except ValueError as e:                         # 引号不配对
            print(f"[!] 命令写法有问题：{e}")
            return True
        if argv and argv[0] not in self.names:          # 不是子命令就提示，别静默
            near = [n for n in self.names if n.startswith(argv[0][:3])][:3]
            print(f"[!] 不是子命令：{argv[0]}" + (f"（想做的是 {'/'.join(near)}？）" if near else ""))
            print("    想跑系统命令用 ! 开头；看帮助输 ?")
            return True
        rc, out = wb.run_argv(argv)
        self._wrap(rc, out)
        st = self._state()
        if st is not None and out:
            new = st.ingest(out)
            st.save()
            if new:
                for nw in new:
                    print(f"  [+] {nw}")
                self._refresh()
                self._show_actions()
        return True

    def loop(self) -> int:
        _readline_setup(self.names)
        interactive = sys.stdin.isatty()
        if interactive:
            print(f"ctfctl 交互式终端（? 看用法，q 退出）")
            if self.target:
                print(f"[i] 目标已设：{self.target}")
        prompt = lambda: f"ctfctl[{self.target or '-'}] ❯ " if interactive else ""
        while True:
            try:
                line = input(prompt() if interactive else "")
            except EOFError:
                break
            except KeyboardInterrupt:                    # Ctrl-C 不退出，只放弃这一行
                print("\n[中断] （再按 q 退出）")
                continue
            try:
                if not self.cmd(line):
                    break
            except Exception as e:                       # 单行出错不结束会话
                print(f"[!] {type(e).__name__}: {e}")
        print()
        st = self.st
        if st is not None:
            flag = f" · ★ {'、'.join(st.flags)}" if st.flags else ""
            print(f"[i] 本次：{st.target} 阶段 {st.stage} · 推进 {st.steps} 步{flag}")
            print(f"[i] 状态已存：{st.path()}（下次进来自动接着走）")
        else:
            print("[i] 本次没设目标，什么都没跑")
        print("[i] 会话结束")
        return 0


def run(args) -> int:
    from . import shell as _self  # noqa: F401  (保持模块自洽)
    names = []
    try:
        from ..cli import build_parser
        names = sorted(build_parser()._subparsers._group_actions[0].choices.keys())
    except Exception:
        names = []
    sh = Shell(target=getattr(args, "target", "") or "", names=names)
    if getattr(args, "full", False):
        sh.full = True
    return sh.loop()


def register(sub) -> None:
    p = sub.add_parser("shell", help="交互式终端（默认入口）：回车推进 / 数字选动作 / 任意行当子命令")
    p.add_argument("target", nargs="?", default="", help="目标 URL 或附件路径（可选，进去后也能 t 设定）")
    p.add_argument("--full", action="store_true", help="分析时列完整清单")
    p.set_defaults(func=run)
