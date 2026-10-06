"""tui —— 工作台（curses，键盘驱动，不用记命令）。

一屏三块：
    顶栏  当前目标（URL 或文件路径）
    左栏  输出/详情（可滚动）
    右栏  动作清单（按键直接执行，来自 core/advise.py 的建议）

    ctfctl            # 不带参数直接进工作台（等价 ctfctl tui）
    ctfctl tui [--target "http://靶机/" ] [--dump [N]]

按键（底部常驻提示）：
    t  输入/更换目标（URL 或文件路径）        r  分析（URL→侦察，文件→初筛）
    ↑↓/jk 滚动输出 · PgUp/PgDn 翻页          1-9 / 回车  执行右栏第 N 条动作
    @  执行右栏全部（逐条，出错就停）          i  直接敲一条 ctfctl 子命令
    k 知识库 · o 工具目录 · u 规则 · h 历史 · c 速查        /  在列表里过滤
    q 退出（在任何输入框里按 Esc 取消）

它不联网改成状态以外的事：分析会真的发请求（跟命令行同一个 Session），
shell 类动作会真的在你机器上执行 —— 右栏每条都会先把命令行打出来。
"""
from __future__ import annotations

import contextlib
import io
import os
import shlex
import subprocess
import sys
import unicodedata

from ..core import advise as advise_mod
from ..core import history as hist_mod
from ..core import rules as rules_mod
from . import file as file_cmd
from . import kb as kb_mod
from . import recon as recon_cmd
from . import tools as tools_mod

BROWSE = [("kb", "知识库"), ("tools", "工具目录"), ("rules", "规则"),
          ("history", "历史"), ("cheat", "速查")]


# ------------------------------------------------------------------ 与 WebUI 共用的东西
# 宽度处理、栏目数据、跑命令的逻辑都在 core/ 里（WebUI 用的是同一套，避免两边行为漂移）
from ..core.browse import (BUILDERS, SECTIONS as BROWSE, dpad, dtrunc,  # noqa: F401
                           dwidth, wrap)
from ..core.workbench import run_argv, run_shell  # noqa: F401


def safe_add(scr, y: int, x: int, text: str, maxw: int, attr: int = 0) -> None:
    """写一行就完事：写满/超出屏幕（尤其右下角那个格子）时 curses 会抛 ERR，这里吞掉。"""
    import curses
    if maxw <= 0 or y < 0 or x < 0:
        return
    try:
        scr.addnstr(y, x, text, maxw, attr)
    except curses.error:
        pass


# ------------------------------------------------------------------ 在进程内跑一条 ctfctl 命令

def run_argv(argv: list[str]) -> tuple[int, str]:
    """把一条 ctfctl 子命令当函数跑，stdout/stderr 全抓回字符串（不污染 TUI）。"""
    from ..cli import build_parser
    buf = io.StringIO()
    rc = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            ap = build_parser()
            args = ap.parse_args(argv)
            if getattr(args, "func", None) is None:
                rc = 2
            else:
                rc = int(args.func(args) or 0)
        except SystemExit as e:
            rc = int(e.code or 0)
        except Exception as e:                                        # 命令内部炸了也别把 TUI 带崩
            print(f"[!] {type(e).__name__}: {e}")
            rc = 1
    return rc, buf.getvalue()


def run_shell(cmd: str) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"[!] {e}"
    out = r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
    return r.returncode, out


# ------------------------------------------------------------------ 主界面

class App:
    def __init__(self, stdscr, target: str = ""):
        self.scr = stdscr
        self.target = target
        self.log: list[str] = [self._hello()]
        self.actions: list[dict] = []
        self.sel = 0
        self.scroll = 0
        self.focus = 1                      # 0=输出 1=动作
        self.mode = "work"                  # work | browse
        self.section = 0
        self.bitems: list[dict] = []
        self.bsel = 0
        self.bscroll = 0
        self.filt = ""
        self.msg = ""

    # -------------------------------------------------- 提示语
    def _hello(self) -> str:
        return ("ctfctl 工作台 —— 键盘搞定全程，不用记命令。\n"
                "  ① t 填目标（URL 或题目附件路径）\n"
                "  ② r 分析（URL→侦察加建议；文件→初筛加建议）\n"
                "  ③ 右栏按 1-9 / 回车执行建议；i 直接敲任意子命令\n"
                "  ④ k 知识库 · o 工具目录 · u 规则 · h 历史 · c 速查\n"
                "别的地方查过的东西（kb/tools）在这里都是同一个入口。")

    def say(self, text: str) -> None:
        self.log.extend((text or "").splitlines() or [""])

    # -------------------------------------------------- 分析
    def analyze(self) -> None:
        t = self.target.strip()
        if not t:
            self.msg = "先按 t 填目标（URL 或附件路径）"
            return
        self.say(f"\n$ ctfctl go {t}")
        if t.startswith(("http://", "https://")):
            import argparse
            ns = argparse.Namespace(url=t, cmd="recon", func=None, jar=None, new=False, proxy=None,
                                    ua=None, timeout=15.0, full=False, threads=4, delay=0.05,
                                    report=None, note=False, no_suggest=False, json=False, verbose=False)
            try:
                recon_cmd.run(ns)
            except Exception as e:
                self.say(f"[!] recon 失败：{type(e).__name__}: {e}")
            last = getattr(recon_cmd, "LAST", None) or {}
            ctx = dict(last.get("ctx") or {})
            if ctx:
                ev = {"kind": "web", "headers": ctx.get("headers", ""), "body": ctx.get("body", ""),
                      "params": ctx.get("params", []), "files": ctx.get("files", []),
                      "status": ctx.get("status")}
                ranked = advise_mod.rank(advise_mod.match(ev), ev)
                self.actions = advise_mod.actions_flat(ranked, {"{url}": t})
                self.say("")
                for line in advise_mod.render_text(ranked, ev, {"{url}": t}, limit=4, title="Web 下一步建议"):
                    self.say(line)
            if not self.actions:
                self.actions = advise_mod.actions_flat(
                    advise_mod.rank(advise_mod.match({"kind": "web"}), {"kind": "web"}),
                    {"{url}": t})
        else:
            if not os.path.exists(t):
                self.say(f"[!] 既不是 http(s) URL，也不是存在的文件：{t}")
                self.msg = "目标不认识"
                return
            tt = file_cmd.triage(t, 15)
            self.say(file_cmd.render(tt, 15))
            ev = file_cmd.evidence_of(tt)
            ranked = advise_mod.rank(advise_mod.match(ev), ev)
            self.actions = advise_mod.actions_flat(ranked, {"{path}": tt.get("path", t)})
            self.say("")
            for line in advise_mod.render_text(ranked, ev, {"{path}": tt.get("path", t)}, limit=4,
                                               title="文件类下一步建议"):
                self.say(line)
        self.sel, self.scroll, self.focus = 0, 0, 1
        self.msg = f"分析完成：{len(self.actions)} 条可执行动作"

    # -------------------------------------------------- 执行动作
    def do_action(self, idx: int) -> None:
        if not (0 <= idx < len(self.actions)):
            return
        a = self.actions[idx]
        kind = a.get("kind")
        if kind == "kb" and a.get("id"):
            self.open_browse("kb", a["id"])
            return
        if kind == "tool" and a.get("name"):
            self.open_browse("tools", a["name"])
            return
        if kind == "cmd":
            argv = [str(x) for x in a.get("argv", [])]
            argv = [{"{url}": self.target, "{path}": self.target}.get(x, x) for x in argv]
            self.say(f"\n$ ctfctl {' '.join(argv)}")
            rc, out = run_argv(argv)
            self.say(out.rstrip() or "(无输出)")
            if rc:
                self.say(f"[rc={rc}]")
        elif kind == "shell":
            cmd = (a.get("cmd") or "").replace("{path}", self.target).replace("{url}", self.target)
            self.say(f"\n$ {cmd}")
            rc, out = run_shell(cmd)
            self.say(out.rstrip() or "(无输出)")
            if rc:
                self.say(f"[rc={rc}]")
        self.scroll = 10 ** 6
        self.focus = 0

    def do_all(self) -> None:
        for i in range(len(self.actions)):
            self.do_action(i)

    # -------------------------------------------------- 浏览
    def open_browse(self, sid: str, key: str = "") -> None:
        self.section = next((i for i, (s, _) in enumerate(BROWSE) if s == sid), 0)
        self.bitems = BUILDERS[sid]()
        self.bsel = next((i for i, it in enumerate(self.bitems) if it["key"] == key), 0)
        self.bscroll, self.filt, self.mode = 0, "", "browse"

    # -------------------------------------------------- 输入框
    def prompt(self, label: str) -> str:
        h, w = self.scr.getmaxyx()
        safe_add(self.scr, h - 1, 0, dpad(f"{label}", w - 1), w - 1, self._attr("rev"))
        self.scr.refresh()
        self._curs(1)
        try:
            s = self.scr.getstr(h - 1, min(len(label), w - 2), w - len(label) - 2)
        except Exception:
            s = b""
        finally:
            self._curs(0)
        return s.decode("utf-8", "replace").strip()

    def _attr(self, name: str):
        import curses
        return {"rev": curses.A_REVERSE, "dim": curses.A_DIM, "bold": curses.A_BOLD}[name]

    def _curs(self, on: int) -> None:
        import curses
        try:
            curses.curs_set(on)
        except curses.error:
            pass

    # -------------------------------------------------- 绘制
    def draw(self) -> None:
        import curses
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        if w < 60 or h < 14:
            safe_add(scr, 0, 0, "终端太小，放大到至少 60x14（现在 %dx%d）" % (w, h), w - 1)
            scr.refresh()
            return
        right = max(44, w // 2)
        left = max(20, w - right - 1)
        if self.mode == "work":
            safe_add(scr, 0, 0, dpad(" ctfctl 工作台 ", w - 1), w - 1, curses.A_REVERSE)
            tabs = "  ".join(f"{i+1}:{n}" for i, (_, n) in enumerate(BROWSE))
            safe_add(scr, 0, max(0, w - dwidth(tabs) - 3), f" {tabs} ", w - 1, curses.A_REVERSE)
            tgt = self.target or "（还没设目标：按 t）"
            safe_add(scr, 0, 15, dtrunc(f"目标 {tgt}", max(0, w - 16 - dwidth(tabs) - 2)),
                     max(0, w - 16 - dwidth(tabs) - 2), curses.A_REVERSE)
            rows = h - 3
            for r, line in enumerate(self.log[self.scroll:self.scroll + rows]):
                safe_add(scr, 1 + r, 0, dtrunc(line, left - 1), left - 1,
                         curses.A_NORMAL if self.focus == 0 else curses.A_DIM)
            for r in range(1, h - 2):
                safe_add(scr, r, left, "│", 1, curses.A_DIM)
            safe_add(scr, 1, left + 1, " 可执行动作（回车/数字键执行）", right - 2, curses.A_BOLD)
            for r, a in enumerate(self.actions[:max(0, rows - 1)]):
                mark = "▶" if r == self.sel else " "
                attr = curses.A_REVERSE if (r == self.sel and self.focus == 1) else curses.A_NORMAL
                safe_add(scr, 2 + r, left + 1, dpad(f" {mark}{r + 1}) {a['label']}", right - 2),
                         right - 2, attr)
                safe_add(scr, 3 + r, left + 1, dtrunc("     " + a.get("render", ""), right - 3),
                         right - 3, curses.A_DIM)
            if not self.actions:
                safe_add(scr, 2, left + 1, "  （按 r 分析后这里会出现动作）", right - 2, curses.A_DIM)
        else:
            sid, name = BROWSE[self.section]
            safe_add(scr, 0, 0, dpad(f" 浏览：{name}（{sid}） ", w - 1), w - 1, curses.A_REVERSE)
            safe_add(scr, 0, 18, " Tab/1-5 换栏 · ↑↓ 选 · / 过滤 · q 返回工作台 ",
                     max(0, w - 19), curses.A_REVERSE)
            items = [it for it in self.bitems
                     if not self.filt or self.filt.lower() in (it["title"] + it["key"]).lower()]
            self.bsel = min(self.bsel, max(0, len(items) - 1))
            rows = h - 3
            top = max(0, min(self.bsel - rows + 1, len(items) - rows)) if len(items) > rows else 0
            for r, it in enumerate(items[top:top + rows]):
                attr = curses.A_REVERSE if (top + r) == self.bsel else curses.A_NORMAL
                safe_add(scr, 1 + r, 0, dpad(" " + it["title"], left - 1), left - 1, attr)
            for r in range(1, h - 2):
                safe_add(scr, r, left, "│", 1, curses.A_DIM)
            detail = items[self.bsel]["body"] if items else ["（空）"]
            for r, line in enumerate(detail[self.bscroll:self.bscroll + rows]):
                safe_add(scr, 1 + r, left + 1, dtrunc(line, right - 2), right - 2)
        keys = (" t 目标 · r 分析 · 回车/1-9 执行 · i 命令 · k 知识库 · o 工具 · u 规则 · h 历史 · c 速查 · q 退出"
                if self.mode == "work" else
                " Tab 换栏 · ↑↓ 选 · PgUp/PgDn 详情 · / 过滤 · q 返回")
        footer = (" " + self.msg + " | " + keys) if self.msg else (" " + keys)
        safe_add(scr, h - 1, 0, dpad(footer, w - 2), w - 2, curses.A_DIM)
        scr.refresh()

    # -------------------------------------------------- 主循环
    def loop(self) -> int:
        import curses
        while True:
            self.draw()
            ch = self.scr.getch()
            if self.mode == "work":
                if ch == ord("q"):
                    return 0
                elif ch == ord("t"):
                    v = self.prompt("目标（URL 或附件路径）: ")
                    if v:
                        self.target = v
                        self.msg = "目标已设置，按 r 分析"
                elif ch == ord("r"):
                    self.draw()
                    self.msg = "分析中…（真的在发请求/读文件）"
                    self.scr.refresh()
                    self.analyze()
                elif ch in (10, 13) or (ord("1") <= ch <= ord("9")):
                    self.do_action(self.sel if ch in (10, 13) else ch - ord("1"))
                elif ch == ord("@"):
                    self.do_all()
                elif ch == curses.KEY_UP:            # 注意：j/k 留给下面的栏目快捷键，别抢
                    if self.focus == 1:
                        self.sel = max(0, self.sel - 1)
                    else:
                        self.scroll = max(0, self.scroll - 1)
                elif ch == curses.KEY_DOWN:
                    if self.focus == 1:
                        self.sel = min(max(0, len(self.actions) - 1), self.sel + 1)
                    else:
                        self.scroll += 1
                elif ch == 9:
                    self.focus = 1 - self.focus
                elif ch == curses.KEY_PPAGE:
                    self.scroll = max(0, self.scroll - 10)
                elif ch == curses.KEY_NPAGE:
                    self.scroll += 10
                elif ch in (ord("i"), ord(":")):
                    v = self.prompt("ctfctl ")
                    if v:
                        argv = shlex.split(v)
                        self.say(f"\n$ ctfctl {v}")
                        rc, out = run_argv(argv)
                        self.say(out.rstrip() or "(无输出)")
                        if rc:
                            self.say(f"[rc={rc}]")
                        self.scroll = 10 ** 6
                elif ch in (ord("k"), ord("o"), ord("u"), ord("h"), ord("c")):
                    self.open_browse({"k": "kb", "o": "tools", "u": "rules", "h": "history", "c": "cheat"}[chr(ch)])
            else:
                sid, _ = BROWSE[self.section]
                if ch in (ord("q"), 27):
                    self.mode = "work"
                elif ch == 9:
                    self.section = (self.section + 1) % len(BROWSE)
                    self.bitems, self.bsel, self.bscroll, self.filt = BUILDERS[BROWSE[self.section][0]](), 0, 0, ""
                elif ord("1") <= ch <= ord("5"):
                    self.section = ch - ord("1")
                    self.bitems, self.bsel, self.bscroll, self.filt = BUILDERS[BROWSE[self.section][0]](), 0, 0, ""
                elif ch in (curses.KEY_UP, ord("k")):
                    self.bsel, self.bscroll = max(0, self.bsel - 1), 0
                elif ch in (curses.KEY_DOWN, ord("j")):
                    self.bsel = min(max(0, len(self.bitems) - 1), self.bsel + 1)
                elif ch == curses.KEY_PPAGE:
                    self.bscroll = max(0, self.bscroll - 10)
                elif ch == curses.KEY_NPAGE:
                    self.bscroll += 10
                elif ch == ord("/"):
                    self.filt = self.prompt("过滤: ")


def items_dump(n: int) -> list[str]:
    out = []
    if n:
        for sid, name in BROWSE:
            items = BUILDERS[sid]()
            out.append(f"=== {name}（{sid}）：{len(items)} 条 ===")
            for it in items[:n]:
                out.append(f"  {it['title']}")
    return out


def run(args) -> int:
    if args.dump:
        for line in items_dump(args.dump):
            print(line)
        return 0
    if not sys.stdout.isatty():
        print("[!] 不是交互终端：用 ctfctl tui --dump N 看内容，或 ctfctl kb / ctfctl tools / ctfctl go", file=sys.stderr)
        return 2
    import curses
    def app(stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)
        a = App(stdscr, target=args.target or "")
        return a.loop()
    try:
        return curses.wrapper(app)
    except KeyboardInterrupt:
        return 130


def register(sub) -> None:
    p = sub.add_parser("tui", help="工作台（键盘驱动：目标→分析→按键执行建议；也含知识库/工具/规则/历史/速查）")
    p.add_argument("--target", default="", help="进来就带上目标（URL 或附件路径）")
    p.add_argument("--dump", type=int, nargs="?", const=5, default=0, metavar="N",
                   help="不开界面：每栏打印前 N 条（给测试/排版检查）")
    p.set_defaults(func=run)
