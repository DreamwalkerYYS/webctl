"""export —— 把请求历史导成**可复现的东西**：bash / python / writeup 片段。

    webctl export script --last 10            # 生成一串 curl（可直接跑）
    webctl export script --range 3-9 -o replay.sh
    webctl export python --indices 1,4,7      # 生成 urllib 脚本（零依赖）
    webctl export md --last 8 --title "QuestionCTF 多阶段 Web lab"   # 直接当 writeup 的"分步过程"
    webctl export md --last 8 --note          # 顺手写进 vault 的 CTF/ 目录

脱敏：`md` 模式默认打码（cookie 值 → `***`、"http://主机" → `http://<target>`），因为笔记要进 vault。
脚本/py 模式默认原样（自己跑要能真复现），要打码加 `--redact`。

⚠️ 历史里的 cookie 是**当时那一次会话**的值，靶机重启/会话过期后就失效了 —— 导出的是"当时怎么打的"，
   不是"现在还能直接打穿"。
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shlex
import sys

from ..core import history

SKIP_HEADERS = {"host", "content-length", "accept-encoding", "connection", "cookie"}


def _pick(args, recs: list[dict]) -> list[dict]:
    if getattr(args, "tag", None):
        recs = [r for r in recs if r.get("tag", "req") == args.tag]
    elif getattr(args, "no_probes", False):
        recs = [r for r in recs if r.get("tag", "req") not in ("recon", "fuzz", "diff")]
    if getattr(args, "indices", None):
        idx = [int(x) for x in re.split(r"[,\s]+", args.indices.strip()) if x.strip().isdigit()]
    elif getattr(args, "range", None):
        a, _, b = args.range.partition("-")
        idx = list(range(int(a), int(b or a) + 1))
    else:
        n = args.last or 10
        idx = list(range(max(1, len(recs) - n + 1), len(recs) + 1))
    out = []
    for i in idx:
        if 1 <= i <= len(recs):
            out.append(recs[i - 1])
        else:
            print(f"[!] 序号 {i} 超范围（历史共 {len(recs)} 条），跳过", file=sys.stderr)
    return out


def _redact(text: str, host: str) -> str:
    """打码：主机 → <target>；**所有** cookie 对的值 → ***（不只第一个）。"""
    text = text.replace(host, "<target>")
    # --cookie 'a=1; b=2' → --cookie 'a=***; b=***'
    text = re.sub(r"(?<![\w-])([A-Za-z0-9_.\-]{1,40})=([^;\s'\"]+)", r"\1=***", text)
    # 兜底：报头形式的 Cookie: a=1; b=2
    text = re.sub(r"(?i)(cookie:\s*)([^\n]+)", lambda m: m.group(1) + re.sub(r"=([^;\s]+)", "=***", m.group(2)), text)
    return text


def _headers_of(rec: dict) -> list[tuple[str, str]]:
    hs = [(k, v) for k, v in (rec.get("req_headers") or {}).items()
          if k.lower() not in SKIP_HEADERS]
    return hs


# ---------------------------------------------------------------- bash
def emit_script(recs: list[dict], args) -> str:
    lines = ["#!/usr/bin/env bash",
             "# 由 webctl export script 生成 —— 请求历史的可复现版本",
             f"# 生成时间：{_dt.datetime.now():%Y-%m-%d %H:%M:%S}",
             "# 注意：里面的 cookie 是当时会话的值，靶机重启/会话过期后要重新拿（webctl req get \"$U/\"）",
             "set -uo pipefail", ""]
    host = ""
    for i, rec in enumerate(recs, 1):
        url = rec.get("url", "")
        if url.startswith("http"):
            from urllib.parse import urlsplit
            s = urlsplit(url)
            host = f"{s.scheme}://{s.netloc}"
        lines.append(f"# ---- [{i}] {rec.get('method')} {url}   "
                     f"（当时：{rec.get('status')} {rec.get('size')}B {rec.get('ctype','')}）")
        cmd = ["curl", "-sS", "-i"]
        ck = rec.get("cookies") or ""
        if ck:
            cmd += ["--cookie", ck]
        for k, v in _headers_of(rec):
            cmd += ["-H", f"{k}: {v}"]
        if rec.get("req_body"):
            if (rec.get("req_headers") or {}).get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                cmd += ["-X", rec.get("method", "POST"), "--data", rec["req_body"]]
            else:
                cmd += ["-X", rec.get("method", "POST"), "--data-raw", rec["req_body"]]
        elif (rec.get("method") or "GET").upper() != "GET":
            cmd += ["-X", rec["method"]]
        cmd.append(url)
        line = " ".join(shlex.quote(c) for c in cmd)
        if args.redact:
            line = _redact(line, host)
        lines.append(line)
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- python
def emit_python(recs: list[dict], args) -> str:
    sep = '"' + '"' + '"'
    head = [
        "#!/usr/bin/env python3",
        f'{sep}由 webctl export python 生成 —— 零依赖可复现脚本。',
        "",
        "cookie 是当时会话的值，过期后先跑一次 GET / 重新拿（注释里那一行）。",
        sep,
        "import http.cookiejar, urllib.parse, urllib.request",
        "",
        "JAR = http.cookiejar.CookieJar()",
        "OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(JAR))",
        "",
        "def put_cookies(raw):",
        "    for pair in (raw or '').split(';'):",
        "        n, _, v = pair.strip().partition('=')",
        "        if n:",
        "            JAR.set_cookie(http.cookiejar.Cookie(0, n, v, None, False, HOST, False, False,",
        "                                               '/', True, False, None, True, None, None, {}))",
        "",
    ]
    lines = list(head)
    for i, rec in enumerate(recs, 1):
        url = rec.get("url", "")
        from urllib.parse import urlsplit
        s = urlsplit(url)
        host = f"{s.scheme}://{s.netloc}"
        lines += [f"# ---- [{i}] {rec.get('method')} {rec.get('path') or url}",
                  f"HOST = {json.dumps(s.hostname or '')}",
                  f"put_cookies({json.dumps(rec.get('cookies') or '')})",
                  "req = urllib.request.Request(",
                  f"    {json.dumps(url)},",
                  f"    method={json.dumps(rec.get('method') or 'GET')},"]
        body = rec.get("req_body") or ""
        if body:
            lines.append(f"    data={json.dumps(body)}.encode(),")
        hdrs = {k: v for k, v in _headers_of(rec) if k.lower() != "user-agent"}
        if hdrs:
            lines.append(f"    headers={json.dumps(hdrs)},")
        lines += [")", "with OPENER.open(req, timeout=20) as r:",
                  "    body = r.read().decode('utf-8', 'replace')",
                  f"print(r.status, len(body), r.headers.get('Content-Type'))   # 当时：{rec.get('status')} {rec.get('size')}B",
                  "print(body[:800])", ""]
    out = "\n".join(lines) + "\n"
    if args.redact:
        out = _redact(out, recs[0].get("url", "") if recs else "")
    return out


# ---------------------------------------------------------------- markdown
def emit_md(recs: list[dict], args) -> str:
    title = args.title or "请求录制（webctl export）"
    lines = [f"## {title}", "",
             f"> 由 `webctl export md` 生成于 {_dt.datetime.now():%Y-%m-%d %H:%M:%S}；"
             f"顺序即当时实际发生的顺序（共 {len(recs)} 条）。", ""]
    for i, rec in enumerate(recs, 1):
        url = rec.get("url", "")
        ck = rec.get("cookies") or ""
        cmd = ["curl", "-sS", "-i"]
        if ck:
            cmd += ["--cookie", ck]
        for k, v in _headers_of(rec):
            cmd += ["-H", f"{k}: {v}"]
        if rec.get("req_body"):
            cmd += ["-X", rec.get("method", "POST"), "--data", rec["req_body"]]
        cmd.append(url)
        line = " ".join(shlex.quote(c) for c in cmd)
        host = re.sub(r"^https?://[^/]+", "", url)
        if args.redact:
            from urllib.parse import urlsplit
            s = urlsplit(url)
            line = _redact(line, f"{s.scheme}://{s.netloc}")
        body = history.body_of(rec).decode("utf-8", "replace")
        snippet = "\n".join(body.splitlines()[:args.lines])[:args.max_chars]
        if args.redact:
            from urllib.parse import urlsplit
            snippet = _redact(snippet, urlsplit(url).netloc)
        lines += [f"### {i}. {rec.get('method')} {host}", "",
                  "```bash", line, "```", "",
                  f"结果：`{rec.get('status')} {rec.get('size')}B {rec.get('ctype','')}`", ""]
        if body.strip():
            lines += ["响应开头：", "", "```", snippet, "```", ""]
    return "\n".join(lines)


def run(args) -> int:
    recs = history.load(host_key=args.host)
    picked = _pick(args, recs)
    if not picked:
        print("[!] 没选中任何历史记录。先发几条：webctl req get \"$U/\"" +
              (f"（当前 host={args.host} 的历史：{len(recs)} 条）" if args.host else ""))
        return 1
    if args.mode == "md" and getattr(args, "no_redact", False):
        args.redact = False
    if args.mode in ("script", "sh", "bash"):
        text, ext = emit_script(picked, args), ".sh"
    elif args.mode in ("python", "py"):
        text, ext = emit_python(picked, args), ".py"
    else:
        text, ext = emit_md(picked, args), ".md"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        if ext == ".sh":
            os.chmod(args.out, 0o755)
        print(f"[导出] {args.out}（{len(picked)} 条）")
    else:
        print(text)
    if getattr(args, "note", False) and ext == ".md":
        from .note import add_to_vault_text
        p = add_to_vault_text(text, getattr(args, "title", "") or "请求录制")
        print(f"[笔记] {p}")
    return 0


def register(sub) -> None:
    p = sub.add_parser("export", help="把请求历史导成 bash / python / writeup 片段")
    v = p.add_subparsers(dest="mode", required=True)
    for name, help_ in (("script", "生成 bash（curl 一串）"), ("python", "生成零依赖 python 脚本"),
                        ("md", "生成 writeup 用的分步片段")):
        sp = v.add_parser(name, help=help_)
        sp.add_argument("--host", help="只导出某个 host 的历史（jar 名/域名）")
        sp.add_argument("--last", type=int, default=10, help="最近 N 条（默认 10）")
        sp.add_argument("--range", help="序号区间，如 3-9")
        sp.add_argument("--indices", help="指定序号，如 1,4,7")
        sp.add_argument("-o", "--out", help="写到文件（不给就打到 stdout）")
        sp.add_argument("--tag", help="只导出某种来源：req / recon / fuzz / diff / replay")
        sp.add_argument("--no-probes", action="store_true", help="排除 recon/fuzz/diff 产生的探测请求")
        if name == "md":
            sp.add_argument("--redact", action="store_true", default=True,
                            help="打码（cookie 值 → ***、主机 → <target>）—— md 默认就开")
            sp.add_argument("--no-redact", action="store_true", help="强制不打码")
            sp.add_argument("--title", default="")
            sp.add_argument("--lines", type=int, default=12, help="每条响应体截几行")
            sp.add_argument("--max-chars", type=int, default=1200)
            sp.add_argument("--note", action="store_true", help="顺手写进 vault 的 CTF/ 目录")
        else:
            sp.add_argument("--redact", action="store_true",
                            help="打码（自己跑要能真复现，所以默认不打）")
        sp.set_defaults(func=run)
