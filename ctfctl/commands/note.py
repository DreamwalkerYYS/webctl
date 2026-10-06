"""note —— 按你的九段模板生成 writeup 骨架，直接落到 Obsidian vault 的 CTF/ 目录。

    ctfctl note new --title 示例题-重复键 --platform ExampleCTF --kps 源码泄露/重复键 \
        --url http://host --flag 'FLAG{...}' --index

--index 会在 CTF/00-索引.md 的第一张表格末尾追加一行（找不到表格就只提示）。
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import shutil
import sys

from ..core.config import TEMPLATES, vault_path


def _slug(s: str) -> str:
    s = re.sub(r"[\\/:*?\"<>|\s]+", "-", s.strip())
    return s.strip("-") or "untitled"


def _template_text() -> str:
    p = os.path.join(TEMPLATES, "writeup.md")
    if os.path.exists(p):
        return open(p, encoding="utf-8").read()
    return "# {{title}}\n\n**flag：`{{flag}}`**\n"


def run_new(args) -> int:
    vault = args.vault or vault_path()
    if not vault:
        print("[!] 找不到 vault：给 --vault 或设置 OBSIDIAN_VAULT_PATH", file=sys.stderr)
        return 2
    outdir = os.path.join(vault, args.dir)
    os.makedirs(outdir, exist_ok=True)
    today = args.date or _dt.date.today().isoformat()
    parts = [p for p in (args.platform, args.title, args.kps) if p]
    name = "-".join(_slug(p) for p in parts) + ".md"
    path = os.path.join(outdir, name)
    if os.path.exists(path) and not args.force:
        print(f"[!] 已存在：{path}（要覆盖加 --force）")
        return 1
    text = _template_text()
    fm = (f"---\ntags: [CTF, Web]\n平台: {args.platform or ''}\n类型: {args.type or 'Web'}\n"
          f"日期: {today}\nflag: {args.flag or ''}\ncreated: {today}\nupdated: {today}\n---\n")
    body = text.split("---", 2)[2].lstrip("\n") if text.startswith("---") else text
    body = (body.replace("{{title}}", args.title or "")
                .replace("{{platform}}", args.platform or "")
                .replace("{{kps}}", args.kps or "")
                .replace("{{url}}", args.url or "")
                .replace("{{flag}}", args.flag or ""))
    head = f"# {args.platform or ''} - {args.title or ''}（{args.kps or '考点'}）\n\n入口：`{args.url or ''}`\n提示：（题目标题/描述/页面话术 原文照抄）\n"
    rest = body.split("\n", 1)[1] if body.startswith("#") else body
    with open(path, "w", encoding="utf-8") as f:
        f.write(fm + "\n" + head + "\n" + rest)
    print(f"[笔记] {path}")
    if args.index:
        _append_index(vault, args, today)
    return 0


def _append_index(vault: str, args, today: str) -> None:
    idx = os.path.join(vault, "CTF", "00-索引.md")
    if not os.path.exists(idx):
        print(f"[索引] 没有 {idx}，跳过")
        return
    row = (f"| {today} | {args.platform or ''} | "
           f"[[{'-'.join(_slug(p) for p in (args.platform, args.title, args.kps) if p)}]] "
           f"| {args.kps or ''} | `{args.flag or '—'}` |")
    lines = open(idx, encoding="utf-8").read().split("\n")
    last = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("|"):
            last = i
    if last is None:
        print("[索引] 没找到表格，手动加吧")
        return
    lines.insert(last + 1, row)
    open(idx, "w", encoding="utf-8").write("\n".join(lines))
    print(f"[索引] 已加一行 -> {idx}")


def add_to_vault(src_md: str, host: str, vault: str | None = None, dirname: str = "CTF") -> str:
    """把一份已有 markdown（如 recon 报告）复制进 vault。"""
    v = vault or vault_path()
    if not v:
        raise SystemExit("[!] 找不到 vault（--vault 或 OBSIDIAN_VAULT_PATH）")
    outdir = os.path.join(v, dirname)
    os.makedirs(outdir, exist_ok=True)
    stamp = _dt.date.today().isoformat()
    dst = os.path.join(outdir, f"{stamp}-recon-{_slug(host)}.md")
    shutil.copyfile(src_md, dst)
    return dst


def add_to_vault_text(text: str, title: str, vault: str | None = None, dirname: str = "CTF") -> str:
    """把一段 markdown 文本直接写成 vault 里的笔记（export md --note 用）。"""
    v = vault or vault_path()
    if not v:
        raise SystemExit("[!] 找不到 vault（--vault 或 OBSIDIAN_VAULT_PATH）")
    outdir = os.path.join(v, dirname)
    os.makedirs(outdir, exist_ok=True)
    stamp = _dt.date.today().isoformat()
    fm = (f"---\ntags: [CTF, Web]\ntype: 录制\n日期: {stamp}\ncreated: {stamp}\nupdated: {stamp}\n---\n\n")
    dst = os.path.join(outdir, f"{stamp}-{_slug(title)}.md")
    with open(dst, "w", encoding="utf-8") as f:
        f.write(fm + text)
    return dst


def register(sub) -> None:
    p = sub.add_parser("note", help="生成 writeup 骨架 / 把报告写进 vault")
    v = p.add_subparsers(dest="notecmd", required=True)
    n = v.add_parser("new", help="按九段模板新建一篇")
    n.add_argument("--title", required=True)
    n.add_argument("--platform", default="")
    n.add_argument("--type", default="Web")
    n.add_argument("--kps", default="", help="考点关键词（会进文件名）")
    n.add_argument("--url", default="")
    n.add_argument("--flag", default="")
    n.add_argument("--date", default="")
    n.add_argument("--dir", default="CTF", help="vault 里的子目录（默认 CTF）")
    n.add_argument("--vault", default="")
    n.add_argument("--index", action="store_true", help="同时在 00-索引.md 加一行")
    n.add_argument("--force", action="store_true")
    n.set_defaults(func=run_new)

    c = v.add_parser("import", help="把已有 md（如 recon 报告）复制进 vault")
    c.add_argument("src")
    c.add_argument("--host", default="target")
    c.add_argument("--vault", default="")
    c.add_argument("--dir", default="CTF")
    c.set_defaults(func=lambda a: (print("[笔记] " + add_to_vault(a.src, a.host, a.vault or None, a.dir)), 0)[1])
