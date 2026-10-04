"""recon —— 一把跑完侦察，并给出"下一步"建议。

对应你笔记里的通用五步（②定指纹 ③扫一遍 ④判族）：
  1) 首页基线：状态/字节数/Content-Type/响应头
  2) 指纹：响应头 + 正文标记 → 语言框架判断
  3) 源码面：注释、隐藏字段、data-*、表单 action、脚本、带参链接
  4) 泄露文件 + 常见路径：**按字节数 + Content-Type 判真假 200**
  5) 规则表匹配 → 打印「看到 X → 想 Y」+ 可粘贴命令，并落一份 markdown 报告
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..core import rules as rules_mod
from ..core.config import CACHE, DATA, ensure_dirs
from ..core.detect import classify
from ..core.session import Session, emit


def _load(name: str) -> dict:
    with open(os.path.join(DATA, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def scan(sess: Session, cands: list[str], base_size: int, base_ctype: str, html_ct: list[str],
         delay: float, threads: int) -> list[tuple[str, str, int, str]]:
    def one(path: str):
        time.sleep(delay)
        r = sess.request("GET", path)
        return path, classify(r, base_size, base_ctype, html_ct), r.size, r.ctype

    with ThreadPoolExecutor(max(1, threads)) as ex:
        return list(ex.map(one, cands))


def fingerprint(resp, body: str) -> list[str]:
    out = []
    h = resp.raw_headers
    if "werkzeug" in resp.header("server").lower() or "flask" in (resp.text + str(h)).lower():
        out.append("Flask / Werkzeug")
    if resp.header("x-powered-by"):
        out.append(f"X-Powered-By: {resp.header('x-powered-by')}")
    if resp.header("server"):
        out.append(f"Server: {resp.header('server')}")
    for kw, name in (("wp-content", "WordPress"), ("laravel", "Laravel"), ("django", "Django"),
                     ("graphql", "GraphQL"), (".jsp", "Java/JSP"), (".aspx", "ASP.NET")):
        if kw in body.lower():
            out.append(name)
    if not out:
        out.append("未识别到明显指纹（看 Server/Set-Cookie/报错页）")
    return out


def source_surface(body: str) -> dict:
    return {
        "comments": sorted(set(re.findall(r"<!--([\s\S]{0,400}?)-->", body)))[:20],
        "hidden_inputs": re.findall(r"<input[^>]*type=[\"']?hidden[\"']?[^>]*>", body, re.I)[:20],
        "data_attrs": sorted(set(re.findall(r"data-[a-z0-9_\-]+=\"[^\"]{0,200}\"", body, re.I)))[:40],
        "scripts": sorted(set(re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.I)))[:20],
        "forms": re.findall(r"<form[^>]*>", body, re.I)[:10],
        "param_links": sorted(set(re.findall(r"[\w./?=&%-]+\?[\w=&%.-]+", body)))[:40],
        "params": sorted(set(re.findall(r"[?&]([A-Za-z_][\w\-]{0,30})=", body)))[:60],
    }


def run(args) -> int:
    ensure_dirs()
    files = _load("files")
    html_ct = files.get("html_ct", ["text/html"])
    url = args.url
    u = urllib.parse.urlsplit(url)
    base = f"{u.scheme}://{u.netloc}" if u.scheme else url
    sess = Session(base=base, jar_name=args.jar, new=args.new, proxy=args.proxy,
                   timeout=args.timeout, ua=args.ua, verbose=args.verbose)

    print(f"=== webctl recon  {base} ===")
    home = sess.request("GET", "/")
    body = home.text
    print(f"[基线] {home.summary()}")
    for k, v in home.raw_headers.items():
        print(f"   {k}: {v}")

    print("\n[指纹]")
    for f in fingerprint(home, body):
        print(f"   - {f}")

    surf = source_surface(body)
    print("\n[源码面]")
    for key, label in (("comments", "注释"), ("hidden_inputs", "隐藏字段"), ("data_attrs", "data-* 属性"),
                       ("forms", "表单"), ("scripts", "脚本"), ("params", "URL 参数")):
        vals = surf[key]
        if vals:
            print(f"   {label}({len(vals)}):")
            for v in vals[:8]:
                print("     " + (v if len(v) < 160 else v[:157] + "..."))

    leak = files["leak"] if args.full else files["leak"][:24]
    paths = files["paths"] if args.full else files["paths"][:16]
    print(f"\n[泄露文件] 扫 {len(leak)} 条（--full 全量）")
    found, fake_n = [], 0
    for path, cls, size, ctype in scan(sess, leak, home.size, home.ctype, html_ct, args.delay, args.threads):
        if cls == "FAKE":
            fake_n += 1
        elif cls in ("REAL", "EMPTY(存在但无输出)", "200?"):
            found.append(path)
            print(f"   {cls:14s} {size:>8}B {ctype or '?':28s} /{path}")
    if not found:
        print("   （没有非假 200 的命中）")
    if fake_n:
        print(f"   [注] 另有 {fake_n} 条是假 200（nginx try_files 回退首页，字节数与首页一致）—— 别当成命中")

    print(f"\n[常见路径] 扫 {len(paths)} 条")
    for path, cls, size, ctype in scan(sess, paths, home.size, home.ctype, html_ct, args.delay, args.threads):
        if cls not in ("404", "FAKE"):
            print(f"   {cls:14s} {size:>8}B {ctype or '?':28s} {path}")

    # ---- 规则匹配：给下一步 ----
    ctx = {
        "headers": "\n".join(f"{k}: {v}" for k, v in home.raw_headers.items()),
        "body": body,
        "params": surf["params"] + surf["param_links"],
        "files": found + (["FAKE"] if fake_n else []),
    }
    hits = rules_mod.match(ctx)
    if home.status in (403, 401) and home.size == 0:
        ctx["_force"] = {"egress_403"}
        hits = rules_mod.match(ctx)

    print(f"\n[下一步] 命中 {len(hits)} 条规则（webctl rules list 看全部）")
    ranked = rules_mod.rank(hits, ctx)
    subs = {}
    for c in sess.jar:                       # 能用真值替换的就替换掉，命令直接可跑
        if c.name == "session":
            subs["<session 值>"] = c.value
        elif c.name in ("token", "credential", "jwt"):
            subs["$TOKEN"] = c.value
        elif c.name == "sid":
            subs["<你的sid>"] = c.value
    top = [] if getattr(args, "no_suggest", False) else ranked[:3]
    if top:
        print("★ 最可能的 " + str(len(top)) + " 条（打分 = 规则权重 + 证据类型数 + 高信号参数 + 真实文件命中）")
    for sc, r in top:
        print(f"\n  [{sc}分] {r['name']}  —— 可直接粘贴：")
        print(f"     {r['hint']}")
        for c in rules_mod.render_cmds(r, base, subs):
            print(f"      {c}")
    rest = ranked[len(top):]
    if rest:
        print("\n其余命中：" + "、".join(f"{r['name']}({sc})" for sc, r in rest))
    if not top and ranked:
        print("（--no-suggest 已关掉自动联想；`webctl rules list -v` 看全部规则）")

    # ---- 报告落盘 ----
    host = u.netloc or base
    rep = args.report or os.path.join(CACHE, f"recon-{host.replace(':', '_')}.md")
    lines = [f"# recon {base}", f"", f"- 基线：{home.summary()}",
             f"- 指纹：" + " / ".join(fingerprint(home, body)), ""]
    if ranked:
        lines += ["## 最可能的下一步（按证据打分）", ""]
        for sc, r in ranked[:3]:
            lines.append(f"### [{sc}分] {r['name']}")
            lines.append("")
            lines.append(r["hint"])
            lines.append("")
            lines.append("```bash")
            lines += rules_mod.render_cmds(r, base, subs)
            lines.append("```")
            lines.append("")
        if len(ranked) > 3:
            lines.append("其余命中：" + "、".join(f"{r['name']}({sc})" for sc, r in ranked[3:]))
            lines.append("")
    lines += ["## 全部命中规则"] + [f"- **{r['name']}**（{sc}分）：{r['hint']}" for sc, r in ranked] or ["- （无）"]
    lines += ["", "## 真实存在的文件/路径"] + ([f"- {p}" for p in found] or ["- （无）"])
    lines += ["", "## 源码面"]
    for key, label in (("comments", "注释"), ("hidden_inputs", "隐藏字段"), ("data_attrs", "data-*"),
                       ("scripts", "脚本"), ("params", "参数")):
        if surf[key]:
            lines.append(f"- {label}: " + "; ".join(str(v) for v in surf[key][:10]))
    os.makedirs(os.path.dirname(os.path.abspath(rep)), exist_ok=True)
    with open(rep, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\n[报告] {rep}")
    if args.note:
        from .note import add_to_vault
        p = add_to_vault(rep, host)
        print(f"[笔记] {p}")
    if args.json:
        print(json.dumps({"base": base, "baseline": home.status, "found": found,
                          "rules": [r["id"] for r in hits],
                          "top": [r["id"] for _sc, r in ranked[:3]],
                          "params": surf["params"]}, ensure_ascii=False, indent=1))
    return 0


def register(sub) -> None:
    p = sub.add_parser("recon", help="一把跑完侦察：指纹/源码面/泄露文件/常见路径 + 下一步建议")
    p.add_argument("url", help="站点地址，如 http://host:8080")
    p.add_argument("--jar", help="用哪份 cookie jar")
    p.add_argument("--new", action="store_true", help="新会话（清空该 host 的 jar）")
    p.add_argument("--proxy", help="走代理（Burp 等）")
    p.add_argument("--ua", help="User-Agent")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--full", action="store_true", help="扫完整清单（默认只扫高频前若干条）")
    p.add_argument("--threads", type=int, default=4, help="并发（默认 4，别把靶机打挂）")
    p.add_argument("--delay", type=float, default=0.05, help="每个请求间隔秒数")
    p.add_argument("--report", help="报告落盘路径")
    p.add_argument("--note", action="store_true", help="报告同时写进 Obsidian vault 的 CTF/ 目录")
    p.add_argument("--no-suggest", action="store_true", help="关掉自动联想（只列规则名）")
    p.add_argument("--json", action="store_true", help="额外输出 JSON 摘要")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=run)
