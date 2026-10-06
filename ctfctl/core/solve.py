"""solve —— 解题状态机：把「一轮探测」变成「持续推进直到出 flag 或走不动」。

设计要点（和之前"不做半自动利用"的红线共存）：
  · 工具负责**机械推进**：把每步输出里的新证据抠出来（flag、路径、参数、令牌、报错、状态变化），
    据此重算下一步该做什么，并去重「已经试过的」——避免原地打转。
  · **自动推进只跑两类动作**：ctfctl 自己的子命令（kind=cmd）与**只读探针**（探针表里那几十个）。
    shell 类（外部利用工具）永远要人按一下才跑 —— 判断权仍在人这边。
  · 每步都留痕（含负结果）。状态可存盘，重开能接着走。

    st = SolveState(target)          # 新建或从 ~/.cache/ctfctl/solve/<key>.json 恢复
    st.advance(limit=3)              # 推进最多 3 步，返回本轮日志
    st.flags                        # 到目前为止的 flag 候选（原文）
    st.report()                     # 给人读的总结（阶段/已试/新证据/候选 flag）
"""
from __future__ import annotations

import json
import os
import re
import time

from . import advise as advise_mod
from .config import CACHE, ensure_dirs

FLAG_RE = re.compile(r"(?<![A-Za-z0-9_.])([A-Za-z0-9_?]{1,24}\{[^}\n]{2,200}\})")
PATH_RE = re.compile(r"""(?<![\w])(/(?:[A-Za-z0-9_\-.]{1,40}/){0,6}[A-Za-z0-9_\-.]{1,60}\.(?:php|phtml|bak|old|zip|tar|gz|txt|log|json|js|html|py|rb|go|env|yml|sql|db|swp|swo|un~|htaccess))""")
URL_RE = re.compile(r"""https?://[^\s"'<>)\]]{4,200}""")
PARAM_RE = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_\-]{0,30})=""")
FORM_RE = re.compile(r"""<input[^>]+name=["']?([A-Za-z_][A-Za-z0-9_\-]{0,30})""", re.I)
DATA_RE = re.compile(r"""data-([a-z0-9_\-]{2,30})=["']([^"']{0,60})["']""", re.I)
JWT_RE = re.compile(r"""\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{0,}""")
B64_RE = re.compile(r"""(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])""")
ERR_RE = re.compile(r"""(SQL syntax|mysql_|You have an error in your SQL|Warning: |Notice: |Fatal error|"
                     r"Traceback \(most recent|undefined constant|Use of undefined|Permission denied|"
                     r"No such file|failed to open stream|Uncaught|XPath|stack trace)""", re.I)
STATUS_RE = re.compile(r"""^\s*(?:\[?)(\d{3})(?:\]?)\s+(\d+)B""")
REAL_RE = re.compile(r"""^\s*(REAL|EMPTY[^\s]*|200\?)\s+(\d+)B\s+(\S*)\s+(\/\S+)""")

#: 只读探针：明确不写文件、不执行命令、不提交任何东西。命中率靠的是"看响应差异"。
#: 每个参数最多试这几个值（信息量/成本比最高的一组；都只读，不改服务端状态）
PROBE_PARAM_VALUES = ["1", "'", "1'-- -", "../../../../etc/passwd", "{{7*7}}"]
PROBE_COOKIES = [{"role": "admin"}, {"is_admin": "1"}]
MAX_PARAM_PROBES = 5          # 最多对几个参数做探针
MAX_PATH_PROBES = 8           # 最多访问几个新发现的路径
MAX_PROBES_PER_ROUND = 24     # 一轮探针总数上限（免得清单爆炸）


def _key(target: str) -> str:
    k = re.sub(r"[^\w.\-]+", "_", target.strip())[:80]
    return k or "target"


class SolveState:
    def __init__(self, target: str, kind: str = "", load: bool = True):
        self.target = target.strip()
        self.kind = kind or ("web" if self.target.startswith(("http://", "https://")) else "file")
        self.stage = "recon"
        self.evidence: dict = {"params": [], "paths": [], "files": [], "urls": [], "tokens": [],
                               "errors": [], "findings": [], "bare_b64": [], "data_attrs": []}
        self.tried: list[dict] = []          # 每步：{render, kind, rc, summary, new}
        self.tried_keys: set[str] = set()
        self.actions: list[dict] = []        # 当前待选动作
        self.flags: list[str] = []
        self.log: list[str] = []
        self.steps = 0
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        if load:
            self._load()

    # ------------------------------------------------------------ 存/取
    def path(self) -> str:
        return os.path.join(CACHE, "solve", _key(self.target) + ".json")

    def _load(self) -> None:
        try:
            d = json.load(open(self.path(), encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for k in ("stage", "evidence", "flags", "steps", "started"):
            if k in d:
                setattr(self, k, d[k])
        self.tried = d.get("tried", [])
        self.tried_keys = {t.get("render", "") for t in self.tried}
        self.log = d.get("log", [])[-200:]

    def save(self) -> None:
        ensure_dirs()
        os.makedirs(os.path.dirname(self.path()), exist_ok=True)
        json.dump({"target": self.target, "kind": self.kind, "stage": self.stage,
                   "evidence": self.evidence, "tried": self.tried[-200:],
                   "flags": self.flags, "steps": self.steps, "started": self.started},
                  open(self.path(), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    # ------------------------------------------------------------ 证据摄取
    def ingest(self, text: str) -> list[str]:
        """从一步的输出里抠新证据，返回「新发现了什么」（去重后的短句）。"""
        if not text:
            return []
        new: list[str] = []
        for f in FLAG_RE.findall(text):
            if f not in self.flags:
                self.flags.append(f)
                new.append(f"flag 候选：{f}")
        ev = self.evidence

        def add(bucket: str, values, label: str) -> None:
            for v in values:
                v = str(v).strip()
                if v and v not in ev[bucket]:
                    ev[bucket].append(v)
                    new.append(f"{label}：{v}")

        add("paths", PATH_RE.findall(text), "路径")
        add("urls", [u for u in URL_RE.findall(text) if u != self.target], "链接")
        add("params", PARAM_RE.findall(text), "参数")
        add("params", FORM_RE.findall(text), "表单字段")
        add("tokens", JWT_RE.findall(text), "JWT")
        add("data_attrs", [f"data-{a}={b}" for a, b in DATA_RE.findall(text)], "data 属性")
        add("bare_b64", [b for b in B64_RE.findall(text) if len(b) > 24][:20], "可疑 base64")
        errs = ERR_RE.findall(text)
        if errs:
            add("errors", sorted(set(e.strip() for e in errs)), "报错特征")
        m = STATUS_RE.findall(text)
        if m:
            new.append("状态/长度：" + "、".join(f"{a} {b}B" for a, b in m[:6]))
        for cls, size, ctype, path in REAL_RE.findall(text):
            if cls != "404":
                add("files", [f"{path}（{cls} {size}B）"], "真实文件")
        if self.stage == "recon" and (ev["paths"] or ev["params"] or ev["files"] or ev["errors"]):
            self.stage = "probe"
        if ev["tokens"]:
            self.stage = "session"
        if self.flags:
            self.stage = "flag"
        self.evidence["findings"] = sorted(set(self.evidence.get("findings", []) + [
            x.split("：")[0] for x in new if not x.startswith("状态/长度")]))
        return new

    # ------------------------------------------------------------ 动作生成
    def _evidence_for_advice(self) -> dict:
        ev = self.evidence
        return {"kind": "web" if self.kind == "web" else self.kind,
                "body": " ".join(ev["errors"] + ev["paths"] + ev["tokens"] + ev["data_attrs"]),
                "headers": "", "params": ev["params"] + [p.rsplit("/", 1)[-1] for p in ev["paths"]],
                "files": ev["files"], "findings": ev["findings"]}

    def probes(self) -> list[dict]:
        """只读探针：参数试几个常见值、新路径 GET 一次、cookie 角色试两种。

        有上限（MAX_*）：探针是"看响应差异"用的，不是炮台；值做 URL 编码，
        免得客户端自己把请求弄坏（含空格/控制字符的 URL urllib 会直接抛错）。
        """
        import urllib.parse
        out: list[dict] = []
        base = self.target.rstrip("/")
        # 高信号参数优先（file/url/cmd/id/search 这类 → advice 里那套 HIGH_SIGNAL 直觉）
        hot = {"file", "path", "url", "src", "include", "page", "cmd", "exec", "system", "do",
               "run", "shell", "code", "eval", "id", "search", "q", "keyword", "name", "template"}
        params = sorted(self.evidence["params"], key=lambda x: (x.lower() not in hot, x))[:MAX_PARAM_PROBES]
        for p in params:
            for v in PROBE_PARAM_VALUES:
                if p in ("FUZZ", "fuzz"):
                    continue
                enc = urllib.parse.quote(v, safe="")
                q = f"{base}/?{p}={enc}"
                out.append({"label": f"探针 参数 {p} = {v[:24]}", "kind": "cmd",
                            "argv": ["req", "get", q, "-q"], "render": f"ctfctl req get \"{q}\" -q",
                            "why": "看响应差异（长度/报错/内容变化）", "probe": True, "rule_name": "只读探针"})
        if len(out) > MAX_PROBES_PER_ROUND:
            out = out[:MAX_PROBES_PER_ROUND]
        for path in self.evidence["paths"][:MAX_PATH_PROBES]:
            u = path if path.startswith("http") else base + path
            out.append({"label": f"探针 访问 {path}", "kind": "cmd", "argv": ["req", "get", u, "-q"],
                        "render": f"ctfctl req get \"{u}\" -q", "probe": True, "rule_name": "只读探针"})
        for tok in self.evidence["tokens"][:3]:
            out.append({"label": "解这个 JWT 的 payload", "kind": "cmd", "argv": ["jwt", "decode", tok],
                        "render": f"ctfctl jwt decode <token>", "probe": True, "rule_name": "只读探针"})
        for ck in PROBE_COOKIES[:2]:
            if self.evidence["errors"] or self.evidence["params"]:
                kv = " ".join(f"-b {k}={v}" for k, v in ck.items())
                out.append({"label": f"试身份 cookie {ck}", "kind": "cmd",
                            "argv": ["req", "get", base + "/", "-q"] + sum([["-b", f"{k}={v}"] for k, v in ck.items()], []),
                            "render": f"ctfctl req get \"{base}/\" {kv}", "probe": True, "rule_name": "只读探针"})
        return out

    def refresh_actions(self) -> list[dict]:
        """重算待选动作 = 规则/建议表命中的动作 + 只读探针，全部去掉已经试过的。"""
        ev = self._evidence_for_advice()
        ranked = advise_mod.rank(advise_mod.match(ev), ev)
        acts = [a for a in advise_mod.actions_flat(ranked, {"{url}": self.target, "{path}": self.target})
                if not a.get("probe")]
        if self.kind != "web":
            # 文件类：把「自动闭环」放最前（编码链/古典/XOR/压缩包/图片/元数据，判定器裁决）
            acts.insert(0, {"label": "自动闭环：类型初筛 + 编码/古典/XOR/压缩包/图片/元数据",
                            "kind": "cmd", "argv": ["auto", self.target],
                            "render": f"ctfctl auto \"{self.target}\"",
                            "why": "这几类有确定性判定器，能自动推到出结果或明确未决项",
                            "rule_name": "自动闭环"})
        if not (self.evidence["params"] or self.evidence["paths"] or self.evidence["files"]
                or self.evidence["urls"] or self.flags):
            acts.insert(0, {"label": "先做一轮分析（侦察／初筛）", "kind": "cmd",
                            "argv": ["go", self.target], "render": f"ctfctl go \"{self.target}\"",
                            "why": "还没有任何证据，先把事实摸回来", "rule_name": "起手"})
        if self.kind == "web":
            acts += self.probes()
        fresh = []
        seen = set()
        for a in acts:
            k = a.get("render") or a.get("label")
            if k in self.tried_keys or k in seen:
                continue
            seen.add(k)
            fresh.append(a)
        self.actions = fresh
        return self.actions

    # ------------------------------------------------------------ 推进
    def step(self, action: dict | None = None) -> dict:
        """执行一步（不给 action 就取第一个待选）。返回 {action, rc, output, new}。"""
        from .workbench import run_action
        if action is None:
            self.refresh_actions()
            if not self.actions:
                return {"action": None, "rc": 0, "output": "", "new": [], "note": "没有新动作了"}
            action = self.actions[0]
        render = action.get("render") or action.get("label")
        self.log.append(f"\n$ {render}")
        rc, out = run_action(action)
        self.log.append(out.rstrip())
        new = self.ingest(out)
        self.tried.append({"render": render, "kind": action.get("kind"), "rc": rc,
                           "summary": (out.strip().splitlines() or [""])[-1][:160], "new": new,
                           "label": action.get("label", ""), "ts": time.strftime("%H:%M:%S")})
        self.tried_keys.add(render)
        self.steps += 1
        self.refresh_actions()
        self.save()
        return {"action": action, "rc": rc, "output": out, "new": new}

    def advance(self, limit: int = 3, budget_s: float = 60.0, stop_on_flag: bool = True) -> list[dict]:
        """连着推进几步：每步结束都重算动作；没有新证据/没有新动作/超预算/拿到 flag 就停。"""
        t0 = time.time()
        results: list[dict] = []
        for _ in range(max(1, limit)):
            if time.time() - t0 > budget_s:
                results.append({"note": f"超预算 {budget_s}s，停下（可以再点继续）", "new": []})
                break
            r = self.step()
            results.append(r)
            if r.get("note"):
                break
            if stop_on_flag and self.flags:
                results.append({"note": f"发现 flag 候选：{self.flags[-1]}", "new": []})
                break
            if not r.get("new"):
                results.append({"note": "这一步没带来新证据；换方向或人工介入", "new": []})
                break
        self.save()
        return results

    # ------------------------------------------------------------ 总结
    def report(self) -> str:
        ev = self.evidence
        L = [f"=== 解题状态 {self.target} ===",
             f"  阶段：{self.stage}   已推进 {self.steps} 步   开始于 {self.started}"]
        if self.flags:
            L.append("  ★ flag 候选：" + "、".join(self.flags))
        for name, key, n in (("参数", "params", 12), ("路径", "paths", 12), ("真实文件", "files", 8),
                             ("令牌", "tokens", 4), ("报错特征", "errors", 6),
                             ("data 属性", "data_attrs", 8), ("可疑 base64", "bare_b64", 6)):
            if ev.get(key):
                L.append(f"  {name}（{len(ev[key])}）：" + "、".join(ev[key][:n]))
        if ev.get("findings"):
            L.append("  证据标签：" + "、".join(ev["findings"]))
        if self.tried:
            L.append("  已试过（含负结果）：")
            for t in self.tried[-10:]:
                mark = "★" if "：" in "".join(t.get("new") or []) and "flag" in "".join(t.get("new") or []) else " "
                L.append(f"    {mark}[{t.get('ts')}] {t.get('render')} → {t.get('summary')}")
        acts = self.actions or self.refresh_actions()
        if acts:
            L.append(f"  下一步可选（{len(acts)} 条，按序号跑）：")
            for i, a in enumerate(acts[:8], 1):
                L.append(f"    {i}) {a.get('label')}  ← {a.get('render')}")
        else:
            L.append("  没有可自动推进的动作了：要么已到需要人工判断的关口，要么该换工具（ctfctl fuzz / browser / 外部脚本）")
        return "\n".join(L)


def load_or_new(target: str) -> SolveState:
    return SolveState(target, load=True)
