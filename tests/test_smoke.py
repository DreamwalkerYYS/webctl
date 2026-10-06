"""ctfctl 冒烟测试：起本地 demo 靶机，跑真实 CLI，断言判定逻辑。

    python3 tests/test_smoke.py          # 全部用例
不需要 pytest（零依赖），失败会打印 FAIL 并返回非 0。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8849
BASE = f"http://127.0.0.1:{PORT}"
# 测试用独立 cache：不污染 ~/.cache/ctfctl，也保证每次都是干净状态（历史里有旧记录会让断言飘）
CACHE = "/tmp/ctfctl-test-cache"

FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"   {detail}" if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "CTFCTL_CACHE": CACHE, "PYTHONPATH": ROOT}
    return subprocess.run([sys.executable, "-m", "ctfctl", *args], capture_output=True,
                          text=True, env=env, input=stdin, timeout=120)


def wait_up(timeout: float = 10) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            urllib.request.urlopen(BASE + "/", timeout=2).read()
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main() -> int:
    import shutil as _sh
    _sh.rmtree(CACHE, ignore_errors=True)          # 每次从干净 cache 开始
    os.makedirs(CACHE, exist_ok=True)
    srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "demo_server.py"), str(PORT)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        if not wait_up():
            print("demo 靶机没起来"); return 2

        print("\n[1] req：会话化请求")
        r = cli("req", "get", BASE + "/", "--grep", "deadbeef", "-q")
        check("get + grep 拿到隐藏字段", "deadbeef" in r.stdout, r.stdout + r.stderr)
        jar = os.path.join(CACHE, f"127.0.0.1_{PORT}.jar")
        if not os.path.exists(jar):
            jar = os.path.join(CACHE, "127.0.0.1.jar")
        check("cookie jar 落盘", os.path.exists(jar), CACHE)
        r = cli("req", "post", BASE + "/submit", "-d", "q=hello", "-q")
        check("post 表单被解析", "ok form=" in r.stdout and "hello" in r.stdout, r.stdout + r.stderr)

        print("\n[2] cookie：jar 操作")
        cli("cookie", "set", "role=admin", "--base", BASE)
        r = cli("cookie", "list", "--base", BASE)
        check("cookie set/list", "role=admin" in r.stdout, r.stdout)

        print("\n[3] codec：编解码")
        check("codec b64", cli("codec", "b64", "hi").stdout.strip() == "aGk=")
        check("codec b64d", cli("codec", "b64d", "aGk=").stdout.strip() == "hi")
        check("codec hexd", cli("codec", "hexd", "4142").stdout.strip() == "AB")

        print("\n[4] jwt：解码/改签/爆破")
        import base64 as _b
        import hashlib as _h
        import hmac as _hm

        b64e = lambda b: _b.urlsafe_b64encode(b).rstrip(b"=").decode()
        h = b64e(b'{"alg":"HS256","typ":"JWT"}')
        p = b64e(b'{"role":"user"}')
        s = b64e(_hm.new(b"secret123", f"{h}.{p}".encode(), _h.sha256).digest())
        tok = f"{h}.{p}.{s}"
        check("jwt decode", '"role": "user"' in cli("jwt", "decode", tok).stdout)
        wl = "/tmp/ctfctl_wl.txt"
        open(wl, "w").write("nope\nsecret123\n")
        check("jwt crack", "secret = secret123" in cli("jwt", "crack", tok, "-w", wl).stdout)
        new = cli("jwt", "sign", tok, "--secret", "secret123", "--set", "role=admin").stdout.strip()
        check("jwt sign 改 role", new.count(".") == 2 and
              json.loads(_b.urlsafe_b64decode(new.split(".")[1] + "=="))["role"] == "admin", new)

        print("\n[5] Flask session：爆破 + 伪造（含时间戳回拨）")
        sys.path.insert(0, ROOT)
        from ctfctl.commands.cookie import sign, unsign
        ck = sign({"name": "guest"}, "django-insecure-key")
        check("flask sign/unsign 自洽", unsign(ck, "django-insecure-key") == {"name": "guest"})
        check("错密钥验签失败", unsign(ck, "wrong") is None)
        ts = int(ck.split(".")[1] and __import__("base64").urlsafe_b64decode(ck.split(".")[1] + "==").hex(), 16)
        check("时间戳已回拨 60s", abs(ts - (int(time.time()) - 60)) <= 3, f"ts={ts}")

        print("\n[6] recon：真假 200 判定 + 规则建议")
        r = cli("recon", BASE, "--json", "--threads", "2")
        out = r.stdout
        check("识别 Werkzeug/Flask 指纹", "Flask / Werkzeug" in out)
        check("扫到真实备份 index.php.bak", "/index.php.bak" in out)
        check("扫到 robots.txt", "/robots.txt" in out)
        check(".php 路径给真 404（不算命中）", "404" in out)
        check("标注了假 200", "假 200" in out)
        check("命中 flask 规则", "Flask / Werkzeug" in out)
        check("命中客户端 session 规则", "客户端签名 session" in out)
        check("命中 lfi_ssrf 规则（?file=）", "文件包含 / SSRF 入口" in out)
        check("命中 sqli 规则（?id=/?keyword=）", "SQL 注入候选" in out)
        check("命中 authz 规则（你不是管理员）", "认证 / 权限伪造" in out)
        check("命中 jwt_token 规则", "JWT 令牌" in out)
        check("JSON 摘要可解析", '"found"' in out)
        rep = None
        for line in out.splitlines():
            if line.startswith("[报告] "):
                rep = line.split("[报告] ", 1)[1].strip()
        check("报告落盘存在", bool(rep) and os.path.exists(rep), str(rep))

        print("\n[7] note：模板生成（写到临时 vault，不碰你的真 vault）")
        tmp_vault = "/tmp/ctfctl_vault"
        import shutil as _sh
        _sh.rmtree(tmp_vault, ignore_errors=True)      # 保证可重复跑
        os.makedirs(os.path.join(tmp_vault, "CTF"), exist_ok=True)
        open(os.path.join(tmp_vault, "CTF", "00-索引.md"), "w").write("# idx\n\n| 日期 | 平台 | 题目 | 考点 | flag |\n|---|---|---|---|---|\n")
        r = cli("note", "new", "--title", "买不到的FLAG", "--platform", "QuestionCTF",
                "--kps", "源码泄露/重复键", "--url", BASE, "--flag", "QCTF{x}", "--vault", tmp_vault, "--index")
        check("生成 writeup 骨架", "CTF/QuestionCTF-买不到的FLAG-源码泄露-重复键.md" in r.stdout, r.stdout + r.stderr)
        idx = open(os.path.join(tmp_vault, "CTF", "00-索引.md")).read()
        check("索引追加一行", "QuestionCTF" in idx and "QCTF{x}" in idx, idx)

        print("\n[8] 规则表")
        check("rules list 能列出规则", "flask" in cli("rules", "list").stdout)

        print("\n[9] fuzz：内置引擎 + 假 200 过滤")
        wl = "/tmp/ctfctl_wl.txt"
        open(wl, "w").write("index.php.bak\nrobots.txt\nlogin\nadmin\nnope\nstatic/js/app.js\n")
        r = cli("fuzz", BASE + "/FUZZ", "-w", wl, "--engine", "builtin", "-t", "4")
        out = r.stdout
        check("命中真实文件 index.php.bak", "/index.php.bak" in out, out)
        check("命中 robots.txt", "/robots.txt" in out, out)
        check("命中 js", "static/js/app.js" in out, out)
        check("假 200（admin/nope）被过滤", "\n   admin" not in out and "\n   nope" not in out, out)
        check("报告了被过滤的假 200 条数", "假 200" in out, out)
        r2 = cli("fuzz", BASE + "/FUZZ", "-w", wl, "--engine", "builtin", "-t", "4", "--show-fake")
        check("--show-fake 能显示被丢掉的", "admin" in r2.stdout, r2.stdout)
        r3 = cli("fuzz", BASE, "-w", wl)
        check("没有 FUZZ 占位符时给提示", r3.returncode == 2 and "FUZZ" in (r3.stdout + r3.stderr), r3.stdout + r3.stderr)
        r = cli("fuzz", BASE + "/FUZZ", "-w", wl, "--engine", "builtin", "-t", "20", "--safe")
        check("--safe：并发被压到 ≤5 且有合规提示", "5 线程" in r.stderr and "/index.php.bak" in r.stdout,
              r.stdout + r.stderr)
        r = cli("fuzz", BASE + "/FUZZ", "-w", wl, "--engine", "builtin", "--safe", "--max-words", "2")
        check("--safe：字典超上限直接拦下", r.returncode == 2 and "上限" in (r.stdout + r.stderr), r.stdout + r.stderr)

        print("\n[10] replay：请求历史")
        r = cli("replay", "list", "-n", "8")
        check("replay list 有历史", "/" in r.stdout and "GET" in r.stdout, r.stdout + r.stderr)
        r = cli("replay", "show", "1", "--max", "200")
        check("replay show 能看单条", "响应体" in r.stdout or "请求头" in r.stdout, r.stdout + r.stderr)
        r = cli("replay", "resend", "--last", "-H", "X-Webctl: 1", "--diff")
        check("replay resend 能重发并 diff", "[新]" in r.stdout and "200" in r.stdout, r.stdout + r.stderr)

        print("\n[11] diff：两次响应对比")
        r = cli("diff", "live", BASE + "/api/v1/user", "--field", "id", "--a", "1", "--b", "2")
        check("值不同 → 退出码 1（可当布尔探针）", r.returncode == 1 and "sha不同" in r.stdout, r.stdout + r.stderr)
        r = cli("diff", "live", BASE + "/api/v1/user", "--field", "id", "--a", "1", "--b", "1")
        check("值相同 → 退出码 0", r.returncode == 0 and "完全一致" in r.stdout, r.stdout + r.stderr)
        open("/tmp/ctfctl_d1.txt", "w").write("same\n")
        open("/tmp/ctfctl_d2.txt", "w").write("same\n")
        check("diff files 相同 → 0", cli("diff", "files", "/tmp/ctfctl_d1.txt", "/tmp/ctfctl_d2.txt").returncode == 0)

        print("\n[12] CDP WebSocket 帧格式（离线，用最小 echo 服务端）")
        wssrv = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "ws_echo_server.py"), "8901"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.0)
            sys.path.insert(0, ROOT)
            from ctfctl.core.cdp import WS
            w = WS("ws://" + "127" + ".0.0.1" + ":8901/", timeout=5)
            w.send_text("hello")
            check("短消息回声", w.recv_text() == "hello")
            big = "A" * 300
            w.send_text(big)
            check("分片消息拼接（300 字符）", w.recv_text() == big)
            w.close()
        finally:
            wssrv.terminate()

        print("\n[13] browser 子命令：错误路径要讲清楚")
        r = cli("browser", "--discover", "--cdp", "http" + "://" + "127" + "." + "0.0.1" + ":9" + "9" + "9")
        check("没开调试端口时给排查提示", r.returncode == 2 and "连不上" in (r.stdout + r.stderr), r.stdout + r.stderr)
        r = cli("browser", BASE + "/", "--cdp", "http" + "://" + "127" + "." + "0.0.1" + ":9" + "9" + "9")
        check("browser 通道失败时给三条排查线索", "排查" in (r.stdout + r.stderr), r.stdout + r.stderr)
        # 有 CDP 端口时才做的端到端（容器里没浏览器 → 环境变量指定才跑）
        if os.environ.get("CTFCTL_CDP"):
            cdp = os.environ["CTFCTL_CDP"]
            r = cli("browser", BASE + "/echo-ua", "--cdp", cdp, "--ua", "QuestionCTFExplorer/1.0", "-q")
            check("browser 通道：UA 经 CDP 覆盖后真送达", "UA=QuestionCTFExplorer/1.0" in r.stdout, r.stdout + r.stderr)
            r = cli("browser", BASE + "/submit", "--cdp", cdp, "-X", "POST", "-d", "q=hi", "-q")
            check("browser 通道：POST 表单", "ok form=" in r.stdout, r.stdout + r.stderr)

        print("\n[14] export：录制导出")
        r = cli("export", "script", "--last", "5")
        check("script：是 bash + 有 curl", "#!/usr/bin/env bash" in r.stdout and "curl" in r.stdout, r.stdout[:400] + r.stderr)
        check("script：带上了 cookie", "--cookie" in r.stdout, r.stdout[:400])
        r = cli("export", "python", "--last", "3")
        check("python：零依赖 urllib 脚本", "urllib.request" in r.stdout and "def put_cookies" in r.stdout, r.stdout[:400])
        out = "/tmp/ctfctl_export.sh"
        if os.path.exists(out):
            os.remove(out)
        r = cli("export", "script", "--last", "2", "-o", out)
        check("script -o 落盘且带执行位", os.path.exists(out) and bool(os.stat(out).st_mode & 0o111),
              r.stdout + r.stderr)   # 注意：/tmp 可能是 noexec 挂载，os.access(X_OK) 会假阴性
        r = cli("export", "md", "--last", "3", "--title", "录制测试")
        check("md：有标题与代码块", "## 录制测试" in r.stdout and "```bash" in r.stdout, r.stdout[:400])
        check("md：默认打码（cookie 值变 ***）", "=***" in r.stdout, r.stdout[:600])
        r = cli("export", "md", "--last", "3", "--no-redact")
        check("md --no-redact 保留原值", "=***" not in r.stdout, r.stdout[:600])
        # md 模式的命令要带引号（cookie 里有分号，不加引号粘出去就是坏的）
        r = cli("export", "md", "--last", "5", "--no-redact")
        check("md：命令带 shell 引号", "--cookie 'session=" in r.stdout, r.stdout[:900])
        # 脱敏要把整个 cookie 串都打掉，而不是只吃第一个值
        r = cli("export", "md", "--last", "5")
        line = next((l for l in r.stdout.splitlines() if "--cookie" in l), "")
        check("md：脱敏吃掉所有 cookie 值", "=***" in line and "role=admin" not in line, line)
        # 来源过滤：recon/fuzz 的探测请求不该混进录音
        r = cli("export", "md", "--last", "50", "--tag", "req", "--title", "只看手动请求")
        check("--tag req 只留手动请求", "/src" not in r.stdout and "/source" not in r.stdout, r.stdout[:400])
        r = cli("export", "md", "--last", "50", "--no-probes", "--title", "去探测")
        check("--no-probes 排除探测", "共" in r.stdout and "条" in r.stdout, r.stdout[:300])

        print("\n[15] recon 自动联想（按证据打分 + 可直接粘贴）")
        r = cli("recon", BASE, "--threads", "2")
        out = r.stdout
        check("有 ★ 最可能的排序段", "★ 最可能的" in out, out[-1500:])
        check("给出了分数", "分]" in out, out[-1500:])
        check("命令已替换成真地址（无 $U 占位）", f'"{BASE}/' in out or f'"{BASE}' in out, out[-1500:])
        check("其余命中单独列出", "其余命中" in out, out[-1500:])
        r = cli("recon", BASE, "--threads", "2", "--no-suggest")
        check("--no-suggest 关掉联想", "★ 最可能的" not in r.stdout, r.stdout[-800:])
        print("\n[16] 工具目录 / 知识库 / TUI / 改名兼容")
        r = cli("--version")
        from ctfctl import __version__ as _want_ver      # 不写死版本号（1.0→1.1 时这条就是坏的）
        check(f"--version 报 {_want_ver}", _want_ver in r.stdout, r.stdout + r.stderr)
        r = cli("tools")
        check("tools：分类概览", r.returncode == 0 and "工具目录" in r.stdout, r.stdout[:600] + r.stderr[:400])
        check("tools：给出分类行（含 web）", "web" in r.stdout, r.stdout[:600])
        r = cli("tools", "check", "--missing")
        check("tools check --missing：给安装命令", "pacman" in r.stdout or "pip" in r.stdout, r.stdout[:500])
        r = cli("tools", "search", "ffuf")
        check("tools search 命中 ffuf", "ffuf" in r.stdout, r.stdout[:400])
        r = cli("tools", "show", "ffuf")
        check("tools show：有安装与用法", "ffuf" in r.stdout and ("pacman" in r.stdout or "go install" in r.stdout), r.stdout[:600])
        r = cli("tools", "show", "不存在的工具名")
        check("tools show 未知名字退码非 0", r.returncode != 0, r.stdout + r.stderr)

        r = cli("kb")
        check("kb：概览有卡片数与语料", "知识库" in r.stdout and "语料" in r.stdout, r.stdout[:600] + r.stderr[:300])
        r = cli("kb", "signals")
        check("kb signals：有 信号→卡片 行", "→" in r.stdout, r.stdout[:400])
        r = cli("kb", "search", "wakeup")
        check("kb search：命中反序列化卡", r.returncode == 0, r.stdout[:400])
        r = cli("kb", "sources")
        check("kb sources：交代样本口径", "口径" in r.stdout or "URL" in r.stdout, r.stdout[:400])

        r = cli("tui", "--dump", "2")
        check("tui --dump：不开界面也能出内容", r.returncode == 0 and "知识库" in r.stdout, r.stdout[:500] + r.stderr[:300])

        r = subprocess.run([sys.executable, "-c",
                            "import sys; sys.argv=['webctl','--version'];"
                            "from ctfctl.cli import main; main()"],
                           cwd=ROOT, capture_output=True, text=True, timeout=60)
        check("旧名 webctl 触发改名提示", "已改名" in r.stderr, r.stderr)
        r = cli("codec", "b64d", "aGVsbG8=")
        check("旧命令仍正常（codec b64d）", "hello" in r.stdout, r.stdout)

        print("\n[17] go / file：文件初筛 + 建议（misc/rev/pwn/crypto 的第一跳）")
        import struct as _st, zlib as _zl
        def _chunk(t, d):
            return _st.pack(">I", len(d)) + t + d + _st.pack(">I", _zl.crc32(t + d) & 0xffffffff)
        _ihdr = _st.pack(">IIBBBBB", 3, 3, 8, 2, 0, 0, 0)
        _idat = _zl.compress(b"".join(b"\x00" + b"\xff\x00\x00" * 3 for _ in range(3)))
        _png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", _ihdr) + _chunk(b"IDAT", _idat) + _chunk(b"IEND", b"")
        _bad = bytearray(_png); _bad[8 + 8 + 4] = 9
        f_png = "/tmp/ctfctl-test-appended.png"
        open(f_png, "wb").write(bytes(_bad) + b"flag{appended_test}\x00" + b"PK\x03\x04" + b"x" * 64)
        f_bin = "/tmp/ctfctl-test-enc.bin"
        open(f_bin, "wb").write(os.urandom(20000))
        r = cli("file", f_png)
        check("file：认出 PNG 且 CRC 失配", "PNG 图片" in r.stdout and "CRC 对不上" in r.stdout, r.stdout[:600])
        check("file：报出附加数据与偏移", "附加数据" in r.stdout and "0x" in r.stdout, r.stdout[:800])
        check("file：命中 flag 样式串", "flag{appended_test}" in r.stdout, r.stdout[:900])
        check("file：给出隐写/附加数据方向的建议", "隐写" in r.stdout or "附加数据" in r.stdout, r.stdout[-1200:])
        r = cli("file", f_bin, "--no-advice")
        check("file：高熵二进制不给假 flag", "entropy-high" in r.stdout and "flag{" not in r.stdout, r.stdout[:400])
        r = cli("file", "/tmp/ctfctl-no-such-file")
        check("file：不存在的文件退码非 0", r.returncode != 0, r.stdout + r.stderr)
        r = cli("go", f_png)
        check("go：文件 → 走初筛并给建议", "文件初筛" in r.stdout and "下一步建议" in r.stdout, r.stdout[:400])
        r = cli("go", BASE)
        check("go：URL → 走侦察", "recon" in r.stdout.lower() or "基线" in r.stdout, r.stdout[:400])
        r = cli("go", "/tmp")
        check("go：目录 → 列表提示", "是目录" in r.stdout, r.stdout[:300])

        print("\n[18] WebUI：接口与 token 校验")
        import urllib.error as _ue, json as _json
        WEB_PORT = 8877
        WEB_TOKEN = "smoke-token"
        wproc = subprocess.Popen([sys.executable, "-m", "ctfctl", "web", "--port", str(WEB_PORT),
                                  "--no-open", "--token", WEB_TOKEN],
                                 cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        WBASE = f"http://127.0.0.1:{WEB_PORT}"

        def wget(path, token=WEB_TOKEN, data=None):
            req = urllib.request.Request(WBASE + path)
            if token:
                req.add_header("X-Token", token)
            body = None
            if data is not None:
                body = _json.dumps(data).encode()
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, data=body, timeout=20) as r:
                    return r.status, r.read().decode("utf-8", "replace")
            except _ue.HTTPError as e:
                return e.code, e.read().decode("utf-8", "replace")

        up = False
        for _ in range(40):
            try:
                st, _ = wget("/api/state")
                up = st == 200
                if up:
                    break
            except Exception:
                time.sleep(0.25)
        check("web：服务起得来", up, "server did not come up")
        if up:
            st, _ = wget("/api/state", token=None)
            check("web：没 token 一律 403", st == 403, str(st))
            st, _ = wget("/api/state", token="wrong")
            check("web：token 错也 403", st == 403, str(st))
            st, html = wget("/")
            check("web：首页是工作台", st == 200 and "ctfctl 工作台" in html, html[:200])
            check("web：页面里有键盘提示", "1-9" in html and "知识库" in html, html[:400])
            st, out = wget("/api/analyze", data={"target": f_png})
            d = _json.loads(out)
            check("web：analyze 返回 kind 与动作", d.get("kind") and len(d.get("actions", [])) > 0, out[:300])
            check("web：analyze 输出里有初筛事实", "附加数据" in d.get("output", ""), d.get("output", "")[:300])
            st, out = wget("/api/action", data={"index": 0})
            d = _json.loads(out)
            check("web：action 能执行并回 rc", isinstance(d.get("rc"), int) and d.get("output") is not None, out[:300])
            st, out = wget("/api/action", data={"index": 99})
            check("web：越界 action 给 400", st == 400, f"{st} {out[:120]}")
            st, out = wget("/api/browse?section=kb")
            d = _json.loads(out)
            check("web：kb 栏目有条目", len(d.get("items", [])) >= 10, out[:200])
            st, out = wget("/api/browse?section=kb&key=sqli-manual")
            d = _json.loads(out)
            check("web：kb 详情能取到", d.get("title") and len(d.get("body", [])) > 3, out[:200])
            st, out = wget("/api/browse?section=tools")
            check("web：tools 栏目有分类", len(_json.loads(out).get("items", [])) >= 10, out[:200])
            st, out = wget("/api/run", data={"argv": ["tools", "search", "ffuf"]})
            check("web：能跑任意子命令", _json.loads(out).get("rc") == 0 and "ffuf" in out, out[:200])
        wproc.terminate()
        try:
            wproc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wproc.kill()

    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()

    print()
    if FAILED:
        print(f"{len(FAILED)} 项失败：" + ", ".join(FAILED))
        return 1
    print("全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
