"""webctl 冒烟测试：起本地 demo 靶机，跑真实 CLI，断言判定逻辑。

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
CACHE = os.path.expanduser("~/.cache/webctl")

FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"   {detail}" if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "WEBCTL_CACHE": CACHE, "PYTHONPATH": ROOT}
    return subprocess.run([sys.executable, "-m", "webctl", *args], capture_output=True,
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
        wl = "/tmp/webctl_wl.txt"
        open(wl, "w").write("nope\nsecret123\n")
        check("jwt crack", "secret = secret123" in cli("jwt", "crack", tok, "-w", wl).stdout)
        new = cli("jwt", "sign", tok, "--secret", "secret123", "--set", "role=admin").stdout.strip()
        check("jwt sign 改 role", new.count(".") == 2 and
              json.loads(_b.urlsafe_b64decode(new.split(".")[1] + "=="))["role"] == "admin", new)

        print("\n[5] Flask session：爆破 + 伪造（含时间戳回拨）")
        sys.path.insert(0, ROOT)
        from webctl.commands.cookie import sign, unsign
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
        check("命中 flask 规则", "▸ Flask / Werkzeug" in out)
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
        tmp_vault = "/tmp/webctl_vault"
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
        wl = "/tmp/webctl_wl.txt"
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
        open("/tmp/webctl_d1.txt", "w").write("same\n")
        open("/tmp/webctl_d2.txt", "w").write("same\n")
        check("diff files 相同 → 0", cli("diff", "files", "/tmp/webctl_d1.txt", "/tmp/webctl_d2.txt").returncode == 0)

        print("\n[12] CDP WebSocket 帧格式（离线，用最小 echo 服务端）")
        wssrv = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "ws_echo_server.py"), "8901"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.0)
            sys.path.insert(0, ROOT)
            from webctl.core.cdp import WS
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
