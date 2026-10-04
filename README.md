# webctl —— Web 题通用工具（小包 + 统一界面）

把「做题 SOP」压成一条命令，省掉每次手搓 curl。**零依赖**（纯标准库），
Python 3.9+ 直接跑，主机系统 python 和容器里的 python 都能用。

## 装 / 跑

```bash
# 方式一：不装，直接跑（开发时最省事）
cd ~/项目/ctf-tool && python3 -m webctl --help

# 方式二：装进 PATH（已在 ~/.local/bin 放了启动器）
webctl --help

# 方式三（可选）：正经安装成包
pipx install -e ~/项目/ctf-tool        # 或 pip install -e . --break-system-packages
```

## 目前有什么

```
webctl req    get|post|req   发请求：cookie 按 host 自动持久化、任意方法/头/体、自动捞 flag
webctl recon  URL            一把跑完侦察：指纹 / 源码面 / 泄露文件 / 常见路径 + 下一步建议
webctl cookie list|set|del|raw|flask-unsign|flask-sign   cookie jar + Flask session 爆破伪造
webctl jwt    decode|sign|crack      解码 / 改字段重签 / 爆破密钥（可从 jar 取令牌）
webctl codec  b64|b64d|url|urld|hex|hexd|guess        编解码（不给参数读 stdin）
webctl note   new|import     按九段模板生成 writeup，或把报告写进 vault
webctl rules  list|test|check  规则表：查看 / 离线试匹配 / 体检
```

## 几个真实用法

```bash
U=http://靶机:端口

# 1) 侦察（几秒钟，输出「下一步」建议 + 落一份 md 报告）
webctl recon "$U"
webctl recon "$U" --full --note          # 全量清单，并把报告写进 vault 的 CTF/

# 2) 多步流程（cookie 自动带，不用手抄 sid）
webctl req get  "$U/" --no-follow -v     # 先看 303 / Location / Set-Cookie
webctl req get  "$U/st4ge1-xxxx"
webctl req post "$U/sT4ge3-xxxx" -d QuestionCTF=hello_web

# 3) 改一个 cookie 再请求（注意别只手拼 Cookie: 头，会丢 sid）
webctl cookie set taste=good --base "$U"
webctl req get "$U/5tAge4-xxxx"

# 4) 换 UA 做人设
webctl req get "$U/" --ua QuestionCTFExplorer/1.0

# 5) JWT 三连（令牌可直接从 cookie jar 取）
webctl jwt decode "$TOKEN"
webctl jwt crack "$TOKEN" -w /usr/share/wordlists/rockyou.txt
webctl jwt sign "$TOKEN" --secret <泄露的密钥> --set role=admin
webctl jwt sign --base "$U" --name credential --secret <密钥> --set role=admin

# 6) Flask session 伪造（时间戳自动回拨 60s，避开 "age in the future" 那个坑）
webctl cookie flask-crack --cookie "$SESSION" -w /usr/share/wordlists/rockyou.txt
webctl cookie flask-sign  --cookie "$SESSION" --secret <密钥> --set role=admin

# 7) 记笔记
webctl note new --title 买不到的FLAG --platform QuestionCTF --kps 源码泄露/重复键 \
  --url "$U" --flag 'QCTF{...}' --index
```

## 加功能（这个包的重点）

**A. 加一个子命令** —— 往 `webctl/commands/` 丢一个文件就行，`cli.py` 用 pkgutil 自动发现：

```python
# webctl/commands/graphql.py
from ..core.session import add_http_args, emit, session_from_args

def run(args) -> int:
    sess = session_from_args(args)
    emit(sess.request("POST", args.url, data='{"query":"{__schema{types{name}}}"}',
                      ctype="application/json"), args, jar_path=sess.jar_path)
    return 0

def register(sub) -> None:
    p = sub.add_parser("graphql", help="GraphQL introspection")
    add_http_args(p)
    p.set_defaults(func=run)
```

改完 `webctl --help` 里就有了，**不用动 cli.py / __init__.py**。

**B. 加一条「看到 X → 想 Y」** —— 只改 `webctl/data/rules.json`：

```json
{"id": "graphql", "name": "GraphQL",
 "when": {"body_re": ["/graphql", "__schema"]},
 "hint": "有 GraphQL：先 introspection 拿全 schema，再看 mutation 的权限校验。",
 "cmds": ["webctl req post \"$U/graphql\" --json '{\"query\":\"{__schema{types{name}}}\"}'"]}
```

规则是 recon「下一步」建议的唯一来源；个人补充放 `~/.config/webctl/rules.json`（随包那份升级会被覆盖）。
写完 `webctl rules check` 体检、`webctl rules test --body '...'` 离线试。

**C. 加一组扫描词** —— `webctl/data/files.json` 里的 `leak` / `paths`。

## 两个刻意的取舍

- **B（目录扫描）**：不做 ffuf 的替代品。recon 只跑内置小清单（默认 24+16 条，几秒出结果）
  并自带**假 200 判定**（按字节数 + Content-Type，不看状态码 —— 你自己踩过的那坑）。
  要上大字典时再 `ffuf -w ... -fs <首页字节数>`，不重造轮子。
- **C（利用）**：不做 payload 库 / 半自动打点。只做"结构化的请求变异"（方法/头/cookie/参数/编码）。
  通用 payload 库最后都长成缝合怪，也会把"想"这件事外包掉 —— 与"像高数那样自己啃"冲突。
  规则里的 `cmds` 是**可粘贴的模板**，判断权仍然在你手里。

## 目录结构

```
ctf-tool/
├── pyproject.toml              # console_scripts: webctl
├── webctl/
│   ├── cli.py                  # 统一入口：pkgutil 自动发现 commands/
│   ├── core/
│   │   ├── config.py           # 路径、UA、flag 正则、vault 定位
│   │   ├── session.py          # cookie jar 会话 + 统一请求/输出
│   │   ├── response.py         # 响应对象（状态/头/体/落盘/捞 flag）
│   │   └── rules.py            # 规则加载与匹配
│   ├── commands/               # ← 加功能只动这里
│   │   ├── req.py  recon.py  cookie.py  jwt.py  codec.py  note.py  rules.py
│   ├── data/
│   │   ├── rules.json          # 「看到 X → 想 Y」规则表
│   │   └── files.json          # 泄露文件 / 常见路径清单
│   └── templates/writeup.md    # 九段 writeup 模板
└── tests/
    ├── demo_server.py          # 本地演示靶机（假 200、备份泄露、JWT、Flask 头…）
    └── test_smoke.py           # 30 项冒烟测试：python3 tests/test_smoke.py
```

## 测试

```bash
cd ~/项目/ctf-tool && python3 tests/test_smoke.py
```

起一个本地 demo 靶机（复刻了 nginx 假 200、.php 真 404、备份泄露、Werkzeug+三段式 session、
隐藏字段、JWT 串、"你不是管理员"话术），跑真实 CLI 断言判定逻辑，全绿才算过。

## 已知边界 / 下一步

- HTTP/2、WebSocket、非文本协议不支持；文件上传只给了模板命令。
- 目前只有"本机出口"一种执行器。403+空响应时手动 `--proxy` 或改用浏览器 fetch
  （容器出口和主机出口 IP 不同，这是踩过的坑）。
- 想加的：`webctl fuzz`（把 ffuf 包一层，自动带首页字节数做过滤）、`webctl replay`（从历史里重放改包）、
  `webctl browser`（CDP 通道，专治出口被拒）、diff 模式（两次响应逐字段对比，用来做盲注/布尔判断）。
