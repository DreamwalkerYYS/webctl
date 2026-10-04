# webctl —— Web 题通用工具包

把"做题 SOP"压成命令：**侦察 → 联想下一步 → 打 → 记录 → 导出成 writeup**。
纯标准库、零依赖，Python 3.9+ 直接跑（你的系统 python 3.14 和 Hermes 容器里的 3.11 都能用）。
目录：`~/项目/ctf-tool`   启动器：`~/.local/bin/webctl`

```
webctl --help                 # 所有子命令（cli.py 用 pkgutil 自动发现 commands/，加功能不用改入口）
```

---

## 1. 装 / 跑

```bash
# ① 不装，直接跑（开发时最省事）
cd ~/项目/ctf-tool && python3 -m webctl --help

# ② 用启动器（已在 ~/.local/bin/webctl；PATH 里没有就加一行 export PATH="$HOME/.local/bin:$PATH"）
webctl --help

# ③ 正经装成包（可选）
pipx install -e ~/项目/ctf-tool        # 或 pip install -e . --break-system-packages
```

---

## 2. 30 秒上手（一次完整流程）

```bash
U=http://靶机:端口

webctl recon "$U"                     # ① 一把侦察：指纹/源码面/泄露文件(带假 200 判定)/常见路径
                                      #    末尾直接给「★ 最可能的 3 条」+ 可直接粘贴的命令

webctl req get "$U/?file=file:///etc/passwd"        # ② 照联想给的命令打
webctl diff live "$U/?id=1" --field id --a 1 --b "1'-- -"   # ③ 盲注判断：有差异退出码 1

webctl replay list -n 10              # ④ 回看刚才都发了什么
webctl export md --last 8 --title "多阶段 Web lab" --note   # ⑤ 导出成 writeup 片段并写进 vault
```

---

## 3. 命令参考

### req —— 会话化请求（替代手写 curl）
```
webctl req get  URL [-H 'K: V']... [-b k=v]... [--ua UA] [--proxy P] [-v] [--head]
                    [--no-follow] [--grep RE] [-o FILE] [--max N] [-q] [--jar NAME] [--new]
webctl req post URL -d k=v [-d k2=v2]... [--json '{...}'] [--ctype CT]
webctl req req  URL -X PUT --data 'raw' --ctype text/plain
```
- cookie 按 host 自动存 `~/.cache/webctl/<host>.jar`，多步流程自动带上；`--new` 开新会话
- `--grep RE` 时状态行走 stderr、stdout 只有匹配（方便 `P=$(...)` 取值）
- 自动捞 `flag{...}` / `?CTF{...}` / `QCTF{...}` 三种前缀
- 403/401 + 空响应会主动提示"这多半是出口问题，不是题目"

### recon —— 一把侦察 + 自动联想
```
webctl recon URL [--full] [--threads 4] [--delay 0.05] [--report F] [--note]
                 [--no-suggest] [--json] [--jar NAME] [--proxy P] [--ua UA]
```
五步：① 首页基线（状态/字节数/Content-Type/响应头）② 指纹（Werkzeug/PHP/Django…）
③ 源码面（注释、隐藏 input、`data-*`、表单、脚本、带参链接）④ 泄露文件 + 常见路径
⑤ 规则匹配 → **打分排序**，输出最可能的 3 条 + 可直接粘贴的命令，报告落 `~/.cache/webctl/recon-<host>.md`。

### fuzz —— 目录/参数爆破（两种引擎，都自动过滤假 200）
```
webctl fuzz "URL/FUZZ" [-w WORDLIST] [-e php,html,bak] [-X POST] [-d 'k=FUZZ'] [-H 'K: FUZZ']
                       [-mc 200,301,302,401,403] [--fs N] [--show-fake]
                       [--engine auto|ffuf|builtin] [-t 20] [--delay S] [--save DIR] [--json]
```
- `auto`：有 ffuf 就调 ffuf（**把完整命令原文打出来**，兼当 ffuf flag 教学），没有就用内置引擎
- 两条路都按「**字节数 == 首页字节数**」过滤 `try_files` 回退产生的假 200（对应 ffuf 的 `-fs`）
- `--show-fake` 把被丢掉的也显示出来；首页连不上时**自动关闭过滤**（否则会把连接错误当首页大小）

### replay —— 请求历史
```
webctl replay list [-n 20] [--host H]
webctl replay show 7 | --last [--max N]
webctl replay resend 7 | --last [-H 'K: V'] [-d 'a=b'] [-X POST] [--raw] [--diff] [--max-diff N]
```
每次请求（req/recon/fuzz/diff/browser…）都连**响应体**一起落进 `~/.cache/webctl/history/<host>/`
（`index.jsonl` + `<ts>-<sha8>.body`），含请求头、请求体、cookie、状态、字节数、body 的 sha256。
"我刚才那条到底怎么发的"不用靠回忆；`resend --diff` 改一个头/体再发，和原始响应逐行对比。

### diff —— 两次响应对比（盲注/布尔/权限差异）
```
webctl diff live URL --a 1 --b "1'-- -" [--field id] [--in-body] [-X M] [--ctype CT] [-H ...] [--save DIR]
webctl diff files A B
webctl diff history 7 8 --host H
```
打印状态/长度/Content-Type/sha256 对照 + 行级差异（difflib）。
**退出码即结论：一致 0、不一致 1** —— 可直接塞进 `for` 循环当布尔探针。

### browser —— 第二条出口（专治 403 + 空响应）
```
webctl browser URL [-X POST] [-d 'a=b'] [-H 'K: V'] [--ua UA]
                   [--cdp http://回环地址:9222] [--launch] [--no-headless] [--discover] [-v] [--grep RE]
```
容器/命令行的出口 IP 常和浏览器不是一个，靶机往往只放行其中一个。这条通道走 CDP：
1. 起（`--launch`）或连上（`--cdp`，可以指向你已登录的 Edge/Chrome）一个带 `--remote-debugging-port` 的浏览器
2. CDP 里覆盖 UA、把 Cookie 写进浏览器 jar（这两个是 `fetch` 的禁止改名单头）
3. 导航到目标**同源**站点 → 注入 `fetch` → 取回状态码/响应头/原始字节

副作用：会先对站点 `/` 发一次 GET（导航用）。另外**别用 Fetch 域拦截实现**：`Page.navigate` 的回复要等导航提交，边等回复边处理 `Fetch.requestPaused` 必死锁（Chrome 145 实测）。

### export —— 录制导出（把历史变成能复现的东西）
```
webctl export script [--last 10 | --range 3-9 | --indices 1,4,7] [-o replay.sh] [--redact]
webctl export python [...]           # 零依赖 urllib 脚本
webctl export md     [...] [--title T] [--lines 12] [--max-chars N] [--note] [--no-redact]
```
- `script`：一串 `curl`（带 cookie、头、body、方法），可直接跑
- `python`：零依赖 urllib 脚本，自带 `put_cookies()` 复现会话
- `md`：直接当 writeup 的"分步过程"（每条：命令 + 当时的状态/字节数 + 响应开头），`--note` 写进 vault
- **脱敏**：`md` 默认打码（cookie 值 → `***`、主机 → `<target>`），笔记进 vault 不怕泄；脚本/py 默认原样（要真复现），要打码加 `--redact`
- ⚠️ 历史里的 cookie 是**当时那一次会话**的值，靶机重启/会话过期后要重新拿

### cookie / jwt / codec / note / rules
```
webctl cookie list|set|del|raw|flask-unsign|flask-sign     cookie jar + Flask session 爆破与伪造
webctl jwt    decode|sign|crack [--base URL --name credential]   解 / 改字段重签 / 爆破密钥
webctl codec  b64|b64d|url|urld|hex|hexd|guess             编解码（不给参数读 stdin）
webctl note   new|import                                   九段模板 writeup / 报告进 vault
webctl rules  list|test|check                              规则表查看 / 离线试匹配 / 体检
```
- `cookie flask-sign` 的时间戳**自动回拨 60s** —— Flask 不接受"比服务端新"的签名（会整块丢弃→500）
- `jwt decode/sign` 可以 `--base URL --name credential` 直接从 cookie jar 里取令牌

---

## 4. 自动联想：怎么打分

规则表就是"看到 X → 想 Y"（`webctl/data/rules.json`）。recon 命中后按**证据**排序：

| 加分项 | 分值 | 意思 |
|---|---|---|
| 规则自带 `weight` | 默认 1 | 想强调某条规则就在 JSON 里写 `"weight": 5` |
| 每命中一类条件（header/body/param/file） | +2 | 证据类型越多越可信 |
| 命中高信号参数（file/url/cmd/id/search…） | 每个 +2 | 能直接利用的入口 > 泛泛的特征 |
| 命中真实文件（REAL，非假 200） | +3，且每个真实文件再 +1 | 扫到源码/备份是硬证据 |
| 命中正文特征（"你不是管理员"…） | +1 | 提示语属于弱证据 |

输出形如：
```
★ 最可能的 3 条（打分 = 规则权重 + 证据类型数 + 高信号参数 + 真实文件命中）

  [12分] 文件包含 / SSRF 入口  —— 可直接粘贴：
     参数名像路径/URL：试 file:// 读文件、回环地址打内网、伪协议读源码。
      webctl req get "http://靶机:8080/?file=file:///etc/passwd"
      ...

其余命中：假 200（nginx try_files 回退）(6)、JWT 令牌(5)
```
命令里的 `$U`、`<host>` 会被替换成真实地址；如果 jar 里有 `session`/`token`/`sid`，占位符也会换成真值。
`--no-suggest` 关掉联想；`--json` 里会多一个 `top` 字段给脚本用。

---

## 5. 设计取舍（三条硬约定）

1. **小包 + 统一入口**：加功能靠往 `webctl/commands/` 丢一个带 `register(sub)` 的模块，`cli.py` 用 pkgutil 自动发现 —— 不改入口、不改 `__init__`。
2. **能包一层就不重造**：目录扫描包 ffuf（打印命令原文 + 自动 `-fs`），自建部分只做小清单 + 假 200 判定；编码/JWT 用标准库自己几行搞定，不引依赖。
3. **不做 payload 库 / 半自动利用**：只做结构化请求变异（方法/头/cookie/参数/编码）；规则里的命令是**可粘贴模板**，判断权留给人。通用 payload 库最后都长成缝合怪，也把"想"这件事外包掉了。

---

## 6. 扩展指南

**A. 加一个子命令**（`webctl/commands/graphql.py`）：
```python
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
改完 `webctl --help` 里就有了。会话、输出、捞 flag、history 记录全是现成的（`Session.request` 自动记账）。

**B. 加一条「看到 X → 想 Y」**（只改 `webctl/data/rules.json`，个人补充放 `~/.config/webctl/rules.json`）：
```json
{"id": "graphql", "name": "GraphQL", "weight": 3,
 "when": {"body_re": ["/graphql", "__schema"]},
 "hint": "有 GraphQL：先 introspection 拿全 schema，再看 mutation 的权限校验。",
 "cmds": ["webctl req post \"$U/graphql\" --json '{\"query\":\"{__schema{types{name}}}\"}'"]}
```
写完 `webctl rules check` 体检、`webctl rules test --body '/graphql'` 离线试匹配。

**C. 加一组扫描词**：`webctl/data/files.json` 的 `leak` / `paths`。

**D. 加一种导出格式**：`webctl/commands/export.py` 里加 `emit_xxx()`，在 `run()` 的分支里接上。

---

## 7. 测试

```bash
cd ~/项目/ctf-tool && python3 tests/test_smoke.py        # 66 项断言
```

自带一个本地 demo 靶机（`tests/demo_server.py`），刻意复刻踩过的坑：
nginx 式**假 200**、`.php` 走真 404、`index.php.bak` 备份泄露、Werkzeug + 三段式 session、
隐藏字段与注释、JWT 串、"你不是管理员"话术、`/echo-ua`（用来验证 UA 真的送达）。
另有最小 WebSocket 回声服务端（`tests/ws_echo_server.py`）离线验证 CDP 帧格式。

想连浏览器通道一起测：先开一个调试端口，再
```bash
WEBCTL_CDP=http://127.0.0.1:9333 python3 tests/test_smoke.py
```
（会在同一次运行里多验证两条：UA 经 CDP 覆盖后真送达、POST 表单正确解码。）

---

## 8. 目录结构

```
ctf-tool/
├── pyproject.toml              # console_scripts: webctl
├── webctl/
│   ├── cli.py                  # 统一入口：pkgutil 自动发现 commands/
│   ├── __main__.py             # python3 -m webctl
│   ├── core/
│   │   ├── config.py           # 路径、UA、flag 正则、vault 定位
│   │   ├── session.py          # cookie jar 会话 + 统一请求/输出 + 请求历史记账
│   │   ├── response.py         # 响应对象（状态/头/体/落盘/捞 flag）
│   │   ├── detect.py           # 真假 200 判定（recon 与 fuzz 共用）
│   │   ├── history.py          # 请求历史的读写
│   │   ├── rules.py            # 规则加载/匹配/打分/命令渲染
│   │   └── cdp.py              # 极简 CDP 客户端（手写 WebSocket 帧，零依赖）
│   ├── commands/               # ← 加功能只动这里
│   │   ├── req.py  recon.py  fuzz.py  replay.py  diff.py  browser.py
│   │   ├── export.py  cookie.py  jwt.py  codec.py  note.py  rules.py
│   ├── data/
│   │   ├── rules.json          # 「看到 X → 想 Y」规则表
│   │   └── files.json          # 泄露文件 / 常见路径清单
│   └── templates/writeup.md    # 九段 writeup 模板
└── tests/
    ├── demo_server.py          # 本地演示靶机
    ├── ws_echo_server.py       # 最小 WS 服务端（验证 CDP 帧）
    └── test_smoke.py           # 冒烟测试
```

---

## 9. 已知边界 / 路线

- HTTP/2、WebSocket、非文本协议不支持；文件上传只给了命令模板。
- `browser` 通道目前只覆盖 `webctl browser` 自己，`req/recon/fuzz` 还走本机出口
  （想做全局换出口，需要给 `Session` 加一层执行器抽象：`--via browser`）。
- 历史不自动清理（它就是证据链），要清 `rm -rf ~/.cache/webctl/history/<host>`。
- 路线：请求录制打包分享（导出成单个可复现 HTML/脚本包）、`recon --via browser`、
  规则自动联想再加一层"这条规则在你的靶机上最可能从哪个参数入手"的具体定位。

---

## 10. 变更日志

- **0.4** — `export`（script/python/md 三种录制导出，md 默认脱敏 + 可写进 vault）；recon **自动联想**（按证据打分、命令替换真地址与真 cookie 值）；README 重写为完整手册
- **0.3.1** — `browser` 通道改「同源 fetch」（避开 `Page.navigate` 死锁）；demo 加 `/echo-ua`
- **0.3** — `replay`（请求历史 + 重放改包 + diff）、`diff`（盲注/布尔探针）、`browser`（CDP 第二出口）
- **0.2** — `fuzz`（ffuf/内置双引擎，自动过滤假 200）
- **0.1** — `req` / `recon` / `cookie` / `jwt` / `codec` / `note` / `rules`；core 分层 + 规则表数据化
