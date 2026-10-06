# ctfctl —— CTF 工具箱（原名 webctl）

把"做题 SOP"压成命令：**侦察 → 联想下一步 → 打 → 记录 → 导出成 writeup**；
再把**工具目录**（Kali / BlackArch 官方分类 + 本机装没装 + 安装命令）和
**知识库**（公开 writeup 归纳出的手法卡片）收进同一个入口，外加一个只读 TUI 面板。

纯标准库、零依赖，Python 3.9+ 直接跑（系统 python 3.14 和容器里的 3.11 都验证过）。

`MIT License` · 仓库 https://github.com/Phirisyyds/ctfctl （镜像：https://github.com/DreamwalkerYYS/ctfctl ）· 目录 `~/项目/ctf-tool` · 启动器 `~/.local/bin/ctfctl`

> **改名说明（0.5 → 1.0）**：这东西已经不只会打 Web 了，名字里的 `web` 是误导，故改名 `ctfctl`。
> - 旧命令名 `webctl` 仍可用（同一个入口，会打印一行改名提示）；启动器两份都在 `~/.local/bin/`
> - `~/.cache/webctl`、`~/.config/webctl` 首次运行**自动搬到** `~/.cache/ctfctl`、`~/.config/ctfctl`，历史请求不丢
> - 环境变量同理：`WEBCTL_CACHE` → `CTFCTL_CACHE`

```
ctfctl --help                 # 所有子命令（cli.py 用 pkgutil 自动发现 commands/，加功能不用改入口）
ctfctl tui                    # 只读面板：知识库 / 工具目录 / 规则 / 历史 / 速查
```

---

## 1. 装 / 跑

```bash
# ① 不装，直接跑（开发时最省事）
cd ~/项目/ctf-tool && python3 -m ctfctl --help

# ② 用启动器（已在 ~/.local/bin/ctfctl；PATH 里没有就加一行 export PATH="$HOME/.local/bin:$PATH"）
ctfctl --help

# ③ 正经装成包（可选）
pipx install -e ~/项目/ctf-tool                  # 本地开发式安装
pipx install git+https://github.com/Phirisyyds/ctfctl     # 或直接从仓库装
# （用 pip 的话加 --break-system-packages）
```

---

## 2. 30 秒上手（一次完整流程）

```bash
ctfctl                                  # ① 裸跑 = 工作台：t 填目标 → r 分析 → 数字键执行建议

# 或者纯命令行（不想开面板时）
U=http://靶机:端口
ctfctl go "$U"                          # ② 一条命令：判类型 → 侦察 → 给方向与可执行动作
ctfctl req get "$U/?file=file:///etc/passwd"        # ③ 照建议打
ctfctl diff live "$U/?id=1" --field id --a 1 --b "1'-- -"   # ④ 盲注判断：有差异退出码 1
ctfctl replay list -n 10                # ⑤ 回看刚才都发了什么
ctfctl export md --last 8 --title "多阶段 Web lab" --note   # ⑥ 导出 writeup 片段写进 vault

# 文件类题目（misc/rev/pwn/crypto）同理
ctfctl go ./chal.zip                    # 类型 + 结构 + 内嵌/附加数据 + 隐藏串 + 保护机制 → 建议
ctfctl file ./pwn_chal --strings 30     # 只想看事实就行
```

**只记三条**：`ctfctl`（开面板）· `ctfctl go <URL或文件>`（一条命令出方向）· `ctfctl kb signals`（看到 X 想 Y 的总表）。
其余子命令都能在面板里按 `i` 直接敲，或从 `ctfctl --help` 找。

---

## 3. 命令参考

### req —— 会话化请求（替代手写 curl）
```
ctfctl req get  URL [-H 'K: V']... [-b k=v]... [--ua UA] [--proxy P] [-v] [--head]
                    [--no-follow] [--grep RE] [-o FILE] [--max N] [-q] [--jar NAME] [--new]
ctfctl req post URL -d k=v [-d k2=v2]... [--json '{...}'] [--ctype CT]
ctfctl req req  URL -X PUT --data 'raw' --ctype text/plain
```
- cookie 按 host 自动存 `~/.cache/ctfctl/<host>.jar`，多步流程自动带上；`--new` 开新会话
- `--grep RE` 时状态行走 stderr、stdout 只有匹配（方便 `P=$(...)` 取值）
- 自动捞 `flag{...}` / `?CTF{...}` / `QCTF{...}` 三种前缀
- 403/401 + 空响应会主动提示"这多半是出口问题，不是题目"

### recon —— 一把侦察 + 自动联想
```
ctfctl recon URL [--full] [--threads 4] [--delay 0.05] [--report F] [--note]
                 [--no-suggest] [--json] [--jar NAME] [--proxy P] [--ua UA]
```
五步：① 首页基线（状态/字节数/Content-Type/响应头）② 指纹（Werkzeug/PHP/Django…）
③ 源码面（注释、隐藏 input、`data-*`、表单、脚本、带参链接）④ 泄露文件 + 常见路径
⑤ 规则匹配 → **打分排序**，输出最可能的 3 条 + 可直接粘贴的命令，报告落 `~/.cache/ctfctl/recon-<host>.md`。

### fuzz —— 目录/参数爆破（两种引擎，都自动过滤假 200）
```
ctfctl fuzz "URL/FUZZ" [-w WORDLIST] [-e php,html,bak] [-X POST] [-d 'k=FUZZ'] [-H 'K: FUZZ']
                       [-mc 200,301,302,401,403] [--fs N] [--show-fake]
                       [--engine auto|ffuf|builtin] [-t 20] [--delay S] [--save DIR] [--json]
                       [--safe] [--max-words 2000]
```
- `auto`：有 ffuf 就调 ffuf（**把完整命令原文打出来**，兼当 ffuf flag 教学），没有就用内置引擎
- 两条路都按「**字节数 == 首页字节数**」过滤 `try_files` 回退产生的假 200（对应 ffuf 的 `-fs`）
- `--show-fake` 把被丢掉的也显示出来；首页连不上时**自动关闭过滤**（否则会把连接错误当首页大小）
- **`--safe`（比赛/共享靶机建议加）**：并发压到 ≤5、请求间隔 ≥0.2s、字典条数超上限（默认 2000，`--max-words` 可调）直接拒绝跑，并打印一条自我约束说明。很多赛事明文禁"重型扫描工具"，低并发 + 小字典是"用手"与"用炮"的分界线

### replay —— 请求历史
```
ctfctl replay list [-n 20] [--host H]
ctfctl replay show 7 | --last [--max N]
ctfctl replay resend 7 | --last [-H 'K: V'] [-d 'a=b'] [-X POST] [--raw] [--diff] [--max-diff N]
```
每次请求（req/recon/fuzz/diff/browser…）都连**响应体**一起落进 `~/.cache/ctfctl/history/<host>/`
（`index.jsonl` + `<ts>-<sha8>.body`），含请求头、请求体、cookie、状态、字节数、body 的 sha256。
"我刚才那条到底怎么发的"不用靠回忆；`resend --diff` 改一个头/体再发，和原始响应逐行对比。

### diff —— 两次响应对比（盲注/布尔/权限差异）
```
ctfctl diff live URL --a 1 --b "1'-- -" [--field id] [--in-body] [-X M] [--ctype CT] [-H ...] [--save DIR]
ctfctl diff files A B
ctfctl diff history 7 8 --host H
```
打印状态/长度/Content-Type/sha256 对照 + 行级差异（difflib）。
**退出码即结论：一致 0、不一致 1** —— 可直接塞进 `for` 循环当布尔探针。

### browser —— 第二条出口（专治 403 + 空响应）
```
ctfctl browser URL [-X POST] [-d 'a=b'] [-H 'K: V'] [--ua UA]
                   [--cdp http://回环地址:9222] [--launch] [--no-headless] [--discover] [-v] [--grep RE]
```
容器/命令行的出口 IP 常和浏览器不是一个，靶机往往只放行其中一个。这条通道走 CDP：
1. 起（`--launch`）或连上（`--cdp`，可以指向你已登录的 Edge/Chrome）一个带 `--remote-debugging-port` 的浏览器
2. CDP 里覆盖 UA、把 Cookie 写进浏览器 jar（这两个是 `fetch` 的禁止改名单头）
3. 导航到目标**同源**站点 → 注入 `fetch` → 取回状态码/响应头/原始字节

副作用：会先对站点 `/` 发一次 GET（导航用）。另外**别用 Fetch 域拦截实现**：`Page.navigate` 的回复要等导航提交，边等回复边处理 `Fetch.requestPaused` 必死锁（Chrome 145 实测）。

### export —— 录制导出（把历史变成能复现的东西）
```
ctfctl export script [--last 10 | --range 3-9 | --indices 1,4,7] [--tag req|recon|fuzz] [--no-probes]
                     [-o replay.sh] [--redact]
ctfctl export python [...]           # 零依赖 urllib 脚本
ctfctl export md     [...] [--title T] [--lines 12] [--max-chars N] [--note] [--no-redact]
```
- `script`：一串 `curl`（带 cookie、头、body、方法，参数都加了 shell 引号），可直接跑
- `python`：零依赖 urllib 脚本，自带 `put_cookies()` 复现会话
- `md`：直接当 writeup 的"分步过程"（每条：命令 + 当时的状态/字节数 + 响应开头），`--note` 写进 vault
- **来源过滤**：每条历史都带 `tag`（req / recon / fuzz / diff / replay）。`--tag req` 只留你手动发的；
  `--no-probes` 排除 recon/fuzz/diff 的探测请求 —— 否则一次 recon 的几十条探测会把录音淹掉
- **脱敏**：`md` 默认打码（**所有** cookie 的值 → `***`、主机 → `<target>`），笔记进 vault 不怕泄；
  脚本/py 默认原样（要真复现），要打码加 `--redact`
- ⚠️ 历史里的 cookie 是**当时那一次会话**的值，靶机重启/会话过期后要重新拿

### cookie / jwt / codec / note / rules
```
ctfctl cookie list|set|del|raw|flask-unsign|flask-sign     cookie jar + Flask session 爆破与伪造
ctfctl jwt    decode|sign|crack [--base URL --name credential]   解 / 改字段重签 / 爆破密钥
ctfctl codec  b64|b64d|url|urld|hex|hexd|guess             编解码（不给参数读 stdin）
ctfctl note   new|import                                   九段模板 writeup / 报告进 vault
ctfctl rules  list|test|check                              规则表查看 / 离线试匹配 / 体检
```
- `cookie flask-sign` 的时间戳**自动回拨 60s** —— Flask 不接受"比服务端新"的签名（会整块丢弃→500）
- `jwt decode/sign` 可以 `--base URL --name credential` 直接从 cookie jar 里取令牌

### go —— 一条命令：是什么 + 下一步做什么
```
ctfctl go "http://靶机/"        # URL → 侦察（指纹/源码面/泄露文件/常见路径）+ 方向建议
ctfctl go ./附件.zip            # 文件 → 初筛（类型/结构/内嵌/字符串/保护）+ 方向建议
ctfctl go ./pwn --strings 30    # 文件：多看些字符串
```
判类型自己来：`http(s)://` 走 Web 流程，存在的路径走文件流程，两者都不是就告诉你用法。

### file —— 文件/二进制初筛（misc · rev · pwn · crypto 的第一步）
```
ctfctl file ./chal.zip [--strings 12] [--limit 3] [--no-advice] [--json F]
```
全部标准库、不联网、不改文件。它做什么：

| 类别 | 具体 |
|---|---|
| 类型 | 40+ 种文件头签名（PNG/JPEG/GIF/BMP/RIFF/MP3/FLAC/PDF/ZIP/RAR/7z/gzip/xz/tar/ELF/PE/SQLite/PCAP/PEM…） |
| 结构 | PNG 逐块 + CRC 校验 + IEND 之后是否还有块 · JPEG 尺寸 · ELF 架构与保护（NX/PIE/Canary/RELRO） · ZIP 条目表 |
| 藏的 | 结构末尾**附加数据**偏移与预览 · **内嵌文件**签名扫描（binwalk 风格） · ZIP **伪加密**（本地头 vs 中央目录标志位不一致） |
| 文本 | 熵（>7.5 提示加密/压缩/异或） · 可疑字符串 · flag 样式串（只在可打印串里找，避免二进制假命中） · RSA 变量 n/e/c · 长哈希串 · base64 行数 |

发现会变成**标签**（`appended`/`embedded`/`zip:pseudo-encrypt`/`elf:nx-off`/`entropy-high`/`text:rsa`…），
标签喂给建议引擎 → 输出带打分的下一步动作（对应 `data/advice.json`）。

### tui —— 工作台（键盘驱动，不用记命令）
```
ctfctl            # 裸跑就是它
ctfctl tui [--target "http://靶机/" ] [--dump [N]]
```
| 键 | 作用 |
|---|---|
| `t` | 填/换目标（URL 或附件路径） |
| `r` | 分析：URL → 侦察；文件 → 初筛（真发请求/真读文件） |
| `1-9` / `回车` | 执行右栏第 N 条建议（`@` 是全部执行） |
| `i` | 直接敲一条 ctfctl 子命令（面板里也能用会话/历史） |
| `k` `o` `u` `h` `c` | 知识库 / 工具目录 / 规则 / 历史 / 速查（`Tab`/`1-5` 换栏，`/` 过滤） |
| `↑↓` `PgUp/PgDn` | 滚动输出与详情 |
| `q` | 退出 |

右栏每条动作都先把**要执行的命令行**打出来（`cmd` 类走 ctfctl 子命令，`shell` 类是真在你机器上跑外部工具），
不会出现「按了键不知道它干了什么」。

### 智能从哪来（可核对，不是玄学）
三层数据 + 一个评分：

```
证据 ──► 规则（data/advice.json，web 面用 rules.json）──► why（为什么怀疑）+ next（可执行动作）
                                                          │
                            打分 = 规则 weight + 证据类型数 + 高信号参数×2 + 硬证据标签×3
```
- **硬证据标签**（file 初筛产出）权重最高：`crc-bad`、`zip:pseudo-encrypt`、`nx-off`、`appended`、`embedded`、`strings:flag`、`entropy-high`
- 每个方向都能追到出处：`tools` 指向工具目录条目，`kb` 指向知识卡，卡片里带**实测语料命中数**
- 想加自己的判断：只改 `~/.config/ctfctl/advice.json`（同 schema、追加），不动代码

### tools —— 工具目录（分类体系 + 装没装 + 装什么命令）
```
ctfctl tools                        # 分类概览（每类几个、本机装了几个）
ctfctl tools list [--cat web] [--installed|--missing]
ctfctl tools search <kw>            # 名称/别名/说明/标签/CTF 用法 全字段
ctfctl tools show ffuf              # 详情 + 安装命令 + 几条用法 + 踩坑
ctfctl tools check [--missing]      # 扫本机（pacman -Qq + PATH）
ctfctl tools install ffuf           # 只打印安装命令；--run 才执行；--manager pacman|pip|go…
```
- 分类用的是 **Kali / BlackArch 的官方分类**（快照落 `ctfctl/data/tools.json`，每条工具记来源与抓取日期）
- `✓` = 本机已装；`tools check --missing` 一次列出缺哪些 + 对应安装命令
- 只做「索引 + 打印命令」：**不代跑利用、不自动下载**（`install --run` 是你显式按的）
- 个人补充放 `~/.config/ctfctl/tools.json`（同 schema，追加不覆盖）

### kb —— 知识库（writeup 归纳的手法卡片）
```
ctfctl kb                      # 按阶段概览 + 语料统计
ctfctl kb list [--phase 注入] [--tag web]
ctfctl kb search <kw>
ctfctl kb show flask-session   # 信号 → 机制 → 步骤 → 命令 → 工具 → 出处 → 语料证据
ctfctl kb signals              # 信号总表：看到 X → 查哪张卡
ctfctl kb sources              # 语料来源与统计口径（样本多大、怎么抽的、许可）
```
- 每张卡的 `corpus` 是**实测数字**：这条手法在这批语料里命中多少个 writeup 文件（怎么算出来的见 `scripts/harvest_writeups.py` 的 docstring）
- 卡片和规则表是同一套东西的两面：**规则**给可粘贴命令，**卡片**讲清机制与信号（先"想"再"抄"）
- 个人卡片放 `~/.config/ctfctl/kb.json`

### tui —— 工作台（见上面第 3 节 `tui` 的按键表）

### 语料统计（kb 的 `corpus` 数字怎么来的）
```bash
python3 scripts/harvest_writeups.py fetch owner/repo [--mirror https://ghfast.top/]
python3 scripts/harvest_writeups.py count --corpus ~/.cache/ctfctl/corpus/xxx --top 30 --json research/kb-evidence.json
python3 scripts/harvest_writeups.py sources
```
口径（报数字前先读这段，也是脚本 docstring 里那段）：
- 单位是**文件**不是题：一个文件里出现 5 次只算 1
- 大小写不敏感子串/正则匹配（见 `data/techniques.json`）
- **每个来源内部**按内容 sha1 去重；跳过语料根目录的索引文件（README/index/…）
- **按来源分开报**：某套语料偏 pwn，就用它的百分比说 pwn，别把它当成全站分布

### 工具目录怎么生成的
```bash
python3 scripts/build_catalog.py            # 用 research/ 下的快照重新生成 data/tools.json
python3 scripts/build_catalog.py --fetch    # 现场重抓（BlackArch 表 + Kali 工具全表）
```
机器字段来自官方页面（BlackArch 48 类 2862 行；Kali 工具全表 3335 个名字 + `kali-meta` 的 29 个分类元包），
中文说明/安装方式/用法来自人工维护的 `ctfctl/data/ctf-tools.json`（叠加优先）。两边数字都会打在生成日志里。

---

## 4. 自动联想：怎么打分

规则表就是"看到 X → 想 Y"（`ctfctl/data/rules.json`）。recon 命中后按**证据**排序：

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
      ctfctl req get "http://靶机:8080/?file=file:///etc/passwd"
      ...

其余命中：假 200（nginx try_files 回退）(6)、JWT 令牌(5)
```
命令里的 `$U`、`<host>` 会被替换成真实地址；如果 jar 里有 `session`/`token`/`sid`，占位符也会换成真值。
`--no-suggest` 关掉联想；`--json` 里会多一个 `top` 字段给脚本用。

---

## 5. 设计取舍（三条硬约定）

1. **小包 + 统一入口**：加功能靠往 `ctfctl/commands/` 丢一个带 `register(sub)` 的模块，`cli.py` 用 pkgutil 自动发现 —— 不改入口、不改 `__init__`。
2. **能包一层就不重造**：目录扫描包 ffuf（打印命令原文 + 自动 `-fs`），自建部分只做小清单 + 假 200 判定；编码/JWT 用标准库自己几行搞定，不引依赖。
3. **不做 payload 库 / 半自动利用**：只做结构化请求变异（方法/头/cookie/参数/编码）；规则里的命令是**可粘贴模板**，判断权留给人。通用 payload 库最后都长成缝合怪，也把"想"这件事外包掉了。

---

## 6. 扩展指南

**A. 加一个子命令**（`ctfctl/commands/graphql.py`）：
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
改完 `ctfctl --help` 里就有了。会话、输出、捞 flag、history 记录全是现成的（`Session.request` 自动记账）。

**B. 加一条「看到 X → 想 Y」**（只改 `ctfctl/data/rules.json`，个人补充放 `~/.config/ctfctl/rules.json`）：
```json
{"id": "graphql", "name": "GraphQL", "weight": 3,
 "when": {"body_re": ["/graphql", "__schema"]},
 "hint": "有 GraphQL：先 introspection 拿全 schema，再看 mutation 的权限校验。",
 "cmds": ["ctfctl req post \"$U/graphql\" --json '{\"query\":\"{__schema{types{name}}}\"}'"]}
```
写完 `ctfctl rules check` 体检、`ctfctl rules test --body '/graphql'` 离线试匹配。

**C. 加一组扫描词**：`ctfctl/data/files.json` 的 `leak` / `paths`。

**D. 加一种导出格式**：`ctfctl/commands/export.py` 里加 `emit_xxx()`，在 `run()` 的分支里接上。

---

## 7. 测试

```bash
cd ~/项目/ctf-tool && python3 tests/test_smoke.py        # 87 项断言（含 tools/kb/tui/file/go）
```

自带一个本地 demo 靶机（`tests/demo_server.py`），刻意复刻踩过的坑：
nginx 式**假 200**、`.php` 走真 404、`index.php.bak` 备份泄露、Werkzeug + 三段式 session、
隐藏字段与注释、JWT 串、"你不是管理员"话术、`/echo-ua`（用来验证 UA 真的送达）。
另有最小 WebSocket 回声服务端（`tests/ws_echo_server.py`）离线验证 CDP 帧格式。

想连浏览器通道一起测：先开一个调试端口，再
```bash
CTFCTL_CDP=http://127.0.0.1:9333 python3 tests/test_smoke.py
```
（会在同一次运行里多验证两条：UA 经 CDP 覆盖后真送达、POST 表单正确解码。）

---

## 8. 目录结构

```
ctf-tool/
├── pyproject.toml              # console_scripts: ctfctl（+ 兼容别名 webctl）
├── scripts/
│   └── harvest_writeups.py     # 开发用：抓公开 writeup 语料 + 手法词频统计（kb 的 corpus 数字来源）
├── ctfctl/
│   ├── cli.py                  # 统一入口：pkgutil 自动发现 commands/
│   ├── __main__.py             # python3 -m ctfctl
│   ├── core/
│   │   ├── config.py           # 路径、UA、flag 正则、vault 定位、旧目录迁移
│   │   ├── session.py          # cookie jar 会话 + 统一请求/输出 + 请求历史记账
│   │   ├── response.py         # 响应对象（状态/头/体/落盘/捞 flag）
│   │   ├── detect.py           # 真假 200 判定（recon 与 fuzz 共用）
│   │   ├── history.py          # 请求历史的读写
│   │   ├── rules.py            # 规则加载/匹配/打分/命令渲染
│   │   └── cdp.py              # 极简 CDP 客户端（手写 WebSocket 帧，零依赖）
│   ├── commands/               # ← 加功能只动这里
│   │   ├── req.py  recon.py  fuzz.py  replay.py  diff.py  browser.py
│   │   ├── export.py  cookie.py  jwt.py  codec.py  note.py  rules.py
│   │   └── tools.py  kb.py  tui.py        # 工具目录 / 知识库 / 全屏面板
│   ├── data/
│   │   ├── rules.json          # 「看到 X → 想 Y」规则表
│   │   ├── files.json          # 泄露文件 / 常见路径清单
│   │   ├── tools.json          # 工具目录（Kali/BlackArch 分类快照 + 安装方式 + 用法）
│   │   ├── kb.json             # 知识库卡片（信号→机制→步骤→命令）+ 语料来源与统计
│   │   ├── techniques.json     # 手法关键词表（语料统计与信号词共用）
│   │   └── cheatsheet.md       # TUI「速查」栏
│   └── templates/writeup.md    # 九段 writeup 模板
└── tests/
    ├── demo_server.py          # 本地演示靶机
    ├── ws_echo_server.py       # 最小 WS 服务端（验证 CDP 帧）
    └── test_smoke.py           # 冒烟测试
```

---

## 9. 比赛时怎么用（合规）

工具本身几乎不是问题 —— 这套等价于 curl + Burp + ffuf 的组合。真正踩线的是**用法强度**和**AI 参与**：

| 用法 | 风险 | 建议 |
|---|---|---|
| `req` / `diff` / `jwt` / `cookie` / `replay` / `export` | 无 | 随便用，请求数和你手打一样 |
| `recon` | 低 | 默认约 40 个请求、10 秒内结束；共享实例上别反复 `--full` |
| `fuzz` 大字典 + 高并发 | **高** | 加 `--safe`（≤5 并发、≥0.2s 间隔、字典上限 2000），命中即停 |
| 对比赛平台/记分板/非题目目标发请求 | **必禁** | 工具只发你给的 URL，但 base 别写错 |
| 让 AI/LLM 替你解题 | 看规则 | 有的赛事专门设"必须由 AI 完成"的赛道，有的直接视为作弊 —— **先读规则再动手** |

常见被禁行为（多数赛事规则里都有）：攻击比赛平台或基础设施、DoS/把靶机打挂、扫描整个网段、
爆破 flag 本身、赛后公开题解或共享 flag。
自查材料：`replay` + `export` 的历史就是"我只对哪些 URL 发过请求"的证据链。

## 10. 已知边界 / 路线

- HTTP/2、WebSocket、非文本协议不支持；文件上传只给了命令模板。
- `browser` 通道目前只覆盖 `ctfctl browser` 自己，`req/recon/fuzz` 还走本机出口
  （想做全局换出口，需要给 `Session` 加一层执行器抽象：`--via browser`）。
- 历史不自动清理（它就是证据链），要清 `rm -rf ~/.cache/ctfctl/history/<host>`。
- 路线：请求录制打包分享（导出成单个可复现 HTML/脚本包）、`recon --via browser`、
  规则自动联想再加一层"这条规则在你的靶机上最可能从哪个参数入手"的具体定位、
  `kb` 卡片与 `rules` 互相反查（recon 命中规则时顺手提示对应卡片）

---

## 11. 变更日志

- **1.0** — 改名 `webctl` → **`ctfctl`**（旧名留作别名；cache/config 自动迁移）；裸跑进**工作台 TUI**（键盘驱动、按键执行建议）；新增 **`go`**（URL/文件一条命令出方向）、**`file`**（文件初筛：结构/内嵌/附加数据/伪加密/ELF 保护/熵/字符串 + 建议）、**`tools`**（2923 条工具目录：BlackArch 48 类 + Kali 官方分类元包 + 人工中文条目，含装没装与安装命令）、**`kb`**（21 张手法卡，带实测语料命中数）、**`advise` 建议引擎**（证据→why→可执行动作，带打分）、`data/techniques.json`、`scripts/harvest_writeups.py`（语料抓取+分来源词频统计）、`scripts/build_catalog.py`（工具目录生成）
- **0.5** — 开源发布（https://github.com/Phirisyyds/ctfctl，MIT；镜像 DreamwalkerYYS/ctfctl）；`fuzz --safe`（并发≤5 / 间隔≥0.2s / 字典超上限拦下）；README 增加"比赛时怎么用（合规）"一节
- **0.4.1** — 历史记录加 `tag` 来源；`export --tag/--no-probes`；md 导出命令加 shell 引号、脱敏打掉全部 cookie 值；测试改用独立 cache
- **0.4** — `export`（script/python/md 三种录制导出，md 默认脱敏 + 可写进 vault）；recon **自动联想**（按证据打分、命令替换真地址与真 cookie 值）；README 重写为完整手册
- **0.3.1** — `browser` 通道改「同源 fetch」（避开 `Page.navigate` 死锁）；demo 加 `/echo-ua`
- **0.3** — `replay`（请求历史 + 重放改包 + diff）、`diff`（盲注/布尔探针）、`browser`（CDP 第二出口）
- **0.2** — `fuzz`（ffuf/内置双引擎，自动过滤假 200）
- **0.1** — `req` / `recon` / `cookie` / `jwt` / `codec` / `note` / `rules`；core 分层 + 规则表数据化
