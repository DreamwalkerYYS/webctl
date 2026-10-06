# 速查：通用五步 + 改请求三板斧

## ① 定方向（先读页面，别先扫）
- 读题面/标题/描述/页面文字与错误信息 —— 很多题把提示直接写在里面
- 响应头认栈：`Server:`、`X-Powered-By:`、`Set-Cookie:` 字段名
- 判"是不是本题"：题面作者名/赛事名 vs 站点品牌；有排行榜/提交数就是平台的公共靶，别在上面挖

## ① 交互式终端（默认入口）
```
ctfctl                 # 进去以后：t 设目标(N+分析) → 回车推进 → 数字选动作 → q 退出
                       # 任意一行都当子命令用：req get / codec b64d / fuzz …（输出自动进证据）
printf 't $U\n1\nq\n' | ctfctl shell     # 管道驱动，可写脚本/可测试
```

## ①.5 整题推进（不想手动串步骤时）
```
ctfctl solve "$U" --auto 5      # 跑一步 → 抠新证据 → 重算下一步（拿到 flag 候选就停）
ctfctl solve "$U" --step        # 只推一步，看清单自己挑
ctfctl solve "$U"               # 只看状态与下一步（不跑任何东西）
```
WebUI 里对应的就是「解题模式 / 推进一步(s) / 自动推进」三个按钮；状态存 `~/.cache/ctfctl/solve/`，命令行与界面共享。

## ② 侦察
```
ctfctl recon "$U"            # 指纹/源码面/泄露文件(假 200 判定)/常见路径 + 最可能的 3 条
ctfctl recon "$U" --full     # 小清单跑完，共享靶机上别反复跑
```
- 程序化扫注释与 `data-*`，别肉眼翻整页
- 扫源码/备份：`index.php.bak`、`.index.php.swp`、`.git/HEAD`、`www.zip`
- 假 200：看**字节数 + Content-Type 是否等于首页**；nginx `try_files` 才回退成 200

## ③ 改请求三板斧（能改的都改一遍）
```
ctfctl req get  "$U/path?a=1" -H 'X-Forwarded-For: 127.0.0.1' -b 'role=admin' --ua ctf/1.0
ctfctl req post "$U/path" -d k=v -d k2=v2 --json '{"a":1}' --ctype application/json
ctfctl replay resend --last -H 'Referer: $U/'          # 改一个头再发，跟原始响应比
```
- 方法、Content-Type、参数位置（GET↔POST↔JSON）、Cookie、UA、Referer —— 六样都试
- 参数名必须从源码/前端 JS 的 form `name` 里读，别照搬上一题

## ④ 判真假（别把客户端问题当题目问题）
- 403 + 空响应（所有路径都一样）= **出口问题**：换网络/`--proxy`/`ctfctl browser`
- 连接被拒 = 服务没起；超时 = 中间被掐；靶机端口每次重启会变，别硬编码
- 一次性状态（排行榜/计数器）上复用同一个标识，别刷公共统计

## ⑤ 记录与收尾
```
ctfctl replay list -n 10
ctfctl export md --last 8 --title 题名 --note     # 脱敏后写进 vault
ctfctl note new --title 题名 --platform 平台 --kps 考点 --flag 'flag{...}' --index
```

## 看到 X → 想 Y（简表；全表见 ctfctl rules list / ctfctl kb signals）
| 看到 | 先想 |
|---|---|
| `Werkzeug` + 三段式 session | flask-unsign 爆密钥 → 伪签名（时间戳回拨） |
| `?file=` / `?url=` | php://filter 读源码、file:// 读文件、回环地址打内网 |
| `?id=` / `?search=` | `'` → `1'-- -` → union，看长度差；sqlmap 兜底 |
| `?cmd=` / `type=run` | 先 `echo 1` 确认执行点，再 `;id` |
| 页面里 `eyJ...` | JWT：解 payload → 密钥泄露就重签，`alg:none` 混用 |
| "只有管理员才能" | 改 cookie/JWT/session，别急字典 |
| `highlight_file` 报错 | 伪协议读源码，找判定条件 + 危险函数 |
| `.zip` 带密码 | 先试伪加密（改 flag 位），再 zip2john + 字典 |
| 图片比内容大 | `binwalk` / 附加数据 / LSB / IHDR 尺寸与 CRC |

## 纪律
- 每轮改动/每次成功与失败都留痕（负结果比成功更值钱）
- 共享靶机：低并发、小字典、命中即停、跑完停后台脚本
- 报数字先说清测量路径（哪张网/哪个出口/多少样本）
