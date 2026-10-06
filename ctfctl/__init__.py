"""ctfctl —— CTF 工具箱（原名 webctl）。

统一入口：`ctfctl <子命令>`。加功能 = 在 ctfctl/commands/ 里丢一个 .py，
里面实现 register(subparsers) 即可（cli.py 用 pkgutil 自动发现）。

命令分三层：
  · 动手：req / recon / fuzz / diff / browser / cookie / jwt / codec / replay / export
  · 查资料：tools（工具目录）/ kb（writeup 归纳的手法卡片）/ rules（看到 X → 想 Y）
  · 看全局：tui（只读面板）
"""
__version__ = "1.3.0"
