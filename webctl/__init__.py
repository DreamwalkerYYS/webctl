"""webctl —— Web 题通用工具包。

统一入口：`webctl <子命令>`。加功能 = 在 webctl/commands/ 里丢一个 .py，
里面实现 register(subparsers) 即可（cli.py 用 pkgutil 自动发现）。
"""
__version__ = "0.5.0"
