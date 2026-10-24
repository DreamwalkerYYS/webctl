"""字典解析 —— 本机字典散落在若干约定路径，统一在这里找。

优先用户目录（无需 root）：~/.local/share/wordlists/rockyou.txt
"""
from __future__ import annotations

import os

ROCKYOU_CANDIDATES = (
    os.path.expanduser("~/.local/share/wordlists/rockyou.txt"),
    os.path.expanduser("~/wordlists/rockyou.txt"),
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
)

DIR_CANDIDATES = (
    os.path.expanduser("~/.local/share/wordlists/common.txt"),
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
)


def first_existing(paths) -> str:
    for p in paths:
        if p and os.path.exists(p):
            return p
    return ""


def rockyou() -> str:
    """rockyou 字典路径（找不到返回空串）。"""
    return first_existing(ROCKYOU_CANDIDATES)


def web_common() -> str:
    """目录爆破常用字典（找不到返回空串）。"""
    return first_existing(DIR_CANDIDATES)


def known() -> dict:
    return {"rockyou": rockyou(), "web_common": web_common()}
