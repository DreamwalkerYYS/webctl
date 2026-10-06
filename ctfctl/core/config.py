"""路径与全局约定。"""
from __future__ import annotations

import os

CACHE = os.path.expanduser(os.environ.get("CTFCTL_CACHE", "~/.cache/ctfctl"))
CONFIG = os.path.expanduser(os.environ.get("CTFCTL_CONFIG", "~/.config/ctfctl"))
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")

DEFAULT_UA = "ctfctl/1.0 (+ctf)"

#: 改名前的目录（webctl → ctfctl）。首次运行自动搬过去，用户的历史请求不丢。
LEGACY_DIRS = ((os.path.expanduser("~/.cache/webctl"), CACHE),
               (os.path.expanduser("~/.config/webctl"), CONFIG))


def migrate_legacy_dirs() -> list[str]:
    """把老名字的 cache/config 目录搬到新名字下（只在目标不存在时搬一次）。"""
    moved = []
    for old, new in LEGACY_DIRS:
        if os.path.isdir(old) and not os.path.exists(new):
            try:
                os.rename(old, new)
                moved.append(f"{old} -> {new}")
            except OSError:
                pass
    return moved

# 三种 flag 前缀都认（比赛现场常见坑：前缀错也判错）
FLAG_RE = r"[A-Za-z0-9_?]{1,24}\{[^}\n]{2,200}\}"


def ensure_dirs() -> None:
    migrate_legacy_dirs()
    for d in (CACHE, CONFIG):
        os.makedirs(d, exist_ok=True)


def vault_path() -> str | None:
    """Obsidian vault：优先 $OBSIDIAN_VAULT_PATH，再看 ~/.hermes/.env，最后猜默认值。"""
    p = os.environ.get("OBSIDIAN_VAULT_PATH")
    if p and os.path.isdir(p):
        return p
    env = os.path.expanduser("~/.hermes/.env")
    if os.path.exists(env):
        try:
            for line in open(env, encoding="utf-8", errors="replace"):
                if line.startswith("OBSIDIAN_VAULT_PATH="):
                    p = line.split("=", 1)[1].strip().strip('"').strip("'")
                    p = os.path.expanduser(p)
                    if os.path.isdir(p):
                        return p
        except OSError:
            pass
    for guess in ("~/文档/Brain", "~/Documents/Obsidian Vault"):
        g = os.path.expanduser(guess)
        if os.path.isdir(g):
            return g
    return None
