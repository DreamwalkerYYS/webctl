"""请求历史 —— replay 的数据源。

每个 host 一份目录：~/.cache/ctfctl/history/<host>/
    index.jsonl          一行一条请求（含响应摘要与 body 文件名）
    <ts>-<sha8>.body     响应体原文（diff / 复验用）

刻意不做自动清理：做题时历史就是证据链。要清就 rm -rf 那个目录。
"""
from __future__ import annotations

import json
import os

from .config import CACHE


def history_dir(host_key: str) -> str:
    return os.path.join(CACHE, "history", host_key)


def index_path(host_key: str) -> str:
    return os.path.join(history_dir(host_key), "index.jsonl")


def load(host_key: str | None = None, limit: int | None = None) -> list[dict]:
    """读历史。给 host_key 读单个 host；不给就按时间合并所有 host。"""
    dirs = [history_dir(host_key)] if host_key else [os.path.join(CACHE, "history", d)
                                                     for d in (os.listdir(os.path.join(CACHE, "history"))
                                                               if os.path.isdir(os.path.join(CACHE, "history")) else [])]
    recs: list[dict] = []
    for d in dirs:
        p = os.path.join(d, "index.jsonl")
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                r["host"] = os.path.basename(d)
                recs.append(r)
    recs.sort(key=lambda r: r.get("ts", 0))
    if limit:
        recs = recs[-limit:]
    return recs


def body_of(rec: dict) -> bytes:
    p = rec.get("body_file", "")
    if p and os.path.exists(p):
        with open(p, "rb") as f:
            return f.read()
    return b""
