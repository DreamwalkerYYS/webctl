"""响应对象：统一收口 状态/头/体/落盘/提取。"""
from __future__ import annotations

import os
import re

from .config import CACHE


class Resp:
    def __init__(self, status: int, headers: dict, body: bytes, url: str, final_url: str | None = None):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.raw_headers = headers
        self.body = body or b""
        self.url = url
        self.final_url = final_url or url

    # ---- 便捷视图 ----
    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def size(self) -> int:
        return len(self.body)

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def redirected(self) -> bool:
        return self.final_url != self.url

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    # ---- 落盘 ----
    def save(self, path: str | None = None) -> str:
        os.makedirs(CACHE, exist_ok=True)
        path = path or os.path.join(CACHE, "last.body")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.body)
        return path

    def flags(self, pattern: str | None = None) -> list[str]:
        from .config import FLAG_RE

        return sorted(set(re.findall(pattern or FLAG_RE, self.text)))

    def grep(self, pattern: str) -> list[str]:
        return re.findall(pattern, self.text)

    # ---- 摘要 ----
    def summary(self) -> str:
        s = f"{self.status} {self.size}B {self.ctype or '?'}"
        if self.redirected:
            s += f"  -> {self.final_url}"
        return s
