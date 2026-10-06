"""真假响应判定 —— 被 recon / fuzz 共用，避免两处逻辑漂移。

铁律：状态码不算数，看 字节数 + Content-Type。
    FAKE  : 200 且 字节数与 Content-Type 都和首页一致（nginx try_files 回退首页）
    REAL  : 200 且 Content-Type 不是 HTML
    EMPTY : 200 且 0 字节（存在但执行后无输出 —— 这本身是"存在性"证据）
    200?  : 200 且是 HTML 但字节数不同（可疑，值得人眼看）
"""
from __future__ import annotations

HTML_CT = ("text/html", "application/xhtml")


def classify(resp, base_size: int = -1, base_ctype: str = "", html_ct: list[str] | None = None) -> str:
    html_ct = html_ct or list(HTML_CT)
    ct = resp.ctype
    if resp.status in (401, 403) and resp.size == 0:
        return "拒绝"
    if resp.status in (404, 410):
        return "404"
    if resp.status == 200:
        if ct in html_ct and resp.size == base_size and ct == base_ctype:
            return "FAKE"
        if resp.size == 0:
            return "EMPTY(存在但无输出)"
        if ct and ct not in html_ct:
            return "REAL"
        return "200?"
    return str(resp.status)
