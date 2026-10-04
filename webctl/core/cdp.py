"""极简 CDP（Chrome DevTools Protocol）客户端 —— 只用标准库。

用途：`webctl browser` 需要"借真浏览器发一次请求"（出口 IP 不同、自带真 cookie、真 UA）。
CDP 的 HTTP 端点拿目标列表，交互（Runtime.evaluate）走 WebSocket —— 这里手写最小 WS 帧，
够发一条文本消息、收一条回复即可（不做 permessage-deflate，不做多路复用）。

配套：tests/ws_echo_server.py 是个最小 WS 服务端，用来离线验证帧格式。
"""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import urllib.parse
import urllib.request


# ---------------------------------------------------------------- HTTP 侧
def http_json(base: str, path: str, timeout: float = 5, method: str = "GET"):
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def list_targets(base: str, timeout: float = 5) -> list[dict]:
    data = http_json(base, "/json/list", timeout)
    return data if isinstance(data, list) else []


def pick_ws_url(base: str, prefer_type: str = "page", timeout: float = 5) -> str:
    """优先挑一个 page 目标；没有就用 /json/version 里的 browser ws（也能 evaluate，但没 DOM）。"""
    for t in list_targets(base, timeout):
        if t.get("type") == prefer_type and t.get("webSocketDebuggerUrl"):
            return t["webSocketDebuggerUrl"]
    for t in list_targets(base, timeout):
        if t.get("webSocketDebuggerUrl"):
            return t["webSocketDebuggerUrl"]
    v = http_json(base, "/json/version", timeout)
    if isinstance(v, dict) and v.get("webSocketDebuggerUrl"):
        return v["webSocketDebuggerUrl"]
    raise RuntimeError(f"找不到可用的 CDP 目标：{base}（浏览器要带 --remote-debugging-port 启动）")


# ---------------------------------------------------------------- WebSocket 侧
class WS:
    """最小 WebSocket 客户端：文本帧 + 分片拼接 + ping/pong。"""

    def __init__(self, url: str, timeout: float = 15):
        u = urllib.parse.urlsplit(url)
        host, port = u.hostname, (u.port or (443 if u.scheme == "wss" else 80))
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        if u.scheme == "wss":
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        path = u.path + (("?" + u.query) if u.query else "")
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("WS 握手连接被关闭")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise RuntimeError("WS 握手失败：" + head.split(b"\r\n")[0].decode("utf-8", "replace"))
        self._buf = rest

    def _recv_more(self) -> bool:
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return False
        if not chunk:
            return False
        self._buf += chunk
        return True

    def send_text(self, text: str) -> None:
        payload = text.encode()
        head = bytearray([0x81])                       # FIN + text
        n = len(payload)
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head.append(0x80 | 126)
            head += struct.pack(">H", n)
        else:
            head.append(0x80 | 127)
            head += struct.pack(">Q", n)
        mask = os.urandom(4)
        head += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(head) + masked)

    def recv_text(self) -> str | None:
        """收一条完整的文本消息（自动拼分片、自动回 pong）。超时返回 None。"""
        data = b""
        while True:
            while len(self._buf) < 2:
                if not self._recv_more():
                    return None
            b0, b1 = self._buf[0], self._buf[1]
            fin, opcode = b0 & 0x80, b0 & 0x0F
            masked, ln = b1 & 0x80, b1 & 0x7F
            off = 2
            if ln == 126:
                while len(self._buf) < 4:
                    if not self._recv_more():
                        return None
                ln = struct.unpack(">H", self._buf[2:4])[0]
                off = 4
            elif ln == 127:
                while len(self._buf) < 10:
                    if not self._recv_more():
                        return None
                ln = struct.unpack(">Q", self._buf[2:10])[0]
                off = 10
            if masked:
                off += 4
            while len(self._buf) < off + ln:
                if not self._recv_more():
                    return None
            mask = self._buf[off - 4:off] if masked else b""
            chunk = self._buf[off:off + ln]
            self._buf = self._buf[off + ln:]
            if masked:
                chunk = bytes(b ^ mask[i % 4] for i, b in enumerate(chunk))
            if opcode == 0x9:                            # ping → pong
                pong = bytearray([0x8A, 0x80 | min(len(chunk), 125)])
                pong += b"\x00\x00\x00\x00"
                self.sock.sendall(bytes(pong) + chunk[:125])
                continue
            if opcode == 0x8:                             # close
                return None
            data += chunk
            if fin:
                return data.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- CDP 高层封装
class CDP:
    def __init__(self, base: str, timeout: float = 20, ws_url: str | None = None):
        self.base = base
        self.timeout = timeout
        self.ws = WS(ws_url or pick_ws_url(base), timeout=timeout)
        self._id = 0
        self._events: list[dict] = []

    def call(self, method: str, params: dict | None = None, timeout: float | None = None):
        """调一个 CDP 方法，等到 id 匹配的响应（路上的事件先缓存）。"""
        self._id += 1
        mid = self._id
        self.ws.send_text(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = (timeout or self.timeout)
        import time as _t
        t0 = _t.time()
        while _t.time() - t0 < deadline:
            msg = self.ws.recv_text()
            if msg is None:
                raise RuntimeError("CDP 连接关闭/超时")
            try:
                obj = json.loads(msg)
            except json.JSONDecodeError:
                continue
            if obj.get("id") == mid:
                if "error" in obj:
                    raise RuntimeError(f"CDP {method} 失败：{obj['error']}")
                return obj.get("result", {})
            if "method" in obj:
                self._events.append(obj)
        raise TimeoutError(f"CDP {method} 超时")

    def evaluate(self, expression: str, await_promise: bool = True, return_by_value: bool = True):
        r = self.call("Runtime.evaluate", {"expression": expression, "awaitPromise": await_promise,
                                           "returnByValue": return_by_value, "allowUnsafeEvalBlockedByCSP": True})
        if r.get("exceptionDetails"):
            raise RuntimeError("页面内 JS 异常：" + json.dumps(r["exceptionDetails"], ensure_ascii=False)[:400])
        return r.get("result", {}).get("value")

    def next_event(self, method: str | None = None, pred=None, timeout: float | None = None) -> dict:
        """等一个 CDP 事件（先进自带的缓存队列，再读新消息）。"""
        import time as _t
        deadline = _t.time() + (timeout or self.timeout)
        for i, e in enumerate(self._events):
            if (method is None or e.get("method") == method) and (pred is None or pred(e)):
                return self._events.pop(i)
        while _t.time() < deadline:
            msg = self.ws.recv_text()
            if msg is None:
                raise RuntimeError("CDP 连接关闭")
            try:
                obj = json.loads(msg)
            except json.JSONDecodeError:
                continue
            if "method" not in obj:
                continue
            if (method is None or obj["method"] == method) and (pred is None or pred(obj)):
                return obj
            self._events.append(obj)
        raise TimeoutError(f"等 {method or '事件'} 超时")


    def close(self) -> None:
        self.ws.close()
