"""最小 WebSocket 回声服务端 —— 只为离线验证 core/cdp.py 的帧格式。

    python3 tests/ws_echo_server.py 8901
然后：cd ~/项目/ctf-tool && python3 -c "from ctfctl.core.cdp import WS; w=WS('ws://127.0.0.1:8901/'); w.send_text('hi'); print(w.recv_text())"

只实现：握手、文本帧（含分片长度）、ping/pong、close。不做压缩。
"""
from __future__ import annotations

import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(payload: bytes, opcode: int = 0x1, fin: bool = True) -> bytes:
    head = bytearray([(0x80 if fin else 0x00) | opcode])
    n = len(payload)
    if n < 126:
        head.append(n)
    elif n < 65536:
        head.append(126); head += struct.pack(">H", n)
    else:
        head.append(127); head += struct.pack(">Q", n)
    return bytes(head) + payload


def handle(conn: socket.socket) -> None:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    key = ""
    for line in head.decode("utf-8", "replace").split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode())
    buf = rest
    while True:
        while len(buf) < 2:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        b0, b1 = buf[0], buf[1]
        opcode, masked, ln, off = b0 & 0x0F, b1 & 0x80, b1 & 0x7F, 2
        if ln == 126:
            while len(buf) < 4:
                buf += conn.recv(65536)
            ln = struct.unpack(">H", buf[2:4])[0]; off = 4
        elif ln == 127:
            while len(buf) < 10:
                buf += conn.recv(65536)
            ln = struct.unpack(">Q", buf[2:10])[0]; off = 10
        if masked:
            off += 4
        while len(buf) < off + ln:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        mask = buf[off - 4:off] if masked else b""
        data = buf[off:off + ln]
        buf = buf[off + ln:]
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode == 0x8:
            conn.sendall(frame(b"", 0x8)); return
        if opcode == 0x9:
            conn.sendall(frame(data, 0xA)); continue
        # 回声：把收到的文本原样发回；大消息故意分两片，用来验证客户端的分片拼接
        if len(data) > 100:
            half = len(data) // 2
            conn.sendall(frame(data[:half], 0x1, fin=False))
            conn.sendall(frame(data[half:], 0x0, fin=True))
        else:
            conn.sendall(frame(data, 0x1))


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8901
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    print(f"ws echo: 回环地址:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
