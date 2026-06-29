from __future__ import annotations

import json
import socket
import struct
from typing import Optional


def send_frame(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> Optional[dict]:
    header = _recv_exactly(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    body = _recv_exactly(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))
