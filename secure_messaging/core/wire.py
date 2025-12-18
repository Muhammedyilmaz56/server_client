import json
import struct
from typing import Any, Dict

def send_msg(sock, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)

def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket kapandı.")
        buf += chunk
    return buf

def recv_msg(sock) -> Dict[str, Any]:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    data = recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))
