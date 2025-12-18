import socket
import threading
import os
import base64
from typing import Callable, Optional, Dict, Any

from .wire import send_msg, recv_msg

from .crypto_utils import kdf_from_passphrase, now_ts, aes_gcm_encrypt

K_C = kdf_from_passphrase("CLIENT_MASTER_KEY_DEMO", 32)
K_S = kdf_from_passphrase("SERVER_MASTER_KEY_DEMO", 32)
SESSION_TTL_SECONDS = 300

_stop_flag = False
_server_sock: Optional[socket.socket] = None

def stop_kdc():
    global _stop_flag, _server_sock
    _stop_flag = True
    try:
        if _server_sock:
            _server_sock.close()
    except:
        pass

def start_kdc(host: str, port: int, log: Optional[Callable[[str], None]] = None):
    global _stop_flag, _server_sock
    _stop_flag = False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(50)
    _server_sock = s

    if log:
        log(f"[KDC] Dinliyor: {host}:{port}")

    while not _stop_flag:
        try:
            conn, addr = s.accept()
        except OSError:
            break
        threading.Thread(target=_handle, args=(conn, addr, log), daemon=True).start()

    if log:
        log("[KDC] Durduruldu.")

def _handle(conn: socket.socket, addr, log):
    try:
        req = recv_msg(conn)
        if req.get("type") != "KEY_REQ":
            send_msg(conn, {"type": "ERR", "error": "Beklenen KEY_REQ"})
            return

        client_id = req.get("client_id")
        server_id = req.get("server_id")
        alg = req.get("alg", "AES_GCM")

        issued_at = now_ts()
        expiry = issued_at + SESSION_TTL_SECONDS

        session_aes = os.urandom(32)
        session_des = os.urandom(8)
        session_hmac = os.urandom(32)

        ticket_plain: Dict[str, Any] = {
            "client_id": client_id,
            "server_id": server_id,
            "issued_at": issued_at,
            "expiry": expiry,
            "session_aes_b64": base64.b64encode(session_aes).decode("ascii"),
            "session_des_b64": base64.b64encode(session_des).decode("ascii"),
            "session_hmac_b64": base64.b64encode(session_hmac).decode("ascii"),
        }
        ticket = aes_gcm_encrypt(K_S, ticket_plain)

        client_pack_plain: Dict[str, Any] = {
            "issued_at": issued_at,
            "expiry": expiry,
            "alg": alg,
            "session_aes_b64": base64.b64encode(session_aes).decode("ascii"),
            "session_des_b64": base64.b64encode(session_des).decode("ascii"),
            "session_hmac_b64": base64.b64encode(session_hmac).decode("ascii"),
            "ticket": ticket,
        }
        enc_for_client = aes_gcm_encrypt(K_C, client_pack_plain)

        send_msg(conn, {"type": "KEY_RES", "enc_for_client": enc_for_client})

        if log:
            log(f"[KDC] KEY_REQ ok | client={client_id} server={server_id} alg={alg} expiry={expiry} from={addr}")
    except Exception as e:
        try:
            send_msg(conn, {"type": "ERR", "error": str(e)})
        except:
            pass
        if log:
            log(f"[KDC] Hata: {e}")
    finally:
        conn.close()
