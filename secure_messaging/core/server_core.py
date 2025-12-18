import socket
import threading
import base64
from typing import Callable, Optional, Dict

from .wire import send_msg, recv_msg
from .crypto_utils import kdf_from_passphrase, aes_gcm_decrypt, decrypt_payload, encrypt_payload, now_ts

K_S = kdf_from_passphrase("SERVER_MASTER_KEY_DEMO", 32)

_stop_flag = False
_server_sock: Optional[socket.socket] = None

def stop_server():
    global _stop_flag, _server_sock
    _stop_flag = True
    try:
        if _server_sock:
            _server_sock.close()
    except:
        pass

def start_server(host: str, port: int, log: Optional[Callable[[str], None]] = None):
    global _stop_flag, _server_sock
    _stop_flag = False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(50)
    _server_sock = s

    if log:
        log(f"[Server] Dinliyor: {host}:{port}")

    while not _stop_flag:
        try:
            conn, addr = s.accept()
        except OSError:
            break
        threading.Thread(target=_handle_conn, args=(conn, addr, log), daemon=True).start()

    if log:
        log("[Server] Durduruldu.")

def _parse_keys(ticket_plain: Dict) -> Dict[str, bytes]:
    return {
        "aes": base64.b64decode(ticket_plain["session_aes_b64"]),
        "des": base64.b64decode(ticket_plain["session_des_b64"]),
        "hmac": base64.b64decode(ticket_plain["session_hmac_b64"]),
    }

def _handle_conn(conn: socket.socket, addr, log):
    try:
        msg = recv_msg(conn)
        if msg.get("type") != "AUTH":
            send_msg(conn, {"type": "ERR", "error": "Beklenen AUTH"})
            return

        ticket = msg.get("ticket")
        authenticator = msg.get("authenticator")

        ticket_plain = aes_gcm_decrypt(K_S, ticket)

        if now_ts() > int(ticket_plain["expiry"]):
            send_msg(conn, {"type": "ERR", "error": "Ticket süresi dolmuş"})
            return

        keys = _parse_keys(ticket_plain)

        auth_plain = decrypt_payload(authenticator, keys)
        if auth_plain.get("client_id") != ticket_plain["client_id"]:
            send_msg(conn, {"type": "ERR", "error": "Client ID uyuşmuyor"})
            return

        ts = int(auth_plain.get("ts", 0))
        if abs(now_ts() - ts) > 30:
            send_msg(conn, {"type": "ERR", "error": "Authenticator timestamp geçersiz"})
            return

        alg = auth_plain.get("alg", "AES_GCM")
        send_msg(conn, {"type": "OK", "msg": f"Handshake tamam. Alg={alg}"})

        if log:
            log(f"[Server] Handshake OK | client={ticket_plain['client_id']} alg={alg} from={addr}")

        expected_counter = 1
        while True:
            pkt = recv_msg(conn)
            if pkt.get("type") == "BYE":
                send_msg(conn, {"type": "BYE"})
                if log:
                    log(f"[Server] BYE | {addr}")
                return
            if pkt.get("type") != "DATA":
                send_msg(conn, {"type": "ERR", "error": "Beklenen DATA"})
                continue

            blob = pkt.get("blob")
            plain = decrypt_payload(blob, keys)

            counter = int(plain.get("counter", 0))
            if counter != expected_counter:
                send_msg(conn, {"type": "ERR", "error": f"Counter beklenen {expected_counter}, gelen {counter}"})
                if log:
                    log(f"[Server] Counter hata | beklenen={expected_counter} gelen={counter} from={addr}")
                return

            text = plain.get("text", "")
            if log:
                log(f"[Server] DATA | from={addr} counter={counter} text='{text}'")

            expected_counter += 1

            resp = {"counter": expected_counter, "text": f"Echo: {text}"}
            expected_counter += 1

            out_blob = encrypt_payload(alg, keys, resp)
            send_msg(conn, {"type": "DATA", "blob": out_blob})

    except Exception as e:
        try:
            send_msg(conn, {"type": "ERR", "error": str(e)})
        except:
            pass
        if log:
            log(f"[Server] Hata: {e} from={addr}")
    finally:
        conn.close()
