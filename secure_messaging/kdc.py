
import socket
import threading
from typing import Dict, Any
import os

from wire import send_msg, recv_msg
from crypto_utils import (
    kdf_from_passphrase, now_ts,
    aes_gcm_encrypt
)

HOST = "127.0.0.1"
PORT = 9000


K_C = kdf_from_passphrase("CLIENT_MASTER_KEY_DEMO", 32)
K_S = kdf_from_passphrase("SERVER_MASTER_KEY_DEMO", 32)

SESSION_TTL_SECONDS = 300  

def handle_client(conn: socket.socket, addr):
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
            "session_aes_b64": __import__("base64").b64encode(session_aes).decode("ascii"),
            "session_des_b64": __import__("base64").b64encode(session_des).decode("ascii"),
            "session_hmac_b64": __import__("base64").b64encode(session_hmac).decode("ascii"),
        }
        ticket = aes_gcm_encrypt(K_S, ticket_plain)

        
        client_pack_plain: Dict[str, Any] = {
            "issued_at": issued_at,
            "expiry": expiry,
            "alg": alg,
            "session_aes_b64": __import__("base64").b64encode(session_aes).decode("ascii"),
            "session_des_b64": __import__("base64").b64encode(session_des).decode("ascii"),
            "session_hmac_b64": __import__("base64").b64encode(session_hmac).decode("ascii"),
            "ticket": ticket,
        }
        enc_for_client = aes_gcm_encrypt(K_C, client_pack_plain)

        send_msg(conn, {"type": "KEY_RES", "enc_for_client": enc_for_client})
    except Exception as e:
        send_msg(conn, {"type": "ERR", "error": str(e)})
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(20)
    print(f"[KDC] Dinliyor: {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
