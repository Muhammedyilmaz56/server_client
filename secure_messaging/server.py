
import socket
import threading
import time
import base64
from typing import Dict, Any

from wire import send_msg, recv_msg
from crypto_utils import kdf_from_passphrase, aes_gcm_decrypt, decrypt_payload, encrypt_payload, now_ts

HOST = "127.0.0.1"
PORT = 9001

K_S = kdf_from_passphrase("SERVER_MASTER_KEY_DEMO", 32)

def parse_keys_from_ticket(ticket_plain: Dict[str, Any]) -> Dict[str, bytes]:
    return {
        "aes": base64.b64decode(ticket_plain["session_aes_b64"]),
        "des": base64.b64decode(ticket_plain["session_des_b64"]),
        "hmac": base64.b64decode(ticket_plain["session_hmac_b64"]),
    }

def handle_conn(conn: socket.socket, addr):
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

        session_keys = parse_keys_from_ticket(ticket_plain)

      
        auth_plain = decrypt_payload(authenticator, {"aes": session_keys["aes"], "des": session_keys["des"], "hmac": session_keys["hmac"]})
        if auth_plain.get("client_id") != ticket_plain["client_id"]:
            send_msg(conn, {"type": "ERR", "error": "Client ID uyuşmuyor"})
            return

        ts = int(auth_plain.get("ts", 0))
        if abs(now_ts() - ts) > 30:
            send_msg(conn, {"type": "ERR", "error": "Authenticator timestamp geçersiz"})
            return

        alg = auth_plain.get("alg", "AES_GCM")
        send_msg(conn, {"type": "OK", "msg": f"Handshake tamam. Alg={alg}"})
        print(f"[Server] Handshake OK. client={ticket_plain['client_id']} alg={alg}")

       
        expected_counter = 1
        while True:
            pkt = recv_msg(conn)
            if pkt.get("type") == "BYE":
                send_msg(conn, {"type": "BYE"})
                return
            if pkt.get("type") != "DATA":
                send_msg(conn, {"type": "ERR", "error": "Beklenen DATA"})
                continue

            blob = pkt.get("blob")
            plain = decrypt_payload(blob, session_keys)

            counter = int(plain.get("counter", 0))
            if counter != expected_counter:
                send_msg(conn, {"type": "ERR", "error": f"Counter beklenen {expected_counter}, gelen {counter}"})
                return
            expected_counter += 1

            text = plain.get("text", "")
            print(f"[Server] DATA: {text}")

           
            resp = {"counter": expected_counter, "text": f"Echo: {text}"}
            expected_counter += 1
            out_blob = encrypt_payload(alg, session_keys, resp)
            send_msg(conn, {"type": "DATA", "blob": out_blob})

    except Exception as e:
        try:
            send_msg(conn, {"type": "ERR", "error": str(e)})
        except:
            pass
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(20)
    print(f"[Server] Dinliyor: {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
