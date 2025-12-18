
import socket
import base64

from wire import send_msg, recv_msg
from crypto_utils import (
    kdf_from_passphrase, aes_gcm_decrypt, encrypt_payload, decrypt_payload, now_ts
)

KDC_HOST = "127.0.0.1"
KDC_PORT = 9000

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001

K_C = kdf_from_passphrase("CLIENT_MASTER_KEY_DEMO", 32)

def get_session_from_kdc(client_id: str, server_id: str, alg: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((KDC_HOST, KDC_PORT))
    send_msg(s, {"type": "KEY_REQ", "client_id": client_id, "server_id": server_id, "alg": alg})
    res = recv_msg(s)
    s.close()

    if res.get("type") != "KEY_RES":
        raise RuntimeError(res.get("error", "KDC hata"))

    enc_for_client = res["enc_for_client"]
    plain = aes_gcm_decrypt(K_C, enc_for_client)

    keys = {
        "aes": base64.b64decode(plain["session_aes_b64"]),
        "des": base64.b64decode(plain["session_des_b64"]),
        "hmac": base64.b64decode(plain["session_hmac_b64"]),
    }
    return plain["ticket"], keys, plain["alg"], plain["expiry"]

def main():
    client_id = "C1"
    server_id = "S1"

    alg = "AES_GCM"

    ticket, session_keys, alg, expiry = get_session_from_kdc(client_id, server_id, alg)
    print(f"[Client] KDC session aldı. Alg={alg} expiry={expiry}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))

    authenticator_plain = {"client_id": client_id, "ts": now_ts(), "alg": alg}
    authenticator = encrypt_payload(alg, session_keys, authenticator_plain)

    send_msg(s, {"type": "AUTH", "ticket": ticket, "authenticator": authenticator})
    ok = recv_msg(s)
    print("[Client]", ok)

    if ok.get("type") != "OK":
        s.close()
        return

    counter = 1
    while True:
        text = input("Mesaj (çıkmak için q): ").strip()
        if text.lower() == "q":
            send_msg(s, {"type": "BYE"})
            print("[Client]", recv_msg(s))
            break

        plain = {"counter": counter, "text": text}
        counter += 1

        blob = encrypt_payload(alg, session_keys, plain)
        send_msg(s, {"type": "DATA", "blob": blob})

        resp = recv_msg(s)
        if resp.get("type") != "DATA":
            print("[Client] Hata:", resp)
            break

        resp_plain = decrypt_payload(resp["blob"], session_keys)
        print("[Client] Server:", resp_plain)
        counter += 1 

    s.close()

if __name__ == "__main__":
    main()
