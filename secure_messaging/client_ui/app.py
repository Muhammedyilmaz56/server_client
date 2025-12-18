import socket
import base64
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] 
sys.path.insert(0, str(ROOT))


from core.wire import send_msg, recv_msg
from core.crypto_utils import kdf_from_passphrase, aes_gcm_decrypt, encrypt_payload, decrypt_payload, now_ts

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"
socketio = SocketIO(app, cors_allowed_origins="*")

K_C = kdf_from_passphrase("CLIENT_MASTER_KEY_DEMO", 32)

STATE = {
    "kdc_host": "",
    "kdc_port": "",
    "server_host": "",
    "server_port": "",
    "client_id": "C1",
    "server_id": "S1",
    "alg": "AES_GCM",
    "ticket": None,
    "keys": None,
    "conn": None,
    "counter": 1,
}

def log(msg: str):
    socketio.emit("log", {"text": msg})

def chat(side: str, alg: str, encrypted: str, decrypted: str):
    socketio.emit("incoming_new", {
        "from": side,
        "algorithm": alg,
        "encrypted": encrypted,
        "decrypted": decrypted
    })

@app.get("/")
def index():
    return render_template("index.html", state=STATE)

@app.post("/save")
def save():
    STATE["kdc_host"] = request.form.get("kdc_host","").strip()
    STATE["kdc_port"] = request.form.get("kdc_port","").strip()
    STATE["server_host"] = request.form.get("server_host","").strip()
    STATE["server_port"] = request.form.get("server_port","").strip()
    STATE["client_id"] = request.form.get("client_id","C1").strip()
    STATE["server_id"] = request.form.get("server_id","S1").strip()
    STATE["alg"] = request.form.get("alg","AES_GCM").strip()
    log("[Client] Ayarlar kaydedildi.")
    return jsonify({"ok": True})

@app.post("/kdc_session")
def kdc_session():
    try:
        if not STATE["kdc_host"] or not STATE["kdc_port"]:
            return jsonify({"ok": False, "error": "KDC host/port gir."})

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((STATE["kdc_host"], int(STATE["kdc_port"])))
        send_msg(s, {"type": "KEY_REQ", "client_id": STATE["client_id"], "server_id": STATE["server_id"], "alg": STATE["alg"]})
        res = recv_msg(s)
        s.close()

        if res.get("type") != "KEY_RES":
            return jsonify({"ok": False, "error": res.get("error","KDC hata")})

        plain = aes_gcm_decrypt(K_C, res["enc_for_client"])

        STATE["ticket"] = plain["ticket"]
        STATE["keys"] = {
            "aes": base64.b64decode(plain["session_aes_b64"]),
            "des": base64.b64decode(plain["session_des_b64"]),
            "hmac": base64.b64decode(plain["session_hmac_b64"]),
        }
        STATE["counter"] = 1

        log(f"[Client] KDC session alındı. alg={plain['alg']} expiry={plain['expiry']}")
        return jsonify({"ok": True})
    except Exception as e:
        log(f"[Client] KDC session hata: {e}")
        return jsonify({"ok": False, "error": str(e)})

@app.post("/connect_server")
def connect_server():
    try:
        if not STATE["server_host"] or not STATE["server_port"]:
            return jsonify({"ok": False, "error": "Server host/port gir."})
        if not STATE["ticket"] or not STATE["keys"]:
            return jsonify({"ok": False, "error": "Önce KDC session al."})

        if STATE["conn"]:
            try: STATE["conn"].close()
            except: pass
            STATE["conn"] = None

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((STATE["server_host"], int(STATE["server_port"])))

        authenticator_plain = {"client_id": STATE["client_id"], "ts": now_ts(), "alg": STATE["alg"]}
        authenticator = encrypt_payload(STATE["alg"], STATE["keys"], authenticator_plain)

        send_msg(conn, {"type":"AUTH", "ticket": STATE["ticket"], "authenticator": authenticator})
        ok = recv_msg(conn)
        if ok.get("type") != "OK":
            conn.close()
            return jsonify({"ok": False, "error": ok})

        STATE["conn"] = conn
        STATE["counter"] = 1
        log("[Client] Server handshake OK.")
        return jsonify({"ok": True})
    except Exception as e:
        log(f"[Client] Server connect hata: {e}")
        return jsonify({"ok": False, "error": str(e)})

@app.post("/send")
def send_data():
    try:
        msg = request.form.get("message","").strip()
        if not msg:
            return jsonify({"ok": False, "error": "Mesaj boş."})
        if not STATE["conn"] or not STATE["keys"]:
            return jsonify({"ok": False, "error": "Server bağlı değil."})

        c = STATE["counter"]
        plain = {"counter": c, "text": msg}
        blob = encrypt_payload(STATE["alg"], STATE["keys"], plain)

        chat("client", STATE["alg"], f"{blob.get('alg')}:{list(blob.keys())}", msg)

        send_msg(STATE["conn"], {"type":"DATA", "blob": blob})
        resp = recv_msg(STATE["conn"])
        if resp.get("type") != "DATA":
            return jsonify({"ok": False, "error": resp})

        resp_plain = decrypt_payload(resp["blob"], STATE["keys"])
        chat("server", STATE["alg"], f"{resp['blob'].get('alg')}:{list(resp['blob'].keys())}", resp_plain.get("text",""))

        STATE["counter"] = c + 2
        return jsonify({"ok": True})
    except Exception as e:
        log(f"[Client] Send hata: {e}")
        return jsonify({"ok": False, "error": str(e)})

@app.post("/clear")
def clear():
    socketio.emit("incoming_cleared")
    return jsonify({"ok": True})

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5300, debug=True)
