from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import socket
import threading
from crypto_algorithms import *
import math
import requests
from rsa_key_exchange import rsa_encrypt_key

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

CURRENT_IP = None
CURRENT_PORT = None
SESSION_AES_KEY = None

incoming_messages = []

listener_thread = None
listener_socket = None
listener_running = False

client_socket = None
client_connected = False

CURRENT_DECRYPT_ALGO = None
CURRENT_DECRYPT_KEY = None

@app.route("/rsa/setup", methods=["POST"])
def rsa_setup():
    global SESSION_AES_KEY
    server_http = request.form.get("server_http")
    aes_password = request.form.get("aes_password")

    if not server_http or not aes_password:
        return jsonify({"success": False, "error": "server_http veya aes_password eksik"})

    b = aes_password.encode("utf-8")
    if len(b) < 16:
        b = b.ljust(16, b"\x00")
    elif len(b) > 16:
        b = b[:16]
    SESSION_AES_KEY = b

    try:
        r = requests.get(f"{server_http}/rsa/public_key", timeout=10)
        pub_pem = r.json()["public_key"].encode("utf-8")
        enc_b64 = rsa_encrypt_key(SESSION_AES_KEY, pub_pem)
        r2 = requests.post(f"{server_http}/rsa/set_aes_key", data={"enc_key": enc_b64}, timeout=10)
        j = r2.json()
        if not j.get("success"):
            return jsonify({"success": False, "error": j.get("error", "RSA setup başarısız")})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

def decrypt_message(algorithm, text, key=None):
    try:
        if not algorithm:
            return (text, 0.0)

        if algorithm == "caesar":
            shift = int(key) if key else 3
            return (caesar_decrypt(text, shift), 0.0)
        elif algorithm == "vigenere":
            key = key if key else "anahtar"
            return (vigenere_decrypt(text, key), 0.0)
        elif algorithm == "substitution":
            key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
            return (substitution_decrypt(text, key_map), 0.0)
        elif algorithm == "affine":
            if not key or "," not in key:
                return ("Hatalı affine anahtarı!", 0.0)
            a, b = map(int, key.split(","))
            if math.gcd(a, 26) != 1:
                return (f"a={a} 26 ile aralarında asal değil!", 0.0)
            return (affine_decrypt(text, a, b), 0.0)
        elif algorithm == "playfair":
            key = key if key else "monarchy"
            return (playfair_decrypt(text, key), 0.0)
        elif algorithm == "railfence":
            key = int(key) if key else 2
            return (rail_fence_decrypt(text, key), 0.0)
        elif algorithm == "route":
            cols = int(key) if key else 5
            return (route_decrypt(text, cols), 0.0)
        elif algorithm == "columnar":
            key = key if key else "TRUVA"
            return (columnar_decrypt(text, key), 0.0)
        elif algorithm == "polybius":
            return (polybius_decrypt(text), 0.0)
        elif algorithm == "pigpen":
            return (pigpen_decrypt(text), 0.0)
        elif algorithm == "hill":
            key = key if key else "3 3 2 5"
            return (hill_decrypt(text, key), 0.0)
        elif algorithm == "des":
            key = key if key else "despass1"
            return des_decrypt_message(text, key)
        elif algorithm == "des_lib":
            key = key if key else "despass1"
            return des_decrypt_message_lib(text, key)
        elif algorithm == "aes":
            key = key if key else "aespass123"
            return aes_decrypt_message(text, key)
        elif algorithm == "aes_lib":
            key = key if key else "aespass123"
            return aes_decrypt_message_lib(text, key)
        elif algorithm == "aes_session":
            if SESSION_AES_KEY is None:
                return ("Hata: RSA ile AES anahtarı kurulmadı (SESSION_AES_KEY boş)", 0.0)
            return aes_decrypt_message(text, SESSION_AES_KEY.decode("utf-8", errors="ignore"))
        else:
            return (text, 0.0)
    except Exception as e:
        return (f"Hata: {e}", 0.0)

def start_client_listener(ip, port):
    global listener_thread, listener_socket, listener_running
    if listener_running:
        return

    def listener():
        global listener_socket, listener_running
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener_socket.bind(("0.0.0.0", int(port)))
            listener_socket.listen(5)
            listener_running = True

            while True:
                conn, addr = listener_socket.accept()
                while True:
                    raw = conn.recv(4096)
                    if not raw:
                        break
                    data = raw.decode("utf-8", errors="replace").strip()

                    algorithm = CURRENT_DECRYPT_ALGO
                    key = CURRENT_DECRYPT_KEY
                    encrypted_text = data

                    parts = data.split("||", 2)
                    if len(parts) == 3:
                        algorithm, key, encrypted_text = parts[0], parts[1], parts[2]
                        if key == "":
                            key = None

                    decrypted, decrypt_time = decrypt_message(algorithm, encrypted_text, key)

                    msg_data = {
                        "from": "server",
                        "algorithm": algorithm or "unknown",
                        "key": key or "-",
                        "encrypted": encrypted_text,
                        "decrypted": decrypted,
                        "decrypt_time": f"{decrypt_time:.6f}" if decrypt_time > 0 else None
                    }

                    incoming_messages.append(msg_data)
                    socketio.emit("incoming_new", msg_data)

                conn.close()
        except OSError:
            pass
        finally:
            listener_running = False

    listener_thread = threading.Thread(target=listener, daemon=True)
    listener_thread.start()

def send_message(ip, port, message, algorithm="caesar", key=None):
    global client_socket, client_connected
    try:
        if not client_connected:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, int(port)))
            client_connected = True

        encrypt_time = 0.0
        if algorithm == "caesar":
            shift = int(key) if key else 3
            encrypted = caesar_encrypt(message, shift)
        elif algorithm == "vigenere":
            key = key if key else "anahtar"
            encrypted = vigenere_encrypt(message, key)
        elif algorithm == "substitution":
            key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
            encrypted = substitution_encrypt(message, key_map)
        elif algorithm == "affine":
            if not key or "," not in key:
                raise ValueError("Affine anahtarı a,b şeklinde olmalı!")
            a, b = map(int, key.split(","))
            if math.gcd(a, 26) != 1:
                raise ValueError(f"a={a} 26 ile aralarında asal değil!")
            encrypted = affine_encrypt(message, a, b)
        elif algorithm == "playfair":
            key = key if key else "monarchy"
            encrypted = playfair_encrypt(message, key)
        elif algorithm == "railfence":
            key = int(key) if key else 2
            encrypted = rail_fence_encrypt(message, key)
        elif algorithm == "route":
            cols = int(key) if key else 5
            encrypted = route_encrypt(message, cols)
        elif algorithm == "columnar":
            key = key if key else "TRUVA"
            encrypted = columnar_encrypt(message, key)
        elif algorithm == "polybius":
            encrypted = polybius_encrypt(message)
        elif algorithm == "pigpen":
            encrypted = pigpen_encrypt(message)
        elif algorithm == "hill":
            key = key if key else "3 3 2 5"
            encrypted = hill_encrypt(message, key)
        elif algorithm == "des":
            key = key if key else "despass1"
            encrypted, encrypt_time = des_encrypt_message(message, key)
        elif algorithm == "des_lib":
            key = key if key else "despass1"
            encrypted, encrypt_time = des_encrypt_message_lib(message, key)
        elif algorithm == "aes":
            key = key if key else "aespass123"
            encrypted, encrypt_time = aes_encrypt_message(message, key)
        elif algorithm == "aes_lib":
            key = key if key else "aespass123"
            encrypted, encrypt_time = aes_encrypt_message_lib(message, key)
        elif algorithm == "aes_session":
            if SESSION_AES_KEY is None:
                return "Hata: Önce RSA ile AES anahtarı kurulmalı."
            encrypted, encrypt_time = aes_encrypt_message(message, SESSION_AES_KEY.decode("utf-8", errors="ignore"))
        else:
            encrypted = message

        payload = f"{algorithm}||{key or ''}||{encrypted}"
        client_socket.send(payload.encode("utf-8"))

        msg_data = {
            "from": "client",
            "algorithm": algorithm,
            "key": key or "-",
            "encrypted": encrypted,
            "decrypted": message,
            "encrypt_time": f"{encrypt_time:.6f}" if encrypt_time > 0 else None
        }
        incoming_messages.append(msg_data)
        socketio.emit("incoming_new", msg_data)
        return "Mesaj gönderildi."
    except Exception as e:
        return f"Hata: {str(e)}"

@app.route("/update_config", methods=["POST"])
def update_config():
    global CURRENT_IP, CURRENT_PORT
    CURRENT_IP = request.form.get("ip")
    CURRENT_PORT = request.form.get("port")
    if not CURRENT_IP or not CURRENT_PORT:
        return jsonify({"status": "error", "message": "IP veya Port eksik!"})

    CURRENT_PORT = int(CURRENT_PORT)
    start_client_listener(CURRENT_IP, CURRENT_PORT)
    return jsonify({"status": "ok", "ip": CURRENT_IP, "port": CURRENT_PORT})

@app.route("/send_message", methods=["POST"])
def send_message_ajax():
    ip = request.form.get("ip")
    port = request.form.get("port")
    message = request.form.get("message")
    algorithm = request.form.get("algorithm")
    key = request.form.get("key")

    if not ip or not port or not message:
        return jsonify({"success": False, "response": "Eksik alanlar var!"})

    response = send_message(ip, port, message, algorithm, key)
    success = not str(response).startswith("Hata:")
    return jsonify({"success": success, "response": response})

@app.route("/update_decryption_algo", methods=["POST"])
def update_decryption_algo():
    global CURRENT_DECRYPT_ALGO, CURRENT_DECRYPT_KEY
    CURRENT_DECRYPT_ALGO = request.form.get("algorithm")
    CURRENT_DECRYPT_KEY = request.form.get("key")
    return jsonify({"status": "ok", "algorithm": CURRENT_DECRYPT_ALGO})

@app.route("/clear", methods=["POST"])
def clear_messages():
    incoming_messages.clear()
    socketio.emit("incoming_cleared")
    return jsonify({"cleared": True})

@app.route("/")
def index():
    return render_template("client.html", ip=CURRENT_IP, port=CURRENT_PORT)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001)
