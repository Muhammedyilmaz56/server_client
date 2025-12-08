from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import socket
import threading
from crypto_algorithms import *
import math

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

CURRENT_IP = None
CURRENT_PORT = None
incoming_messages = []

listener_thread = None
listener_socket = None
listener_running = False

client_socket = None
client_connected = False


LAST_ALGO_SENT = None
LAST_KEY_SENT = None
CURRENT_DECRYPT_ALGO = None
CURRENT_DECRYPT_KEY = None



def decrypt_message(algorithm, text, key=None):
    try:
        if not algorithm:
            return text
        if algorithm == "caesar":
            shift = int(key) if key else 3
            return caesar_decrypt(text, shift)
        elif algorithm == "vigenere":
            key = key if key else "anahtar"
            return vigenere_decrypt(text, key)
        elif algorithm == "substitution":
            key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
            return substitution_decrypt(text, key_map)
        elif algorithm == "affine":
            if not key or "," not in key:
                return "Hatalı affine anahtarı!"
            a, b = map(int, key.split(","))
            if math.gcd(a, 26) != 1:
                return f"a={a} 26 ile aralarında asal değil!"
            return affine_decrypt(text, a, b)
        elif algorithm == "playfair":
            key = key if key else "monarchy"
            return playfair_decrypt(text, key)
        elif algorithm == "railfence":
            key = int(key) if key else 2
            return rail_fence_decrypt(text, key)
        elif algorithm == "route":
            cols = int(key) if key else 5
            return route_decrypt(text, cols)
        elif algorithm == "columnar":
            key = key if key else "TRUVA"
            return columnar_decrypt(text, key)
        elif algorithm == "polybius":
            return polybius_decrypt(text)
        elif algorithm == "pigpen":
            return pigpen_decrypt(text)
        elif algorithm == "pigpen":
            return pigpen_decrypt(text)

        
        elif algorithm == "hill":
            key = key if key else "3 3 2 5"   
            return hill_decrypt(text, key)

        else:
            return text
    except Exception as e:
        return f"Hata: {e}"



def start_client_listener(ip, port):
    global listener_thread, listener_socket, listener_running
    if listener_running:
        print("Dinleyici zaten çalışıyor.")
        return

    def listener():
        global listener_socket, listener_running
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener_socket.bind(("0.0.0.0", int(port)))
            listener_socket.listen(5)
            listener_running = True
            print(f"Client {ip}:{port} adresinde dinliyor...")

            while True:
                conn, addr = listener_socket.accept()
                while True:
                    data = conn.recv(4096).decode("utf-8", errors="replace")
                    if not data:
                        break

                    # 🔹 Server "algo||key||şifreli" formatında gönderir
                    if "||" in data:
                        parts = data.split("||", 2)
                        algorithm = parts[0]
                        if len(parts) == 3:
                            key, encrypted_text = parts[1], parts[2]
                        else:
                            key, encrypted_text = None, parts[1]
                    else:
                        algorithm = CURRENT_DECRYPT_ALGO
                        key = CURRENT_DECRYPT_KEY
                        encrypted_text = data.strip()

                    decrypted = decrypt_message(algorithm, encrypted_text, key)

                    msg_data = {
                        "from": "server",
                        "algorithm": algorithm or "unknown",
                        "key": key or "-",
                        "encrypted": encrypted_text,
                        "decrypted": decrypted
                    }

                    incoming_messages.append(msg_data)
                    socketio.emit("incoming_new", msg_data)

                conn.close()
        except OSError as e:
            print(f"Listener başlatılamadı: {e}")
        finally:
            listener_running = False

    listener_thread = threading.Thread(target=listener, daemon=True)
    listener_thread.start()


# ---------------- Mesaj Gönderme ----------------
def send_message(ip, port, message, algorithm="caesar", key=None):
    global client_socket, client_connected, LAST_ALGO_SENT, LAST_KEY_SENT
    try:
        LAST_ALGO_SENT, LAST_KEY_SENT = algorithm, key

        if not client_connected:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, int(port)))
            client_connected = True
            print(f"{ip}:{port} adresine bağlantı kuruldu.")

        # 🔹 Mesajı şifrele
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

        else:
            encrypted = message

        # 🔹 Server’a gönder
        client_socket.send(encrypted.encode("utf-8"))

        msg_data = {
            "from": "client",
            "algorithm": algorithm,
            "key": key or "-",
            "encrypted": encrypted,
            "decrypted": message
        }
        incoming_messages.append(msg_data)
        socketio.emit("incoming_new", msg_data)
        return "Mesaj gönderildi."
    except Exception as e:
        return f"Hata: {str(e)}"


# ---------------- Flask Routes ----------------
@app.route("/update_config", methods=["POST"])
def update_config():
    global CURRENT_IP, CURRENT_PORT
    CURRENT_IP = request.form.get("ip")
    CURRENT_PORT = request.form.get("port")
    if not CURRENT_IP or not CURRENT_PORT:
        return jsonify({"status": "error", "message": "IP veya Port eksik!"})
    CURRENT_PORT = int(CURRENT_PORT)
    print(f"Dinleme başlatıldı: {CURRENT_IP}:{CURRENT_PORT}")
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
    print(f"Client çözüm algoritması güncellendi: {CURRENT_DECRYPT_ALGO} ({CURRENT_DECRYPT_KEY})")
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
    print("Client başlatıldı.")
    socketio.run(app, host="0.0.0.0", port=5001)
