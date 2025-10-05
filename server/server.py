# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
import socket
import threading
from crypto_algorithms import *  # Şifreleme algoritmaları burada

app = Flask(__name__)

CURRENT_IP = None
CURRENT_PORT = None
messages = []
server_socket = None
server_running = False

# 🔹 Mesaj çözme
def decrypt_message(algorithm, text):
    try:
        if algorithm == "caesar":
            return caesar_decrypt(text, 3)
        elif algorithm == "vigenere":
            return vigenere_decrypt(text, "anahtar")
        elif algorithm == "substitution":
            key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
            return substitution_decrypt(text, key_map)
        elif algorithm == "affine":
            return affine_decrypt(text, 5, 8)
        return text
    except Exception:
        return "❌ Çözülemedi"

# 🔹 Socket server başlatma
def start_socket_server(ip, port):
    global server_socket, server_running
    if server_running:
        print("⚠️ Server zaten çalışıyor!")
        return

    def server_loop():
        global server_socket, server_running
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("0.0.0.0", int(port)))
            server_socket.listen(5)
            server_running = True
            print(f"🟢 Server {ip}:{port} adresinde dinliyor...")

            while True:
                conn, addr = server_socket.accept()
                print(f"📡 Bağlantı geldi: {addr}")
                try:
                    data = conn.recv(4096).decode("utf-8", errors="replace")
                    if not data:
                        conn.close()
                        continue

                    if "||" in data:
                        algorithm, encrypted_text = data.split("||", 1)
                        decrypted_text = decrypt_message(algorithm, encrypted_text)
                    else:
                        algorithm = "plain"
                        decrypted_text = data

                    messages.append({
                        "direction": "Client → Server",
                        "algorithm": algorithm,
                        "encrypted": data,
                        "decrypted": decrypted_text
                    })
                    print(f"[CLIENT] {encrypted_text} ({algorithm}) → {decrypted_text}")
                    conn.send(f"Sunucu mesajı çözdü: {decrypted_text}".encode("utf-8"))
                except Exception as e:
                    print(f"⚠️ Hata: {e}")
                finally:
                    conn.close()
        except OSError as e:
            print(f"❌ Server başlatılamadı: {e}")
        finally:
            server_running = False

    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

# 🔹 Client’a mesaj gönderme
def send_to_client(ip, port, message, algorithm="caesar"):
    try:
        if algorithm == "caesar":
            encrypted = caesar_encrypt(message, 3)
        elif algorithm == "vigenere":
            encrypted = vigenere_encrypt(message, "anahtar")
        elif algorithm == "substitution":
            key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
            encrypted = substitution_encrypt(message, key_map)
        elif algorithm == "affine":
            encrypted = affine_encrypt(message, 5, 8)
        else:
            encrypted = message

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, int(port)))
        client_socket.send(f"{algorithm}||{encrypted}".encode("utf-8"))
        client_socket.close()

        messages.append({
            "direction": "Server → Client",
            "algorithm": algorithm,
            "encrypted": encrypted,
            "decrypted": message
        })
        print(f"[SERVER] {message} ({algorithm}) → {encrypted}")
        return True
    except Exception as e:
        print(f"⚠️ Gönderim hatası: {e}")
        return False

# 🔹 Ana sayfa
@app.route("/", methods=["GET"])
def index():
    return render_template("server.html", started=server_running, ip=CURRENT_IP, port=CURRENT_PORT)

# 🔹 Server başlatma
@app.route("/start_server", methods=["POST"])
def start_server():
    global CURRENT_IP, CURRENT_PORT
    CURRENT_IP = request.form.get("ip")
    CURRENT_PORT = request.form.get("port")

    if not CURRENT_IP or not CURRENT_PORT:
        return jsonify({"success": False, "error": "IP veya Port eksik!"})

    CURRENT_PORT = int(CURRENT_PORT)
    print(f"⚙️ Yeni ayarlar: {CURRENT_IP}:{CURRENT_PORT}")
    start_socket_server(CURRENT_IP, CURRENT_PORT)
    return jsonify({"success": True, "ip": CURRENT_IP, "port": CURRENT_PORT})

# 🔹 Mesaj geçmişi
@app.route("/messages")
def get_messages():
    return jsonify(messages[-10:])

# 🔹 Geçmişi temizle
@app.route("/clear", methods=["POST"])
def clear_messages():
    messages.clear()
    return jsonify({"cleared": True})

# 🔹 Client’a mesaj gönder
@app.route("/send", methods=["POST"])
def send_message():
    ip = request.form["ip"]
    port = request.form["port"]
    msg = request.form["message"]
    algorithm = request.form.get("algorithm", "caesar")
    success = send_to_client(ip, port, msg, algorithm)
    return jsonify({"success": success})

if __name__ == "__main__":
    print("🟡 Server başlatılabilir durumda — tarayıcıdan aç: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000)