# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
import socket
import threading
from crypto_algorithms import *  # Şifreleme algoritmalarınız burada

app = Flask(__name__)

CURRENT_IP = None
CURRENT_PORT = None
incoming_messages = []
listener_thread = None
listener_socket = None
listener_running = False


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
        else:
            return text
    except Exception:
        return "❌ Çözülemedi"


# 🔸 Client dinleyicisini başlat
def start_client_listener(ip, port):
    global listener_thread, listener_socket, listener_running

    if listener_running:
        print("⚠️ Dinleyici zaten çalışıyor.")
        return

    def listener():
        global listener_socket, listener_running
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener_socket.bind(("0.0.0.0", int(port)))  # 🔸 Tüm IP’leri dinle
            listener_socket.listen(5)
            listener_running = True
            print(f"🟢 Client {ip}:{port} adresinde dinliyor...")

            while True:
                conn, addr = listener_socket.accept()
                data = conn.recv(2048).decode("utf-8", errors="replace")

                if not data:
                    conn.close()
                    continue

                print(f"[SERVER'DAN GELEN]: {data}")

                if "||" in data:
                    algorithm, encrypted_text = data.split("||", 1)
                    decrypted_text = decrypt_message(algorithm, encrypted_text)
                    incoming_messages.append(f"🔓 {algorithm.upper()} → {decrypted_text}")
                else:
                    incoming_messages.append(f"📩 {data}")

                conn.close()

        except OSError as e:
            print(f"⚠️ Listener başlatılamadı: {e}")
        finally:
            listener_running = False

    listener_thread = threading.Thread(target=listener, daemon=True)
    listener_thread.start()


# 🔸 Sunucuya mesaj gönder
def send_message(ip, port, message):
    if not ip or not port:
        return "⚠️ IP veya port belirtilmedi."
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send(message.encode("utf-8", errors="replace"))
        try:
            response = s.recv(1024).decode("utf-8", errors="replace")
        except:
            response = "✅ Mesaj gönderildi."
        s.close()
        return response
    except Exception as e:
        return f"⚠️ Bağlantı hatası: {str(e)}"


# 🔸 IP & Port ayarlarını güncelle
@app.route("/update_config", methods=["POST"])
def update_config():
    global CURRENT_IP, CURRENT_PORT
    CURRENT_IP = request.form.get("ip")
    CURRENT_PORT = request.form.get("port")

    if not CURRENT_IP or not CURRENT_PORT:
        return jsonify({"status": "error", "message": "IP veya Port eksik!"})

    CURRENT_PORT = int(CURRENT_PORT)
    print(f"⚙️ Yeni dinleme ayarları: {CURRENT_IP}:{CURRENT_PORT}")
    start_client_listener(CURRENT_IP, CURRENT_PORT)
    return jsonify({"status": "ok", "ip": CURRENT_IP, "port": CURRENT_PORT})


# 🔸 Mesaj gönderme (AJAX)
@app.route("/send_message", methods=["POST"])
def send_message_ajax():
    ip = request.form.get("ip")
    port = request.form.get("port")
    message = request.form.get("message")
    algorithm = request.form.get("algorithm")

    try:
        # 🔐 Şifreleme
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

        response = send_message(ip, port, f"{algorithm}||{encrypted}")
        return jsonify({"success": True, "response": response})
    except Exception as e:
        return jsonify({"success": False, "response": str(e)})


# 🔸 Mesaj geçmişi
@app.route("/incoming")
def get_incoming_messages():
    return jsonify(incoming_messages[-10:])


# 🔸 Mesaj geçmişini temizle
@app.route("/clear", methods=["POST"])
def clear_messages():
    incoming_messages.clear()
    return jsonify({"cleared": True})


@app.route("/")
def index():
    return render_template("client.html", ip=CURRENT_IP, port=CURRENT_PORT)


if __name__ == "__main__":
    print("🟡 Client başlatıldı — IP girilmeden dinleme yapılmayacak.")
    app.run(host="0.0.0.0", port=5001)
