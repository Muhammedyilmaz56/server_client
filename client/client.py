from flask import Flask, render_template, request, jsonify
import socket
import threading
from crypto_algorithms import *

app = Flask(__name__)

# 🔧 Dinamik olarak değişebilecek IP ve Port
CURRENT_IP = None
CURRENT_PORT = None

# 🔹 Gelen mesaj geçmişi
incoming_messages = []
listener_thread = None


# 🔸 Server'dan gelen mesajları dinle
def start_client_listener(ip, port):
    """Sunucudan gelen mesajları dinleyen thread."""
    def listener():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((ip, int(port)))
            s.listen(5)
            print(f"🟢 Client {ip}:{port} adresinde dinliyor...")

            while True:
                conn, addr = s.accept()
                data = conn.recv(1024).decode("utf-8")
                print(f"[SERVER'DAN GELEN]: {data}")
                incoming_messages.append(data)
                conn.close()

        except OSError as e:
            print(f"⚠️ Port {port} veya IP {ip} kullanılabilir değil: {e}")

    global listener_thread
    listener_thread = threading.Thread(target=listener, daemon=True)
    listener_thread.start()


# 🔸 Server'a mesaj gönder
def send_message(ip, port, message):
    """Server'a soket ile mesaj gönderir."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, int(port)))
        client_socket.send(message.encode("utf-8"))
        response = client_socket.recv(1024).decode("utf-8")
        client_socket.close()
        return response
    except Exception as e:
        return f"Hata: {str(e)}"


# 🔸 IP & Port ayarlarını güncelle (arayüzden)
@app.route("/update_config", methods=["POST"])
def update_config():
    global CURRENT_IP, CURRENT_PORT
    CURRENT_IP = request.form.get("ip")
    CURRENT_PORT = int(request.form.get("port"))

    print(f"⚙️ Yeni IP/Port: {CURRENT_IP}:{CURRENT_PORT}")

    start_client_listener(CURRENT_IP, CURRENT_PORT)
    return jsonify({"status": "ok", "ip": CURRENT_IP, "port": CURRENT_PORT})


# 🔸 Ana sayfa (mesaj gönderme)
@app.route("/", methods=["GET", "POST"])
def index():
    global CURRENT_IP, CURRENT_PORT
    response = None
    algorithm = None

    if request.method == "POST":
        ip = request.form.get("ip") or CURRENT_IP
        port = request.form.get("port") or CURRENT_PORT
        message = request.form.get("message")
        algorithm = request.form.get("algorithm")

        if not (ip and port):
            return render_template("client.html", response="⚠️ Lütfen önce IP ve port ayarlarını yapın!", ip=CURRENT_IP, port=CURRENT_PORT)

        if not algorithm:
            return render_template("client.html", response="⚠️ Lütfen bir şifreleme yöntemi seçiniz!", ip=CURRENT_IP, port=CURRENT_PORT)

        try:
            if algorithm == "caesar":
                shift = int(request.form.get("shift", 3))
                encrypted = caesar_encrypt(message, shift)

            elif algorithm == "vigenere":
                key = request.form.get("key", "anahtar").strip()

                if not key:
                    return render_template("client.html", response="Vigenère hatası: Anahtar boş olamaz!", ip=CURRENT_IP, port=CURRENT_PORT, selected_algorithm=algorithm)

                if not key.isalpha():
                    return render_template("client.html", response="Vigenère hatası: Anahtar sadece İngilizce harflerden oluşmalı!", ip=CURRENT_IP, port=CURRENT_PORT, selected_algorithm=algorithm)

                forbidden_chars = "ığüşöçİĞÜŞÖÇ"
                if any(ch in forbidden_chars for ch in key):
                    return render_template("client.html", response="Vigenère hatası: Anahtar Türkçe karakter içeremez!", ip=CURRENT_IP, port=CURRENT_PORT, selected_algorithm=algorithm)

                encrypted = vigenere_encrypt(message, key)

            elif algorithm == "substitution":
                key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
                encrypted = substitution_encrypt(message, key_map)

            elif algorithm == "affine":
                a = int(request.form.get("a", 5))
                b = int(request.form.get("b", 8))
                encrypted = affine_encrypt(message, a, b)

            else:
                encrypted = message

            response = send_message(ip, port, f"{algorithm}||{encrypted}")

        except Exception as e:
            response = f"Hata: {e}"

    return render_template("client.html", response=response, ip=CURRENT_IP, port=CURRENT_PORT, selected_algorithm=algorithm)


# 🔸 Mesaj geçmişini JSON olarak döndür
@app.route("/incoming")
def get_incoming_messages():
    return jsonify(incoming_messages)


# 🔸 Geçmiş temizleme
@app.route("/clear", methods=["POST"])
def clear_messages():
    incoming_messages.clear()
    return jsonify({"cleared": True})


# 🔸 Uygulama başlatma
if __name__ == "__main__":
    app.run(debug=False, port=5001)
