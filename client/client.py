from flask import Flask, render_template, request, jsonify
import socket
import threading
from crypto_algorithms import *

app = Flask(__name__)

# Sunucudan gelen mesaj geçmişi
incoming_messages = []

# 🔹 Socket ile server'a mesaj gönder
def send_message(ip, port, message):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, int(port)))
        client_socket.send(message.encode("utf-8"))
        response = client_socket.recv(1024).decode("utf-8")
        client_socket.close()
        return response
    except Exception as e:
        return f"Hata: {str(e)}"

# 🔹 Server'dan gelen mesajları dinle
def start_client_listener(port=6001):
    def listener():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", port))
        s.listen(5)
        print(f"Client gelen mesajları {port} portundan dinliyor...")

        while True:
            conn, addr = s.accept()
            data = conn.recv(1024).decode("utf-8")
            print(f"[SERVER'DAN GELEN]: {data}")
            incoming_messages.append(data)
            conn.close()

    threading.Thread(target=listener, daemon=True).start()

# 🔹 Ana sayfa (mesaj gönderme)
@app.route("/", methods=["GET", "POST"])
def index():
    response = None
    if request.method == "POST":
        ip = request.form.get("ip")
        port = request.form.get("port")
        message = request.form.get("message")
        algorithm = request.form.get("algorithm")

        if not algorithm:
            return render_template("client.html", response="Lütfen bir şifreleme yöntemi seçiniz!")

        # Şifreleme türüne göre işle
        if algorithm == "caesar":
            shift = int(request.form.get("shift", 3))
            encrypted = caesar_encrypt(message, shift)
        elif algorithm == "vigenere":
            key = request.form.get("key", "anahtar")
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

    return render_template("client.html", response=response)

# 🔹 Sunucudan gelen mesajları JSON olarak döndür (AJAX için)
@app.route("/incoming")
def get_incoming_messages():
    return jsonify(incoming_messages)

@app.route("/clear", methods=["POST"])
def clear_messages():
    incoming_messages.clear()
    return jsonify({"cleared": True})

if __name__ == "__main__":
    start_client_listener(6001)
    app.run(debug=True, port=5001)
