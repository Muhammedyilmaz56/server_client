from flask import Flask, render_template, request, jsonify
import socket
import threading
from crypto_algorithms import *

app = Flask(__name__)

messages = []


# 🔹 Socket server başlatma
def start_socket_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    server_socket.listen(5)
    print(f"Socket server {ip}:{port} üzerinde dinleniyor...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Bağlantı geldi: {addr}")

        try:
            data = conn.recv(4096).decode("utf-8")
            if not data:
                conn.close()
                continue

            # Mesaj formatı: algorithm||encrypted_text
            try:
                algorithm, encrypted_text = data.split("||", 1)
            except ValueError:
                algorithm = "unknown"
                encrypted_text = data

            decrypted_text = decrypt_message(algorithm, encrypted_text)

            messages.append({
                "direction": "Client → Server",
                "algorithm": algorithm,
                "encrypted": encrypted_text,
                "decrypted": decrypted_text
            })

            print(f"[CLIENT] {encrypted_text} ({algorithm}) → {decrypted_text}")
            conn.send(f"Sunucu mesajı çözdü: {decrypted_text}".encode("utf-8"))

        except Exception as e:
            print(f"Hata: {e}")
        finally:
            conn.close()


# 🔹 Mesaj çözme
def decrypt_message(algorithm, encrypted_text):
    try:
        if algorithm == "caesar":
            return caesar_decrypt(encrypted_text, 3)
        elif algorithm == "vigenere":
            return vigenere_decrypt(encrypted_text, "anahtar")
        elif algorithm == "substitution":
            key_map = {chr(97 + i): chr(97 + ((i + 5) % 26)) for i in range(26)}
            return substitution_decrypt(encrypted_text, key_map)
        elif algorithm == "affine":
            return affine_decrypt(encrypted_text, 5, 8)
        else:
            return encrypted_text
    except Exception:
        return "Çözülemedi"


# 🔹 Server'dan client'a mesaj gönder
def send_to_client(ip, port, message):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, int(port)))
        client_socket.send(f"plain||{message}".encode("utf-8"))
        client_socket.close()

        messages.append({
            "direction": "Server → Client",
            "algorithm": "plain",
            "encrypted": message,
            "decrypted": message
        })
        return True
    except Exception as e:
        print(f"Gönderim hatası: {e}")
        return False


# 🔹 Flask Routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip = request.form["ip"]
        port = request.form["port"]

        t = threading.Thread(target=start_socket_server, args=(ip, port))
        t.daemon = True
        t.start()

        return render_template("server.html", started=True, ip=ip, port=port)
    return render_template("server.html", started=False)


@app.route("/messages")
def get_messages():
    # Sadece son 10 mesajı döndür
    return jsonify(messages[-10:])


@app.route("/clear", methods=["POST"])
def clear_messages():
    messages.clear()
    return jsonify({"cleared": True})


@app.route("/send", methods=["POST"])
def send_message():
    ip = request.form["ip"]
    port = request.form["port"]
    msg = request.form["message"]
    success = send_to_client(ip, port, msg)
    return jsonify({"success": success})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
