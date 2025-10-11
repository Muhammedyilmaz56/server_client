from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import socket
import threading
from crypto_algorithms import *
import math

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

CURRENT_IP = None
CURRENT_PORT = None
messages = []
server_socket = None
server_running = False


def decrypt_message(algorithm, text, key=None):
    try:
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
                return "Hatalı affine anahtarı"
            a, b = map(int, key.split(","))
            if math.gcd(a, 26) != 1:
                return f"a={a} 26 ile aralarında asal değil!"
            return affine_decrypt(text, a, b)
        return text
    except Exception as e:
        return f"Hata: {e}"


def start_socket_server(ip, port):
    global server_socket, server_running
    if server_running:
        return

    def server_loop(bind_ip, bind_port):
        global server_socket, server_running
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((bind_ip, int(bind_port)))
            server_socket.listen(5)
            server_running = True
            print(f"Server {bind_ip}:{bind_port} adresinde dinliyor...")

            while server_running:
                conn, addr = server_socket.accept()
                client_ip, client_port = addr
                data = conn.recv(4096).decode("utf-8", errors="replace")
                if not data:
                    conn.close()
                    continue

                if "||" in data:
                    parts = data.split("||", 2)
                    algorithm = parts[0]
                    if len(parts) == 3:
                        key, encrypted_text = parts[1], parts[2]
                    else:
                        key, encrypted_text = None, parts[1]
                    decrypted_text = decrypt_message(algorithm, encrypted_text, key)
                    payload = data
                else:
                    algorithm = "plain"
                    payload = data
                    decrypted_text = data

                new_message = {
                    "direction": "Client → Server",
                    "algorithm": algorithm,
                    "encrypted": payload,
                    "decrypted": decrypted_text
                }
                messages.append(new_message)
                socketio.emit('new_message', new_message)
                conn.send(f"Sunucu cevabı: {decrypted_text}".encode("utf-8"))
                conn.close()
        except Exception as e:
            print("Server hatası:", e)
        finally:
            server_running = False
            if server_socket:
                try:
                    server_socket.close()
                except:
                    pass
            print("Server kapatıldı.")

    t = threading.Thread(target=server_loop, args=(ip, port), daemon=True)
    t.start()


def send_to_client(ip, port, message, algorithm="caesar", key=None):
    try:
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
                raise ValueError("Affine anahtarı a,b şeklinde olmalı")
            a, b = map(int, key.split(","))
            if math.gcd(a, 26) != 1:
                raise ValueError(f"a={a} 26 ile aralarında asal değil!")
            encrypted = affine_encrypt(message, a, b)
        else:
            encrypted = message

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        send_data = f"{algorithm}||{key or ''}||{encrypted}"
        s.send(send_data.encode("utf-8"))
        s.close()

        new_message = {
            "direction": "Server → Client",
            "algorithm": algorithm,
            "encrypted": encrypted,
            "decrypted": message
        }
        messages.append(new_message)
        socketio.emit('new_message', new_message)
        return True
    except Exception as e:
        print("Gönderim hatası:", e)
        return False


@app.route("/")
def index():
    return render_template("server.html", started=server_running, ip=CURRENT_IP, port=CURRENT_PORT)


@app.route("/start_server", methods=["POST"])
def start_server():
    global CURRENT_IP, CURRENT_PORT
    CURRENT_IP = request.form.get("ip")
    CURRENT_PORT = request.form.get("port")
    if not CURRENT_IP or not CURRENT_PORT:
        return jsonify({"success": False, "error": "IP veya Port eksik"})
    start_socket_server(CURRENT_IP, int(CURRENT_PORT))
    return jsonify({"success": True, "ip": CURRENT_IP, "port": CURRENT_PORT})


@app.route("/send", methods=["POST"])
def send_message():
    ip = request.form["ip"]
    port = request.form["port"]
    msg = request.form["message"]
    algorithm = request.form.get("algorithm", "caesar")
    key = request.form.get("key")
    success = send_to_client(ip, port, msg, algorithm, key)
    return jsonify({"success": success})


@socketio.on("connect")
def on_connect():
    emit("message_history", messages)


@socketio.on("clear_messages")
def on_clear():
    messages.clear()
    emit("messages_cleared")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
