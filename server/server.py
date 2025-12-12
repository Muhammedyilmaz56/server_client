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

        elif algorithm == "hill":
            key = key if key else "3 3 2 5"
            return hill_decrypt(text, key)

       
        elif algorithm == "des":
            key = key if key else "despass1"
            return des_decrypt_message(text, key)
        elif algorithm == "des_lib":
            key = key if key else "despass1"
            return des_decrypt_message_lib(text, key)


        else:
            return text

    except Exception as e:
        return f"Hata: {e}"


def start_socket_server(ip, port):
    global server_socket, server_running
    if server_running:
        print("Sunucu zaten çalışıyor.")
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
                print(f"Yeni bağlantı: {client_ip}:{client_port}")

                while True:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            break
                        payload = data.decode("utf-8", errors="replace").strip()
                    except ConnectionResetError:
                        break

                    
                    algo_label = ""
                    key_used = None
                    cipher_text = payload

                    parts = payload.split("||", 2)
                    if len(parts) == 3:
                        algo_label, key_used, cipher_text = parts[0], parts[1], parts[2]
                        if key_used == "":
                            key_used = None

                    decrypted_text = decrypt_message(algo_label, cipher_text, key_used)

                    new_message = {
                        "direction": "Client → Server",
                        "algorithm": algo_label,
                        "encrypted": cipher_text,
                        "decrypted": decrypted_text
                    }
                    messages.append(new_message)
                    socketio.emit('new_message', new_message)

                    try:
                        conn.send(b"OK")
                    except:
                        pass

                conn.close()
                print(f"Bağlantı kapandı: {client_ip}:{client_port}")

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
            encrypted = des_encrypt_message(message, key)
        elif algorithm == "des_lib":
            key = key if key else "despass1"
            encrypted = des_encrypt_message_lib(message, key)


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
        return True, None

    except Exception as e:
        print("Gönderim hatası:", e)
        return False, str(e)


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

    success, error = send_to_client(ip, port, msg, algorithm, key)
    return jsonify({"success": success, "error": error})


@app.route("/send_message", methods=["POST"])
def send_message_legacy():
    return send_message()


@socketio.on("connect")
def on_connect():
    emit("message_history", messages)


@socketio.on("clear_messages")
def on_clear():
    messages.clear()
    emit("messages_cleared")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
