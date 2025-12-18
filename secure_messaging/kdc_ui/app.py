import threading
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] 
sys.path.insert(0, str(ROOT))


from core.kdc_core import start_kdc, stop_kdc

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"
socketio = SocketIO(app, cors_allowed_origins="*")

STATE = {"running": False, "host": "0.0.0.0", "port": 9000}
_thread = None

def log(msg: str):
    socketio.emit("log", {"text": msg})

@app.get("/")
def index():
    return render_template("index.html", state=STATE)

@app.post("/start")
def start():
    global _thread
    if STATE["running"]:
        return jsonify({"ok": False, "error": "KDC zaten çalışıyor."})

    host = request.form.get("host", "0.0.0.0").strip()
    port = int(request.form.get("port", "9000"))

    STATE["host"] = host
    STATE["port"] = port
    STATE["running"] = True

    def run():
        try:
            start_kdc(host, port, log=log)
        finally:
            STATE["running"] = False

    _thread = threading.Thread(target=run, daemon=True)
    _thread.start()
    return jsonify({"ok": True})

@app.post("/stop")
def stop():
    stop_kdc()
    STATE["running"] = False
    log("[KDC] Stop komutu gönderildi.")
    return jsonify({"ok": True})

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5100, debug=True)
