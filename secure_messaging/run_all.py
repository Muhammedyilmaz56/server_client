from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent

def run(cmd, title):
    return subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

def main():
    procs = []
    try:
        procs.append(run([sys.executable, "kdc_ui/app.py"], "KDC UI"))
        time.sleep(0.5)
        procs.append(run([sys.executable, "server_ui/app.py"], "Server UI"))
        time.sleep(0.5)
        procs.append(run([sys.executable, "client_ui/app.py"], "Client UI"))

        print("Hepsi başlatıldı:")
        print("KDC UI    : http://127.0.0.1:5100")
        print("Server UI : http://127.0.0.1:5200")
        print("Client UI : http://127.0.0.1:5300")
        print("\nKapatmak için bu terminalde CTRL+C")

        
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nKapatılıyor...")
    finally:
        for p in procs:
            try:
                p.terminate()
            except:
                pass

if __name__ == "__main__":
    main()
