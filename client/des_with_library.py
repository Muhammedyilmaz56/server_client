import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def password_to_key_bytes(password: str) -> bytes:
    b = password.encode("utf-8")
    if len(b) < 8:
        b = b.ljust(8, b"\x00")
    elif len(b) > 8:
        b = b[:8]
    return b

def des_encrypt_message_lib(message: str, password: str) -> tuple:
    start_time = time.time()
    key = password_to_key_bytes(password)
    cipher = DES.new(key, DES.MODE_ECB)
    data = pad(message.encode("utf-8"), 8)
    ct = cipher.encrypt(data)
    result = ct.hex().upper()
    elapsed = time.time() - start_time
    return (result, elapsed)

def des_decrypt_message_lib(cipher_hex: str, password: str) -> tuple:
    start_time = time.time()
    key = password_to_key_bytes(password)
    cipher = DES.new(key, DES.MODE_ECB)
    ct = bytes.fromhex(cipher_hex)
    pt = unpad(cipher.decrypt(ct), 8)
    result = pt.decode("utf-8", errors="ignore")
    elapsed = time.time() - start_time
    return (result, elapsed)
