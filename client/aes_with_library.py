from Crypto.Cipher import AES

def password_to_key_bytes(password: str) -> bytes:
    b = password.encode("utf-8")
    if len(b) < 16:
        b = b.ljust(16, b"\x00")
    elif len(b) > 16:
        b = b[:16]
    return b

def pad(data: bytes, bs: int = 16) -> bytes:
    pad_len = bs - (len(data) % bs)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding hatalı")
    return data[:-pad_len]

def aes_encrypt_message_lib(message: str, password: str) -> str:
    key = password_to_key_bytes(password)
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(message.encode("utf-8"), 16))
    return ct.hex().upper()

def aes_decrypt_message_lib(cipher_hex: str, password: str) -> str:
    key = password_to_key_bytes(password)
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(bytes.fromhex(cipher_hex)))
    return pt.decode("utf-8", errors="ignore")
