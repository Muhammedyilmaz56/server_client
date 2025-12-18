
import os
import time
import base64
import json
import hmac
import hashlib
from typing import Dict, Any, Tuple

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def now_ts() -> int:
    return int(time.time())

def kdf_from_passphrase(passphrase: str, out_len: int = 32) -> bytes:
   
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return digest[:out_len]


def aes_gcm_encrypt(key: bytes, payload: Dict[str, Any]) -> Dict[str, str]:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ct, tag = cipher.encrypt_and_digest(data)
    return {
        "alg": "AES_GCM",
        "nonce": b64e(nonce),
        "ct": b64e(ct),
        "tag": b64e(tag),
    }

def aes_gcm_decrypt(key: bytes, blob: Dict[str, str]) -> Dict[str, Any]:
    nonce = b64d(blob["nonce"])
    ct = b64d(blob["ct"])
    tag = b64d(blob["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ct, tag)
    return json.loads(data.decode("utf-8"))

def des_cbc_hmac_encrypt(des_key_8: bytes, mac_key_32: bytes, payload: Dict[str, Any]) -> Dict[str, str]:
    iv = os.urandom(8)
    cipher = DES.new(des_key_8, DES.MODE_CBC, iv=iv)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ct = cipher.encrypt(pad(data, 8))
    mac = hmac.new(mac_key_32, iv + ct, hashlib.sha256).digest()
    return {
        "alg": "DES_CBC_HMAC",
        "iv": b64e(iv),
        "ct": b64e(ct),
        "mac": b64e(mac),
    }

def des_cbc_hmac_decrypt(des_key_8: bytes, mac_key_32: bytes, blob: Dict[str, str]) -> Dict[str, Any]:
    iv = b64d(blob["iv"])
    ct = b64d(blob["ct"])
    mac = b64d(blob["mac"])
    expect = hmac.new(mac_key_32, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise ValueError("MAC doğrulanamadı (mesaj bozulmuş veya saldırı var).")
    cipher = DES.new(des_key_8, DES.MODE_CBC, iv=iv)
    data = unpad(cipher.decrypt(ct), 8)
    return json.loads(data.decode("utf-8"))


def encrypt_payload(alg: str, keys: Dict[str, bytes], payload: Dict[str, Any]) -> Dict[str, Any]:
    if alg == "AES_GCM":
        return aes_gcm_encrypt(keys["aes"], payload)
    if alg == "DES_CBC_HMAC":
        return des_cbc_hmac_encrypt(keys["des"], keys["hmac"], payload)
    raise ValueError("Bilinmeyen alg")

def decrypt_payload(blob: Dict[str, Any], keys: Dict[str, bytes]) -> Dict[str, Any]:
    alg = blob.get("alg")
    if alg == "AES_GCM":
        return aes_gcm_decrypt(keys["aes"], blob)
    if alg == "DES_CBC_HMAC":
        return des_cbc_hmac_decrypt(keys["des"], keys["hmac"], blob)
    raise ValueError("Bilinmeyen alg")
