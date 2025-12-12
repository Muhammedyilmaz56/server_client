
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    private_pem = key.export_key()            
    public_pem = key.publickey().export_key() 
    return private_pem, public_pem

def rsa_encrypt_key(aes_key_bytes: bytes, public_pem: bytes) -> str:
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub)
    ct = cipher.encrypt(aes_key_bytes)
    return base64.b64encode(ct).decode("utf-8")

def rsa_decrypt_key(enc_b64: str, private_pem: bytes) -> bytes:
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv)
    ct = base64.b64decode(enc_b64.encode("utf-8"))
    return cipher.decrypt(ct)
