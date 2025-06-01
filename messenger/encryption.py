from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
import base64, os, hashlib

FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# --- RSA Key Persistence ---
KEY_PATH = "rsa_key.pem"

if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        rsa_key = RSA.import_key(f.read())
else:
    rsa_key = RSA.generate(2048)
    with open(KEY_PATH, "wb") as f:
        f.write(rsa_key.export_key())

rsa_public = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(rsa_key)
rsa_public_cipher = PKCS1_OAEP.new(rsa_public)

def encrypt_message(algorithm, message):
    if algorithm == "AES":
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(message.encode(), AES.block_size))
        return f"AES|{base64.b64encode(cipher.iv + key + ct).decode()}"
    elif algorithm == "Fernet":
        return f"Fernet|{fernet.encrypt(message.encode()).decode()}"
    elif algorithm == "RSA":
        encrypted = rsa_public_cipher.encrypt(message.encode())
        return f"RSA|{base64.b64encode(encrypted).decode()}"
    elif algorithm == "Hash":
        return f"Hash|{hashlib.sha256(message.encode()).hexdigest()}"
    return message

def decrypt_message(enc_message):
    try:
        if "|" not in enc_message:
            return enc_message
        algo, data = enc_message.split("|", 1)
        if algo == "AES":
            raw = base64.b64decode(data)
            iv, key, ct = raw[:16], raw[16:32], raw[32:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        elif algo == "Fernet":
            return fernet.decrypt(data.encode()).decode()
        elif algo == "RSA":
            return rsa_cipher.decrypt(base64.b64decode(data)).decode()
        elif algo == "Hash":
            return "[HASHED MESSAGE – Cannot decrypt]"
        return data
    except Exception as e:
        return f"[DECRYPTION ERROR: {e}]"