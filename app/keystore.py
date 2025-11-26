import os
import json
import base64
from datetime import datetime
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Genera una clave privada Ed25519
def generate_ed25519_private_key():
    sk = SigningKey.generate()
    return sk.encode(RawEncoder())


# Deriva una clave simétrica usando Argon2id
def derive_symmetric_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MB
        parallelism=1,
        length=32,
        salt=salt
    )
    return kdf.derive(passphrase.encode('utf-8'))


# Cifra la clave privada usando AES-256-GCM
def encrypt_private_key(private_key: bytes, passphrase: str):
    salt = os.urandom(16)
    key = derive_symmetric_key(passphrase, salt)

    aesgcm = AESGCM(key)
    iv = os.urandom(12)

    ciphertext = aesgcm.encrypt(iv, private_key, None)

    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
        "salt_b64": base64.b64encode(salt).decode(),
    }


# Construye el JSON del keystore
def create_keystore_json(passphrase: str) -> dict:
    private_key = generate_ed25519_private_key()
    encrypted = encrypt_private_key(private_key, passphrase)

    return {
        "scheme": "ed25519-aesgcm-argon2id",
        "created": datetime.utcnow().isoformat() + "Z",
        "cipher": "AES-256-GCM",
        "kdf": "Argon2id",
        "kdf_params": {
            "memory": 65536,
            "iterations": 3,
            "parallelism": 1,
            "salt_b64": encrypted["salt_b64"]
        },
        "cipher_params": {
            "iv_b64": encrypted["iv_b64"]
        },
        "ciphertext_b64": encrypted["ciphertext_b64"]
    }


# Guarda el keystore en un archivo JSON
def save_keystore_file(data: dict, output_path: str):
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
