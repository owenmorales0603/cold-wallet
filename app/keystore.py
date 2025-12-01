import os
import json
import base64
from datetime import datetime

# Claves Ed25519 (PyNaCl)
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

# Argon2id usando argon2-cffi
from argon2 import low_level

# AES-256-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Genera una clave privada Ed25519 usando PyNaCl
def generate_ed25519_private_key() -> bytes:
    """
    Genera una nueva clave privada Ed25519 y la regresa en bytes crudos.
    """
    sk = SigningKey.generate()
    return sk.encode(RawEncoder())


# Deriva una clave simétrica usando Argon2id (argon2-cffi)
def derive_symmetric_key(passphrase: str, salt: bytes) -> bytes:
    """
    Deriva una clave de 32 bytes (para AES-256) a partir de la passphrase,
    usando Argon2id (Type.ID) con parámetros razonables.
    """
    key = low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,             # iteraciones
        memory_cost=64 * 1024,   # 64 MiB en KiB
        parallelism=1,
        hash_len=32,             # 32 bytes = 256 bits
        type=low_level.Type.ID
    )
    return key


# Cifra la clave privada usando AES-256-GCM
def encrypt_private_key(private_key: bytes, passphrase: str) -> dict:
    """
    Cifra la private key con una clave derivada de la passphrase.
    Regresa un diccionario con ciphertext, iv y salt codificados en Base64.
    """
    # Salt aleatoria para Argon2id
    salt = os.urandom(16)

    # Derivar clave simétrica
    key = derive_symmetric_key(passphrase, salt)

    # AES-GCM requiere un nonce/IV de 12 bytes
    aesgcm = AESGCM(key)
    iv = os.urandom(12)

    # Cifrar la clave privada (sin AAD)
    ciphertext = aesgcm.encrypt(iv, private_key, None)

    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "iv_b64": base64.b64encode(iv).decode("utf-8"),
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
    }


# Construye el JSON del keystore
def create_keystore_json(passphrase: str) -> dict:
    """
    Genera una nueva clave privada Ed25519, la cifra con AES-256-GCM
    usando una clave derivada con Argon2id, y construye el diccionario
    JSON con todos los parámetros necesarios para recuperar la clave.
    """
    private_key = generate_ed25519_private_key()
    encrypted = encrypt_private_key(private_key, passphrase)

    return {
        "scheme": "ed25519-aesgcm-argon2id",
        "created": datetime.utcnow().isoformat() + "Z",
        "cipher": "AES-256-GCM",
        "kdf": "Argon2id",
        "kdf_params": {
            "memory": 64 * 1024,        # igual que derive_symmetric_key
            "iterations": 3,
            "parallelism": 1,
            "salt_b64": encrypted["salt_b64"],
        },
        "cipher_params": {
            "iv_b64": encrypted["iv_b64"],
        },
        "ciphertext_b64": encrypted["ciphertext_b64"],
    }


# Guarda el keystore en un archivo JSON
def save_keystore_file(data: dict, output_path: str) -> None:
    """
    Guarda el diccionario de keystore en un archivo JSON.
    """
    # Crear carpeta si no existe (por si la ruta incluye directorios)
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
