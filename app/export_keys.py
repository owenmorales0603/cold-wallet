import os
import json
import base64
from typing import Tuple

from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# === KDF: misma configuración que keystore.py / signing.py ===
def _derive_symmetric_key(passphrase: str, salt: bytes) -> bytes:
    """
    Deriva una clave simétrica de 32 bytes usando Argon2id.
    Debe ser consistente con la usada en keystore.py.
    """
    return low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MB
        parallelism=1,
        hash_len=32,
        type=low_level.Type.ID,
    )


def _load_private_key_from_keystore(keystore_path: str, passphrase: str) -> bytes:
    """
    Lee el keystore JSON, deriva la clave simétrica y descifra
    la clave privada Ed25519.
    """
    with open(keystore_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Estructura esperada (la que genera tu keystore.py):
    # {
    #   "scheme": "ed25519-aesgcm-argon2id",
    #   "created": "...",
    #   "cipher": "AES-256-GCM",
    #   "kdf": "Argon2id",
    #   "kdf_params": { "memory": 65536, "iterations": 3, "parallelism": 1, "salt_b64": "..." },
    #   "cipher_params": { "iv_b64": "..." },
    #   "ciphertext_b64": "..."
    # }

    kdf_params = data["kdf_params"]
    cipher_params = data["cipher_params"]

    salt = base64.b64decode(kdf_params["salt_b64"])
    iv = base64.b64decode(cipher_params["iv_b64"])
    ciphertext = base64.b64decode(data["ciphertext_b64"])

    key = _derive_symmetric_key(passphrase, salt)

    aesgcm = AESGCM(key)
    private_key_bytes = aesgcm.decrypt(iv, ciphertext, None)

    return private_key_bytes


def load_keypair_from_keystore(keystore_path: str, passphrase: str) -> Tuple[bytes, bytes]:
    """
    Devuelve (private_key_bytes, public_key_bytes) a partir de un keystore.
    La pública se deriva de la privada con PyNaCl.
    """
    private_key_bytes = _load_private_key_from_keystore(keystore_path, passphrase)

    # Derivar la clave pública usando PyNaCl
    sk = SigningKey(private_key_bytes, encoder=RawEncoder())
    vk = sk.verify_key
    public_key_bytes = vk.encode(RawEncoder())

    return private_key_bytes, public_key_bytes


# ========= Funciones de exportación =========

def export_private_key_hex(path: str, private_key: bytes) -> None:
    """
    Exporta la clave privada en formato hex (texto).
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(private_key.hex())


def export_public_key_hex(path: str, public_key: bytes) -> None:
    """
    Exporta la clave pública en formato hex (texto).
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(public_key.hex())


def export_private_key_pem(path: str, private_key: bytes) -> None:
    """
    Exporta la clave privada en formato PEM (PKCS8), usando cryptography.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    pem = ed_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(path, "wb") as f:
        f.write(pem)


def export_public_key_pem(path: str, public_key: bytes) -> None:
    """
    Exporta la clave pública en formato PEM (SubjectPublicKeyInfo).
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    pem = ed_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(path, "wb") as f:
        f.write(pem)


def export_all_from_keystore(
    keystore_path: str,
    passphrase: str,
    output_dir: str = "exports",
) -> dict:
    """
    Carga el keystore, recupera la clave privada y pública, y exporta:
      - private_key.hex
      - public_key.hex
      - private_key.pem
      - public_key.pem

    Devuelve un dict con las rutas generadas.
    """
    os.makedirs(output_dir, exist_ok=True)

    priv, pub = load_keypair_from_keystore(keystore_path, passphrase)

    paths = {
        "private_hex": os.path.join(output_dir, "private_key.hex"),
        "public_hex": os.path.join(output_dir, "public_key.hex"),
        "private_pem": os.path.join(output_dir, "private_key.pem"),
        "public_pem": os.path.join(output_dir, "public_key.pem"),
    }

    export_private_key_hex(paths["private_hex"], priv)
    export_public_key_hex(paths["public_hex"], pub)
    export_private_key_pem(paths["private_pem"], priv)
    export_public_key_pem(paths["public_pem"], pub)

    return paths


if __name__ == "__main__":
    # Pequeña utilidad interactiva
    print("=== Exportador de claves desde keystore ===")
    keystore = input("Ruta del keystore (por ejemplo outbox/keystore-YYYYMMDD-HHMMSS.json): ").strip()
    passwd = input("Passphrase del keystore: ").strip()

    out_dir = "exports"
    result = export_all_from_keystore(keystore, passwd, out_dir)

    print("\nClaves exportadas en:")
    for label, p in result.items():
        print(f" - {label}: {p}")
