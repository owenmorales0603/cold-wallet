import os
import json
import base64
from datetime import datetime

from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# === KDF: misma función que usa keystore.py ===
def _derive_symmetric_key(passphrase: str, salt: bytes) -> bytes:
    """
    Deriva una clave simétrica de 32 bytes usando Argon2id.
    Debe ser idéntica a la usada en create_keystore_json().
    """
    return low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,          # mismos parámetros que en keystore.py
        memory_cost=64 * 1024,
        parallelism=1,
        hash_len=32,          # 32 bytes = 256 bits
        type=low_level.Type.ID
    )


def _load_signing_key_from_keystore(keystore_path: str, passphrase: str) -> SigningKey:
    """
    Lee el archivo keystore JSON, deriva la clave simétrica,
    descifra la private key y regresa un SigningKey (Ed25519).
    """
    with open(keystore_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Extraer parámetros de KDF y cifrado
    kdf_params = data["kdf_params"]
    cipher_params = data["cipher_params"]

    salt = base64.b64decode(kdf_params["salt_b64"])
    iv = base64.b64decode(cipher_params["iv_b64"])
    ciphertext = base64.b64decode(data["ciphertext_b64"])

    # Derivar clave simétrica (MISMA que en keystore.py)
    key = _derive_symmetric_key(passphrase, salt)

    # Descifrar private key con AES-256-GCM
    aesgcm = AESGCM(key)
    private_key_bytes = aesgcm.decrypt(iv, ciphertext, None)

    # Construir SigningKey de PyNaCl
    signing_key = SigningKey(private_key_bytes, encoder=RawEncoder())
    return signing_key


def sign_message_with_keystore(
    keystore_path: str,
    passphrase: str,
    message: bytes
) -> dict:
    """
    Carga la clave privada del keystore y firma el mensaje.
    Devuelve un diccionario con todo lo necesario para guardar en JSON.
    """
    sk = _load_signing_key_from_keystore(keystore_path, passphrase)

    # Firmar (PyNaCl devuelve firma + mensaje, pero aquí nos quedamos con la firma)
    signed = sk.sign(message)
    signature = signed.signature  # 64 bytes

    # Clave pública asociada
    pubkey_bytes = sk.verify_key.encode(RawEncoder())

    env = {
        "scheme": "ed25519",
        "message_b64": base64.b64encode(message).decode("utf-8"),
        "signature_b64": base64.b64encode(signature).decode("utf-8"),
        "pubkey_b64": base64.b64encode(pubkey_bytes).decode("utf-8"),
        "created": datetime.utcnow().isoformat() + "Z",
        "keystore_path": keystore_path,
    }
    return env


def save_signed_message(env: dict, output_path: str) -> None:
    """
    Guarda el JSON del mensaje firmado en la ruta indicada.
    Crea la carpeta si no existe.
    """
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=4)
