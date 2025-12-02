
import json
import base64
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def verify_signature(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Verifica una firma Ed25519."""
    verify_key = VerifyKey(pubkey)
    try:
        verify_key.verify(message, signature)
        return True
    except BadSignatureError:
        # Firma incorrecta
        return False


def verify_signed_json(path: str) -> bool:
    """
    Lee un JSON firmado (como los de outbox/signed-*.json),
    decodifica todo y verifica la firma.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    scheme = data.get("scheme")
    if scheme != "ed25519":
        raise ValueError(f"Scheme no soportado: {scheme}")

    msg = base64.b64decode(data["message_b64"])
    signature = base64.b64decode(data["signature_b64"])
    pubkey = base64.b64decode(data["pubkey_b64"])

    ok = verify_signature(msg, signature, pubkey)

    if ok:
        print(f"✅ Firma válida para {path}")
    else:
        print(f"❌ Firma inválida para {path}")

    return ok
