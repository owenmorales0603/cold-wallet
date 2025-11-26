import os
from datetime import datetime

from .keystore import create_keystore_json, save_keystore_file


# Inicializa la wallet y crea un archivo keystore en outbox/
def wallet_init(passphrase: str) -> str:
    # Crear el JSON del keystore usando la passphrase del usuario
    keystore_data = create_keystore_json(passphrase)

    # Asegurar que exista la carpeta outbox/
    outbox_dir = "outbox"
    os.makedirs(outbox_dir, exist_ok=True)

    # Generar un nombre de archivo con marca de tiempo
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"keystore-{timestamp}.json"
    output_path = os.path.join(outbox_dir, filename)

    # Guardar el archivo
    save_keystore_file(keystore_data, output_path)

    # Regresar la ruta del archivo creado (útil para pruebas o CLI)
    return output_path
