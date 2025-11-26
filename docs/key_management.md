# Explicación acerca del diseño para el sistema de gestión de llaves para nuestra cold wallet

Objetivo:
El presente documento trata de explicar las componentes principales para poder generar, proteger y usar las llaves dentro del proyecto, así también se busca explicar el por qué se eligen cada una de las configuraciones que se nos indican en el proyecto

1. Firma elegida Ed25519
Para este proyecto se usará el sistema de firmas digitales Ed25519 basado en curvas elípticas, las características que nos proporciona son las siguientes:
- Seguridad
- Firmas rápidas
- No requiere números aleatorios para cada firma
- Implementación robusca

Clave privada -> Cifra y almacena en keystore
Clave pública -> Genera la dirección y verifica firmas

2. Passphrase del usuario
La cold wallet no almacena la clave privada en texto claro por lo que se proporcionará una passphrase

3. Derivación de Argon2id
Para derivar una clave simétrica segura se usa Argon2id donde se ha comprobado que es resistente a ataquetes de fuerza bruta

4. Cifrado de la clave privada AES-256-GCM
La clave privada Ed25519 no se guarda en texto plano por lo que se usa AES-256-GCM que nos permite tener confidencialidad en los elementos generados

5. Derivación de la dirección
La dirección de la wallet no es la clave pública. Por lo que siguen los siguientes pasos:
    1. KECCAK-256(pubkey)
    2. Tomar los últimos 20 bytes
    3. Convertir a hexadecimal en Ethereum

6. Diseño del archivo keystore.json
Se contendrá en el archivo información par aque la wallet pueda recuperar la clave privada con la passphrase correcta, lo que tiene que contener es:

- Algoritmo de firma (`scheme`)
- Método de derivación (`kdf` y `kdf_params`)
- Método de cifrado (`cipher` y `cipher_params`)
- Datos cifrados (`ciphertext_b64`, `tag_b64`)
- Datos públicos (`pubkey_b64`, `address`)
- Metadatos (`created`)
