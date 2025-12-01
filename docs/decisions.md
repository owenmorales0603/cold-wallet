# Decisiones del proyecto

**¿Por qué elegimos Python?**
Python es el lenguaje de programación más populares para realizar aplicaciones y prototipos que permitan dar una base de lo que pueda ser un desarrollo en real, dónde aunque si bien Python no sea el lengauje de programación más eficiente, si es de los más rápidos en programar debido a la flexibilidad que nos ofrece, además de que existen muchas librerías que nos pueden facilitar la implementación.

**Esquema de firma**
Para el uso de las firmas digitales se uso Ed25519 basado en curvas elípticas donde se proporciona una alta seguridad, firmas rápidas y fáciles de verificar.

**Derivación de la llave**
Para derivar la clave simétrica a partir del passphrase se optó por usar la que se recomendó la cual es Argon2id que permite dentro de sus características configurar el consumo de memoria y cuenta con la protección necesaria.

**Cifrado de la clave privada**
La clave privada nunca se guarda en texto claro, por lo que cuando se deriva la clave simétrica con Argon2id se cifra ahora la clave privada mediante Ed25519 usando AES-256-GCM que nos permite tener confidencialidad e integridad al momento de realizar la operación, así también AES-256-GCM cuenta con un alto estándar ampliamente utilizado.

**Inicialización de la wallet**
Se optó por usar CLI, donde se siguen los siguientes pasos:

1. Recibir la passphrase del usuario.
2. Llamar a `create_keystore_json` para construir la estructura del keystore.
3. Asegurar que exista el directorio `outbox/`.
4. Generar un nombre de archivo con marca de tiempo.
5. Guardar el `keystore.json` en `outbox/` usando `save_keystore_file`.

**Ramas y colaboración en el equipo**
Decidimos hacer uso de GitHub ya que el equipo alguna vez lo ocupó para poder colaborar en equipo y realizar repositorios, en este proyecto se uso la rama main como la principal, mientras que para las evidencias se usan los pull request que permiten tener evidencia de lo que se realizó en el equipo.