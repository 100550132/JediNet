# JediNet
Aplicación de mensajería segura entre miembros de la Orden Jedi con PKI X.509 v3, CRL, firma digital ECDSA, cifrado híbrido (AES-256-GCM + RSA-3072-OAEP) y registro de auditoría HMAC-SHA256.

## Requisitos
* Python 3.10 o superior
* `cryptography==44.0.0`
* `pytest==8.3.4`

## Instalación y ejecución desde un entorno limpio
1. Crear y activar un entorno virtual:
   * **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   * **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
2. Instalar las dependencias fijadas:
   ```bash
   pip install -r requirements.txt
3. Para ejecutar las pruebas automáticas (positivas y negativas):
   ```bash
   pytest -v
4. Para iniciar la aplicación:
   ```bash
   python main.py
## Los datos generados durante el uso (claves cifradas, certificados, CRL, usuarios y mensajes) se crean automáticamente en la carpeta local data/. Para reiniciar el sistema desde cero, basta con eliminar esa carpeta.
