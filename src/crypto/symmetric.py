"""
Archivo de criptografía simétrica para JediNet.
Implementa:
-Cifrado autenticado (AEAD) mediante AES-256-GCM con nonce único de 96 bits
  y soporte para Datos Asociados Autenticados (AAD).
-Generación y verificación de etiquetas de autenticación de mensajes mediante
  HMAC-SHA256 para datos no cifrados (como el registro de auditoría del Templo).
"""
import base64
import os
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Parámetros criptográficos vigentes
AES_KEY_BITS = 256
AES_KEY_BYTES = AES_KEY_BITS // 8  #32 bytes
GCM_NONCE_BYTES = 12               #96 bits (longitud recomendada para GCM)
GCM_TAG_BYTES = 16                 #128 bits (tag completo sin truncar)
AES_ALGORITHM = "AES-256-GCM"

HMAC_KEY_BITS = 256
HMAC_KEY_BYTES = HMAC_KEY_BITS // 8 #32 bytes
HMAC_ALGORITHM = "HMAC-SHA256"

class SymmetricCryptoError(Exception):
    """Error genérico en operaciones de criptografía simétrica."""

class IntegrityVerificationError(SymmetricCryptoError):
    """Se lanza cuando falla la verificación de un tag AEAD o una etiqueta HMAC."""

def generate_aes_key() -> bytes:
    """Genera una clave simétrica aleatoria de 256 bits criptográficamente segura."""
    return AESGCM.generate_key(bit_length=AES_KEY_BITS)

def generate_hmac_key() -> bytes:
    """Genera una clave secreta independiente de 256 bits para HMAC-SHA256."""
    return os.urandom(HMAC_KEY_BYTES)

def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """
    Cifra y autentica 'plaintext' con AES-256-GCM.
    -Genera un nonce aleatorio único de 96 bits en cada llamada (nunca constante).
    -Autentica 'associated_data' (AAD) sin cifrarlos (ej. metadatos del mensaje).
    -Separa explícitamente ciphertext y tag (128 bits) en Base64 para facilitar
      la inspección, depuración y pruebas negativas de manipulación.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES:
        raise SymmetricCryptoError(
            f"La clave AES debe tener exactamente {AES_KEY_BYTES} bytes ({AES_KEY_BITS} bits)."
        )
    if not isinstance(plaintext, bytes):
        raise SymmetricCryptoError("El texto en claro debe proporcionarse en bytes.")
    if not isinstance(associated_data, bytes):
        raise SymmetricCryptoError("Los datos asociados (AAD) deben proporcionarse en bytes.")

    nonce = os.urandom(GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    #En la librería cryptography, los últimos 16 bytes corresponden al Auth Tag de GCM
    ciphertext = ciphertext_with_tag[:-GCM_TAG_BYTES]
    tag = ciphertext_with_tag[-GCM_TAG_BYTES:]

    return {
        "algorithm": AES_ALGORITHM,
        "key_bits": AES_KEY_BITS,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }

def decrypt_aes_gcm(
    key: bytes,
    encrypted_package: dict[str, Any],
    associated_data: bytes = b"",
) -> bytes:
    """
    Verifica el tag de autenticación y descifra un paquete AES-256-GCM.
    Si el ciphertext, el tag, el nonce, los AAD o la clave son incorrectos,
    rechaza explícitamente los datos lanzando IntegrityVerificationError.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES:
        raise SymmetricCryptoError(
            f"La clave AES debe tener exactamente {AES_KEY_BYTES} bytes ({AES_KEY_BITS} bits)."
        )
    if not isinstance(encrypted_package, dict):
        raise IntegrityVerificationError("Formato de paquete cifrado inválido.")
    if not isinstance(associated_data, bytes):
        raise SymmetricCryptoError("Los datos asociados (AAD) deben proporcionarse en bytes.")

    try:
        if encrypted_package.get("algorithm") != AES_ALGORITHM:
            raise IntegrityVerificationError("Algoritmo simétrico no reconocido.")

        nonce = base64.b64decode(encrypted_package["nonce"], validate=True)
        ciphertext = base64.b64decode(encrypted_package["ciphertext"], validate=True)
        tag = base64.b64decode(encrypted_package["tag"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityVerificationError("Campos criptográficos corruptos o incompletos.") from exc

    if len(nonce) != GCM_NONCE_BYTES:
        raise IntegrityVerificationError("Longitud de nonce inválida para AES-GCM.")
    if len(tag) != GCM_TAG_BYTES:
        raise IntegrityVerificationError("Longitud de tag de autenticación inválida.")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
    except InvalidTag as exc:
        raise IntegrityVerificationError(
            "Verificación AES-256-GCM fallida: el mensaje, el tag o los metadatos han sido "
            "alterados (o la clave de descifrado es incorrecta)."
        ) from exc

def compute_hmac_sha256(key: bytes, data: bytes) -> str:
    """
    Genera una etiqueta HMAC-SHA256 en Base64 para garantizar integridad y autenticidad
    de información almacenada o intercambiada sin cifrado.
    """
    if not isinstance(key, bytes) or len(key) < HMAC_KEY_BYTES:
        raise SymmetricCryptoError(
            f"La clave HMAC debe tener al menos {HMAC_KEY_BYTES} bytes ({HMAC_KEY_BITS} bits)."
        )
    if not isinstance(data, bytes):
        raise SymmetricCryptoError("Los datos para calcular HMAC deben estar en bytes.")

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return base64.b64encode(mac.finalize()).decode("ascii")


def verify_hmac_sha256(key: bytes, data: bytes, expected_mac_b64: str) -> None:
    """
    Verifica una etiqueta HMAC-SHA256 en tiempo constante.
    Si la etiqueta no coincide o los datos fueron modificados, lanza explícitamente
    IntegrityVerificationError para impedir que la aplicación continúe con datos manipulados.
    """
    if not isinstance(key, bytes) or len(key) < HMAC_KEY_BYTES:
        raise SymmetricCryptoError(
            f"La clave HMAC debe tener al menos {HMAC_KEY_BYTES} bytes ({HMAC_KEY_BITS} bits)."
        )
    if not isinstance(data, bytes) or not isinstance(expected_mac_b64, str):
        raise IntegrityVerificationError("Entrada inválida para verificación HMAC.")

    try:
        expected_mac = base64.b64decode(expected_mac_b64, validate=True)
    except ValueError as exc:
        raise IntegrityVerificationError("Formato de etiqueta HMAC inválido.") from exc

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    try:
        mac.verify(expected_mac)
    except InvalidSignature as exc:
        raise IntegrityVerificationError(
            "Verificación HMAC-SHA256 fallida: los datos o la etiqueta MAC han sido manipulados."
        ) from exc
