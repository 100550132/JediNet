"""
Módulo de criptografía asimétrica y firma digital para JediNet.

Implementa:
- Generación de claves RSA-3072 exclusivas para cifrado híbrido (RSA-OAEP + SHA-256).
- Generación de claves ECDSA (curva SECP256R1 / P-256) exclusivas para firma digital.
- Protección de claves privadas en disco mediante formato PKCS#8 cifrado con contraseña.
- Gestión explícita de errores ante firmas alteradas, descifrados fallidos o claves erróneas.
"""

import base64
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# Parámetros criptográficos vigentes (equivalentes a ~128 bits de seguridad)
RSA_KEY_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537
RSA_ALGORITHM = "RSA-3072-OAEP-SHA256"

ECDSA_CURVE = ec.SECP256R1()
ECDSA_KEY_BITS = 256
ECDSA_ALGORITHM = "ECDSA-P256-SHA256"

PrivateKeyType = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
PublicKeyType = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]


class AsymmetricCryptoError(Exception):
    """Error genérico en operaciones de criptografía asimétrica."""


class PrivateKeyDecryptionError(AsymmetricCryptoError):
    """Se lanza cuando la contraseña no logra descifrar una clave privada PKCS#8."""


class AsymmetricDecryptionError(AsymmetricCryptoError):
    """Se lanza cuando falla el descifrado RSA-OAEP."""


class SignatureVerificationError(AsymmetricCryptoError):
    """Se lanza cuando una firma digital es inválida o los datos han sido alterados."""


def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    """Genera un par de claves RSA de 3072 bits para cifrado de claves de sesión."""
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_BITS,
    )


def generate_ecdsa_keypair() -> ec.EllipticCurvePrivateKey:
    """Genera un par de claves ECDSA sobre la curva segura P-256 (SECP256R1)."""
    return ec.generate_private_key(ECDSA_CURVE)


def serialize_private_key_encrypted(private_key: PrivateKeyType, password: str) -> bytes:
    """
    Exporta una clave privada en formato PEM PKCS#8 cifrada con la contraseña del usuario.
    Nunca se almacena una clave privada en claro en disco.
    """
    if not isinstance(password, str) or not password:
        raise AsymmetricCryptoError("Se requiere una contraseña no vacía para cifrar la clave privada.")

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def load_private_key_encrypted(pem_data: bytes, password: str) -> PrivateKeyType:
    """
    Carga y descifra una clave privada PKCS#8 protegida con contraseña.
    Lanza PrivateKeyDecryptionError si la contraseña no es válida o el fichero está corrupto.
    """
    if not isinstance(pem_data, bytes) or not isinstance(password, str) or not password:
        raise PrivateKeyDecryptionError("Datos de clave privada o contraseña inválidos.")

    try:
        key = serialization.load_pem_private_key(pem_data, password=password.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise PrivateKeyDecryptionError(
            "No se pudo descifrar la clave privada: contraseña incorrecta o archivo alterado."
        ) from exc

    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise PrivateKeyDecryptionError("Tipo de clave privada no soportado por JediNet.")
    return key


def serialize_public_key(public_key: PublicKeyType) -> bytes:
    """Exporta una clave pública en formato PEM estándar (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> str:
    """
    Cifra datos cortos (ej. clave de sesión AES de 256 bits) con RSA-OAEP (MGF1 + SHA-256).
    Devuelve el texto cifrado codificado en Base64.
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise AsymmetricCryptoError("Se requiere una clave pública RSA para cifrar con OAEP.")
    if not isinstance(data, bytes) or not data:
        raise AsymmetricCryptoError("Los datos a cifrar con RSA-OAEP deben ser bytes no vacíos.")

    try:
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise AsymmetricCryptoError(
            "Error en cifrado RSA-OAEP (longitud de datos excesiva para el tamaño de clave)."
        ) from exc

    return base64.b64encode(ciphertext).decode("ascii")


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> bytes:
    """
    Descifra una clave de sesión cifrada con RSA-OAEP (MGF1 + SHA-256).
    Rechaza explícitamente cualquier texto cifrado corrupto o clave incorrecta.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise AsymmetricDecryptionError("Se requiere una clave privada RSA para descifrar con OAEP.")
    if not isinstance(ciphertext_b64, str) or not ciphertext_b64:
        raise AsymmetricDecryptionError("Texto cifrado RSA-OAEP inválido.")

    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise AsymmetricDecryptionError(
            "Fallo al descifrar la clave de sesión con RSA-OAEP: clave privada incorrecta "
            "o bloque cifrado manipulado."
        ) from exc


def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    """
    Genera una firma digital ECDSA (curva P-256) sobre el resumen SHA-256 de 'data'.
    Devuelve la firma en formato DER codificada en Base64.
    """
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise AsymmetricCryptoError("Se requiere una clave privada ECDSA para firmar.")
    if not isinstance(data, bytes):
        raise AsymmetricCryptoError("Los datos a firmar deben proporcionarse en bytes.")

    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def ecdsa_verify(
    public_key: ec.EllipticCurvePublicKey,
    data: bytes,
    signature_b64: str,
) -> None:
    """
    Verifica una firma digital ECDSA-SHA256.
    Si la firma está alterada, no corresponde al emisor o los datos fueron modificados,
    lanza explícitamente SignatureVerificationError.
    """
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise SignatureVerificationError("Se requiere una clave pública ECDSA para verificar la firma.")
    if not isinstance(data, bytes) or not isinstance(signature_b64, str) or not signature_b64:
        raise SignatureVerificationError("Datos o firma digital con formato inválido.")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError as exc:
        raise SignatureVerificationError("Formato Base64 de firma digital inválido.") from exc

    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Firma digital ECDSA inválida: el mensaje ha sido alterado o no fue firmado por el emisor."
        ) from exc