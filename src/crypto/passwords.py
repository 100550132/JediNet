"""
Archivo para la gestión segura de contraseñas de JediNet.
Incluye:
- Validación de robustez de contraseñas
- Derivación y almacenamiento seguro mediante PBKDF2-HMAC-SHA256 con sal aleatoria
- Verificación en tiempo constante para evitar ataques de temporización (timing attacks)
"""
import base64
import os
from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Parámetros criptográficos vigentes (recomendación OWASP para PBKDF2-HMAC-SHA256)
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16 #128 bits de sal aleatoria única por usuario
HASH_BYTES = 32 #256 bits de salida (coincide con SHA-256)
PASSWORD_ALGORITHM = "PBKDF2-HMAC-SHA256"

class WeakPasswordError(ValueError):
    """Se lanza cuando una contraseña no cumple la robustez mínima"""

def validate_password_strength(password: str) -> None:
    """
    Comprueba que la contraseña cumple los requisitos mínimos de seguridad:
    -Al menos 12 caracteres
    -Al menos una letra mayúscula, una minúscula, un dígito y un símbolo
    """
    if not isinstance(password, str) or not password:
        raise WeakPasswordError("La contraseña no puede estar vacía.")

    errors: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"tener al menos {MIN_PASSWORD_LENGTH} caracteres")
    if not any(c.isupper() for c in password):
        errors.append("incluir al menos una mayúscula")
    if not any(c.islower() for c in password):
        errors.append("incluir al menos una minúscula")
    if not any(c.isdigit() for c in password):
        errors.append("incluir al menos un número")
    if not any(not c.isalnum() for c in password):
        errors.append("incluir al menos un carácter especial (ej. !@#$%*)")

    if errors:
        detail = ", ".join(errors)
        raise WeakPasswordError(f"Contraseña demasiado débil: debe {detail}.")

def hash_password(password: str) -> dict[str, Any]:
    """
    Valida la robustez de la contraseña y genera su registro seguro para almacenamiento.
    Nunca almacena la contraseña en claro; devuelve un diccionario serializable
    con el algoritmo, iteraciones, sal aleatoria (Base64) y resumen derivado (Base64).
    """
    validate_password_strength(password)
    #Fuente de aleatoriedad criptográficamente segura del sistema operativo (CSPRNG)
    salt = os.urandom(SALT_BYTES)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=HASH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    derived_key = kdf.derive(password.encode("utf-8"))

    return {
        "algorithm": PASSWORD_ALGORITHM,
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(derived_key).decode("ascii"),
    }

def verify_password(password: str, stored_record: dict[str, Any]) -> bool:
    """
    Verifica una contraseña frente al registro almacenado.
    Utiliza PBKDF2HMAC.verify(), que compara en tiempo constante para evitar
    filtraciones por tiempo de respuesta. Devuelve True solo si coincide exactamente.
    """
    if not isinstance(password, str) or not isinstance(stored_record, dict):
        return False

    try:
        if stored_record.get("algorithm") != PASSWORD_ALGORITHM:
            return False

        iterations = int(stored_record["iterations"])
        if iterations <= 0:
            return False

        salt = base64.b64decode(stored_record["salt"], validate=True)
        expected_hash = base64.b64decode(stored_record["hash"], validate=True)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=len(expected_hash),
            salt=salt,
            iterations=iterations,
        )
        kdf.verify(password.encode("utf-8"), expected_hash)
        return True
    except (InvalidKey, KeyError, TypeError, ValueError):
        return False