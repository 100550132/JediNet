"""
Servicio de autenticación, registro y gestión PKI de usuarios para JediNet.
Coordina:
- Inicialización y desbloqueo en memoria del Consejo Jedi (AC Raíz + clave HMAC derivada).
- Registro de Jedis con contraseñas robustas (PBKDF2-HMAC-SHA256), generación de pares
  de claves separados (RSA-3072 para cifrado y ECDSA P-256 para firma) y emisión de
  certificados X.509 v3.
- Autenticación de usuarios verificando contraseña, certificados y estado en la CRL.
- Revocación de certificados (p. ej. caída al Lado Oscuro) y auditoría HMAC del Templo.
"""
from dataclasses import dataclass
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from src.crypto.asymmetric import (
    ECDSA_ALGORITHM,
    ECDSA_KEY_BITS,
    PrivateKeyDecryptionError,
    RSA_ALGORITHM,
    RSA_KEY_BITS,
    generate_ecdsa_keypair,
    generate_rsa_keypair,
)
from src.crypto.passwords import (
    PASSWORD_ALGORITHM,
    PBKDF2_ITERATIONS,
    hash_password,
    validate_password_strength,
    verify_password,
)
from src.crypto.pki import (
    PURPOSE_ENCRYPTION,
    PURPOSE_SIGNATURE,
    create_crl,
    create_root_ca,
    get_certificate_summary,
    issue_user_certificate,
    revoke_certificates_in_crl,
    validate_user_certificate,
)
from src.crypto.symmetric import HMAC_ALGORITHM, HMAC_KEY_BITS
from src.storage.repository import JediRepository, StorageError, normalize_username

ALLOWED_RANKS = ("Padawan", "Caballero Jedi", "Maestro Jedi")

class AuthError(Exception):
    """Error en el registro, inicio de sesión o gestión de identidades."""

@dataclass
class CouncilSession:
    """Sesión administrativa en memoria del Consejo Jedi (nunca se persiste en claro)."""

    ca_private_key: ec.EllipticCurvePrivateKey
    ca_cert: x509.Certificate
    audit_hmac_key: bytes

@dataclass
class JediSession:
    """Sesión autenticada en memoria de un Jedi con sus claves descifradas."""

    username: str
    rank: str
    enc_private_key: rsa.RSAPrivateKey
    sig_private_key: ec.EllipticCurvePrivateKey
    enc_cert: x509.Certificate
    sig_cert: x509.Certificate

class AuthService:
    """Capa de negocio para identidades, autenticación y autoridad del Consejo Jedi."""

    def __init__(self, repo: JediRepository) -> None:
        self.repo = repo

    def initialize_council(self, council_password: str) -> tuple[CouncilSession, list[str]]:
        """
        Inicializa por primera vez la AC Raíz del Consejo Jedi, la CRL vacía y el log HMAC.
        Exige una contraseña robusta para proteger la clave privada de la AC y derivar el HMAC.
        """
        if self.repo.is_initialized():
            raise AuthError("El Consejo Jedi ya está inicializado en este repositorio.")

        validate_password_strength(council_password)

        ca_private_key, ca_cert = create_root_ca()
        crl = create_crl(ca_private_key, ca_cert)
        self.repo.save_ca(ca_private_key, ca_cert, crl, council_password)

        audit_hmac_key = self.repo.derive_audit_hmac_key(council_password)
        self.repo.append_audit_event(
            audit_hmac_key,
            event="COUNCIL_INIT",
            actor="consejo_jedi",
            details="AC Raíz X.509 v3, CRL inicial y registro de auditoría HMAC creados.",
        )

        ca_info = get_certificate_summary(ca_cert)
        debug_logs = [
            f"[PKI] AC Raíz '{ca_info['cn']}' creada ({ca_info['key_info']}, serial={ca_info['serial_hex']}).",
            "[CLAVES] Clave privada de la AC cifrada en PKCS#8 con la contraseña del Consejo.",
            f"[HMAC] Registro de auditoría inicializado con {HMAC_ALGORITHM} (clave derivada de {HMAC_KEY_BITS} bits, no almacenada en disco).",
        ]
        return CouncilSession(ca_private_key, ca_cert, audit_hmac_key), debug_logs

    def unlock_council(self, council_password: str) -> tuple[CouncilSession, list[str]]:
        """Desbloquea en memoria la clave privada de la AC Raíz y deriva la clave HMAC."""
        if not self.repo.is_initialized():
            raise AuthError("El sistema JediNet aún no está inicializado.")

        try:
            ca_private_key = self.repo.load_ca_private_key(council_password)
        except PrivateKeyDecryptionError as exc:
            raise AuthError("Contraseña del Consejo Jedi incorrecta.") from exc

        ca_cert = self.repo.load_ca_certificate()
        audit_hmac_key = self.repo.derive_audit_hmac_key(council_password)

        ca_info = get_certificate_summary(ca_cert)
        debug_logs = [
            f"[PKI] Sesión del Consejo Jedi desbloqueada (AC Raíz serial={ca_info['serial_hex']}).",
            f"[HMAC] Clave de auditoría {HMAC_ALGORITHM} ({HMAC_KEY_BITS} bits) derivada en memoria.",
        ]
        return CouncilSession(ca_private_key, ca_cert, audit_hmac_key), debug_logs

    def register_jedi(
        self,
        council: CouncilSession,
        username: str,
        rank: str,
        password: str,
    ) -> list[str]:
        """
        Registra un nuevo Jedi:
        1. Valida nombre, rango y robustez de contraseña.
        2. Deriva el hash de autenticación con PBKDF2-HMAC-SHA256 + sal aleatoria.
        3. Genera par RSA-3072 (cifrado) y par ECDSA P-256 (firma).
        4. Emite certificados X.509 v3 separados firmados por el Consejo Jedi.
        5. Guarda claves privadas cifradas en PKCS#8 y registra el evento en el log HMAC.
        """
        clean_user = normalize_username(username)
        clean_rank = rank.strip() if isinstance(rank, str) else ""
        if clean_rank not in ALLOWED_RANKS:
            raise AuthError(f"Rango inválido. Opciones permitidas: {', '.join(ALLOWED_RANKS)}.")

        if self.repo.user_exists(clean_user):
            raise AuthError(f"El Jedi '{clean_user}' ya está registrado en JediNet.")

        password_record = hash_password(password)

        enc_private_key = generate_rsa_keypair()
        sig_private_key = generate_ecdsa_keypair()

        enc_cert = issue_user_certificate(
            ca_private_key=council.ca_private_key,
            ca_cert=council.ca_cert,
            username=clean_user,
            user_public_key=enc_private_key.public_key(),
            purpose=PURPOSE_ENCRYPTION,
        )
        sig_cert = issue_user_certificate(
            ca_private_key=council.ca_private_key,
            ca_cert=council.ca_cert,
            username=clean_user,
            user_public_key=sig_private_key.public_key(),
            purpose=PURPOSE_SIGNATURE,
        )

        self.repo.save_user(
            username=clean_user,
            rank=clean_rank,
            password_record=password_record,
            enc_private_key=enc_private_key,
            enc_cert=enc_cert,
            sig_private_key=sig_private_key,
            sig_cert=sig_cert,
            user_password=password,
        )

        self.repo.append_audit_event(
            council.audit_hmac_key,
            event="JEDI_REGISTERED",
            actor="consejo_jedi",
            details=f"Registrado '{clean_user}' ({clean_rank}) con certificados X.509 de cifrado y firma.",
        )

        enc_summary = get_certificate_summary(enc_cert)
        sig_summary = get_certificate_summary(sig_cert)
        return [
            f"[AUTH] Contraseña protegida con {PASSWORD_ALGORITHM} ({PBKDF2_ITERATIONS} iteraciones, sal aleatoria de 128 bits).",
            f"[CLAVES] Par de cifrado generado ({RSA_ALGORITHM}, {RSA_KEY_BITS} bits) y guardado cifrado en PKCS#8.",
            f"[CLAVES] Par de firma generado ({ECDSA_ALGORITHM}, {ECDSA_KEY_BITS} bits) y guardado cifrado en PKCS#8.",
            f"[PKI] Certificado de cifrado emitido (serial={enc_summary['serial_hex']}, KeyUsage=keyEncipherment).",
            f"[PKI] Certificado de firma emitido (serial={sig_summary['serial_hex']}, KeyUsage=digitalSignature).",
            f"[HMAC] Evento JEDI_REGISTERED autenticado con {HMAC_ALGORITHM} ({HMAC_KEY_BITS} bits).",
        ]

    def authenticate_jedi(
        self,
        username: str,
        password: str,
        council: Optional[CouncilSession] = None,
    ) -> tuple[JediSession, list[str]]:
        """
        Autentica a un Jedi verificando:
        1. Contraseña frente al resumen PBKDF2-HMAC-SHA256 almacenado.
        2. Validez y estado de revocación (CRL) de ambos certificados X.509.
        3. Descifrado correcto de sus claves privadas PKCS#8.
        """
        try:
            clean_user = normalize_username(username)
            profile = self.repo.load_user_profile(clean_user)
        except StorageError as exc:
            raise AuthError("Credenciales inválidas.") from exc

        if not verify_password(password, profile.get("password_record", {})):
            if council is not None:
                self.repo.append_audit_event(
                    council.audit_hmac_key,
                    event="LOGIN_FAILED",
                    actor=clean_user,
                    details="Intento de inicio de sesión fallido (contraseña incorrecta).",
                )
            raise AuthError("Credenciales inválidas.")

        ca_cert = self.repo.load_ca_certificate()
        crl = self.repo.load_crl()
        enc_cert, sig_cert = self.repo.load_user_certificates(clean_user)

        # Un Jedi con certificados caducados o revocados en la CRL no puede iniciar sesión
        validate_user_certificate(enc_cert, ca_cert, crl, clean_user, PURPOSE_ENCRYPTION)
        validate_user_certificate(sig_cert, ca_cert, crl, clean_user, PURPOSE_SIGNATURE)

        try:
            enc_priv, sig_priv = self.repo.load_user_private_keys(clean_user, password)
        except PrivateKeyDecryptionError as exc:
            raise AuthError("No se pudieron descifrar las claves privadas del Jedi.") from exc

        if council is not None:
            self.repo.append_audit_event(
                council.audit_hmac_key,
                event="LOGIN_SUCCESS",
                actor=clean_user,
                details="Inicio de sesión verificado y certificados validados frente a la CRL.",
            )

        session = JediSession(
            username=clean_user,
            rank=profile.get("rank", "Jedi"),
            enc_private_key=enc_priv,
            sig_private_key=sig_priv,
            enc_cert=enc_cert,
            sig_cert=sig_cert,
        )
        debug_logs = [
            f"[AUTH] Autenticación superada para '{clean_user}' mediante {PASSWORD_ALGORITHM}.",
            "[PKI] Certificados X.509 de cifrado y firma verificados contra AC Raíz y CRL (estado: VÁLIDOS).",
            "[CLAVES] Claves privadas RSA-3072 y ECDSA-P256 descifradas en memoria desde PKCS#8.",
        ]
        return session, debug_logs

    def revoke_jedi(
        self,
        council: CouncilSession,
        username: str,
        reason: str = "Caída al Lado Oscuro / compromiso de claves",
    ) -> list[str]:
        """Revoca los certificados de cifrado y firma de un Jedi añadiéndolos a la CRL firmada."""
        clean_user = normalize_username(username)
        if not self.repo.user_exists(clean_user):
            raise AuthError(f"El Jedi '{clean_user}' no existe.")

        enc_cert, sig_cert = self.repo.load_user_certificates(clean_user)
        current_crl = self.repo.load_crl()
        updated_crl = revoke_certificates_in_crl(
            ca_private_key=council.ca_private_key,
            ca_cert=council.ca_cert,
            current_crl=current_crl,
            certs_to_revoke=[enc_cert, sig_cert],
        )
        self.repo.save_crl(updated_crl)

        profile = self.repo.load_user_profile(clean_user)
        profile["revoked"] = True
        self.repo.update_user_profile(clean_user, profile)

        self.repo.append_audit_event(
            council.audit_hmac_key,
            event="JEDI_REVOKED",
            actor="consejo_jedi",
            details=f"Certificados de '{clean_user}' revocados en la CRL. Motivo: {reason}",
        )

        return [
            f"[PKI] Certificado de cifrado de '{clean_user}' revocado (serial={format(enc_cert.serial_number, 'x')}).",
            f"[PKI] Certificado de firma de '{clean_user}' revocado (serial={format(sig_cert.serial_number, 'x')}).",
            "[PKI] Nueva CRL firmada por el Consejo Jedi y publicada en el repositorio.",
            f"[HMAC] Evento JEDI_REVOKED autenticado con {HMAC_ALGORITHM} ({HMAC_KEY_BITS} bits).",
        ]

    def verify_temple_audit_log(self, council: CouncilSession) -> tuple[list[dict[str, Any]], list[str]]:
        """Verifica la integridad de todas las entradas encadenadas del log de auditoría HMAC."""
        entries = self.repo.verify_audit_log(council.audit_hmac_key)
        debug_logs = [
            f"[HMAC] Verificación íntegra completada con {HMAC_ALGORITHM} (clave derivada: {HMAC_KEY_BITS} bits).",
            f"[HMAC] {len(entries)} entradas verificadas sin alteraciones ni rupturas de secuencia.",
        ]
        return entries, debug_logs
