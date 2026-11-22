"""
Servicio de mensajería secreta extremo a extremo para JediNet.

Implementa el envío y la recepción verificada de transmisiones combinando:
- Validación PKI (certificados X.509 v3 + CRL) de emisor y receptor.
- Firma digital ECDSA P-256 + SHA-256 (autoría, integridad y no repudio).
- Cifrado híbrido: AES-256-GCM (AEAD con AAD y nonce único) + RSA-3072-OAEP (clave de sesión).
- Protección frente a ataques de repetición (números de secuencia e IDs únicos).
"""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from src.app.auth_service import CouncilSession, JediSession
from src.crypto.asymmetric import (
    ECDSA_ALGORITHM,
    ECDSA_KEY_BITS,
    RSA_ALGORITHM,
    RSA_KEY_BITS,
    SignatureVerificationError,
    ecdsa_sign,
    ecdsa_verify,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
)
from src.crypto.pki import (
    PURPOSE_ENCRYPTION,
    PURPOSE_SIGNATURE,
    get_certificate_summary,
    load_certificate,
    serialize_certificate,
    validate_user_certificate,
)
from src.crypto.symmetric import (
    AES_ALGORITHM,
    AES_KEY_BITS,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
)
from src.storage.repository import JediRepository, normalize_username


class MailSecurityError(Exception):
    """Error de seguridad o formato durante el envío o recepción de una transmisión."""


class ReplayAttackError(MailSecurityError):
    """Se lanza cuando se detecta una transmisión repetida o con secuencia ya procesada."""


@dataclass
class DecryptedMessage:
    """Representa una transmisión verificada criptográficamente y descifrada."""

    message_id: str
    sender: str
    recipient: str
    sequence_number: int
    timestamp: str
    subject: str
    body: str
    debug_logs: list[str]


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    """Serializa un diccionario a bytes JSON deterministas para firma y AAD."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _build_envelope_aad(package: dict[str, Any]) -> bytes:
    """
    Construye los Datos Asociados Autenticados (AAD) a partir de la cabecera en claro.
    Cualquier alteración de emisor, receptor, secuencia, fecha o certificados rompe el tag GCM.
    """
    header = {
        "message_id": package["message_id"],
        "sender": package["sender"],
        "recipient": package["recipient"],
        "sequence_number": package["sequence_number"],
        "timestamp": package["timestamp"],
        "recipient_enc_cert_serial": package["recipient_enc_cert_serial"],
        "sender_sig_cert_serial": package["sender_sig_cert_serial"],
    }
    return _canonical_bytes(header)


class MailService:
    """Capa de negocio para el intercambio cifrado y firmado de transmisiones Jedi."""

    def __init__(self, repo: JediRepository) -> None:
        self.repo = repo

    def send_message(
        self,
        sender: JediSession,
        recipient_username: str,
        subject: str,
        body: str,
        council: Optional[CouncilSession] = None,
    ) -> tuple[dict[str, Any], list[str]]:
        """
        Construye, firma, cifra y almacena una transmisión segura de 'sender' a 'recipient_username'.
        Devuelve (paquete_almacenado, debug_logs_sin_secretos).
        """
        recipient = normalize_username(recipient_username)
        if not self.repo.user_exists(recipient):
            raise MailSecurityError(f"El destinatario '{recipient}' no existe en JediNet.")

        clean_subject = subject.strip() if isinstance(subject, str) else ""
        clean_body = body.strip() if isinstance(body, str) else ""
        if not clean_subject or not clean_body:
            raise MailSecurityError("El asunto y el cuerpo del mensaje no pueden estar vacíos.")

        ca_cert = self.repo.load_ca_certificate()
        crl = self.repo.load_crl()

        # 1. Validar el certificado de firma del propio emisor (por si fue revocado)
        validate_user_certificate(
            sender.sig_cert, ca_cert, crl, sender.username, PURPOSE_SIGNATURE
        )

        # 2. Obtener y validar el certificado de cifrado RSA del destinatario antes de confiar en su clave
        recipient_enc_cert, _ = self.repo.load_user_certificates(recipient)
        validate_user_certificate(
            recipient_enc_cert, ca_cert, crl, recipient, PURPOSE_ENCRYPTION
        )
        recipient_rsa_pub = recipient_enc_cert.public_key()
        if not isinstance(recipient_rsa_pub, rsa.RSAPublicKey):
            raise MailSecurityError("La clave pública del destinatario no es RSA válida.")

        # 3. Construir metadatos anti-repetición
        message_id = uuid.uuid4().hex[:16]
        timestamp = datetime.now(timezone.utc).isoformat()
        seq = self.repo.get_next_send_sequence(sender.username, recipient)

        payload = {
            "message_id": message_id,
            "sender": sender.username,
            "recipient": recipient,
            "sequence_number": seq,
            "timestamp": timestamp,
            "subject": clean_subject,
            "body": clean_body,
        }

        # 4. Firma digital ECDSA P-256 + SHA-256 sobre el contenido estructurado (Sign-then-Encrypt)
        signature_b64 = ecdsa_sign(sender.sig_private_key, _canonical_bytes(payload))

        inner_document = {
            "payload": payload,
            "signature_algorithm": ECDSA_ALGORITHM,
            "signature_key_bits": ECDSA_KEY_BITS,
            "signature": signature_b64,
        }

        # 5. Cabecera externa y Datos Asociados Autenticados (AAD)
        package: dict[str, Any] = {
            "message_id": message_id,
            "sender": sender.username,
            "recipient": recipient,
            "sequence_number": seq,
            "timestamp": timestamp,
            "recipient_enc_cert_serial": format(recipient_enc_cert.serial_number, "x"),
            "sender_sig_cert_serial": format(sender.sig_cert.serial_number, "x"),
            "sender_sig_cert_pem": serialize_certificate(sender.sig_cert).decode("ascii"),
            "key_encapsulation_algorithm": RSA_ALGORITHM,
            "key_encapsulation_bits": RSA_KEY_BITS,
        }
        aad_bytes = _build_envelope_aad(package)

        # 6. Cifrado híbrido: clave efímera AES-256 + AES-256-GCM (AEAD) + RSA-3072-OAEP
        session_key = generate_aes_key()
        cipher_package = encrypt_aes_gcm(
            key=session_key,
            plaintext=_canonical_bytes(inner_document),
            associated_data=aad_bytes,
        )
        encrypted_session_key = rsa_oaep_encrypt(recipient_rsa_pub, session_key)

        package["encrypted_session_key"] = encrypted_session_key
        package["cipher_package"] = cipher_package

        self.repo.save_message(package)

        if council is not None:
            self.repo.append_audit_event(
                council.audit_hmac_key,
                event="MESSAGE_SENT",
                actor=sender.username,
                details=f"Transmisión {message_id} enviada a '{recipient}' (seq={seq}).",
            )

        rec_summary = get_certificate_summary(recipient_enc_cert)
        sig_summary = get_certificate_summary(sender.sig_cert)
        debug_logs = [
            f"[PKI] Certificado de cifrado de '{recipient}' validado (serial={rec_summary['serial_hex']}, {rec_summary['key_info']}).",
            f"[FIRMA] Transmisión firmada con {ECDSA_ALGORITHM} ({ECDSA_KEY_BITS} bits, cert serial={sig_summary['serial_hex']}).",
            f"[CIFRADO AEAD] Contenido cifrado con {AES_ALGORITHM} (clave efímera: {AES_KEY_BITS} bits, nonce único: {GCM_NONCE_BYTES * 8} bits, tag: {GCM_TAG_BYTES * 8} bits, AAD incluidos).",
            f"[CIFRADO ASIMÉTRICO] Clave de sesión encapsulada con {RSA_ALGORITHM} ({RSA_KEY_BITS} bits).",
            f"[ANTI-REPLAY] Asignados message_id={message_id} y sequence_number={seq}.",
        ]
        return package, debug_logs

    def receive_message(
        self,
        recipient: JediSession,
        message_id: str,
        council: Optional[CouncilSession] = None,
    ) -> DecryptedMessage:
        """Carga una transmisión del repositorio por su ID y la verifica/descifra."""
        package = self.repo.load_message(message_id)
        return self.verify_and_decrypt_package(recipient, package, council=council)

    def verify_and_decrypt_package(
        self,
        recipient: JediSession,
        package: dict[str, Any],
        council: Optional[CouncilSession] = None,
    ) -> DecryptedMessage:
        """
        Verifica y descifra un paquete de transmisión completo.
        Rechaza explícitamente cualquier fallo de replay, PKI, RSA-OAEP, AES-GCM o firma ECDSA.
        """
        required_fields = (
            "message_id",
            "sender",
            "recipient",
            "sequence_number",
            "timestamp",
            "recipient_enc_cert_serial",
            "sender_sig_cert_serial",
            "sender_sig_cert_pem",
            "encrypted_session_key",
            "cipher_package",
        )
        if not isinstance(package, dict) or any(f not in package for f in required_fields):
            raise MailSecurityError("Estructura de transmisión incompleta o corrupta.")

        if package["recipient"] != recipient.username:
            raise MailSecurityError("Esta transmisión no está dirigida al Jedi autenticado.")

        sender_username = normalize_username(package["sender"])
        message_id = str(package["message_id"])
        try:
            seq = int(package["sequence_number"])
        except (TypeError, ValueError) as exc:
            raise MailSecurityError("Número de secuencia inválido en la transmisión.") from exc
        if seq <= 0:
            raise MailSecurityError("El número de secuencia debe ser positivo.")

        # 1. Comprobación anti-repetición (replay attack)
        if self.repo.check_replay(sender_username, recipient.username, seq, message_id):
            raise ReplayAttackError(
                f"Ataque de repetición detectado: la transmisión '{message_id}' (seq={seq}) "
                f"de '{sender_username}' ya fue procesada o está fuera de secuencia."
            )

        ca_cert = self.repo.load_ca_certificate()
        crl = self.repo.load_crl()

        # 2. Validar certificado propio del receptor y certificado de firma adjunto del emisor
        validate_user_certificate(
            recipient.enc_cert, ca_cert, crl, recipient.username, PURPOSE_ENCRYPTION
        )
        sender_sig_cert = load_certificate(package["sender_sig_cert_pem"].encode("ascii"))
        validate_user_certificate(
            sender_sig_cert, ca_cert, crl, sender_username, PURPOSE_SIGNATURE
        )

        # Comprobar coherencia entre el número de serie declarado en cabecera y el certificado adjunto
        if format(sender_sig_cert.serial_number, "x") != package["sender_sig_cert_serial"]:
            raise MailSecurityError("El número de serie del certificado del emisor no coincide con la cabecera.")

        sender_ecdsa_pub = sender_sig_cert.public_key()
        if not isinstance(sender_ecdsa_pub, ec.EllipticCurvePublicKey):
            raise MailSecurityError("La clave pública de firma del emisor no es ECDSA válida.")

        # 3. Descifrar clave de sesión efímera con RSA-3072-OAEP
        session_key = rsa_oaep_decrypt(recipient.enc_private_key, package["encrypted_session_key"])

        # 4. Verificar tag AEAD + AAD y descifrar contenido con AES-256-GCM
        aad_bytes = _build_envelope_aad(package)
        plaintext_bytes = decrypt_aes_gcm(
            key=session_key,
            encrypted_package=package["cipher_package"],
            associated_data=aad_bytes,
        )

        # 5. Parsear documento interno y comprobar coherencia de metadatos
        try:
            inner_document = json.loads(plaintext_bytes.decode("utf-8"))
            payload = inner_document["payload"]
            signature_b64 = inner_document["signature"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise MailSecurityError("Contenido interno descifrado con formato inválido.") from exc

        for field in ("message_id", "sender", "recipient", "sequence_number", "timestamp"):
            if payload.get(field) != package.get(field):
                raise MailSecurityError(
                    f"Inconsistencia de seguridad: el campo '{field}' no coincide entre cabecera y carga firmada."
                )

        # 6. Verificar firma digital ECDSA P-256 + SHA-256 (autoría, integridad y no repudio)
        ecdsa_verify(sender_ecdsa_pub, _canonical_bytes(payload), signature_b64)

        # 7. Registrar recepción solo después de superar TODAS las comprobaciones criptográficas
        self.repo.record_received_message(sender_username, recipient.username, seq, message_id)

        if council is not None:
            self.repo.append_audit_event(
                council.audit_hmac_key,
                event="MESSAGE_VERIFIED",
                actor=recipient.username,
                details=f"Transmisión {message_id} de '{sender_username}' (seq={seq}) verificada y descifrada.",
            )

        sig_summary = get_certificate_summary(sender_sig_cert)
        debug_logs = [
            f"[ANTI-REPLAY] Comprobación superada (message_id={message_id}, seq={seq}).",
            f"[PKI] Certificado de firma de '{sender_username}' validado contra AC Raíz y CRL (serial={sig_summary['serial_hex']}).",
            f"[DESCIFRADO ASIMÉTRICO] Clave de sesión recuperada con {RSA_ALGORITHM} ({RSA_KEY_BITS} bits).",
            f"[DESCIFRADO AEAD] Tag {AES_ALGORITHM} y metadatos AAD verificados correctamente (clave: {AES_KEY_BITS} bits).",
            f"[FIRMA] Firma digital {ECDSA_ALGORITHM} ({ECDSA_KEY_BITS} bits) VÁLIDA — autoría de '{sender_username}' confirmada.",
        ]

        return DecryptedMessage(
            message_id=message_id,
            sender=sender_username,
            recipient=recipient.username,
            sequence_number=seq,
            timestamp=str(payload["timestamp"]),
            subject=str(payload["subject"]),
            body=str(payload["body"]),
            debug_logs=debug_logs,
        )

    def list_inbox(self, username: str) -> list[dict[str, Any]]:
        """Devuelve un resumen de las transmisiones recibidas (sin descifrar aún)."""
        packages = self.repo.list_messages_for_user(username)
        summaries: list[dict[str, Any]] = []
        for pkg in packages:
            already_read = self.repo.check_replay(
                pkg["sender"],
                pkg["recipient"],
                int(pkg["sequence_number"]),
                pkg["message_id"],
            )
            summaries.append(
                {
                    "message_id": pkg["message_id"],
                    "sender": pkg["sender"],
                    "sequence_number": pkg["sequence_number"],
                    "timestamp": pkg["timestamp"],
                    "processed": already_read,
                }
            )
        return summaries
