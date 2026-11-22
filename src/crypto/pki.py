"""
Módulo PKI (Infraestructura de Clave Pública) del Consejo Jedi para JediNet.

Implementa:
- Creación de la Autoridad de Certificación Raíz (AC Raíz) del Consejo Jedi.
- Emisión de certificados X.509 v3 separados por propósito (cifrado vs. firma digital)
  con extensiones BasicConstraints y KeyUsage marcadas como críticas.
- Gestión de Lista de Certificados Revocados (CRL) firmada por la AC Raíz.
- Validación completa de certificados: firma de la AC, periodo de validez, identidad (CN),
  restricciones de uso de clave (KeyUsage) y comprobación frente a la CRL.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from src.crypto.asymmetric import PublicKeyType, generate_ecdsa_keypair

ORGANIZATION_NAME = "Orden Jedi - JediNet"
CA_COMMON_NAME = "Consejo Jedi Root CA"

CA_VALIDITY_DAYS = 3650        # 10 años para la AC Raíz
USER_CERT_VALIDITY_DAYS = 365  # 1 año para certificados de usuario
CRL_VALIDITY_DAYS = 30

PURPOSE_ENCRYPTION = "encryption"
PURPOSE_SIGNATURE = "signature"


class PKIError(Exception):
    """Error genérico de la infraestructura PKI."""


class CertificateValidationError(PKIError):
    """Se lanza cuando un certificado no supera alguna comprobación de validez."""


class CertificateRevokedError(CertificateValidationError):
    """Se lanza cuando un certificado figura en la Lista de Certificados Revocados (CRL)."""


def create_root_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Crea el par de claves ECDSA P-256 y el certificado autofirmado X.509 v3
    de la Autoridad de Certificación Raíz del Consejo Jedi.
    """
    ca_private_key = generate_ecdsa_keypair()
    ca_public_key = ca_private_key.public_key()

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        ]
    )

    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key),
            critical=False,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )
    return ca_private_key, ca_cert


def issue_user_certificate(
    ca_private_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    username: str,
    user_public_key: PublicKeyType,
    purpose: str,
    validity_days: int = USER_CERT_VALIDITY_DAYS,
) -> x509.Certificate:
    """
    Emite un certificado X.509 v3 firmado por el Consejo Jedi para un usuario concreto.

    Separa estrictamente el uso de clave mediante la extensión crítica KeyUsage:
    - purpose='encryption': clave pública RSA, solo key_encipherment=True.
    - purpose='signature': clave pública ECDSA, solo digital_signature=True.
    """
    if not isinstance(username, str) or not username.strip():
        raise PKIError("El nombre de usuario (CN) no puede estar vacío.")
    if validity_days <= 0:
        raise PKIError("El periodo de validez debe ser mayor que cero.")

    if purpose == PURPOSE_ENCRYPTION:
        if not isinstance(user_public_key, rsa.RSAPublicKey):
            raise PKIError("Un certificado de cifrado requiere una clave pública RSA.")
        key_usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    elif purpose == PURPOSE_SIGNATURE:
        if not isinstance(user_public_key, ec.EllipticCurvePublicKey):
            raise PKIError("Un certificado de firma requiere una clave pública ECDSA.")
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    else:
        raise PKIError(f"Propósito de certificado no soportado: {purpose}")

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, purpose),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ]
    )

    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(user_public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )


def create_crl(
    ca_private_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    revoked_entries: Optional[list[tuple[int, datetime]]] = None,
) -> x509.CertificateRevocationList:
    """
    Genera y firma una Lista de Certificados Revocados (CRL) emitida por el Consejo Jedi.
    """
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=CRL_VALIDITY_DAYS))
    )

    for serial_number, rev_date in revoked_entries or []:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_number)
            .revocation_date(rev_date)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    return builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())


def revoke_certificates_in_crl(
    ca_private_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    current_crl: x509.CertificateRevocationList,
    certs_to_revoke: list[x509.Certificate],
) -> x509.CertificateRevocationList:
    """
    Añade uno o varios certificados a la CRL actual y la vuelve a firmar con la AC Raíz.
    """
    entries: dict[int, datetime] = {
        revoked.serial_number: revoked.revocation_date_utc for revoked in current_crl
    }
    now = datetime.now(timezone.utc)
    for cert in certs_to_revoke:
        if cert.serial_number not in entries:
            entries[cert.serial_number] = now

    return create_crl(ca_private_key, ca_cert, list(entries.items()))


def validate_user_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    crl: x509.CertificateRevocationList,
    expected_username: str,
    expected_purpose: str,
    now_utc: Optional[datetime] = None,
) -> None:
    """
    Valida un certificado de usuario antes de confiar en su clave pública.

    Comprueba en orden:
    1. Autenticidad y vigencia de la CRL (firmada por la AC Raíz).
    2. Firma criptográfica del certificado frente a la AC Raíz.
    3. Vigencia temporal del certificado.
    4. Extensión BasicConstraints (no debe ser una CA).
    5. Identidad del titular (Common Name coincide con el Jedi esperado).
    6. Extensión KeyUsage y tipo de clave acordes al propósito (cifrado o firma).
    7. Ausencia del número de serie en la CRL (no revocado).
    """
    now = now_utc or datetime.now(timezone.utc)

    # 0. Verificar vigencia y usos permitidos de la propia AC Raíz
    if now < ca_cert.not_valid_before_utc or now > ca_cert.not_valid_after_utc:
        raise CertificateValidationError(
            "El certificado de la AC Raíz está caducado.")
    try:
        ca_bc = ca_cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value
        ca_ku = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError(
            "Certificado de AC Raíz sin extensiones requeridas.") from exc
    if not ca_bc.ca or not ca_ku.key_cert_sign or not ca_ku.crl_sign:
        raise CertificateValidationError(
            "La AC Raíz no está autorizada para emitir certificados o CRLs.")

    # 1. Validar integridad y autenticidad de la CRL
    if crl.issuer != ca_cert.subject or not crl.is_signature_valid(ca_cert.public_key()):
        raise CertificateValidationError(
            "La CRL no tiene una firma válida de la AC Raíz del Consejo Jedi."
        )
    if crl.next_update_utc is not None and now > crl.next_update_utc:
        raise CertificateValidationError("La CRL del Consejo Jedi está caducada.")

    # 2. Verificar firma e emisor del certificado
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise CertificateValidationError(
            "Certificado rechazado: no está firmado válidamente por el Consejo Jedi."
        ) from exc

    # 3. Verificar fechas de validez
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise CertificateValidationError("Certificado rechazado: fuera de su periodo de validez.")

    # 4. Verificar que es certificado de entidad final (no CA)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("Certificado sin extensión BasicConstraints.") from exc
    if bc.ca:
        raise CertificateValidationError("Certificado de CA no puede utilizarse como usuario final.")

    # 5. Verificar identidad (Common Name)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != expected_username:
        raise CertificateValidationError(
            f"Identidad del certificado no coincide con el usuario esperado ('{expected_username}')."
        )

    # 6. Verificar KeyUsage y tipo de clave según propósito
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("Certificado sin extensión KeyUsage.") from exc

    pub_key = cert.public_key()
    if expected_purpose == PURPOSE_ENCRYPTION:
        if not ku.key_encipherment or not isinstance(pub_key, rsa.RSAPublicKey):
            raise CertificateValidationError(
                "El certificado no está autorizado para cifrado de claves (keyEncipherment / RSA)."
            )
    elif expected_purpose == PURPOSE_SIGNATURE:
        if not ku.digital_signature or not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise CertificateValidationError(
                "El certificado no está autorizado para firma digital (digitalSignature / ECDSA)."
            )
    else:
        raise CertificateValidationError(f"Propósito de validación desconocido: {expected_purpose}")

    # 7. Comprobar estado de revocación en la CRL
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        raise CertificateRevokedError(
            f"Certificado de '{expected_username}' REVOCADO por el Consejo Jedi (presente en la CRL)."
        )


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serializa un certificado X.509 a formato PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate(pem_data: bytes) -> x509.Certificate:
    """Carga un certificado X.509 desde bytes PEM."""
    try:
        return x509.load_pem_x509_certificate(pem_data)
    except ValueError as exc:
        raise CertificateValidationError("No se pudo leer el certificado PEM (archivo corrupto).") from exc


def serialize_crl(crl: x509.CertificateRevocationList) -> bytes:
    """Serializa una CRL X.509 a formato PEM."""
    return crl.public_bytes(serialization.Encoding.PEM)


def load_crl(pem_data: bytes) -> x509.CertificateRevocationList:
    """Carga una CRL X.509 desde bytes PEM."""
    try:
        return x509.load_pem_x509_crl(pem_data)
    except ValueError as exc:
        raise PKIError("No se pudo leer la CRL PEM (archivo corrupto).") from exc


def get_certificate_summary(cert: x509.Certificate) -> dict[str, Any]:
    """
    Devuelve metadatos seguros de un certificado para mostrar en logs de depuración
    (nunca expone secretos ni claves privadas).
    """
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ou_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    pub = cert.public_key()
    key_info = (
        f"RSA-{pub.key_size}"
        if isinstance(pub, rsa.RSAPublicKey)
        else f"ECDSA-{pub.curve.name}"
        if isinstance(pub, ec.EllipticCurvePublicKey)
        else "Unknown"
    )
    return {
        "cn": cn_attrs[0].value if cn_attrs else "N/A",
        "purpose": ou_attrs[0].value if ou_attrs else "root_ca",
        "serial_hex": format(cert.serial_number, "x"),
        "key_info": key_info,
        "valid_until": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
    }