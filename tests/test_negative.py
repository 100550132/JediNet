"""
Pruebas negativas (fallo seguro y resistencia a ataques) para JediNet.

Demuestran explícitamente que la aplicación rechaza los datos y detiene el procesamiento ante:
- Contraseñas débiles o credenciales incorrectas.
- Alteración de ciphertext, tag de autenticación, metadatos AAD o clave simétrica en AES-256-GCM.
- Alteración de datos o etiqueta en HMAC-SHA256 y manipulación/borrado del log de auditoría.
- Alteración de la clave encapsulada RSA-3072-OAEP o uso de clave privada incorrecta.
- Alteración de firma digital ECDSA P-256 o suplantación de firmante.
- Ataques de repetición (replay) y números de secuencia antiguos.
- Certificados revocados en la CRL, emitidos por una CA no confiable, caducados o con KeyUsage erróneo.
- Entradas maliciosas tipo Path Traversal.
"""

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from src.app.auth_service import AuthError, AuthService
from src.app.mail_service import MailSecurityError, MailService, ReplayAttackError
from src.crypto.asymmetric import (
    AsymmetricDecryptionError,
    ECDSA_ALGORITHM,
    ECDSA_KEY_BITS,
    PrivateKeyDecryptionError,
    RSA_ALGORITHM,
    RSA_KEY_BITS,
    SignatureVerificationError,
    ecdsa_sign,
    ecdsa_verify,
    generate_ecdsa_keypair,
    generate_rsa_keypair,
    load_private_key_encrypted,
    rsa_oaep_encrypt,
    serialize_private_key_encrypted,
)
from src.crypto.passwords import WeakPasswordError, hash_password
from src.crypto.pki import (
    PURPOSE_ENCRYPTION,
    PURPOSE_SIGNATURE,
    CertificateRevokedError,
    CertificateValidationError,
    create_crl,
    create_root_ca,
    issue_user_certificate,
    serialize_certificate,
    validate_user_certificate,
)
from src.crypto.symmetric import (
    IntegrityVerificationError,
    compute_hmac_sha256,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_hmac_key,
    verify_hmac_sha256,
)
from src.storage.repository import JediRepository, StorageError


def _flip_first_bit_b64(value_b64: str) -> str:
    """Invierte un único bit en una cadena codificada en Base64 para simular manipulación."""
    raw = bytearray(base64.b64decode(value_b64))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def _setup_two_jedis(tmp_path: Path) -> dict[str, Any]:
    """Crea un entorno completo y limpio con Consejo Jedi, obiwan y anakin."""
    repo = JediRepository(tmp_path)
    auth = AuthService(repo)
    mail = MailService(repo)
    council, _ = auth.initialize_council("ConsejoJedi!2026")
    auth.register_jedi(council, "obiwan", "Maestro Jedi", "HelloThere!2026")
    auth.register_jedi(council, "anakin", "Caballero Jedi", "ChosenOne!2026")
    obi, _ = auth.authenticate_jedi("obiwan", "HelloThere!2026", council)
    ani, _ = auth.authenticate_jedi("anakin", "ChosenOne!2026", council)
    return {
        "repo": repo,
        "auth": auth,
        "mail": mail,
        "council": council,
        "obi": obi,
        "ani": ani,
    }


# ----------------------------------------------------------------------
# 1. Autenticación y contraseñas
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "weak_pwd",
    [
        "",
        "corta1!",
        "solominusculas123!",
        "SOLOMAYUSCULAS123!",
        "SinNumerosEnEstaClave!",
        "SinSimbolos2026Clave",
    ],
)
def test_weak_passwords_rejected(weak_pwd: str) -> None:
    with pytest.raises(WeakPasswordError):
        hash_password(weak_pwd)


def test_wrong_credentials_rejected(tmp_path: Path) -> None:
    env = _setup_two_jedis(tmp_path)

    with pytest.raises(AuthError):
        env["auth"].authenticate_jedi("obiwan", "ClaveIncorrecta!999", env["council"])

    with pytest.raises(AuthError):
        env["auth"].authenticate_jedi("darthmaul", "HelloThere!2026", env["council"])

    with pytest.raises(AuthError):
        env["auth"].unlock_council("ConsejoFalso!2026")

    # Contraseña incorrecta al intentar descifrar clave privada PKCS#8
    ec_priv = generate_ecdsa_keypair()
    pem = serialize_private_key_encrypted(ec_priv, "RealPassword!2026")
    with pytest.raises(PrivateKeyDecryptionError):
        load_private_key_encrypted(pem, "WrongPassword!2026")


# ----------------------------------------------------------------------
# 2. Integridad AEAD (AES-256-GCM) y HMAC-SHA256
# ----------------------------------------------------------------------

def test_aes_gcm_rejects_tampered_ciphertext_tag_aad_and_wrong_key() -> None:
    key = generate_aes_key()
    wrong_key = generate_aes_key()
    aad = b"from:obiwan|to:anakin|seq:1"
    pkg = encrypt_aes_gcm(key, b"Mensaje secreto", associated_data=aad)

    # 1 bit alterado en el ciphertext
    tampered_ct = copy.deepcopy(pkg)
    tampered_ct["ciphertext"] = _flip_first_bit_b64(tampered_ct["ciphertext"])
    with pytest.raises(IntegrityVerificationError):
        decrypt_aes_gcm(key, tampered_ct, associated_data=aad)

    # 1 bit alterado en el tag AEAD
    tampered_tag = copy.deepcopy(pkg)
    tampered_tag["tag"] = _flip_first_bit_b64(tampered_tag["tag"])
    with pytest.raises(IntegrityVerificationError):
        decrypt_aes_gcm(key, tampered_tag, associated_data=aad)

    # Metadatos asociados (AAD) modificados
    with pytest.raises(IntegrityVerificationError):
        decrypt_aes_gcm(key, pkg, associated_data=b"from:palpatine|to:anakin|seq:1")

    # Clave simétrica incorrecta
    with pytest.raises(IntegrityVerificationError):
        decrypt_aes_gcm(wrong_key, pkg, associated_data=aad)


def test_hmac_rejects_tampered_data_tag_or_wrong_key() -> None:
    key = generate_hmac_key()
    wrong_key = generate_hmac_key()
    data = b"Registro oficial del Templo"
    mac = compute_hmac_sha256(key, data)

    with pytest.raises(IntegrityVerificationError):
        verify_hmac_sha256(key, b"Registro alterado por Sith", mac)

    with pytest.raises(IntegrityVerificationError):
        verify_hmac_sha256(key, data, _flip_first_bit_b64(mac))

    with pytest.raises(IntegrityVerificationError):
        verify_hmac_sha256(wrong_key, data, mac)


def test_audit_log_detects_modification_and_deletion(tmp_path: Path) -> None:
    env = _setup_two_jedis(tmp_path)
    repo: JediRepository = env["repo"]
    council = env["council"]

    original_text = repo.audit_log_path.read_text(encoding="utf-8")

    # Caso A: modificación de un carácter en el texto de un evento
    data = json.loads(original_text)
    data["entries"][0]["details"] += " [ALTERADO]"
    repo.audit_log_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    with pytest.raises(IntegrityVerificationError):
        env["auth"].verify_temple_audit_log(council)

    # Caso B: borrado de una entrada intermedia (ruptura de secuencia y cadena prev_hmac)
    data_del = json.loads(original_text)
    assert len(data_del["entries"]) >= 3
    del data_del["entries"][1]
    repo.audit_log_path.write_text(json.dumps(data_del, indent=2), encoding="utf-8")
    with pytest.raises(IntegrityVerificationError):
        env["auth"].verify_temple_audit_log(council)


# ----------------------------------------------------------------------
# 3. Firma digital ECDSA y ataques sobre mensajes completos
# ----------------------------------------------------------------------

def test_ecdsa_rejects_altered_signature_message_or_wrong_signer() -> None:
    signer_priv = generate_ecdsa_keypair()
    other_priv = generate_ecdsa_keypair()
    data = b"Directiva oficial del Consejo"
    sig = ecdsa_sign(signer_priv, data)

    with pytest.raises(SignatureVerificationError):
        ecdsa_verify(signer_priv.public_key(), data, _flip_first_bit_b64(sig))

    with pytest.raises(SignatureVerificationError):
        ecdsa_verify(signer_priv.public_key(), b"Directiva manipulada", sig)

    with pytest.raises(SignatureVerificationError):
        ecdsa_verify(other_priv.public_key(), data, sig)


def test_e2e_message_rejects_tampered_ciphertext_tag_aad_and_rsa_key(tmp_path: Path) -> None:
    env = _setup_two_jedis(tmp_path)
    mail: MailService = env["mail"]
    pkg, _ = mail.send_message(env["obi"], "anakin", "Secreto", "Contenido confidencial")

    # 1. Ciphertext AES-GCM alterado
    bad_ct = copy.deepcopy(pkg)
    bad_ct["cipher_package"]["ciphertext"] = _flip_first_bit_b64(bad_ct["cipher_package"]["ciphertext"])
    with pytest.raises(IntegrityVerificationError):
        mail.verify_and_decrypt_package(env["ani"], bad_ct)

    # 2. Tag AES-GCM alterado
    bad_tag = copy.deepcopy(pkg)
    bad_tag["cipher_package"]["tag"] = _flip_first_bit_b64(bad_tag["cipher_package"]["tag"])
    with pytest.raises(IntegrityVerificationError):
        mail.verify_and_decrypt_package(env["ani"], bad_tag)

    # 3. Cabecera en claro (AAD) alterada
    bad_aad = copy.deepcopy(pkg)
    bad_aad["timestamp"] = "2099-01-01T00:00:00+00:00"
    with pytest.raises(IntegrityVerificationError):
        mail.verify_and_decrypt_package(env["ani"], bad_aad)

    # 4. Clave de sesión cifrada con RSA-OAEP alterada
    bad_rsa = copy.deepcopy(pkg)
    bad_rsa["encrypted_session_key"] = _flip_first_bit_b64(bad_rsa["encrypted_session_key"])
    with pytest.raises(AsymmetricDecryptionError):
        mail.verify_and_decrypt_package(env["ani"], bad_rsa)

    # 5. Otro Jedi intenta leer una transmisión que no es para él
    with pytest.raises(MailSecurityError):
        mail.verify_and_decrypt_package(env["obi"], pkg)


def test_e2e_message_rejects_altered_signature_inside_valid_aead(tmp_path: Path) -> None:
    """
    Construye un paquete con cifrado AES-GCM y RSA-OAEP válidos, pero con 1 bit alterado
    en la firma ECDSA interna, demostrando que la verificación de firma lo rechaza explícitamente.
    """
    env = _setup_two_jedis(tmp_path)
    obi = env["obi"]
    ani = env["ani"]
    mail: MailService = env["mail"]

    payload = {
        "message_id": "forged_sig_001",
        "sender": "obiwan",
        "recipient": "anakin",
        "sequence_number": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subject": "Orden falsa",
        "body": "Texto con firma manipulada",
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    altered_sig = _flip_first_bit_b64(ecdsa_sign(obi.sig_private_key, canonical_payload))

    inner_doc = {
        "payload": payload,
        "signature_algorithm": ECDSA_ALGORITHM,
        "signature_key_bits": ECDSA_KEY_BITS,
        "signature": altered_sig,
    }

    pkg: dict[str, Any] = {
        "message_id": payload["message_id"],
        "sender": payload["sender"],
        "recipient": payload["recipient"],
        "sequence_number": payload["sequence_number"],
        "timestamp": payload["timestamp"],
        "recipient_enc_cert_serial": format(ani.enc_cert.serial_number, "x"),
        "sender_sig_cert_serial": format(obi.sig_cert.serial_number, "x"),
        "sender_sig_cert_pem": serialize_certificate(obi.sig_cert).decode("ascii"),
        "key_encapsulation_algorithm": RSA_ALGORITHM,
        "key_encapsulation_bits": RSA_KEY_BITS,
    }
    aad = json.dumps(
        {
            "message_id": pkg["message_id"],
            "sender": pkg["sender"],
            "recipient": pkg["recipient"],
            "sequence_number": pkg["sequence_number"],
            "timestamp": pkg["timestamp"],
            "recipient_enc_cert_serial": pkg["recipient_enc_cert_serial"],
            "sender_sig_cert_serial": pkg["sender_sig_cert_serial"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    session_key = generate_aes_key()
    pkg["encrypted_session_key"] = rsa_oaep_encrypt(ani.enc_cert.public_key(), session_key)
    pkg["cipher_package"] = encrypt_aes_gcm(
        session_key,
        json.dumps(inner_doc, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        associated_data=aad,
    )

    with pytest.raises(SignatureVerificationError):
        mail.verify_and_decrypt_package(ani, pkg)


# ----------------------------------------------------------------------
# 4. Ataques de repetición (Replay)
# ----------------------------------------------------------------------

def test_replay_attack_rejected_on_duplicate_or_old_sequence(tmp_path: Path) -> None:
    env = _setup_two_jedis(tmp_path)
    mail: MailService = env["mail"]

    pkg1, _ = mail.send_message(env["obi"], "anakin", "Orden 1", "Primer mensaje")
    pkg2, _ = mail.send_message(env["obi"], "anakin", "Orden 2", "Segundo mensaje")

    # Lectura legítima del mensaje #2 (seq=2)
    msg2 = mail.receive_message(env["ani"], pkg2["message_id"])
    assert msg2.sequence_number == 2

    # Reenvío del mismo mensaje #2 -> bloqueado
    with pytest.raises(ReplayAttackError):
        mail.receive_message(env["ani"], pkg2["message_id"])

    # Intento de inyectar un mensaje más antiguo (seq=1 <= last_seq=2) -> bloqueado
    with pytest.raises(ReplayAttackError):
        mail.receive_message(env["ani"], pkg1["message_id"])


# ----------------------------------------------------------------------
# 5. PKI: CRL (revocación), CA fraudulenta, caducidad, KeyUsage y validación de entradas
# ----------------------------------------------------------------------

def test_revoked_jedi_blocked_across_login_send_and_receive(tmp_path: Path) -> None:
    env = _setup_two_jedis(tmp_path)
    auth: AuthService = env["auth"]
    mail: MailService = env["mail"]

    # Anakin envía un mensaje antes de ser revocado
    pkg_from_anakin, _ = mail.send_message(env["ani"], "obiwan", "Aviso", "Estoy en Mustafar")

    # El Consejo Jedi revoca los certificados de Anakin en la CRL
    auth.revoke_jedi(env["council"], "anakin", "Caída al Lado Oscuro")

    # 1. Anakin ya no puede iniciar sesión
    with pytest.raises(CertificateRevokedError):
        auth.authenticate_jedi("anakin", "ChosenOne!2026", env["council"])

    # 2. Obi-Wan no puede cifrar un nuevo mensaje para un destinatario revocado
    with pytest.raises(CertificateRevokedError):
        mail.send_message(env["obi"], "anakin", "Intento", "No debería enviarse")

    # 3. Obi-Wan rechaza la transmisión pendiente cuya firma pertenece a un certificado revocado
    with pytest.raises(CertificateRevokedError):
        mail.receive_message(env["obi"], pkg_from_anakin["message_id"])


def test_pki_rejects_wrong_key_usage_rogue_ca_and_expired_cert() -> None:
    ca_priv, ca_cert = create_root_ca()
    crl = create_crl(ca_priv, ca_cert)
    rogue_ca_priv, rogue_ca_cert = create_root_ca()

    rsa_priv = generate_rsa_keypair()
    ec_priv = generate_ecdsa_keypair()

    enc_cert = issue_user_certificate(
        ca_priv, ca_cert, "yoda", rsa_priv.public_key(), PURPOSE_ENCRYPTION, validity_days=10
    )
    rogue_cert = issue_user_certificate(
        rogue_ca_priv, rogue_ca_cert, "yoda", ec_priv.public_key(), PURPOSE_SIGNATURE
    )

    # Uso de certificado de cifrado para propósito de firma -> rechazado
    with pytest.raises(CertificateValidationError):
        validate_user_certificate(enc_cert, ca_cert, crl, "yoda", PURPOSE_SIGNATURE)

    # Identidad (CN) distinta a la esperada -> rechazada
    with pytest.raises(CertificateValidationError):
        validate_user_certificate(enc_cert, ca_cert, crl, "macewindu", PURPOSE_ENCRYPTION)

    # Certificado firmado por una CA falsa (Sith) -> rechazado
    with pytest.raises(CertificateValidationError):
        validate_user_certificate(rogue_cert, ca_cert, crl, "yoda", PURPOSE_SIGNATURE)

    # Certificado caducado -> rechazado
    future = datetime.now(timezone.utc) + timedelta(days=30)
    with pytest.raises(CertificateValidationError):
        validate_user_certificate(enc_cert, ca_cert, crl, "yoda", PURPOSE_ENCRYPTION, now_utc=future)


def test_path_traversal_username_rejected(tmp_path: Path) -> None:
    env = _setup_two_jedis(tmp_path)
    with pytest.raises(StorageError):
        env["auth"].register_jedi(env["council"], "../ca", "Padawan", "PasswordSegura!2026")