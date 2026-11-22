"""
Pruebas positivas (funcionamiento correcto) para JediNet.

Verifican que todas las primitivas criptográficas y los flujos completos
de usuario funcionan correctamente bajo condiciones legítimas.
"""

from pathlib import Path

from src.app.auth_service import AuthService
from src.app.mail_service import MailService
from src.crypto.asymmetric import (
    ecdsa_sign,
    ecdsa_verify,
    generate_ecdsa_keypair,
    generate_rsa_keypair,
    load_private_key_encrypted,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    serialize_private_key_encrypted,
)
from src.crypto.passwords import hash_password, verify_password
from src.crypto.pki import (
    PURPOSE_ENCRYPTION,
    PURPOSE_SIGNATURE,
    create_crl,
    create_root_ca,
    issue_user_certificate,
    validate_user_certificate,
)
from src.crypto.symmetric import (
    compute_hmac_sha256,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_hmac_key,
    verify_hmac_sha256,
)
from src.storage.repository import JediRepository


def test_password_hashing_uses_unique_salt_and_verifies() -> None:
    """Dos contraseñas iguales generan sales y resúmenes distintos, y ambas verifican."""
    pwd = "MayTheForce!2026"
    rec1 = hash_password(pwd)
    rec2 = hash_password(pwd)

    assert rec1["salt"] != rec2["salt"]
    assert rec1["hash"] != rec2["hash"]
    assert verify_password(pwd, rec1) is True
    assert verify_password(pwd, rec2) is True


def test_aes_gcm_uses_unique_nonces_and_authenticates_aad() -> None:
    """AES-256-GCM genera nonces únicos por cifrado y descifra verificando los AAD."""
    key = generate_aes_key()
    plaintext = b"Planos secretos de la Estrella de la Muerte"
    aad = b"sender:leia|recipient:obiwan|seq:1"

    pkg1 = encrypt_aes_gcm(key, plaintext, associated_data=aad)
    pkg2 = encrypt_aes_gcm(key, plaintext, associated_data=aad)

    assert pkg1["nonce"] != pkg2["nonce"]
    assert pkg1["ciphertext"] != pkg2["ciphertext"]
    assert decrypt_aes_gcm(key, pkg1, associated_data=aad) == plaintext
    assert decrypt_aes_gcm(key, pkg2, associated_data=aad) == plaintext


def test_hmac_sha256_generation_and_verification() -> None:
    """Una etiqueta HMAC-SHA256 válida supera la verificación correctamente."""
    key = generate_hmac_key()
    data = b"Evento de auditoria del Templo Jedi"
    tag = compute_hmac_sha256(key, data)

    verify_hmac_sha256(key, data, tag)


def test_asymmetric_rsa_oaep_ecdsa_and_pkcs8_protection() -> None:
    """RSA-3072-OAEP no es determinista, ECDSA P-256 firma/verifica y PKCS#8 cifra la clave."""
    rsa_priv = generate_rsa_keypair()
    ec_priv = generate_ecdsa_keypair()

    # RSA-OAEP debe producir distintos textos cifrados para el mismo mensaje (IND-CPA)
    secret = generate_aes_key()
    ct1 = rsa_oaep_encrypt(rsa_priv.public_key(), secret)
    ct2 = rsa_oaep_encrypt(rsa_priv.public_key(), secret)
    assert ct1 != ct2
    assert rsa_oaep_decrypt(rsa_priv, ct1) == secret
    assert rsa_oaep_decrypt(rsa_priv, ct2) == secret

    # Firma digital ECDSA P-256 + SHA-256
    msg = b"Orden del Consejo Jedi #42"
    sig = ecdsa_sign(ec_priv, msg)
    ecdsa_verify(ec_priv.public_key(), msg, sig)

    # Protección PKCS#8 de clave privada en disco
    pem = serialize_private_key_encrypted(ec_priv, "ClavePrivada!2026")
    assert b"ENCRYPTED PRIVATE KEY" in pem
    loaded = load_private_key_encrypted(pem, "ClavePrivada!2026")
    assert loaded.public_key().public_numbers() == ec_priv.public_key().public_numbers()


def test_pki_certificate_issuance_and_validation() -> None:
    """La AC Raíz emite certificados X.509 v3 separados por uso que pasan la validación."""
    ca_priv, ca_cert = create_root_ca()
    crl = create_crl(ca_priv, ca_cert)
    rsa_priv = generate_rsa_keypair()
    ec_priv = generate_ecdsa_keypair()

    enc_cert = issue_user_certificate(
        ca_priv, ca_cert, "yoda", rsa_priv.public_key(), PURPOSE_ENCRYPTION
    )
    sig_cert = issue_user_certificate(
        ca_priv, ca_cert, "yoda", ec_priv.public_key(), PURPOSE_SIGNATURE
    )

    validate_user_certificate(enc_cert, ca_cert, crl, "yoda", PURPOSE_ENCRYPTION)
    validate_user_certificate(sig_cert, ca_cert, crl, "yoda", PURPOSE_SIGNATURE)


def test_end_to_end_jedi_workflow_and_no_secret_leakage(tmp_path: Path) -> None:
    """
    Prueba de integración completa:
    - Inicialización del Consejo Jedi y desbloqueo posterior.
    - Registro y autenticación de dos Jedis.
    - Envío y recepción secuencial de múltiples mensajes cifrados y firmados.
    - Verificación íntegra del registro de auditoría HMAC-SHA256.
    - Comprobación de que las contraseñas no aparecen en disco ni en logs de depuración.
    """
    repo = JediRepository(tmp_path)
    auth = AuthService(repo)
    mail = MailService(repo)

    council_pwd = "ConsejoJedi!2026"
    obi_pwd = "HelloThere!2026"
    ani_pwd = "ChosenOne!2026"

    _, init_logs = auth.initialize_council(council_pwd)
    council, unlock_logs = auth.unlock_council(council_pwd)

    reg_logs_1 = auth.register_jedi(council, "obiwan", "Maestro Jedi", obi_pwd)
    reg_logs_2 = auth.register_jedi(council, "anakin", "Caballero Jedi", ani_pwd)

    obi, login_logs_1 = auth.authenticate_jedi("obiwan", obi_pwd, council)
    ani, login_logs_2 = auth.authenticate_jedi("anakin", ani_pwd, council)

    pkg1, send_logs_1 = mail.send_message(
        obi, "anakin", "Misión Utapau", "Grievous se oculta en el nivel 10.", council
    )
    pkg2, send_logs_2 = mail.send_message(
        obi, "anakin", "Actualización", "Refuerzos en camino.", council
    )

    inbox = mail.list_inbox("anakin")
    assert len(inbox) == 2
    assert all(item["processed"] is False for item in inbox)

    msg1 = mail.receive_message(ani, pkg1["message_id"], council)
    msg2 = mail.receive_message(ani, pkg2["message_id"], council)

    assert msg1.sender == "obiwan"
    assert msg1.subject == "Misión Utapau"
    assert msg1.body == "Grievous se oculta en el nivel 10."
    assert msg1.sequence_number == 1
    assert msg2.sequence_number == 2
    assert msg2.body == "Refuerzos en camino."

    # Verificación del log de auditoría HMAC-SHA256
    entries, audit_logs = auth.verify_temple_audit_log(council)
    assert len(entries) >= 8

    # Verificar que ninguna contraseña en claro aparece en los logs ni en archivos de disco
    all_logs = "\n".join(
        init_logs
        + unlock_logs
        + reg_logs_1
        + reg_logs_2
        + login_logs_1
        + login_logs_2
        + send_logs_1
        + send_logs_2
        + msg1.debug_logs
        + msg2.debug_logs
        + audit_logs
    )
    for secret in (council_pwd, obi_pwd, ani_pwd):
        assert secret not in all_logs

    # Verificar que las claves privadas en disco están cifradas y los mensajes no guardan texto en claro
    enc_pem = (tmp_path / "users" / "obiwan" / "enc_private.pem").read_text(encoding="utf-8")
    assert "BEGIN ENCRYPTED PRIVATE KEY" in enc_pem
    raw_msg_file = (tmp_path / "messages" / f"{pkg1['message_id']}.json").read_text(encoding="utf-8")
    assert "Grievous" not in raw_msg_file