"""
Interfaz de línea de comandos (CLI) para JediNet.
Permite operar todos los servicios criptográficos desde la terminal:
- Inicialización y gestión de la AC Raíz del Consejo Jedi (PKI X.509 v3, CRL y log HMAC).
- Registro, autenticación y revocación de Jedis.
- Envío y lectura de transmisiones con firma ECDSA y cifrado híbrido AES-256-GCM + RSA-3072-OAEP.
- Laboratorio de demostración de ataques negativos sin corromper el repositorio real.
"""
import base64
import copy
import getpass
import json
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.app.auth_service import (
    ALLOWED_RANKS,
    AuthError,
    AuthService,
    CouncilSession,
    JediSession,
)
from src.app.mail_service import MailSecurityError, MailService, ReplayAttackError
from src.crypto.asymmetric import (
    AsymmetricCryptoError,
    ECDSA_ALGORITHM,
    ECDSA_KEY_BITS,
    RSA_ALGORITHM,
    RSA_KEY_BITS,
    SignatureVerificationError,
    ecdsa_sign,
    rsa_oaep_encrypt,
)
from src.crypto.passwords import WeakPasswordError
from src.crypto.pki import (
    CertificateRevokedError,
    CertificateValidationError,
    PKIError,
    get_certificate_summary,
    serialize_certificate,
)
from src.crypto.symmetric import (
    IntegrityVerificationError,
    SymmetricCryptoError,
    encrypt_aes_gcm,
    generate_aes_key,
)
from src.storage.repository import JediRepository, StorageError

HANDLED_ERRORS = (
    AuthError,
    MailSecurityError,
    WeakPasswordError,
    SymmetricCryptoError,
    AsymmetricCryptoError,
    PKIError,
    StorageError,
)


def print_header(title: str) -> None:
    line = "=" * 68
    print(f"\n{line}\n  {title}\n{line}")


def print_logs(logs: list[str]) -> None:
    print("\n--- Registro criptográfico de depuración (sin secretos) ---")
    for line in logs:
        print(f"  {line}")
    print("-" * 59)


def read_password(prompt: str) -> str:
    """
    Lee una contraseña sin mostrarla en pantalla cuando la terminal lo soporta.
    En consolas no interactivas (p. ej. consola Run básica de PyCharm) evita bloqueos.
    """
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(f"{prompt}(aviso: entrada visible en esta consola) ")


def _canonical_json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _build_demo_package(
    jedi: JediSession,
    tamper_mode: str,
) -> dict[str, Any]:
    """
    Construye en memoria una transmisión de prueba dirigida al propio Jedi autenticado
    con una manipulación controlada ('ciphertext' o 'signature') sin guardarla en disco.
    """
    msg_id = f"sim_{uuid.uuid4().hex[:12]}"
    timestamp = datetime.now(timezone.utc).isoformat()
    seq = 999_999

    payload = {
        "message_id": msg_id,
        "sender": jedi.username,
        "recipient": jedi.username,
        "sequence_number": seq,
        "timestamp": timestamp,
        "subject": "Prueba de seguridad JediNet",
        "body": "Coordenadas secretas del Templo Jedi en Coruscant.",
    }

    sig_b64 = ecdsa_sign(jedi.sig_private_key, _canonical_json_bytes(payload))
    if tamper_mode == "signature":
        # Alteramos 1 bit de la firma digital manteniendo el cifrado externo válido
        raw_sig = bytearray(base64.b64decode(sig_b64))
        raw_sig[-1] ^= 0x01
        sig_b64 = base64.b64encode(bytes(raw_sig)).decode("ascii")

    inner_document = {
        "payload": payload,
        "signature_algorithm": ECDSA_ALGORITHM,
        "signature_key_bits": ECDSA_KEY_BITS,
        "signature": sig_b64,
    }

    package: dict[str, Any] = {
        "message_id": msg_id,
        "sender": jedi.username,
        "recipient": jedi.username,
        "sequence_number": seq,
        "timestamp": timestamp,
        "recipient_enc_cert_serial": format(jedi.enc_cert.serial_number, "x"),
        "sender_sig_cert_serial": format(jedi.sig_cert.serial_number, "x"),
        "sender_sig_cert_pem": serialize_certificate(jedi.sig_cert).decode("ascii"),
        "key_encapsulation_algorithm": RSA_ALGORITHM,
        "key_encapsulation_bits": RSA_KEY_BITS,
    }

    header_aad = _canonical_json_bytes(
        {
            "message_id": package["message_id"],
            "sender": package["sender"],
            "recipient": package["recipient"],
            "sequence_number": package["sequence_number"],
            "timestamp": package["timestamp"],
            "recipient_enc_cert_serial": package["recipient_enc_cert_serial"],
            "sender_sig_cert_serial": package["sender_sig_cert_serial"],
        }
    )

    session_key = generate_aes_key()
    cipher_package = encrypt_aes_gcm(
        key=session_key,
        plaintext=_canonical_json_bytes(inner_document),
        associated_data=header_aad,
    )

    if tamper_mode == "ciphertext":
        # Alteramos 1 bit del texto cifrado AES-256-GCM
        raw_ct = bytearray(base64.b64decode(cipher_package["ciphertext"]))
        raw_ct[0] ^= 0x01
        cipher_package["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")

    package["encrypted_session_key"] = rsa_oaep_encrypt(jedi.enc_cert.public_key(), session_key)
    package["cipher_package"] = cipher_package
    return package


class JediNetCLI:
    """Controlador del menú interactivo en terminal para JediNet."""

    def __init__(self, data_dir: Path = Path("data")) -> None:
        self.repo = JediRepository(data_dir)
        self.auth = AuthService(self.repo)
        self.mail = MailService(self.repo)
        self.council: Optional[CouncilSession] = None
        self.jedi: Optional[JediSession] = None

    def run(self) -> None:
        print_header("JEDINET - RED DE COMUNICACIONES SEGURAS DE LA ORDEN JEDI")
        print("  Criptografía: PBKDF2-HMAC-SHA256 | AES-256-GCM | RSA-3072-OAEP")
        print("                ECDSA P-256 | HMAC-SHA256 | PKI X.509 v3 + CRL")

        while True:
            try:
                if not self.repo.is_initialized():
                    if not self._menu_uninitialized():
                        break
                elif self.jedi is not None:
                    self._menu_jedi()
                else:
                    if not self._menu_main():
                        break
            except KeyboardInterrupt:
                print("\n[INFO] Sesión finalizada por el usuario.")
                break
            except HANDLED_ERRORS as exc:
                print(f"\n[RECHAZO / ERROR DE SEGURIDAD] {exc}")

    # ------------------------------------------------------------------
    # Menús principales
    # ------------------------------------------------------------------

    def _menu_uninitialized(self) -> bool:
        print("\nEl sistema JediNet aún no tiene inicializada la AC Raíz del Consejo Jedi.")
        print("  1. Inicializar Consejo Jedi (crear AC Raíz, CRL y log HMAC)")
        print("  0. Salir")
        choice = input("\nSelecciona una opción: ").strip()

        if choice == "1":
            print("\nCrea una contraseña maestra robusta para el Consejo Jedi")
            print("(mínimo 12 caracteres, mayúscula, minúscula, número y símbolo).")
            pwd1 = read_password("Contraseña del Consejo Jedi: ")
            pwd2 = read_password("Repite la contraseña: ")
            if pwd1 != pwd2:
                print("\n[ERROR] Las contraseñas no coinciden.")
                return True
            self.council, logs = self.auth.initialize_council(pwd1)
            print("\n[OK] Consejo Jedi inicializado correctamente.")
            print_logs(logs)
            return True
        if choice == "0":
            print("Que la Fuerza te acompañe.")
            return False

        print("[AVISO] Opción no válida.")
        return True

    def _menu_main(self) -> bool:
        council_status = "DESBLOQUEADO" if self.council else "BLOQUEADO"
        print(f"\n=== MENÚ PRINCIPAL (Consejo Jedi: {council_status}) ===")
        print("  1. Panel del Consejo Jedi (altas, certificados, CRL, auditoría HMAC)")
        print("  2. Iniciar sesión como Jedi")
        print("  3. Ver directorio de Jedis registrados")
        print("  0. Salir")
        choice = input("\nSelecciona una opción: ").strip()

        if choice == "1":
            self._handle_council_access()
        elif choice == "2":
            self._handle_jedi_login()
        elif choice == "3":
            self._show_directory()
        elif choice == "0":
            print("Que la Fuerza te acompañe.")
            return False
        else:
            print("[AVISO] Opción no válida.")
        return True

    # ------------------------------------------------------------------
    # Panel del Consejo Jedi (AC Raíz + CRL + HMAC)
    # ------------------------------------------------------------------

    def _handle_council_access(self) -> None:
        if self.council is None:
            pwd = read_password("\nIntroduce la contraseña del Consejo Jedi: ")
            self.council, logs = self.auth.unlock_council(pwd)
            print("\n[OK] Consejo Jedi desbloqueado.")
            print_logs(logs)

        while self.council is not None:
            print("\n--- PANEL DEL CONSEJO JEDI (AC Raíz / PKI / Auditoría) ---")
            print("  1. Registrar nuevo Jedi (claves PKCS#8 + certificados X.509)")
            print("  2. Ver directorio de Jedis y certificados")
            print("  3. Revocar certificados de un Jedi en la CRL (Lado Oscuro)")
            print("  4. Verificar y mostrar registro de auditoría HMAC-SHA256")
            print("  5. [DEMO ATAQUE] Simular alteración del log HMAC (en copia temporal)")
            print("  6. Bloquear sesión del Consejo Jedi y volver")
            print("  0. Volver al menú principal (manteniendo Consejo desbloqueado)")
            choice = input("\nSelecciona una opción: ").strip()

            try:
                if choice == "1":
                    self._register_jedi()
                elif choice == "2":
                    self._show_directory()
                elif choice == "3":
                    self._revoke_jedi()
                elif choice == "4":
                    self._verify_audit_log()
                elif choice == "5":
                    self._simulate_hmac_attack()
                elif choice == "6":
                    self.council = None
                    print("[INFO] Sesión del Consejo Jedi bloqueada.")
                    return
                elif choice == "0":
                    return
                else:
                    print("[AVISO] Opción no válida.")
            except HANDLED_ERRORS as exc:
                print(f"\n[RECHAZO / ERROR DE SEGURIDAD] {exc}")

    def _register_jedi(self) -> None:
        assert self.council is not None
        print("\n--- Registro de nuevo Jedi ---")
        username = input("Nombre de usuario (ej. obiwan, yoda, anakin): ").strip()
        print("Rangos disponibles:")
        for idx, rank in enumerate(ALLOWED_RANKS, start=1):
            print(f"  {idx}. {rank}")
        rank_choice = input("Elige el número de rango: ").strip()
        if not rank_choice.isdigit() or not (1 <= int(rank_choice) <= len(ALLOWED_RANKS)):
            print("[ERROR] Selección de rango inválida.")
            return
        rank = ALLOWED_RANKS[int(rank_choice) - 1]

        print("Contraseña robusta (mín. 12 caracteres, mayúscula, minúscula, número y símbolo):")
        pwd1 = read_password("Contraseña del Jedi: ")
        pwd2 = read_password("Repite la contraseña: ")
        if pwd1 != pwd2:
            print("[ERROR] Las contraseñas no coinciden.")
            return

        logs = self.auth.register_jedi(self.council, username, rank, pwd1)
        print(f"\n[OK] Jedi '{username.lower()}' registrado correctamente.")
        print_logs(logs)

    def _show_directory(self) -> None:
        users = self.repo.list_users()
        print("\n--- Directorio de Jedis registrados ---")
        if not users:
            print("  (Todavía no hay Jedis registrados)")
            return

        crl = self.repo.load_crl()
        for u in users:
            profile = self.repo.load_user_profile(u)
            enc_cert, sig_cert = self.repo.load_user_certificates(u)
            enc_info = get_certificate_summary(enc_cert)
            sig_info = get_certificate_summary(sig_cert)
            revoked_in_crl = (
                crl.get_revoked_certificate_by_serial_number(sig_cert.serial_number) is not None
                or crl.get_revoked_certificate_by_serial_number(enc_cert.serial_number) is not None
            )
            status = "REVOCADO EN CRL" if revoked_in_crl else "ACTIVO"
            print(f"  * {u} ({profile.get('rank', 'Jedi')}) -> [{status}]")
            print(f"      Cert Cifrado: {enc_info['key_info']} | serial={enc_info['serial_hex']} | válido hasta {enc_info['valid_until']}")
            print(f"      Cert Firma  : {sig_info['key_info']} | serial={sig_info['serial_hex']} | válido hasta {sig_info['valid_until']}")

    def _revoke_jedi(self) -> None:
        assert self.council is not None
        self._show_directory()
        username = input("\nNombre del Jedi cuyos certificados deseas revocar: ").strip()
        reason = input("Motivo (Enter para valor por defecto): ").strip()
        logs = (
            self.auth.revoke_jedi(self.council, username, reason)
            if reason
            else self.auth.revoke_jedi(self.council, username)
        )
        print(f"\n[OK] Certificados de '{username.lower()}' revocados en la CRL.")
        print_logs(logs)

    def _verify_audit_log(self) -> None:
        assert self.council is not None
        entries, logs = self.auth.verify_temple_audit_log(self.council)
        print("\n[OK] Registro de auditoría íntegro y auténtico.")
        print_logs(logs)
        print("\nÚltimos eventos registrados:")
        for entry in entries[-10:]:
            print(
                f"  #{entry['seq']} [{entry['timestamp'][:19]}Z] "
                f"{entry['event']} | actor={entry['actor']} | {entry['details']}"
            )

    def _simulate_hmac_attack(self) -> None:
        assert self.council is not None
        print("\n[DEMO] Copiando audit_log.json a un entorno temporal y alterando 1 carácter...")
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_repo = JediRepository(Path(tmp_dir))
            tmp_repo.ensure_directories()
            shutil.copy2(self.repo.audit_log_path, tmp_repo.audit_log_path)

            raw_data = json.loads(tmp_repo.audit_log_path.read_text(encoding="utf-8"))
            if not raw_data.get("entries"):
                print("[AVISO] El log está vacío, no hay entradas para alterar.")
                return
            raw_data["entries"][0]["details"] += " [MANIPULADO POR SITH]"
            tmp_repo.audit_log_path.write_text(
                json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8"
            )

            try:
                tmp_repo.verify_audit_log(self.council.audit_hmac_key)
                print("[ERROR INESPERADO] La alteración no fue detectada.")
            except IntegrityVerificationError as exc:
                print(f"[ATAQUE BLOQUEADO CORRECTAMENTE] {exc}")

    # ------------------------------------------------------------------
    # Panel del Jedi autenticado (Mensajería + Laboratorio de ataques)
    # ------------------------------------------------------------------

    def _handle_jedi_login(self) -> None:
        print("\n--- Inicio de sesión Jedi ---")
        username = input("Usuario Jedi: ").strip()
        password = read_password("Contraseña: ")
        self.jedi, logs = self.auth.authenticate_jedi(username, password, council=self.council)
        print(f"\n[OK] Bienvenido/a, {self.jedi.rank} {self.jedi.username}.")
        print_logs(logs)

    def _menu_jedi(self) -> None:
        assert self.jedi is not None
        print(f"\n--- PANEL JEDI ({self.jedi.rank} {self.jedi.username}) ---")
        print("  1. Enviar transmisión secreta (cifrado híbrido + firma ECDSA)")
        print("  2. Ver bandeja de entrada y leer una transmisión")
        print("  3. Ver detalles de mis certificados X.509")
        print("  4. [DEMO ATAQUE] Simular alteración de ciphertext AES-256-GCM")
        print("  5. [DEMO ATAQUE] Simular firma digital ECDSA falsificada/alterada")
        print("  0. Cerrar sesión Jedi")
        choice = input("\nSelecciona una opción: ").strip()

        if choice == "1":
            self._send_message()
        elif choice == "2":
            self._read_inbox()
        elif choice == "3":
            self._show_my_certs()
        elif choice == "4":
            self._simulate_message_attack("ciphertext")
        elif choice == "5":
            self._simulate_message_attack("signature")
        elif choice == "0":
            print(f"[INFO] Sesión cerrada para '{self.jedi.username}'.")
            self.jedi = None
        else:
            print("[AVISO] Opción no válida.")

    def _send_message(self) -> None:
        assert self.jedi is not None
        users = self.repo.list_users()
        print(f"\nJedis disponibles: {', '.join(users)}")
        recipient = input("Destinatario: ").strip()
        subject = input("Asunto: ").strip()
        body = input("Mensaje secreto: ").strip()

        package, logs = self.mail.send_message(
            sender=self.jedi,
            recipient_username=recipient,
            subject=subject,
            body=body,
            council=self.council,
        )
        print(f"\n[OK] Transmisión '{package['message_id']}' enviada y cifrada correctamente.")
        print_logs(logs)

    def _read_inbox(self) -> None:
        assert self.jedi is not None
        inbox = self.mail.list_inbox(self.jedi.username)
        print(f"\n--- Bandeja de entrada de '{self.jedi.username}' ---")
        if not inbox:
            print("  (No tienes transmisiones recibidas)")
            return

        for idx, item in enumerate(inbox, start=1):
            status = "YA PROCESADA (reintentar dispara anti-replay)" if item["processed"] else "PENDIENTE"
            print(
                f"  {idx}. ID={item['message_id']} | De: {item['sender']} "
                f"| Seq={item['sequence_number']} | {item['timestamp'][:19]}Z | [{status}]"
            )

        sel = input("\nElige el número de transmisión a verificar y descifrar (Enter para volver): ").strip()
        if not sel:
            return
        if not sel.isdigit() or not (1 <= int(sel) <= len(inbox)):
            print("[ERROR] Selección inválida.")
            return

        msg_id = inbox[int(sel) - 1]["message_id"]
        try:
            msg = self.mail.receive_message(self.jedi, msg_id, council=self.council)
        except ReplayAttackError as exc:
            print(f"\n[ATAQUE DE REPETICIÓN BLOQUEADO] {exc}")
            return
        except CertificateRevokedError as exc:
            print(f"\n[CERTIFICADO REVOCADO EN CRL] {exc}")
            return

        print_logs(msg.debug_logs)
        print("\n" + "-" * 59)
        print(f"  DE     : {msg.sender}")
        print(f"  PARA   : {msg.recipient}")
        print(f"  FECHA  : {msg.timestamp}")
        print(f"  ASUNTO : {msg.subject}")
        print(f"  MENSAJE: {msg.body}")
        print("-" * 59)

    def _show_my_certs(self) -> None:
        assert self.jedi is not None
        enc_info = get_certificate_summary(self.jedi.enc_cert)
        sig_info = get_certificate_summary(self.jedi.sig_cert)
        print(f"\n--- Certificados X.509 de '{self.jedi.username}' ---")
        print(f"  Cifrado: {enc_info['key_info']} | serial={enc_info['serial_hex']} | válido hasta {enc_info['valid_until']}")
        print(f"  Firma  : {sig_info['key_info']} | serial={sig_info['serial_hex']} | válido hasta {sig_info['valid_until']}")

    def _simulate_message_attack(self, mode: str) -> None:
        assert self.jedi is not None
        label = (
            "1 bit alterado en el ciphertext AES-256-GCM"
            if mode == "ciphertext"
            else "1 bit alterado en la firma digital ECDSA P-256 (cifrado externo válido)"
        )
        print(f"\n[DEMO ATAQUE] Construyendo transmisión en memoria con: {label}...")
        tampered_pkg = copy.deepcopy(_build_demo_package(self.jedi, tamper_mode=mode))

        try:
            self.mail.verify_and_decrypt_package(self.jedi, tampered_pkg)
            print("[ERROR INESPERADO] La transmisión manipulada fue aceptada.")
        except (IntegrityVerificationError, SignatureVerificationError, CertificateValidationError) as exc:
            print(f"[ATAQUE BLOQUEADO CORRECTAMENTE] {exc}")

def main() -> None:
    JediNetCLI().run()

if __name__ == "__main__":
    main()