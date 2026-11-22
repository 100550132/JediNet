"""
Capa de persistencia segura para JediNet.
Gestiona el almacenamiento local dentro de la carpeta data/.
- Certificados y clave privada cifrada (PKCS#8) de la AC Raíz del Consejo Jedi y su CRL.
- Perfiles de Jedis, certificados X.509 v3 y claves privadas cifradas con permisos restrictivos.
- Transmisiones cifradas/firmadas y control de estado anti-repetición (replay).
- Registro de auditoría del Templo protegido con etiquetas HMAC-SHA256 encadenadas,
  cuya clave se deriva de la contraseña del Consejo Jedi (nunca se almacena en disco).
"""
import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from src.crypto.asymmetric import (
    load_private_key_encrypted,
    serialize_private_key_encrypted,
)
from src.crypto.passwords import derive_key_from_password, generate_salt
from src.crypto.pki import (
    load_certificate,
    load_crl,
    serialize_certificate,
    serialize_crl,
)
from src.crypto.symmetric import (
    HMAC_ALGORITHM,
    HMAC_KEY_BITS,
    HMAC_KEY_BYTES,
    IntegrityVerificationError,
    compute_hmac_sha256,
    verify_hmac_sha256,
)

# Expresiones regulares estrictas para prevenir ataques de Path Traversal (ej. ../../)
USERNAME_PATTERN = re.compile(r"^[a-z0-9_-]{3,30}$")
MESSAGE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class StorageError(Exception):
    """Error genérico en operaciones de lectura o escritura del repositorio."""


def normalize_username(username: str) -> str:
    """Valida y normaliza un nombre de Jedi para evitar caracteres inválidos o path traversal."""
    if not isinstance(username, str):
        raise StorageError("El nombre de usuario debe ser una cadena de texto.")
    normalized = username.strip().lower()
    if not USERNAME_PATTERN.match(normalized):
        raise StorageError(
            "Nombre de Jedi inválido: usa entre 3 y 30 caracteres (letras, números, '_' o '-')."
        )
    return normalized


def validate_message_id(message_id: str) -> str:
    """Valida el identificador de un mensaje antes de construir rutas en disco."""
    if not isinstance(message_id, str) or not MESSAGE_ID_PATTERN.match(message_id):
        raise StorageError("Identificador de mensaje inválido.")
    return message_id


def _canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serializa un diccionario de forma determinista para calcular y verificar HMAC."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _write_secure_bytes(path: Path, data: bytes, restricted: bool = False) -> None:
    """
    Escribe bytes en disco creando directorios padre si no existen.
    Si 'restricted=True', aplica permisos restrictivos (solo propietario: 0o600 en POSIX).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if restricted:
        try:
            os.chmod(path, 0o600)
        except OSError:
            # En algunos sistemas Windows los permisos POSIX tienen efecto limitado
            pass


def _write_json(path: Path, data: dict[str, Any], restricted: bool = False) -> None:
    """Guarda un diccionario como JSON legible en UTF-8."""
    raw = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    _write_secure_bytes(path, raw, restricted=restricted)


def _read_json(path: Path) -> dict[str, Any]:
    """Lee un archivo JSON validando su existencia e integridad sintáctica."""
    if not path.exists():
        raise StorageError(f"Archivo no encontrado: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageError(f"No se pudo leer el archivo JSON '{path.name}': {exc}") from exc


class JediRepository:
    """Repositorio local de datos para una instancia de JediNet."""

    def __init__(self, base_dir: Path | str = Path("data")) -> None:
        self.base_dir = Path(base_dir)
        self.ca_dir = self.base_dir / "ca"
        self.users_dir = self.base_dir / "users"
        self.messages_dir = self.base_dir / "messages"
        self.replay_state_path = self.base_dir / "replay_state.json"
        self.audit_log_path = self.base_dir / "audit_log.json"

    def ensure_directories(self) -> None:
        """Crea la estructura de carpetas base si todavía no existe."""
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.users_dir.mkdir(parents=True, exist_ok=True)
        self.messages_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Autoridad de Certificación (Consejo Jedi) y CRL
    # ------------------------------------------------------------------

    def is_initialized(self) -> bool:
        """Comprueba si la AC Raíz del Consejo Jedi ya ha sido inicializada."""
        return (
            (self.ca_dir / "ca_private.pem").exists()
            and (self.ca_dir / "ca_cert.pem").exists()
            and (self.ca_dir / "crl.pem").exists()
            and self.audit_log_path.exists()
        )

    def save_ca(
        self,
        ca_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
        crl: x509.CertificateRevocationList,
        council_password: str,
    ) -> None:
        """Guarda la AC Raíz cifrando su clave privada con la contraseña del Consejo Jedi."""
        self.ensure_directories()

        ca_priv_pem = serialize_private_key_encrypted(ca_private_key, council_password)
        _write_secure_bytes(self.ca_dir / "ca_private.pem", ca_priv_pem, restricted=True)
        _write_secure_bytes(self.ca_dir / "ca_cert.pem", serialize_certificate(ca_cert))
        _write_secure_bytes(self.ca_dir / "crl.pem", serialize_crl(crl))

        # Inicializa el log de auditoría con una sal aleatoria (la clave HMAC no se guarda)
        audit_salt = generate_salt()
        _write_json(
            self.audit_log_path,
            {
                "algorithm": HMAC_ALGORITHM,
                "key_bits": HMAC_KEY_BITS,
                "kdf_salt": base64.b64encode(audit_salt).decode("ascii"),
                "entries": [],
            },
        )

        # Inicializa el estado anti-repetición
        _write_json(
            self.replay_state_path,
            {
                "next_send_seq": {},
                "last_received_seq": {},
                "seen_message_ids": [],
            },
        )

    def load_ca_certificate(self) -> x509.Certificate:
        path = self.ca_dir / "ca_cert.pem"
        if not path.exists():
            raise StorageError("Certificado de la AC Raíz no encontrado.")
        return load_certificate(path.read_bytes())

    def load_ca_private_key(self, council_password: str) -> ec.EllipticCurvePrivateKey:
        path = self.ca_dir / "ca_private.pem"
        if not path.exists():
            raise StorageError("Clave privada de la AC Raíz no encontrada.")
        key = load_private_key_encrypted(path.read_bytes(), council_password)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise StorageError("La clave privada de la AC Raíz no es de tipo ECDSA.")
        return key

    def load_crl(self) -> x509.CertificateRevocationList:
        path = self.ca_dir / "crl.pem"
        if not path.exists():
            raise StorageError("Lista de Certificados Revocados (CRL) no encontrada.")
        return load_crl(path.read_bytes())

    def save_crl(self, crl: x509.CertificateRevocationList) -> None:
        _write_secure_bytes(self.ca_dir / "crl.pem", serialize_crl(crl))

    # ------------------------------------------------------------------
    # Usuarios (Jedis), claves privadas cifradas y certificados X.509
    # ------------------------------------------------------------------

    def _user_dir(self, username: str) -> Path:
        return self.users_dir / normalize_username(username)

    def user_exists(self, username: str) -> bool:
        return (self._user_dir(username) / "profile.json").exists()

    def list_users(self) -> list[str]:
        if not self.users_dir.exists():
            return []
        return sorted(
            d.name for d in self.users_dir.iterdir()
            if d.is_dir() and (d / "profile.json").exists()
        )

    def save_user(
        self,
        username: str,
        rank: str,
        password_record: dict[str, Any],
        enc_private_key: rsa.RSAPrivateKey,
        enc_cert: x509.Certificate,
        sig_private_key: ec.EllipticCurvePrivateKey,
        sig_cert: x509.Certificate,
        user_password: str,
    ) -> None:
        """Almacena perfil, certificados y claves privadas cifradas (PKCS#8) de un nuevo Jedi."""
        clean_user = normalize_username(username)
        u_dir = self._user_dir(clean_user)
        if (u_dir / "profile.json").exists():
            raise StorageError(f"El Jedi '{clean_user}' ya está registrado.")

        profile = {
            "username": clean_user,
            "rank": rank.strip(),
            "password_record": password_record,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "revoked": False,
        }
        _write_json(u_dir / "profile.json", profile)

        enc_priv_pem = serialize_private_key_encrypted(enc_private_key, user_password)
        sig_priv_pem = serialize_private_key_encrypted(sig_private_key, user_password)

        _write_secure_bytes(u_dir / "enc_private.pem", enc_priv_pem, restricted=True)
        _write_secure_bytes(u_dir / "sig_private.pem", sig_priv_pem, restricted=True)
        _write_secure_bytes(u_dir / "enc_cert.pem", serialize_certificate(enc_cert))
        _write_secure_bytes(u_dir / "sig_cert.pem", serialize_certificate(sig_cert))

    def load_user_profile(self, username: str) -> dict[str, Any]:
        return _read_json(self._user_dir(username) / "profile.json")

    def update_user_profile(self, username: str, profile: dict[str, Any]) -> None:
        _write_json(self._user_dir(username) / "profile.json", profile)

    def load_user_certificates(self, username: str) -> tuple[x509.Certificate, x509.Certificate]:
        """Devuelve (certificado_cifrado_RSA, certificado_firma_ECDSA) del usuario."""
        u_dir = self._user_dir(username)
        enc_path = u_dir / "enc_cert.pem"
        sig_path = u_dir / "sig_cert.pem"
        if not enc_path.exists() or not sig_path.exists():
            raise StorageError(f"Certificados no encontrados para el Jedi '{username}'.")
        return load_certificate(enc_path.read_bytes()), load_certificate(sig_path.read_bytes())

    def load_user_private_keys(
        self,
        username: str,
        user_password: str,
    ) -> tuple[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        """Descifra y devuelve (clave_privada_RSA, clave_privada_ECDSA) del usuario."""
        u_dir = self._user_dir(username)
        enc_path = u_dir / "enc_private.pem"
        sig_path = u_dir / "sig_private.pem"
        if not enc_path.exists() or not sig_path.exists():
            raise StorageError(f"Claves privadas no encontradas para el Jedi '{username}'.")

        enc_key = load_private_key_encrypted(enc_path.read_bytes(), user_password)
        sig_key = load_private_key_encrypted(sig_path.read_bytes(), user_password)
        if not isinstance(enc_key, rsa.RSAPrivateKey) or not isinstance(
            sig_key, ec.EllipticCurvePrivateKey
        ):
            raise StorageError("Tipos de claves privadas inconsistentes para el usuario.")
        return enc_key, sig_key

    # ------------------------------------------------------------------
    # Mensajes cifrados y control anti-repetición (replay)
    # ------------------------------------------------------------------

    def save_message(self, message_package: dict[str, Any]) -> Path:
        msg_id = validate_message_id(message_package.get("message_id", ""))
        path = self.messages_dir / f"{msg_id}.json"
        _write_json(path, message_package)
        return path

    def load_message(self, message_id: str) -> dict[str, Any]:
        clean_id = validate_message_id(message_id)
        return _read_json(self.messages_dir / f"{clean_id}.json")

    def list_messages_for_user(self, username: str) -> list[dict[str, Any]]:
        """Lista todos los paquetes de transmisión dirigidos a 'username' ordenados por fecha."""
        clean_user = normalize_username(username)
        if not self.messages_dir.exists():
            return []

        inbox: list[dict[str, Any]] = []
        for file_path in sorted(self.messages_dir.glob("*.json")):
            try:
                pkg = _read_json(file_path)
            except StorageError:
                continue
            if pkg.get("recipient") == clean_user:
                inbox.append(pkg)

        inbox.sort(key=lambda m: (m.get("timestamp", ""), m.get("sequence_number", 0)))
        return inbox

    def _load_replay_state(self) -> dict[str, Any]:
        if not self.replay_state_path.exists():
            return {"next_send_seq": {}, "last_received_seq": {}, "seen_message_ids": []}
        return _read_json(self.replay_state_path)

    def get_next_send_sequence(self, sender: str, recipient: str) -> int:
        """Asigna y persiste el siguiente número de secuencia monotónico para un canal (emisor->receptor)."""
        state = self._load_replay_state()
        channel = f"{normalize_username(sender)}->{normalize_username(recipient)}"
        seq = int(state["next_send_seq"].get(channel, 0)) + 1
        state["next_send_seq"][channel] = seq
        _write_json(self.replay_state_path, state)
        return seq

    def check_replay(self, sender: str, recipient: str, seq: int, message_id: str) -> bool:
        """
        Devuelve True si el mensaje corresponde a un intento de repetición (replay):
        - Su message_id ya fue procesado anteriormente, o
        - Su número de secuencia es menor o igual al último ya aceptado para ese emisor->receptor.
        """
        state = self._load_replay_state()
        channel = f"{normalize_username(sender)}->{normalize_username(recipient)}"
        last_seq = int(state["last_received_seq"].get(channel, 0))
        seen_ids = set(state.get("seen_message_ids", []))
        return message_id in seen_ids or seq <= last_seq

    def record_received_message(
        self,
        sender: str,
        recipient: str,
        seq: int,
        message_id: str,
    ) -> None:
        """Registra un mensaje verificado para impedir que vuelva a aceptarse en el futuro."""
        state = self._load_replay_state()
        channel = f"{normalize_username(sender)}->{normalize_username(recipient)}"
        current_last = int(state["last_received_seq"].get(channel, 0))
        if seq > current_last:
            state["last_received_seq"][channel] = seq
        if message_id not in state["seen_message_ids"]:
            state["seen_message_ids"].append(message_id)
        _write_json(self.replay_state_path, state)

    # ------------------------------------------------------------------
    # Registro de auditoría protegido con HMAC-SHA256
    # ------------------------------------------------------------------

    def derive_audit_hmac_key(self, council_password: str) -> bytes:
        """Deriva en memoria la clave HMAC-SHA256 de 256 bits a partir de la contraseña del Consejo."""
        log_data = _read_json(self.audit_log_path)
        try:
            salt = base64.b64decode(log_data["kdf_salt"], validate=True)
        except (KeyError, ValueError) as exc:
            raise IntegrityVerificationError("Metadatos de sal del log de auditoría corruptos.") from exc
        return derive_key_from_password(council_password, salt, key_bytes=HMAC_KEY_BYTES)

    def append_audit_event(
        self,
        hmac_key: bytes,
        event: str,
        actor: str,
        details: str,
    ) -> dict[str, Any]:
        """
        Añade una entrada en texto claro al log de auditoría y la autentica con HMAC-SHA256.
        Cada entrada encadena el HMAC anterior ('prev_hmac') para detectar borrados o reordenaciones.
        """
        log_data = _read_json(self.audit_log_path)
        entries: list[dict[str, Any]] = log_data.get("entries", [])

        seq = len(entries) + 1
        prev_hmac = entries[-1]["hmac"] if entries else "GENESIS"

        payload = {
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "details": details,
            "prev_hmac": prev_hmac,
        }
        mac_b64 = compute_hmac_sha256(hmac_key, _canonical_json_bytes(payload))
        entry = {**payload, "hmac": mac_b64}

        entries.append(entry)
        log_data["entries"] = entries
        _write_json(self.audit_log_path, log_data)
        return entry

    def verify_audit_log(self, hmac_key: bytes) -> list[dict[str, Any]]:
        """
        Verifica la integridad y autenticidad detodo el registro de
        auditoría del Templo.
        Lanza IntegrityVerificationError si cualquier entrada, secuencia o HMAC fue alterado.
        """
        log_data = _read_json(self.audit_log_path)
        if log_data.get("algorithm") != HMAC_ALGORITHM:
            raise IntegrityVerificationError("Algoritmo de auditoría HMAC no reconocido.")

        entries = log_data.get("entries")
        if not isinstance(entries, list):
            raise IntegrityVerificationError("Estructura del log de auditoría corrupta.")

        expected_prev_hmac = "GENESIS"
        for expected_seq, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                raise IntegrityVerificationError(f"Entrada #{expected_seq} del log corrupta.")
            if entry.get("seq") != expected_seq:
                raise IntegrityVerificationError(
                    f"Ruptura de secuencia en el log de auditoría (esperada #{expected_seq})."
                )
            if entry.get("prev_hmac") != expected_prev_hmac:
                raise IntegrityVerificationError(
                    f"Cadena HMAC rota en la entrada #{expected_seq}: posible borrado o alteración."
                )

            entry_hmac = entry.get("hmac")
            if not isinstance(entry_hmac, str):
                raise IntegrityVerificationError(f"Falta etiqueta HMAC en la entrada #{expected_seq}.")

            payload = {
                "seq": entry["seq"],
                "timestamp": entry["timestamp"],
                "event": entry["event"],
                "actor": entry["actor"],
                "details": entry["details"],
                "prev_hmac": entry["prev_hmac"],
            }
            verify_hmac_sha256(hmac_key, _canonical_json_bytes(payload), entry_hmac)
            expected_prev_hmac = entry_hmac

        return entries
