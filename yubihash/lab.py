"""
Lab Environment: test the vault without Active Directory.

A lab is a folder that simulates everything the vault normally gets from a
Windows domain, so the *real* VaultOrchestrator, ledger, and crypto code can be
exercised on a standalone (non domain-joined) machine:

    <lab_dir>/
    ├── lab.json                 # Lab config + per-user YubiKey bindings
    ├── directory.json           # Simulated AD: users, groups, userCertificate
    ├── kds_root.key             # Simulated DC KDS Root Key (DPAPI-NG / Half_A)
    ├── attestation_ca.key.pem   # Lab stand-in for the Yubico PIV Root CA
    ├── attestation_ca.cert.pem
    ├── session.json             # Currently "signed-in" lab user
    └── yubikeys/<user>.json     # Software YubiKeys (PIN-encrypted)

Each lab user is bound to either a persistent software YubiKey or a real
physical YubiKey (selected by serial number).

WARNING: Lab key material is stored on disk for testing only. Never use a lab
environment to protect real secrets.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from yubihash.backends.base import YubiKeyBackend
from yubihash.backends.local.local_directory import LocalDirectory
from yubihash.backends.local.local_kds import LocalKdsDpapiNg
from yubihash.backends.local.software_yubikey import DEFAULT_PIV_PIN, SoftwareYubiKey
from yubihash.ledger.storage import VaultStorage
from yubihash.vault import VaultOrchestrator

LAB_FORMAT = "yubihash-lab/1"
FIRST_SOFTWARE_SERIAL = 20000001

LAB_CONFIG_FILE = "lab.json"
DIRECTORY_FILE = "directory.json"
KDS_ROOT_KEY_FILE = "kds_root.key"
CA_KEY_FILE = "attestation_ca.key.pem"
CA_CERT_FILE = "attestation_ca.cert.pem"
SESSION_FILE = "session.json"
YUBIKEYS_DIR = "yubikeys"


class LabError(Exception):
    """Raised for lab environment configuration or usage errors."""


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def _create_attestation_ca() -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YubiHash Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "YubiHash Lab PIV Attestation Root CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


class LabEnvironment:
    """
    Manages a lab folder and builds vault orchestrators backed by local services.
    """

    def __init__(self, lab_dir: Union[str, Path]):
        self.lab_dir = Path(lab_dir)
        self.config_path = self.lab_dir / LAB_CONFIG_FILE
        if not self.config_path.exists():
            raise LabError(
                f"No lab environment found at '{self.lab_dir}'. "
                f"Create one with: yubihash lab init --lab-dir \"{self.lab_dir}\""
            )
        self.directory = LocalDirectory(self.lab_dir / DIRECTORY_FILE)

    # ------------------------------------------------------------------ #
    # Creation & config
    # ------------------------------------------------------------------ #

    @classmethod
    def create(
        cls,
        lab_dir: Union[str, Path],
        domain: str = "lab.local",
        verify_attestation: bool = True,
    ) -> "LabEnvironment":
        lab_path = Path(lab_dir)
        if (lab_path / LAB_CONFIG_FILE).exists():
            raise LabError(f"A lab environment already exists at '{lab_path}'")
        lab_path.mkdir(parents=True, exist_ok=True)
        (lab_path / YUBIKEYS_DIR).mkdir(exist_ok=True)

        LocalDirectory.create(lab_path / DIRECTORY_FILE, domain=domain)
        LocalKdsDpapiNg.create_root_key(lab_path / KDS_ROOT_KEY_FILE)

        ca_key, ca_cert = _create_attestation_ca()
        (lab_path / CA_KEY_FILE).write_bytes(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        (lab_path / CA_CERT_FILE).write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        _atomic_write_json(lab_path / LAB_CONFIG_FILE, {
            "format": LAB_FORMAT,
            "verify_attestation": verify_attestation,
            "next_software_serial": FIRST_SOFTWARE_SERIAL,
            "yubikeys": {},
        })
        return cls(lab_path)

    def _load_config(self) -> Dict[str, Any]:
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("format") != LAB_FORMAT:
            raise LabError(f"Unsupported lab config format: {data.get('format')!r}")
        return data

    def _save_config(self, data: Dict[str, Any]) -> None:
        _atomic_write_json(self.config_path, data)

    @property
    def verify_attestation(self) -> bool:
        return bool(self._load_config()["verify_attestation"])

    def attestation_ca(self) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        key = serialization.load_pem_private_key((self.lab_dir / CA_KEY_FILE).read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise LabError("Lab attestation CA key must be an EC key")
        cert = x509.load_pem_x509_certificate((self.lab_dir / CA_CERT_FILE).read_bytes())
        return key, cert

    @property
    def root_ca_cert(self) -> Optional[x509.Certificate]:
        """Attestation trust anchor handed to the orchestrator (None disables checks)."""
        return self.attestation_ca()[1] if self.verify_attestation else None

    # ------------------------------------------------------------------ #
    # Directory administration
    # ------------------------------------------------------------------ #

    def add_group(self, name: str) -> str:
        return self.directory.create_group(name)

    def add_user(
        self,
        name: str,
        groups: Optional[List[str]] = None,
        display_name: Optional[str] = None,
        pin: str = DEFAULT_PIV_PIN,
        hardware: bool = False,
        hardware_serial: Optional[int] = None,
    ) -> str:
        """
        Creates a lab user, binds a YubiKey (software or physical), publishes the
        Slot 9c / 9d / attestation certificates to the directory ("onboarding"),
        and adds the user to the requested groups.
        """
        group_sids = [self.directory.resolve_group(g) for g in (groups or [])]
        config = self._load_config()
        user_sid = self.directory.create_user(name, display_name=display_name)
        created_key_file: Optional[Path] = None

        try:
            if hardware:
                yubikey = self._open_hardware_yubikey(hardware_serial)
                binding = {"type": "hardware", "serial": yubikey.get_serial()}
            else:
                serial = int(config["next_software_serial"])
                config["next_software_serial"] = serial + 1
                ca_key, ca_cert = self.attestation_ca()
                rel_path = f"{YUBIKEYS_DIR}/{name.lower()}.json"
                yubikey = SoftwareYubiKey.provision(
                    self.lab_dir / rel_path,
                    serial=serial,
                    user_name=display_name or name,
                    attestation_ca_key=ca_key,
                    attestation_ca_cert=ca_cert,
                    pin=pin,
                )
                created_key_file = self.lab_dir / rel_path
                binding = {"type": "software", "serial": serial, "file": rel_path}

            config["yubikeys"][user_sid] = binding
            self._save_config(config)
            self.publish_certificates(user_sid, yubikey)
        except Exception:
            # Roll back everything created for this half-onboarded user
            self.directory.delete_user(user_sid)
            cfg = self._load_config()
            if cfg["yubikeys"].pop(user_sid, None) is not None:
                self._save_config(cfg)
            if created_key_file is not None and created_key_file.exists():
                created_key_file.unlink()
            raise

        for g_sid in group_sids:
            self.directory.add_user_to_group(user_sid, g_sid)
        return user_sid

    def publish_certificates(self, user_sid: str, yubikey: Optional[YubiKeyBackend] = None) -> None:
        """Re-publishes a user's YubiKey certificates to the directory (``yubihash onboard``)."""
        yubikey = yubikey or self.yubikey_for(user_sid)
        self.directory.clear_user_certificates(user_sid)
        certs = [yubikey.get_signing_certificate(), yubikey.get_decryption_certificate()]
        try:
            certs.append(yubikey.get_attestation_certificate("9d"))
        except Exception:
            pass
        for cert in certs:
            self.directory.publish_user_certificate(user_sid, cert.public_bytes(serialization.Encoding.DER))

    def join_group(self, user_ref: str, group_ref: str) -> bool:
        return self.directory.add_user_to_group(
            self.directory.resolve_user(user_ref), self.directory.resolve_group(group_ref)
        )

    def leave_group(self, user_ref: str, group_ref: str) -> bool:
        return self.directory.remove_user_from_group(
            self.directory.resolve_user(user_ref), self.directory.resolve_group(group_ref)
        )

    def yubikey_binding(self, user_sid: str) -> Optional[Dict[str, Any]]:
        return self._load_config()["yubikeys"].get(user_sid)

    # ------------------------------------------------------------------ #
    # Session ("who is signed in to Windows")
    # ------------------------------------------------------------------ #

    def login(self, user_ref: str) -> str:
        user_sid = self.directory.resolve_user(user_ref)
        _atomic_write_json(self.lab_dir / SESSION_FILE, {"user_sid": user_sid})
        return user_sid

    def logout(self) -> None:
        session = self.lab_dir / SESSION_FILE
        if session.exists():
            session.unlink()

    def current_user_sid(self) -> Optional[str]:
        session = self.lab_dir / SESSION_FILE
        if not session.exists():
            return None
        with open(session, "r", encoding="utf-8") as f:
            return json.load(f).get("user_sid")

    def resolve_acting_user(self, user_ref: Optional[str]) -> str:
        """Explicit ``--user`` wins, otherwise the signed-in lab session user."""
        if user_ref:
            return self.directory.resolve_user(user_ref)
        sid = self.current_user_sid()
        if not sid:
            raise LabError("No lab user signed in. Run 'yubihash lab login <user>' or pass --user-sid.")
        return sid

    # ------------------------------------------------------------------ #
    # Backend factories
    # ------------------------------------------------------------------ #

    @staticmethod
    def _open_hardware_yubikey(serial: Optional[int]) -> YubiKeyBackend:
        # Imported lazily so software-only labs never touch PC/SC.
        from yubihash.backends.live.yubikey import LiveYubiKey
        return LiveYubiKey(serial=serial)

    def yubikey_for(self, user_sid: str, default_pin: Optional[str] = None) -> YubiKeyBackend:
        binding = self.yubikey_binding(user_sid)
        if binding is None:
            raise LabError(f"Lab user '{user_sid}' has no YubiKey bound")
        if binding["type"] == "hardware":
            return self._open_hardware_yubikey(binding.get("serial"))
        return SoftwareYubiKey(self.lab_dir / binding["file"], default_pin=default_pin)

    def dpapi_for(self, user_sid: str) -> LocalKdsDpapiNg:
        return LocalKdsDpapiNg(self.lab_dir / KDS_ROOT_KEY_FILE, self.directory, current_user_sid=user_sid)

    def orchestrator(self, vault_dir: Union[str, Path], user_sid: str) -> VaultOrchestrator:
        """Builds the production VaultOrchestrator wired to lab backends for ``user_sid``."""
        return VaultOrchestrator(
            storage=VaultStorage(vault_dir),
            yubikey=self.yubikey_for(user_sid),
            dpapi_ng=self.dpapi_for(user_sid),
            directory=self.directory,
            root_ca_cert=self.root_ca_cert,
        )
