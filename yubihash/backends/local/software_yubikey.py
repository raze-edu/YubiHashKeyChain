"""
Persistent Software YubiKey (PIV emulation).

A file-backed YubiKey replacement for lab testing without hardware:

- Slot 9c (Digital Signature) and Slot 9d (Key Management) ECC P-256 keypairs.
- Slot certificates with the same KeyUsage layout as the real onboarding flow.
- A Slot 9d attestation certificate signed by the *lab* attestation CA
  (carrying the Yubico serial / PIN-policy / touch-policy OIDs).

Private keys are stored PKCS#8-encrypted with the PIV PIN, so a wrong PIN
fails exactly where a real YubiKey would refuse to sign or decrypt.
Touch policy and PIN retry counters are not simulated.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yubihash.backends.base import YubiKeyBackend
from yubihash.backends.mock.mock_yubikey import MockYubiKey
from yubihash.core.crypto import sign_ecdsa_sha256, unwrap_half_b_ecc

SOFTWARE_YUBIKEY_FORMAT = "yubihash-software-yubikey/1"
DEFAULT_PIV_PIN = "123456"  # Factory default PIN of a real YubiKey PIV applet


class IncorrectPinError(PermissionError):
    """Raised when the supplied PIN cannot unlock the software YubiKey."""


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: ec.EllipticCurvePrivateKey, pin: str) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pin.encode("utf-8")),
    ).decode("ascii")


class SoftwareYubiKey(YubiKeyBackend):
    """
    YubiKeyBackend whose PIV slots are persisted to a JSON file.
    """

    def __init__(self, key_file: Union[str, Path], default_pin: Optional[str] = None):
        self.path = Path(key_file)
        self.default_pin = default_pin or DEFAULT_PIV_PIN
        if not self.path.exists():
            raise FileNotFoundError(f"Software YubiKey file not found: {self.path}")
        with open(self.path, "r", encoding="utf-8") as f:
            self._data: Dict[str, object] = json.load(f)
        if self._data.get("format") != SOFTWARE_YUBIKEY_FORMAT:
            raise ValueError(f"Unsupported software YubiKey format: {self._data.get('format')!r}")

        self._cert_9c = x509.load_pem_x509_certificate(self._data["slot_9c"]["certificate"].encode("ascii"))
        self._cert_9d = x509.load_pem_x509_certificate(self._data["slot_9d"]["certificate"].encode("ascii"))
        attest = self._data.get("attestation_9d")
        self._attest_9d = x509.load_pem_x509_certificate(attest.encode("ascii")) if attest else None

    @classmethod
    def provision(
        cls,
        key_file: Union[str, Path],
        serial: int,
        user_name: str,
        attestation_ca_key: ec.EllipticCurvePrivateKey,
        attestation_ca_cert: x509.Certificate,
        pin: str = DEFAULT_PIV_PIN,
    ) -> "SoftwareYubiKey":
        """
        Generates fresh Slot 9c / 9d keys plus an attestation cert signed by the
        lab attestation CA, and writes them to ``key_file``.
        """
        if not pin or not (6 <= len(pin) <= 8):
            raise ValueError("PIV PIN must be 6-8 characters")

        path = Path(key_file)
        if path.exists():
            raise FileExistsError(f"Software YubiKey already exists: {path}")

        # MockYubiKey already implements authentic key / cert / attestation generation.
        generated = MockYubiKey(
            serial=serial,
            user_name=user_name,
            root_ca_priv=attestation_ca_key,
            root_ca_cert=attestation_ca_cert,
        )

        data = {
            "format": SOFTWARE_YUBIKEY_FORMAT,
            "serial": serial,
            "user_name": user_name,
            "slot_9c": {
                "private_key": _key_pem(generated.priv_9c, pin),
                "certificate": _cert_pem(generated.cert_9c),
            },
            "slot_9d": {
                "private_key": _key_pem(generated.priv_9d, pin),
                "certificate": _cert_pem(generated.cert_9d),
            },
            "attestation_9d": _cert_pem(generated.attest_9d),
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        return cls(path, default_pin=pin)

    def _unlock(self, slot: str, pin: Optional[str]) -> ec.EllipticCurvePrivateKey:
        effective_pin = pin or self.default_pin
        pem = self._data[f"slot_{slot}"]["private_key"].encode("ascii")
        try:
            key = serialization.load_pem_private_key(pem, password=effective_pin.encode("utf-8"))
        except (ValueError, TypeError):
            hint = "" if pin else " (no PIN supplied; tried the default PIN - pass --pin)"
            raise IncorrectPinError(f"Software YubiKey {self.get_serial()}: incorrect PIV PIN{hint}")
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(f"Slot {slot} does not hold an EC private key")
        return key

    # ------------------------------------------------------------------ #
    # YubiKeyBackend interface
    # ------------------------------------------------------------------ #

    def get_serial(self) -> int:
        return int(self._data["serial"])

    def get_signing_certificate(self) -> x509.Certificate:
        return self._cert_9c

    def get_decryption_certificate(self) -> x509.Certificate:
        return self._cert_9d

    def get_attestation_certificate(self, slot: str = "9d") -> x509.Certificate:
        if slot.lower() != "9d" or self._attest_9d is None:
            raise ValueError(f"Attestation certificate for slot {slot} not available on software YubiKey")
        return self._attest_9d

    def sign_block(self, block_canonical_bytes: bytes, pin: Optional[str] = None) -> bytes:
        return sign_ecdsa_sha256(self._unlock("9c", pin), block_canonical_bytes)

    def unwrap_half_b(self, wrapped_half_b: Dict[str, str], pin: Optional[str] = None) -> bytes:
        return unwrap_half_b_ecc(self._unlock("9d", pin), wrapped_half_b)
