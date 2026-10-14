"""
Live YubiKey PIV Backend using official Yubico yubikit and ykman SDKs.
Handles hardware operations for Slot 9c (Signing), Slot 9d (ECDH Decryption),
and Slot f9 (Hardware Attestation).
"""

from __future__ import annotations
import base64
from typing import Dict, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession, SLOT, KEY_TYPE

from yubihash.backends.base import YubiKeyBackend
from yubihash.core.crypto import derive_wrap_key_from_shared_secret, decrypt_aes_gcm


class LiveYubiKey(YubiKeyBackend):
    """
    Interacts directly with a physical YubiKey over PC/SC smartcard interface.
    """

    def __init__(self, serial: Optional[int] = None):
        self._target_serial = serial

    def _open_session(self) -> tuple[SmartCardConnection, PivSession]:
        devices = list_all_devices()
        if not devices:
            raise RuntimeError("No YubiKey detected. Please insert your YubiKey.")

        selected_dev = None
        for dev, info in devices:
            if self._target_serial is None or info.serial == self._target_serial:
                selected_dev = dev
                break

        if selected_dev is None:
            raise RuntimeError(f"YubiKey with serial {self._target_serial} not found.")

        connection = selected_dev.open_connection(SmartCardConnection)
        piv = PivSession(connection)
        return connection, piv

    def get_serial(self) -> int:
        conn, piv = self._open_session()
        try:
            return piv.get_serial()
        finally:
            conn.close()

    def get_signing_certificate(self) -> x509.Certificate:
        conn, piv = self._open_session()
        try:
            return piv.get_certificate(SLOT.SIGNATURE)
        finally:
            conn.close()

    def get_decryption_certificate(self) -> x509.Certificate:
        conn, piv = self._open_session()
        try:
            return piv.get_certificate(SLOT.KEY_MANAGEMENT)
        finally:
            conn.close()

    def get_attestation_certificate(self, slot: str = "9d") -> x509.Certificate:
        conn, piv = self._open_session()
        try:
            target_slot = SLOT.KEY_MANAGEMENT if slot.lower() == "9d" else SLOT.SIGNATURE
            return piv.attest_key(target_slot)
        finally:
            conn.close()

    def sign_block(self, block_canonical_bytes: bytes, pin: Optional[str] = None) -> bytes:
        """
        Prompts for PIN and touch if required by Slot 9c policy, and signs with ECDSA SHA-256.
        """
        conn, piv = self._open_session()
        try:
            if pin:
                piv.verify_pin(pin)
            cert = piv.get_certificate(SLOT.SIGNATURE)
            pubkey = cert.public_key()
            if isinstance(pubkey, ec.EllipticCurvePublicKey):
                key_type = KEY_TYPE.ECCP256
            else:
                key_type = KEY_TYPE.RSA2048

            return piv.sign(SLOT.SIGNATURE, key_type, block_canonical_bytes, hashes.SHA256())
        finally:
            conn.close()

    def unwrap_half_b(self, wrapped_half_b: Dict[str, str], pin: Optional[str] = None) -> bytes:
        """
        Extracts ephemeral public key from wrapped package, performs hardware ECDH
        in Slot 9d, derives wrapping key via HKDF, and decrypts Half_B.
        """
        eph_der = base64.b64decode(wrapped_half_b["ephemeral_pubkey"])
        ephemeral_public = serialization.load_der_public_key(eph_der)
        if not isinstance(ephemeral_public, ec.EllipticCurvePublicKey):
            raise TypeError("Ephemeral key must be an EllipticCurvePublicKey")

        salt = base64.b64decode(wrapped_half_b["salt"])
        iv = base64.b64decode(wrapped_half_b["iv"])
        ciphertext = base64.b64decode(wrapped_half_b["ciphertext"])
        tag = base64.b64decode(wrapped_half_b["tag"])

        conn, piv = self._open_session()
        try:
            if pin:
                piv.verify_pin(pin)
            # Hardware calculates ECDH shared secret inside secure element
            shared_secret = piv.calculate_secret(SLOT.KEY_MANAGEMENT, ephemeral_public)
            wrapping_key = derive_wrap_key_from_shared_secret(shared_secret, salt)
            return decrypt_aes_gcm(wrapping_key, iv, ciphertext, tag)
        finally:
            conn.close()
