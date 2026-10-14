"""
Mock / Software-simulated YubiKey PIV Backend.
Provides authentic cryptographic behavior (ECC P-256 keypairs, ECDSA signing,
ECDH Half_B unwrapping, and attestation certificate generation) without requiring
physical hardware.
"""

from __future__ import annotations
import datetime
from typing import Dict, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from yubihash.backends.base import YubiKeyBackend
from yubihash.core.attestation import (
    OID_YUBICO_SERIAL,
    OID_YUBICO_TOUCH_POLICY,
    OID_YUBICO_PIN_POLICY,
)
from yubihash.core.crypto import (
    sign_ecdsa_sha256,
    unwrap_half_b_ecc,
)


class MockYubiKey(YubiKeyBackend):
    """
    A simulated YubiKey PIV applet with Slot 9c, Slot 9d, and Slot f9 Attestation.
    """

    def __init__(
        self,
        serial: int = 12345678,
        user_name: str = "Test User",
        root_ca_priv: Optional[ec.EllipticCurvePrivateKey] = None,
        root_ca_cert: Optional[x509.Certificate] = None,
    ):
        self.serial = serial
        self.user_name = user_name

        # Generate Slot 9c (Digital Signature) ECC P-256 Keypair
        self.priv_9c = ec.generate_private_key(ec.SECP256R1())
        self.pub_9c = self.priv_9c.public_key()

        # Generate Slot 9d (Key Management) ECC P-256 Keypair
        self.priv_9d = ec.generate_private_key(ec.SECP256R1())
        self.pub_9d = self.priv_9d.public_key()

        # Mock Root CA for attestation if not provided
        if root_ca_priv is None or root_ca_cert is None:
            self._root_ca_priv = ec.generate_private_key(ec.SECP256R1())
            self._root_ca_cert = self._create_root_ca(self._root_ca_priv)
        else:
            self._root_ca_priv = root_ca_priv
            self._root_ca_cert = root_ca_cert

        # Self-signed Slot 9c cert (Key Usage: digital_signature)
        self.cert_9c = self._create_slot_cert(
            self.priv_9c,
            digital_signature=True,
            key_agreement=False,
            cn=f"{user_name} - Slot 9c",
        )

        # Self-signed Slot 9d cert (Key Usage: key_agreement / key_encipherment)
        self.cert_9d = self._create_slot_cert(
            self.priv_9d,
            digital_signature=False,
            key_agreement=True,
            cn=f"{user_name} - Slot 9d",
        )

        # Slot 9d Attestation Cert signed by Mock Root CA with Yubico OIDs
        self.attest_9d = self._create_attestation_cert(self.pub_9d, slot="9d")

    @property
    def root_ca_cert(self) -> x509.Certificate:
        return self._root_ca_cert

    def get_serial(self) -> int:
        return self.serial

    def get_signing_certificate(self) -> x509.Certificate:
        return self.cert_9c

    def get_decryption_certificate(self) -> x509.Certificate:
        return self.cert_9d

    def get_attestation_certificate(self, slot: str = "9d") -> x509.Certificate:
        if slot == "9d":
            return self.attest_9d
        raise ValueError(f"Attestation certificate for slot {slot} not configured in mock")

    def sign_block(self, block_canonical_bytes: bytes, pin: Optional[str] = None) -> bytes:
        return sign_ecdsa_sha256(self.priv_9c, block_canonical_bytes)

    def unwrap_half_b(self, wrapped_half_b: Dict[str, str], pin: Optional[str] = None) -> bytes:
        return unwrap_half_b_ecc(self.priv_9d, wrapped_half_b)

    def _create_root_ca(self, ca_priv: ec.EllipticCurvePrivateKey) -> x509.Certificate:
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yubico AB"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Mock Yubico PIV Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_priv, hashes.SHA256())
        )

    def _create_slot_cert(
        self,
        priv_key: ec.EllipticCurvePrivateKey,
        digital_signature: bool,
        key_agreement: bool,
        cn: str,
    ) -> x509.Certificate:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(priv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=digital_signature,
                    content_commitment=False,
                    key_encipherment=key_agreement,
                    data_encipherment=False,
                    key_agreement=key_agreement,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(priv_key, hashes.SHA256())
        )

    def _create_attestation_cert(
        self, target_pub: ec.EllipticCurvePublicKey, slot: str
    ) -> x509.Certificate:
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yubico AB"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"YubiKey PIV Attestation {slot.upper()}"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)

        serial_bytes = self.serial.to_bytes(4, byteorder="big")
        # touch_policy = 2 (always)
        touch_bytes = bytes([2])
        pin_bytes = bytes([2])

        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_ca_cert.subject)
            .public_key(target_pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.UnrecognizedExtension(OID_YUBICO_SERIAL, serial_bytes), critical=False)
            .add_extension(x509.UnrecognizedExtension(OID_YUBICO_TOUCH_POLICY, touch_bytes), critical=False)
            .add_extension(x509.UnrecognizedExtension(OID_YUBICO_PIN_POLICY, pin_bytes), critical=False)
            .sign(self._root_ca_priv, hashes.SHA256())
        )
