"""
Cryptographic primitives for the YubiHashKeyChain vault:
- AES-256-GCM payload and key encryption
- 256-bit XOR for Half_A ^ Half_B = KEK
- ECDH + HKDF-SHA256 + AES-GCM for wrapping Half_B to ECC P-256 Slot 9d
- ECDSA SHA-256 signing and verification for Slot 9c
- X.509 certificate parsing and key usage inspection
"""

from __future__ import annotations
import base64
import os
from typing import Any, Dict, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Computes bitwise XOR between two byte sequences of equal length.
    Ensures both inputs are non-empty and matched in length.
    """
    if len(a) != len(b):
        raise ValueError(f"Lengths must match for XOR: got {len(a)} and {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


# --- AES-256-GCM ---

def encrypt_aes_gcm(
    key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext with AES-256-GCM.
    Returns (iv, ciphertext, tag).
    AESGCM in cryptography appends the 16-byte tag to the ciphertext.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return iv, ciphertext, tag


def decrypt_aes_gcm(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext given iv, ciphertext, and 16-byte tag.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(iv, ct_with_tag, associated_data)


def encrypt_aes_gcm_packed(
    key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None
) -> bytes:
    """
    Encrypts plaintext and returns packed format: IV (12B) + TAG (16B) + CIPHERTEXT.
    """
    iv, ct, tag = encrypt_aes_gcm(key, plaintext, associated_data)
    return iv + tag + ct


def decrypt_aes_gcm_packed(
    key: bytes, packed_data: bytes, associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypts packed format: IV (12B) + TAG (16B) + CIPHERTEXT.
    """
    if len(packed_data) < 28:
        raise ValueError("Packed data too short for IV and TAG")
    iv = packed_data[:12]
    tag = packed_data[12:28]
    ciphertext = packed_data[28:]
    return decrypt_aes_gcm(key, iv, ciphertext, tag, associated_data)


# --- ECDH + HKDF Half_B Wrapping ---

WRAP_INFO_HALF_B = b"YubiHash-HalfB-Wrap"


def wrap_half_b_ecc(
    recipient_public_key: ec.EllipticCurvePublicKey,
    half_b: bytes,
) -> Dict[str, str]:
    """
    Wraps 32-byte Half_B for recipient's Slot 9d public key using ECIES:
    1. Generates ephemeral EC P-256 keypair.
    2. ECDH shared secret Z.
    3. HKDF-SHA256 -> wrapping key.
    4. AES-256-GCM encrypts Half_B.
    Returns dictionary with base64-encoded fields suitable for JSON.
    """
    if len(half_b) != 32:
        raise ValueError("Half_B must be exactly 32 bytes")

    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)

    salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=WRAP_INFO_HALF_B,
    )
    wrapping_key = hkdf.derive(shared_secret)

    iv, ct, tag = encrypt_aes_gcm(wrapping_key, half_b)

    eph_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "alg": "ECDH-HKDF-AES256GCM",
        "ephemeral_pubkey": base64.b64encode(eph_bytes).decode("ascii"),
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def derive_wrap_key_from_shared_secret(shared_secret: bytes, salt: bytes) -> bytes:
    """Derives AES-256 key from ECDH shared secret and salt."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=WRAP_INFO_HALF_B,
    )
    return hkdf.derive(shared_secret)


def unwrap_half_b_ecc(
    recipient_private_key: ec.EllipticCurvePrivateKey,
    wrapped_data: Dict[str, str],
) -> bytes:
    """
    Unwraps Half_B using recipient's private key.
    """
    eph_der = base64.b64decode(wrapped_data["ephemeral_pubkey"])
    ephemeral_public = serialization.load_der_public_key(eph_der)
    if not isinstance(ephemeral_public, ec.EllipticCurvePublicKey):
        raise TypeError("Ephemeral key is not an EllipticCurvePublicKey")

    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)
    salt = base64.b64decode(wrapped_data["salt"])
    iv = base64.b64decode(wrapped_data["iv"])
    ciphertext = base64.b64decode(wrapped_data["ciphertext"])
    tag = base64.b64decode(wrapped_data["tag"])

    wrapping_key = derive_wrap_key_from_shared_secret(shared_secret, salt)
    return decrypt_aes_gcm(wrapping_key, iv, ciphertext, tag)


# --- ECDSA Signing & Verification ---

def sign_ecdsa_sha256(
    private_key: ec.EllipticCurvePrivateKey, data: bytes
) -> bytes:
    """Signs data with ECDSA SHA-256 and returns DER signature."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa_sha256(
    public_key: ec.EllipticCurvePublicKey, signature: bytes, data: bytes
) -> bool:
    """Verifies DER ECDSA SHA-256 signature against data. Returns True if valid."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# --- X.509 Certificate Helpers ---

def load_der_certificate(der_bytes: bytes) -> x509.Certificate:
    """Loads X.509 certificate from DER bytes."""
    return x509.load_der_x509_certificate(der_bytes)


def cert_sha256_fingerprint(cert: x509.Certificate) -> str:
    """Returns SHA-256 fingerprint in lowercase hex."""
    return cert.fingerprint(hashes.SHA256()).hex().lower()


def get_cert_key_usage(cert: x509.Certificate) -> Optional[x509.KeyUsage]:
    """Retrieves KeyUsage extension if present."""
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        return ext.value
    except x509.ExtensionNotFound:
        return None


def is_signing_certificate(cert: x509.Certificate) -> bool:
    """Checks if certificate is designated for digital signatures (Slot 9c)."""
    ku = get_cert_key_usage(cert)
    if ku is None:
        return True  # If no KU extension is present, allow by default
    return bool(ku.digital_signature)


def is_decryption_certificate(cert: x509.Certificate) -> bool:
    """Checks if certificate is designated for key encipherment or agreement (Slot 9d)."""
    ku = get_cert_key_usage(cert)
    if ku is None:
        return True
    return bool(ku.key_encipherment or ku.key_agreement)
