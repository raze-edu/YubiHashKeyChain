"""
Core cryptographic, memory hygiene, attestation, and permission primitives.
"""

from yubihash.core.canonical_json import canonicalize_json, hash_canonical_json
from yubihash.core.crypto import (
    cert_sha256_fingerprint,
    decrypt_aes_gcm,
    decrypt_aes_gcm_packed,
    encrypt_aes_gcm,
    encrypt_aes_gcm_packed,
    is_decryption_certificate,
    is_signing_certificate,
    load_der_certificate,
    unwrap_half_b_ecc,
    wrap_half_b_ecc,
    xor_bytes,
)
from yubihash.core.memory import SecureBuffer, secure_zero, zero_bytearray
from yubihash.core.permissions import (
    CREATOR_PERMISSIONS,
    DEFAULT_MEMBER_PERMISSIONS,
    VaultPermission,
    can_delegate_permissions,
    has_permission,
    normalize_permissions,
)

__all__ = [
    "canonicalize_json",
    "hash_canonical_json",
    "cert_sha256_fingerprint",
    "decrypt_aes_gcm",
    "decrypt_aes_gcm_packed",
    "encrypt_aes_gcm",
    "encrypt_aes_gcm_packed",
    "is_decryption_certificate",
    "is_signing_certificate",
    "load_der_certificate",
    "unwrap_half_b_ecc",
    "wrap_half_b_ecc",
    "xor_bytes",
    "SecureBuffer",
    "secure_zero",
    "zero_bytearray",
    "CREATOR_PERMISSIONS",
    "DEFAULT_MEMBER_PERMISSIONS",
    "VaultPermission",
    "can_delegate_permissions",
    "has_permission",
    "normalize_permissions",
]
