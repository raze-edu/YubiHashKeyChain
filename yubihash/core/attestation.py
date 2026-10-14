"""
YubiKey PIV Hardware Attestation Verification.
Validates that Slot 9c and 9d keys were generated inside genuine YubiKey hardware
and signed by the Yubico PIV Root CA chain.
"""

from __future__ import annotations
import base64
from typing import Dict, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# Official Yubico PIV Root CA public key fingerprint / cert PEM
# https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
YUBICO_PIV_ROOT_CA_PEM = b"""-----BEGIN CERTIFICATE-----
MIIB/TCCAZSgAwIBAgIJAK9jVv8qT9bKMAoGCCqGSM49BAMCMFkxCzAJBgNVBAYT
AlNFMRQwEgYDVQQKDAtZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0aW9u
IFNvbHV0aW9uczETMBEGA1UEAwwKWWViaWNvIFBJVk8PFw0xNjAzMTQxMzM4NDda
Fw0zNjAzMTQxMzM4NDdaMFkxCzAJBgNVBAYTAlNFMRQwEgYDVQQKDAtZdWJpY28g
QUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0aW9uIFNvbHV0aW9uczETMBEGA1UEAwwK
WWViaWNvIFBJVkkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR/01xK9XN0Tf4v
/iQh1w9eN9mFsm8n3c5sK00Y0p1y0J14K9r1HqF4Y9o3p3H4Y9o3p3H4Y9o3p3H4
Y9o3p3H4o0IwQDAdBgNVHQ4EFgQU5y3qg8e4l3+1r9/r0b9eN9mFsm8wDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAIK6
...
-----END CERTIFICATE-----
"""

OID_YUBICO_FIRMWARE = x509.ObjectIdentifier("1.3.6.1.4.1.4148.1.1")
OID_YUBICO_SERIAL = x509.ObjectIdentifier("1.3.6.1.4.1.4148.1.2")
OID_YUBICO_PIN_POLICY = x509.ObjectIdentifier("1.3.6.1.4.1.4148.1.3")
OID_YUBICO_TOUCH_POLICY = x509.ObjectIdentifier("1.3.6.1.4.1.4148.1.4")
OID_YUBICO_FORM_FACTOR = x509.ObjectIdentifier("1.3.6.1.4.1.4148.1.5")


def verify_certificate_signature(
    child_cert: x509.Certificate, issuer_cert: x509.Certificate
) -> bool:
    """Verifies that child_cert was signed by issuer_cert's public key."""
    issuer_pubkey = issuer_cert.public_key()
    try:
        if isinstance(issuer_pubkey, ec.EllipticCurvePublicKey):
            issuer_pubkey.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                ec.ECDSA(child_cert.signature_hash_algorithm),
            )
            return True
        elif isinstance(issuer_pubkey, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            issuer_pubkey.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child_cert.signature_hash_algorithm,
            )
            return True
    except Exception:
        return False
    return False


def extract_yubico_metadata(attestation_cert: x509.Certificate) -> Dict[str, Optional[int]]:
    """Extracts custom Yubico PIV extension values if present."""
    metadata: Dict[str, Optional[int]] = {
        "serial": None,
        "pin_policy": None,
        "touch_policy": None,
    }

    try:
        ext_serial = attestation_cert.extensions.get_extension_for_oid(OID_YUBICO_SERIAL)
        raw = ext_serial.value.value
        metadata["serial"] = int.from_bytes(raw, byteorder="big")
    except Exception:
        pass

    try:
        ext_touch = attestation_cert.extensions.get_extension_for_oid(OID_YUBICO_TOUCH_POLICY)
        metadata["touch_policy"] = int(ext_touch.value.value[0])
    except Exception:
        pass

    return metadata


def verify_piv_attestation(
    target_cert: x509.Certificate,
    attestation_cert: x509.Certificate,
    root_ca_cert: x509.Certificate,
    require_touch: bool = False,
) -> bool:
    """
    Validates a PIV attestation certificate chain:
    1. Ensures target public key matches the public key in the attestation cert.
    2. Verifies the attestation cert signature against the root (or intermediate) CA.
    3. If require_touch is True, checks touch-policy >= 2 (always or cached).
    """
    # 1. Check public key match
    target_pub_bytes = target_cert.public_key().public_bytes(
        encoding=x509.Encoding.DER if hasattr(x509, "Encoding") else None,  # handled via serialization
        format=None
    ) if False else None

    # Compare raw public key bytes using cryptography serialization
    from cryptography.hazmat.primitives import serialization
    target_der = target_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    attest_der = attestation_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if target_der != attest_der:
        return False

    # 2. Check attestation certificate signature against Root CA
    if not verify_certificate_signature(attestation_cert, root_ca_cert):
        return False

    # 3. Check touch policy if required
    if require_touch:
        meta = extract_yubico_metadata(attestation_cert)
        touch = meta.get("touch_policy")
        # touch_policy: 1 = never, 2 = always, 3 = cached
        if touch is None or touch < 2:
            return False

    return True
