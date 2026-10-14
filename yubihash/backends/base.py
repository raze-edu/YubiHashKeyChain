"""
Abstract Base Classes for Vault Backends:
- YubiKeyBackend (PIV operations, signing, unwrapping, attestation)
- DpapiNgBackend (Windows CNG DPAPI-NG SID-bound secret protection)
- DirectoryBackend (LDAP / Active Directory group membership and certificate discovery)
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from cryptography import x509


@dataclass
class DirectoryUser:
    """Represents an Active Directory user account."""
    sid: str
    upn: str
    display_name: str
    groups: List[str] = field(default_factory=list)
    certificates: List[bytes] = field(default_factory=list)  # DER-encoded X.509 certs


class YubiKeyBackend(ABC):
    """Abstract interface for smartcard / YubiKey PIV applet operations."""

    @abstractmethod
    def get_serial(self) -> int:
        """Returns the hardware serial number of the YubiKey."""
        pass

    @abstractmethod
    def get_signing_certificate(self) -> x509.Certificate:
        """Retrieves the public certificate in Slot 9c (Digital Signature)."""
        pass

    @abstractmethod
    def get_decryption_certificate(self) -> x509.Certificate:
        """Retrieves the public certificate in Slot 9d (Key Management)."""
        pass

    @abstractmethod
    def get_attestation_certificate(self, slot: str = "9d") -> x509.Certificate:
        """Retrieves the hardware attestation certificate for the given slot."""
        pass

    @abstractmethod
    def sign_block(self, block_canonical_bytes: bytes, pin: Optional[str] = None) -> bytes:
        """
        Signs canonical block bytes using Slot 9c (Digital Signature).
        Returns DER-encoded ECDSA signature.
        """
        pass

    @abstractmethod
    def unwrap_half_b(self, wrapped_half_b: Dict[str, str], pin: Optional[str] = None) -> bytes:
        """
        Performs ECDH / decryption using Slot 9d to recover the 32-byte Half_B.
        """
        pass


class DpapiNgBackend(ABC):
    """Abstract interface for Windows CNG DPAPI-NG protection bound to AD Group SID."""

    @abstractmethod
    def protect_secret(self, group_sid: str, secret: bytes) -> bytes:
        """
        Protects secret bytes using descriptor 'SID=<group_sid>'.
        Returns opaque protected blob.
        """
        pass

    @abstractmethod
    def unprotect_secret(self, protected_blob: bytes) -> bytes:
        """
        Unprotects blob using Windows DPAPI-NG and current Kerberos context.
        Returns unprotected secret bytes into memory.
        """
        pass


class DirectoryBackend(ABC):
    """Abstract interface for Active Directory LDAP queries."""

    @abstractmethod
    def get_group_members(self, group_sid: str) -> List[DirectoryUser]:
        """Returns all user objects belonging to the specified AD group SID."""
        pass

    @abstractmethod
    def get_user_by_sid(self, user_sid: str) -> Optional[DirectoryUser]:
        """Returns the user object corresponding to the given SID."""
        pass

    @abstractmethod
    def publish_user_certificate(self, user_sid: str, cert_der: bytes) -> bool:
        """Adds a DER certificate to the user's userCertificate attribute."""
        pass
