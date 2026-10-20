"""
Cryptographic key container and per-block key derivation for authorized users.
Integrates user permissions and active epoch to govern block access.
"""

from __future__ import annotations
import struct
from typing import Iterable, List, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from yubihash.archive.policy import BlockPolicy
from yubihash.core.memory import SecureBuffer
from yubihash.core.permissions import (
    VaultPermission,
    has_permission,
    normalize_permissions,
)


class ArchiveUserKey:
    """
    Represents an unlocked cryptographic key held by an authorized user.
    Maintains memory hygiene using SecureBuffer for key material.
    """

    def __init__(
        self,
        user_sid: str,
        fek: Union[bytes, bytearray, SecureBuffer],
        permissions: Iterable[str],
        epoch: int = 0,
    ):
        self.user_sid = user_sid
        self.epoch = epoch
        self.permissions: List[str] = normalize_permissions(permissions)

        if isinstance(fek, SecureBuffer):
            self._buffer = fek
            self._owns_buffer = False
        else:
            if len(fek) != 32:
                raise ValueError("Vault encryption key must be exactly 32 bytes")
            self._buffer = SecureBuffer(bytes(fek))
            self._owns_buffer = True

    @property
    def key_bytes(self) -> bytes:
        """Access the raw key bytes."""
        return self._buffer.to_bytes()

    def derive_block_key(self, block_index: int, scope: str = "") -> bytes:
        """
        Derives an independent 256-bit AES-GCM key for a specific block index and epoch.
        Uses HKDF-SHA256 with epoch salt and block context info.
        """
        salt = struct.pack(">I", self.epoch)
        info = f"binbin:block:{block_index}:{scope}".encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(self.key_bytes)

    def can_read(self, block_index: int, policy: Optional[BlockPolicy] = None) -> bool:
        """Checks if this user key permits reading the target block."""
        if policy is None:
            policy = BlockPolicy()
        return policy.can_read(self.permissions, block_index)

    def can_write(self, block_index: int, policy: Optional[BlockPolicy] = None) -> bool:
        """Checks if this user key permits writing the target block."""
        if policy is None:
            policy = BlockPolicy()
        return policy.can_write(self.permissions, block_index)

    def has_capability(self, required: Union[str, VaultPermission]) -> bool:
        """Checks if the user has a specific vault permission."""
        return has_permission(self.permissions, required)

    def close(self) -> None:
        """Zero out sensitive key memory if owned."""
        if self._owns_buffer and self._buffer is not None:
            self._buffer.wipe()

    def __enter__(self) -> "ArchiveUserKey":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"<ArchiveUserKey user='{self.user_sid}' "
            f"epoch={self.epoch} perms={self.permissions}>"
        )
