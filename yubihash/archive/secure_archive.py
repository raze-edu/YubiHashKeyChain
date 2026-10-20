"""
SecureBlockArchive — Encrypted, permission-enforced block archive.
Integrates BinBin with YubiHashKeyChain access control and cryptographic key material.
"""

from __future__ import annotations
import math
import os
import struct
import sys
from pathlib import Path
from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure BinBin is importable
try:
    from BinBin.archive import BlockArchive
except ImportError:
    parent_dir = str(Path(__file__).resolve().parent.parent.parent.parent)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from BinBin.archive import BlockArchive

from yubihash.archive.key import ArchiveUserKey
from yubihash.archive.policy import BlockPolicy
from yubihash.core.permissions import VaultPermission

# 12-byte IV + 16-byte GCM Tag + 4-byte payload length prefix
BLOCK_OVERHEAD = 32
GCM_TAG_AND_IV = 28  # 12 IV + 16 TAG


class DecryptionError(Exception):
    """Raised when block authentication fails (tampering, wrong key, wrong epoch)."""
    pass


class SecureBlockArchive:
    """
    An encrypted, block-addressable archive providing transparent encryption/decryption
    and granular access control based on user permissions.
    """

    def __init__(
        self,
        raw_archive: BlockArchive,
        key: ArchiveUserKey,
        policy: Optional[BlockPolicy] = None,
    ):
        self._raw = raw_archive
        self._key = key
        self._policy = policy or BlockPolicy()
        self._block_size = self._raw.block_size
        if self._block_size <= BLOCK_OVERHEAD:
            raise ValueError(
                f"Block size {self._block_size} too small to support encryption overhead ({BLOCK_OVERHEAD}B)"
            )
        self._payload_size = self._block_size - BLOCK_OVERHEAD

    @classmethod
    def create(
        cls,
        path: Union[str, Path],
        block_size: int,
        block_count: int,
        key: ArchiveUserKey,
        policy: Optional[BlockPolicy] = None,
        raw_block_size: bool = False,
    ) -> "SecureBlockArchive":
        """
        Creates a new encrypted BinBin archive.

        Parameters
        ----------
        path : str | Path
            Destination archive file path.
        block_size : int
            Block size in bytes. If raw_block_size is False (default), this represents
            the usable payload size, and 32 bytes of cryptographic overhead are added.
            If raw_block_size is True, block_size is the exact physical size on disk.
        block_count : int
            Total number of blocks to pre-allocate.
        key : ArchiveUserKey
            Authorized user key.
        policy : BlockPolicy, optional
            Block access control rules.
        """
        if not key.has_capability(VaultPermission.CAN_WRITE) and not key.has_capability(VaultPermission.CAN_MANAGE_ARCHIVE):
            raise PermissionError(f"User '{key.user_sid}' lacks write permission to create an archive")

        phys_block_size = block_size if raw_block_size else (block_size + BLOCK_OVERHEAD)
        raw = BlockArchive.create(path, block_size=phys_block_size, block_count=block_count)
        return cls(raw_archive=raw, key=key, policy=policy)

    @classmethod
    def open(
        cls,
        path: Union[str, Path],
        key: ArchiveUserKey,
        policy: Optional[BlockPolicy] = None,
        mode: str = "r+b",
    ) -> "SecureBlockArchive":
        """
        Opens an existing encrypted BinBin archive.
        """
        raw = BlockArchive.open(path, mode=mode)
        return cls(raw_archive=raw, key=key, policy=policy)

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._raw.path

    @property
    def block_size(self) -> int:
        """Physical block size on disk."""
        return self._block_size

    @property
    def payload_block_size(self) -> int:
        """Maximum usable plaintext bytes per block."""
        return self._payload_size

    @property
    def block_count(self) -> int:
        return self._raw.block_count

    @property
    def used_blocks(self) -> int:
        return self._raw.used_blocks

    @property
    def free_blocks(self) -> int:
        return self._raw.free_blocks

    @property
    def policy(self) -> BlockPolicy:
        return self._policy

    @property
    def key(self) -> ArchiveUserKey:
        return self._key

    # -----------------------------------------------------------------
    # Permission Queries
    # -----------------------------------------------------------------

    def can_read_block(self, index: int) -> bool:
        """Returns True if the current user key is authorized to read block index."""
        return self._key.can_read(index, self._policy)

    def can_write_block(self, index: int) -> bool:
        """Returns True if the current user key is authorized to write block index."""
        return self._key.can_write(index, self._policy)

    # -----------------------------------------------------------------
    # Single-block I/O
    # -----------------------------------------------------------------

    def read_block(self, index: int) -> bytes:
        """
        Reads and automatically decrypts block at index.
        Verifies cryptographic integrity (AES-256-GCM) and block-swapping protection (AAD).

        Raises
        ------
        PermissionError
            If current user lacks permission for this block.
        DecryptionError
            If the block was tampered with, swapped, or encrypted with an invalid key/epoch.
        """
        if not self.can_read_block(index):
            req = self._policy.get_read_requirement(index)
            raise PermissionError(
                f"User '{self._key.user_sid}' lacks read permission for block {index} (requires '{req}')"
            )

        raw_data = self._raw.read_block(index)
        # Check if block is entirely unwritten / empty
        if not self._raw.is_allocated(index) and raw_data == b"\x00" * self._block_size:
            return b""

        iv = raw_data[:12]
        ct_with_tag = raw_data[12:]
        aad = struct.pack(">QII", index, self._key.epoch, self._block_size)
        scope = self._policy.get_read_requirement(index)
        block_key = self._key.derive_block_key(index, scope=scope)

        try:
            aesgcm = AESGCM(block_key)
            padded_payload = aesgcm.decrypt(iv, ct_with_tag, aad)
        except Exception as e:
            raise DecryptionError(
                f"Decryption failed for block {index}: block tampered, wrong key, or wrong epoch ({e})"
            ) from e

        data_len = struct.unpack(">I", padded_payload[:4])[0]
        if data_len > len(padded_payload) - 4:
            raise DecryptionError(f"Corrupt length prefix at block {index}: {data_len} > {len(padded_payload) - 4}")

        return padded_payload[4 : 4 + data_len]

    def write_block(self, index: int, data: bytes) -> None:
        """
        Encrypts data and writes it to block at index.

        Raises
        ------
        PermissionError
            If current user lacks permission to write to this block.
        ValueError
            If data length exceeds payload_block_size.
        """
        if not self.can_write_block(index):
            req = self._policy.get_write_requirement(index)
            raise PermissionError(
                f"User '{self._key.user_sid}' lacks write permission for block {index} (requires '{req}')"
            )

        if len(data) > self._payload_size:
            raise ValueError(
                f"Data length {len(data)} exceeds maximum payload size {self._payload_size} (block_size={self._block_size})"
            )

        scope = self._policy.get_read_requirement(index)
        block_key = self._key.derive_block_key(index, scope=scope)
        iv = os.urandom(12)
        aad = struct.pack(">QII", index, self._key.epoch, self._block_size)

        # Pack length + data, then pad to (block_size - 28)
        packed = struct.pack(">I", len(data)) + data
        diff = (self._block_size - 28) - len(packed)
        padded_payload = packed + (b"\x00" * diff)

        aesgcm = AESGCM(block_key)
        ct_with_tag = aesgcm.encrypt(iv, padded_payload, aad)
        raw_block = iv + ct_with_tag

        self._raw.write_block(index, raw_block)

    # -----------------------------------------------------------------
    # Multi-block I/O
    # -----------------------------------------------------------------

    def read_blocks(self, start: int, count: int) -> bytes:
        """
        Reads and decrypts count contiguous blocks starting at start.
        """
        if count <= 0:
            return b""

        # Pre-verify permissions for all target blocks
        for i in range(start, start + count):
            if not self.can_read_block(i):
                req = self._policy.get_read_requirement(i)
                raise PermissionError(
                    f"User '{self._key.user_sid}' lacks read permission for block {i} (requires '{req}')"
                )

        chunks = []
        for i in range(start, start + count):
            chunks.append(self.read_block(i))
        return b"".join(chunks)

    def write_blocks(self, start: int, data: bytes) -> int:
        """
        Chunks data into payload_block_size blocks and encrypts them across
        contiguous blocks starting at start.
        Returns the number of blocks written.
        """
        if not data:
            return 0

        chunk_size = self._payload_size
        num_blocks = math.ceil(len(data) / chunk_size)

        # Pre-verify permissions for all target blocks
        for i in range(start, start + num_blocks):
            if not self.can_write_block(i):
                req = self._policy.get_write_requirement(i)
                raise PermissionError(
                    f"User '{self._key.user_sid}' lacks write permission for block {i} (requires '{req}')"
                )

        for b_idx in range(num_blocks):
            chunk = data[b_idx * chunk_size : (b_idx + 1) * chunk_size]
            self.write_block(start + b_idx, chunk)

        return num_blocks

    # -----------------------------------------------------------------
    # Bitmap Allocation
    # -----------------------------------------------------------------

    def alloc(self, count: int = 1) -> Union[int, List[int]]:
        """Allocates contiguous free blocks in the archive."""
        return self._raw.alloc(count)

    def free(self, index: int, count: int = 1) -> None:
        """Marks blocks as free."""
        self._raw.free(index, count)

    def is_allocated(self, index: int) -> bool:
        """Checks if a block is marked as used in the bitmap."""
        return self._raw.is_allocated(index)

    def flush(self) -> None:
        """Flushes archive to disk."""
        self._raw.flush()

    def close(self) -> None:
        """Flushes and closes the archive."""
        self._raw.close()

    # -----------------------------------------------------------------
    # Epoch Rotation / Re-keying
    # -----------------------------------------------------------------

    def rekey_for_epoch(self, new_key: ArchiveUserKey) -> int:
        """
        Re-encrypts all currently allocated blocks with the new epoch key.
        Requires CAN_ROTATE_EPOCH or CAN_MANAGE_ARCHIVE permission.
        """
        if not self._key.has_capability(VaultPermission.CAN_ROTATE_EPOCH) and not self._key.has_capability(VaultPermission.CAN_MANAGE_ARCHIVE):
            raise PermissionError(f"User '{self._key.user_sid}' lacks CAN_ROTATE_EPOCH permission to re-key archive")

        rekeyed_count = 0
        old_key = self._key

        for i in range(self.block_count):
            if self.is_allocated(i):
                # Decrypt with old key
                plaintext = self.read_block(i)
                # Encrypt with new key
                self._key = new_key
                self.write_block(i, plaintext)
                self._key = old_key
                rekeyed_count += 1

        self._key = new_key
        self.flush()
        return rekeyed_count

    # -----------------------------------------------------------------
    # Lifecycle & Context Manager
    # -----------------------------------------------------------------

    def __enter__(self) -> "SecureBlockArchive":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"<SecureBlockArchive {self.path.name!r} "
            f"payload_block_size={self._payload_size} "
            f"blocks={self.block_count} "
            f"used={self.used_blocks} "
            f"user='{self._key.user_sid}'>"
        )
