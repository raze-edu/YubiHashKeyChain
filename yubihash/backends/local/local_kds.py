"""
Local KDS (Key Distribution Service) DPAPI-NG Simulation.

Stands in for Windows CNG DPAPI-NG with an ``SID=<group>`` protection descriptor
when no Domain Controller is available:

- A persistent 256-bit "KDS root key" file plays the role of the DC's KDS Root Key.
- A per-group key is derived via HKDF-SHA256(root_key, info=descriptor).
- ``unprotect_secret`` only succeeds if the *current lab user* is a member of
  the bound group in the local directory, which mirrors how the real
  DC only releases group keys to members holding a valid Kerberos ticket.

The protected blob format is a JSON envelope and is intentionally NOT
compatible with real DPAPI-NG blobs: a lab vault cannot be opened by the
live backend and vice versa.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from yubihash.backends.base import DirectoryBackend, DpapiNgBackend
from yubihash.core.crypto import decrypt_aes_gcm_packed, encrypt_aes_gcm_packed

ENVELOPE_MAGIC = "YUBIHASH_LAB_DPAPI_NG"
ENVELOPE_VERSION = 1
KDF_INFO_PREFIX = b"yubihash-lab-kds|"


class LocalKdsDpapiNg(DpapiNgBackend):
    """
    Simulated DPAPI-NG bound to a local directory's group memberships.
    """

    def __init__(
        self,
        root_key_file: Union[str, Path],
        directory: DirectoryBackend,
        current_user_sid: Optional[str] = None,
    ):
        self.root_key_file = Path(root_key_file)
        self.directory = directory
        self.current_user_sid = current_user_sid

    @staticmethod
    def create_root_key(root_key_file: Union[str, Path]) -> None:
        """Generates a new 256-bit KDS root key file (like ``Add-KdsRootKey``)."""
        path = Path(root_key_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(os.urandom(32))

    def set_current_user(self, user_sid: str) -> None:
        self.current_user_sid = user_sid

    def _root_key(self) -> bytes:
        if not self.root_key_file.exists():
            raise FileNotFoundError(f"Lab KDS root key not found: {self.root_key_file}")
        key = self.root_key_file.read_bytes()
        if len(key) != 32:
            raise ValueError("Lab KDS root key must be exactly 32 bytes")
        return key

    @staticmethod
    def _root_key_id(root_key: bytes) -> str:
        return hashlib.sha256(b"kds-root-key-id|" + root_key).hexdigest()[:16]

    @staticmethod
    def _derive_group_key(root_key: bytes, descriptor: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=KDF_INFO_PREFIX + descriptor.encode("utf-8"),
        ).derive(root_key)

    def protect_secret(self, group_sid: str, secret: bytes) -> bytes:
        descriptor = f"SID={group_sid}"
        root_key = self._root_key()
        group_key = self._derive_group_key(root_key, descriptor)
        ciphertext = encrypt_aes_gcm_packed(group_key, secret, associated_data=descriptor.encode("utf-8"))
        envelope = {
            "magic": ENVELOPE_MAGIC,
            "version": ENVELOPE_VERSION,
            "descriptor": descriptor,
            "root_key_id": self._root_key_id(root_key),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(envelope, sort_keys=True).encode("utf-8")

    def unprotect_secret(self, protected_blob: bytes) -> bytes:
        try:
            envelope = json.loads(protected_blob.decode("utf-8"))
        except Exception as e:
            raise ValueError(
                "Protected blob is not a lab DPAPI-NG envelope. Was this vault created "
                f"with the live (Active Directory) backend? ({e})"
            )
        if envelope.get("magic") != ENVELOPE_MAGIC:
            raise ValueError("Protected blob is not a lab DPAPI-NG envelope")

        descriptor: str = envelope["descriptor"]
        if not descriptor.startswith("SID="):
            raise ValueError(f"Unsupported protection descriptor: {descriptor!r}")
        group_sid = descriptor[len("SID="):]

        root_key = self._root_key()
        if envelope.get("root_key_id") != self._root_key_id(root_key):
            raise ValueError(
                "NTE_BAD_KEY: blob was protected by a different lab KDS root key "
                "(vault belongs to another lab environment)"
            )

        if not self.current_user_sid:
            raise PermissionError("NTE_BAD_KEY_STATE: No signed-in lab user session")

        member_sids = {m.sid for m in self.directory.get_group_members(group_sid)}
        if self.current_user_sid not in member_sids:
            raise PermissionError(
                f"NTE_BAD_KEY_STATE / ERROR_ACCESS_DENIED: User '{self.current_user_sid}' "
                f"is not a member of lab group '{group_sid}'"
            )

        group_key = self._derive_group_key(root_key, descriptor)
        ciphertext = base64.b64decode(envelope["ciphertext"])
        return decrypt_aes_gcm_packed(group_key, ciphertext, associated_data=descriptor.encode("utf-8"))
