"""
Mock Windows CNG DPAPI-NG Backend.
Simulates Domain Controller KDS Root Key protection bound to an Active Directory Security Group SID.
"""

from __future__ import annotations
import json
import os
from typing import Optional

from yubihash.backends.base import DpapiNgBackend
from yubihash.backends.mock.mock_directory import MockDirectory
from yubihash.core.crypto import encrypt_aes_gcm_packed, decrypt_aes_gcm_packed


class MockDpapiNg(DpapiNgBackend):
    """
    Simulated DPAPI-NG service backed by MockDirectory.
    Validates whether the current_user_sid belongs to the group_sid.
    """

    def __init__(self, directory: MockDirectory, current_user_sid: Optional[str] = None):
        self.directory = directory
        self.current_user_sid = current_user_sid
        # Simulated Domain Controller KDS Root Key
        self._kds_root_key = os.urandom(32)

    def set_current_user(self, user_sid: str) -> None:
        self.current_user_sid = user_sid

    def protect_secret(self, group_sid: str, secret: bytes) -> bytes:
        """
        Encrypts secret bound to group_sid.
        Opaque blob contains header with group_sid + encrypted ciphertext.
        """
        encrypted_secret = encrypt_aes_gcm_packed(self._kds_root_key, secret, associated_data=group_sid.encode("utf-8"))
        envelope = {
            "magic": "MOCK_DPAPI_NG",
            "group_sid": group_sid,
            "ciphertext_hex": encrypted_secret.hex(),
        }
        return json.dumps(envelope).encode("utf-8")

    def unprotect_secret(self, protected_blob: bytes) -> bytes:
        """
        Unprotects blob if current_user_sid is a member of the bound group_sid.
        """
        try:
            envelope = json.loads(protected_blob.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid DPAPI-NG protected blob format: {e}")

        group_sid = envelope.get("group_sid")
        ciphertext = bytes.fromhex(envelope["ciphertext_hex"])

        if not self.current_user_sid:
            raise PermissionError("NTE_BAD_KEY_STATE: No signed-in Windows user session")

        # Verify group membership against Directory
        members = self.directory.get_group_members(group_sid)
        member_sids = [m.sid for m in members]

        if self.current_user_sid not in member_sids:
            raise PermissionError(
                f"NTE_BAD_KEY_STATE / ERROR_ACCESS_DENIED: User '{self.current_user_sid}' "
                f"is not a member of AD Group '{group_sid}'"
            )

        return decrypt_aes_gcm_packed(self._kds_root_key, ciphertext, associated_data=group_sid.encode("utf-8"))
