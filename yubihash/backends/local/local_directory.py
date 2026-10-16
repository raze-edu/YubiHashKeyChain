"""
Local (non-AD) Directory Backend.

Persists users, security groups, group memberships, and the multi-valued
``userCertificate`` attribute in a single JSON file. It stands in for Active
Directory / LDAP when testing the vault on machines that are not domain-joined.

The file is re-read on every query so that membership changes made by one
process (e.g. an "admin" removing a user from a group) are immediately visible
to every other process, just like a shared Domain Controller.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from yubihash.backends.base import DirectoryBackend, DirectoryUser

DIRECTORY_FORMAT = "yubihash-lab-directory/1"
FIRST_RID = 1100


class DirectoryEntryNotFound(LookupError):
    """Raised when a user or group reference cannot be resolved."""


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def generate_domain_sid() -> str:
    """Generates a random, realistic-looking domain SID prefix (S-1-5-21-x-y-z)."""
    parts = [str(secrets.randbelow(2**32 - 1) + 1) for _ in range(3)]
    return "S-1-5-21-" + "-".join(parts)


class LocalDirectory(DirectoryBackend):
    """
    File-backed simulation of Active Directory users, groups, and certificates.
    """

    def __init__(self, directory_file: Union[str, Path]):
        self.path = Path(directory_file)

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    @classmethod
    def create(
        cls,
        directory_file: Union[str, Path],
        domain: str = "lab.local",
        domain_sid: Optional[str] = None,
    ) -> "LocalDirectory":
        """Creates a new, empty directory file."""
        directory = cls(directory_file)
        _atomic_write_json(directory.path, {
            "format": DIRECTORY_FORMAT,
            "domain": domain,
            "domain_sid": domain_sid or generate_domain_sid(),
            "next_rid": FIRST_RID,
            "users": {},
            "groups": {},
        })
        return directory

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            raise FileNotFoundError(f"Lab directory file not found: {self.path}")
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("format") != DIRECTORY_FORMAT:
            raise ValueError(f"Unsupported directory file format: {data.get('format')!r}")
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        _atomic_write_json(self.path, data)

    def _allocate_sid(self, data: Dict[str, Any]) -> str:
        rid = int(data["next_rid"])
        data["next_rid"] = rid + 1
        return f"{data['domain_sid']}-{rid}"

    @property
    def domain(self) -> str:
        return self._load()["domain"]

    # ------------------------------------------------------------------ #
    # Administration (what a Domain Admin would do in ADUC)
    # ------------------------------------------------------------------ #

    def create_group(self, name: str) -> str:
        data = self._load()
        if self._find_group_sid(data, name):
            raise ValueError(f"Group '{name}' already exists")
        sid = self._allocate_sid(data)
        data["groups"][sid] = {"name": name, "members": []}
        self._save(data)
        return sid

    def create_user(self, name: str, display_name: Optional[str] = None) -> str:
        data = self._load()
        if self._find_user_sid(data, name):
            raise ValueError(f"User '{name}' already exists")
        sid = self._allocate_sid(data)
        data["users"][sid] = {
            "name": name,
            "upn": f"{name}@{data['domain']}",
            "display_name": display_name or name.capitalize(),
            "certificates": [],
        }
        self._save(data)
        return sid

    def add_user_to_group(self, user_sid: str, group_sid: str) -> bool:
        """Adds a member to a group. Returns False if already a member."""
        data = self._load()
        self._require_user(data, user_sid)
        members = self._require_group(data, group_sid)["members"]
        if user_sid in members:
            return False
        members.append(user_sid)
        self._save(data)
        return True

    def remove_user_from_group(self, user_sid: str, group_sid: str) -> bool:
        """Removes a member from a group. Returns False if not a member."""
        data = self._load()
        members = self._require_group(data, group_sid)["members"]
        if user_sid not in members:
            return False
        members.remove(user_sid)
        self._save(data)
        return True

    def clear_user_certificates(self, user_sid: str) -> None:
        data = self._load()
        self._require_user(data, user_sid)["certificates"] = []
        self._save(data)

    def delete_user(self, user_sid: str) -> None:
        """Deletes a user account and removes it from every group."""
        data = self._load()
        data["users"].pop(user_sid, None)
        for group in data["groups"].values():
            if user_sid in group["members"]:
                group["members"].remove(user_sid)
        self._save(data)

    # ------------------------------------------------------------------ #
    # Lookup helpers
    # ------------------------------------------------------------------ #

    def resolve_user(self, ref: str) -> str:
        """Resolves a user name, UPN, or SID to a SID."""
        sid = self._find_user_sid(self._load(), ref)
        if not sid:
            raise DirectoryEntryNotFound(f"Unknown lab user: '{ref}'")
        return sid

    def resolve_group(self, ref: str) -> str:
        """Resolves a group name or SID to a SID."""
        sid = self._find_group_sid(self._load(), ref)
        if not sid:
            raise DirectoryEntryNotFound(f"Unknown lab group: '{ref}'")
        return sid

    def list_users(self) -> List[DirectoryUser]:
        data = self._load()
        return [self._to_directory_user(data, sid) for sid in data["users"]]

    def list_groups(self) -> Dict[str, Dict[str, Any]]:
        """Returns {group_sid: {"name": ..., "members": [...]}}."""
        return self._load()["groups"]

    def name_of(self, sid: str) -> Optional[str]:
        data = self._load()
        if sid in data["users"]:
            return data["users"][sid]["name"]
        if sid in data["groups"]:
            return data["groups"][sid]["name"]
        return None

    @staticmethod
    def _find_user_sid(data: Dict[str, Any], ref: str) -> Optional[str]:
        if ref in data["users"]:
            return ref
        needle = ref.lower()
        for sid, u in data["users"].items():
            if u["name"].lower() == needle or u["upn"].lower() == needle:
                return sid
        return None

    @staticmethod
    def _find_group_sid(data: Dict[str, Any], ref: str) -> Optional[str]:
        if ref in data["groups"]:
            return ref
        needle = ref.lower()
        for sid, g in data["groups"].items():
            if g["name"].lower() == needle:
                return sid
        return None

    @staticmethod
    def _require_user(data: Dict[str, Any], user_sid: str) -> Dict[str, Any]:
        if user_sid not in data["users"]:
            raise DirectoryEntryNotFound(f"Unknown lab user SID: '{user_sid}'")
        return data["users"][user_sid]

    @staticmethod
    def _require_group(data: Dict[str, Any], group_sid: str) -> Dict[str, Any]:
        if group_sid not in data["groups"]:
            raise DirectoryEntryNotFound(f"Unknown lab group SID: '{group_sid}'")
        return data["groups"][group_sid]

    @staticmethod
    def _to_directory_user(data: Dict[str, Any], sid: str) -> DirectoryUser:
        u = data["users"][sid]
        groups = [g_sid for g_sid, g in data["groups"].items() if sid in g["members"]]
        return DirectoryUser(
            sid=sid,
            upn=u["upn"],
            display_name=u["display_name"],
            groups=groups,
            certificates=[base64.b64decode(c) for c in u["certificates"]],
        )

    # ------------------------------------------------------------------ #
    # DirectoryBackend interface
    # ------------------------------------------------------------------ #

    def get_group_members(self, group_sid: str) -> List[DirectoryUser]:
        data = self._load()
        group = data["groups"].get(group_sid)
        if group is None:
            return []
        return [
            self._to_directory_user(data, sid)
            for sid in group["members"]
            if sid in data["users"]
        ]

    def get_user_by_sid(self, user_sid: str) -> Optional[DirectoryUser]:
        data = self._load()
        if user_sid not in data["users"]:
            return None
        return self._to_directory_user(data, user_sid)

    def publish_user_certificate(self, user_sid: str, cert_der: bytes) -> bool:
        data = self._load()
        if user_sid not in data["users"]:
            return False
        encoded = base64.b64encode(cert_der).decode("ascii")
        certs = data["users"][user_sid]["certificates"]
        if encoded not in certs:
            certs.append(encoded)
            self._save(data)
        return True
