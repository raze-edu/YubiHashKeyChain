"""
Mock Active Directory LDAP Backend.
Maintains in-memory directory state of users, groups, and multi-valued userCertificate attributes.
"""

from __future__ import annotations
from typing import Dict, List, Optional
from cryptography import x509

from yubihash.backends.base import DirectoryBackend, DirectoryUser


class MockDirectory(DirectoryBackend):
    """
    In-memory simulation of Active Directory with group memberships and certificates.
    """

    def __init__(self):
        self.users: Dict[str, DirectoryUser] = {}
        self.groups: Dict[str, List[str]] = {}  # group_sid -> list of user_sids

    def add_user(
        self,
        sid: str,
        upn: str,
        display_name: str,
        groups: Optional[List[str]] = None,
        certificates: Optional[List[bytes]] = None,
    ) -> DirectoryUser:
        user = DirectoryUser(
            sid=sid,
            upn=upn,
            display_name=display_name,
            groups=groups or [],
            certificates=certificates or [],
        )
        self.users[sid] = user
        for g_sid in user.groups:
            self.groups.setdefault(g_sid, [])
            if sid not in self.groups[g_sid]:
                self.groups[g_sid].append(sid)
        return user

    def add_user_to_group(self, user_sid: str, group_sid: str) -> None:
        if user_sid in self.users:
            if group_sid not in self.users[user_sid].groups:
                self.users[user_sid].groups.append(group_sid)
        self.groups.setdefault(group_sid, [])
        if user_sid not in self.groups[group_sid]:
            self.groups[group_sid].append(user_sid)

    def remove_user_from_group(self, user_sid: str, group_sid: str) -> None:
        if user_sid in self.users and group_sid in self.users[user_sid].groups:
            self.users[user_sid].groups.remove(group_sid)
        if group_sid in self.groups and user_sid in self.groups[group_sid]:
            self.groups[group_sid].remove(user_sid)

    def get_group_members(self, group_sid: str) -> List[DirectoryUser]:
        member_sids = self.groups.get(group_sid, [])
        return [self.users[sid] for sid in member_sids if sid in self.users]

    def get_user_by_sid(self, user_sid: str) -> Optional[DirectoryUser]:
        return self.users.get(user_sid)

    def publish_user_certificate(self, user_sid: str, cert_der: bytes) -> bool:
        if user_sid not in self.users:
            return False
        if cert_der not in self.users[user_sid].certificates:
            self.users[user_sid].certificates.append(cert_der)
        return True
