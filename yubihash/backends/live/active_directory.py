"""
Active Directory LDAP Backend using ldap3 with Kerberos / SASL authentication.
Queries AD Group members and extracts/publishes X.509 certificates in userCertificate.
"""

from __future__ import annotations
import os
from typing import List, Optional
from cryptography import x509
import ldap3
from ldap3.core.exceptions import LDAPException

from yubihash.backends.base import DirectoryBackend, DirectoryUser


class LiveActiveDirectory(DirectoryBackend):
    """
    Connects to Active Directory using the current logged-in Windows user's Kerberos token.
    """

    def __init__(
        self,
        domain_controller: Optional[str] = None,
        base_dn: Optional[str] = None,
        use_ssl: bool = False,
    ):
        if domain_controller is None:
            # Discover DC from Windows environment variables
            logon_server = os.environ.get("LOGONSERVER", "").replace("\\", "").strip()
            dns_domain = os.environ.get("USERDNSDOMAIN", "").strip()
            domain_controller = logon_server or dns_domain or "localhost"

        if base_dn is None and "USERDNSDOMAIN" in os.environ:
            parts = os.environ["USERDNSDOMAIN"].split(".")
            base_dn = ",".join(f"DC={p}" for p in parts)

        self.domain_controller = domain_controller
        self.base_dn = base_dn
        self.use_ssl = use_ssl

    def _get_connection(self) -> ldap3.Connection:
        server = ldap3.Server(self.domain_controller, use_ssl=self.use_ssl, get_info=ldap3.ALL)
        # Use Kerberos / GSSAPI pass-through via current Windows session
        conn = ldap3.Connection(
            server,
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.KERBEROS,
            auto_bind=True,
        )
        return conn

    def get_group_members(self, group_sid: str) -> List[DirectoryUser]:
        users: List[DirectoryUser] = []
        conn = self._get_connection()
        try:
            # Query group object to get its DN
            search_filter = f"(objectSid={group_sid})"
            conn.search(self.base_dn, search_filter, attributes=["distinguishedName"])
            if not conn.entries:
                return []
            group_dn = conn.entries[0].distinguishedName.value

            # Recursive LDAP query for all user members of group_dn
            user_filter = f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))"
            conn.search(
                self.base_dn,
                user_filter,
                attributes=["objectSid", "userPrincipalName", "displayName", "userCertificate"],
            )

            for entry in conn.entries:
                sid = entry.objectSid.value if "objectSid" in entry else ""
                upn = entry.userPrincipalName.value if "userPrincipalName" in entry else ""
                name = entry.displayName.value if "displayName" in entry else upn
                raw_certs = entry.userCertificate.raw_values if "userCertificate" in entry else []

                users.append(DirectoryUser(
                    sid=str(sid),
                    upn=str(upn),
                    display_name=str(name),
                    groups=[group_sid],
                    certificates=[bytes(c) for c in raw_certs],
                ))
            return users
        finally:
            conn.unbind()

    def get_user_by_sid(self, user_sid: str) -> Optional[DirectoryUser]:
        conn = self._get_connection()
        try:
            search_filter = f"(&(objectClass=user)(objectSid={user_sid}))"
            conn.search(
                self.base_dn,
                search_filter,
                attributes=["objectSid", "userPrincipalName", "displayName", "userCertificate", "memberOf"],
            )
            if not conn.entries:
                return None
            entry = conn.entries[0]
            raw_certs = entry.userCertificate.raw_values if "userCertificate" in entry else []
            groups = [str(g) for g in entry.memberOf.values] if "memberOf" in entry else []

            return DirectoryUser(
                sid=user_sid,
                upn=str(entry.userPrincipalName.value if "userPrincipalName" in entry else ""),
                display_name=str(entry.displayName.value if "displayName" in entry else ""),
                groups=groups,
                certificates=[bytes(c) for c in raw_certs],
            )
        finally:
            conn.unbind()

    def publish_user_certificate(self, user_sid: str, cert_der: bytes) -> bool:
        conn = self._get_connection()
        try:
            search_filter = f"(&(objectClass=user)(objectSid={user_sid}))"
            conn.search(self.base_dn, search_filter, attributes=["distinguishedName"])
            if not conn.entries:
                return False
            user_dn = conn.entries[0].distinguishedName.value

            return conn.modify(
                user_dn,
                {"userCertificate": [(ldap3.MODIFY_ADD, [cert_der])]},
            )
        finally:
            conn.unbind()
