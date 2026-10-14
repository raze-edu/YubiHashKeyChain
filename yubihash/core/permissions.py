"""
Granular capability and delegation model for the YubiHashKeyChain vault.
"""

from __future__ import annotations
from enum import Enum
from typing import Iterable, List, Set, Union


class VaultPermission(str, Enum):
    CAN_READ = "CAN_READ"
    CAN_ADD_USER = "CAN_ADD_USER"
    CAN_ROTATE_EPOCH = "CAN_ROTATE_EPOCH"
    CAN_GRANT_PERMISSIONS = "CAN_GRANT_PERMISSIONS"


ALL_PERMISSIONS: Set[VaultPermission] = {
    VaultPermission.CAN_READ,
    VaultPermission.CAN_ADD_USER,
    VaultPermission.CAN_ROTATE_EPOCH,
    VaultPermission.CAN_GRANT_PERMISSIONS,
}

DEFAULT_MEMBER_PERMISSIONS: List[str] = [
    VaultPermission.CAN_READ.value,
]

CREATOR_PERMISSIONS: List[str] = [
    VaultPermission.CAN_READ.value,
    VaultPermission.CAN_ADD_USER.value,
    VaultPermission.CAN_ROTATE_EPOCH.value,
    VaultPermission.CAN_GRANT_PERMISSIONS.value,
]


def normalize_permissions(perms: Iterable[Union[str, VaultPermission]]) -> List[str]:
    """Converts a collection of permissions to sorted, unique uppercase strings."""
    result = set()
    for p in perms:
        val = p.value if isinstance(p, VaultPermission) else str(p).strip().upper()
        if val in [e.value for e in VaultPermission]:
            result.add(val)
        else:
            raise ValueError(f"Unknown vault permission: {val}")
    return sorted(list(result))


def has_permission(granted: Iterable[str], required: Union[str, VaultPermission]) -> bool:
    """Checks whether granted permissions include the required capability."""
    req_val = required.value if isinstance(required, VaultPermission) else str(required).strip().upper()
    return req_val in [g.strip().upper() for g in granted]


def can_delegate_permissions(
    granter_permissions: Iterable[str],
    permissions_to_grant: Iterable[str],
) -> bool:
    """
    Validates whether the granter has CAN_GRANT_PERMISSIONS.
    """
    if not has_permission(granter_permissions, VaultPermission.CAN_GRANT_PERMISSIONS):
        return False
    # Validate that all requested permissions are recognized
    normalize_permissions(permissions_to_grant)
    return True
