"""
Granular capability and delegation model for the YubiHashKeyChain vault.
"""

from __future__ import annotations
from enum import Enum
from typing import Iterable, List, Set, Union


class VaultPermission(str, Enum):
    CAN_READ = "CAN_READ"
    CAN_WRITE = "CAN_WRITE"
    CAN_ADD_USER = "CAN_ADD_USER"
    CAN_ROTATE_EPOCH = "CAN_ROTATE_EPOCH"
    CAN_GRANT_PERMISSIONS = "CAN_GRANT_PERMISSIONS"
    CAN_MANAGE_ARCHIVE = "CAN_MANAGE_ARCHIVE"


ALL_PERMISSIONS: Set[VaultPermission] = {
    VaultPermission.CAN_READ,
    VaultPermission.CAN_WRITE,
    VaultPermission.CAN_ADD_USER,
    VaultPermission.CAN_ROTATE_EPOCH,
    VaultPermission.CAN_GRANT_PERMISSIONS,
    VaultPermission.CAN_MANAGE_ARCHIVE,
}

DEFAULT_MEMBER_PERMISSIONS: List[str] = [
    VaultPermission.CAN_READ.value,
]

CREATOR_PERMISSIONS: List[str] = [
    VaultPermission.CAN_READ.value,
    VaultPermission.CAN_WRITE.value,
    VaultPermission.CAN_ADD_USER.value,
    VaultPermission.CAN_ROTATE_EPOCH.value,
    VaultPermission.CAN_GRANT_PERMISSIONS.value,
    VaultPermission.CAN_MANAGE_ARCHIVE.value,
]


def parse_block_range(spec: str) -> Set[int]:
    """
    Parses a block range specification into a set of block indices.
    Examples:
        '0-10' -> {0, 1, ..., 10}
        '5' -> {5}
        '0-3,8,10-12' -> {0, 1, 2, 3, 8, 10, 11, 12}
    """
    indices: Set[int] = set()
    parts = spec.strip().split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end or start < 0:
                raise ValueError(f"Invalid range: {part}")
            indices.update(range(start, end + 1))
        else:
            val = int(part)
            if val < 0:
                raise ValueError(f"Invalid block index: {val}")
            indices.add(val)
    return indices


def is_valid_permission(val: str) -> bool:
    """Checks whether a permission string is known or matches a recognized pattern."""
    standard = {e.value for e in VaultPermission}
    if val in standard:
        return True
    # Scoped block permissions
    for prefix in ("BLOCK_READ:", "BLOCK_WRITE:", "BLOCK_ACCESS:"):
        if val.startswith(prefix):
            spec = val[len(prefix):]
            try:
                parse_block_range(spec)
                return True
            except Exception:
                return False
    # Tier / Classification permissions
    if val.startswith("TIER:") and len(val) > 5:
        return True
    if (val.startswith("CAN_READ_") or val.startswith("CAN_WRITE_")) and len(val) > 9:
        return True
    return False


def normalize_permissions(perms: Iterable[Union[str, VaultPermission]]) -> List[str]:
    """Converts a collection of permissions to sorted, unique uppercase strings."""
    result = set()
    for p in perms:
        val = p.value if isinstance(p, VaultPermission) else str(p).strip().upper()
        if is_valid_permission(val):
            result.add(val)
        else:
            raise ValueError(f"Unknown vault permission: {val}")
    return sorted(list(result))


def has_permission(granted: Iterable[str], required: Union[str, VaultPermission]) -> bool:
    """Checks whether granted permissions include the required capability."""
    req_val = required.value if isinstance(required, VaultPermission) else str(required).strip().upper()
    return req_val in [g.strip().upper() for g in granted]


def can_read_block(
    granted: Iterable[str],
    block_index: int,
    required_perm: Optional[str] = None,
) -> bool:
    """Checks whether granted permissions allow reading the given block index."""
    granted_list = [g.strip().upper() for g in granted]
    if "CAN_MANAGE_ARCHIVE" in granted_list or "CAN_GRANT_PERMISSIONS" in granted_list:
        return True

    # Check non-default requirement
    if required_perm and required_perm != "CAN_READ":
        req = required_perm.strip().upper()
        if req in granted_list:
            return True
        if req.startswith("TIER:") and f"CAN_READ_{req[5:]}" in granted_list:
            return True
        return False

    # Default/standard block reading
    if "CAN_READ" in granted_list:
        return True

    for p in granted_list:
        if p.startswith("BLOCK_READ:") or p.startswith("BLOCK_ACCESS:"):
            spec = p.split(":", 1)[1]
            try:
                if block_index in parse_block_range(spec):
                    return True
            except Exception:
                continue
    return False


def can_write_block(
    granted: Iterable[str],
    block_index: int,
    required_perm: Optional[str] = None,
) -> bool:
    """Checks whether granted permissions allow writing the given block index."""
    granted_list = [g.strip().upper() for g in granted]
    if "CAN_MANAGE_ARCHIVE" in granted_list or "CAN_GRANT_PERMISSIONS" in granted_list:
        return True

    if required_perm and required_perm != "CAN_WRITE":
        req = required_perm.strip().upper()
        if req in granted_list:
            return True
        if req.startswith("TIER:") and f"CAN_WRITE_{req[5:]}" in granted_list:
            return True
        return False

    if "CAN_WRITE" in granted_list:
        return True

    for p in granted_list:
        if p.startswith("BLOCK_WRITE:") or p.startswith("BLOCK_ACCESS:"):
            spec = p.split(":", 1)[1]
            try:
                if block_index in parse_block_range(spec):
                    return True
            except Exception:
                continue
    return False


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
