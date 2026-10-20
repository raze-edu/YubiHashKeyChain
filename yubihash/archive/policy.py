"""
Block access control policy for encrypted BinBin archives.
Defines required permissions and security tiers per block.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Union

from yubihash.core.permissions import (
    VaultPermission,
    can_read_block,
    can_write_block,
    normalize_permissions,
    parse_block_range,
)


@dataclass
class BlockRule:
    """Access control requirement for a specific block or range of blocks."""
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    tier: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "read_permission": self.read_permission,
            "write_permission": self.write_permission,
            "tier": self.tier,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BlockRule:
        return cls(
            read_permission=data.get("read_permission"),
            write_permission=data.get("write_permission"),
            tier=data.get("tier"),
        )


class BlockPolicy:
    """
    Manages per-block permission requirements and security classifications.
    """

    def __init__(
        self,
        default_read_permission: str = VaultPermission.CAN_READ.value,
        default_write_permission: str = VaultPermission.CAN_WRITE.value,
        rules: Optional[Dict[int, BlockRule]] = None,
    ):
        self.default_read_permission = default_read_permission
        self.default_write_permission = default_write_permission
        self._rules: Dict[int, BlockRule] = rules or {}

    def set_rule(
        self,
        indices: Union[int, Iterable[int]],
        read_permission: Optional[str] = None,
        write_permission: Optional[str] = None,
        tier: Optional[str] = None,
    ) -> None:
        """Sets access requirements for a block index or multiple block indices."""
        idx_list = [indices] if isinstance(indices, int) else list(indices)
        for idx in idx_list:
            if idx < 0:
                raise ValueError(f"Block index must be >= 0: got {idx}")
            rule = self._rules.get(idx) or BlockRule()
            if read_permission is not None:
                rule.read_permission = read_permission
            if write_permission is not None:
                rule.write_permission = write_permission
            if tier is not None:
                rule.tier = tier
                if not rule.read_permission:
                    rule.read_permission = f"TIER:{tier}"
                if not rule.write_permission:
                    rule.write_permission = f"TIER:{tier}"
            self._rules[idx] = rule

    def set_range_rule(
        self,
        range_spec: str,
        read_permission: Optional[str] = None,
        write_permission: Optional[str] = None,
        tier: Optional[str] = None,
    ) -> None:
        """Sets requirements using a range string like '0-9' or '10,20-30'."""
        indices = parse_block_range(range_spec)
        self.set_rule(
            indices=indices,
            read_permission=read_permission,
            write_permission=write_permission,
            tier=tier,
        )

    def get_rule(self, block_index: int) -> Optional[BlockRule]:
        return self._rules.get(block_index)

    def get_read_requirement(self, block_index: int) -> str:
        rule = self._rules.get(block_index)
        if rule and rule.read_permission:
            return rule.read_permission
        return self.default_read_permission

    def get_write_requirement(self, block_index: int) -> str:
        rule = self._rules.get(block_index)
        if rule and rule.write_permission:
            return rule.write_permission
        return self.default_write_permission

    def get_tier(self, block_index: int) -> Optional[str]:
        rule = self._rules.get(block_index)
        return rule.tier if rule else None

    def can_read(self, granted_permissions: Iterable[str], block_index: int) -> bool:
        """Evaluates whether the granted permissions allow reading block_index."""
        req = self.get_read_requirement(block_index)
        tier = self.get_tier(block_index)
        return can_read_block(granted_permissions, block_index, required_perm=req)

    def can_write(self, granted_permissions: Iterable[str], block_index: int) -> bool:
        """Evaluates whether the granted permissions allow writing block_index."""
        req = self.get_write_requirement(block_index)
        tier = self.get_tier(block_index)
        return can_write_block(granted_permissions, block_index, required_perm=req)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "default_read_permission": self.default_read_permission,
            "default_write_permission": self.default_write_permission,
            "rules": {str(k): v.to_dict() for k, v in sorted(self._rules.items())},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BlockPolicy:
        rules = {}
        for k, v in data.get("rules", {}).items():
            rules[int(k)] = BlockRule.from_dict(v)
        return cls(
            default_read_permission=data.get("default_read_permission", VaultPermission.CAN_READ.value),
            default_write_permission=data.get("default_write_permission", VaultPermission.CAN_WRITE.value),
            rules=rules,
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> BlockPolicy:
        return cls.from_dict(json.loads(json_str))
