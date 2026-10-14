"""
Block schema and serialization for the YubiHashKeyChain DAG ledger.
"""

from __future__ import annotations
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from yubihash.core.canonical_json import canonicalize_json, hash_canonical_json


class BlockAction(str, Enum):
    GENESIS = "GENESIS"
    ADD_USER = "ADD_USER"
    REMOVE_USER = "REMOVE_USER"
    GRANT_PERMISSIONS = "GRANT_PERMISSIONS"
    ROTATE_EPOCH = "ROTATE_EPOCH"
    MERGE = "MERGE"


@dataclass
class BlockSigner:
    user_sid: str
    key_id: str  # SHA-256 fingerprint of Slot 9c public cert
    signature: str  # Base64-encoded DER ECDSA signature

    def to_dict(self) -> Dict[str, str]:
        return {
            "key_id": self.key_id,
            "signature": self.signature,
            "user_sid": self.user_sid,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> BlockSigner:
        return cls(
            user_sid=data["user_sid"],
            key_id=data["key_id"],
            signature=data["signature"],
        )


@dataclass
class Block:
    index: int
    parents: List[str]  # List of parent SHA-256 hex digests (empty for genesis)
    epoch: int
    timestamp: str  # ISO-8601 UTC
    action: BlockAction
    payload: Dict[str, Any]
    signer: Optional[BlockSigner] = None

    def unsigned_dict(self) -> Dict[str, Any]:
        """Returns the canonical dictionary of data to be hashed and signed."""
        return {
            "action": self.action.value if isinstance(self.action, BlockAction) else str(self.action),
            "epoch": self.epoch,
            "index": self.index,
            "parents": sorted(self.parents),
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    def canonical_bytes(self) -> bytes:
        """Returns RFC 8785 canonical JSON bytes of the unsigned block."""
        return canonicalize_json(self.unsigned_dict())

    def block_hash(self) -> str:
        """Returns the SHA-256 hex digest of the canonical unsigned block."""
        return hash_canonical_json(self.unsigned_dict())

    def to_dict(self) -> Dict[str, Any]:
        d = self.unsigned_dict()
        if self.signer:
            d["signer"] = self.signer.to_dict()
        else:
            d["signer"] = None
        return d

    def to_json(self) -> str:
        return canonicalize_json(self.to_dict()).decode("utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Block:
        action = BlockAction(data["action"])
        signer = BlockSigner.from_dict(data["signer"]) if data.get("signer") else None
        return cls(
            index=int(data["index"]),
            parents=list(data["parents"]),
            epoch=int(data["epoch"]),
            timestamp=data["timestamp"],
            action=action,
            payload=dict(data["payload"]),
            signer=signer,
        )

    @classmethod
    def create(
        cls,
        index: int,
        parents: List[str],
        epoch: int,
        action: BlockAction,
        payload: Dict[str, Any],
        timestamp: Optional[str] = None,
    ) -> Block:
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        return cls(
            index=index,
            parents=parents,
            epoch=epoch,
            timestamp=timestamp,
            action=action,
            payload=payload,
            signer=None,
        )
