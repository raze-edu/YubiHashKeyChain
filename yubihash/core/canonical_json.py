"""
Canonical JSON (RFC 8785 / JCS) serialization and SHA-256 block hashing.
"""

from __future__ import annotations
import hashlib
import json
from typing import Any


def canonicalize_json(data: Any) -> bytes:
    """
    Serializes data into canonical JSON (RFC 8785) UTF-8 bytes.
    Keys are sorted, and no extraneous whitespace is introduced.
    """
    # Deterministic JSON serialization
    serialized = json.dumps(
        data,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )
    return serialized.encode("utf-8")


def hash_canonical_json(data: Any) -> str:
    """
    Computes the SHA-256 hex digest of the canonical JSON representation of the data.
    """
    canonical_bytes = canonicalize_json(data)
    return hashlib.sha256(canonical_bytes).hexdigest()
