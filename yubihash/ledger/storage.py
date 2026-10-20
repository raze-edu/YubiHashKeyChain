"""
File storage and atomic I/O layout on the SMB share:
- payload.enc
- genesis.blk
- blocks/0001_<hash>.blk
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import List, Optional, Union

from yubihash.ledger.block import Block


class VaultStorage:
    """
    Manages persistent files in the SMB share vault directory.
    Uses atomic writes to prevent corruption during concurrent network operations.
    """

    def __init__(self, vault_dir: Union[str, Path]):
        self.vault_dir = Path(vault_dir)
        self.blocks_dir = self.vault_dir / "blocks"
        self.payload_path = self.vault_dir / "payload.enc"
        self.genesis_path = self.vault_dir / "genesis.blk"
        self.archive_path = self.vault_dir / "archive.binbin"
        self.policy_path = self.vault_dir / "archive_policy.json"

    def ensure_directories(self) -> None:
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.blocks_dir.mkdir(parents=True, exist_ok=True)

    def has_archive(self) -> bool:
        return self.archive_path.exists()

    def write_archive_policy(self, policy: Any) -> None:
        self.ensure_directories()
        tmp_path = self.policy_path.with_suffix(".tmp")
        content = policy.to_json() if hasattr(policy, "to_json") else json.dumps(policy, indent=2)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.policy_path)

    def load_archive_policy(self) -> Optional[Any]:
        if not self.policy_path.exists():
            return None
        from yubihash.archive.policy import BlockPolicy
        with open(self.policy_path, "r", encoding="utf-8") as f:
            return BlockPolicy.from_json(f.read())

    def write_payload(self, data: bytes) -> None:
        self.ensure_directories()
        tmp_path = self.payload_path.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.payload_path)

    def read_payload(self) -> bytes:
        if not self.payload_path.exists():
            raise FileNotFoundError(f"Vault payload file not found: {self.payload_path}")
        with open(self.payload_path, "rb") as f:
            return f.read()

    def write_block(self, block: Block) -> Path:
        self.ensure_directories()
        h = block.block_hash()

        if block.index == 0:
            target_path = self.genesis_path
        else:
            # Format: 0001_a8f9c2.blk
            short_h = h[:8]
            target_path = self.blocks_dir / f"{block.index:04d}_{short_h}.blk"

        tmp_path = target_path.with_suffix(".tmp")
        content = block.to_json()
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target_path)
        return target_path

    def load_genesis_block(self) -> Optional[Block]:
        if not self.genesis_path.exists():
            return None
        with open(self.genesis_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return Block.from_dict(data)

    def load_all_blocks(self) -> List[Block]:
        """Loads genesis.blk and all sequential .blk files in blocks/."""
        blocks: List[Block] = []
        genesis = self.load_genesis_block()
        if genesis:
            blocks.append(genesis)

        if self.blocks_dir.exists():
            for p in sorted(self.blocks_dir.glob("*.blk")):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        blocks.append(Block.from_dict(data))
                except Exception as e:
                    raise IOError(f"Failed to read block file {p}: {e}")

        return blocks
