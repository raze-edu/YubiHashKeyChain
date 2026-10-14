"""
DAG Ledger verification, DAG merge consensus, and state projection for the vault.
"""

from __future__ import annotations
import base64
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from cryptography import x509
from yubihash.core.canonical_json import hash_canonical_json
from yubihash.core.crypto import (
    load_der_certificate,
    verify_ecdsa_sha256,
    cert_sha256_fingerprint,
)
from yubihash.core.permissions import (
    VaultPermission,
    has_permission,
    can_delegate_permissions,
    CREATOR_PERMISSIONS,
    DEFAULT_MEMBER_PERMISSIONS,
)
from yubihash.ledger.block import Block, BlockAction


@dataclass
class MemberState:
    user_sid: str
    slot_9c_cert_der: bytes
    slot_9d_cert_der: bytes
    attestation_cert_der: Optional[bytes]
    wrapped_half_b: Dict[str, str]
    permissions: List[str]


@dataclass
class VaultState:
    epoch: int = 0
    group_sid: str = ""
    half_a_dpapi_ng_b64: str = ""
    encrypted_fek_b64: str = ""
    members: Dict[str, MemberState] = field(default_factory=dict)
    blocks: Dict[str, Block] = field(default_factory=dict)
    tips: Set[str] = field(default_factory=set)
    max_index: int = 0

    def get_member(self, user_sid: str) -> Optional[MemberState]:
        return self.members.get(user_sid)

    def is_member_active(self, user_sid: str) -> bool:
        return user_sid in self.members


class ChainVerificationError(Exception):
    """Raised when block or chain validation fails."""
    pass


class ChainStateProjector:
    """
    Validates a set of blocks and projects the current authorized vault state.
    Handles DAG branching and merge resolutions.
    """

    def __init__(self, root_ca_cert: Optional[x509.Certificate] = None):
        self.root_ca_cert = root_ca_cert

    def project(self, blocks: List[Block]) -> VaultState:
        """
        Validates all blocks in topological order and returns the projected VaultState.
        """
        if not blocks:
            raise ChainVerificationError("No blocks provided for chain projection")

        # Map by hash
        blocks_by_hash: Dict[str, Block] = {}
        for b in blocks:
            h = b.block_hash()
            blocks_by_hash[h] = b

        # Find genesis block (index 0, empty parents)
        genesis_blocks = [b for b in blocks if b.index == 0 and len(b.parents) == 0]
        if len(genesis_blocks) != 1:
            raise ChainVerificationError(
                f"Expected exactly 1 genesis block, found {len(genesis_blocks)}"
            )
        genesis = genesis_blocks[0]
        genesis_hash = genesis.block_hash()

        # Build DAG adjacency
        in_degree: Dict[str, int] = defaultdict(int)
        children: Dict[str, List[str]] = defaultdict(list)
        for h, b in blocks_by_hash.items():
            for p in b.parents:
                if p not in blocks_by_hash:
                    raise ChainVerificationError(f"Block {h} references unknown parent {p}")
                children[p].append(h)
                in_degree[h] += 1

        # Kahn's topological sort
        queue = deque([genesis_hash])
        topo_order: List[Block] = []

        while queue:
            # Deterministic ordering by index then hash
            curr_hash = queue.popleft()
            curr_block = blocks_by_hash[curr_hash]
            topo_order.append(curr_block)

            for child_hash in sorted(children[curr_hash]):
                in_degree[child_hash] -= 1
                if in_degree[child_hash] == 0:
                    queue.append(child_hash)

        if len(topo_order) != len(blocks):
            raise ChainVerificationError("Cycle detected in block DAG or disconnected components")

        # Now sequentially project state
        state = VaultState()
        for block in topo_order:
            self._apply_block(state, block)

        return state

    def _apply_block(self, state: VaultState, block: Block) -> None:
        block_h = block.block_hash()
        state.blocks[block_h] = block
        state.max_index = max(state.max_index, block.index)

        # Update tips: remove parents from tips, add current block
        for p in block.parents:
            state.tips.discard(p)
        state.tips.add(block_h)

        if block.action == BlockAction.GENESIS:
            self._apply_genesis(state, block)
            return

        # For all subsequent blocks, verify signer and signature
        if not block.signer:
            raise ChainVerificationError(f"Block {block_h} has no signer")

        signer_sid = block.signer.user_sid
        signer_member = state.get_member(signer_sid)
        if not signer_member:
            raise ChainVerificationError(
                f"Block {block_h} signer '{signer_sid}' is not an authorized member in active state"
            )

        # Verify signature with signer's Slot 9c cert
        cert_9c = load_der_certificate(signer_member.slot_9c_cert_der)
        expected_key_id = cert_sha256_fingerprint(cert_9c)
        if block.signer.key_id.lower() != expected_key_id.lower():
            raise ChainVerificationError(
                f"Block {block_h} key_id '{block.signer.key_id}' does not match signer certificate '{expected_key_id}'"
            )

        sig_bytes = base64.b64decode(block.signer.signature)
        canonical_bytes = block.canonical_bytes()
        if not verify_ecdsa_sha256(cert_9c.public_key(), sig_bytes, canonical_bytes):
            raise ChainVerificationError(f"Cryptographic signature verification failed for block {block_h}")

        # Check action permissions
        if block.action == BlockAction.ADD_USER:
            self._apply_add_user(state, block, signer_member)
        elif block.action == BlockAction.REMOVE_USER:
            self._apply_remove_user(state, block, signer_member)
        elif block.action == BlockAction.GRANT_PERMISSIONS:
            self._apply_grant_permissions(state, block, signer_member)
        elif block.action == BlockAction.ROTATE_EPOCH:
            self._apply_rotate_epoch(state, block, signer_member)
        elif block.action == BlockAction.MERGE:
            self._apply_merge(state, block, signer_member)
        else:
            raise ChainVerificationError(f"Unknown block action: {block.action}")

    def _apply_genesis(self, state: VaultState, block: Block) -> None:
        p = block.payload
        state.epoch = block.epoch
        state.group_sid = p["group_sid"]
        state.half_a_dpapi_ng_b64 = p["half_a_dpapi_ng"]
        state.encrypted_fek_b64 = p["encrypted_fek"]

        # Creator verification
        creator = p["creator"]
        creator_sid = creator["user_sid"]
        slot_9c_der = base64.b64decode(creator["slot_9c_cert"])
        slot_9d_der = base64.b64decode(creator["slot_9d_cert"])
        attest_der = base64.b64decode(creator["attestation_cert"]) if creator.get("attestation_cert") else None

        cert_9c = load_der_certificate(slot_9c_der)
        if not block.signer:
            raise ChainVerificationError("Genesis block must have a signer")

        sig_bytes = base64.b64decode(block.signer.signature)
        if not verify_ecdsa_sha256(cert_9c.public_key(), sig_bytes, block.canonical_bytes()):
            raise ChainVerificationError("Genesis block signature invalid against creator's Slot 9c cert")

        state.members[creator_sid] = MemberState(
            user_sid=creator_sid,
            slot_9c_cert_der=slot_9c_der,
            slot_9d_cert_der=slot_9d_der,
            attestation_cert_der=attest_der,
            wrapped_half_b=creator["wrapped_half_b"],
            permissions=list(CREATOR_PERMISSIONS),
        )

        # Additional initial members
        for m in p.get("initial_members", []):
            sid = m["user_sid"]
            state.members[sid] = MemberState(
                user_sid=sid,
                slot_9c_cert_der=base64.b64decode(m["slot_9c_cert"]),
                slot_9d_cert_der=base64.b64decode(m["slot_9d_cert"]),
                attestation_cert_der=base64.b64decode(m["attestation_cert"]) if m.get("attestation_cert") else None,
                wrapped_half_b=m["wrapped_half_b"],
                permissions=m.get("permissions", DEFAULT_MEMBER_PERMISSIONS),
            )

    def _apply_add_user(self, state: VaultState, block: Block, signer: MemberState) -> None:
        if not has_permission(signer.permissions, VaultPermission.CAN_ADD_USER):
            raise ChainVerificationError(
                f"Signer '{signer.user_sid}' lacks CAN_ADD_USER permission for block {block.index}"
            )

        p = block.payload
        user_sid = p["user_sid"]
        assigned_perms = p.get("permissions", DEFAULT_MEMBER_PERMISSIONS)

        # Validate permission delegation
        if not can_delegate_permissions(signer.permissions, assigned_perms):
            raise ChainVerificationError(
                f"Signer '{signer.user_sid}' lacks CAN_GRANT_PERMISSIONS to assign permissions: {assigned_perms}"
            )

        state.members[user_sid] = MemberState(
            user_sid=user_sid,
            slot_9c_cert_der=base64.b64decode(p["slot_9c_cert"]),
            slot_9d_cert_der=base64.b64decode(p["slot_9d_cert"]),
            attestation_cert_der=base64.b64decode(p["attestation_cert"]) if p.get("attestation_cert") else None,
            wrapped_half_b=p["wrapped_half_b"],
            permissions=assigned_perms,
        )

    def _apply_remove_user(self, state: VaultState, block: Block, signer: MemberState) -> None:
        can_remove = (
            has_permission(signer.permissions, VaultPermission.CAN_ROTATE_EPOCH)
            or has_permission(signer.permissions, VaultPermission.CAN_ADD_USER)
            or has_permission(signer.permissions, VaultPermission.CAN_GRANT_PERMISSIONS)
        )
        if not can_remove:
            raise ChainVerificationError(f"Signer '{signer.user_sid}' not authorized to remove users")

        user_sid = block.payload["user_sid"]
        if user_sid in state.members:
            del state.members[user_sid]

    def _apply_grant_permissions(self, state: VaultState, block: Block, signer: MemberState) -> None:
        target_sid = block.payload["user_sid"]
        new_perms = block.payload["permissions"]

        if not can_delegate_permissions(signer.permissions, new_perms):
            raise ChainVerificationError(
                f"Signer '{signer.user_sid}' lacks CAN_GRANT_PERMISSIONS to grant permissions"
            )

        if target_sid not in state.members:
            raise ChainVerificationError(f"Cannot grant permissions to non-existent member '{target_sid}'")

        state.members[target_sid].permissions = new_perms

    def _apply_rotate_epoch(self, state: VaultState, block: Block, signer: MemberState) -> None:
        if not has_permission(signer.permissions, VaultPermission.CAN_ROTATE_EPOCH):
            raise ChainVerificationError(
                f"Signer '{signer.user_sid}' lacks CAN_ROTATE_EPOCH permission"
            )

        p = block.payload
        state.epoch = block.epoch
        state.half_a_dpapi_ng_b64 = p["half_a_dpapi_ng"]
        state.encrypted_fek_b64 = p["encrypted_fek"]

        # Update wrapped Half_B for remaining active members
        wrapped_for_all: Dict[str, Dict[str, str]] = p["wrapped_half_b_by_user"]
        for sid, wrapped in wrapped_for_all.items():
            if sid in state.members:
                state.members[sid].wrapped_half_b = wrapped

    def _apply_merge(self, state: VaultState, block: Block, signer: MemberState) -> None:
        if len(block.parents) < 2:
            raise ChainVerificationError("MERGE block must reference 2 or more parent hashes")
        # No extra payload mutation required; merging is a DAG synchronization checkpoint
