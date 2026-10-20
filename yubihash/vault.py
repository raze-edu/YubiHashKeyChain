"""
High-Level Vault Orchestration:
- Initialization (Genesis Block + payload encryption)
- Opening & Decrypting (AD DPAPI-NG + YubiKey PIV Slot 9d)
- Peer Synchronization (Discovering new AD members and verifying hardware attestation)
- Epoch Rotation (Handling member revocation and payload re-encryption)
- DAG Concurrency Merge resolution
"""

from __future__ import annotations
import base64
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from yubihash.archive import ArchiveUserKey, BlockPolicy, SecureBlockArchive
from yubihash.backends.base import DirectoryBackend, DpapiNgBackend, YubiKeyBackend
from yubihash.core.attestation import verify_piv_attestation
from yubihash.core.crypto import (
    cert_sha256_fingerprint,
    decrypt_aes_gcm_packed,
    encrypt_aes_gcm_packed,
    is_decryption_certificate,
    is_signing_certificate,
    load_der_certificate,
    wrap_half_b_ecc,
    xor_bytes,
)
from yubihash.core.memory import SecureBuffer
from yubihash.core.permissions import (
    CREATOR_PERMISSIONS,
    DEFAULT_MEMBER_PERMISSIONS,
    VaultPermission,
    has_permission,
)
from yubihash.ledger.block import Block, BlockAction, BlockSigner
from yubihash.ledger.chain import ChainStateProjector, VaultState
from yubihash.ledger.storage import VaultStorage


class VaultOrchestrator:
    """
    Coordinates storage, chain ledger, cryptographic engines, and backend services.
    """

    def __init__(
        self,
        storage: VaultStorage,
        yubikey: YubiKeyBackend,
        dpapi_ng: DpapiNgBackend,
        directory: DirectoryBackend,
        root_ca_cert: Optional[x509.Certificate] = None,
    ):
        self.storage = storage
        self.yubikey = yubikey
        self.dpapi_ng = dpapi_ng
        self.directory = directory
        self.root_ca_cert = root_ca_cert
        self.projector = ChainStateProjector(root_ca_cert=root_ca_cert)

    def _sign_and_save_block(
        self,
        index: int,
        parents: List[str],
        epoch: int,
        action: BlockAction,
        payload: dict,
        signer_sid: str,
        pin: Optional[str] = None,
    ) -> Block:
        block = Block.create(
            index=index,
            parents=parents,
            epoch=epoch,
            action=action,
            payload=payload,
        )
        sig_bytes = self.yubikey.sign_block(block.canonical_bytes(), pin=pin)
        key_id = cert_sha256_fingerprint(self.yubikey.get_signing_certificate())
        block.signer = BlockSigner(
            user_sid=signer_sid,
            key_id=key_id,
            signature=base64.b64encode(sig_bytes).decode("ascii"),
        )
        self.storage.write_block(block)
        return block

    def init_vault(
        self,
        group_sid: str,
        initial_payload: bytes,
        creator_sid: str,
        pin: Optional[str] = None,
        verify_member_attestation: bool = True,
    ) -> Block:
        """
        Phase 2: Initializes the vault on the SMB share:
        1. Generates 256-bit FEK, Half_A, and Half_B.
        2. Encrypts payload with FEK (AES-256-GCM).
        3. Protects Half_A via DPAPI-NG bound to group_sid.
        4. Wraps Half_B for creator and verified AD group members.
        5. Creates and signs genesis.blk.
        """
        self.storage.ensure_directories()

        # Step 1: Generate secrets
        fek = os.urandom(32)
        half_a = os.urandom(32)
        half_b = os.urandom(32)

        with SecureBuffer(fek) as s_fek, SecureBuffer(half_a) as s_ha, SecureBuffer(half_b) as s_hb:
            # Step 2: Compute KEK and encrypt FEK
            kek = xor_bytes(s_ha.to_bytes(), s_hb.to_bytes())
            with SecureBuffer(kek) as s_kek:
                encrypted_fek = encrypt_aes_gcm_packed(s_kek.to_bytes(), s_fek.to_bytes())

            # Step 3: Encrypt payload with FEK and write payload.enc
            encrypted_payload = encrypt_aes_gcm_packed(s_fek.to_bytes(), initial_payload)
            self.storage.write_payload(encrypted_payload)

            # Step 4: Protect Half_A with DPAPI-NG
            protected_half_a = self.dpapi_ng.protect_secret(group_sid, s_ha.to_bytes())

            # Step 5: Wrap Half_B for creator
            creator_9c = self.yubikey.get_signing_certificate()
            creator_9d = self.yubikey.get_decryption_certificate()
            try:
                creator_attest = self.yubikey.get_attestation_certificate("9d")
                attest_der = creator_attest.public_bytes(serialization.Encoding.DER)
            except Exception:
                creator_attest = None
                attest_der = None

            creator_wrapped_b = wrap_half_b_ecc(creator_9d.public_key(), s_hb.to_bytes())

            creator_dict = {
                "user_sid": creator_sid,
                "slot_9c_cert": base64.b64encode(creator_9c.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                "slot_9d_cert": base64.b64encode(creator_9d.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                "attestation_cert": base64.b64encode(attest_der).decode("ascii") if attest_der else None,
                "wrapped_half_b": creator_wrapped_b,
            }

            # Step 6: Discover other initial group members from AD
            initial_members = []
            ad_members = self.directory.get_group_members(group_sid)
            for m in ad_members:
                if m.sid == creator_sid:
                    continue
                certs = self._extract_user_certs(m.certificates)
                if certs:
                    c_9c, c_9d, c_attest = certs
                    if verify_member_attestation and self.root_ca_cert and c_attest:
                        if not verify_piv_attestation(c_9d, c_attest, self.root_ca_cert):
                            continue
                    m_wrapped_b = wrap_half_b_ecc(c_9d.public_key(), s_hb.to_bytes())
                    initial_members.append({
                        "user_sid": m.sid,
                        "slot_9c_cert": base64.b64encode(c_9c.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                        "slot_9d_cert": base64.b64encode(c_9d.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                        "attestation_cert": base64.b64encode(c_attest.public_bytes(serialization.Encoding.DER)).decode("ascii") if c_attest else None,
                        "wrapped_half_b": m_wrapped_b,
                        "permissions": DEFAULT_MEMBER_PERMISSIONS,
                    })

            # Step 7: Create and sign Genesis block
            genesis_payload = {
                "group_sid": group_sid,
                "half_a_dpapi_ng": base64.b64encode(protected_half_a).decode("ascii"),
                "encrypted_fek": base64.b64encode(encrypted_fek).decode("ascii"),
                "creator": creator_dict,
                "initial_members": initial_members,
            }

            return self._sign_and_save_block(
                index=0,
                parents=[],
                epoch=0,
                action=BlockAction.GENESIS,
                payload=genesis_payload,
                signer_sid=creator_sid,
                pin=pin,
            )

    def init_archive(
        self,
        group_sid: str,
        creator_sid: str,
        block_size: int,
        block_count: int,
        policy: Optional[BlockPolicy] = None,
        pin: Optional[str] = None,
        verify_member_attestation: bool = True,
        raw_block_size: bool = False,
    ) -> Tuple[Block, SecureBlockArchive]:
        """
        Initializes an encrypted BinBin archive in the vault on the SMB share.
        Binds decryption to Active Directory group_sid and member YubiKeys.
        Creates genesis.blk and pre-allocates archive.binbin.
        """
        self.storage.ensure_directories()

        fek = os.urandom(32)
        half_a = os.urandom(32)
        half_b = os.urandom(32)

        with SecureBuffer(fek) as s_fek, SecureBuffer(half_a) as s_ha, SecureBuffer(half_b) as s_hb:
            kek = xor_bytes(s_ha.to_bytes(), s_hb.to_bytes())
            with SecureBuffer(kek) as s_kek:
                encrypted_fek = encrypt_aes_gcm_packed(s_kek.to_bytes(), s_fek.to_bytes())

            protected_half_a = self.dpapi_ng.protect_secret(group_sid, s_ha.to_bytes())

            creator_9c = self.yubikey.get_signing_certificate()
            creator_9d = self.yubikey.get_decryption_certificate()
            try:
                creator_attest = self.yubikey.get_attestation_certificate("9d")
                attest_der = creator_attest.public_bytes(serialization.Encoding.DER)
            except Exception:
                creator_attest = None
                attest_der = None

            creator_wrapped_b = wrap_half_b_ecc(creator_9d.public_key(), s_hb.to_bytes())

            creator_dict = {
                "user_sid": creator_sid,
                "slot_9c_cert": base64.b64encode(creator_9c.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                "slot_9d_cert": base64.b64encode(creator_9d.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                "attestation_cert": base64.b64encode(attest_der).decode("ascii") if attest_der else None,
                "wrapped_half_b": creator_wrapped_b,
            }

            initial_members = []
            ad_members = self.directory.get_group_members(group_sid)
            for m in ad_members:
                if m.sid == creator_sid:
                    continue
                certs = self._extract_user_certs(m.certificates)
                if certs:
                    c_9c, c_9d, c_attest = certs
                    if verify_member_attestation and self.root_ca_cert and c_attest:
                        if not verify_piv_attestation(c_9d, c_attest, self.root_ca_cert):
                            continue
                    m_wrapped_b = wrap_half_b_ecc(c_9d.public_key(), s_hb.to_bytes())
                    initial_members.append({
                        "user_sid": m.sid,
                        "slot_9c_cert": base64.b64encode(c_9c.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                        "slot_9d_cert": base64.b64encode(c_9d.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                        "attestation_cert": base64.b64encode(c_attest.public_bytes(serialization.Encoding.DER)).decode("ascii") if c_attest else None,
                        "wrapped_half_b": m_wrapped_b,
                        "permissions": DEFAULT_MEMBER_PERMISSIONS,
                    })

            genesis_payload = {
                "group_sid": group_sid,
                "half_a_dpapi_ng": base64.b64encode(protected_half_a).decode("ascii"),
                "encrypted_fek": base64.b64encode(encrypted_fek).decode("ascii"),
                "creator": creator_dict,
                "initial_members": initial_members,
                "archive": {
                    "block_size": block_size,
                    "block_count": block_count,
                    "raw_block_size": raw_block_size,
                },
            }

            genesis_block = self._sign_and_save_block(
                index=0,
                parents=[],
                epoch=0,
                action=BlockAction.GENESIS,
                payload=genesis_payload,
                signer_sid=creator_sid,
                pin=pin,
            )

            if policy:
                self.storage.write_archive_policy(policy)

            creator_key = ArchiveUserKey(
                user_sid=creator_sid,
                fek=s_fek.to_bytes(),
                permissions=CREATOR_PERMISSIONS,
                epoch=0,
            )

            archive = SecureBlockArchive.create(
                path=self.storage.archive_path,
                block_size=block_size,
                block_count=block_count,
                key=creator_key,
                policy=policy,
                raw_block_size=raw_block_size,
            )

            return genesis_block, archive

    def get_user_key(
        self,
        current_user_sid: str,
        pin: Optional[str] = None,
    ) -> ArchiveUserKey:
        """
        Unwraps and returns the ArchiveUserKey for the current user.
        Authenticates against AD DPAPI-NG (Half_A) and YubiKey Slot 9d (Half_B).
        Includes the user's active permissions and current epoch.
        """
        blocks = self.storage.load_all_blocks()
        state = self.projector.project(blocks)

        member = state.get_member(current_user_sid)
        if not member:
            raise PermissionError(f"User '{current_user_sid}' is not an authorized member in the vault ledger")

        if len(state.tips) > 1:
            self._resolve_dag_merge(state, current_user_sid, pin=pin)
            blocks = self.storage.load_all_blocks()
            state = self.projector.project(blocks)
            member = state.get_member(current_user_sid)

        protected_half_a = base64.b64decode(state.half_a_dpapi_ng_b64)
        raw_half_a = self.dpapi_ng.unprotect_secret(protected_half_a)
        raw_half_b = self.yubikey.unwrap_half_b(member.wrapped_half_b, pin=pin)

        with SecureBuffer(raw_half_a) as s_ha, SecureBuffer(raw_half_b) as s_hb:
            kek = xor_bytes(s_ha.to_bytes(), s_hb.to_bytes())
            with SecureBuffer(kek) as s_kek:
                encrypted_fek = base64.b64decode(state.encrypted_fek_b64)
                fek = decrypt_aes_gcm_packed(s_kek.to_bytes(), encrypted_fek)
                return ArchiveUserKey(
                    user_sid=current_user_sid,
                    fek=fek,
                    permissions=member.permissions,
                    epoch=state.epoch,
                )

    def open_archive(
        self,
        current_user_sid: str,
        pin: Optional[str] = None,
        auto_sync: bool = True,
        auto_rotate: bool = True,
    ) -> SecureBlockArchive:
        """
        Opens the vault's BinBin archive, returning an authorized SecureBlockArchive handle.
        """
        if not self.storage.has_archive():
            raise FileNotFoundError(f"Vault archive file not found: {self.storage.archive_path}")

        user_key = self.get_user_key(current_user_sid, pin=pin)
        policy = self.storage.load_archive_policy()
        archive = SecureBlockArchive.open(self.storage.archive_path, key=user_key, policy=policy)

        if auto_sync:
            blocks = self.storage.load_all_blocks()
            state = self.projector.project(blocks)
            member = state.get_member(current_user_sid)
            if member:
                raw_half_b = self.yubikey.unwrap_half_b(member.wrapped_half_b, pin=pin)
                with SecureBuffer(raw_half_b) as s_hb:
                    self._sync_peers_internal(
                        state=state,
                        current_user_sid=current_user_sid,
                        current_half_b=s_hb.to_bytes(),
                        payload_plaintext=b"",
                        pin=pin,
                        auto_rotate=auto_rotate,
                    )

        return archive

    def open_and_decrypt(
        self,
        current_user_sid: str,
        pin: Optional[str] = None,
        auto_sync: bool = True,
        auto_rotate: bool = True,
    ) -> bytes:
        """
        Phase 3: Opens and decrypts the vault payload:
        1. Loads and verifies Hash-Chain DAG.
        2. Factor 1: Unprotects Half_A via DPAPI-NG and AD Kerberos ticket.
        3. Factor 2: Unwraps Half_B via YubiKey PIV Slot 9d.
        4. Reconstructs KEK = Half_A ^ Half_B, unwraps FEK, and decrypts payload.enc.
        5. Performs peer-to-peer auto-sync and epoch rotation if needed.
        """
        # Step 1: Verify DAG chain
        blocks = self.storage.load_all_blocks()
        state = self.projector.project(blocks)

        member = state.get_member(current_user_sid)
        if not member:
            raise PermissionError(f"User '{current_user_sid}' is not an authorized member in the vault ledger")

        # Handle DAG merge if multiple tips exist
        if len(state.tips) > 1:
            self._resolve_dag_merge(state, current_user_sid, pin=pin)
            blocks = self.storage.load_all_blocks()
            state = self.projector.project(blocks)

        # Step 2: Factor 1 (AD Check via DPAPI-NG)
        protected_half_a = base64.b64decode(state.half_a_dpapi_ng_b64)
        raw_half_a = self.dpapi_ng.unprotect_secret(protected_half_a)

        # Step 3: Factor 2 (YubiKey Check via Slot 9d)
        raw_half_b = self.yubikey.unwrap_half_b(member.wrapped_half_b, pin=pin)

        # Step 4: Reconstruct and decrypt
        with SecureBuffer(raw_half_a) as s_ha, SecureBuffer(raw_half_b) as s_hb:
            kek = xor_bytes(s_ha.to_bytes(), s_hb.to_bytes())
            with SecureBuffer(kek) as s_kek:
                encrypted_fek = base64.b64decode(state.encrypted_fek_b64)
                fek = decrypt_aes_gcm_packed(s_kek.to_bytes(), encrypted_fek)
                with SecureBuffer(fek) as s_fek:
                    encrypted_payload = self.storage.read_payload()
                    decrypted_payload = decrypt_aes_gcm_packed(s_fek.to_bytes(), encrypted_payload)

            # Step 5: Phase 4 Peer-to-Peer Auto-Sync while Half_B is in memory
            if auto_sync:
                self._sync_peers_internal(
                    state=state,
                    current_user_sid=current_user_sid,
                    current_half_b=s_hb.to_bytes(),
                    payload_plaintext=decrypted_payload,
                    pin=pin,
                    auto_rotate=auto_rotate,
                )

            return decrypted_payload

    def _resolve_dag_merge(self, state: VaultState, signer_sid: str, pin: Optional[str] = None) -> None:
        """Creates a MERGE block to consolidate concurrent branch tips."""
        new_index = state.max_index + 1
        tips_list = sorted(list(state.tips))
        self._sign_and_save_block(
            index=new_index,
            parents=tips_list,
            epoch=state.epoch,
            action=BlockAction.MERGE,
            payload={"merged_tips": tips_list},
            signer_sid=signer_sid,
            pin=pin,
        )

    def _sync_peers_internal(
        self,
        state: VaultState,
        current_user_sid: str,
        current_half_b: bytes,
        payload_plaintext: bytes,
        pin: Optional[str],
        auto_rotate: bool,
    ) -> None:
        """
        Discovers new AD members and departed members.
        Appends ADD_USER or ROTATE_EPOCH blocks.
        """
        signer_member = state.get_member(current_user_sid)
        if not signer_member:
            return

        ad_members = self.directory.get_group_members(state.group_sid)
        ad_sids = {m.sid for m in ad_members}
        active_chain_sids = set(state.members.keys())

        # 1. Detect departed members
        departed_sids = active_chain_sids - ad_sids
        if departed_sids and auto_rotate and has_permission(signer_member.permissions, VaultPermission.CAN_ROTATE_EPOCH):
            self.rotate_epoch(
                current_user_sid=current_user_sid,
                payload_plaintext=payload_plaintext,
                pin=pin,
            )
            return

        # 2. Detect new members to add
        new_sids = ad_sids - active_chain_sids
        if new_sids and has_permission(signer_member.permissions, VaultPermission.CAN_ADD_USER):
            for ad_user in ad_members:
                if ad_user.sid in new_sids:
                    certs = self._extract_user_certs(ad_user.certificates)
                    if certs:
                        c_9c, c_9d, c_attest = certs
                        if self.root_ca_cert and c_attest:
                            if not verify_piv_attestation(c_9d, c_attest, self.root_ca_cert):
                                continue

                        wrapped_b = wrap_half_b_ecc(c_9d.public_key(), current_half_b)
                        add_payload = {
                            "user_sid": ad_user.sid,
                            "slot_9c_cert": base64.b64encode(c_9c.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                            "slot_9d_cert": base64.b64encode(c_9d.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                            "attestation_cert": base64.b64encode(c_attest.public_bytes(serialization.Encoding.DER)).decode("ascii") if c_attest else None,
                            "wrapped_half_b": wrapped_b,
                            "permissions": DEFAULT_MEMBER_PERMISSIONS,
                        }
                        # Reload state to get latest tips
                        cur_blocks = self.storage.load_all_blocks()
                        cur_state = self.projector.project(cur_blocks)
                        self._sign_and_save_block(
                            index=cur_state.max_index + 1,
                            parents=sorted(list(cur_state.tips)),
                            epoch=cur_state.epoch,
                            action=BlockAction.ADD_USER,
                            payload=add_payload,
                            signer_sid=current_user_sid,
                            pin=pin,
                        )

    def rotate_epoch(
        self,
        current_user_sid: str,
        payload_plaintext: Optional[bytes] = None,
        pin: Optional[str] = None,
    ) -> Block:
        """
        Generates brand-new FEK, Half_A, and Half_B.
        Re-encrypts payload or archive and wraps new Half_B only for active, verified AD members.
        """
        cur_blocks = self.storage.load_all_blocks()
        state = self.projector.project(cur_blocks)

        signer_member = state.get_member(current_user_sid)
        if not signer_member or not has_permission(signer_member.permissions, VaultPermission.CAN_ROTATE_EPOCH):
            raise PermissionError(f"User '{current_user_sid}' lacks CAN_ROTATE_EPOCH permission")

        ad_members = self.directory.get_group_members(state.group_sid)
        ad_sids = {m.sid for m in ad_members}

        # Keep only members that are still in Active Directory
        valid_members = [m for sid, m in state.members.items() if sid in ad_sids]

        new_fek = os.urandom(32)
        new_half_a = os.urandom(32)
        new_half_b = os.urandom(32)
        new_epoch = state.epoch + 1

        with SecureBuffer(new_fek) as s_fek, SecureBuffer(new_half_a) as s_ha, SecureBuffer(new_half_b) as s_hb:
            # Re-encrypt payload.enc if present
            if payload_plaintext is not None and (self.storage.payload_path.exists() or not self.storage.has_archive()):
                encrypted_payload = encrypt_aes_gcm_packed(s_fek.to_bytes(), payload_plaintext)
                self.storage.write_payload(encrypted_payload)

            # Re-encrypt archive.binbin if present
            if self.storage.has_archive():
                new_key = ArchiveUserKey(
                    user_sid=current_user_sid,
                    fek=s_fek.to_bytes(),
                    permissions=signer_member.permissions,
                    epoch=new_epoch,
                )
                archive = self.open_archive(current_user_sid, pin=pin, auto_sync=False, auto_rotate=False)
                archive.rekey_for_epoch(new_key)

            # Re-protect Half_A with DPAPI-NG
            new_protected_a = self.dpapi_ng.protect_secret(state.group_sid, s_ha.to_bytes())

            # Re-encrypt FEK with new KEK
            kek = xor_bytes(s_ha.to_bytes(), s_hb.to_bytes())
            with SecureBuffer(kek) as s_kek:
                new_encrypted_fek = encrypt_aes_gcm_packed(s_kek.to_bytes(), s_fek.to_bytes())

            # Wrap new Half_B for each valid member
            wrapped_by_user = {}
            for m in valid_members:
                cert_9d = load_der_certificate(m.slot_9d_cert_der)
                wrapped_by_user[m.user_sid] = wrap_half_b_ecc(cert_9d.public_key(), s_hb.to_bytes())

            rotate_payload = {
                "half_a_dpapi_ng": base64.b64encode(new_protected_a).decode("ascii"),
                "encrypted_fek": base64.b64encode(new_encrypted_fek).decode("ascii"),
                "wrapped_half_b_by_user": wrapped_by_user,
            }

            return self._sign_and_save_block(
                index=state.max_index + 1,
                parents=sorted(list(state.tips)),
                epoch=new_epoch,
                action=BlockAction.ROTATE_EPOCH,
                payload=rotate_payload,
                signer_sid=current_user_sid,
                pin=pin,
            )

    def _extract_user_certs(
        self, cert_ders: List[bytes]
    ) -> Optional[Tuple[x509.Certificate, x509.Certificate, Optional[x509.Certificate]]]:
        """
        Distinguishes Slot 9c, Slot 9d, and Attestation certs from userCertificate attribute:
        1. Checks KeyUsage: digitalSignature -> 9c; keyEncipherment/keyAgreement -> 9d.
        2. Checks for Yubico OIDs -> Attestation cert.
        """
        c_9c = None
        c_9d = None
        c_attest = None

        for der in cert_ders:
            try:
                cert = load_der_certificate(der)
            except Exception:
                continue

            # Check for Yubico attestation extension
            from yubihash.core.attestation import OID_YUBICO_TOUCH_POLICY
            has_yubico_oid = False
            try:
                cert.extensions.get_extension_for_oid(OID_YUBICO_TOUCH_POLICY)
                has_yubico_oid = True
            except Exception:
                pass

            if has_yubico_oid:
                c_attest = cert
            elif is_signing_certificate(cert) and not is_decryption_certificate(cert):
                c_9c = cert
            elif is_decryption_certificate(cert):
                c_9d = cert
            elif c_9c is None:
                c_9c = cert

        if c_9c and c_9d:
            return c_9c, c_9d, c_attest
        return None
