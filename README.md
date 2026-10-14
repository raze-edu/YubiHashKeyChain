# YubiHashKeyChain: Serverless AD + YubiKey Hash-Chain Vault

A domain-wide, serverless file encryption system stored on an SMB share. It binds decryption to **both** an Active Directory Security Group (independent of the specific Windows workstation) and a physical **YubiKey**, with a **Local Cryptographic Hash-Chain (Git-style DAG ledger)** to eliminate Active Directory key-poisoning and SMB race conditions.

---

## 1. Cryptographic Formula

The File Encryption Key ($\text{FEK}$) is split across two independent factors:

$$\text{KEK} = \text{Half}_A \oplus \text{Half}_B$$
$$\text{FEK} = \text{AES-GCM-Decrypt}_{\text{KEK}}(\text{Encrypted\_FEK})$$

1. **$\text{Half}_A$ (256-bit random secret):** Protected via Windows **CNG DPAPI-NG (`NCryptProtectSecret`)** bound to the Active Directory Group SID (`SID=S-1-5-21-...`). Unwrapped transparently via the Domain Controller's KDS Root Key on any domain-joined Windows machine.
2. **$\text{Half}_B$ (256-bit random secret):** Protected individually for each group member's **YubiKey PIV Slot `9d` (Key Management)** public key using ECC P-256 (ECDH + HKDF-SHA256 + AES-256-GCM).
3. **The Hash-Chain DAG Ledger (`genesis.blk` + `blocks/`):** An append-only sequence of Canonical JSON (RFC 8785) blocks chained via $\text{SHA-256}$ and signed by an authorized member's **YubiKey PIV Slot `9c` (Digital Signature)**. Supports DAG merge commits for concurrent SMB operations.
4. **Granular Capability Delegation:** Dynamic permissions (`CAN_READ`, `CAN_ADD_USER`, `CAN_ROTATE_EPOCH`, `CAN_GRANT_PERMISSIONS`) enforced directly along the chain.

---

## 2. File System Layout (SMB Share)

```
\\domain.local\share\SecureVault\
│
├── payload.enc               # Encrypted vault file (AES-256-GCM)
├── genesis.blk               # Block 0: Initial group state, Half_A blob, creator signatures
└── blocks\                   # Append-only state transition blocks
    ├── 0001_a8f9c2.blk       # Block 1: Added User B (Signed by User A)
    ├── 0002_7b3d1e.blk       # Block 2: Added User C
    └── 0003_f4c10a.blk       # Block 3: DAG Merge or Epoch Rotation
```

---

## 3. Installation & Requirements

### Windows Domain Requirements
1. **Domain Controller KDS Root Key:** Run once on a Domain Controller in PowerShell:
   ```powershell
   Add-KdsRootKey -EffectiveImmediately
   ```
2. **Active Directory Security Group:** Create a security group (e.g. `SG_Vault_Access`).

### Local Dependencies
```bash
pip install -e .
```

---

## 4. CLI Usage

The tool provides the `yubihash` CLI (or `python -m yubihash.cli`):

### Phase 1: Onboard User YubiKey
Exports Slot `9c` (Signing), Slot `9d` (Decryption), and Slot `f9` (Hardware Attestation) certificates and uploads them to the user's `userCertificate` attribute in Active Directory:
```bash
yubihash onboard
```

### Phase 2: Initialize Vault (Genesis Block)
Encrypts an initial payload file and initializes the vault on the SMB share:
```bash
yubihash init --vault-dir "\\domain.local\share\SecureVault" --group-sid "S-1-5-21-..." --input-file "secrets.txt"
```

### Phase 3: Open & Decrypt Vault
Unwraps $\text{Half}_A$ via AD DPAPI-NG and $\text{Half}_B$ via YubiKey PIV Slot `9d`, reconstructs $\text{KEK}$, decrypts the payload, and automatically syncs new group members:
```bash
yubihash open --vault-dir "\\domain.local\share\SecureVault" --output-file "decrypted_secrets.txt"
```

### Phase 4: Peer Synchronization & Epoch Rotation
Sync new members from Active Directory into the ledger:
```bash
yubihash sync --vault-dir "\\domain.local\share\SecureVault"
```

Explicitly rotate vault keys ($\text{FEK}$, $\text{Half}_A$, $\text{Half}_B$) and re-encrypt the payload:
```bash
yubihash rotate-epoch --vault-dir "\\domain.local\share\SecureVault" --payload-file "current_payload.txt"
```

### Inspect Vault State & DAG History
Displays the current epoch, active members, permissions, and DAG tips:
```bash
yubihash inspect --vault-dir "\\domain.local\share\SecureVault"
```

---

## 5. Python API & Architecture

The package is built with clean adapter abstractions:

- `yubihash.backends.base`: Abstract interfaces (`YubiKeyBackend`, `DpapiNgBackend`, `DirectoryBackend`)
- `yubihash.backends.live`: Native Windows `ncrypt.dll` DPAPI-NG, official `yubikit`/`ykman` PIV, and `ldap3` Kerberos
- `yubihash.backends.mock`: Software-simulated YubiKey, simulated DPAPI-NG, and in-memory directory for testing
- `yubihash.core.memory`: Secure buffers with Windows `VirtualLock` and `RtlSecureZeroMemory`
- `yubihash.vault.VaultOrchestrator`: High-level operations (init, open, sync, rotate)

---

## 6. Running Tests

All unit, integration, and simulation tests reside in the `tests/` directory:

```bash
pytest tests/ -v
```
