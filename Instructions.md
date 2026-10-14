# Serverless AD \+ YubiKey Hash-Chain Vault: Architectural Blueprint

## 1\. Executive Summary & Cryptographic Formula

This architecture enables domain-wide, serverless file encryption stored on an SMB share. It binds decryption to **both** an Active Directory Security Group (independent of the specific Windows PC) and a physical **YubiKey**, while using a **Local Cryptographic Hash-Chain (Git-style ledger)** to prevent Active Directory key-poisoning and SMB race conditions.

The core cryptographic equation for unwrapping the **File Encryption Key ($\text{FEK}$)** is:

$$\text{KEK} = \text{Half}_A \oplus \text{Half}_B$$
$$\text{FEK} = \text{AES-GCM-Decrypt}_{\text{KEK}}(\text{Encrypted\_FEK})$$

* **$\text{Half}_A$ (256-bit random secret):** Protected via Windows **CNG DPAPI-NG (`NCryptProtectSecret`)** bound to the Active Directory Group SID (`SID=S-1-5-21-...`). Unwrapped transparently via the Domain Controller's KDS Root Key on any domain-joined PC.  
* **$\text{Half}_B$ (256-bit random secret):** Protected individually for each group member's **YubiKey PIV Slot `9d` (Key Management)** public key using ECIES or RSA-OAEP.  
* **The Hash-Chain Ledger (`vault.chain`):** An append-only sequence of JSON blocks where every user addition, revocation, or key rotation is chained via $\text{SHA-256}$ and signed by an authorized member's **YubiKey PIV Slot `9c` (Digital Signature)**.

---

## 2\. Core Components Needed

### A. Active Directory & Windows Infrastructure

1. **Domain Controller KDS Root Key:** Required for DPAPI-NG (`ncrypt.dll`) to encrypt/decrypt data bound to an AD Group SID across any PC.  
   * *Command (Run once on DC):* `Add-KdsRootKey -EffectiveImmediately`  
2. **AD Security Group:** A dedicated group (e.g., `SG_Vault_Access`) whose `objectSid` governs $\text{Half}_A$.
3. **AD User Attributes (`userCertificate`):** Stores each user's exported YubiKey PIV public certificates (Slot `9c` for signing blocks, Slot `9d` for decrypting $\text{Half}_B$) so peers can discover new members via LDAP.

### B. YubiKey Hardware Configuration (Per User)

We utilize two distinct PIV slots on each YubiKey to enforce cryptographic separation of duties:

* **PIV Slot `9c` (Digital Signature):** Signs and validates Hash-Chain blocks (State transitions, adding/removing users). Configured with `pin-policy=always` and `touch-policy=always`.  
* **PIV Slot `9d` (Key Management):** Decrypts the user's wrapped copy of $\text{Half}_B$. Configured with `pin-policy=once` and `touch-policy=always`.  
* **PIV Slot `f9` (Attestation):** Used during onboarding/sync to cryptographically prove that the public key stored in Active Directory was actually generated on genuine YubiKey hardware (preventing software key injection).

### C. File System Layout (On the SMB Share)

Instead of a single monolithic file, separate the payload from the ledger to avoid race conditions and large re-writes during group syncs:

```
\\domain.local\share\SecureVault\
│
├── payload.enc               # The actual file encrypted with FEK (AES-256-GCM)
├── genesis.blk               # Block 0: Initial group state, Half_A blob, and Root Signatures
└── blocks\                   # Append-only state transition blocks
    ├── 0001_a8f9c2.blk       # Block 1: Added User C (Signed by User A)
    └── 0002_7b3d1e.blk       # Block 2: Countersignature / Key Rotation
```

&nbsp;

---

## 3\. Recommended Python Libraries

| Library / Module | Purpose in the Architecture | Why This Specific Library? |
| :---- | :---- | :---- |
| **`cryptography`** | AES-256-GCM payload encryption, RSA-OAEP / ECDH wrapping of $\text{Half}_B$, X.509 certificate parsing, and $\text{SHA-256}$ block hashing. | Industry-standard, Rust-backed CFFI bindings to OpenSSL. Fast and memory-safe. |
| **`yubikit` & `yubikey-manager`** | Communicating directly with the YubiKey's PIV applet (`PivSession`) to sign blocks (Slot `9c`), decrypt $\text{Half}_B$ (Slot `9d`), and verify hardware attestation. | Official Yubico Python SDK. Avoids fragile CLI wrapper calls (`subprocess`) and handles smart card APDUs natively. |
| **`pyscard`** | Low-level PC/SC smart card interface (dependency of `yubikit`). | Detects YubiKey insertion/removal events in real time. |
| **`ctypes` (Built-in)** | Calling Windows native `ncrypt.dll` (`NCryptCreateProtectionDescriptor`, `NCryptProtectSecret`, `NCryptUnprotectSecret`). | Python has no pip package for **DPAPI-NG** (note: `pywin32`'s `CryptProtectData` only does legacy local-PC DPAPI, *not* AD-Group SID DPAPI-NG). `ctypes` is mandatory here. |
| **`ldap3` or `msactive-directory`** | Querying the Domain Controller via SASL/Kerberos (current signed-in Windows user) to fetch group members and their `userCertificate` attributes. | Pure Python LDAP client that supports Windows SSPI/GSSAPI (Kerberos pass-through authentication without asking the user for their AD password). |
| **`winkerberos` / `pyspnego`** | Implicit Windows authentication for `ldap3`. | Allows the script to query AD using the currently logged-in Windows session token automatically. |

&nbsp;

---

## 4\. Step-by-Step Implementation Instructions

### Phase 1: YubiKey Provisioning (Onboarding a User)

Every user joining the system runs an onboarding script once on their domain PC:

1. Generate an ECCP256 or RSA-2048 keypair in **Slot `9c`** (Signing) and **Slot `9d`** (Decryption).  
2. Generate a hardware attestation certificate for both slots using `yubikit.piv` (`attest()`).  
3. Bundle the Slot `9c` cert, Slot `9d` cert, and the YubiKey Hardware Attestation cert, and upload them to the user's own `userCertificate` attribute in Active Directory (or have an admin publish them).

### Phase 2: Vault Initialization (`Genesis Block`)

The creator initializes the encrypted vault:

1. Generate random 256-bit $\text{FEK}$, $\text{Half}_A$, and $\text{Half}_B$.
2. Compute $\text{KEK} = \text{Half}_A \oplus \text{Half}_B$ and encrypt $\text{FEK}$ with $\text{KEK}$.
3. Call `ncrypt.dll` \-\> `NCryptProtectSecret` with descriptor `"SID=<AD_GROUP_SID>"` on $\text{Half}_A$.  
4. Query AD for all current members of the AD Group. Verify each member's YubiKey Attestation certificate against Yubico's Root CA (proving the key lives on a physical YubiKey).  
5. Wrap $\text{Half}_B$ for each verified member's Slot `9d` public key.  
6. Construct `genesis.blk` (Block `0`), compute its $\text{SHA-256}$ hash, and sign the hash using the creator's YubiKey **Slot `9c`**.

### Phase 3: Decryption & Chain Verification (Any AD PC)

When any user runs the script to open the file:

1. **Verify the Hash-Chain First:**  
   * Read `genesis.blk` and all sequential `.blk` files in `blocks\`.  
   * Verify that each block's `prev_hash` matches the $\text{SHA-256}$ of the preceding block.  
   * Verify that every block's signature was signed by a YubiKey **Slot `9c`** public key that was *already authorized* in a preceding block (or meets your $M$\-of\-$N$ multi-sig threshold).  
2. **Factor 1 (Windows AD Check):**  
   * Pass `half_a_dpapi_ng` from the latest epoch block to `ncrypt.dll` \-\> `NCryptUnprotectSecret`.  
   * Windows silently contacts the Domain Controller using the signed-in user's Kerberos ticket. If valid, $\text{Half}_A$ is returned into RAM.  
3. **Factor 2 (YubiKey Hardware Check):**  
   * Locate the signed-in user's SID in the current state derived from the blockchain.  
   * Send `encrypted_half_b` to the local YubiKey **Slot `9d`**.  
   * Prompt for YubiKey PIN and physical touch. Receive $\text{Half}_B$ in RAM.  
4. **Reconstruct & Decrypt:**  
   * XOR $\text{Half}_A$ and $\text{Half}_B$ in memory to get $\text{KEK}$, unwrap $\text{FEK}$, and decrypt `payload.enc`.

### Phase 4: Peer-to-Peer Auto-Sync (Adding/Removing Users)

While the authorized user still holds $\text{Half}_B$ in memory during Phase 3:

1. Query LDAP for the current members of the AD Group.  
2. **If a new AD Group member is found** who is not in the blockchain's active state:  
   * Fetch their certificates from AD and **verify the YubiKey PIV Attestation signature**.  
   * Encrypt $\text{Half}_B$ with their Slot `9d` public key.  
   * Create a new `ADD_USER` block referencing the latest `prev_hash`, sign it with the current user's YubiKey **Slot `9c`**, and write `000X_<hash>.blk` to the `blocks\` folder.

---

## 5\. Critical Things to Be Aware Of (Keynotes & Gotchas)

* **Memory Hygiene in Python:** Python strings and `bytes` objects are **immutable** and garbage-collected unpredictably, meaning raw keys ($\text{FEK}$, $\text{Half}_A$, $\text{Half}_B$) can linger in RAM or get paged to `pagefile.sys`.  
  * *Mitigation:* Store sensitive key material in mutable `bytearray` or `ctypes` buffers, call Windows `VirtualLock` via `ctypes` to prevent paging to disk, and explicitly zero-out (`memset` to `0`) the buffers immediately after decrypting the payload.  
* **YubiKey PIV Attestation is Non-Negotiable:** Because Active Directory is only used as a lookup directory for public keys, never trust an X.509 certificate in AD unless you verify its **PIV Attestation chain** back to the *Yubico PIV Root CA*. This mathematically guarantees the private key was generated *inside* a physical YubiKey chip and can never be exported.  
* **Kerberos Ticket Caching on Group Changes:** When an admin adds a user to the AD Security Group, that user's local Windows PC will **not** know they are in the group until their Kerberos TGT refreshes. Your Python script should catch the `NTE_BAD_KEY_STATE` / `ERROR_ACCESS_DENIED` return code from `NCryptUnprotectSecret` and automatically run `subprocess.run(["klist", "purge"])` to force Windows to fetch a fresh Kerberos ticket from the Domain Controller.  
* **True Revocation Requires a New "Epoch" Block:** Removing a user from the AD Group immediately stops them from unwrapping $\text{Half}_A$ via the Domain Controller. However, if they previously cached $\text{Half}_A$, they could still decrypt the old file offline. Therefore, when the sync routine detects a user was *removed* from the AD group, it should generate a `ROTATE_EPOCH` block: generating a brand-new $\text{FEK}$, $\text{Half}_A$, and $\text{Half}_B$, re-encrypting the payload, and wrapping the new $\text{Half}_B$ only for the remaining valid members.  
* **Handling SMB Forking (Split-Brain Chains):** If User A and User B open the file at the exact same millisecond and both write `0004_aaaa.blk` and `0004_bbbb.blk` when syncing a new user, your chain verifier shouldn't crash. Because additive `ADD_USER` blocks commute, the next client can simply create block `0005` referencing *both* parent hashes (a DAG / Git merge commit).