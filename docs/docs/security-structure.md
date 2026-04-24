---
sidebar_position: 6
title: Security Structure
---
# Security Structure

This document describes the security measures applied to BastionVault's data-at-rest and key-management paths across every surface — the vault core, the desktop GUI, the cloud storage targets, and the per-vault keystore.

It is the authoritative reference for reviewers and operators. When an implementation detail changes, update this document alongside the code.

---

## 1. Data-at-rest on the vault core

Every byte written into the vault's logical namespace (`secret/`, `auth/`, `sys/`, `identity/`, …) passes through the **barrier** before reaching storage. The barrier is the vault's envelope encryption layer.

- **Cipher**: `ChaCha20-Poly1305` AEAD, 256-bit key, 96-bit nonce. Nonces are randomly generated per write.
- **Key hierarchy**: a root master key (unseal key, split into Shamir shares at `init` time) wraps a rotating data-encryption key (the *keyring*), which encrypts every stored entry. Key rotation (`sys/rotate`) mints a new keyring entry without re-encrypting the data — old ciphertexts stay readable via their embedded key-epoch tag.
- **Post-quantum posture**: symmetric 256-bit keys survive Grover's algorithm with ~128 effective bits — within the NIST PQC-safe envelope. The asymmetric operations (identity, key wrapping) use `ML-KEM-768` for key establishment and `ML-DSA-65` for signatures, both NIST-standardised PQC schemes.
- **TLS**: `rustls` with the `aws-lc-rs` backend and the `X25519MLKEM768` hybrid PQC key-exchange group — in-transit data is PQC-protected from vault ↔ client round-trips.

No OpenSSL / Tongsuo / libxmlsec1 C dependencies. The whole crypto stack is pure Rust with vetted crates (`chacha20poly1305`, `ml-kem`, `ml-dsa`, `rsa`, `x509-parser`).

---

## 2. Desktop-GUI keystore (local-key + vault-keys file)

The Tauri desktop app hosts multiple saved vaults (Local file, Local Hiqlite, Remote BastionVault server, Cloud-backed S3 / OneDrive / Google Drive / Dropbox). Each vault has its own unseal key. We store those keys on the operator's machine so a normal launch doesn't require re-entering them — but we do it without letting any one vault's key stomp on another's.

### 2.1 The two layers

```
         OS keychain
         ┌────────────────────────────────────────┐
         │ bastion-vault-gui / local-master-key   │  32 random bytes
         │                        (hex-encoded)   │  (the Local Key)
         └──────────────┬─────────────────────────┘
                        │ decrypts
                        ▼
         ┌────────────────────────────────────────┐
         │ <data_local>/.bastion_vault_gui/       │
         │   vault-keys.enc                       │
         │                                        │
         │  BVK\x01 ‖ nonce(12) ‖                 │
         │  ChaCha20-Poly1305(plaintext, key)     │
         │                                        │
         │  plaintext = {                         │
         │    version: 1,                         │
         │    vaults: {                           │
         │      "<vault-id-1>": { key, token },   │
         │      "<vault-id-2>": { key, token },   │
         │      …                                 │
         │    }                                   │
         │  }                                     │
         └────────────────────────────────────────┘
```

- **Local Key**: one 32-byte symmetric key per installation. Minted on first launch via `rand::rng().fill_bytes()` and persisted to the OS keychain (`bastion-vault-gui / local-master-key`). This is the ONLY credential the keychain ever holds for BastionVault.
- **vault-keys.enc**: ChaCha20-Poly1305 AEAD envelope. Nonce = 12 random bytes per write. Header = 4-byte magic `BVK\x01` so future format versions can be detected cleanly. The file is written atomically (tmp-then-rename + `fsync`) so a crash mid-write can't leave a partial-ciphertext state that would permanently lock out every vault.
- **Scope**: the file lives outside any storage-kind subdirectory, so switching a profile between File / Hiqlite / Cloud does not require moving the keystore.

### 2.2 Why two layers

Earlier revisions stored each vault's unseal key directly in the keychain (`bastion-vault-gui / unseal-key`, one entry total). Initialising a second vault overwrote the first entry; switching back tried to unseal vault A with vault B's key and failed with "BastionVault unseal failed." The two-layer model indexes records by vault id inside the encrypted file, so adding vaults never touches existing entries.

Splitting the local key from the per-vault secrets also means an operator who wants to rotate "everything stored locally" just has to delete the local-master-key keychain entry — the next launch regenerates it and prompts to re-enter each vault's unseal key, without leaving plaintext remnants.

### 2.3 Threat model

| Threat | Mitigation |
|---|---|
| Disk theft (file-only) | Local key lives in OS keychain, not the file. Attacker has ciphertext but no key. |
| Keychain theft (key-only) | File only exists in the data_local directory. Attacker has key but no ciphertext. |
| Both compromised | Expected failure. Operator must treat as total key compromise and rotate every vault's unseal key via `sys/rotate` + re-seal + re-init GUI. |
| Malicious process on the same user account | Can read keychain + file, same as the operator. The OS keychain is not a sandbox against same-user code. This is an inherent limit of every "password manager" — not specific to BastionVault. |
| Quantum adversary with stored ciphertext | ChaCha20-Poly1305 with a 256-bit key gives ~128-bit PQC-safe strength (Grover). The ML-KEM envelope in § 2.5 raises the bar further by making the PQC private-key material itself a prerequisite for decryption. |

### 2.4 Migration from the legacy single-slot layout

On first launch after upgrade, `local_keystore::get_unseal_key(vault_id)` checks the legacy keychain slots (`unseal-key` / `root-token`). If present AND the target `vault_id` has no record yet in the encrypted file, the values are copied over, then the legacy slots are purged via `secure_store::delete_all_keys()`. The migration path runs from every `get_*` call and is idempotent — re-running after a partial failure just re-copies the same values and no-ops the purge.

### 2.5 ML-KEM envelope (shipped — v2 file format)

The on-disk layout is now **`BVK\x02`**. The plaintext JSON is wrapped in a KEM/DEM envelope:

```
plaintext JSON
     │
     ▼
 ChaCha20-Poly1305 (content key = 32 random bytes per save)
     │
     ▼                       ┌─ per unlock slot ─┐
 payload_ct + payload_nonce  │  ML-KEM-768       │
                             │  encapsulate to   │
                             │  slot's ek        │
                             │     │             │
                             │     ▼             │
                             │  (kem_ct,         │
                             │   shared_secret)  │
                             │     │             │
                             │     ▼             │
                             │  HKDF(ss, "…      │
                             │  wrap-v1")        │
                             │     │             │
                             │     ▼             │
                             │  ChaCha20-Poly1305│
                             │  (wrap_key, nonce,│
                             │   content_key)    │
                             │     │             │
                             │     ▼             │
                             │  wrapped_content  │
                             │  _key (48 bytes)  │
                             └───────────────────┘
```

Each unlock slot stores its ML-KEM encapsulation key (`ek`), its KEM ciphertext (`kem_ct`), a fresh wrap nonce, and the wrapped content key. Opening the file tries each slot in turn until one decapsulates successfully; saving re-encapsulates against every slot's `ek` (so the operator does not need every registered YubiKey physically present for every save — only to *open* with a given slot).

The Local Key continues to live in the OS keychain. Its role is narrowed: it is no longer an AEAD key, it is *an HKDF input* for a 64-byte ML-KEM seed. That seed deterministically re-generates the ML-KEM-768 keypair on every open. A quantum adversary that captures the on-disk file and the Local Key still has to break ML-KEM-768 to recover the content key; a quantum adversary without the Local Key has no path at all.

Crate: `bv_crypto` (the vault core's own PQC stack) is reused so the GUI inherits the same well-tested `MlKem768Provider` + `KemDemEnvelopeV1` primitives.

---

## 3. YubiKey failsafe (shipped)

The keychain-anchored Local Key gives good-enough protection for most desktop operators, but we also want a path that survives OS-level compromise of the keychain. A YubiKey-anchored recovery flow is the planned Phase 2.

### 3.1 Why not PQC-on-device

Current YubiKey firmware (5.7 and earlier) does not store NIST PQC keys — PIV slots are limited to RSA (1024 / 2048 / 3072 / 4096) and ECC (P-256 / P-384 / Ed25519). A pure-YubiKey-signs-the-ciphertext design cannot therefore be PQC on the hardware side.

### 3.2 The signature-seed construction

We use the YubiKey's traditional signing key as the *seed source* for a PQC key that we derive on every open, rather than as the encryption primitive directly:

```
 salt  ────────► YubiKey PIV sign ────► signature
                 (RSA-PKCS1 or
                  deterministic ECDSA,
                  RFC 6979)
                                         │
                                         ▼
                 HKDF-SHA-256(ikm = signature,
                              salt = salt,
                              info = "bastion-vault / yubikey-seed-v1")
                                         │
                                         ▼
                                  32-byte seed
                                         │
                                         ▼
                 ML-KEM-768 deterministic key generation
                                         │
                                         ▼
                      (ek, dk) — ephemeral per-open keypair
                                         │
                                         ▼
                 Decapsulate file's KEM ciphertext → shared secret
                                         │
                                         ▼
                 ChaCha20-Poly1305 decrypt vault-keys.enc
```

Properties:

- **Deterministic signature → reproducible seed**. RSA-PKCS1v15 signatures are deterministic by construction. ECDSA signatures are deterministic when the nonce follows RFC 6979, which all current YubiKey firmwares do. The same (salt, private-key) pair always produces the same seed and therefore the same ML-KEM keypair.
- **Salt stored openly next to the ciphertext**. The salt is 32 random bytes minted per YubiKey at registration time. Storing it openly is intentional — the security of the scheme rests on the YubiKey's private key, not the salt.
- **No private key material ever leaves the YubiKey.** The signature is computed on-card. HKDF + ML-KEM keygen happen in the host process from the signature value.
- **Spare YubiKeys**: each registered YubiKey has its own (salt, public-key-for-identification, ML-KEM-wrapped-content-key) triple in the file header. Decryption tries each in turn until one succeeds. Operators can register N keys and lose N-1 without being locked out.

### 3.3 Registration flow

On `init_embedded` (first-vault init), the GUI presents three options:

1. **Keychain only** — today's behaviour. Local key lives in the OS keychain.
2. **Keychain + YubiKey** — both unlock paths are registered. Either one can decrypt. Matches the "I travel without my keychain sometimes" operator.
3. **YubiKey only** — the Local Key is never stored in the keychain at all. Losing every registered YubiKey means losing every vault (same property as losing a physical hardware security module without a backup).

Later, from Settings → Security → "Register spare YubiKey", operators add additional keys. Each registration opens the file with one of the currently-registered paths, re-encrypts it so the new key's wrapped-content-key lives alongside the existing ones, and writes the updated file atomically.

### 3.4 Crate + integration

Shipped on [`yubikey = "0.8"`](https://crates.io/crates/yubikey) — pure-Rust PIV client. The bridge module (`gui/src-tauri/src/yubikey_bridge.rs`) exposes `list_devices` + `load_signing_public_key` + `sign` and nothing else; the keystore wraps these with HKDF → ML-KEM seed derivation. Tauri commands under `commands::yubikey` surface enrolment / removal to the GUI; the Settings page "YubiKey Failsafe" card drives the ceremony.

Hardware-dependent tests are marked `#[ignore]` — run explicitly with `cargo test -p bastion-vault-gui --lib yubikey_bridge -- --ignored` after plugging in a provisioned card. The non-hardware primitives (seed reproducibility, wrap-key derivation, slot management) run under normal `cargo test`.

### 3.5 Registration prerequisites

Operators provision slot 9a before registration via the standard Yubico toolchain:

```bash
ykman piv keys generate 9a pub.pem
ykman piv certificates generate 9a pub.pem
```

RSA-2048 is the recommended algorithm (best compatibility with YubiKey firmware pre-5.7). ECC P-256 and P-384 also work. Ed25519 is rejected by the bridge today because older firmwares don't carry it — if operator demand grows this is a one-line change in `yubikey_bridge::detect_algorithm`.

---

## 4. Desktop-GUI cached auth tokens

The GUI caches per-vault auth tokens in memory so Switch-vault does not force a re-login for an already-authenticated target. See `gui/src/stores/authStore.ts` § `sessions` / `rememberSession` / `restoreSession`.

- **Storage**: process memory only. No disk persistence. Closing the GUI forgets every cached token — matching the operator's mental model that tokens are session-scoped.
- **Validation on restore**: `login_token` calls `auth/token/lookup-self` with the cached token before trusting it. Revoked or expired tokens drop from the cache on the first failure rather than loop.
- **Scope**: ONLY the tokens the operator has actively logged in with during this GUI session are cached. Root tokens minted during `init_embedded` are stored in the per-vault keystore file (§ 2) instead, because that fits the "auto-unseal-and-login on next launch" UX that the desktop app already provides for single-operator deployments.

---

## 5. Cloud storage targets

When a vault's storage backend is cloud-backed (S3 / OneDrive / Google Drive / Dropbox), additional protections layer on top of the barrier:

- **Key obfuscation** (`ObfuscatingTarget`): every vault key is rewritten to `HMAC-SHA-256(target_salt, raw_key)` hex-encoded before reaching the provider. An attacker with bucket-read access sees object counts, sizes, and timestamps but cannot reverse the HMAC output into a meaningful vault path. Target salt is 32 random bytes stored at a well-known key inside the bucket; operators who want to rotate it run the migration flow through a non-obfuscated intermediate.
- **Memory cache** (`CachingTarget`): caches ciphertext bytes only — the bytes already emitted by the barrier above. No plaintext keys, tokens, or secrets pass through the cache layer. Same invariant the vault-core `CachingBackend` relies on.
- **OAuth tokens**: stored via the `credentials_ref` URI scheme (`env:` / `file:` / `inline:` / `keychain:`) with a `Secret`-newtype zero-on-drop so they don't linger in freed memory longer than strictly necessary.

---

## 6. Defence-in-depth summary

| Layer | Cipher / primitive | Key source | Scope |
|---|---|---|---|
| Vault barrier | ChaCha20-Poly1305 (AEAD) | Shamir-split unseal key → rotating keyring | Every logical secret / auth / sys entry |
| Vault PQC ops | ML-KEM-768 + ML-DSA-65 | Barrier-encrypted at rest | Identity KEM, signatures, TLS key-exchange |
| Vault TLS | `rustls` + `aws-lc-rs` + `X25519MLKEM768` | Per-connection ephemeral | Vault ↔ client transit |
| Desktop keystore | ChaCha20-Poly1305 + ML-KEM-768 (KEM/DEM) | OS keychain OR YubiKey PIV signature | Per-vault unseal keys + root tokens + PQC envelope + multi-slot failsafe |
| Cloud target | HMAC-SHA-256 key obfuscation | Per-target random salt | Cloud bucket metadata opacity |
| Auth cache | None (in-memory only) | User-supplied at login | Vault token reuse within one GUI session |

Every persistent layer uses either symmetric 256-bit AEAD or NIST PQC primitives. No single-compromise point exists: breaking the OS keychain does not reveal vault plaintext (the barrier still stands); breaking the barrier does not reveal keychain state; breaking any one cloud target decorator does not reveal vault ciphertext from the others.
