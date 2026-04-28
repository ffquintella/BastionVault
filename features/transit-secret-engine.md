# Feature: Secret Engine -- Transit (Encryption-as-a-Service, PQC-Capable)

## Summary

Add a Vault-compatible **Transit** secret engine that performs cryptographic operations on caller-supplied data without ever storing the plaintext. Callers ship plaintext (or ciphertext, or a digest) to BastionVault; BastionVault returns the cryptographic result. Keys live inside the barrier, never leave it (unless explicitly exported), and rotate on demand or on a schedule.

The engine ships on a fully **pure-Rust** crypto stack -- no OpenSSL, no `aws-lc-sys` -- by reusing the existing `bv_crypto` crate (`aead`, `kem`, `signature`, `envelope` modules). It exposes both classical and **post-quantum** key types: ChaCha20-Poly1305 + AES-GCM for symmetric AEAD, ML-KEM-768 for asymmetric encryption (datakey / key wrapping), ML-DSA-65 for asymmetric signing, plus classical RSA / ECDSA / Ed25519 for compatibility.

This is a new feature; there is no legacy Transit module to displace.

## Motivation

- **Encryption-as-a-service**: many BastionVault deployments will sit alongside applications that need to encrypt application-layer data (PII columns in a database, files in object storage, message-bus payloads). Letting those apps offload the key handling to BastionVault means key rotation, access control, and audit logging happen in one place instead of being scattered through every application.
- **Vault-compatible API**: customers migrating from HashiCorp Vault expect `transit/keys/:name`, `transit/encrypt/:name`, `transit/decrypt/:name`, `transit/sign/:name`, `transit/verify/:name`, `transit/hmac/:name`, `transit/rewrap/:name`, `transit/datakey/{plaintext,wrapped}/:name`, and `transit/rotate/:name`. Reimplementing that surface here is a big migration unblocker.
- **Post-quantum primitives, exposed**: `bv_crypto` already speaks ML-KEM-768 and ML-DSA-65, but those primitives are only used internally for the barrier and seal today. A Transit engine surfaces them to callers so applications can start producing PQC ciphertexts and signatures now, without each one having to integrate `fips204` / `ml-kem` directly.
- **Crypto-agility through versioned keys**: Vault's Transit model versions every key. Rotating a key creates a new version; ciphertexts carry the version they were produced with; old versions stay available for decrypt only until explicitly trimmed. This is exactly the discipline a PQC migration needs -- new versions can flip from RSA-OAEP to ML-KEM-768 without breaking existing ciphertexts.

## Current State

- **Phases 1–3 implemented.** The engine ships at [`src/modules/transit/`](../src/modules/transit/) with the full Vault-compatible `/v1/transit/*` HTTP surface (keys CRUD + rotate + config + trim, encrypt/decrypt/rewrap, sign/verify, hmac/verify-hmac, datakey/{plaintext,wrapped,unwrap}, random, hash). `TransitModule` is registered in [`src/module_manager.rs`](../src/module_manager.rs) so operators mount via `POST /v1/sys/mounts/transit type=transit`.
- **Key types shipped today**: `chacha20-poly1305` (symmetric AEAD), `hmac` (MAC only), `ed25519` (classical signing), `ml-kem-768` (PQC KEM for datakey wrap), `ml-dsa-44/65/87` (PQC signing). Capability matrix at [`keytype.rs`](../src/modules/transit/keytype.rs) structurally enforces "no key supports both sign and encrypt" — refused at the path layer before any crypto runs.
- **Pure-Rust crypto stack**: `bv_crypto` for AEAD + ML-KEM + ML-DSA, `ed25519-dalek` 2.x for Ed25519, `hmac` 0.13 + `sha2` 0.11 for HMAC + hashing, `subtle` 2.6 for constant-time compare, `hkdf` 0.13 for the KEM→datakey derivation. No OpenSSL, no `aws-lc-sys`.
- **Wire framing**: `bvault:vN[:pqc:<algo>]:<base64>`. The algorithm tag is mandatory for every PQC payload — a signature or wrapped datakey presented with the wrong algorithm tag is refused before any cryptographic operation runs.
- **Dedicated baseline policies**: `transit-user` (crypto operations + key metadata read, no key lifecycle) and `transit-admin` (full mount management) ship by default — both registered in [`src/modules/policy/policy_store.rs`](../src/modules/policy/policy_store.rs).
- **Phase 4 implemented** — derived + convergent encryption (always-on, HKDF subkey via `bvault-transit-derive\0 || context`, domain-separated deterministic nonce via `HMAC(parent || "bvault-transit-conv-nonce", len(context) || context || plaintext)[..12]`); **BYOK import** behind `transit_byok` cargo feature (`/wrapping_key`, `/keys/:name/import`, `/keys/:name/import_version` — per-mount ML-KEM-768 wrapping key, lazily generated, private half stays in the barrier); **hybrid composite signing** `hybrid-ed25519+ml-dsa-65` + **hybrid KEM** `hybrid-x25519+ml-kem-768` behind `transit_pqc_hybrid` (KEM combiner concatenates the X25519 + ML-KEM shared secrets and feeds HKDF-SHA-256). Pulls one new optional dep — `x25519-dalek = "2"` (gated by `transit_pqc_hybrid`).
- **RSA + ECDSA classical types remain deferred**: not blocking the PQC story; they need direct `rsa` / `p256` / `p384` deps and a separate set of capability-matrix entries. Tracked as the only outstanding Phase 2 work.
- **GUI page deferred**: the engine is fully usable from the API and any Vault-compatible CLI today; a Transit tab on the desktop GUI is tracked separately.

## Design

### Vault-compatible HTTP Surface

```
LIST   /v1/transit/keys
POST   /v1/transit/keys/:name                 # create
GET    /v1/transit/keys/:name                 # read (metadata + public keys for asym types)
DELETE /v1/transit/keys/:name                 # delete (refused unless deletion_allowed=true)
POST   /v1/transit/keys/:name/config          # update min_decryption_version, deletion_allowed, ...
POST   /v1/transit/keys/:name/rotate          # add a new version
POST   /v1/transit/keys/:name/trim            # drop versions below min_available_version

POST   /v1/transit/encrypt/:name              # symmetric or asymmetric encrypt
POST   /v1/transit/decrypt/:name
POST   /v1/transit/rewrap/:name               # decrypt-then-reencrypt with latest version

POST   /v1/transit/sign/:name[/:hash_algo]    # asymmetric sign
POST   /v1/transit/verify/:name[/:hash_algo]

POST   /v1/transit/hmac/:name[/:hash_algo]    # symmetric HMAC
POST   /v1/transit/verify/:name/hmac          # HMAC verify

POST   /v1/transit/datakey/plaintext/:name    # generate a datakey, return plaintext + wrapped
POST   /v1/transit/datakey/wrapped/:name      # generate a datakey, return only wrapped form

POST   /v1/transit/random[/:bytes]            # CSPRNG passthrough (uses OsRng)
POST   /v1/transit/hash[/:hash_algo]          # SHA2 / SHA3 hashing passthrough

POST   /v1/transit/keys/:name/export/:type/:version   # only if exportable=true
POST   /v1/transit/keys/:name/restore                  # restore from a Vault-format backup blob
POST   /v1/transit/keys/:name/backup                   # produce a backup blob

POST   /v1/transit/wrapping_key                       # public RSA / ML-KEM key for BYOK import
POST   /v1/transit/keys/:name/import                  # BYOK: caller supplies wrapped key material
POST   /v1/transit/keys/:name/import_version          # BYOK: add a wrapped version
```

Behaviour matches Vault's Transit engine v1 except where PQC `key_type` values introduce new fields. Endpoints not in this list (cache config, managed keys, CMAC) are out of scope for the initial cut -- see "Not In Scope".

### Key Types

| `key_type` | Class | Algorithm | Notes |
|---|---|---|---|
| `aes256-gcm96` | sym AEAD | AES-256-GCM, 96-bit nonce | Vault parity. |
| `chacha20-poly1305` | sym AEAD | ChaCha20-Poly1305 | Default for new keys; matches barrier algorithm. |
| `xchacha20-poly1305` | sym AEAD | XChaCha20-Poly1305 (192-bit nonce) | For high-volume keys where 96-bit nonce reuse risk matters. |
| `hmac` | sym MAC | HMAC-SHA-256/384/512 | HMAC-only key, refuses encrypt/sign. |
| `rsa-2048` / `rsa-3072` / `rsa-4096` | asym | RSA-OAEP-SHA-256 (encrypt) + RSA-PSS-SHA-256 (sign) | Pure-Rust `rsa` crate. |
| `ecdsa-p256` / `ecdsa-p384` | asym sig | ECDSA over P-256 / P-384 | RustCrypto `ecdsa` + `p256`/`p384`. |
| `ed25519` | asym sig | Ed25519 | `ed25519-dalek`. |
| `ml-kem-768` | asym KEM | ML-KEM-768 (NIST FIPS 203) | **PQC**. Used for encrypt / decrypt / rewrap and datakey-wrapping. |
| `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87` | asym sig | ML-DSA (NIST FIPS 204) | **PQC**. Sign / verify only. |
| `hybrid-x25519+ml-kem-768` | asym KEM (hybrid) | X25519 || ML-KEM-768, KEM combiner per draft-ietf-lamps | Feature-gated `transit_pqc_hybrid`. |
| `hybrid-ed25519+ml-dsa-65` | asym sig (hybrid) | Composite Ed25519 + ML-DSA-65 | Feature-gated `transit_pqc_hybrid`. Mirrors PKI's composite mode. |

A key that is asymmetric for *encryption* (e.g. `ml-kem-768`, `rsa-*`) refuses sign/verify; an asymmetric *signing* key (e.g. `ml-dsa-65`, `ed25519`) refuses encrypt/decrypt. This matches Vault's separation and prevents algorithm misuse.

### Key Versions

Every key is a **list of versions**, not a single keypair:

- New keys start at version 1.
- `rotate` appends a new version; the latest is used for *encrypt / sign / wrap / hmac*; **all** versions ≥ `min_decryption_version` are tried for *decrypt / verify / unhmac*.
- Ciphertexts and signatures carry the version inside their wire format (Vault's `vault:vN:...` prefix; PQC variants use `bvault:vN:pqc:<algo>:...` to keep the parser unambiguous).
- `min_decryption_version` lets operators retire compromised versions without losing the ability to decrypt newer payloads.
- `min_available_version` lets `trim` drop old material entirely.

### Storage Layout

All under the engine's per-mount UUID-scoped barrier prefix:

```
transit/
  policy/<name>            -- KeyPolicy: type, versions, config (JSON, encrypted by barrier)
  archive/<name>           -- compressed historical versions for trimmed keys (still inside barrier)
  cache/<name>/derived/... -- subkeys for derivation contexts (when derived=true)
```

Private key material (every version) lives inside `KeyPolicy` and is therefore barrier-encrypted at rest. ML-DSA / ML-KEM keys are stored in their canonical FIPS encoding; classical keys use the RustCrypto `*-pem` representations.

### Data on the Wire

Symmetric ciphertext format (matches Vault's framing):

```
bvault:v<version>:<base64(nonce || ct || tag)>
```

PQC asymmetric ciphertext (ML-KEM-768 datakey wrapping):

```
bvault:v<version>:pqc:ml-kem-768:<base64(kem_ct || aead_nonce || aead_ct || aead_tag)>
```

PQC signature:

```
bvault:v<version>:pqc:ml-dsa-65:<base64(sig)>
```

The `pqc:` namespace and explicit algorithm tag are deliberate: it avoids any ambiguity with the existing Vault `vault:vN:` prefix and lets a single endpoint serve mixed key types over time.

### Convergent Encryption and Key Derivation

Vault parity:

- `derived = true` -- per-request subkey derived via HKDF-SHA-256(parent_key, context). Caller passes `context` on every encrypt/decrypt. Useful for per-row encryption where you want the same row to always produce the same ciphertext only when the same key+context is used.
- `convergent_encryption = true` (requires `derived = true`) -- nonce is derived from `HMAC(key_v9, plaintext || context)` instead of being random. Same plaintext → same ciphertext under the same key+context. AEAD only.

PQC keys do **not** support convergent mode in the initial release: ML-KEM produces a fresh random shared secret per encapsulation by design, and forcing determinism would require contructions outside the FIPS spec.

### Engine Architecture

```
src/modules/transit/
├── mod.rs                  -- TransitModule; route registration; setup/cleanup
├── backend.rs              -- TransitBackend: storage I/O, policy load/save, lock per key
├── policy.rs               -- KeyPolicy struct, KeyVersion enum, serialisation
├── keytype.rs              -- KeyType enum + capability checks (encrypt? sign? wrap?)
├── crypto/
│   ├── mod.rs              -- traits: SymKey, AsymEncKey, AsymSigKey, MacKey
│   ├── sym.rs              -- ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM via bv_crypto::aead
│   ├── rsa.rs              -- RSA-OAEP / RSA-PSS via the `rsa` crate
│   ├── ecdsa.rs            -- ECDSA P-256 / P-384 via `ecdsa` + `p256`/`p384`
│   ├── ed25519.rs          -- Ed25519 via `ed25519-dalek`
│   ├── ml_kem.rs           -- ML-KEM-768 via bv_crypto::kem
│   ├── ml_dsa.rs           -- ML-DSA-44/65/87 via bv_crypto::signature
│   ├── hybrid.rs           -- (feature-gated) composite KEM + composite signatures
│   ├── hkdf.rs             -- derived-key support
│   └── ciphertext.rs       -- bvault:vN:[pqc:<algo>:]<b64> framer/parser
├── path_keys.rs            -- /v1/transit/keys/:name CRUD + config + rotate + trim
├── path_encrypt.rs         -- /v1/transit/encrypt/:name + /decrypt + /rewrap (batch-aware)
├── path_sign.rs            -- /v1/transit/sign + /verify
├── path_hmac.rs            -- /v1/transit/hmac + /verify/hmac
├── path_datakey.rs         -- /v1/transit/datakey/{plaintext,wrapped}/:name
├── path_random.rs          -- /v1/transit/random + /hash
├── path_export.rs          -- /v1/transit/keys/:name/export/:type/:version
├── path_backup.rs          -- /v1/transit/keys/:name/{backup,restore}
└── path_import.rs          -- /v1/transit/wrapping_key + /import + /import_version
```

### Trait Abstractions

```rust
pub trait SymKey: Send + Sync {
    fn key_type(&self) -> KeyType;
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: Option<&[u8]>) -> Result<Vec<u8>, RvError>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RvError>;
    fn hmac(&self, msg: &[u8], hash: HashAlgo) -> Result<Vec<u8>, RvError>;
}

pub trait AsymEncKey: Send + Sync {
    fn key_type(&self) -> KeyType;
    fn public_key_pem(&self) -> Result<String, RvError>;
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, RvError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RvError>;
    /// Encapsulate a fresh shared secret; for KEMs (ML-KEM, hybrid).
    fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), RvError> { ... } // (kem_ct, ss)
    fn decapsulate(&self, kem_ct: &[u8]) -> Result<Vec<u8>, RvError> { ... }
}

pub trait AsymSigKey: Send + Sync {
    fn key_type(&self) -> KeyType;
    fn public_key_pem(&self) -> Result<String, RvError>;
    fn sign(&self, msg_or_digest: &[u8], hash: HashAlgo, prehashed: bool) -> Result<Vec<u8>, RvError>;
    fn verify(&self, msg_or_digest: &[u8], sig: &[u8], hash: HashAlgo, prehashed: bool) -> Result<bool, RvError>;
}
```

`KeyVersion` is an enum carrying one of these and the bytes it was deserialised from. The path handlers never touch raw key material directly.

### Datakey Operations

`/v1/transit/datakey/plaintext/:name` and `/wrapped/:name` are the linchpin for application-side encryption:

- For **symmetric** parent keys: not supported (Vault parity -- datakey only makes sense when the parent is asymmetric or "derived" symmetric).
- For **RSA**: generate a random 256-bit data key, encrypt it with RSA-OAEP under the parent.
- For **ML-KEM-768**: encapsulate to the parent's public key, derive a 256-bit data key from the shared secret via HKDF-SHA-256(`bvault-transit-datakey`, ss), return the KEM ciphertext as the wrapped form. This is the default PQC datakey path and the one we expect applications to use most.
- For **hybrid KEM**: combine X25519 + ML-KEM-768 shared secrets via the IETF KEM combiner draft, then HKDF as above.

The plaintext form is only returned to callers whose policy grants the `update` capability on the `/datakey/plaintext/:name` path -- it's the higher-privilege variant.

### Mount, Lease, Audit Wiring

Transit fits the standard engine model documented in [docs/secret-engines.md](../docs/docs/secret-engines.md):

- `TransitModule::setup()` calls `core.add_logical_backend("transit", factory)`.
- Operators mount via `POST /v1/sys/mounts/transit type=transit`.
- Per-mount UUID isolates one tenant's keys from another's.
- All operations go through the audit broadcaster; `plaintext` and `ciphertext` request fields are HMAC'd in audit logs (Vault parity), not stored raw.
- Transit operations do **not** issue leases -- there is no per-secret lifecycle; the key version itself carries the lifecycle.
- Per-key locks (`Arc<RwLock<KeyPolicy>>`) prevent rotate/encrypt races.

## Implementation Scope

### Phase 1 -- Symmetric Engine + Vault Parity — **Done**

| File | Purpose |
|---|---|
| `src/modules/transit/mod.rs` | Module + route registration. |
| `src/modules/transit/backend.rs` | Backend wiring, per-key lock map, storage helpers. |
| `src/modules/transit/policy.rs` | `KeyPolicy`, `KeyVersion`, JSON (de)serialisation. |
| `src/modules/transit/keytype.rs` | `KeyType` enum + capability matrix. |
| `src/modules/transit/crypto/{mod,sym,hkdf,ciphertext}.rs` | `SymKey` trait + AEAD impls + framer. |
| `src/modules/transit/path_keys.rs` | CRUD + config + rotate + trim. |
| `src/modules/transit/path_encrypt.rs` | encrypt / decrypt / rewrap (batch-aware). |
| `src/modules/transit/path_hmac.rs` | hmac / verify-hmac. |
| `src/modules/transit/path_random.rs` | random / hash passthroughs. |
| `src/modules/transit/path_backup.rs` | backup / restore (round-trips a barrier-encrypted blob). |

Dependencies (already in `bv_crypto` via the workspace): `chacha20poly1305`, `aes-gcm`, `hmac`, `sha2`, `sha3`, `hkdf`, `subtle`. No new top-level deps required.

### Phase 2 -- Asymmetric (Classical) Encryption + Signing — **Partially done (Ed25519 only)**

| File | Purpose |
|---|---|
| `src/modules/transit/crypto/rsa.rs` | RSA-OAEP / RSA-PSS via `rsa`. |
| `src/modules/transit/crypto/ecdsa.rs` | ECDSA P-256 / P-384. |
| `src/modules/transit/crypto/ed25519.rs` | Ed25519. |
| `src/modules/transit/path_sign.rs` | sign / verify (batch-aware). |
| `src/modules/transit/path_datakey.rs` | datakey for RSA. |
| `src/modules/transit/path_export.rs` | exportable=true keys only. |

Re-uses the same RustCrypto deps as the PKI feature ([features/pki-secret-engine.md](pki-secret-engine.md)) -- if PKI Phase 1 lands first, those Cargo entries already exist.

### Phase 3 -- PQC Key Types — **Done**

| File | Purpose |
|---|---|
| `src/modules/transit/crypto/ml_kem.rs` | ML-KEM-768 encrypt/decrypt + datakey via `bv_crypto::kem`. |
| `src/modules/transit/crypto/ml_dsa.rs` | ML-DSA-44/65/87 sign/verify via `bv_crypto::signature`. |
| `src/modules/transit/crypto/ciphertext.rs` (extension) | Recognise `bvault:vN:pqc:<algo>:...` framing. |
| `src/modules/transit/path_keys.rs` (extension) | Allow `key_type = "ml-kem-768" \| "ml-dsa-44|65|87"`. |
| `src/modules/transit/path_datakey.rs` (extension) | KEM-based datakey. |

No new external crates -- `bv_crypto` already has the primitives.

### Phase 4 -- Hybrid (Composite) Modes, BYOK Import, Convergent Mode — **Done**

Feature flags: `transit_pqc_hybrid`, `transit_byok`.

| File | Purpose |
|---|---|
| `src/modules/transit/crypto/hybrid.rs` | X25519+ML-KEM-768 KEM combiner; Ed25519+ML-DSA-65 composite sigs. |
| `src/modules/transit/path_import.rs` | wrapping_key issuance + key-material import using ML-KEM-768 (or RSA-OAEP for legacy callers). |
| `src/modules/transit/policy.rs` (extension) | `derived` + `convergent_encryption` flags + per-context subkey cache. |

### Not In Scope

- **Managed keys** (HSM-backed Transit keys via PKCS#11) -- tracked under [features/hsm-support.md](hsm-support.md) Phase 3.
- **CMAC** key type -- niche, deferred until requested.
- **Cache config** (`/v1/transit/cache-config`) -- the engine uses a fixed in-memory LRU keyed by `(name, version)`; tuning knobs come later.
- **Auto-rotate** (rotate on a schedule) -- a follow-up using the existing rollback / scheduler infrastructure once Phase 1 is stable.
- **Cross-cluster key replication** -- relies on storage-backend replication (Hiqlite Raft); no engine-level replication primitive is added.
- **FPE / format-preserving encryption** -- not in Vault's Transit either; if requested it would be a separate engine.

## Testing Requirements

### Unit Tests

- AEAD round-trip per algorithm: encrypt then decrypt reproduces plaintext, AAD mismatch fails closed, tag mismatch fails closed.
- HMAC round-trip + verification timing-safe via `subtle`.
- RSA, ECDSA, Ed25519, ML-DSA, ML-KEM round-trips per algorithm.
- Ciphertext framer: every supported `bvault:vN[:pqc:<algo>]:b64` form parses; malformed framings reject with `RvError::InvalidCiphertext`.
- Key rotation invariants: new version = old `latest_version + 1`; old versions still decrypt; `min_decryption_version` enforcement actually blocks decrypt of older versions.
- Convergent encryption: same `(key, context, plaintext)` produces byte-identical ciphertext; differing context produces different ciphertext.

### Integration Tests

- Mount transit, create a `chacha20-poly1305` key, encrypt 1 MiB, rotate, decrypt with the old version still works, rewrap upgrades to the new version.
- Mount transit, create an `ml-kem-768` key, generate a wrapped datakey, decrypt the wrapped datakey, derive the same 256-bit AES key locally and decrypt an AEAD blob produced by the caller.
- Sign with `ml-dsa-65`, verify against the public key returned by `GET /v1/transit/keys/:name`. Tamper with the message; verify fails closed.
- Backup a key, delete it, restore from the backup, confirm both old and new versions work.
- BYOK: fetch wrapping_key, wrap a 256-bit AES key client-side using ML-KEM-768, import; encrypt/decrypt round-trip with the imported key.

### Cucumber BDD Scenarios

- Operator creates a Transit mount and an `aes256-gcm96` key, application encrypts a payload, fetches the ciphertext, decrypts it, gets the original.
- Operator rotates a key after a suspected compromise and sets `min_decryption_version`. Old ciphertexts produced before rotation now fail to decrypt; payloads rewrapped via `/transit/rewrap` succeed.
- Operator creates an `ml-dsa-65` key, the caller signs a message; a third party with only the public key (fetched via `GET /v1/transit/keys/:name`) verifies the signature using `fips204` directly.

### Negative Tests

- Encrypt against a sign-only key (`ed25519`, `ml-dsa-65`): rejected at the path with a clear error.
- Sign against an encrypt-only key (`ml-kem-768`, `aes256-gcm96`): rejected.
- `convergent_encryption = true` without `derived = true`: rejected at key creation.
- Convergent mode requested with key_type `ml-kem-768`: rejected (not supported in initial release).
- Decrypt of a `bvault:v3:...` blob when only versions 1-2 exist: rejected with version-not-found.
- Decrypt of a version below `min_decryption_version`: rejected with policy-violation.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as PKI. CI must fail if `cargo tree` shows either reachable from `bastion-vault`.
- **Key material at rest**: every `KeyPolicy` is barrier-encrypted before hitting the physical storage. Plaintext key bytes never persist.
- **Audit redaction**: `plaintext`, `ciphertext`, `signature`, `input` fields in requests/responses are HMAC'd in audit logs using the audit-device-specific HMAC key. Default behaviour matches Vault's `log_raw = false`.
- **Constant-time primitives**: AEAD tag comparison and HMAC verification go through `subtle::ConstantTimeEq`. ECDSA / RSA / ML-DSA / ML-KEM rely on the constant-time guarantees of their respective RustCrypto / `fips204` / `ml-kem` implementations.
- **Nonce management**: AEAD nonces are random 96-bit (or 192-bit for XChaCha) by default; XChaCha is recommended for any key that may exceed 2^32 encryptions. Convergent mode uses a deterministic nonce -- the caveats are documented in the API page.
- **Datakey responses**: `/v1/transit/datakey/plaintext/:name` returns the datakey in plaintext form. Operators must restrict that path to short-lived, narrowly-scoped tokens; the wrapped variant should be the default in policies.
- **Versioned framing locks ciphertext to algorithm**: a `bvault:v3:pqc:ml-kem-768:...` blob cannot be decrypted by version 3 of an `aes256-gcm96` key, even if both happen to live at the same key name across a destructive type change. The framer enforces algorithm match before any cryptographic operation runs.
- **Exportable keys are sticky**: once `exportable = false` is set on creation, the engine refuses to flip it to true later. Same for `allow_plaintext_backup`.
- **PQC algorithm churn**: ML-DSA OIDs and encodings are still settling in IETF lamps; the wire framing carries the algorithm string explicitly so future OID changes do not invalidate stored ciphertexts.

## Tracking

When phases land, update:

1. [CHANGELOG.md](../CHANGELOG.md) under `[Unreleased]` -- `Added` for new endpoints, key types, and PQC operations.
2. [roadmap.md](../roadmap.md) -- move the "Secret Engine: Transit" row from `Todo` to `In Progress` (Phase 1 in flight) → `Done` once Phase 3 ships.
3. This file (`features/transit-secret-engine.md`) -- mark phases Done and refresh "Current State".
