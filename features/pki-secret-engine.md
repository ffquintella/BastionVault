# Feature: Secret Engine -- PKI (Pure-Rust, PQC-Capable)

## Summary

Re-introduce the PKI secrets engine on a fully pure-Rust cryptographic stack (no OpenSSL, no `aws-lc-sys`, no system C libraries) and extend it beyond classical X.509 to issue and validate **post-quantum** certificates using ML-DSA-65 (and, optionally, hybrid composite signatures). The engine exposes the Vault-compatible `/v1/pki/*` HTTP surface (roles, root/intermediate CA, issue, sign, revoke, fetch, CRL) so existing Vault clients keep working, while the underlying crypto, ASN.1 encoding, and CSR/CRL handling are done entirely with RustCrypto and `rcgen`-family crates.

This feature replaces the retired legacy module at `src/modules/pki/` (currently a stub -- see [src/modules/pki/mod.rs:1](src/modules/pki/mod.rs:1)).

## Motivation

- **OpenSSL-free build**: BastionVault's active migration is to remove every C-linked crypto dependency. The legacy PKI engine was the last subsystem that pulled OpenSSL in, which is why it was disabled in the default build (see [roadmap.md:46](roadmap.md:46) and the doc comment in [src/modules/pki/mod.rs:1](src/modules/pki/mod.rs:1)).
- **Post-quantum readiness**: BastionVault already ships ML-KEM-768 and ML-DSA-65 via `bv_crypto` ([crates/bv_crypto/Cargo.toml](crates/bv_crypto/Cargo.toml)). A PQC-capable PKI lets operators issue certificates whose signatures resist a future cryptanalytically relevant quantum computer, and lets BastionVault dogfood its own PQC primitives end-to-end.
- **Vault API parity**: customers migrating from HashiCorp Vault expect the same `pki/roles/*`, `pki/issue/*`, `pki/sign/*`, `pki/revoke`, `pki/ca`, `pki/crl` paths. Reimplementing these on a Rust stack preserves drop-in compatibility while unblocking PQC roles.
- **Auditability**: a pure-Rust ASN.1/X.509 path is easier to audit, easier to fuzz, and avoids the well-known footguns of OpenSSL's certificate parsing surface.

## Current State

**Phases 1 + 2 — Done.** Phase 1 ships the pure-Rust classical engine (RSA / ECDSA P-256/P-384 / Ed25519) on `rcgen` 0.14 with the `ring` provider; Phase 2 layers on ML-DSA-44/65/87 PQC roles built directly on `x509-cert` + `der` + `fips204`, sidestepping rcgen for PQC because rcgen's ML-DSA support is gated behind `aws_lc_rs_unstable` (forbidden). No `openssl-sys` or `aws-lc-sys` is pulled in by this module across either phase. The legacy OpenSSL-bound `path_*.rs` files have been removed; the new module lives in flat layout at `src/modules/pki/`:

- [`mod.rs`](../src/modules/pki/mod.rs) — `PkiModule` + `PkiBackend` + route registration
- [`crypto.rs`](../src/modules/pki/crypto.rs) — `CertSigner` (classical), `Signer` (unified Classical | MlDsa enum that path handlers round-trip through storage), `KeyAlgorithm` + `AlgorithmClass` (the mixed-chain gate)
- [`pqc.rs`](../src/modules/pki/pqc.rs) — `MlDsaSigner` + `MlDsaLevel` + OID table for `2.16.840.1.101.3.4.3.{17,18,19}`. Wraps `bv_crypto::MlDsa{44,65,87}Provider`; storage envelope is a custom `BV PQC SIGNER` PEM (engine-internal, barrier-encrypted, never returned over the API in `internal` mode).
- [`x509.rs`](../src/modules/pki/x509.rs) — classical TBS / CRL builders via `rcgen::CertificateParams`
- [`x509_pqc.rs`](../src/modules/pki/x509_pqc.rs) — PQC TBS / CRL DER assembly via `x509-cert` + `der`, signed with `MlDsaSigner`. Emits BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAltName (DNS + IP), SubjectKeyIdentifier (RFC 7093 method 1), AuthorityKeyIdentifier; CRLs carry `crlNumber`.
- [`storage.rs`](../src/modules/pki/storage.rs) — sealed-storage layout (`ca/cert`, `ca/key`, `certs/<hex>`, `crl/state`, `crl/cached`, `config/{urls,crl}`)
- [`path_roles.rs`](../src/modules/pki/path_roles.rs), [`path_root.rs`](../src/modules/pki/path_root.rs), [`path_issue.rs`](../src/modules/pki/path_issue.rs), [`path_fetch.rs`](../src/modules/pki/path_fetch.rs), [`path_revoke.rs`](../src/modules/pki/path_revoke.rs), [`path_crl.rs`](../src/modules/pki/path_crl.rs), [`path_config.rs`](../src/modules/pki/path_config.rs) — dispatch on `Signer` variant; classical roles flow through `x509`, PQC through `x509_pqc`.

Wired into [`set_default_modules`](../src/module_manager.rs:38) so a fresh core registers the `pki` engine type automatically.

End-to-end coverage:
- [tests/test_pki_engine.rs](../tests/test_pki_engine.rs) — Phase 1 classical: mount → generate root → fetch CA → create / list roles → issue leaf (DNS + IP SANs) → fetch by serial → empty CRL → revoke → CRL contains revoked serial (parsed via `x509-parser`) → stubs return clear errors.
- [tests/test_pki_pqc.rs](../tests/test_pki_pqc.rs) — Phase 2 ML-DSA-65: mount → generate ML-DSA-65 root → confirm signatureAlgorithm OID → directly verify the root self-signature with `fips204` against the SPKI-extracted public key (proves our TBS DER path is correct) → role with `key_type=ml-dsa-65` (and `key_bits != 0` rejected) → issue leaf → re-verify leaf signature under root pk → revoke → CRL contains revoked serial → mixed-chain rejection (classical role on PQC CA fails).

**Implementation deviations from the spec, called out for review:**

- **Layout is flat**, not the nested `backend/`, `crypto/`, `x509/` tree the design proposed. After Phase 2 the file count is now 11; if Phase 3 (composite) doubles that we'll consider promoting `crypto/{classical,ml_dsa,composite}.rs` and `x509/{classical,pqc}.rs` directories. Today flat is still readable.
- **`rcgen` is configured with `ring`, not "ring-free"**. The spec asked for a ring-free profile, but `rcgen` 0.14 only supports `ring` or `aws_lc_rs` as crypto providers — there is no provider-less mode that still does cert assembly. We picked `ring` because it has no system C dep (the spec's CI failure condition is `openssl-sys` / `aws-lc-sys`, both of which `ring` avoids). Phase 2's ML-DSA work can decouple from rcgen's provider entirely by going through the `SigningKey` trait + `x509-cert` for DER assembly, at which point ring becomes optional.
- **RSA generation is rejected at signer creation time** with `ErrPkiKeyTypeInvalid`. `rcgen` cannot generate RSA keypairs through its provider stack; rather than panic mid-issuance, we fail early. Phase 2 will plug a `rsa`-crate-backed `SigningKey` impl into rcgen so `key_type = "rsa"` works.
- **`sign/:role`, `sign-verbatim`, `sign-intermediate`, `intermediate/{generate,set-signed}`, `tidy`, `config/ca` are stubs** that return `ErrLogicalOperationUnsupported`. They live on the route table so clients see Vault-shape responses; their handler bodies will be filled in alongside the CSR-parsing infrastructure in a Phase 1.1 / 2.1 follow-up.
- **PQC private key returned by `pki/issue/:role` is in our `BV PQC SIGNER` envelope, not PKCS#8.** There is no widely-deployed PKCS#8 wrapper for ML-DSA seeds yet (the IETF-LAMPS draft was still in flux when this shipped). The envelope is engine-defined but the body is plain JSON containing the seed and public key — clients can extract those directly. When the IETF draft stabilises, Phase 2.1 will add a PKCS#8-encoded variant alongside the existing envelope.
- **Mixed-chain `--allow-mixed-chain` opt-in is not yet exposed.** Phase 2 ships the closed-by-default form: PQC role → PQC CA, classical → classical, mixed → reject. The migration-window opt-in lands in Phase 2.1.
- **`allowed_domains` / `allow_glob_domains` are not yet enforced.** The Phase 1 role schema accepts `allow_any_name`, `allow_localhost`, `allow_subdomains`, `allow_bare_domains` (used as Vault parity flags) but the constraint matrix beyond `allow_any_name + allow_localhost` is deferred. Roles default to `allow_any_name = true` to match the legacy stub's behaviour.

Crypto building blocks now in tree (additions over what was already present):

- Phase 1: `rcgen = "0.14"` with `x509-parser` feature on, `time = "0.3"` (top-level `Cargo.toml`)
- Phase 2: `x509-cert = "0.2"` (`builder` + `pem` + `std` features), `fips204 = "0.4"` (direct), `const-oid = "0.9"` with `db` feature
- bv_crypto: new `ml-dsa-44` and `ml-dsa-87` features (default-on) wrapping `fips204::ml_dsa_{44,87}`, mirroring the existing `ml-dsa-65` provider.

Already in tree from prior work and reused: `rsa = "0.9"`, `x509-parser = "0.17"`, `zeroize`, `rand = "0.10"`, `der = "0.7"` (transitive via `x509-cert`), `spki = "0.7"` (transitive via `x509-cert`).

## Design

### Crypto Stack (no OpenSSL, no `aws-lc-sys`)

| Concern | Crate | Notes |
|---|---|---|
| Certificate / CSR generation | `rcgen` (with `pem` + `ring`-free profile) | Generates X.509 v3 certs and PKCS#10 CSRs. Supports custom signers via the `KeyPair::from_remote` / `SigningKey` extension points. |
| ASN.1 DER encoding | `der`, `spki`, `x509-cert` (RustCrypto formats) | Used directly when we need to attach a non-`rcgen`-native algorithm (i.e. ML-DSA). |
| Certificate parsing | `x509-parser` (already in tree) and `x509-cert` | `x509-parser` for read-mostly inspection; `x509-cert` when we need to round-trip / re-encode. |
| CRL build / parse | `x509-cert::crl` + `der` | Pure-Rust CRL v2 with custom signature algorithm support. |
| Classical signatures | `rsa` (PKCS#1 v1.5 + PSS, SHA-256/384/512), `ecdsa` + `p256` / `p384`, `ed25519-dalek` | All RustCrypto, no C deps. |
| PQC signatures | `fips204` (ML-DSA-65) -- already used by `bv_crypto` | Plus a new `ml-dsa-44` / `ml-dsa-87` opt-in for cert roles that need different security levels. |
| RNG | `rand_core` + `getrandom` | Already used by `ml-kem` and `fips204`. |

`rcgen` is the workhorse for classical certs because it already speaks all the X.509 v3 extensions Vault's PKI engine touches (SAN, key usage, EKU, basic constraints, name constraints, AIA, CRL DPs). For ML-DSA we bypass `rcgen`'s built-in algorithm enum and instead assemble the `TBSCertificate` with `x509-cert` + `der`, sign the DER bytes with `fips204`, and wrap into the final `Certificate` structure ourselves. This keeps the surface area for "custom" PQC code small and well-bounded.

### PQC Certificate Profile

We support two PQC modes per role, selected by the role's `key_type`:

1. **Pure ML-DSA-65** (`key_type = "ml-dsa-65"`).
   - `SubjectPublicKeyInfo.algorithm` OID: `2.16.840.1.101.3.4.3.18` (id-ml-dsa-65, IETF / NIST PQC).
   - `signatureAlgorithm` OID: same as above (ML-DSA is a signature scheme; the same OID identifies both the key and the signature alg, per draft-ietf-lamps-dilithium-certificates).
   - `subjectPublicKey`: raw 1952-byte ML-DSA-65 public key, wrapped as a BIT STRING.
   - `signatureValue`: 3293-byte ML-DSA-65 signature over the DER-encoded `TBSCertificate`.
   - Supports `ml-dsa-44` (lower security, smaller) and `ml-dsa-87` (higher security, larger) via the same code path with a different OID and `fips204` security level.

2. **Hybrid / composite** (`key_type = "ecdsa-p256+ml-dsa-65"`, optional, gated behind feature flag `pki_pqc_composite`).
   - Uses the IETF "composite signature" draft (`id-composite-signature`) so a verifier that does not yet trust ML-DSA can still validate the classical half.
   - `SubjectPublicKey` is a SEQUENCE of two SPKIs; `signatureValue` is a SEQUENCE of two BIT STRINGs.
   - Useful during the migration window when relying parties have mixed PQC support.

The engine refuses to issue a PQC cert from a classical CA (and vice-versa) unless the role is explicitly configured as a hybrid CA with both keypairs.

### Engine Architecture

```
src/modules/pki/
├── mod.rs                  -- PkiModule, route registration, feature wiring
├── backend/
│   ├── mod.rs              -- Backend storage (CA cert/key, issued certs index, CRL state)
│   └── storage.rs          -- Reads/writes through the barrier; no plaintext keys on disk
├── crypto/
│   ├── mod.rs              -- `CertSigner` trait abstraction
│   ├── classical.rs        -- RSA, ECDSA, Ed25519 signers via RustCrypto
│   ├── ml_dsa.rs           -- ML-DSA-44/65/87 signers via fips204
│   └── composite.rs        -- (feature-gated) hybrid signer
├── x509/
│   ├── mod.rs              -- TBSCertificate / TBSCertList builders
│   ├── extensions.rs       -- SAN, KU, EKU, BC, NC, AIA, CRL DP, SKI, AKI
│   ├── csr.rs              -- PKCS#10 build/parse (rcgen + x509-parser)
│   └── pqc_oids.rs         -- Centralised PQC OID table
├── path_roles.rs           -- /v1/pki/roles/:name (CRUD + classical and PQC key_type)
├── path_root.rs            -- /v1/pki/root/generate, /v1/pki/root/sign-intermediate
├── path_keys.rs            -- /v1/pki/keys/* (key material lifecycle, sealed in barrier)
├── path_issue.rs           -- /v1/pki/issue/:role
├── path_sign.rs            -- /v1/pki/sign/:role and /v1/pki/sign-verbatim
├── path_revoke.rs          -- /v1/pki/revoke (+ /tidy)
├── path_fetch.rs           -- /v1/pki/cert/:serial, /v1/pki/ca, /v1/pki/ca_chain
├── path_config_ca.rs       -- /v1/pki/config/ca, /v1/pki/config/urls
└── path_config_crl.rs      -- /v1/pki/config/crl, /v1/pki/crl/rotate
```

Note the new files relative to the legacy layout: `crypto/`, `x509/`, and a dedicated `path_sign.rs` (the legacy module folded sign + sign-verbatim into `path_issue.rs`).

### `CertSigner` Trait

Every signing identity (root CA, intermediate CA, issued leaf when self-signing for tests) goes through one trait. This is what keeps PQC and classical paths uniform.

```rust
pub trait CertSigner: Send + Sync {
    /// OID + parameters to embed in `signatureAlgorithm` and `tbsCertificate.signature`.
    fn algorithm_identifier(&self) -> AlgorithmIdentifier;

    /// Sign the DER encoding of a TBSCertificate or TBSCertList.
    fn sign_der(&self, tbs_der: &[u8]) -> Result<Vec<u8>, RvError>;

    /// SubjectPublicKeyInfo for this signer (for self-signed roots and for
    /// intermediate generation so the parent can embed it in the leaf).
    fn public_key_info(&self) -> SubjectPublicKeyInfo;

    /// What `key_type` string identifies this signer in role configs.
    fn key_type(&self) -> &'static str;
}
```

Implementations: `RsaSigner`, `EcdsaP256Signer`, `EcdsaP384Signer`, `Ed25519Signer`, `MlDsa65Signer`, `MlDsa44Signer`, `MlDsa87Signer`, `CompositeSigner` (feature-gated).

### Role Configuration -- New / Changed Fields

Existing Vault-compatible fields (`allowed_domains`, `allow_subdomains`, `allow_glob_domains`, `ttl`, `max_ttl`, `key_usage`, `ext_key_usage`, `ou`, `organization`, `country`, etc.) are preserved.

New fields:

| Field | Type | Description |
|---|---|---|
| `key_type` | string | `"rsa"`, `"ec"`, `"ed25519"`, `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"`, `"ecdsa-p256+ml-dsa-65"` (hybrid). Default: `"ec"`. |
| `key_bits` | int | For `rsa`: `2048`/`3072`/`4096`. For `ec`: `256`/`384`. Ignored for ML-DSA / Ed25519. |
| `signature_bits` | int | RSA-PSS hash size (256/384/512). Ignored for non-RSA. |
| `pqc_only` | bool | If true, the role refuses to issue from a classical CA even if the operator points the role at one. |
| `composite_classical` | string | When `key_type` is composite, which classical alg to pair with ML-DSA. Default: `"ecdsa-p256"`. |

### CA Hierarchies

- **Pure classical**: RSA / ECDSA / Ed25519 root signs classical leaves. No change from legacy semantics.
- **Pure PQC**: ML-DSA root signs ML-DSA intermediates and leaves. The whole chain is PQC.
- **PQC root, classical leaves** (or vice-versa): rejected by default. Operators opt in via `--allow-mixed-chain` on `/v1/pki/root/sign-intermediate`. This is needed for migration scenarios but is logged as a security-relevant audit event.
- **Hybrid (composite) root**: signs every cert with the composite signature. Verifiers fall back to whichever half they support.

### Storage and Sealing

- CA private keys live under `pki/ca/<issuer_id>/key` inside the barrier-encrypted storage. They are never written in plaintext, never written to logs, and are zeroized in memory after use (`zeroize` crate, already a transitive dep).
- Issued cert metadata is indexed at `pki/certs/<serial>` for lookup; the cert body is stored alongside.
- CRL state is at `pki/crl/<issuer_id>` with a monotonic `crl_number`. CRL is regenerated on revoke and on `/v1/pki/crl/rotate`.
- HSM integration (see `features/hsm-support.md`): when an HSM seal is configured, CA private keys can optionally be wrapped by the HSM wrapping key in addition to the barrier. This is a follow-up phase.

### HTTP Surface (Vault-compatible)

Listed for reviewer reference; behaviour matches Vault's PKI engine v1 except where PQC fields are introduced.

```
POST   /v1/pki/root/generate/{exported|internal}
POST   /v1/pki/root/sign-intermediate
POST   /v1/pki/intermediate/generate/{exported|internal}
POST   /v1/pki/intermediate/set-signed
GET    /v1/pki/ca[/pem]
GET    /v1/pki/ca_chain
POST   /v1/pki/roles/:name
GET    /v1/pki/roles/:name
LIST   /v1/pki/roles
DELETE /v1/pki/roles/:name
POST   /v1/pki/issue/:role
POST   /v1/pki/sign/:role
POST   /v1/pki/sign-verbatim
POST   /v1/pki/revoke
POST   /v1/pki/tidy
GET    /v1/pki/cert/:serial[/pem]
GET    /v1/pki/cert/ca_chain
GET    /v1/pki/crl[/pem]
POST   /v1/pki/crl/rotate
POST   /v1/pki/config/ca
POST   /v1/pki/config/urls
POST   /v1/pki/config/crl
```

## Implementation Scope

### Phase 1 -- Pure-Rust Classical Engine — **Done**

Re-implement the legacy engine on `rcgen` + RustCrypto, no PQC yet. This proves the OpenSSL-free path before adding novel cryptography.

| File | Purpose |
|---|---|
| `src/modules/pki/mod.rs` | Replace stub with real module; register routes; load CA from storage on `setup`. |
| `src/modules/pki/crypto/mod.rs` | `CertSigner` trait + `AlgorithmIdentifier` helper. |
| `src/modules/pki/crypto/classical.rs` | RSA / ECDSA / Ed25519 signers. |
| `src/modules/pki/x509/mod.rs` | TBS builders that emit DER for `CertSigner::sign_der`. |
| `src/modules/pki/x509/extensions.rs` | All v3 extensions used by Vault PKI. |
| `src/modules/pki/x509/csr.rs` | PKCS#10 build/parse. |
| `src/modules/pki/backend/storage.rs` | Sealed storage of CA keys, cert index, CRL state. |
| `src/modules/pki/path_*.rs` | Reimplement each path on the new stack. |

Dependencies to add to top-level `Cargo.toml`:

```toml
rcgen          = { version = "0.13", default-features = false, features = ["pem", "x509-parser"] }
x509-cert      = { version = "0.2", default-features = false, features = ["builder", "pem"] }
der            = { version = "0.7", features = ["alloc", "derive"] }
spki           = { version = "0.7", features = ["alloc"] }
ecdsa          = { version = "0.16", features = ["pem", "signing", "verifying"] }
p256           = { version = "0.13", features = ["ecdsa", "pem"] }
p384           = { version = "0.13", features = ["ecdsa", "pem"] }
ed25519-dalek  = { version = "2.1", features = ["rand_core", "pem"] }
```

(`rsa` and `x509-parser` are already present.)

### Phase 2 -- PQC Roles (ML-DSA) — **Done**

Final layout differs slightly from the original plan (flat, not nested under `crypto/` and `x509/`):

| File | Purpose |
|---|---|
| `src/modules/pki/pqc.rs` | OID table for `2.16.840.1.101.3.4.3.{17,18,19}`, `MlDsaLevel`, `MlDsaSigner` (wraps `bv_crypto::MlDsa{44,65,87}Provider`), `BV PQC SIGNER` storage envelope. |
| `src/modules/pki/x509_pqc.rs` | Manual TBSCertificate / TBSCertList DER assembly via `x509-cert` + `der`, signed with ML-DSA. |
| `src/modules/pki/crypto.rs` (extension) | `KeyAlgorithm::MlDsa{44,65,87}` variants, `AlgorithmClass`, unified `Signer` enum dispatching Classical vs PQC. |
| `src/modules/pki/path_roles.rs` (extension) | `key_type = "ml-dsa-*"` validation; rejects `key_bits != 0` for PQC roles. |
| `src/modules/pki/path_root.rs` / `path_issue.rs` / `path_revoke.rs` (extensions) | Dispatch on `Signer` variant; PQC chains route through `x509_pqc` builders. Mixed-chain rejection at issue time. |

Dependency:

```toml
fips204 = { version = "0.4.6", default-features = false, features = ["default-rng", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] }
```

(Already a dep of `bv_crypto`; we'd re-use it through `bv_crypto` rather than adding a second copy when feasible.)

### Phase 3 -- Composite / Hybrid Signatures (Feature-Gated)

Feature flag: `pki_pqc_composite` (default off until the IETF draft stabilises).

| File | Purpose |
|---|---|
| `src/modules/pki/crypto/composite.rs` | `CompositeSigner` pairing one classical + one PQC signer. |
| `src/modules/pki/x509/pqc_oids.rs` (extension) | Composite OIDs. |

### Phase 4 -- CRL Modernisation and Tidy

CRL build via `x509-cert::crl`. `tidy` job sweeps expired entries from the CRL and from the cert index; runs on a configurable interval (Vault parity).

### Not In Scope

- ACME server endpoints (`/v1/pki/acme/*`). Vault added these in 1.14; tracked as a separate feature once Phase 1-2 land.
- OCSP responder. Phase 1-4 deliver CRL only; OCSP is a follow-up.
- Cross-signing across two distinct CAs. Single-issuer-per-mount only, like the original Vault PKI engine before multi-issuer support.
- Hardware-backed CA keys via PKCS#11. Tracked under HSM Support ([features/hsm-support.md](features/hsm-support.md)) Phase 3.
- BR / CA/Browser Forum compliance for publicly trusted CAs. The engine targets **internal** PKI use cases.

## Testing Requirements

### Unit Tests

- `CertSigner` round-trip for every algorithm: generate keypair, sign 32 bytes, verify with the corresponding RustCrypto / `fips204` verifier.
- TBS DER encoding stability: a fixed input must produce a byte-identical TBS across runs (rules out non-determinism in extension ordering).
- CSR build -> parse -> rebuild round-trip for every algorithm.
- OID table coverage: every `key_type` string maps to exactly one `AlgorithmIdentifier`.

### Integration Tests

- Generate a classical root CA, issue a leaf, validate the chain with `rustls-webpki` (pure Rust, no OpenSSL).
- Generate an ML-DSA-65 root CA, issue an ML-DSA-65 leaf, verify the leaf signature with `fips204` directly (no third-party verifier exists in pure Rust yet for ML-DSA in X.509; the test exercises our own parser path).
- Revoke a cert; fetch CRL; confirm the revoked serial is in the CRL with the correct `crl_number` and that the CRL signature verifies.
- Mixed-chain rejection: a classical root must refuse to sign a PQC intermediate without `--allow-mixed-chain`.
- Sealed-storage round-trip: seal the vault, restart, unseal, confirm CA key is still loadable and a new leaf can be issued.

### Cucumber BDD Scenarios

- Operator enables the PKI engine, creates a role with `key_type = "ml-dsa-65"`, issues a cert, fetches it back, and the returned PEM parses with `x509-parser`.
- Operator rotates a CA: old issued certs still validate against the old CA in storage; new issuances use the new CA.
- Operator revokes a cert; the CRL endpoint returns a CRL whose `revokedCertificates` includes the serial.

### Negative Tests

- Issuing with `key_type = "ml-dsa-65"` from a classical-only role config must fail with a clear error.
- Setting `key_bits = 2048` on a `key_type = "ml-dsa-65"` role must fail at role creation.
- A CSR signed with an algorithm not allowed by the role must be rejected by `/v1/pki/sign/:role`.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: this feature must not (re)introduce a C-linked crypto dep. CI must fail if `cargo tree` shows `openssl-sys` or `aws-lc-sys` reachable from `bastion-vault`. (Note: `rustls` is configured with `aws_lc_rs` elsewhere in the tree; the PKI engine does not depend on rustls's crypto provider. If the `aws_lc_rs` provider is later swapped to `ring` or `rustls-rustcrypto`, this engine is unaffected.)
- **CA key handling**: CA private keys are barrier-encrypted at rest, zeroized on drop, and never logged. Operators can mark a CA as `exported = false` so that `internal` generation refuses to ever return the private key over the API.
- **PQC algorithm churn**: NIST and IETF are still finalising X.509 OIDs and encodings for ML-DSA. The OID table in `x509/pqc_oids.rs` is the single source of truth and must be updated alongside any IETF lamps draft change. Issued certs carry the OID at issuance time; rotating OIDs requires reissuance.
- **Hybrid mode caveats**: composite signatures protect against either half being broken, but they double cert size and signing latency. The composite mode is feature-gated and disabled by default; operators must opt in.
- **Random number quality**: all key generation routes through `rand_core::OsRng` via `getrandom`. No manual seeding.
- **Side-channel exposure**: RustCrypto's `rsa` is constant-time for private operations as of 0.9; `ecdsa` + `p256`/`p384` use constant-time scalar arithmetic. `fips204` is constant-time per its FIPS 204 reference. We rely on these guarantees and do not roll our own.
- **CRL distribution**: CRL responses are public by design. No barrier-protected data is leaked, but operators should still rate-limit `/v1/pki/crl` to avoid amplification.
- **Audit logging**: every issue / sign / revoke / CA-generate operation is logged through the existing audit subsystem with the serial, role, and requestor identity. CA private key material never appears in audit logs.

## Tracking

When phases land, update:

1. [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` -- `Added` for new endpoints and PQC roles, `Changed` for the route layout changes from the legacy engine.
2. [roadmap.md:46](roadmap.md:46) -- move the row from `Partial` to `In Progress` (Phase 1 in flight) -> `Done` (Phase 2 shipped).
3. This file (`features/pki-secret-engine.md`) -- mark phases Done and refresh "Current State".
