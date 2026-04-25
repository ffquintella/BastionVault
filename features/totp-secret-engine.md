# Feature: Secret Engine -- TOTP

## Summary

Add a Vault-compatible **TOTP** secret engine that generates and validates time-based one-time passwords (RFC 6238). The engine operates in two modes per key:

1. **Generate mode** -- BastionVault generates a fresh TOTP secret, returns a `key_url` (`otpauth://totp/...`) plus a QR-encoded barcode for the operator to scan into Google Authenticator / Authy / 1Password / a YubiKey OATH applet, and thereafter serves on-demand 6/8-digit codes.
2. **Provider mode** -- the operator imports an existing TOTP secret (e.g. a seed they already have for an external service); BastionVault stores it sealed and validates submitted codes against it.

The engine is built on a fully **pure-Rust** stack -- no OpenSSL, no `aws-lc-sys`. It exposes the Vault `/v1/totp/*` HTTP surface (`keys`, `code`) so existing Vault TOTP clients are drop-in compatible.

## Motivation

- **Common deployment ask**: TOTP-as-a-service is one of the highest-value engines for shops that issue 2FA seeds to operators. Today those seeds live in spreadsheets or a shared password manager. Letting BastionVault hold them turns a soft-secret into a policy-gated, audit-logged secret.
- **Pairs naturally with the FIDO2 / YubiKey work already in tree**: BastionVault already speaks PIV + WebAuthn for unlock and for vault auth. TOTP completes the OATH side -- "BastionVault is where every shared 2FA seed lives" is a coherent story.
- **Vault parity for migrations**: HashiCorp Vault has shipped `secret/totp` since 0.9. Customers migrating off Vault expect this engine.
- **Operational hygiene**: rotating a TOTP seed today means re-enrolling the user manually. With an engine that owns the seed, rotation is one API call + a re-scan of the new QR code.

## Current State

- No TOTP engine exists in the repository. The legacy code base never shipped a TOTP module.
- The barrier (ChaCha20-Poly1305 in [crates/bv_crypto](crates/bv_crypto/src/aead)) handles at-rest encryption of any engine's storage, so per-key TOTP secrets are already protected once the engine writes them through `req.storage_put`.
- HMAC-SHA1 / SHA-256 / SHA-512 are available transitively through `bv_crypto`'s dependency tree (`hmac` + `sha1` + `sha2`), so no new top-level crypto crates are strictly required.

## Design

### Vault-compatible HTTP Surface

```
LIST   /v1/totp/keys
POST   /v1/totp/keys/:name        # create (generate or provider mode)
GET    /v1/totp/keys/:name        # read metadata (never the secret)
DELETE /v1/totp/keys/:name        # delete

GET    /v1/totp/code/:name        # generate-mode: return current 6/8-digit code
POST   /v1/totp/code/:name        # provider-mode:  validate a submitted code
```

Behaviour matches Vault's `secret/totp` engine v1.

### Key Configuration

A TOTP key is stored with these fields, all under the engine's per-mount UUID-scoped barrier prefix at `totp/key/<name>`:

| Field | Type | Description | Mode |
|---|---|---|---|
| `generate` | bool | If true, the engine creates the seed; if false, the operator imports one. | both (selector) |
| `key` | string (base32) | TOTP secret. Required in provider mode; refused on input in generate mode. | provider |
| `key_size` | int | Random secret length in bytes when `generate=true`. Default 20 (RFC 4226 recommendation). | generate |
| `account_name` | string | Embedded in the `otpauth://` URL as `Issuer:Account`. | both |
| `issuer` | string | Same. | both |
| `algorithm` | enum | `SHA1` (default, broadest authenticator support), `SHA256`, `SHA512`. | both |
| `digits` | int | 6 (default) or 8. | both |
| `period` | int | Step in seconds; default 30. | both |
| `skew` | int | Number of preceding/following steps accepted on validate. Default 1 (i.e. ±period seconds). | both |
| `qr_size` | int | Pixel size of the returned PNG QR. 0 disables PNG. Default 200. | generate |
| `exported` | bool | Whether the seed is returned in the create response (one-shot). Default true; once `false`, the seed is never returned. | generate |
| `url` | string | Pre-built `otpauth://...` URL accepted as input. Mutually exclusive with the discrete fields. | provider |

The seed itself never appears in `GET /v1/totp/keys/:name`. It only appears in the **response of the create call** (and only when `exported=true`), and even then is returned exactly once per Vault parity.

### Two Operational Modes

**Generate mode** (`POST /v1/totp/keys/:name {"generate": true, "issuer": "...", "account_name": "..."}`):
1. Engine draws `key_size` bytes from `rand_core::OsRng` (via `getrandom`).
2. Base32-encodes the seed (RFC 4648, no padding -- authenticator-friendly).
3. Builds an `otpauth://totp/<urlencode(issuer)>:<urlencode(account_name)>?secret=<b32>&issuer=<...>&algorithm=<...>&digits=<...>&period=<...>` URL.
4. Renders that URL to a PNG QR via `qrcode` (pure Rust; produces an `image::ImageBuffer` that is then PNG-encoded).
5. Returns `{ "key": "<b32>", "url": "<otpauth://...>", "barcode": "<base64-PNG>" }`.
6. Persists the policy + raw seed bytes to `totp/key/<name>` through the barrier.

**Provider mode** (`POST /v1/totp/keys/:name {"generate": false, "key": "JBSWY3DPEHPK3PXP", "issuer": "...", ...}` or `{"generate": false, "url": "otpauth://..."}`):
1. Engine parses the inbound seed (decode base32; strip whitespace; tolerate lowercase) **or** parses the supplied `otpauth://` URL.
2. Validates algorithm/digits/period are within supported ranges.
3. Persists the key with `exported=false` implicitly -- provider-mode keys never re-export the seed.

### Code Generation and Validation

- `GET /v1/totp/code/:name` (generate mode): compute `HOTP(seed, floor(now / period))` per RFC 4226 with the configured hash + digits, return `{ "code": "123456" }`.
- `POST /v1/totp/code/:name {"code": "123456"}` (provider mode): for each step `t` in `[now - skew*period, now + skew*period]`, compute the expected code and constant-time compare. Return `{ "valid": true|false }`. **Replay protection**: on a successful validation, persist the matched step in `totp/used/<name>` and refuse any future validate of the same step+code, so a captured code cannot be replayed within its acceptance window.

### Engine Architecture

```
src/modules/totp/
├── mod.rs                  -- TotpModule; route registration; setup/cleanup
├── backend.rs              -- TotpBackend: storage I/O, replay-cache, per-key lock
├── policy.rs               -- KeyPolicy struct + serialisation
├── crypto/
│   ├── mod.rs              -- HOTP + TOTP via hmac + sha1/sha2
│   └── otpauth.rs          -- otpauth:// URL build + parse (RFC 6238 Appendix B)
├── barcode.rs              -- QR PNG rendering via `qrcode` + `image`
├── path_keys.rs            -- /v1/totp/keys/:name CRUD + LIST
└── path_code.rs            -- /v1/totp/code/:name GET (generate) + POST (validate)
```

### Replay Protection

Without replay protection, a 30-second-window code captured by an attacker can be replayed up to `(skew*2 + 1)` times across the validate endpoint. The engine stores `(name, step, code-hash)` for every successful validation in `totp/used/<name>/<step>` and treats a hit as `valid=false`. A small reaper sweeps entries older than `(skew + 1) * period` so the index doesn't grow unbounded.

This is **stronger** than HashiCorp Vault's TOTP engine, which by default does not deduplicate. Operators can opt out via `replay_check = false` on the key for parity with Vault's exact behaviour.

### Mount, Audit, Lease Wiring

Standard secret-engine wiring (per [docs/secret-engines.md](../docs/docs/secret-engines.md)):

- `TotpModule::setup()` calls `core.add_logical_backend("totp", factory)`.
- Operators mount via `POST /v1/sys/mounts/totp type=totp`.
- Per-mount UUID isolates one tenant's TOTP keys from another's.
- Audit logs HMAC the `key`, `url`, `barcode`, and `code` fields by default. `code` validation results (`valid: true|false`) are not redacted -- they are the actionable signal.
- TOTP operations issue **no leases** -- codes are ephemeral by definition; the seed lifecycle is the key's CRUD lifecycle.
- A small per-key `RwLock` serialises code-validate calls so two concurrent validations cannot both consume the same step.

### Configuration Knobs

Per-key (above) plus engine-wide tunables on `POST /v1/sys/mounts/totp/tune`:
- `default_period` (default 30s)
- `default_skew` (default 1 step)
- `default_digits` (default 6)
- `default_algorithm` (default SHA1)
- `replay_check_default` (default true; flip to false for strict Vault parity)

## Implementation Scope

### Phase 1 -- Core Engine

| File | Purpose |
|---|---|
| `src/modules/totp/mod.rs` | Module + route registration. |
| `src/modules/totp/backend.rs` | Backend wiring, per-key lock map, storage helpers. |
| `src/modules/totp/policy.rs` | `KeyPolicy` struct + JSON (de)serialisation. |
| `src/modules/totp/crypto/mod.rs` | HOTP + TOTP via `hmac` + `sha1` + `sha2`. |
| `src/modules/totp/crypto/otpauth.rs` | `otpauth://` URL build + parse. |
| `src/modules/totp/path_keys.rs` | `keys` CRUD + LIST. |
| `src/modules/totp/path_code.rs` | `code` generate + validate. |

Dependencies to add to top-level `Cargo.toml`:

```toml
sha1   = "0.10"   # RFC 6238 default; not a transitive dep of bv_crypto today
url    = "2.5"    # otpauth:// parser
base32 = "0.5"    # RFC 4648 base32 encode/decode
```

(`hmac`, `sha2`, `subtle`, `rand_core`, `getrandom` are already available transitively.)

### Phase 2 -- QR Barcode + Authenticator UX

| File | Purpose |
|---|---|
| `src/modules/totp/barcode.rs` | `qrcode` -> `image::ImageBuffer` -> PNG bytes -> base64. |

```toml
qrcode = "0.14"   # pure-Rust QR encoder
image  = { version = "0.25", default-features = false, features = ["png"] }
base64 = "0.22"   # already in tree
```

### Phase 3 -- Replay Protection + Tidy

| File | Purpose |
|---|---|
| `src/modules/totp/backend.rs` (extension) | Replay index storage + per-validate dedupe. |
| `src/modules/totp/tidy.rs` | Sweeper that drops replay entries older than `(skew + 1) * period`. |

### Phase 4 -- GUI Integration

| File | Purpose |
|---|---|
| `gui/src/routes/SecretsPage.tsx` (extension) | "TOTP" tab listing TOTP mounts and keys. |
| `gui/src/components/TotpKeyModal.tsx` | Create-key modal with generate/provider toggle, returns the QR PNG inline so the operator can scan it without ever copying the seed. |
| `gui/src/components/TotpCodeWidget.tsx` | Live "current code" display with a circular timer for the remaining period seconds; refreshes every second. |

The GUI piece is what makes the engine practically useful for a desktop user; without it operators must use the CLI to fetch a code every 30 seconds.

### Not In Scope

- **HOTP** (counter-based, RFC 4226) keys. The engine is TOTP-only; HOTP requires a separate counter-persistence model and very different replay handling. Tracked as a possible follow-up if requested.
- **OCRA** (RFC 6287) challenge-response. Niche.
- **Push-notification 2FA** (Duo / Authy push). Out of scope -- that's an auth backend, not a secret engine.
- **PQC variants of TOTP**. RFC 6238 is HMAC-based by definition; there is no NIST-standardised PQC HOTP/TOTP construction. The engine sticks to the RFC and relies on barrier encryption + (planned) HSM-backed seal for at-rest protection.
- **Hardware OATH applet provisioning** (writing the seed directly into a YubiKey OATH slot via PC/SC). Tracked separately under the YubiKey work; if added it would consume this engine's `key` response rather than duplicating logic.

## Testing Requirements

### Unit Tests

- HOTP test vectors from RFC 4226 Appendix D (8 vectors): byte-identical output for `(K, counter)` pairs.
- TOTP test vectors from RFC 6238 Appendix B (10 vectors across SHA1/SHA256/SHA512, 8-digit): byte-identical output for known `(K, T)` pairs.
- `otpauth://` round-trip: build URL from policy, parse it back, get the same policy.
- Base32 decoder tolerates lowercase, whitespace, and missing padding.
- Validator accepts codes within `±skew` and rejects codes outside.
- Replay test: validate code C at step T succeeds; validate code C at step T again returns `valid: false`.

### Integration Tests

- Mount totp, create a generate-mode key, fetch a code, sleep `period+1`s, fetch again, confirm the codes differ.
- Create a provider-mode key from a known seed (the "JBSWY3DPEHPK3PXP" RFC test seed), validate a code computed externally with `oathtool`, expect `valid: true`.
- Create a generate-mode key with `qr_size=200`, confirm the response includes a base64 PNG that decodes to a 200x200 image whose decoded QR text equals the `url` field.
- Tune `default_skew=2`, validate a code from `now - 2*period`, expect `valid: true`. Tune back to `1`, same input, expect `valid: false`.

### Cucumber BDD Scenarios

- Operator mounts the TOTP engine, generates a key for `acme.example.com:alice`, scans the QR with an authenticator app, and the next 30-second window's `GET /code/:name` matches what the app shows.
- Operator imports an existing TOTP seed (provider mode) used by an external SaaS, then validates the code their phone displays via `POST /code/:name` -- the engine returns `valid: true`.
- Operator rotates a key by deleting and re-creating it; the old seed no longer validates; the new QR scans cleanly.

### Negative Tests

- Posting `code` to a generate-mode key: rejected with a clear "generate-mode keys do not validate, use GET" error.
- GET `code` on a provider-mode key: rejected with the symmetric error.
- Creating a key with `digits=7`: rejected at policy validation.
- Creating a key with both `key` and `url`: rejected (mutually exclusive inputs).
- Reading `GET /v1/totp/keys/:name`: response must not include the `key` or `url` fields.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as PKI / Transit. CI must fail if either becomes reachable from `bastion-vault`.
- **Seed protection at rest**: TOTP seeds are stored inside `KeyPolicy` and barrier-encrypted with ChaCha20-Poly1305. Plaintext seeds never persist; a memory dump only sees the active in-memory copy during an active code-generation request.
- **One-shot seed disclosure**: in generate mode the seed is returned **in the create response only**. Subsequent `GET /v1/totp/keys/:name` calls return metadata with the seed redacted. This matches Vault's behaviour and means an audit log replay cannot leak the seed (since the create response body is HMAC'd by audit policy by default).
- **Constant-time validation**: candidate codes are compared with `subtle::ConstantTimeEq`. A timing oracle on the validator must not narrow the search space.
- **Replay window**: with default `skew=1`, the legitimate validation window is 90 seconds. Replay protection (Phase 3) closes the duplicate-validation hole within that window; without it, captured codes can be replayed `2*skew+1` times. The flag is on by default and operators must explicitly opt out.
- **Algorithm choice**: SHA1 is the RFC 6238 default and the only algorithm most consumer authenticator apps support. SHA256 and SHA512 are exposed for callers (e.g. YubiKey OATH applets) that handle them. SHA1 is **not** considered broken in the HMAC construction; the SHA-1 collision attacks (SHAttered et al.) do not apply to HMAC. We do not add a deprecation warning for SHA1 specifically because doing so would push operators toward keys their phones cannot scan.
- **Audit redaction**: `key`, `url`, and `barcode` are HMAC'd in audit logs. `code` request bodies are HMAC'd too; only the boolean `valid` from the response is logged in clear.
- **QR image rendering**: `qrcode` + `image` are pure-Rust and run in the engine process. The PNG buffer is built in memory and dropped after the response is serialised; no temp files are written.
- **Clock skew tolerance**: TOTP is fundamentally clock-bound. If BastionVault's clock drifts more than `skew*period` from the authenticator's clock, codes silently stop matching. Phase 1 documents the requirement to run `chrony` / `w32time` on the BastionVault host; a Phase 4 follow-up could optionally pin to an NTS source and surface drift in the GUI.

## Tracking

When phases land, update:

1. [CHANGELOG.md](../CHANGELOG.md) under `[Unreleased]` -- `Added` for new endpoints and the GUI tab.
2. [roadmap.md](../roadmap.md) -- move "Secret Engine: TOTP" from `Todo` -> `In Progress` (Phase 1 in flight) -> `Done` (Phase 3 shipped; Phase 4 GUI optional).
3. This file (`features/totp-secret-engine.md`) -- mark phases Done and refresh "Current State".
