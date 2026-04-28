# Feature: PKI — ACME Server Endpoints

## Summary

Expose an [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) ACME (Automated Certificate Management Environment) server on the PKI engine so internal clients (`certbot`, `acme.sh`, `lego`, container-orchestrator cert-managers) can request and renew certificates without operator-mediated `pki/issue` calls. The same engine that already issues certs via the Vault-shape API gains a parallel ACME-shape API rooted at `/v1/pki/acme/*`.

This is a **separate feature** from the core PKI engine ([features/pki-secret-engine.md](pki-secret-engine.md)). It was originally listed under "Not In Scope" of that feature; it has been spun out so the core engine can ship phases 1–5 without entangling with the ACME state machine, JWS verification, and challenge-validation infrastructure.

## Status

**Phases 6.1 + 6.1.5 + 6.2 shipped** — full RFC 8555 server surface for HTTP-01 **and DNS-01** issuance: JWS auth, directory + new-nonce, new-account + account/<id> (with contact / deactivate update **and EAB**), new-order + order/<id> + order/<id>/finalize, authz/<id> + chall/<id> with both HTTP-01 and DNS-01 validators, cert/<id> retrieval, and **revoke-cert** wired to the engine's existing CRL state. Operator-facing `acme/eab/<key_id>` CRUD provisions HMAC keys for External Account Binding. DNS-01 uses pinned resolvers (`dns_resolvers` config). Phase 6.3 (key-change, expiry sweep, rate limiting) follows.

## Motivation

- **`certbot --server` parity** with HashiCorp Vault. Vault added ACME server endpoints in 1.14 so the same automation that issues from Let's Encrypt can issue from a private Vault PKI mount. Operators expect the same surface from BastionVault.
- **No operator in the loop.** Today every leaf cert requires either an operator-driven `pki/issue` (engine generates the keypair) or `pki/sign/:role` (Phase 5; client supplies a CSR). Both require a Vault token. ACME accounts authenticate via JWS-signed account keys, not BastionVault tokens — closer to how internal-PKI consumers actually want to interact (per-cert renewal automation without persistent BastionVault credentials).
- **Compatibility with cert-manager / Traefik / Caddy.** All major cloud-native cert tooling speaks ACME natively. Supporting ACME is the cheapest way to make BastionVault the trust root for internal microservice mTLS.

## Scope

### In scope

- **RFC 8555 directory + nonce** (`GET /v1/pki/acme/directory`, `HEAD /v1/pki/acme/new-nonce`).
- **Account lifecycle** (`POST /v1/pki/acme/new-account`, `POST /v1/pki/acme/account/<id>`, account key rollover via `POST /v1/pki/acme/key-change`).
- **Order lifecycle** (`POST /v1/pki/acme/new-order`, `POST /v1/pki/acme/order/<id>`, `POST /v1/pki/acme/order/<id>/finalize`).
- **Authorizations + challenges** (`POST /v1/pki/acme/authz/<id>`, `POST /v1/pki/acme/chall/<id>`).
  - **HTTP-01** validator (engine issues a GET to `http://<domain>/.well-known/acme-challenge/<token>` and matches the keyAuthorization).
  - **DNS-01** validator (engine resolves `_acme-challenge.<domain>` TXT records and matches the keyAuthorization).
  - **TLS-ALPN-01** is out of scope for v1.
- **Certificate retrieval** (`POST /v1/pki/acme/cert/<id>`) and **revoke-cert** (`POST /v1/pki/acme/revoke-cert`).
- **JWS request envelope verification** with `RS256`, `ES256`, `EdDSA` account-key algorithms (matching what `certbot` and `acme.sh` emit by default).
- **Replay-Nonce tracking** with a barrier-stored ring buffer that carries N most-recent issued nonces.
- **Per-mount ACME enable flag** so an operator can mount `pki/` without exposing ACME if they prefer the Vault-shape API only.
- **Tying ACME orders into the existing role/CA stack.** A finalize call is a `pki/sign/:role` under the hood — same role policy, same CA, same CRL.
- **EAB (External Account Binding)** support so an operator can require pre-shared HMAC keys before a new account is accepted (Phase 6.2).

### Out of scope (explicit)

- **CAA record checking.** Internal PKI only — operators control DNS for the names they're issuing.
- **CA/Browser Forum Baseline Requirements compliance.** Same reason as the core engine: this is internal PKI, not a publicly-trusted CA.
- **OCSP stapling responses.** OCSP responder is its own deferred feature on the core engine; CRLs are sufficient for ACME revocation tracking.
- **CT (Certificate Transparency) submission.** Internal PKI does not log to CT.
- **Pre-RFC-8555 ACME v1.** Not implemented anywhere modern; clients that still speak v1 should be upgraded.

## Phases

### Phase 6.1 — Read-only flow + HTTP-01 — **Done (6.1 foundation + 6.1.5 lifecycle)**

**Done in this cut** (`src/modules/pki/acme/{jws,storage,path_config,directory,account}.rs`):
- JWS verification (RS256 / ES256 / EdDSA) with RFC 7638 thumbprints.
- Per-mount `pki/acme/config` operator-facing CRUD.
- `acme/directory` + `acme/new-nonce` (with bounded FIFO ring-buffer nonce store; single-use; aged-out nonces rejected as `acme: badNonce`).
- `acme/new-account` (verifies embedded `jwk`, persists at `acme/accounts/<thumbprint>`, idempotent on repeat with the same key, `onlyReturnExisting = true` returns `accountDoesNotExist`).
- `acme/account/<id>` (POST-as-GET; `kid`-flow JWS; refuses thumbprint mismatch).
- ACME endpoints registered as `unauth_paths`; JWS is the auth.
- `Replay-Nonce` + `Cache-Control: no-store` + `Link: <directory>;rel="index"` headers on every protocol response.

**Phase 6.1.5 shipped** (`src/modules/pki/acme/{order,authz}.rs`):
- `acme/new-order`, `acme/order/<id>`, `acme/order/<id>/finalize`.
- `acme/authz/<id>`, `acme/chall/<id>`.
- HTTP-01 validator (engine fetches `http://<domain>/.well-known/acme-challenge/<token>` via `ureq` with 5 s connect / 10 s global timeout, no redirects, 4 KiB body cap).
- `acme/cert/<id>` retrieval (returns `application/pem-certificate-chain` of leaf + issuer).
- `finalize` → existing `build_leaf_from_spki` path using `default_role` + `default_issuer_ref`; identifiers re-checked against the order, mixed classical/PQC chains rejected.
- Account-update (contact list + `status = "deactivated"`).
- Per-leaf cert recorded in the engine's normal `certs/<serial>` index so revoke + CRL flows pick it up.

### Original Phase 6.1 (full) — **Foundation done**

| Surface | Notes |
|---|---|
| `directory`, `new-nonce` | Unauthenticated. |
| `new-account`, `account/<id>` | JWS verification (RS256/ES256/EdDSA). Account state stored at `acme/accounts/<thumbprint>`. |
| `new-order`, `order/<id>` | Pending state; identifiers limited to `dns` type. |
| `authz/<id>`, `chall/<id>` (HTTP-01 only) | Engine fetches `http://<domain>/.well-known/acme-challenge/<token>` and matches keyAuthorization (RFC 8555 §8.3). |
| `finalize`, `cert/<id>` | Wraps `pki/sign/:role` under the hood; the role and CA are configured per-mount. |

**Storage layout (proposed):**
```
acme/config         # directory metadata + per-mount settings
acme/accounts/<id>  # ACME account record + JWK
acme/orders/<id>    # order state + CSR + identifiers
acme/authz/<id>     # authorization state per identifier
acme/chall/<id>     # challenge state + last-attempt result
acme/nonces/issued  # ring buffer of recently issued nonces (replay window)
```

### Phase 6.2 — DNS-01 + EAB + revoke — **Done**

Shipped (`src/modules/pki/acme/{dns01,eab,revoke}.rs`):
- DNS-01 validator (`hickory-resolver` 0.24, `_acme-challenge.<domain>` TXT lookup, match against `base64url(SHA-256(keyAuthorization))`). Pinned resolvers via `acme/config.dns_resolvers` (comma-separated `<ip>` or `<ip>:<port>`); falls back to the system resolver only when the list is empty. New-order now mints both an HTTP-01 and a DNS-01 challenge per authz so the client picks which to satisfy.
- External Account Binding (RFC 8555 §7.3.4): operator-facing `acme/eab/<key_id>` CRUD mints/lists HMAC-SHA-256 keys; `new-account` validates the inner JWS (`alg = HS256`, `kid` resolves to a stored key, payload JWK matches the outer envelope's account JWK by RFC 7638 thumbprint, HMAC verifies). Per-mount `eab_required` flag gates whether the binding is mandatory; consumed keys are marked single-use.
- `acme/revoke-cert` (RFC 8555 §7.6): kid-flow JWS, payload `{ certificate: <b64url DER>, reason?: <int> }`. The requesting account must own an order whose stashed cert chain encodes the supplied serial; on match, drops into the same `pki/revoke` plumbing (flip `CertRecord.revoked_at_unix`, append to the issuer's CRL state, rebuild that issuer's CRL).

### Phase 6.3 — Polish

- Account key rollover (`key-change`).
- Order/authz expiry sweep (folded into the existing Phase 4 tidy job).
- Per-mount HMAC-signed external bindings rotation.

## Design Sketch

### Module layout (proposed)

```
src/modules/pki/acme/
├── mod.rs          -- route registration, ACME-Mount config
├── jws.rs          -- JWS verification (RS256/ES256/EdDSA), Replay-Nonce
├── directory.rs    -- directory + new-nonce
├── account.rs      -- new-account / account / key-change
├── order.rs        -- new-order / order / finalize / cert
├── authz.rs        -- authz / chall + state machine
├── http01.rs       -- HTTP-01 validator
├── dns01.rs        -- DNS-01 validator (Phase 6.2)
└── storage.rs      -- per-mount ACME storage layout
```

### Tying into the existing PKI engine

ACME's `finalize` endpoint takes a CSR (the client's CSR) and a fulfilled order. The handler:

1. Verifies all identifiers in the order have `valid` authorizations.
2. Re-validates the CSR's subject and SAN identifiers against the order's identifiers (RFC 8555 §7.4: the CSR may NOT add identifiers the order didn't authorize).
3. Calls into the same code path `pki/sign/:role` already uses (`x509::build_leaf_from_spki`) with the role configured for the ACME mount.
4. Stores the resulting cert at `acme/orders/<id>/cert` AND in the engine's normal `certs/<serial>` index so revoke + CRL flows pick it up.

This keeps ACME cert issuance as a *thin shim* over the Phase 5 CSR signing path — no new TBS/signature plumbing.

### Security considerations

- **JWS signature verification is the auth.** Account keys are bound at `new-account` and every subsequent request must be signed by that key. Replay-Nonce prevents replay; key thumbprint identifies the account.
- **External Account Binding** for environments where operators want pre-distributed credentials before any account can be created. Phase 6.2.
- **HTTP-01 validator must follow `Host:` header**, must enforce a small response-size limit, and must time out aggressively (avoid SSRF amplification).
- **DNS-01 resolver pinning** so a misbehaving system resolver cannot be used to validate non-issued names. Phase 6.2.
- **Order / authz lifetimes** configurable; default 7 days for orders, 30 days for authz (RFC 8555 §7.1.2 doesn't mandate specific lifetimes, but most CAs use these).
- **Rate limiting per account.** Phase 6.3 — without it, a compromised account key can DoS the engine.

## Dependencies (planned)

- `josekit` or hand-rolled JWS — `josekit` is heavy but well-tested; hand-rolled is feasible because we already have `rsa`, `p256`, `ed25519-dalek` for the three account-key algorithms ACME requires. Decision deferred to Phase 6.1 implementation time.
- `hickory-resolver` (formerly `trust-dns-resolver`) for the DNS-01 validator. Phase 6.2.
- `ureq` (already in tree) for the HTTP-01 validator's outbound GET.

No new C-linked deps. ACME does not require any cryptographic primitive the existing engine doesn't already use.

## Testing plan

### Unit tests

- JWS round-trip for each supported algorithm (RS256/ES256/EdDSA).
- Nonce replay rejection.
- HTTP-01 keyAuthorization computation matches RFC 8555 §8.1.

### Integration tests

- Boot a `lego` or `acme.sh` client against a BastionVault PKI mount with ACME enabled, request a cert, validate the chain.
- Order with mismatched CSR identifiers must fail `finalize`.
- Revoke a cert via `revoke-cert` and verify the serial appears on the engine's `pki/crl`.

### Cucumber BDD scenarios

- Operator enables ACME on a PKI mount; `certbot` registers an account, requests a cert with HTTP-01, gets a valid cert chained to the mount's CA.

## Tracking

This is a **future feature**, not in the current PKI roadmap row. When implementation starts:

1. Add a row in `roadmap.md` under "Secret Engines" (or a new "PKI Add-ons" sub-section) referring back to this file.
2. Update `features/pki-secret-engine.md`'s "Not In Scope" list to point here for ACME.
3. Update `CHANGELOG.md` per phase, the same way the core PKI engine tracks Phases 1–4.1.
