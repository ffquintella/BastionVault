# Feature: PKI Key Management + Centralized Cert Lifecycle

## Summary

Extend the existing PKI engine ([features/pki-secret-engine.md](pki-secret-engine.md)) with first-class **managed private keys** (so a user can generate, import, list, reuse, and rotate keys independently of any single certificate), tighten the **emission-control** surface (issuer policy, role constraints, per-role ACME gating), and introduce a **sibling `cert-lifecycle` module** that centralizes SSL certificate distribution to consumers (agents, plugins, ACME-driven targets) without bloating the CA itself.

The split is deliberate:

- The **PKI engine stays a CA** — issuer chains, roles, CRLs, ACME server, key store. Auditable, narrow, crypto-only.
- The **`cert-lifecycle` module is a workflow engine** — inventory of managed endpoints, renewal scheduling, push transport, plugin trait. It *consumes* the PKI engine (or external ACME) but holds no signing keys of its own.

## Motivation

- **Key reuse is a real operator need.** Embedded devices, HSM-bound keys, certificate pinning in mobile clients, and "cert renewed but app re-uses the existing private key" workflows all require decoupling key lifecycle from cert lifecycle. Today every `pki/issue` call mints a fresh keypair; there is no way to say "renew this leaf, keep the same key".
- **Emission control is currently spread thin.** Roles enforce `key_type` / `ttl` / SAN flags, but `allowed_domains` / `allow_glob_domains` are still deferred (per [features/pki-secret-engine.md:56](pki-secret-engine.md)). Operators need a single matrix of *who can mint what under which issuer*.
- **Centralized SSL means more than issuance.** Issuing a cert is step one; getting it onto the right load balancer, k8s secret, file path, or device, then renewing before expiry, is the actual operational burden. Vault delegates this to external tools (cert-manager, Traefik). BastionVault can do better by exposing a lifecycle module that the existing plugin system can target.
- **Plugin / agent integration.** The plugin-ext branch already establishes a plugin surface. A lifecycle module gives plugins a stable contract ("deliver this cert+key bundle to target X, report back") instead of each plugin re-implementing renewal scheduling.

## Scope

### In scope — PKI engine extensions

1. **Managed key store** (`pki/keys/*`)
   - Generate: `POST pki/keys/generate/{exported|internal}` — algorithm + bits, returns `key_id` (and the PEM if `exported`).
   - Import: `POST pki/keys/import` — caller-supplied PEM (PKCS#8 or our `BV PQC SIGNER` envelope for ML-DSA), barrier-encrypted on store.
   - List / read / delete: `LIST pki/keys`, `GET pki/keys/{key_id}`, `DELETE pki/keys/{key_id}` (delete refuses if any active issuer or unexpired cert references the key).
   - Rotate-pointer-only: keys are immutable once stored; "rotation" means generating a new key and updating references, never editing an existing key blob.
2. **Key reuse on issuance**
   - `pki/issue/:role` and `pki/sign/:role` accept an optional `key_ref` (`key_id` or `name`). When set, the engine signs a cert that binds to the referenced public key instead of generating fresh material.
   - For `sign/:role`, this is a no-op unless the CSR's SPKI matches the referenced key — mismatch is a hard error.
   - Roles gain `allow_key_reuse` (default `false`) and `allowed_key_refs` (optional allow-list). Default is closed: a role must explicitly opt in before any caller can pin a key.
3. **Issuer-bound keys**
   - `pki/issuers/generate/root` and `pki/intermediate/generate` accept `key_ref` so a pre-generated key (e.g. from an HSM-backed import path, future) can be promoted to issuer.
   - On issuer rotation, the old key remains in the key store referenced by the historical issuer entry; CRL signing for already-issued certs continues to work.
4. **Emission-control completion**
   - Implement deferred `allowed_domains` / `allow_glob_domains` / `allow_subdomains` enforcement (closes [features/pki-secret-engine.md:56](pki-secret-engine.md)).
   - Per-role `acme_enabled` flag — ACME `new-order` against a role with `acme_enabled = false` rejects.
   - Per-issuer `max_path_length` and `max_ttl` clamps so an intermediate cannot mint past its own validity.
5. **Chain UX polish**
   - `GET pki/issuer/:ref/chain` returns the PEM bundle root → leaf-issuer.
   - `pki/issue/*` and ACME finalize responses include `ca_chain` consistently (today varies by path).

### In scope — new `cert-lifecycle` module

6. **Target inventory** (`cert-lifecycle/targets/*`)
   - A *target* is a named consumer of a cert: `{name, kind, address, role_ref, key_policy, schedule}`.
   - `kind` is one of `file` (agent writes to disk), `k8s-secret`, `http-push` (PUT to a webhook), `plugin/<plugin_id>` (delegate to a plugin-ext plugin).
   - `key_policy` is one of `rotate` (new keypair every renewal), `reuse` (pin one `key_ref` from the PKI key store across renewals), `agent-generates` (target produces CSR, lifecycle module only signs).
7. **Renewal scheduler**
   - Single tokio task (mirrors `pki/scheduler.rs`), wakes on a tick, finds targets whose cert is past `renew_at = NotAfter - renew_before`, drives a renewal.
   - Renewal goes through `pki/sign/:role` (CSR-driven) or `pki/issue/:role` (engine-generated) depending on `key_policy`.
   - Outcome (success / failure / next-attempt) recorded under `cert-lifecycle/state/<target>`; failures back off exponentially.
8. **Plugin trait**
   - `trait CertDeliveryPlugin { fn deliver(&self, target: &Target, bundle: &CertBundle) -> Result<DeliveryReceipt>; }`
   - Built-in implementations: `file`, `k8s-secret`, `http-push`. External plugins register through plugin-ext.
9. **Audit + observability**
   - Every renewal attempt emits an audit record (target name, role, issuer, serial issued, delivery status).
   - Status endpoint `GET cert-lifecycle/status` lists targets with `{last_renewal, next_renewal, current_serial, last_error}`.

### Out of scope (explicit)

- **HSM-backed managed keys.** The key store accepts software-only keys in this feature. HSM integration is tracked separately in [features/hsm-support.md](hsm-support.md); when it lands, `key_id` becomes a uniform handle whether the material is in-barrier or in-HSM.
- **Cert distribution to public-internet targets.** The lifecycle module assumes targets reachable from the BastionVault server (or via a plugin transport). Public ACME-style validation flips the direction and is out of scope here.
- **Multi-CA failover.** Each target binds to one role on one PKI mount. "Renew from CA-A, fall back to CA-B on outage" is not in v1.
- **Cert pinning policy enforcement on the consumer side.** The lifecycle module delivers; whether the consumer pins, validates, or hot-reloads is the consumer's responsibility.

## Security Considerations

- **Key reuse extends the exposure window of a private key.** Default `allow_key_reuse = false` on roles is intentional. Operators opting in must understand they are trading rotation hygiene for operational convenience. This is documented on the role schema.
- **`pki/keys/import` must reject obviously-weak material** (RSA < 2048, non-curve EC, malformed PKCS#8). Import validates SPKI parses cleanly and the private/public halves agree before storing.
- **`pki/keys/generate/exported`** returns the private key once at generation time; subsequent reads of an `exported`-mode key still return the PEM (matches Vault semantics) but the audit log records every read. `internal` mode never returns the private key over the API.
- **Key deletion is reference-counted.** A key referenced by an active issuer or any unexpired non-revoked cert cannot be deleted — operators must rotate or revoke first. Force-delete is not exposed.
- **Lifecycle module never holds plaintext private keys at rest.** Material in transit between PKI engine and target lives only in the renewal task's heap; on success, only the public cert is recorded under `cert-lifecycle/state`. Private keys delivered to targets are zeroized after the plugin's `deliver` returns.
- **Plugin trust boundary.** A `CertDeliveryPlugin` receives a private key in memory. Plugin authorization rides on the existing plugin-ext permission model; targets must explicitly name the plugin they delegate to. No plugin can subscribe to "all renewals".
- **Audit completeness.** Every key generation, key import, key reference, issuance via reused key, target creation, and renewal attempt is audited. Audit records reference `key_id` not key material.

## Current State

**Phases L1 + L2 + L3 + L4 — Done.**

**L1** ships the managed key store at `pki/keys/*` (LIST + generate `internal`/`exported` + import) and `pki/key/<key_ref>` (READ + DELETE). Storage: `keys/<id>` (KeyEntry), `key-names/<name>` (id pointer), `key-refs/<id>` (KeyRefs). Import accepts PKCS#8 RSA / ECDSA / Ed25519, PKCS#8 ML-DSA (lamps-draft layout), and the engine-internal `BV PQC SIGNER` envelope; an explicit RSA-strength gate rejects sub-2048 modulus before reaching the lenient `Signer::from_storage_pem` fallback. Delete refuses while `KeyRefs` is non-empty.

**L2** lights up key reuse on `pki/issue/:role` and `pki/sign/:role` via an optional `key_ref` body field. Roles gain `allow_key_reuse` (default `false`, closed) and `allowed_key_refs` (optional allow-list). On `issue`, the leaf is signed against the pinned managed key — renewals share the private key. On `sign`, the CSR's SubjectPublicKeyInfo must match the pinned key (mismatch is a hard error). Algorithm-class mismatch (e.g. RSA managed key on EC role) is rejected. After successful issuance, the cert serial is recorded in the key's refs file via `keys::add_cert_ref`.

**L3** ties managed keys to issuers and surfaces the chain consistently:
- `pki/root/generate/{internal|exported}` and `pki/intermediate/generate/{internal|exported}` accept `key_ref` to promote a managed key to issuer instead of generating fresh material. Algorithm-mismatch is rejected. Bindings recorded in `KeyRefs.issuer_ids`. When `key_ref` is supplied on `exported` mode, the route does *not* re-echo the private key (the operator owns it through the key store).
- `CertRecord.key_id` is populated when a leaf was issued via `key_ref`. `PendingIntermediate.key_id` carries the binding through the two-stage intermediate flow until `set-signed` lands.
- `pki/revoke` clears the cert-serial binding from the managed key's `KeyRefs` so deletion can succeed once all certs the key bound are revoked. Best-effort: revoke proceeds even if refs cleanup fails.
- `build_issuer_chain` walks the local issuer registry by Subject/Issuer DN matching to assemble a `[leaf-issuer, …, root]` PEM array, stopping when it hits a self-signed root or an off-mount parent.
- New route `READ /v1/pki/issuer/<ref>/chain` returns `{ca_chain, certificate_bundle}`.
- `pki/issue`, `pki/sign/:role`, and `pki/sign-verbatim` responses now include a `ca_chain` array consistently.

**L4** closes the deferred emission-control gap from Phase 1 and adds chain-correctness gates:
- `RoleEntry` gains `allowed_domains: Vec<String>`, `allow_glob_domains: bool`, and `acme_enabled: bool` (default `true` for backwards compatibility).
- `validate_common_name` and the new `validate_dns_name` implement the full Vault matrix: `allow_any_name`, `allow_localhost`, `allow_bare_domains`, `allow_subdomains`, `allow_glob_domains` (single-label `*` matches that don't span dots).
- DNS SANs are validated alongside the CN on `pki/issue/:role`, `pki/sign/:role`, and ACME finalize.
- `pki/acme/new-order` rejects up front when the configured role has `acme_enabled = false` so the client doesn't burn through authz state.
- New `issuers::clamp_ttl_to_issuer` ensures every leaf's `NotAfter` ≤ issuer's `NotAfter`. Wired into `issue`, `sign/:role`, `sign-verbatim`, and ACME finalize. Already-expired issuers return `ErrPkiCaNotConfig`.
- `pki/root/sign-intermediate` reads the parent issuer's `BasicConstraints.pathLenConstraint` and clamps the child's pathLen to `parent_max - 1`. Refuses to sign when parent has `pathLenConstraint = 0`.

End-to-end coverage in [tests/test_pki_managed_keys.rs](../tests/test_pki_managed_keys.rs) (L1, 9 cases), [tests/test_pki_key_reuse.rs](../tests/test_pki_key_reuse.rs) (L2, 7 cases), [tests/test_pki_issuer_keys.rs](../tests/test_pki_issuer_keys.rs) (L3, 6 cases), and [tests/test_pki_emission_control.rs](../tests/test_pki_emission_control.rs) (L4, 6 cases).

**Implementation notes / deviations:**
- `key_ref` is honoured on `pki/issue/:role`, `pki/sign/:role`, `pki/root/generate/*`, and `pki/intermediate/generate/*`. `pki/sign-verbatim` is intentionally excluded from leaf reuse — it has no role to gate `allow_key_reuse` against.
- The chain walk uses textual DN comparison via `x509-parser`'s `to_string()`. Distinct issuers with identical Subject DNs (a pre-existing data hazard at the mount) cause first-match-wins behaviour. Real deployments use unique CA names, so this is acceptable for L3.

L5–L7 (the cert-lifecycle module) are not yet implemented. Roadmap entry tracks the active phase under "PKI: Key Management + Cert Lifecycle" in [roadmap.md](../roadmap.md).

## Phases

| Phase | Scope | Depends on |
|-------|-------|-----------|
| **L1** | Managed key store: generate / import / list / read / delete (software keys only). | PKI Phase 5.2 (multi-issuer storage). |
| **L2** | Key reuse on `pki/issue` + `pki/sign` (role flag, `key_ref` param). | L1. |
| **L3** | Issuer-bound keys (`key_ref` on root/intermediate generate). Chain UX polish. | L1. |
| **L4** | Deferred emission controls: `allowed_domains` enforcement, per-role `acme_enabled`, per-issuer `max_ttl` / `max_path_length`. | None — independent. |
| **L5** | `cert-lifecycle` module: target inventory + state storage, no scheduler yet. Manual `cert-lifecycle/renew/<target>` endpoint. | L2 (so `key_policy = reuse` works). |
| **L6** | Renewal scheduler. Backoff + audit. | L5. |
| **L7** | Plugin trait + built-in `file`, `k8s-secret`, `http-push` deliverers. External plugin-ext integration. | L5, plugin-ext. |

Each phase ships independently; L4 has no dependency on the key store and can land first if it unblocks ACME consumers.

## Storage Layout (additions)

PKI engine:

```
pki/<mount>/keys/<key_id>          -- KeyEntry { algorithm, public_key_der, private_key_pem (sealed), created_at, exported_mode }
pki/<mount>/keys/by-name/<name>    -- pointer to key_id (optional human-friendly alias)
pki/<mount>/keys/refs/<key_id>     -- reference set: issuers + cert serials currently bound to this key
```

Lifecycle module (new top-level mount):

```
cert-lifecycle/targets/<name>      -- Target { kind, address, role_ref, key_policy, schedule, ... }
cert-lifecycle/state/<name>        -- TargetState { current_serial, current_not_after, last_renewal, last_error, next_attempt }
cert-lifecycle/audit/<ts>-<name>   -- append-only renewal log (subject to existing audit retention)
```

All entries pass through the storage barrier; private-key material in `pki/<mount>/keys/<key_id>` is sealed identically to existing CA keys.

## Test Plan

- `tests/test_pki_managed_keys.rs` — generate (exported + internal), import (RSA, ECDSA, Ed25519, ML-DSA-65), list, read, delete, delete-with-references-fails, weak-key-rejection.
- `tests/test_pki_key_reuse.rs` — issue with `key_ref` (matches role allow-list), issue with `key_ref` not in allow-list (rejected), `sign/:role` with mismatched CSR/key (rejected), renewal across two issuance calls produces two certs sharing one SPKI.
- `tests/test_pki_emission_control.rs` — `allowed_domains` accept + reject matrix, `allow_glob_domains`, `allow_subdomains`, per-role `acme_enabled = false` blocks ACME `new-order`, per-issuer `max_ttl` clamps.
- `tests/test_cert_lifecycle_basic.rs` — create target with `kind = file`, manual renew, file written with cert+key, audit record emitted.
- `tests/test_cert_lifecycle_scheduler.rs` — target with short TTL + small `renew_before`, wait past threshold, scheduler tick fires renewal, state updated, second tick within window does not re-fire.
- `tests/test_cert_lifecycle_plugin.rs` — register a stub plugin, target delegates to it, plugin receives bundle, deliver succeeds + records receipt; deliver-fails path records error and schedules backoff.

## Open Questions

1. **Key naming uniqueness scope** — per-mount or global? Per-mount matches issuer scoping today; argues for per-mount.
2. **Cross-mount key reuse** — should a key generated in `pki-prod/` be referenceable from `pki-dr/`? Default no; explicit export/import keeps the audit trail clean.
3. **Lifecycle module mount semantics** — single global mount (`cert-lifecycle/`) or pluggable like `pki/`? Single global is simpler; revisit if multi-tenant namespaces (see [features/namespaces-multitenancy.md](namespaces-multitenancy.md)) demand per-namespace lifecycle.
4. **ACME-driven targets** — should a target be able to declare "renew from external ACME (Let's Encrypt) instead of internal PKI"? Useful for centralizing public + private cert lifecycle in one inventory. Likely a Phase L8.

## Tracking

On completion of each phase:

- Update `roadmap.md` with the new initiative + phase status.
- Update `CHANGELOG.md` under `[Unreleased]` (`Added` for new endpoints / module, `Changed` for role schema additions).
- Update this file's "Current State" section (to be added on first phase landing) with shipped phases + deviations.
