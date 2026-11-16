# Feature: Identity Provider (Workforce Identity Brokering for Downstream Systems)

## Summary

Turn BastionVault into an **outbound identity provider** for the systems it
guards, so that an administrator who connects to a server, firewall, switch, or
appliance *through the vault* arrives **as themselves** rather than as a shared
`admin` / `root` / `fortinet` account. Every privileged session is then
attributable to a real, named human, and the destination system enforces that
person's own entitlements.

Today BastionVault consumes external identity (it is an OIDC **relying party**
and a SAML **service provider** — see [oidc-auth.md](oidc-auth.md),
[saml-auth.md](saml-auth.md)) and it *mints credentials* for targets via the
SSH/PKI engines. What it does **not** do is project a **stable, authoritative
human identity** onto those targets in a way the targets natively understand.
This feature adds that projection through three pillars:

1. **Canonical workforce identity with a stable POSIX mapping.** Every
   authorized human is allocated, exactly once, an immutable `(login, uid, gid)`
   triple that is **identical across every environment, namespace, and target**
   and is **never reused** after the person leaves. This is the anchor that
   makes "who was logged in to that box at 02:00?" answerable from the OS audit
   trail alone.
2. **Identity-bearing credential issuance, gated by environment authorization.**
   Credentials are only ever issued to people who are *authorized for the
   specific environment* being entered, and they carry the canonical identity
   inside them: SSH certificates whose `valid principals` and `key id` are the
   person's login + UID; RADIUS/SAML/OIDC assertions whose subject is the
   person; LDAP-compat entries with consistent `uidNumber`/`gidNumber`.
3. **Lifecycle-driven revocation propagation.** When an identity is disabled or
   removed, it is **blocked at the destinations** — short credential TTLs expire,
   an SSH KRL revokes outstanding certs, federated sessions are killed, RADIUS
   rejects, the LDAP-compat bind fails, and a signed **deny feed** lets agents on
   targets enforce the block proactively.

The downstream-facing surface is deliberately **multi-protocol** because the
targets are heterogeneous:

- **Linux hosts** consume **SSH certificates** (the existing SSH CA engine) plus
  an optional **NSS/`AuthorizedPrincipalsCommand` feed** so the host resolves the
  certificate principal to the canonical UID without a local account per person.
- **FortiGate and other network appliances** consume **RADIUS** (admin login with
  vendor attributes like `Fortinet-Group-Name`) and/or **SAML SP** SSO — both
  protocols FortiOS speaks natively.
- **Generic SSO-capable apps** consume **OIDC** (BastionVault as an OpenID
  Provider) or **SAML IdP**.
- **LDAP-only systems** consume a **read-only LDAP-compatible directory** front
  that serves the consistent POSIX attributes.

> This feature is the *mirror image* of the existing OIDC/SAML auth backends.
> Those let a human prove identity **to** BastionVault. This lets BastionVault
> assert that identity **to** everything downstream. The two share the entity
> model but are separate code paths (relying-party verify vs. provider issue).

## Motivation

- **Attribution / accountability.** Shared break-glass accounts (`root`,
  `admin`, the FortiGate `admin` superuser) destroy attribution: the OS / device
  audit log shows the shared name, and you must cross-reference the bastion's own
  log to learn who it really was — assuming the two clocks and session IDs line
  up. Projecting the real identity onto the target makes the target's *own* logs
  authoritative. This directly extends the value of the v0.18.0 login-audit work
  ([CHANGELOG](../CHANGELOG.md)) from "who logged into the vault" to "who logged
  into the *fleet*."
- **Consistent UID across environments is an operational hard requirement.** If
  Alice is `uid=80017` on dev but `uid=90042` on prod, file ownership, `sudo`
  rules, `last`/`utmp`, auditd `auid`, and config-management drift all break the
  moment a host or a backup moves between environments. A single
  vault-authoritative UID space fixes this once.
- **Joiner/mover/leaver enforcement at the edge.** Disabling someone in a central
  directory is worthless if their cached SSH key still works on 400 hosts for the
  next 90 days. Short-lived, identity-bound credentials + an active deny feed turn
  "disabled in the IdP" into "locked out of the fleet in minutes."
- **Appliances are first-class.** Network/security gear (FortiGate, switches,
  WAFs) is where shared-admin risk is highest and where individual local accounts
  are least practical. RADIUS/SAML let those devices defer to BastionVault for
  *who* and *what role* without per-device account sprawl.
- **We already have the building blocks.** The SSH CA engine
  ([ssh-secret-engine.md](ssh-secret-engine.md)), the identity/entity model
  ([identity-groups.md](identity-groups.md),
  [per-user-scoping.md](per-user-scoping.md)), namespaces as the environment
  boundary ([namespaces-multitenancy.md](namespaces-multitenancy.md)), the
  policy engine, and the audit chain are all in place. This feature composes them
  and adds the missing projection layer rather than building a parallel identity
  store.

## Current State

**Phase 1 (POSIX identity core), Phase 2 (entitlements + gate), Phase 3
(SSH identity issue + revocation) and Phase 4 (RADIUS) are implemented, with
caveats; Phases 5–7 are Pending.** Phases 2–4 are described after Phase 1's
caveats below.
The code lives in the Tier 3 crate `crates/bv-engine-idp` (not
`src/modules/idp/`: engines are separate crates since the workspace
decomposition), registered in the facade's `default_modules()` as the `idp`
mount type. What exists:

- **Mounting.** Not a default mount: an operator enables it once in the root
  namespace (`sys/mounts/idp type=idp`), so existing deployments gain no new
  surface on upgrade. The store does not live on the mount's own view but on
  the root system view (`sys/` barrier, sub-path `idp/posix/`), so every `idp`
  mount shares one uid/gid space. Requests are refused unless they are `v2`,
  come from the root namespace, *and* arrive through an `idp` mount of the
  root mount table (a child namespace that mounts the type is refused in both
  the header and the path-prefix addressing forms).
- **Records** (all JSON, `version: 1`, unknown versions and unknown fields
  refused): `config` (uid/gid ranges), `alloc/uid` and `alloc/gid` (high-water
  mark, run-length-encoded `used` set, `retired` tombstones), `identities/<entity_id>`,
  and never-deleted index keys `index/{login,uid,gid}/<key>` → `entity_id`.
- **Allocator.** Every write runs under a process-local mutex plus the storage
  backend's lock (Raft-replicated on hiqlite, a lock file on the file
  backend). Allocator state is written before the index keys and the identity
  record, so a crash burns an id but never reissues one. Four guards against
  reuse: the high-water mark (vault allocation only moves upward), the `used`
  set, the `retired` set and the per-id index key (re-checked with an uncached
  read before an id is committed). Primary gid = uid when free
  (user-private-group convention).
- **Import mode** (`uid_source: "imported"`) seeds existing uids/gids from
  `1000`–`2147483647`, collision-checked against all of the above; imports do
  not move the high-water mark.
- **Lifecycle** `active → disabled → removed`, `disabled → active`; removal is
  terminal, tombstones uid and primary gid, and keeps the login reserved.
  `DELETE` is the `removed` transition. Only `display_name` and supplementary
  `gids` are mutable.
- **Supplementary gids** may not name another identity's primary group
  (current or removed) and are reserved against future primary allocation.

Decisions taken where this spec was open: logins are never reused (not only
uids); `DELETE` maps to removal rather than erasing the record; the entity must
exist in the identity store at allocation time (later updates and lifecycle
changes do not require it); imported ids below `1000` are refused.

Caveats: not run against a multi-node hiqlite cluster (concurrency is covered
by unit tests over an in-memory store and by the lock design); with the
optional `secret_cache_ttl_secs` read cache enabled on a cluster, the allocator
record can be read stale on a non-leader node — the per-id index check still
prevents reissuing a uid or primary gid because negative reads are never
cached, but a supplementary-group reservation (which has no index key) could be
dropped by a write based on the stale record; on the file backend a
crash while the lock file is held leaves a stale lock that blocks further
writes until it is removed (a property of the existing storage lock, not new
here). No CLI, GUI or dedicated audit-event type yet (lifecycle changes are
logged under the `idp` log target and appear in the normal request audit).

**Phase 2 (entitlements + gate).** `crates/bv-engine-idp/src/entitlement/`
(`model.rs`, `store.rs`, `gate.rs`) plus the `v2` handlers in
`src/backend/authz.rs`, on the same root-only guard. Store: root system view,
sub-path `idp/authz/`, shared by every `idp` mount; writes take a
process-local mutex plus the storage lock `bv-idp/authz`.

- **Environments** (`environments/<name>`, JSON `version: 1`, unknown
  versions and fields refused): a lower-case name bound at creation to one
  existing namespace, by path *and* the uuid it had then, never re-bound; at
  most one active environment per namespace; root (`""`) allowed. `roles`
  maps role names to ACL policy names in that namespace (`root`,
  `response-wrapping`, `control-group` refused). `DELETE` retires: terminal,
  and the name stays reserved.
- **Entitlements** (`entitlements/<entity_id>/<environment>`, `version: 1`):
  `roles` (each defined on the environment), optional `not_after` (future
  when granted), `source` `manual` | `external`, and `granted_by` /
  `granted_at` stamped by the server from the caller. A write replaces the
  grant; `DELETE` removes it. Needs a non-removed identity and an active
  environment.
- **Gate** (`entitlement::gate::IssueGate`, from `IdpModule::issue_gate()`):
  a Rust API for the providers, with no HTTP route. Allow requires, in
  order: well-formed input; both stores available; an `active` identity; an
  `active` environment whose namespace still resolves to the pinned uuid; a
  caller namespace that is root or the environment's own; an entitlement
  with `now < not_after`; requested roles all entitled; every effective role
  still defined on the environment. It returns login, uid, gids, the
  namespace, the roles and the union of their policies. Anything else is a
  deny with a reason code, including a storage read error, a record that
  does not decode, a namespace-registry error and an audit device refusing
  the allow event.
- **Audit.** Each decision is a `security` log line plus, with an audit
  device enabled, an `event` entry `idp.issue` / `idp.issue-denied` through
  the audit broker (`AuditEntry::event`, as the MCP connect events). Fields:
  decision, reason, provider, entity_id, environment, caller_namespace,
  requested_roles, login, uid, namespace, roles, policies, not_after.
  Caller-supplied strings are cut at 128 characters; no credential field
  exists.

Decisions taken where this spec was open (Phase 2):

- *Environment ↔ namespace* is an explicit, immutable binding by path and
  uuid, not "environment name = namespace path": names stay URL-safe
  single segments while namespaces may nest, and a namespace deleted and
  recreated under the same path is refused (`namespace_replaced`) instead of
  inheriting its predecessor's entitlements.
- *Role ↔ policy* is a per-environment map evaluated at issue time, so a
  policy change applies to the next issue. Rejected: copying policies into
  each entitlement, which would freeze them at grant time.
- *Caller namespace*: root may target any environment; any other namespace
  only the environment bound to itself (strict equality, no parent reach).
  Phase 3 settles which namespace a self-service `ssh/sign` caller
  presents (see Phase 3 below).
- An entitled role later removed from the environment denies the whole
  issue (`unknown_role`) rather than silently dropping the role.
- No `v2` dry-run/check route: the spec lists none, and an admin check would
  write `idp.issue` for something never issued.
- `group`-derived entitlements are deferred: the kernel contract has no
  entity → groups lookup, so `source: "group"` is refused.

Caveats (Phase 2): the SSH provider (Phase 3) is the gate's only caller.
Policy names are not checked against the namespace's policy store.
Entitlements are kept, not cascaded, when an identity is removed or an
environment retired (the gate denies both). Gate events go to root audit
devices only; a tenant's own devices do not see issuance into its
namespace. Not run on a multi-node cluster (Phase 1's read-cache caveat
applies to these records too).

**Phase 3 (SSH identity issue + revocation).** `src/provider/ssh/` (sign
flow, `idp/ssh/` store), `src/revoke/` (revocation view, KRL encoder, deny
feed, `idp/revoke/` store), `src/backend/ssh.rs`, and the reference host
helper (`src/host.rs` + `src/bin/bv-idp-host.rs`). Routes in
[docs/api.md](../docs/api.md).

- **Sign** (`v2/idp/ssh/sign/<environment>`): input checks, then the gate
  (its first caller; an issue happens only after an allow, and the gate's
  `idp.issue` event is the issuance record), then the SSH engine mounted
  at the configured `mount`/`role` **in the environment's namespace**
  signs, router-direct as `bv_kernel_api::ssh_credentials` does (no new
  kernel or SSH-engine API; no second signer). The IdP reads the
  certificate back with `ssh-key` and discards it unless principals = the
  login, key id = `bv:<entity_id>:<login>:uid=<uid>:env=<env>`, the four
  `*@bastionvault` extensions, public key, `user` type and validity all
  match; it then records it (`certs/<entity_id>/<serial>`, JSON
  `version: 1`) before returning it. TTL: default 30m, `max_ttl` at most
  8h, a larger request refused.
- **Revocation**: leaving `active` marks the identity's outstanding
  certificates revoked; a certificate whose owner is not active is listed
  even unmarked; reinstating marks first. The KRL (`v2/idp/ssh/krl`,
  checked against OpenSSH 10.5 `ssh-keygen -Q`) and the deny feed are built
  from one view under one version.
- **Deny feed** (`v2/idp/deny-feed`): signed with `bv_crypto`'s composite
  Ed25519 + ML-DSA-65 detached signature (the one Rustion's BVRG envelope
  uses) under a context prefix; version bound to a SHA-256 of the content,
  advanced under a lock, never lowered. Key in `idp/revoke/feed/key`,
  created on first use; an unreadable key is an error, never replaced.
- **Host helper** (`cargo build -p bv-engine-idp --bin bv-idp-host`):
  `install-feed` verifies a fetched feed (signature, version not below the
  installed one, `--max-age`, default 24h) and installs it atomically;
  `principals` is the `AuthorizedPrincipalsCommand`; `nss-entry` prints
  `libnss-extrausers` passwd/group lines from a certificate it verifies
  against the CA key. Wiring:

  ~~~
  TrustedUserCAKeys /etc/ssh/bv_user_ca.pub      # the environment's SSH CA
  RevokedKeys /etc/ssh/bv_revoked.krl             # base64 -d of .data.krl
  AuthorizedPrincipalsCommand /usr/local/sbin/bv-idp-host principals --key /etc/bv-idp/feed-key.json --state-dir /var/lib/bv-idp --environment prod %u %s %i
  AuthorizedPrincipalsCommandUser bv-idp
  ~~~

  plus a timer that fetches `v2/idp/ssh/krl` and `v2/idp/deny-feed` with a
  read-only token and runs `install-feed`. `--shared-account <user>` lets
  every identity log in as one local account, attributed by key id.

Decisions taken where this spec was open (Phase 3):

- *Caller namespace*: the sign route presents the namespace the request is
  served in (`caller_namespace`), the same rule the Phase 2 gate documents.
  The guard admits root only, so this is always root and the gate's
  namespace rule passes; which environments a caller reaches is decided by
  the entitlement plus the root ACL on `idp/ssh/sign/<environment>`.
  Rejected: presenting the token's home namespace binding, which no other
  route uses and which a root-only mount cannot be reached from anyway.
- *Self-service only*: the entity is the token's; there is no admin
  sign-on-behalf. The root token (no entity) is refused.
- *One CA per environment*: the SSH engine of the environment's own
  namespace signs, so a host trusting the prod CA rejects a dev
  certificate natively. The KRL has one section per CA.
- *Extensions*: `uid@`, `gid@` (spec) plus `env@` and `roles@bastionvault`;
  supplementary gids are not in the certificate.
- *TTL above `max_ttl`* is refused, not clamped.
- *Revocation scope*: lifecycle-driven only. Revoking an entitlement stops
  new issues but leaves outstanding certificates to expire; there is no
  single-certificate revoke route.

Caveats (Phase 3): no real sshd or Linux host was run; the helper's
`principals` and `install-feed` logic is unit-tested, its CLI and sshd
wiring are not. The NSS side is a line generator from a verified
certificate: sshd looks the user up before authentication, so an account
must exist first (provisioned with `nss-entry`, or the Phase 6
LDAP-compat front); on-login materialization is not delivered. An ML-DSA-65
(PQC) SSH CA is unsupported (certificates are refused at read-back). The
feed key is not rotated and not HSM-backed. Certificate records of expired
certificates are pruned 24h after expiry, at that identity's next issue.
The KRL and feed are authenticated routes (hosts need a token). Not run on a
multi-node cluster.

**Phase 4 (RADIUS).** `src/provider/radius/` (`packet.rs` codec, `vendor.rs`
attribute templates, `store.rs` on `idp/radius/`, `tls.rs`, `server.rs`
listeners, `mod.rs` decision) and `src/backend/radius.rs`. Routes in
[docs/api.md](../docs/api.md).

- **Who the human is.** Spec §3b says the human authenticates against a
  BastionVault auth backend. A RADIUS PAP exchange cannot carry FIDO2 or an
  OIDC redirect, and checking a userpass password from the RADIUS path would
  bypass the login pipeline (MFA, step-up, lockout). So the human logs in to
  the vault with any backend and mints a **one-time passcode** for one
  environment (`v2/idp/radius/passcode/:environment`, self-service, gated
  as provider `radius-passcode`), then types it as the password at the
  NAS. 128 random bits, TTL 2m by default (at most 15m), stored only as a
  SHA-256 under the identity, consumed on first presentation, at most 8
  outstanding. This mirrors the SSH engine's OTP mode; no password store is
  added.
- **Who the NAS is.** A client record binds one NAS to exactly one
  environment and one attribute profile of that environment. RadSec
  (default): the NAS certificate must chain to `client_ca_pem` and its
  SHA-256 must be pinned on a client; the RFC 6614 shared secret `radsec`
  is used. UDP (opt-in, `udp_enabled`): source IP plus a 16–128 character
  shared secret. Secrets and the TLS key live behind the barrier, are
  write-only, zeroized on drop and never logged.
- **Decision.** Message-Authenticator required and checked in constant
  time (BlastRADIUS); `User-Name` must be a valid login; the passcode must
  belong to that login, be unexpired and be for the NAS's environment; the
  gate (provider `radius`) must allow; the profile must yield at least one
  attribute for the granted roles. Replies carry the Message-Authenticator
  first. Unknown NAS, bad or missing Message-Authenticator and malformed
  packets are discarded silently, as RFC 2865 §3 and RFC 3579 §3.2 require
  (no reflection, no oracle); every other refusal, including any storage
  or audit error, is an Access-Reject with no attributes.
- **Listeners.** Started from `Module::start_background` (no kernel change);
  a supervisor binds what `idp/radius/config` asks for, re-reads it every
  30 s and at once after a write, and stops everything when sealed.
  Unspecified addresses need `allow_unspecified_bind`. Per-source rate
  limit (default 120/min) before any work, bounded concurrency (64 UDP in
  flight, 128 RadSec connections), RFC 5080 duplicate cache (30 s) so a
  retransmission gets the same reply, packets bounded at 4096 octets and
  128 attributes. Unknown UDP sources never reach the limiter's table.
- **Profiles** are data: per environment role, `fortinet-group-name` (and
  `fortinet-vdom-name`, `fortinet-access-profile`, `cisco-avpair`) or a
  generic `vsa`, validated at write time against the environment's roles.
- **Audit.** Besides the gate's `idp.issue` / `idp.issue-denied`, every
  outcome writes `idp.radius.accept` or `idp.radius.reject` (decision,
  reason, gate reason, client, environment, transport, peer, user name,
  entity). An Accept whose event cannot be recorded is sent as a Reject.
  Drops before a NAS record is read (unknown source, rate limited, busy)
  are audited at most 30 times a minute in all, so a flood cannot flood the
  audit log.

Decisions taken where this spec was open (Phase 4): passcode rather than
password pass-through (above; rejected: router-direct userpass login);
one NAS serves one environment (rejected: a NAS-supplied environment
attribute, which the NAS could choose); the gate is asked with the root
caller namespace (NAS clients are root-administered); a passcode is burnt
when presented even if the request is then refused; CHAP, EAP,
Access-Challenge and Status-Server are not supported.

Caveats (Phase 4): **no real FortiGate or other NAS was run**, and no
FreeRADIUS, `radtest` or `pyrad` was available locally for interop; the
codec, both listeners and FortiGate's VSA layout are verified only by this
crate's own client code (unit tests over real UDP and RadSec sockets, and a
whole-vault test). Listen addresses are cluster-wide settings: a node that
cannot bind the configured address reports `last_error`; not run on a
multi-node cluster, and a client added on another node is admitted after
the next 30 s refresh. The NAS's login prompt must accept a 32-character
passcode. RFC 6614's legacy cipher suites are not offered (rustls only).

## Concepts and Terminology

| Term | Meaning |
|---|---|
| **Workforce identity** | A canonical record for one human, keyed by the existing BastionVault `entity_id`. Holds the immutable POSIX mapping and lifecycle state. |
| **POSIX mapping** | The immutable `(login, uid, gid, [supplementary gids])` allocated to a workforce identity, stable for life. |
| **Environment** | An authorization boundary a target belongs to (e.g. `prod`, `dev`, `pci`). Mapped 1:1 onto a **namespace** ([namespaces-multitenancy.md](namespaces-multitenancy.md)) so existing per-namespace policy + isolation applies unchanged. |
| **Entitlement** | A binding `(identity → environment → role-set)` that says *this person may enter this environment as these roles*. The gate for issuing any identity credential. |
| **Provider / projection** | A downstream-facing adapter (SSH, RADIUS, SAML-IdP, OIDC-OP, LDAP-compat) that asserts the identity to a target in that target's native protocol. |
| **Deny feed** | A signed, monotonically-versioned list of revoked identities/credentials that target-side agents poll to enforce blocks proactively. |

## Design

### 1. Canonical Workforce Identity & Stable POSIX Mapping

A new logical store under `src/modules/idp/posix/` maintains one record per
workforce identity, keyed by `entity_id`:

```
idp/identities/<entity_id> = {
  "login":      "alice",          // immutable once allocated
  "uid":        80017,            // immutable, allocated from a configured range, never reused
  "primary_gid":80017,
  "gids":       [80017, 4],       // supplementary (e.g. a shared "wheel"=4)
  "display_name":"Alice Souza",
  "state":      "active",         // active | disabled | removed
  "allocated_at": "...",
  "uid_source": "vault"           // vault | imported (carry an external UID in verbatim)
}
```

**Allocation rules (the heart of "consistent and uniform"):**

- UID/GID are allocated from an **operator-configured range** (default
  `80000–999999`, configurable via `idp/config`) by a monotonic allocator that
  **persists a high-water mark and a free/used bitmap**. Allocation is a single
  Raft-serialized write (Hiqlite) so two concurrent first-logins can never get
  the same UID.
- Once allocated, `login`/`uid`/`primary_gid` are **immutable**. There is no
  edit path; only `state` transitions and supplementary-group changes are
  allowed. A rename requires creating a new identity (new UID) — deliberately
  expensive, because a UID rename is exactly what breaks file ownership.
- **No reuse.** When an identity is removed its UID is *retired*, not freed, so a
  future hire can never inherit a departed admin's file ownership or `sudo` rules.
  Retired UIDs live in a tombstone set; the allocator skips them forever.
- **Authoritative across environments.** The store lives in the **root
  namespace** and is read by every environment/namespace. Environments do not get
  their own UID space — that is the whole point. A `uid_source: "imported"` mode
  lets an operator seed existing UIDs from an authoritative payroll/HR/AD source
  during migration (collision-checked against the bitmap) so BastionVault adopts
  the org's existing numbering instead of renumbering the fleet.

This mapping is what every downstream provider reads, so the *same* person is the
*same* UID whether they SSH to a dev box, authenticate to a prod FortiGate over
RADIUS, or bind against the LDAP-compat front.

### 2. Environment Authorization (Entitlements)

```
idp/entitlements/<entity_id>/<environment> = {
  "roles":     ["sysadmin", "dba"],   // environment-local role names
  "not_after": "2026-12-31T00:00:00Z",// optional time-box (contractor, JIT)
  "granted_by":"<approver entity_id>",
  "source":    "manual" | "group" | "external"
}
```

- An environment maps to a namespace; a role maps to that namespace's ACL
  policies (reusing the existing policy union from
  [identity-groups.md](identity-groups.md)). Entitlements can be granted
  **directly** or **derived from group membership** so existing group→policy
  mappings flow through without re-modelling.
- **No credential of any kind is issued for an environment the caller is not
  entitled to.** This is enforced *before* the provider runs, fail-closed, and is
  the single chokepoint the audit trail records as `idp.issue` /
  `idp.issue-denied`.
- Time-boxed entitlements (`not_after`) give native JIT access without a separate
  workflow — the entitlement simply expires and the next issue attempt is denied.

### 3. Downstream Providers (Projection Adapters)

All providers share one resolution core
(`src/modules/idp/resolve.rs`): given `(entity_id, environment)` →
check identity state is `active` → check entitlement → load POSIX mapping → build
the protocol-specific assertion. Each adapter is a thin, separately-auditable
module.

```
src/modules/idp/
├── mod.rs              -- IdpModule; route registration; config
├── posix/              -- identity store + UID/GID allocator (Pillar 1)
├── entitlement.rs      -- entitlement store + the authorization gate (Pillar 2)
├── resolve.rs          -- shared "who + may they + as what UID" core
├── revoke/             -- lifecycle state machine + deny-feed builder (Pillar 3)
└── provider/
    ├── ssh.rs          -- identity-bound SSH cert issue (wraps the SSH engine)
    ├── radius.rs       -- RADIUS server (FortiGate et al.)
    ├── saml_idp.rs     -- SAML 2.0 IdP (FortiGate SSO, generic SP)
    ├── oidc_op.rs      -- OpenID Provider (generic SSO apps)
    └── ldap_dir.rs     -- read-only LDAP-compat directory front
```

#### 3a. SSH (Linux) — the primary path

Reuses the existing **SSH CA engine** ([ssh-secret-engine.md](ssh-secret-engine.md))
rather than re-implementing signing. The IdP layer adds an **identity-aware
issue endpoint** that:

- Sets `valid principals = [login]` (the canonical login, never a free-form
  string), so a host's `AuthorizedPrincipalsFile`/`AuthorizedPrincipalsCommand`
  maps principal → local policy deterministically.
- Encodes attribution in `key id`:
  `bv:<entity_id>:<login>:uid=<uid>:env=<environment>` — this lands verbatim in
  the host's `sshd` auth log, giving OS-native attribution with the UID inline.
- Carries the UID/GID in a certificate **extension**
  (`uid@bastionvault`, `gid@bastionvault`) for hosts running the optional
  BastionVault NSS/principals helper, so a person needs **no pre-existing local
  account** — the helper materializes the account from the cert at login and tears
  it down (or leaves it owned by the retired UID) afterward.
- Clamps TTL hard (minutes-to-hours) so revocation is mostly a matter of waiting
  out the window; the KRL (below) handles the rest.

Linux integration options, in order of preference:
1. **`TrustedUserCAKeys` + `AuthorizedPrincipalsCommand`** — host trusts the
   BastionVault SSH CA, and an `AuthorizedPrincipalsCommand` script resolves the
   principal/UID against the deny feed locally. No per-user accounts.
2. **NSS module / SSSD-style feed** — for sites that want the UID visible to
   `id`, `ls -l`, auditd `auid`, etc., a small read path (LDAP-compat front, 3e)
   feeds `getpwnam`.

#### 3b. RADIUS — FortiGate and network gear

A RADIUS server (`src/modules/idp/provider/radius.rs`) handling Access-Request:

- Authenticates the human against a BastionVault auth backend (userpass+FIDO2 /
  OIDC-brokered), checks the entitlement for the device's environment, and returns
  **vendor-specific attributes** mapping the BastionVault role to the device's
  native admin profile — e.g. `Fortinet-Group-Name` for FortiGate, Cisco
  `Cisco-AVPair shell:priv-lvl`, Juniper, etc., via a per-vendor attribute
  template.
- Supports **RADIUS over TLS (RadSec, RFC 6614)** so the shared-secret weakness of
  classic UDP RADIUS is contained; classic UDP is opt-in for legacy gear on a
  trusted segment only.
- The subject in the device's audit log is the **real username**, not a shared
  admin account — attribution achieved without the device speaking SSH certs.

#### 3c. SAML 2.0 IdP

`src/modules/idp/provider/saml_idp.rs` — the **issuing** counterpart to the
existing SAML **SP** ([saml-auth.md](saml-auth.md)), reusing that module's
pure-Rust XML signing/canonicalization (no libxml2/xmlsec). Handles SP-initiated
SSO: validates the `AuthnRequest`, authenticates the human, checks the
entitlement, and emits a signed `Response`/`Assertion` whose `NameID` is the
canonical login and whose attribute statement carries the role-set and UID.
FortiOS and most appliances/apps speak SAML SP, so this covers the GUI-SSO case.

#### 3d. OIDC Provider (OP)

`src/modules/idp/provider/oidc_op.rs` — BastionVault as an OpenID Provider for
apps that prefer OIDC: discovery document, JWKS (signed with an ML-DSA-65 +
EdDSA composite where the RP supports it, EdDSA/ES256 otherwise), authorization
endpoint (code + PKCE), token endpoint. `sub` is the stable `entity_id`; a
`uid` claim carries the POSIX UID; `groups`/`roles` carry the environment
role-set.

#### 3e. LDAP-compat read-only directory

`src/modules/idp/provider/ldap_dir.rs` — a minimal, **read-only** LDAPv3 front
(bind + search) for systems that can only consume LDAP. Serves `posixAccount`
/ `posixGroup` entries with the consistent `uidNumber`/`gidNumber`/`gecos` from
Pillar 1. Bind succeeds only for `active` identities (so it doubles as a live
authorization check); `disabled`/`removed` binds fail. This is intentionally
**not** a general-purpose LDAP server — it is a projection of the workforce store.

### 4. Lifecycle & Revocation Propagation (the "block at destinations" guarantee)

A state machine on the workforce identity drives propagation:

```
active --disable--> disabled --remove--> removed
   ^                    |
   +------reinstate-----+        (removed is terminal; UID is tombstoned)
```

On **disable** or **remove**, BastionVault propagates the block across *every*
channel, because no single channel is sufficient on its own:

| Channel | Propagation mechanism |
|---|---|
| **SSH certs** | Add the identity's certs (by serial / by `entity_id` key-id prefix) to an **OpenSSH KRL** served at `GET /v2/idp/ssh/krl`; hosts load it via `RevokedKeys`. Outstanding certs also expire on their own short TTL. |
| **SSH future-issue** | The entitlement gate refuses new issues immediately. |
| **RADIUS** | Access-Request for a non-`active` identity returns Access-Reject. |
| **SAML / OIDC** | New assertions refused; existing OIDC tokens are short-lived and the OP refresh path refuses; a back-channel logout is emitted to registered RPs that support it. |
| **LDAP-compat** | Bind fails for non-`active` identities. |
| **Deny feed** | `GET /v2/idp/deny-feed` returns a **composite-signed (Ed25519 + ML-DSA-65), monotonically-versioned** list of revoked logins/UIDs/cert-serials. Target-side agents (the `AuthorizedPrincipalsCommand`, the NSS helper) poll it and enforce the block **without waiting for TTL expiry**. The feed is signed so a target can trust it offline; versioned so a target can detect rollback. |

**Design choice — defense in depth, fail-closed.** Short TTL is the baseline
(bounded exposure even if every push fails), the KRL/deny-feed is the active
push (fast revocation), and the issue-gate is the front door (no new access).
A target that can only do *one* of these still gets bounded exposure from TTL;
a target that polls the deny feed gets near-real-time lockout.

### HTTP / Logical Surface (all under `v2/`, per agent.md)

```
# Identity & POSIX mapping (root-namespace, admin)
POST   /v2/idp/identities/:entity_id        # allocate/seed identity + POSIX mapping
GET    /v2/idp/identities/:entity_id
LIST   /v2/idp/identities
POST   /v2/idp/identities/:entity_id/state  # active | disabled | removed (+reinstate)
GET    /v2/idp/config                        # uid/gid ranges, providers enabled
POST   /v2/idp/config

# Environments (Phase 2 addition: environment <-> namespace and role <-> policy)
LIST   /v2/idp/environments
POST   /v2/idp/environments/:environment     # namespace (create only, immutable), roles, description
GET    /v2/idp/environments/:environment
DELETE /v2/idp/environments/:environment     # retire; the name is never reused

# Entitlements
POST   /v2/idp/entitlements/:entity_id/:environment
GET    /v2/idp/entitlements/:entity_id
GET    /v2/idp/entitlements/:entity_id/:environment
DELETE /v2/idp/entitlements/:entity_id/:environment

# Issuance (entitlement-gated)
POST   /v2/idp/ssh/sign/:environment         # identity-bound SSH cert (wraps ssh engine)
GET    /v2/idp/ssh/krl                        # OpenSSH KRL for revoked certs
GET    /v2/idp/deny-feed                       # signed, versioned revocation feed

# Provider metadata (consumed by downstream systems)
GET    /v2/idp/oidc/.well-known/openid-configuration
GET    /v2/idp/oidc/jwks
GET    /v2/idp/saml/metadata
```

RADIUS (UDP/RadSec) and the LDAP-compat front listen on their own configured
sockets, not the HTTP API — they are protocol servers, gated by `idp/config`,
bound by default to explicit operator-chosen interfaces (never `0.0.0.0` without
opt-in), and each can be independently disabled.

### GUI

A new **Identity Provider** admin page (root/admin-gated, `requiresMountType`-style
nav like the PKI/SSH pages):
- **Identities** tab — list with login/UID/GID/state, allocate, disable/remove,
  reinstate; UID shown read-only with a tooltip explaining immutability.
- **Entitlements** tab — matrix of identity × environment × roles, with the
  `not_after` time-box picker.
- **Providers** tab — enable/configure SSH / RADIUS / SAML-IdP / OIDC-OP /
  LDAP-compat, copy provider metadata (OIDC discovery URL, SAML metadata XML,
  RADIUS client config snippet, the `TrustedUserCAKeys`/`AuthorizedPrincipalsCommand`
  install snippet for Linux).
- **Revocations** tab — deny-feed version, KRL contents, last propagation status.

## Implementation Scope (Phased)

| Phase | Scope | Status |
|---|---|---|
| **1 — POSIX identity core** | `idp/posix/` store + Raft-serialized UID/GID allocator (range, high-water, free bitmap, tombstone/no-reuse), `v2/idp/identities` CRUD + state machine, `idp/config`. Import mode for seeding existing UIDs. | **Complete, with caveats** — `crates/bv-engine-idp`; opt-in `idp` mount; not run on a multi-node cluster; no CLI/GUI (see Current State) |
| **2 — Entitlements + gate** | `entitlement.rs` store, environment↔namespace mapping, role↔policy mapping, the fail-closed issue gate + `idp.issue`/`idp.issue-denied` audit events. | **Complete, with caveats** — `crates/bv-engine-idp/src/entitlement/`; `v2/idp/environments` + `v2/idp/entitlements`; the gate is a Rust API with no caller until Phase 3; policy existence unchecked; not run on a multi-node cluster (see Current State) |
| **3 — SSH identity issue + revocation** | `provider/ssh.rs` identity-bound `sign` wrapping the SSH engine (principals=login, key-id attribution, uid/gid extensions), `GET /v2/idp/ssh/krl`, the signed/versioned `deny-feed`, and the reference `AuthorizedPrincipalsCommand` + NSS helper for Linux. | **Complete, with caveats** — `crates/bv-engine-idp/src/{provider/ssh,revoke}/`, `bin/bv-idp-host`; KRL checked with `ssh-keygen`; no real sshd/Linux host run; NSS helper generates entries from a certificate, no on-login materialization; PQC CA unsupported; feed key not rotated (see Current State) |
| **4 — RADIUS provider** | `provider/radius.rs` (RadSec + opt-in UDP), per-vendor attribute templates (FortiGate first), entitlement-gated, Access-Reject for non-active. Live-tested against a FortiGate (or `freeradius`/`pyrad` harness). | **Complete, with caveats** — `crates/bv-engine-idp/src/provider/radius/`; one-time passcodes minted through the vault; RadSec with pinned NAS certificates, UDP opt-in; verified by the crate's own client over real sockets only: **no FortiGate, FreeRADIUS or pyrad run**; not run on a multi-node cluster (see Current State) |
| **5 — SAML IdP + OIDC OP** | `provider/saml_idp.rs` (reusing the SAML-auth signing core) + `provider/oidc_op.rs` (discovery/JWKS/authz/token), both entitlement-gated, UID + role-set in assertions/claims. | Pending |
| **6 — LDAP-compat directory** | `provider/ldap_dir.rs` read-only bind+search serving `posixAccount`/`posixGroup`; bind = live active-state check. | Pending |
| **7 — GUI** | Identity Provider admin page (Identities / Entitlements / Providers / Revocations tabs) + Tauri commands + API wrappers. | Pending |

Phases 1–3 are the minimum viable slice: stable UID + entitlement gate + SSH
identity certs + revocation. That alone delivers attributable, environment-gated,
revocable Linux admin access. RADIUS (4) unlocks FortiGate; 5/6 broaden coverage.

## Testing Requirements

### Unit
- Allocator: concurrent allocation never collides; removed UID never reissued;
  high-water + bitmap survive a reload; import mode rejects a colliding seed.
- Immutability: any attempt to change `login`/`uid`/`primary_gid` is rejected.
- Entitlement gate: issue denied when identity disabled, when no entitlement,
  when entitlement `not_after` is past; allowed when active+entitled.
- SSH cert: `valid principals` = login only; `key id` carries the expected
  `bv:<entity_id>:...:uid=<uid>` string; uid/gid extensions present.
- Deny feed: composite signature verifies; version is monotonic; a tampered feed
  fails verification.

### Integration / E2E
- **UID consistency across environments**: allocate Alice, issue SSH certs for
  `dev` and `prod` namespaces, assert identical UID/login in both certs.
- **SSH end-to-end**: configure an OpenSSH container with `TrustedUserCAKeys` +
  `AuthorizedPrincipalsCommand` + `RevokedKeys`; an entitled identity logs in as
  the canonical login with the right UID; after `disable`, the same cert is
  refused (KRL) and a fresh issue is denied (gate).
- **RADIUS**: a `pyrad`/`freeradius`-client harness (or a real FortiGate when
  available) gets Access-Accept with the correct `Fortinet-Group-Name` for an
  entitled identity and Access-Reject after disable.
- **Revocation race**: disable mid-session; assert deny-feed version bumps, KRL
  contains the serial, and the next `AuthorizedPrincipalsCommand` poll blocks.

### Negative
- Issue for an environment the caller is not entitled to → denied + audited.
- LDAP bind / RADIUS / SAML / OIDC for a `removed` identity → all refuse.
- Removed identity's UID is never handed to a newly-allocated identity.

## Security Considerations

- **No custom crypto.** SSH signing reuses the SSH engine; SAML signing reuses
  the SAML-auth core; OIDC/JWKS and the deny-feed signature use `bv_crypto`
  (Ed25519 / ML-DSA-65 composite). No OpenSSL, no `aws-lc-sys` — same constraint
  as every other module.
- **UID immutability is a security property, not just hygiene.** A mutable or
  reusable UID lets a new hire silently inherit a departed admin's file ownership
  and `sudo` grants. The tombstone/no-reuse rule is therefore enforced in the
  allocator, not left to operator discipline.
- **Fail-closed gate.** Every issuance path runs the entitlement+state check
  first and denies on any error (missing record, expired entitlement, storage
  error). There is no implicit-allow fallback.
- **Defense-in-depth revocation.** Short TTL bounds exposure even if every active
  push fails; the signed/versioned deny feed gives offline-verifiable,
  rollback-detectable near-real-time lockout; the KRL covers SSH specifically.
- **RADIUS shared-secret weakness** is contained by defaulting to **RadSec
  (TLS)**; classic UDP RADIUS is opt-in and documented as trusted-segment-only.
- **Protocol servers bind explicitly.** RADIUS and the LDAP-compat front never
  bind `0.0.0.0` without an explicit operator opt-in, mirroring the MCP-bridge
  loopback rule in [agent.md](../agent.md).
- **Audit redaction.** SSH private keys (if `issue` ever returns one), OIDC
  tokens, SAML assertions, and RADIUS attributes are redacted/HMAC'd in audit
  logs; the issue/deny decisions themselves are logged in full for attribution.
- **Blast radius of the IdP signing keys** is the whole fleet's identity. Keys
  are barrier-encrypted at rest, rotation reuses the PKI/SSH rotation machinery,
  and HSM-backed storage is a natural follow-up ([hsm-support.md](hsm-support.md)).

## Relationship to Existing Features

- **Inverse of [oidc-auth.md](oidc-auth.md) / [saml-auth.md](saml-auth.md):**
  those are relying-party/SP (verify inbound); this is OP/IdP (issue outbound).
  The provider modules live under `idp/provider/` to keep the two directions
  cleanly separated.
- **Wraps [ssh-secret-engine.md](ssh-secret-engine.md):** identity issuance is a
  thin policy/attribution layer over the existing CA signer, not a second signer.
- **Uses [namespaces-multitenancy.md](namespaces-multitenancy.md):** environment
  = namespace, so isolation, per-namespace policy, and audit attribution come for
  free.
- **Builds on [identity-groups.md](identity-groups.md) /
  [per-user-scoping.md](per-user-scoping.md):** entitlements can derive from
  existing group→policy mappings; the workforce identity is keyed by the existing
  `entity_id`.
- **Complements [machine-authentication.md](machine-authentication.md):** that
  proves *which machine* is connecting; this proves *which human*. Combined-auth
  sessions can carry both (machine SPIFFE ID ∩ human identity).
- **Feeds [audit-logging.md](audit-logging.md) and the dashboard:** `idp.issue` /
  `idp.issue-denied` / `idp.revoke` events extend the login-audit attribution
  story to the whole fleet.

## Not In Scope

- **SCIM provisioning / write-back to an external directory.** This feature is
  authoritative for the *projection* of identity onto targets, not a sync engine
  with an upstream HR/AD system. A SCIM ingest path (to seed entitlements/UIDs
  from an HRIS) is a possible follow-up.
- **General-purpose LDAP server.** The LDAP-compat front is a read-only
  projection of the workforce store, not a writable DIT.
- **Kerberos/PKINIT.** Smart-card/Kerberos identity to Windows targets is tracked
  with the Rustion RDP work ([rustion-integration.md](rustion-integration.md)),
  not here.
- **Windows local-account materialization.** The NSS/principals helper targets
  Linux first; Windows account projection is a later phase if demand appears.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [ROADMAP.md](../ROADMAP.md),
and this file's "Current State" / phase table.
