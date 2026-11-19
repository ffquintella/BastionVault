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

**All seven phases are implemented, with caveats: Phase 1 (POSIX identity
core), Phase 2 (entitlements + gate), Phase 3 (SSH identity issue +
revocation), Phase 4 (RADIUS), Phase 5 (SAML IdP + OIDC OP), Phase 6
(LDAP-compat directory) and Phase 7 (GUI).** Phases 2–7 are described after
Phase 1's caveats below, followed by what is not yet implemented.
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
here). No CLI or dedicated audit-event type yet (lifecycle changes are
logged under the `idp` log target and appear in the normal request audit);
the GUI arrived in Phase 7.

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
must exist first (provisioned with `nss-entry`, or resolved through the
Phase 6 directory by sssd/nslcd, which no real host has run yet); on-login
materialization is not delivered. An ML-DSA-65
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

**Phase 5 (SAML IdP + OIDC OP).** `src/provider/oidc_op/` (`mod.rs`
flows, `store.rs` on `idp/oidc/`, `jwt.rs`), `src/provider/saml_idp/`
(`mod.rs` flows, `store.rs` on `idp/saml/`, `request.rs` AuthnRequest
decode and parse, `xml.rs` response, signature and metadata),
`src/provider/federation/` (key ring, audit sink, URL rules) and
`src/backend/{oidc,saml}.rs`. Routes in [docs/api.md](../docs/api.md).

- **Who the human is.** As for RADIUS, the person has already logged in to
  the vault with any backend: `v2/idp/oidc/authorize`, `v2/idp/saml/sso`
  and `v2/idp/saml/initiate/<sp>` are self-service with that token (root
  refused). The provider asserts only that identity, gated: OIDC as
  `oidc-authorize` when the code is minted and `oidc` when it is redeemed
  (so a disable or a revoked role in between denies), SAML as `saml`.
- **Who the relying party is.** An OIDC client or a SAML SP is bound at
  creation, for life, to exactly one active environment (as a RADIUS NAS),
  and its registered `https` URLs are matched byte for byte. Client secrets
  are minted by the vault, shown once, stored as SHA-256; an SP entity ID
  maps to one SP (index checked against the record).
- **OIDC.** Code flow only, PKCE `S256` required, `client_secret_post`
  (and `client_secret_basic` on the form token endpoint since T546),
  codes of 256 random bits stored hashed, single use, 60 s by default,
  consumed after client authentication whatever the outcome. ID tokens are
  RS256 (`sub` = entity id, `preferred_username` = login, `uid`, `gid`,
  `roles`, `groups`, `environment`, `nonce`), 5 min by default. Discovery,
  JWKS and the token endpoint are the mount's `unauth_paths` (the router
  hook the PKI ACME endpoints use; no kernel change).
- **SAML.** HTTP-Redirect (bounded inflate) or HTTP-POST AuthnRequests,
  parsed namespace-aware with DTDs and custom entities refused; the
  `Issuer` must be a registered SP, the ACS URL one of its own, the request
  younger than `request_max_age` and not seen before (replay cache keyed
  on the request alone). One assertion per response, signed enveloped
  RSA-SHA256 with exclusive C14N, `NotOnOrAfter` 5 min, audience-restricted,
  bearer subject confirmation with `Recipient` and `InResponseTo`.
  IdP-initiated responses only for SPs with `allow_idp_initiated`.
  Metadata is an unauthenticated path.
- **Keys.** One RSA-3072 key ring per protocol in the barrier, generated
  with aws-lc on first use under the storage lock, never replaced on a
  read error; `kid` = RFC 7638 thumbprint; `keys/rotate` keeps the retired
  key in the JWKS and metadata for an overlap (default 24h). Not HSM-backed.
- **Audit.** `idp.oidc.token`, `idp.saml.response`, `idp.oidc.refused`,
  `idp.saml.refused` besides the gate's events; IDs only, never a code,
  secret, token or assertion. A token or response whose event cannot be
  recorded is not returned.

Decisions taken where this spec was open (Phase 5):

- *Hosting*: the logical surface with `unauth_paths`, JSON envelope, no
  bv-server change. Rejected for now: a bv-server adapter serving raw
  discovery/JWKS/metadata, form-encoded token requests and redirects (a
  Tier 4 change; needed before a standard RP can talk to the OP directly).
  T545 then added the redirect and T546 the OIDC back channel, below.
- *Signing*: the spec's "SAML-auth signing core" is verify-only; the IdP
  signs with aws-lc (constant time, already linked by rustls) over bytes
  canonicalised by `bv-auth-saml`'s exclusive C14N, made public for this.
  The assertion is emitted already in canonical form (a test pins it as a
  C14N fixed point), so a different conformant canonicaliser at the SP
  reproduces the signed bytes. Rejected: RustCrypto `rsa` for signing
  (RUSTSEC-2023-0071, no constant-time release) and a second canonicaliser.
- *Algorithm*: RS256 / RSA-SHA256 only (OIDC's mandatory algorithm and what
  SAML SPs and `bv-auth-saml` verify). Rejected for now: the spec's
  EdDSA / ML-DSA-65 composite JWKS, which few RPs accept.
- *Clients*: confidential only, PKCE required for all; no implicit or
  hybrid flow, no refresh token, no userinfo, `prompt`/`max_age` ignored.
- *SAML*: AuthnRequest signatures not verified (nothing in a request is
  trusted beyond naming a registered SP and one of its ACS URLs); the
  Response element is not signed, nothing is encrypted, `ForceAuthn` and
  `AssertionConsumerServiceIndex` are refused; `NameID` format
  `unspecified` = login.

Caveats (Phase 5): **no real SP, RP or browser was run.** The OIDC side is
checked with the `openidconnect` RP library (RustCrypto RSA, independent of
aws-lc) and the SAML side with `bv-auth-saml`'s parser, validator and
verifier (whose C14N also signs, so a shared C14N bug would cancel out; the
fixed-point test is the guard). Because the HTTP layer only speaks the JSON
envelope, a standard RP cannot fetch discovery or metadata, POST a
form-encoded token request or be redirected without a relay (the GUI,
T107) or a bv-server adapter. (Since T545 the vault answers the browser
redirect itself and since T546 serves the OIDC back channel, below; SAML
metadata is still envelope-only.) No back-channel logout; outstanding ID tokens
and assertions expire on their own (5 min). Signing keys are not
HSM-backed. Not run on a multi-node cluster. Testing this phase showed
that `bv-auth-saml`'s inbound parser merges the attributes of an unsigned
assertion placed before a signed one; that is a separate SP-side fix.

**Phase 6 (LDAP-compat directory).** `src/provider/ldap_dir/` (`ber.rs`
bounded codec, `proto.rs` messages, `filter.rs`, `dn.rs`, `directory.rs`
entries, `store.rs` on `idp/ldap/`, `server.rs` listeners, `mod.rs`
decisions) and `src/backend/ldap.rs`. Routes in [docs/api.md](../docs/api.md).

- **Who the client is.** A client record binds one host or service, for
  life, to one environment (as a RADIUS NAS): `tls` clients are pinned by
  the SHA-256 of a certificate that must also chain to `client_ca_pem`
  (LDAPS, or StartTLS on the cleartext port); `plain` clients by source
  address, served in cleartext only while `plaintext_enabled` (off by
  default, warned) holds. Record, pin and config are re-read per operation.
- **What it sees.** Only identities the gate would issue to in that
  environment, decided per entry by the gate's own decision run unrecorded
  (`IssueGate::evaluate_unrecorded`, crate-private); each search is one
  `idp.ldap.search` event instead. Entries: `posixAccount` under
  `ou=people`, the user-private `posixGroup` (no members) and one
  `posixGroup` `gid.<n>` per supplementary gid with its visible holders
  under `ou=groups`. No credential attribute exists.
- **Who the human is.** As for RADIUS: the person mints a single-use bind
  passcode for one environment (`v2/idp/ldap/passcode/<environment>`, gated
  as `ldap-passcode`) and binds as `uid=<login>,ou=people,<base_dn>` with
  it. The bind consumes it and asks the gate (provider `ldap`) live, so a
  disable or removal refuses the next bind and hides the entries at once.
  SASL `EXTERNAL` binds a TLS client as itself. Anonymous and
  unauthenticated binds are refused; every other refused bind is
  `invalidCredentials`, including storage errors, so a client never falls
  back to cached credentials on a refusal.
- **Protocol.** Bind, Search, Unbind, Abandon, StartTLS; every write and
  Compare is `unwillingToPerform`. BER is hand-written and bounded: definite
  lengths, single-octet tags, PDUs at most 64 KiB checked from the header,
  filters at most 16 deep and 128 elements, no recursion outside the
  depth-bounded filter decoder, no regular expressions. 128 connections,
  per-source rate limit (600/min), 5 min idle timeout, size (1000) and time
  (10 s) limits.
- **Audit.** `idp.ldap.bind`, `idp.ldap.search`, `idp.ldap.refused`, plus
  the gate's events for binds and passcodes; never a passcode. A bind or a
  search whose event cannot be recorded is refused.

Decisions taken where this spec was open (Phase 6): the bind credential is
a one-time passcode, not a userpass password (rejected: router-direct
password checks, which bypass the login pipeline, and any stored reusable
password); one client serves one environment (rejected: a per-environment
base DN a client could choose); searches need no bind because the client
identity decides visibility (rejected: requiring a bind, which sssd and
nslcd only offer as a stored password); supplementary groups are named
`gid.<n>` because Phase 1 stores them as numbers only; the BER codec is
in-crate (rejected: ldap3's `lber`, which recurses without a depth bound
and reads an indefinite length as zero; no LDAP server crate is in the
graph).

Caveats (Phase 6): **no sssd, nslcd or pam_ldap was run.** Verified by
the crate's unit tests, the ldap3 client over real LDAPS, StartTLS and
cleartext sockets, a whole-vault test, and one run of OpenLDAP's
`ldapsearch` (macOS build) over cleartext (passcode bind and search); the
same `ldapsearch` failed the LDAPS handshake in macOS's TLS stack with PEM
files, so TLS interop with a non-rustls client is unverified. Each search
scans the identity store (sized for hundreds to low thousands of
identities); search timing can reveal whether a login exists outside the
client's environment. Hosts must not cache credentials (sssd
`cache_credentials = false`): with the directory unreachable, sssd would
accept an already-used passcode from its offline cache, outside the live
check; the server cannot enforce this. Not run on a multi-node cluster; a
client added on another node is admitted after the next 30 s refresh.

**Phase 7 (GUI).** `gui/src/routes/IdentityProviderPage.tsx` (shell),
`gui/src/components/idp/` (one file per tab, provider panel and modal),
`gui/src/lib/idp.ts` (typed wrappers) and
`gui/src-tauri/src/commands/idp.rs` (Tauri commands). See the GUI section
below for what each tab does.

- **Reaching the engine.** Every command names an absolute `/v2/idp/...`
  path and is pinned to the root namespace (`make_request_root`). The remote
  backend sends a leading-slash path as the URL path; the embedded backend
  (`gui/src-tauri/src/backend.rs`) now reads a `/v1/` or `/v2/` prefix as
  the request's API version, so the v2-only engine is reachable in both
  modes while every relative path keeps the default version. No idp path
  ends in `auth/<x>/login`, so the remote backend's tokenless-login rule
  (`is_auth_login_path`) never drops the token from one.
- **Route allowlist.** The commands take a settings kind, a record kind or
  a key ring from closed enums, never a path; a caller-supplied name is one
  segment (no `/`, `.`/`..`, `?`, `#`, `%` or whitespace). An identity is
  removed only through its state command, never the generic delete.
- **Mount detection.** The page probes `v2/idp/config`; "mount not found"
  (both backends' wording) shows an enable prompt that mounts `idp/` in the
  root namespace, any other error (a 403, say) is shown as an error.
- **Secrets.** OIDC client secrets, RADIUS and LDAP passcodes and a UDP
  shared secret the operator just set are shown once in a dialog with a copy
  action, held only in that component's state and dropped when it closes;
  nothing is written to web storage, the console or a URL (tests spy on
  both). TLS private keys are masked, write-only fields that are never
  filled from a read and are sent only when typed; settings writes send
  only the fields that changed.
- **Self-service.** SSH sign and passcode minting use the session's own
  token. A token with no entity is refused by the vault (403); the page
  explains it and warns beforehand when the session holds `root`.
- **Confirmations.** Disable, reinstate, removal (login typed), environment
  retirement (name typed), entitlement revocation, client/SP/NAS removal,
  client-secret rotation and signing-key rotation each name the object and
  the consequence before any request is sent.

Decisions taken where this spec was open (Phase 7): the page sits in the
Admin section, root-namespace only and not mount-gated (so it can offer to
enable the engine); self-service actions live on the provider panels of the
same page rather than a separate user page; the deny feed is decoded for
display but not verified in the GUI (hosts verify it with `bv-idp-host`);
"TLS keys on write" are treated as write-only input, never shown back.
Rejected: a generic "any idp path" command, which would hand the webview a
path parameter.

Caveats (Phase 7): **not clicked through against a live vault**, embedded
or remote; checked by vitest over the page, tabs, dialogs and wrappers with
a mocked Tauri layer, the command module's unit tests, and one
embedded-vault test that mounts `idp` and reads `/v2/idp/config` through
the embedded backend. The page assumes the mount path `idp/` (as the API
documents); an `idp` mount elsewhere is not found. The entitlement matrix
reads one identity's grants per row, 20 rows a page. The SSH panel does not
probe each namespace's SSH engine. A self-service page for people outside
the Admin section is not provided.

**Launch sessions and the browser authorization endpoint (T545).** Closes
the gap that blocked Web Application Connect's `sso` mode (T107): a browser
a relying party redirects to the OP had no way to say who the operator is.
`src/provider/oidc_op/launch.rs` (decisions), `store.rs`
(`idp/oidc/launch-sessions/`), `src/backend/oidc.rs`, and in bv-server
`src/idp_routes.rs` (the HTTP adapter) plus a `PassThrough` resource
fallback in `src/routes.rs`. Contract in [docs/api.md](../docs/api.md).

- **Mint** (`POST v2/idp/oidc/launch-session`, self-service with the
  operator's token, root refused): gated as provider `oidc-launch-session`
  for the client's environment and the asked roles; stores a
  `LaunchSession` record (`version: 1`, unknown fields refused) bound to
  entity, client, environment, granted roles and the SHA-256 of the
  caller's `launch_id`, keyed `<expiry>-<sha256(secret)>`. The secret
  (`<expiry>.<256 random bits>`) is returned once, zeroized, with the
  cookie attributes; neither it nor the launch id is stored or audited.
  Lifetime 2 min by default, 10 s to 5 min.
- **Consume** (`GET v2/idp/oidc/authorize` in bv-server, relaying to the
  unauthenticated logical path `oidc/launch-session/authorize`): the
  session is taken first (single use: any later outcome, success or
  refusal, has already burned it), then expiry, then the client named in
  the request must be the session's and still in the session's
  environment, then the same request checks as `authorize` (exact
  `redirect_uri`, `code`, `openid`, PKCE `S256`, bounded `state`/`nonce`),
  then the gate again as `oidc-authorize` with the session's roles. The
  adapter answers `302` to the registered URI built by the engine, or a
  `text/plain` page; it never redirects a refusal and expires the cookie
  on every answer. A miss is answered without the cluster-wide store lock.
- **Audit**: `idp.oidc.launch-session` (mint), `idp.oidc.launch-session-
  consumed` (code minted for it), refusals as `idp.oidc.refused` with
  stage `launch-session` / `launch-session-authorize`; each carries
  `session_id` and `launch_id_sha256`, never a secret, launch id or code.
  A session or code whose event cannot be recorded is not returned.

Decisions taken where this was open (T545):

- *Where the browser lands*: `GET` on the existing `<issuer>/authorize`
  (`/v2/idp/oidc/authorize`), so discovery's default needs no change; the
  bv-server resource claims `GET` only and every other method falls
  through to the logical API (the token-authenticated JSON `POST`).
  Rejected: a separate URL, which would need either a changed discovery
  default (a silent behaviour change for operators who rely on it for a
  relay) or extra configuration; and a generic raw-response or cookie
  channel in the logical catch-all, which would hand every backend a
  redirect primitive.
- *Cookie*: `__Host-bv-idp-launch`, `Secure`, `HttpOnly`, `SameSite=Lax`,
  `Path=/`, no `Domain`. `__Host-` makes the browser enforce host-only
  binding (no sibling subdomain can set or shadow it); `Lax` is the
  strictest mode sent on the RP's top-level redirect (`Strict` drops it
  there). Rejected: a narrow `Path` with `__Secure-` (path is not a
  security boundary, and the prefix's host binding is worth more), and
  setting the cookie from the vault (the host plants it with `set_cookie`
  in its own ephemeral store; the mint response only names the attributes).
- *Vault token*: never read on the browser route. The vault's `token`
  cookie rides along on a cross-site top-level `GET`, so accepting it
  would let any registered RP sign a logged-in operator in silently.
- *Single use*: consumed before any other check, so a mistaken or hostile
  request burns it; the host mints another (cheap) rather than a refused
  request leaving a live credential behind. Errors are pages, never
  RFC 6749 §4.1.2.1 error redirects, as for `authorize`.
- *`launch_id`*: caller-asserted correlation data, validated for shape
  (base64url, 22-128) and stored and audited only as its SHA-256 (the
  digest Web Application Connect's own audit lines carry), not checked
  against the resource engine's launch store: an engine may not depend on
  another engine. The host enforces that it mints only for its own launch.
- *Mount path*: the `GET` adapter targets the documented `idp/` mount, as
  the GUI does; the JSON consume path works on any mount.

Caveats (T545): not run in a real browser or against a real RP; the
browser route is `GET` only (no form-`POST` authorization requests);
`request`, `request_uri`, `response_mode`, `prompt` and `max_age` are
ignored; actix keeps its own parsed copy of the cookie header, which this
code cannot zeroize. T546, below, finishes the flow for a standard RP.

**Back channel for standard relying parties (T546).** What an
off-the-shelf RP does once the browser is back: read discovery and the
JWKS, redeem the code, verify the ID token.
`src/provider/oidc_op/back_channel.rs` is the wire format (form parsing,
Basic credentials, RFC 6749 §5.1 / §5.2 answers, cache headers; no
actix), `Issued::response_data` the token fields both shapes share; in
bv-server, `src/idp_routes.rs` has the three adapters and
`src/routes.rs` a `PassThroughJson` resource fallback. Contract in
[docs/api.md](../docs/api.md).

- **Discovery and JWKS** (`GET`): the logical read's `data` as the bare
  JSON object, `application/json`, `Cache-Control: public, max-age=3600`
  and `max-age=300`; an error is RFC 6749-shaped JSON, `no-store`.
- **Token** (`POST`, any content type but `application/json`): the body
  read with a 16 KiB cap (a declared length checked first), parsed by
  `back_channel::parse_token_request`, relayed as the same fields to the
  logical `oidc/token` path (so audit, `unauth_paths` and the `token` flow
  are unchanged), answered per §5.1 / §5.2. The raw body, the logical body
  and the logical response's token strings are zeroized after use.

Decisions taken where this was open (T546):

- *Same URLs*: the adapters sit at the URLs discovery advertises with the
  documented issuer, and OIDC Discovery §4 fixes the discovery URL itself.
  Rejected: separate raw URLs advertised in discovery (the discovery URL
  cannot move, and two shapes of one document invite drift). So over HTTP
  a `GET` of discovery or the JWKS no longer returns the envelope: no
  in-tree HTTP caller read it, and the identity provider has not shipped
  in a release, so the v2 shape may still change.
- *JSON keeps the logical API*: the token resource claims `POST` unless
  `Content-Type` is `application/json`, so the vault's own clients (which
  always send it) keep the envelope API, and a request with no or another
  content type is the form endpoint, refused unless it is a UTF-8 form.
  Rejected: claiming only form bodies, which leaves `text/plain` or a
  missing content type to the JSON parser and its envelope errors.
- *`client_secret_basic`*: added, and advertised first, because it is the
  OIDC default and many RP libraries' only default; it is small (base64,
  one `:` split, RFC 6749 §2.3.1 form-decoding that refuses a stray `%`).
  The secret is still compared by the flow (constant-time digest compare).
  Basic plus a body secret, or a body `client_id` that differs, is
  `invalid_request`; another scheme is `invalid_client`.
- *Status mapping*: `invalid_client` is `401` with `WWW-Authenticate:
  Basic` only when Basic was used, `400` otherwise (RFC 6749 §5.2), where
  the JSON API says `401`. A gate denial at redemption is `invalid_grant`
  (the grant was revoked), not the JSON API's `403 access_denied`, which
  RFC 6749 does not define for this endpoint. `server_error` keeps the
  flow's status (`404` while disabled, `500`).
- *Error text*: only the flow's `Refusal` codes are translated, with their
  fixed reason as `error_description` (dropped outside RFC 6749's
  charset); any other error is a bare `invalid_request` or `server_error`
  with its status, and a 5xx cause is logged, never sent. The adapter reads
  the code back from the `Refusal`'s `<code>: <reason>` error text; a unit
  test pins that round trip for every variant.
- *Checks before the flow*: a repeated known parameter and a missing
  `grant_type`, `code` or `redirect_uri` are refused before the engine,
  so the code survives and nothing is audited (as for T545's malformed
  browser requests). Missing client credentials and a missing verifier are
  the flow's (`invalid_client`; `invalid_grant` per RFC 7636 §4.6) and are
  audited.
- *Cache*: discovery 1 h (it changes only with the config); JWKS 5 min,
  because `keys/rotate` signs with the new key at once and an RP that does
  not refetch on an unknown `kid` fails until its copy expires (5 min is
  also the ID token lifetime). No CORS headers: confidential clients only.
- *JWKS media type*: `application/json`, which every RP library accepts
  (`application/jwk-set+json` is not universal).

Caveats (T546): not run against a real RP. Verified with the
`openidconnect` library driving discovery, the JWKS fetch and both client
authentication methods over the exact answers bv-server sends, and an
end-to-end HTTP test over a real vault that verifies the ID token against
the raw JWKS (with the OP's own verifier). Only the `idp/` mount has the
adapters. actix's own request buffers (headers, a chunked body's
segments) cannot be zeroized here. Raw SAML metadata is not served.

### What is not yet implemented

- A CLI for the `v2/idp` surface.
- Entitlements derived from identity groups (`source: "group"`).
- On-login NSS account materialization on Linux hosts (Phase 3 generates
  entries only); an ML-DSA-65 SSH CA; deny-feed key rotation; a
  single-certificate revoke route.
- CHAP, EAP, Access-Challenge and Status-Server for RADIUS.
- Raw SAML metadata for a standard service provider (the OIDC back
  channel is served raw since T546), and a form-`POST` authorization
  request (the `GET` browser endpoint and launch sessions exist, T545).
- A refresh token, userinfo, back-channel logout, signed Responses,
  encrypted assertions and AuthnRequest signature checks.
- HSM-backed IdP signing keys.
- Any run against real targets (sshd, FortiGate/FreeRADIUS, a real SP or
  RP, sssd/nslcd) or a multi-node cluster, and a live-vault run of the GUI.

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
POST   /v2/idp/oidc/launch-session            # single-use OP login cookie for a host's browser (T545)
GET    /v2/idp/oidc/authorize                 # browser authorization endpoint: launch-session cookie -> 302 (T545)

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

An **Identity Provider** admin page (*Admin → Identity Provider*, root
namespace only; implemented in Phase 7). The nav item is not mount-gated:
the page offers to mount `idp/` when the engine is missing.
- **Identities** tab — allocation ranges and counters (editable), list with
  login/uid/gid/state and a state filter, allocate or import, edit display
  name and supplementary gids, disable/reinstate/remove; uid and primary gid
  shown read-only with a tooltip explaining immutability.
- **Entitlements** tab — environments (create bound to a namespace, edit the
  role → policy map, retire), and the matrix of identity × environment ×
  roles with the `not_after` time-box picker, source and revoke.
- **Providers** tab — sub-tabs SSH / RADIUS / OIDC / SAML / LDAP: settings,
  listener status and the engine's warnings; NAS clients and attribute
  profiles, OIDC clients (secret shown once, rotate), SAML SPs, LDAP
  clients; signing keys with rotation; copyable OIDC discovery URL, SAML
  metadata XML, a NAS settings summary, the `TrustedUserCAKeys` /
  `RevokedKeys` / `AuthorizedPrincipalsCommand` snippet and an sssd snippet;
  self-service SSH sign and RADIUS/LDAP passcodes. Classic UDP RADIUS and
  cleartext LDAP carry a prominent warning while enabled.
- **Revocations** tab — deny-feed version, blocked identities and revoked
  serials (decoded for display, not verified), the KRL and its version, the
  identities that are not active, and the feed verification key to pin.

## Implementation Scope (Phased)

| Phase | Scope | Status |
|---|---|---|
| **1 — POSIX identity core** | `idp/posix/` store + Raft-serialized UID/GID allocator (range, high-water, free bitmap, tombstone/no-reuse), `v2/idp/identities` CRUD + state machine, `idp/config`. Import mode for seeding existing UIDs. | **Complete, with caveats** — `crates/bv-engine-idp`; opt-in `idp` mount; not run on a multi-node cluster; no CLI (GUI in Phase 7; see Current State) |
| **2 — Entitlements + gate** | `entitlement.rs` store, environment↔namespace mapping, role↔policy mapping, the fail-closed issue gate + `idp.issue`/`idp.issue-denied` audit events. | **Complete, with caveats** — `crates/bv-engine-idp/src/entitlement/`; `v2/idp/environments` + `v2/idp/entitlements`; the gate is a Rust API with no caller until Phase 3; policy existence unchecked; not run on a multi-node cluster (see Current State) |
| **3 — SSH identity issue + revocation** | `provider/ssh.rs` identity-bound `sign` wrapping the SSH engine (principals=login, key-id attribution, uid/gid extensions), `GET /v2/idp/ssh/krl`, the signed/versioned `deny-feed`, and the reference `AuthorizedPrincipalsCommand` + NSS helper for Linux. | **Complete, with caveats** — `crates/bv-engine-idp/src/{provider/ssh,revoke}/`, `bin/bv-idp-host`; KRL checked with `ssh-keygen`; no real sshd/Linux host run; NSS helper generates entries from a certificate, no on-login materialization; PQC CA unsupported; feed key not rotated (see Current State) |
| **4 — RADIUS provider** | `provider/radius.rs` (RadSec + opt-in UDP), per-vendor attribute templates (FortiGate first), entitlement-gated, Access-Reject for non-active. Live-tested against a FortiGate (or `freeradius`/`pyrad` harness). | **Complete, with caveats** — `crates/bv-engine-idp/src/provider/radius/`; one-time passcodes minted through the vault; RadSec with pinned NAS certificates, UDP opt-in; verified by the crate's own client over real sockets only: **no FortiGate, FreeRADIUS or pyrad run**; not run on a multi-node cluster (see Current State) |
| **5 — SAML IdP + OIDC OP** | `provider/saml_idp.rs` (reusing the SAML-auth signing core) + `provider/oidc_op.rs` (discovery/JWKS/authz/token), both entitlement-gated, UID + role-set in assertions/claims. | **Complete, with caveats** — `crates/bv-engine-idp/src/provider/{saml_idp,oidc_op,federation}/`; aws-lc RS256 signing over `bv-auth-saml`'s C14N; verified with an RP library and the SAML auth verifier only: **no real SP, RP or browser run**; OIDC back channel served raw for standard RPs since T546 (SAML metadata still envelope-only); not run on a multi-node cluster (see Current State) |
| **6 — LDAP-compat directory** | `provider/ldap_dir.rs` read-only bind+search serving `posixAccount`/`posixGroup`; bind = live active-state check. | **Complete, with caveats** — `crates/bv-engine-idp/src/provider/ldap_dir/`; LDAPS with pinned client certificates, StartTLS, cleartext opt-in; one-time bind passcodes, gate-scoped visibility; verified with the ldap3 client over real sockets and OpenLDAP `ldapsearch` over cleartext only: **no sssd/nslcd/pam_ldap run**, no non-rustls TLS client; not run on a multi-node cluster (see Current State) |
| **7 — GUI** | Identity Provider admin page (Identities / Entitlements / Providers / Revocations tabs) + Tauri commands + API wrappers. | **Complete, with caveats** — `gui/src/routes/IdentityProviderPage.tsx`, `gui/src/components/idp/`, `gui/src/lib/idp.ts`, `gui/src-tauri/src/commands/idp.rs`; embedded backend reads an explicit `/v2/` path; one-time secrets shown once and cleared, TLS keys write-only; unit-tested with a mocked backend plus one embedded-vault test: **not run against a live vault**; mount path fixed at `idp/` (see Current State) |

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
