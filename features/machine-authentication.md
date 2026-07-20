# Feature: Machine Authentication (FerroGate)

## Summary

A new auth method that lets BastionVault **only admit known, authorized machines** by delegating the
*"is this a real, attested machine?"* question to **[FerroGate](../../FerroGate)** — a TPM 2.0-attested,
post-quantum SPIFFE machine-identity system — and keeping for itself the *"is this machine **allowed** to use
**this** vault?"* question via an **administrator approval gate**.

FerroGate already proves a machine's identity in hardware: its Machine Identity Agent (MIA) runs a four-phase
TPM attestation handshake against the Central Machine Identity Service (CMIS) and obtains a short-lived,
composite-signed (Ed25519 **and** ML-DSA-65) **SVID** bound to the host's TPM Endorsement Key. The MIA can then
mint short-lived, **DPoP-bound child tokens** for a named audience. BastionVault becomes the *relying party*: a
client on an attested host asks its local MIA for a child token whose audience is the BastionVault server,
presents it, and BastionVault **cryptographically verifies it offline** against FerroGate's published
verification keys (JWKS + CRL).

A valid FerroGate token proves the machine is genuine and hardware-attested — but **not** that it may use this
vault. So the first time a new machine (identified by its stable SPIFFE ID) presents a valid token, BastionVault
records a **pending enrolment** and denies real access (`403 enrolment_pending`) until an **administrator
approves it** from the GUI (*Auth → Machines*) or the CLI (`bvault ferrogate approve <spiffe-id>`). On approval
the admin attaches the policy set the machine may use; subsequent logins mint a normal BastionVault token bound
to those policies.

To break the bootstrap chicken-and-egg (you need an approved machine to do admin work, but approval needs an
admin), **the first machine that authenticates while the system holds zero approved machines and presents a
valid BastionVault root token is auto-approved** with a configurable bootstrap policy. Every later machine goes
through the human-in-the-loop gate.

This is implemented as a **self-contained plugin** (an in-tree auth module mounted at `auth/ferrogate/`, built
as its own crate so it stays cleanly separable) that depends only on FerroGate's published, `#![forbid(unsafe_code)]`
**reference verifier crates** — no custom crypto.

> **Supersedes the earlier host-fingerprint design.** A prior draft of this feature had BastionVault roll *its
> own* machine identity from a host-hardware fingerprint (CPU/SMBIOS/disk/NIC) plus a locally-stored random part,
> with an optional TPM backend. That approach is **dropped** in favour of delegating hardware-rooted identity to
> FerroGate: the fingerprint was only software-readable (no in-silicon signing key), whereas a FerroGate SVID is
> bound to a TPM-resident key that never leaves the chip and is verified through a vendor-rooted EK chain. The
> admin-approval workflow, audit-event vocabulary, and *Auth → Machines* GUI shape carry over unchanged; only the
> identity-proof half is replaced.

## Security model — what this does and doesn't protect

**Protects against**

- **Unattested / unknown machines.** A machine with no FerroGate MIA, or one FerroGate has not enrolled
  (its TPM EK hash is not in the CMIS fleet manifest), cannot obtain a child token at all → it can never reach
  even the `pending` state.
- **Stolen bearer token replay.** Child tokens are DPoP sender-constrained: a captured token presented without
  the matching DPoP private-key proof is rejected (`verify_bound` fails). Tokens are also short-lived (≤ 600 s).
- **Quantum (harvest-now-decrypt-later) forgery.** The token signature is composite — an attacker must break
  **both** Ed25519 and ML-DSA-65 to forge it.
- **Revoked / decommissioned hosts.** FerroGate publishes a composite-signed CRL inside the JWKS extension;
  BastionVault refuses tokens whose SVID/`jti` is revoked.
- **Unauthorized-but-genuine machines.** A real attested machine still cannot use the vault until an admin
  approves its SPIFFE ID. Genuine ≠ authorized.

**Does NOT protect against**

- **A FerroGate compromise.** BastionVault trusts FerroGate's signing key as the machine-identity root. If CMIS's
  composite key is compromised an attacker can mint valid tokens. Mitigation is FerroGate's own (TEE-resident,
  Shamir 3-of-5 key); BastionVault's residual defense is the admin-approval gate — a freshly forged SPIFFE ID is
  still `pending` until approved.
- **Local privileged compromise on an approved host.** `root` on an already-approved, attested host can ask the
  local MIA for child tokens (subject to FerroGate's own caller allowlist). Mitigation: short BastionVault token
  TTLs, admin revoke, audit alerting on unexpected source IPs.
- **Misconfigured trust anchor.** If the operator points `auth/ferrogate/config` at the wrong JWKS / trust domain,
  the gate is only as good as that config. Config writes are root/sudo-gated and audited.

## Motivation

- **Hardware-rooted, non-exportable machine identity.** A FerroGate SVID is bound to a TPM-resident key that
  never leaves the chip — the strongest machine-trust posture BastionVault can offer, and strictly better than a
  software-readable host fingerprint.
- **Don't reinvent attestation.** FerroGate already does TPM quote verification, RIM allowlists, credential
  activation, fleet enrolment, CRLs, and formal proofs. BastionVault should *consume* that, not duplicate it.
- **Two-party authorization the operator understands.** The machine proves *what it is* (FerroGate); the admin
  decides *what it may do* (BastionVault policies). Clean separation of attestation from authorization.
- **Reuse vetted, self-contained verifiers.** FerroGate ships `ferro-svid-verify` and `ferro-child-verify` as
  copy-pasteable, `#![forbid(unsafe_code)]` reference verifiers whose only crypto dependency is `ferro-crypto`'s
  composite primitive — exactly the "use vetted libraries, avoid custom crypto" posture `agent.md` mandates.
- **No human-in-the-loop today for new machine trust.** Today a new client is trusted because someone handed it
  a working `secret_id`. This feature adds an explicit admin-approval gate keyed on a hardware-attested identity.

## Current State

- **Phase 1 shipped.** The `ferrogate` auth backend is registered and mounts at `auth/ferrogate/`
  ([`src/modules/credential/ferrogate/`](../src/modules/credential/ferrogate/)). Trust-anchor `config`
  read/write, the `MachineEntry` storage layout, and the admin lifecycle routes (`register`, `LIST machines`,
  `GET/DELETE machines/{id}`, `approve`, `reject`, `revoke`) are implemented and covered by an integration test.
  `{id}` is the BLAKE3 hex of the SPIFFE ID (a raw SPIFFE ID can't be a path segment). `register` doubles as
  admin pre-authorization and as the way to exercise the lifecycle before real `login` lands. `login` returns a
  `not_implemented` error pending Phase 2.
- **Phase 2 shipped.** `auth/ferrogate/login` verifies a DPoP-bound, composite-signed FerroGate child token via
  the vendored `ferro-child-verify` reference verifier ([`third_party/ferrogate-sdk-rust/`](../third_party/ferrogate-sdk-rust/),
  pinned to FerroGate `releases/v0.13.2`) against a `static_jwks` trust anchor, then checks audience + trust
  domain and applies the approval gate: an approved machine mints a token bound to its policies/TTL; an unknown
  machine is recorded `pending` and denied; pending/rejected/revoked are denied. The DPoP proof is read from the
  `DPoP` header (now plumbed through the HTTP logical layer) or a `dpop` body field. Covered by an integration
  test that mints a real composite-signed token + DPoP proof and exercises unknown→pending→approve→mint, the
  bare-token (no-DPoP) rejection, and the audience-mismatch rejection.
- **Phase 3 shipped.** The one-shot **first-machine root bootstrap** is live: when no machine is yet approved
  and the login request carries a BastionVault root-policy token, the presenting machine is auto-approved with
  `bootstrap_policies` and minted immediately (`approver = "bootstrap(root)"`); the moment one machine is
  approved, every later machine falls back to the admin gate. Added a token-authenticated self-poll
  `POST auth/ferrogate/status` (verifies the token, mints nothing, returns the machine's enrolment status —
  `unknown` if never seen). Key transitions emit `audit`-target log events (`ferrogate.machine.first_seen` /
  `.bootstrap_approved` / `.login`). Tested: bootstrap approves+mints the first machine, the second machine in
  the same conditions goes `pending`, and the status endpoint reports approved/unknown.
- **Phase 4 shipped — both transports validated live.** Plaintext was validated against CMIS 0.13.1; the
  **hybrid post-quantum TLS path is now validated end-to-end against the live CMIS 0.15.0** (`X25519MLKEM768`-only,
  SHA-384 SPKI-pinned ECDSA-P256 server cert) — BastionVault negotiates the PQ key exchange, pins the cert, and
  fetches the JWKS (`kid cmis-dev-1`). The vendored FerroGate SDK is bumped to `releases/v0.15.0`
  (`ferro-crypto` + `ferro-child-verify`; public APIs and the proto are unchanged from 0.13.2). The
  `cmis_grpc` JWKS source calls FerroGate's `ferrogate.v1.MachineIdentity/JWKS` RPC
  and caches the result for `jwks_refresh_secs` (default 60), with stale-while-revalidate on fetch failure. The
  gRPC stubs are **pre-generated** from `machine_identity.proto` and vendored
  ([`cmis_proto.rs`](../src/modules/credential/ferrogate/cmis_proto.rs)) so `protoc` is **not** a BastionVault
  build dependency (runtime `tonic`/`prost` only). Transport is selectable by `cmis_tls_enable`: hybrid
  post-quantum TLS (`X25519MLKEM768` via `ferro-crypto`, SHA-384 SPKI-pinned, no CA chain) when enabled, or
  cleartext gRPC when disabled. **Validated end-to-end against the live dev CMIS** (`segdc1vds0005.fgv.br`,
  CMIS 0.13.1, plaintext — it's an M2 bring-up server) via an `#[ignore]`d live test; the PQ-TLS path compiles
  and is wired but awaits a TLS-enabled CMIS for its full validation. CRL is **not** enforced on the child-token
  path (FerroGate's child-token verifier does not check the CRL; the `x-ferrogate-crl` JWKS extension applies to
  the direct-SVID path — deferred to Phase 7). A `cmis_same_host` config flag (2026-06-11) handles the
  server-and-CMIS-on-one-machine topology: the configured `cmis_endpoint` (the host's public name, right for
  external MIAs) can be unreachable from the server's own vantage point — inside a rootless-podman (pasta)
  container the host's own address hairpins into the container's empty namespace — so with the flag set the
  fetch tries `host.containers.internal:<port>`, then loopback, then the configured endpoint (SPKI pin
  authenticates the peer whichever name connects). Connect errors also unwrap tonic's `source()` chain so the
  real cause (pin mismatch, refused, handshake alert) is surfaced instead of a bare `"transport error"`. A
  `cmis_srv` config flag (2026-06-12) gives the mount the MIA's own SRV failover: set a DNS SRV owner name and
  the CMIS client resolves it on each fetch, then dials every advertised node in RFC 2782 order until one
  connects *and* verifies its SPKI pin — so a node whose cert has diverged from the shared cluster pin is
  skipped rather than taking the mount down. Takes precedence over `cmis_endpoint`; *Autofill from local MIA*
  now stores the SRV name (not a single resolved node) so the mount fails over the way the MIA does.
- **Phase 5 shipped (Unix).** Client CLI `bvault ferrogate login|status|whoami` driving the FerroGate **MIA
  helper socket** (`/run/ferrogate/mia.sock`, length-delimited CBOR, mirrored from `mia::helper::proto`): `login`
  mints a DPoP-bound child token from the MIA, builds the RFC 9449 proof, and exchanges it at
  `auth/<mount>/login`, persisting the issued BastionVault token; `status` reports enrolment without minting a
  vault token; `whoami` prints the host SPIFFE id locally. A missing MIA fails clean with
  `ferrogate_mia_unavailable`. The CLI's DPoP construction is proven against FerroGate's own `verify_dpop_proof`
  in a unit test; the wire framing has a CBOR round-trip test. Unix-only for now (Windows named-pipe is a
  follow-up). Full live login isn't exercised in the current dev env (the dev CMIS has no RIM bundle, so its MIA
  can't attest/mint), but every layer the CLI owns is unit-validated.
- **Phase 5.1 — app-facing token minting.** `bvault ferrogate token` (2026-07-03) is the headless companion to
  `login` for applications: the same MIA + DPoP exchange at `auth/<mount>/login`, but the minted machine token
  and its attributes (policies, TTL, hoisted `metadata` such as `spiffe_id`) are printed as structured output
  (`--format json`, `--field client_token` for bare-token piping) and **never persisted** to the on-disk token
  helper, so an app can exec it at startup without disturbing the host's stored CLI session. The token serves
  as `X-Vault-Token` for direct API calls or as the `machine_token` of an AppID login. The MIA
  mint/DPoP/body construction is shared with `login`/`status` via a common helper.
- **Phase 6 shipped.** Admin GUI page `Machines (FerroGate)` (route `/ferrogate`, sidebar entry) with Pending /
  Approved / History / Config tabs: approve (policies + TTL + comment), reject (reason), revoke, and a
  trust-anchor config form (trust domain, audience, JWKS source, CMIS endpoint + SPKI pins, static JWKS,
  PQ-TLS toggle, bootstrap toggles). Backed by seven Tauri commands in
  [`gui/src-tauri/src/commands/ferrogate.rs`](../gui/src-tauri/src/commands/ferrogate.rs) routing to
  `auth/ferrogate/*`, with `api.ts` wrappers, TS types, an `AUTH_TYPES` entry, and two `vitest` tests
  (full GUI suite of 116 passes; tsc + vite build clean).
- **Phase 6.1 — GUI is now a MIA client too.** The GUI was previously only the relying-party/admin side; a
  **Machine Login** tab on the *Machines (FerroGate)* page now puts it on the *client* side of the protocol —
  the same self-bootstrap flow as the CLI. It dials the local MIA helper socket, mints a DPoP-bound child token,
  and exchanges it at `auth/<mount>/login`, with *Whoami* / *Check status* / *Log in* actions. Four new Tauri
  commands (`ferrogate_default_socket`, `ferrogate_machine_login`, `ferrogate_machine_status`, `ferrogate_whoami`)
  **reuse `bastion_vault::cli::command::ferrogate_mia` verbatim** (no second copy of the DPoP/CBOR/thumbprint
  crypto); the blocking socket I/O runs on `spawn_blocking`, and non-Unix targets return clear "Unix-only" stubs.
  The socket field is prefilled with the resolved socket. Logging in here does not replace the admin session
  token.
- **Phase 6.3 — one-shot mount autoconfig from the local MIA.** `bvault ferrogate autoconfig` (and a GUI
  *Autofill from local MIA* button on the config page, via the `ferrogate_autoconfig` Tauri command) derives
  a complete `ferrogate` mount config from the FerroGate MIA installed on the host: the CMIS endpoint + SPKI
  pin come from `mia.toml` `[cmis]`, the trust domain from the signed allowlist (`allowlist.cbor` — read
  without minting a token, so a not-yet-allowlisted caller can still provision), and the live composite JWKS
  is fetched from CMIS by reusing the mount's own `cmis::fetch_jwks_json` (so the fetch path is identical to
  the running mount's). Sets `jwks_source = cmis_grpc`; `--apply` writes it to `auth/<mount>/config`. The
  core (`ferrogate_mia::build_autoconfig`) is shared verbatim between CLI and GUI.
- **Phase 6.2 — socket path is discovered from the MIA's own config, not hard-coded.** The earlier per-OS
  `DEFAULT_MIA_SOCKET` constant broke when MIA ≥0.18 moved its macOS default to
  `/Library/Application Support/FerroGate/run/mia.sock` (and because the path is operator-configurable in
  `mia.toml` regardless). `resolve_mia_socket()` now mirrors MIA's own resolution order — the
  `FERROGATE_HELPER_SOCKET` env override, then `[helper].socket` from the first config found
  (`$FERROGATE_CONFIG`, the per-OS system path `/Library/Application Support/FerroGate/mia.toml` (macOS) or
  `/etc/ferrogate/mia.toml` (Linux), then the per-user path), then the per-OS `mia setup` wizard default as a
  last resort. `ferrogate_default_socket` and the `--socket` flags resolve through it; the constant remains only
  as the fallback. Adds `toml` as a runtime dependency.
- **Phase 7 shipped — feature complete.** Opt-in **direct-SVID mode** (`accept_svid`): a host SVID presented at
  `login` is verified via the vendored `ferro-svid-verify::verify_unrevoked`, which **enforces FerroGate's
  composite-signed CRL** (a revoked host, or a stale/absent CRL, fails closed); the host identity is the SVID
  `sub`, and attestation evidence (`ek_cert_sha384`, `policy_id`) is recorded on the machine. Login routes by
  JOSE `typ` (SVID vs child token). Added a per-source-IP **login rate limit** (`login_rate_limit_per_min`,
  default 10, `0` = unlimited). Added **Prometheus counters** (`bvault_ferrogate_login_total`,
  `_login_denied_total{reason}`, `_pending_total`, `_approved_total`) registered in the metrics manager. Wrote
  the operator + threat-model guide at [`docs/ferrogate-machine-auth.md`](../docs/ferrogate-machine-auth.md).
  Tests: SVID `accept_svid` gate + CRL-enforced direct-SVID approve→mint.
- **Phase 8 shipped — combined machine+user auth & enrolment lifecycle.** `auth/ferrogate/login` accepts an
  optional `user_token`; when bound, the minted token's policies are the **intersection** of the machine's
  approved set and the user token's set (`default` re-injected by the token store), the combined token carries
  the *user's* `entity_id`/`username` (ownership/ACL) alongside the attesting `spiffe_id`, and the broader
  intermediate user token is revoked. A `require_user_token` config flag enforces the user factor server-side
  (a login without a valid `user_token` is denied; root tokens can't be bound). New operator CLI
  `bvault operator ferrogate {list,approve,reject,revoke}` administers the queue against the running server
  with a root token and **does not require an approved machine** — the bootstrap escape hatch (address a
  machine by handle or SPIFFE id). The GUI gains a per-connection "Require machine identity" option: the
  connect flow gates on machine approval before user login (approved → bind user token into a combined
  session; pending/unknown → enrolment dialog with the SPIFFE id + `operator ferrogate approve` hint +
  Recheck; rejected/revoked → hard access-denied), `ferrogate_machine_login` returns a typed
  `enrolment`/`message`, and the config page exposes a "Require user token" toggle. Covered by
  `test_ferrogate_combined_user_binding` (intersection, non-shared-policy drop, user-token revocation,
  `require_user_token` enforcement).
- **Phase 8.1 shipped — server-enforced machine identity.** A `require_machine_identity` config flag makes
  machine authentication a property of the **server**, not the client. When set, `TokenStore::pre_route`
  rejects every authenticated request whose token is not FerroGate machine-bound (lacks `spiffe_id` in its
  metadata); root tokens stay exempt so bootstrap/approval and break-glass admin keep working. The flag is
  mirrored to the system view (`core/ferrogate-require-machine-identity`) and an in-memory `Core` atomic loaded
  at `post_unseal`, so enforcement is one atomic read on the hot path. A new unauthenticated
  `auth/ferrogate/requirement` endpoint advertises the flag (+ expected audience / trust domain); the GUI
  connect flow now queries it and runs the machine gate from the **server's** answer rather than a local
  toggle (the per-connection "Require machine identity" client checkbox is removed; the server config page
  gains a "Require machine identity (all sessions)" toggle). Independent of `require_user_token` — set both for
  full combined enforcement. Covered by `test_ferrogate_require_machine_identity_enforced` (user-token denied,
  root exempt, machine-bound accepted, `requirement` endpoint unauthenticated, flag round-trip). Operators can
  toggle it without curl via `bvault operator ferrogate require-machine-identity [on|off]` (no argument prints
  the current value); the server admin GUI exposes the same as a "Require machine identity (all sessions)" toggle.
- **Phase 9 shipped — unauthenticated machine self-enrolment.** A new unauthenticated path
  `POST auth/ferrogate/enroll` lets an arbitrary machine request registration of its own (self-asserted)
  SPIFFE ID. It only records a `pending` `MachineEntry` (flagged `self_enrolled`) for an administrator to
  approve via the existing approve/reject/revoke flow — it **never mints a token or grants access**; real
  authentication still requires the attested `login` flow, so a spoofed SPIFFE ID is inert on its own. An
  existing record is returned unchanged (an unauthenticated caller can never reset/downgrade an admin
  decision). Gated by four `auth/ferrogate/config` fields: `self_enroll_enabled` (master switch, off by
  default), `self_enroll_allowlist` / `self_enroll_blocklist` (block-list wins; each entry matches the source
  IP for IP/CIDR entries or the claimed `spiffe_id` — exact or `*`-prefix — / machine id otherwise), and
  `self_enroll_rate_limit_per_min` (per-source-IP limiter, default 5, using a dedicated counter map). Surfaced
  in the GUI FerroGate Config tab (enable toggle + allow/block-list editors + rate-limit field) with a
  **self-enrolled** badge on queue rows; `bvault ferrogate enroll` CLI (reads the SPIFFE ID from the local MIA
  when `--spiffe-id` is omitted); `self_enroll_denied` metric reason. Covered by four lib tests
  (`test_ferrogate_self_enroll_*`: lifecycle→approve→attested-login, disabled-by-default, allow/block lists,
  rate limit).
- **Fix — GUI DPoP audience derives from the server.** Both the connect-flow machine gate (`ConnectPage.tsx`
  `runMachineGate`) **and** the combined machine+user user-login step (`LoginPage.tsx` `finalizeLogin`)
  previously signed the DPoP proof with `profile.address` (the vault server URL), assuming
  `expected_audience == <server URL>` as this doc describes. A mount configured with a *trust-domain* audience
  (e.g. `https://ferrogate.dev`) then failed login with an `htu` binding mismatch ("DPoP proof does not match
  the request"). The connect flow now captures the server-advertised `expected_audience` (from
  `auth/ferrogate/requirement`) onto the in-memory `RemoteProfile`, and both signing paths read it, falling
  back to `profile.address` only when the server leaves it unset.
- **GUI — edit policies of an approved machine.** The *Machines (FerroGate)* page now exposes an **Edit
  policies** action on approved machines (previously only revoke was available), reopening the approve modal
  prefilled with the current policies/TTL/comment and re-approving in place. Because combined auth intersects
  machine ∩ user policies, the machine's approved set is the ceiling; editing it is how an operator restores a
  user's effective policies (e.g. raising a machine from `default` to `administrator`) without re-enrolling.
- **GUI/CLI — validated bootstrap policies + MIA environment selector (v0.13.5–v0.14.0).** v0.13.5 replaced the
  approve-modal free-text policies field with a multi-select over the vault's existing ACL policies (a typo'd
  name silently grants nothing under combined auth). v0.14.0 generalizes that into a reusable `PolicySelect`
  autocomplete and applies it to the Config tab's **bootstrap policies** field — only existing policies are
  selectable (`default` offered as the baseline), unknown names render as amber ⚠ chips and **block Save**. It
  also adds an **MIA environment** selector to the Config + Machine Login tabs and a `--environment <env>` flag
  on `bvault ferrogate {login,status,whoami,autoconfig}`: a host running side-by-side FerroGate deployments has
  one `mia-<env>.toml` per environment (e.g. `mia-hml.toml`), and the selector reads that file's CMIS
  endpoint/pin, allowlist, and helper socket instead of the default `mia.toml`. CMIS may be configured
  either as a literal `[cmis].endpoint` or as a DNS SRV record (`[cmis].srv`, an HA cluster) — for an SRV
  source, autofill now carries the SRV owner name straight into the mount's `cmis_srv` field (2026-06-12)
  so the mount resolves it on every fetch and fails over across all advertised nodes, rather than pinning the
  single best node resolved at config time (the v0.14.1 behavior, which could not fail over if that node's cert
  diverged from the shared pin). Environment selectors are
  validated as safe single path components; the GUI discovers installed environments by scanning the system and
  per-user config dirs (`ferrogate_list_environments`). The MIA helper layer gained `_for(environment)` variants
  (`resolve_mia_socket_for`, `read_cmis_config_for`, `read_allowlist_trust_domain_for`, `build_autoconfig`).
- **MIA environment persisted + advertised (Unreleased, 2026-06-12).** The Config tab's MIA environment was
  previously transient autofill state — lost on Save, and every GUI MIA dial (connect-time machine gate,
  combined machine+user binding in `finalizeLogin`, Machine Login tab) used the default `mia.toml`. The mount
  config now has a `mia_environment` field (validated as a safe single path component server-side), the
  unauthenticated `requirement` endpoint advertises it, and clients capture it onto the in-memory
  `RemoteProfile` (alongside `expected_audience`) so all machine logins resolve the matching
  `mia-<env>.toml` socket automatically. The Config and Machine Login tabs prefill from the saved value.
- **MIA environment combobox + cross-screen selection (Unreleased, 2026-06-12).** The Config and Machine Login
  tabs now render the MIA environment as a dropdown built from the discovered `ferrogate_list_environments`
  (plus a `(default)` entry and the saved value when its selector isn't installed locally), replacing the
  free-text datalist. The selection is page-level shared state, so choosing an environment in the Config tab
  immediately re-targets the Machine Login tab's socket; the Connect screen continues to read the advertised
  value from the `requirement` endpoint after Save.
- **Per-server MIA environment override on the setup screen (Unreleased, 2026-06-15, v0.14.6).** The Server
  add/edit form (`ConnectPage.tsx`) now has its own "MIA environment" combobox (same option builder: installed
  `ferrogate_list_environments` selectors + a `(server default)` entry + the saved value when not installed
  locally). The choice persists on the profile as `RemoteProfile.mia_environment` and, on connect, is seeded
  into the shared env store *before* the `requirement` fetch, so a pinned environment takes precedence over the
  server-advertised one when the machine gate dials `mia-<env>.toml`. Fixes the dead-end where a connect failed
  with "not on the MIA's local allowlist" (wrong MIA daemon dialed) and the operator had no way to override the
  environment from the Get Started screen.
- Caveats: `cmis_grpc` is async-build only (the `sync_handler` feature is independently broken repo-wide);
  child-token revocation on the `static_jwks` source relies on short token TTL (the CRL is enforced on the SVID
  path); audit events are structured log lines (no dedicated audit-store rows).
- BastionVault ships Token, UserPass, AppRole, Certificate, and FIDO2/WebAuthn auth methods. None consume an
  external attestation authority.
- FerroGate (sibling repo `../FerroGate`) exposes: a CMIS `JWKS` gRPC RPC returning composite verification keys
  plus the signed CRL (`x-ferrogate-crl` extension); SVIDs of `typ: ferrogate-svid+jwt`; child tokens of
  `typ: ferrogate-child+jwt`; and the two reference-verifier crates with public entry points
  `ferro_svid_verify::verify` / `verify_unrevoked` and `ferro_child_verify::verify` / `verify_bound`.

## Identity model — how a machine proves itself

The authoritative machine identity is the **SPIFFE ID** FerroGate derives from `SHA-384(ek_cert)`:

```
spiffe://ferrogate.<env>/host/<uuid>
```

It appears as `iss` on the host SVID and as `iss` on every child token that host mints. BastionVault keys all
enrolment records on this SPIFFE ID — it is stable across SVID rotations and across child tokens.

### Verification path (recommended: child-token + DPoP)

The FerroGate-intended path for a host application talking to a third-party API. The BastionVault client is that
application:

```
client host (FerroGate MIA present)                         BastionVault server
  1. client → local MIA helper socket:
       HelperReq { audience: "<bvault-url>", dpop_jkt, ttl_secs ≤ 600 }
     MIA returns a child token (ferrogate-child+jwt), DPoP-bound to the client's key
  2. client builds a DPoP proof JWS over (htm=POST, htu=<login url>, iat, jti)
  3. POST auth/ferrogate/login
       headers: DPoP: <proof-jws>
       body:    { token: "<child-token>" }                  ──►
                                                              verify_bound(
                                                                token, jwks, Some(dpop_proof),
                                                                DpopExpectation{htm,htu,...}, now, leeway)
                                                              → Verified { claims }   (or fail-closed)
                                                              extract spiffe_id = claims.iss
                                                              look up enrolment(spiffe_id)
                                                              ├─ approved  → mint BastionVault token (policies)
                                                              ├─ pending   → 403 enrolment_pending
                                                              ├─ none      → create pending; 403 enrolment_pending
                                                              │              (unless bootstrap auto-approve, below)
                                                              └─ rejected/revoked → 403
                                              ◄── { client_token, lease_duration, accessor } | 403
```

`verify_bound` (from `ferro-child-verify`) checks, fail-closed: three well-formed segments; the FerroGate child
`alg`/`typ`; a `kid` present in the configured JWK set; a valid **composite** (Ed25519 **and** ML-DSA-65)
signature; the `exp` bound; **and** the DPoP sender-constraint (the proof's RFC 7638 thumbprint equals the
token's `cnf.jkt`, and the proof matches this HTTP request). Revocation is enforced by checking the JWKS's
`x-ferrogate-crl` extension.

### Alternative path (direct SVID)

For hosts/clients that present the host SVID itself rather than a minted child token (e.g. a thin agent without
the MIA helper round-trip), BastionVault verifies with `ferro_svid_verify::verify_unrevoked`. This drops the
per-request DPoP sender-constraint, so it is **opt-in** via `auth/ferrogate/config { accept_svid: true }` and
documented as the weaker mode. Default is child-token-only.

### Trust anchor (JWKS) distribution

`auth/ferrogate/config` records how BastionVault obtains FerroGate's composite verification keys + CRL. Two
sources, pick one:

1. **`cmis_grpc`** *(recommended)* — BastionVault periodically calls the CMIS `JWKS` RPC over hybrid-PQC TLS,
   pinning CMIS SPKI hashes from config; caches keys + CRL; refreshes on a configurable interval (default 60 s,
   matching FerroGate's CRL cadence). Stale-while-revalidate with a hard max-age fail-closed.
2. **`static_jwks`** *(air-gapped / simple)* — operator pastes a pinned JWK set; CRL refresh is the operator's
   responsibility (documented caveat). Useful for tests and offline deployments.

Config fields: `trust_domain` (e.g. `ferrogate.prod`), `expected_audience` (this vault's URL, matched against
child-token `aud`), `jwks_source`, CMIS endpoint + SPKI pins (for `cmis_grpc`), `jwks` blob (for `static_jwks`),
`accept_svid` (default `false`), `clock_leeway_secs` (default 60), `default_token_ttl`, and the bootstrap knobs
below. Writes are root/sudo-gated and audited; secrets (none here — all public keys) are not logged.

## Bootstrap: first-machine auto-approval

Goal: *"the first machine to login using the root token should be automatically authorized."*

Rule, evaluated at `auth/ferrogate/login` when an unknown SPIFFE ID presents a fully-verified FerroGate token:

```
if config.bootstrap_root_auto_approve
   and approved_machine_count == 0
   and request carries a valid BastionVault token with the "root" policy:
       auto-approve this SPIFFE ID with config.bootstrap_policies (default: ["default"])
       emit ferrogate.machine.bootstrap_approved (records actor = root, spiffe_id)
       mint token immediately
else:
       create/keep pending; 403 enrolment_pending
```

Properties:

- **One-shot by construction:** the condition `approved_machine_count == 0` is only ever true once; the moment
  the first machine is approved, every later machine takes the normal admin-approval path.
- **Requires root, not just any token:** the bootstrap login must be authenticated by the BastionVault root
  token (or a `sudo`/root-policy token), so an attacker who merely owns an attested host cannot self-bootstrap.
- **Disable-able:** `bootstrap_root_auto_approve: false` forces *every* machine — including the first — through
  explicit admin approval, for operators who want zero auto-grants.
- **Embedded mode:** in the Tauri embedded vault the operator *is* root locally, so the first machine bootstrap
  is the natural path; documented.

## Scope

### In scope — server (the `ferrogate` auth plugin)

- **New auth backend** mounted at `auth/ferrogate/` (configurable mount path). Routes (all under the `v2/`
  HTTP prefix per `agent.md`):
  - `POST auth/ferrogate/config` / `GET auth/ferrogate/config` — root/sudo-gated trust-anchor configuration
    (fields above). `GET` redacts nothing sensitive (all public) but is still admin-gated.
  - `POST auth/ferrogate/login` — unauthenticated path (no prior BastionVault token required, except that the
    bootstrap branch *reads* a presented root token if any). Body `{ token }`, header `DPoP: <proof>`. Verifies,
    resolves enrolment state, mints a token or returns `403 enrolment_pending` / `403 enrolment_rejected` /
    `403 machine_revoked`. On an unknown SPIFFE ID it **creates** the pending record as a side effect so it
    surfaces in the admin queue.
  - `GET auth/ferrogate/enrolment/{spiffe_id}` — status poll. Returns `{ status, approved_at, approver,
    policies, ttl_seconds }`. Readable by a presenter of a valid (even if `pending`) FerroGate token for that
    SPIFFE ID, so a client can poll its own status without admin rights.
  - `LIST auth/ferrogate/machines` — admin-only; lists machines with `spiffe_id`, short id, status, first-seen,
    last-login, last source IP, attestation summary (`ek_cert_sha384` prefix, `policy_id`), attached policies.
  - `POST auth/ferrogate/machines/{spiffe_id}/approve` — admin approves; body `{ policies, ttl_seconds,
    max_uses?, comment? }`. Approver cannot grant policies they don't hold (same rule as other policy-granting
    paths; `sudo` is the escape hatch). Audited.
  - `POST auth/ferrogate/machines/{spiffe_id}/reject` — admin rejects with `{ reason }`. Audited.
  - `POST auth/ferrogate/machines/{spiffe_id}/revoke` — admin revokes an approved machine; active
    BastionVault tokens for it are revoked through the lease manager. Audited.

- **Storage layout** under the backend's barrier-encrypted view:
  - `config` — the trust-anchor config blob.
  - `machine/<spiffe_id_hash>` — `{ spiffe_id, status, policies, ttl_seconds, ek_cert_sha384, policy_id,
    first_seen_at, approved_at, approver, last_login_at, last_login_ip, reject_reason? }`. Keyed by a salted
    hash of the SPIFFE ID to avoid storing raw ids as keys.
  - `jwks_cache` — last-fetched JWK set + CRL + fetch timestamp (for `cmis_grpc` source).
  - `index/approved_count` — small counter to make the bootstrap check O(1).
  - All entries encrypted under the existing barrier; no new crypto introduced.

- **Verification core** — a thin wrapper around `ferro-child-verify` / `ferro-svid-verify`. The plugin crate
  depends on `ferro-child-verify`, `ferro-svid-verify`, and `ferro-crypto` (path/git dependency on the sibling
  repo, version-pinned). No signature/crypto code is written in BastionVault — only orchestration.

- **JWKS refresher** — for `cmis_grpc`, a background task (lifecycle-tied to the mount) that refreshes the
  cached JWKS + CRL on `jwks_refresh_secs`, with stale-while-revalidate and a hard fail-closed max-age.

- **Audit events** — `ferrogate.config.write`, `ferrogate.machine.first_seen`, `ferrogate.machine.bootstrap_approved`,
  `ferrogate.machine.approved`, `ferrogate.machine.rejected`, `ferrogate.machine.login`,
  `ferrogate.machine.login.denied` (with reason: `pending` | `rejected` | `revoked` | `verify_failed`),
  `ferrogate.machine.revoke`, `ferrogate.token.renew`. Each carries `spiffe_id`, attestation summary, source IP,
  and (for admin actions) actor + comment. **Never** logs token bytes or DPoP proofs.

- **Rate limits** — `login` is per-source-IP rate-limited (default 10/min, configurable) so a flood of unknown
  SPIFFE IDs can't spam the pending queue.

- **Policy integration** — the minted token carries exactly the policies from the approval payload (or
  `bootstrap_policies` for the auto-approved first machine), renewable like any other Vault token.

### In scope — client (`bvault` CLI)

- **`bvault ferrogate login --server <url>`** — the command a service/cron runs each time it needs a token:
  1. Connects to the local FerroGate MIA helper socket, requests a child token for `audience = <server>`.
  2. Builds a DPoP proof for the login request.
  3. `POST auth/ferrogate/login`; on `200` writes the BastionVault token to
     `~/.config/bvault/<server-name>/token` (or stdout); on `403 enrolment_pending` exits non-zero with a
     clear "awaiting admin approval" message.
- **`bvault ferrogate status --server <url>`** — fetches and prints the machine's enrolment status, SPIFFE ID,
  attestation summary, and approved policies.
- **`bvault ferrogate whoami`** — prints the local SPIFFE ID (read from the MIA / current SVID) so an operator
  can copy it into an `approve` command.
- The client **requires a running FerroGate MIA**; if the helper socket is absent it fails with a clear
  `ferrogate_mia_unavailable` hint rather than falling back to anything weaker.

### In scope — admin tooling

- **CLI** — `bvault ferrogate list`, `bvault ferrogate approve <spiffe-id> --policy default --ttl 720h
  [--comment ...]`, `bvault ferrogate reject <spiffe-id> --reason ...`, `bvault ferrogate revoke <spiffe-id>`,
  `bvault ferrogate show <spiffe-id>`, `bvault ferrogate config ...`. Admin-gated identically to the GUI.
- **Admin GUI page** — `Settings → Auth → Machines`, reusing existing admin-page chrome (pagination, search,
  audit-style timeline) — no new components:
  - **Pending** — rows: short SPIFFE id, attestation summary (`ek_cert` prefix + `policy_id`), first-seen age,
    *Approve* / *Reject*. Approve modal requires picking the policy set (filtered to the operator's grant-able
    policies) + TTL + optional comment.
  - **Approved** — searchable; last-login, source IP, current token count, *Revoke*.
  - **History** — rejections, revocations, and bootstrap approvals as an audit-style timeline.
  - **Config** — a small panel to set/inspect the trust anchor (trust domain, audience, JWKS source + CMIS
    endpoint/pins or static JWKS, `accept_svid`, bootstrap knobs). Responsive per the GUI rules (no `max-w-*`
    on the container; `grid grid-cols-2 gap-3` forms; `min-w-0`/`truncate` on SPIFFE IDs and endpoints).
  - Add `{ value: "ferrogate", label: "FerroGate Machine Identity" }` to `MountsPage.tsx`'s `AUTH_TYPES`.

### Out of scope (explicit)

- **Issuing or rotating SVIDs.** That is FerroGate's job. BastionVault only verifies and authorizes.
- **TPM interaction in BastionVault.** All TPM work happens in the FerroGate MIA/CMIS. BastionVault never
  touches `/dev/tpmrm0`.
- **Self-service approval beyond the one-shot root bootstrap.** Every non-bootstrap machine requires an admin.
- **Mutating FerroGate state** (enrol/revoke hosts in FerroGate). Decommissioning a host is done in FerroGate;
  BastionVault honors the resulting CRL and additionally offers its own `revoke` for vault-scoped removal.
- **A FerroGate-less fallback.** This backend assumes a FerroGate fleet. Deployments without FerroGate use
  AppRole / Certificate auth instead; there is no home-grown host-fingerprint fallback (the superseded design).

## Workflow Diagrams

### Enrolment + approval

```
client (attested host)                       server                      admin
  │  bvault ferrogate login                    │                          │
  │   ├─ MIA → child token (aud = server)       │                          │
  │   ├─ build DPoP proof                       │                          │
  │   └─ POST auth/ferrogate/login              │                          │
  │ ───────────────────────────────────────────►│                          │
  │     verify_bound(token, jwks, dpop, …)      │                          │
  │     spiffe_id unknown → create pending      │                          │
  │              403 enrolment_pending          │                          │
  │ ◄───────────────────────────────────────────│   LIST machines          │
  │                                             │ ◄────────────────────────│
  │   (client retries / polls status)           │   approve <spiffe-id>    │
  │ ───────────────────────────────────────────►│ ◄────────────────────────│
  │              403 enrolment_pending          │   policies + ttl + note  │
  │ ◄───────────────────────────────────────────│                          │
  │  bvault ferrogate login (after approval)    │                          │
  │ ───────────────────────────────────────────►│                          │
  │              {client_token, lease, accessor}│                          │
  │ ◄───────────────────────────────────────────│                          │
```

### First-machine bootstrap (root auto-approve)

```
operator on attested host                     server
  │  (holds BastionVault root token)            │   approved_machine_count == 0
  │  bvault ferrogate login                     │
  │   token=<child>  +  X-Vault-Token: <root>   │
  │ ───────────────────────────────────────────►│
  │     verify_bound(...) ok                    │
  │     unknown spiffe_id + root + count==0      │
  │     → auto-approve (bootstrap_policies)      │
  │              {client_token, lease, accessor}│
  │ ◄───────────────────────────────────────────│
  │   (every later machine → normal pending)    │
```

## Phases

| # | Title | Notes |
|---|---|---|
| 1 ✅ | **Plugin skeleton + config + storage** | **Done.** `auth/ferrogate/` mount, `config` read/write, `MachineEntry` storage layout, admin `register`/`list`/`show`/`delete`/`approve`/`reject`/`revoke`. `login` stubbed `not_implemented`. Integration test covers the full admin lifecycle. (Audit-event emission deferred to land with `login` in Phase 3.) |
| 2 ✅ | **Verification core (static JWKS) + login** | **Done.** `ferro-child-verify::verify_bound` wired end-to-end against a `static_jwks` anchor (verifier vendored from FerroGate `releases/v0.13.2` under `third_party/`). Child-token + DPoP login mints a token for an approved machine; unknown → pending; audience + trust-domain enforced. DPoP read from `DPoP` header or `dpop` body field. Deterministic test mints a real composite-signed token. |
| 3 ✅ | **Enrolment state machine + bootstrap** | **Done.** First-seen → pending side effect, token-authenticated self-poll (`POST status`), admin approve/reject/revoke transitions, and the **root-token one-shot bootstrap** (`approved_count == 0` + root). `audit`-target log events on key transitions. Tests cover the bootstrap happy path, the second-machine-not-bootstrapped guard, and the status endpoint. (Self-poll is `POST status` with the token rather than `GET enrolment/{spiffe_id}` — a SPIFFE ID can't be a path segment, and presenting the token both identifies and authorizes the poll.) |
| 4 ✅ | **CMIS gRPC JWKS source** | **Done — plaintext + PQ-TLS both validated live.** `cmis_grpc` source calls `MachineIdentity/JWKS` with cache + stale-while-revalidate; pre-generated tonic stubs (no protoc in build); transport selectable plaintext / SPKI-pinned hybrid-PQ-TLS via `cmis_tls_enable`. PQ-TLS (`X25519MLKEM768`) validated end-to-end against the live CMIS 0.15.0 on `segdc1vds0005`. SDK vendored at v0.15.0. CRL enforcement applies to the SVID path → folded into Phase 7. |
| 5 ✅ | **Client CLI** | **Done (Unix).** `bvault ferrogate login|status|whoami` driving the MIA helper socket (CBOR framing mirrored from `mia::helper::proto`) + DPoP proof construction; `ferrogate_mia_unavailable` when the MIA is absent. DPoP proof proven against `ferro-child-verify::verify_dpop_proof`; CBOR wire round-trip test. Windows named-pipe deferred. |
| 6 ✅ | **Admin GUI page** | **Done.** `Machines (FerroGate)` admin page (route `/ferrogate`, sidebar nav) with Pending / Approved / History / Config tabs; approve/reject/revoke modals; enable-mount empty state; `AUTH_TYPES` entry. Seven Tauri commands (`ferrogate_read_config`/`write_config`/`list_machines`/`approve`/`reject`/`revoke`/`delete_machine`) + api.ts wrappers + types. Two vitest tests. |
| 7 ✅ | **Direct-SVID mode + hardening + docs** | **Done.** Opt-in `accept_svid` via `verify_unrevoked` (CRL-enforced, fail-closed); per-source-IP `login` rate limit; Prometheus counters (`bvault_ferrogate_login_total` / `_login_denied_total{reason}` / `_pending_total` / `_approved_total`); operator + threat-model guide at `docs/ferrogate-machine-auth.md`. Test covers the `accept_svid` gate + CRL-enforced SVID approve→mint. |
| 9 ✅ | **Unauthenticated machine self-enrolment** | **Done.** `POST auth/ferrogate/enroll` (unauth) records a `pending`, `self_enrolled` machine on a self-asserted SPIFFE ID for admin approval — never mints a token; existing records are returned unchanged. Gated by `self_enroll_enabled` + allow/block lists (source IP/CIDR or claimed id, block-list wins) + per-source-IP `self_enroll_rate_limit_per_min`. GUI Config toggle/list editors + queue badge; `bvault ferrogate enroll` CLI; `self_enroll_denied` metric reason. Four lib tests. |

## Open questions

- **Child token vs. direct SVID as the default.** Recommended default is child-token + DPoP (sender-constrained,
  short-lived, FerroGate's intended relying-party path). Direct-SVID is weaker (no per-request DPoP) and stays
  opt-in. Confirm no deployment needs SVID-direct as the *default*.
- **How BastionVault depends on the FerroGate verifier crates.** Path dependency on the sibling repo, a git
  dependency pinned to a tag, or vendoring the (deliberately copy-pasteable) verifier modules? Leaning
  git-pinned-by-tag so verifier upgrades are explicit and reviewable.
- **Multi-trust-domain.** v1 assumes a single FerroGate trust domain per mount. Operators with several FerroGate
  environments can mount `auth/ferrogate/` more than once with different configs. Is a single mount that holds
  multiple trust anchors worth it later?
- **SPIFFE ID ↔ BastionVault identity/entity.** Should an approved machine also materialize a row in the
  identity/entity system ([identity-groups.md](identity-groups.md)) so machine tokens can join identity groups,
  or is the per-machine policy set on the enrolment record sufficient for v1? Leaning: entity mapping is a
  follow-up phase.
- **Bootstrap without root (embedded edge case).** In embedded mode is there ever a need to bootstrap the first
  machine without a root token present? Current design says no — embedded operator is root locally.

## Acceptance criteria

- **Phase-level:** each phase ships green CI + at least one integration test covering the happy path and the
  unauthorized path.
- **Feature-level:**
  - A client on a FerroGate-attested host can `bvault ferrogate login`; an unknown machine is denied with
    `403 enrolment_pending` and appears in the admin *Pending* queue.
  - An admin can `approve` from CLI **or** GUI with a chosen policy set + TTL; the machine's next `login` returns
    a token whose policies match the approval.
  - The **first** machine, presenting a valid FerroGate token **and** a BastionVault root token while no machine
    is yet approved, is auto-approved with `bootstrap_policies`; the **second** machine in the same conditions is
    *not* auto-approved (goes to `pending`).
  - A token whose SPIFFE ID/`jti` is on FerroGate's CRL is rejected (`cmis_grpc` source); a captured child token
    presented **without** a valid DPoP proof is rejected.
  - An unattested host with no FerroGate MIA cannot obtain a token at any stage.
  - `revoke` immediately invalidates active tokens for that machine via the lease manager; the next `login`
    fails with `machine_revoked`.
  - The full flow works against an HA (Hiqlite) cluster.
