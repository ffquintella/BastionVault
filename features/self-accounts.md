# Feature: Self-Accounts — operator-registered accounts, picked at Connect (plugin)

## Summary

An operator registers **their own accounts** for resources — a login name plus
a password or SSH private key — and tags each one with the **resource types**
(and, optionally, the OS families and target hosts) it applies to. These are
**self-accounts**. A connection profile opts in by selecting the
**Self-account** credential source. When the operator presses **Connect** on
such a profile, the GUI shows a list of *that operator's* self-accounts that
match the resource's type, OS and the profile's protocol. The operator picks
one and the session opens with it. The operator never re-types the password,
the webview never receives it, and every release is audited server-side.

The feature ships as a **plugin**, `bastion-plugin-self-accounts` (WASM). The
plugin owns the account records, their CRUD API, the matching rules and the
management UI (a declarative surface). The host does not learn what a
self-account is. It gains one small, generic and reusable mechanism instead:
**credential providers**. A credential provider is a plugin that a connection
profile can name as its credential source, and that the Connect paths ask for
(1) the list of candidates the operator may pick from and (2) the credential
for the one picked. Self-accounts is the first provider. Anything else that
supplies credentials at connect time, such as a bridge to an external password
manager, would plug in the same way.

| | Default Resource Account ([S11](default-resource-account.md)) | Self-Accounts (this spec) |
|---|---|---|
| Records per operator | one login name per OS family | many accounts, each scoped by resource type |
| Holds a secret | no (optional Windows password only) | yes: password or SSH private key |
| Chosen at connect | no, resolved automatically | yes, the operator picks from a list |
| Where it lives | kernel identity module (`identity/default-account/…`) | a plugin, its own encrypted storage |
| Credential source kind | `default-account` | `provider` naming `self-accounts` |

`default-account` stays as it is. The two coexist: a resource can have one
profile of each.

Builds on [features/resource-connect.md](resource-connect.md) (S46),
[features/connect-only-access.md](connect-only-access.md) (S10),
[features/connect-mfa-and-fido2-ssh.md](connect-mfa-and-fido2-ssh.md) (S9),
[features/web-application-connect.md](web-application-connect.md) (S105),
[features/plugin-system.md](plugin-system.md) (S41),
[features/plugin-extensibility.md](plugin-extensibility.md) (S40) and
[features/plugin-app-extensions.md](plugin-app-extensions.md) (S39). Desktop
GUI only, like the rest of Resource Connect.

## Motivation

- **One account per OS is not enough.** Operators commonly hold several named
  accounts on the same class of target: `felipe` for daily work, `felipe-adm`
  for administration, `CORP\felipe.adm` for domain administration, and a
  personal account on each family of network appliance. `default-account`
  models exactly one login name per OS family and carries no secret for SSH.
- **Personal credentials have no good home today.** If the organisation does
  not manage an account through the LDAP engine or the SSH CA, the operator has
  two options. Storing it as a resource secret makes it shared: anyone with
  `read` on the resource can see it, and it is tied to one resource instead of
  a type. Typing it by hand means revealing and pasting, which is the path that
  connect-only access exists to remove, and it leaves no audit record of which
  account was used.
- **Attribution.** A named personal account makes target-side logs point at
  the real person, which shared resource credentials cannot do.
- **Why a plugin.**
  - **Policy choice.** Some organisations forbid operators from keeping
    personal credentials in the vault (every privileged account must be
    managed and rotated). Shipping this as a plugin makes it opt-in by
    installation, and an administrator decides by registering and granting it.
  - **Smaller trusted computing base.** Deployments that do not install it
    carry no self-account code, storage or routes.
  - **The mechanism is reusable.** The host work is a generic
    credential-provider extension point, not "self-accounts in the core".
    This mirrors the precedent of plugin notification channels, where a
    plugin declares `notification_channels` in its manifest and the
    notifications engine calls it through `PluginHost`
    ([crates/bv-kernel-api/src/engines.rs:223](../crates/bv-kernel-api/src/engines.rs:223)).
  - **Independent release cadence**, as with the XCA importer
    ([features/xca-import.md](xca-import.md), S63).

## Current State

**Status: In progress (2026-10-07). All five phases are implemented apart from the items listed under each: the host substrate (1), the plugin (2), Connect integration on the server (3) and in the GUI and desktop host (4), and hardening and UX (5: the first-use badge, preselection of the account last used on the target, per-user counts for administrators, an audited and retried entity purge, and the operator guide `docs/self-accounts.md`). The feature stays in progress until the review gate closes: the L4 `make test-release` run, the manual per-platform checks against real SSH / RDP / web / Rustion targets (none run yet), and the security-review sign-off.**

| Phase | Status |
|---|---|
| Phase 0 — verification spike | Partly answered (see the phase) |
| Phase 1 — host substrate: caller identity, entity storage scope, credential providers | Done except the items listed under the phase |
| Phase 2 — the `bastion-plugin-self-accounts` plugin | Done except the items listed under the phase |
| Phase 3 — Connect integration, server side | Done except the items listed under the phase |
| Phase 4 — Connect integration, GUI and Tauri host | Done except the items listed under the phase |
| Phase 5 — hardening and UX follow-ups | Done except the items listed under the phase |

### Context this feature builds on (verified 2026-10-05)

- **The plugin envelope carries no caller identity.** `build_envelope`
  ([src/plugins/logical_backend.rs](../src/plugins/logical_backend.rs)) sends
  only `{op, path, data}`. A plugin therefore cannot tell users apart today, so
  per-user data in a plugin needs a host change (Phase 1).
- **Plugin storage is one scope per plugin name**, at
  `core/plugins/<name>/data/…`
  ([src/plugins/catalog.rs:15](../src/plugins/catalog.rs:15)). The host
  rebases every key and rejects `..`.
- **The host ABI is at 1.2** (`HOST_ABI_MINOR = 2`,
  [crates/bv-plugin-manifest/src/lib.rs:454](../crates/bv-plugin-manifest/src/lib.rs:454)).
  Version 1.2 added notifications.
- **`PluginHost` is the engines' view of the plugin runtime**
  ([crates/bv-kernel-api/src/engines.rs:223](../crates/bv-kernel-api/src/engines.rs:223)).
  It has `notification_channels()` and `invoke(plugin, input)`, and it is the
  natural place for the provider contract.
- **Credential sources are a closed union** on the GUI side (`CredentialSource`
  in [gui/src/lib/types.ts](../gui/src/lib/types.ts)). They are
  matched by string in the Tauri host (`resolve_ssh_credential` /
  `resolve_rdp_credential` in
  [gui/src-tauri/src/commands/connect.rs](../gui/src-tauri/src/commands/connect.rs),
  and the `v2_resolvable` set at
  [connect.rs:133](../gui/src-tauri/src/commands/connect.rs:133)), and on the
  server for web form logins (`WebCredentialSource` in
  [crates/bv-engine-resource/src/connect_web/profile.rs](../crates/bv-engine-resource/src/connect_web/profile.rs)).
- **The direct path's pre-flight is `resources/v2/connect/authorize`**
  (`handle_connect_authorize`,
  [crates/bv-engine-resource/src/connect_mfa.rs:737](../crates/bv-engine-resource/src/connect_mfa.rs:737)).
  It burns the MFA ticket for gated profiles and is the one server round trip
  every direct SSH/RDP launch makes.
- **Older GUIs do not check `credential_source.kind`.** `isKnownProfile`
  ([gui/src/lib/connectionProfiles.ts](../gui/src/lib/connectionProfiles.ts))
  checked only that the field is an object, so an older client would show a
  `provider` profile as launchable. Phase 0 settles what that client then does;
  Phase 4 hardened this build (a known `kind` is required).
- **The declarative surface form renders a small subset** of JSON Schema:
  `string`/`integer`/`boolean`, `format: "password"` (masked), `format:
  "textarea"` (not masked) and a single-select `enum`
  ([gui/src/components/surface/SurfaceForm.tsx:7](../gui/src/components/surface/SurfaceForm.tsx:7)).
  It has no multi-select, no masked multi-line field and no host-supplied
  option lists. The management UI needs all three (Phase 1, §7).
- **No "self-account" concept exists anywhere in the tree today.** The name is
  free.

## Scope

### In scope

- **Per-operator account records**: a label, a login name, an optional
  domain, a secret kind (`password` or `ssh-key`), the secret itself, an
  optional TOTP seed (web `form` logins, off unless an administrator enables
  it) and an **applicability** block (resource types, optional OS families,
  optional protocols, optional target patterns).
- **Self-service management by the owner only.** Secrets are **write-only**:
  no HTTP read returns them, not even to the owner. The owner can replace them
  or delete the account.
- **A Connect-time picker** for SSH, RDP and web `form` profiles, on both the
  `direct` and the `rustion` transports.
- **Server-side audit** of every release, plus plugin audit events for CRUD.
- **Administrator controls** through the plugin's config: allowed secret
  kinds, whether TOTP seeds are allowed, a per-user account cap, the MFA
  requirement and the target-pattern requirement. An administrator can purge
  one user's data (offboarding) but cannot read it.
- **Lifecycle**: deleting an identity entity purges its plugin data.
- **The generic host substrate** that the plugin needs, specified so that a
  second credential provider needs no new host code.

### Out of scope (explicit)

- **Sharing self-accounts between operators.** Shared credentials are resource
  secrets, LDAP static roles or LDAP library sets.
- **Rotation by the vault.** BastionVault does not manage the target account.
  It stores what the owner typed.
- **Reveal or copy.** There is no path that returns a self-account's secret to
  a person. This is deliberate (see *Security Considerations*).
- **Use outside Connect** (for example, exposing self-accounts to MCP clients
  or to other plugins).
- **Web `http-auth` and `sso` modes.** They follow S105 Phases 3 and 7 and can
  adopt the `provider` source when they land.
- **A dedicated CLI.** The plugin's paths are ordinary logical paths, so
  `bvault write self-accounts/v2/accounts …` works through the generic
  commands.
- **Migration from `default-account`.** The two features coexist. Folding
  `default-account` into a provider is listed under *Alternatives considered*.
- **Admin visibility into other users' account metadata.** Decided in Phase 5
  (*Open questions* 2): administrators see per-user counts only.

## Design

### 1. Components

```
 React GUI                 Tauri host (Rust)                Server
 ─────────                 ─────────────────                ──────
 Connect ──► profile ──► connect_provider_candidates ──► resources/v2/connect/provider/candidates
             │                                                  │  (connect grant, profile check,
             ▼                                                  │   target from stored metadata)
       host-rendered  ◄── metadata only ◄───────────────────────┘          │
       account picker                                                      ▼
             │ account_id                                   PluginHost::provider_candidates
             ▼                                                             │
       (MFA step-up when the profile requires it)                          ▼
             │                                              bastion-plugin-self-accounts
             ▼                                              (WASM, entity-scoped storage)
 session_open_{ssh,rdp,web}{…, provider_account_id}                        ▲
             │                                                             │
             ├─ direct ──► resources/v2/connect/authorize ──► PluginHost::provider_release
             ├─ rustion ─► rustion/v2/session/open ─────────► (server seals it; host never holds it)
             └─ web ─────► resources/v2/connect/web/launch ──► (Rust host fills; JS never holds it)
```

| Component | Owns | Where |
|---|---|---|
| `bastion-plugin-self-accounts` | records, CRUD, matching, release, surface | `plugins-ext/bastion-plugin-self-accounts` (WASM) |
| Plugin substrate (generic) | ABI 1.3 caller block, `entity` storage scope, `credential_provider` manifest block, its grant, provider ops, entity purge | `crates/bv-plugin-manifest`, `src/plugins/`, `crates/bastion-plugin-sdk`, `crates/bastion-plugin-testkit` |
| Kernel contract | `PluginHost` provider methods, entity purge call | `crates/bv-kernel-api/src/engines.rs` |
| Resource engine | the `provider` source, candidates endpoint, release on authorize / web launch | `crates/bv-engine-resource` |
| Rustion engine | release on `rustion/v2/session/open` | `crates/bv-engine-rustion` |
| GUI and Tauri host | profile editor option, picker, command plumbing | `gui/src/`, `gui/src-tauri/src/commands/` |

### 2. Plugin data model

Every key is relative to the plugin's storage scope. With `storage_scope =
"entity"` (§4) the host places that scope at
`core/plugins/self-accounts/data/entity/<entity_id>/`, so the plugin never
writes an entity id into a key and cannot address another user's records.

```text
accounts/<id>/meta    -> AccountMeta   (JSON, never contains secret material)
accounts/<id>/secret  -> AccountSecret (JSON)
```

Metadata and secret are separate keys so that listing, candidate matching and
reads never deserialise secret material.

```jsonc
// AccountMeta, version 1
{
  "v": 1,
  "id": "sa_5k2q…",               // 128 random bits, base32; plugin-generated
  "label": "Domain admin",        // ≤ 64 chars, shown in the picker
  "username": "felipe.adm",       // ≤ 256 chars, required
  "domain": "CORP",               // optional; RDP and web
  "secret_kind": "password",      // "password" | "ssh-key"
  "has_totp": false,
  "applies_to": {
    "resource_types": ["server"],         // ≥ 1, ids from resources/config/types
    "os_types": ["windows"],              // optional; only types that carry os_type
    "protocols": ["rdp"],                 // optional; default = all compatible
    "targets": ["*.corp.example.com", "10.20.0.0/16"]   // optional, see §5
  },
  "description": "",              // optional, ≤ 512 chars
  "created_at": "2026-10-05T12:00:00Z",
  "updated_at": "2026-10-05T12:00:00Z",
  "last_used_at": null
}

// AccountSecret, version 1
{ "v": 1, "kind": "password", "password": "…", "totp_seed": "…" }
{ "v": 1, "kind": "ssh-key",  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----…" }
```

**Compatibility of secret kind and protocol.** The plugin applies these rules
when it matches candidates, and the host checks them again on what the plugin
releases.

| `secret_kind` | `ssh` | `rdp` | `web` (`form`) |
|---|---|---|---|
| `password` | password auth | NLA password | username + password (+ TOTP when `has_totp`) |
| `ssh-key` | public-key auth | ✗ | ✗ |

**Limits** (validated on write; the plugin rejects oversize input with a
`400`-class error): label ≤ 64, username ≤ 256, domain ≤ 256, description ≤
512, password ≤ 1 KiB, private key ≤ 16 KiB, at most 32 entries in each
`applies_to` list, and at most `max_accounts_per_user` records (config, default
25). An `ssh-key` secret is parsed on write (OpenSSH or PKCS#8 PEM, with the
`ssh-key` crate, which builds for `wasm32`). Phase 2 accepts only unencrypted
keys, because the barrier is the at-rest protection. Passphrase-protected keys
follow if Phase 0 confirms the SSH session path can take a passphrase.

**Versioning.** Both records carry `v`. Readers accept every version up to the
current one and writers always write the current one, following the
repository's read-old / write-new rule.

### 3. Plugin API

The plugin is mounted with `type = "plugin:self-accounts"`, at
`self-accounts/` by convention. All paths are `v2/`. **No path names a user or
an entity**: the host-attested caller (§4) decides whose records a request
touches.

| Path (under the mount) | Op | Behaviour |
|---|---|---|
| `v2/accounts` | `list` | The caller's accounts, metadata only. |
| `v2/accounts` | `write` | Create. Body: metadata fields plus the secret fields. Returns `id`. |
| `v2/accounts/<id>` | `read` | Metadata plus `has_secret` and `has_totp`. **Never** returns the secret. |
| `v2/accounts/<id>` | `write` | Update. Secret fields are **write-preserve**: an absent or empty `password` / `private_key` keeps the stored one. Changing `secret_kind` requires the new secret in the same write. |
| `v2/accounts/<id>/totp` | `delete` | Clears the TOTP seed. This is a separate path because a form cannot express "clear" with write-preserve semantics. |
| `v2/accounts/<id>` | `delete` | Deletes both keys. |
| `v2/settings` | `read` | The effective administrator settings (allowed kinds, TOTP allowed, cap, target rule). The management UI uses them to shape its forms. Contains no secrets. |

A request whose caller has no identity entity (for example, a root token
without an entity) is refused by the host with `403` before the plugin runs
(§4). Self-accounts belong to entities, not to tokens.

**Plugin config** (`config_schema`, set by an administrator under Plugins):

| Key | Kind | Default | Meaning |
|---|---|---|---|
| `allow_ssh_keys` | bool | `true` | Accept `secret_kind = "ssh-key"`. |
| `allow_totp_seeds` | bool | `false` | Accept a TOTP seed next to a password. Off by default: storing both collapses two factors into one record. |
| `max_accounts_per_user` | int | `25` | Cap per entity. |
| `require_connect_mfa` | bool | `true` | Refuse a release unless the host attests that a connect-time MFA ticket was redeemed for this launch (§4, `connect.mfa_verified`). |
| `require_targets` | select `web` / `all` | `web` | Which protocols require a non-empty `applies_to.targets` (§5). |
| `allowed_resource_types` | string (comma list) | empty = all | Restrict which resource types accounts may be tagged with. |

### 4. Host substrate: credential providers (generic)

This is the part that turns "a plugin with storage" into "a plugin Connect can
ask for credentials". None of it mentions self-accounts.

#### 4.1 Manifest

```toml
name = "self-accounts"
runtime = "wasm"
abi_version = "1.3"

[capabilities]
audit_emit = true
log_emit = true
caller_identity = true          # new: the host adds a `caller` block to every envelope
storage_scope = "entity"        # new: "plugin" (default, today's behaviour) | "entity"

[capabilities.credential_provider]   # new
display_name = "Self-account"        # what the profile editor shows
selection = "operator"               # the operator picks among candidates
protocols = ["ssh", "rdp", "web"]
secret_kinds = ["password", "ssh-key"]
```

- Each new key is a **capability**. The existing capability-widening guard
  (plugin-system Phase 5.9) therefore applies: a new version cannot add any of
  them without a delete and re-register.
- `selection = "operator"` is the only value this spec defines. Manifest
  validation rejects anything else, so a future automatic-selection provider
  needs its own spec rather than an accidental default.
- `storage_scope = "entity"` requires `caller_identity = true`. Validation
  rejects the combination without it.
- `credential_provider` requires `storage_scope = "entity"` in this version.
  Every candidate list is per-operator, and a provider with global storage
  would have to implement user separation itself, which is exactly what the
  host scope exists to take away.

#### 4.2 ABI 1.3: the `caller` block

When a plugin declares `caller_identity`, the host adds a block that it builds
from the request's token. The plugin cannot influence it.

```jsonc
{
  "op": "read",
  "path": "v2/accounts",
  "data": {},
  "caller": {
    "entity_id": "4f0c…",
    "display_name": "userpass-felipe",
    "principal": { "mount": "userpass/", "name": "felipe" },
    "namespace": ""
  }
}
```

The block never carries the token, its accessor or its policies. Plugins that
do not declare the capability receive exactly today's envelope, and
`HOST_ABI_MINOR` moves from 2 to 3.

#### 4.3 `entity` storage scope

For a plugin with `storage_scope = "entity"`, the host sets the storage prefix
of **each invocation** to `core/plugins/<name>/data/entity/<entity_id>/`,
taking the entity id from the attested caller. The existing prefix enforcement
and `..` rejection then confine every `bv.storage_*` call to that one entity.
Even a buggy or hostile plugin build cannot read or write another user's keys,
because the boundary is the host's rebasing, not the plugin's code.

An invocation with no caller entity is refused before the plugin runs, with
`403` and the message *"this plugin stores per-user data and needs an
identity-backed login"*.

#### 4.4 Provider operations

Two new envelope ops exist **only on the provider bridge**.
`build_envelope` maps the closed `Operation` enum (`read` / `write` / …) and
has no way to produce them, so **no HTTP request can invoke them**.

```jsonc
// host → plugin
{ "op": "provider.candidates",
  "caller": { … },
  "data": {
    "protocol": "rdp",                    // ssh | rdp | web
    "resource": { "type": "server", "os_type": "windows" },
    "target": { "host": "dc01.corp.example.com", "port": 3389 }   // web: { "origin": "https://…" }
  } }
// plugin → host
{ "data": { "candidates": [
    { "id": "sa_5k2q…", "label": "Domain admin", "username": "felipe.adm",
      "domain": "CORP", "secret_kind": "password", "has_totp": false,
      "last_used_at": "2026-10-01T09:12:00Z" } ] } }

// host → plugin
{ "op": "provider.release",
  "caller": { … },
  "data": {
    "account_id": "sa_5k2q…",
    "protocol": "rdp",
    "resource": { "type": "server", "os_type": "windows" },
    "target": { "host": "dc01.corp.example.com", "port": 3389 },
    "needs": { "password": true, "totp": false },   // web: what the recipe fills
    "connect": { "mfa_verified": true, "transport": "direct" }
  } }
// plugin → host
{ "data": { "username": "felipe.adm", "domain": "CORP",
            "secret": { "kind": "password", "password": "…" } } }
```

- The resource **name is not sent**. The plugin needs the type, the OS and the
  target to match, and nothing else (data minimisation).
- `release` re-runs the same matching as `candidates`. A stale or forged
  `account_id` that does not match this resource, protocol and target is
  refused. The plugin updates `last_used_at` on success.
- The plugin returns only what `needs` asks for. A web recipe that fills no
  TOTP gets no TOTP seed back.
- **The host never trusts the shape of the plugin's output.** It checks that
  the secret kind is in the provider's declared `secret_kinds` and compatible
  with the protocol, that the username is non-empty, and that every field is
  within the §2 size limits. It fails closed with an operator-facing error
  otherwise.

#### 4.5 The provider grant

Like network access (`src/plugins/grants.rs`), a credential provider is
**double-gated**:

1. The manifest declares `[capabilities.credential_provider]`.
2. An administrator approves it at
   `PUT v2/sys/plugins/<name>/grants/credential-provider`. The record is
   stored at `core/plugins/engine/grants/<name>/credential-provider`, a new
   key that leaves the existing network grant record's format untouched. It is
   pinned by the SHA-256 of the manifest's `credential_provider` block, so any
   change to that block, even a narrowing one, voids the grant until it is
   re-approved. Grants and revocations are audited.

Until the grant exists, the profile editor does not offer the provider, and
both the candidates and the release paths refuse with *"credential provider
`self-accounts` is not approved on this server"*. The Plugins page gets a
**Credential provider** consent panel next to the existing **Network access**
panel. The route is `v2/` because `sys/plugins/*` grants today are `v1`, and
v1 is frozen.

#### 4.6 Kernel contract

`PluginHost` ([crates/bv-kernel-api/src/engines.rs:223](../crates/bv-kernel-api/src/engines.rs:223))
gains these methods, implemented in the facade (`src/plugins/provider.rs`):

```rust
/// Granted, active credential providers. A catalog read failure yields an
/// empty list, mirroring `notification_channels`.
async fn credential_providers(&self) -> Vec<CredentialProviderDecl>;
async fn provider_candidates(&self, provider: &str, caller: &CallerIdentity,
                             query: &ProviderQuery) -> Result<Vec<ProviderCandidate>, RvError>;
async fn provider_release(&self, provider: &str, caller: &CallerIdentity,
                          req: &ProviderReleaseRequest) -> Result<ReleasedCredential, RvError>;
/// Deletes `core/plugins/<p>/data/entity/<entity_id>/` for every plugin with
/// `storage_scope = "entity"`. Called when an identity entity is deleted.
async fn purge_entity_data(&self, entity_id: &str) -> Result<(), RvError>;
```

`ReleasedCredential` holds its secret in `Zeroizing` buffers and does not
implement `Debug` for the secret fields. Editing `bv-kernel-api` rebuilds
every engine (26 of 41 packages, see AGENTS.md §3), so the trait change lands
once, in Phase 1, and nothing in Phases 2–4 touches it again.

#### 4.7 Entity lifecycle

- **Delete.** When the identity module deletes an entity, it calls
  `purge_entity_data`. A purge failure is logged at `ERROR` and audited, but
  it does not block the entity delete. A retry runs on the next plugin-runtime
  tidy pass, recorded as a pending-purge marker. (As built, Phase 0 and
  Phase 5: the trigger is the removal of the entity's last alias, and the
  retry runs on the next automatic purge and on every administrator purge;
  there is no plugin-runtime tidy pass.)
- **Administrator purge.** `DELETE v2/sys/plugins/<name>/entity-data/<entity_id>`
  (granted by the `plugin-admin` policy) is used for offboarding and for the
  merge case below. It is audited. Its only read counterpart is the per-user
  *count* (`GET v2/sys/plugins/<name>/entity-data`, Phase 5).
- **Merge.** See *Open questions*. Until that is decided, data under a
  merged-away entity id is retained and reachable only by the purge route.

### 5. Target binding: why accounts carry `targets`

Anyone who can edit a resource can point it at any host or origin and give it
a self-account profile. Without a binding, an operator who picks their
"Domain admin" account on a malicious `web_application` resource whose URL is
`https://evil.example` would hand their domain password to that host. Matching
by resource type alone cannot stop this, because the attacker chooses the type
too.

So each account can carry `applies_to.targets`:

- **SSH / RDP**: DNS patterns (`dc01.corp.example.com`, `*.corp.example.com`;
  a wildcard only as the whole left-most label) and IP CIDRs (`10.20.0.0/16`).
  They are matched against the **resolved dial target**: the profile's
  `target_host` override, else the resource's hostname or IP, computed
  server-side from stored metadata. The request never supplies it.
- **Web**: exact origins (`https://grafana.corp.example.com`) or
  `https://*.corp.example.com`. They are matched against every origin the
  profile's recipe may fill: the start URL's origin and the
  `allowed_origins` list. All of them must match, because the fill routine may
  run on any allowed origin.
- `require_targets` (config, default `web`) makes `targets` mandatory for
  those protocols. An account without targets is then never a candidate for
  them. With `require_targets = all`, SSH and RDP need targets too.
- The picker shows the target next to the list (§6). Phase 5 adds a
  "first use on this target" badge, a hint on top of the binding, never a
  replacement for it.

The plugin does the matching, because it owns the patterns. The host supplies
the target and is the only party that computes it.

### 6. Connect flow and the picker

1. The operator presses **Connect**, and the usual profile choice happens
   (the default profile, or the profile picker).
2. If the profile's `credential_source.kind` is `provider`, the GUI calls the
   Tauri command `connect_provider_candidates(resource_name, profile_id)`. The
   Rust host calls `POST resources/v2/connect/provider/candidates`, which:
   - requires the `connect` grant on the resource, as `connect/authorize` does;
   - loads the stored profile and checks that its source names a granted
     provider that supports the profile's protocol;
   - builds `resource` and `target` from stored metadata;
   - calls `PluginHost::provider_candidates` and returns **metadata only**.
3. The GUI shows a **host-rendered** `ProviderAccountPicker` modal. It lists
   the label, `DOMAIN\username`, a kind badge (password / key), a TOTP badge
   and the last-used time, with the target ("Connecting to
   `dc01.corp.example.com:3389`") in the header. A single candidate is
   preselected; arrow keys and Enter work, as they do in `ConnectPalette`.
   - **Empty list**: *"You have no self-accounts for `server` (Windows) on
     this target."* with an **Add a self-account** link to the plugin's
     surface page. Connect stays disabled.
4. If the profile has `require_mfa`, the existing step-up runs now, after the
   pick, so cancelling the picker costs no factor ceremony.
5. The GUI calls `session_open_ssh` / `session_open_rdp` / `session_open_web`
   with the new optional field `provider_account_id`. The release then
   happens in exactly one place for each route:
   - **direct SSH / RDP**: `POST resources/v2/connect/authorize` gains
     `provider_account_id`. For a `provider` profile the field is required,
     and the response gains a `credential` object. That object is consumed by
     the Rust host only and dropped when the session closes. The MFA ticket is
     burnt in the same call, so release and gate are one step.
   - **Rustion**: `rustion/v2/session/open` gains `provider_account_id`. The
     server releases the credential and seals it into the bastion envelope,
     like the `secret` source on that path. The GUI host never holds it, so
     `provider` joins the `v2_resolvable` set.
   - **web `form`**: `resources/v2/connect/web/launch` gains
     `provider_account_id`. `WebCredentialSource` gains `Provider { provider
     }`. The server releases, and the Rust host fills as it does for the
     other sources.
6. The profile's own `username` is ignored for `provider` profiles. The
   released username is authoritative, as with `default-account`, and the
   editor hides the field.

The picker is host code on purpose. A plugin-drawn picker inside the Connect
flow could imitate host chrome. The host renders only metadata that it
received and validated (see the plugin-app-extensions threat table).

### 7. Management UI: a plugin surface

The plugin ships a declarative surface (Extensibility v1). It needs no app
module and no custom code in the webview.

- **Menu**: *My accounts* (key icon) in the `secrets` section.
- **Page**: a `table` bound to `{mount}/v2/accounts` (`list`), with columns
  for label, username, kind, resource types, targets and last used, and row
  actions *Edit* and *Delete* (`{mount}/v2/accounts/{id}`).
- **Forms**: two forms, *Add password account* and *Add SSH-key account*, so
  that no conditional fields are needed. The password form gets an optional
  TOTP field only when `v2/settings` reports `allow_totp_seeds`.

Phase 1 adds three **generic** keywords to the `SurfaceForm` subset, each
useful to any plugin:

| Addition | Renders as | Why |
|---|---|---|
| `type: "array"` with `items.enum` | multi-select | resource types, OS types, protocols |
| `format: "secret-textarea"` | masked multi-line input that never echoes into the DOM after save | private keys |
| `x-bv-options: "resource-types" \| "os-types"` | options filled by the host from the list the Resources page already reads (`resources/config/types`) | the plugin cannot read other mounts, and should not have to |

Fields for secrets submit write-preserve: an empty value on edit means
"keep".

The **My Profile** page (features/self-service-profile.md) gets a link to *My
accounts* when the provider is active and granted. It shows nothing else.

### 8. Policy

- **Plugin paths.** Ship a policy template, `self-accounts-user`, in the
  plugin's docs. It grants `create/read/update/delete/list` on
  `self-accounts/v2/accounts` and `self-accounts/v2/accounts/*`, plus `read`
  on `self-accounts/v2/settings`. Granting it broadly is safe, because the
  entity scope (§4.3) isolates users and not because of the path. It is
  **not** added to `default` automatically: installing a plugin must not
  silently widen a built-in policy. The administrator attaches it to
  `default` or to groups. This follows the reasoning in
  features/self-service-profile.md about mount-relative paths in built-in
  policies.
- **Connect.** `resources/v2/connect/provider/candidates` (`update`) is added
  to the baseline policies wherever `resources/v2/connect/authorize` is
  already granted (`crates/bv-kernel/src/modules/policy/policy_store.rs`, the
  same place as the web form-mode endpoints).
- **Administration.** `v2/sys/plugins/*/grants/credential-provider` and
  `v2/sys/plugins/*/entity-data/*` go to `plugin-admin`.

### 9. Audit and metrics

- **Server, per release**: `connect.provider.release` with `principal`,
  `entity_id`, `resource`, `profile_id`, `protocol`, `transport`,
  `provider`, `account_id`, `login_name` and `outcome`. The account id is an
  opaque random value, and the login name is not a secret: target-side
  attribution is the point. **No secret, no TOTP code.** `session.open` also
  records `credential_source = provider` and `provider`.
- **Server, per refusal**: the same event with `outcome = denied` and a
  reason (`no_entity`, `not_granted`, `no_match`, `mfa_required`,
  `bad_provider_output`).
- **Plugin** (`audit_emit`): `self-accounts.account.created` / `.updated` /
  `.deleted`, carrying `id`, `secret_kind`, `applies_to` and, on update, which
  fields changed (`secret_changed: true`, never the value).
- **Metrics**: `bvault_plugin_provider_requests_total{plugin, op, protocol,
  outcome}` beside the existing per-plugin families.

### 10. Compatibility and migration

- **New data only.** No existing record changes shape. Plugin records are
  versioned (§2).
- **Connection profiles.** `credential_source = {"kind": "provider",
  "provider": "self-accounts"}` is a new value in an existing field. Resource
  metadata treats profiles as opaque JSON, so the server stores it unchanged.
  An older GUI reads it as known (see *Current State*), so Phase 0 must
  confirm two things: that the older editor round-trips the profile without
  rewriting `credential_source`, and that the older host's launch fails closed
  with a clear "unsupported credential source" error. If either fails, fix
  `isKnownProfile` to require a known `kind` (in the T102 style) and ship that
  fix **before** the first release that can create `provider` profiles.
- **ABI.** Plugins declaring `abi_version = "1.3"` are refused by older hosts
  through the existing major/minor check. Existing plugins see no change.
- **Backups.** BVBK full backups include `core/plugins/<name>/data/`, so
  self-account secrets are in them, encrypted like the rest of the barrier.
  Phase 0 confirms whether `.bvx` exchange exports can include plugin data.
  If they can, entity-scoped plugin data is excluded unless explicitly
  selected.
- **HA.** This is ordinary barrier storage, so hiqlite replication applies
  unchanged.

## API surface (all `v2`)

| Path | Op | Who | Phase |
|---|---|---|---|
| `self-accounts/v2/accounts` | list, write | the owner (entity-scoped) | 2 |
| `self-accounts/v2/accounts/<id>` | read, write, delete | the owner | 2 |
| `self-accounts/v2/accounts/<id>/totp` | delete | the owner | 2 |
| `self-accounts/v2/settings` | read | the owner | 2 |
| `resources/v2/connect/provider/candidates` | update | `connect` grant on the resource | 3 |
| `resources/v2/connect/providers` | read | baseline policies (names and declarations only) | 4 |
| `resources/v2/connect/authorize` | update, new field `provider_account_id`, new response field `credential` | unchanged | 3 |
| `resources/v2/connect/web/launch` | update, new field `provider_account_id` | unchanged | 3 |
| `rustion/v2/session/open` | update, new field `provider_account_id` | unchanged | 3 |
| `v2/sys/plugins/<name>/grants/credential-provider` | read, write, delete | `plugin-admin` | 1 |
| `v2/sys/plugins/<name>/entity-data/<entity_id>` | delete | `plugin-admin` | 1 |
| `v2/sys/plugins/<name>/entity-data` | read (counts only) | `plugin-admin` | 5 |

Tauri commands: `connect_provider_candidates` and `connect_credential_providers`
(new); `session_open_ssh`, `session_open_rdp` and `session_open_web` gain
`provider_account_id`. Phase 5: `plugins_entity_data_usage` and
`plugins_purge_entity_data` (embedded, and remote pinned to `/v2`).
Document all of it in `docs/api.md`, and the plugin in its own README under
`plugins-ext/`.

## Phases

### Phase 0 — verification spike — **Partly answered (2026-10-07)**

Answer the questions this spec defers, and record the answers here:

- How older clients treat a `provider` profile (§10).
- Whether `.bvx` exchange exports include plugin data (§10).
- Where entity deletion happens, to place the purge call.
- Whether the SSH session path accepts passphrase-protected keys (§2).
- Whether `resources/config/types` is readable by every operator who can
  connect.

**Answers so far** (read from the code; none of them run):

- **Older clients.** `isKnownProfile` accepts any object as `credential_source`,
  so an older GUI lists a `provider` profile as launchable. The older Tauri host
  then fails closed in `resolve_ssh_credential` with *"unknown credential source"*
  (`gui/src-tauri/src/commands/connect.rs`, the `other =>` arm), which is the
  behaviour §10 asks for. Read again for Phase 4 (from the code, not run):
  against a Phase 3 server the older host never gets that far on the direct
  path — its `connect/authorize` call carries no `provider_account_id`, and the
  server refuses with `invalid_request: provider_account_id is required for a
  provider profile …` before any ticket is redeemed or anything released; the
  older GUI shows that text in its toast. It has already run the MFA ceremony
  by then (it gates before opening), so a gated profile costs that operator a
  factor prompt, not a ticket. The older RDP arm says *"credential source
  `provider` lands in a later phase"* (reached only against a pre-Phase 3
  server); the older web host refuses the profile before anything with
  *"credential source `provider` cannot sign in a `form` login"*. The older
  editor keeps an unknown `credential_source` as long as its source select is
  not touched (its `validateProfile` returns `undefined` for the kind, which
  does not block Save); changing the select replaces it. This build hardens
  `isKnownProfile` (Phase 4): a profile whose source kind it does not know is
  hidden, kept byte-for-byte on every write, and counted in a notice on the
  Connection tab.
- **`.bvx` exports.** `src/exchange/` and `src/backup/` reference no
  `core/plugins/` key, so exchange exports do not carry plugin data. BVBK full
  backups copy the barrier and do include it, as §10 says.
- **Entity deletion.** There is none. `EntityStore` has no delete: the entity
  record is kept on purpose (share and owner records point at it), and deleting
  a principal only calls `IdentityService::forget_alias`. §4.7's "when the
  identity module deletes an entity" therefore had no hook. The purge now runs
  when `forget_alias` removes an entity's **last** alias, since a recreated
  principal gets a new entity and the old data could never be reached again.
- **Passphrase-protected SSH keys.** The direct SSH path accepts one
  (`SshCredential::PrivateKey { pem, passphrase }`). The Rustion path refuses it,
  because the bastion envelope has no passphrase channel
  (`connect.rs`, the `rustion-required` check). Phase 2 stays with unencrypted
  keys; passphrases would be direct-only.
- **`resources/config/types` readability.** Not determined. No baseline policy
  mentions the path, so who may read it depends on the operator's own policies.
  The `x-bv-options` option list reads it through the GUI's existing
  `resource_types_read`, and falls back to the built-in types if that fails.

### Phase 1 — host substrate — **Done except the items below (2026-10-07)**

- Manifest: `caller_identity`, `storage_scope`, `[capabilities.credential_provider]`,
  with validation and the widening guard. `HOST_ABI_MINOR = 3`.
- Envelope `caller` block, entity storage rebasing, the no-entity refusal.
- Provider ops on the bridge only, and the `PluginHost` methods (§4.6).
- The credential-provider grant, its consent panel, and the purge route and
  hook.
- SDK: a `CredentialProvider` trait with typed request and response, a
  `Caller` type, and a `provider_module!` macro. Testkit: drive the
  `provider.*` ops and entity scoping.
- `SurfaceForm`: the three generic additions (§7).

**Where the implementation differs from §4, and what is left:**

- The grant is stored under `core/plugins/engine/provider-grants/<name>`, not
  `grants/<name>/credential-provider`: a key and a directory of the same name
  cannot coexist on the file backend, and the network grant keeps its record.
- `storage_scope = "entity"` is accepted for `runtime = "wasm"` only. The
  process runtimes have their own storage path and were not given the rebasing.
- A granted provider that is also quarantined is treated as not approved.
- The consent panel and the three grant commands exist (embedded and remote);
  the remote calls pin `/v2` because the route is not on the v1 scope.
- **Not done:** the audit event and the pending-purge retry marker for a failed
  entity purge (done in Phase 5); the
  `plugin-admin` policy entries (no such policy exists in the tree, so the new
  `v2/sys/plugins/*` routes are covered only by the default deny); and a test
  that drives `forget_alias` through a real plugin host. (The
  `bvault_plugin_provider_requests_total` metric listed here landed with
  Phase 3.)
- **Not run:** the `provider` SDK feature was only built and tested on the host.
  The `wasm32-wasip1` target is not installed here, so its `no_std` build is
  unverified.

### Phase 2 — the plugin — **Done except the items below (2026-10-07)**

`plugins-ext/bastion-plugin-self-accounts`: the data model, CRUD, the
matching rules (type, OS, protocol, targets), config, the surface, the
signed `.bvplugin`, and testkit-driven tests.

Tested at four levels: handlers against the SDK's host stubs (29), the shipped
`plugin.toml` and `surface.json` as artefacts (6), the compiled wasm in the
testkit's mirror of the host (7), and the compiled wasm in the **real** host
(`engine_tests::self_accounts_host`, 4, `#[ignore]`d until the wasm is built;
`make plugins-test` does both). The last level is the one that proves the
testkit's mirror has not drifted from `PluginCtx`: entity prefixes, the 403 for
a token with no entity, the grant gate, the shape check on a release, and the
purge when a principal's last alias goes.

**Where the implementation differs from the spec, and what is left:**

- **Built for `wasm32-unknown-unknown`, not `wasm32-wasip1`.** The host links
  only the `bv` import module. A `wasip1` build imports
  `wasi_snapshot_preview1` (`environ_get`, `fd_write`, `proc_exit`) and fails to
  instantiate with *unknown import*. `plugins-wasm` and `plugins-test` build
  this plugin for `PLUGINS_WASM_TARGET`, which is now `wasm32-unknown-unknown`
  for every reference wasm plugin (an earlier draft of this note named a
  separate `PLUGINS_NOWASI_TARGET`, which does not exist). **The `wasip1`
  builds of the other reference plugins imported the same four functions.** The `totp` build made
  here fails to instantiate in the testkit (which mirrors the host's linker)
  with the same *unknown import*; the real host was not run against it.
- **`list` returns `data.entries`, not `data.keys`**, because the management
  table prefers `keys` and would render bare ids.
- **The management page cannot edit an account**, only add and delete: a
  surface row action cannot open a form. Editing is `write v2/accounts/<id>`.
  The password form always carries a TOTP field (a static surface cannot hide
  it); the plugin refuses a seed with a clear message unless allowed.
- **Form fields are flat** (`resource_types`, `targets`, …) rather than a nested
  `applies_to`, because that is what a surface form submits. `targets` is one
  comma- or newline-separated text field.
- **OpenSSH keys only.** A PKCS#8 PEM is refused with a precise message; the SSH
  session reads the OpenSSH form.
- **A write that stores an account which can never be offered** (no `https://`
  origin for web, or no host target under `require_targets = all`) succeeds
  with a `warnings` entry instead of failing.
- **Not done:** the signed `.bvplugin` carries no surface, because
  `bv-plugin-pack` cannot embed `surface.json` yet. Registering it needs a
  `[surface]` table (`schema_version`, `sha256`, `size`) in `plugin.toml`
  before packing and signing, plus `surface_b64` on `POST /v1/sys/plugins`:
  the register handler ignores `surface_b64` when the manifest declares no
  surface, and the GUI's Register dialog never sends it (found while writing
  the Phase 5 operator guide); the plugin was not signed or registered through the GUI by
  hand; `plugin.toml` and the host test's `manifest()` are two copies of one
  manifest (the plugin's own test checks the file, the host test mirrors it);
  and the SDK gained `Host::random_bytes` and `test_support::enable_storage`,
  which are new public API of `bastion-plugin-sdk`.

### Phase 3 — Connect integration, server — **Done except the items below (2026-10-07)**

The `provider` source in `bv-engine-resource` (candidates endpoint, release on
`authorize` and `web/launch`) and in `bv-engine-rustion` (`session/open`).
Target computation from stored metadata, audit, metrics and baseline policy
grants.

What landed:

- `POST resources/v2/connect/provider/candidates` (`connect_provider.rs`). Reads
  `resource` and `profile_id` from the body and nothing else; checks the
  `connect` grant, loads the stored profile, requires a `provider` source naming
  a live, granted provider that declares the profile's protocol, builds the
  query from the stored record, and returns metadata only (`candidates`, the
  `target`, `resource_type`, `os_type`, `display_name`).
- `authorize` (direct SSH / RDP): `provider_account_id`, release after the
  ticket, `credential` in the response. `web/launch` (`form`):
  `WebCredentialSource::Provider`, `provider_account_id`, the release in the
  launch bundle. `rustion/v2/session/open`: the `provider` source, released and
  sealed server-side. Every pre-check that can fail without the provider runs
  before the MFA ticket is redeemed on all three routes; the provider is told
  `mfa_verified = true` only when a ticket was redeemed for that very call.
- The host bridge maps the SDK's statuses to `404 no_match`, `403
  mfa_required`, `400 bad_request` and `500 provider_error`, never echoing the
  plugin's text, and a failed shape check to `502 bad_provider_output`. Every
  provider-path error starts with a stable reason code (`<reason>: …`).
- `connect.provider.release` and `connect.provider.candidates` audit lines, the
  `bvault_plugin_provider_requests_total` metric, and the candidates endpoint in
  the baseline policies (`default`, `shared-access`, the namespace baseline,
  `administrator`).
- Tests: pure ones in `bv-kernel-api` (target rule, caller attestation, reason
  codes, audit line), `bv-engine-resource` (profile parsing, needs, the bundle
  credential, the `credential` object), `bv-engine-rustion` (envelope kinds,
  encrypted-key refusal) and the facade (status mapping, metric export); and
  `engine_tests::self_accounts_connect`, four tests against the real wasm through
  the full pipeline (`#[ignore]`d like `self_accounts_host`, run by `make
  plugins-test`). They assert that the released password appears in no audit
  device entry, captured log line, refusal text or candidates response.

**Where the implementation differs from §4–§9, and why:**

- **The dial target is the desktop host's first candidate**: the profile's
  `target_host`, else the resource's `ip_address`, else its `hostname`
  (`profile_host_candidates` puts the IP before the name). §5 said "hostname or
  IP". It is normalised the way `recipe::origin_key` normalises an origin's
  host: ASCII only, lower-cased, no trailing dot, no `*`, `%`, `[`, `]`,
  userinfo, path or surrounding whitespace, and a `:` only when the whole value
  is an IPv6 address, so the provider matches exactly one spelling of one
  host. So a resource with both set is matched on its IP, and an account bound
  only by DNS pattern does not match it. Only that one host is bound: the
  `authorize` response carries `target`, and **Phase 4 must dial exactly it**,
  with no fallback to another host candidate — otherwise a resource whose IP
  matches and whose hostname is hostile would receive the credential on a
  network-layer fallback.
- **`authorize` refuses to release when the transport policy forbids a direct
  session** (`rustion-required` or a lock violation, `403 transport_policy`).
  Not in the spec, but without it *Where it stops*'s advice to route these
  profiles through Rustion would not hold against a client that calls
  `authorize` directly.
- **`rustion/v2/session/open` pins the envelope's target.** The request's
  `target_host` / `target_port` / `target_protocol` must equal the stored target
  (or be omitted) and are overwritten with it; `credential_material` with a
  `provider` source is refused; the request's `credential_source.provider` must
  equal the stored profile's. The envelope kind is `ssh-password`, `ssh-key` or
  `rdp-password`; RDP has no password-domain field on the wire, so a domain
  travels as `DOMAIN\user`, and SSH ignores it.
- **Web**: `http-auth` refuses a `provider` source (§ *Out of scope*);
  `credential_source.totp` is read as for `secret`; a TOTP code from a provider
  seed is computed once at launch and `connect/web/totp` offers no refresh for it
  (the seed is not kept server-side); heuristic recipes never ask the provider
  for a TOTP (asking for one the account lacks is refused); the domain is not a
  web fill.
- **Shared rules live in `bv-kernel-api::provider`**, not in either engine:
  `CallerIdentity::from_request` (the facade's `caller_from_request` now
  delegates to it), the reason codes, `host_target`, `provider_resource`,
  `profile_provider` and the `ProviderAudit` line. The `PluginHost` trait itself
  is unchanged.
- **Audit lines are `target: "audit"` log lines** next to `connect.web.*`, not
  audit-broker entries. Reasons beyond §9's list: `unsupported_protocol`,
  `bad_request`, `provider_error`, `invalid_profile`, `invalid_request`,
  `connect_denied`, `transport_policy`. A refused connect grant on `authorize`
  writes no `connect.provider.release` line: the profile cannot be read before
  the grant, so the call is not known to be a provider launch (the pipeline's
  own audit entry records it).
- **The metric counts calls that reach the host bridge.** A refusal an engine
  makes first (no entity, provider not live) is in the audit line only. A
  provider name that is not in the catalog is counted as `plugin="unregistered"`.

**AppRole identity fix (found in the Phase 3 review).** `CallerIdentity` takes
`entity_id` and `username` from the token metadata, and an AppRole token's
metadata started as a copy of the secret-id's caller-supplied `metadata`, with
`entity_id` overwritten only when entity resolution succeeded and `username`
never. Whoever could create a secret-id could name another person's entity and
release their accounts. Secret-id creation now refuses every reserved key
(`bv_logical::is_reserved_token_meta_key`) and login drops any a stored
secret-id still carries (`engine_tests::approle_reserved_meta`). Tokens issued
before the fix keep their metadata until they expire or are revoked.

**Audit-pipeline check.** The `authorize` response now carries a secret. The
request pipeline builds its audit-device entry with `log_raw = false` hard-coded
(`bv-core` `handle_log_phase`), and `bv-audit` HMACs every string in the
response body, nested objects included, so `credential.secret.password` reaches
a device as `hmac:<hex>`. No change was needed; `self_accounts_connect` asserts
it.

**Known limits left from the Phase 3 review (not fixed):**

- On `rustion/v2/session/open` the MFA ticket is redeemed, and the release is
  audited `outcome=success` (stamping `last_used_at`), before a bastion is
  chosen. With no bastion available the caller sees a 502/503 after a
  "successful" release. The fix is to check bastion availability before the MFA
  gate.
- A forged or stale `provider_account_id` costs the caller an MFA ticket
  (`no_match` is reported after the redeem; a test asserts this). Checking the
  id against `provider_candidates` before redeeming would avoid it.

**Not done:**

- The GUI and Tauri host (Phase 4), including the direct-path `session.open`
  line with `credential_source = provider`, which the desktop host writes.
  (Done in Phase 4.)
- `tests/test_self_accounts_connect.rs` with a signed fixture plugin (§ Testing
  Plan): the engine test covers the same flow in-process with an unsigned
  registration.
- `make test-release` (L4), which the review gate requires before merge.
- AppRole `login_renew` still looks the role up by `metadata["username"]`, which
  an AppRole token never carries legitimately, so renewal never applies the
  role's current TTLs. Pre-existing and left alone; with reserved keys stripped
  at login it can no longer be pointed at another role.

### Phase 4 — Connect integration, GUI and Tauri host — **Done except the items below (2026-10-07)**

- `CredentialSource` gains `{ kind: "provider"; provider: string }`.
- The profile editor offers each granted provider by its `display_name`
  (*Self-account (pick at connect)*).
- Update the `connectionProfiles.ts` helpers: `validateProfile`,
  `isLaunchableProfile`, `isLaunchableForCaller` and `needsOperatorPrompt`.
- Build `ProviderAccountPicker`, `connect_provider_candidates`, and the
  `provider` arms in `resolve_ssh_credential` / `resolve_rdp_credential` and
  in the web launcher.
- **Dial exactly the `target` that `connect/authorize` returns** for a
  provider profile, and never fall back to another host candidate
  (`profile_host_candidates`) on a network-layer error: the credential is
  released for that one host (Phase 3, *Where the implementation differs*).

What landed:

- **GUI** (`gui/src/`): `CredentialSource` `provider` (with the optional
  `totp` parameters the server reads for a web `form` source); the
  `connectionProfiles.ts` helpers and `webFormProfile.ts` checks for it;
  `components/ProviderAccountPicker.tsx` (the picker and
  `useProviderAccountPicker`); `lib/connectFlow.ts` (`connectProfile`, the one
  sequence picker → MFA → open that the Connection tab, the card
  quick-Connect, the ⌘K palette and a Session Workspace layout restore all
  use); `components/ProviderSourceFields.tsx` (the editor's provider options
  and notice); `lib/credentialProviders.ts` (pure helpers, refusal-code
  wording, the provider page route); `hooks/useCredentialProviders.ts`; the
  *Accounts for Connect* link card on My Profile.
- **Desktop host** (`gui/src-tauri/src/commands/connect_provider.rs`):
  `connect_credential_providers`, `connect_provider_candidates`, the direct
  release (`authorize_provider_direct`), `DialPlan` / `dial_in_order`, which the
  SSH and RDP open paths now share. `session_open_ssh` / `_rdp` / `_web` take
  `provider_account_id`; `provider` joins the `v2_resolvable` set (SSH) and the
  RDP v2 route; the web launcher sends the id to `connect/web/launch`.
- **Server**: `GET resources/v2/connect/providers` (see below) and its
  baseline-policy `read` rule; the SSH login-class rule on every provider
  route (see *Review fixes*).
- **Tests**: vitest — `credentialProviders.test.ts` (helpers, the hardened
  `isKnownProfile` and the unknown-source round trip, web-form checks),
  `providerAccountPicker.test.tsx` (rendering, empty state, preselection,
  keyboard, hostile strings as text, and the call order candidates → picker →
  MFA → open, with a cancelled picker never reaching MFA),
  `providerResources.test.tsx` (the card quick-Connect, the editor's offer and
  filtering, the Connection-tab notice and a save keeping an unknown profile).
  Rust — `commands::connect_provider::tests` (target pinning with a fake
  dialler, the redacted `Debug`, a missing or malformed `provider_account_id`,
  release/candidate parsing, hostile display strings), the web profile parser,
  the window ACL; `bv-engine-resource` (`providers_listing`), `bv-kernel`
  (`the_baselines_grant_the_provider_listing_read_only`), the facade
  (`gate_tests::the_provider_listing_is_a_baseline_read` over HTTP, and the
  listing before and after a revoked grant in the `#[ignore]`d
  `self_accounts_connect` test).

**Where the implementation differs from the spec, and why:**

- **The provider list is `GET resources/v2/connect/providers`**, a logical path
  on the resource engine, not a `v2/sys/…` route. The editor needs the list
  in both the embedded and the remote mode; a logical path goes through the
  same pipeline (token, ACL, namespace rewrite) in both, needs no actix
  surface, and its baseline rule sits next to the other Connect endpoints'.
  It returns names and declarations only.
- **The candidate list is fetched before the picker opens.** A refusal
  (`not_granted`, `no_entity`, …) is an error toast with operator text, not an
  empty modal.
- **The host withholds candidates it cannot show as text**: a label, login or
  domain carrying control or invisible formatting characters (bidi overrides,
  zero-width), an id with whitespace, a key for RDP, an unknown kind, a
  duplicate id, anything past 256. The picker says how many were withheld.
  Only one candidate is preselected, and only when it is the only one; with
  several, Connect stays disabled until the operator picks.
- **The *Add a self-account* link exists only in the main window** (Resources
  page and its ⌘K palette). The Session Workspace shows no plugin pages, so its
  picker states the empty case without a link. The route is the provider's
  own registered surface page under `/plugin/<provider>/`, else no link.
- **A connect-only caller may launch a provider profile on the direct path.**
  Connect-only protects the resource's stored secrets, which this source never
  reads; what reaches the desktop is the operator's own account, behind the
  `connect` grant and (by default) MFA — the boundary *Where it stops*
  describes.
- **A brokered SSH resource refuses a provider profile**: every SSH login to
  such a resource must be minted by the SSH engine, and a provider account is a
  static credential. The editor does not offer the source there; the desktop
  host settles the login class before *either* route (direct or Rustion); and
  the server refuses it on every provider route — candidates, `authorize` and
  `rustion/v2/session/open` — with `403 brokered_requires_ssh_engine`, before
  any MFA ticket is redeemed, audited as `outcome=denied`. RDP and web are not
  governed by the SSH login class and still release on a brokered resource.
- **The direct path never re-routes a released credential.** After
  `authorize` the host does not consult the Rustion policy again (the v2 route
  already took any bastion route, and the server refuses a direct release under
  `rustion-required`), so the credential cannot be handed to the v1
  `rustion/session/open`.
- **RDP**: the released `domain` goes in the CredSSP domain slot; a login of
  the form `DOMAIN\user` / `user@realm` with no separate domain is split like
  every other source's.
- **Audit**: the SSH direct `session.open` line gains
  `credential_source=provider provider=… account_id=… login_name=…`; the RDP
  direct path had no `session.open` line, and gets one for provider launches
  only; the web form line adds `provider` and `account_id`.
- **Unknown profiles are announced**: the Connection tab says how many
  profiles use a protocol or credential source this version cannot read.
- **No sign-in re-run for a provider web session.** The toolbar's *Re-run
  login* is unavailable, with the reason shown, for a `form` session that
  signed in with a provider account: the provider releases again only after a
  fresh connect-time MFA check, which the toolbar cannot run (its webview is
  granted three commands, none a factor ceremony). Sent anyway, every re-run
  would fail with `mfa_required` and leave a denied audit line. Disconnecting
  and connecting again runs the picker and the check. Chosen over running the
  MFA gate from the toolbar because it widens nothing.

**Review fixes (2026-10-07).** An independent review of the Phase 4 diff found
four issues, all fixed:

1. *Brokered resources could still get a provider credential* on the Rustion
   route: the host settled the SSH login class only on its direct branch,
   after the bastion route, and no server route checked it. Now the host
   settles it before either route, and the resource and Rustion engines refuse
   a provider account for SSH on a brokered resource
   (`bv_kernel_api::provider::require_not_brokered_for`, reason
   `brokered_requires_ssh_engine`), on the candidates endpoint as well.
   `engine_tests::self_accounts_connect::a_brokered_resource_never_releases_an_account_for_ssh`
   covers both release routes, the candidates refusal, the unspent tickets, the
   audit lines and RDP on the same brokered resource.
2. *The released login and domain* end up in the session label and window
   title, so they are now held to the picker's plain-text rule; a release
   whose login or domain carries a bidi override or an invisible character is
   refused (no secret in the refusal).
3. *The invisible-character rule* is now by category: every `Cc` and `Cf`
   code point, `Zl` / `Zp`, and every other `Default_Ignorable_Code_Point`
   (variation selectors, the combining grapheme joiner, Hangul and Khmer
   fillers, tags, the reserved ignorable ranges), from the Unicode 16.0
   tables, with a test per code point class.
4. *The web sign-in re-run* is unavailable for provider sessions (above).

**Not done:**

- **Not run against real targets.** No SSH, RDP or web session was opened with
  a released account; the manual checks under *Testing Plan* (SSH password, SSH
  key, RDP with a domain account, web `form` with a TOTP seed, Rustion SSH) are
  outstanding, on every platform. The GUI was not driven in the desktop app
  either: the picker and editor were checked through vitest only.
- `make test-release` (L4), which the review gate requires before merge.
- A Rustion-routed provider session's window label shows the profile's (empty)
  username: the released login is known only server-side on that route.
- The direct RDP path still writes no `session.open` line for the other
  credential sources (pre-existing).
- An older GUI facing a provider profile sees the server's
  `invalid_request: provider_account_id is required …` (see Phase 0). Wording it
  as *"this app is too old for this profile"* would need a server change.
- The released secret is moved out of the response map, but the HTTP client's
  own read buffer (remote mode) is not under the host's control; the same holds
  for the web launch bundle.

### Phase 5 — hardening and UX — **Done except the items below (2026-10-07)**

- A "first use on this target" badge (the plugin keeps a per-account set of
  target hashes).
- Preselect the account last used on this resource.
- Per-user account counts on the admin Plugins page (counts only, never
  metadata).
- The operator guide.

What landed:

- **The seen-target record** (`plugins-ext/bastion-plugin-self-accounts/src/seen.rs`).
  Per account, a separate key `accounts/<id>/seen` (so `meta` and the listing
  stay small and secret-free) holding `{v: 1, targets: [{h, at}]}`: at most 64
  entries, each a lowercase-hex SHA-256 and the unix-ms time of the last
  release there; past 64 the least recently used entry is evicted. The digest
  is domain-separated (`bastionvault/self-accounts/seen-target/v1`) and
  length-framed over the target kind and its canonical form: for SSH / RDP the
  dial host the host computed (trimmed, no trailing dot, lower case; **no
  port**, and SSH and RDP share the kind, because the credential reaches the
  same machine either way), for web the sorted, de-duplicated origin set
  (lower case, no trailing `/`, `:443` dropped). Never the target text. A
  record from a newer plugin is left untouched; an unreadable one reads as
  empty and is replaced on the next release. The account's delete removes it.
- **Recording**: only in `provider.release`, after every check passed (match,
  MFA, the TOTP request, the secret), next to the `last_used_at` stamp; never
  in `provider.candidates`, never for a refused release. Bookkeeping failures
  are logged and never fail a launch. The release response is unchanged.
- **Candidates** carry `first_use_on_target` (`true` when the record has no
  entry for this target; an unreadable record errs toward `true`) and
  `last_used_on_target` (RFC 3339, the time only). Both are additive and
  serde-defaulted in `bv-kernel-api::provider::ProviderCandidate` (`false` /
  absent from a provider that predates them) and the SDK's `Candidate`, which
  now derives `Default` so a provider can write `..Default::default()`. The
  host bridge and the resource engine pass them through unchanged; the
  desktop host types them (a non-boolean flag withholds the candidate, a time
  that does not parse is dropped) like `has_totp` and `last_used_at`.
- **The picker** (`ProviderAccountPicker.tsx`, `credentialProviders.ts`)
  shows a warning badge *First use on this host* (web: *on this site*) on
  each such account and, while the selected account is a first use, the line
  *You have not used this account on this host before. Check that <target> is
  where you mean to sign in.* It preselects the candidate with the most recent
  `last_used_on_target`, else a single candidate, else none; the list keeps
  the provider's (label) order, and arrows and Enter are unchanged.
- **Why the preselection is server-side**: the record lives in the plugin's
  entity scope rather than in the desktop's `localStorage`, because
  `localStorage` is per device and not replicated — the history would not
  follow the operator to another desktop, and a Rustion-routed or remote
  session could not contribute to it. It also keeps the plugin from learning
  the resource *name* (§4.4): the plugin keys the history by the target it is
  already told, so "last used on this resource" is, as built, "last used on
  this target".
- **Per-user counts**: `GET v2/sys/plugins/<name>/entity-data` (actix,
  `crates/bv-server/src/sys.rs`; logic in `src/plugins/entity_data.rs`). For a
  registered plugin with `storage_scope = "entity"` it lists
  `core/plugins/<name>/data/entity/` and, per entity, counts the
  `accounts/<id>/` directories that hold a `meta` key — **listing only, no
  value is read and the plugin is not invoked** (a unit test fails on any
  `get`). An entity holding other data is listed with `0` so it can still be
  purged; an emptied directory the file backend keeps is not data.
  `display_name` is the entity's primary name (else its first alias name)
  from `IdentityService::entity_profile`. The response also counts pending
  purges. ACL path `sys/plugins/<name>/entity-data`, `read`, audited like the
  other sys reads, `404` for any other plugin, v2 only. Tauri:
  `plugins_entity_data_usage` / `plugins_purge_entity_data` (embedded:
  in-process with a sys audit entry; remote: pinned to `/v2`). The Plugins
  page shows a *Per-user data* button on entity-scoped plugins: totals, a
  table of user / entity id / record count, a *Delete* per user behind a
  confirm dialog (the existing purge route), and a notice when purges are
  pending.
- **The failed-purge audit and retry marker** (Phase 1 leftover). The
  automatic purge (`PluginHost::purge_entity_data`, called when an entity
  loses its last alias) now goes through `entity_data::purge_orphaned_entity`:
  every purge is audited at `sys/plugins/entity-data/<entity_id>` (`delete`,
  `trigger` = `last-alias-removed` | `pending-purge-retry`, `outcome` =
  `purged` | `failed`, the error on failure). A failure writes
  `core/plugins/engine/pending-purges/<entity_id>` (`v`, `entity_id`,
  first/last failure time, attempt count; no plugin data) and returns the
  error, which the identity module logs without undoing the principal delete.
  Markers are retried, at most 16 per pass, by the next automatic purge and by
  every administrator `DELETE …/entity-data/<entity_id>` (server and
  embedded). This is the smallest mechanism that needs no new scheduler: the
  plugin runtime has no tidy pass, and both retry points already run with the
  barrier unsealed. A retry purges without re-checking the identity store,
  because a marker is written only for an entity the identity module found
  with no alias left and the store never re-attaches an alias to an existing
  entity (a recreated principal gets a new entity).
- **Plugin names in entity-data paths are checked.** `runtime::entity_data_root`
  now also refuses an empty plugin name or one carrying `/`, `\` or `..`: the
  administrator purge takes the name from the request path and interpolates it
  into a storage prefix (before, only the entity id was checked). The counts
  route additionally requires the stored manifest's name to equal the
  requested one.
- **Operator guide**: `docs/self-accounts.md`, linked from the docs sidebar
  and `docs/administration.md`.
- Tests: the plugin's host-stub suite (+7: the flag flips only after a
  successful release and never after a refused one, candidates never write,
  `seen` holds digests only and never sits in `meta` or the listing, the cap
  and eviction through the handler, origin sets in any order, delete removes
  the record, a newer record is not downgraded) and `seen` unit tests (+5:
  canonicalisation, domain separation, framing, cap, version handling); the
  testkit e2e (`seen` is per entity and a refused release records nothing);
  the real-host tests (`self_accounts_connect`: the flag before and after a
  release through `authorize`; `self_accounts_host`: no marker after a
  successful purge, and the counts after it); `plugins::entity_data` (counting
  by listing only, markers created / bumped / cleared, an automatic purge
  retrying an earlier failure, counts with names, and the HTTP route:
  admin-only, counts only against stored values that would show if read,
  `404`, v2 only); `bv-kernel-api` and the SDK (old and new candidate shapes);
  the desktop host's candidate parser; vitest for the badge, the caution,
  preselection and order, the helpers and the *Per-user data* panel.

**Where the implementation differs, and why:**

- **"Last used on this resource" is "last used on this target".** The plugin
  never learns the resource name (§4.4), so two resources with the same dial
  host share their history. Accepted: the badge's question is "has this
  credential gone to this host before", which is exactly that.
- **The counts route is generic over entity-scoped plugins but counts the
  provider record layout** (`accounts/<id>/meta`), now a documented
  convention of the provider contract rather than self-accounts knowledge in
  the host. A plugin with another layout gets its entities listed with `0`.
- **First use is recorded when the plugin releases**, so a release the host
  then refuses (bad output shape), a Rustion open that then finds no bastion,
  or a session that fails to open still counts as used.

**Not done:**

- GUI row-edit of accounts, PKCS#8 / passphrase keys and packer surface
  embedding stay the documented limits of Phases 2 and 4.
- `tests/test_self_accounts_connect.rs` with a signed fixture (skipped as
  optional; the `#[ignore]`d engine tests run by `make plugins-test` cover the
  same flow in-process).
- The `plugin-admin` policy still does not exist; the new `GET` route, like
  the other `v2/sys/plugins/*` routes, is reachable by root, the built-in
  `administrator` policy (`path "*"`) and policies
  granting `sys/plugins/*` explicitly.
- Not run against real targets, not driven in the desktop app, and no L4
  `make test-release` (the review gate).

## Dependencies

- Plugin system Phases 1–5 (S41), Extensibility v1 surfaces (S40) and the
  grant machinery from Extensibility v2 (S39). All of them are done.
- Resource Connect (S46), connect-time MFA (S9) and Web Application Connect
  Phase 2 `form` mode (S105). For web support, Phase 3 of this spec waits on
  S105 Phase 2 being merged.
- Rustion integration for the brokered route. If it is not ready, the
  `rustion` arm can follow Phase 3 without blocking the direct and web
  routes.

## Security Considerations

| Threat | Mitigation |
|---|---|
| One operator reads or uses another operator's accounts | Paths carry no user id. The caller is attested by the host from the token (§4.2). Storage is rebased per entity by the host, so the plugin's code is not the boundary (§4.3). A caller with no entity is refused. |
| A stolen session token exfiltrates personal passwords | There is no read path for secrets, not even for the owner. A release happens only through Connect, and each release requires the `connect` grant on a resource whose stored profile names the provider and whose type, OS, protocol and target match the account. It also requires MFA when `require_connect_mfa` is set (the default), and it is audited. On the `rustion` route the secret never leaves the server. |
| A malicious resource definition harvests credentials (attacker-controlled host or origin) | `targets` binding, matched against the target computed server-side from stored metadata. It is mandatory for web by default and can be made mandatory everywhere (§5). The picker shows the target. Web keeps S105's exact-origin, HTTPS-only and top-frame fill rules. |
| A forged or stale `account_id` | `release` re-matches the account against this resource, protocol and target. The host re-validates the shape of the plugin's output (§4.4). |
| The webview or an XSS in the GUI reads secrets | The candidates response holds metadata only. Release goes to the Rust host (direct and web) or stays server-side (rustion). No Tauri command returns secret material to JS. |
| A malicious or tampered plugin | ML-DSA-65 signature checked at registration and on every load. A double-gated provider grant pinned to the manifest block's hash. The capability-widening guard. A WASM sandbox. The self-accounts manifest declares **no** network capability, so a compromised build has no egress. The consent panel warns when a provider also requests network access. |
| The provider learns more than it needs | It receives no resource name, token, accessor or policy list, and no target beyond the one being dialled (§4.4). |
| Secret at rest | Barrier encryption, as for every vault record. No plugin-level crypto layer is added: Transit envelope encryption through `bv.crypto_*` was considered and rejected, because the plugin would hold the unwrap authority anyway, so it adds key management without a new boundary, and the scheme stays the barrier's vetted one (AGENTS.md §7). |
| Secrets in memory and logs | `Zeroizing` buffers in the host and in the SDK's release type, and no `Debug` on secret fields. The plugin's `log_emit` goes through an SDK helper that refuses secret-typed values. Tests assert that released bytes appear in no log or audit output. |
| TOTP seed stored with the password | Off by default (`allow_totp_seeds = false`). When enabled, the settings page states that the account is then one factor. |
| Resource exhaustion | A per-user cap, field size limits, and the existing per-invoke fuel and time limits. |
| Silent downgrade | None: an ungranted, inactive or quarantined provider fails every launch with an explicit error. There is no fallback to another credential source. |

**Where it stops.** An operator who holds the `connect` grant on a resource can
release their *own* credential for it to their own desktop through
`connect/authorize`, outside the GUI. That is the same boundary
connect-only access documents for the direct path. Here it exposes only a
credential the operator typed in themselves. Organisations that need the
secret never to reach the endpoint should route these profiles through
Rustion.

**Review gate.** This touches authentication, the plugin ABI, a persisted
format and secret handling. Run `make test-release` (L4) before merging any
phase, and route the Phase 1 and Phase 3 diffs through a security review.

## Testing Plan

### Host (Rust unit)

- The `caller` block is present only for plugins with `caller_identity`, and
  it is built from the token, never from the request body.
- An HTTP request cannot produce `provider.*` ops (envelope builder test over
  every `Operation`).
- Entity rebasing: two entities writing the same key see their own values. A
  key containing `..` is rejected. A no-entity caller gets `403` and the
  plugin is not invoked.
- Manifest validation: `entity` without `caller_identity`, a provider without
  `entity`, an unknown `selection`, and the widening guard.
- Grants: hash pinning, voiding on a narrowed block, refusal before a grant
  exists, and audit records.
- Validation of the plugin's output: a wrong kind, an incompatible protocol,
  an empty username and oversize fields all fail closed.
- Entity purge removes only that entity's prefix, across every entity-scoped
  plugin.

### Plugin (testkit)

- CRUD round-trip. `read` and `list` never contain secret bytes (asserted on
  the raw response).
- Write-preserve on update, the TOTP clear path, and a `secret_kind` change
  that requires a new secret.
- Matching: type, OS, protocol, targets (DNS wildcard rules, CIDR, origins,
  all-origins-must-match), and `require_targets`.
- `release` refuses a non-matching id, a missing `mfa_verified` when MFA is
  required, and an unrequested TOTP.
- Malformed input: oversize fields, an invalid key PEM, an unknown kind,
  `v` greater than the current version, and over-cap creates.
- Version migration: a v1 record is read and rewritten as the current
  version.

### Resource and Rustion engines

- The candidates endpoint requires the `connect` grant and refuses a profile
  whose source is not `provider`. `type`, `os_type` and `target` come from
  stored metadata even when the request body supplies them.
- `authorize` for a `provider` profile requires `provider_account_id`, burns
  the MFA ticket before releasing, and returns `credential` only for that
  source.
- `web/launch` and `rustion/v2/session/open` resolve the provider source.
- A regression test that the audit lines and logs contain no released
  password or key bytes.

### Frontend (vitest)

- Picker rendering, the empty state, single-candidate preselection and
  keyboard flow.
- `connectionProfiles` helpers for the `provider` kind, the profile editor
  offering only granted providers, and an older-profile round-trip (§10).
- The `SurfaceForm` additions: multi-select, masked textarea, host-supplied
  options.

### Integration and manual

- `tests/test_self_accounts_connect.rs`: a signed fixture plugin, end to end
  through `candidates` and `authorize`.
- Manual checks per platform: SSH with a password, SSH with a key, RDP with a
  domain account, web `form` with a TOTP seed, and Rustion SSH.

## Tracking

| Item | Where |
|---|---|
| Task | T103 in `ROADMAP.md` under M5 (Resources) |
| Spec row | S107 in `ROADMAP.md` `## Specs` |
| Changelog | One `CHANGELOG.md` entry per phase as it lands, referencing `(T103, S107)` |

## Alternatives considered

- **Build it into the core as an engine (`bv-engine-self-accounts`).**
  Simpler wiring, and no ABI work. Rejected: it forces the feature on every
  deployment, grows the trusted computing base, and leaves the next
  connect-time credential provider to repeat the work.
- **A hard-coded `self-account` credential kind.** Rejected: the Connect code
  would then know about one plugin by name, and every future provider would
  add a kind to the four places that match on it (GUI types, the Tauri host,
  the web profile parser and the Rustion path). The profile editor still
  shows *Self-account*, through the provider's `display_name`.
- **Extending `default-account` to hold many accounts with secrets.**
  Rejected: it would turn a name-only kernel record into a secret store keyed
  by principal rather than entity, and it would remain in the core.
  `default-account` could later be re-expressed as a built-in provider, which
  is a separate decision.
- **KV under a per-user path with templated policies.** Rejected: KV values
  are readable (no write-only secrets), have no applicability model, and the
  Connect paths would still need KV-specific code.
- **A plugin-drawn picker (an app-module window).** Rejected because of the
  spoofing risk explained in §6.
- **Storing accounts on the operator's machine (OS keychain).** Rejected: the
  accounts would be per-device, not replicated or audited, and not usable by
  the Rustion route.

## Open questions

1. **Entity merge.** Should a merge move the merged-away entity's records to
   the surviving entity? Moving credentials between identities on an
   operator's mistake is dangerous. **Decided (Phase 5): no.** Records under a
   merged-away entity are retained, never moved, and reachable only by the
   administrator purge; the per-user counts list them so the administrator
   can find and purge them. (No merge operation exists in the identity store
   today, so nothing triggers this yet.)
2. **Administrator visibility.** Should an administrator be able to list
   another user's account *metadata* (labels, usernames, targets) for audit?
   **Decided (Phase 5): no — counts only.** `GET v2/sys/plugins/<name>/entity-data`
   returns per-entity record counts and the entity's identity name, by
   listing keys; it reads no value and never invokes the plugin. Which
   account was used where is already in the server's `connect.provider.*`
   audit lines (account id and login name), so the audit need is met without
   a metadata read path.
3. **Profile-side narrowing.** Should a profile be able to restrict which
   accounts qualify (for example, a `username_pattern` such as `*-adm`)?
4. **Defaults.** Is `require_connect_mfa = true` the right default for every
   deployment, or should it follow the profile's `require_mfa`?
