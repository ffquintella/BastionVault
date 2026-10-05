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

**Status: Planned. Spec only (2026-10-05); nothing is implemented.**

| Phase | Status |
|---|---|
| Phase 0 — verification spike | Todo |
| Phase 1 — host substrate: caller identity, entity storage scope, credential providers | Todo |
| Phase 2 — the `bastion-plugin-self-accounts` plugin | Todo |
| Phase 3 — Connect integration, server side | Todo |
| Phase 4 — Connect integration, GUI and Tauri host | Todo |
| Phase 5 — hardening and UX follow-ups | Todo |

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
  ([gui/src/lib/connectionProfiles.ts:114](../gui/src/lib/connectionProfiles.ts:114))
  checks only that the field is an object, so an older client would show a
  `provider` profile as launchable. Phase 0 settles what that client then does.
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
- **Admin visibility into other users' account metadata.** See *Open
  questions*.

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
  tidy pass, recorded as a pending-purge marker.
- **Administrator purge.** `DELETE v2/sys/plugins/<name>/entity-data/<entity_id>`
  (granted by the `plugin-admin` policy) is used for offboarding and for the
  merge case below. It is audited. There is no read counterpart.
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
  "first use on this target" badge.

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
| `resources/v2/connect/authorize` | update, new field `provider_account_id`, new response field `credential` | unchanged | 3 |
| `resources/v2/connect/web/launch` | update, new field `provider_account_id` | unchanged | 3 |
| `rustion/v2/session/open` | update, new field `provider_account_id` | unchanged | 3 |
| `v2/sys/plugins/<name>/grants/credential-provider` | read, write, delete | `plugin-admin` | 1 |
| `v2/sys/plugins/<name>/entity-data/<entity_id>` | delete | `plugin-admin` | 1 |

Tauri commands: `connect_provider_candidates` (new); `session_open_ssh`,
`session_open_rdp` and `session_open_web` gain `provider_account_id`.
Document all of it in `docs/api.md`, and the plugin in its own README under
`plugins-ext/`.

## Phases

### Phase 0 — verification spike — **Todo**

Answer the questions this spec defers, and record the answers here:

- How older clients treat a `provider` profile (§10).
- Whether `.bvx` exchange exports include plugin data (§10).
- Where entity deletion happens, to place the purge call.
- Whether the SSH session path accepts passphrase-protected keys (§2).
- Whether `resources/config/types` is readable by every operator who can
  connect.

### Phase 1 — host substrate — **Todo**

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

### Phase 2 — the plugin — **Todo**

`plugins-ext/bastion-plugin-self-accounts`: the data model, CRUD, the
matching rules (type, OS, protocol, targets), config, the surface, the
signed `.bvplugin`, and testkit-driven tests.

### Phase 3 — Connect integration, server — **Todo**

The `provider` source in `bv-engine-resource` (candidates endpoint, release on
`authorize` and `web/launch`) and in `bv-engine-rustion` (`session/open`).
Target computation from stored metadata, audit, metrics and baseline policy
grants.

### Phase 4 — Connect integration, GUI and Tauri host — **Todo**

- `CredentialSource` gains `{ kind: "provider"; provider: string }`.
- The profile editor offers each granted provider by its `display_name`
  (*Self-account (pick at connect)*).
- Update the `connectionProfiles.ts` helpers: `validateProfile`,
  `isLaunchableProfile`, `isLaunchableForCaller` and `needsOperatorPrompt`.
- Build `ProviderAccountPicker`, `connect_provider_candidates`, and the
  `provider` arms in `resolve_ssh_credential` / `resolve_rdp_credential` and
  in the web launcher.

### Phase 5 — hardening and UX — **Todo**

- A "first use on this target" badge (the plugin keeps a per-account set of
  target hashes).
- Preselect the account last used on this resource.
- Per-user account counts on the admin Plugins page (counts only, never
  metadata).
- The operator guide.

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
   operator's mistake is dangerous. The current proposal is to retain them
   and let the administrator purge them.
2. **Administrator visibility.** Should an administrator be able to list
   another user's account *metadata* (labels, usernames, targets) for audit?
   The current proposal is no; Phase 5 adds counts only.
3. **Profile-side narrowing.** Should a profile be able to restrict which
   accounts qualify (for example, a `username_pattern` such as `*-adm`)?
4. **Defaults.** Is `require_connect_mfa = true` the right default for every
   deployment, or should it follow the profile's `require_mfa`?
