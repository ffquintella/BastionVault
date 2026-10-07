# Self-Accounts — Operator Runbook

Self-accounts lets each operator keep **their own** accounts (a login name plus a password or an SSH private key) in the vault and pick one when pressing **Connect**. The operator never retypes the password, the webview never receives it, and every release is audited on the server. It ships as an optional WASM plugin, `bastion-plugin-self-accounts`, that plugs into Resource Connect as a **credential provider**.

See the feature spec: [`features/self-accounts.md`](../features/self-accounts.md). The plugin's own reference (paths, field limits) is its README under `plugins-ext/bastion-plugin-self-accounts/`.

This page is for the administrator who installs and approves the plugin and for the operators who use it. Resource Connect itself is covered in [`gui.md`](gui.md) and [`rustion-integration.md`](rustion-integration.md).

---

## 1. What it is, and when not to use it

Each operator registers accounts under **My accounts**. An account carries a label, a login name, an optional domain, a secret (password or SSH key) and an **applicability** block: the resource types, and optionally the OS families, protocols and **targets** it may be used for. A connection profile opts in by choosing the credential source **Self-account (pick at connect)**. At Connect the operator sees only their own accounts that match the resource, protocol and target, picks one, and the server releases that one credential for that one connect.

Secrets are write-only. No HTTP path returns a password, key or TOTP seed, not even to the account's owner. The host (not the plugin's code) keeps users apart: every request is attributed to the caller's identity entity and the plugin's storage is confined to that entity.

**Do not install it if your organisation forbids personal credentials in the vault** (for example, every privileged account must be managed and rotated centrally). A deployment that never registers and approves the plugin carries no self-account code, storage or routes. Shared credentials do not belong here either; keep them as resource secrets, LDAP static roles or LDAP library sets.

| | Default resource account | Self-accounts |
|---|---|---|
| Accounts per operator | one login name per OS family | many, each scoped by resource type |
| Holds a secret | no | yes (password or SSH key) |
| Chosen at connect | no, resolved automatically | yes, the operator picks |
| Lives in | the identity module | the plugin's own entity-scoped storage |

The two coexist: a resource can have one profile of each.

---

## 2. Installing

### 2.1 Build

~~~bash
make plugins-wasm
~~~

`plugins-wasm` builds the reference WASM plugins, including this one, for `wasm32-unknown-unknown` (the Makefile variable `PLUGINS_WASM_TARGET`) and copies `bastion_plugin_self_accounts.wasm` into `plugins-ext/dist/`. `make plugins-target` installs the Rust target if it is missing.

The plugin cannot be built for `wasm32-wasip1`. The host links only its own `bv` import module and no WASI, and a `wasip1` build imports `wasi_snapshot_preview1` (`environ_get`, `fd_write`, `proc_exit`). Such a module cannot be instantiated, and the plugin catalog refuses to register one.

### 2.2 Pack and sign

~~~bash
make plugins-pack      # unsigned .bvplugin bundles in plugins-ext/dist/
make plugins-keygen    # once: mint the dev ML-DSA-65 signing keypair
make plugins-sign      # the same bundles, signed
~~~

The bundle is `plugins-ext/dist/bastion-plugin-self-accounts.bvplugin`. Both targets also build the other reference plugins, including the native process ones. Signing uses `$(PLUGINS_SIGNING_KEY).seed` and the publisher name `$(PLUGINS_SIGNING_KEY_NAME)`; register the matching public key as a publisher under **Plugins** so the signature validates, or the registration is refused unless the server accepts unsigned plugins (development only).

`make plugins-test` runs the plugin's own tests, including the compiled wasm against the real host. It is not needed to install.

### 2.3 Register

Register the bundle under **Plugins → Register**, or with the API (`POST /v1/sys/plugins`).

**The packed bundle carries no management surface.** `bv-plugin-pack` cannot embed `surface.json`, and the shipped `plugin.toml` has no `[surface]` table, so a bundle registered as it is gives you the credential provider (Connect works) but no **My accounts** page. Accounts can then only be managed through the API (section 10). To get the page you register the surface alongside the plugin, and the GUI's Register dialog cannot do that: it never sends the surface. Use the API:

1. Compute the surface's hash and size: `shasum -a 256 surface.json` and `wc -c < surface.json`.
2. Add a `[surface]` table to `plugin.toml` **before** packing and signing, because the signature covers the manifest:

   ~~~toml
   [surface]
   schema_version = 1
   sha256 = "<sha256 of surface.json, hex>"
   size   = <size of surface.json in bytes>
   ~~~

3. Pack (and sign) again, then `POST /v1/sys/plugins` with a JSON body:

   | Field | Meaning |
   |---|---|
   | `manifest` | The manifest as JSON (the one embedded in the `.bvplugin`, including `surface`) |
   | `binary_b64` | The `.wasm` module, base64 |
   | `surface_b64` | `surface.json`, base64 |

The host checks that the uploaded bytes hash to `manifest.surface.sha256`. A manifest that declares a `surface` but a request without `surface_b64` is refused. The opposite, `surface_b64` sent with a manifest that has no `surface`, is **ignored without an error**, and the page silently does not appear.

### 2.4 Mount

The plugin is mounted like an engine, with type `plugin:self-accounts`, at `self-accounts/` by convention:

~~~bash
bvault write sys/mounts/self-accounts type=plugin:self-accounts
~~~

All its paths are `v2/` under the mount, for example `self-accounts/v2/accounts`.

### 2.5 Approve the credential provider

Declaring `[capabilities.credential_provider]` in the manifest is not enough. Nothing can ask the plugin for a credential until an administrator approves it:

- GUI: **Plugins**, the plugin's **Credentials** button (the consent panel), tick the consent box, **Approve**. The panel shows what the manifest declares (display name, protocols, secret kinds) and warns if the plugin also requests network access. The self-accounts manifest requests none.
- API: `PUT /v2/sys/plugins/self-accounts/grants/credential-provider` (no body). `GET` shows the requested block, the stored grant and whether it is `live`; `DELETE` revokes it.

The grant is pinned to the SHA-256 of the manifest's `credential_provider` block. **Any change to that block, even a narrowing one, voids the grant** until you approve again; the panel then shows the status as stale. Approval and revocation are audited. Until the grant is live, the profile editor does not offer the provider and Connect refuses with `not_granted`. A quarantined plugin counts as not approved.

### 2.6 Attach the `self-accounts-user` policy

The policy is **not** added to `default` or any built-in policy: installing a plugin must not silently widen one. Attach it to `default`, or to the groups whose members may keep accounts:

~~~hcl
# self-accounts-user
path "self-accounts/v2/accounts"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "self-accounts/v2/accounts/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "self-accounts/v2/settings"   { capabilities = ["read"] }
~~~

Granting it broadly is safe: users are separated by the host's per-entity storage scope, not by the path. A token with no identity entity (for example a bare root token) is refused with `403` before the plugin runs, because self-accounts belong to entities, not tokens.

Connect itself needs no extra grant: the baseline policies already allow `resources/v2/connect/provider/candidates` and the provider listing wherever they allow `connect/authorize`. The operator still needs the `connect` grant on the resource.

---

## 3. Configuration

Set under **Plugins → Configure** (the plugin's `config_schema`). Every key is optional and has a default.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow_ssh_keys` | bool | `true` | Accept `ssh-key` accounts. Turning it off also stops existing key accounts being offered. |
| `allow_totp_seeds` | bool | `false` | Accept a TOTP seed next to a password (web `form` logins). Off by default: a record holding both collapses two factors into one. Turning it off also stops existing seeds being used. |
| `max_accounts_per_user` | int | `25` | Cap per person. A value that is not a positive number falls back to 25; the effective maximum is 1000. |
| `require_connect_mfa` | bool | `true` | Refuse a release unless the host attests that a connect-time MFA ticket was redeemed for this launch. |
| `require_targets` | `web` or `all` | `web` | Which protocols need a non-empty targets list on an account. An account without targets is never offered for those protocols. An unknown value is read as `all` (strict). |
| `allowed_resource_types` | comma list | empty | Resource type ids accounts may be tagged with. Empty allows every type. |

The plugin's `v2/settings` path shows the effective values to the owner (no secrets). Note that the settings also change what is **offered**: lowering a restriction does not delete accounts, it stops them matching.

---

## 4. Opting a connection profile in

1. Open the resource, **Connection profile** tab, and edit (or add) the profile.
2. Set **Credential source** to **Self-account (pick at connect)**. The label is the provider's `display_name` plus "(pick at connect)". The option appears only when the provider is approved and active on this server and declares the profile's protocol (SSH, RDP, or a web `form` login). `http-auth` web profiles cannot use it.
3. Tick **Require MFA re-validation** (`require_mfa`). With the default `require_connect_mfa = true` the plugin releases only after a connect-time MFA ticket was redeemed for that very launch; without `require_mfa` on the profile, every connect is refused with `mfa_required`. The editor shows a note while it is unticked. Only an administrator who set `require_connect_mfa = false` removes the requirement.
4. Save.

The profile carries no username or secret. **Its `username` field is ignored**: the login name released with the picked account is authoritative, and the editor hides the field.

A profile that names a provider this server does not offer is kept as it is, shown as not available, and Connect with it is refused until an administrator approves the provider. Nothing falls back to another credential source.

Brokered SSH resources do not offer the source (see section 7).

---

## 5. Targets

Anyone who can edit a resource can point it at any host or origin and give it a self-account profile. Without a binding, an operator who picked their "Domain admin" account on a hostile resource pointing at `https://evil.example` or at an attacker's host would hand that credential over. Matching by resource type alone cannot stop this, because the attacker chooses the type too. **Targets bind an account to where it may be used.**

Enter them as a comma- or newline-separated list (at most 32 entries) when adding the account.

| Protocol | Entry | Matches |
|---|---|---|
| SSH, RDP | `dc01.corp.example.com` | that name, case-insensitive |
| SSH, RDP | `*.corp.example.com` | exactly one label under the suffix. Not the apex, not two labels. |
| SSH, RDP | `10.20.0.0/16`, `fd00::/8`, `10.0.0.5` | an IP inside the range or equal to the address |
| web | `https://grafana.corp.example.com` | that origin, HTTPS only, port 443 unless written |
| web | `https://grafana.corp.example.com:8443` | that origin and exact port |
| web | `https://*.corp.example.com[:port]` | exactly one label |

- A wildcard is accepted only as the **whole left-most label** with a real suffix. `*.com`, `*`, `a*.example.com` and `a.*.example.com` are refused when you save.
- Names are never resolved. A DNS pattern never matches an IP target and an IP or CIDR never matches a name.

### What is matched

The **server** computes the target from the stored profile and resource. The request never supplies it, so editing the request cannot change what the plugin matches.

- **SSH / RDP:** the profile's `target_host`, else the resource's `ip_address`, else its `hostname`. The IP is preferred. So **an account bound only by a DNS pattern does not match a resource that has an IP address set** (add the IP or a CIDR as a target too). The host is normalised to one lower-case ASCII spelling; a value with a trailing dot, wildcard, brackets, `%` or whitespace is refused with `invalid_profile`. The port is the profile's `target_port`, else 22 (SSH) or 3389 (RDP). The Connect client dials exactly that host and never falls back to another candidate, so the credential reaches only the host it was matched against.
- **Web:** **every** origin the recipe may fill (the start URL's origin and each `allowed_origins` entry) must match one of the account's origin targets, because the fill routine may run on any of them.

### Requiring targets

`require_targets` (default `web`) makes targets mandatory for web; with `all`, SSH and RDP need them too. An account without the required targets is never offered. When you save an account that could therefore never be offered, the write succeeds with a warning that says which kind of target is missing.

---

## 6. The account picker

Pressing **Connect** on a `provider` profile opens a host-drawn picker. It lists only the operator's own accounts that match the resource type, OS, protocol and target, with label, `DOMAIN\username`, kind (password or key), a TOTP badge and the last-used time, under "Connecting to `<host>:<port>`" (for web, the origins). Arrow keys and Enter work. With several accounts and none preselected (see below), Connect stays disabled until one is picked. The picker is host code on purpose: a plugin-drawn picker could imitate host chrome. If the MFA step-up is required it runs after the pick, so cancelling the picker costs no factor ceremony.

If nothing matches, the picker says the operator has no self-accounts for that resource type on this target, with an **Add a self-account** link to the plugin's page (main window only, and only when the plugin registered a surface). The host withholds any candidate whose label, login or domain it cannot show as plain text (bidi overrides, zero-width and other invisible characters, over-long values) and says how many.

### First use and last used

- **First-use badge.** An account that has never been released for this target is marked **First use on this host** (web: **First use on this site**), and a one-line caution under the list appears while the selected account is a first use.
- **Preselection.** The picker preselects the account most recently used on this same target, without reordering the list. When there is no such account, a single candidate is preselected; with several and no history, the operator must choose.

How it works: for each account the plugin remembers up to 64 SHA-256 hashes of the targets it has released that account for, each with the time of the last release there (key `accounts/<id>/seen` inside the entity's storage; past 64, the least recently used target is forgotten and becomes a first use again). The hash is domain-separated and taken over the canonical dial host for SSH and RDP (lower case, no trailing dot; the port is **not** included, and SSH and RDP to the same host count as the same target), or over the sorted, de-duplicated origin set for web (so a recipe that may fill an extra origin is a new target). The target text itself is never stored, and the resource name never reaches the plugin. A target is recorded only by a **successful** release; listing candidates and refused releases record nothing. This is kept server-side in the plugin, not in the desktop's local storage, because local storage is per device and is not replicated: the history follows the operator to every desktop and to the server-side Rustion route. An unreadable record reads as "never used here", so it errs toward showing the caution.

**The badge is a hint, not a protection.** It helps an operator notice an unexpected host, but it can be ignored and a hostile target can be one the account has been used on before. The protection is target binding (section 5).

---

## 7. Brokered SSH and Rustion

### Brokered SSH resources

A resource whose SSH login class is `brokered` ([`ssh-login-brokering.md`](ssh-login-brokering.md)) takes every SSH login from the SSH engine, and a self-account is a static credential. So **a provider profile is refused for SSH on a brokered resource**: the editor does not offer the source, the desktop checks it before either route (direct or Rustion), and the server refuses on every provider route (candidates, `connect/authorize` and `rustion/v2/session/open`) with `403 brokered_requires_ssh_engine`, before any MFA ticket is redeemed. RDP and web profiles on the same resource still work.

### Where it stops, and Rustion routing

On the **direct** path the released credential goes to the operator's desktop for the session. An operator who holds the `connect` grant can also release their own credential for the resource to their own machine through `connect/authorize` outside the GUI. That exposes only a credential the operator typed in themselves, behind the `connect` grant and (by default) MFA, but it is a real boundary: **if the secret must never reach the endpoint, route these profiles through Rustion.** On the Rustion route the server releases the credential and seals it into the bastion envelope; the desktop never holds it. An SSH key account over Rustion must be an unencrypted OpenSSH key, and an RDP domain account travels as `DOMAIN\user`.

To force the bastion, set the resource's transport policy to `rustion-required` ([`rustion-integration.md`](rustion-integration.md), "Forcing transport at policy time"). `connect/authorize` then refuses a direct release with `403 transport_policy`, so the credential is released only through `rustion/v2/session/open`.

---

## 8. Offboarding and per-user data

Personal credentials must not outlive their owner. Plugin data lives under `core/plugins/self-accounts/data/entity/<entity_id>/`.

### Automatic purge

When a principal's **last** alias is removed (deleting the userpass user or the AppRole role), the host purges that entity's data in every entity-scoped plugin. The entity record itself is kept (shares and ownership point at it), but with no alias left it can never log in again, so its data could never be reached.

If the automatic purge **fails**:

- the failure is logged at `ERROR` and the principal's delete is not undone;
- a pending-purge marker is recorded at `core/plugins/engine/pending-purges/<entity_id>` (the entity id, the first and last failure times and the attempt count; no plugin data);
- markers are retried, up to 16 per pass, on the next automatic purge and on every administrator entity-data `DELETE` (GUI or API), until the delete succeeds. A marker is only ever written for an entity with no alias left, and the identity store never re-attaches an alias to an existing entity (a recreated principal gets a new one), so a retry purges without asking again;
- `GET .../entity-data` (below) reports how many markers are pending.

Every automatic purge and every retry is audited: path `sys/plugins/entity-data/<entity_id>`, operation `delete`, with `trigger` (`last-alias-removed` or `pending-purge-retry`), `outcome` (`purged` or `failed`) and, on failure, the error.

### Administrator purge

~~~
DELETE /v2/sys/plugins/self-accounts/entity-data/<entity_id>
~~~

Deletes that entity's data under that one plugin. It is audited, and it also retries any pending automatic purges. Use it for offboarding when the automatic purge did not run or failed, and for the merge case below.

### Per-entity counts

~~~
GET /v2/sys/plugins/self-accounts/entity-data
~~~

Returns **counts only**: never labels, usernames, targets or secrets. The server lists keys and reads no value, and never invokes the plugin: an entity's count is the number of `accounts/<id>/meta` keys in its scope. An entity that holds other data but no such record is listed with `0`, so it can still be purged.

~~~json
{
  "entities": [ { "entity_id": "…", "display_name": "felipe", "accounts": 3 } ],
  "total_accounts": 3,
  "total_entities": 1,
  "pending_purges": 0
}
~~~

`display_name` is the entity's name from the identity store (its primary name, else its first alias name), present when the identity store knows the entity. `pending_purges` counts failed automatic purges across every plugin. A plugin that is not registered or does not declare `storage_scope = "entity"` answers `404`. The route exists on `v2` only. It is administrator-only: of the built-in policies only `administrator` (`path "*"`) reaches it (and the `DELETE` above); no user baseline such as `default` or `shared-access` grants either, so give `sys/plugins/<name>/entity-data` (`read`) and `.../entity-data/*` (`delete`) to a narrower admin policy explicitly if you need one. On the **Plugins** page, entity-scoped plugins have a **Per-user data** button that shows this list, with a **Delete** action per entity behind a confirmation dialog.

### Entity merge

Data under a merged-away entity is **retained** and reachable only by the administrator purge above. Merging never moves credentials between identities.

---

## 9. Backups and exports

- **BVBK full backups** (`sys/backup`) copy the barrier and include `core/plugins/<name>/data/`. Self-account secrets are therefore in them, encrypted like the rest of the barrier. Protect and expire backups accordingly, and remember that restoring an old backup restores accounts that were deleted since.
- **`.bvx` exchange exports** (`sys/exchange/export`) do **not** carry plugin data: no `core/plugins/` key is part of the exchange format.

---

## 10. Known limits

- **No edit in the GUI.** **My accounts** adds and deletes. To edit an account, write `self-accounts/v2/accounts/<id>`; secret fields are write-preserve (an absent or empty value keeps the stored one), and `DELETE .../<id>/totp` clears a seed.
- **OpenSSH private keys only.** A PKCS#8 PEM is refused with a precise message, because the SSH session reads the OpenSSH form.
- **No passphrase-protected keys.** Store an unencrypted key; the barrier is the at-rest protection.
- **The signed `.bvplugin` carries no surface** (section 2.3), and the Register dialog cannot upload one.
- **TOTP from a provider seed is computed once at launch.** There is no refresh for it, and the seed is not kept server-side. The password form always shows a TOTP field; a seed is refused with a clear message unless `allow_totp_seeds` is on.
- **No sign-in re-run for a provider web session.** The toolbar's re-run login is unavailable (the provider releases again only after a fresh MFA check, which the toolbar cannot run). Disconnect and connect again.
- **First use is recorded when the plugin releases.** A release the host later refuses (an output of the wrong shape), a Rustion open that then finds no bastion, or a session that then fails to open still counts as used.
- **The first-use history forgets.** Past 64 targets per account the least recently used one is dropped and shows the badge again; deleting and re-creating an account starts with no history.
- **Desktop GUI only**, like the rest of Resource Connect. Web `http-auth` and SSO profiles cannot use the source.
- **A forged or stale account id costs an MFA ticket**: the refusal (`no_match`) is reported after the ticket is redeemed.
- **Older GUIs** facing a provider profile show the server's `provider_account_id is required` text rather than a "too old" message; they do not release anything.

---

## 11. Audit

### Server

Connect writes one line per provider call to the `audit` log target:

| Line | When |
|---|---|
| `connect.provider.candidates` | the picker's candidate listing; success adds `candidates=<n>` |
| `connect.provider.release` | each release attempt on `connect/authorize`, `web/launch` and `rustion/v2/session/open` |

Fields: `outcome` (`success` or `denied`), `reason` (`-` on success), `principal`, `entity_id`, `resource`, `profile_id`, `protocol`, `transport` (`direct`, `rustion`, `web`, or `-` for a listing), `provider`, `account_id` (an opaque random id), and `login_name` (successful release only; not a secret). **No password, key or TOTP code is ever in these lines.** The session-open lines also record `credential_source=provider`, `provider`, `account_id` and `login_name`.

Refusal reasons: `no_entity`, `not_granted`, `unsupported_protocol`, `no_match`, `mfa_required`, `bad_request`, `bad_provider_output`, `provider_error`, `invalid_profile`, `invalid_request`, `connect_denied`, `transport_policy`, `brokered_requires_ssh_engine`. The same code starts the error message the client sees. A refused `connect` grant on `authorize` writes no `connect.provider.release` line (the pipeline's own audit entry records it).

The authorize response carries the released credential, but the audit pipeline HMACs every string in a response body, so the password reaches an audit device only as `hmac:<hex>`. The Prometheus family `bvault_plugin_provider_requests_total{plugin, op, protocol, outcome}` counts calls that reach the plugin.

Grants, revocations and entity-data deletes are audited under `sys/plugins/<name>/grants/credential-provider` and `sys/plugins/<name>/entity-data/<entity_id>`.

### Plugin

The plugin emits `self-accounts.account.created`, `self-accounts.account.updated` and `self-accounts.account.deleted`. They carry the account `id`, `secret_kind`, `applies_to` and `entity_id`; an update adds `changed` (which fields) and `secret_changed` (a flag, never the value).

---

## 12. Manual verification checklist

Run these against real targets, on each desktop platform you support, after installing. None of them has been run against real targets by the project yet.

Setup

- [ ] Plugin registered, mounted at `self-accounts/`, and approved under **Plugins → Credentials** (status live).
- [ ] `self-accounts-user` attached to the test operator, who has an identity entity and the `connect` grant on the test resources.
- [ ] A profile with **Self-account (pick at connect)** and **Require MFA re-validation** on each test resource.

Connect

- [ ] SSH with a password account: the picker lists it, MFA runs after the pick, the session opens and logs the account's login on the target.
- [ ] SSH with an OpenSSH key account.
- [ ] RDP with a domain account (`CORP` + login); the session authenticates as `CORP\login`.
- [ ] Web `form` login with a TOTP seed (`allow_totp_seeds` on, a seed on the account, a recipe that fills `totp`).
- [ ] Rustion SSH: the profile on a `rustion` transport opens through the bastion, and the audit shows `transport=rustion`.
- [ ] A resource with `rustion-required` refuses a direct release (`transport_policy`).
- [ ] A brokered SSH resource offers no provider source, and its RDP or web profile still works (`brokered_requires_ssh_engine` for SSH).

Picker behaviour

- [ ] First time on a host: the account shows **First use on this host** (web: **on this site**) and the caution line appears.
- [ ] After one successful connect, the badge is gone for that host, and the account is **preselected** next time.
- [ ] An account used on host A still shows the badge on host B.
- [ ] With no matching account, the empty state appears with the **Add a self-account** link (main window).
- [ ] A resource re-pointed at a host outside the account's `targets` offers nothing.
- [ ] With the profile's `require_mfa` off and `require_connect_mfa` on, Connect is refused with `mfa_required`.

Offboarding

- [ ] **Plugins → Per-user data** lists the test entity with the right account count and nothing else.
- [ ] Deleting the test userpass user (its last alias) removes that entity's accounts automatically.
- [ ] **Delete** on a remaining entity (confirm dialog) removes its accounts, and the entity is gone from the **Per-user data** list.

Audit

- [ ] The audit log shows `connect.provider.candidates` and `connect.provider.release` with the account id and login name, and no secret.
- [ ] Adding, editing and deleting an account produce the three `self-accounts.account.*` events.
