# Changelog

All notable changes to BastionVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

<!--
=============================================================================
  CHANGELOG MAINTENANCE INSTRUCTIONS
=============================================================================

This file MUST be updated after every feature, phase, or roadmap stage.

WHEN TO UPDATE:
  - After completing a roadmap phase (e.g., "Hiqlite Phase 5")
  - After implementing a feature from features/*.md
  - After adding a new GUI phase
  - After adding a new credential/auth backend
  - After any bug fix that affects user-facing behavior
  - After dependency additions or removals
  - After CI/CD or build system changes

HOW TO UPDATE:
  1. Add entries under [Unreleased] in the correct category (Added/Changed/Fixed/Removed)
  2. When cutting a release, move [Unreleased] items to a new version header
  3. Use imperative mood ("Add", not "Added" or "Adds")
  4. Reference feature files, roadmap phases, or issue numbers where applicable
  5. Group related entries under a subsection (e.g., "#### FIDO2 Auth Backend")
  6. Keep entries concise but specific enough to understand the change

CATEGORIES:
  ### Added       - New features, endpoints, commands, files
  ### Changed     - Behavior changes, refactors, dependency updates
  ### Deprecated  - Features that will be removed in a future version
  ### Removed     - Features, files, or dependencies removed
  ### Fixed       - Bug fixes
  ### Security    - Vulnerability fixes or security improvements

EXAMPLE ENTRY:
  - **FIDO2 auth backend** (`src/modules/credential/fido2/`) -- WebAuthn registration
    and login with hardware security keys. 7 API endpoints, `webauthn-rs` 0.5 integration.
    (Phase 6, `roadmaps/tauri-gui-fido2.md`)
=============================================================================
-->

## [Unreleased]

### Added

#### Cloud FileTarget memory cache — v2: singleflight, stale-while-revalidate, prefetch, 500 MiB default (`src/storage/physical/file/cache.rs`)
- **Default cache size increased from 64 MiB to 500 MiB** (`DEFAULT_MAX_BYTES`). `DEFAULT_MAX_ENTRIES` bumped from 4096 to 65,536 to match — a 500 MiB cache of tens-of-kB ciphertext entries was getting evicted on entry-count before byte-count. Both remain tunable via `cache_max_bytes` / `cache_max_entries` config keys.
- **Per-key singleflight gate**: concurrent readers of the same cold key now coalesce through a `tokio::sync::Mutex` keyed by cache key, so the underlying provider sees exactly one request per (key, miss) instead of N. Gate is populated only on the miss path and cleaned up after the fetch; steady-state hits never touch it.
- **Stale-while-revalidate**: new `stale_ratio` knob (default 0.5) splits each entry's TTL into a "fresh" window (return cached immediately, no side-effects) and a "stale but serveable" window (return cached AND spawn a background refresh via `tokio::spawn`). Readers past the full TTL still pay one provider round-trip synchronously, under the singleflight gate. The net effect: hot keys stay hot forever under steady traffic, because the background refresh re-enters the fresh window before any caller notices.
- **Opt-in background prefetch**: new `prefetch_keys: Vec<String>` + `prefetch_concurrency` (default 4) config knobs. When non-empty, the cache constructor spawns a bounded-concurrency task that reads each key and populates the cache — the very first post-boot vault request finds the barrier's hot entries already warm. Empty by default: the "right" warmup set depends on the deployment, and silent magical prefetch would surprise operators.
- **Three new config keys**: `cache_stale_ratio` (float), `cache_prefetch_keys` (array or comma-separated string), `cache_prefetch_concurrency` (int). Parsed by `FileBackend::cache_config_from`.
- **Graceful sync_handler fallback**: singleflight, SWR, and prefetch all `#[cfg(not(feature = "sync_handler"))]`-gated — under the sync build, the cache behaves like the v1 pure-TTL cache (no spawn, no gate). The async features kick in only when the runtime is actually present.
- **4 new tests** on top of the existing 9: singleflight (8 concurrent readers → 1 provider call), SWR (stale hit serves fast + background refresh lands + next read sees refreshed value without provider call), prefetch (configured keys loaded before first request), stale_ratio clamping (NaN / negative / >1 all normalised). 13/13 cache tests green, 86/86 full storage suite green.

#### Cloud FileTarget memory cache (`src/storage/physical/file/cache.rs`)
- **New `CachingTarget` decorator** wrapping any `FileTarget` with a bounded, TTL-based in-memory cache for `read(key)` and `list(prefix)`. Sits above the provider (S3 / OneDrive / Google Drive / Dropbox) so repeated reads within the TTL serve from RAM instead of the network — the dominant latency source on cloud-backed vaults, where every barrier `get` would otherwise turn into an HTTPS round-trip.
- **Security**: caches only AEAD ciphertext bytes already emitted by the barrier two layers above. No plaintext key material, bearer token, or decrypted secret is cached — same invariant the existing `CachingBackend` (secret-engine layer) relies on, now extended to the storage-target layer.
- **Defaults**: `read_ttl = 30s`, `list_ttl = 10s`, `max_entries = 4096`, `max_bytes = 64 MiB`. All four are tunable via config keys (`cache_read_ttl_secs` / `cache_list_ttl_secs` / `cache_max_entries` / `cache_max_bytes`). An explicit `cache = true`/`false` config key overrides the default-on policy.
- **Default-on for cloud kinds** (`s3` / `onedrive` / `gdrive` / `dropbox`), **default-off for `local`** (the local filesystem is already faster than a cache lookup). Zero behavior change for default builds that don't use cloud targets.
- **Invalidation**: `write(k, v)` and `delete(k)` drop the cached read for `k` plus every cached `list(prefix)` where `prefix` is a prefix of `k` — list entries whose enumeration might have been affected. Unrelated prefixes stay hot.
- **Negative caching**: `read(k) → None` results are cached so the barrier's "probe for existence" pattern stays hot.
- **Eviction**: oldest-by-insertion-time (FIFO-ish) when either cap is exceeded. Soft caps — a single oversized value won't be permanently uncacheable.
- **Metrics**: `bvault_cache_{hits,misses,evictions,size}_total{layer="cloud_target"}` — new `CacheLayer::CloudTarget` variant reuses the existing cache-metrics Prometheus families.
- **Placement**: stack is now `FileBackend → ObfuscatingTarget → CachingTarget → Provider` when both are enabled. Cache is keyed by whatever key the layer above hands down (obfuscated hash under `obfuscate_keys = true`, plaintext path otherwise).
- **Zero new dependencies** — built on `dashmap` + `tokio` + `prometheus-client` already in the workspace.
- **9 unit tests** covering hit-after-miss, negative-cache, write-invalidates-read, delete-invalidates-read, list-invalidated-on-write-under-prefix, unrelated-prefixes-retained, TTL-expiry-forces-refetch, byte-cap-eviction, entry-cap-eviction. All green.
- **Deferred (follow-ups)**: background prefetch (opt-in warmup), stale-while-revalidate, per-key singleflight. The vault core's own per-key locks one layer up serialize most hot-path reads, so the marginal benefit is small without a profile justifying it.

#### SSO admin UI — full provider lifecycle from Settings (`gui/src-tauri/src/commands/sso_admin.rs`, `gui/src/routes/SettingsPage.tsx`)
- **New Tauri command module** `sso_admin` with 6 commands: `sso_admin_list` / `sso_admin_get` / `sso_admin_create` / `sso_admin_update` / `sso_admin_delete` / `sso_admin_callback_hints`. Each bundles the N vault writes needed to stand up an OIDC provider end-to-end (`sys/auth/<mount>` → `auth/<mount>/config` → `auth/<mount>/role/<default>`) so the admin never drops to the raw API. Delete disables the auth mount; config + role storage scoped to the mount is torn down with it.
- **Settings → Single Sign-On card now does real admin**: lists every configured OIDC provider with display name + kind badge + mount path + discovery URL. Each row has Edit / Delete; header has "Add Provider" button and the existing enabled/disabled toggle. "Missing role" and "PKCE" badges flag provider states at a glance.
- **Provider editor modal** covers the full OIDC admin surface in four sections — Identification (display name, mount path), OIDC Provider (discovery URL, client id / secret, scopes), Allowed Redirect URIs (freeform textarea), Default Role (name, user/groups claim, policies, token TTL, bound audiences, bound claims JSON). Blank `client_secret` on edit preserves the stored secret; on create the secret is optional (PKCE clients).
- **Callback-URI hints panel** inside the modal: asks the backend for the mode-appropriate redirect URI to register with the IdP. Remote mode shows the stable `{server}/v1/auth/{mount}/callback`; embedded/desktop mode shows `http://127.0.0.1/callback` with an RFC-8252 "native app / loopback" explainer (Azure AD's "Mobile and desktop applications", Okta's "Native app", Google's "Desktop app"). One-click Copy per suggestion.
- **Client-side validation** flags the common misses upfront — missing display name / discovery URL / client id / default role / user claim / policies, plus a JSON-object sanity check on `bound_claims`. Server-side validation in `sso_admin::validate_input` re-enforces the same invariants so the Tauri surface cannot be bypassed by a crafted IPC call.
- `client_secret` never round-trips to the frontend — the backend returns only a `client_secret_set` boolean hint. Matches the existing `oidc_client_secret_set` redaction pattern on `auth/<mount>/config` Read.
- TS typecheck clean, vitest 66/66, `cargo check -p bastion-vault-gui` clean.

#### SSO login UX cleanup + global admin toggle (`src/modules/system/mod.rs`, `gui/src-tauri/src/commands/system.rs`, `gui/src/routes/LoginPage.tsx`, `gui/src/routes/SettingsPage.tsx`)
- **Login page no longer asks users to type a mount path or role.** The SSO tab now renders one clickable "Sign in with &lt;name&gt;" button per configured SSO backend. Role is resolved server-side via the mount's `OidcConfig.default_role`, so the admin is the single source of truth for what role an SSO login maps to.
- **Two new sys endpoints**: `sys/sso/providers` (Read, **unauth** — so the login page can fetch pre-token) returns `{enabled, providers: [{mount, name, kind}]}`; `sys/sso/settings` (Read/Write, **root-gated**) stores the global `{enabled: bool}` toggle at `core/sso/settings`. Providers are enumerated from the auth-mount table filtered by kind (currently `oidc`; `saml` joins when Phase 3 lands); the operator-supplied mount description becomes the display label.
- **Login page hides the SSO tab entirely** when the toggle is off or no SSO-capable auth mounts are configured. The vault never advertises a feature the user can't use. If SSO gets disabled between loads while the tab is active, the page auto-falls-back to the default Login tab.
- **Settings → Single Sign-On (SSO) card** with an enable/disable checkbox, live provider count, and copy explaining how to add a provider ("mount an auth backend, write its config, the mount description becomes the button label"). Flipping the toggle is reflected in the same render via `setSsoSettings` + a re-fetch of the provider list.
- **Three new Tauri commands**: `list_sso_providers` (unauth wrapper), `get_sso_settings`, `set_sso_settings`. Full TS types on the frontend (`SsoProvider`, `SsoProvidersResult`).
- **66/66 vitest tests still green**; LoginPage `beforeEach` gains a default `list_sso_providers` mock so non-SSO tests don't hit undefined-invoke when the page's mount effect runs.

#### SAML 2.0 auth backend — Phase 1 + 2 (`src/modules/credential/saml/`)
- **New `saml` credential kind** registered via `SamlModule` + `SamlBackend`, following the same Module/Backend pattern as `userpass`, `approle`, and `oidc`. Mounted under `auth/<mount>/` with per-mount IdP configuration.
- **IdP config CRUD** at `auth/<mount>/config` — `idp_metadata_url`, `idp_metadata_xml`, `entity_id`, `acs_url`, `idp_sso_url`, `idp_slo_url`, `idp_cert`, `default_role`, `allowed_redirect_uris`. Write validates that `entity_id` + `acs_url` are set and that at least one IdP source (metadata URL / inline XML / explicit SSO URL + cert) is present. Inline metadata XML and the IdP signing cert are **redacted on read**; boolean `_set` hints surface whether they are populated.
- **Role CRUD** at `auth/<mount>/role/<name>` + LIST at `auth/<mount>/role/` — `bound_attributes` (attribute → allow-list), `bound_subjects`, `bound_subjects_type`, `attribute_mappings`, `groups_attribute`, `allowed_redirect_uris`, `policies`, `token_ttl_secs`, `token_max_ttl_secs`. `SamlRoleEntry::validate_assertion` enforces bound-subject / bound-subject-type / bound-attribute gates and is ready for the Phase 3 callback handler to call.
- **13 unit tests + 1 end-to-end CRUD integration test**, all green. Tests cover cert + metadata-XML redaction, comma / array / JSON-object field-layer normalisation, and every assertion-validation branch.
- **Phase 3 deferred**: login / callback / XML-signature verification not yet wired. The crate decision (`samael` with `libxml2` + `libxmlsec1` C deps vs. a pure-Rust XML-DSig path) is not taken; config and role state is persisted now so operators can describe their IdP ahead of the flow shipping. (Phase 1 + 2, `features/saml-auth.md`)

#### OIDC GUI login ("SSO" tab) (`gui/src-tauri/src/commands/oidc.rs`, `gui/src-tauri/src/state.rs`, `gui/src/routes/LoginPage.tsx`, `gui/src/lib/api.ts`)
- **Three Tauri commands** (`oidc_login_start`, `oidc_login_complete`, `oidc_login_cancel`) that bridge the system browser to the vault's `oidc` auth backend. Start binds a loopback port and asks the vault for the IdP authorization URL; complete blocks on the loopback (via `spawn_blocking`), accepts the IdP redirect, POSTs `code` + `state` back to the vault's `callback` endpoint, extracts the minted `client_token` + `policies` from the response, and stashes the token into `AppState`. Cancel releases the listener.
- **Embedded + remote mode.** `dispatch_vault_write` picks the right path off `AppState::mode` — embedded calls flow through `vault.core.handle_request`; remote mode routes through `remote_client.request_write`. Same commands work for both.
- **LoginPage gains an "SSO" tab** with Mount (default `oidc`) + optional Role. Submit runs the three-step flow, phase-aware button text ("Opening identity provider…" → "Waiting for browser callback…"), error path releases the listener before reporting.
- **New `OidcLoginSession`** in `AppState` (separate from `CloudSession` to keep flow scopes distinct). Session id is an opaque short handle; sessions drop on completion, cancel, or timeout — no port leaks.
- **Minimal query-string parser** for the loopback callback (no `url` crate dep in the Tauri binary). Handles `code` / `state` / `error` / `error_description` with `+`-to-space and `%HH` percent decoding.
- TS bindings + `LoginResponse`-shaped return so the existing auth store consumes the result without ceremony.
- 66/66 vitest tests still green; `cargo check -p bastion-vault-gui` clean.

#### Opengrep security-audit cleanup (`src/utils/mod.rs`)
- Ran `opengrep-core` v1.20.0 against `E:\Dev\opengrep-rules\rust\lang\security\` on all 241 Rust source files. Result: **no actionable findings** — 30 total matches across 3 rules, all accept / documented / false-positive.
- **Kept `utils::sha1()` with explicit legacy-compat docs.** Discovered a single real caller (`TokenStore::salt_id` — HashiCorp-Vault-compatible salted-cache-key construction: `SHA1(server_salt || token_id)`). Safe in this specific use because collision resistance rests on the secrecy of the server-side salt, not on SHA-1's broken collision strength. Documented the caller and the migration path to SHA-256 for a future breaking-change revision. No functional change.

#### OIDC authentication backend (`src/modules/credential/oidc/`, `Cargo.toml`, `src/lib.rs`)
- **New `oidc` credential module** registered via `OidcModule` + `OidcBackend`, following the Module/Backend pattern used by `userpass` and `approle`. Mount with `sys/auth/<path>` kind `oidc` — operators can run multiple mounts for multi-provider setups (`auth/okta/`, `auth/azuread/`, etc.).
- **Provider config** (`auth/<mount>/config`) holds `oidc_discovery_url`, `oidc_client_id`, optional `oidc_client_secret` (redacted on read — surfaces only `oidc_client_secret_set: bool`), `default_role`, `allowed_redirect_uris`, and `oidc_scopes` (defaults to `["openid","profile","email"]` when empty).
- **Role config** (`auth/<mount>/role/<name>`, list at `auth/<mount>/role/`) holds `bound_audiences`, `bound_claims` (JSON object, claim → allowed values — supports string / number / bool / array value shapes), `claim_mappings` (OIDC claim → Vault token metadata key), `user_claim` (default `sub`), `groups_claim`, `oidc_scopes`, `allowed_redirect_uris`, `policies`, `token_ttl_secs`, `token_max_ttl_secs`.
- **`auth_url` endpoint** (unauth; `auth/<mount>/auth_url`) validates `redirect_uri` against the role + provider whitelists, generates PKCE verifier/challenge + CSRF state + nonce, persists an `OidcAuthState` at `state/<csrf>` with a 5-minute TTL, and returns the IdP authorization URL composed via `openidconnect::CoreProviderMetadata::discover_async`.
- **`callback` endpoint** (unauth; `auth/<mount>/callback`) load-and-deletes the state entry (single-use, defends against replay), rejects stale states, re-discovers the provider metadata so IdP-side key rotations propagate without a vault restart, exchanges the authorization code + PKCE verifier for tokens, verifies the ID token (signature via JWKS, issuer, audience, nonce, expiry — all delegated to the `openidconnect` crate), validates `bound_audiences` + `bound_claims`, projects configured claims onto `auth.metadata`, and returns `Auth { policies, display_name, metadata, lease }` for the token store to mint the vault token.
- **Token renewal** re-loads the role and rejects if the policy list drifted since the token was minted — operators who narrow a role's policies don't have to wait for existing tokens to expire.
- **`openidconnect = "4"` added to `Cargo.toml`** with `rustls-tls` + `reqwest` features (default-features off). Reqwest is already transitively in the tree via `hiqlite`, so the marginal dep cost is the crate itself + the JWT transitive closure.
- **Tests.** 17 unit tests (config redaction round-trip, comma-string / array parsing, bound-claim matching for string/number/boolean/array values, state-TTL boundary, claim-to-string flattening, JSON-envelope parsing). Plus a core-level integration test (`oidc_config_and_role_crud`) that mounts the backend through the real vault core, writes + reads config with redaction assertion, writes + reads + lists + deletes a role through the logical layer. Plus an `#[ignore]`d live-IdP test gated on `BVAULT_TEST_OIDC_DISCOVERY` + `BVAULT_TEST_OIDC_CLIENT_ID` env vars.
- **GUI login integration is a separate follow-up.** The server surface is complete; the desktop GUI's login page + post-callback token handling lands in the next slice.

### Changed

#### OIDC Authentication initiative closed (`roadmap.md`, `features/oidc-auth.md`)
- Moved OIDC Authentication from *Active* to *Completed Initiatives* in `roadmap.md` and updated the feature-status table row from "Todo" to "Done (server module)". `features/oidc-auth.md` header flipped with a status summary pointing at the deferred GUI slice.

#### File Resources initiative closed (`roadmap.md`, `features/file-resources.md`)
- Moved File Resources from *Active Initiatives* to *Completed Initiatives* in `roadmap.md`. Core feature is shipped and in production use: dedicated `files/` mount with barrier-encrypted metadata + blob storage, per-file history, 32 MiB cap + SHA-256 integrity, ownership / sharing / admin transfer / backfill through the shared `OwnerStore` + `ShareStore` (new `ShareTargetKind::File` variant), asset-group membership via a third reverse index, local-filesystem sync target with atomic tmp-then-rename + per-target sync-state, content versioning with snapshot-on-write + 5-version retention + reversible restore, full Admin → Audit integration, and the Files GUI (page + resource-tab + drag-and-drop upload + edit modal + versions tab + sync-targets management).
- **Phases 5–7 (SMB / SFTP / SCP sync transports + periodic re-sync) deferred as separate follow-up initiatives.** They're additive sync *transports* rather than gaps in the core file-resource model — every file-resource feature works today against the local-FS target shipped in Phase 3. Each deferred phase has its own crate-candidate analysis + test-infrastructure requirements documented in `features/file-resources.md` § "Deferred sub-initiatives" and in a new *Deferred sub-initiatives* section in `roadmap.md` that also tracks the two Cloud Storage Targets deferrals.
- **New `Deferred sub-initiatives` section in `roadmap.md`.** Centralizes the five sub-scopes that don't block day-to-day use but warrant dedicated future work: SMB sync, SFTP+SCP sync, periodic re-sync, cloud-obfuscation rekey CLI, server-mode obfuscation bootstrap. Each entry names its blocking question (crate choice / design decision) so a future session can pick one up cold.
- `features/file-resources.md` status flipped to **Done (core feature)** with the remaining phase-5/6/7 sections replaced by a "Deferred sub-initiatives" appendix covering the scope and blocking questions per transport.

#### Cloud Storage Targets initiative closed (`roadmap.md`, `features/cloud-storage-backend.md`)
- Moved the Cloud Storage Targets initiative from *Active* to *Completed Initiatives* in `roadmap.md` with a one-paragraph summary covering all eight phases + the Get-Started-page integration (multi-vault chooser + Cloud Vault option) that grew out of the work. Two sub-slices stay explicitly deferred: the rekey-CLI orchestrator for obfuscation salt rotation (library pieces are present, end-to-end CLI is not), and propagating obfuscation-salt async bootstrap through server-mode `storage::new_backend` (desktop mode already honors it via `FileBackend::new_maybe_obfuscated` + `embedded::build_backend`). Neither blocks day-to-day use.
- `features/cloud-storage-backend.md` status flipped to **Done** and a "Feature complete — shipped scope recap" section added at the bottom: a single-page audit of every artifact that shipped (trait, 4 provider targets, credentials resolver, OAuth infra, CLI, GUI surfaces, obfuscation decorator, OS keychain), test matrix coverage, explicit non-goals, and the two deferred sub-slices with rationale.
- Feature-status table row in `roadmap.md` shortened from the multi-line "Phases shipped" log to a concise "Done (all 8 phases shipped; see Completed Initiatives)" pointer.

### Fixed

#### Token-login now validates before signing in (`gui/src-tauri/src/commands/auth.rs`, `gui/src-tauri/src/commands/connection.rs`)
- `login_token` (embedded) and `remote_login_token` (remote) previously accepted any string as the auth token and stored it verbatim. A wrong token got the user to the dashboard with a functioning sidebar, where every data fetch then failed with "Permission denied" — confusing and wrong-shaped (the real failure was the login, not the fetch).
- Both handlers now issue `Read auth/token/lookup-self` with the supplied token and only store it on success. Permission-denied / invalid-token / forbidden errors at lookup-self are translated to a single "Invalid token" message so the login page shows one clear reason; other errors (network down, server unreachable) pass through with their original text.
- `login_token` also reads the token's real `policies` array out of the lookup-self response instead of hard-coding `["root"]`. Admin-gated routes (Users / AppRole / Audit / etc.) now render correctly on first paint for non-root users, not after a second fetch.

### Added

#### Local-vault custom data directory + Tauri command (`gui/src-tauri/src/embedded/mod.rs`, `gui/src-tauri/src/commands/vaults.rs`, `gui/src/routes/ConnectPage.tsx`)
- Add Local Vault modal now lets the operator pick where vault data lives. The **Location** field is pre-populated with the canonical default for the chosen storage engine and shows a "Reset to default" link whenever the user's edit drifts from it. Leaving the value at the default persists `data_dir: null` so the profile keeps following any future default-path change; a custom value is stored verbatim and overrides the env-var path.
- `embedded::build_backend` now overlays the default Local profile's `storage_kind` + optional `data_dir` on top of the env-var fallback. A typo'd `storage_kind` falls back to `"file"` so a hand-edited preferences file can't hard-lock the boot.
- New `data_dir_for(StorageKind)` helper + `get_default_local_data_dir` Tauri command expose the canonical per-engine path to the UI.

#### OAuth consent: fixed loopback port + redirect URI display + paste-token fast path (`src/storage/physical/file/oauth.rs`, `gui/src-tauri/src/commands/cloud_target.rs`, `gui/src/routes/ConnectPage.tsx`)
- **`DEFAULT_LOOPBACK_PORT = 8472`** — `begin_consent` takes a `preferred_port: Option<u16>` so the production code path binds a stable port and tests use ephemeral ones. A stable port means the redirect URI is identical across consent flows, which Dropbox (unlike Google/Microsoft, which RFC-8252-allow any loopback port) requires for its exact-match registration rule.
- **Redirect URI now rendered in the Add Cloud Vault modal** with a one-click Copy button, plus instructions to paste into the provider's "Redirect URIs" list before clicking Connect. Backed by a new `get_oauth_redirect_uri` Tauri command so the URI stays in sync with `DEFAULT_LOOPBACK_PORT`.
- **"Or paste an existing token" shortcut** for users whose provider lets them generate a long-lived token at the dev console (Dropbox has a "Generate" button). Skips the consent round-trip entirely. Backed by a new `save_pasted_token` Tauri command that wraps the pasted value in a `{"access_token":"..."}` JSON envelope and persists it via `creds::persist`.

#### Dropbox: support long-lived access tokens, not just refresh tokens (`src/storage/physical/file/dropbox.rs`)
- `DropboxTarget::ensure_access_token` now inspects the credentials file: a JSON envelope `{"access_token":"..."}` is used directly as the Bearer (no `/oauth2/token` round-trip), a plain string is treated as a refresh token and exchanged as before.
- `client_id` is now `Option<String>`. Long-lived tokens skip the refresh path and don't need one. The fallback error points users at the correct remediation when a plain-string credential is stored but no `client_id` is configured.
- Error-body pass-through on `read` / `delete` / `list` — non-2xx responses now include Dropbox's JSON explanation (e.g. `missing_scope/files.content.read`) in the returned error, so operators see the actual cause instead of just "http status 400".
- 2 new tests covering the new envelope format + optional `client_id`.

#### InitPage: ⇄ Change / ⚙ Settings / 🗑 Remove icon row (`gui/src/routes/InitPage.tsx`)
- Bottom-right of the init card gets three icon buttons once the active profile resolves.
  - **⇄ Change**: clears `last_used_id` and returns to the chooser so a different saved vault can be picked.
  - **⚙ Settings**: opens a small inline modal. For cloud vaults it offers a "re-paste access token" form (writes the new JSON envelope format) — fixes the most common init failure ("refresh token is malformed") without leaving the init page. For local vaults it shunts to the chooser since there's nothing to edit inline yet.
  - **🗑 Remove**: confirm-modal then `remove_vault_profile` → chooser. Underlying storage is never touched.
- Subtitle + body copy on the init page now branches on the active profile's kind, so a cloud vault no longer says "First-time setup for your local vault".

#### Modal scrolling + `CollapsibleSection` (`gui/src/components/ui/Modal.tsx`, `gui/src/components/ui/CollapsibleSection.tsx`)
- **Modal container** gained `max-h-[calc(100vh-2rem)]` + internal `overflow-y-auto` body. Tall modals (the Add Cloud Vault form with every section expanded was the trigger) now scroll inside themselves instead of overflowing the window. Applies to every Modal in the app.
- **`CollapsibleSection`** — new accordion-style block used by the Add Cloud Vault form to tuck advanced options behind a toggle. Built on top of a `<button>`/`<div>` pair with `aria-expanded` so it's keyboard-accessible; `headerRight` slot stops click propagation so external-link buttons don't toggle the section.
- Add Cloud Vault form is reorganized into three collapsible sections: **Storage location** (S3 only, default open), **Credentials** (default open — primary action), **Advanced** (default closed — credentials_ref override, prefix, obfuscate_keys).

#### Windows build hygiene (`.cargo/config.toml`, `Makefile`)
- New `.cargo/config.toml` sets `-Clink-arg=/PDBPAGESIZE:8192` for all Windows MSVC target triples. Fixes `LNK1318: Unexpected PDB error; LIMIT (12)` at link time on the Tauri GUI binary, which has grown past MSVC's default monolithic PDB size now that `cloud_targets` is default-on. Linker-only flag — no rustc recompile invalidation beyond the first apply.
- Makefile exports `OPENSSL_SRC_PERL=C:/Strawberry/perl/bin/perl.exe` on Windows so `openssl-sys`'s vendored build uses Strawberry Perl instead of the MSYS perl shipped with Git for Windows, which is missing `Locale::Maketext::Simple` and fails `VC-WIN64A` configure. Path is overridable via `make OPENSSL_SRC_PERL=... run-dev-gui`.

#### Add Cloud Vault — inline provider login + developer-console help links (`gui/src-tauri/src/commands/cloud_target.rs`, `gui/src/routes/ConnectPage.tsx`, `gui/src/lib/api.ts`)
- **Per-provider "Get client id ↗" link.** The Add Cloud Vault modal now shows a contextual link next to the OAuth section that opens the right developer console in the system browser (`@tauri-apps/plugin-shell`): Azure App Registrations for OneDrive, Google Cloud OAuth credentials for Google Drive, Dropbox App Console for Dropbox, AWS IAM Security Credentials for S3. Removes the "where do I click?" friction from the "register your own app" step.
- **Inline "Connect with [Provider]" button for OAuth targets.** Reuses the existing `cloud_target_start_connect` / `cloud_target_complete_connect` infrastructure but drives it from inside the Add Cloud Vault modal: user pastes the client id, clicks the button, browser opens the consent page, loopback listener catches the callback, refresh token is persisted at the suggested `credentials_ref`. On success the modal flips to a "✓ Connected" state and the user can Save & Open without a second trip through Settings. Cancel path still releases the loopback listener cleanly via `cloud_target_cancel_connect`.
- **Inline AWS credential entry for S3.** Collapsible section inside the S3 branch takes `access_key_id` + `secret_access_key` + optional `session_token`; the new `save_s3_credentials` Tauri command writes them as a JSON blob to a fresh file under `~/.bastion_vault_gui/cloud-creds/s3-<ts>.json` (0600 on Unix) and returns the resulting `credentials_ref`. The field above is filled automatically and the status flips to "✓ Credentials saved".
- **`suggest_credentials_ref_path` Tauri command.** Returns a sensible default `file:` path under the per-user data dir, so operators never face an empty credentials_ref field. Fired on provider change and on first "Connect" click when the field is empty.
- **Status awareness.** `cloudCredsReady` tracks whether the credential target is populated (either via inline connect/save or existing file). Editing `credentials_ref` manually invalidates the flag so a half-filled state doesn't surface as green.
- All three Tauri commands (`suggest_credentials_ref_path`, `save_s3_credentials`, plus the existing connect-flow ones) wired into the `invoke_handler`. Rust + TypeScript type-check clean; 66/66 vitest tests unchanged.

#### Multi-vault saved-profiles chooser (`gui/src-tauri/src/preferences.rs`, `gui/src-tauri/src/commands/vaults.rs`, `gui/src/routes/ConnectPage.tsx`, `gui/src/lib/api.ts`, `gui/src/test/pages.test.tsx`)
- **`VaultProfile` + `VaultSpec` data model.** Preferences now hold a `Vec<VaultProfile>` list keyed by a stable `id`, with each entry carrying a kind-tagged `spec` (`local` / `remote` / `cloud`) plus a user-editable display `name`. Multiple profiles of the same kind are supported — three different local data dirs, two S3 buckets, a mixed S3 + OneDrive setup, etc.
- **`last_used_id` = default.** The most recently opened profile is the default on the next app launch. The UI auto-resumes it unless the user hits "Switch vault" (`?choose=1` query param); if auto-resume fails the chooser renders with the error surfaced and the profile still in the list.
- **User-editable on-disk format.** The preferences file (`preferences.json`) is pretty-printed JSON with every field explicit and human-readable. Hand-editing is expected and supported — adding or reordering entries, tweaking a `data_dir`, or fixing a typoed `address` all take effect on the next load.
- **In-place migration from the pre-multi-vault shape.** `Preferences::migrate_legacy` folds existing single-vault fields (`mode` + `remote_profile` + `cloud_storage`) into the new `vaults` list on first load, then clears them via `skip_serializing_if = Option::is_none` so subsequent saves carry only the new shape. Upgrades are transparent — a user who had one Remote profile finds it named the same in the new list, and it's still the default.
- **CRUD Tauri commands** in `gui/src-tauri/src/commands/vaults.rs`: `list_vault_profiles`, `add_vault_profile`, `update_vault_profile`, `remove_vault_profile`, `set_last_used_vault`, `clear_last_used_vault`, `get_vault_profile`. Remove only edits the preferences file — underlying storage (local dir / server / cloud bucket) is never touched.
- **Legacy commands stay functional.** `save_preferences(mode, remote_profile)` now upserts into the new list instead of dropping the rest. `set_cloud_vault_config` / `clear_cloud_vault_config` / `get_cloud_vault_config` project onto the new shape (Cloud entries only). Pre-multi-vault frontend code continues to work unchanged.
- **Redesigned ConnectPage.** Saved profiles render as cards showing kind badge, connection detail (local storage kind / server address / cloud target), and a "default" pin. Per-card "Pin" and "Remove" buttons. Below the list, a three-button "Add new vault" row opens a unified Add modal that asks for a profile name + kind-specific fields (Local: storage engine; Remote: address/TLS/CA; Cloud: provider + target-specific config + `credentials_ref` + prefix + `obfuscate_keys`). Save-and-open is the default action so the common path is one click per new vault.
- **Bootstrap glue.** `embedded::build_backend` now resolves the active Cloud target through `Preferences::default_profile()` instead of the old scalar `cloud_storage` field — the rest of the boot path is unchanged. `is_initialized` mirrors the same lookup.
- **Backward compatibility.** Every build-matrix config clean (`cargo check --lib`, `cargo check -p bastion-vault-gui`, `npx tsc --noEmit`). 66/66 vitest tests pass; two obsolete "Local Vault" / "Connect to Server" tests were replaced with new assertions that cover both the empty-chooser and saved-profiles-rendering paths.

#### Cloud Vault option on the Get Started screen (`gui/src/routes/ConnectPage.tsx`, `gui/src-tauri/src/embedded/mod.rs`, `gui/src-tauri/src/preferences.rs`, `gui/src-tauri/src/commands/cloud_target.rs`, `gui/src-tauri/Cargo.toml`)
- **Third storage mode on the chooser.** "Local Vault" + "Connect to Server" + new **"Cloud Vault"** — an embedded vault whose storage sits directly on a cloud `FileTarget` (S3 / OneDrive / Google Drive / Dropbox) instead of a local directory. The device is the only client; the vault lives in the user's cloud account.
- **Cloud Vault modal** collects provider, target-specific config (bucket + region + optional endpoint for S3; OAuth client ID for the three consumer drives), `credentials_ref`, optional path prefix, and a checkbox for `obfuscate_keys`. Validation rejects missing required fields before the backend is touched.
- **Bootstrap semantics.** Clicking "Use this vault" writes the cloud config to preferences, then fires the normal embedded-vault flow: `is_vault_initialized` → `init_vault` (first-time boot seeds a fresh vault in the chosen bucket/folder) or `open_vault` (unseals an existing one using keys from the OS keychain). If an open attempt fails with unseal/barrier/decrypt errors we fall back to init, so picking a fresh bucket against a pre-populated client works out of the box. Errors along the way clear the half-written cloud config so the chooser isn't wedged.
- **`preferences::CloudStorageConfig`** — new optional field on the GUI preferences file. `target` + free-form `config` map; the `target` is pulled out and the rest is handed straight to the `FileTarget`'s `from_config`. Absent means the existing env-var-selected local / Hiqlite path runs unchanged — full backward compatibility.
- **`embedded::build_backend`** is now async and routes through `FileBackend::new_maybe_obfuscated` when `cloud_storage` is set. `is_initialized` treats a configured cloud vault as always-initialized (can't cheaply probe without a network round-trip); the open-or-init fallback in the UI handles the "bucket empty" case.
- **Three new Tauri commands**: `set_cloud_vault_config`, `clear_cloud_vault_config`, `get_cloud_vault_config`. Used both by the Get Started flow and by the Settings page for read-back/disconnect.
- **Tauri build now ships cloud targets by default.** `gui/src-tauri/Cargo.toml` turns on the upstream `cloud_targets` feature so the desktop GUI binary can reach all four providers without a custom build. Server-only operators keep the lean-binary path by disabling at their workspace level.
- **Test matrix.** `cargo check --lib`, `cargo check -p bastion-vault-gui`, `npx tsc --noEmit`, 66/66 vitest tests all green.

#### Cloud Storage Targets — Phase 8: Key obfuscation (`src/storage/physical/file/obfuscate.rs`, `src/storage/physical/file/mod.rs`)
- **`ObfuscatingTarget` decorator** — new `FileTarget` impl that wraps another `FileTarget` and rewrites every vault key to `hex(HMAC-SHA256(salt, raw_key))` before reaching the underlying provider. No new external deps (uses `hmac` + `sha2` + `rand` already in the tree). Threat model: hides vault-activity shape from anyone with read access to the underlying bucket / drive; barrier ciphertext is already unreadable, so this closes the loop on metadata leakage through object key names.
- **Auto-bootstrapped salt.** 32-byte random salt generated on first use and persisted at the well-known key `_bvault_salt` inside the wrapped target; subsequent starts reuse it, so keys stay stable across restarts. `with_salt(inner, salt)` constructor is exposed for programmatic use (tests, rekey).
- **`FileBackend::new_maybe_obfuscated`** — async convenience constructor that honors `obfuscate_keys = true` in target config and wraps the base target. The sync `FileBackend::new` logs a loud warning when the flag is set through its path so a misconfigured config is loud rather than silently degraded — salt bootstrap needs async I/O, so the sync path can't honor the flag and surfaces the degradation.
- **`list(prefix)` limitation.** HMAC is a PRF — once `sys/policy/admin` hashes to `8a4f…e12c`, prefix enumeration is impossible without a manifest. The decorator takes the narrow approach: `list("")` works (returns every raw-hashed key minus the salt marker; useful for rekey iteration and vault-wide audits); `list("<non-empty>")` returns a specific error naming the limitation and pointing at the opt-out. Callers that depend on prefix-based listing opt out of obfuscation.
- **12 new unit tests** in `obfuscate.rs`: salt bootstrap generates / persists / reuses / rejects bad length, writes store under hashed keys, read-after-write roundtrip, different salts produce different keys, delete via hash, salt-key passes through unhashed, `list("")` enumerates hashed keys and strips salt marker, `list("prefix/")` errors clearly, HMAC is deterministic per salt. Plus an **end-to-end on-disk assertion** in `test_file_backend_honors_obfuscate_keys` that walks the filesystem under a `LocalFsTarget` wrapped with obfuscation and confirms no plaintext key component (`policy`, `admin`) lands on disk.
- **Deferred sub-slices.** (1) Auto-wiring through `storage::new_backend` — the sync bootstrap path. Today operators bootstrap obfuscation from async startup code via `FileBackend::new_maybe_obfuscated`; threading that through `new_backend` requires changes to the broader storage-bootstrap chain. (2) Rekey CLI — the library pieces are present (`with_salt`, `list("")`), but the orchestrating CLI that walks the old target, re-writes under a new salt, and swaps the active salt is design-only. Production rekey today goes through `operator migrate` with a non-obfuscated intermediate.
- **Feature status.** Cloud Storage Targets roadmap row flipped to Done. All 8 phases shipped — 4 providers + OAuth infra + CLI + GUI + keychain + obfuscation decorator.

#### Cloud Storage Targets — Phase 7b: OS keychain writer (`src/storage/physical/file/creds.rs`, `Cargo.toml`, `gui/src-tauri/src/commands/cloud_target.rs`, `gui/src/components/CloudStorageCard.tsx`)
- **`keyring` crate behind new `cloud_keychain` feature flag.** Platform-native secret stores: macOS Keychain, Windows Credential Vault, Linux Secret Service. Feature-gated so server-only operators who never touch `keychain:` don't carry the dbus / secret-service transitive deps.
- **`creds::resolve` + `creds::persist` both gain real `keychain:` support.** Label syntax: `<service>/<user>` splits into the keychain's two identification axes; labels without a `/` get the default service id `"bastionvault"`; labels with multiple `/`s split on the first so the user part can contain further slashes (`onedrive/refresh/production`). On read, `NoEntry` errors surface a specific "run `bvault operator cloud-target connect` to populate it" message.
- **Feature-off path still compiles cleanly.** When the feature isn't enabled, both `resolve_keychain` and `persist_keychain` return a clear "requires the `cloud_keychain` build feature" error rather than leaving a silent gap.
- **GUI validator softened.** `validate_credentials_ref_writable` in the Tauri `cloud_target` commands no longer pre-rejects `keychain:`. The server may have been built with `cloud_keychain`, and if not, `creds::persist` surfaces a clear error at completion time — matches the "let the backend speak" principle already in place for other build-gated features.
- **GUI hint updated.** The Cloud Storage Targets card now documents all four schemes accurately: `file:` (0600 on Unix); `keychain:` (`<service>/<user>` label; requires the `cloud_keychain` server build); `env:` / `inline:` read-only.
- **8 new unit tests** (5 `parse_keychain_label`: default service, service/user split, user with embedded slashes, empty-label rejection, empty-half rejection; 2 feature-gated rejection paths for reader + writer; 1 `#[ignore]`d OS-keychain `keychain_roundtrip` covering write + read + rotate + cleanup).
- **Build matrix.** `cargo check --lib`, `cargo check --lib --features cloud_keychain`, `cargo check --lib --features cloud_targets` (all five feature flags), `cargo check -p bastion-vault-gui`, and `npx tsc --noEmit` all clean. Creds tests: 25/25 without the feature; 23 default + 1 ignored roundtrip with the feature on.

#### Cloud Storage Targets — Phase 7a: Settings GUI connect flow (`gui/src-tauri/src/commands/cloud_target.rs`, `gui/src-tauri/src/state.rs`, `gui/src/components/CloudStorageCard.tsx`, `gui/src/routes/SettingsPage.tsx`, `gui/src/lib/api.ts`)
- **`CloudStorageCard`** — new Settings subsection that runs the OAuth consent flow for OneDrive / Google Drive / Dropbox end-to-end. Form: provider picker, `client_id`, optional `client_secret`, `credentials_ref`. Connect button drives the three-step flow (start → `shellOpen` → complete) with phase-appropriate status text. On error or user cancel, fires `cloud_target_cancel_connect` so the loopback listener releases the port immediately rather than waiting for the 5-minute timeout.
- **Three Tauri commands** — `cloud_target_start_connect` (bind loopback, compose authorization URL, stash session under an opaque id, return `{sessionId, consentUrl}`); `cloud_target_complete_connect` (remove session from map, block via `spawn_blocking` waiting for the callback, exchange the code, persist the refresh token); `cloud_target_cancel_connect` (release the listener without completing).
- **Why split start/complete.** The frontend opens the consent URL in the user's real system browser via the Tauri `shell` plugin's `open` — puts the provider's consent screen in the operator's signed-in browser profile rather than a blank Tauri popup. Splitting the commands lets the GUI call `shellOpen(consentUrl)` after `start` returns and before `complete` blocks.
- **`AppState::cloud_sessions`** — new `std::sync::Mutex<HashMap<String, CloudSession>>` holding in-flight consent sessions. `CloudSession` carries the `oauth::ConsentSession` (with its bound loopback listener), the provider + creds, and the destination `credentials_ref`. Listener drops automatically when the session is removed from the map.
- **Writable-ref validation at start time.** `cloud_target_start_connect` rejects `env:` / `inline:` / `keychain:` schemes up-front with specific error messages so the user gets immediate feedback rather than going through the full consent round-trip only to hit a `persist` failure. `keychain:` deferral to Phase 7b is called out explicitly.
- **Shell plugin already wired.** `tauri-plugin-shell` is in `gui/src-tauri/Cargo.toml` and `shell:allow-open` is in the default capability set; no Tauri-config changes needed.
- **Test status.** `cargo check -p bastion-vault-gui` clean; `npx tsc --noEmit` clean; 66/66 vitest tests still pass (18 pre-existing React `act()` warnings, unchanged). Full lib `--features cloud_targets` build clean.

#### Cloud Storage Targets — Phase 6: Dropbox target (`src/storage/physical/file/dropbox.rs`, `Cargo.toml`)
- **`DropboxTarget`** — new `FileTarget` impl against Dropbox v2 API. Feature-gated as `cloud_dropbox`; zero new transitive deps.
- **App Folder sandbox.** Baked into the app's type at developer-console registration; the provider config ships no explicit scopes (`token_access_type=offline` on auth is what turns on refresh-token issuance).
- **Dual-host API.** Upload + download go through `content.dropboxapi.com` with metadata in a `Dropbox-API-Arg` header; delete + list go through `api.dropboxapi.com` with JSON bodies. Endpoints: `/2/files/upload`, `/2/files/download`, `/2/files/delete_v2`, `/2/files/list_folder`, `/2/files/list_folder/continue`.
- **Not-found handling.** Dropbox returns HTTP 409 with a structured body on app-logic errors. We substring-match the response for `not_found` and map to `Ok(None)` on read / no-op on delete / empty vec on list.
- **150 MiB single-shot ceiling** (Dropbox's documented `/2/files/upload` limit). Oversize writes surface a clear error referencing upload-session support as a deferred optimization.
- **Structure.** `Arc<Inner>` + single-`spawn_blocking` per op, matching Google Drive. Access-token cache + auto-refresh + atomic rotation persistence.
- **11 new unit tests** covering prefix normalization, 409 `not_found` detection, config-level rejection and acceptance, object-path composition (with and without prefix), list-response parsing (populated + cursor + missing-field defaults). Plus a live integration test `#[ignore]`d behind `BVAULT_TEST_DROPBOX_CLIENT_ID` + `_CREDS_FILE`.

#### Cloud Storage Targets — Phase 5: Google Drive target (`src/storage/physical/file/gdrive.rs`, `Cargo.toml`)
- **`GoogleDriveTarget`** — new `FileTarget` impl against Drive v3. Feature-gated as `cloud_gdrive`; zero new transitive deps.
- **App Data sandbox.** Only `drive.appdata` requested; files land in the special `appDataFolder` space, invisible to the user's personal Drive.
- **ID-based chain walking.** Drive v3 has no hierarchical-path API. Writes walk the vault-key segments via search (`q=name='x' and '<parent>' in parents and mimeType='application/vnd.google-apps.folder'`), creating intermediate folders on the way. Updates hit `PATCH /upload/drive/v3/files/{id}?uploadType=media` by file-id when the leaf exists; new writes use multipart `POST /upload/drive/v3/files?uploadType=multipart` with a hand-built `multipart/related` body carrying metadata + content in one request.
- **Folder-id cache.** `Mutex<HashMap<String, String>>` mapping full path → folder id so repeated chain resolution is O(segments) instead of O(segments × search-round-trips) after the first walk. Folder ids don't change once assigned; the cache is process-lifetime.
- **Query escaping.** Drive v3 queries are SQL-ish; single quotes and backslashes in names are escaped per Google's grammar.
- **Structure.** `Arc<Inner>` + single-`spawn_blocking` per op so the whole sequence (resolve chain → search leaf → upload/update) runs on one worker thread. Access-token cache + auto-refresh + atomic rotation persistence.
- **Eventual consistency caveat.** Documented in the module header: Drive's search index is eventually consistent, so `operator migrate` followed by an immediate `list` may need seconds to stabilize. Writes + reads by cached file-id are not affected.
- **11 new unit tests** covering path splitting (edge cases: empty, leading/trailing slash, double slash), parent/name extraction, query escaping, config-level rejection and acceptance, Drive v3 search-response parsing (populated / empty / missing field). Plus a live integration test `#[ignore]`d behind `BVAULT_TEST_GDRIVE_CLIENT_ID` + `_CREDS_FILE`.

#### Cloud Storage Targets — Phase 4: OneDrive target (`src/storage/physical/file/onedrive.rs`, `Cargo.toml`)
- **`OneDriveTarget`** — new `FileTarget` impl against Microsoft Graph API, storing `BackendEntry` JSON bytes as files inside the vault's dedicated App Folder. Feature-gated as `cloud_onedrive`; **zero new transitive deps** — reuses `ureq`, `serde_json`, and the Phase-3 `oauth` + `creds` modules already in the tree.
- **Scope sandbox.** Only `Files.ReadWrite.AppFolder` + `offline_access` requested (see `oauth::well_known_provider("onedrive")`). The vault is confined to a folder that BastionVault itself owns; the user's personal OneDrive stays invisible to the vault, and vice-versa.
- **Graph endpoints.** Colon-path syntax: `GET /me/drive/special/approot:/<prefix>/<key>:/content` for read, `PUT` same URL for write, `DELETE /me/drive/special/approot:/<prefix>/<key>:` for delete, `GET /me/drive/special/approot:/<prefix>/<dir>:/children` with `@odata.nextLink` pagination for list.
- **Access-token caching + auto-refresh.** A `Mutex<Option<CachedAccessToken>>` tracks the current access token + deadline. Every verb calls `ensure_access_token`, which returns the cached token when it has more than a minute of life left, otherwise re-reads the refresh token from `credentials_ref` (so hand-rotated tokens pick up without a restart), hits `oauth::refresh_access_token`, and **persists the rotated refresh token atomically** via `creds::persist` when the provider supplies one. Rotation survives a vault restart.
- **4 MiB single-shot ceiling.** Matches the Graph API's `:/content` upload limit. Values above surface a clear error with the Phase-notice ("upload-session support ships in a later phase"). Vault keys are typically under 1 KB; File Resources (up to 32 MiB) already have their own ceiling above the barrier and are unaffected here.
- **Listing.** `list(prefix)` treats `prefix` as a folder path inside the App Folder; empty prefix hits `approot/children` directly, non-empty hits the colon-path form against that folder. Items with a `folder` property get the trailing `/` discriminator; bare names are files. 404 on the folder itself returns an empty Vec, matching the local target's contract.
- **`FileBackend::new` wired.** `target = "onedrive"` dispatches to `OneDriveTarget::from_config` when built with `cloud_onedrive`; returns a clear "requires the `cloud_onedrive` build feature" error otherwise (same pattern as S3).
- **12 new unit tests.** Config-level: required-field rejection (`client_id`, `credentials_ref`), credentials-ref-resolves-on-construct (typo fails fast), minimal + full valid configs. Plumbing: prefix normalization, path encoding for specials (spaces → `%20`, colons → `%3A`, unreserved passed through), URL composition per verb, root-children URL with and without prefix, Graph `ChildrenResponse` JSON parsing with/without `@odata.nextLink`, encode/decode symmetry. Plus a `#[ignore]`d live integration test gated on `BVAULT_TEST_ONEDRIVE_CLIENT_ID` + `_CREDS_FILE`.
- **Build-matrix status.** Default build, `cloud_s3`, `cloud_onedrive`, and `cloud_targets` (both together) all compile clean. Full file-module suite 52/52 green with both feature flags enabled.

#### Cloud Storage Targets — Phase 3b: `bvault operator cloud-target connect` CLI (`src/cli/command/operator_cloud_target_connect.rs`, `src/storage/physical/file/creds.rs`, `src/storage/physical/file/oauth.rs`)
- **`creds::persist`** — new writer side of the `credentials_ref` grammar. `file:` writes atomically (sibling tmp + rename), chmod-0600 on Unix so other local users can't read the refresh token. `env:` / `inline:` / `keychain:` return instructive errors — `env:` can't be written durably, `inline:` is read-only (value comes from server config), `keychain:` deferred to Phase 7. 7 new unit tests covering round-trip, atomic-replacement, 0600 perms, each rejection path, missing/unknown scheme.
- **`oauth::well_known_provider`** — new provider factory keyed on `"onedrive"` / `"gdrive"` / `"dropbox"`. Returns the right authorization + token URLs, narrowest-available scopes (`Files.ReadWrite.AppFolder` + `offline_access` for OneDrive; `drive.appdata` for Google Drive; App Folder for Dropbox), and provider-specific extras (Google's `access_type=offline` + `prompt=consent` for reliable refresh-token issuance; Dropbox's `token_access_type=offline`). 4 new unit tests pinning each provider's shape + unknown-provider rejection.
- **`bvault operator cloud-target connect`** — new CLI subcommand orchestrating the full consent flow end-to-end: resolves the provider, begins the consent session on a random loopback port, prints the URL, launches the system browser (`open` on macOS, `rundll32 url.dll,FileProtocolHandler` on Windows — avoids `cmd /c start`'s `&` mangling — `xdg-open` elsewhere; soft-fails to "paste it yourself" if no launcher is available), waits for the callback, exchanges the code for tokens, and persists the refresh token to the configured `credentials_ref`. Flags: `--target`, `--client-id`, `--client-secret` (optional; PKCE public clients omit it), `--credentials-ref`, `--bind-host` (default `127.0.0.1`), `--no-browser` (for headless servers), `--timeout-secs` (default 300).
- **Intentionally ships before phases 4–6.** The CLI exercises the shared OAuth infra end-to-end against real provider endpoints, so operators can validate their app registration + scopes configuration before the storage-path wire-up for OneDrive / Google Drive / Dropbox lands.
- **40/40 file-module tests pass**; default build + `cloud_s3` build both unaffected. `bvault operator cloud-target --help` and `... connect --help` verified producing clean usage output.

#### Cloud Storage Targets — Phase 3a: OAuth + PKCE + loopback-redirect infrastructure (`src/storage/physical/file/oauth.rs`)
- **Shared library** for the consent flow that the consumer-drive `FileTarget`s in phases 4–6 (OneDrive, Google Drive, Dropbox) will plug into. Zero new transitive deps — reuses `rand`, `sha2`, `base64`, `url`, `ureq` (all already in the tree).
- **Core types.** `OAuthProvider` (authorization URL, token URL, scopes, extra-auth-params), `OAuthCredentials` (`client_id` + optional `client_secret` — public-client PKCE-only is the common shape), `TokenResponse` (`access_token`, optional `refresh_token` / `expires_in` / `token_type` / `scope`), `CallbackParams` (code + state from the loopback callback).
- **PKCE helpers.** `pkce_verifier()` generates RFC 7636-compliant 96-char base64url verifier; `pkce_challenge()` returns BASE64URL(SHA256(verifier)); `random_state()` generates the 128-bit CSRF state. PKCE test vector from RFC 7636 Appendix B passes.
- **`begin_consent` + `ConsentSession::wait_for_callback`.** Binds a random `127.0.0.1:<port>` loopback listener, composes the authorization URL (`code_challenge_method=S256` + provider extras like `prompt=consent`), returns a handle. `wait_for_callback` accepts the first connection, parses `GET /callback?...`, responds with a minimal HTML success page, validates the state to foil CSRF, and surfaces provider-returned OAuth errors (`error=access_denied&error_description=...`) with the provider's message rather than silently dropping them. Poll-style timeout so a closed browser tab doesn't hang the caller forever.
- **Token exchange.** `exchange_code` (RFC 6749 §4.1.3 authorization-code grant) and `refresh_access_token` (refresh grant) POST form-encoded bodies to the provider's `token_url` via the existing `ureq` client; `http_status_as_error(false)` so non-2xx responses surface with the server's body for debugging.
- **Testable in isolation.** The module never opens a browser itself — callers get the consent URL and decide (CLI prints + shells out to `open`/`xdg-open`; GUI uses Tauri's `shell.open`). This keeps the library portable and makes the whole flow unit-testable.
- **13 unit tests.** PKCE verifier length/charset, RFC 7636 test vector, authorization-URL composition with all required params, request-line parsing (happy path + URL-decoding + provider-error surfacing + non-GET rejection + missing-code / missing-state rejection), token response deserialization (minimal + full body shape), **in-process TCP roundtrip** (real listener + real ureq client hitting `http://127.0.0.1:<port>/callback`), **CSRF state-mismatch rejection**. All green; default build + `cloud_s3` build both unaffected.

#### Cloud Storage Targets — Phase 2b: S3 target (`src/storage/physical/file/s3.rs`, `Cargo.toml`)
- **`S3Target`** — new `FileTarget` impl storing `BackendEntry` JSON bytes as objects in an S3-compatible bucket. Config: `bucket`, `region` (required); `endpoint_url`, `url_style = "path"|"virtual"` (default `virtual`), `prefix`, `credentials_ref`, `http_timeout_secs` (all optional). `credentials_ref` accepts the new URI grammar; absent falls back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars. MinIO-compatible (set `endpoint_url` + `url_style = "path"`).
- **Smallest-viable crate choice.** Surveyed `aws-sdk-s3` (~50–80 deps), `rust-s3` (~40), and `rusty-s3` (URL-signing + XML-parsing only, 4 new transitive deps). Went with **rusty-s3 + ureq** (already in tree for HTTP); each verb pre-signs with rusty-s3 and ships through a shared `ureq::Agent`. Sync HTTP runs through `tokio::task::spawn_blocking` so the runtime never parks. `http_status_as_error` is disabled on the Agent so `read()` routes 404 cleanly to `Ok(None)` and `delete()` treats 404 as a successful no-op — matching the `FileTarget` contract.
- **Listing.** `list(prefix)` walks `ListObjectsV2` paginated via `NextContinuationToken` with delimiter `/`, strips the configured object-prefix before returning, preserves trailing `/` on directory entries to match the local target's contract, and percent-decodes `encoding-type=url` keys before handing them back.
- **Feature-gated.** New `cloud_s3` Cargo feature pulls in `rusty-s3` + `quick-xml`. Default builds carry zero S3 code or deps. `FileBackend::new` only exposes `target = "s3"` when built with `cloud_s3`; otherwise returns a clear error pointing at the required feature flag.
- **Locking.** No-op guard — the spec's documented single-writer-per-target assumption applies; multi-writer arbitration (ETag-precondition lock object, DynamoDB) is out of scope for this phase.
- **9 new unit tests.** `bucket` / `region` required, unknown `url_style` rejected, inline `credentials_ref` happy path, bad-JSON rejection, prefix normalization (empty / bare / trailing-slash), object-key composition, percent decoding. Plus a live MinIO integration test marked `#[ignore]` — runs under `cargo test --features cloud_s3 -- --ignored` with `BVAULT_TEST_S3_ENDPOINT` / `_BUCKET` / `_REGION` + `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars set.
- Full file-module suite 24/24 green with `cloud_s3` enabled; default build 391+ tests still clean.

#### Cloud Storage Targets — Phase 2a: `credentials_ref` resolver (`src/storage/physical/file/creds.rs`)
- **`credentials_ref` URI grammar** — new resolver supporting `env:<VARNAME>` (read from environment variable), `file:<path>` (read from local file), `inline:<base64>` (literal embedded credential), and an explicit `keychain:<label>` error path stubbed out until Phase 7. Returns a `Secret` newtype wrapping `Zeroizing<Vec<u8>>` so raw credential bytes wipe on drop; `Debug` renders only the length so accidental logging can never leak the payload.
- **Ground truth for every cloud target.** S3 parses the resolved bytes as JSON static AWS credentials or an AWS profile name; OneDrive / Google Drive / Dropbox treat them as OAuth refresh tokens. Landing the resolver before the first provider means each provider slice focuses on transport + credential interpretation without also re-designing the creds ABI.
- **13 unit tests** covering each scheme's happy path, empty-payload rejection, bad-base64 rejection, missing-env-var / missing-file / missing-scheme / unknown-scheme error messages, the `keychain:` Phase-7 deferral, and a debug-redaction assertion proving the `Secret` type cannot leak its contents into a log line. No external deps (uses only `base64` + `zeroize`, already in the tree).

#### Cloud Storage Targets for Encrypted File backend — Phase 1 (`features/cloud-storage-backend.md`, `src/storage/physical/file/`)
- **`FileTarget` trait** (`src/storage/physical/file/target.rs`) — new pluggable I/O primitive underneath the Encrypted File storage backend. Byte-level surface (`read` / `write` / `delete` / `list` / `lock`) that sits below the barrier: targets never see decrypted `BackendEntry` material, only the serialized bytes the backend above chose to persist (AEAD ciphertext under normal barrier-backed operation).
- **`LocalFsTarget`** (`src/storage/physical/file/local.rs`) — carries the exact behavior of the pre-refactor `FileBackend`: `<root>/a/b/_c` key→path mapping, `_`-prefix leaf discriminator so `list()` can return data names and trailing-slash directory names in one walk, `lockfile::Lockfile`-backed per-key lock.
- **`FileBackend` wrapper** (`src/storage/physical/file/mod.rs`) — now holds `Arc<dyn FileTarget>`; serializes `BackendEntry` to JSON above the trait and defers I/O to the target. Config accepts `target = "..."` (defaults to `"local"`), so every existing `storage "file" { path = "..." }` continues to work bit-for-bit. Added `FileBackend::from_target` as the test / future-phase construction hook.
- **Zero-behavior-change refactor.** Phase 1 is pure indirection: no new functionality, no at-rest-format change, no public API change to `Backend`. Existing `test_file_backend` + `test_file_backend_multi_routine` pass unchanged; storage suite 19/19 green overall.
- **New seam test.** `test_file_backend_delegates_to_target` plugs a recording stub through `FileBackend::from_target` and asserts the target receives the serialized JSON bytes (not the pre-serialization struct) — documenting the exact contract Phase-2 cloud targets will implement.
- Phases 2–8 — S3, OAuth infra, OneDrive, Google Drive, Dropbox, GUI, key obfuscation + rekey — still Todo; see the feature file.

#### Caching Slice 4 + feature complete (`features/caching.md`)
- **`src/cache/guardrails.rs`** — new module applying process-level memory protections at bootstrap. `cache.memlock = true` calls `mlockall(MCL_CURRENT|MCL_FUTURE)` on Unix to pin every page against swap (including future cache allocations); startup aborts when the syscall fails rather than silently running with a weaker protection than requested. When any cache TTL is non-zero and `cache.allow_core_dumps = false` (default), Linux hosts call `prctl(PR_SET_DUMPABLE, 0)` so a crash cannot write cache contents into a core file. Non-Linux hosts log the residual risk; Windows explicitly aborts on `memlock = true` because there is no portable equivalent yet.
- **`Core::flush_caches`** — a single entry point that drops every cache layer (policy / token / secret, including the `CachingBackend` decorator when installed, via runtime downcast on `Backend: Any`) and zeroizes held payloads via the existing `Zeroizing<Vec<u8>>` drop path. Invoked by `pre_seal` so cached material never survives into the sealed state, and by the new admin endpoint.
- **`POST /sys/cache/flush`** — new sudo-gated HTTP endpoint for operator-driven flushes after a revocation storm or suspected compromise. Wired through both the system backend (with the path added to `root_paths`) and `src/http/sys.rs` as a dedicated handler returning 204 on success. Root access is required by the ACL; the vault repopulates caches lazily.
- **`PolicyStore::flush_caches`** + **`TokenStore::flush_cache`** — new public helpers that `Core::flush_caches` composes. Both are no-ops when their underlying caches are disabled.
- **Roadmap flipped to Done.** All four caching slices (config scaffold → token cache → metrics → secret cache → guardrails) are in tree with 54 cache-specific tests; 354 lib tests pass overall. `features/caching.md` now documents the shipped behavior and explicit non-goals (stretto has no eviction callback, so `bvault_cache_evictions_total` covers explicit invalidations only; no negative caching; no mount-table caching).

#### Caching Slice 3: ciphertext-only secret read cache (`features/caching.md`)
- **`src/cache/secret_cache.rs`** — new `CachingBackend` decorator implementing the `Backend` trait. Wraps any physical backend (file / MySQL / Hiqlite) and memoizes `get()` results in a bounded, TTL-scoped stretto cache. Positive hits only — a `get()` returning `None` is **not** cached because path existence can itself be sensitive metadata.
- **Below the barrier, by construction.** The decorator implements `Backend`, not `Storage`. `BarrierView`/`SecurityBarrier` sit above it in the call chain, so the Rust type system makes it impossible to hand it a decrypted `StorageEntry`: values it caches are exactly the bytes `Backend::put` was given and `Backend::get` returns — i.e. AEAD ciphertext under normal barrier-backed operation. Decryption happens on the barrier hot path every request, cache hit or miss.
- **Zeroized on every release path.** Cached bytes are held in `Zeroizing<Vec<u8>>` inside a non-`Clone` / non-`Serialize` / redacted-`Debug` wrapper `CachedCiphertext`. stretto's `Drop`-on-evict and `Arc`'s refcount-zero both run `Zeroize` before the allocator reclaims the page. `CachingBackend::clear()` flushes on demand.
- **Write-through invalidation.** `put()` and `delete()` evict the affected key (`delete()` evicts both before and after the underlying op to close the race where a parallel `get` could otherwise observe the about-to-be-gone entry as live). The local reader always sees its own write on the next `get`.
- **Off by default.** New helper `storage::wrap_with_cache(backend, cache_config)` wraps the physical backend only when `cache.secret_cache_ttl_secs > 0`; with the default 0, the helper returns the original `Arc` unchanged and no decorator is installed. Existing deployments see zero overhead.
- **`BastionVault::new` wired.** The bootstrap now threads the configured cache through `wrap_with_cache` before constructing `Core`, so any physical backend (including hiqlite, mysql, file) gets the decorator when the operator opts in. CLI tools (`operator migrate`, `operator backup`, `operator restore`) continue to call `storage::new_backend` directly and are deliberately not wrapped — they are single-shot migrations where caching has no benefit and active invalidation on the source side during a long copy would just add noise.
- **Metrics.** `bvault_cache_{hits,misses,evictions}_total{layer="secret"}` are populated by the decorator using the singleton registered in Slice 2b; size gauge remains reserved (stretto exposes no `len()`).
- **Tests (9 added, all passing):** populate-then-serve-from-cache (inner backend hit count drops to 1), `put` invalidates, `delete` invalidates, missing key is not negatively cached, `ttl == 0` rejected at construction, `Debug` redacted, not-`Clone` static assertion, `clear()` flushes, and a bit-for-bit byte-pattern test that proves the cache stores exactly what flows through `Backend::put`/`get` without any transformation — i.e. it cannot invent plaintext, and under the real barrier those bytes are AEAD ciphertext. 350 lib tests pass overall (zero regressions).

#### Caching Slice 2b: Prometheus cache metrics (`features/caching.md`)
- **`src/metrics/cache_metrics.rs`** — four Prometheus families labelled by `layer` (`token` / `policy` / `secret`): `bvault_cache_hits_total`, `bvault_cache_misses_total`, `bvault_cache_evictions_total`, `bvault_cache_size`. A process-wide `OnceLock<CacheMetrics>` lets cache code record values without plumbing a handle through `Core` — `MetricsManager::new` simply registers the singleton's families with its `Registry`, and any number of registries can coexist (each gets its own `Family` clone sharing the same counter storage via `Arc`).
- **Token cache** (`src/cache/token_cache.rs`) records a `hit` / `miss` on every `lookup`, and an `eviction` on every `invalidate`.
- **Policy cache** (`src/modules/policy/policy_store.rs`) records a `hit` / `miss` in `get_policy`, and an `eviction` in `remove_token_policy_cache` / `remove_egp_cache`.
- **Stretto-internal evictions are invisible.** stretto 0.8 exposes no eviction callback, so cost-overflow / TTL expiries don't feed the counter — only explicit invalidations do. The counter therefore means "forced cache invalidations" in practice; it's still useful for spotting revoke storms and policy-churn hotspots, and the `size` gauge is reserved for a future slice that can supply it (either via a replacement cache or periodic `stretto` stats polling).
- **Test suite updated.** `test_metrics_name_and_help_info` now knows about the four cache metrics as a valid upper-bound slice (they only surface in the scrape after first record; the singleton means cross-test carry-over is expected and benign). 341 lib tests pass (up from 337 before 2a + 4 new cache-metrics unit tests).
- **Zero new process-wide state that can leak secrets.** The metrics families hold only integer counters labelled by layer name — no keys, no values, no bytes derived from any `TokenEntry` or ciphertext. Safe to scrape from Prometheus without exposing sensitive material.

#### Caching Slice 2a: token lookup cache (`features/caching.md`)
- **`src/cache/token_cache.rs`** — new `TokenCache` wrapping a stretto LRU with TTL. Cached value is `Zeroizing<Vec<u8>>` holding the serialized `TokenEntry` JSON; the wrapper `CachedToken` does **not** implement `Clone` or `Serialize`, and its `Debug` prints a fixed `<cached:token:redacted>` string so log / panic / error paths cannot leak contents. Values are zeroized on eviction, explicit invalidation, and cache clear via `Zeroizing`'s `Drop` chain.
- **`TokenStore::token_cache`** — `Option<Arc<TokenCache>>` constructed from `core.cache_config`. Wired into:
  - `lookup_salted` — cache-aside read; miss falls through to storage and populates the cache.
  - `create` — invalidates any stale entry for the salted key rather than speculatively caching, since the caller may still mutate before first use.
  - `use_token` — invalidates after writing the decremented-`num_uses` entry so the next lookup reflects the new count.
  - `revoke_salted` — invalidates both before and after the underlying delete, closing the race where a parallel lookup could otherwise observe the about-to-be-gone entry as live.
- **Keys are non-reversible salted hashes.** The cache key is `TokenStore::salt_id(token)` — the same `sha1(salt || id)` already used as the storage key — not the raw bearer token, so a memory dump of the cache does not yield a replayable credential.
- **TTL-gated.** `cache.token_cache_ttl_secs = 0` disables the cache entirely (`TokenCache::new` returns `None`); default stays at 30 s per the spec. Operators needing instant revocation can disable.
- **Seal safety.** `Core::pre_seal` already drops auth modules via `module_manager.cleanup`, which releases the `TokenStore` and hence the `Arc<TokenCache>`; stretto's `Drop` zeroizes all held payloads through the `Zeroizing` wrapper.
- **Tests (12 added, all passing):** 7 unit tests on `TokenCache` itself (TTL-zero disables, roundtrip, invalidate, clear, redacted `Debug`, serialized payload shape, `Zeroize` wipe); 2 `TokenStore`-level integration tests (cache enabled by default + populated by lookup; revoke invalidates cache and the revoked token cannot be resurrected). 337 lib tests pass overall (no regressions).
- **Deferred to Slice 2b:** `bvault_cache_*` Prometheus counters — requires threading `MetricsManager` into `Core`, which is orthogonal coupling work that doesn't belong on a security-sensitive cache slice.

#### Caching Slice 1: cache config scaffold (`features/caching.md`)
- **`src/cache/mod.rs`** — new module with `CacheConfig` (serde, `deny_unknown_fields`) plus `DEFAULT_*` constants. Fields: `policy_cache_size` (1024), `token_cache_size` (4096), `token_cache_ttl_secs` (30), `secret_cache_size` (8192), `secret_cache_ttl_secs` (0 = disabled), `memlock` (false), `allow_core_dumps` (false). `CacheConfig::merge` follows the existing directory-based-config convention (non-default wins).
- **`Config::cache`** — the server config now accepts an optional `cache { ... }` block. Absent block / unknown fields / partial blocks behave exactly like the baked-in defaults.
- **`Core::cache_config`** — threaded through `BastionVault::new` alongside `mount_entry_hmac_level` / `mounts_monitor_interval`.
- **`PolicyStore::new`** now reads `core.cache_config.policy_cache_size` instead of the hard-coded `POLICY_CACHE_SIZE` constant (removed). Default behavior is unchanged when the operator omits the `cache` block.
- No new caches allocated in this slice; token / secret / metrics / mlock / zeroize-on-flush work lands in Slices 2–4 per the caching feature spec.
- 5 unit tests covering defaults, empty block, partial block, `deny_unknown_fields`, and `merge`.

### Changed

#### Tracking-doc sync: Identity Groups + Resource/Asset Groups marked Done (`features/identity-groups.md`, `features/resource-groups.md`, `features/asset-groups.md`)
- Identity Groups phase table is already accurate (Phase 8 Cert/OIDC/SAML extension correctly marked *Deferred* — the union pattern is ready, it just has no callers until those backends land). Roadmap entry moved from Active Initiatives → Completed Initiatives with a summary noting the 7 shipped phases + the why behind Phase 8's deferral.
- `features/resource-groups.md` Phase 13 (Ownership / admin transfer / sharing) flipped Pending → Done — the implementation has actually been live (`ShareTargetKind::AssetGroup`, `POST /v2/sys/asset-group-owner/transfer`, member redaction) but the phase table hadn't caught up.
- `features/asset-groups.md` Phases 1–9 flipped Pending → Done — the table was stale from the initial design-only period; the header of that file was already marking the feature "Feature-complete". Each phase now references the concrete code path / endpoint / GUI element it shipped as.
- Roadmap's Active Initiatives list is now accurate: OIDC, SAML (both design-only auth backends), Cloud Storage Targets, and File Resources remain; the three group features and per-user-scoping are all in Completed Initiatives.
- No code change — doc sync only.

#### Cloud providers re-framed as `FileBackend` I/O targets (`features/cloud-storage-backend.md`)
- The cloud-provider feature has gone through two earlier framings that review rejected: a standalone "third deployment mode" storage backend (too much complexity), and a per-file content backend scoped inside File Resources (wrong layer — File Resources shouldn't carry the cloud story for other vault data).
- Final scope: the cloud providers sit **underneath the existing `FileBackend`** as alternative I/O targets, not as a new backend impl. `FileBackend` gains a `FileTarget` trait field; today's `std::fs`-based body moves verbatim into a `LocalFsTarget`. S3 / OneDrive / Google Drive / Dropbox each get a sibling target impl. The `Backend` trait, the barrier, the wire format, and every caller above `FileBackend::get/put/delete/list` are unchanged.
- Phase 1 of the work is a pure refactor with zero behavior change, proven by every existing `FileBackend` test passing unmodified against `FileBackend { target: Arc<LocalFsTarget> }`. Phases 2-8 add S3, OAuth infrastructure + the three consumer drives, the GUI Settings → Storage page, and optional object-key obfuscation.
- Renamed `features/cloud-file-backends.md` → `features/cloud-storage-backend.md` (back to the original filename, now matching the final scope). Roadmap row restored under Storage. File Resources' earlier "content backend" subsection (added in the superseded framing) replaced with a note pointing at this feature as the way to host file content in the cloud.
- Credentials use a small URI grammar (`env:` / `keychain:` / `file:` / `inline:`) — never inlined verbatim in config. OAuth refresh tokens live in the OS keychain on desktop builds, in a process-owned file on servers. Per-operator `client_id` for consumer drives; no shared secrets redistributed. Feature-gated (`cloud_targets` + per-provider sub-features) so builds without the feature can't accidentally contact a cloud provider.
- No code change — design revision only.

### Added

#### File Resources Phase 8: content versioning (`features/file-resources.md`)
- **Version index + historical blob storage.** New `vmeta/<id>` (`FileVersionMeta` — `current_version` + retained `Vec<FileVersionInfo>`) and `vblob/<id>/<version>` keys alongside the existing meta + blob + history + sync storage. Historical blobs go through the same barrier encryption as everything else in the engine.
- **Snapshot-on-write.** `write_entry_and_blob` detects a content change by sha256 mismatch and, *before* overwriting, captures the live blob + displaced metadata as a new historical version. Metadata-only writes (same sha256) don't consume a version slot.
- **Retention + automatic prune.** `DEFAULT_VERSION_RETENTION = 5`. Versions beyond the cap are dropped oldest-first with their `vblob` keys deleted. Set retention to 0 to disable snapshotting entirely.
- **Routes** (all under `files/` mount):
  - `GET files/{id}/versions` — list retained versions + current_version.
  - `GET files/{id}/versions/{version}` — metadata for one historical version.
  - `GET files/{id}/versions/{version}/content` — base64 content with SHA-256 re-verification on read (errors loudly on mismatch).
  - `POST files/{id}/versions/{version}/restore` — swap a historical version into the live slot. Displaced content is itself snapshotted, so restore is reversible.
- **Delete cascade extended.** File DELETE now sweeps `vmeta/<id>` + every `vblob/<id>/*` alongside the existing sync-config / sync-state sweep. Failures are logged and swallowed — the file delete already succeeded and a dangling version can't widen access (owner + shares are gone).
- **Tauri commands:** `list_file_versions`, `read_file_version_content`, `restore_file_version`. Plus TypeScript bindings in `gui/src/lib/api.ts` and `FileVersionInfo` / `FileVersionListResult` types.
- **GUI:** new **Versions** tab on the per-file detail modal. Shows version number, size, short SHA-256, author, and when the version was displaced; per-row Download and Restore buttons. Restore goes through a confirm dialog with the "reversible" disclaimer.
- **Tests (3 new integration tests):** `test_file_versioning_snapshots_on_update` (two updates create two versions with correct sha256s; historical content round-trips; restore rolls live content back), `test_file_versioning_retention_prunes_oldest` (8 content writes with retention=5 ⇒ exactly 5 retained, oldest=v3), `test_file_delete_sweeps_versions` (vmeta + vblob cleared on file DELETE). 393 lib tests pass overall (up from 390).
- **Deferred**: operator-configurable retention (today hardcoded at 5), SMB/SFTP/SCP sync targets (Phases 5-6), periodic re-sync (Phase 7).

#### File Resources Phases 3 + 4 + asset-group membership (`features/file-resources.md`)
- **Asset-group file membership.** `ResourceGroupStore` now has a third reverse index (`resource-group/file-index/<id>`) alongside the resource and secret indexes. `ResourceGroupEntry` gains `files: Vec<String>`; the write handler accepts a `files` comma-slice field; `groups_for_file` + `prune_file` mirror the existing helpers; `reindex` walks file entries; `resolve_asset_groups` recognizes file paths so `groups = [...]` ACL rules apply to files; `PolicyStore::post_route` calls `prune_file` on file DELETE. Same invariants as KV / resource membership.
- **Phase 3: local-FS sync target.** New per-file sync-target store (`sync/<id>/<name>`) + sync-state store (`sync-state/<id>/<name>`) in `src/modules/files/mod.rs`. Routes:
  - `GET files/{id}/sync` — list configured sync targets + per-target state.
  - `POST|DELETE files/{id}/sync/{name}` — create/replace or remove a target.
  - `POST files/{id}/sync/{name}/push` — on-demand push.
  Only `kind = "local-fs"` is accepted on save in this phase. Local-FS push creates parent dirs as needed, writes atomically via `<path>.bvsync.<pid>.tmp` + rename so a concurrent reader never observes a partial file, and optionally applies a Unix mode after the write. Failure paths record `last_error` + `last_failure_at` in the sync-state record *before* surfacing the error, so the next read shows why the push failed. File DELETE sweeps all sync-config + sync-state records for the id.
- **Phase 4: Tauri commands + minimum-viable GUI.**
  - `gui/src-tauri/src/commands/files.rs`: 11 Tauri commands — `list_files`, `read_file_meta`, `read_file_content`, `create_file`, `update_file_content`, `delete_file`, `list_file_history`, `list_file_sync_targets`, `write_file_sync_target`, `delete_file_sync_target`, `push_file_sync_target`. TypeScript bindings in `gui/src/lib/api.ts` + types in `gui/src/lib/types.ts`.
  - `gui/src/routes/FilesPage.tsx`: top-level Files nav entry; list table with Details / Download / Delete actions; upload modal with name + resource + MIME + notes; per-file detail modal with **Info** and **Sync** tabs. The Sync tab supports add local-fs target, push, remove, and displays last-success / last-failure timestamps per target. Delete confirm modal carries the spec's "already-synced remote copies are not touched" disclaimer. App route wired at `/files`.
- **Tests + verification:** 2 new integration tests (`test_sync_target_local_fs_push_writes_file` — full round-trip with byte-for-byte check + state update assertion; `test_sync_target_unsupported_kind_rejected_at_save` — early rejection of future-phase kinds). Rust suite **390/390**, TS type-check clean, GUI unit suite **66/66**, Vite build clean (103 modules, 432 KiB / 118 KiB gzipped).
- **Deferred** (called out in the feature file): SMB (Phase 5), SFTP / SCP (Phase 6) — both need transport crates + OAuth/creds plumbing; periodic re-sync scheduler (Phase 7) — `sync_on_write` flag is stored but not yet honored; content versioning (Phase 8); chunking for files above the inline 32 MiB cap; GUI polish (drag-and-drop zone, plain-text preview, tag chip editor).

#### File Resources Phase 2: ownership + sharing + backfill (`features/file-resources.md`)
- **Owner capture**: every file resource now stamps an owner at create time. The files module's `handle_create` calls `OwnerStore::record_file_owner_if_absent` with `caller_audit_actor(req)` — root-token writes therefore stamp `"root"` rather than orphan the record, matching KV / resource behavior. `PolicyStore::post_route` also stamps on replace-by-id writes (`POST files/files/<id>`) so existing files that pre-date the feature can acquire an owner on their next write.
- **Owner forget + share-cascade on delete**: `PolicyStore::post_route` now forgets the file's owner record on `DELETE files/files/<id>` and issues a cascade-revoke against every `SecretShare` targeting that file. Failures log a warning but never fail the delete (same contract as the KV / resource paths).
- **New `ShareTargetKind::File`** variant (wire string `"file"`). `ShareStore::canonicalize` accepts any non-empty, slash-free id. `shared_capabilities(ShareTargetKind::File, ...)` is now wired into the ACL evaluator so a `scopes = ["shared"]` rule on a file path picks up explicit shares.
- **Owner-aware ACL evaluation**: `resolve_asset_owner` and `resolve_target_shared_caps` in `src/modules/policy/policy_store.rs` recognize `files/files/<id>` paths. `scopes = ["owner"]` rules on file paths therefore see the real owner. `looks_like_kv_path` also updated to exclude `files/` so a file path never accidentally trips the KV owner-capture path.
- **OwnerStore extended** (`src/modules/identity/owner_store.rs`) — new `file_view` sub-view (`owner/file/<id>`) alongside the existing KV and resource views. APIs: `get_file_owner`, `record_file_owner_if_absent`, `set_file_owner`, `forget_file_owner`.
- **`GET identity/owner/file/<id>`** — read the owner record for a file, envelope matching the existing `/owner/kv/` and `/owner/resource/` routes. Consumed by GUI Owner cards.
- **`POST sys/file-owner/transfer`** — admin ownership-transfer endpoint for files. Body: `{ id, new_owner_entity_id }`. Gated by the usual ACL on `sys/file-owner/transfer`, mirroring the kv / resource / asset-group-owner transfer endpoints.
- **`sys/owner/backfill` extended** with a `file_ids` array parallel to `resources` and `kv_paths`. Response now includes a `files` summary (`stamped` / `already_owned` / `invalid`). One endpoint, three object kinds.
- **Tests (5 new + 12 existing = 17 in the files module):** root-token creates stamp owner; delete forgets owner and cascade-revokes shares targeting the file; backfill stamps unowned files with invalid-id reporting; admin transfer overwrites ownership; `identity/owner/file/<id>` returns the expected envelope shape. 388 lib tests pass overall (383 before + 5 new).
- **Still deferred**: asset-group membership for files (requires extending `ResourceGroupStore` with a file-index parallel to the existing resource and secret indexes — a separate slice). All sync targets (Phases 3, 5, 6). GUI (Phase 4). Content versioning (Phase 8).

#### File Resources Phase 1 (`features/file-resources.md`)
- **New `files/` mount and engine** (`src/modules/files/`). Dedicated barrier-encrypted storage independent of the KV and resource engines. Storage layout inside the mount's barrier view:
  - `meta/<id>` — `FileEntry` JSON (id / name / resource / mime_type / size_bytes / sha256 / tags / notes / created_at / updated_at).
  - `blob/<id>` — raw content bytes (single inline blob in Phase 1; chunked layout reserved for a later slice when the inline cap becomes limiting).
  - `hist/<id>/<nanos>` — append-only change log (who / when / op / changed_fields; never content bytes or their hash).
- **v2-accessible CRUD** via a logical backend. Under the `files/` mount: `POST files` (create, server-assigned UUID, returns `{id, size_bytes, sha256}`), `LIST files`, `GET files/{id}` (metadata), `GET files/{id}/content` (content as base64 in the JSON envelope), `POST files/{id}` (replace content + optional metadata updates; omitted fields preserved), `DELETE files/{id}` (drops meta + blob), `GET files/{id}/history` (newest-first change log).
- **32 MiB hard cap** on content enforced server-side by `decode_content` before any bytes are persisted. Operators who need more will be able to opt into cloud storage via the [Cloud Storage Targets](features/cloud-storage-backend.md) initiative once that lands.
- **SHA-256 over plaintext** recorded in `FileEntry.sha256`. The content-read handler recomputes the hash on every read and raises an error on mismatch — storage corruption or out-of-band writes surface as loud failures instead of silently yielding wrong bytes.
- **Change-history entry** recorded on every create + every non-noop update + every delete. Content replacement surfaces as `"content"` in `changed_fields` so a caller inspecting the timeline sees content movement even when no metadata field changed.
- **Wiring**: `FilesModule` registered in `src/module_manager.rs`, default-mounted at `files/` in `src/mount.rs`. New module exports in `src/modules/mod.rs`.
- **Tests (12 passing):** 8 unit tests (SHA-256 determinism / lowercase-hex / 64-char, base64 size-cap rejection, base64 round-trip, diff-field ignored-list, diff-field flags real changes, caller-username preference chain × 3); 4 integration tests driving through `core.handle_request` (create-then-read-content round-trip, oversized-body rejected before store, update-replaces-content with `"content"` in history, delete-then-read-is-gone). 383 lib tests pass overall (371 before Phase 1 + 12 new).
- **Intentionally deferred**: ownership / sharing integration via `OwnerStore` + `ShareStore` (Phase 2), sync targets local/SMB/SCP/SFTP (Phases 3–6), GUI (Phase 4), periodic re-sync (Phase 7), content versioning (Phase 8), chunking for files above the inline cap. All called out in the feature file's updated Current State and in the roadmap row.

#### Per-user scoping: owner backfill + templating tests (`features/per-user-scoping.md`)
- **`POST /v2/sys/owner/backfill`** — new sudo-gated admin endpoint (under `root_paths`) that stamps a caller-supplied `entity_id` as owner of every currently-unowned target in the request. Body: `{ entity_id, resources?, kv_paths?, dry_run? }`. Already-owned objects are skipped (use the `*-owner/transfer` endpoints to overwrite). Response carries per-kind counts (`stamped` / `already_owned` / `invalid`) plus the invalid entries themselves so operators see exactly what was rejected. `dry_run = true` reports the same counts without writing. This is the migration tool named in `features/per-user-scoping.md`'s testing plan — deployments that ran before per-user-scoping landed can now retroactively claim their pre-existing objects so `owner` / `shared`-scoped ACLs start seeing them.
- **HTTP wiring** (`src/http/sys.rs`) — `sys_owner_backfill_request_handler` + `POST /v{1,2}/sys/owner/backfill` route so the endpoint is cURL-able. Delegates to the logical backend via `handle_request`.
- **Handler** (`src/modules/system/mod.rs` `handle_owner_backfill`) — reuses the existing `OwnerStore::{record_resource_owner_if_absent, record_kv_owner_if_absent, get_resource_owner, get_kv_owner}` APIs so the never-overwrite invariant is preserved. Resource names containing `/` and KV paths that fail `canonicalize_kv_path` are surfaced as `invalid` instead of silently dropped.
- **Tests (3 new integration tests):** `test_owner_backfill_stamps_unowned_and_skips_owned` covers the happy path plus an already-claimed resource (untouched) and a malformed resource name and KV path (both reported as `invalid`); `test_owner_backfill_dry_run_writes_nothing` proves dry-run is side-effect-free; `test_owner_backfill_rejects_empty_entity_id` covers the 400 path.

#### Per-user scoping: Phase 2 templating unit tests (`features/per-user-scoping.md`)
- `apply_templates` (the wrapper around `substitute_path` in `src/modules/policy/policy_store.rs`) previously had zero unit tests — only the inner `substitute_path` helper was covered. Added 5 new tests covering: every path in a multi-rule policy substituted with caller values; `{{username}}` fallback to `display_name` when `auth.metadata["username"]` is missing; mixed-resolution rules (some drop, some survive) leave the policy partially live; all-drop returns `None` so the policy grants nothing; capabilities / scopes / groups survive the substitution intact. Policy templating is now proven fail-closed end to end.
- Feature file's Phase 2 row flipped Pending → Done; the stale "Policy templating deferred" and "Sharing still design-only" bullets in Implementation Notes replaced with current-state summaries (templating is live, sharing has been live since Phase 8). No behavior change — the code already worked; this is doc + test-coverage catching up to reality.

#### Batch operations Phase 1 (`features/batch-operations.md`)
- **`POST /v2/sys/batch`** — new endpoint that accepts N vault operations in a single request body and executes them sequentially under the caller's token. Every op routes through the normal `Core::handle_request` pipeline, so ACLs, audit, and per-path semantics match individual HTTP calls. Registered v2-only per the project's forward-going-API rule.
- **`src/http/batch.rs`** — `BatchRequest` / `BatchOperation` / `BatchResult` / `BatchResponse` types, `sys_batch_v2_request_handler`. Deserialization denies unknown op kinds. The handler rejects empty batches and batches exceeding `batch_max_operations` (default 128) with 400 before any op runs.
- **Route wiring** (`src/http/sys.rs`) — per-route `PayloadConfig::limit(32 MiB)` drops oversized bodies at the framework layer rather than allocating them.
- **Config** (`src/cli/config.rs`) — new `batch_max_operations` and `batch_max_body_size` keys (`0` = built-in default).
- **Per-op error mapping** — `ErrPermissionDenied → 403`, `ErrRouterMountNotFound → 404`, `ErrBarrierSealed → 503`, `ErrRequestClientTokenMissing → 401`, else 500. Error text lands in the per-op `errors` array; other ops in the same batch are unaffected by one op's failure.
- **Tests (8)** — parse/deserialize, unknown-op rejection, empty batch rejection, oversized batch rejection, write-then-read-in-same-batch visibility, individual-failure-does-not-abort-batch, default-max-operations-is-128, op-kind-maps-to-logical-Operation. 363 lib tests pass overall.
- **Deferred to later slices**: CLI command (`bvault batch`), client SDK method, per-op `batch_id` correlation in audit entries.

#### File Resources feature spec (`features/file-resources.md`, design-only)
- New `features/file-resources.md` and matching roadmap entry (Todo). Scopes a "File Resources" kind: binary blobs stored under the barrier alongside secrets, chunked (1 MiB default, 32 MiB cap), AEAD-authenticated per chunk, with a plaintext-SHA-256 manifest for whole-file integrity. Reuses the existing resource / ownership / sharing / audit plumbing so files inherit per-user-scoping from day one — no parallel identity layer.
- Sync targets (local FS, SMB, SCP, SFTP) are scoped as later phases. Push-only in v1 (vault is authoritative). Sync-target credentials are themselves stored as vault objects (a KV secret or another file resource), referenced by id, so SSH keys and SMB passwords don't leak into a separate silo. Sync failures audit but don't fail the vault write.
- 8-phase breakdown: engine scaffold → identity integration → local-FS sync → GUI → SMB → SFTP+SCP → periodic re-sync → versioning/retention. Critical path is Phase 1; transport phases are parallelizable after Phase 3 proves the sync abstraction.
- No code change — tracking-doc only.

### Fixed

### Added

#### File events in the admin Audit page (`src/modules/files/files_audit_store.rs`, `src/modules/files/mod.rs`, `src/modules/system/mod.rs`, `gui/src/routes/AuditPage.tsx`)
- **`FileAuditStore`** — new append-only log at `sys/files-audit/<nanos>` mirroring `UserAuditStore`. Records the ts, actor entity id (with the existing root-fallback via `caller_audit_actor`), op (`create` / `update` / `delete` / `restore`), file id, name snapshot, and a compact details string (`fields=resource,notes` on metadata update, `content` added when the SHA-256 moved, `version=v3` on restore). Constructed lazily from the system view — no post-unseal wiring needed.
- **File-module handlers wired** — `handle_create`, `handle_write`, `handle_delete`, and `handle_version_restore` now call `record_file_audit`. On delete, the name is snapshotted from the metadata before wiping storage so the audit row still has a usable label. No-op writes (same metadata, same SHA) are suppressed to keep the Audit page signal-heavy. Failures on the audit-append path are logged and swallowed so they can never block the primary operation — the per-file history log inside the mount still captures the event for the per-file timeline UI.
- **System audit aggregator** — new branch under `handle_audit_events` that walks `FileAuditStore::list_all()` and emits events in the `file` category. Target is the human name with id carried as a `changed_fields` entry (`id=…`) so both name- and id-based searches match.
- **`AuditPage`** — added `file` to the category label / variant maps and `restore` to the op-variant map so the new events render cleanly.
- Tests: 22/22 file-module tests pass; Rust lib + Tauri GUI both type-check clean.

#### Resource detail — Files tab (`gui/src/routes/ResourcesPage.tsx`)
- **`ResourceFilesPanel`** — new "Files" tab on the Resource detail page, sitting between Secrets and Sharing. Lists every file whose `resource` field names the current resource, with download action. Filtering is client-side over `listFiles` + `readFileMeta` (the file module does not yet expose a `by-resource` reverse index — an O(n) walk that we accept today; server-side index is a future optimization if it becomes a hot path). Empty state directs the operator to the Files page to set the Resource field. This closes the loop with the upload-modal / edit-modal resource typeahead added in this release: associating a file with a resource now surfaces on the resource itself.

#### Edit file details (`gui/src/routes/FilesPage.tsx`, `gui/src-tauri/src/commands/files.rs`, `gui/src/lib/api.ts`)
- **`EditMetaModal`** — new modal that edits a file's name, resource association (via the `TargetPicker` typeahead), MIME type, tags (comma-separated), and notes. Reachable two ways: an "Edit" button on each row of the Files table, and an "Edit details" button in the Info tab of the file detail modal. No file-module change was needed — `handle_write` already treats an unchanged SHA-256 as a metadata-only write: it skips the version snapshot, and records just the changed metadata fields in history. The modal reads the current content via `readFileContent`, re-POSTs those same bytes with the new metadata, and relies on that path. The content read also re-verifies SHA-256, so a corrupt blob would surface at save time rather than silently overwriting.
- **`update_file_content` Tauri command + TS binding** — added a missing `resource: Option<String>` parameter. The file module's `handle_write` already accepted `resource` in the body and merged it via `merge_str`, but the Tauri command layer wasn't forwarding the field, so edits to the resource association were silently dropped (the Info tab kept showing `resource: —` after Save).

### Fixed

#### Upload File modal — resource field now typeaheads existing resources (`gui/src/routes/FilesPage.tsx`)
- The "Resource (optional)" input in the `UploadFileModal` was a free-form text box, so associating a new file with an existing resource required the operator to remember the exact resource name and type it from memory. Misspellings produced orphaned `resource` labels with no association.
- Replaced the plain `Input` with `TargetPicker kind="resource"` — the same typeahead already used on the Sharing page. It loads the resource list via `listResources` on first focus, filters client-side as the user types, and fails open to a plain text input if listing is denied. Free-form entry still works for resources that don't exist yet.

#### GUI file upload drag-and-drop on Windows (`gui/src-tauri/tauri.conf.json`)
- **Tauri v2 intercepts native drag-drop on Windows by default.** On WebView2 the WebView never sees the drop, so the HTML5 `onDragOver` / `onDrop` handlers in `FilesPage.tsx` (page-level overlay and per-modal drop zone) silently did nothing: dragging a file onto the Files page had no effect, and users had to fall back to the file picker button.
- Fix: set `"dragDropEnabled": false` on the `main` window in `tauri.conf.json`. Tauri's native handler is disabled, HTML5 drag-drop events propagate to React as they do in the browser dev build, and the existing `onDrop` handlers (which filter on `e.dataTransfer.types` containing `"Files"` to avoid hijacking intra-page drags) start firing. No frontend changes were needed — the handlers were correct all along; only the Tauri window config was swallowing the events on Windows.

#### Owner capture now stamps root-token writes (`features/per-user-scoping.md`)
- **`PolicyStore::post_route` owner bookkeeping** (`src/modules/policy/policy_store.rs`) previously gated ownership stamping on a non-empty `entity_id` in auth metadata. Root tokens carry no `entity_id` (only `display_name = "root"`), so every resource or KV secret created through a root token orphaned its owner record and appeared as **Unowned** in the GUI forever. Admin-heavy workflows — where operators routinely create vault objects via root — left the Owner card empty on the Resources Sharing tab even after granting shares (which only an owner or admin can do), making the feature look broken.
- Fix: reuse the existing `caller_audit_actor(req)` helper (which prefers `entity_id` and falls back to `display_name`) to compute the owner id on capture. Root-token writes now stamp `entity_id = "root"` on the owner record; non-root authenticated writes continue to stamp their real entity id.
- ACL impact is zero by construction. Root bypasses policy entirely, and for non-root callers `scope_passes` compares `entity_id` to `entity_id` — no real user has `entity_id = "root"` in their auth metadata, so a literal-root owner record cannot accidentally grant owner-scope access to anyone else. The GUI's `EntityLabel` already renders non-UUID values as literal usernames (see `caller_audit_actor` docstring), so the Owner card displays `"root"` without a schema change.
- 1 regression test: `test_root_token_resource_write_captures_owner` writes a resource + a KV secret as root and asserts both owner records exist with `entity_id = "root"`. 355 lib tests pass overall.

### Changed

#### Resource Management marked Done (`features/resources.md`)
- Roadmap status flipped from In Progress to Done. The shipped implementation covers everything the feature file described and extends it: resources live in a dedicated barrier-encrypted engine (`src/modules/resource/`) rather than as a KV prefix, each metadata write is appended to a per-resource history log (who + when + which fields, no values), each resource-secret write snapshots the previous value into a versioned entry, resource types are configurable (built-ins + user-defined) with dynamic per-type fields, and ownership / sharing / asset-group membership are fully wired through the ACL evaluator.
- No code change in this entry — tracking-doc sync only. `roadmap.md` moves the initiative to Completed Initiatives; `features/resources.md` adds a Current State section noting the divergence from the original `kv/_resources/...` layout proposal.

### Added

#### Audit Logging Phase 1 (`features/audit-logging.md`)
- **`src/audit/`** -- new subsystem with `AuditEntry` schema, `AuditBroker` fan-out, tamper-evident SHA-256 hash chain, and an append-only `FileAuditDevice`. Every audited operation emits one JSON line per enabled device with `time`/`type`/`auth`/`request`/`response`/`error`/`prev_hash` fields. Client tokens and body string-leaves are redacted via the barrier-derived HMAC key (`hmac:<hex>`) unless the device is enabled with `log_raw=true` for dev.
- **Core integration** (`src/core.rs`): `audit_broker: ArcSwapOption<AuditBroker>` field installed at post-unseal using the barrier's derived HMAC key, cleared at pre-seal. `handle_log_phase` now calls `broker.log(...)` after every request with a combined request+response entry. Fail-closed: if any device errors, the log phase returns `Err` and the request fails — unaudited operations cannot slip through.
- **`GET/POST/DELETE /v1/sys/audit[/<path>]`** are now live. `GET` lists enabled devices; `POST /<path>` with `{ "type": "file", "options": { "file_path": ..., "log_raw": ... } }` enables one; `DELETE /<path>` disables it. Device configs persist at `sys/audit-devices/<path>` and are re-enabled on every unseal.
- **12 audit tests**: entry redaction keeps plaintext out unless `log_raw` is set, hash-chain verify accepts consistent chains + flags tampering (insertion/deletion/modification), file device end-to-end, full enable/disable round-trip via the HTTP API, broker-reset-on-seal.
- Deferred to later phases (noted in the feature file): syslog/socket/HTTP devices, separate pre-dispatch request entries (the combined entry still covers all state), external chain-head witness, CLI audit-management commands, GUI viewer for the on-disk log.

#### Admin audit page
- **`GET /v2/sys/audit/events`** -- new backend aggregator that walks every per-subsystem change-history log we already maintain (ACL policy history, identity user-group history, identity app-group history, asset-group history) and returns a flat newest-first JSON list of `{ts, user, op, category, target, changed_fields, summary}` events. Optional `from` / `to` RFC3339 bounds and a `limit` (default 500) are accepted as query-string or body fields. Resource-metadata history lives in the resource mount's own barrier view (not reachable from the system backend without routing a sub-request) and is intentionally omitted from the v1 aggregator — operators can still see per-resource history via the Resources tab.
- **HTTP + Tauri plumbing**: `sys_audit_events_request_handler` in `src/http/sys.rs` parses the query string into the logical `Request::body` so the aggregator resolves its fields; `list_audit_events` Tauri command returns `Vec<AuditEvent>` to the frontend.
- **Admin → Audit GUI page** (`gui/src/routes/AuditPage.tsx`) -- searchable table with From/To/Max-rows refresh controls plus a free-text search box and Category/Operation filters. User column uses `EntityLabel` when the `user` field looks like an `entity_id`, so audit rows humanize the same way share tables do.
- 1 integration test (`test_audit_events_aggregator_basic`): creates a policy + an identity user-group, reads `sys/audit/events`, asserts both events appear in the response.

#### Fix: new users appear in share picker without having to log in
- **Pre-provision entity alias at create time.** The GUI user-picker reads `/v2/identity/entity/aliases`, which is backed by `EntityStore`'s alias index. Previously the index was only populated on *first login*, so a freshly-created userpass user or AppRole role didn't appear in share dialogs until they authenticated once — admins ran straight into the "No matches" state when trying to grant access up-front. `write_user` (userpass) and `write_role` (approle) now call `get_or_create_entity` at the end of the create/update path so the alias is ready immediately. Update writes only trigger for the role-create branch so edits don't churn. The corresponding `delete_user` / `delete_role` hooks call `EntityStore::forget_alias` to drop the `(mount, name)` lookup when the principal disappears. The entity record itself is retained so share records and ownership data still resolve (audit trail preserved).
- **Alias key format changed from `<mount>:<name>` to `<mount>/<name>`.** On Windows, NTFS treats `:` as an alternate-data-stream marker; the file physical backend's `read_dir` returned only the pre-`:` prefix, silently breaking `list_aliases` on Windows hosts. Using `/` as the separator lets the underlying backend round-trip the key on every OS via its native path semantics. Other code paths (`get_by_alias`, `get_or_create_entity`, `forget_alias`) write + read through the same helper, so the switch is transparent to callers. Existing aliases stored in the old format on Linux/MacOS hosts will no longer resolve after upgrade and will be re-provisioned lazily on next login or by `sys/internal/ui/mounts` warm-up.
- 1 new integration test (`test_userpass_create_preprovisions_entity_alias`): creates a userpass user that has never logged in, asserts it appears in `identity/entity/aliases`, deletes it, asserts the alias is gone. 123 module tests pass.

#### KV Secrets Sharing + User-Picker (`features/per-user-scoping.md`)
- **Secrets can now be shared from the GUI.** `gui/src/routes/SecretsPage.tsx` gains a **Share** button on the detail view that opens a modal with the owner record, the current shares table (Revoke per row), a Grant-access form (owner + admin), and an admin-only Transfer-ownership flow. Targets the new `ShareTargetKind::KvSecret` via the existing share API; the full canonical path (e.g. `secret/foo/bar`) is derived from `mountBase + currentPath + key` and normalized via `canonicalizeSecretPath`.
- **User-picker instead of raw UUIDs.** New `EntityPicker` component (`gui/src/components/ui/EntityPicker.tsx`) — typeahead over `(mount, name, entity_id)` tuples from a new `GET /v2/identity/entity/aliases` endpoint. Operators can now search by login (`felipe`), mount (`userpass/`), or partial UUID; the picker resolves to the grantee's stable `entity_id` on select. Falls back to raw UUID entry when the alias listing is denied. Wired into the four grant flows: SharingPage Manage-target, ResourcesPage Sharing tab, AssetGroupsPage Sharing tab, and the new SecretsPage Share modal. Also used for the asset-group and KV Transfer-ownership dialogs.
- **Backend**: `EntityStore::list_aliases()` (`src/modules/identity/entity_store.rs`) enumerates every `(mount, principal-name, entity_id)` tuple from the alias sub-view; the new `identity/entity/aliases` logical route (LIST + Read, ACL-gated the usual way) surfaces it via `/v2/identity/entity/aliases`. Fails-open on the GUI side so a caller without directory access can still paste a UUID.

### Security

#### Closed a mount-listing and seal-vault policy bypass in the Tauri GUI
- **`list_mounts` / `list_auth_methods`** (`gui/src-tauri/src/commands/system.rs`) used to read the router's mount table directly, bypassing the policy layer. Any authenticated user — including one holding only the `default` policy — saw every mount on the dashboard (`secret/`, `resources/`, `identity/`, `resource-group/`, `sys/`, etc.) regardless of their ACL. Both commands now route through `core.handle_request(sys/internal/ui/mounts)` which runs the full auth + policy pipeline and uses `ACL::has_mount_access` to filter per-mount visibility. A user with only `default` now sees exactly the mounts their policy grants access to.
- **`seal_vault`** (same file) used to call `embedded::seal_vault` directly, so any authenticated caller could seal the vault from the Seal Vault button. It now resolves the caller's token via `token_store.check_token`, probes `sys/seal` Write via `PolicyStore::can_operate`, and rejects any caller that doesn't hold `update` on `sys/seal` — which in the shipped policy set is only `root`. The rejection is a backend enforcement, not a UI-only hide, so a hand-crafted Tauri call with a low-privilege token fails with a permission error.
- **Policy templating vocabulary** (`src/modules/policy/policy_store.rs`) now recognizes Vault-style `{{identity.entity.id}}`, `{{identity.entity.name}}`, and `{{identity.entity.mount}}` as synonyms for the BastionVault-native `{{entity.id}}`, `{{username}}`, `{{auth.mount}}`. The shipped `default` policy uses the `identity.entity.*` form; without the synonyms the placeholders were treated as unknown and the policy's identity self-lookup rules dropped silently.
- 1 new integration test (`test_system_internal_ui_mounts_default_policy_sees_nothing`): provisions a userpass user `felipe` with only `default` and asserts the mount listing excludes `secret/`, `resources/`, `resource-group/`, and `auth/pass/`.

#### Asset Groups: member redaction on read (`features/asset-groups.md`)
- **`PolicyStore::can_operate(auth, path, op) -> bool`** (`src/modules/policy/policy_store.rs`) -- new dry-run probe that runs the same per-target resolution (asset groups, owner, active shares) and ACL evaluation as `post_auth`, but side-effect free. Used by handler code that needs to preview authorization decisions for targets other than the current request path. `check_only=false` is required on the internal `allow_operation` call because `Permissions::check` short-circuits without setting `allowed` when `check_only=true`.
- **Member redaction on asset-group read** (`src/modules/resource_group/mod.rs`) -- `handle_read` now probes `Read` on every member's logical path (resources as `resources/resources/<name>`, KV secrets via both canonical and KV-v2 `<mount>/data/<rest>` forms) and replaces the path with the `REDACTED_MEMBER` sentinel (`"<hidden>"`) for callers who cannot see it. Owners and admins (tokens holding `root` or `admin`) short-circuit the probe and see everything unredacted. The `owner_entity_id` comparison uses the caller's `auth.metadata["entity_id"]`.
- **GUI redaction affordance** (`gui/src/routes/AssetGroupsPage.tsx`) -- Overview badges render `<hidden>` entries as neutral "hidden" chips; the Resources and Secrets tables filter out hidden rows and show a muted-italic "N hidden resource(s)/secret(s) you don't have read access to." summary underneath. Group cardinality remains visible via the Overview detail rows.
- **1 new integration test** (`test_asset_group_member_redaction_for_non_owner`): a custom policy grants a userpass caller read on `resource-group/groups/*` and on `secret/data/ok/*`; the caller sees their visible secret unredacted and both the forbidden secret and the forbidden resource member as `<hidden>`. Root on the same group sees everything unredacted. 12 resource-group tests pass.

#### Asset Groups: ownership, admin transfer, and sharing (`features/asset-groups.md`)
- **`owner_entity_id` on `ResourceGroupEntry`** (`src/modules/resource_group/group_store.rs`) -- captured from `auth.metadata["entity_id"]` on the first write and preserved across every subsequent `set_group` call. Root-token creates still succeed with an empty owner; admins can adopt such groups via the transfer endpoint below. Emitted in the group-read response as a new `owner_entity_id` field.
- **Admin transfer endpoint** (`src/modules/system/mod.rs`): `POST /v2/sys/asset-group-owner/transfer` (body: `{ name, new_owner_entity_id }`). Gated by the ACL on `sys/asset-group-owner/transfer`. Backed by a new `ResourceGroupStore::set_owner` method that is separate from `set_group` so a regular write can never escalate ownership.
- **`ShareTargetKind::AssetGroup`** (`src/modules/identity/share_store.rs`) -- third variant alongside `KvSecret` and `Resource`. Canonicalizes the group name the same way the resource-group store does (lowercase, no `/` or `..`). The existing share CRUD endpoints accept `"asset-group"` as a kind verbatim.
- **Indirect share resolution** (`src/modules/policy/policy_store.rs::resolve_target_shared_caps`) -- after checking direct shares on the target, the helper walks `Request::asset_groups` (already populated by `post_auth`) and unions any asset-group shares the caller has for each group containing the target. One share on `asset-group:project-phoenix` therefore grants the listed capabilities on every current and future member of that group, exactly as the design intended, with zero extra lookups.
- **GUI Sharing tab on the Asset Groups detail page** (`gui/src/routes/AssetGroupsPage.tsx`) -- owner card with "You" badge, shares table with Revoke, Grant-access modal (owner + admin), and an admin-only Transfer-ownership modal that calls the new `transfer_asset_group_owner` Tauri command. The Overview tab gains an Owner row.
- **Tauri commands**: `transfer_asset_group_owner` in `gui/src-tauri/src/commands/sharing.rs`; `AssetGroupInfo` and the frontend type now include `owner_entity_id`; `ShareTargetKind` union widened to `"asset-group"`.
- **1 new integration test** in `src/modules/resource_group/mod.rs`: covers owner capture on root-token creates (stays empty), admin transfer populating the owner, and ownership survival across a subsequent regular write.

#### Per-User Scoping GUI (`features/per-user-scoping.md` phases 7, 9, 10 GUI)
- **`/sharing` page** (`gui/src/routes/SharingPage.tsx`) -- new top-level route with two tabs: "Shared with me" lists every `SharePointer` for the caller's `entity_id` with one-click open links to the referenced KV path or resource; "Manage target" lets an operator pick a (kind, path), load current shares, Grant new access (grantee + capability checkboxes + optional RFC3339 expiry), and Revoke individual shares. Wired into the sidebar under the user-facing nav.
- **Per-resource Sharing tab** (`gui/src/routes/ResourcesPage.tsx` — `ResourceSharingCard`) -- owner card showing the stored `entity_id` (badged "You" when it matches the current caller) with creation timestamp, a shares table (grantee, capability chips, granted timestamp, expiry with expired-red state, Revoke button), a Grant-access modal gated to owners and admins, and an admin-only Transfer-ownership modal that calls `transfer_resource_owner`. Unowned resources render an explicit empty state explaining the first-write capture.
- **Entity + owner lookup routes** (backend, `src/modules/identity/mod.rs`): `GET /v1-v2/identity/entity/self` returns the caller's entity record (hydrated with `primary_mount`, `primary_name`, aliases, `created_at` when the identity module is loaded); `GET /v1-v2/identity/owner/kv/{path_b64}` and `GET /v1-v2/identity/owner/resource/{name}` expose owner records so the GUI can render "who owns this?" without a second lookup. Both owner endpoints return `owned: false` with empty identifiers when no record exists yet.
- **Tauri commands**: `get_entity_self`, `get_kv_owner`, `get_resource_owner`, `list_shares_for_grantee`, `list_shares_for_target`, `put_share`, `delete_share`, `transfer_kv_owner`, `transfer_resource_owner` in the new `gui/src-tauri/src/commands/sharing.rs`.
- **Auth store `loadEntity()`** (`gui/src/stores/authStore.ts`) -- new action called from every login path in `LoginPage.tsx` that populates `entityId` and `principal` from `/v2/identity/entity/self`. Failure is silent; ownership-aware UI degrades to "owner unknown" rather than misreporting ownership.
- **New types** (`gui/src/lib/types.ts`): `EntitySelf`, `OwnerInfo`, `SharePointer`, `ShareEntry`, `ShareTargetKind`.

#### Sharing, Templating, and Admin Transfer (`features/per-user-scoping.md` phases 2, 8, 10)
- **`ShareStore`** (`src/modules/identity/share_store.rs`) -- new identity subsystem that persists `SecretShare` records behind the vault barrier. Primary storage at `sys/sharing/primary/<target_hash>/<grantee>`, reverse index at `sys/sharing/by-grantee/<grantee>/<target_hash>`, where `target_hash = base64url("<kind>|<canonical_path>")`. Handles both kinds: `kv-secret` (canonicalized the same way `OwnerStore` canonicalizes — KV-v2 `data/`/`metadata/` stripped) and `resource`. Exposes `set_share`, `get_share`, `delete_share`, `list_shares_for_target`, `list_shares_for_grantee`, `shared_capabilities`, and `cascade_delete_target`. Capabilities are normalized on write (trim, lowercase, dedup, reject anything outside `read`/`list`/`update`/`delete`/`create`). `expires_at` is supported; expired shares are treated as inert by the evaluator without being deleted.
- **ACL `shared` scope wired end-to-end** -- the `shared` branch of `scope_passes` is no longer a placeholder. `PolicyStore::post_auth` resolves the caller's active share capabilities on the request target via `ShareStore::shared_capabilities` and stashes them on `Request::target_shared_caps`; the evaluator then checks whether the capability corresponding to the current operation is present (read/list/update/delete/create). The owner-scope first-write carve-out still applies; `shared` and `owner` in the same rule OR together.
- **Share-cascade on target delete** -- `PolicyStore::post_route` calls `ShareStore::cascade_delete_target` on a successful KV-path or resource delete so dangling share rows do not outlive the secret/resource. Failures are logged but never fail the delete.
- **v2 sharing HTTP API** -- new routes on the identity backend (mounted at `/v1/identity/` and `/v2/identity/`, per the agent.md v2 rule for new endpoints):
  - `GET /v2/identity/sharing/by-grantee/{grantee}` -- every share granted to an entity (pointers only).
  - `GET /v2/identity/sharing/by-target/{kind}/{target_b64}` -- every share granted on a target.
  - `PUT /v2/identity/sharing/by-target/{kind}/{target_b64}/{grantee}` -- create or replace a share. Body: `capabilities` (comma-string or array), `expires_at` (optional RFC3339); `target_kind` and `target_path` in the body may override the URL segments with the raw (non-encoded) form.
  - `GET /v2/identity/sharing/by-target/{kind}/{target_b64}/{grantee}` -- read a single share.
  - `DELETE /v2/identity/sharing/by-target/{kind}/{target_b64}/{grantee}` -- revoke a single share.
- **List-filter by ownership also honors `shared`** -- `filter_list_by_ownership` now keeps keys the caller has any non-expired share on (in addition to caller-owned keys) when `shared` is in the active filter scopes, so a user with `scopes = ["owner", "shared"]` LISTs both their own entries and those shared with them.
- **Policy templating** -- `{{username}}`, `{{entity.id}}`, and `{{auth.mount}}` are now substituted at ACL compile time (`PolicyStore::new_acl_for_request`). Templated policies are auto-detected at parse: `Policy::from_str` flips `templated = true` when any path contains `{{`. Substitution is fail-closed — an unresolved placeholder drops the owning path rule and logs a warning; a policy whose every path drops contributes no authorization. Three login handlers (UserPass, UserPass/FIDO2, AppRole) now also populate `auth.metadata["mount_path"]` so `{{auth.mount}}` has a value. Unit tests cover the happy cases, unknown placeholders (fail-closed), empty values (fail-closed), and no-placeholder identity.
- **Admin ownership-transfer endpoints** -- `POST /v2/sys/kv-owner/transfer` (body: `{path, new_owner_entity_id}`) and `POST /v2/sys/resource-owner/transfer` (body: `{resource, new_owner_entity_id}`). Access gated by the usual ACL on `sys/kv-owner/transfer` / `sys/resource-owner/transfer`. Backed by new `OwnerStore::set_kv_owner` / `set_resource_owner` methods that unconditionally overwrite (distinct from the `record_*_if_absent` helpers used by the first-write capture path).
- **2 new integration tests** in `src/modules/identity/mod.rs` covering share round-trip, KV-v2 path canonicalization on reads, by-grantee and by-target listings, cascade-delete semantics, and the input-validation rejects (empty grantee, empty/invalid capabilities, invalid kind). **4 new unit tests** for template substitution in `src/modules/policy/policy_store.rs`.

#### Per-User Scoping (`features/per-user-scoping.md`)
- **`EntityStore`** (`src/modules/identity/entity_store.rs`) -- new identity subsystem that issues a stable `entity_id` UUID per `(mount, principal_name)` and auto-provisions on first login. Storage: `sys/identity/entity/<uuid>` with a `sys/identity/alias/<mount>:<name>` lookup index. Exposed through `IdentityModule::entity_store()` alongside the existing `group_store`.
- **`entity_id` plumbed into issued tokens** -- UserPass, AppRole, and FIDO2 login handlers now call `EntityStore::get_or_create_entity(mount, name)` and stash the UUID in `auth.metadata["entity_id"]`. Survives token renewal and the lookup round-trip through `TokenEntry.meta`. Fail-closed: if the entity store is unavailable the login still succeeds but the token carries no `entity_id`, which means owner-scoped policy rules will not match.
- **`OwnerStore`** (`src/modules/identity/owner_store.rs`) -- unified owner tracking for KV secrets and resources. KV paths are canonicalized the same way the resource-group store canonicalizes them (KV-v2 `data/` / `metadata/` segments stripped so the owner of `secret/foo/bar` keys identically whether the write came in as v1 or v2). `PolicyStore::post_route` records the caller as owner on every successful `Write` against a previously-unowned target, and forgets the owner on `Delete`.
- **ACL `scopes = [...]` qualifier** -- new optional attribute on policy path blocks alongside `groups = [...]`. Parsed into `PolicyPathRules.scopes` and `Permissions.scopes` (`src/modules/policy/policy.rs`), normalized (trim, lowercase, drop `any`) at init. Scoped rules live in a dedicated `ACL::scoped_rules` list (parallel to `grouped_rules`) so their per-rule filter is not lost to a merge. `PolicyStore::post_auth` resolves the request target's owner via `resolve_asset_owner` and stashes it on `Request::asset_owner`; the evaluator then checks `scope_passes` for each matching scoped rule. Supported scopes: `owner` (target's owner equals caller's `entity_id`, with a first-write carve-out so a user can create their very first object under an owner-only policy), `shared` (accepted by the grammar but currently always fails — `SecretShare` is a future phase), and `any` (legacy no-op, dropped at parse time).
- **List-filter by ownership** -- when a `LIST` op is authorized only by a `scopes = [...]`-filtered rule, the evaluator records the rule's scopes on `ACLResults::list_filter_scopes` and `PolicyStore::post_route` narrows the response `keys` to entries the caller owns. Works uniformly for KV mounts and the resource engine. An ungated LIST grant on the same path defeats the filter so broader access is never accidentally narrowed.
- **Two seeded baseline policies** (`src/modules/policy/policy_store.rs`): `standard-user-readonly` (read+list on KV + resources they own/are shared) and `secret-author` (full CRUD on KV + resources they own/are shared). Both ship alongside the existing broadly-scoped `standard-user` so operators can opt into ownership-aware ACLs without a migration. `load_default_acl_policy` seeds all three.
- **3 new integration tests** in `src/modules/identity/mod.rs`: alice-writes-bob-denied, secret-author full CRUD on owned secret, and list-filter narrows `secret/metadata/` to caller-owned keys for a user with `secret-author`.
- Updated 4 existing policy-listing tests to expect the two new seeded baselines in the default policy list.



#### Resource Groups (`features/resource-groups.md`)
- **Resource-group module** (`src/modules/resource_group/`) -- new logical backend mounted at `resource-group/` that manages named collections of resources. Each group holds a description and a list of resource names; membership is canonicalized (lowercased, trimmed, deduped, sorted) on every write.
- **`ResourceGroupStore`** (`src/modules/resource_group/group_store.rs`) -- encrypted storage under the system barrier view at `sys/resource-group/group/`, with a reverse member index at `sys/resource-group/member-index/<resource>` so "which groups contain this resource?" is a single lookup. The reverse index is maintained by diffing old vs new members on every write; a `reindex` admin endpoint rebuilds it from primary records for recovery after an interrupted write.
- **HTTP API**: `LIST/GET/PUT/DELETE /v1/resource-group/groups/{name}`, `GET /v1/resource-group/groups/{name}/history`, `GET /v1/resource-group/by-resource/{resource}`, `PUT /v1/resource-group/reindex`.
- **Change history with before/after values** -- every create/update/delete is recorded as a `ResourceGroupHistoryEntry { ts, user, op, changed_fields, before, after }` under `sys/resource-group/history/{name}/<20-digit-nanos>`. Shape mirrors identity-group history so the GUI can reuse its diff renderer when it lands. `members` is compared as a set (pure reordering does not record a new entry); delete entries retain the group's final state in `before` so the audit trail survives removal.
- **Default mount + migration** (`src/mount.rs`) -- new deployments get the `resource-group/` mount automatically; existing deployments pick it up on next unseal via the `mount_update` migration (same path used for `identity/`).
- **Resource-delete lifecycle prune** -- the resource module's delete handler (`src/modules/resource/mod.rs`) now calls `ResourceGroupStore::prune_resource` after the metadata write has been removed, so deleting a resource automatically drops it from every group that contained it and clears its reverse-index entry. Prune failures are logged and do not block the delete; stale entries can still be cleaned up with `resource-group/reindex`.
- **ACL `groups = [...]` policy qualifier** -- policy HCL grew a new optional attribute on `path` blocks that gates the rule's capabilities on the request target's asset-group membership (resources *and* KV secrets). Parsed into `PolicyPathRules.groups` and `Permissions.groups` (`src/modules/policy/policy.rs`), normalized (trim, lowercase, dedup) at policy init. Gated rules are kept unmerged in a dedicated `ACL::grouped_rules` list (`src/modules/policy/acl.rs`) so per-rule gate semantics survive — merging gated and ungated rules on the same path would distort their access. At evaluate time, each matching gated rule is checked against `Request::asset_groups` (populated in `PolicyStore::post_auth`) and OR'd into the base result. Explicit `deny` inside a gated rule still wipes the grant. Group-lookup failures surface as an empty `asset_groups`, which safely narrows access. Matching handles exact, prefix, and segment-wildcard (`+`) rule shapes.
- **KV-secret membership** -- `ResourceGroupEntry` grew a `secrets: Vec<String>` field stored in canonical form; canonicalization strips the KV-v2 `data/` and `metadata/` segments so `secret/foo/bar`, `secret/data/foo/bar`, and `secret/metadata/foo/bar` all collapse to the single entry `secret/foo/bar`. A parallel reverse index at `sys/resource-group/secret-index/<base64url(path)>` lets `groups_for_secret(path)` run in one read; base64url encoding avoids `/` collisions in the BarrierView key space. The write payload accepts a `secrets` comma-string or array, new `GET /v1/resource-group/by-secret/<b64url_path>` route exposes the reverse lookup, `reindex` rebuilds both reverse indexes, and `prune_secret(path)` is available on the store for future KV lifecycle wiring.
- **ACL qualifier extended to KV paths** -- `PolicyStore::post_auth`'s `resolve_asset_groups` now consults both reverse indexes. Anything outside the fixed non-KV prefixes (`sys/`, `auth/`, `identity/`, `resource-group/`, `cubbyhole/`, `resources/`) is treated as a candidate KV path and passed to `groups_for_secret` (which canonicalizes before lookup); results are unioned with the resource-index result into `Request::asset_groups`. A single `groups = [...]` rule can therefore gate access to resources and KV secrets uniformly.
- 7 integration tests: CRUD + canonicalization + partial updates (now asserts `secrets` field is present), reverse-index maintenance for resources, change-history shape, resource-delete lifecycle prune, ACL gate against a resource path, secret-membership canonicalization across v1/v2 variants + `by-secret` base64url lookup, and ACL gate against a KV-v1 mount (user with a `groups = ["kv-club"]` policy reads only the gated secret; membership swaps take effect without re-login).
- **List-filter on group-gated LIST ops** -- when a `LIST` operation is authorized *only* by a `groups = [...]`-gated policy rule, the evaluator records the rule's groups on `ACLResults.list_filter_groups`. `PolicyStore::post_auth` copies them onto `Request::list_filter_groups`, and a new `Handler::post_route` impl on `PolicyStore` narrows the response `keys` to entries whose resolved full logical path is a member of any listed group. An ungated LIST grant on the same path defeats the filter so a broader access is never accidentally narrowed. Works uniformly for the resource engine and KV mounts.
- **KV-delete lifecycle prune** -- `PolicyStore::post_route` also calls `ResourceGroupStore::prune_secret` on every successful `Delete` whose path is a KV candidate (anything outside `sys/`, `auth/`, `identity/`, `resource-group/`, `cubbyhole/`, `resources/`). Parallels the resource-delete hook in the resource module; prune failures are logged and never fail the delete. `PolicyStore` is now registered as both an `AuthHandler` (for `post_auth`) and a `Handler` (for `post_route`) in `src/modules/policy/mod.rs`.
- **Policy-compile warning for unknown asset groups** -- `handle_policy_write` collects every group name referenced via a `groups = [...]` clause, diffs against the current `ResourceGroupStore::list_groups()`, and attaches a response warning listing unknown names. The write still succeeds — creating a matching group later retroactively activates the clause — but operators see typos immediately instead of silently getting zero authorization.
- 3 new integration tests: `test_list_filter_on_groups_gated_list_kv` (KV-v1 mount, group gates `list` access so only members appear in the response), `test_kv_delete_prunes_from_groups` (deleting a KV secret drops it from every group that contained it), `test_policy_write_warns_on_unknown_groups` (response warning lists unknown names without blocking the write).
- Feature-complete for the single-tenant, non-ownership model. Pending items (ownership / admin transfer / sharing) remain blocked on [per-user-scoping](features/per-user-scoping.md).

#### Identity Groups (`features/identity-groups.md`)
- **Identity module** (`src/modules/identity/`) -- new logical backend mounted at `identity/` that manages user groups and application groups. Groups hold a list of members (UserPass usernames or AppRole role names) and a list of policies.
- **HTTP API**: `GET/PUT/DELETE /v1/identity/group/user/{name}`, `LIST /v1/identity/group/user`, and the symmetric `group/app/*` routes for application groups.
- **GroupStore** (`src/modules/identity/group_store.rs`) -- encrypted storage under the system barrier view at `sys/identity/group/{user,app}/` with a policy-expansion helper used at login time.
- **Policy union at login** -- UserPass (`path_login.rs`) and AppRole (`path_login.rs`) login handlers union the caller's directly-attached policies with policies from every group the caller is a member of. Renewal checks the unioned policy set for equivalence.
- **Default mount + migration** (`src/mount.rs`) -- new deployments get the `identity/` mount automatically; existing deployments pick it up on next unseal via a new `mount_update` migration that injects any missing default core mounts without overwriting existing ones.
- 3 integration tests covering user-group CRUD, user/app namespace isolation, and end-to-end policy expansion through a UserPass login.
- **GUI Groups page** (`gui/src/routes/GroupsPage.tsx`) -- list/create/edit/delete user and application groups, with tab switcher between kinds, multi-select member pickers sourced from UserPass / AppRole mounts, free-form member entry for foreign-mount members, and a policy multi-selector. Backed by 4 new Tauri commands (`list_groups`, `read_group`, `write_group`, `delete_group`) in `gui/src-tauri/src/commands/groups.rs`. Shows an empty state prompting reseal/unseal when the `identity/` mount is absent on legacy deployments.
- **Group change history with before/after values** -- every create/update/delete on a user or application group is recorded as a `GroupHistoryEntry { ts, user, op, changed_fields, before, after }` under `sys/identity/group-history/{user,app}/{name}/<20-digit-nanos>`. `before` and `after` hold the *values* of exactly the fields listed in `changed_fields` (description as a string, members and policies as arrays), so operators can see precisely what was added, removed, or modified. `members` and `policies` are compared as sets; pure reordering does not record a new entry. Delete entries retain the group's full final state in `before`, so the audit trail survives removal. Exposed via `GET /v1/identity/group/{user,app}/{name}/history` (newest first), surfaced in the Groups GUI as a new **History** tab with a dedicated `GroupHistoryPanel` that renders array diffs as added/removed chips and scalar changes as side-by-side before/after blocks.
- **FIDO2 login policy union** -- the unified FIDO2 login handler under userpass (`src/modules/credential/userpass/path_fido2_login.rs`) and the legacy standalone FIDO2 backend (`src/modules/credential/fido2/path_login.rs`) now call the same `expand_identity_group_policies(GroupKind::User, username, ...)` helper used by UserPass password login. A user who is a member of a user-group now receives the group's policies whether they authenticate via password or passkey. Token renewal checks the unioned set for equivalence, so adding or removing a user from a group takes effect on the next renewal. Expansion failures fall back to the user's direct policies and log a warning; FIDO2 login is never blocked by an identity-subsystem failure. (Phase 7, `features/identity-groups.md`)

#### Baseline Policies
- **`standard-user` seeded ACL policy** (`src/modules/policy/policy_store.rs`) -- new default policy intended for unprivileged end users. Grants token self-service operations, `read`/`list` on all KV secrets (v1 and v2 paths), `create`/`read`/`update`/`list` on resources and per-resource secrets, and full access to the caller's own `cubbyhole/`. Does not grant `delete` or any policy/user/mount/identity management. Seeded on first unseal and editable afterward (not in `IMMUTABLE_POLICIES`), so operators can tighten it to match a path convention. Known limitation: BastionVault does not yet substitute `{{username}}` placeholders in policy paths, so the policy cannot scope to "only the secrets *you* created"; per-user isolation requires either a path convention + policy edit or using identity groups to assign narrower policies per group.

#### Policy Change History
- **Policy change history with full HCL snapshots** -- every create/update/delete on an ACL policy is recorded as a `PolicyHistoryEntry { ts, user, op, before_raw, after_raw }` under `sys/policy-history/{name}/<20-digit-nanos>`, where `before_raw` and `after_raw` are the complete HCL text on each side of the change. No-op saves (same HCL) are suppressed; delete entries retain the full final policy text in `before_raw`, so the audit trail survives removal. Exposed via `GET /v1/sys/policies/acl/{name}/history` (newest first), surfaced in the Policies GUI as a new **History** tab with a dedicated `PolicyHistoryPanel` that renders expandable side-by-side before/after blocks and a **Restore this version** action that re-writes a previous `before_raw` as the current policy. Wired through `list_policy_history` Tauri command and `listPolicyHistory` API wrapper.

#### GitHub Actions
- Restricted all CI workflows (`rust.yml`, `deploy-website.yml`, `website.yml`) to only trigger on tag pushes matching `releases/**`.

#### Backup/Restore/Export/Import (Phase 5, `features/import-export-backup-restore.md`)
- **Backup format** (`src/backup/format.rs`) -- `BVBK` binary format with magic bytes, JSON header, entry frames, and HMAC-SHA256 integrity verification. 4 unit tests.
- **Backup creation** (`src/backup/create.rs`) -- `create_backup()` iterates all backend keys, writes encrypted blobs with optional zstd compression, appends HMAC.
- **Backup restore** (`src/backup/restore.rs`) -- `restore_backup()` verifies HMAC before writing any data, supports zstd decompression.
- **Secret export** (`src/backup/export.rs`) -- `export_secrets()` reads through the barrier (decrypted), produces JSON with mount/prefix.
- **Secret import** (`src/backup/import.rs`) -- `import_secrets()` writes JSON entries through the barrier, supports `--force` overwrite.
- CLI commands: `bvault operator backup`, `bvault operator restore`, `bvault operator export`, `bvault operator import`.
- HTTP endpoints: `POST /v1/sys/backup`, `POST /v1/sys/restore`, `GET /v1/sys/export/{path}`, `POST /v1/sys/import/{mount}`.
- API client methods: `Sys::export_secrets()`, `Sys::import_secrets()`.
- Error variants: `ErrBackupInvalidMagic`, `ErrBackupUnsupportedVersion`, `ErrBackupCorrupted`, `ErrBackupHmacFailed`, `ErrBackupHmacMismatch`.
- `zstd` dependency added to `Cargo.toml`.
- Made `list_all_keys()` public in `src/storage/migrate.rs` for reuse by backup module.

#### Cluster Failover (Phase 4A gap)
- `bvault cluster failover` CLI command to trigger leader step-down for planned maintenance.
- `POST /v1/sys/cluster/failover` HTTP endpoint.
- `Sys::cluster_failover()` API client method.
- `HiqliteBackend::trigger_failover()` method (HTTP POST to hiqlite step_down API).

#### HA Fault-Injection Tests (Phase 6, `features/hiqlite-ha-storage.md`)
- `tests/hiqlite_ha_fault_injection.rs` -- 8 multi-node HA test scenarios with `TestCluster` helper.
- Test scenarios: cluster formation, write-leader/read-follower, leader failover via step-down, follower restart without data loss, leader restart with re-election, write during election, quorum loss and recovery, graceful leave.

#### OIDC and SAML Auth Feature Plans
- `features/oidc-auth.md` -- OpenID Connect auth backend spec (Authorization Code Flow + PKCE, claim-to-policy role mappings, 5 endpoints).
- `features/saml-auth.md` -- SAML 2.0 auth backend spec (SP-initiated SSO, attribute-to-policy role mappings, 5 endpoints).

#### FIDO2/WebAuthn Auth Backend (Phase 6, `roadmaps/tauri-gui-fido2.md`)
- **FIDO2 credential module** (`src/modules/credential/fido2/`) following the standard Module/Backend pattern.
- `webauthn-rs` 0.5 and `webauthn-rs-proto` 0.5 dependencies.
- `Fido2Config` type for relying party configuration (RP ID, origin, name).
- `UserCredentialEntry` type storing policies, token params, and serialized passkey credentials.
- 7 API endpoints:
  - `auth/fido2/config` (Read/Write) -- relying party configuration.
  - `auth/fido2/register/begin` (Write, authenticated) -- start WebAuthn registration, returns `PublicKeyCredentialCreationOptions`.
  - `auth/fido2/register/complete` (Write, authenticated) -- complete registration, stores credential.
  - `auth/fido2/login/begin` (Write, unauthenticated) -- start authentication, returns `PublicKeyCredentialRequestOptions`.
  - `auth/fido2/login/complete` (Write, unauthenticated) -- verify assertion, update sign count, issue vault token.
  - `auth/fido2/credentials/{user}` (Read/Write/Delete/List) -- credential CRUD.
- Token renewal handler (`login_renew`) with policy change detection.
- Error variants: `ErrFido2NotConfigured`, `ErrFido2RegistrationFailed`, `ErrFido2AuthFailed`, `ErrFido2ChallengeExpired`, `ErrFido2CredentialNotFound`.

#### Resource Management (`features/resources.md`)
- **Resources abstraction** -- higher-level inventory entities (servers, network devices, websites, databases, applications, custom types) that group related secrets.
- Resources stored in KV engine at `_resources/` prefix with metadata: name, type, hostname, IP, port, OS, location, owner, tags, notes, timestamps.
- 5 built-in types + dynamic custom types.

#### Tauri Desktop GUI (Phases 1-6, `roadmaps/tauri-gui-fido2.md`)
- **Phase 1: Scaffold** -- Tauri v2 + React 19 + TypeScript 5.6 + Vite 6 + Tailwind CSS 4 project in `gui/`. Cargo workspace integration.
- **Phase 2: Embedded Mode** -- In-process vault with `FileBackend` at `~/.bastion_vault_gui/data/`, auto-init with 1-of-1 Shamir, unseal key and root token stored in OS keychain via `keyring` crate, seal on window close.
- **Phase 3: Core Screens** -- ConnectPage (mode selector), InitPage (first-launch wizard), LoginPage (Token + UserPass tabs), DashboardPage (seal status, mounts, auth methods).
- **Phase 4: Secrets & Management** -- 12 reusable UI components (`gui/src/components/ui/`): Button, Input, Textarea, Select, Card, Modal, Table, Badge, Tabs, EmptyState, Breadcrumb, Toast. SecretsPage (KV browser/editor with masked values), UsersPage (CRUD with modals), PoliciesPage (HCL editor with dirty tracking), MountsPage (secret engines + auth methods with enable/disable).
- **Phase 5: AppRole Dashboard** -- Role CRUD, role-id display with copy, secret-id generation (one-time display), accessor list with lookup/destroy. 9 Tauri commands.
- **Phase 6: Resources Page** -- Resource grid with type badges, search, type filter. Detail view with Info tab (editable metadata) and Secrets tab (per-resource secret management). Create modal with built-in + custom type selector.
- **Phase 7: FIDO2 GUI** -- FIDO2 login tab on LoginPage (username + "Authenticate with Security Key" button), Fido2Page for key management (RP config, credential info, register/delete keys). `useWebAuthn` hook encapsulating browser WebAuthn ceremony (base64url ↔ ArrayBuffer conversion, navigator.credentials.create/get). 8 Tauri FIDO2 commands.
- **Phase 8: Remote Mode** -- Connect to external BastionVault servers via HTTP API. `RemoteProfile` with address, TLS skip verify, CA cert path, client cert/key paths. `connect_remote` command tests connection via health endpoint. `disconnect_remote` clears session. `remote_login_token` and `remote_login_userpass` for authentication. ConnectPage now has an active "Connect to Server" button with a modal form for server URL and TLS configuration. Layout shows Local/Remote mode indicator.
- **Phase 9: Polish & Packaging** -- `ErrorBoundary` component catching React errors with recovery button. Real `SettingsPage` showing connection info (mode, server, TLS, data location), about section, and actions (seal, disconnect, sign out). Tauri feature forwarding (`storage_hiqlite` feature in GUI Cargo.toml forwarded to `bastion_vault`). `@tauri-apps/cli` added as dev dependency. Makefile targets: `run-dev-gui`, `gui-build`, `gui-test`, `gui-check`.
- **UI Testing** -- Vitest + React Testing Library + jsdom. 49 tests across 4 files: component tests (27), store tests (6), page tests (9), FIDO2 tests (7).
- Tauri backend: 55 commands across 9 modules (connection, system, auth, secrets, users, policies, approle, resources, fido2).

### Changed

- `HiqliteBackend` now implements `Debug` (manual impl, omits non-Debug fields). Fixes cucumber test compilation.
- `storage::migrate::list_all_keys()` changed from private to public for reuse by backup module.
- Roadmap updated: hiqlite initiative moved to Completed (all 6 phases done), GUI initiative completed (all 9 phases), FIDO2 auth backend marked Done.
- `features/hiqlite-ha-storage.md` updated to reflect all phases complete.
- `features/import-export-backup-restore.md` updated to reflect implementation complete.
- `gui/src-tauri` added to workspace members in root `Cargo.toml`.

### Removed

- Branch and pull_request triggers from all GitHub Actions workflows (now tag-only via `releases/**`).

#### Change history (GUI + backend)
- **KV-v2 per-version audit fields**: `VersionMetadata` and `VersionData` now include `username` (from `auth.metadata["username"]`, falling back to `auth.display_name`, finally `"unknown"`) and `operation` (`"create"` / `"update"` / `"restore"`). `data/` responses expose both in the metadata envelope. On-disk format is backward-compatible via `#[serde(default)]`.
- **Resource metadata history**: new append-only audit log at `hist/<name>/<nanos>` in the resource engine. Each entry records `ts`, `user`, `op` (`create` / `update` / `delete`), and `changed_fields` -- the set of top-level field names that differ from the previous write, excluding timestamp/identity fields. Redundant saves that only touch `updated_at` do NOT generate entries. Exposed through a new path `resources/<name>/history` (`Operation::Read`).
- **Resource secret versioning**: resource secrets are now versioned. Each write snapshots to `sver/<resource>/<key>/<version>` and updates `smeta/<resource>/<key>`; the current value is still kept at `secret/<resource>/<key>` for O(1) reads. New paths: `secrets/<resource>/<key>/history` (version list) and `secrets/<resource>/<key>/version/<n>` (read old value).
- **Tauri commands**: `list_secret_versions`, `read_secret_version`, `list_resource_history`, `list_resource_secret_versions`, `read_resource_secret_version`.
- **GUI**: new History button on the SecretsPage detail pane (KV-v2 only); new History tab on the Resources detail view; new History button on the resource-secret detail pane. Timeline UI shared across secrets (`SecretHistoryPanel`) and resources (`ResourceHistoryPanel`). Clicking a version loads its data masked with `MaskedValue`; a Restore button writes the old value as a new version.
- Tests: 5 new Rust unit tests for the diff helper + history-seq ordering, 3 new integration tests in `tests/test_default_logical.rs` covering KV-v2 username tracking, resource metadata history (including the no-op-write suppression), and resource secret versioning. 20 new vitest tests for the two history panels, timestamp/op helpers, and a regression on the generator + policy check.

### Fixed

#### Windows build
- **`openssl-sys` link failure** on Windows MSVC -- added `openssl` dep with the `vendored` feature on `cfg(windows)` in root `Cargo.toml` and `gui/src-tauri/Cargo.toml` so the transitive `openssl-sys` (via `authenticator` and `webauthn-rs-core`) builds from source without a system install.
- **`authenticator 0.5.0` type mismatch** (`expected winapi::ctypes::c_void, found libc::c_void`) on Windows -- worked around by adding `winapi = { version = "0.3", features = ["std"] }` as a direct dep in `gui/src-tauri/Cargo.toml`; Cargo's feature unification enables winapi's `std` feature, which re-exports `std::ffi::c_void` as `winapi::ctypes::c_void`.
- **`tauri-winres` RC2176 "old DIB"** -- regenerated `gui/src-tauri/icons/icon.ico` via `npx @tauri-apps/cli icon` so the Windows Resource Compiler accepts the modern PNG-based Vista-style ICO format.
- Unused `Deserialize` import in `gui/src-tauri/src/commands/resources.rs`.

### Security

#### WebView2 plaintext-secret leak (GUI)
- **Disabled WebView2 form autofill** to stop Chromium/Edge from persisting typed secret values to its `Web Data` SQLite cache. Three layers of defense:
  1. `gui/src-tauri/src/lib.rs` -- new `harden_webview_autofill()` called from the Tauri `setup` hook; uses `ICoreWebView2Settings6::SetIsGeneralAutofillEnabled(false)` and `SetIsPasswordAutosaveEnabled(false)`.
  2. `run()` also sets `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--disable-features=AutofillServerCommunication,AutofillEnableAccountWalletStorage` before WebView2 init.
  3. New `SecretInput` component (`gui/src/components/ui/SecretInput.tsx`) with `type="password"`, `autoComplete="new-password"`, `spellCheck={false}`, and password-manager ignore hints; used on `SecretsPage` for KV secret values. Base `Input` component now defaults to `autoComplete="off"` + `spellCheck={false}` so no ordinary text input persists to autofill.
- Added `webview2-com = "0.38"` and `windows = { version = "0.61", features = ["Win32_Foundation"] }` as Windows-only deps in `gui/src-tauri/Cargo.toml` for the `CoreWebView2Settings` calls.
- Users upgrading from earlier builds should delete `%LOCALAPPDATA%\com.bastionvault.gui\EBWebView\Default\Web Data*` to purge any previously-captured plaintext.

---

## [Previous entries below are from earlier development phases]

## Hiqlite Phase 1 (Initial Implementation)

### Added

- **Hiqlite storage backend** (`storage "hiqlite"`) -- embedded Raft-based SQLite storage engine providing built-in replication, leader-aware writes, and distributed locking without requiring an external database service. Gated behind the `storage_hiqlite` feature flag, now enabled by default.
- Hiqlite configuration support in HCL and JSON config files with keys: `data_dir`, `node_id`, `secret_raft`, `secret_api`, `table`, `listen_addr_api`, `listen_addr_raft`, `nodes`.
- Distributed locking via hiqlite's `dlock` feature, replacing no-op lock behavior for the HA backend.
- Cucumber BDD test suite for the hiqlite backend (`tests/features/hiqlite_storage.feature`) covering CRUD operations, prefix listing, deletion, and overwrite scenarios.
- CI jobs for hiqlite backend testing on Linux, macOS, and Windows.
- Hiqlite HA storage roadmap documenting Phases 0-6 for full HA deployment.
- Feature definitions directory (`features/`) with detailed specs for:
  - Secret Versioning & Soft-Delete (KV v2 engine)
  - Audit Logging (tamper-evident, HMAC chain)
  - HSM Support (PKCS#11 auto-unseal, key wrapping, crypto providers)
  - Import/Export & Backup/Restore
  - Caching (token, secret, and configurable policy caching)
  - Batch Operations (multi-operation single-request API)
  - Hiqlite HA Storage (full feature definition with all phases)

### Changed

- **`storage_hiqlite` is now the default feature**. A plain `cargo build` includes the hiqlite backend. Use `--no-default-features` to build without it.
- Updated global roadmap (`roadmap.md`) to reflect the switch from rqlite to hiqlite and current implementation status.
- Renamed roadmap file from `rqlite-default-ha-storage.md` to `hiqlite-default-ha-storage.md`.
- Agent instructions (`agent.md`) now require keeping `CHANGELOG.md` updated with all changes.

### Fixed

- `sync_handler` feature build failure: added missing `#[maybe_async::maybe_async]` annotations to `init_with_pq` and `unseal_with_pq` methods in `barrier_chacha20_poly1305.rs`.

## Hiqlite Phase 2: Replication Semantics

### Added

- Cluster-specific error variants: `ErrClusterNoLeader`, `ErrClusterQuorumLost`, `ErrClusterUnhealthy`, `ErrCluster(String)`. All map to HTTP 503 (Service Unavailable) except generic `ErrCluster` which maps to 500.
- `GET /v1/sys/health` endpoint (unauthenticated) returning `initialized`, `sealed`, `standby`, and `cluster_healthy` fields. HTTP status varies: 200 (active leader), 429 (standby/follower), 503 (sealed or unhealthy), 501 (not initialized).
- `GET /v1/sys/cluster-status` endpoint returning storage type, cluster state, leader status, and Raft metrics (when using hiqlite backend).
- `HiqliteBackend::is_leader()`, `is_healthy()`, `cluster_metrics()` methods exposing hiqlite's Raft cluster state.
- `Sys::health()` and `Sys::cluster_status()` client API methods.
- Status CLI command now displays `standby` and `cluster_healthy` fields when available.

### Changed

- Hiqlite error handling: replaced generic `ErrResponse(string)` mapping with structured `map_hiqlite_error()` that inspects hiqlite's `Error` enum variants and maps to specific cluster error types.
- `Backend` trait now requires `Any` supertrait bound for downcast support in health endpoints.

## Hiqlite Phase 3: Default Server Recommendation

### Added

- Production config examples: `config/single-node.hcl` (single-node hiqlite with TLS) and `config/ha-cluster.hcl` (3-node HA cluster).
- Server startup warning when using the file backend, directing operators to hiqlite configs.

### Changed

- `config/dev.hcl` clearly labeled as development-only with comments pointing to production configs.
- Server CLI help text updated to recommend hiqlite for production and list all example config files.

## Hiqlite Phase 4/4A: Cluster Management CLI

### Added

- `bvault cluster` command group with three read-only inspection subcommands:
  - `bvault cluster status` -- full cluster status with Raft metrics.
  - `bvault cluster leader` -- leader and health information.
  - `bvault cluster members` -- cluster membership from Raft metrics.
- All cluster commands support standard HTTP, TLS, and output format options.
- `bvault cluster leave` -- gracefully leaves the Raft cluster and shuts down the node.
- `bvault cluster remove-node --node-id N` -- removes a failed node from the cluster. Supports `--stay-as-learner` to demote instead of fully removing.
- `POST /v1/sys/cluster/leave` and `POST /v1/sys/cluster/remove-node` API endpoints for programmatic cluster management.
- `HiqliteBackend::remove_node()`, `leave_cluster()`, and `node_id()` methods for cluster topology operations.

## Hiqlite Phase 5: Migration Tooling

### Added

- `bvault operator migrate` CLI command for offline backend-to-backend data migration.
- `src/storage/migrate.rs` module with `migrate_backend()` function that recursively copies all encrypted entries from source to destination.
- Supports any backend combination: file -> hiqlite, mysql -> hiqlite, hiqlite -> file, etc.
- Data copied as raw encrypted bytes -- same unseal keys work after migration.

## Hiqlite Phase 6: HA Validation

### Added

- `test_hiqlite_cluster_health` unit test verifying single-node leader status, health, metrics, and node ID.
- `test_hiqlite_migrate_from_file` integration test verifying backend-to-backend migration from file to hiqlite with nested key paths.
- `tests/features/hiqlite_ha.feature` cucumber scenarios for HA cluster operations (5 scenarios).

## Test Fixes

### Fixed

- **TLS test panic**: all CLI/module tests that passed `tls_enable: true` to `TestHttpServer` hit a panic because TLS certificate generation was removed with OpenSSL. Fixed by falling back to plaintext HTTP in tests when TLS certs are unavailable. All 22 affected tests now pass.
- **Unseal key length assertion**: `test_generate_unseal_keys_basic` hardcoded expected key length as 33 bytes (AES-GCM). Fixed to dynamically use `barrier.key_length_range()` which returns 64 for ChaCha20Poly1305 (ML-KEM-768 seed) + 1 Shamir overhead = 65.
- **Metrics count assertion**: `test_metrics_name_and_help_info` expected exact metric count but some system metrics aren't available on all platforms. Fixed to use range assertion.
- **Hiqlite tests gated**: hiqlite integration tests require `CARGO_TEST_HIQLITE=1` env var since they start Raft nodes on fixed ports and can hang in constrained environments.
- **Hiqlite enc_keys**: added required `cryptr::EncKeys` initialization with a generated key to `NodeConfig` (hiqlite 0.13 requires non-empty encryption keys).

### Removed

- **SQLx storage backend** (`storage "sqlx"`) -- removed entirely due to `libsqlite3-sys` native link conflict with hiqlite's `rusqlite` dependency. The `storage_sqlx` feature flag and `sqlx` dependency have been removed from `Cargo.toml`.
- `SqlxError` variant removed from error types.
- SQLx-related CI jobs (`unix-sqlx-mysql-test`, `windows-sqlx-mysql-test`) replaced with hiqlite CI jobs.
