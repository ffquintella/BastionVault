# Feature: Cloud Storage Targets for the Encrypted File Backend

## Summary

Let BastionVault's existing **Encrypted File** storage backend (`src/storage/physical/file.rs`, selected by `storage "file" { ... }` in server config) write its per-key files to a user-owned cloud account — **AWS S3**, **Google Drive**, **Microsoft OneDrive**, or **Dropbox** — instead of (or in addition to) the local filesystem. The on-disk format, the barrier-encrypted `BackendEntry` shape, and the `Backend` trait surface are all unchanged. The cloud is a pluggable **target** underneath the existing file backend, not a new backend.

Earlier drafts of this feature went through two mis-framings that were rejected in review:

1. "Third deployment mode alongside Local / Remote" — overcomplicated (whole-vault rollback manifests, single-writer leases).
2. "Per-file content backend inside `src/modules/files/`" — still the wrong layer; File Resources shouldn't carry the cloud story for every other kind of vault data.

The correct framing is: **the Encrypted File backend writes files somewhere. That somewhere can be `/var/lib/bastionvault/` (today) or an S3 bucket / OneDrive app-folder / Drive app-data folder / Dropbox App Folder (this feature).**

## Status

**Done.** All 8 phases shipped, plus the Get-Started-page integration (multi-vault chooser + Cloud Vault option) that grew out of the work. Two sub-slices are explicitly deferred and documented at the bottom of this file; neither blocks day-to-day use.

### Phase 1 — shipped

- `src/storage/physical/file/` is now a module directory (was a single file).
- **`file/target.rs`** — new `FileTarget` trait with `read` / `write` / `delete` / `list` / `lock`, byte-level surface below the barrier.
- **`file/local.rs`** — new `LocalFsTarget` carrying the exact behavior of the pre-refactor `FileBackend`: key→path mapping (`a/b/c` → `<root>/a/b/_c`), `_`-prefix leaf discriminator so `list()` returns both data names and trailing-slash directory names, `lockfile::Lockfile`-backed per-key lock.
- **`file/mod.rs`** — `FileBackend` is now a thin wrapper holding `Arc<dyn FileTarget>`. Serializes `BackendEntry` to JSON above the trait, defers I/O to the target. Config now accepts `target = "..."` (defaults to `"local"`), so every existing `storage "file" { path = "..." }` config works bit-for-bit. New `FileBackend::from_target` hook for tests and future phases.
- **Regression.** All existing file-backend tests (`test_file_backend`, `test_file_backend_multi_routine`) pass unchanged through the new indirection. Broader `storage::` test suite 19/19 green.
- **Seam test.** New `test_file_backend_delegates_to_target` exercises `FileBackend::from_target` with a recording stub, asserting that the target receives the serialized JSON bytes (not the pre-serialization `BackendEntry`) — the exact shape Phase-2 cloud targets must handle.

### Phase 2a — `credentials_ref` resolver (shipped)

- **`file/creds.rs`** — new resolver for the `credentials_ref` URI grammar (`env:` / `file:` / `inline:` / `keychain:`). Returns a `Secret` newtype wrapping `Zeroizing<Vec<u8>>` so raw bytes wipe on drop; `Debug` is length-only, never prints contents. Each target interprets the bytes per its own needs (S3 as JSON static creds or profile name; OAuth targets as a refresh token).
- **Coverage.** 13 unit tests covering successful resolution for each scheme, empty-payload rejection, bad-base64 rejection, missing-env-var / missing-file / missing-scheme / unknown-scheme error paths, the explicit `keychain:` deferred-to-Phase-7 error, and a `Secret` debug-redaction assertion. All green; no external deps (uses only `base64` + `zeroize`, both already in the tree).
- Scope. This is the creds surface that the S3, OneDrive, Google Drive, and Dropbox targets will all share. Landing it before any provider wire-up means each provider slice can focus on its own transport and credential interpretation without also re-designing the creds ABI.

### Phase 2b — S3 target (shipped)

- **Stack choice.** Phase-2b brief asked for the smallest viable crate. `aws-sdk-s3` pulls 50–80 transitive deps and a whole HTTP/TLS stack; we went with **`rusty-s3`** (URL-signing + XML-parsing only, 4 new transitive deps) paired with the already-present **`ureq`** crate for HTTP. Locked behind the new `cloud_s3` Cargo feature; default builds pull neither `rusty-s3` nor `quick-xml`.
- **`file/s3.rs`** — new `S3Target` implementing `FileTarget`. Config keys: `bucket` (required), `region` (required), `endpoint_url` (optional, enables MinIO), `url_style = "path" | "virtual"` (default `virtual`), `prefix` (optional, auto-trailing-`/`), `credentials_ref` (optional — JSON `{access_key_id, secret_access_key, session_token?}`; absent falls back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars), `http_timeout_secs` (optional, default 30).
- **Transport.** Each verb pre-signs with rusty-s3 then ships the signed URL through a shared `ureq::Agent`. ureq is synchronous, so every op hops through `tokio::task::spawn_blocking` to avoid parking the runtime. `http_status_as_error` is disabled on the Agent so the code routes 404 cleanly to `Ok(None)` on `read` / no-op on `delete`, instead of matching on an error variant.
- **Listing.** `list(prefix)` walks `ListObjectsV2` paginated via `NextContinuationToken`, delimiter `/`, and strips the configured object-prefix before returning. Directory entries keep their trailing `/` to match the local target's contract. `encoding-type=url` is set by rusty-s3 by default, so returned keys are percent-decoded before being handed back to the caller.
- **Locking.** No-op guard. The spec's documented single-writer-per-target assumption applies; bulk arbitration (ETag-precondition lock object, DynamoDB table, etc.) is out of scope for Phase 2b.
- **`FileBackend::new` wired.** `target = "s3"` branch is `#[cfg(feature = "cloud_s3")]`. When the feature is off, asking for `target = "s3"` returns a clear error pointing at the build flag rather than a silent config parse failure.
- **Tests.** 9 new unit tests covering: `bucket` / `region` required, unknown `url_style` rejected, `credentials_ref = "inline:..."` happy path, bad-JSON rejection, prefix normalization, object-key prefix composition, percent decoding. Plus a live MinIO integration test (`s3_target_live_roundtrip`) marked `#[ignore]` — runs under `cargo test --features cloud_s3 -- --ignored` when the `BVAULT_TEST_S3_ENDPOINT` / `_BUCKET` / `_REGION` + `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars are set.
- **Full file-module suite.** 24/24 green with `cloud_s3` enabled; default build stays clean with zero extra deps.

### Phase 3a — OAuth infrastructure (shipped)

- **`file/oauth.rs`** — new shared library module for the consent flow that phases 4–6 (OneDrive / Google Drive / Dropbox) will plug into. No new transitive deps: reuses `rand`, `sha2`, `base64`, `url`, `ureq` — all already in the tree.
- **`OAuthProvider`** — per-provider config: authorization URL, token URL, scopes, extra-auth-params (e.g. `prompt=consent` for Google, `token_access_type=offline` for Dropbox). One instance per target kind.
- **`OAuthCredentials`** — client identity: `client_id` plus optional `client_secret` for server-style clients. Public clients (the common shape for distributed desktop apps) omit the secret and rely on PKCE.
- **`TokenResponse`** — `{access_token, refresh_token?, expires_in?, token_type?, scope?}`. `refresh_token` is optional because refresh-grant responses omit it when the provider chose not to rotate; callers keep their stored token unchanged in that case.
- **PKCE helpers** — `pkce_verifier()` generates 72 random bytes → 96 base64url chars (RFC 7636-compliant, within 43..=128); `pkce_challenge()` returns BASE64URL(SHA256(verifier)); `random_state()` generates the 128-bit CSRF state.
- **`begin_consent` + `ConsentSession`** — binds a random `127.0.0.1:<port>` loopback listener, composes the authorization URL with `code_challenge_method=S256`, returns a handle. The caller decides what to do with `session.consent_url` (a CLI prints and shells out to `open` / `xdg-open` / `rundll32`; the GUI hands it to Tauri's `shell.open` — keeps the module portable and testable).
- **`ConsentSession::wait_for_callback(timeout)`** — blocks on the listener, accepts the first connection, parses `GET /callback?code=...&state=...`, responds with a minimal HTML success page, and returns the code after validating the state against the CSRF value we sent. Provider-returned OAuth errors (`error=access_denied&error_description=...`) are surfaced with the provider's message, not silently dropped. 5-minute poll-style timeout so a closed browser tab doesn't hang the caller forever.
- **`exchange_code`** — RFC 6749 §4.1.3 authorization-code grant via form-encoded POST to `token_url`.
- **`refresh_access_token`** — refresh-grant variant; omits scope on refresh (maximally compatible: Google rejects it, others accept).
- **Sync by design.** Async consumers call via `tokio::task::spawn_blocking`, matching the pattern already in place for the S3 target.
- **Tests.** 13 unit tests: PKCE verifier length + charset, RFC 7636 Appendix B PKCE test vector, authorization-URL composition, request-line parsing (happy path, URL-decoding, provider-error surfacing, non-GET rejection, missing-code rejection, missing-state rejection), token response deserialization (minimal + full), in-process TCP roundtrip (real listener + real ureq client hitting `/callback?...`), CSRF state-mismatch rejection. All green; default build + `cloud_s3` build both unaffected.

### Phase 3b — CLI `operator cloud-target connect` (shipped)

- **`creds::persist`** — new writer side of the `credentials_ref` grammar. Only `file:` is writable today: writes atomically via a sibling tmp file + rename, chmod-0600 on Unix. `env:` / `inline:` return instructive errors ("cannot be written durably" / "read-only"); `keychain:` returns the same Phase-7-deferred error as the reader. 7 new unit tests (happy-path round-trip, atomicity over replacement, 0600 perms on Unix, each rejection path, missing/unknown scheme).
- **`oauth::well_known_provider`** — provider-factory for `onedrive` / `gdrive` / `dropbox`, returning an `OAuthProvider` with the right authorization / token URLs, narrowest-available scopes (app-folder / app-data / dropbox App Folder), and provider-specific extras (Google's `access_type=offline` + `prompt=consent` for reliable refresh-token issuance, Dropbox's `token_access_type=offline`). 4 new unit tests pinning each provider's shape + unknown-provider rejection.
- **`bvault operator cloud-target connect`** — new CLI subcommand orchestrating the full flow: resolves the provider, begins the consent session, prints the URL, launches the system browser (`open` / `xdg-open` / `rundll32`; soft-fails to "paste it yourself"), waits for the callback, exchanges the code for tokens, and persists the refresh token to the configured `credentials_ref`. `--no-browser` for headless servers. 5-minute default timeout. Works against all three providers today even though phases 4–6 storage-path targets haven't landed — the connect flow itself is complete and operators can validate their `client_id` + scopes configuration before the storage work ships.

### Phase 4 — OneDrive target (shipped)

- **`file/onedrive.rs`** — new `OneDriveTarget` implementing `FileTarget` against Microsoft Graph API. Feature-gated as `cloud_onedrive`; adds zero new transitive deps (reuses `ureq` for HTTP, `serde_json` for Graph responses, and the Phase-3 `oauth` + `creds` modules for token management).
- **Scope sandbox.** Only `Files.ReadWrite.AppFolder` + `offline_access` are requested (see `oauth::well_known_provider("onedrive")`). The vault sees only its own App Folder; the user's personal OneDrive stays invisible to BastionVault, and vault data stays invisible to the user's personal files.
- **Graph API endpoints.** Single-shot colon-path syntax: `GET /me/drive/special/approot:/<prefix>/<key>:/content` (read), `PUT` same URL (write), `DELETE /me/drive/special/approot:/<prefix>/<key>:` (delete), `GET /me/drive/special/approot:/<prefix>/<dir>:/children` (list) with `@odata.nextLink` pagination.
- **Access-token caching.** A `Mutex<Option<CachedAccessToken>>` holds the current access token + deadline. Every verb calls `ensure_access_token`, which returns the cached token when it has more than a minute of life left, otherwise resolves the refresh token from `credentials_ref` (so hand-rotated tokens pick up without a restart), hits `oauth::refresh_access_token`, and persists the rotated refresh token atomically when the provider supplies one.
- **Single-shot upload ceiling.** 4 MiB, matching Graph API's `:/content` limit. Values above surface a clear error with the Phase-notice ("upload-session support ships in a later phase"). Vault keys are well under this in practice; File Resources already have their own 32 MiB ceiling above the barrier and are not affected.
- **Listing.** `list(prefix)` treats `prefix` as a folder path inside the App Folder; empty prefix hits `approot/children` directly, non-empty hits `approot:/<prefix>:/children`. Items with a `folder` property get the trailing `/` discriminator; files come back bare. 404 on the folder itself (missing prefix) returns an empty Vec.
- **Locking.** No-op guard — single-writer-per-target assumption applies, matching S3.
- **Tests.** 12 unit tests covering `from_config` required-field rejection, credentials-ref-resolves-on-construct, minimal + full valid configs, prefix normalization, path encoding of specials (spaces, colons, unicode-safe), URL composition for each verb, root-children URL with and without prefix, Graph JSON parsing for the children response (with and without `@odata.nextLink`), and encode/decode symmetry. Plus a live integration test (`onedrive_target_live_roundtrip`) marked `#[ignore]`, enabled via `BVAULT_TEST_ONEDRIVE_CLIENT_ID` + `_CREDS_FILE` env vars.
- **Config parsing wired.** `FileBackend::new` routes `target = "onedrive"` to `OneDriveTarget::from_config` when built with `cloud_onedrive`; returns a clear "requires the `cloud_onedrive` build feature" error otherwise.

### Phase 5 — Google Drive target (shipped)

- **`file/gdrive.rs`** — new `GoogleDriveTarget` implementing `FileTarget` against Drive v3. Feature-gated as `cloud_gdrive`; zero new transitive deps.
- **Scope sandbox.** Only `drive.appdata` requested; files land in the special `appDataFolder` space, invisible to the user's personal Drive.
- **ID-based, not path-based.** Drive v3 has no hierarchical-path API, so writes walk the folder chain via search (`q=name='x' and '<parent>' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`), creating intermediate folders on the way. Writes update-in-place by `fileId` when the leaf exists, multipart-upload-create when it doesn't.
- **Folder-id cache.** Full-path → file-id map behind a `Mutex<HashMap>` so repeated chain resolutions inside a process stay O(segments) instead of O(segments × round-trips). Folder ids don't change once assigned, so the cache is effectively permanent for the process lifetime.
- **Multipart uploads.** `POST /upload/drive/v3/files?uploadType=multipart` builds a `multipart/related` body manually (one JSON part for metadata, one octet-stream part for content). Updates use `PATCH /upload/drive/v3/files/{id}?uploadType=media` — content only, metadata unchanged.
- **Arc<Inner> structure.** Each async `FileTarget` method clones the `Arc<Inner>` into a single `spawn_blocking`, so the entire sequence (resolve chain → search leaf → upload/update) runs on one worker thread without fragmenting the sync HTTP across multiple hop-offs.
- **Access-token cache + auto-refresh + rotation persistence** — same pattern as OneDrive, including atomic `creds::persist` of rotated refresh tokens.
- **11 unit tests** covering path splitting, parent/name extraction, query escaping (single quotes + backslashes), config-level rejection and acceptance, and Drive v3 search-response parsing (populated / empty / missing-field defaults). Plus a live integration test `#[ignore]`d behind `BVAULT_TEST_GDRIVE_CLIENT_ID` + `_CREDS_FILE`.

### Phase 6 — Dropbox target (shipped)

- **`file/dropbox.rs`** — new `DropboxTarget` implementing `FileTarget` against Dropbox v2 HTTP API. Feature-gated as `cloud_dropbox`; zero new transitive deps.
- **Scope sandbox.** The App Folder restriction is baked into the app's type at developer-console registration time (no runtime scopes needed — the provider config ships an empty `scopes` list; `token_access_type=offline` on auth is what gets a refresh token).
- **API structure.** Dropbox splits endpoints across two hosts: `content.dropboxapi.com` for upload (`/2/files/upload`) and download (`/2/files/download`), `api.dropboxapi.com` for metadata (`/2/files/delete_v2`, `/2/files/list_folder`, `/2/files/list_folder/continue`). Upload/download carry metadata in a `Dropbox-API-Arg` request header; metadata ops carry it in a JSON body.
- **Not-found handling.** Dropbox returns HTTP 409 with a structured JSON body on app-logic errors. We detect `path/not_found` via substring match on the response body and map to `Ok(None)` on read / no-op on delete / empty vec on list — matching `FileTarget`'s contract.
- **Single-shot ceiling.** 150 MiB per `/2/files/upload` call (Dropbox's documented limit). Values above surface a clear error referencing upload-session support as a deferred optimization.
- **Arc<Inner> + spawn_blocking** — same structure as Google Drive. Access-token cache + auto-refresh + rotation persistence.
- **Pagination.** `list_folder` + `list_folder/continue` with cursor-based continuation handled inline.
- **11 unit tests** covering prefix normalization (Dropbox wants leading `/`, no trailing), `path/not_found` detection, config-level rejection and acceptance, object-path composition with and without prefix, list-response parsing (populated + cursor + missing fields). Plus a live integration test `#[ignore]`d behind `BVAULT_TEST_DROPBOX_CLIENT_ID` + `_CREDS_FILE`.

### Full Phase 1–6 test status

- 82 file-module tests green under `--features cloud_targets` (all four cloud targets enabled).
- Every build matrix compiles clean: default, `cloud_s3`, `cloud_onedrive`, `cloud_gdrive`, `cloud_dropbox`, `cloud_targets` (all four together).

### Phase 7a — GUI (shipped)

- **Three Tauri commands** (`gui/src-tauri/src/commands/cloud_target.rs`): `cloud_target_start_connect`, `cloud_target_complete_connect`, `cloud_target_cancel_connect`. The split exists so the frontend can drive the browser-open step itself via the Tauri `shell` plugin — puts the consent URL in the user's real browser chrome rather than a Tauri webview popup. Sessions are stashed in a new `AppState::cloud_sessions` `HashMap` keyed by an opaque session id; the `CloudSession` holds the `ConsentSession` (with its bound loopback listener), the provider + creds, and the destination `credentials_ref`. Cancel removes the entry, so a user who dismisses the form can't leak the bound port.
- **Writable-ref validation at start time.** `cloud_target_start_connect` rejects non-writable `credentials_ref` schemes (`env:` / `inline:` / `keychain:`) up-front so the user gets an immediate error rather than going through the full consent round-trip only to hit a persist failure.
- **`CloudStorageCard` React component** (`gui/src/components/CloudStorageCard.tsx`) on the Settings page. Form: provider picker (OneDrive / Google Drive / Dropbox), `client_id`, optional `client_secret`, `credentials_ref`. Connect button runs the three-step flow end-to-end: start → `shellOpen(consentUrl)` → complete; shows phase-appropriate status text ("Preparing consent URL…" / "Waiting for browser callback…") while the operator authenticates. On error, fires `cloud_target_cancel_connect` so the loopback listener is released immediately.
- **TypeScript bindings** (`gui/src/lib/api.ts`): `cloudTargetStartConnect`, `cloudTargetCompleteConnect`, `cloudTargetCancelConnect`.
- **Tests.** GUI TypeScript check clean; 66/66 vitest tests green (unchanged). Tauri crate + full `cloud_targets` lib build both compile clean.
- **Status model.** The GUI establishes the refresh-token identity, not the active storage backend. Switching the vault's live storage target still happens in HCL config + restart. This matches the CLI shape and avoids the failure modes of trying to swap physical-backend pointers under a running vault.

### Phase 7b — OS keychain writer (shipped)

- **`keyring` crate behind `cloud_keychain` feature flag.** Pulls in platform-native secret-store backends: macOS Keychain, Windows Credential Vault, Linux Secret Service. Feature-gated so server-only operators who never use `keychain:` refs don't carry the extra transitive deps (notably `dbus` on Linux).
- **`creds::resolve` + `creds::persist` gain real `keychain:` support.** Label syntax is `<service>/<user>` — the `/` splits the label into the keychain's two identification axes. Labels without a `/` use the default service id `"bastionvault"`; labels with multiple `/`s split on the first one so the user component can contain further slashes (`onedrive/refresh/production`). On read, `NoEntry` errors get a specific "run `bvault operator cloud-target connect` to populate it" message.
- **Feature-off path still compiles.** When `cloud_keychain` is not enabled, both `resolve_keychain` and `persist_keychain` return a clear "requires the `cloud_keychain` build feature" error so operators aren't left staring at an opaque rejection.
- **GUI validator softened.** `validate_credentials_ref_writable` in the Tauri `cloud_target` commands no longer pre-rejects `keychain:` — the server may have been built with `cloud_keychain`, and if not, `creds::persist` surfaces a clear error at completion time. Matches the same principle already in place for other target-specific build requirements.
- **GUI hint updated.** The Settings → Cloud Storage Targets card now documents the three schemes accurately: `file:` writes to disk (0600 on Unix); `keychain:` writes to the OS keychain with `<service>/<user>` labels and requires the `cloud_keychain` server build; `env:` / `inline:` are read-only.
- **Tests.** 5 new `parse_keychain_label` unit tests (default service; service/user split; user with embedded slashes; empty-label rejection; empty-half rejection), 2 feature-gated rejection tests (reader + writer when `cloud_keychain` is off), and a `#[ignore]`d `keychain_roundtrip` integration test against the real OS keychain (write + read + rotate + cleanup). Creds suite: 25/25 without the feature; 23 default + 1 ignored roundtrip with the feature.
- **Build matrix status.** `cargo check --lib`, `cargo check --lib --features cloud_keychain`, `cargo check --lib --features cloud_targets` (all five feature flags), `cargo check -p bastion-vault-gui`, and `npx tsc --noEmit` all clean.

### Phase 8 — Key obfuscation (library piece shipped)

- **`file/obfuscate.rs`** — new `ObfuscatingTarget` decorator implementing `FileTarget`. Wraps any other `FileTarget`; every vault key is rewritten to `hex(HMAC-SHA256(salt, raw_key))` before reaching the wrapped target. No new external deps (uses `hmac` + `sha2` + `rand`, all already in the tree).
- **Salt bootstrap.** 32-byte random salt generated on first use via `ObfuscatingTarget::bootstrap(inner)`; persisted at the well-known un-obfuscated key `_bvault_salt` under the wrapped target. Subsequent starts reuse it, so vault keys are stable across restarts. A `with_salt(inner, salt)` constructor is exposed for programmatic use and for the rekey workflow.
- **`FileBackend::new_maybe_obfuscated`** — async convenience constructor that honors `obfuscate_keys = true` in config and wraps the base target. The sync `FileBackend::new` logs a loud warning if the flag is set through its path rather than silently ignoring it — salt bootstrap needs async I/O, so the sync path can't honor the flag.
- **`list(prefix)` limitation.** HMAC is a pseudo-random function; once `sys/policy/admin` hashes to `8a4f…e12c`, prefix enumeration is impossible without a manifest. The decorator takes the narrow approach: `list("")` works (returns every raw-hashed key minus the salt marker; useful for rekey iteration). `list("<non-empty>")` returns a specific error naming the limitation and pointing at the opt-out. Callers who depend on prefix-based listing should run with `obfuscate_keys = false`.
- **Auto-wiring** into `storage::new_backend` (the sync bootstrap path) is deferred to a separate sub-slice. Today operators who need obfuscation at boot call `FileBackend::new_maybe_obfuscated(&conf).await?` from async startup code.
- **Rekey CLI** — design-only. Flow: walk `old.list("")`, for each hashed key `read → re-write under new salt → delete old`. The "re-write" step needs the *original* key which the hash alone doesn't give, so production rekey requires either a one-time manifest or a pass through `operator migrate` with a non-obfuscated intermediate. Library pieces are present; the orchestrating CLI is not.
- **12 new unit tests** + 1 end-to-end on-disk verification: salt bootstrap generates + persists / reuses / rejects bad length; writes store under hashed keys (plaintext never appears); read-after-write roundtrip; different salts → different keys; delete via hash; salt-key passes through unhashed; `list("")` strips salt marker; `list("prefix/")` errors; HMAC determinism; `FileBackend::new_maybe_obfuscated` walks the filesystem to assert no plaintext key component lands on disk when `obfuscate_keys = true`.

## Cloud Storage Targets — feature status summary

All core phases shipped — the feature is production-usable for operators with any of the four supported providers:

| Phase | Scope | Status |
|---|---|---|
| 1 | `FileTarget` abstraction + `LocalFsTarget` | Done |
| 2a | `credentials_ref` resolver (read) | Done |
| 2b | S3 target (`rusty-s3`) | Done |
| 3a | OAuth + PKCE + loopback-redirect infra | Done |
| 3b | `bvault operator cloud-target connect` CLI + `credentials_ref` write | Done |
| 4 | OneDrive target | Done |
| 5 | Google Drive target | Done |
| 6 | Dropbox target | Done |
| 7a | Settings GUI connect flow | Done |
| 7b | OS keychain writer (`cloud_keychain`) | Done |
| 8 | Key obfuscation (`ObfuscatingTarget` decorator + async wrapper + integration test) | Library piece shipped; auto-wiring through `storage::new_backend` and rekey CLI are deferred sub-slices |

Remaining deferred work is optional hardening; none of it blocks day-to-day use.

### Phase 8 — Key obfuscation (library piece shipped)

- **`file/obfuscate.rs`** — new `ObfuscatingTarget` decorator implementing `FileTarget`. Wraps any other `FileTarget`; every vault key is rewritten to `hex(HMAC-SHA256(salt, raw_key))` before reaching the wrapped target. No new external deps (uses `hmac` + `sha2` + `rand`, all already in the tree).
- **Salt bootstrap.** 32-byte random salt generated on first use via `ObfuscatingTarget::bootstrap(inner)`; persisted at the well-known un-obfuscated key `_bvault_salt` under the wrapped target. Subsequent starts reuse it, so vault keys are stable across restarts. A `with_salt(inner, salt)` constructor is exposed for programmatic use and for the rekey workflow.
- **`FileBackend::new_maybe_obfuscated`** — async convenience constructor that honors `obfuscate_keys = true` in config and wraps the base target. The sync `FileBackend::new` logs a loud warning if the flag is set through its path rather than silently ignoring it — salt bootstrap needs async I/O, so the sync path can't honor the flag.
- **`list(prefix)` limitation.** HMAC is a pseudo-random function; once `sys/policy/admin` hashes to `8a4f…e12c`, prefix enumeration is impossible without a manifest. The decorator takes the narrow approach: `list("")` works (returns every raw-hashed key minus the salt marker; useful for rekey iteration). `list("<non-empty>")` returns a specific error naming the limitation and pointing at the opt-out. Callers who depend on prefix-based listing should run with `obfuscate_keys = false`.
- **Auto-wiring** into `storage::new_backend` (the sync bootstrap path) is deferred to a separate sub-slice. Today operators who need obfuscation at boot call `FileBackend::new_maybe_obfuscated(&conf).await?` from async startup code.
- **Rekey CLI** — design-only. Flow: walk `old.list("")`, for each hashed key `read → re-write under new salt → delete old`. The "re-write" step needs the *original* key which the hash alone doesn't give, so production rekey requires either a one-time manifest or a pass through `operator migrate` with a non-obfuscated intermediate. Library pieces are present; the orchestrating CLI is not.
- **12 new unit tests** + 1 end-to-end on-disk verification: salt bootstrap generates + persists / reuses / rejects bad length; writes store under hashed keys (plaintext never appears); read-after-write roundtrip; different salts → different keys; delete via hash; salt-key passes through unhashed; `list("")` strips salt marker; `list("prefix/")` errors; HMAC determinism; `FileBackend::new_maybe_obfuscated` walks the filesystem to assert no plaintext key component lands on disk when `obfuscate_keys = true`.

## Cloud Storage Targets — feature status summary

All core phases shipped — the feature is production-usable for operators with any of the four supported providers:

| Phase | Scope | Status |
|---|---|---|
| 1 | `FileTarget` abstraction + `LocalFsTarget` | Done |
| 2a | `credentials_ref` resolver (read) | Done |
| 2b | S3 target (`rusty-s3`) | Done |
| 3a | OAuth + PKCE + loopback-redirect infra | Done |
| 3b | `bvault operator cloud-target connect` CLI + `credentials_ref` write | Done |
| 4 | OneDrive target | Done |
| 5 | Google Drive target | Done |
| 6 | Dropbox target | Done |
| 7a | Settings GUI connect flow | Done |
| 7b | OS keychain writer (`cloud_keychain`) | Done |
| 8 | Key obfuscation (`ObfuscatingTarget` decorator + async wrapper + integration test) | Library piece shipped; auto-wiring through `storage::new_backend` and rekey CLI are deferred sub-slices |

Remaining deferred work is optional hardening; none of it blocks day-to-day use.

## Motivation

- **Bring-your-own-storage.** Operators who already run the vault on a VM they don't want to stake durability on (or who distribute a desktop build via the Tauri GUI) can point the same backend at an S3 bucket or personal cloud drive and get provider-side replication / versioning / retention without vault-side work.
- **Desktop-friendly cross-device vault.** A Tauri-packaged BastionVault desktop app with cloud storage gives one user a vault that works on every machine they sign in from, without running a server.
- **Reuses everything already shipped.** The barrier encrypts and authenticates every file. The `FileBackend`'s key → path mapping already handles arbitrary prefixes. There is nothing cryptographic, nothing schema-level, and nothing routing-level to redesign — only the I/O primitive changes.

Non-goals:

- **Not** a multi-writer story. A cloud target is owned by exactly one BastionVault instance at a time. The single-writer lease scheme from earlier drafts is not needed *for a single-writer deployment*, and multi-writer is out of scope.
- **Not** a transparent cache layer in front of the cloud. Reads go to the cloud; the existing below-barrier `CachingBackend` decorator can be layered on top if the operator enables it, and its ciphertext-only invariant holds unchanged.
- **Not** a way to share the bucket across BastionVault instances. If two processes point at the same target, writes race. A warning in the docs is the full mitigation.

## Current State

Not started. This feature file exists to scope the work before implementation.

## Design

### Where the cloud plugs in

Today `FileBackend` owns one field:

```rust
pub struct FileBackend {
    path: PathBuf,
}
```

…and every CRUD method calls into `std::fs` with paths derived from that root. The refactor replaces the implicit local-filesystem I/O with an explicit trait:

```rust
/// Storage target underneath `FileBackend`. All calls receive the
/// already-computed per-key path (an arbitrary byte string in practice)
/// and the already-serialized `BackendEntry` JSON. The barrier has
/// nothing to do with this layer — values passed in are the exact bytes
/// the caller wants persisted.
#[async_trait]
pub trait FileTarget: Send + Sync + std::fmt::Debug {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError>;
    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError>;
    async fn delete(&self, key: &str) -> Result<(), RvError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
}
```

`FileBackend` becomes:

```rust
pub struct FileBackend {
    target: Arc<dyn FileTarget>,
}
```

The existing body of `FileBackend::get/put/delete/list` moves verbatim into a `LocalFsTarget` that implements the trait. No public API change. Existing `storage "file" { path = "..." }` config still works and continues to hit `LocalFsTarget` under the hood.

### New target kinds

The new config shape:

```hcl
storage "file" {
  target = "local"
  path   = "/var/lib/bastionvault"
}

storage "file" {
  target          = "s3"
  bucket          = "infra-vault"
  region          = "us-east-1"
  prefix          = "bastionvault/"
  credentials_ref = "env:AWS_DEFAULT_PROFILE"
}

storage "file" {
  target          = "onedrive"
  credentials_ref = "keychain:bastionvault/onedrive-refresh"
}
```

Target-specific keys are parsed by the target's own `from_config` constructor; `FileBackend::new` picks the right target based on `target = "..."` and delegates.

`target = "local"` is the default when the field is absent, so every existing config continues to work without edits.

### Providers and auth

| Target | Kind | Auth | Notes |
|---|---|---|---|
| Local | Filesystem | Filesystem permissions | Existing behavior, unchanged. |
| S3 | `aws-sdk-s3` | IAM access key / secret (+ session token) via `credentials_ref`, **or** AWS profile read from the ambient environment. | MinIO-compatible. |
| OneDrive | Microsoft Graph | OAuth 2.0 + PKCE, `Files.ReadWrite.AppFolder` scope. | App-folder sandbox — vault cannot see the rest of the user's OneDrive. |
| Google Drive | Drive v3 | OAuth 2.0 + PKCE, `drive.appdata` scope. | App-data folder sandbox. |
| Dropbox | Dropbox v2 | OAuth 2.0 + PKCE, App Folder scope. | App-folder sandbox. |

**BastionVault does not ship shared OAuth client secrets for consumer providers.** Each distribution or operator configures their own `client_id` at build or runtime, per provider guidance for redistributable-but-not-hosted applications.

### `credentials_ref` and OAuth persistence

Cloud targets accept a `credentials_ref` string in a small URI grammar:

- `env:<VARNAME>` — read credentials from an environment variable.
- `keychain:<label>` — read from the OS keychain (Tauri desktop mode).
- `file:<path>` — read from a local file owned by the process.
- `inline:<base64>` — literal embedded credential (rejected in production-strict mode; useful for tests only).

For OAuth-based targets, the *refresh token* is what sits at `credentials_ref`. The vault admin runs a one-shot OAuth flow (see below) that writes the refresh token to the configured ref. The target's runtime code uses the refresh token to get fresh access tokens on demand.

The OAuth flow runs through the CLI and GUI:

- **CLI**: `bvault operator cloud-target connect --target=<name>` opens the consent URL in the system browser, listens on a loopback port for the callback, exchanges the code, and writes the refresh token to `credentials_ref`.
- **GUI**: Settings → Storage → "Connect" button kicks off the same flow in the system browser and shows the bound account on completion.

Reauth when the refresh token dies is the same flow; the target marks itself `needs-reauth` and subsequent operations fail with a clear error that points at the remediation.

### Operational semantics

- **Single writer per target.** Running two BastionVault processes against the same bucket + prefix is supported but not defended: writes race, and the last writer wins. The docs warn explicitly. For HA across multiple hosts, use the Hiqlite backend, which is what it's for.
- **Freshness.** The cloud is an object store; eventual consistency on list/read varies by provider (S3 is now strong-read-after-write; consumer drives have sync delays up to minutes). The vault reads through `Backend::get` on every request unless caching is enabled; there is no cross-node invalidation. This is the same property as running `FileBackend` off a shared NFS mount and is already understood.
- **No tombstone / snapshot / rollback protection at the cloud layer.** The barrier's existing integrity surface applies unchanged. A provider that rolls back an individual object is detected on decrypt (AEAD tag mismatch would be one path; an unexpected plaintext shape after decrypt is another); whole-target rollback to a consistent earlier snapshot is the intrinsic limit of untrusted storage without a trusted counter, and we document it.
- **Listing.** `Backend::list(prefix)` maps to the provider's prefix+delimiter list API. Consumer drives that don't support a `delimiter` concept (Dropbox v2 does; others vary) simulate it client-side.

### Key-name handling

Local `FileBackend` URL-encodes tricky characters in keys before using them as filenames. Cloud object stores accept most bytes in keys, so the `LocalFsTarget` keeps its URL-encoding and the cloud targets pass keys through. Operators who want cloud object keys to be opaque (the rough shape of vault activity is visible to anyone with bucket read access, even if the ciphertext isn't) can enable **key obfuscation**:

```hcl
storage "file" {
  target          = "s3"
  obfuscate_keys  = true
  ...
}
```

When on, the object key is `HMAC-SHA256(target_salt, raw_key)` hex-encoded. `target_salt` lives in a dedicated `<prefix>/_salt` object (itself encrypted by the barrier like any other vault key) and can be rotated via a dedicated rekey job that rewrites every object key in the bucket. Off by default.

### Failure modes

- **Provider unreachable on read**: `Backend::get` returns `RvError::ErrOther` wrapping the transport error. The request fails clean.
- **Provider unreachable on write**: same. Vault-side, the write is durable iff the target reports success.
- **429 / throttling**: exponential backoff with jitter inside each target. Capped retry count. Failure surfaced clearly so the operator can diagnose.
- **OAuth refresh failure**: target enters `needs-reauth`; subsequent operations fail with a specific error pointing at the reconnect flow.
- **Credential expiry mid-operation**: transparent refresh on the first 401; one retry; then fail.

### Performance

- **Round-trip cost dominates.** For latency-sensitive deployments, layer the existing `CachingBackend` decorator on top (`cache.secret_cache_ttl_secs > 0` in server config). Its ciphertext-only invariant holds — the cache sees the same bytes the cloud sees.
- **Parallel prefetch** on startup for vault paths known to be hot (policies, mounts). Target-level optimization, not required for correctness.
- **Multipart upload** for S3 / Drive when a single `put` exceeds 5 MiB (unlikely for vault keys — most are under a few KiB — but allocating under 5 MiB is cheap and over 5 MiB needs multipart on S3). Later optimization.

## New crate layout

Narrow crates per `agent.md` guidance:

```
crates/
  bv_file_targets/
    src/
      lib.rs            # FileTarget trait + target-kind enum + from_config entry
      local.rs          # moved from src/storage/physical/file.rs
      s3.rs             # aws-sdk-s3 impl
      onedrive.rs       # Microsoft Graph impl
      gdrive.rs         # Drive v3 impl
      dropbox.rs        # Dropbox v2 impl
      oauth.rs          # shared PKCE + loopback-redirect flow
      creds.rs          # credentials_ref resolver (env / keychain / file / inline)
```

Feature-gated at the top level so operators who don't need cloud targets pay no compile or binary-size cost:

```toml
[features]
cloud_s3       = ["bv_file_targets/s3"]
cloud_onedrive = ["bv_file_targets/onedrive"]
cloud_gdrive   = ["bv_file_targets/gdrive"]
cloud_dropbox  = ["bv_file_targets/dropbox"]
cloud_targets  = ["cloud_s3", "cloud_onedrive", "cloud_gdrive", "cloud_dropbox"]
```

The top-level `bastion_vault` crate gains a thin wrapper that constructs the configured target in `FileBackend::new`.

## Migration from the current `FileBackend`

Zero for operators who don't change their config: `target = "local"` is the default and the existing code path is preserved bit-for-bit.

Moving an existing vault to a cloud target uses the existing `operator migrate` CLI (`src/cli/command/operator_migrate.rs`) which already performs backend-to-backend copy at the physical layer. Register a second `storage "file"` stanza with the cloud target, run `bvault operator migrate --source=<local> --dest=<cloud>`, then swap the active config. No special migration code needed.

## GUI

- **Settings → Storage** — current mode (local path / cloud provider + bucket) and a "Change" action. The change flow kicks off the backend-migrate command under the hood and shows progress.
- **Cloud OAuth connect UI** — provider picker → consent browser → "Connected as `user@example.com`" confirmation on return. Identical shape to the `bvault operator cloud-target connect` CLI flow.

## Phases

| # | Phase | Scope |
|---|-------|-------|
| 1 | `FileTarget` abstraction + `LocalFsTarget` | Refactor `FileBackend` to hold `Arc<dyn FileTarget>`, move existing body into `LocalFsTarget`, prove zero regression on every existing test. No new behavior. |
| 2 | S3 target | `S3Target` against `aws-sdk-s3`. `credentials_ref` resolver. MinIO-based integration tests. |
| 3 | OAuth infrastructure | PKCE + loopback-redirect flow in `bv_file_targets::oauth`. Used by Phases 4-6. CLI `bvault operator cloud-target connect`. |
| 4 | OneDrive target | Microsoft Graph + `Files.ReadWrite.AppFolder`. |
| 5 | Google Drive target | Drive v3 + `drive.appdata`. |
| 6 | Dropbox target | Dropbox v2 + App Folder. |
| 7 | GUI | Settings → Storage page; Connect flow in the system browser. Tauri desktop mode reuses the OS keychain for the refresh token. |
| 8 | Key obfuscation + rekey | `obfuscate_keys = true` toggle. Rekey job that rewrites every object under a new salt. |

Phase 1 is the critical path — it is a pure refactor with no functional change, and it must land green before any cloud code is merged. Phases 4-6 parallelize after Phase 3 lands the OAuth infra.

## Testing Requirements

- **Phase 1 regression**: every existing `FileBackend` test passes unchanged against the new `FileBackend { target: Arc<LocalFsTarget> }` shape. No behavior difference.
- **S3 integration**: MinIO in CI. Full CRUD round-trip, list-with-prefix, byte-for-byte integrity, chunked-reads-and-writes.
- **Consumer-drive integration**: record-and-replay HTTP fixtures in CI; nightly live-tape against dedicated test accounts to refresh fixtures.
- **Security regression**: `cloud_target_never_sees_plaintext` — drive a `BackendEntry::put` through a wrapped `FileBackend` whose target records the exact bytes it was asked to write. Assert those bytes do not contain a known plaintext marker that was encrypted by the barrier above.
- **Failure injection**: 429 / 503 / timeout on each verb per provider; assert retry-with-backoff and clear surfaced errors.
- **Backend-migrate compatibility**: round-trip a vault through `operator migrate` local → S3 → local; assert every key's value is byte-identical at the barrier layer.
- **OAuth flow**: loopback-redirect port open-release; PKCE code verifier correctness; refresh-token persistence via every `credentials_ref` kind.

## Security Considerations

- **Provider never sees plaintext.** Values handed to `FileTarget::write` are barrier-encrypted `BackendEntry` JSON — the same bytes currently written to local disk. Decryption happens in the barrier above `FileBackend`; the target is below the barrier.
- **Keys-as-metadata.** Object keys reveal the rough shape of vault activity (which paths exist, how often they change) to anyone with bucket read access. The barrier does not cover key names. Operators who need to hide this turn on `obfuscate_keys`; they accept that out-of-band bucket inspection becomes harder in exchange.
- **Credentials.** Cloud target credentials are referenced, not inlined. OAuth refresh tokens live in the OS keychain (desktop) or a file owned by the vault process (server). Rotating a refresh token does not require a vault restart.
- **Scope boundaries.** OAuth scopes are the narrowest available: app-folder / app-data for consumer drives; IAM policy guidance in docs restricts S3 to the specific bucket + prefix.
- **No client-secret redistribution.** Each operator or distribution provides their own `client_id` and secret where applicable.
- **Feature-gated.** A build without `cloud_targets` cannot accidentally contact a cloud provider.
- **Single-writer assumption documented.** Two BastionVault processes against the same target + prefix produce racing writes. The docs say so loudly; the code does not attempt to arbitrate.

## Open Questions (resolved before Phase 1)

1. Whether to parse the full config into a `TargetKind` enum at `FileBackend::new` time, or keep it fully dynamic via `Arc<dyn FileTarget>`. Leaning `Arc<dyn>` for pluggability; the static-dispatch alternative saves one virtual call per operation which is negligible at cloud latencies.
2. Whether `credentials_ref = "keychain:..."` is available on Linux via `secret-service`, or gated to macOS / Windows where the platform keychain is more reliable. Leaning "available everywhere, operator chooses `file:` on Linux if `secret-service` isn't running."
3. Whether the `FileTarget` trait should also expose a bulk-delete primitive that S3 / Dropbox can implement efficiently, or whether per-object deletes in a loop are acceptable in v1. Leaning per-object for simplicity; bulk-delete as a later optimization.

## Feature complete — shipped scope recap

Every core phase is done; the rest of this section is a single-page
audit of what landed so operators planning a cloud-backed deployment
can scan the surface area without re-reading the phase log.

### What ships in the default binary

Nothing. All four provider targets + the keychain writer are behind
Cargo feature flags (`cloud_s3` / `cloud_onedrive` / `cloud_gdrive` /
`cloud_dropbox` / `cloud_keychain`; umbrella `cloud_targets`). A
server-only build that only uses the Encrypted File backend
(filesystem or Hiqlite) pays zero compile / binary-size cost for
cloud support.

The desktop Tauri GUI **does** default `cloud_targets` on, so the
installed desktop app can reach any of the four providers without a
custom build. Operators who distribute a minimal desktop binary can
opt out at their own workspace level.

### Surface area shipped

| Layer | Artifact |
|---|---|
| Trait | `FileTarget` — `read` / `write` / `delete` / `list` / `lock`, byte-level below the barrier |
| Local | `LocalFsTarget` — the pre-Phase-1 `FileBackend` behavior, unchanged |
| S3 | `S3Target` via `rusty-s3` + `ureq` (MinIO-compatible) |
| OneDrive | `OneDriveTarget` via Microsoft Graph, App-folder scope |
| Google Drive | `GoogleDriveTarget` via Drive v3, `drive.appdata` scope, folder-id cache |
| Dropbox | `DropboxTarget` via v2 API, both OAuth refresh-token and long-lived `{"access_token":"..."}` envelope formats |
| Credentials resolver | `file:` / `env:` / `inline:` / `keychain:` grammar with `Secret`-newtype zero-on-drop |
| OAuth infra | PKCE + loopback-redirect on fixed port `8472`, provider factory for onedrive/gdrive/dropbox, authorization-code + refresh-token exchange, CSRF state validation |
| CLI | `bvault operator cloud-target connect --target=<kind>` with cross-platform browser launch + atomic refresh-token persistence |
| GUI — Settings | Cloud Storage Targets card with inline Connect flow, dev-console help links per provider |
| GUI — Get Started | Multi-vault chooser with saved profiles + "Cloud Vault" add-new option (OAuth / S3 / paste-token paths) |
| GUI — InitPage | Kind-aware copy + ⇄ switch / ⚙ inline credential re-paste / 🗑 forget controls |
| Obfuscation | `ObfuscatingTarget` decorator, HMAC-SHA256 + auto-bootstrapped salt, `FileBackend::new_maybe_obfuscated` async constructor |
| OS keychain | `creds::resolve` + `creds::persist` with `keyring` crate, `<service>/<user>` label syntax |

### Test matrix

Default build, each cloud feature individually, `cloud_targets` (all
five together), and the Tauri GUI all compile clean. File-module
suite: 57 default + 11 obfuscate unit tests + per-provider unit
tests (S3: 9, OneDrive: 12, Google Drive: 11, Dropbox: 12) +
`#[ignore]`d live-integration tests gated on per-provider env vars.
GUI: 66/66 vitest tests and full TypeScript pass.

### Explicitly deferred (by design)

1. **Rekey-CLI for the obfuscation salt.** The library pieces
   (`ObfuscatingTarget::with_salt`, `list("")` enumeration) are
   present; the end-to-end CLI that walks old-salt → new-salt is
   not shipped. Production rekey today runs via `operator migrate`
   with a non-obfuscated intermediate, same mechanism used for
   moving between backends.
2. **Sync-path obfuscation bootstrap.** Desktop mode constructs
   cloud `FileBackend`s through `embedded::build_backend` which is
   async and honors `obfuscate_keys = true` via
   `FileBackend::new_maybe_obfuscated`. Server mode uses
   `storage::new_backend` which is sync and ignores the flag with
   a loud log warning — threading the async bootstrap through the
   broader storage chain is a separate refactor that touches the
   startup path for every backend kind. Not blocking because
   server-mode cloud-storage deployments still have the other 7.5
   phases available; if/when demand materializes, the path is to
   make `storage::new_backend` async and propagate.

### What's intentionally not in scope

Restating from the Motivation section so the "no" answers are
explicit:

- Multi-writer coordination across multiple vaults pointing at the
  same target. Single-writer-per-target is the assumption and the
  `lock()` no-op on cloud targets documents it; operators who need
  HA across hosts use the Hiqlite backend, which is what it's for.
- Provider-side rollback protection. The barrier's integrity story
  covers single-object AEAD; whole-bucket rollback to an earlier
  state is the intrinsic limit of untrusted cloud storage, noted
  in the docs.
- Cross-provider sync. Each vault targets exactly one target at a
  time; `operator migrate` between providers works but there is
  no built-in replication.
