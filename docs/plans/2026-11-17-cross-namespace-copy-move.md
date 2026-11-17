# Cross-namespace copy and move implementation plan

> **Outcome (2026-11-17).** The plan below is kept as written; execution changed it in these ways:
>
> - **Task 2b added (ACL on the real path).** Review found that an import route is its own ACL path, so deny rules, owner and share scopes and per-secret paths for the real item did not apply. A policy-layer mapping now authorises `<mount>/v2/transfer/import/<p>` against the path a normal write is checked on.
> - **Task 4 split into 4a and 4b.** 4a is the orchestrator (reads, rights probes, `dry_run`, collisions, import, caller ownership, verified move, route); 4b is shares, asset-group membership and attached files.
> - **`overwrite` and `rename` are orchestrator-level.** The two import endpoints accept `on_conflict` `refuse` only. The orchestrator implements `rename` as `refuse` imports at `<name>-<n>` (so the ACL checks every name) and `overwrite` as an ordinary DELETE of the destination followed by an import, so it is not atomic. This supersedes the plan's `on_conflict` text for the endpoints and its "write on the import path allows overwrite" notes.
> - **Per-resource cap of 1000 secrets** on the import.
> - **Import routes internal-only (final review).** Both import routes answer 404 to any request the orchestrator did not mark in-process, over HTTP or not, so no client can supply history, origins or version authors; this replaced an earlier acceptance of the KV import being reachable under `/v1/`.
> - **Scope trimmed in Task 6.** The GUI action shipped on the Resources page only; the KV secrets page is a follow-up (T496).
>
> The result is recorded in `features/cross-namespace-copy-move.md` (see "Known limits") and `ROADMAP.md` (T494, follow-ups T496-T505).

> For agents: use `subagent-driven-development` (recommended) or `executing-plans` to
> implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Copy or move a resource or a KV secret between namespaces, with all secrets, versions, history and validated shares, enforcing the caller's own permissions in both namespaces.

**Architecture:** A new orchestrator in the kernel `sys/` module drives the transfer by issuing ordinary requests through `Core::handle_request` carrying the **caller's token**, once per namespace. Reads use the existing resource and KV endpoints, so ACL, token binding, quotas and audit apply per object in each namespace with no elevated privilege. Writes that must preserve version numbers and timestamps go through one new import endpoint per engine. Shares are planned by a pure function and written through the identity `ShareStore`.

**Tech stack:** Rust (`bv-engine-resource`, `bv-engine-kv`, `bv-kernel`, `bvault-cli`), Tauri + React/TS GUI. Test with `cargo nextest`; integration tests live in `src/engine_tests/` because they need `test_utils`.

**Spec:** `features/cross-namespace-copy-move.md` (read it first; the decisions table is binding).

## Global constraints

- New routes go under `v2/` (AGENTS.md §7); `v1` is frozen.
- Copy: read on every origin object read + write on destination. Move: also **delete on origin**. Overwrite also needs **delete on destination**.
- Name collision: refuse by default; `on_conflict` is `refuse` | `rename` | `overwrite`.
- Ownership in the destination is the **caller**; the original owner goes into the destination history entry, never carried over.
- Shares: kept only if the grantee is valid in the destination, else dropped with a structured warning; a run with warnings is a success.
- Move = copy, verify, then delete source. A mid-failure leaves the source intact.
- Never log or audit secret values; audit records operation, both paths and counts, in **both** namespaces.
- No persisted-format change; if one appears necessary, stop and apply read-old / write-new first.
- High-risk (authz, secret handling): tasks marked complex go to `architect`; the final review runs on Opus.

## Review focus

- A secret on the resource the caller cannot read (ACL deny on one key): whole transfer refused, nothing written, source untouched.
- Destination write fails halfway: source is never deleted on move; response says what was written.
- Source mutated during the copy (new version arrives): move aborts before delete and reports it.
- Caller token not usable in the destination namespace (binding): refused with the underlying permission error, not a partial copy.
- Share grantee is a group that exists only in the source namespace, or an entity from a sibling namespace: dropped with a named warning.

---

### Task 1: Resource import endpoint

**Tier:** complex (architect) - writes secrets and history, security-sensitive

**Files:**
- Modify: `crates/bv-engine-resource/src/lib.rs` (route table near line 415; new handler beside `handle_resource_rename`, ~line 1524)
- Test: in-crate `#[cfg(test)]` in the same crate

**Interfaces:**
- Produces: `resources/v2/transfer/import/<name>` (Write), body `ResourceBundle { meta: Map, secrets: Vec<SecretBundle>, history: Vec<ResourceHistoryEntry>, on_conflict: String, origin_owner: String, origin: String }` where `SecretBundle { key: String, versions: Vec<{version: u64, created_time: String, deleted: bool, data: Map}>, current: u64 }`. Response `{ name: String, secrets: usize, versions: usize, history: usize }`.
- Consumes: the storage layout consts `META_PREFIX`, `HIST_PREFIX`, `SECRET_PREFIX`, `SMETA_PREFIX`, `SVER_PREFIX`.

- [ ] **Step 1: Write failing tests** `import_writes_meta_secrets_versions_and_history`, `import_refuses_existing_name_by_default`, `import_overwrite_replaces_and_rename_picks_free_name`, `import_rejects_name_with_slash_or_dotdot`. Assert version numbers and timestamps equal the bundle's, and that a final history entry has `op == "transfer-in"` carrying `origin` and `origin_owner`.
- [ ] **Step 2: Run** `cargo nextest run -p bv-engine-resource --lib import_` ; expect FAIL (no handler).
- [ ] **Step 3: Implement** `handle_resource_import(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError>` reusing rename's name validation and case-insensitive collision scan. Write order: secrets/versions, history, then `meta/` last so a half-written import is invisible to listings. Do not touch ownership or shares here.
- [ ] **Step 4: Run** the same command; expect PASS. Then `cargo check -p bv-engine-resource && cargo fmt -p bv-engine-resource && cargo clippy -p bv-engine-resource --lib`.
- [ ] **Step 5: Commit** `feat(resource): import endpoint that preserves versions and history (T494, S120)`.

### Task 2: KV import endpoint

**Tier:** complex (architect) - secret handling, KV v2 version layout to be read first

**Files:**
- Modify: `crates/bv-engine-kv/src/v2/mod.rs`, `crates/bv-engine-kv/src/v2/version.rs`
- Test: in-crate tests

**Interfaces:**
- Produces: `<kv-mount>/v2/transfer/import/<path>` (Write), body `{ versions: [{version, created_time, deleted, data}], current: u64, metadata: Map, on_conflict }`, response `{ path, versions: usize }`.

- [ ] **Step 1: Write failing tests** `import_preserves_version_numbers_and_flags`, `import_refuses_existing_path_by_default`, `import_overwrite_replaces_all_versions`.
- [ ] **Step 2: Run** `cargo nextest run -p bv-engine-kv --lib import_` ; expect FAIL.
- [ ] **Step 3: Implement** the handler beside the v2 metadata handlers; write the metadata record last.
- [ ] **Step 4: Run** the tests, `cargo check -p bv-engine-kv`, `cargo fmt -p bv-engine-kv`; expect PASS.
- [ ] **Step 5: Commit** `feat(kv): import endpoint that preserves versions (T494, S120)`.

### Task 3: Share planner

**Tier:** complex (architect) - authz decision logic

**Files:**
- Create: `crates/bv-kernel/src/modules/system/transfer/shares.rs`, `crates/bv-kernel/src/modules/system/transfer/mod.rs`
- Modify: `crates/bv-kernel/src/modules/system/mod.rs` (declare `mod transfer;`)

**Interfaces:**
- Produces:
  `pub struct ShareWarning { pub code: String, pub subject: String, pub message: String }`
  `pub struct SharePlan { pub keep: Vec<SecretShare>, pub dropped: Vec<ShareWarning> }`
  `pub async fn plan_shares(source: Vec<SecretShare>, dest_ns: &str, caller_may_grant: bool, entities: &EntityStore, groups: &GroupStore) -> SharePlan`
- Consumes: `ShareStore::list_shares_for_target`, `SecretShare`, `ShareGranteeKind`, `Entity.namespace`.

- [ ] **Step 1: Write failing tests** `entity_in_destination_is_kept`, `entity_from_root_is_kept_for_namespaced_destination`, `entity_from_sibling_namespace_is_dropped`, `group_missing_in_destination_is_dropped`, `no_grant_right_drops_all_with_reason`, `capabilities_unchanged_including_connect`. Assert the warning `code`s are `grantee-not-in-destination`, `group-not-in-destination`, `cannot-grant`.
- [ ] **Step 2: Run** `cargo nextest run -p bv-kernel --lib shares::` ; expect FAIL.
- [ ] **Step 3: Implement** `plan_shares` following the spec's "Share validation" section; pure over its inputs apart from the store lookups, never mutating stores.
- [ ] **Step 4: Run** tests, `cargo check -p bv-kernel`, `cargo fmt -p bv-kernel`; expect PASS.
- [ ] **Step 5: Commit** `feat(kernel): share validation for namespace transfer (T494, S120)`.

### Task 4: Orchestrator and `v2/sys/namespace-transfer`

**Tier:** complex (architect) - permission model, multi-namespace writes, partial-failure safety

**Files:**
- Create: `crates/bv-kernel/src/modules/system/transfer/orchestrate.rs`
- Modify: `crates/bv-kernel/src/modules/system/transfer/mod.rs`, `crates/bv-kernel/src/modules/system/mod.rs` (path `namespace-transfer/(?P<op>copy|move)$`, Write, v2 shim only)

**Interfaces:**
- Consumes: Task 1, 2 import endpoints; Task 3 `plan_shares`; `VaultCtx::handle_request`; `ObjectKind`.
- Produces: request body `TransferRequest { kind: "resource"|"kv-secret", source: Location, destination: Location, on_conflict: String, dry_run: bool }` with `Location { namespace: String, mount: String, path: String }`; response `TransferResult { transferred: {secrets, versions, history, shares}, warnings: Vec<ShareWarning>, dry_run: bool, destination: Location }`.
  `async fn run_transfer(core: &dyn VaultCtx, caller: &Request, op: TransferOp, t: TransferRequest) -> Result<TransferResult, RvError>` where `enum TransferOp { Copy, Move }`.

- [ ] **Step 1: Write failing integration tests** in `src/engine_tests/namespace_transfer.rs` (needs `test_utils`): `copy_resource_carries_secrets_versions_history`, `move_deletes_source_only_after_verified_copy`, `move_requires_delete_on_origin`, `read_denied_on_one_secret_refuses_everything`, `write_denied_on_destination_refuses`, `collision_refuse_rename_overwrite`, `overwrite_requires_delete_on_destination`, `owner_is_caller_and_origin_owner_in_history`, `dry_run_writes_nothing_and_returns_warnings`, `audit_entries_in_both_namespaces`, `source_changed_during_copy_aborts_move`.
- [ ] **Step 2: Run** `cargo nextest run -p bastion_vault --lib namespace_transfer` ; expect FAIL.
- [ ] **Step 3: Implement** `run_transfer`. Order: (1) plan: read source through sub-requests with the caller's client token (`namespace_path` = source), failing on the first denied read; (2) capability probes for destination write, origin delete (move), destination delete (overwrite); (3) share plan; (4) if `dry_run` return; (5) import into destination via sub-request; (6) set ownership to caller via `record_owner_if_absent`, write kept shares via `ShareStore::set_share` with a share-history `copy`/`move` entry; (7) move only: re-read source versions, abort without deleting if they differ, else delete source through the normal delete endpoint. Resource asset-group membership re-created only when a same-named group exists in the destination, else a warning `group-membership-dropped`; attached files re-pointed via the files engine's existing `files/repoint-resource`, a failure there becomes a warning.
- [ ] **Step 4: Run** the tests, then `cargo check -p bv-kernel && cargo check --lib && cargo fmt --all --check`; expect PASS.
- [ ] **Step 5: Commit** `feat(sys): copy and move resources and secrets across namespaces (T494, S120)`.

### Task 5: CLI

**Tier:** routine (builder)

**Files:**
- Create: `crates/bvault-cli/src/command/namespace_transfer.rs`
- Modify: `crates/bvault-cli/src/command/mod.rs`
- Test: `crates/bvault-cli/` command test following `secrets_move.rs` conventions

**Interfaces:**
- Consumes: Task 4 request/response shapes.
- Produces: `bvault transfer copy|move --kind resource|kv-secret <ns/mount/path> <ns/mount/path> [--on-conflict refuse|rename|overwrite] [--dry-run]`; prints counts, then each warning on stderr; exit code 0 with warnings.

- [ ] **Step 1: Write failing test** `parses_locations_and_flags` and `prints_warnings_and_exits_zero`.
- [ ] **Step 2: Run** `cargo nextest run -p bvault-cli --lib transfer` ; expect FAIL.
- [ ] **Step 3: Implement** modelled on `secrets_move.rs`.
- [ ] **Step 4: Run** the tests and `cargo check -p bvault-cli`; expect PASS.
- [ ] **Step 5: Commit** `feat(cli): bvault transfer copy|move (T494, S120)`.

### Task 6: Tauri command and GUI

**Tier:** routine (builder), three files

**Files:**
- Modify: `gui/src-tauri/src/commands/resources.rs` (new `transfer_resource`), `gui/src/routes/ResourcesPage.tsx` (Info tab action **Copy / Move to namespace**)
- Create: `gui/src/components/TransferToNamespaceModal.tsx` and `TransferToNamespaceModal.test.tsx`

**Interfaces:**
- Consumes: Task 4 over `v2/sys/namespace-transfer/{copy|move}`.
- Produces: modal that first calls with `dry_run: true`, shows counts and a warnings list (dropped shares by grantee and reason), asks confirmation, then runs for real. Follows GUI rules in AGENTS.md §7 (`min-w-0`, `truncate`, Modal sizes).

- [ ] **Step 1: Write failing test** `shows_dropped_share_warnings_before_confirm` and `move_requires_explicit_confirm`.
- [ ] **Step 2: Run** `cd gui && npx vitest run src/components/TransferToNamespaceModal.test.tsx` ; expect FAIL.
- [ ] **Step 3: Implement** the modal and command.
- [ ] **Step 4: Run** the test, `cd gui && npx tsc --noEmit`, `cargo check -p bastion-vault-gui`; expect PASS.
- [ ] **Step 5: Commit** `feat(gui): copy or move a resource to another namespace (T494, S120)`.

### Task 7: Docs and tracking

**Tier:** routine (builder), no code

**Files:**
- Modify: `docs/api.md`, `docs/cli-reference.md`, `features/cross-namespace-copy-move.md` (Current State, phase table), `CHANGELOG.md`, `ROADMAP.md` (T494 to `[x]`)

- [ ] **Step 1:** Add the endpoint, CLI usage and the permission rules to the docs; changelog entry under `[Unreleased]` / Added, first line ending `(T494, S120)`.
- [ ] **Step 2: Verify** the PTF invariants (`docs/tracking-format.md` §5) hold: T494 `[x]` has a changelog entry.
- [ ] **Step 3: Commit** `docs: cross-namespace copy and move (T494, S120)`.

### Final gate

- [ ] Run `make test-plan` then `make test-changed` once (one cargo at a time, AGENTS.md §5).
- [ ] `reviewer` on Opus over the full diff (authz and secret handling). Required before merge.
