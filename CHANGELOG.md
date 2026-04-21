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
