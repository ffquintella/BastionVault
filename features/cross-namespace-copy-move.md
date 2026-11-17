# Feature: Cross-namespace copy and move of resources and secrets

## Summary

Let an operator **copy** or **move** a resource, or a KV secret, from one
namespace to another, carrying everything that belongs to it: the record, every
secret on a resource, every secret's version history, the resource's change
history, and the explicit shares. The caller must hold the rights to do it in
both namespaces, and anything that cannot be carried over faithfully is
reported to the caller as a warning, never dropped silently.

## Motivation

`bvault secrets move` relocates a whole engine mount (`secrets_move.rs`). There
is no way to relocate one resource or one secret. Operators who reorganise
tenants today must read each value, rewrite it by hand in the other namespace
and lose the version history, the change history and the shares.

## Current State

**Done (2026-11-17).** One resource, or one KV v2 secret, can be copied or
moved to another namespace (or inside one) with its record, every secret and
version, the change history of a resource, its shares and its asset-group
membership, from three surfaces:

- `POST /v2/sys/namespace-transfer/{copy|move}` (`docs/api.md`): reads, rights
  checks, `dry_run`, refuse / rename / overwrite, caller ownership, a verified
  move, warnings and the relations below.
- `bvault transfer copy|move` (`docs/cli-reference.md`), with
  `--source-mount` / `--destination-mount`, `--on-conflict` and `--dry-run`.
- The Resources page of the desktop app: a Copy or move action on a
  resource's Info tab that checks first (dry run) and shows the warnings
  before anything is written. It calls the Tauri command `transfer_object`.

Not done: the KV secrets page has no action yet (the modal and the command
are reusable), and the GUI was proven only in jsdom, not in a live window.
Follow-ups are tracked in `ROADMAP.md` (T496-T505; T502 and T503 are
done). What the feature cannot
carry is under "Known limits".

Closest existing behaviour before this feature, reused as the pattern, not
called as-is:

- `handle_resource_rename` (resource engine) migrates `meta/`, `hist/`,
  `secret/` `smeta/` `sver/`, asset-group membership, shares
  (`ShareStore::rename_target`) and ownership (`OwnerStore`), write-new then
  delete-old, refusing a name collision. It stays inside one namespace.
- Share and owner records are keyed `<ns>/<name>`; entities carry a
  `namespace` tag and the alias index is per namespace
  (`identity/entity_store.rs`).
- `src/exchange/namespaces.rs` already splits exports per namespace; it is a
  file-based path and is not the mechanism here.

## Decisions (confirmed by the maintainer, 2026-11-17)

| Topic | Decision |
|---|---|
| Permissions, copy | Caller needs **read** on every object being read in the origin (record, each secret, each version, history, shares) and **write** on the destination. |
| Permissions, move | Everything copy needs, **plus delete** on the origin, because a move removes the source. |
| Name collision | Refuse by default. The caller may choose *rename to a free name* or *overwrite*; overwrite additionally requires **delete** on the destination item. |
| Ownership | The **caller** owns the item in the destination. The original owner is recorded in the destination history entry. Ownership is never carried over. |
| Shares | Validated against the destination; carried over where valid, otherwise dropped with a warning (below). |
| Warnings | Any dropped or altered part is returned in a structured `warnings` list and shown by the CLI and GUI. A run with warnings is a success, not an error. |

## Scope

- **Resource**: record (`meta/`), change history (`hist/`), all secrets
  (`secret/`), all versions (`smeta/`, `sver/`), explicit shares, asset-group
  membership, attached file resources.
- **KV secret**: the secret, all its versions and metadata, explicit shares.
- Entry points: `v2/` HTTP API (AGENTS.md §7 — new routes go under `v2/`),
  `bvault` CLI, Tauri command, GUI action on the Resources page (the KV
  secrets page is a follow-up).
- A move is **copy, verify, then delete the source**. A mid-failure leaves the
  source intact and at most a recoverable partial destination, never a gap, the
  same ordering rename already uses. Copy never touches the source.

## Non-goals

- Moving a whole mount or engine (that is `secrets move`).
- Rewriting policy documents. Policies are namespace-scoped and cannot
  reference another namespace's paths, so a policy that named the old path is
  not carried and the result tells the user to review policies.
- Dynamic or engine-generated state (PKI, transit keys, leases). Only
  resources and KV secrets.
- Bulk copy of a whole tree in one call in the first release; one object per
  call, with the API shaped so a list of objects can be added later.

## Anti-goals

- The copy must never expose a value to a caller who could not already read
  it. No privilege is gained by routing through this operation.
- No silent partial result: if a version, a secret or a share did not make it,
  the caller is told which.
- Ownership and share grants must never be widened by the move.

## Share validation

A share is `(target, grantee, capabilities)` (`share_store.rs`). Per share,
the destination check is:

1. **Entity grantee**: kept only if the entity exists and lives in the
   destination namespace or in the root namespace (the rule the grantee picker
   uses, `grantee_namespaces`). An entity of any other namespace is dropped
   with `grantee-not-in-destination`; the grantee is never guessed from its
   login across namespaces.
2. **Group grantee** (`group_user` / `group_app`): kept only if a group of that
   name exists in the destination namespace. Otherwise dropped.
3. **Asset-group targets** are not shares of the moved object; asset-group
   membership is re-created only if a group of the same name exists in the
   destination itself (not merely inherited), the caller can see all its
   members and may modify it. A group is never created. Otherwise it is
   reported as `group-membership-dropped`.
4. **Capabilities** are carried unchanged; the vocabulary is the store's
   existing one (including `connect`).
5. Dropped shares are listed individually (grantee, capabilities, reason). If
   every share is dropped the warning says so. Carried shares are re-keyed to
   `<dest-ns>/<name>` and logged in the share history as a `copy` / `move` op.
6. The caller needs the right to grant shares in the destination for the
   carried shares to be written; without it all shares are dropped with
   `cannot-grant` (the object itself is still copied). Shares are written
   through the share API as the caller, so its owner-or-administrator check
   applies; only the item's owner or an administrator may list the source's
   shares (otherwise `shares-unreadable`). Expired shares and unknown grantee
   kinds are dropped with their own codes.

## API and result shape

`POST v2/sys/namespace-transfer/{copy|move}` with body
`{ kind: "resource"|"kv-secret", source: {namespace, mount, path},
destination: {namespace, mount, path}, on_conflict: "refuse"|"rename"|
"overwrite", dry_run: bool }`. `docs/api.md` is the reference for the fields,
the rights, the collision modes and every warning code.

`dry_run: true` runs every read, rights check and collision check and returns
the plan and the warnings without writing anything, so the GUI can show the
warnings before the user confirms. The response is
`{ transferred: {secrets, versions, history, shares}, warnings: [{code,
subject, message}], dry_run, destination }`: counts and warnings, never a
value.

`rename` and `overwrite` are the orchestrator's doing. The two import routes
it writes through accept `refuse` only: rename tries `refuse` imports at
`<name>-2` ... `<name>-100` so the ACL checks every name it attempts, and
overwrite tries the import first and, if the name is taken, runs an ordinary
DELETE of the destination (which cleans up its owner, shares and groups) and
imports again.

## Security notes

- Authorization is evaluated per object against the **caller's** token in each
  namespace, using the normal ACL path; the operation does not run with
  elevated privileges. This is high-risk (authz, secret handling): any
  implementation goes to `architect` and review runs on Opus (AGENTS.md §1).
- Secret values are read and written inside the server and never logged or put
  in audit entries.
- Every step is an ordinary request made with the caller's token, so each one
  is audited by the normal request pipeline (the reads and the delete at the
  origin, the writes at the destination, no secret value in an entry). Entries
  are attributed to the token's namespace, as for every request, so a root
  token's transfer reaches only root audit devices; this feature does not
  change that. The orchestrator adds one server-log line per transfer
  (operation, kind, user, both paths, counts), never a value.
- Versioning data written to the destination keeps version numbers and
  timestamps from the source; the history entry marks the arrival.
- The two import routes are **internal-only**: the orchestrator marks its own
  import sub-requests in-process (`Request::ctx`, which HTTP cannot set), and
  any other request to them, over HTTP or in-process, is refused as an
  unknown route there: the ACL and the token's namespace binding run on the
  literal path (403 for a token that may not write there), then the policy
  layer, and again the handler, answer 404. The body is never read and the
  item never looked up, so the answer does not reveal whether the mount or
  the item exists. A client therefore cannot write history, origins or
  version authors of its choosing. Any Rust code linked into the server
  process can set the marker: it guards against clients (HTTP, MCP,
  plugins), not against in-process code, which is trusted (WASM and process
  plugins cannot set it). As defence in depth,
  the marked imports are authorised against the **real** item path (the
  policy layer maps `<mount>/v2/transfer/import/<p>` to the path a normal
  write is checked on), so deny rules, owner and share scopes and per-secret
  paths apply. One transfer carries at most 1000 secrets per resource.
- A namespace the token may not operate in is answered exactly as one that
  does not exist, and as a mount the caller cannot see (one 400), so the
  route tells nothing about namespaces the caller may not use (T503).
- An import whose answer names another item than the one the ACL checked
  fails with a 500 naming the item, never leaving it silently unowned (T502).
- No persisted-format change is expected; if one is needed, apply the
  read-old / write-new rule before building.

## Decisions taken while building

- The orchestration lives in the kernel `sys/` module
  (`crates/bv-kernel/src/modules/system/transfer/`), driving ordinary requests
  through `Core::handle_request` with the caller's token, once per namespace.
- Concurrency: a move re-reads the source after the copy and deletes it only
  if nothing changed; otherwise it answers 409, keeps both and says what was
  written.
- One object per call; `dry_run` is on the API. A soft-deleted KV version
  arrives destroyed (its value cannot be read), and the source is never
  undeleted.

## Known limits

- Fixed by T504: a deny written as `<mount>/data/<path>` now refuses a KV
  import of `<path>`, as it refuses every KV v2 route to that secret.

- **Entity shares.** An entity grantee is carried only if its entity lives in
  the destination namespace or in the root namespace, so entity shares
  survive a root to namespace transfer; an entity of another namespace is
  dropped with a warning. Group shares carry wherever a group of the same
  name exists in the destination.
- **Attached files** are re-pointed only by a move within one namespace; in
  every other case the blobs stay where they are, attached to the source name,
  and `files-not-transferred` says so. Each namespace has its own files
  engine.
- **Overwrite is not atomic**: it tries the import first; if the name is
  taken it deletes the destination and imports again, and if that import
  fails the destination stays deleted (the error says so). It cannot
  pre-check the brokered-resource and agent-access gates, which depend on the
  asset groups the delete prunes.
- **Namespace existence.** The transfer route answers a namespace the token
  may not operate in as one that does not exist (T503), but the request
  pipeline still answers a namespace header naming a missing namespace with
  a 404 before authentication (T512).
- **At most 1000 secrets per resource** (400 above that).
- **Soft-deleted KV versions** are copied as destroyed, with a
  `deleted-version-not-recoverable` warning. A move then deletes the only
  copy `undelete` could still recover, and its warning says so.
- **KV environment overrides** are rebuilt from per-environment reads, so an
  override equal to its base value is normalised away
  (`kv-environment-overrides-normalized`).
- **Group membership updates are read-modify-write**: a concurrent edit to
  that asset group between the read and the write can be lost.
- **Tokens bound to a CIDR are refused** before any step (403 naming the
  binding): the steps are internal sub-requests with no client address, so
  the binding could not be checked on them.
- **Use-limited tokens** (`num_uses`) spend one use per sub-request (each
  read, rights check, import, share write and delete), so a transfer can
  exhaust the token partway. That is data-safe: what was copied stands and the
  source is untouched until the copy is complete, when a move deletes it.
  The exception is an overwrite whose token runs out between its delete and
  its import, which leaves the destination deleted like any failed overwrite.
- **Rights.** The route is evaluated in the request's active namespace and
  needs `update` on `sys/namespace-transfer/*` plus `sys/capabilities-self`
  there; no built-in policy grants the former. `bvault transfer` has no flag
  for the namespace header (planned).
- **Policies naming the source path are not rewritten** (always warned as
  `policies-not-carried`).
- **The import routes are internal-only.**
  `resources/v2/transfer/import/<name>` and `<kv-mount>/v2/transfer/import/<p>`
  exist for the orchestrator and cannot be called directly: any request the
  orchestrator did not mark is answered as an unknown route at that place
  (404 for a token otherwise allowed to write there, 403 otherwise), never
  revealing whether the mount or the item exists. The marker is trusted
  in-process: any Rust code linked into the server can set it, no client
  (HTTP, MCP, WASM or process plugin) can. The orchestrator's own imports
  are refuse-only and ACL-checked against the real path; one its import
  route refuses as an unknown route is reported as a 500 internal error.

## Phases

| Phase | Content | Status |
|---|---|---|
| 1 | Engine-side import of a resource and a KV secret with versions and history, collision handling | Done |
| 2 | Import routes authorised against the real item path (ACL, owner and share scopes) and internal-only (an unknown route unless the orchestrator marked the request) | Done |
| 3 | Share planner, `dry_run`, warnings | Done |
| 4 | Orchestrator and `POST /v2/sys/namespace-transfer/{copy\|move}`: rights checks, refuse / rename / overwrite, verified move, shares, asset-group membership, files | Done |
| 5 | `bvault transfer copy\|move` | Done |
| 6 | Tauri command `transfer_object` and the Resources page action with the dry-run warning preview | Done |
| 7 | Tests: permission matrix, collision, partial failure, shares kept / dropped, aliasing of one item, in-crate, facade and GUI | Done |
