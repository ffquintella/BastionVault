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

**In progress (2026-11-17).** Implemented: the import endpoints
(`resources/v2/transfer/import/<name>`, `<kv-mount>/v2/transfer/import/<path>`,
refuse-only, authorized as a write of the real item), the share planner, and
`POST /v2/sys/namespace-transfer/{copy|move}` (`docs/api.md`): reads, rights
checks, `dry_run`, refuse/rename/overwrite, caller ownership, verified move,
warnings, and the relations: shares written through the share API as the
caller (history op `copy` / `move`), membership of same-named destination
asset groups, and attached files re-pointed by a move within one namespace
(otherwise `files-not-transferred`: blobs are never copied between
namespaces). Not yet: CLI, Tauri command, GUI.

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
  `bvault` CLI, Tauri command, GUI action on the resource and KV pages.
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

1. **Entity grantee**: kept only if the entity exists and is usable in the
   destination namespace (its `namespace` is the destination or an ancestor
   whose aliases the destination can see, as the grantee picker already
   allows). Otherwise dropped.
2. **Group grantee** (`group_user` / `group_app`): kept only if a group of that
   name exists in the destination namespace. Otherwise dropped.
3. **Asset-group targets** are not shares of the moved object; asset-group
   membership is re-created only if a group of the same name exists in the
   destination, otherwise reported.
4. **Capabilities** are carried unchanged; the vocabulary is the store's
   existing one (including `connect`).
5. Dropped shares are listed individually (grantee, capabilities, reason). If
   every share is dropped the warning says so. Carried shares are re-keyed to
   `<dest-ns>/<name>` and logged in the share history as a `copy` / `move` op.
6. The caller needs the right to grant shares in the destination for the
   carried shares to be written; without it all shares are dropped with that
   reason (the object itself is still copied).

## API and result shape (proposal, builder may refine)

`POST v2/sys/namespace-transfer/{copy|move}` with body
`{ kind: "resource"|"kv-secret", source: {namespace, path}, destination:
{namespace, path}, on_conflict: "refuse"|"rename"|"overwrite", dry_run: bool }`.

`dry_run: true` runs every permission and share check and returns the plan and
the warnings without writing anything, so the GUI can show the warnings before
the user confirms. The response lists what was transferred (counts of secrets,
versions, history entries, shares) and `warnings: [{code, subject, message}]`.

## Security notes

- Authorization is evaluated per object against the **caller's** token in each
  namespace, using the normal ACL path; the operation does not run with
  elevated privileges. This is high-risk (authz, secret handling): any
  implementation goes to `architect` and review runs on Opus (AGENTS.md §1).
- Secret values are read and written inside the server and never logged or put
  in audit entries; audit records the operation, the two paths and counts.
- Audit entries are emitted in **both** namespaces (the origin sees the read /
  delete, the destination sees the write), consistent with the cross-namespace
  audit rules in `namespaces-multitenancy.md`.
- Versioning data written to the destination keeps version numbers and
  timestamps from the source; the history entry marks the arrival.
- No persisted-format change is expected; if one is needed, apply the
  read-old / write-new rule before building.

## Left to the builder

Where the orchestration lives (the facade, since it spans the resource engine,
KV engine and `ShareStore`), how the destination namespace's barrier view is
reached with the caller's token, exact error codes, the file-resource
re-point step, GUI wording, and concurrency behaviour when the source changes
during the copy (recommended: re-read versions after copy and fail the move,
leaving the source, if they differ).

## Open points for the maintainer

None blocking. Calls made by the author, not confirmed: one object per call;
`dry_run` on the API; file resources travel with their resource; asset-group
membership is re-created only when a same-named group exists in the destination.

## Phases

| Phase | Content | Status |
|---|---|---|
| 1 | Engine-side copy/move of a resource and a KV secret with versions and history, collision handling, permission checks | Done |
| 2 | Share validation, warnings, `dry_run` | Done (shares, asset-group membership and files carried or reported) |
| 3 | CLI, Tauri command, GUI action with warning dialog | Planned |
| 4 | Tests: permission matrix, collision, partial failure, shares kept/dropped, audit in both namespaces | Planned |
