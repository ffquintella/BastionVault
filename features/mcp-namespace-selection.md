# Feature: MCP Namespace Selection — agent calls run in the operator's child namespace

**Status: Implemented — Phases 1, 2 and 3 (2026-10-26).** Owner decisions recorded 2026-10-19 (see "Decisions"). Tracked as ROADMAP T457 under M8, next to MCP Access (T80, T94) and MCP Brokered Sessions (T136–T138). Written against the tree at 0.44.46; landed on 0.45.7 (see "Phase 1 as built" and "Phases 2 and 3 as built"). **High-risk area** (authn/authz, token binding, persisted pairing record): `make test-release` is required before merge.

## Summary

An operator signed in to a child namespace (for example `dti/esi`) pairs an AI client through `bvault mcp serve` or the desktop app. Today:

- `bv_resource_list` sees only root-namespace resources;
- `bv_resource_ssh_exec` cannot reach the operator's servers;
- MFA-gated profiles fail with `mcp_session_mfa_unavailable`.

`docs/mcp.md:586-589` records this as a known gap ("agent calls run in the root namespace"). This spec makes the MCP principal act in the operator's own namespace, with the namespace taken from the token's stored binding and never from anything the client or model supplies.

**Recommendation: option C, a token-bound namespace fixed at the pairing exchange.** Phase 1 inherits the operator's namespace and fixes the reported case with no new input. Phase 2 optionally narrows to a descendant. No tool schema, catalogue hash or route changes.

## Root cause (verified)

1. **The minted MCP token is root-bound.** `mint_mcp_token` builds `TokenEntry { .., ..TokenEntry::default() }` (`crates/bv-kernel/src/modules/auth/token_store.rs:1174-1184`), so `meta` is empty. With no `ns_path`, the token reads as root-bound and non-child-visible (`crates/bv-kernel/src/modules/namespace/token_binding.rs`, module doc). The operator's namespace is recorded only in `McpBinding.operator.namespace` (`crates/bv-kernel/src/modules/system/mcp.rs:340-359`, `crates/bv-logical/src/auth.rs:341-352`), which is read for attribution and MFA ticket redemption only, never for enforcement.
2. **Dispatch carries no namespace.** `InProcessMcpBackend::handle` builds `Request::new(path)` and sets no `namespace_path` (`src/mcp_endpoint.rs:310-335`), so every tool call routes to root. `mcp_token_exchange` and `mcp_dispatch` (`crates/bv-server/src/mcp_routes.rs`) do not read `X-BastionVault-Namespace`.
3. **The MFA guard is correct and fails closed.** `agent_session.rs:381-392` compares `caller_namespace(req)` (always root today) with `operator.namespace` (`dti/esi`) and refuses with `mcp_session_mfa_unavailable`.
4. **The operator-side step-up sends no namespace either.** `connect_mfa_begin` / `connect_mfa_verify` in `crates/bvault-cli/src/command/mcp_serve.rs` (`HttpVaultLink`) and `gui/src-tauri/src/mcp_host/link.rs` call the vault with the operator's client and no namespace header.

## Options

| | A. `namespace` argument on each tool | B. Per-session / profile setting chosen by the client | C. **Token-bound, fixed at pairing exchange (recommended)** |
|---|---|---|---|
| Who picks the namespace | the model, per call | the client, at connect | the vault, from the operator's own login (optionally narrowed, Phase 2) |
| Authorization source | a client-supplied string | a client-supplied string | the token's stored binding, re-checked by `token_may_operate` |
| Model can widen the blast radius | yes, every call | no | no |
| Tool schemas / catalogue hash | all change | unchanged | unchanged |
| MFA ticket and `args_hash` binding | the argument joins the hash; namespace can drift per call | ok | ok; constant for the token's life |
| Confirmation dialog shows namespace | per call | once | once, read from the token |

**Reject A.** The model controls the namespace, so a prompt injection could steer calls across tenants, and every tool schema and the catalogue hash change. **Reject B as an authority.** A client string cannot be trusted; it survives only as a narrowing *request* validated by C's rules (Phase 2).

## Design

### Phase 1 — inherit the operator's namespace

- **Mint.** `exchange_pairing` derives `(ns_path, child_visible)` from the exchanging operator token's metadata with `binding_from_metadata`, normalized as `operator_ref_from_auth` already does (`mcp.rs:347-352`). `mint_mcp_token` stamps `NS_PATH_META = ns_path` and `CHILD_VISIBLE_META = "false"` on the new token's `meta`, using the existing `kernel_api::namespace` keys. An MCP token is never child-visible.
- **Dispatch.** `InProcessMcpBackend` holds the namespace read from the token's binding (`binding_from_metadata(auth.metadata)`) and sets `req.namespace_path` on every request. It never reads a header, a body field or a tool argument. `X-BastionVault-Namespace` on `/v2/mcp` has no effect for an MCP-bound token.
- **Enforcement.** Policies already resolve per token namespace, and `enforce_request_token_binding` stays the second gate.
- **No fallback to root.** A namespace that is deleted, unresolvable or malformed fails the call with `mcp_namespace_unavailable` (403). A root-bound operator is unchanged.
- **MFA.** Calls now run in `dti/esi`, so the guard at `agent_session.rs:384` passes unchanged. The operator-side `connect/mfa/begin|verify` calls must go to the same namespace: `HttpVaultLink` and the desktop `link.rs` send `X-BastionVault-Namespace` taken from the **operator's own session**, not from the MCP client. See open question 1.
- **Audit.** The request is in the namespace, so the per-namespace broadcaster and the root mirror record it. The `mcp` audit enrichment (`McpAuditContext`), the `connect.agent.*` events and the transcripts also carry an explicit `namespace` field. The pairing approval dialog, the per-call confirmation dialog and `bv_whoami` show it.
- **Follow the operator's session (decided).** The pairing does not pin a namespace (as built in Phase 2, a narrowing chosen in the desktop dialog is kept on the pairing record as a request, re-validated by the vault at every exchange). Each exchange binds the new token to the namespace of the session that exchanges it, so an operator who signs in elsewhere and reconnects gets a token for that namespace. The pairing approval dialog and the per-call confirmation always show the namespace the token is bound to, and a change of namespace between two exchanges of the same pairing is recorded in the audit trail. `path_scope` globs are evaluated relative to the token's namespace, so the same pairing reaching a different tenant is visible to the operator in the dialog, not hidden.

### Phase 2 — optional narrowing to a descendant (in scope, decided)

The pairing request may carry `namespace` (for example a child-visible root admin who wants `dti/esi`). The vault accepts it only when `token_may_operate(operator_binding, requested)` holds, and mints the token bound to the requested namespace with `child_visible = false`. Otherwise it answers 403 `mcp_namespace_not_permitted`; it never downgrades silently. **The requested policies must resolve in the target namespace** (decided): the exchange checks each requested policy name against the target namespace's policy store and refuses with 400 `mcp_policy_not_in_namespace` naming the missing ones, instead of minting a token whose root-namespace policies evaluate to nothing. Surfaces: one optional field on the existing `sys/mcp/token` write, `bvault mcp serve --namespace`, and a selector in the desktop pairing dialog.

### Phase 3 — documentation and GUI

Retire `docs/mcp.md:586-589` and the namespace clause of the `mcp_session_mfa_*` troubleshooting row; show the namespace in Settings → AI Assistants.

## API and v2 rule

No new route. `v2/mcp` and `v2/mcp/token` already exist; Phase 2 adds one optional body field on the existing exchange write, under `v2/`. `v1` is untouched. `docs/api.md` documents the field.

## Persisted formats (read-old / write-new)

| Record | Change | Old data |
|---|---|---|
| Token entry | none; reuses `ns_path` / `child_visible` meta | tokens minted before have no `ns_path` and stay root-bound (their prior behavior; TTL ≤ 24 h) |
| `McpBinding` | none; token meta is the single source of truth, so the two cannot drift | unchanged |
| `PairingRecord` (local file) | additive optional `namespace` (as built, Phase 2): the narrowing chosen in the desktop dialog, written only when chosen | absent = follows the operator's session, as before |
| `McpAuditContext`, audit events, transcripts | additive `namespace` field | absent = root |
| `McpTokenIndexEntry` (`mcp/app-tokens/…`) | additive `namespace` (as built) | absent = minted before binding existed, i.e. root-bound |
| `mcp/pairing-namespaces/<id>` (as built) | new, `version: 1`: the namespace of a pairing's last exchange, for the move record; deleted with the pairing | absent with index entries = the previous tokens were root-bound |

## Security analysis

- **Authority** is the token's stored binding, evaluated by `token_may_operate` and `enforce_request_token_binding`. A client string is never authoritative: not a header, not a tool argument, not a pairing-file value.
- **Mint-time input** is the operator's own authenticated token (Phase 1) or is validated against it (Phase 2), mirroring the policy-subset rule in `mint_mcp_token` (`token_store.rs:1158`).
- **Never child-visible**, so an MCP token cannot climb or descend after mint.
- **Narrowing re-resolves policy names (as built, trade-off).** A narrowed token's policy names are evaluated in the target namespace's store, as they would be for the same login made directly in that namespace. A same-named policy authored in the descendant therefore defines the agent's reach there, which can differ from (and exceed) what the operator's own token, whose names resolve in its binding namespace, has in that descendant. The pairing grant still narrows it, and `token_may_operate` limits narrowing to namespaces the operator's namespace configuration already lets that login reach.
- **Cross-tenant reach is unchanged**: the agent gets at most what the operator has in that namespace, narrowed by the pairing grant (`tool_allowlist`, `path_scope`, reveal/destructive flags). Per-call confirmation and MFA stay bound to one call.
- **Forgery check (to do at implementation).** `NS_PATH_META` is not in `RESERVED_TOKEN_META_KEYS` (`crates/bv-logical/src/auth.rs:92`). Confirm that an `auth/token/create` body `meta` cannot set it for a non-root caller, and reserve it if it can. `mcp_*` keys are already reserved.
- **Fail closed**: malformed, deleted, mismatched or not-permitted namespaces are refused with stable codes, never rewritten to root.
- **Logging**: namespace paths are not secrets and may appear in errors; tokens never do.

## Phase 1 as built (2026-10-26)

- **Mint.** `TokenStore::mint_mcp_token` stamps `namespace_path` (canonical), the parent's `namespace_id` when it has one, and `child_visible = "false"` from the parent's *stored* entry; a malformed binding is refused (`mcp_namespace_unavailable`). The exchange also resolves the namespace in the store first and refuses a deleted one, and checks the minted token agrees (revoking it otherwise). The answer's `auth.metadata.namespace` names it.
- **Apps too (decision).** The same mint path serves `sys/mcp/apps` exchanges, so an app token is bound to its AppRole login's namespace. Rejected: keeping app tokens root-bound, which let a tenant AppRole's token resolve its policy names in the root store.
- **Dispatch.** `mcp_endpoint` resolves the token's binding before any tool runs and again on every routed request, and sets both the namespace header and `namespace_path` on the request it builds; HTTP headers never reach it.
- **Follow.** `mcp/pairing-namespaces/<id>` records each pairing's last namespace; a different one emits `mcp.pairing.namespace_changed` (fail closed on an audit device error) before the token is minted.
- **Step-up fix (Decision 1 result).** The engine test showed the step-up preflight failing with `Router mount not found` for any operator signed in to a child namespace: it was addressed at `<ns>/auth/<mount>/…`, but every auth mount lives in the root auth table. It is now addressed at root (`connect_mfa::step_up_path`). With that, a userpass + TOTP operator in `tenant-a` completes an MFA-gated SSH session through the gatekeeper (`src/engine_tests/mcp_sessions_ssh.rs`).
- **Operator namespace on the client side.** `bvault mcp serve` and the desktop link read it from `auth/token/lookup-self` as the operator (cached per session), never from the MCP client, and send it on `connect/mfa/begin|verify`. `api::Client` now sends the headers `add_header` sets (it silently dropped them).
- **Gap found.** A tenant policy cannot grant `sys/mcp/token` through `sys/policy` (`refuse_cross_namespace_paths` rejects `sys/` rules), so the tests seed it with `PolicyStore::set_policy_ns`. How a tenant operator should be granted the exchange is not settled by this spec.

## Phases 2 and 3 as built (2026-10-26)

- **Exchange.** `sys/mcp/token` takes an optional top-level `namespace` (pairing mode; with `app` it is refused, 400). It is normalized, judged by `token_may_operate` over the exchanging session's stored binding and, failing that, by an explicit namespace assignment read live from the assignment store (see "Amendment: assignments count"), and only then resolved, so a refusal reveals nothing about namespaces out of reach. Codes: 403 `mcp_namespace_not_permitted` (malformed, parent, sibling, unrelated, or a descendant of a non-child-visible session), 403 `mcp_namespace_unavailable` (a permitted descendant that does not exist), 400 `mcp_policy_not_in_namespace` (names the missing policies; `default` excepted, as in ACL building). `TokenStore::mint_mcp_token` takes the resolved target and re-checks `token_may_operate` against the parent's *stored* entry before stamping it, unless the target carries the handler's `assignment_granted` verdict, so the single mint point cannot be talked into another namespace by anything but the handler's own check.
- **Operator reference (decision).** A narrowed binding records the target as `McpBinding.operator.namespace`, so the MFA guard and the ticket binding compare the namespace the calls run in. Rejected: keeping the session's namespace there, which made every MFA-gated session of a narrowed pairing fail with `mcp_session_mfa_unavailable`. The session's namespace is still in the `mcp.pairing.namespace_changed` record.
- **Follow.** A narrowing is a namespace change like any other: the pairing-namespace record and `mcp.pairing.namespace_changed` use the target.
- **Gatekeeper.** `LocalServer::with_requested_namespace` (`bvault mcp serve --namespace`) asks for one namespace on every exchange; a desktop approval may pin one on the pairing record (`PairingGrant.namespace` → `PairingRecord.namespace`). Both set and different: `mcp_namespace_conflict`, nothing sent. A narrowed exchange whose answer names any other namespace (or none, i.e. an older vault that ignores the field) is refused locally, `mcp_namespace_mismatch`, and the token dropped.
- **Deviation 5 fixed.** The token is now minted *before* a per-call confirmation, and the dialog shows `MintedToken.namespace`, read from the exchange answer, not the operator session. The pairing dialog, which precedes any exchange, shows the requested namespace or else the session's. `VaultLink::connect_mfa_begin|verify` take the token's namespace, so the operator's step-up runs where the call runs (falling back to the session's only when the vault did not report one).
- **Desktop.** The approval dialog offers a "Namespace for its tokens" selector: the session's namespace and the operable namespaces beneath it (`sys/namespaces-self`), never a parent or sibling; the vault still decides. Confirmations show "Runs in namespace …". Settings → AI Assistants has a Namespace column: the live token's namespace (`LocalServer::token_namespaces`), else the pinned one, else "follows your sign-in", with a `narrowed` badge.
- **Docs.** `docs/mcp.md` "Namespaces", known gaps and troubleshooting; `docs/api.md` exchange field, codes and response `namespace`.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Token stamped with the operator's namespace; dispatch sets `namespace_path`; operator-side MFA calls carry the namespace header; audit field; follow-the-session rebind; dialogs, `bv_whoami` and `bv_resource_list` show the namespace | Done |
| 2 | Optional descendant narrowing on the exchange, policy-resolves-in-target check, CLI flag, desktop selector | Done |
| 3 | Docs and Settings → AI Assistants display; dialogs draw the namespace | Done |

## Testing requirements

- **Kernel / logical.** The minted MCP token carries `ns_path` and `child_visible=false`; a token without the key stays root-bound; a forged `ns_path` through token create is refused.
- **`src/engine_tests/mcp_access.rs`.** An operator in `tenant-a` pairs; `bv_resource_list` sees `tenant-a` resources and not root's; a root resource is not readable; a root operator is unchanged.
- **Injection regression.** `X-BastionVault-Namespace: other` on `/v2/mcp` and a `namespace` tool argument change nothing.
- **Isolation.** Sibling and parent namespaces are refused; a deleted namespace yields `mcp_namespace_unavailable`, not root.
- **`src/engine_tests/mcp_sessions_ssh.rs`.** An MFA-gated profile in a child namespace completes (replacing the current "unavailable" expectation); a ticket minted for namespace A is refused in B.
- **Follow.** Re-exchanging the same pairing from a session in another namespace yields a token bound to that namespace, with a namespace-change audit record; the dialog payload carries the namespace.
- **Phase 2 policies.** A requested policy absent from the target namespace is refused with `mcp_policy_not_in_namespace` (`src/engine_tests/mcp_access.rs`).
- **Phase 2.** Table test over `token_may_operate` (`token_store.rs`, `mcp_namespace_narrowing_follows_token_may_operate`): descendant with a child-visible parent allowed; sibling, parent and non-child-visible refused. Engine tests: narrowing acts in the target and is audited as a move; every refusal code; the header is not a request; a narrowed pairing completes an MFA-gated SSH session (`mcp_sessions_ssh.rs`, feature `mcp_sessions_ssh`).
- **Phase 2 clients.** `bv-mcp` gatekeeper (host narrowing, pinned narrowing, conflict, mismatch, MFA namespace, dialogs from the exchange answer), CLI flag parsing and link, desktop grant input, GUI vitest for the selector and the Settings column.
- **Audit.** The event carries `namespace` in the namespace broadcaster and the root mirror.
- **Links.** CLI and desktop preflight/verify send the operator session's namespace header (fake-link unit tests).
- **Gate.** `make test-release` before merge.

## Decisions (owner, 2026-10-19)

1. **Userpass MFA in a child namespace — to be verified by test.** Reading the code (2026-10-19) shows most of it already follows the token's own namespace: `token_namespace` (`connect_mfa.rs:534`) routes the step-up sub-request to the namespace the token was issued in, and tickets carry a `namespace` binding (`connect_mfa.rs:113`, compared at `:287`). What is still needed is the header: `begin`/`verify` bind the ticket to `caller_namespace(req)` (`:511`, `:691`, `:849`), the request namespace, so an operator call without `X-BastionVault-Namespace` would bind `""` and fail the `operator.namespace` match. The clients must send it. A live test (userpass user with TOTP inside a child namespace, MFA-gated SSH profile) must confirm it before Phase 1 is called done; the resource engine mount's reachability under the header is part of that test.
2. **Phase 2 requires the policies to resolve in the target namespace** — see Phase 2.
3. **Follow the operator's session**, no pin — see Phase 1. The `mcp_pairing_namespace_changed` refusal is dropped.
4. **The namespace is shown**: `bv_whoami` and `bv_resource_list` return it, and the pairing and per-call confirmation dialogs show it as their own line.
5. **Phase 2 ships with Phase 1's release train**, not on demand.

## Open questions

Decision 1 is verified (see "Phase 1 as built"). Open: **how a session signed in to a tenant namespace is granted `update` on `sys/mcp/token`.** Verified 2026-10-26, no supported route exists today:

- A tenant-bound token resolves its policy names in the tenant's own store (`PolicyStore::new_acl_inner`), so a root policy that names `sys/mcp/token` grants it nothing.
- `sys/policy` writes inside a namespace go through `refuse_cross_namespace_paths` (`crates/bv-kernel/src/modules/namespace/policy_scope.rs`), which rejects any `sys/` rule for every writer, root tokens included (the writer's namespace comes from the header).
- The implicit `namespace-self` policy (`policy_store.rs`) carries only caller-scoped self-service paths, and `sys/mcp/token` is not among them.

The route that works since Phase 2: sign in to a child-visible ancestor (root, or any namespace with `child_visible_default`) whose own policy grants `sys/mcp/token`, and narrow to the tenant (`--namespace`, or the desktop selector), with tenant-authored policies named in the token. Candidate fixes, not implemented and for the owner: add `sys/mcp/token` to `namespace-self` (the exchange only ever mints a subset of the caller's own token, so it is caller-scoped in effect, but it would let *every* tenant principal mint MCP tokens), or a root-authored per-namespace delegation of the exchange. The tests seed the grant with `PolicyStore::set_policy_ns`.

## Amendment: assignments count (2026-10-27)

**Decision reversed by the owner.** Phase 2 judged a narrowing by the stored binding alone and did not consult namespace assignments. That left a gap for the common operator who signs in at root and works in a tenant through the GUI's namespace picker: every other request honours the explicit `ns_assignment` record (`token_operable_resolved`), but the MCP exchange refused the same namespace with `mcp_namespace_not_permitted`, so an assistant could never run where the operator works.

- **Rule.** `narrowing_target` accepts the namespace when `token_may_operate` holds over the stored binding, or else when `token_operable_checked` finds an explicit assignment covering it (the assigned namespace and its descendants). The lookup is live, so revoking the record applies at the next exchange; no record keeps the strict binding verdict, so an absent record never widens a bound token.
- **Failure.** An unreadable assignment store is `403 mcp_namespace_unavailable`, not a refusal claiming the session lacks reach, and nothing is minted.
- **Second gate.** `McpNamespaceTarget` gained `assignment_granted`, set only by the handler when the binding did not cover the target but an assignment did. `mcp_namespace_binding` skips its binding re-check for such a target and keeps it for every other: `token_store` has no access to the assignment store to re-derive the verdict. A malformed binding is still refused first.
- **Unchanged.** The minted token is bound to the target, never child-visible; policies must resolve there (`mcp_policy_not_in_namespace`); an app exchange cannot narrow; the root-policy exemption in `token_operable` applies as for any request, and the desktop app does not serve MCP under a root token.
- **Tests.** `test_mcp_narrowing_honors_a_namespace_assignment` (engine: no record refused, assigned namespace accepted and bound, parent, sibling and unrelated refused, revoked record refused again) and `mcp_namespace_binding_accepts_an_assignment_verified_target_only` (token store).
- **Not covered by a test.** The store-error branch of the handler (reporting `mcp_namespace_unavailable`) is simple mapping over `token_operable_checked`, whose error propagation has its own test in `kernel_token_binding.rs`.

## Dependencies

[namespaces-multitenancy.md](namespaces-multitenancy.md) (token binding, `token_may_operate`), [mcp-access.md](mcp-access.md), [mcp-brokered-sessions.md](mcp-brokered-sessions.md) (operator reference, MFA ticket binding).

## Tracking

When a phase lands: update `CHANGELOG.md` (operator-facing entry ending in `(T457, S115)`), `ROADMAP.md` T457, this file's Status and phase table, `docs/mcp.md` (known gaps and troubleshooting), `docs/api.md` (Phase 2 field) and `features/mcp-brokered-sessions.md` ("Still open").
