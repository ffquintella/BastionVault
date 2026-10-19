# Feature: MCP Namespace Selection — agent calls run in the operator's child namespace

**Status: Design only (nothing implemented).** Owner decisions recorded 2026-10-19 (see "Decisions"). Tracked as ROADMAP T457 under M8, next to MCP Access (T80, T94) and MCP Brokered Sessions (T136–T138). Written against the tree at 0.44.46. Every "today" statement was verified by reading the code on 2026-10-19 and carries a file reference; re-check line numbers when this is picked up. **High-risk area** (authn/authz, token binding, persisted pairing record): `make test-release` is required before merge.

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
- **Follow the operator's session (decided).** The pairing does not pin a namespace. Each exchange binds the new token to the namespace of the session that exchanges it, so an operator who signs in elsewhere and reconnects gets a token for that namespace. The pairing approval dialog and the per-call confirmation always show the namespace the token is bound to, and a change of namespace between two exchanges of the same pairing is recorded in the audit trail. `path_scope` globs are evaluated relative to the token's namespace, so the same pairing reaching a different tenant is visible to the operator in the dialog, not hidden.

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
| `PairingRecord` (local file) | none (the pairing does not pin a namespace) | unchanged |
| `McpAuditContext`, audit events, transcripts | additive `namespace` field | absent = root |

## Security analysis

- **Authority** is the token's stored binding, evaluated by `token_may_operate` and `enforce_request_token_binding`. A client string is never authoritative: not a header, not a tool argument, not a pairing-file value.
- **Mint-time input** is the operator's own authenticated token (Phase 1) or is validated against it (Phase 2), mirroring the policy-subset rule in `mint_mcp_token` (`token_store.rs:1158`).
- **Never child-visible**, so an MCP token cannot climb or descend after mint.
- **Cross-tenant reach is unchanged**: the agent gets at most what the operator has in that namespace, narrowed by the pairing grant (`tool_allowlist`, `path_scope`, reveal/destructive flags). Per-call confirmation and MFA stay bound to one call.
- **Forgery check (to do at implementation).** `NS_PATH_META` is not in `RESERVED_TOKEN_META_KEYS` (`crates/bv-logical/src/auth.rs:92`). Confirm that an `auth/token/create` body `meta` cannot set it for a non-root caller, and reserve it if it can. `mcp_*` keys are already reserved.
- **Fail closed**: malformed, deleted, mismatched or not-permitted namespaces are refused with stable codes, never rewritten to root.
- **Logging**: namespace paths are not secrets and may appear in errors; tokens never do.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Token stamped with the operator's namespace; dispatch sets `namespace_path`; operator-side MFA calls carry the namespace header; audit field; follow-the-session rebind; dialogs, `bv_whoami` and `bv_resource_list` show the namespace | Not started |
| 2 | Optional descendant narrowing on the exchange, policy-resolves-in-target check, CLI flag, desktop selector (in scope) | Not started |
| 3 | Docs and Settings → AI Assistants display | Not started |

## Testing requirements

- **Kernel / logical.** The minted MCP token carries `ns_path` and `child_visible=false`; a token without the key stays root-bound; a forged `ns_path` through token create is refused.
- **`src/engine_tests/mcp_access.rs`.** An operator in `tenant-a` pairs; `bv_resource_list` sees `tenant-a` resources and not root's; a root resource is not readable; a root operator is unchanged.
- **Injection regression.** `X-BastionVault-Namespace: other` on `/v2/mcp` and a `namespace` tool argument change nothing.
- **Isolation.** Sibling and parent namespaces are refused; a deleted namespace yields `mcp_namespace_unavailable`, not root.
- **`src/engine_tests/mcp_sessions_ssh.rs`.** An MFA-gated profile in a child namespace completes (replacing the current "unavailable" expectation); a ticket minted for namespace A is refused in B.
- **Follow.** Re-exchanging the same pairing from a session in another namespace yields a token bound to that namespace, with a namespace-change audit record; the dialog payload carries the namespace.
- **Phase 2 policies.** A requested policy absent from the target namespace is refused with `mcp_policy_not_in_namespace`.
- **Phase 2.** Table test over `token_may_operate`: descendant with a child-visible parent allowed; sibling, parent and non-child-visible refused.
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

None outstanding beyond the verification in decision 1.

## Dependencies

[namespaces-multitenancy.md](namespaces-multitenancy.md) (token binding, `token_may_operate`), [mcp-access.md](mcp-access.md), [mcp-brokered-sessions.md](mcp-brokered-sessions.md) (operator reference, MFA ticket binding).

## Tracking

When a phase lands: update `CHANGELOG.md` (operator-facing entry ending in `(T457, S115)`), `ROADMAP.md` T457, this file's Status and phase table, `docs/mcp.md` (known gaps and troubleshooting), `docs/api.md` (Phase 2 field) and `features/mcp-brokered-sessions.md` ("Still open").
