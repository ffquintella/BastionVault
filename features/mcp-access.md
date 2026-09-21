# Feature: MCP Access — authenticated, permission-scoped Model Context Protocol server

**Status: Todo.** Nothing in this document is implemented. It is the design for
exposing BastionVault to AI assistants and agents over the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) in two deployment
shapes — a **local** MCP server on the operator's workstation and a **network**
MCP endpoint on `bv-server` — without weakening a single one of the vault's
existing authentication, authorization or audit guarantees. Written 2026-09-21
against MCP specification revision **2026-07-28** after the research pass in
§ "Research basis".

## Summary

An MCP *client* (Claude Desktop, Claude Code, an IDE, a CI agent, a scheduled
automation) wants to call BastionVault: list what it may see, read a secret's
metadata, encrypt through Transit, occasionally read a value or issue a
certificate. Today the only route is to hand the assistant a raw vault token and
let it drive the HTTP API — the shape every published secrets-manager MCP server
takes, including HashiCorp's own, which is documented as "intended for local use
only" and "do not use with untrusted MCP clients or LLMs".

BastionVault does it differently. MCP access is a **first-class, separately
authorized principal type**:

- **An MCP client never holds a general-purpose vault token.** It holds an
  **MCP-bound token**: a child token that carries a typed, unforgeable
  `mcp_binding` on the `TokenEntry`, minted only by the `v2/mcp/token` exchange,
  and accepted **only** by the MCP endpoint. Any other token presented to
  `/v2/mcp` is refused; an MCP-bound token presented to `/v1/*` or `/v2/*`
  outside the MCP endpoint is refused. This is the spec's "MUST validate that
  access tokens were issued specifically for them" rule made structural.
- **Every MCP principal is an app account with specific permissions.** In
  network mode the caller is an **MCP app** — a registered record in
  `sys/mcp/apps/<name>` that names an AppID role, a **tool allow-list**, a
  **path scope**, and the reveal/destructive switches — and its effective rights
  are the intersection of the AppID role's policies, the app record's scope, and
  whatever [shares](per-user-scoping.md) have been granted to the app's entity.
  In local mode the principal is the signed-in operator, narrowed by a
  **per-client pairing grant** the operator approved by hand.
- **Network MCP requires machine authentication.** The AppID login that
  precedes the exchange presents a live FerroGate `machine_token`
  ([machine-authentication.md](machine-authentication.md)), exactly as
  [approle-machine-env.md](approle-machine-env.md) already requires. A
  **machine-identity waiver** exists for hosts that cannot run the FerroGate
  agent; it is per-app, sudo-gated, time-boxed, reason-bearing and audited, and
  it must be set in *two* places (the AppID role's `bypass_machine_binding`
  **and** the MCP app record) before an unattested token reaches the endpoint.
- **Network MCP is encrypted, post-quantum by default.** `/v2/mcp` is served
  by the existing `bv-server` listener; with `rustls` 0.23.42 + `aws-lc-rs` the
  hybrid `X25519MLKEM768` key exchange is the top-priority group **today** (the
  crate's `prefer-post-quantum` default feature — verified against the pinned
  version in `Cargo.lock`, not the stale docs.rs page). The endpoint refuses to
  serve over a `tls_disable = true` listener unless the operator explicitly
  opts in *and* the listener is loopback-only, and a `require_hybrid_kex`
  switch turns "PQ preferred" into "PQ required" for high-assurance deployments.
- **Local MCP binds loopback only, and loopback is not consent.** The local
  server (`bvault mcp serve`, or the desktop GUI's *AI Assistants* panel) speaks
  stdio, a Unix domain socket, or HTTP on `127.0.0.1` — never `0.0.0.0`, no
  flag to change that. Every new MCP client must be **paired**: the operator
  sees the client's name, version and OS peer identity (`SO_PEERCRED` /
  `getpeereid`) and approves a scope (tools, path prefix, reveal, destructive,
  TTL) in a GUI dialog or an interactive TTY prompt. A non-interactive
  environment cannot pair. Loopback HTTP additionally validates `Origin` and
  `Host` and demands a per-client pairing token, because CVE-2025-49596 showed
  that a bound-to-localhost, unauthenticated MCP server is reachable from any
  browser tab.
- **Every tool call is on the audit chain.** `tools/call` is dispatched as an
  ordinary logical `Request` through `Core::handle_request`, so the existing
  tamper-evident [audit pipeline](audit-logging.md) records it with its normal
  redaction discipline, plus an `mcp` block: app or pairing, client identity,
  transport, tool, catalogue hash, reveal decision, negotiated TLS group.
  MCP-specific lifecycle events (`mcp.app.*`, `mcp.token.*`, `mcp.local.*`)
  are emitted through the same broker.

Secret **values** are never returned unless the app or pairing grant says
`reveal_allowed` *and* the call asks `reveal: true`; the default answer to
"read a secret" is its metadata. Write and delete tools exist but ship
**disabled** per principal. The tool catalogue is static, deterministically
ordered, and hashed; a change to a tool's description is a release event.

## Security model — what this does and doesn't protect

**Protects against**

- **Token passthrough / audience confusion.** A general vault token cannot drive
  MCP and an MCP-bound token cannot drive anything else. The binding is a typed
  `TokenEntry` field (`#[serde(default)]`, fails closed for every pre-existing
  token), not a metadata key — the `auth/token/create` body copies caller
  `meta` verbatim, which is exactly why `machine_identity_exempt` was made a
  typed field (see `crates/bv-kernel/src/modules/auth/token_store.rs`).
- **Over-broad agents.** Effective rights are `policies(AppID role) ∩ policies(exchange request) ∩ tool allow-list ∩ path scope`, with
  ACL remaining authoritative underneath; the dispatcher's allow-list is a
  *second* gate, never a substitute. Shares granted to the app's entity work
  through the existing `scopes = ["shared"]` machinery unchanged.
- **Unattested callers on the network.** The AppID login that precedes the
  exchange enforces machine binding; the exchange refuses a login token that
  carries neither `spiffe_id` nor an active, unexpired waiver on the named app.
- **Stolen MCP tokens.** Short TTL (default 1 h, max 24 h), `bound_cidrs`
  inherited from the AppID role, optional DPoP sender-constraint (Phase 6),
  revocable from the *MCP Apps* page and via `v2/sys/mcp/tokens`.
- **Session and state-handle hijacking.** The 2026-07-28 protocol is stateless.
  The endpoint keeps no session; the only handle it mints is the MRTR
  `requestState` for destructive/reveal confirmations, which is HMAC-bound to
  the token id, the argument hash and an expiry, and is **never** treated as
  authentication.
- **DNS rebinding and cross-origin drive-by against the local server.**
  `Origin`/`Host` validation with 403, loopback-only bind, pairing token
  required on HTTP, stdio and UDS preferred.
- **Tool poisoning, rug-pull, shadowing.** Tool descriptions are constants in
  `bv-mcp`; no stored data (secret names, resource notes) is ever interpolated
  into a description. `tools/list` is deterministic and its BLAKE3 catalogue
  hash is exposed in `server/discover`; clients and operators can pin it.
- **Prompt injection carried in secret content.** Values are returned only on
  explicit reveal; results are wrapped in `structuredContent`, control
  characters and ANSI escapes are stripped from every string the model or the
  user will see; the catalogue contains **no open-world tool** (no HTTP fetch,
  no shell), so the "lethal trifecta" needs a *second* server to complete.
- **Exfiltration through write tools.** `kv_write`/`kv_delete`/`pki_issue`/
  `ssh_sign` are `destructiveHint` tools, disabled per principal by default,
  MRTR-confirmed in local mode, and audited with argument HMACs.
- **Volumetric abuse.** The endpoint sits behind the existing per-IP
  [DoS guard](dos-abuse-protection.md); on top, per-principal and per-tool
  ceilings from the app record / pairing, a per-call timeout and a result-size
  cap.

**Does NOT protect against**

- **A compromised MCP client with a valid grant, acting within the grant.** If
  an app may `reveal` a path and the agent driving it is hijacked, that value
  leaks. Mitigation is the grant design (deny reveal, share narrowly, short
  TTL), the audit trail, and — in local mode — the per-call confirmation.
- **Same-user local malware.** A process running as the operator's own uid can
  read what the operator can read. Peer-credential checks distinguish *users*,
  not *processes of one user*; the pairing prompt and per-call confirmations
  raise the bar but are not a sandbox. Documented plainly in `docs/mcp.md`.
- **A FerroGate or AppID compromise.** Inherited from those features.
- **The model's reasoning.** MCP gives the model the *ability* to call; it does
  not make the model's decision to call correct. Human-in-the-loop is the
  spec's own answer ("there SHOULD always be a human in the loop with the
  ability to deny tool invocations") and is why destructive tools default off.

## Motivation

- **Operators are already doing it, badly.** The alternative to an official
  path is `VAULT_TOKEN=<root-ish token>` in an assistant's environment and a
  community MCP server of unknown provenance — OWASP MCP01 (token
  mismanagement) and MCP09 (shadow MCP servers) in one move.
- **The primitives exist and are stronger than anything published.** Machine
  attestation, an app-account auth method with machine binding, path ACLs,
  per-object shares, a hash-chained audit log, a hybrid-PQ TLS stack and a
  desktop client with a local PQC keystore. MCP is glue over those, not new
  trust.
- **Transit and PKI are ideal MCP tools.** Encrypt/decrypt/sign/verify through
  Transit lets an agent *use* a key without *seeing* it; issuing a cert through
  PKI gives it exactly one credential with a TTL. Both fit MCP's tool model far
  better than "read the secret and paste it".
- **The spec finally stabilised the pieces that matter.** 2026-07-28 removed
  sessions and the handshake, made `Origin` validation and audience binding
  normative, deprecated dynamic client registration, and adopted an
  enterprise-managed authorization extension. Designing against it now avoids
  building on the deprecated 2025-11-25 session model.

## Current State

**Status: Todo.** No code. Related things that exist and are reused:

- `gui/src-tauri` has a **dev-only** `mcp_local_dev` feature for the
  `tauri-plugin-mcp-bridge` GUI-automation bridge (`AGENTS.md` § "Local Tauri
  MCP bridge"). It is unrelated to this feature — it exposes the *GUI's DOM* to
  a local assistant for development, is compiled out of release builds and
  stays that way. This feature exposes the *vault*, in release builds, under
  the rules below. The loopback-only rule is the one thing carried over.
- `auth/approle` machine binding + `bypass_machine_binding`
  ([approle-machine-env.md](approle-machine-env.md)) is the login half of
  "app account with machine auth and optional waiver".
- `TokenEntry.machine_identity_exempt` is the precedent for a typed,
  unforgeable token attribute.
- `SecretShare` + `scopes = ["shared"]` ([per-user-scoping.md](per-user-scoping.md))
  is the share model; MCP adds a grantee, not a mechanism.
- `emit_sys_audit` (`src/audit/sys_emit.rs`) is the pattern for auditing a
  request that does not traverse `Core::handle_request`; MCP tool calls *do*
  traverse it, so only lifecycle events need the helper.
- `bv-client::Backend` is the transport-agnostic "issue a logical request"
  trait the GUI already dispatches through; the MCP dispatcher targets it so
  one implementation serves the server (in-process `Core`), the CLI
  (`RemoteBackend`) and the GUI (`EmbeddedBackend` / `RemoteBackend`).

## Research basis

Web research done 2026-09-21 (sources in the table). The design rules in this
document that come from a normative source are marked **(spec MUST)** /
**(spec SHOULD)**; everything else is vendor guidance or published attack
research and is marked as such.

| Source | What it establishes for this design |
|---|---|
| [MCP spec 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) | Protocol is stateless: no `initialize`, no `Mcp-Session-Id`, `server/discover` MUST be implemented, every request carries version + client identity in `_meta`, MRTR (`resultType: "input_required"`) replaces server-initiated elicitation, `Mcp-Method`/`Mcp-Name` headers required on HTTP POST, deterministic `tools/list` SHOULD, RFC 7591 DCR deprecated for Client ID Metadata Documents, `iss` (RFC 9207) validation MUST. Verified directly, not via the research agent. |
| [Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | `Origin` MUST be validated, 403 on mismatch; local servers SHOULD bind `127.0.0.1`; `MCP-Protocol-Version` MUST be present and match `_meta`; header/body mismatch → 400 `HeaderMismatch` (-32020); GET/DELETE → 405 on a 2026-only server; do not mirror sensitive params into `Mcp-Param-*`. |
| [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) + [security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) | Servers MUST validate tokens were issued for them and MUST NOT accept or transit others; RFC 9728 PRM MUST; RFC 8707 `resource` MUST; PKCE S256 MUST; bearer tokens MUST NOT be in the query string; 401 invalid / 403 `insufficient_scope` step-up; claimed scopes are not authorization — server-side checks are. stdio SHOULD NOT use the OAuth flow and takes credentials from the environment. |
| [Security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices) | Confused deputy, token passthrough, SSRF via OAuth metadata, **state-handle hijacking** (possession of a handle MUST NOT be authentication), local-server compromise (stdio, or auth token, or UDS with restricted access), never open URLs via a shell. |
| [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Human in the loop SHOULD; annotations are untrusted unless the server is trusted; servers MUST validate inputs, enforce access control, rate-limit, sanitise outputs; `readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`. |
| [Elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) | Form-mode elicitation MUST NOT collect passwords, keys or tokens. |
| [Enterprise-Managed Authorization ext.](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx) | ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant) + RFC 8693/7523; token MUST be audience-restricted to the MCP server. Shipped by Anthropic 2026-08-24 (Okta first). Target for Phase 7. |
| [Invariant Labs — tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [GitHub MCP leak](https://invariantlabs.ai/blog/mcp-github-vulnerability) | Hidden instructions in descriptions; rug-pull after approval; cross-server shadowing; least-privilege tokens and one-scope-per-session as mitigations. |
| [Trail of Bits — line jumping](https://blog.trailofbits.com/2025/04/23/how-mcp-servers-can-steal-your-conversation-history/), [ANSI hiding](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/) | Descriptions act before any call; strip control characters from anything rendered. |
| [Willison — lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/), [Supabase MCP](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/) | Private data + untrusted content + exfil channel; the fix that worked was read-only mode and not bypassing row-level security. |
| [CVE-2025-49596 — MCP Inspector](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) | Loopback-bound, unauthenticated MCP server exploited from a browser via DNS rebinding / `0.0.0.0`; fix = random session token + Host/Origin checks. |
| [CVE-2025-6514 — mcp-remote](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p) | Command injection from a malicious `authorization_endpoint`; origin of the "never shell-open URLs" rule. |
| [OWASP MCP Top 10 (beta)](https://owasp.org/www-project-mcp-top-10/), [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | MCP01 token/secret exposure, MCP02 scope creep, MCP07 authn/authz, MCP08 audit, MCP09 shadow servers, MCP10 context over-sharing. |
| [NSA CSI — MCP security design considerations](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/) (2026-05-20), [CISA — agentic AI adoption](https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai) (2026-05-01) | Minimum access, screen all inputs, human oversight for automated actions, log "which tool was requested, by whom, and what resulted", separate by trust level. |
| [Azure MCP Server security](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security), [Cloudflare MCP portals](https://blog.cloudflare.com/zero-trust-mcp-server-portals/), [AWS AgentCore gateway auth](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html) | Validate issuer/audience/expiry per request; per-client consent; re-approval when tool metadata changes; default-deny writes; sign or encrypt request state. |
| [HashiCorp Vault MCP Server](https://developer.hashicorp.com/vault/docs/ai/mcp-server/overview), [1Password Environments MCP](https://www.1password.dev/environments/mcp-server), [Bitwarden MCP](https://github.com/bitwarden/mcp-server) | The competitive baseline: HashiCorp = raw `VAULT_TOKEN`, no read-only mode, no allow-list, "local use only"; 1Password = cannot return values to the client at all, per-client desktop prompt; Bitwarden = stdio only, "never expose over a network". |
| [Cloudflare PQ status](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/), [OpenSSL 3.5 notes](https://openssl-library.org/news/openssl-3.5-notes/), rustls 0.23.42 `Cargo.toml` (local registry) | Hybrid `X25519MLKEM768` is default in Chrome ≥131, Firefox ≥132, OpenSSL 3.5, Go 1.24 and **rustls (`prefer-post-quantum` default feature)**. No MCP document mentions post-quantum anything; the spec only requires HTTPS. |

Things that **do not exist**, for the record: an MCP audit-log schema; MCP
guidance on post-quantum transport; a read-only mode or tool allow-list in
HashiCorp's server; a final (non-beta) OWASP MCP Top 10.

## Scope

### In scope — shared core (`crates/bv-mcp`)

- JSON-RPC 2.0 message types for MCP **2026-07-28**: `server/discover`,
  `tools/list`, `tools/call`, `resultType` (`complete` | `input_required`),
  `_meta.io.modelcontextprotocol/*` (protocol version, client capabilities,
  client info, server info, `logLevel`), OpenTelemetry `traceparent` /
  `tracestate` / `baggage` passthrough into the audit entry, `ttlMs` +
  `cacheScope: "private"` on list results. Error codes per the spec's
  allocation policy (`-32020` HeaderMismatch, `-32022`
  UnsupportedProtocolVersion) plus BastionVault errors in the
  implementation-defined range.
- The **tool catalogue** (§ Tool catalogue): constants, deterministic order,
  BLAKE3 catalogue hash, annotations, JSON Schema 2020-12 input/output schemas.
- The **dispatcher**: `tools/call` → `(Operation, path, data)` →
  `bv_client::Backend`, with the tool allow-list, path-scope, reveal and
  destructive gates evaluated *before* dispatch; result shaping
  (`structuredContent`), redaction, control-character stripping, size cap,
  timeout.
- MRTR confirmation: `input_required` with an HMAC-bound `requestState`;
  verification on retry.
- `prompts/*` and `resources/*`: **not** in v1 (see Out of scope).

### In scope — kernel (`bv-kernel`, `bv-kernel-api`)

- `TokenEntry.mcp_binding: Option<McpBinding>` — typed, `#[serde(default)]`.
  `McpBinding { kind: App(name) | Pairing(id), catalogue_hash, tool_allowlist,
  path_scope, reveal_allowed, destructive_allowed, client_name, client_version }`.
- `TokenStore::check_token` gate (the auth chokepoint — five callers bypass
  `pre_route`, so per-token gates belong there): a token with `mcp_binding`
  is accepted only when the request is flagged as originating from the MCP
  dispatcher; the MCP dispatcher accepts only tokens with `mcp_binding`.
- `sys/mcp/config`, `sys/mcp/apps/<name>`, `sys/mcp/apps/<name>/machine-waiver`,
  `sys/mcp/tokens` storage + logical paths (system module).
- `mcp/token` exchange (§ Token exchange).
- Audit events and Prometheus families (§ Audit and metrics).

### In scope — server (`crates/bv-server`)

- `POST /v2/mcp` route (`mcp_routes.rs`); `GET`/`DELETE` → 405 **(spec
  SHOULD for a 2026-only server)**.
- `GET /.well-known/oauth-protected-resource/v2/mcp` — RFC 9728 PRM **(spec
  MUST)**. Anonymous, minimal: `resource`, `authorization_servers` (possibly
  empty), `bearer_methods_supported: ["header"]`, `scopes_supported`. No
  version, no build info (same disclosure discipline as `sys/info`).
- Transport rules: `Origin`/`Host` validation, `MCP-Protocol-Version`,
  `Mcp-Method`/`Mcp-Name` consistency, bearer in `Authorization` header only
  (a token in the query string → 400, never processed), TLS gate,
  `require_hybrid_kex`, negotiated-group capture, DoS guard participation.

### In scope — client (`bvault` CLI)

- `bvault mcp serve [--stdio | --socket <path> | --listen 127.0.0.1:<port>]`
- `bvault mcp pair`, `bvault mcp pairings list|revoke`
- `bvault mcp token --app <name>` (app mode: FerroGate login → AppID login →
  exchange; prints the MCP-bound token as structured output, never persists it
  — same discipline as `bvault ferrogate token`)
- `bvault mcp catalogue` (print tools + hash for pinning)

### In scope — admin tooling (GUI)

- **Settings → AI Assistants (MCP)** (operator, local mode): enable local
  server, transport choice, pairing consent dialog, pairing list with revoke,
  per-call confirmation dialogs (MRTR), recent local calls.
- **Admin → MCP Apps** (server mode): app CRUD, waiver grant/revoke with reason
  and expiry, catalogue hash display, active MCP tokens with revoke, recent
  calls and denials, config.
- Tauri commands in `gui/src-tauri/src/commands/mcp.rs`, `api.ts` wrappers,
  vitest coverage.

### Out of scope (explicit)

- **BastionVault as an MCP *client*.** Nothing here dials a remote MCP server.
  If a later feature does (Rustion, notification plugins), it inherits the
  spec's SSRF rules: HTTPS only, block private ranges, exact redirect match,
  never shell-open a URL.
- **BastionVault as an OAuth 2.1 authorization server.** Human-interactive
  OAuth for MCP clients waits on the
  [Identity Provider](identity-provider.md) feature (Phase 7 here). Until then
  the bearer is a BastionVault MCP-bound token obtained out of band, and PRM
  advertises an `authorization_servers` list only when the operator configures
  an external AS whose JWTs the existing OIDC auth mount validates with
  `aud = canonical_url`.
- **`prompts/*`, `resources/*`, MCP Apps (UI extension), Tasks extension.**
  Tools cover the use cases; resources would be a second read path to audit.
- **Legacy protocol revisions (2025-11-25 and earlier).** No `initialize`,
  no `Mcp-Session-Id`, no SSE resumability. A legacy client gets
  `UnsupportedProtocolVersion`. See Open questions — this is the one scope
  decision most likely to be revisited by client-support data.
- **Windows named-pipe local transport.** Unix first (UDS + peer creds), as
  with the FerroGate MIA socket. Windows gets stdio and loopback HTTP with the
  pairing token.
- **Binding to a non-loopback address in local mode.** There is no flag.
- **A `bvault-mcp` standalone binary.** It is a subcommand of `bvault` so it
  shares the token helper, the FerroGate MIA client and the packaging.

## Design

### 1. Principals: MCP app vs. local pairing

| | **MCP app** (network mode) | **Local pairing** (local mode) |
|---|---|---|
| Who | An unattended or semi-attended application on an attested host | The signed-in operator's assistant on their own workstation |
| Identity | AppID role (`auth/approle/role/<role>`) + FerroGate machine (or waiver) | The operator's own session token + the paired client's identity |
| Record | `sys/mcp/apps/<name>` (server-side, admin-managed) | Pairing record in the local keystore (client-side, operator-managed) + `McpBinding::Pairing` on the minted token (server-side) |
| Effective rights | role policies ∩ exchange-requested policies ∩ tool allow-list ∩ path scope; shares to the app's entity apply | operator policies ∩ pairing tool allow-list ∩ pairing path scope; operator's shares apply |
| Human in the loop | None at call time; `destructive_allowed` off by default | Pairing consent + per-call MRTR confirmation for reveal/destructive |
| Token TTL | `ttl` from app record, default 1 h, max 24 h | Pairing `ttl`, default 8 h, max 24 h; re-minted per `serve` run |
| Transport | `POST /v2/mcp` over the server listener | stdio / UDS / loopback HTTP into the local server, which itself talks to the vault as an ordinary client |

The two are deliberately different *records* over one *mechanism*: both end in
an MCP-bound child token minted by the same exchange and enforced by the same
dispatcher and the same `check_token` gate.

### 2. MCP app record

```
sys/mcp/apps/<name>  →  McpApp {
    name:                 String,            // [a-z0-9-]{1,64}
    approle_role:         String,            // must exist in auth/approle
    entity_id:            String,            // resolved from the role's alias; share grantee
    description:          String,
    tool_allowlist:       Vec<String>,       // tool names; empty = deny all (not allow all)
    path_scope:           Vec<String>,       // glob prefixes, e.g. ["secret/data/ai/*", "transit/encrypt/ai-*"]; empty = deny all
    reveal_allowed:       bool,              // default false
    destructive_allowed:  bool,              // default false
    ttl_secs:             u64,               // default 3600, max 86400
    rate_limit_per_min:   u32,               // default 60; 0 = unlimited
    tool_rate_limits:     Map<String, u32>,  // per-tool override
    max_result_bytes:     u32,               // default 65536, max 1 MiB
    machine_waiver:       Option<MachineWaiver>,
    created_by, created_at, updated_by, updated_at
}

MachineWaiver {
    reason:       String,     // required, non-empty
    granted_by:   String,     // entity_id of the sudo caller
    granted_at:   RFC3339,
    expires_at:   RFC3339,    // required; max 90 days from granted_at; not renewable in place — grant again
}
```

Rules:

- **Empty means deny.** An app with no tools or no path scope can exchange for
  a token but every `tools/call` is refused with `mcp_tool_not_allowed` /
  `mcp_path_out_of_scope`. There is no `"*"` tool wildcard; the operator lists
  the tools. Path scope accepts the same glob syntax as ACL paths.
- **`reveal_allowed` and `destructive_allowed` are independent switches**, both
  default false, both audited on change (`mcp.app.updated` carries the diff).
- **Path scope is checked by the dispatcher before dispatch and by ACL after
  routing.** The dispatcher's check is defence in depth; a bug in it cannot
  grant what the role's policies deny.
- **Waiver is two-key.** The AppID role must have `bypass_machine_binding`
  (login layer, [approle-machine-env.md](approle-machine-env.md)) *and* the app
  record must carry an active `machine_waiver` (MCP layer). Setting the waiver
  requires `sudo` on `sys/mcp/apps/<name>/machine-waiver`; the reason and
  expiry are mandatory; expiry is enforced at exchange time *and* at every
  `tools/call` (the binding records `waived_until`), so an expired waiver cuts
  live tokens off at the next call rather than at their TTL. The waiver never
  touches the server-wide `require_machine_identity` gate: an app on a server
  with that gate on still needs `machine_identity_exempt` from its role, which
  the role's bypass already stamps.
- **Deleting an app revokes its outstanding MCP-bound tokens** through the
  lease manager (same path as `ferrogate revoke`).
- Namespaced: apps live in the caller's namespace; the minted token carries it.

### 3. Local pairing record

Held by the local MCP server, never by the vault, in the GUI's per-vault PQC
keystore (`local_keystore.rs`) or, for the CLI, in
`$XDG_CONFIG_HOME/bvault/mcp-pairings.json` (mode 0600, ML-KEM-768 envelope
using the same `bv_crypto` seal box the keystore uses — no second scheme).

```
Pairing {
    id:                  String,           // random 128-bit, hex
    client_name:         String,           // from _meta clientInfo at pairing time
    client_version:      String,
    peer:                Option<PeerId>,   // { uid, gid, pid, exe_path } from SO_PEERCRED / getpeereid+LOCAL_PEERPID; None for stdio
    transport:           "stdio" | "uds" | "loopback-http",
    pairing_token_hash:  Option<[u8;32]>,  // BLAKE3 of the random bearer handed to loopback-HTTP clients; None otherwise
    tool_allowlist:      Vec<String>,
    path_scope:          Vec<String>,
    reveal_allowed:      bool,             // default false
    destructive_allowed: bool,             // default false
    confirm_reveal:      bool,             // default true  → MRTR prompt per reveal
    confirm_destructive: bool,             // default true  → MRTR prompt per destructive call
    ttl_secs:            u64,              // default 28800, max 86400
    approved_at:         RFC3339,
    expires_at:          Option<RFC3339>,  // pairing itself can expire; default 30 days
    last_used_at:        RFC3339,
}
```

Pairing flow (the "intentional permission from the user" requirement):

1. A client connects. For UDS the server reads peer credentials from the
   kernel; for loopback HTTP it requires `Authorization: Bearer <pairing
   token>` and validates `Origin` (must be absent or in the allow-list, which
   defaults to empty) and `Host` (must be `127.0.0.1:<port>` or
   `localhost:<port>`) — 403 otherwise **(spec MUST for Origin)**. For stdio
   the client *is* the parent process; identity is `clientInfo` only.
2. The first request's `_meta.io.modelcontextprotocol/clientInfo` names the
   client. If no pairing matches `(client_name, peer.uid, transport)` — or
   the peer's `exe_path` changed for a UDS pairing — the server returns
   `input_required` with a URL-mode-free, **local** confirmation: in the GUI a
   modal (client name, version, executable path, pid, requested transport, the
   proposed default scope, editable), in the CLI an interactive TTY prompt
   (`bvault mcp pair` is the same prompt started by hand). **If no TTY and no
   GUI is present, pairing fails closed** with `mcp_pairing_requires_operator`.
3. On approval the local server calls `v2/mcp/token` on the vault with the
   operator's session token and the pairing scope; the vault mints an
   MCP-bound child token (`McpBinding::Pairing`) with the intersected
   policies. The local server holds that token in memory for the pairing's TTL
   and never writes it to disk. Loopback-HTTP clients receive a fresh random
   pairing token to present on later connections; its hash is stored.
4. Revoking a pairing (GUI list, `bvault mcp pairings revoke <id>`) drops the
   in-memory token, revokes it on the vault (`v2/sys/mcp/tokens/<accessor>`),
   and deletes the record. `mcp.local.unpaired` is emitted through the vault
   the same way the plugin grant events are.

Pairing is per `(client_name, uid, transport)`; a same-user process claiming an
already-paired name over UDS with a different `exe_path` triggers a
re-pairing prompt, not silent reuse. This is the honest limit stated in the
security model: it raises the bar against same-user malware, it does not
sandbox it.

### 4. Token exchange — `POST v2/mcp/token`

The only path that mints an MCP-bound token.

```
POST /v2/mcp/token
X-Vault-Token: <login token>
{
  "app":        "ci-secrets-reader",          // network mode; mutually exclusive with "pairing"
  "pairing":    { "id": "…", "client_name": "…", "client_version": "…",
                  "tool_allowlist": [...], "path_scope": [...],
                  "reveal_allowed": false, "destructive_allowed": false,
                  "ttl_secs": 28800 },        // local mode
  "policies":   ["ai-reader"],                // optional; must be ⊆ caller policies
  "ttl_secs":   3600                          // optional; clamped to record max
}
→ 200 { "auth": { "client_token", "accessor", "policies", "lease_duration",
                  "metadata": { "mcp_kind": "app|pairing", "mcp_name": "…",
                                "catalogue_hash": "…", "spiffe_id": "…" } } }
```

Checks, in order, all fail-closed:

1. Caller token is valid, non-root, **not itself MCP-bound**, and has
   `update` on `mcp/token`.
2. **App mode:** the app exists in the caller's namespace; the caller token was
   minted by `auth/approle` for exactly `approle_role` (`meta.role_name` and
   `mount_path`); the token carries `spiffe_id` **or** the app has an
   unexpired `machine_waiver` — otherwise `403 mcp_machine_identity_required`.
   Rate-limit per source IP like FerroGate login.
3. **Pairing mode:** caller token is a user session (has `entity_id`, is not
   an approle/ferrogate token); requested `tool_allowlist` ⊆ catalogue;
   `ttl_secs` ≤ 86400.
4. Effective policies = caller policies ∩ requested (`default` re-injected by
   the token store as usual). Never a superset — same rule as
   `auth/token/create`.
5. Mint a child token with `mcp_binding` set, `display_name = "mcp-<kind>-<name>"`,
   `bound_cidrs` inherited, `renewable = false`, `num_uses = 0`. The binding
   copies `catalogue_hash` at mint time so a catalogue change between mint and
   call is visible in the audit entry.
6. Emit `mcp.token.issued`.

The token is a **service token** (persisted, revocable, listable). Batch tokens
are not used: revocation from the *MCP Apps* page must work.

### 5. The MCP endpoint — `POST /v2/mcp`

Request handling in `bv-server/src/mcp_routes.rs`, in this order:

| Step | Rule | Failure |
|---|---|---|
| 1 | Listener TLS gate: if the listener has `tls_disable = true`, serve only when `mcp.allow_plaintext_loopback = true` **and** the bound address is loopback | 503 `mcp_requires_tls` (logged once at startup too) |
| 2 | If `mcp.require_hybrid_kex = true`, the connection's negotiated key-exchange group must be `X25519MLKEM768` (rustls `negotiated_key_exchange_group()`) | 421 `mcp_hybrid_kex_required` |
| 3 | DoS guard (existing middleware, `auth`-class ceiling) | 429 + `Retry-After` |
| 4 | `Origin` present → must be in `mcp.allowed_origins` (exact scheme+host+port) **(spec MUST)**; `Host` must match `canonical_url` host | 403 |
| 5 | `MCP-Protocol-Version` present, equals `2026-07-28`, equals `_meta` version **(spec MUST)** | 400 `-32022` / `-32020` |
| 6 | `Mcp-Method` equals JSON-RPC `method`; `Mcp-Name` equals `params.name` for `tools/call` **(spec MUST)** | 400 `-32020` |
| 7 | Bearer token from `Authorization` only; any `token`/`access_token` query parameter → reject without reading it **(spec MUST NOT)** | 400 |
| 8 | `check_token` with the MCP-origin flag: token must carry `mcp_binding`; binding's waiver (if any) unexpired; `bound_cidrs` honoured | 401 with `WWW-Authenticate: Bearer resource_metadata="<PRM URL>"` |
| 9 | Body ≤ `mcp.max_request_bytes` (default 256 KiB); single JSON-RPC request (no batches) | 413 / 400 |
| 10 | Dispatch (§ 6). Response is JSON (`Content-Type: application/json`); SSE is used only for `notifications/progress` on long calls, closed with the result | — |

`GET`, `DELETE`, `PUT` → 405. `Mcp-Session-Id`, if a legacy client sends it,
is ignored and never minted. The response `_meta` carries
`io.modelcontextprotocol/serverInfo = { name: "bastionvault", version: <major.minor only> }`
— no patch version, no build id.

No session table. Nothing is kept between requests except the token store's
own entries and the DoS counters.

### 6. Dispatcher — `bv-mcp`

```
tools/call ─▶ catalogue lookup ─▶ binding.tool_allowlist ─▶ binding.path_scope
          ─▶ reveal/destructive gates (+ MRTR) ─▶ per-tool/per-principal rate limit
          ─▶ build Request{op, path, data} ─▶ Backend::request (→ Core::handle_request → ACL → engine)
          ─▶ redact/shape/strip/cap ─▶ CallToolResult
```

- The dispatcher never constructs a path from model-supplied text without
  validation: every tool has a typed input schema; path arguments are
  normalised (`no ..`, no leading `/`, no `sys/`, no `auth/`) and matched
  against `path_scope` **before** routing. `sys/*` and `auth/*` are
  unreachable from any tool by construction; `bv_whoami` is answered from the
  token entry, not by routing to `auth/token/lookup-self`.
- **Reveal gate:** a tool that can return a secret value takes `reveal:
  boolean` (default false). With `reveal: false` it returns metadata and a
  `value: "<redacted>"` sentinel. With `reveal: true` the binding must have
  `reveal_allowed`; in local mode with `confirm_reveal` the first call returns
  `input_required` and the retry must carry the confirmed `requestState`.
- **Destructive gate:** same shape with `destructive_allowed` /
  `confirm_destructive`.
- **`requestState`:** `base64(payload || HMAC-BLAKE3(key, payload))` where
  `payload = { token_accessor, tool, args_hash, decision, exp (≤ 300 s) }` and
  `key` is barrier-derived (same derivation family as the audit HMAC key). It
  is verified, single-use (accessor+args_hash+exp kept in a short in-memory
  set, per process), and **never** substitutes for the bearer — the retry is
  re-authenticated from scratch **(spec MUST)**.
- **Result shaping:** `structuredContent` per the tool's `outputSchema`, plus a
  short `content[0].text` summary. Every string leaf passes through
  `sanitize_for_model()` — strips C0/C1 controls except `\n`/`\t`, ANSI CSI/OSC
  sequences, and Unicode bidi overrides. Results over `max_result_bytes` are
  truncated with `"truncated": true` and a `list` hint.
- **Timeouts:** `mcp.tool_timeout_secs` (default 30); the underlying request
  is cancelled through the existing task context.
- **Errors** are typed JSON-RPC errors with stable `data.code` strings
  (`mcp_tool_not_allowed`, `mcp_path_out_of_scope`, `mcp_reveal_denied`,
  `mcp_destructive_denied`, `mcp_confirmation_required`, `mcp_rate_limited`,
  `permission_denied` passthrough from ACL). Error messages never echo secret
  paths' *contents*; they may echo the path.

### 7. Tool catalogue (v1)

Descriptions are constants. Order is the order below. `catalogue_hash` =
BLAKE3 over the canonical JSON of the full `tools/list` result.

| Tool | Maps to | `readOnly` | `destructive` | `idempotent` | Default state |
|---|---|---|---|---|---|
| `bv_whoami` | token entry (no routing) | ✓ | | ✓ | always available |
| `bv_capabilities` | `sys/capabilities-self` for a given path (v2) | ✓ | | ✓ | always available |
| `bv_kv_list` | `LIST <mount>/metadata/<path>` | ✓ | | ✓ | allow-listable |
| `bv_kv_read_metadata` | `GET <mount>/metadata/<path>` | ✓ | | ✓ | allow-listable |
| `bv_kv_read` (`reveal`) | `GET <mount>/data/<path>` | ✓ | | ✓ | allow-listable; value only with reveal |
| `bv_resource_list` / `bv_resource_describe` | `resources/…` (never `resources/secrets/*` without reveal) | ✓ | | ✓ | allow-listable |
| `bv_transit_encrypt` / `bv_transit_decrypt` | `transit/encrypt|decrypt/<key>` | ✓* | | ✓ | allow-listable — *decrypt output is plaintext and is treated as a reveal* |
| `bv_transit_sign` / `bv_transit_verify` | `transit/sign|verify/<key>` | ✓ | | ✓ | allow-listable |
| `bv_totp_code` | `totp/code/<name>` | ✓ | | | allow-listable; treated as reveal |
| `bv_pki_list_certs` / `bv_pki_read_cert` | `pki/certs`, `pki/cert/<serial>` (public material only; `cert/+`, never `cert/*` — see the private-key trap in `docs/policies`) | ✓ | | ✓ | allow-listable |
| `bv_kv_write` | `POST <mount>/data/<path>` | | ✓ | | Phase 6; requires `destructive_allowed` |
| `bv_kv_delete` | `DELETE <mount>/data/<path>` (soft-delete only; no `destroy`, no `metadata` delete) | | ✓ | ✓ | Phase 6; requires `destructive_allowed` |
| `bv_pki_issue` | `pki/issue/<role>` | | ✓ | | Phase 6; requires `destructive_allowed` **and** `reveal_allowed` (returns a private key) |
| `bv_ssh_sign` | `ssh/sign/<role>` | | ✓ | | Phase 6; requires `destructive_allowed` |

Deliberately **absent**, permanently: anything under `sys/` or `auth/`
(mounts, policies, tokens, seal, plugins, backup), `kv metadata destroy`,
`pki/root/*`, `transit/keys/*` writes, file-resource downloads, anything that
opens a network connection (`openWorldHint` is `false` on every tool and no
tool will ever set it `true`). An agent that needs those needs an operator.

### 8. Configuration

Static transport settings in HCL (they change what the process binds and how
it terminates TLS, so they belong with the listener):

```hcl
mcp {
  enabled                  = false
  canonical_url            = "https://vault.example.com:8200/v2/mcp"  # RFC 8707 resource; required when enabled
  allowed_origins          = []          # exact origins; empty = only non-browser clients (no Origin header)
  require_hybrid_kex       = false       # true → refuse non-X25519MLKEM768 connections on /v2/mcp
  allow_plaintext_loopback = false       # only honoured when the listener address is loopback
  max_request_bytes        = 262144
  tool_timeout_secs        = 30
  authorization_servers    = []          # RFC 9728 PRM; Phase 7
}
```

Runtime policy settings via `v2/sys/mcp/config` (stored, `sudo`):
`default_ttl_secs`, `max_ttl_secs`, `default_rate_limit_per_min`,
`waiver_max_days` (default 90), `catalogue_pin` (optional expected hash — the
endpoint refuses to start serving if the compiled catalogue's hash differs,
which is how an operator turns "a description changed" into a deliberate
upgrade step).

### 9. HTTP API (v2 only)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v2/mcp` | MCP-bound bearer | The MCP endpoint |
| `GET` | `/.well-known/oauth-protected-resource/v2/mcp` | none | RFC 9728 metadata (minimal) |
| `POST` | `/v2/mcp/token` | login token | Exchange for an MCP-bound token |
| `GET`/`POST` | `/v2/sys/mcp/config` | `sudo` | Runtime policy settings |
| `LIST` | `/v2/sys/mcp/apps` | ACL | List apps |
| `GET`/`PUT`/`DELETE` | `/v2/sys/mcp/apps/{name}` | ACL | App CRUD; `DELETE` revokes outstanding tokens |
| `PUT`/`DELETE` | `/v2/sys/mcp/apps/{name}/machine-waiver` | `sudo` | Grant (reason + expires_at required) / revoke waiver |
| `GET` | `/v2/sys/mcp/catalogue` | any token | Tool catalogue + hash |
| `LIST` | `/v2/sys/mcp/tokens` | ACL | Active MCP-bound tokens (accessor, kind, name, client, issued, expires, last call) |
| `DELETE` | `/v2/sys/mcp/tokens/{accessor}` | ACL | Revoke one |
| `GET` | `/v2/sys/mcp/calls` | ACL | Last N calls/denials ring buffer (operator convenience; the audit log is the record) |

Nothing under `v1/`. `docs/api.md` gains an "MCP" section; `docs/mcp.md` is the
operator guide (threat model, pairing, waivers, client configuration snippets
for Claude Desktop / Claude Code / generic Streamable-HTTP clients).

### 10. Audit and metrics

Every `tools/call` traverses `Core::handle_request`, so it produces a normal
`AuditEntry` (token HMAC'd, body string leaves HMAC'd, `remote_address*`
populated). The MCP layer adds, on `request.data`'s sibling key `mcp`:

```
mcp: {
  kind: "app" | "pairing", name, client_name, client_version,
  transport: "https" | "stdio" | "uds" | "loopback-http",
  tool, catalogue_hash, reveal_requested, reveal_granted,
  destructive, confirmed_by_operator, decision: "allowed" | "denied:<code>",
  tls_kx_group, waived: bool, peer_uid, peer_pid,
  otel: { traceparent, tracestate }
}
```

Secret values, tokens, pairing tokens and `requestState` never appear; tool
arguments are subject to the existing string-leaf HMAC redaction; `bv_kv_write`
values are HMAC'd like any other write body.

Lifecycle events (via `emit_sys_audit`): `mcp.config.updated`,
`mcp.app.created|updated|deleted`, `mcp.app.machine_waiver.granted|revoked|expired`,
`mcp.token.issued|revoked`, `mcp.local.paired|unpaired|confirm_approved|confirm_denied`,
`mcp.catalogue.pin_mismatch`.

Prometheus (`crates/bv-metrics/src/mcp_metrics.rs`):
`bvault_mcp_tool_calls_total{tool,kind,outcome}`,
`bvault_mcp_denied_total{reason}`, `bvault_mcp_tokens_issued_total{kind}`,
`bvault_mcp_active_tokens`, `bvault_mcp_waived_apps`,
`bvault_mcp_tls_kx_total{group}`, `bvault_mcp_call_duration_seconds`.

### 11. Transport security detail

- **TLS.** No new TLS code. `/v2/mcp` is served by the same `rustls`
  `ServerConfig` as every other route. Hybrid PQ is the default preference in
  the pinned rustls; `require_hybrid_kex` makes it mandatory for this route
  only (a legacy monitoring client on `/v1/sys/health` is unaffected). mTLS
  via `tls_require_and_verify_client_cert` composes: a client cert is an
  *additional* factor, never a substitute for the MCP-bound token.
- **DPoP (Phase 6).** An app that logged in through FerroGate already holds a
  DPoP key. The exchange may bind the MCP token to that key's JWK thumbprint;
  the endpoint then requires an RFC 9449 proof per request, read from the
  `DPoP` header the logical layer already surfaces.
- **Local UDS.** Socket created `0600` in a `0700` directory under the user's
  runtime dir; `SO_PEERCRED` (Linux) / `getpeereid` + `LOCAL_PEERPID` (macOS)
  must return the server's own uid or the connection is dropped before any
  byte is read. stdio framing over the socket, as the 2026-07-28 spec
  describes.
- **Local loopback HTTP.** Bind `127.0.0.1` or `[::1]` only; port chosen by the
  operator (default 8250); pairing token required; `Origin`/`Host` checks as in
  § 5; TLS optional (self-signed from the GUI's keystore) because the
  threat is a browser tab, not a network sniffer — documented.

## Threat table

| Threat | Mitigation |
|---|---|
| Agent given a root or broad token "to make it work" | The MCP endpoint refuses non-MCP-bound tokens, so the shortcut does not function; the documented path is an app record with an explicit allow-list |
| Reuse of the MCP token against the REST API | `check_token` refuses MCP-bound tokens outside the MCP dispatcher |
| Forged binding via `auth/token/create` `meta` | Binding is a typed field; `RESERVED_TOKEN_META_KEYS` also refuses the `mcp_*` spellings |
| Unattested host in network mode | Exchange requires `spiffe_id` or a two-key, expiring, sudo-granted waiver |
| Waiver becomes permanent by neglect | `expires_at` mandatory, ≤ `waiver_max_days`, enforced per call; `mcp.app.machine_waiver.expired` emitted; GUI badge |
| Browser-tab DNS rebinding against the local server | Loopback bind + `Origin`/`Host` 403 + pairing bearer token (Inspector CVE lesson) |
| Same-user process impersonating a paired client | Peer creds + `exe_path` recorded; change → re-pair prompt; honest limit documented |
| Poisoned tool description | Constants in code; catalogue hash in `server/discover`; `catalogue_pin` refuses to serve a changed catalogue until the operator updates the pin |
| Prompt injection inside a secret value | Values only on explicit reveal; control-character stripping; no open-world tools in the catalogue |
| Secret written out through `bv_kv_write` | Destructive off by default, MRTR-confirmed locally, argument HMACs in audit |
| Confirmation handle replay | `requestState` HMAC-bound to accessor+args+expiry, single-use, never authentication |
| Legacy client sends `Mcp-Session-Id` expecting state | Ignored; nothing keyed on it |
| Plaintext MCP by misconfiguration | Endpoint refuses on `tls_disable = true` unless loopback + explicit opt-in |
| Downgrade to classical key exchange | `prefer-post-quantum` default; `require_hybrid_kex` for mandatory; negotiated group in audit + metrics |
| Volumetric abuse / brute force on `/v2/mcp/token` | Existing DoS guard (auth-class ceiling on the exchange), per-principal + per-tool limits, timeout, size caps |
| Audit blind spot | Tool calls traverse the standard pipeline; lifecycle via `emit_sys_audit`; OTel context captured |

## Dependencies

- [machine-authentication.md](machine-authentication.md) — shipped.
- [approle-machine-env.md](approle-machine-env.md) — shipped
  (`bypass_machine_binding` is the login-layer half of the waiver).
- [per-user-scoping.md](per-user-scoping.md) — shipped (shares to the app entity).
- [audit-logging.md](audit-logging.md), [dos-abuse-protection.md](dos-abuse-protection.md) — shipped.
- [identity-provider.md](identity-provider.md) — **Todo**; gates Phase 7 only.
- New runtime dependency candidates (each justified in the manifest): none
  expected beyond `serde_json`/`schemars` for the tool schemas, which are
  already in the graph. The official Rust MCP SDK is **not** a dependency:
  the protocol subset here is small, the SDK's transport layer would
  duplicate `bv-server`, and keeping the JSON-RPC surface in-tree keeps it
  reviewable. Its conformance test-suite is used as a **dev** tool where it
  helps (Phase 1 acceptance).

## Phases

| # | Title | Notes |
|---|---|---|
| 0 ✅ | **Spec + research** | This document. Research pass 2026-09-21; spec revision and rustls PQ default verified directly. |
| 1 | **`bv-mcp` core** | New crate: JSON-RPC 2026-07-28 types, `server/discover`, `tools/list`, `tools/call`, read-only catalogue (`bv_whoami` … `bv_pki_read_cert`), dispatcher over `bv_client::Backend`, gates, `sanitize_for_model`, size/timeout caps, `requestState` HMAC. Unit tests: every gate's allow + deny, catalogue hash determinism, sanitiser against the Trail of Bits ANSI corpus, schema validity. Conformance smoke against the reference client over stdio in a dev script. |
| 2 | **Kernel: binding, apps, exchange** | `TokenEntry.mcp_binding` (typed, `serde(default)`), `check_token` MCP-origin gate, `RESERVED_TOKEN_META_KEYS` additions, `sys/mcp/config|apps|tokens` storage + logical paths, `mcp/token` exchange with all six checks, waiver two-key rule, revoke-on-delete via lease manager, audit events, metrics families. Tests: old `TokenEntry` JSON deserialises with `mcp_binding = None` and is refused at the MCP gate; MCP token refused on `/v1/secret/*`; non-MCP token refused at dispatcher; waiver expiry cuts a live token; policy superset request refused. **L4 gate: this phase touches authn/authz.** |
| 3 | **Server transport** | `mcp_routes.rs`: `POST /v2/mcp`, 405s, PRM well-known, steps 1–10 of § 5, negotiated-group capture, DoS participation. Integration test drives a real HTTPS listener: hybrid kex negotiated (assert `X25519MLKEM768`), `require_hybrid_kex` refuses a classical-only client, `Origin` 403, header-mismatch 400, query-string token 400, `tls_disable` refusal, legacy version `-32022`. `docs/api.md`, `docs/configuration.md`. |
| 4 | **CLI** | `bvault mcp serve` (stdio / UDS + peer creds / loopback HTTP + pairing token), `pair`, `pairings list|revoke`, `token --app`, `catalogue`. Pairing store with the `bv_crypto` envelope. Tests: peer-uid mismatch drops pre-read; no-TTY pairing fails closed; loopback `Origin` 403; token never written to disk. `docs/cli-reference.md`. |
| 5 | **GUI** | *Settings → AI Assistants (MCP)*: enable, transport, pairing consent modal, per-call MRTR confirmation dialogs, pairing list. *Admin → MCP Apps*: app CRUD, waiver modal (reason + expiry mandatory), catalogue hash + pin, active tokens with revoke, recent calls. `commands/mcp.rs`, `api.ts`, vitest. GUI rules per `AGENTS.md` § GUI. |
| 6 | **Write tools + DPoP** | `bv_kv_write`, `bv_kv_delete`, `bv_pki_issue`, `bv_ssh_sign` behind `destructive_allowed` + MRTR; DPoP sender-constraint on app tokens reusing the FerroGate key. Tests: destructive denied by default; confirmed `requestState` replay refused; DPoP-bound token without proof refused. |
| 7 | **External / enterprise authorization** | PRM `authorization_servers`; accept AS-issued JWTs (`aud = canonical_url`) via the OIDC mount and exchange; Enterprise-Managed Authorization (ID-JAG) once the Identity Provider feature exists; CIMD for interactive clients. **Blocked on** [identity-provider.md](identity-provider.md). |
| 8 | **Docs + hardening + release gate** | `docs/mcp.md` operator guide with client snippets and the threat model; `make test-release` (authn/authz + new persisted `TokenEntry` field); CHANGELOG, roadmap, this file. |

Phases 1–3 are the minimum useful network-mode release; 4–5 the minimum
local-mode release. 6 is opt-in power; 7 is external.

## Testing requirements

- **Compatibility:** `TokenEntry` persisted before Phase 2 deserialises with
  `mcp_binding = None` (read-old); a Phase-2 entry round-trips (write-new).
  `McpApp` and `Pairing` carry a `version` field from day one.
- **Malformed input:** every § 5 step has a negative test; JSON-RPC batch,
  oversized body, non-UTF-8, `..` in every path argument, `Mcp-Name` ≠
  `params.name`, missing `_meta` version.
- **Authz regression:** a token minted by `auth/token/create` with
  `meta.mcp_binding = "…"` is refused; a role policy narrower than the app
  scope wins; an MCP token with `sudo`-capable policies still cannot reach
  `sys/*` through any tool.
- **Cucumber:** one feature file `tests/features/mcp_access.feature` — app
  lifecycle, exchange, read-with-and-without-reveal, denial audit entry
  present, waiver grant/expiry.
- **GUI:** pairing modal renders peer identity; confirm dialog denies by
  default on Escape; token never reaches `localStorage`.

## Open questions

- **Legacy protocol support.** As of writing, which shipping clients speak
  2026-07-28 exclusively is unknown to this document. Recommendation: build
  2026-07-28 only (Phase 1–3), measure against Claude Desktop / Claude Code /
  the reference clients during Phase 3, and add a **read-only** 2025-11-25
  compatibility mode (`initialize` answered, `Mcp-Session-Id` minted as an
  opaque random value that is never authentication) *only* if a first-party
  client still needs it. Do not implement it speculatively.
- **App record vs. AppID role flag.** Decided here: a separate
  `sys/mcp/apps` record referencing the role, so MCP knobs do not leak into
  the Vault-compatible `auth/approle/role/*` shape and one role can serve
  non-MCP clients. Revisit only if operators find two records confusing.
- **Should `bv_transit_decrypt` count as a reveal?** Decided yes (output is
  plaintext the model will see). Encrypt/sign/verify do not.
- **Per-namespace `canonical_url`.** One URL per server in v1; the token
  carries the namespace. If a deployment needs per-namespace PRM documents,
  extend PRM with a path segment later.
- **Should the local server exist inside the GUI process or as a spawned
  `bvault mcp serve`?** Leaning: the GUI spawns and supervises the CLI
  subcommand (one implementation, one pairing store format), the way the
  FerroGate commands reuse `ferrogate_mia` verbatim. Confirm during Phase 5.
- **DPoP mandatory for waived apps?** A waived app has no FerroGate key. Option:
  require the app to generate and register a DPoP key at first exchange when
  waived, so *something* sender-constrains its token. Decide in Phase 6.

## Acceptance criteria

- **Phase-level:** green CI + at least one integration test covering the happy
  path and the unauthorized path per phase; Phase 2 additionally passes
  `make test-release`.
- **Feature-level:**
  - A registered MCP app on a FerroGate-attested host can `bvault mcp token
    --app` and call `bv_kv_read_metadata` within its path scope over
    `POST /v2/mcp`; the negotiated key exchange is `X25519MLKEM768`; the audit
    log carries the call with `mcp.kind = "app"`.
  - The same app calling `bv_kv_read` with `reveal: true` is denied until
    `reveal_allowed` is set; the denial is audited.
  - The same app's login token (not exchanged) presented to `/v2/mcp` is
    refused; the MCP-bound token presented to `/v1/secret/data/x` is refused.
  - An app on an unattested host is refused at exchange; after a sudo waiver
    with reason and expiry it succeeds; after expiry its live token fails at
    the next call.
  - On a workstation, an MCP client connecting to `bvault mcp serve --socket`
    triggers a pairing prompt naming the client, uid, pid and executable; with
    no TTY and no GUI the pairing fails closed; after approval a
    `bv_kv_read reveal: true` call raises a confirmation and proceeds only on
    approval.
  - `bvault mcp serve --listen 0.0.0.0:8250` is a usage error.
  - A request to the loopback HTTP server with a foreign `Origin` returns 403
    without touching the vault.
  - `tools/list` is byte-identical across restarts and its hash matches
    `bvault mcp catalogue`; with `catalogue_pin` set to a different value the
    endpoint refuses to serve and emits `mcp.catalogue.pin_mismatch`.
  - The full network-mode flow works against an HA (Hiqlite) cluster.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md),
[roadmap.md](../roadmap.md) (row "MCP Access" under Infrastructure), this
file's Status line and phase table, and `docs/mcp.md`. Any change to a tool
description or schema is a `### Changed` CHANGELOG entry that quotes the new
catalogue hash.
