# MCP Access — operator guide

BastionVault can be used by AI assistants and agents over the
[Model Context Protocol](https://modelcontextprotocol.io) without giving them a
vault token. This guide is for the people who turn it on. The design and the
reasoning behind it are in [`features/mcp-access.md`](../features/mcp-access.md).

There are two ways in, and they are deliberately different:

| | **Local** — an assistant on your workstation | **Network** — an application calling the vault |
|---|---|---|
| Who acts | You, narrowed to a scope you approve per client | An *MCP app*: an AppID role plus an admin-set tool list and path scope |
| Entry point | `bvault mcp serve` (stdio, Unix socket or loopback HTTP) | `POST /v2/mcp` on the vault |
| Human in the loop | Pairing approval, and per-call confirmation for reveals and writes | None at call time; reveal and writes default off |
| Token | Minted from your login, held in memory only | Exchanged from the app's AppID login |

In both cases the client holds an **MCP-bound token**. It works against
`/v2/mcp` and nowhere else: presented to any other endpoint it is refused, and a
normal vault token presented to `/v2/mcp` is refused too. There is no way to
"make it work" by handing an assistant a broad token.

## What an assistant can do

`bvault mcp catalogue` prints every tool. The read tools: `bv_whoami`,
`bv_capabilities`, `bv_kv_list`, `bv_kv_read_metadata`, `bv_kv_read`,
`bv_resource_list`, `bv_resource_describe`, `bv_transit_encrypt|decrypt|sign|verify`,
`bv_totp_code`, `bv_pki_list_certs`, `bv_pki_read_cert`. The write tools:
`bv_kv_write`, `bv_kv_delete` (soft-delete only), `bv_pki_issue`, `bv_ssh_sign`.

Secret **values** come back only when the grant allows `reveal` *and* the call
asks for it; by default "read a secret" returns its metadata. A tool that
returns plaintext or a private key (`bv_transit_decrypt`, `bv_totp_code`,
`bv_pki_issue`) counts as a reveal. There is no tool for `sys/`, `auth/`,
`kv metadata destroy`, `pki/root/*`, file downloads, or anything that opens a
network connection, and there never will be.

Tool descriptions are constants in the software. `sys/mcp/config` accepts a
`catalogue_pin`, and the Admin → MCP Apps → Catalogue tab pins the hash with one
click. **Note:** endpoint enforcement of the pin is not built yet (T94); the pin
is recorded and shown as matching or not, nothing more.

## Enabling the network endpoint

Static transport settings live in the server's HCL config:

```hcl
mcp {
  enabled                  = true
  canonical_url            = "https://vault.example.com:8200/v2/mcp"
  allowed_origins          = []      # exact origins; empty = only non-browser clients
  allow_plaintext_loopback = false   # plaintext only on a loopback-only listener
  max_request_bytes        = 262144  # 0 = default; also the ceiling
  tool_timeout_secs        = 30      # 0 = default
}
```

- **TLS is required.** The endpoint refuses plaintext (503 `mcp_requires_tls`)
  unless the listener is loopback-only *and* `allow_plaintext_loopback = true`.
  This is judged on the listener itself, not on `X-Forwarded-Proto`.
- **`require_hybrid_kex` fails closed.** The negotiated key-exchange group is not
  yet available to the route, so while it is set `/v2/mcp` answers 503
  `mcp_hybrid_kex_unverifiable` rather than pretending to enforce it. The
  listener's rustls build prefers the hybrid `X25519MLKEM768` group by default,
  but that is a preference, not a guarantee.
- Runtime limits (`default_ttl_secs`, `max_ttl_secs`, `waiver_max_days`,
  `catalogue_pin`) are in `sys/mcp/config` (sudo), or Admin → MCP Apps → Settings.

### Registering an MCP app

An app is a record, `sys/mcp/apps/<name>`, that names an AppID role:

```bash
bvault write sys/mcp/apps/ci-secrets-reader \
  approle_role=reader-role \
  tool_allowlist=bv_kv_read_metadata,bv_kv_list \
  path_scope='secret/metadata/ai/*' \
  ttl_secs=3600
```

- **Empty means deny.** No tools or no path scope lets the app exchange a token,
  but every call is refused.
- `reveal_allowed` and `destructive_allowed` are separate switches, both off by
  default.
- The app's effective rights are its role's policies, narrowed by the tool list
  and path scope. ACL stays authoritative underneath; the tool list and scope are
  a second gate, never a substitute.
- Deleting an app revokes every token it was issued.

The caller needs a policy granting `update` on `sys/mcp/token`:

```hcl
path "sys/mcp/token" { capabilities = ["update"] }
```

### Machine identity and waivers

The AppID login that precedes the exchange must carry a live FerroGate machine
identity. A host that cannot run the FerroGate agent needs a **waiver**, which is
deliberately hard to get and impossible to forget:

- set per app, with `sudo` on `sys/mcp/apps/<name>/machine-waiver`;
- a reason is mandatory, and an expiry of 1 to 90 days (`waiver_max_days`);
- the AppID role must *also* allow `bypass_machine_binding`;
- it is checked at **every call**: when it expires, or is revoked, the tokens
  minted under it stop working at their next call rather than at their TTL.

```bash
bvault write sys/mcp/apps/legacy-batch/machine-waiver \
  reason="no FerroGate agent on this runner" expires_in_days=14
```

### Getting a token for an app

```bash
# after the AppID login (with its machine token) has produced VAULT_TOKEN
bvault mcp token --app ci-secrets-reader --format json
bvault mcp token --app ci-secrets-reader --field client_token
```

The token is printed, never stored. Send it as `Authorization: Bearer <token>`
to `POST /v2/mcp` (JSON-RPC, MCP revision 2026-07-28). Tokens last an hour by
default and at most 24; revoke from Admin → MCP Apps → Tokens or
`DELETE /v2/sys/mcp/tokens/<accessor>`.

## Connecting a local assistant

1. Sign in: `bvault login`.
2. Approve the assistant, **at a terminal**:

   ```bash
   bvault mcp pair --client-name claude-desktop
   ```

   `--client-name` must match the name the client reports in its MCP
   `clientInfo`. You are shown who is asking and choose the path scope, the tools
   (default: read-only, never reveals a value), whether it may reveal values or
   make changes, and whether you want to confirm each such call.
3. Point the assistant at the server.

   Claude Desktop (`claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "bastionvault": {
         "command": "bvault",
         "args": ["mcp", "serve"],
         "env": { "VAULT_ADDR": "https://vault.example.com:8200" }
       }
     }
   }
   ```

   Claude Code: `claude mcp add bastionvault -- bvault mcp serve`

Other transports:

```bash
bvault mcp serve --socket ~/.bvault/mcp.sock        # owner-only Unix socket
bvault mcp pair --client-name my-tool --transport loopback-http
bvault mcp serve --listen 127.0.0.1:8250            # loopback only, no flag widens it
```

For loopback HTTP, `pair` prints a pairing token **once** (only its hash is
stored); the client sends it as `Authorization: Bearer <token>` to
`POST http://127.0.0.1:8250/mcp`. Browser-origin requests are refused unless you
add `--allowed-origin`.

List and revoke clients:

```bash
bvault mcp pairings list
bvault mcp pairings revoke <id>     # removes it here, then revokes its tokens on the vault
```

The same list, with revoke, is in the desktop app under Settings → AI Assistants.
If the vault cannot be reached during a revoke the local record is still removed
(so no new token can be minted) and the command exits non-zero; the orphaned
tokens expire on their own.

Where pairings live: `$XDG_CONFIG_HOME/bvault/mcp-pairings.json` (else
`~/.config/bvault/…`), mode 0600, in a 0700 directory. They hold no tokens.
Override with `--pairings-file` or `BVAULT_MCP_PAIRINGS_FILE`.

### Headless launches

An assistant that launches `bvault mcp serve` itself usually has no terminal.
With none, a client that is not yet paired is **refused**
(`mcp_pairing_requires_operator`) and a call that needs confirmation is refused
(`mcp_confirmation_denied`). This is intentional: nothing is approved silently.
Run `bvault mcp pair` first, and choose "no" to per-call confirmation only if you
accept an unattended reveal or write.

## The limits, stated plainly

**Protects against:** an assistant given a broad token (it does not work),
reuse of an MCP token against the REST API, over-broad agents (tool list and
path scope on top of ACL), unattested hosts (machine identity or an expiring,
sudo-gated waiver), browser tabs reaching the local server (loopback only,
`Origin` and `Host` checks, pairing token), a different local user connecting to
the socket (peer uid checked before any read), tool-description poisoning (fixed
constants, hashed catalogue), and control characters or ANSI escapes in
returned data.

**Does not protect against:**

- A compromised client acting *within* its grant. If an assistant may reveal a
  path and is hijacked, that value leaks. Keep reveal off, scope narrowly, and
  prefer the per-call confirmation.
- Malware running as **your own user**. Peer credentials tell users apart, not
  processes of one user; the pairing prompt raises the bar but is not a sandbox.
- The pairing store's decapsulation key sitting beside the data. A headless CLI
  has no keychain; file permissions are the boundary, and a store readable by
  others is refused.
- A FerroGate or AppID compromise.
- The model deciding to call a tool it should not.

## Known gaps

Tracked in ROADMAP T94 and T93: DPoP sender-constraint for app tokens,
endpoint enforcement of `catalogue_pin`, the audit `mcp` enrichment block
(every `tools/call` is still audited through the normal pipeline), `bvault_mcp_*`
metrics, per-principal rate limits, a barrier-derived `requestState` key (it is
process-local, so MRTR confirmations are not shared across an HA cluster or a
restart), GUI-driven pairing consent (pairing is terminal-only for now), and
external/enterprise authorization (blocked on the Identity Provider feature).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `mcp_requires_tls` | Plaintext listener; use TLS or a loopback listener with `allow_plaintext_loopback` |
| `mcp_hybrid_kex_unverifiable` | `require_hybrid_kex` is set; it cannot be verified yet |
| `mcp_machine_identity_required` | No FerroGate identity on the login and no active waiver |
| `mcp_pairing_requires_operator` | Client not paired and no terminal; run `bvault mcp pair` |
| `mcp_client_info_required` | The client sent no `clientInfo`; pairing is matched on it |
| `mcp_confirmation_denied` | Declined, or needed a confirmation with no terminal to give it |
| `mcp_token_refused` | Token revoked, expired, or its waiver ended; retry mints a fresh one |
| `mcp_tool_not_allowed` / `mcp_path_out_of_scope` | Outside the grant |
| `mcp_reveal_denied` / `mcp_destructive_denied` | The grant does not allow it |
| `is too long for a Unix socket path` | Choose a shorter `--socket` (about 100 bytes) |
| `is accessible to other users` | `chmod 600` the pairing store |
