# MCP Access — operator guide

BastionVault can be used by AI assistants and agents over the
[Model Context Protocol](https://modelcontextprotocol.io) without giving them a
vault token. This guide is for the people who turn it on. The design and the
reasoning behind it are in [`features/mcp-access.md`](../features/mcp-access.md).

There are two ways in, and they are deliberately different:

| | **Local** — an assistant on your workstation | **Network** — an application calling the vault |
|---|---|---|
| Who acts | You, narrowed to a scope you approve per client | An *MCP app*: an AppID role plus an admin-set tool list and path scope |
| Entry point | The desktop app (`--mcp-stdio`), or `bvault mcp serve` (stdio, Unix socket or loopback HTTP) | `POST /v2/mcp` on the vault |
| Human in the loop | Pairing approval, and per-call confirmation for reveals and writes — a dialog in the app, or a terminal prompt | None at call time; reveal and writes default off |
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
The session tools: `bv_resource_ssh_exec`, which runs one command on a server
over an SSH session the vault opens (see
[Brokered SSH sessions](#brokered-ssh-sessions)), and `bv_resource_web_fetch`,
which fetches one page of a web application over an HTTPS session the vault
opens (see [Brokered web fetches](#brokered-web-fetches)).

A grant's **path scope** is matched against the path the tool sends to the
vault, not the argument the assistant typed. Each line is an exact path or a
prefix ending in `*`:

| Tool | Path checked against the scope |
|---|---|
| `bv_kv_list` (`mount`, optional `path`) | `<mount>/metadata/<path>/`; no `path` lists `<mount>/metadata/` |
| `bv_kv_read_metadata`, `bv_kv_read` | `<mount>/metadata/<path>`, `<mount>/data/<path>` |
| `bv_resource_list` (no arguments) | `resources/resources/` |
| `bv_resource_describe` (`name`) | `resources/resources/<name>` |
| `bv_capabilities` (`path`) | the `path` asked about, not `sys/capabilities-self` |
| `bv_resource_ssh_exec` (`resource`, `profile`, `command`) | `resources/secrets/<resource>/`, the path the `connect` capability is checked on |
| `bv_resource_web_fetch` (`resource`, `profile`, `path`, optional `method`) | `resources/secrets/<resource>/`, likewise |

So `secret/*` covers every KV tool on the `secret` mount, and `resources/*`
covers both resource tools.

Secret **values** come back only when the grant allows `reveal` *and* the call
asks for it; by default "read a secret" returns its metadata. A tool that
returns plaintext or a private key (`bv_transit_decrypt`, `bv_totp_code`,
`bv_pki_issue`) counts as a reveal. There is no tool for `sys/`, `auth/`,
`kv metadata destroy`, `pki/root/*` or file downloads.

**Earlier versions of this guide said no tool would ever open a network
connection. That is no longer true, and the statement is withdrawn.**
`bv_resource_ssh_exec` connects from the vault to a server and runs a command
there; `bv_resource_web_fetch` connects from the vault to a web application
and fetches a page. Each is off unless you turn it on in five places (below),
and every call must be confirmed by a person.

Tool descriptions are constants in the software. `sys/mcp/config` accepts a
`catalogue_pin`, and the Admin → MCP Apps → Catalogue tab pins the hash with one
click. **Note:** endpoint enforcement of the pin is not built yet (T94); the pin
is recorded and shown as matching or not, nothing more.

## Brokered SSH sessions

`bv_resource_ssh_exec` lets a paired assistant run **one command** on a
resource's server. The vault opens the SSH session, runs the command, closes
the session and returns capped, sanitized output. The assistant never
receives a password, key or certificate. The design, and what it does not
protect against, is in
[`features/mcp-brokered-sessions.md`](../features/mcp-brokered-sessions.md).

**You approve every call.** The desktop app or `bvault mcp serve` shows each
session call before anything is dialed — resource, profile, protocol and the
exact command — and it runs only if you allow it. There is no setting, grant
or "allow for a while" that skips this. See
[Approving session calls](#approving-session-calls).

**What turns it on.** All of these, and a binary built with the
`mcp_sessions_ssh` cargo feature:

1. The server config:

   ```hcl
   mcp {
     brokered_sessions {
       enabled   = true
       protocols = ["ssh"]
       # allowed_target_cidrs = ["10.20.0.0/16"]   # default: RFC 1918 + fc00::/7
       # call_timeout_secs = 20, max_output_bytes = 65536, rate_per_binding_per_min = 6, max_concurrent = 4
       # ssh { cert_source_addresses = ["203.0.113.7"] }
     }
   }
   ```

2. The runtime switch: `bvault write sys/mcp/config brokered_sessions_enabled=true`
   (sudo). Turning it off ends running sessions within two seconds.
3. The resource type: `connect.agent_sessions_max = "allow"` in the saved type
   configuration.
4. The connection profile: `agent_access = "allow"`, an SSH profile with a
   `host_key_pin` (`SHA256:…`) and an `ssh-engine` (CA mode) or `secret`
   credential source.
5. The pairing: `connect_allowed`, chosen when you approve the assistant. A
   pairing that may also reveal secrets can carry a revealed secret into a
   command; the only check on that is you, reading the command before you
   allow it.

The operator also needs `update` on `resources/v2/connect/agent/ssh/exec` and
`connect` on `resources/secrets/<resource>/*`, granted by policy — ownership
and shares never authorize an assistant. Network-mode apps can never open
sessions.

**Logins.** A certificate minted per call is preferred: the SSH engine role
must allow `force-command` (and `source-address` when
`cert_source_addresses` is set), add no `default_extensions`, and sign for at
most 60 s; the server then runs only the confirmed command. A stored password
or key also works, used inside the vault only; for a key, put `restrict` on
its `authorized_keys` line, since only the vault's own client keeps it to one
command.

**What the vault refuses to dial.** Only addresses inside the allow-list, and
never loopback, link-local (including `169.254.169.254`), multicast, this
host's own addresses or the cluster's nodes, whatever the list says. The name
is resolved once and only the checked addresses are dialed. The host key must
match the pin before any credential is sent.

### Approving session calls

When a paired assistant calls `bv_resource_ssh_exec`, the gatekeeper first
checks what the vault would refuse anyway — a pairing without brokered
sessions, a malformed command, a resource outside the path scope — and relays
those unprompted, so the vault answers them with its own code and audit event
and nobody is asked. Every other call is shown to you:

- **Desktop app:** **Run a command on *web-01*?**, with the resource, profile,
  protocol and the command in a box with numbered lines and its byte length;
  for a web fetch, **Fetch a page from *grafana*?**, with the method and the
  whole path with its query.
  It is never truncated (the box scrolls). A character that could hide or
  disguise text — a control, a bidi or zero-width character, an unusual space
  — is shown as `\u{XXXX}`; most of them are refused before you are asked.
  **Deny** has the focus; Escape, closing the dialog and 90 seconds without an
  answer deny.
- **`bvault mcp serve`:** the same lines on the terminal it runs in, then
  `Run this command once? [y/N]` (for a web fetch, `Request:   GET <path>`
  and `Fetch this page once? [y/N]`). Anything but `y` denies, and so does no
  answer within 90 seconds. Keys typed before the question are discarded, so
  a stray `y` cannot approve the next call.

**MFA-gated profiles.** When the profile has `require_mfa`, the same prompt
says "*claude-code* is asking you to complete MFA to access *web-01*" and asks
for **your** second factor — the assistant never completes MFA:

- the desktop app takes a TOTP code, or runs your security key (with its PIN
  if it has one);
- `bvault mcp serve` takes a TOTP code only. An operator whose only factor is
  a security key is refused there, with a message naming the desktop app.

The gatekeeper asks the vault, as you (your login, not the assistant's token),
whether the profile is gated (`resources/v2/connect/mfa/begin`), then verifies
your factor (`…/mfa/verify`) for that **one call**: the vault mints a ticket
bound to your login, the resource, the profile, this pairing, the tool and the
hash of the call's arguments, valid for 60 seconds and usable once. The
gatekeeper keeps it in memory and relays it to the vault with the call; the
assistant never sees it, the desktop window never sees it, and no result
echoes it. A wrong code denies the call. A different command, another
assistant, a second use, a human Connect window or a late use all find the
ticket refused (`mcp_session_mfa_ticket_refused`).

Only a **userpass** operator can do this: TOTP keys and security keys are
enrolled on userpass users. An operator who signed in another way can use
ungated profiles only; a gated one is refused before you are asked
(`mcp_session_mfa_unavailable`).

**What reaches the vault.** On approval the gatekeeper adds
`_meta["io.bastionvault/confirmation"] = {"by": "operator", "at": …, "mfa": …}`
(and, for a gated profile, the ticket) after removing any `io.bastionvault/*`
key the assistant sent. The vault cannot see your click, so it records the
confirmation as `operator_confirmation: "asserted-by-local-host"`; the MFA leg
is verified by the vault itself.

**Pairing.** Brokered sessions are a separate, off-by-default choice when you
approve an assistant: the desktop dialog's **Brokered sessions** section (one
checkbox per session tool), or the `Allow brokered sessions?` question of
`bvault mcp pair`. If the same assistant may also reveal secret values, you
are warned: it can read a secret **and** run a command that sends it
somewhere — you will approve each command, so read them.

**What is recorded.** Every refusal and every session is audited
(`connect.agent.refused`, `connect.agent.ssh.exec`, `connect.agent.aborted`;
the command only as an HMAC). Every session that ran is kept for 30 days as
an encrypted transcript — the command and its output, with the session's own
credential removed — readable with `read`/`list` **and** `sudo` on
`v2/sys/mcp/transcripts`. Transcripts can contain other secrets a command
printed.

## Brokered web fetches

`bv_resource_web_fetch` lets a paired assistant read **one page** of a
web-application resource — a status page, an API's JSON, an appliance's
console — with `GET` or `HEAD`. The vault makes the request from its own
process, logs in when the profile is `http-auth`, and returns the status, the
content type and the page reduced to text. The assistant never receives the
password, a cookie, a session URL or any response header but the content
type. Everything in [Brokered SSH sessions](#brokered-ssh-sessions) about
approval, MFA, pairing, limits, audit and transcripts applies unchanged.

**What turns it on.** The same five places, with `web` instead of `ssh`, and a
binary built with the `mcp_sessions_web` cargo feature:

1. `protocols = ["web"]` (or `["ssh", "web"]`) in `mcp.brokered_sessions`;
2. the runtime switch;
3. the resource type's `connect.agent_sessions_max = "allow"`;
4. the connection profile: `agent_access = "allow"` on a **web** profile whose
   `login_mode` is `open` or `http-auth` (with a `secret` credential source),
   whose `start_url` and `allowed_origins` are `https://`, and without
   `allow_insecure_http`. `form` and `sso` profiles are refused
   (`mcp_web_login_mode_unsupported`): filling a login form needs a browser,
   which waits on proxy mode or Rustion browser isolation;
5. the pairing's brokered sessions, with `bv_resource_web_fetch` ticked.

The operator needs `update` on `resources/v2/connect/agent/web/fetch` and
`connect` on `resources/secrets/<resource>/*`.

**What is fetched.** The assistant sends only a path, such as
`/api/health?verbose=1`. The vault fetches it from the origin of the profile's
`start_url` — never a host the assistant names. Absolute URLs, `//host`,
fragments, `..` segments (also percent-encoded), and anything a URL parser
would rewrite are refused before you are asked.

**Redirects** are followed by the vault, at most five, and only to the
profile's own https origins (`start_url` and `allowed_origins`); each hop's
address is checked against the destination allow-list before anything is
sent there. A redirect anywhere else stops the fetch, and where it pointed is
not returned.

**Certificates.** The vault trusts the operating system's certificate store,
read when it first fetches (restart the vault after adding a CA). An appliance
with a self-signed or private-CA certificate needs `tls_pin_sha256` on its
profile — the same pins the desktop app uses, decided by the same code: a
pin of the server's key, or of a CA in the chain it presents. There is no
"trust on first use" and no "accept anyway" for an assistant: an untrusted
certificate with no matching pin is refused (`mcp_web_tls_unpinned`,
`mcp_web_tls_pin_mismatch`), and the request is never sent.

**Logins.** An `http-auth` profile's stored username and password are sent
(HTTP Basic) only when the site asks for them with a Basic challenge, at most
once per site and realm in a call; Digest, NTLM and Negotiate are not
answered. A second challenge after the answer means the site refused the
credential, and the assistant gets that `401`. Cookies the site sets during the call are sent
back to it within the call and then dropped.

**What comes back.** At most 2 MiB of the page is read. HTML is reduced to
text — scripts, styles, comments, hidden templates, SVG and frames dropped,
links kept as `text <href>` — and JSON, XML and plain text are returned as
they are; anything else is reported as binary and not returned. The text is
capped at `max_output_bytes` and ends with `[… truncated by the vault]` when
cut. The profile's password, and every session cookie value the site set, are
replaced with `<redacted:credential>` wherever the page echoes them, in every
encoding the vault knows. Text a page hides with CSS is still returned: the
reduction does not run the page's styles.

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

## Connecting a local assistant through the desktop app

No `bvault` CLI is needed: the desktop app runs the local server itself, and
the assistant reaches it by launching the app's own binary.

1. In BastionVault, unlock your vault and **sign in as a regular user**. The
   server does not run under a root token, because the vault never mints an
   MCP token from one. A freshly initialised local vault signs you in as root,
   so first create a user (Admin → Users) whose policy grants `update` on
   `sys/mcp/token` and read on what the assistant should see:

   ```hcl
   path "sys/mcp/token"        { capabilities = ["update"] }
   path "sys/mcp/pairings/*"   { capabilities = ["delete"] }   # to revoke from Settings
   path "secret/metadata/ai/*" { capabilities = ["read", "list"] }
   ```

2. Settings → AI Assistants → **Serve AI assistants** → **Turn on**. The switch
   is remembered: from then on the server starts when you sign in, and it stops
   when you lock the vault, sign out, switch or reconnect vaults, forgetting
   every token it minted. Turning it off also revokes those tokens on the vault where your
   session may (`delete` on `sys/mcp/tokens/*`); otherwise they die with your
   session at sign-out, or expire.
3. Point the assistant at the app. Settings shows both snippets with this
   machine's path filled in, ready to copy. Claude Code:

   ```bash
   claude mcp add bastionvault -s user -- /Applications/BastionVault.app/Contents/MacOS/bastion-vault-gui --mcp-stdio
   ```

   Claude Desktop (`claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "bastionvault": {
         "command": "/Applications/BastionVault.app/Contents/MacOS/bastion-vault-gui",
         "args": ["--mcp-stdio"]
       }
     }
   }
   ```

   Nothing secret goes into either: no token, no address.
4. The first time the assistant connects, the app shows **Approve an AI
   assistant?** with the client's name and version, the vault you are signed in
   to, and whether the kernel confirmed it runs as your user. Choose the tools (preselected: the read-only
   ones that never reveal a value), the path scope (required), whether it may
   reveal values or make changes, whether to confirm each such call (on by
   default), the token lifetime, and — in its own section, off by default —
   whether it may open **brokered sessions**. **Deny**, closing the dialog, or no answer
   within 3 minutes refuses it. An assistant that gave up waiting reconnects and
   finds the approval recorded. An approval belongs to the assistant on this
   computer, not to the vault: signed in to another vault later, the app serves
   it without asking again, limited by that session's own policies. Revoke it
   under *Paired assistants* if that is not what you want.
5. A paired assistant's reveal or write, when you asked to confirm it, shows
   **Allow this AI-assistant call?** naming the tool and what it touches (mount,
   path, key — never a value). Deny is the default; no answer within 90 seconds
   refuses the call. A brokered-session call always shows **Run a command on
   …?** ([Approving session calls](#approving-session-calls)), with the MFA
   step when the profile requires it.

How it fits together: `--mcp-stdio` starts no window. It connects to the app's
socket — `mcp-gui.sock` beside the pairing store (`$XDG_CONFIG_HOME/bvault/`,
else `~/.config/bvault/`), 0600 in a 0700 directory — refuses one served by
any other user, and relays stdin and stdout. The app checks the relay's uid
before it reads a byte, answers the MCP `initialize` handshake, and mints
MCP-bound tokens from your session. Against a remote vault it makes the same two
calls `bvault mcp serve` makes (`POST /v2/mcp/token`, `POST /v2/mcp`), so the
server's `mcp { enabled = true }` and TLS rules apply. Against the embedded vault
the same exchange and the same `/v2/mcp` handling run in process; the Settings
switch is the only enablement there is. Pairings are the records `bvault mcp`
keeps (transport `uds`, your uid), listed and revocable under *Paired
assistants*. Only the main window can turn the server on or answer a request.

When the relay cannot connect it writes the reason to stderr (stdout is the MCP
channel) and exits non-zero, so the assistant reports a failed server:

| Exit | Meaning |
|---|---|
| 69 | The app is not running, its server is off, or the vault is locked — nothing is listening on the socket |
| 75 | The app closed the connection: the server was turned off, or the vault was locked or signed out |
| 77 | The socket is served by another user; not contacted |
| 64 | Bad arguments (only `--mcp-stdio [--socket <path>]` is accepted) |

If the assistant runs with a different `XDG_CONFIG_HOME` or `HOME` than the app,
pass the socket path Settings shows: `--mcp-stdio --socket <path>`.

macOS and Linux. On Windows the app reports the server as unsupported (no Unix
domain sockets in this build); use `bvault mcp serve`.

## Connecting a local assistant with the CLI

1. Sign in: `bvault login`.
2. Approve the assistant, **at a terminal**:

   ```bash
   bvault mcp pair --client-name claude-desktop
   ```

   `--client-name` must match the name the client reports in its MCP
   `clientInfo`. Claude Code reports `claude-code`; Claude Desktop reports
   `claude-desktop`. You are shown who is asking and choose the path scope, the tools
   (default: read-only, never reveals a value), whether it may reveal values or
   make changes, whether you want to confirm each such call, and whether it may
   open brokered sessions (every one of which you confirm, at the terminal
   `bvault mcp serve` runs in).
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

   Claude Code:

   ```bash
   claude mcp add bastionvault -e VAULT_ADDR=https://vault.example.com:8200 -- bvault mcp serve
   ```

### Clients on earlier MCP revisions

The vault speaks the stateless MCP revision 2026-07-28, in which every request
names its client. Most assistants today, Claude Code and Claude Desktop among
them, speak an earlier, stateful revision instead: they open with `initialize`
and name themselves only there.

`bvault mcp serve` bridges the two on stdio and on the Unix socket. It answers
`initialize` itself for revisions 2025-11-25, 2025-06-18 and 2025-03-26, and
offers 2025-11-25 to a client that asks for anything else. It checks the
pairing at that point, so an unapproved client fails when it connects rather
than at its first tool call. It then attaches the name the client gave to every
request it relays, and answers `ping` locally. A connection initializes once,
and a later request that names a different client is refused
(`mcp_client_info_mismatch`).

Loopback HTTP does not take the handshake: a client on that transport must
speak 2026-07-28.

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
accept an unattended reveal or write. A brokered-session call has no such
choice: it always needs you at a terminal (or in the desktop app), so a headless
`bvault mcp serve` refuses every one.

## The limits, stated plainly

**Changed by brokered sessions.** Before `bv_resource_ssh_exec` and
`bv_resource_web_fetch`, an
assistant needed a second MCP server to combine private data, untrusted
content and a way to send data out. With sessions enabled, BastionVault alone
can provide all three, even within one pairing. The control is procedural —
default-off switches, opt-ins on both sides, the destination allow-list, caps,
audit and transcripts, and above all **your confirmation of every call** — not
structural. Read each command before you allow it.

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
restart), a log of recent local calls in the desktop app, and
external/enterprise authorization (blocked on the Identity Provider feature).

Brokered sessions (T136): the embedded vault in the desktop app has no
brokered-sessions switch yet, so sessions work against a remote vault only;
`bvault mcp serve` cannot use a security key for the MFA step; an operator
who did not sign in with userpass cannot reach MFA-gated profiles; and an
operator signed in to a child namespace cannot either, because agent calls
run in the root namespace.

Web fetches (T137): `GET` and `HEAD` only; `form` and `sso` login modes are
refused (they wait on proxy mode, T106, or Rustion browser isolation, T97);
HTTP Digest is not answered; the operating system's certificate store is read
once per vault process; the per-call cookie jar keeps cookies per exact
origin and ignores `Domain` and `Path`; and the HTML reduction does not apply
CSS, so text a page hides is returned.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `mcp_requires_tls` | Plaintext listener; use TLS or a loopback listener with `allow_plaintext_loopback` |
| `mcp_hybrid_kex_unverifiable` | `require_hybrid_kex` is set; it cannot be verified yet |
| `mcp_machine_identity_required` | No FerroGate identity on the login and no active waiver |
| `mcp_pairing_requires_operator` | Client not paired and nobody approved it: no terminal (CLI; run `bvault mcp pair`), or the app's dialog was not answered in time, its window was closed or the vault locked |
| `mcp_server_stopped` | The server stopped while the call was in flight (turned off, lock, sign-out, vault switch); reconnect once it runs |
| "cannot be served from a root session" | The desktop app refuses to serve under a root token; sign in as a regular user |
| `--mcp-stdio` exits 69 | The app is not serving: open it, unlock, turn on Settings → AI Assistants |
| `mcp_client_info_required` | The client sent no `clientInfo`; pairing is matched on it |
| `mcp_confirmation_denied` | Declined, or needed a confirmation with no terminal to give it |
| `mcp_token_refused` | Token revoked, expired, or its waiver ended; retry mints a fresh one |
| `mcp_tool_not_allowed` / `mcp_path_out_of_scope` | Outside the grant |
| `mcp_reveal_denied` / `mcp_destructive_denied` | The grant does not allow it |
| `mcp_connect_not_allowed` | The pairing was not granted brokered sessions (`connect_allowed`) |
| `mcp_confirmation_required` | A session call reached the vault without a gatekeeper's confirmation: the assistant called `/v2/mcp` directly, or through a gatekeeper older than this release |
| `mcp_brokered_sessions_disabled` / `mcp_session_protocol_disabled` | A switch is off: `mcp.brokered_sessions`, its `protocols`, the runtime switch, or a build without `mcp_sessions_ssh` / `mcp_sessions_web` |
| `mcp_session_profile_not_agent_enabled` | The type's `agent_sessions_max` or the profile's `agent_access` is not `allow` |
| `mcp_session_mfa_required` / `mcp_session_mfa_unavailable` | The profile requires MFA and the call carried no ticket (a gatekeeper older than this release) / you cannot complete it here: not a userpass user, no factor enrolled, only a security key at `bvault mcp serve`, or signed in to a child namespace |
| `mcp_session_mfa_ticket_refused` | Your MFA ticket was for another call, expired (60 s) or already used; it is burnt, and the assistant's retry asks you again |
| `mcp_session_mfa_check_failed` | The gatekeeper could not ask the vault whether the profile is gated (unreachable, or your session may not read the resource or profile) |
| `mcp_session_requires_bastion` | The resource must be reached through Rustion, which cannot run an agent's command |
| `mcp_session_destination_refused` | The target address is outside `allowed_target_cidrs`, or always denied |
| `mcp_session_host_key_unpinned` / `mcp_session_host_key_mismatch` | No pin on the profile / the server's key is not the pinned one |
| `mcp_session_login_class_unsupported` | The credential source cannot be used for sessions, or the SSH role cannot bind the command (named in the message) |
| `mcp_rate_limited` / `mcp_session_busy` | Too many calls this minute / a session is already open |
| `mcp_session_timeout` / `mcp_session_failed` / `mcp_session_aborted` | Connecting took over 10 s, or a fetch outlived the call timeout / the connection or login failed, or a fetch redirected more than five times / revoked or switched off mid-session |
| `mcp_web_login_mode_unsupported` | A `form` or `sso` web profile: an assistant can use `open` and `http-auth` only |
| `mcp_web_origin_refused` | The profile is not https only, or the site redirected outside the profile's origins |
| `mcp_web_tls_unpinned` / `mcp_web_tls_pin_mismatch` | The site's certificate is not trusted by the operating system and the profile pins no key / pins keys, none of which matches |
| `is too long for a Unix socket path` | Choose a shorter `--socket` (about 100 bytes) |
| `is accessible to other users` | `chmod 600` the pairing store |
