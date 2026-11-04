# Prompt: relay database sessions (PostgreSQL, MySQL, MariaDB, SQL Server, Oracle) through Rustion

Run this in the **Rustion** repository (`../Rustion`). It unblocks the
BastionVault SQL browser running on a resource whose effective transport is
`rustion-required` (`features/sql-browser.md` §6.6, "Future work: a Rustion
database relay transport"). BastionVault does **not** change in this task:
section "Contract BastionVault will consume" lists what it needs from you.

---

Implement database relaying on Rustion for sessions opened with a
BastionVault ticket, for every database engine the BastionVault SQL browser
supports: **PostgreSQL, MySQL, MariaDB, SQL Server (TDS) and Oracle (TNS,
23ai and later)**. Follow this repo's `AGENTS.md` for build, test, tracking
and change discipline. This is a security-sensitive change to the proxy path:
no silent fallbacks, no downgrade of TLS or authentication, explicit
failures, no secrets or statement text in logs.

## Why, and what the client is

Today the SQL browser's plugin (`dbms-management`, a long-lived process
plugin on the vault server) dials the database directly. A resource whose
transport policy is `rustion-required` is refused, because Rustion's target
protocols are SSH and RDP only. Operators who put databases behind a bastion
for network segmentation, recording and a single audit point cannot use the
SQL browser on them.

The only client that will use the relay is that plugin. It speaks the real
wire protocol through the Rust drivers `tokio-postgres`, `mysql_async`,
`tiberius` (TDS 7.3) and, for Oracle, its own TNS session layer over the
Sans-I/O crate `oraclemcp-driver-cx-protocol`. You may therefore define how
the ticket is carried per protocol (see "Ticket carriage"), but prefer
in-band standard fields so `psql`, `mysql` and `sqlcmd` could be pointed at
the listener too, and say plainly where that is not possible.

## Current state (verify before changing anything)

- Rustion's target protocols are SSH and RDP. Listeners and their TLS/host-key
  `pin` are advertised by `GET /v1/listeners` (schema v2).
- Ticket flow (`docs/` and `crates/rustion-control-plane/src/session.rs`):
  BastionVault `POST /v1/sessions` with a BVRG-v1 envelope; Rustion verifies,
  decrypts, materialises a session and returns
  `{session_id, host, port, ticket, expires_at}`. The ticket is `tkt_<32 hex>`,
  **single-use, IP-bound, 30 s**. `ticket_auth::consume_ticket_for_login`
  collapses every failure to `Invalid` on the wire (no enumeration) and logs
  the detailed reason. `TicketWrongListener` rejects a ticket minted for
  another protocol's listener.
- `bv_credential::materialise` turns the envelope's credential into what the
  target dial needs and refuses, never downgrades. `target_hostkey_pin`
  handling exists for SSH. Recording carries `rustion.{authority,
  correlation_id}`. `session/renew` and `session/kill` exist.
- The SSH and RDP proxies show the pattern to follow: the ticket is the first
  authentication step, the socket is bound to the materialised session, the
  control-plane session is ended when the relay closes (`bv_session_end`),
  and a consumed ticket cannot open another channel.

Confirm each point in the source, and correct this list in your report where
it is wrong.

## What to build

### Phase 1 — a TLS-terminating, pin-verifying TCP relay for all five engines

One listener per wire protocol (`postgres`, `mysql` serving MySQL and
MariaDB, `mssql`, `oracle`), each with its own port, advertised in
`/v1/listeners` with a TLS leaf `pin` (`sha256:<hex>`) like the RDP gateway.
Do not sniff protocols on a shared port.

1. **Ticket check before anything reaches the target.** Consume the ticket as
   the first step of the protocol's login (see "Ticket carriage"). Any failure
   closes the connection with the protocol's generic login-failure form and no
   detail. Nothing is dialled until the ticket is valid.
2. **Target comes from the session only.** The host, port, service/database
   named by the client in its startup, connect string or login packet is
   ignored or refused, never dialled. This closes an SSRF path: a client must
   not turn the relay into a generic dialer.
3. **TLS is mandatory on both legs.** Client leg: refuse any ticket sent in
   cleartext (PostgreSQL `SSLRequest` required before the startup, MySQL SSL
   upgrade before the auth response, TDS TLS inside prelogin, Oracle TCPS).
   Target leg: verify the target certificate against the CA the session
   names (or the system roots), honour the profile's TLS mode carried in the
   envelope (`require`, `verify-ca`, `verify-full`, server name), and refuse
   a downgrade or a target that does not offer TLS when the session demands
   it. SQL Server wraps its TLS handshake inside TDS prelogin packets; MySQL
   and MariaDB upgrade mid-handshake; PostgreSQL uses a one-byte `S`/`N`
   answer to `SSLRequest` (refuse `GSSENCRequest`); Oracle 23ai is TCPS only.
4. **Byte relay after authentication.** Relay frames both ways without
   interpreting statements, with EOF/close in each direction and bounded
   buffering under backpressure. Large result sets and bulk loads must not
   grow memory without limit. Never block the listener task.
5. **Limits.** Handshake timeout, idle timeout, maximum packet size per
   protocol, maximum concurrent sessions per listener and per session. All
   configurable with safe defaults.
6. **Lifecycle.** Register the session in the active-session registry with a
   protocol marker per engine (check every match on the protocol enum),
   honour `session/kill` by closing both legs, enforce the session TTL and
   `session/renew`, and end the control-plane session on close.
7. **Audit.** Session start and end, bytes in each direction, duration,
   outcome and close reason, stamped with the BastionVault authority and
   correlation id like the SSH path. No statement text, result data or
   credential is logged.

Phase 1 satisfies "reach the database only through the bastion". The client
still authenticates to the database itself, so the database credential is
still released to the plugin.

### Phase 2 — credential-isolating relay (the target state)

Add, per engine, a mode in which Rustion terminates the client's database
login with the **ticket** and performs the real login to the target itself
with the materialised credential, so the plugin never receives the database
password. After the target login succeeds, relay as in Phase 1. Implement in
this order and ship each as its own change, because the cost and the risk
differ:

1. **PostgreSQL**: `AuthenticationCleartextPassword` toward the client over
   TLS with the ticket as the password; toward the target, SCRAM-SHA-256 and
   MD5 (refuse `trust` and cleartext on a non-TLS leg), then forward
   `ParameterStatus`/`BackendKeyData`. Handle `CancelRequest` by mapping the
   client's cancel key to the target's.
2. **MySQL and MariaDB**: server handshake v10 toward the client with
   `mysql_clear_password` (ticket as the password, over TLS); toward the
   target, `caching_sha2_password` and `mysql_native_password`, plus
   MariaDB's `ed25519` if the profile asks for it. Pass the negotiated
   capabilities through only where they are safe (no `LOCAL INFILE`).
3. **SQL Server**: TDS prelogin/Login7 toward the client with the ticket in
   the Login7 password, TLS inside prelogin; toward the target, SQL
   authentication (refuse an unencrypted login). Named instances and
   `instance` resolution must come from the session, never the client.
4. **Oracle**: the hardest. Toward the client, TNS connect and the O5LOGON
   challenge/response server side, using the ticket as the secret (Rustion
   knows it, so it can derive the verifier); toward the target, O5LOGON client
   side with the materialised credential. If you decide a pre-login ticket
   frame is the only safe option for Oracle, justify it in the docs and say
   what a standard client loses. Refuse TNS redirect and any packet that
   names another host.

Where Phase 2 for an engine is not delivered, that engine stays Phase 1 and
the docs say so. Never present a Phase 1 relay as credential-isolating.

## Ticket carriage

Choose per engine and document it. Defaults to evaluate first:

| Engine | Where the `tkt_…` goes | Notes |
|---|---|---|
| PostgreSQL | password message (user `bv`), after `SSLRequest` | standard `password` auth over TLS |
| MySQL / MariaDB | auth response (`mysql_clear_password`) after the SSL upgrade | the client must allow cleartext plugin, over TLS only |
| SQL Server | Login7 password inside the TLS-in-prelogin tunnel | the obfuscated field is protected by TLS |
| Oracle | decided by you (see Phase 2.4) | document the loss of standard clients, if any |

The ticket must be compared in constant time, never echoed, never logged, and
spent exactly once. A second connection with the same ticket is refused. A
ticket minted for one engine's listener is refused on every other
(`TicketWrongListener` extends to the new protocols).

## Session-open contract

`POST /v1/sessions` accepts the new `target_protocol` values
(`postgres`, `mysql`, `mariadb`, `mssql`, `oracle`) and a credential kind per
engine (for example `sql-password`), with the target's TLS mode, server name
and optional CA PEM carried in the envelope. Validate strictly: unknown keys
fail closed. An older Rustion that does not know these values must answer in
a way BastionVault can tell apart from a refusal (document the exact error),
and `GET /v1/listeners` must say which database listeners exist so
BastionVault can detect support before it opens a session.

## Contract BastionVault will consume (document, do not implement here)

BastionVault will, in a follow-up: stop refusing `rustion-required` for
database resources; call `rustion/v2/session/open` with the new
`target_protocol`; have the plugin dial `bastion-host:listener-port` with the
ticket instead of the database, pinning the listener's TLS leaf digest; and
record the effective transport as `rustion` in its audit. Write down, in
Rustion's docs, the exact listener schema, the ticket carriage per engine,
the session-open fields, the error codes, the minimum Rustion version, and
what the relay logs, so that change can be written without reading your code.

## Out of scope (say so in the docs)

Statement parsing, classification or blocking at the bastion (BastionVault
classifies, authorizes and audits every statement before it is sent);
recording of result data; connection pooling or multiplexing across tickets;
non-relational databases; Kerberos/GSSAPI/Windows-integrated login toward the
target.

## Tests

- Unit tests per engine for the decision points: ticket missing, malformed,
  reused, wrong listener, wrong source IP, expired; cleartext attempt
  refused; client-named target ignored; target without TLS refused when the
  session demands it; certificate or pin mismatch refused; oversized packet
  refused; handshake and idle timeouts.
- Integration tests against real servers, using the images BastionVault's own
  `make test-dbms` uses: `postgres:16`, `mysql:8.4`, `mariadb:11.4`,
  `mcr.microsoft.com/mssql/server:2022-latest` (linux/amd64) and
  `gvenzl/oracle-free:23-full`. For each: mint a ticket, connect through the
  listener with the same driver family the plugin uses, run a query, a
  result set larger than the socket buffers, a cancel, and a clean close;
  then `session/kill` mid-query and check both legs close. SQL Server needs
  a server certificate that is X.509 v3 (the one it generates is v1).
- Phase 2 additionally: a test that a client holding only the ticket cannot
  log in to the target directly, and that the materialised credential appears
  in no log line, audit row, error text or core dump path you can reach.
- A regression test proving the SSH and RDP proxies behave exactly as before.
- Extend `tests/e2e/` or the docker-compose scaffold with a database target.

## Security checks before you call it done

No `openssl-sys` or `aws-lc-sys` where the manifests say so. Credentials and
tickets zeroized where practical, never in `Debug` output. Constant-time
comparisons. No unbounded allocation driven by a length field read from the
network, in any of the five protocols. Fuzz or property tests for each
protocol's framing parser (a malformed or truncated frame closes the session,
it never panics). Review the two TLS legs together: a failure on either must
close both.

## Tracking (this repo's PTF)

Add tasks per engine and per phase under the right milestone, follow
`docs/tracking-format.md`, and add the changelog entries in the same commits.
Create a feature file for the relay before implementing it, record the
Phase 1 / Phase 2 status per engine in it ("Current State"), and update the
integration docs. Do not mark an engine's credential isolation done until its
Phase 2 tests pass.

## Done means

A BastionVault-style client authenticates to each database listener with a
`tkt_…` ticket over TLS, runs queries against each of the five engines
through the bastion, with the target reachable only from Rustion, audit rows,
session-end marking and no statement text or credential in any log. For every
engine, the report states whether it is Phase 1 (tunnel) or Phase 2
(credential-isolating). Report what you ran and what failed, and the Rustion
version this ships in, so BastionVault can record it as the minimum bastion
version for database transport.
