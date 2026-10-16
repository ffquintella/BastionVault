# Prompt: relay the SFTP subsystem through Rustion's SSH listener

Run this in the **Rustion** repository (`../Rustion`). It unblocks BastionVault
T141 (brokered SFTP in the desktop SFTP window, `features/sftp-connect.md`
Phase 4).

---

Implement real SFTP subsystem relaying on Rustion's SSH listener, for
sessions opened with a BastionVault ticket. Follow this repo's `AGENTS.md`
for build, test, tracking and change discipline. This is a security-sensitive
change to the proxy path: no silent fallbacks, explicit failures, no secrets
in logs.

## Current state (verify before changing anything)

- `crates/rustion-ssh/src/server.rs`, `subsystem_request` (~L1030): replies
  `channel_success` to `sftp` and `channel_failure` to anything else, but
  never dials the target and never relays data. A client gets a success
  reply and then hangs in the SFTP handshake.
- `crates/rustion-ssh/src/subsystem.rs`: holds only the `"sftp"` constant and
  `is_sftp`. Its doc comment claims a relay that does not exist.
- `shell_request` (~L488) is the only consumer of the BastionVault ticket
  session (`bv_active_session`, taken in the "BV-mediated session fast path").
  It goes through `connect_to_target_with_credential_and_relay` (~L1484),
  which always calls `request_pty` and `request_shell` on the target
  (~L1656–1690).
- `ROADMAP.md` marks T85 "Proxy the SFTP subsystem" `[x]`, and
  `docs/history/roadmap-pre-ptf.md` says "detection + relay". Both are
  inaccurate. The relay is missing.
- The ticket check (`crates/rustion-ssh/src/ticket_auth.rs`,
  `SessionError::TicketWrongListener`) rejects a ticket minted for another
  protocol's listener. BastionVault mints SSH tickets with `protocol: "ssh"`.

## What to build

1. **Ticket session to SFTP subsystem.** When `subsystem_request` asks for
   `sftp` and a BastionVault ticket session is pending in
   `bv_active_session`, take it exactly as the shell fast path does. Reuse
   the same credential materialisation (`bv_credential::materialise`, which
   refuses and never downgrades), the same `target_hostkey_pin` handling and
   the same brokered-login and target-cert audit events. Then dial the
   target, open a session channel, and call `request_subsystem(true, "sftp")`.
   Do **not** request a PTY or a shell. Reply `channel_success` to the client
   only after the target accepts the subsystem. If the target refuses, or
   dialling or auth fails, reply `channel_failure` and close the channel. No
   ANSI banner text goes on an SFTP channel, because it would corrupt the
   SFTP framing. Factor the shared dial and auth part out of
   `connect_to_target_with_credential_and_relay` rather than copying it. The
   shell path must keep working exactly as before.
2. **Byte relay.** Relay channel data both ways with no PDU parsing and no
   transformation, plus EOF and close in each direction. Go through the
   existing decoupled-forwarding pattern (the `input_tx` task) so the russh
   handler task is never blocked. Do not route SFTP bytes through the
   interactive menu or the command filter. Respect channel window and
   backpressure: large transfers must not buffer unboundedly in memory.
3. **Classical (non-ticket) sessions.** Decide explicitly and document it.
   Either refuse `sftp` with `channel_failure` when there is no
   ticket-selected target (the menu cannot run on an SFTP channel), or
   support it only when the target is already fixed. Never acknowledge a
   subsystem you will not relay.
4. **One channel per ticket.** A ticket session drives exactly one upstream
   channel, shell *or* sftp. A second subsystem or shell request on the same
   connection must not reuse the consumed credential. Keep the existing
   rule that a consumed ticket cannot open another channel.
5. **Session lifecycle.** Register the session in the active-session
   registry with a protocol marker that distinguishes SFTP from SSH, if one
   exists (add one if not, and check every match on `Protocol`). Mark the
   control-plane BastionVault session ended when the relay closes, exactly
   as the shell relay does (`bv_session_end`), so it does not linger in
   `/v1/sessions/active` until the lease expires. Honour `rustion/session/kill`.
6. **Recording and audit.** Do not write SFTP bytes to the asciicast
   recorder. Emit audit events for session start and end with byte counts in
   each direction and the outcome, stamped with the BastionVault authority
   and correlation id like the shell path. File contents are never logged.
   Per-file SFTP operation parsing is out of scope. Say so in the docs.
7. **Ticket protocol.** Keep accepting `protocol: "ssh"` tickets for SFTP on
   the SSH listener (BastionVault's SSH open path will be reused). Do not add
   an `sftp` ticket protocol unless there is a concrete reason, and if you
   do, write down the compatibility consequence for BastionVault.

## Tests

- Unit tests for the new decision points: refusal without a ticket target,
  refusal of a second channel after the ticket is consumed, subsystem names
  other than `sftp` refused.
- An integration test against a real SFTP server, for example a russh
  `sftp_server` like `libs/russh/russh/examples/sftp_server.rs` with
  `russh-sftp`. Mint a ticket, connect through the listener with a russh
  client, `request_subsystem("sftp")`, and run an `SftpSession`: list, upload
  and download a file bigger than one channel window, and compare the
  checksum. Cover a target that refuses the subsystem (client gets
  `channel_failure`, no hang) and a bad host-key pin (refused).
- A regression test proving `shell_request` behaviour is unchanged.
- If `tests/` has the BDD `ssh_proxy.feature`, add an SFTP scenario.

## Tracking (this repo's PTF)

- Correct T85: re-open it, or add a new task for the relay with a note on
  what T85 actually delivered. Follow `docs/tracking-format.md`, never edit
  history silently, and add the changelog entry in the same commit.
- Update the SSH proxy / BastionVault integration docs: SFTP is relayed for
  ticket sessions, and classical-session behaviour is whatever you decided
  in step 3.

## Done means

A BastionVault-style client authenticates to the listener with a `tkt_…`
ticket, opens the `sftp` subsystem, and transfers files to and from the
target, with audit rows, session-end marking and no recording of file bytes.
Report what you ran and what failed, and the Rustion version this ships in,
so BastionVault T141 can record it as the minimum bastion version.
