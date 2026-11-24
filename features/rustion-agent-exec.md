# Feature: Rustion-routed agent exec

Status: **phases 0-2 done.** Phase 1 shipped in Rustion 0.20.0
(`docs/rustion-agent-exec.md` there, which fixes the wire contract); phase 2,
the vault side, is built and tested against a simulated bastion (T483).
Phase 3, the end-to-end run against a real Rustion, is Rustion's T484.
Companion to [mcp-brokered-sessions.md](mcp-brokered-sessions.md) (S111) and
[rustion-integration.md](rustion-integration.md) (S51). The work spans two
repositories: this one and `../Rustion`.

## Summary

Let an MCP assistant run one confirmed command on a resource whose transport
policy routes through a Rustion bastion. Before this the vault refused every
such call with `mcp_session_requires_bastion`, because Rustion's
`exec_request` was a no-op: it answered success and ran nothing
(`tests/e2e/rustion-ssh/run.sh:292-300` here).

The vault asks Rustion for a ticket that already carries the confirmed command,
dials Rustion over SSH with the ticket in the password slot, and sends an
`exec`. Rustion runs exactly that command on the target, records it, and
returns output and exit status.

## Why

- A resource set to `rustion-required` exists so that nothing reaches it except
  through the bastion's recording and choke-point. The only options today are
  to relax that policy for the agent (which defeats it) or to leave the
  resource out of MCP.
- Production resources are the ones most likely to be `rustion-required`, and
  the ones an operator most wants an auditable, recorded agent path to.

## Decisions

Decided by the owner on 2026-10-30:

1. **Transport:** SSH `exec` through the bastion. The vault opens a ticket
   (`rustion/v2/session/open`), dials Rustion with russh, and Rustion relays
   the exec to the target. Not a new HTTP endpoint on Rustion.
2. **`rustion-preferred` with a bastion available:** route through the
   bastion. It is no longer refused. It never dials direct while a bastion
   exists, so the recording cannot be bypassed.

Confirmed by the Rustion implementation (0.20.0) and built here:

3. **The command is bound into the ticket.** The envelope sealed for Rustion
   carries the confirmed command. Rustion runs only a byte-identical command, so
   an operator's confirmation holds at the bastion and a stolen ticket cannot
   run something else.
4. **Exec tickets and interactive tickets are different kinds.** An exec
   ticket refuses `shell`, `pty` and `subsystem`. An interactive ticket that
   receives `exec` is refused, where today it is accepted and ignored.
5. **Capability negotiation.** The vault routes through Rustion only when that
   Rustion advertises exec support (`"ssh_exec"` in `capabilities` on
   `GET /v1/authorities/self`, read fresh for every exec open). Against an
   older Rustion the refusal stays `mcp_session_requires_bastion`, with a
   message saying the bastion needs an update. No silent fallback to direct.
   Second line: an open whose `201` lacks `kind: "exec"` has its session
   ended (`kill` envelope) and is refused.

Decided while building phase 2 (T483):

6. **`rustion-preferred` never falls back to direct once a bastion is
   named,** even where Rustion's contract would allow it (open failed, or
   `CHANNEL_FAILURE`, so nothing ran). Decision 2 already says the route
   never dials direct while a bastion exists, and a fallback would let a
   bastion outage take the recording off an agent's command.
7. **The vault resolves the credential, the bastion seals it.** The agent
   route resolves or mints the credential with the direct path's functions
   and passes it as `credential_material` to `rustion/v2/session/open`, so
   its scrubber redacts an echoed secret as on the direct path. A
   certificate keeps `force-command`, no extensions and 60 s validity, without
   `source-address` (the bastion dials the target from an address the vault
   does not know). A passphrase-protected key is refused (the envelope has no
   passphrase channel).
8. **MFA is redeemed once, before the credential.** The agent route redeems
   the operator's call-bound ticket, then carries the redeemed record to the
   gate `rustion/v2/session/open` runs as an in-process grant (a value of a
   type private to the resource engine in the sub-request's context, bound to
   the resource and profile, spent once), never as a request field.
9. **Destination policy on the target, pinning on the bastion.** The agents'
   allow-list still applies to the target, where the command lands. The
   bastion's listener is enrolled infrastructure: it is not held to that
   list, and is authenticated by the host key discovered from it at
   enrolment (the pin the desktop app's interactive path uses), required
   before the ticket is sent. A bastion without that pin is not tried.
10. **No exit status is a failure.** After `CHANNEL_SUCCESS`, an exit status
    or signal is the result; anything else is `mcp_session_failed` with the
    bastion's hint, and the command is not retried. `CHANNEL_FAILURE` is
    "nothing ran". On a timeout, an abort or a missing result, the bastion
    session is ended through `rustion/session/kill`.

## Goals

- A confirmed command runs on a `rustion-required` target and is recorded.
- The operator's confirmation, the 60 s validity, single use and the host-key
  pin all hold on the bastion path exactly as on the direct path.
- Output limits, sanitization, audit and kill switches behave as on the direct
  path.

## Non-goals

- Interactive agent shells, PTYs, port forwarding or SFTP for agents.
- RDP and web agent sessions through Rustion (these stay on their own tasks,
  T138 and T97).
- Changing how human Connect sessions use Rustion.
- Any fallback to a direct dial when the bastion is down.

## Anti-goals

- A bastion that runs a command the operator did not confirm.
- A ticket reusable for a second command or a second connection.
- A silent downgrade: an old Rustion, a failed negotiation or an unavailable
  bastion must refuse, not dial direct.

## Design

### Vault side (built, T483)

- `check_transport` (`crates/bv-engine-resource/src/agent_session.rs`)
  returns the route (`decide_route`, unit-tested per policy) and is checked
  before MFA, so a refusal costs no ticket. An unresolvable or unknown
  policy is refused. The web route refuses a bastion route.
- The bastion leg is `crates/bv-engine-resource/src/agent_ssh/bastion.rs`;
  the executor's bastion mode is `exec::run_via_bastion`; the exec form of
  the open is in `crates/bv-engine-rustion/src/{lib,session,envelope}.rs`;
  the envelope keys are `bv_crypto::BvrgPayload::{kind, command}`, not
  written when absent (an interactive envelope is byte-for-byte unchanged).
- The SSH executor gains a bastion route beside the direct one. It reuses the
  one-command contract, limits, sanitizer and `Zeroizing` handling already
  there.
- `rustion/v2/session/open` gains an exec form: the command and a purpose of
  `exec`, sealed into the envelope with the credential. The response already
  carries `ticket` and `expires_at`.
- The server-side credential rules are unchanged: a `secret` credential is
  resolved by the same resolver the Rustion path uses; an `ssh-engine` CA
  credential is minted by the same function. For agent exec the minted
  certificate keeps the direct path's `force-command`, no extensions and 60 s
  validity.

### Rustion side

- Session records gain a `kind` (interactive, exec) and, for exec, the bound
  command. It travels in the sealed envelope and is verified with the vault's
  signature like every other field.
- `exec_request` on an exec ticket compares the command to the bound one,
  applies the command filter, opens an exec channel to the target with the
  sealed credential and the pinned host key, relays stdout, stderr and exit
  status, closes, and ends the session.
- The recording captures the command and its output.
- Capability: Rustion exposes that it supports exec, in a form the vault can
  read before choosing the route.

### Audit

One audit record per call, as on the direct path, naming the resource, profile,
command hash, bastion, session id and recording pointer. The command text and
output follow the existing transcript rules (S111 §10). Built as the direct
path's `connect.agent.ssh.exec` record plus a `bastion` block (`bastion_id`,
`bastion_name`, `session_id`, `correlation_id`, `recording_id`, `route`,
`listener`, `listener_host_key_fingerprint`, `outcome`, `reason`); the
transcript format is unchanged.

## Threat table

| Threat | Control |
|---|---|
| Stolen ticket runs another command | Command bound in the signed envelope; byte-identical check; single use; 60 s |
| Old Rustion treats exec as a no-op and reports success | Capability negotiation; refusal otherwise; never infer success from a closed channel without an exit status |
| Bastion down, agent session dials direct | No fallback; refusal |
| Operator confirmed command A, bastion runs a filtered or rewritten A | Bastion runs the bound bytes or refuses; the filter can only refuse |
| Interactive ticket used to run an exec | Ticket kinds are distinct; refused |
| Credential reaches the operator's machine | Unchanged: sealed to Rustion only |

## Phases

| Phase | Where | Delivers | State |
|---|---|---|---|
| 0 | both | Read-only spike: how the ticket, envelope and relay fit; settle the open items below; fix the wire shape | Done (Rustion `docs/rustion-agent-exec.md`) |
| 1 | Rustion | Exec ticket kind, bound command, relay with recording, capability flag, tests | Done (Rustion 0.20.0, its T478-T483) |
| 2 | vault | Exec form of `session/open`, bastion route in the SSH executor, `check_transport` change, tests | Done (T483) |
| 3 | both | End-to-end test with a real Rustion, docs, changelog | Docs and changelog done here; the real-Rustion run is Rustion's T484 |

Phase 2 depends on a Rustion release from phase 1. They are separate
branches in separate repositories.

## Phase 0 items (resolved)

All five are answered by Rustion's `docs/rustion-agent-exec.md`:

- Capability flag: `capabilities: ["ssh_exec"]` on `GET /v1/authorities/self`
  (decision 5 above).
- Result mapping: `CHANNEL_FAILURE` = nothing ran; `CHANNEL_SUCCESS` then
  exit status, exit signal, or neither (= failure); output capped per
  stream, truncation hinted in-band (decision 10).
- Command filter: refuse-only, may refuse a confirmed `ssh`/`scp`/`sftp`
  command; surfaces as `CHANNEL_FAILURE` with `exec_command_filtered`.
- `rustion-preferred` health: no pre-check; the open is authoritative
  (decision 6 above for what the vault does with a failure).
- Envelope compatibility: `kind` and `command` are optional top-level keys,
  absent on an interactive open; tested byte for byte in `bv_crypto`.

## Testing requirements

- Rustion: exec ticket runs the bound command; a different command is refused;
  a reused ticket is refused; shell and subsystem on an exec ticket are
  refused; exec on an interactive ticket is refused; recording contains the
  command.
- Vault (built): each transport policy yields the right route
  (`agent_session::tests`); an old Rustion yields the named refusal and is
  never posted to (`bv-engine-rustion` `session::exec_tests`, HTTPS stand-in);
  an open without `kind: "exec"` is killed; a down bastion refuses and never
  dials direct (`src/engine_tests/mcp_sessions_ssh.rs`); the confirmed, sealed
  and sent bytes are the same (`bastion::tests`, `envelope::tests`,
  `exec::tests`); `CHANNEL_FAILURE` vs `SUCCESS` without a status vs a signal
  (`exec::tests`, test server as listener); envelope over 16384 bytes;
  `BvrgPayload` compatibility and malformed keys (`bv_crypto` `bvrg::tests`).
- End to end: `bv_resource_ssh_exec` against a `rustion-required` resource
  returns the command's output and exit status, and the recording exists.

## Tracking

Tracked as S119 (Specs table) and T483 (M8, next to T136–T138), both in
`ROADMAP.md`. Both repositories need their own changelog entries.
