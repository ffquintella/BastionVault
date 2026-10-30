# Feature: Rustion-routed agent exec

Status: **design, not approved.** Nothing here is built. Companion to
[mcp-brokered-sessions.md](mcp-brokered-sessions.md) (S111) and
[rustion-integration.md](rustion-integration.md) (S51). The work spans two
repositories: this one and `../Rustion`.

## Summary

Let an MCP assistant run one confirmed command on a resource whose transport
policy routes through a Rustion bastion. Today the vault refuses every such
call with `mcp_session_requires_bastion`, because Rustion's `exec_request` is a
no-op: it answers success and runs nothing (`crates/rustion-ssh/src/server.rs:1066`
in Rustion, `tests/e2e/rustion-ssh/run.sh:292-300` here).

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

My calls (not yet confirmed; change them here before building):

3. **The command is bound into the ticket.** The envelope sealed for Rustion
   carries the confirmed command. Rustion runs only a byte-identical command, so
   an operator's confirmation holds at the bastion and a stolen ticket cannot
   run something else.
4. **Exec tickets and interactive tickets are different kinds.** An exec
   ticket refuses `shell`, `pty` and `subsystem`. An interactive ticket that
   receives `exec` is refused, where today it is accepted and ignored.
5. **Capability negotiation.** The vault routes through Rustion only when that
   Rustion advertises exec support. Against an older Rustion the refusal stays
   `mcp_session_requires_bastion`, with a message saying the bastion needs an
   update. No silent fallback to direct.

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

### Vault side

- `check_transport` (`crates/bv-engine-resource/src/agent_session.rs:442`)
  stops refusing a `rustion` profile, `rustion-required`, and `rustion-preferred`
  with a bastion. It returns the route (direct or bastion). An unresolvable
  policy is still refused.
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
output follow the existing transcript rules (S111 §10).

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

| Phase | Where | Delivers |
|---|---|---|
| 0 | both | Read-only spike: how the ticket, envelope and relay fit; settle the open items below; fix the wire shape |
| 1 | Rustion | Exec ticket kind, bound command, relay with recording, capability flag, tests |
| 2 | vault | Exec form of `session/open`, bastion route in the SSH executor, `check_transport` change, tests |
| 3 | both | End-to-end test with a real Rustion, docs, changelog |

Phase 2 depends on a Rustion release from phase 1. They are separate
branches in separate repositories.

## Open items for phase 0

- Exact shape of the capability flag and how the vault reads it.
- How an exec result (exit status, stderr, truncation) maps onto Rustion's
  existing relay and recording.
- Whether the command filter's current blocklist can break a legitimate
  confirmed command, and what the operator sees when it does.
- Whether `rustion-preferred` needs the vault to check bastion health before
  choosing the route, or can rely on `session/open`'s candidate selection.
- Compatibility of the envelope change with Rustion versions that predate it
  (read-old/write-new, per the persisted-format rule).

## Testing requirements

- Rustion: exec ticket runs the bound command; a different command is refused;
  a reused ticket is refused; shell and subsystem on an exec ticket are
  refused; exec on an interactive ticket is refused; recording contains the
  command.
- Vault: each transport policy yields the right route; an old Rustion yields
  the named refusal; a down bastion refuses and never dials direct; the
  confirmed command and the bound command are the same bytes.
- End to end: `bv_resource_ssh_exec` against a `rustion-required` resource
  returns the command's output and exit status, and the recording exists.

## Tracking

New task under S111's milestone and a row in `ROADMAP.md`'s Specs table when
approved; both repositories need their own changelog entries.
