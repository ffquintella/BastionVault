# Feature: RDP clipboard redirection (host ⇄ session)

**Status:** In Progress — Phase 1 (text) implemented, see the phase table.

Copy on one side, paste on the other. An operator running an in-app RDP
session (Resources → Connect, or the ⌘K palette) can `Ctrl+C` in the remote
Windows desktop and `Cmd/Ctrl+V` into a local editor, and the reverse.

This is the MS-RDPECLIP (`CLIPRDR`) static virtual channel, driven by
[`ironrdp-cliprdr`](../IronRDP/crates/ironrdp-cliprdr), bridged to the host OS
clipboard inside the Tauri host.

---

## 1. Why this is not simply "on"

BastionVault is a privileged-access product and the clipboard is a
**bidirectional data channel into and out of a privileged session**. Turning it
on unconditionally would:

- give every RDP session an unlogged egress path for whatever the operator can
  see on the target (the exact thing a session recording exists to make
  accountable), and
- give every session an ingress path into a production host.

So the channel is **opt-in per connection profile and off by default**, with an
explicit direction, a size cap, and observable counters. An operator who wants
it says so; nobody gets it by accident on upgrade.

This does not conflict with the existing "credentials never reach the
clipboard" property in [resource-connect.md](resource-connect.md) §Security:
that is about *our* handling of the resource's stored secret, which still never
goes near `navigator.clipboard` or the host clipboard. Clipboard redirection
moves *operator-initiated* content, and only when the profile allows it.

---

## 2. The switch

Profile key `rdp_clipboard`, parsed strictly — an unrecognised value is a
connect-time error, not a silent fall back to a default (AGENTS.md §7: no
implicit fallbacks on a path an operator configured deliberately). This matches
the existing `rdp_bulk_compression` key exactly.

| Value | Meaning |
|---|---|
| `off`, `none`, `""` (absent) | **Default.** The `CLIPRDR` channel is not attached at all — nothing is advertised to the server, so the remote desktop sees a client with no clipboard redirection. |
| `host-to-session`, `in` | Host clipboard → session only. The remote may *request* our clipboard; remote copies are ignored and never touch the host clipboard. |
| `session-to-host`, `out` | Session clipboard → host only. Remote copies land on the host clipboard; our own clipboard is never advertised or served to the remote. |
| `bidirectional`, `both`, `on` | Both directions. |

`off` deliberately means "not attached" rather than "attached but inert": a
capability we do not intend to honour should not be advertised.

---

## 3. Data model — Phase 1 is text only

| Format | Direction | Phase |
|---|---|---|
| `CF_UNICODETEXT` (13) | both | **1 (this phase)** |
| `CF_TEXT` / `CF_OEMTEXT` | — | not offered; every Windows target since NT converts from `CF_UNICODETEXT`, and offering a code-page format invites mojibake |
| `CF_DIB` / `CF_DIBV5` (images) | — | 2 |
| `CF_HDROP` (file copy) | — | 3, and gated separately — a file channel is a materially bigger control question than text |

Wire conversion (MS-RDPECLIP 2.2.5.2):

- Outbound: host UTF-8 → UTF-16LE, `\n` → `\r\n`, NUL-terminated.
- Inbound: UTF-16LE → UTF-8, trailing NULs stripped, `\r\n` → `\n` on
  non-Windows hosts (a Windows host keeps CRLF, which is what its own
  applications expect).
- Lone surrogates are replaced, not rejected: a paste is not the place to fail
  a session, and `String::from_utf16_lossy` is the honest reading of a
  malformed UTF-16 payload.

**Size cap**: `MAX_CLIPBOARD_BYTES` (1 MiB). A payload over the cap in either
direction is dropped and counted, never truncated — a half-pasted credential or
config file is worse than a failed paste. The cap applies to the wire payload,
which is the attacker-influenced side.

---

## 4. Architecture

```
 host OS clipboard                                   remote desktop
        │                                                   ▲
        │ arboard (own thread)                              │
        ▼                                                   │
 ClipboardBridge ──ClipboardMessage──▶ pump select! ──▶ CliprdrClient ──▶ CLIPRDR SVC
   (poll 500ms,     (unbounded mpsc)    (rdp.rs)      (initiate_copy /
    read/write)                                       initiate_paste /
        ▲                                             submit_format_data)
        │                                                   │
        └──────────────── TextCliprdrBackend ◀──────────────┘
                          (CliprdrBackend impl)
```

- **`ClipboardBridge`** owns the single `arboard::Clipboard` handle on its own
  `std::thread`. Two reasons it is not inline in the pump: X11/Wayland
  clipboard calls can block for as long as the *owning application* takes to
  answer, and a blocked pump is a frozen session; and platform clipboard
  handles have thread affinity that a `tokio` worker cannot promise.
- **Host-change detection is a poll**, because no cross-platform clipboard
  change notification exists (Windows has one; X11 and macOS do not). 500 ms
  is under human copy→paste latency and costs one clipboard read per tick.
- **`TextCliprdrBackend`** implements `CliprdrBackend`. Every trait method is
  either a no-op (files, locks, palettes) or a direction-gated text path. It
  never blocks: it turns a request into a `ClipboardMessage` for the pump or a
  command for the bridge.
- **Loop breaking** uses `ironrdp_cliprdr::loop_detector::LoopDetector` with
  content hashing. Writing remote text to the host clipboard records the
  content hash as `Remote`; the poller's next tick sees that same content as a
  "local change" and `would_cause_content_loop` suppresses re-advertising it.
  Without this, one copy ping-pongs forever.
- **The pump** grows one `select!` branch and one `RdpControl`-adjacent
  unbounded channel, mirroring `ironrdp-client`'s reason for keeping clipboard
  off the bounded input channel: backpressure meant for keyboard and pointer
  input would desynchronize the clipboard protocol state machine.
- **That branch must be gated on the channel still having senders**, and the
  receiver is wrapped in `ClipboardInbox` to make that impossible to forget.
  `UnboundedReceiver::recv()` does not park once the last sender is dropped —
  it resolves to `None` immediately, and on every poll after. The pump's
  `select!` is `biased` with `read_pdu` *below* this branch, so an ungated
  branch is not an idle no-op: it wins every iteration and the session never
  reads a single PDU. With redirection `Off` — the default — no sender is ever
  created, so this hit every session, and it read as a graphics fault (black
  desktop, input accepted, nothing painted, `0 pdus` in the session log line,
  100 % CPU) rather than as a stalled reader. Fixed in `[Unreleased]`.

---

## 5. Observability, and what is deliberately not logged

- **Never** the clipboard content, in any log level, on either side. The logs
  carry direction, byte counts, format ids and outcomes only.
- Per-session counters (`in_bytes`, `out_bytes`, `in_transfers`,
  `out_transfers`, `dropped_oversize`, `suppressed_loop`) ride the existing
  per-session stats line and are pushed to the session window, so an operator
  can see the channel working — or see that it never became ready.
- `ready` state is surfaced too. A brokered (Rustion) session dials the
  bastion's RDP listener; whether `CLIPRDR` survives that hop depends on the
  bastion forwarding the channel, which is **not verified**. So enabling
  clipboard on a `rustion-required` profile logs a warning at connect time and
  the indicator stays "not ready" if the channel never negotiates, rather than
  looking enabled and doing nothing.

**Not in this phase:** a vault audit row per transfer. The session already
audits open/close with a correlation id; per-transfer audit wants batching and
a rate limit of its own, and is tracked as Phase 4 below rather than bolted on.

---

## 6. Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | `CF_UNICODETEXT` both directions, `rdp_clipboard` profile key, bridge + backend + pump wiring, loop detector, size cap, counters | **In Progress** |
| 2 | Images (`CF_DIB` / `CF_DIBV5`) | Todo |
| 3 | File copy (`CF_HDROP` + `FileContents`), gated by its own policy value — not folded into `bidirectional` | Todo |
| 4 | Per-transfer audit rows (batched, rate-limited) + a four-tier lockable policy matching the transport policy tiers, so an admin can pin clipboard off for a resource type / asset group / global | Todo |
| 5 | Clipboard through a Rustion-brokered session — requires bastion-side `CLIPRDR` forwarding, so it is cross-repo and blocked on Rustion | Blocked (cross-repo) |

---

## 7. Security notes

- Off by default. Upgrading changes no session's behaviour.
- Direction is explicit; `host-to-session` and `session-to-host` are separately
  expressible because they are different risks (ingress vs egress).
- Size-capped, never truncated.
- No file transfer in Phase 1 — a file channel is a different control question
  and gets its own switch.
- Content never logged, never persisted, never sent to the frontend. The
  bridge holds at most one clipboard payload at a time and drops it after the
  transfer.
- The clipboard is not a credential path: the resource's stored secret still
  goes straight into the protocol and never onto any clipboard.
