# Feature: RDP clipboard redirection (host ⇄ session)

**Status:** Implemented — Phases 1–4 done (text, images, file copy, per-transfer
audit and a four-tier lockable policy). Phase 5, clipboard through a
Rustion-brokered session, is postponed: it needs bastion-side `CLIPRDR`
forwarding, which is cross-repo (T104). Nothing here has been exercised
against a live Windows host yet — see §11.

Copy on one side, paste on the other. An operator running an in-app RDP
session (Resources → Connect, or the ⌘K palette) can `Ctrl+C` in the remote
Windows desktop and `Cmd/Ctrl+V` into a local editor, and the reverse — text,
images and, where the resource allows it, files.

This is the MS-RDPECLIP (`CLIPRDR`) static virtual channel, driven by
[`ironrdp-cliprdr`](../IronRDP/crates/ironrdp-cliprdr), bridged to the host OS
clipboard inside the Tauri host
(`gui/src-tauri/src/session/rdp_clipboard/`).

---

## 1. On by default, disallowable per resource

BastionVault is a privileged-access product and the clipboard is a
**bidirectional data channel into and out of a privileged session**:

- it is an egress path for whatever the operator can see on the target (the
  exact thing a session recording exists to make accountable), and
- an ingress path into a production host.

Phase 1 shipped it **off by default**, opt-in per profile. That was reversed
after operator feedback: a session where you cannot paste a command in or
carry an error message back out pushes people onto a direct RDP client that
the bastion never sees, which is the worse outcome. So text and images are
**on in both directions unless the resource or a policy tier disallows them**,
and the controls that made the opt-in defensible all stay: explicit
direction, size caps, no logging of content, per-session counters — and now a
per-transfer audit row and a policy ceiling an administrator can lock.

**File copy is the opposite posture**: off unless the resource opts in
(`rdp_clipboard_files`, §2). A file channel is a materially larger control
question than text, and it is never implied by `rdp_clipboard: bidirectional`.

This does not conflict with the existing "credentials never reach the
clipboard" property in [resource-connect.md](resource-connect.md) §Security:
that is about *our* handling of the resource's stored secret, which still never
goes near `navigator.clipboard` or the host clipboard. Clipboard redirection
moves *operator-initiated* content, and only when profile and policy allow it.

---

## 2. The switches

Two profile keys, parsed strictly — an unrecognised value is a connect-time
error, not a silent fall back to a default (AGENTS.md §7: no implicit
fallbacks on a path an operator configured deliberately). Both are parsed
*before* anything is dialled or an MFA ticket is burnt.

| Value | `rdp_clipboard` (text, images) | `rdp_clipboard_files` (file copy) |
|---|---|---|
| *absent* | **Default — `bidirectional`** (`PROFILE_DEFAULT_DIRECTION`) | **Default — `off`** (`PROFILE_DEFAULT_FILES_DIRECTION`) |
| `off`, `none`, `""` | The `CLIPRDR` channel is not attached at all. | No file capability is advertised. |
| `host-to-session`, `in` | Host → session only (paste into the target). | Files into the target only. |
| `session-to-host`, `out` | Session → host only (copy out of the target). | Files out of the target only. |
| `bidirectional`, `both`, `on` | Both directions. | Both directions. |

`off` deliberately means "not attached" rather than "attached but inert": a
capability we do not intend to honour should not be advertised.

File copy can only travel where the clipboard itself may: the effective file
direction is `rdp_clipboard_files ∩ rdp_clipboard`. Both are then
intersected with the policy ceiling (§6), which no profile value can widen.
The RDP profile editor shows *File copy* only while *Clipboard redirection*
is not `off`.

---

## 3. Data model and caps

| Format | Direction | Cap | Phase |
|---|---|---|---|
| `CF_UNICODETEXT` (13) | both | 1 MiB wire payload | 1 |
| `CF_DIB` (8) / `CF_DIBV5` (17) | both | 32 MiB wire payload, 16384 px per side, 48 MiB decoded | 2 |
| `FileGroupDescriptorW` + `FileContents` | both, own switch | 256 MiB per file, 1 GiB per list, 128 files | 3 |
| `CF_TEXT` / `CF_OEMTEXT` | — | — | not offered: every Windows target since NT converts from `CF_UNICODETEXT`, and a code-page format invites mojibake |
| `CF_HDROP` | — | — | not used on the wire: MS-RDPECLIP carries files as a `FileGroupDescriptorW` list plus `FileContents` streams; `CF_HDROP` is what each *side's* OS clipboard holds, handled by `arboard` on the host |

**Every cap drops, never truncates**: a payload, image or file list over its
cap is refused whole and counted — a half-pasted credential, a half image or
the part of a file list that fit is worse than a failed paste. The caps apply
to the wire payload, which is the attacker-influenced side.

Text wire conversion (MS-RDPECLIP 2.2.5.2):

- Outbound: host UTF-8 → UTF-16LE, `\n` → `\r\n`, NUL-terminated.
- Inbound: UTF-16LE → UTF-8, trailing NULs stripped, `\r\n` → `\n` on
  non-Windows hosts (a Windows host keeps CRLF, which is what its own
  applications expect).
- Lone surrogates are replaced, not rejected: a paste is not the place to fail
  a session, and `String::from_utf16_lossy` is the honest reading of a
  malformed UTF-16 payload.

When the remote offers several formats, the host takes, in order: a file list
(if file copy is on and the server negotiated it), text, then `CF_DIB`, then
`CF_DIBV5`. A host clipboard holding files is offered as files when file copy
allows it; otherwise text wins over an image.

---

## 4. Architecture

```
 host OS clipboard                                    remote desktop
        │                                                    ▲
        │ arboard (own thread, + file I/O)                   │
        ▼                                                    │
     Bridge ────ClipboardMessage───▶ pump select! ──▶ CliprdrClient ──▶ CLIPRDR SVC
   (poll 500 ms,  (unbounded mpsc)    (rdp.rs)      (initiate_copy / paste /
    read/write,                                      file copy / contents)
    staging dir)                                          │
        ▲                                                 │
        └────────────── BridgeBackend ◀───────────────────┘
                         (CliprdrBackend)
                              │ TransferEvent
                              ▼
                        audit task ──▶ host audit line + resources/v2/connect/clipboard/audit
```

- **The bridge thread** owns the single `arboard::Clipboard` handle and every
  file read and write. X11/Wayland clipboard calls can block for as long as
  the *owning application* takes to answer, a disk can be slow, and a blocked
  pump is a frozen session; platform clipboard handles also have thread
  affinity a `tokio` worker cannot promise.
- **Host-change detection is a poll** (500 ms; images every 2 s and only
  while the clipboard holds no text, because reading an image decodes it),
  because no cross-platform change notification exists.
- **`BridgeBackend`** implements `CliprdrBackend`. It never blocks: it turns
  a request into a `ClipboardMessage` for the pump or a command for the
  bridge, and it records what it asked the remote for, so an **unsolicited**
  format-data response is dropped rather than written to the host clipboard.
- **Initialisation always completes.** `CLIPRDR` reaches Ready only after
  the client sends a format list in answer to the server's Monitor Ready.
  The bridge sends an *empty* one whatever the direction — the pre-session
  host clipboard is never offered to the remote. (Phase 1 sent one only when
  the host held text and the direction allowed ingress, so a
  `session-to-host` session, or one opened with a non-text host clipboard,
  never initialised; fixed here.)
- **Loop breaking**: text uses `ironrdp_cliprdr::loop_detector` content
  hashing plus a last-seen cache; images use a dimension match within 10 s of
  our own write, because pasteboards re-encode images; a received file list
  is recorded as the last host file list so it is not offered straight back.
- **The pump's clipboard branch is gated on the channel still having
  senders** (`ClipboardInbox`): `UnboundedReceiver::recv()` resolves to
  `None` on every poll once the last sender is dropped, and an ungated branch
  in the `biased` `select!` starves `read_pdu` (black desktop, `0 pdus`).

---

## 5. Images (Phase 2)

`gui/src-tauri/src/session/rdp_clipboard/dib.rs`.

- **The remote's DIB is parsed by our own strict decoder**, never by an image
  codec: a closed set of header sizes (`BITMAPINFOHEADER`, V4, V5), 24/32 bpp,
  `BI_RGB` or `BI_BITFIELDS` with the standard 8-bit masks only, no colour
  table, `planes == 1`, positive width, non-zero height (not `i32::MIN`), at
  most 16384 px a side, every offset and length checked with overflow-safe
  arithmetic before a byte is read, and a declared V5 colour profile must lie
  inside the payload. Palette, 16 bpp, RLE and embedded JPEG/PNG are refused
  — a modern Windows clipboard synthesises a 24/32-bit `CF_DIB` for any
  bitmap. Each refusal is a typed `DibError`, counted as `malformed` (or
  `oversize`) and audited.
- The validated RGBA is handed to `arboard`, which only *encodes* it for the
  host pasteboard. Host → session, `arboard` decodes the operator's own local
  image and we encode a bottom-up 32-bit `CF_DIB` (`BI_RGB`, alpha in the
  reserved byte) or `CF_DIBV5` (`BI_BITFIELDS` with an alpha mask, sRGB) on
  request.
- **Dependency:** `arboard`'s `image-data` feature — the only `arboard` path
  to a host image. `image` 0.25 was already in the graph; the lockfile delta
  is `tiff`, `fax`, `weezl`, `quick-error`, all pure Rust. Justified in
  `gui/src-tauri/Cargo.toml`.

---

## 6. Policy ceiling (Phase 4)

The clipboard knobs ride **the same four tiers as the Rustion transport
policy** (`crates/bv-engine-rustion/src/policy.rs`) — global, resource type,
asset group, resource — on the same records, with the same lock:

| Tier knob | Values | Default |
|---|---|---|
| `clipboard` | `off` · `host-to-session` · `session-to-host` · `bidirectional` | unset (constrains nothing) |
| `clipboard_files` | same | unset |

- **Most-restrictive wins, by intersection** of the permitted directions —
  the rule transport and recording already follow. `host-to-session` ∩
  `session-to-host` is `off`. An unset knob constrains nothing.
- The connect path intersects the profile's values with the result
  (`rdp_clipboard::resolve_settings`) and logs every narrowing with the tier
  that caused it. **No profile value can widen past the ceiling**, so an
  administrator pins the clipboard (or file copy) off by setting `off` on the
  global, type or asset-group tier — locked, so the resource owner cannot
  argue with it.
- **`lock`** is the tier's existing flag and freezes only the knobs the tier
  sets. A per-resource write that would widen a locked global ceiling is
  refused `403` like a weakened transport. At connect time a clipboard
  conflict is reported as `clipboard_lock_conflict`, **not** as the transport
  `lock_violation` the GUI refuses a session on: the intersection already
  pins the value, and refusing the session would push the operator off the
  bastion.
- **Strict and migration-safe.** Values outside the four are refused `400`
  on write. A tier written before the knobs existed reads as unset (`serde`
  default); an unset knob is not serialised, so an untouched record keeps
  its old shape. A tier write that **omits** a clipboard key leaves the
  stored value alone (an older GUI or CLI rewriting a tier for its transport
  fields cannot erase a pin by omission); `""` clears it.
- **Fail closed.** The ceiling is read from `rustion/policy/effective` before
  dialling; a denied or failed resolve refuses the connect, exactly as for
  transport. A value the client does not recognise withholds the clipboard
  for the session. A vault that predates the knobs (no `clipboard` key in
  the response) constrains nothing — no tier can have set one — and is
  logged once.
- Editors: Settings → Rustion policy (global), the resource-type and
  asset-group policy cards, and the resource's Connection tab (per-resource).

---

## 7. File copy (Phase 3)

`gui/src-tauri/src/session/rdp_clipboard/files.rs`.

- **Own switch, default off** (§2), intersected with the clipboard direction
  and the policy ceiling. When it is off the client advertises no file
  capability at all; when it is on it advertises `STREAM_FILECLIP_ENABLED |
  FILECLIP_NO_FILE_PATHS | CAN_LOCK_CLIPDATA` (no huge-file support — the
  per-file cap is far below 4 GiB), and the temporary-directory PDU carries
  `.`, never a host path.
- **Accepted whole or refused whole.** Caps: 128 files, 256 MiB each, 1 GiB
  per list. Files only: a folder entry or a nested relative path refuses the
  list (folders are not carried in this phase), as does a remote descriptor
  without a declared size, a duplicate name (case-insensitive), or any name
  that fails sanitisation.
- **Names.** Host → session: only the basename is sent, never a path, and it
  must be a name a Windows target can create (no `<>:"/\|?*`, no control
  characters, no trailing dot or space, no device names, ≤ 259 UTF-16
  units). Session → host: on top of `ironrdp`'s own sanitisation, separators
  are stripped to the last component, then the same rules apply plus the
  Unicode look-alikes of `/` and `\`, ≤ 255 bytes. Traversal and absolute
  forms cannot survive either step.
- **Received files** are written with `create_new` (mode 0600; a planted file
  or symlink is never written through) into a private per-session staging
  directory, `<app cache>/rdp-clipboard/<session token>/` (mode 0700, a held
  `.lock` so a later session sweeps a dead one's leftovers), one request
  outstanding at a time, each response checked against the stream, the
  requested length and the declared size, 30 s per request before the
  transfer is abandoned. Only when every file is on disk is the host
  clipboard set to the list. **The staging directory is removed when the
  session ends** — paste before you disconnect.
- **Served files** are read from the snapshot that was advertised (or the
  snapshot taken when the server locked it), re-checked against the
  advertised size before every read: a file changed since it was offered is
  refused, never read under the old size. Ranges are capped at 1 MiB.
- **`ironrdp-cliprdr` logs remote file names** at `warn` while it sanitises
  them; the GUI's logger caps that target at `error`, after `RUST_LOG` is
  read, so they never reach a log (§9).

---

## 8. Audit (Phase 4)

`gui/src-tauri/src/session/rdp_clipboard/audit.rs` (host) and
`crates/bv-engine-resource/src/connect_clipboard.rs` (vault).

- **What is a transfer.** Something attempted across the channel: a paste
  the remote asked for (host → session) or content the remote offered that
  we fetched (session → host). Each becomes one event — direction, kind
  (`text`, `image`, `file`, one event per file), outcome (`ok`, `oversize`,
  `refused`, `malformed`, `error`) and a byte count. A copy made *inside* the
  remote desktop that is never fetched, and a host copy that is never
  requested, are not transfers: they are counted, not audited.
- **Batched and rate-limited**: a batch goes out after 10 s or 64 entries,
  at most 12 batches a minute; past that, transfers are folded into an
  `overflow` count and byte total, so a flood costs a bounded number of
  records and still accounts for every transfer. The session's last batch is
  marked `final` and exempt from the rate limit.
- **Two records per batch**: a host audit line (`target: "audit"`,
  `connect.rdp.clipboard`), and `POST resources/v2/connect/clipboard/audit`,
  which the request pipeline writes to every vault audit device. The body's
  metadata words are map *keys* and every value a *number* — the audit
  device HMACs strings but passes keys and numbers through, so the row stays
  readable, and there is no string slot a file name could ride in. The
  endpoint validates that shape strictly and is gated by the caller's
  `connect` grant on the resource; it is in every baseline policy.
- **Fail closed.** If the vault refuses a batch (after one retry), the
  session's clipboard is **withdrawn**: every further transfer is refused,
  and a `connect.rdp.clipboard.withdrawn` audit line says why. The one
  exception is a vault that predates the endpoint, detected from the policy
  resolver before the session opens (§6) — never guessed from a failed write
  — where the host line is the only record.

---

## 9. Observability, and what is never logged

- **Never** clipboard content or file names, in any log or audit record, on
  either side. Logs carry direction, byte counts, format ids, reasons and
  outcomes only.
- Per-session counters ride the per-session stats line: `ready`, transfers
  and bytes each way, images and files each way, oversize drops,
  wrong-direction refusals, malformed payloads, refused file lists, loops
  suppressed, errors, and whether the clipboard was withdrawn.
- `ready` is the check for a brokered (Rustion) session: it dials the
  bastion's RDP listener, and whether `CLIPRDR` survives that hop depends on
  the bastion forwarding the channel. Enabling clipboard on a brokered
  session logs a warning at connect time, and `ready` stays false if the
  channel never negotiates (Phase 5, T104).

---

## 10. Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | `CF_UNICODETEXT` both directions, `rdp_clipboard` profile key (bidirectional unless the resource disallows it — see §1), bridge + backend + pump wiring, loop detector, size cap, counters | **Done** |
| 2 | Images (`CF_DIB` / `CF_DIBV5`), both directions, strict DIB decoder, 32 MiB cap | **Done** |
| 3 | File copy (`FileGroupDescriptorW` + `FileContents`), own `rdp_clipboard_files` switch (default off, not folded into `bidirectional`), caps, name sanitisation, private staging | **Done** |
| 4 | Per-transfer audit (batched, rate-limited, metadata only, vault + host, fail closed) and the clipboard ceilings on the four lockable Rustion policy tiers | **Done** |
| 5 | Clipboard through a Rustion-brokered session — requires bastion-side `CLIPRDR` forwarding, so it is cross-repo | **Postponed** (T104) |

---

## 11. Security notes and residual risk

- On by default for text and images; **a resource can disallow it**
  (`rdp_clipboard: off`) or narrow it to one direction, and **an
  administrator can pin it off** on a locked policy tier. Absent means
  bidirectional; a present but unrecognised value is a connect-time error.
- File copy is off unless a resource opts in, and is never implied by
  `bidirectional`.
- Direction is explicit; ingress and egress are separately expressible
  because they are different risks.
- Size-capped, never truncated; file lists accepted whole or refused whole.
- Content and file names are never logged, never persisted beyond the
  per-session staging directory, and never sent to the frontend. The
  clipboard buffers the host side owns — cached text, host and decoded
  images, file chunks read or received — are zeroized on drop; the copies
  inside `ironrdp`'s PDU encoding and the OS pasteboard are not ours to
  zeroize.
- The clipboard is not a credential path: the resource's stored secret still
  goes straight into the protocol and never onto any clipboard.
- **Client-side enforcement.** For a direct session the direction switches,
  the policy ceiling and the audit are enforced and reported by the desktop
  host — the vault never sees the traffic. They bind the official client; a
  modified client holding the credential could ignore them, which is the
  same boundary every direct-path control has (resource-connect.md). The
  brokered path (Phase 5) is where the bastion can enforce and observe it
  independently.
- **Not yet validated against a live Windows host**: the image formats, the
  file-copy sequence (locks, chunking, Explorer's paste), and the
  initialisation fix are built to MS-RDPECLIP and the `ironrdp-cliprdr`
  state machine and unit-tested against them, but no session to a real
  Windows target has exercised them.
