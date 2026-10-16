# Feature: SFTP Connect — dual-pane file transfer to server resources

**Status: Done (direct 2026-10-15, through a Rustion bastion 2026-10-16).**
Tracked as ROADMAP T140 (spec S112); Rustion-brokered SFTP (Phase 4) is T141. Next to Resource Connect (T36,
[resource-connect.md](resource-connect.md)),
which listed SFTP as a separate feature reusing the same `russh` session.

## Summary

A connection profile can now have protocol **`sftp`**. Connect on such a
profile opens a session window with two side-by-side file panes — the
operator's own machine on the left, the resource on the right — in the style
of a classic commander-type file manager. The operator browses both sides and
copies files and folders in either direction.

The SSH transport, the credential resolution and the host-key check are the
same as for an `ssh` profile; only the channel differs (`sftp` subsystem
instead of a PTY + shell). The credential never reaches the webview.

## Scope

| | v1 (this change) |
|---|---|
| Credential sources | `secret`, `ldap`, `pki`, `ssh-engine`, `default-account`, `fido2` — resolved by the same `resolve_ssh_credential` path as SSH, so the SSH login-class rule applies unchanged |
| `provider` source | Not launchable for `sftp` (fails closed in the editor and the host) |
| Transport | Direct, or **through a Rustion bastion** when the effective policy routes there (`rustion-required`, or `rustion-preferred` with bastions configured) — the same route choice as SSH (Phase 4, below). Never silently dialled direct under `rustion-required`. A lock violation is refused as for SSH. |
| Connect-time MFA | Same as SSH: `connect/authorize` redeems the ticket before any credential is resolved |
| Placement | Always its own window (`sftp-<token>`). An SFTP session is not a Session Workspace pane kind; an explicit workspace placement is refused. |
| Remote operations | list, home, create folder, rename, delete (file / empty folder) |
| Local operations | list, home, create folder |
| Transfers | upload and download of files and folders (recursive), progress events, cancel, explicit overwrite confirmation |

Out of scope for v1: resume of partial transfers,
remote `chmod`/`chown`, drag-and-drop from the OS file manager, an SFTP pane
attached to an existing SSH terminal session.

## Profile shape

Same fields as an `ssh` profile (`target_host`, `target_port` default 22,
`username`, `credential_source`, `host_key_pin`, `require_mfa`). `login_class`
is honoured exactly as for SSH. Unknown protocols remain fail-closed in every
parser (old clients hide and preserve an `sftp` profile untouched, per
[web-application-connect.md](web-application-connect.md) "Strict parsing /
old clients").

No server change: profiles are opaque JSON on the resource record and the
`connect/authorize` pre-flight does not inspect the protocol. Resource types
offer the protocol through `connect.protocols`; the built-in `server` type
offers `ssh`, `rdp` and `sftp`.

## Host surface (`gui/src-tauri`)

- `session/sftp.rs` — opens the russh connection (shared connect + auth with
  `session/ssh.rs`), requests the `sftp` subsystem, holds the `SftpSession`
  and the client handle in `SessionState::Sftp`, and implements the
  operations and the transfer engine.
- `commands/connect_sftp.rs` — `session_open_sftp` plus the per-window
  commands `sftp_list`, `sftp_home`, `sftp_mkdir`, `sftp_rename`,
  `sftp_remove`, `sftp_transfer`, `sftp_cancel_transfer`, `sftp_local_list`,
  `sftp_local_home`, `sftp_local_mkdir`.
- Every per-window command takes the session token and passes
  `require_session_window`: only the window holding a live SFTP session may
  call it, and the local-filesystem commands are therefore unusable without
  one.
- Window ACL: capability `session-window` covers `sftp-*`; the commands are in
  that window set only.

## Through a Rustion bastion (Phase 4)

`session_open_sftp` chooses the route the way `session_open_ssh` does:

1. `secret`, `ssh-engine` and `default-account` sources go to
   `rustion/v2/session/open` first. When the policy picks a bastion the
   server evaluates the profile's MFA gate, burns the connect ticket and
   seals the credential into the bastion envelope — nothing is resolved on
   the operator's machine. Otherwise it answers *direct* and step 2 runs.
2. Every other source (and those three when direct): connect-time MFA, then
   `resolve_ssh_credential` (login-class rule included), then
   `resolve_ssh_connect_route`, which hands a brokerable credential
   (password, unencrypted key, SSH certificate) to `rustion/session/open`.
   A passphrase-protected key or a FIDO2 security key cannot be brokered:
   refused under `rustion-required`, dialled direct under
   `rustion-preferred` — exactly as for SSH.

On a bastion route the dial is the bastion only (`dial_inputs`): user
`operator`, the one-shot ticket as the password, and the **bastion's**
host-key pin from its listener record (empty = TOFU with a warning, never the
target's pin, which names a different key). The client then asks for the
`sftp` subsystem; the bastion relays it byte for byte to the target, which it
dials with the sealed credential and checks against the target's pin.

- **Ticket protocol.** An ordinary `ssh` ticket on the SSH listener; Rustion
  has no SFTP ticket protocol. A used ticket cannot open a second channel.
- **Minimum bastion.** Rustion 0.17.0 (its M39, T450–T453). An older bastion
  acknowledges `sftp` without relaying it; the open then fails (the SFTP
  handshake does not complete within the connect timeout) with an error that
  names the required version, rather than hanging.
- **Lifecycle.** The bastion session's bundle (`protocol: "sftp"`) is kept
  under the local token like SSH and RDP; the SFTP window shows the Rustion
  chip (bastion, time left, renew, terminate), and the bundle is dropped with
  the session. Disconnect closes the bastion connection, which ends the
  bastion-side session.
- **Window ACL.** The `sftp-window` set gains `session_rustion_info`,
  `rustion_session_renew` and `rustion_session_kill` — the three an SSH
  window already has for the same chip.
- **Audit.** The host's `session.open` line for a bastion route has
  `transport=rustion`, the bastion name, the Rustion session id and the
  correlation id; login class, mint and cert serial are stamped server-side
  on the control plane's own row. Rustion audits the relay with
  `sftp_session_started` / `sftp_session_ended` (byte counts, no file names).
  The per-transfer `sftp.transfer` lines are written by the desktop app on
  both routes.

## Security considerations

- **Remote names are untrusted.** A directory listing from a hostile server
  can contain `..`, `/`, `\` or NUL in a name. Such entries are dropped from
  listings and refused as transfer sources or destinations, so a download can
  never write outside the destination folder the operator picked.
- **On Windows, a downloaded name must also be a valid Windows file name.**
  `Path::join` with a drive-qualified name (`D:x`) replaces the destination
  folder rather than extending it, `a:b` writes an NTFS alternate data stream
  and `CON` / `NUL` / `COM1` open devices. A remote name with `< > : " | ? *`,
  a control character, a trailing dot or space, or a reserved device stem is
  refused as a download source (top level or inside a folder, before anything
  is written) and as a local *New folder* name (`is_windows_file_name`). It
  still shows in the remote listing, where it is a valid name.
- **Recursion does not follow symlinked folders** on either side, so a link
  loop cannot make a transfer unbounded. A symlink to a file is transferred as
  the file's content.
- **No silent overwrite.** A transfer whose destination exists fails with
  `exists` unless the request says `overwrite: true`, which the UI sets only
  after the operator confirms.
- **Partial files are not left behind as if complete.** Downloads write to
  `<name>.bvpart` and rename on success; a failed or cancelled transfer
  removes the partial file on both sides.
- **Audit.** `session.open` (as for SSH) and one `sftp.transfer` line per
  top-level transfer: direction, paths, files, bytes, outcome. File contents
  are never logged.
- **Local filesystem access** is limited to the operator's own account
  through the desktop process — it is not a new privilege, but it is now
  reachable from a session window, which is why each local command needs a
  live SFTP session token held by the calling window.
- **Host key.** Pinned with `host_key_pin` exactly as SSH; unpinned is
  trust-on-first-use with a warning log line, unchanged.

## Phases

| Phase | Content | Status |
|---|---|---|
| 1 | `sftp` protocol in the profile model, editor, resource types and launch matrix | Done |
| 2 | Host session, operations, transfer engine, commands, ACL | Done |
| 3 | Dual-pane session window | Done |
| 4 | SFTP through a Rustion bastion | Done (T141) |

## Current State

Phases 1–4 done. Phases 1–3 (0.44.37; the Windows file-name rule in 0.44.39)
on macOS, Windows and Linux: the local pane takes Windows drive paths (`C:\…`,
the verbatim `\\?\` prefix stripped) and names are checked against the local
platform's rules. Phase 4 (Unreleased) routes a brokered resource through a
Rustion ≥ 0.17.0 bastion. Unit-tested (name sanitisation including the
Windows rule, path joining, protocol parsing, window ACL, the brokered dial
decision); not yet exercised by hand against a live SFTP server or a live
bastion in a desktop build, and the Windows build is not compiled on the
development hosts — per-platform manual checks.

## What Is Not Yet Implemented

- `provider` credential sources (direct or brokered).
- UNC paths (`\\server\share`) in the local pane: the backend lists them, but the
  pane's breadcrumb and parent navigation understand drive paths only.
- Resume, permissions editing, OS drag-and-drop.
