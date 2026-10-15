# Feature: SFTP Connect — dual-pane file transfer to server resources

**Status: Done for direct connections (2026-10-15).** Tracked as ROADMAP T140
(spec S112); Rustion-brokered SFTP (Phase 4) is T141. Next to Resource Connect (T36,
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
| Transport | **Direct only.** When the effective Rustion policy would route the session through a bastion (`rustion-required`, or `rustion-preferred` with bastions configured) the open is refused — it is never silently dialled direct. A lock violation is refused as for SSH. |
| Connect-time MFA | Same as SSH: `connect/authorize` redeems the ticket before any credential is resolved |
| Placement | Always its own window (`sftp-<token>`). An SFTP session is not a Session Workspace pane kind; an explicit workspace placement is refused. |
| Remote operations | list, home, create folder, rename, delete (file / empty folder) |
| Local operations | list, home, create folder |
| Transfers | upload and download of files and folders (recursive), progress events, cancel, explicit overwrite confirmation |

Out of scope for v1: SFTP through a Rustion bastion (needs the bastion to
accept the `sftp` subsystem on its SSH listener), resume of partial transfers,
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
| 4 | SFTP through a Rustion bastion | Not started (T141) |

## Current State

Phases 1–3 done (0.44.37; the Windows file-name rule is Unreleased) on macOS,
Windows and Linux: the local pane takes Windows drive paths (`C:\…`, the
verbatim `\\?\` prefix stripped) and names are checked against the local
platform's rules. Unit-tested (name sanitisation including the Windows rule,
path joining, protocol parsing, window ACL); not yet exercised by hand against
a live SFTP server in a desktop build, and the Windows build is not compiled
on the development hosts — per-platform manual checks.

## What Is Not Yet Implemented

- Rustion-brokered SFTP (Phase 4, T141).
- UNC paths (`\\server\share`) in the local pane: the backend lists them, but the
  pane's breadcrumb and parent navigation understand drive paths only.
- Resume, permissions editing, OS drag-and-drop.
