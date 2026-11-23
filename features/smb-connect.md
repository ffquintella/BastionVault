# Feature: SMB Connect — the dual-pane file window over an SMB share

**Status: Done (direct, Unreleased).** Tracked as ROADMAP T552 (spec S122).
The window, the transfer engine and their rules are those of
[SFTP Connect](sftp-connect.md) (T140, S112); this spec records only what
differs.

## Summary

A connection profile can now have protocol **`smb`**. Connect opens the same
two-pane window as an `sftp` profile — this computer on the left, an SMB2/3
share on the right — in its own `smb-<token>` window. Browsing, folder
creation, rename, delete (file or empty folder), and recursive upload and
download with progress, cancel and overwrite confirmation behave exactly as
for SFTP. The password never reaches the webview.

## Scope

| | This change |
|---|---|
| Profile fields | `target_host`, `target_port` (default **445**), **`share`** (required: the share name alone, 1–80 characters, no `\ / : * ? " < > |`), `domain` (optional), `username`, `credential_source`, `require_mfa` |
| Credential sources | `secret` (`username` + `password`), `ldap` (operator, static role, library check-out), `default-account` (the connecting operator's Windows account, stored or prompted password) — resolved by the RDP password resolver. `pki`, `ssh-engine`, `fido2`, `provider` and `none` fail closed in the editor and the host. |
| NTLM domain | A domain in the login itself (`CORP\user`, `user@corp.example`, or the LDAP source's) wins; the profile's `domain` applies to a bare user. |
| Transport | Direct only. A `rustion` profile, a policy lock violation, or a `rustion-required` effective transport is refused (Rustion has no SMB relay) — never silently dialled direct. `rustion-preferred` dials direct with a warning log line. |
| Login class | A `brokered` resource takes only logins the SSH engine mints per connect, which an SMB password never is: SMB is refused there (`brokered_requires_ssh_engine`). |
| Connect-time MFA | As for SSH/RDP: `connect/authorize` redeems the ticket before any credential is resolved. |
| Placement | Always its own window; never a Session Workspace pane, never saved in a layout. |
| Vault audit | `resources/v2/connect/session/open` accepts `protocol: "smb"` (the vault-side row is written before the dial and fails the connect closed). A vault without this change answers 400 and the SMB connect fails. |

## Host surface (`gui/src-tauri`)

- `session/file_transfer.rs` — the engine both protocols share: the
  `RemoteFs` trait (list, mkdir, rename, remove, and the transfer
  primitives), the local pane, the planner (`MAX_PLANNED_ENTRIES`,
  `MAX_DEPTH`) and the copy loop (`.bvpart`, cancel, progress). Moved out of
  `session/sftp.rs`, which now implements `RemoteFs` for `SftpSession`.
- `session/smb.rs` — `smolder-smb-core` 0.3 (pure Rust) for NTLM and the
  tree connection; the session drives typed CREATE / READ / WRITE /
  QUERY_DIRECTORY / SET_INFO requests itself so transfers stream in 64 KiB
  pieces. Directory records are parsed here (bounds-checked), keeping every
  attribute bit.
- `commands/connect_smb.rs` — `session_open_smb`.
- The window calls the **same** `sftp_*` commands as an SFTP window; each
  dispatches on the session's kind. Window ACL: capability `smb-window`
  (`smb-*`) grants the `sftp-window` set; `session_open_smb` is in the
  Session Workspace set (its palette opens SMB into its own window).

## Paths

SMB paths are POSIX-style inside the app: `/` is the share root, `\` is read
as `/`, empty components are dropped. Every component must pass the
SFTP name rule and the Windows file-name rule (`a:b` would address an NTFS
stream, `CON` a device); `.` and `..` refuse the whole path. Uploads,
new folders and renames use the same rule, so an upload named `a:b` is
refused at planning, before anything is written.

## Security considerations

- **No host key.** SMB has none to pin. The connection requests SMB 2.1 /
  3.0.2 / 3.1.1 with **signing required**; a session the server admits as
  guest or anonymous (which would prove nothing about the password and
  cannot be signed), or one neither signed nor encrypted, is refused at
  open. An attacker in the path can still read an unencrypted SMB 2.x
  session; SMB 3 encryption is used when the share or server requires it.
- **Credential handling.** The password is resolved in the host, held in a
  `Zeroizing` buffer and handed to the library's `NtlmCredentials`, whose own
  copy is a plain `String` (not zeroized) dropped right after the
  session setup. No message or log line carries it.
- **Reparse points are not followed.** A directory entry with the reparse
  attribute (symlink, junction, mount point) is listed as a link that is not
  navigable and is skipped by a transfer. A Samba server that follows a
  Unix symlink server-side presents it as an ordinary entry the client
  cannot tell apart; `MAX_DEPTH` and `MAX_PLANNED_ENTRIES` bound such a loop.
- **Objects the library cannot decode fail closed.** `smolder-smb-core` 0.3
  refuses a CREATE response whose attributes include bits it does not model
  (reparse, compressed, sparse, offline, encrypted, not-content-indexed …);
  such a file or folder cannot be opened, and the error says so.
- **Connection loss.** A request is bounded to 60 s; a timeout or transport
  error drops the connection (never reused out of step), and the window is
  told. An idle session sends ECHO every 30 s.
- **Audit.** `session.open` (`protocol=smb`, `share=`, `signing=required`,
  login class) and the per-operation `smb.mkdir` / `smb.rename` /
  `smb.remove` / `smb.transfer` lines, as for SFTP.

## Resource types

The built-in `server` type, whose `connect.protocols` is unset, now offers
SMB with SSH, SFTP and RDP. A type with its own `connect.protocols` list
offers SMB only when the list names `smb` (Settings → Resource Types);
older clients drop the value they do not know.

## Phases

| Phase | Content | Status |
|---|---|---|
| 1 | `smb` protocol in the profile model, editor, resource types, launch | Done |
| 2 | Shared transfer engine (`RemoteFs`), SMB session, `session_open_smb`, ACL | Done |
| 3 | The dual-pane window mounted at `/session/smb` | Done |

## Current State

Phases 1–3 done (Unreleased). Unit-tested: profile parsing and validation,
path normalisation and refusal, the directory-record parser (bounds,
reparse bit, bad UTF-16), the session-security refusal, the source and
transport refusals, the window ACL, and the planner rules shared with SFTP;
frontend tests cover the profile model, the launch dispatch, the editor and
the session bundle. **Not yet exercised against a live SMB server** (Samba
or Windows) in a desktop build.

## What Is Not Yet Implemented

- Kerberos authentication (the library supports it behind a feature this
  build does not enable); `pki` and `provider` sources.
- A Rustion-brokered SMB route (Rustion has no SMB relay).
- Objects whose attributes the library cannot decode (see above), DFS
  referrals, and share enumeration (the share is named on the profile).
- Pipelined (multi-credit) reads and writes: throughput is one 64 KiB
  request per round trip.
