//! SMB sync transport (`FileSyncTarget { kind = "smb" }`).
//!
//! Pushes the file's bytes to a Windows / Samba share via SMB2/3 with
//! NTLM authentication. Driven by [`smolder-smb-core`] — pure-Rust
//! SMB stack, no `libsmbclient` / `libsmb2` C dependency, no
//! Windows-only restriction.
//!
//! `target_path` is parsed as a UNC-style URL:
//!
//! ```text
//! smb://server[:port]/share/path/to/file
//! ```
//!
//! The share + remote path are separated at the first `/` of the URL
//! path component; everything after the share is the destination path
//! inside that share. Backslashes in the path are normalised to `/`
//! before the parse so a Windows-style `\\server\share\path` line
//! pasted from a Server Manager is also accepted.
//!
//! **Atomicity**: SMB has no rename-replace primitive that's
//! universally portable. We approximate the local-fs pattern by
//! writing to `<basename>.bvsync.<pid>.tmp` in the same directory,
//! then renaming to the final basename on success. A reader holding
//! the destination file open during the swap will see the old
//! content until they reopen — same semantics as POSIX rename.
//!
//! **Security**: NTLM credentials are pulled from the sync target's
//! barrier-encrypted record (`smb_username` / `smb_password` /
//! optional `smb_domain`). They never leave the host process. The
//! read path of the sync-target API redacts the password.

use std::time::Duration;

use smolder_core::auth::NtlmCredentials;
use smolder_core::facade::Client;

use super::FileSyncTarget;
use crate::errors::RvError;

/// Push a single file blob to an SMB share. Blocking-from-the-host's
/// perspective; runs the smolder client on a fresh single-threaded
/// tokio runtime spawned on its own OS thread (same pattern the
/// PKI / ACME DNS-01 validator uses) so the call site doesn't have
/// to assume an ambient runtime — works under both the default async
/// build and `--features sync_handler`.
pub fn push_smb(target: &FileSyncTarget, bytes: &[u8]) -> Result<(), RvError> {
    if target.smb_username.trim().is_empty() {
        return Err(RvError::ErrString(
            "smb: smb_username is required".into(),
        ));
    }
    if target.smb_password.is_empty() {
        return Err(RvError::ErrString(
            "smb: smb_password is required".into(),
        ));
    }
    let parsed = parse_smb_url(&target.target_path)?;

    let username = target.smb_username.clone();
    let password = target.smb_password.clone();
    let domain = target.smb_domain.clone();
    let bytes = bytes.to_vec();

    // Run the SMB client on its own thread + runtime. Cap the whole
    // push at 30 s — the host's per-request timeout posture; an
    // unresponsive Samba server shouldn't lock the calling Tauri
    // command.
    let handle = std::thread::Builder::new()
        .name("bv-smb-push".into())
        .spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("smb: tokio runtime build: {e}"))?;
            rt.block_on(async move {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    push_smb_inner(parsed, username, password, domain, bytes),
                )
                .await
                .map_err(|_| "smb: push timed out after 30s".to_string())
                .and_then(|r| r)
            })
        })
        .map_err(|e| RvError::ErrString(format!("smb: spawn worker thread: {e}")))?;

    handle
        .join()
        .map_err(|_| RvError::ErrString("smb: worker thread panicked".into()))?
        .map_err(RvError::ErrString)
}

async fn push_smb_inner(
    target: SmbTarget,
    username: String,
    password: String,
    domain: String,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let mut creds = NtlmCredentials::new(username, password);
    if !domain.is_empty() {
        creds = creds.with_domain(domain);
    }

    let client = Client::builder(target.host)
        .with_port(target.port)
        .with_ntlm_credentials(creds)
        .build()
        .map_err(|e| format!("smb: build client: {e}"))?;

    let mut share = client
        .connect_share(&target.share)
        .await
        .map_err(|e| format!("smb: connect_share `{}`: {e}", target.share))?;

    // Atomic-ish write: put to <basename>.bvsync.<pid>.tmp, rename to
    // basename on success. SMB rename across the same directory is
    // atomic from the server's filesystem perspective — same
    // guarantee POSIX rename gives.
    let final_path = target.path.clone();
    let tmp_path = tmp_path_for(&final_path);

    share
        .put(&tmp_path, &bytes)
        .await
        .map_err(|e| format!("smb: put `{tmp_path}`: {e}"))?;

    // Best-effort: drop any pre-existing destination so rename
    // succeeds on servers whose SMB rename refuses to overwrite.
    // Ignore the error — a missing-file delete is the common case.
    let _ = share.remove(&final_path).await;

    match share.rename(&tmp_path, &final_path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // On failure, try to clean up the orphan temp file so a
            // failed push doesn't leave noise on the share. Best-
            // effort; the underlying error is what we surface.
            let _ = share.remove(&tmp_path).await;
            Err(format!("smb: rename `{tmp_path}` -> `{final_path}`: {e}"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmbTarget {
    host: String,
    port: u16,
    share: String,
    /// Path inside the share, with `/` separators (smolder accepts
    /// both `/` and `\`; we normalise to `/` for consistency).
    path: String,
}

/// Parse an `smb://` URL into `(host, port, share, path)`. Accepts:
/// - `smb://server/share/path/to/file`
/// - `smb://server:1445/share/path/to/file`
/// - `\\server\share\path\to\file` (Windows UNC; backslashes
///   normalised to `/` before parse, no scheme required).
///
/// Default port is 445.
fn parse_smb_url(input: &str) -> Result<SmbTarget, RvError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(RvError::ErrString("smb: target_path is empty".into()));
    }
    // Normalise Windows UNC backslashes for both the scheme- and
    // bare-UNC paths. We do this first so the rest of the parse can
    // assume forward slashes.
    let normalised = raw.replace('\\', "/");

    let after_scheme = if let Some(rest) = normalised.strip_prefix("smb://") {
        rest
    } else if let Some(rest) = normalised.strip_prefix("//") {
        // Bare UNC `\\server\share\...` after backslash → forward
        // normalisation. Tolerated for paste-from-Server-Manager.
        rest
    } else {
        return Err(RvError::ErrString(format!(
            "smb: target_path `{raw}` must start with `smb://` or `\\\\` (UNC)"
        )));
    };

    // Split off the host[:port] from the rest (share + path).
    let (host_port, share_and_path) = after_scheme.split_once('/').ok_or_else(|| {
        RvError::ErrString(format!(
            "smb: target_path `{raw}` is missing the share component"
        ))
    })?;
    if host_port.is_empty() {
        return Err(RvError::ErrString(format!(
            "smb: target_path `{raw}` has empty host"
        )));
    }
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        if h.is_empty() {
            return Err(RvError::ErrString(format!(
                "smb: target_path `{raw}` has empty host"
            )));
        }
        let parsed_port = p
            .parse::<u16>()
            .map_err(|_| RvError::ErrString(format!("smb: invalid port `{p}`")))?;
        (h.to_string(), parsed_port)
    } else {
        (host_port.to_string(), 445u16)
    };

    // Share + path inside share.
    let (share, path) = match share_and_path.split_once('/') {
        Some((s, p)) => (s.to_string(), p.to_string()),
        None => (share_and_path.to_string(), String::new()),
    };
    if share.is_empty() {
        return Err(RvError::ErrString(format!(
            "smb: target_path `{raw}` has empty share name"
        )));
    }
    if path.is_empty() {
        return Err(RvError::ErrString(format!(
            "smb: target_path `{raw}` is missing the destination filename"
        )));
    }
    if path.ends_with('/') {
        return Err(RvError::ErrString(format!(
            "smb: target_path `{raw}` ends with `/` — must point at a file, not a directory"
        )));
    }
    Ok(SmbTarget {
        host,
        port,
        share,
        path,
    })
}

/// Public-facing wrapper used by the sync-write handler to validate
/// the URL shape at config-save time (so the operator gets an
/// immediate error instead of a push-time failure).
pub fn validate_target_path(input: &str) -> Result<(), RvError> {
    parse_smb_url(input).map(|_| ())
}

fn tmp_path_for(path: &str) -> String {
    // Place the temp file alongside the destination so the rename is
    // a same-directory operation — required for SMB to keep the
    // operation atomic on the server side.
    let pid = std::process::id();
    if let Some(idx) = path.rfind('/') {
        let (dir, base) = path.split_at(idx + 1);
        format!("{dir}{base}.bvsync.{pid}.tmp")
    } else {
        format!("{path}.bvsync.{pid}.tmp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_default_port() {
        let t = parse_smb_url("smb://server/share/file.txt").unwrap();
        assert_eq!(t.host, "server");
        assert_eq!(t.port, 445);
        assert_eq!(t.share, "share");
        assert_eq!(t.path, "file.txt");
    }

    #[test]
    fn parse_with_explicit_port() {
        let t = parse_smb_url("smb://server:1445/share/dir/file.txt").unwrap();
        assert_eq!(t.host, "server");
        assert_eq!(t.port, 1445);
        assert_eq!(t.share, "share");
        assert_eq!(t.path, "dir/file.txt");
    }

    #[test]
    fn parse_unc_backslash() {
        let t = parse_smb_url(r"\\server\share\dir\file.txt").unwrap();
        assert_eq!(t.host, "server");
        assert_eq!(t.port, 445);
        assert_eq!(t.share, "share");
        assert_eq!(t.path, "dir/file.txt");
    }

    #[test]
    fn parse_rejects_no_scheme() {
        assert!(parse_smb_url("server/share/file").is_err());
    }

    #[test]
    fn parse_rejects_no_share() {
        assert!(parse_smb_url("smb://server").is_err());
    }

    #[test]
    fn parse_rejects_no_path() {
        assert!(parse_smb_url("smb://server/share").is_err());
    }

    #[test]
    fn parse_rejects_dir_path() {
        assert!(parse_smb_url("smb://server/share/dir/").is_err());
    }

    #[test]
    fn parse_rejects_invalid_port() {
        assert!(parse_smb_url("smb://server:notaport/share/x").is_err());
    }

    #[test]
    fn tmp_path_lives_in_same_directory() {
        assert_eq!(tmp_path_for("dir/sub/file.txt"),
                   format!("dir/sub/file.txt.bvsync.{}.tmp", std::process::id()));
        assert_eq!(tmp_path_for("file.txt"),
                   format!("file.txt.bvsync.{}.tmp", std::process::id()));
    }
}
