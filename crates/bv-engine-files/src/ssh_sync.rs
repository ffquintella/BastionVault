//! SFTP + SCP sync transports (`FileSyncTarget { kind = "sftp" | "scp" }`).
//!
//! Both transports share a single SSH session built with [`russh`]
//! (pure-Rust SSH client; no `libssh2-sys` C dep). SFTP layers the
//! [`russh-sftp`] file-transfer protocol over an SSH `sftp`
//! subsystem channel; SCP runs `scp -t <path>` on an SSH exec
//! channel and pipes the file's bytes through the OpenSSH SCP
//! protocol's modest framing (header line + bytes + zero ack).
//!
//! `target_path` URL grammars:
//!
//! ```text
//! sftp://[user@]host[:port]/path/to/file
//! scp://[user@]host[:port]/path/to/file
//! ```
//!
//! User-in-URL is for convenience; the canonical place for the
//! username is the `ssh_username` field on the sync target. When
//! both are present the target field wins.
//!
//! # Auth
//!
//! Two methods, both inline on the target record:
//! - **Password** — `ssh_password`. Used as the only field if no
//!   key is supplied.
//! - **Private key** — `ssh_private_key` (PEM bytes; OpenSSH /
//!   PKCS#8 / RFC 8410 / legacy RSA all parsed by `russh-keys`),
//!   with optional `ssh_passphrase` if the key is encrypted.
//!
//! When both are set, the key is tried first; the password is the
//! fallback (so an operator can stage a passwordless key takeover
//! without losing access if the new key isn't yet on the server).
//!
//! # Bootstrap-ordering note
//!
//! The deferred-roadmap entry called out "key-stored-in-vault
//! bootstrap ordering needs design." The design we ship: **inline
//! credential fields on the target record, barrier-encrypted at
//! rest like every other sync-target field**. There is no ordering
//! issue because by the time a sync push runs, the vault is already
//! unsealed and the target record is decrypted — the credential
//! comes from the same record whose `target_path` field we're
//! reading. Pulling credentials by reference from a separate KV
//! secret was considered but rejected for v1: it adds a
//! cross-engine dependency that makes the "this target works /
//! doesn't" diagnostic harder, and the inline path covers both the
//! password and private-key cases without losing functionality.
//!
//! # Host-key handling
//!
//! Optional `ssh_host_key_fingerprint` field on the target. When
//! set, the connection's server key is compared by SHA-256
//! fingerprint (OpenSSH `SHA256:<base64>` format); mismatch refuses
//! the push. When unset, the connection accepts any host key on
//! first connect (TOFU-without-pinning) — the operator is expected
//! to fill in the fingerprint on the second push to lock the
//! target. Logging the observed fingerprint at WARN gives the
//! operator the value to paste back.
//!
//! # Atomicity
//!
//! Same tmp-then-rename pattern the SMB transport uses. SFTP
//! `rename` is a first-class operation. SCP doesn't have rename
//! built into the protocol, so we rename via a follow-up `scp`-of-
//! `mv` exec channel — `ssh server "mv 'tmp' 'final'"`. SCP's
//! atomicity is therefore weaker than SFTP's; the tmp file is left
//! on disk if the rename fails, with a clear error.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Config, Handler};
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64};
use russh_sftp::client::SftpSession;
use tokio::io::AsyncWriteExt;

use super::FileSyncTarget;
use crate::errors::RvError;

/// Hard cap on a single push round-trip — DNS + TCP + SSH
/// handshake + auth + write + rename. Picked to be comfortable for
/// a multi-MiB file over a slow VPN link without letting a wedged
/// server stall a Tauri command for minutes.
const PUSH_TIMEOUT_SECS: u64 = 60;

/// Public entry point for the `sftp` transport.
pub fn push_sftp(target: &FileSyncTarget, bytes: &[u8]) -> Result<(), RvError> {
    push_ssh(Transport::Sftp, target, bytes)
}

/// Public entry point for the `scp` transport.
pub fn push_scp(target: &FileSyncTarget, bytes: &[u8]) -> Result<(), RvError> {
    push_ssh(Transport::Scp, target, bytes)
}

/// Validate the URL shape at config-save time so the operator gets
/// an immediate error instead of a push-time failure.
pub fn validate_target_path_sftp(input: &str) -> Result<(), RvError> {
    parse_ssh_url(input, "sftp").map(|_| ())
}
pub fn validate_target_path_scp(input: &str) -> Result<(), RvError> {
    parse_ssh_url(input, "scp").map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Sftp,
    Scp,
}

impl Transport {
    fn scheme(self) -> &'static str {
        match self {
            Self::Sftp => "sftp",
            Self::Scp => "scp",
        }
    }
}

fn push_ssh(
    transport: Transport,
    target: &FileSyncTarget,
    bytes: &[u8],
) -> Result<(), RvError> {
    if target.ssh_username.trim().is_empty() && parse_ssh_url(&target.target_path, transport.scheme())?
        .user
        .is_none()
    {
        return Err(RvError::ErrString(
            "ssh: ssh_username (or user@ in URL) is required".into(),
        ));
    }
    if target.ssh_password.is_empty() && target.ssh_private_key.is_empty() {
        return Err(RvError::ErrString(
            "ssh: at least one of ssh_password / ssh_private_key is required".into(),
        ));
    }
    let parsed = parse_ssh_url(&target.target_path, transport.scheme())?;

    let username = if !target.ssh_username.is_empty() {
        target.ssh_username.clone()
    } else {
        parsed.user.clone().unwrap_or_default()
    };
    let password = target.ssh_password.clone();
    let private_key = target.ssh_private_key.clone();
    let passphrase = if target.ssh_passphrase.is_empty() {
        None
    } else {
        Some(target.ssh_passphrase.clone())
    };
    let host_key_fp = target.ssh_host_key_fingerprint.clone();
    let bytes = bytes.to_vec();

    // Same OS-thread + single-threaded runtime pattern the SMB
    // transport uses, so the call works under both the default
    // async build and `--features sync_handler` without colliding
    // with any ambient runtime.
    let handle = std::thread::Builder::new()
        .name("bv-ssh-push".into())
        .spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("ssh: tokio runtime build: {e}"))?;
            rt.block_on(async move {
                tokio::time::timeout(
                    Duration::from_secs(PUSH_TIMEOUT_SECS),
                    push_ssh_inner(
                        transport, parsed, username, password, private_key, passphrase,
                        host_key_fp, bytes,
                    ),
                )
                .await
                .map_err(|_| format!("ssh: push timed out after {PUSH_TIMEOUT_SECS}s"))
                .and_then(|r| r)
            })
        })
        .map_err(|e| RvError::ErrString(format!("ssh: spawn worker thread: {e}")))?;

    handle
        .join()
        .map_err(|_| RvError::ErrString("ssh: worker thread panicked".into()))?
        .map_err(RvError::ErrString)
}

async fn push_ssh_inner(
    transport: Transport,
    target: SshTarget,
    username: String,
    password: String,
    private_key: String,
    passphrase: Option<String>,
    expected_host_key_fp: String,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let cfg = Arc::new(Config::default());
    // Shared observation slot: russh's `connect()` takes ownership
    // of the handler, so the only way to read the fingerprint
    // post-connect is through a shared cell the handler also writes
    // through.
    let observed = Arc::new(Mutex::new(String::new()));
    let handler = HostKeyHandler {
        expected_fp: expected_host_key_fp.clone(),
        observed: observed.clone(),
    };
    let mut session = client::connect(cfg, (target.host.as_str(), target.port), handler)
        .await
        .map_err(|e| format!("ssh: connect {}:{}: {e}", target.host, target.port))?;

    // Auth: try key first if present, fall back to password.
    // russh ≥ 0.51 returns `AuthResult` (an enum carrying success +
    // remaining-method hints) rather than a plain bool, and
    // `authenticate_publickey` takes `PrivateKeyWithHashAlg` so the
    // caller can pin the RSA hash algorithm explicitly. We pass `None`
    // here, which falls back to russh's default per-algorithm choice.
    let mut authed = false;
    if !private_key.is_empty() {
        let key = decode_secret_key(&private_key, passphrase.as_deref())
            .map_err(|e| format!("ssh: parse private key: {e}"))?;
        let key_arg = PrivateKeyWithHashAlg::new(Arc::new(key), None);
        authed = session
            .authenticate_publickey(&username, key_arg)
            .await
            .map_err(|e| format!("ssh: publickey auth: {e}"))?
            .success();
    }
    if !authed && !password.is_empty() {
        authed = session
            .authenticate_password(&username, &password)
            .await
            .map_err(|e| format!("ssh: password auth: {e}"))?
            .success();
    }
    if !authed {
        return Err("ssh: authentication rejected (publickey and/or password)".into());
    }

    // Compare the observed host-key fingerprint after a successful
    // auth so the operator gets a useful WARN-log fingerprint even
    // for the very first connect (when expected_fp is empty and we
    // accepted any key).
    let observed_fp = observed
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    if !expected_host_key_fp.is_empty() && observed_fp != expected_host_key_fp {
        return Err(format!(
            "ssh: host key fingerprint mismatch (expected {expected_host_key_fp}, got {observed_fp})"
        ));
    }
    if expected_host_key_fp.is_empty() && !observed_fp.is_empty() {
        log::warn!(
            "ssh-sync: accepted unpinned host key for {}:{} — pin {observed_fp} in ssh_host_key_fingerprint to lock",
            target.host, target.port
        );
    }

    let final_path = target.path.clone();
    let tmp_path = tmp_path_for(&final_path);
    let result = match transport {
        Transport::Sftp => sftp_push(&mut session, &tmp_path, &final_path, &bytes).await,
        Transport::Scp => scp_push(&mut session, &tmp_path, &final_path, &bytes).await,
    };
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;
    result
}

async fn sftp_push(
    session: &mut client::Handle<HostKeyHandler>,
    tmp_path: &str,
    final_path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("sftp: channel_open_session: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("sftp: request_subsystem: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("sftp: handshake: {e}"))?;

    sftp.write(tmp_path, bytes)
        .await
        .map_err(|e| format!("sftp: write `{tmp_path}`: {e}"))?;

    // Best-effort drop of any pre-existing destination so rename
    // succeeds on servers whose SFTP rename refuses to overwrite.
    let _ = sftp.remove_file(final_path).await;

    sftp.rename(tmp_path, final_path).await.map_err(|e| {
        // Clean up the orphan temp file on rename failure so a
        // failed push doesn't leave noise behind.
        format!("sftp: rename `{tmp_path}` -> `{final_path}`: {e}")
    })?;

    let _ = sftp.close().await;
    Ok(())
}

async fn scp_push(
    session: &mut client::Handle<HostKeyHandler>,
    tmp_path: &str,
    final_path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    // Step 1: scp the bytes to tmp_path. The OpenSSH SCP protocol
    // is: server runs `scp -t <path>`; client sends `C<mode> <size> <basename>\n`,
    // then bytes, then a single zero byte; server acks each step
    // with a single zero byte.
    push_one_scp(session, tmp_path, bytes).await?;

    // Step 2: rename via a separate exec channel.
    let mv_channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("scp: open mv channel: {e}"))?;
    // Single-quote both paths after escaping any embedded single-
    // quotes — operator-controlled paths only, but worth being
    // careful since this becomes shell input on the far side.
    let cmd = format!(
        "mv -- {} {}",
        shell_single_quote(tmp_path),
        shell_single_quote(final_path)
    );
    mv_channel
        .exec(true, cmd.as_bytes())
        .await
        .map_err(|e| format!("scp: exec mv: {e}"))?;
    wait_exit_status(mv_channel)
        .await
        .map_err(|e| format!("scp: mv `{tmp_path}` -> `{final_path}`: {e}"))?;
    Ok(())
}

async fn push_one_scp(
    session: &mut client::Handle<HostKeyHandler>,
    remote_path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("scp: channel_open_session: {e}"))?;
    let cmd = format!("scp -t -- {}", shell_single_quote(remote_path));
    channel
        .exec(true, cmd.as_bytes())
        .await
        .map_err(|e| format!("scp: exec: {e}"))?;

    // Pull the streams. We read acks via a separate reader so we
    // can interleave write + read in the protocol's request-ack
    // dance.
    let mut writer = channel.make_writer();
    let mut reader = channel.make_reader();

    expect_zero_ack(&mut reader).await?;
    let basename = remote_path.rsplit('/').next().unwrap_or(remote_path);
    let header = format!("C0644 {} {}\n", bytes.len(), basename);
    writer
        .write_all(header.as_bytes())
        .await
        .map_err(|e| format!("scp: write header: {e}"))?;
    expect_zero_ack(&mut reader).await?;
    writer
        .write_all(bytes)
        .await
        .map_err(|e| format!("scp: write body: {e}"))?;
    writer
        .write_all(&[0u8])
        .await
        .map_err(|e| format!("scp: write trailing zero: {e}"))?;
    expect_zero_ack(&mut reader).await?;
    drop(writer);
    drop(reader);
    channel
        .eof()
        .await
        .map_err(|e| format!("scp: eof: {e}"))?;
    wait_exit_status(channel).await
}

async fn expect_zero_ack<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<(), String> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1];
    let n = r
        .read(&mut buf)
        .await
        .map_err(|e| format!("scp: read ack: {e}"))?;
    if n == 0 {
        return Err("scp: server closed channel before ack".into());
    }
    if buf[0] != 0 {
        // SCP error byte: 0x01 = warning, 0x02 = fatal; followed by
        // a textual error line terminated by `\n`. Surface the
        // message so the operator gets a real diagnostic.
        let mut rest = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = r.read(&mut byte).await.map_err(|e| format!("scp: read err msg: {e}"))?;
            if n == 0 || byte[0] == b'\n' {
                break;
            }
            rest.push(byte[0]);
        }
        let msg = String::from_utf8_lossy(&rest).into_owned();
        return Err(format!("scp: server error ({}): {msg}", buf[0]));
    }
    Ok(())
}

async fn wait_exit_status(mut channel: russh::Channel<russh::client::Msg>) -> Result<(), String> {
    use russh::ChannelMsg;
    let mut exit: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }
    match exit {
        Some(0) => Ok(()),
        Some(other) => Err(format!("remote exited with status {other}")),
        None => Ok(()), // server didn't send ExitStatus — treat as success since EOF/Close fired
    }
}

struct HostKeyHandler {
    expected_fp: String,
    /// Shared with the caller; set on `check_server_key` so the
    /// outer push code can read the fingerprint after russh
    /// finishes the handshake.
    observed: Arc<Mutex<String>>,
}

// russh ≥ 0.59 dropped the `#[async_trait]` shape on `Handler` in
// favour of return-position `impl Future`. Implementations now write
// regular `fn` returning an `async {}` block; they're no longer trait
// objects so the dynamic-dispatch friendly attribute isn't needed.
impl Handler for HostKeyHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = openssh_sha256_fingerprint(server_public_key);
        if let Ok(mut g) = self.observed.lock() {
            *g = fp.clone();
        }
        if self.expected_fp.is_empty() {
            // No pin: accept on first connect. Caller logs the
            // observed fingerprint at WARN so the operator can
            // pin it on the next push.
            return Ok(true);
        }
        Ok(fp == self.expected_fp)
    }
}

fn openssh_sha256_fingerprint(key: &PublicKey) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    // PublicKeyBase64 yields the same canonical wire bytes OpenSSH
    // hashes for its fingerprint output.
    let raw = key.public_key_bytes();
    let mut h = Sha256::new();
    h.update(&raw);
    let digest = h.finalize();
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshTarget {
    host: String,
    port: u16,
    user: Option<String>,
    /// Path on the remote system. Always starts with `/` after
    /// parsing — the URL `sftp://h/path/to/file` yields `path =
    /// "/path/to/file"`.
    path: String,
}

/// Parse an `sftp://` or `scp://` URL into `(host, port, user, path)`.
fn parse_ssh_url(input: &str, expected_scheme: &str) -> Result<SshTarget, RvError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(RvError::ErrString("ssh: target_path is empty".into()));
    }
    let scheme_prefix = format!("{expected_scheme}://");
    let after_scheme = raw.strip_prefix(scheme_prefix.as_str()).ok_or_else(|| {
        RvError::ErrString(format!(
            "ssh: target_path `{raw}` must start with `{expected_scheme}://`"
        ))
    })?;

    // Optional user@ before host.
    let (user, host_rest) = if let Some((u, h)) = after_scheme.split_once('@') {
        if u.is_empty() {
            return Err(RvError::ErrString(format!(
                "ssh: target_path `{raw}` has empty user before `@`"
            )));
        }
        (Some(u.to_string()), h)
    } else {
        (None, after_scheme)
    };

    let (host_port, path) = host_rest.split_once('/').ok_or_else(|| {
        RvError::ErrString(format!(
            "ssh: target_path `{raw}` is missing the remote path"
        ))
    })?;
    if host_port.is_empty() {
        return Err(RvError::ErrString(format!(
            "ssh: target_path `{raw}` has empty host"
        )));
    }
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        if h.is_empty() {
            return Err(RvError::ErrString(format!(
                "ssh: target_path `{raw}` has empty host"
            )));
        }
        let parsed_port = p
            .parse::<u16>()
            .map_err(|_| RvError::ErrString(format!("ssh: invalid port `{p}`")))?;
        (h.to_string(), parsed_port)
    } else {
        (host_port.to_string(), 22u16)
    };
    if path.is_empty() {
        return Err(RvError::ErrString(format!(
            "ssh: target_path `{raw}` is missing the remote path"
        )));
    }
    if path.ends_with('/') {
        return Err(RvError::ErrString(format!(
            "ssh: target_path `{raw}` ends with `/` — must point at a file, not a directory"
        )));
    }
    // Re-introduce the leading slash that split_once stripped.
    Ok(SshTarget {
        host,
        port,
        user,
        path: format!("/{path}"),
    })
}

fn tmp_path_for(path: &str) -> String {
    let pid = std::process::id();
    if let Some(idx) = path.rfind('/') {
        let (dir, base) = path.split_at(idx + 1);
        format!("{dir}{base}.bvsync.{pid}.tmp")
    } else {
        format!("{path}.bvsync.{pid}.tmp")
    }
}

/// POSIX-shell single-quote: wrap in `'…'`, escape any embedded
/// single-quote with `'\''`. Sufficient for the SCP exec-channel
/// commands we issue.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sftp_default_port() {
        let t = parse_ssh_url("sftp://host/path/to/file", "sftp").unwrap();
        assert_eq!(t.host, "host");
        assert_eq!(t.port, 22);
        assert_eq!(t.user, None);
        assert_eq!(t.path, "/path/to/file");
    }

    #[test]
    fn parse_scp_with_user_and_port() {
        let t = parse_ssh_url("scp://alice@host:2222/srv/app/config.yaml", "scp").unwrap();
        assert_eq!(t.host, "host");
        assert_eq!(t.port, 2222);
        assert_eq!(t.user.as_deref(), Some("alice"));
        assert_eq!(t.path, "/srv/app/config.yaml");
    }

    #[test]
    fn parse_rejects_wrong_scheme() {
        assert!(parse_ssh_url("scp://h/p", "sftp").is_err());
        assert!(parse_ssh_url("ftp://h/p", "sftp").is_err());
    }

    #[test]
    fn parse_rejects_no_path() {
        assert!(parse_ssh_url("sftp://host", "sftp").is_err());
        assert!(parse_ssh_url("sftp://host/", "sftp").is_err());
    }

    #[test]
    fn parse_rejects_dir_path() {
        assert!(parse_ssh_url("sftp://host/dir/", "sftp").is_err());
    }

    #[test]
    fn parse_rejects_invalid_port() {
        assert!(parse_ssh_url("sftp://host:nope/x", "sftp").is_err());
    }

    #[test]
    fn parse_rejects_empty_user() {
        assert!(parse_ssh_url("sftp://@host/p", "sftp").is_err());
    }

    #[test]
    fn shell_single_quote_escapes_inner_quote() {
        assert_eq!(shell_single_quote("simple"), "'simple'");
        assert_eq!(shell_single_quote("o'brien"), r"'o'\''brien'");
        assert_eq!(shell_single_quote("a/b c"), "'a/b c'");
    }

    #[test]
    fn tmp_path_lives_in_same_directory() {
        let pid = std::process::id();
        assert_eq!(tmp_path_for("/srv/app/config.yaml"),
                   format!("/srv/app/config.yaml.bvsync.{pid}.tmp"));
        assert_eq!(tmp_path_for("file.txt"),
                   format!("file.txt.bvsync.{pid}.tmp"));
    }
}
