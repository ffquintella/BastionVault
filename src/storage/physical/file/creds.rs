//! `credentials_ref` resolver — the URI grammar all cloud file
//! targets use to locate credentials without ever inlining them in
//! the server config.
//!
//! Grammar (per `features/cloud-storage-backend.md`):
//!
//!   env:<VARNAME>       — read from an environment variable
//!   file:<path>         — read from a local file owned by the process
//!   inline:<base64>     — literal embedded credential; rejected in
//!                         production-strict mode, useful for tests
//!   keychain:<label>    — read from the OS keychain (Tauri desktop).
//!                         Deferred to Phase 7 — currently returns
//!                         `RvError::ErrOther("keychain: not yet
//!                         supported")` so operators get a clear
//!                         message rather than a silent fallback.
//!
//! Callers receive a `Secret` newtype wrapping `Zeroizing<Vec<u8>>`
//! so the raw bytes are wiped on drop. Each target interprets those
//! bytes per its own needs — S3 parses them as JSON static creds or
//! as an AWS profile name; OAuth targets treat them as a refresh
//! token; etc.
//!
//! The resolver is deliberately unit-testable without touching any
//! cloud provider: `env:` and `file:` resolution works in isolation
//! and `inline:` needs nothing at all. Integration-test fixtures
//! that want to exercise a target end-to-end pass `inline:…` refs
//! for determinism; production configs should use `env:` or `file:`.

use std::{env, fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroizing;

use crate::errors::RvError;

/// Raw credential bytes with zero-on-drop semantics. Targets pull
/// out the string or parse a JSON payload as needed; either way the
/// underlying allocation is wiped when the `Secret` goes out of
/// scope, matching the same hygiene applied to cache entries.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the bytes — used by target-specific parsers. The
    /// lifetime is bounded by the `Secret`, so targets that want to
    /// keep the material alive must copy it into their own
    /// zeroize-aware storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// View as UTF-8 text when the target expects a string form
    /// (AWS profile name, OAuth refresh token, …).
    pub fn as_str(&self) -> Result<&str, RvError> {
        std::str::from_utf8(&self.0)
            .map_err(|e| RvError::ErrString(format!("credentials_ref: not valid utf-8: {e}")))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted by construction — never print the bytes. Length
        // is safe to surface; it helps debug "empty file" mistakes.
        write!(f, "Secret(<{} bytes redacted>)", self.0.len())
    }
}

/// Resolve a `credentials_ref` string to the raw credential bytes.
///
/// Leading / trailing whitespace in the reference itself is trimmed
/// before parsing so config files are forgiving; the underlying
/// source (env var value, file contents) is returned verbatim.
pub fn resolve(reference: &str) -> Result<Secret, RvError> {
    let trimmed = reference.trim();
    let (scheme, rest) = trimmed
        .split_once(':')
        .ok_or_else(|| RvError::ErrString(format!(
            "credentials_ref: missing scheme (expected `env:`, `file:`, `inline:`, or `keychain:`), got: {trimmed}"
        )))?;

    match scheme {
        "env" => resolve_env(rest),
        "file" => resolve_file(rest),
        "inline" => resolve_inline(rest),
        "keychain" => resolve_keychain(rest),
        other => Err(RvError::ErrString(format!(
            "credentials_ref: unknown scheme `{other}` (expected `env` / `file` / `inline` / `keychain`)"
        ))),
    }
}

/// Resolve `keychain:<label>` against the OS keychain.
///
/// Label syntax: `<service>/<user>` — the `/` splits the label into
/// the keychain's two identification axes. If no `/` is present, the
/// whole label is treated as the user under a default service id of
/// `"bastionvault"`.
///
/// Only compiled when the `cloud_keychain` feature is enabled.
/// Without the feature, the scheme is rejected at parse time with a
/// pointer at the build flag.
#[cfg(feature = "cloud_keychain")]
fn resolve_keychain(label: &str) -> Result<Secret, RvError> {
    let (service, user) = parse_keychain_label(label)?;
    let entry = keyring::Entry::new(&service, &user).map_err(|e| {
        RvError::ErrString(format!(
            "credentials_ref: keychain open `{service}`/`{user}`: {e}"
        ))
    })?;
    match entry.get_secret() {
        Ok(bytes) => Ok(Secret::new(bytes)),
        Err(keyring::Error::NoEntry) => Err(RvError::ErrString(format!(
            "credentials_ref: keychain entry `{service}`/`{user}` not found — run \
             `bvault operator cloud-target connect` or use the GUI Settings page to \
             populate it"
        ))),
        Err(e) => Err(RvError::ErrString(format!(
            "credentials_ref: keychain read `{service}`/`{user}`: {e}"
        ))),
    }
}

#[cfg(not(feature = "cloud_keychain"))]
fn resolve_keychain(_label: &str) -> Result<Secret, RvError> {
    Err(RvError::ErrString(
        "credentials_ref: `keychain:` requires the `cloud_keychain` build feature".into(),
    ))
}

fn resolve_env(varname: &str) -> Result<Secret, RvError> {
    if varname.is_empty() {
        return Err(RvError::ErrString(
            "credentials_ref: `env:` requires a variable name".into(),
        ));
    }
    // `env::var` returns `NotUnicode` for OS strings that aren't
    // valid UTF-8; fall back to `env::var_os` + the lossy path so
    // the caller gets a clearer error than a raw panic.
    match env::var(varname) {
        Ok(v) => Ok(Secret::new(v.into_bytes())),
        Err(env::VarError::NotPresent) => Err(RvError::ErrString(format!(
            "credentials_ref: env var `{varname}` is not set"
        ))),
        Err(env::VarError::NotUnicode(_)) => Err(RvError::ErrString(format!(
            "credentials_ref: env var `{varname}` is not valid UTF-8"
        ))),
    }
}

fn resolve_file(path: &str) -> Result<Secret, RvError> {
    if path.is_empty() {
        return Err(RvError::ErrString(
            "credentials_ref: `file:` requires a path".into(),
        ));
    }
    let p = PathBuf::from(path);
    let bytes = fs::read(&p).map_err(|e| {
        RvError::ErrString(format!(
            "credentials_ref: cannot read `{}`: {e}",
            p.display()
        ))
    })?;
    Ok(Secret::new(bytes))
}

/// Persist a freshly-obtained secret (typically an OAuth refresh
/// token returned from `exchange_code`) back to the destination
/// named by `reference`.
///
/// Only `file:` is writable in Phase 3b:
///   * `env:` — process env is not durable; rejected with an
///     instructive error pointing at `file:` as the portable option.
///   * `inline:` — config is static; writing would require mutating
///     the server config file, which is explicitly out of scope.
///   * `keychain:` — shipped in Phase 7; returns the same deferred-
///     feature error as the reader.
///
/// Writes set file perms to `0o600` on Unix so the refresh token
/// cannot be read by other local users.
pub fn persist(reference: &str, bytes: &[u8]) -> Result<(), RvError> {
    let trimmed = reference.trim();
    let (scheme, rest) = trimmed.split_once(':').ok_or_else(|| {
        RvError::ErrString(format!(
            "credentials_ref: missing scheme (expected `file:` or `keychain:`), got: {trimmed}"
        ))
    })?;
    match scheme {
        "file" => persist_file(rest, bytes),
        "env" => Err(RvError::ErrString(
            "credentials_ref: `env:` cannot be written durably — use `file:` for a refresh token"
                .into(),
        )),
        "inline" => Err(RvError::ErrString(
            "credentials_ref: `inline:` is read-only (value comes from server config)".into(),
        )),
        "keychain" => persist_keychain(rest, bytes),
        other => Err(RvError::ErrString(format!(
            "credentials_ref: unknown scheme `{other}` (expected `file` / `keychain`)"
        ))),
    }
}

fn persist_file(path: &str, bytes: &[u8]) -> Result<(), RvError> {
    if path.is_empty() {
        return Err(RvError::ErrString(
            "credentials_ref: `file:` requires a path".into(),
        ));
    }
    let p = PathBuf::from(path);
    // Ensure the parent dir exists so operators can point at
    // new locations without a preceding `mkdir`. Errors on dir
    // creation are surfaced — ACL problems should be loud.
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                RvError::ErrString(format!(
                    "credentials_ref: create parent `{}`: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    // Atomic write: write to a sibling tmp file then rename over
    // the target. Guarantees a concurrent reader either sees the
    // old bytes or the new bytes, never a partial write — matters
    // for `credentials_ref` because a half-written refresh token
    // locks the target out of re-auth.
    let tmp = p.with_extension(format!(
        "bvault-creds-tmp-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::write(&tmp, bytes).map_err(|e| {
        RvError::ErrString(format!(
            "credentials_ref: write tmp `{}`: {e}",
            tmp.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp, perms).map_err(|e| {
            RvError::ErrString(format!(
                "credentials_ref: chmod 0600 `{}`: {e}",
                tmp.display()
            ))
        })?;
    }
    fs::rename(&tmp, &p).map_err(|e| {
        // Best-effort cleanup of the tmp file if the rename fails.
        let _ = fs::remove_file(&tmp);
        RvError::ErrString(format!(
            "credentials_ref: rename `{}` -> `{}`: {e}",
            tmp.display(),
            p.display()
        ))
    })?;
    Ok(())
}

/// Write a secret into the OS keychain. Overwrites any existing
/// entry with the same label. Only compiled with `cloud_keychain`.
#[cfg(feature = "cloud_keychain")]
fn persist_keychain(label: &str, bytes: &[u8]) -> Result<(), RvError> {
    let (service, user) = parse_keychain_label(label)?;
    let entry = keyring::Entry::new(&service, &user).map_err(|e| {
        RvError::ErrString(format!(
            "credentials_ref: keychain open `{service}`/`{user}`: {e}"
        ))
    })?;
    entry.set_secret(bytes).map_err(|e| {
        RvError::ErrString(format!(
            "credentials_ref: keychain write `{service}`/`{user}`: {e}"
        ))
    })
}

#[cfg(not(feature = "cloud_keychain"))]
fn persist_keychain(_label: &str, _bytes: &[u8]) -> Result<(), RvError> {
    Err(RvError::ErrString(
        "credentials_ref: `keychain:` requires the `cloud_keychain` build feature".into(),
    ))
}

/// Split `<service>/<user>` into its two keychain-identifier axes.
/// A label without a `/` gets the default service id `"bastionvault"`;
/// a label with multiple `/`s splits on the first one so the user
/// part can contain further slashes (`onedrive/refresh/production`).
/// Empty labels are rejected to match the other schemes' behaviour.
///
/// Compiled unconditionally (not gated on `cloud_keychain`) so the
/// unit tests that verify label-splitting rules run in the default
/// build too — the parsing itself has no keyring dependency.
#[allow(dead_code)] // only used from `cfg(feature = "cloud_keychain")` paths + tests
fn parse_keychain_label(label: &str) -> Result<(String, String), RvError> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(RvError::ErrString(
            "credentials_ref: `keychain:` requires a label".into(),
        ));
    }
    match trimmed.split_once('/') {
        Some((svc, user)) if !svc.is_empty() && !user.is_empty() => {
            Ok((svc.to_string(), user.to_string()))
        }
        Some(_) => Err(RvError::ErrString(format!(
            "credentials_ref: keychain label `{trimmed}` must have non-empty service and user \
             parts on either side of the `/`"
        ))),
        None => Ok(("bastionvault".to_string(), trimmed.to_string())),
    }
}

fn resolve_inline(b64: &str) -> Result<Secret, RvError> {
    if b64.is_empty() {
        return Err(RvError::ErrString(
            "credentials_ref: `inline:` requires a base64 payload".into(),
        ));
    }
    let bytes = STANDARD.decode(b64).map_err(|e| {
        RvError::ErrString(format!("credentials_ref: `inline:` base64 decode: {e}"))
    })?;
    Ok(Secret::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_roundtrip() {
        let s = resolve("inline:aGVsbG8=").expect("decode ok");
        assert_eq!(s.as_bytes(), b"hello");
    }

    #[test]
    fn inline_requires_payload() {
        let err = resolve("inline:").unwrap_err();
        assert!(format!("{err}").contains("requires a base64 payload"));
    }

    #[test]
    fn inline_rejects_bad_base64() {
        let err = resolve("inline:!!!not-base64!!!").unwrap_err();
        assert!(format!("{err}").contains("base64 decode"));
    }

    #[test]
    fn env_resolves_set_var() {
        // Use a nanos-tagged var name so parallel test runs don't
        // race each other through the global process env.
        let var = format!(
            "BVAULT_CREDS_TEST_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        std::env::set_var(&var, "super-secret");
        let s = resolve(&format!("env:{var}")).expect("resolve ok");
        assert_eq!(s.as_str().unwrap(), "super-secret");
        std::env::remove_var(&var);
    }

    #[test]
    fn env_missing_var_errors_clearly() {
        let var = format!(
            "BVAULT_CREDS_TEST_MISSING_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        // Defensive: ensure it really isn't set before we check.
        std::env::remove_var(&var);
        let err = resolve(&format!("env:{var}")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("is not set"), "got: {msg}");
    }

    #[test]
    fn env_requires_var_name() {
        let err = resolve("env:").unwrap_err();
        assert!(format!("{err}").contains("requires a variable name"));
    }

    #[test]
    fn file_resolves_bytes() {
        // Manual tempfile (no tempfile dep in the tree for this
        // crate; nanos-tagged path is collision-free enough).
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bvault_creds_test_{}.bin",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::write(&p, b"file-body").unwrap();

        let s = resolve(&format!("file:{}", p.display())).expect("resolve ok");
        assert_eq!(s.as_bytes(), b"file-body");

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn file_missing_path_errors_clearly() {
        let err = resolve("file:/definitely/does/not/exist/nowhere.bin").unwrap_err();
        assert!(format!("{err}").contains("cannot read"));
    }

    #[test]
    fn file_requires_path() {
        let err = resolve("file:").unwrap_err();
        assert!(format!("{err}").contains("requires a path"));
    }

    #[test]
    fn parse_keychain_label_default_service() {
        let (svc, user) = parse_keychain_label("my-label").unwrap();
        assert_eq!(svc, "bastionvault");
        assert_eq!(user, "my-label");
    }

    #[test]
    fn parse_keychain_label_service_user() {
        let (svc, user) = parse_keychain_label("bvault/onedrive-refresh").unwrap();
        assert_eq!(svc, "bvault");
        assert_eq!(user, "onedrive-refresh");
    }

    #[test]
    fn parse_keychain_label_user_with_slashes() {
        let (svc, user) = parse_keychain_label("bvault/a/b/c").unwrap();
        assert_eq!(svc, "bvault");
        // Splits on the first `/` so downstream slashes stay in the
        // user component.
        assert_eq!(user, "a/b/c");
    }

    #[test]
    fn parse_keychain_label_empty_rejected() {
        let err = parse_keychain_label("").unwrap_err();
        assert!(format!("{err}").contains("requires a label"));
    }

    #[test]
    fn parse_keychain_label_empty_halves_rejected() {
        assert!(parse_keychain_label("/user").is_err());
        assert!(parse_keychain_label("service/").is_err());
    }

    #[cfg(not(feature = "cloud_keychain"))]
    #[test]
    fn keychain_rejected_without_feature() {
        let err = resolve("keychain:my-label").unwrap_err();
        assert!(
            format!("{err}").contains("cloud_keychain"),
            "got: {err}"
        );
        let err = persist("keychain:my-label", b"x").unwrap_err();
        assert!(
            format!("{err}").contains("cloud_keychain"),
            "got: {err}"
        );
    }

    /// Roundtrip against the real OS keychain — ignored by default
    /// since CI environments vary (Linux without a running
    /// Secret Service / dbus will fail). Run locally with:
    ///
    ///   cargo test --features cloud_keychain -- --ignored keychain_roundtrip
    #[cfg(feature = "cloud_keychain")]
    #[test]
    #[ignore]
    fn keychain_roundtrip() {
        let label = format!(
            "bvault-test-{}-{}/refresh",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let reference = format!("keychain:{label}");
        persist(&reference, b"the-refresh-token").expect("persist");
        let got = resolve(&reference).expect("resolve");
        assert_eq!(got.as_bytes(), b"the-refresh-token");

        // Rotate: second write overwrites the first value.
        persist(&reference, b"rotated").expect("rotate");
        let got = resolve(&reference).expect("resolve after rotate");
        assert_eq!(got.as_bytes(), b"rotated");

        // Cleanup so the OS keychain isn't littered with test entries.
        let (svc, user) = parse_keychain_label(&label).unwrap();
        if let Ok(entry) = keyring::Entry::new(&svc, &user) {
            let _ = entry.delete_credential();
        }
    }

    #[test]
    fn missing_scheme_errors_clearly() {
        let err = resolve("just-a-string-no-colon").unwrap_err();
        assert!(format!("{err}").contains("missing scheme"));
    }

    #[test]
    fn unknown_scheme_errors_clearly() {
        let err = resolve("gopher:not-a-real-thing").unwrap_err();
        assert!(format!("{err}").contains("unknown scheme"));
    }

    #[test]
    fn secret_debug_never_leaks_bytes() {
        let s = Secret::new(b"sensitive".to_vec());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("sensitive"));
        assert!(rendered.contains("9 bytes redacted"));
    }

    #[test]
    fn persist_file_writes_and_resolve_reads_back() {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bvault_creds_persist_{}.bin",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let reference = format!("file:{}", p.display());
        persist(&reference, b"fresh-refresh-token").unwrap();
        let round = resolve(&reference).unwrap();
        assert_eq!(round.as_bytes(), b"fresh-refresh-token");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn persist_file_is_atomic_over_replacement() {
        // Write the first value, then overwrite. A reader after the
        // second write must see the full second value, never a mix.
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bvault_creds_atomic_{}.bin",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let reference = format!("file:{}", p.display());
        persist(&reference, b"v1-tokens").unwrap();
        persist(&reference, b"v2-fresh-rotated-token").unwrap();
        let round = resolve(&reference).unwrap();
        assert_eq!(round.as_bytes(), b"v2-fresh-rotated-token");
        std::fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn persist_file_sets_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bvault_creds_perms_{}.bin",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let reference = format!("file:{}", p.display());
        persist(&reference, b"secret").unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn persist_env_is_rejected() {
        let err = persist("env:WHATEVER", b"x").unwrap_err();
        assert!(format!("{err}").contains("cannot be written"));
    }

    #[test]
    fn persist_inline_is_rejected() {
        let err = persist("inline:YQ==", b"x").unwrap_err();
        assert!(format!("{err}").contains("read-only"));
    }

    #[cfg(not(feature = "cloud_keychain"))]
    #[test]
    fn persist_keychain_rejected_without_feature() {
        let err = persist("keychain:label", b"x").unwrap_err();
        assert!(format!("{err}").contains("cloud_keychain"));
    }

    #[test]
    fn persist_requires_scheme() {
        let err = persist("no-scheme-here", b"x").unwrap_err();
        assert!(format!("{err}").contains("missing scheme"));
    }

    #[test]
    fn persist_unknown_scheme_errors() {
        let err = persist("s3://bucket/path", b"x").unwrap_err();
        // Note: "s3" is an unknown scheme here (not to be confused
        // with the FileBackend target). The error points operators
        // at the supported schemes.
        assert!(format!("{err}").contains("unknown scheme"));
    }
}
