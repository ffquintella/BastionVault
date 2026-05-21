use std::path::PathBuf;

pub use crate::utils::string::{ensure_no_leading_slash, ensure_no_trailing_slash, ensure_trailing_slash};

pub fn sanitize_path(s: &str) -> String {
    ensure_no_trailing_slash(&ensure_no_leading_slash(s))
}

/// Resolve the path for the on-disk token helper. Honors `$BVAULT_TOKEN_FILE`
/// for deployments that pin the location (e.g. the puppet-bastionvault
/// wrapper sets it to a per-user file under a bind-mounted volume so the
/// token survives container restarts); otherwise falls back to the
/// HashiCorp Vault convention `~/.vault-token`.
///
/// Returns `None` when no path can be determined (no env override, no
/// `$HOME`). Callers treat that as "skip persistence silently" rather than
/// failing the command.
pub fn token_helper_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BVAULT_TOKEN_FILE") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".vault-token"))
}

/// Read a previously persisted token (trailing whitespace trimmed). Errors
/// — including the common `NotFound` case — collapse to `None` so the
/// caller can fall through to other token sources without noise.
pub fn read_persisted_token() -> Option<String> {
    let path = token_helper_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Persist a token to the helper path with 0600 permissions on Unix. Best
/// effort: any failure (e.g. read-only volume, missing parent dir) is
/// returned to the caller so they can surface a warning, but does NOT
/// abort the surrounding command — the token is still usable from this
/// shell via the printed value.
pub fn write_persisted_token(token: &str) -> std::io::Result<PathBuf> {
    let path = token_helper_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no token helper path"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}
