//! Filename sanitising and collision-handling helpers for the web
//! session nav bar's download path.
//!
//! Pure Rust, no webview dependency; the per-platform shims build their
//! destination path through [`sanitize_filename`] and [`next_free_path`]
//! so a hostile `Content-Disposition` or last URL segment cannot escape
//! the Downloads directory or shadow a Windows-reserved stem.
//!
//! Rules come from the spec (docs/specs/2026-10-20-web-session-nav-controls-design.md §7.6):
//! strip path separators, zero bytes, control characters, leading dots,
//! trailing dots and spaces; replace `:` with `_` (NTFS streams); prefix
//! Windows reserved stems with `_`; retry collisions with ` (n)` before
//! the extension up to 999, then fail.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Collision retry budget. Mirrors spec §7.6: after `name`, try `name (1)`
/// through `name (999)` before giving up.
pub const MAX_COLLISION_SUFFIX: u32 = 999;

/// Reserved by `next_free_path` when the directory already holds the
/// name and every suffix up to [`MAX_COLLISION_SUFFIX`]. The caller
/// surfaces this as the `collision_exhausted` audit reason and a
/// short-lived error state on the bar (spec §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollisionExhausted;

impl std::fmt::Display for CollisionExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("destination directory already holds this name and every (n) suffix up to 999")
    }
}

impl std::error::Error for CollisionExhausted {}

/// Return a safe basename for `raw`. Empty input returns an empty string;
/// the caller then falls back to the `download-YYYYMMDD-HHMMSS.bin` form
/// per spec §7.6.
pub fn sanitize_filename(raw: &str) -> String {
    // 1. Drop path separators, zero bytes and other C0/DEL control
    //    characters outright. These are the only chars that can create a
    //    path traversal or truncate the name on a legacy syscall. The
    //    NTFS alternate data stream separator `:` is replaced rather than
    //    dropped, so a name that used `:` between fields still reads.
    let filtered: String = raw
        .chars()
        .filter_map(|c| match c {
            '/' | '\\' => None,
            c if c.is_control() => None,
            ':' => Some('_'),
            c => Some(c),
        })
        .collect();

    // 2. Strip leading dots (a leading-dot name is "hidden" on Unix and
    //    breaks Windows path parsing). Safe to drop them wholesale: the
    //    rest of the name still identifies the file.
    let no_leading_dots = filtered.trim_start_matches('.');

    // 3. Strip trailing dots and spaces (Windows ignores them silently,
    //    so `x.pdf. ` would read as `x.pdf` and shadow an existing file).
    let trimmed = no_leading_dots.trim_end_matches(['.', ' ']);

    // 4. If the stem (part before the last dot) is a Windows reserved
    //    device name, prefix `_` so the saved file can be opened on NTFS.
    if trimmed.is_empty() {
        return String::new();
    }
    if stem_is_windows_reserved(trimmed) {
        let mut out = String::with_capacity(trimmed.len() + 1);
        out.push('_');
        out.push_str(trimmed);
        out
    } else {
        trimmed.to_string()
    }
}

/// Return the first path under `dir` whose basename does not already
/// exist, trying `name`, `name (1)`, ..., up to [`MAX_COLLISION_SUFFIX`].
///
/// Uses `O_CREAT|O_EXCL` (via `create_new(true)`) to race safely against
/// a concurrent writer: a successful create means the file is now ours;
/// an `AlreadyExists` error means we must try the next suffix. The caller
/// re-opens the returned path for writing — this helper only reserves it
/// and leaves it as a zero-byte placeholder so the next download in the
/// same session does not collide against it.
pub fn next_free_path(dir: &Path, name: &str) -> Result<PathBuf, CollisionExhausted> {
    // Try the bare name first (no `(0)` suffix).
    if let Some(path) = try_create(dir, name)? {
        return Ok(path);
    }
    for n in 1..=MAX_COLLISION_SUFFIX {
        let candidate = decorate_name(name, n);
        if let Some(path) = try_create(dir, &candidate)? {
            return Ok(path);
        }
    }
    Err(CollisionExhausted)
}

/// Insert ` (n)` immediately before the final extension, if any:
/// `a.pdf` + 1 → `a (1).pdf`; `tarball.tar.gz` + 2 → `tarball.tar (2).gz`
/// (the common two-dot archive case keeps the final suffix for the OS
/// filer, which is what operators expect to recognise); `README` + 3 →
/// `README (3)`.
fn decorate_name(name: &str, n: u32) -> String {
    match name.rfind('.') {
        // Leading-dot names are already stripped by sanitize_filename;
        // defend against a direct caller all the same.
        Some(0) => format!("{name} ({n})"),
        Some(dot) => {
            let (stem, ext) = name.split_at(dot);
            format!("{stem} ({n}){ext}")
        }
        None => format!("{name} ({n})"),
    }
}

/// Try to reserve `dir/name`. `Ok(Some(path))` on success, `Ok(None)` on
/// a plain `AlreadyExists`. Other IO errors (permission denied, no space,
/// name too long) are also folded to `Ok(None)` on purpose: the next
/// suffix will hit the same error and the loop falls through to
/// `CollisionExhausted` after a bounded number of attempts, which keeps a
/// locked-down Downloads directory from spin-looping. The real IO error
/// resurfaces when the caller re-opens the returned path for writing.
/// The signature returns `Result<_, CollisionExhausted>` for symmetry
/// with [`next_free_path`] — it never actually constructs that error.
fn try_create(dir: &Path, name: &str) -> Result<Option<PathBuf>, CollisionExhausted> {
    let path = dir.join(name);
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_file) => Ok(Some(path)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
        Err(_) => {
            // Treat an unexpected IO error (permission denied, no space,
            // name too long on this filesystem) as a collision so the loop
            // exits after a bounded number of attempts; the next suffix
            // will hit the same error and we fall through to
            // CollisionExhausted. The caller already has a cheaper audit
            // line for "collision_exhausted", and the download delegate
            // re-opens the returned path for writing — the real IO error
            // surfaces there with full context.
            Ok(None)
        }
    }
}

/// Windows reserves these device names in any directory. The check is
/// case-insensitive and applies to the stem (the part before the first
/// dot): `CON`, `CON.txt` and `CON.anything` are all reserved.
fn stem_is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("");
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || is_com_or_lpt(&upper)
}

fn is_com_or_lpt(upper: &str) -> bool {
    if upper.len() != 4 {
        return false;
    }
    let bytes = upper.as_bytes();
    let prefix = &bytes[..3];
    let digit = bytes[3];
    (prefix == b"COM" || prefix == b"LPT") && digit.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir()
            .join(format!("bv-nav-bar-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create tempdir");
        p
    }

    #[test]
    fn sanitize_strips_separators_and_controls() {
        assert_eq!(sanitize_filename("foo/bar.pdf"), "foobar.pdf");
        assert_eq!(sanitize_filename("foo\\bar.pdf"), "foobar.pdf");
        assert_eq!(sanitize_filename("foo\0bar.pdf"), "foobar.pdf");
        assert_eq!(sanitize_filename("foo\x01bar\x1fbaz\x7f.pdf"), "foobarbaz.pdf");
        // Newlines, tabs and carriage returns are controls too.
        assert_eq!(sanitize_filename("a\nb\tc\rd.pdf"), "abcd.pdf");
        // The NTFS stream separator is replaced, not dropped, so the name
        // still reads correctly for the operator.
        assert_eq!(sanitize_filename("report:summary.pdf"), "report_summary.pdf");
    }

    #[test]
    fn sanitize_prefixes_windows_reserved_stems() {
        // Bare device names.
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("LPT1"), "_LPT1");
        // Reserved stems with an extension stay reserved.
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("com0.log"), "_com0.log");
        // Case insensitive.
        assert_eq!(sanitize_filename("prn"), "_prn");
        assert_eq!(sanitize_filename("Aux"), "_Aux");
        assert_eq!(sanitize_filename("Nul.dat"), "_Nul.dat");
        // COM/LPT must be followed by one digit — `COMA` is not reserved.
        assert_eq!(sanitize_filename("COMA"), "COMA");
        assert_eq!(sanitize_filename("LPT"), "LPT");
        assert_eq!(sanitize_filename("COM10"), "COM10");
    }

    #[test]
    fn sanitize_strips_trailing_dots_and_spaces() {
        assert_eq!(sanitize_filename("x.pdf. "), "x.pdf");
        assert_eq!(sanitize_filename("x.pdf  "), "x.pdf");
        assert_eq!(sanitize_filename("x.pdf..."), "x.pdf");
        assert_eq!(sanitize_filename("x.pdf. . "), "x.pdf");
        // And leading dots.
        assert_eq!(sanitize_filename(".hidden.txt"), "hidden.txt");
        // All-dot name collapses to empty: caller falls back.
        assert_eq!(sanitize_filename("..."), "");
    }

    #[test]
    fn next_free_path_returns_input_on_empty_dir() {
        let dir = tempdir("empty");
        let p = next_free_path(&dir, "report.pdf").expect("free name");
        assert_eq!(p, dir.join("report.pdf"));
        assert!(p.exists(), "placeholder reserved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_free_path_appends_n_before_extension() {
        let dir = tempdir("one-collision");
        std::fs::write(dir.join("a.pdf"), b"").expect("seed existing file");
        let p = next_free_path(&dir, "a.pdf").expect("free name");
        assert_eq!(p, dir.join("a (1).pdf"));
        // And the next call steps past both.
        let p2 = next_free_path(&dir, "a.pdf").expect("second free name");
        assert_eq!(p2, dir.join("a (2).pdf"));
        // No extension — suffix goes at the end.
        let p3 = next_free_path(&dir, "README").expect("README free");
        assert_eq!(p3, dir.join("README"));
        std::fs::write(&p3, b"").ok();
        let p4 = next_free_path(&dir, "README").expect("README (1) free");
        assert_eq!(p4, dir.join("README (1)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collision_exhausted_at_999() {
        // Seed every name the helper would try: `a.pdf` plus
        // `a (1).pdf` through `a (999).pdf`. 1000 placeholders total.
        let dir = tempdir("exhausted");
        std::fs::write(dir.join("a.pdf"), b"").expect("seed base");
        for n in 1..=MAX_COLLISION_SUFFIX {
            std::fs::write(dir.join(format!("a ({n}).pdf")), b"")
                .expect("seed suffix");
        }
        let err = next_free_path(&dir, "a.pdf").expect_err("exhausted");
        assert_eq!(err, CollisionExhausted);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
