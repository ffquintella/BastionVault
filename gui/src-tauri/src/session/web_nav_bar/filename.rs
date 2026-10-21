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
//! the extension up to 999, then fail. Names are also capped at
//! [`MAX_FILENAME_BYTES`] so the ` (n)` suffix never pushes a name past
//! the common 255-byte filesystem limit.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Collision retry budget. Mirrors spec §7.6: after `name`, try `name (1)`
/// through `name (999)` before giving up.
pub const MAX_COLLISION_SUFFIX: u32 = 999;

/// Upper bound on a sanitised name, in bytes, including any `_` prefix.
/// Leaves room for the ` (999)` collision suffix under the 255-byte name
/// limit of APFS, NTFS, ext4 and friends.
pub const MAX_FILENAME_BYTES: usize = 200;

/// An extension longer than this is not treated as one when a long name
/// is truncated: the whole name is cut instead.
const MAX_EXTENSION_BYTES: usize = 16;

/// Every name [`next_free_path`] would try already exists: the base name
/// and every suffix up to [`MAX_COLLISION_SUFFIX`]. The caller surfaces
/// this as the `collision_exhausted` audit reason and a short-lived error
/// state on the bar (spec §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollisionExhausted;

impl std::fmt::Display for CollisionExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not save, directory full of this name (every (n) suffix up to 999 is taken)")
    }
}

impl std::error::Error for CollisionExhausted {}

/// Why [`next_free_path`] could not reserve a destination.
#[derive(Debug)]
pub enum NextPathError {
    /// Every candidate name exists. Audit reason `collision_exhausted`.
    Exhausted(CollisionExhausted),
    /// A filesystem error other than "already exists" (missing directory,
    /// permission denied, read-only filesystem, no space, name too long).
    /// Returned on the first such error; the remaining suffixes are not
    /// tried, since they would fail the same way.
    Io(io::Error),
    /// `name` is not a single plain path component: empty, `.`, `..`, or
    /// containing a path separator, `:` or a NUL. Callers pass the output
    /// of [`sanitize_filename`], which never produces one of these.
    InvalidName,
}

impl std::fmt::Display for NextPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted(e) => e.fmt(f),
            Self::Io(e) => write!(f, "could not reserve the download destination: {e}"),
            Self::InvalidName => f.write_str("download file name is not a single plain path component"),
        }
    }
}

impl std::error::Error for NextPathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Exhausted(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::InvalidName => None,
        }
    }
}

/// Return a safe basename for `raw`, at most [`MAX_FILENAME_BYTES`] bytes.
/// A name that sanitises to nothing returns an empty string; the caller
/// then falls back to the `download-YYYYMMDD-HHMMSS.bin` form per spec
/// §7.6.
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

    // 2. Strip leading dots (hidden on Unix, ambiguous on Windows) and
    //    trailing dots and spaces (Windows drops them silently, so
    //    `x.pdf. ` would land as `x.pdf` and shadow an existing file).
    // 3. Cap the length, keeping one byte for a possible `_` prefix, and
    //    trim again: the cut can expose a trailing space or dot.
    let capped = cap_length(trim_dots_and_spaces(&filtered), MAX_FILENAME_BYTES - 1);
    let name = trim_dots_and_spaces(&capped);
    if name.is_empty() {
        return String::new();
    }

    // 4. A Windows reserved device stem gets a `_` prefix so the saved file
    //    can be opened on NTFS. Done last, so no later step can turn a
    //    name back into a reserved one.
    if stem_is_windows_reserved(name) {
        format!("_{name}")
    } else {
        name.to_string()
    }
}

/// Reserve the first free path under `dir`, trying `name`, then
/// `name (1)`, ..., `name (999)` with the suffix before the extension.
///
/// Each candidate is created with `O_CREAT|O_EXCL` (`create_new(true)`),
/// so the reservation is race-free against any other writer.
///
/// **Placeholder contract.** On success the returned path exists as a
/// zero-byte file this call created. The caller must:
/// - open it for writing with `write(true).truncate(true)` — not
///   `create_new`, which would fail on the placeholder; and
/// - delete it on any abort (cancel, transfer failure, size cap
///   exceeded, policy refusal), so a failed download leaves no empty file
///   in the operator's Downloads folder.
///
/// Errors: [`NextPathError::InvalidName`] when `name` is not a single plain
/// component (nothing is created); [`NextPathError::Io`] on the first
/// filesystem error other than "already exists";
/// [`NextPathError::Exhausted`] once all 1000 candidates exist.
pub fn next_free_path(dir: &Path, name: &str) -> Result<PathBuf, NextPathError> {
    if !is_plain_component(name) {
        return Err(NextPathError::InvalidName);
    }
    if let Some(path) = try_create(dir, name).map_err(NextPathError::Io)? {
        return Ok(path);
    }
    for n in 1..=MAX_COLLISION_SUFFIX {
        if let Some(path) = try_create(dir, &decorate_name(name, n)).map_err(NextPathError::Io)? {
            return Ok(path);
        }
    }
    Err(NextPathError::Exhausted(CollisionExhausted))
}

/// Create `dir/name` exclusively. `Ok(Some(path))` when it was created,
/// `Ok(None)` when it already exists, `Err` for any other IO error.
fn try_create(dir: &Path, name: &str) -> io::Result<Option<PathBuf>> {
    let path = dir.join(name);
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_file) => Ok(Some(path)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether `name` joins onto a directory as exactly one entry inside it.
fn is_plain_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':', '\0'])
}

/// Insert ` (n)` immediately before the final extension, if any:
/// `a.pdf` + 1 → `a (1).pdf`; `tarball.tar.gz` + 2 → `tarball.tar (2).gz`;
/// `README` + 3 → `README (3)`.
fn decorate_name(name: &str, n: u32) -> String {
    match name.rfind('.') {
        // A leading dot is not an extension separator (sanitize_filename
        // strips it, but a direct caller may not have).
        Some(0) | None => format!("{name} ({n})"),
        Some(dot) => {
            let (stem, ext) = name.split_at(dot);
            format!("{stem} ({n}){ext}")
        }
    }
}

fn trim_dots_and_spaces(name: &str) -> &str {
    name.trim_start_matches('.').trim_end_matches(['.', ' '])
}

/// Cut `name` to at most `max` bytes on a char boundary, keeping a short
/// final extension (at most [`MAX_EXTENSION_BYTES`]) intact.
fn cap_length(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 && name.len() - dot <= MAX_EXTENSION_BYTES => name.split_at(dot),
        _ => (name, ""),
    };
    format!("{}{ext}", floor_char_boundary(stem, max - ext.len()))
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a
/// char boundary.
fn floor_char_boundary(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Windows reserves these device names in any directory. The check is
/// case-insensitive and applies to the stem (the part before the first
/// dot): `CON`, `CON.txt` and `CON.anything` are all reserved.
fn stem_is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("");
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") || is_com_or_lpt(&upper)
}

fn is_com_or_lpt(upper: &str) -> bool {
    let bytes = upper.as_bytes();
    bytes.len() == 4 && (&bytes[..3] == b"COM" || &bytes[..3] == b"LPT") && bytes[3].is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("bv-nav-bar-{tag}-{}-{n}", std::process::id()))
    }

    fn tempdir(tag: &str) -> PathBuf {
        let p = tempdir_path(tag);
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
    fn sanitize_caps_long_names_and_keeps_extension() {
        // A 300-byte Content-Disposition name would hit ENAMETOOLONG on
        // most filesystems once the ` (n)` suffix is added.
        let long = format!("{}.pdf", "a".repeat(296));
        let out = sanitize_filename(&long);
        assert!(out.len() <= 200, "capped: {} bytes", out.len());
        assert!(out.ends_with(".pdf"), "extension kept: {out}");
        assert!(out.starts_with('a'));

        // Multi-byte characters are cut on a char boundary.
        let wide = format!("{}.pdf", "é".repeat(150));
        let out = sanitize_filename(&wide);
        assert!(out.len() <= 200, "capped: {} bytes", out.len());
        assert!(out.ends_with(".pdf"), "extension kept: {out}");
        assert!(out.trim_end_matches(".pdf").chars().all(|c| c == 'é'));

        // Short names are untouched.
        assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
    }

    #[test]
    fn sanitize_cap_cannot_produce_a_reserved_stem() {
        // The cut exposes trailing spaces, which are trimmed, leaving `CON`:
        // the reserved-stem prefix runs after the cap, so it still applies.
        let raw = format!("CON{}x", " ".repeat(300));
        assert_eq!(sanitize_filename(&raw), "_CON");
        // A reserved stem with an over-long "extension" stays within the cap
        // including its `_` prefix.
        let raw = format!("CON.{}", "x".repeat(300));
        let out = sanitize_filename(&raw);
        assert!(out.starts_with("_CON."), "{out}");
        assert!(out.len() <= MAX_FILENAME_BYTES, "{} bytes", out.len());
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
            std::fs::write(dir.join(format!("a ({n}).pdf")), b"").expect("seed suffix");
        }
        let err = next_free_path(&dir, "a.pdf").expect_err("exhausted");
        assert!(matches!(err, NextPathError::Exhausted(CollisionExhausted)), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_free_path_reports_io_error_not_exhaustion() {
        // A missing directory is an IO failure, not a full one: the
        // `collision_exhausted` audit reason would be false.
        let dir = tempdir_path("missing");
        assert!(!dir.exists());
        let err = next_free_path(&dir, "a.pdf").expect_err("missing dir");
        match err {
            NextPathError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
        assert!(!dir.exists(), "nothing created");
    }

    #[test]
    fn next_free_path_refuses_names_that_are_not_one_component() {
        let dir = tempdir("invalid");
        for name in ["", ".", "..", "a/b.pdf", "../a.pdf", "a\\b.pdf", "a.pdf:stream", "a\0b"] {
            let err = next_free_path(&dir, name).expect_err(name);
            assert!(matches!(err, NextPathError::InvalidName), "{name:?}: {err:?}");
        }
        let left: Vec<_> = std::fs::read_dir(&dir).expect("read dir").collect();
        assert!(left.is_empty(), "nothing created: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
