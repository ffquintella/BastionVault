//! File-based structured logging.
//!
//! Splits the server's log output into three on-disk streams:
//!
//! * `operations.log` — every record the `log` crate emits at or above
//!   the configured level. The general "what is the server doing"
//!   stream.
//! * `security.log` — records whose target starts with `security` (the
//!   convention this crate adopts for security-relevant events:
//!   seal/unseal transitions, failed authentication, denied policies,
//!   token revocation, etc.). Security records are *also* written to
//!   `operations.log` so an operator tailing one file still sees them.
//! * `audit.log` — the audit subsystem's per-request JSON stream,
//!   written by [`crate::audit::FileAuditDevice`]. This module
//!   stashes the configured path in [`default_audit_log_path`] so
//!   `Core::post_unseal` can auto-register a file device on first
//!   boot when no audit devices are persisted yet.
//!
//! The split lets operators ship the audit stream to immutable
//! storage / SIEM under one set of retention rules, and keep the
//! noisier operations stream local with a different retention.
//!
//! ## Format
//!
//! One record per line: `<RFC3339-UTC> <LEVEL> [<target>] <message>`.
//!
//! ## Rotation
//!
//! Each on-disk log is size-rotated in-process. When `operations.log`
//! (or `security.log`) reaches `rotate_size_bytes`, it's renamed to
//! `operations.log.1`, the previous `.1` shifts to `.2`, and so on up
//! to `rotate_keep` historical copies. The oldest is unlinked. A
//! fresh file is opened in its place. Audit-log rotation is owned by
//! [`crate::audit::FileAuditDevice`] which honours the same limits
//! when the broker auto-bootstraps it from [`default_audit_options`].

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use chrono::Utc;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};

/// Target prefix that routes a log record into `security.log`. Use
/// `log::warn!(target: "security", "...")` (or one of the
/// `security_*!` macros). Plain operational logs should *not* use
/// this prefix.
pub const SECURITY_TARGET_PREFIX: &str = "security";

/// Default per-file rotation threshold when the operator doesn't
/// override it. 100 MiB keeps a noisy month-of-traffic burst on one
/// file while bounding worst-case disk use to ~600 MiB at the
/// default keep-count.
pub const DEFAULT_ROTATE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Default number of rotated copies retained per stream.
pub const DEFAULT_ROTATE_KEEP: u32 = 5;

/// Path the audit broker should default to if no devices are
/// configured. Set by [`init`] when `log_dir` is non-empty; read by
/// `Core::post_unseal`.
pub fn default_audit_log_path() -> Option<PathBuf> {
    DEFAULT_AUDIT_PATH.get().cloned()
}

/// Options the broker should pass to a freshly-bootstrapped
/// `FileAuditDevice` so it rotates with the same policy as the
/// operations/security streams.
pub fn default_audit_options() -> Option<(PathBuf, u64, u32)> {
    let path = DEFAULT_AUDIT_PATH.get()?.clone();
    let (size, keep) = ROTATE_POLICY.get().copied().unwrap_or((
        DEFAULT_ROTATE_SIZE_BYTES,
        DEFAULT_ROTATE_KEEP,
    ));
    Some((path, size, keep))
}

static DEFAULT_AUDIT_PATH: OnceLock<PathBuf> = OnceLock::new();
static ROTATE_POLICY: OnceLock<(u64, u32)> = OnceLock::new();

/// Inputs for [`init`]. Kept as a plain struct so the CLI config
/// layer is the only thing that knows about TOML/HCL field names.
pub struct LogConfig<'a> {
    /// `RUST_LOG`-style filter. A bare level sets the global ceiling
    /// (`"info"`, `"debug"`); `target=level` tokens override matching
    /// targets by prefix (`"info,hiqlite=warn"` keeps everything at
    /// info but quiets the chatty hiqlite raft logs). Empty → `"info"`.
    pub level: &'a str,
    /// Directory that will hold `operations.log`, `security.log`, and
    /// `audit.log`. Empty disables file logging entirely.
    pub log_dir: &'a str,
    /// Also mirror records to stderr (useful in foreground/dev mode).
    pub log_to_stderr: bool,
    /// Per-file rotation threshold in bytes. `0` → use
    /// [`DEFAULT_ROTATE_SIZE_BYTES`].
    pub rotate_size_bytes: u64,
    /// Number of rotated copies to keep per stream. `0` → use
    /// [`DEFAULT_ROTATE_KEEP`].
    pub rotate_keep: u32,
}

/// Install the global logger. Idempotent within a process (a second
/// call is a no-op — useful for tests that spin up multiple servers).
pub fn init(cfg: LogConfig<'_>) -> Result<(), SetLoggerError> {
    let filter = LevelFilters::parse(cfg.level);
    let rotate_size = if cfg.rotate_size_bytes == 0 {
        DEFAULT_ROTATE_SIZE_BYTES
    } else {
        cfg.rotate_size_bytes
    };
    let rotate_keep = if cfg.rotate_keep == 0 {
        DEFAULT_ROTATE_KEEP
    } else {
        cfg.rotate_keep
    };

    let file_sink = if cfg.log_dir.is_empty() {
        None
    } else {
        match open_sinks(Path::new(cfg.log_dir), rotate_size, rotate_keep) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "logging: failed to open log files under `{}`: {e}. Falling back to stderr.",
                    cfg.log_dir
                );
                None
            }
        }
    };

    if let Some(sink) = &file_sink {
        let _ = DEFAULT_AUDIT_PATH.set(sink.audit_path.clone());
        let _ = ROTATE_POLICY.set((rotate_size, rotate_keep));
    }

    // When no on-disk files are open, stderr is the only sink — keep
    // it on regardless of the caller's preference so the process
    // doesn't log to nowhere.
    let stderr = cfg.log_to_stderr || file_sink.is_none();
    // The `log` crate's macros short-circuit on `max_level` before
    // ever building a `Record`, so the global ceiling must be the
    // *most verbose* level any directive can enable — otherwise a
    // per-target override like `hiqlite=debug` under a `warn` global
    // would be filtered out before `FanoutLogger::log` runs.
    let max_level = filter.max_verbosity();
    let logger = FanoutLogger {
        filter,
        files: file_sink.map(Mutex::new),
        stderr,
    };

    log::set_max_level(max_level);
    match log::set_boxed_logger(Box::new(logger)) {
        Ok(()) => Ok(()),
        Err(e) => {
            log::debug!("logging: logger already installed: {e}");
            Ok(())
        }
    }
}

/// A parsed `RUST_LOG`-style filter: one global level plus optional
/// per-target overrides. Directives are comma/space separated; a bare
/// token (`info`) sets the global level, a `target=level` token
/// (`hiqlite=warn`) overrides everything whose target *starts with*
/// that prefix. This lets operators quiet a chatty dependency
/// (`info,hiqlite=warn`) without lowering the global level.
struct LevelFilters {
    global: LevelFilter,
    /// Sorted longest-prefix-first so the most specific override wins.
    targets: Vec<(String, LevelFilter)>,
}

impl LevelFilters {
    fn parse(s: &str) -> Self {
        let mut global = LevelFilter::Info;
        let mut targets: Vec<(String, LevelFilter)> = Vec::new();

        for token in s.split(&[',', ' '][..]).filter(|t| !t.trim().is_empty()) {
            let token = token.trim();
            match token.split_once('=') {
                // `target=level` — per-target override.
                Some((target, lvl)) => {
                    let target = target.trim();
                    if let (false, Some(level)) = (target.is_empty(), parse_one(lvl)) {
                        targets.push((target.to_string(), level));
                    }
                }
                // Bare token — global level.
                None => {
                    if let Some(level) = parse_one(token) {
                        global = level;
                    }
                }
            }
        }

        // Longest prefix first: `hiqlite::network=debug` should beat a
        // broader `hiqlite=warn` for a matching target.
        targets.sort_by_key(|t| std::cmp::Reverse(t.0.len()));
        Self { global, targets }
    }

    /// Effective level for a record target — the most specific
    /// matching override, falling back to the global level.
    fn level_for(&self, target: &str) -> LevelFilter {
        for (prefix, level) in &self.targets {
            if target == prefix.as_str() || target.starts_with(&format!("{prefix}::")) {
                return *level;
            }
        }
        self.global
    }

    /// The most verbose level any directive can enable. Used to set
    /// the `log` crate's global `max_level` ceiling.
    fn max_verbosity(&self) -> LevelFilter {
        self.targets
            .iter()
            .map(|(_, l)| *l)
            .fold(self.global, |acc, l| acc.max(l))
    }
}

fn parse_one(s: &str) -> Option<LevelFilter> {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Some(LevelFilter::Info),
        "trace" => Some(LevelFilter::Trace),
        "debug" => Some(LevelFilter::Debug),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "error" => Some(LevelFilter::Error),
        "off" => Some(LevelFilter::Off),
        _ => None,
    }
}

/// One on-disk stream with size-rotation. Owns the open `File`
/// handle plus the bookkeeping needed to rotate without re-statting
/// on every write.
struct RotatingFile {
    path: PathBuf,
    file: std::fs::File,
    size: u64,
    max_size: u64,
    keep: u32,
}

impl RotatingFile {
    fn open(path: PathBuf, max_size: u64, keep: u32) -> io::Result<Self> {
        let file = open_append(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            file,
            size,
            max_size,
            keep,
        })
    }

    /// Append a line + newline. Rotates first if the write would
    /// push us over `max_size`. Best-effort: on rotation failure we
    /// keep writing to the existing file so a transient FS error
    /// doesn't lose records.
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        // +1 for the newline writeln! emits below.
        let needed = line.len() as u64 + 1;
        if self.max_size > 0 && self.size + needed > self.max_size && self.size > 0 {
            if let Err(e) = self.rotate() {
                // Log to stderr because the file sink is what's
                // failing — using log::warn! here would recurse.
                eprintln!(
                    "logging: rotate of {} failed: {e}. Continuing in place.",
                    self.path.display()
                );
            }
        }
        writeln!(self.file, "{line}")?;
        self.size += needed;
        Ok(())
    }

    /// Rename `path` → `path.1`, shifting any prior `.1` → `.2`,
    /// `.2` → `.3`, ..., dropping anything beyond `keep`. Then
    /// reopen `path` fresh.
    fn rotate(&mut self) -> io::Result<()> {
        // Drop the oldest first so the shift up doesn't overwrite a
        // file we'd rather keep.
        if self.keep > 0 {
            let oldest = numbered_path(&self.path, self.keep);
            let _ = fs::remove_file(&oldest);
            // Shift .{i} → .{i+1} from the top down.
            for i in (1..self.keep).rev() {
                let src = numbered_path(&self.path, i);
                if src.exists() {
                    let dst = numbered_path(&self.path, i + 1);
                    fs::rename(&src, &dst)?;
                }
            }
            // Current → .1
            fs::rename(&self.path, numbered_path(&self.path, 1))?;
        } else {
            // keep == 0: just unlink. Surprising but valid: operator
            // explicitly opted out of history.
            let _ = fs::remove_file(&self.path);
        }

        self.file = open_append(&self.path)?;
        self.size = 0;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn numbered_path(base: &Path, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

struct FileSink {
    ops: RotatingFile,
    security: RotatingFile,
    audit_path: PathBuf,
}

fn open_sinks(dir: &Path, max_size: u64, keep: u32) -> io::Result<FileSink> {
    fs::create_dir_all(dir)?;
    let ops = RotatingFile::open(dir.join("operations.log"), max_size, keep)?;
    let security = RotatingFile::open(dir.join("security.log"), max_size, keep)?;
    let audit_path = dir.join("audit.log");
    Ok(FileSink {
        ops,
        security,
        audit_path,
    })
}

fn open_append(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

struct FanoutLogger {
    filter: LevelFilters,
    files: Option<Mutex<FileSink>>,
    stderr: bool,
}

impl Log for FanoutLogger {
    fn enabled(&self, meta: &Metadata) -> bool {
        meta.level() <= self.filter.level_for(meta.target())
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let line = format_line(record);
        let is_security = record
            .target()
            .split("::")
            .next()
            .map(|t| t == SECURITY_TARGET_PREFIX)
            .unwrap_or(false);

        if self.stderr {
            // Best-effort; ignore stderr write failures (closed pipe,
            // daemonized parent, etc.) — the file sinks are the
            // authoritative record.
            let _ = writeln!(io::stderr(), "{line}");
        }

        if let Some(mtx) = &self.files {
            if let Ok(mut sink) = mtx.lock() {
                let _ = sink.ops.write_line(&line);
                if is_security {
                    let _ = sink.security.write_line(&line);
                }
            }
        }
    }

    fn flush(&self) {
        if let Some(mtx) = &self.files {
            if let Ok(mut sink) = mtx.lock() {
                let _ = sink.ops.flush();
                let _ = sink.security.flush();
            }
        }
    }
}

fn format_line(record: &Record) -> String {
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    format!(
        "{ts} {lvl:<5} [{target}] {msg}",
        lvl = level_str(record.level()),
        target = record.target(),
        msg = record.args(),
    )
}

fn level_str(l: Level) -> &'static str {
    match l {
        Level::Error => "ERROR",
        Level::Warn => "WARN",
        Level::Info => "INFO",
        Level::Debug => "DEBUG",
        Level::Trace => "TRACE",
    }
}

/// Convenience macros for security-event logging. Equivalent to
/// `log::<lvl>!(target: "security", ...)`. The explicit macro makes
/// the intent obvious at call sites and keeps the target prefix
/// consistent — a typo'd target wouldn't reach `security.log`.
#[macro_export]
macro_rules! security_warn {
    ($($arg:tt)+) => { log::warn!(target: "security", $($arg)+) };
}

#[macro_export]
macro_rules! security_info {
    ($($arg:tt)+) => { log::info!(target: "security", $($arg)+) };
}

#[macro_export]
macro_rules! security_error {
    ($($arg:tt)+) => { log::error!(target: "security", $($arg)+) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn rotates_when_size_exceeded() {
        let dir = std::env::temp_dir().join(format!("bv_log_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.log");

        // 100-byte cap, keep 3.
        let mut rf = RotatingFile::open(path.clone(), 100, 3).unwrap();
        // Each line ~30 bytes, write 10 lines → forces multiple rotations.
        for i in 0..10 {
            rf.write_line(&format!("line {i:03} aaaaaaaaaaaaaaaaaa")).unwrap();
        }
        rf.flush().unwrap();

        assert!(path.exists(), "current log should exist");
        // .1, .2, .3 may or may not exist depending on exact sizes;
        // .4 must NOT exist (keep=3).
        let dot4 = numbered_path(&path, 4);
        assert!(!dot4.exists(), "keep=3 violated: {dot4:?} exists");

        // Re-open and confirm we can append without re-reading size
        // off disk going wrong.
        drop(rf);
        let mut rf2 = RotatingFile::open(path.clone(), 100, 3).unwrap();
        rf2.write_line("post-reopen").unwrap();
        rf2.flush().unwrap();

        let mut content = String::new();
        std::fs::File::open(&path).unwrap().read_to_string(&mut content).unwrap();
        assert!(content.contains("post-reopen"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_target_override_quiets_dependency() {
        // The motivating case: keep info globally but silence the
        // chatty hiqlite raft WebSocket logs.
        let f = LevelFilters::parse("info,hiqlite=warn");
        assert_eq!(f.global, LevelFilter::Info);
        assert_eq!(
            f.level_for("hiqlite::network::raft_server"),
            LevelFilter::Warn
        );
        // A WARN from hiqlite still passes; INFO does not.
        assert!(LevelFilter::Warn >= LevelFilter::Warn);
        assert!(f.level_for("hiqlite::network::raft_server") < LevelFilter::Info);
        // Unrelated targets keep the global level.
        assert_eq!(f.level_for("bastion_vault::core"), LevelFilter::Info);
    }

    #[test]
    fn longest_prefix_wins() {
        let f = LevelFilters::parse("warn,hiqlite=info,hiqlite::network=error");
        assert_eq!(f.level_for("hiqlite::network::raft_server"), LevelFilter::Error);
        assert_eq!(f.level_for("hiqlite::store"), LevelFilter::Info);
        assert_eq!(f.level_for("other"), LevelFilter::Warn);
    }

    #[test]
    fn bare_level_and_empty_default_to_info() {
        assert_eq!(LevelFilters::parse("").global, LevelFilter::Info);
        assert_eq!(LevelFilters::parse("debug").global, LevelFilter::Debug);
        assert!(LevelFilters::parse("info").targets.is_empty());
    }

    #[test]
    fn max_verbosity_covers_overrides() {
        // Global warn but a debug override must lift the ceiling.
        let f = LevelFilters::parse("warn,hiqlite=debug");
        assert_eq!(f.max_verbosity(), LevelFilter::Debug);
        // Quieter override doesn't lower the global ceiling.
        let f = LevelFilters::parse("info,hiqlite=warn");
        assert_eq!(f.max_verbosity(), LevelFilter::Info);
    }

    #[test]
    fn prefix_does_not_match_unanchored() {
        // `hiqlite` must not match `hiqlitemore` — only exact or `::`.
        let f = LevelFilters::parse("info,hiqlite=warn");
        assert_eq!(f.level_for("hiqlitemore::x"), LevelFilter::Info);
        assert_eq!(f.level_for("hiqlite"), LevelFilter::Warn);
    }
}
