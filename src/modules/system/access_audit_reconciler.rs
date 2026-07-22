//! Cluster-aware reconciler: local `audit.log` → replicated access store.
//!
//! The audit broker writes every request/response to a **local** file
//! device (`audit.log`) on the node that served it. The unified Audit
//! page, by contrast, reads only replicated system-view stores. So a
//! successful `secret/…` read — recorded to the local file but nowhere
//! replicated — never reached the page, while a *denied* one (captured
//! by [`super::denial_audit_store`] from the request hot path) did.
//!
//! This reconciler closes that gap without adding a Raft write to the
//! read hot path. On every node a background task tails that node's own
//! local audit log(s) and ingests new successful lines into
//! [`super::access_audit_store`] (barrier-backed → Hiqlite-replicated).
//!
//! Cluster model:
//!   * Each node reconciles only its **own** local file(s). It never
//!     reads another node's disk.
//!   * The store is replicated, so the union of every node's ingest is
//!     what the Audit page reads — a cluster shows every member's
//!     successful access no matter which node serves the GUI.
//!   * Dedup is structural, not coordinated: the store keys each entry
//!     by `(nanos, digest-of-raw-line)`, so re-reading a line (after a
//!     restart, a cursor loss, or a rotation re-scan) overwrites in
//!     place, and two nodes never collide (each line's digest is
//!     unique). No leader election or cross-node locking is required.
//!
//! Progress is tracked by a **node-local** cursor sidecar next to each
//! log file (`<path>.reconcile-cursor`) — node-local state about a
//! node-local file, so it is neither replicated nor keyed by node id.
//! The cursor is a pure optimization: losing it re-scans the file,
//! which is safe because ingest is idempotent.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
    sync::Mutex,
};

use super::access_audit_store::{AccessAuditEntry, AccessAuditStore};
use crate::{
    audit::AuditEntry,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// How often the reconciler wakes. Chosen (over 30s) to keep replicated
/// write pressure low; new successful access appears on the Audit page
/// within roughly this interval.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60);

const CONFIG_SUB_PATH: &str = "access-audit-cfg/";
const CONFIG_KEY: &str = "config";

/// Global on/off switch for the reconciler, persisted (and replicated)
/// so an operator can disable ingest cluster-wide. Missing record ==
/// defaults (enabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AccessAuditConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl AccessAuditConfig {
    async fn load(core: &Core) -> Self {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Self::default();
        };
        let view = system_view.new_sub_view(CONFIG_SUB_PATH);
        match view.get(CONFIG_KEY).await {
            Ok(Some(e)) => serde_json::from_slice(&e.value).unwrap_or_default(),
            _ => Self::default(),
        }
    }
}

/// Node-local ingest cursor for one log file. Persisted as JSON beside
/// the log. `offset` is the byte position up to which the file has been
/// ingested (always at a line boundary).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Cursor {
    offset: u64,
}

fn cursor_path(log_path: &Path) -> PathBuf {
    let mut s = log_path.as_os_str().to_owned();
    s.push(".reconcile-cursor");
    PathBuf::from(s)
}

async fn load_cursor(log_path: &Path) -> Cursor {
    match tokio::fs::read(cursor_path(log_path)).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Cursor::default(),
    }
}

async fn save_cursor(log_path: &Path, cursor: &Cursor) {
    let path = cursor_path(log_path);
    match serde_json::to_vec(cursor) {
        Ok(bytes) => {
            if let Err(e) = tokio::fs::write(&path, bytes).await {
                log::warn!(
                    "access-audit: failed to persist cursor {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => log::warn!("access-audit: cursor serialize failed: {e}"),
    }
}

/// Numbered rotation sibling (`<path>.1`), matching `FileAuditDevice`'s
/// rotation naming.
fn rotated_sibling(log_path: &Path) -> PathBuf {
    let mut s = log_path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

/// Spawn the reconciler. Detached task; loops until the process exits
/// and self-skips while sealed. One task per process (per node).
pub fn start_access_audit_reconciler(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let running: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        log::info!(
            "access-audit: reconciler started (tick every {}s)",
            TICK_INTERVAL.as_secs()
        );

        let mut interval = tokio::time::interval(TICK_INTERVAL);
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            // Serialize overlapping ticks (a very large first scan can
            // outrun the interval).
            let _guard = running.lock().await;
            let started = Instant::now();
            match run_tick(&core).await {
                Ok(ingested) if ingested > 0 => log::debug!(
                    "access-audit: tick ingested {ingested} entries in {} ms",
                    started.elapsed().as_millis()
                ),
                Ok(_) => {}
                Err(e) => log::warn!("access-audit: tick failed: {e}"),
            }
        }
    })
}

/// Run one reconciliation sweep across every enabled file audit
/// device's local path. Returns the number of entries ingested.
/// Exposed for tests and (future) a manual admin trigger.
pub async fn run_tick(core: &Arc<Core>) -> Result<usize, RvError> {
    if !AccessAuditConfig::load(core).await.enabled {
        return Ok(0);
    }
    let Some(broker) = core.audit_broker.load_full() else {
        return Ok(0);
    };
    let store = AccessAuditStore::from_core(core)?;

    let mut total = 0usize;
    for path in broker.file_source_paths() {
        match reconcile_file(&store, &path).await {
            Ok(n) => total += n,
            Err(e) => log::warn!(
                "access-audit: reconcile of {} failed: {e}",
                path.display()
            ),
        }
    }
    Ok(total)
}

/// Ingest new complete lines from one log file. Handles a single level
/// of rotation: when the file is shorter than our saved offset the log
/// rotated, so we first drain the un-ingested tail of `<path>.1` (the
/// old file, now renamed), then rescan the fresh primary from zero.
async fn reconcile_file(store: &AccessAuditStore, log_path: &Path) -> Result<usize, RvError> {
    let mut cursor = load_cursor(log_path).await;
    let mut ingested = 0usize;

    let cur_len = match tokio::fs::metadata(log_path).await {
        Ok(m) => m.len(),
        // No file yet (device not written to, or path not created): nothing to do.
        Err(_) => return Ok(0),
    };

    if cur_len < cursor.offset {
        // Rotation (or truncation): the tail we had not yet read lives
        // in the rotated sibling. Best-effort drain from the old offset;
        // idempotent keys make a re-read harmless if we misjudge.
        let sibling = rotated_sibling(log_path);
        if tokio::fs::try_exists(&sibling).await.unwrap_or(false) {
            match read_new_lines(&sibling, cursor.offset).await {
                Ok((lines, _)) => ingested += ingest_lines(store, &lines).await,
                Err(e) => log::warn!(
                    "access-audit: rotation tail drain of {} failed: {e}",
                    sibling.display()
                ),
            }
        }
        cursor.offset = 0;
    }

    let (lines, new_offset) = read_new_lines(log_path, cursor.offset).await?;
    ingested += ingest_lines(store, &lines).await;
    cursor.offset = new_offset;

    save_cursor(log_path, &cursor).await;
    Ok(ingested)
}

/// Read from `offset` to the last newline, returning the complete lines
/// and the new offset (start-of-any-trailing-partial-line). A partial
/// last line (no trailing newline yet) is left for the next tick.
async fn read_new_lines(path: &Path, offset: u64) -> Result<(Vec<String>, u64), RvError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| crate::bv_error_string!(format!("open {} failed: {e}", path.display())))?;
    file.seek(SeekFrom::Start(offset))
        .await
        .map_err(|e| crate::bv_error_string!(format!("seek failed: {e}")))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .await
        .map_err(|e| crate::bv_error_string!(format!("read failed: {e}")))?;

    // Only consume through the last complete line.
    let last_nl = buf.iter().rposition(|&b| b == b'\n');
    let Some(last_nl) = last_nl else {
        // No complete line available yet.
        return Ok((Vec::new(), offset));
    };
    let consumed = &buf[..=last_nl];
    let new_offset = offset + consumed.len() as u64;

    let text = String::from_utf8_lossy(consumed);
    let lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    Ok((lines, new_offset))
}

/// Parse, filter, and append each line. Returns how many were ingested.
/// Parse / filter failures are skipped silently (a malformed or
/// uninteresting line is not an error).
async fn ingest_lines(store: &AccessAuditStore, lines: &[String]) -> usize {
    let mut n = 0usize;
    for line in lines {
        let Some(entry) = parse_ingestable(line) else {
            continue;
        };
        if store.append(entry, line).await.is_ok() {
            n += 1;
        }
    }
    n
}

/// Decide whether a raw audit line should surface on the Audit page and,
/// if so, project it to an [`AccessAuditEntry`]. Returns `None` for
/// lines we deliberately skip.
///
/// Ingested: successful (`type == "response"`, empty `error`) requests.
/// Skipped:
///   * request-type entries (only response entries carry the outcome);
///   * errored responses (failures are not "access"; denials never
///     reach the file device's log phase anyway);
///   * `*/login` paths — already covered by the login-audit store, so
///     ingesting them would double-list every login;
///   * `sys/audit/events` — the Audit page's own read. Ingesting it
///     creates a self-referential feedback loop (viewing the log logs a
///     view), which would swamp the store with GUI-poll noise.
fn parse_ingestable(line: &str) -> Option<AccessAuditEntry> {
    let entry: AuditEntry = serde_json::from_str(line).ok()?;
    if entry.r#type != "response" || !entry.error.is_empty() {
        return None;
    }
    let path = entry.request.path.as_str();
    // Skip auth-backend logins (already covered by the login-audit
    // store; ingesting them would double-list every login) and the
    // Audit page's own read (self-referential feedback loop).
    //
    // Match a `login` path *segment* under an `auth/` mount rather than
    // a raw substring: a plain `contains("/login")` would also drop a
    // secret whose own path embeds it — e.g. `secret/data/login` or
    // `secret/data/app/login-config` — so those legitimate reads would
    // silently never reach the Audit page.
    let is_auth_login =
        path.starts_with("auth/") && path.split('/').any(|seg| seg == "login");
    if is_auth_login || path == "sys/audit/events" {
        return None;
    }

    let user = if entry.auth.display_name.is_empty() {
        "(unnamed principal)".to_string()
    } else {
        entry.auth.display_name.clone()
    };

    Some(AccessAuditEntry {
        ts: entry.time,
        user,
        path: entry.request.path,
        operation: entry.request.operation,
        remote_addr: entry.request.remote_address,
        namespace: entry.namespace,
    })
}

/// Persist the reconciler enable flag (replicated). Exposed for a future
/// admin toggle; unused wiring is intentional.
#[allow(dead_code)]
pub async fn set_config(core: &Core, cfg: &AccessAuditConfig) -> Result<(), RvError> {
    let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
        return Err(RvError::ErrBarrierSealed);
    };
    let view: Arc<BarrierView> = Arc::new(system_view.new_sub_view(CONFIG_SUB_PATH));
    let value = serde_json::to_vec(cfg)?;
    view.put(&StorageEntry {
        key: CONFIG_KEY.to_string(),
        value,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_line(path: &str, op: &str, name: &str, error: &str) -> String {
        let mut e = AuditEntry {
            time: "2026-07-21T09:15:19Z".into(),
            r#type: "response".into(),
            ..Default::default()
        };
        e.request.path = path.into();
        e.request.operation = op.into();
        e.request.remote_address = "10.0.0.5".into();
        e.auth.display_name = name.into();
        e.error = error.into();
        crate::audit::entry::serialize_line(&e).unwrap()
    }

    #[test]
    fn ingests_successful_secret_read() {
        let line = response_line("secret/data/foo", "read", "felipe", "");
        let out = parse_ingestable(&line).expect("should ingest");
        assert_eq!(out.path, "secret/data/foo");
        assert_eq!(out.operation, "read");
        assert_eq!(out.user, "felipe");
        assert_eq!(out.remote_addr, "10.0.0.5");
    }

    #[test]
    fn skips_request_type_entries() {
        let mut e = AuditEntry {
            time: "2026-07-21T09:15:19Z".into(),
            r#type: "request".into(),
            ..Default::default()
        };
        e.request.path = "secret/data/foo".into();
        let line = crate::audit::entry::serialize_line(&e).unwrap();
        assert!(parse_ingestable(&line).is_none());
    }

    #[test]
    fn skips_errored_responses() {
        let line = response_line("secret/data/foo", "read", "felipe", "some backend error");
        assert!(parse_ingestable(&line).is_none());
    }

    #[test]
    fn skips_login_paths() {
        let line = response_line("auth/userpass/login/felipe", "write", "felipe", "");
        assert!(
            parse_ingestable(&line).is_none(),
            "logins are covered by the login store"
        );
    }

    #[test]
    fn ingests_secret_whose_path_embeds_login() {
        // A `contains("/login")` filter would wrongly drop these; the
        // segment-precise check keeps them.
        for p in [
            "secret/data/login",
            "secret/data/app/login-config",
            "secret/data/logins",
        ] {
            let line = response_line(p, "read", "felipe", "");
            assert!(
                parse_ingestable(&line).is_some(),
                "secret path {p} should be ingested"
            );
        }
    }

    #[test]
    fn skips_approle_login_without_username_segment() {
        let line = response_line("auth/approle/login", "write", "app", "");
        assert!(parse_ingestable(&line).is_none());
    }

    #[test]
    fn skips_self_referential_audit_events_read() {
        let line = response_line("sys/audit/events", "read", "felipe", "");
        assert!(parse_ingestable(&line).is_none());
    }

    #[test]
    fn unnamed_principal_when_no_display_name() {
        let line = response_line("secret/data/foo", "read", "", "");
        let out = parse_ingestable(&line).unwrap();
        assert_eq!(out.user, "(unnamed principal)");
    }

    #[test]
    fn malformed_line_is_skipped() {
        assert!(parse_ingestable("not json").is_none());
    }

    #[test]
    fn config_defaults_to_enabled() {
        assert!(AccessAuditConfig::default().enabled);
    }
}
