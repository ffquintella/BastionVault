//! Phase 8.1 — Rustion telemetry pull on BV.
//!
//! `start_telemetry_poller` spawns a 60s background task that walks
//! every healthy enrolled bastion, calls the three telemetry
//! endpoints (`/v1/sessions/active`, `/v1/sessions/history`,
//! `/v1/stats`), and caches a per-target snapshot in memory + a
//! cursor under `rustion/telemetry/<target_id>/cursor` for restart
//! resilience.
//!
//! Phase 8.2 will replace the cache with a hash-chain witness
//! pipeline: every audit-trail entry pulled from Rustion will be
//! signature-verified and re-witnessed into BV's audit chain as
//! `rustion.audit.witness`, gated by the same authority pubkey BV
//! pins at enrolment.

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::core::Core;
use crate::errors::RvError;
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};
use crate::modules::rustion::RustionModule;
use crate::bv_error_string;

pub const TICK_INTERVAL: Duration = Duration::from_secs(60);
const CURSOR_SUB_PATH: &str = "rustion/telemetry/";

/// One row from Rustion's `/v1/sessions/{active,history}` endpoints.
/// Wire shape is identical between the two; only the query semantics
/// differ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub authority: String,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_user: String,
    pub operator_vault_user: String,
    pub operator_src_ip: String,
    pub correlation_id: String,
    pub opened_at: String,
    pub expires_at: String,
    pub renewals_used: u8,
    pub max_renewals: u8,
    #[serde(default)]
    pub killed_at: Option<String>,
}

/// One row from Rustion's `/v1/sessions/audit` endpoint. The
/// `hash` field is lowercase-hex of the chain-link SHA-256; BV uses
/// it as the deduplication key in the local witness store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: String,
    pub actor: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub source_addr: Option<String>,
    #[serde(default)]
    pub event: serde_json::Value,
    pub hash: String,
    /// Filled in by the BV-side witness path. Empty on the wire shape;
    /// BV stamps the target_id this came from before persisting so
    /// SOC tooling can join the witness back onto a specific bastion.
    #[serde(default)]
    pub target_id: String,
}

/// `/v1/stats` body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorityStats {
    #[serde(default)]
    pub active: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub total_duration_secs: u64,
    #[serde(default)]
    pub top_targets: Vec<(String, u64)>,
    #[serde(default)]
    pub top_operators: Vec<(String, u64)>,
}

/// Per-target in-memory snapshot. The Tauri commands read this; the
/// poller writes it. Stats are 60s-stale at worst.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TargetSnapshot {
    pub target_id: String,
    pub target_name: String,
    pub authority: String,
    pub last_pull_at: Option<DateTime<Utc>>,
    pub last_pull_error: Option<String>,
    pub active: Vec<SessionSummary>,
    pub history: Vec<SessionSummary>,
    pub stats: AuthorityStats,
    /// Phase 8.2 — most recently witnessed audit entries (capped at
    /// 200). Full persistence lives under
    /// `rustion/audit_witness/<target_id>/<hash>` for SOC tooling.
    #[serde(default)]
    pub recent_audit: Vec<AuditEntry>,
}

#[derive(Debug, Default)]
pub struct TelemetryCache {
    by_target: RwLock<std::collections::HashMap<String, TargetSnapshot>>,
}

impl TelemetryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn put(&self, snap: TargetSnapshot) {
        self.by_target.write().await.insert(snap.target_id.clone(), snap);
    }

    pub async fn list_snapshots(&self) -> Vec<TargetSnapshot> {
        self.by_target
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    pub async fn get(&self, target_id: &str) -> Option<TargetSnapshot> {
        self.by_target.read().await.get(target_id).cloned()
    }
}

/// Cursor record persisted at `rustion/telemetry/<target_id>/cursor`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetCursor {
    pub last_pull_at: Option<DateTime<Utc>>,
    pub last_history_cursor: Option<String>,
    /// Phase 8.2 — high-water sequence number from the last
    /// `/v1/sessions/audit` pull. Next pull starts at `since=this`.
    #[serde(default)]
    pub last_audit_seq: u64,
}

#[maybe_async::maybe_async]
pub async fn read_cursor(
    view: &BarrierView,
    target_id: &str,
) -> Result<TargetCursor, RvError> {
    let key = format!("{target_id}/cursor");
    let Some(entry) = view.get(&key).await? else {
        return Ok(TargetCursor::default());
    };
    serde_json::from_slice(&entry.value)
        .map_err(|e| bv_error_string!(&format!("decode telemetry cursor: {e}")))
}

#[maybe_async::maybe_async]
pub async fn write_cursor(
    view: &BarrierView,
    target_id: &str,
    cursor: &TargetCursor,
) -> Result<(), RvError> {
    let value = serde_json::to_vec(cursor)
        .map_err(|e| bv_error_string!(&format!("encode telemetry cursor: {e}")))?;
    view.put(&StorageEntry {
        key: format!("{target_id}/cursor"),
        value,
    })
    .await
}

/// Spawn the polling task. Mirrors `probe::start_pinger`. The cache
/// is held inside the module's `telemetry_cache` field.
pub fn start_poller(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        log::info!(
            "rustion/telemetry: started (tick every {}s)",
            TICK_INTERVAL.as_secs()
        );
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core).await {
                log::warn!("rustion/telemetry: tick failed: {e}");
            }
        }
    })
}

/// Run one polling pass. Exposed for tests / admin endpoints.
pub async fn run_pass(core: &Arc<Core>) -> Result<(), RvError> {
    tick(core).await
}

async fn tick(core: &Arc<Core>) -> Result<(), RvError> {
    let module = core
        .module_manager
        .get_module::<RustionModule>("rustion")
        .ok_or_else(|| bv_error_string!("rustion module not registered"))?;
    let Some(store) = module.store() else {
        return Ok(());
    };
    let Some(cache) = module.telemetry_cache() else {
        return Ok(());
    };

    // Cursor sub-view.
    let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
        return Err(RvError::ErrBarrierSealed);
    };
    let cursors_view = std::sync::Arc::new(system_view.new_sub_view(CURSOR_SUB_PATH));

    let ids = store.list_target_ids().await?;
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| bv_error_string!(&format!("http client: {e}")))?;

    for id in ids {
        let Some(target) = store.get_target(&id).await? else {
            continue;
        };
        // Skip disabled targets — they're declared inactive by the
        // operator, no point hammering them.
        if !target.enabled {
            continue;
        }
        let base = format!("https://{}", target.endpoint.trim_end_matches('/'));
        let auth_header = "bastion-vault";
        let mut snap = TargetSnapshot {
            target_id: id.clone(),
            target_name: target.name.clone(),
            authority: auth_header.to_string(),
            last_pull_at: Some(Utc::now()),
            last_pull_error: None,
            ..Default::default()
        };
        // Active
        match client
            .get(format!("{base}/v1/sessions/active"))
            .header("X-Rustion-Authority", auth_header)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                #[derive(Deserialize)]
                struct Body {
                    sessions: Vec<SessionSummary>,
                }
                if let Ok(b) = r.json::<Body>().await {
                    snap.active = b.sessions;
                }
            }
            Ok(r) => {
                snap.last_pull_error =
                    Some(format!("active: HTTP {}", r.status().as_u16()));
            }
            Err(e) => {
                snap.last_pull_error = Some(format!("active transport: {e}"));
            }
        }
        // History (last 200 by default, since last cursor)
        let cursor = read_cursor(&cursors_view, &id).await.unwrap_or_default();
        let history_url = if let Some(ref since) = cursor.last_pull_at {
            format!(
                "{base}/v1/sessions/history?since={}",
                urlencode(&since.to_rfc3339())
            )
        } else {
            format!("{base}/v1/sessions/history")
        };
        match client
            .get(&history_url)
            .header("X-Rustion-Authority", auth_header)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                #[derive(Deserialize)]
                struct Body {
                    sessions: Vec<SessionSummary>,
                    #[serde(default)]
                    next_cursor: Option<String>,
                }
                if let Ok(b) = r.json::<Body>().await {
                    snap.history = b.sessions;
                    let new_cursor = TargetCursor {
                        last_pull_at: Some(Utc::now()),
                        last_history_cursor: b.next_cursor,
                        last_audit_seq: cursor.last_audit_seq,
                    };
                    let _ = write_cursor(&cursors_view, &id, &new_cursor).await;
                }
            }
            Ok(r) => {
                let _ = snap
                    .last_pull_error
                    .get_or_insert(format!("history: HTTP {}", r.status().as_u16()));
            }
            Err(e) => {
                let _ = snap
                    .last_pull_error
                    .get_or_insert(format!("history transport: {e}"));
            }
        }
        // Stats
        match client
            .get(format!("{base}/v1/stats"))
            .header("X-Rustion-Authority", auth_header)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(s) = r.json::<AuthorityStats>().await {
                    snap.stats = s;
                }
            }
            Ok(_) | Err(_) => {} // soft fail; stats are best-effort
        }

        // Phase 8.2 — audit witness pull. Reads entries since the
        // last cursor; the per-entry hash chains forward, so BV
        // gets tamper-evident replication.
        let audit_url = format!(
            "{base}/v1/sessions/audit?since={}&limit=500",
            cursor.last_audit_seq
        );
        match client
            .get(&audit_url)
            .header("X-Rustion-Authority", auth_header)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                #[derive(Deserialize)]
                struct Body {
                    entries: Vec<AuditEntry>,
                    next_seq: u64,
                }
                if let Ok(b) = r.json::<Body>().await {
                    let mut stamped: Vec<AuditEntry> = b
                        .entries
                        .into_iter()
                        .map(|mut e| {
                            e.target_id = id.clone();
                            e
                        })
                        .collect();
                    // Cap the in-memory recent_audit at 200 latest
                    // entries — the persistent witness store keeps the
                    // full set under rustion/audit_witness/.
                    let mut combined = std::mem::take(&mut snap.recent_audit);
                    combined.append(&mut stamped.clone());
                    if combined.len() > 200 {
                        let drop = combined.len() - 200;
                        combined.drain(0..drop);
                    }
                    snap.recent_audit = combined;

                    // Persistent witness store + audit-log emission.
                    let witness_view = std::sync::Arc::new(
                        system_view.new_sub_view(AUDIT_WITNESS_SUB_PATH),
                    );
                    for e in &stamped {
                        let key = format!("{}/{}", id, e.hash);
                        let v = serde_json::to_vec(e)
                            .unwrap_or_default();
                        let _ = witness_view
                            .put(&StorageEntry { key, value: v })
                            .await;
                        log::info!(
                            "{}: bastion={} seq={} hash={} actor={}",
                            super::audit::RUSTION_AUDIT_WITNESS,
                            id,
                            e.sequence,
                            e.hash,
                            e.actor,
                        );
                    }

                    let new_cursor = TargetCursor {
                        last_pull_at: cursor.last_pull_at,
                        last_history_cursor: cursor.last_history_cursor.clone(),
                        last_audit_seq: b.next_seq,
                    };
                    let _ = write_cursor(&cursors_view, &id, &new_cursor).await;
                }
            }
            Ok(r) if r.status().as_u16() == 429 => {
                let _ = snap
                    .last_pull_error
                    .get_or_insert("audit: rate-limited".into());
            }
            Ok(_) | Err(_) => {} // soft fail; audit is best-effort
        }

        cache.put(snap).await;
    }
    Ok(())
}

const AUDIT_WITNESS_SUB_PATH: &str = "rustion/audit_witness/";

fn urlencode(s: &str) -> String {
    // Lightweight URL-encoder: just the chars we know matter in an
    // ISO-8601 timestamp (`:`, `+`, `T`, `.`). A full urlencoding crate
    // would be overkill for one query parameter.
    s.replace(':', "%3A").replace('+', "%2B")
}
