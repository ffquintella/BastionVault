//! Cluster-wide catalog of the backup files scheduled runs have produced.
//!
//! The runner writes each backup to a directory on the **node that fired the
//! run**, and there is no shared filesystem requirement. On a cluster that
//! makes a plain `read_dir` of the destination a per-node view: every node
//! runs its own tick loop but they all resume from the same Raft-replicated
//! run record, so a cron instant is claimed by whichever node reaches it
//! first and only that node's disk holds the file. An operator connected to
//! any other node sees an empty list and concludes the backups are gone.
//!
//! This module fixes that by recording, in barrier-encrypted (and therefore
//! Raft-replicated) storage, one record per produced file:
//!
//! ```text
//! core/scheduled_exports/backups/<schedule_id>/<filename>
//! ```
//!
//! The record carries the owning node's id, name and API address, so:
//!
//! - the listing endpoint can present every backup in the cluster, annotated
//!   with the node that holds it, from any node; and
//! - a restore can fetch the bytes from the owning node instead of failing
//!   with "backup file not found".
//!
//! Records are metadata only — the backup bytes stay on the node's
//! filesystem. See `features/scheduled-exports.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::schedule::{DestinationKind, ExportFormat, Schedule};

const BACKUPS_PREFIX: &str = "core/scheduled_exports/backups/";

/// Identity of the node a backup file lives on.
///
/// `api_addr` is the server's own `api_addr` config value — the externally
/// reachable base URL an operator (or a peer node) can call. It is `None`
/// when the config does not set one, in which case peers can still see where
/// the file is but cannot fetch it automatically.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRef {
    #[serde(default)]
    pub node_id: Option<u64>,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub api_addr: Option<String>,
}

impl NodeRef {
    /// Whether `other` denotes the same node as `self`.
    ///
    /// Node id is authoritative when both sides have one (a renamed host is
    /// still the same Raft voter); otherwise fall back to the name, which is
    /// all a non-clustered deployment has.
    pub fn is_same(&self, other: &NodeRef) -> bool {
        match (self.node_id, other.node_id) {
            (Some(a), Some(b)) => a == b,
            _ => !self.node_name.is_empty() && self.node_name == other.node_name,
        }
    }

    /// Display label for logs and API responses.
    pub fn label(&self) -> String {
        match (&self.node_name, self.node_id) {
            (name, Some(id)) if !name.is_empty() => format!("{name} (node {id})"),
            (name, None) if !name.is_empty() => name.clone(),
            (_, Some(id)) => format!("node {id}"),
            _ => "unknown node".to_string(),
        }
    }
}

/// One produced backup file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub schedule_id: String,
    /// Bare file name within `dir` — never a path.
    pub filename: String,
    /// Directory on the owning node the file was written to.
    pub dir: String,
    pub size_bytes: u64,
    pub format: ExportFormat,
    /// Hex SHA-256 of the file as written, so a cross-node fetch can be
    /// verified before it is decrypted and imported.
    pub sha256: String,
    /// RFC3339 write time (UTC).
    pub created_at: String,
    #[serde(default, flatten)]
    pub node: NodeRef,
}

/// Hex SHA-256 of a produced backup's bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Stateless helper, same shape as [`super::store::ScheduleStore`]: storage is
/// passed per call so nothing holds an `Arc<dyn Storage>` across seal/unseal.
#[derive(Default, Clone)]
pub struct BackupCatalog;

impl BackupCatalog {
    pub fn new() -> Self {
        Self
    }

    pub async fn put(&self, storage: &dyn Storage, record: &BackupRecord) -> Result<(), RvError> {
        let key = format!("{BACKUPS_PREFIX}{}/{}", record.schedule_id, record.filename);
        let value = serde_json::to_vec(record)?;
        storage.put(&StorageEntry { key, value }).await
    }

    pub async fn get(
        &self,
        storage: &dyn Storage,
        schedule_id: &str,
        filename: &str,
    ) -> Result<Option<BackupRecord>, RvError> {
        let key = format!("{BACKUPS_PREFIX}{schedule_id}/{filename}");
        match storage.get(&key).await? {
            None => Ok(None),
            // A record we cannot parse is treated as absent rather than fatal:
            // the file may still be listed by the local directory scan, and a
            // single bad record must not break the whole listing.
            Some(entry) => Ok(serde_json::from_slice::<BackupRecord>(&entry.value).ok()),
        }
    }

    /// Every recorded backup for a schedule, across all nodes.
    pub async fn list(
        &self,
        storage: &dyn Storage,
        schedule_id: &str,
    ) -> Result<Vec<BackupRecord>, RvError> {
        let prefix = format!("{BACKUPS_PREFIX}{schedule_id}/");
        let keys = storage.list(&prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(entry) = storage.get(&format!("{prefix}{k}")).await? {
                if let Ok(rec) = serde_json::from_slice::<BackupRecord>(&entry.value) {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    pub async fn delete(
        &self,
        storage: &dyn Storage,
        schedule_id: &str,
        filename: &str,
    ) -> Result<(), RvError> {
        storage.delete(&format!("{BACKUPS_PREFIX}{schedule_id}/{filename}")).await
    }

    /// Drop every record belonging to a schedule — called when the schedule
    /// itself is deleted so the catalog does not outlive it.
    pub async fn delete_schedule(
        &self,
        storage: &dyn Storage,
        schedule_id: &str,
    ) -> Result<(), RvError> {
        let prefix = format!("{BACKUPS_PREFIX}{schedule_id}/");
        if let Ok(keys) = storage.list(&prefix).await {
            for k in keys {
                let _ = storage.delete(&format!("{prefix}{k}")).await;
            }
        }
        Ok(())
    }
}

/// One row of the merged listing: what the catalog knows plus what this node
/// can actually see on disk.
#[derive(Debug, Clone, Serialize)]
pub struct BackupEntry {
    pub name: String,
    pub size_bytes: u64,
    /// RFC3339 mtime when this node holds the file; the record's `created_at`
    /// otherwise (all a remote entry can offer).
    pub modified: Option<String>,
    pub format: String,
    #[serde(flatten)]
    pub node: NodeRef,
    /// True when the file is on the filesystem of the node answering this
    /// request — i.e. restorable without a cross-node fetch.
    pub local: bool,
    /// False for a catalog record whose file has since vanished from its
    /// owning node (only ever determinable for `local` entries; a remote
    /// entry is reported as present because this node cannot see the file to
    /// say otherwise).
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Map a backup file name's extension to a known export format, or `None` for
/// files that are not backups we recognise.
pub fn format_of(name: &str) -> Option<&'static str> {
    if name.ends_with(".bvx") {
        Some("bvx")
    } else if name.ends_with(".json") {
        Some("json")
    } else {
        None
    }
}

/// Reject anything that is not a bare file name within the destination
/// directory — path separators or `..` components would escape it.
pub fn valid_filename(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.contains("..")
}

/// The cluster-wide listing for a schedule: every catalog record merged with a
/// scan of this node's destination directory, newest first.
///
/// The local scan is not redundant with the catalog — it also surfaces files
/// written before the catalog existed and files an operator dropped into the
/// directory by hand, both of which must stay restorable.
pub async fn list_backups(
    storage: &dyn Storage,
    sched: &Schedule,
    local_node: &NodeRef,
) -> Result<(String, Vec<BackupEntry>), RvError> {
    let DestinationKind::LocalPath { path: dir } = &sched.destination;
    let dir = dir.clone();

    let catalog = BackupCatalog::new();
    let records = catalog.list(storage, &sched.id).await.unwrap_or_default();

    // What this node can see on disk, by file name.
    let mut on_disk: std::collections::HashMap<String, (u64, Option<String>)> =
        std::collections::HashMap::new();
    if let Ok(read_dir) = std::fs::read_dir(&dir) {
        for entry in read_dir.flatten() {
            let meta = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            // Skip in-flight temp files written by the atomic-rename path.
            if name.starts_with('.') || format_of(&name).is_none() {
                continue;
            }
            let modified = meta
                .modified()
                .ok()
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
            on_disk.insert(name, (meta.len(), modified));
        }
    }

    let mut entries: Vec<BackupEntry> = Vec::with_capacity(records.len() + on_disk.len());

    for rec in records {
        let owned_here = rec.node.is_same(local_node);
        let disk = on_disk.remove(&rec.filename);
        // A file we can see is restorable without a fetch, whoever recorded
        // it — that covers shared storage and manual copies as well as our
        // own runs. `present` can only be judged for files we could see: a
        // peer's record is taken at face value, since this node has no way to
        // know the peer still has it.
        let local = disk.is_some();
        let present = if owned_here { disk.is_some() } else { true };
        let (size_bytes, modified) = match &disk {
            Some((size, modified)) => (*size, modified.clone().or_else(|| Some(rec.created_at.clone()))),
            None => (rec.size_bytes, Some(rec.created_at.clone())),
        };
        entries.push(BackupEntry {
            name: rec.filename.clone(),
            size_bytes,
            modified,
            format: format_of(&rec.filename).unwrap_or("bvx").to_string(),
            node: rec.node,
            local,
            present,
            sha256: Some(rec.sha256),
        });
    }

    // Files on this node with no catalog record: pre-catalog runs, or
    // operator-placed files. They are local by definition.
    for (name, (size_bytes, modified)) in on_disk {
        let format = format_of(&name).unwrap_or("bvx").to_string();
        entries.push(BackupEntry {
            name,
            size_bytes,
            modified,
            format,
            node: local_node.clone(),
            local: true,
            present: true,
            sha256: None,
        });
    }

    // Newest first: by timestamp when known, then name descending so the
    // runner's timestamp-suffixed names fall in chronological order.
    entries.sort_by(|a, b| {
        b.modified.cmp(&a.modified).then_with(|| b.name.cmp(&a.name))
    });

    Ok((dir, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::schema::{ScopeKind, ScopeSpec};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    /// In-memory `Storage`, same shape as the one in `exchange::scope`'s tests.
    #[derive(Default)]
    struct MemStorage {
        inner: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let map = self.inner.lock().unwrap();
            let mut seen = std::collections::BTreeSet::new();
            for k in map.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    if let Some(slash) = rest.find('/') {
                        seen.insert(format!("{}/", &rest[..slash]));
                    } else {
                        seen.insert(rest.to_string());
                    }
                }
            }
            Ok(seen.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let map = self.inner.lock().unwrap();
            Ok(map.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            let mut map = self.inner.lock().unwrap();
            map.insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            let mut map = self.inner.lock().unwrap();
            map.remove(key);
            Ok(())
        }
    }

    /// Unique scratch directory per test (no `tempfile` dev-dep in this crate).
    /// Dropped by the OS, not by us — these hold a couple of tiny files.
    fn scratch_dir(tag: &str) -> String {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bv-backup-catalog-{}-{tag}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.to_string_lossy().into_owned()
    }

    fn node(id: u64, name: &str) -> NodeRef {
        NodeRef {
            node_id: Some(id),
            node_name: name.to_string(),
            api_addr: Some(format!("https://{name}:5200")),
        }
    }

    fn schedule(dir: &str) -> Schedule {
        Schedule {
            id: "sched-1".to_string(),
            name: "daily".to_string(),
            cron: "0 0 3 * * *".to_string(),
            format: ExportFormat::Bvx,
            scope: ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            destination: DestinationKind::LocalPath { path: dir.to_string() },
            password_ref: None,
            allow_plaintext: false,
            comment: None,
            created_at: "2026-07-20T12:00:00Z".to_string(),
            updated_at: "2026-07-20T12:00:00Z".to_string(),
            enabled: true,
        }
    }

    fn record(filename: &str, dir: &str, node: NodeRef) -> BackupRecord {
        BackupRecord {
            schedule_id: "sched-1".to_string(),
            filename: filename.to_string(),
            dir: dir.to_string(),
            size_bytes: 42,
            format: ExportFormat::Bvx,
            sha256: sha256_hex(b"hello"),
            created_at: "2026-07-27T16:34:07Z".to_string(),
            node,
        }
    }

    #[test]
    fn node_ref_identity_prefers_id_over_name() {
        // A renamed host is the same Raft voter.
        assert!(node(1, "old-name").is_same(&node(1, "new-name")));
        assert!(!node(1, "a").is_same(&node(2, "a")));
        // Without ids (non-clustered), the name is all we have.
        let a = NodeRef { node_id: None, node_name: "solo".into(), api_addr: None };
        assert!(a.is_same(&a.clone()));
        let unnamed = NodeRef::default();
        assert!(!unnamed.is_same(&unnamed.clone()));
    }

    #[tokio::test]
    async fn lists_remote_records_and_local_files_together() {
        let dir_path = scratch_dir("both");
        let storage = MemStorage::default();
        let sched = schedule(&dir_path);
        let me = node(1, "bv-1");
        let peer = node(2, "bv-2");

        // One file this node holds, recorded; one only the peer holds.
        std::fs::write(std::path::Path::new(&dir_path).join("mine.bvx"), b"hello").expect("write");
        let catalog = BackupCatalog::new();
        catalog.put(&storage, &record("mine.bvx", &dir_path, me.clone())).await.expect("put");
        catalog.put(&storage, &record("theirs.bvx", "/elsewhere", peer.clone())).await.expect("put");

        let (listed_dir, entries) = list_backups(&storage, &sched, &me).await.expect("list");
        assert_eq!(listed_dir, dir_path);
        assert_eq!(entries.len(), 2, "both nodes' backups must be listed: {entries:?}");

        let mine = entries.iter().find(|e| e.name == "mine.bvx").expect("mine listed");
        assert!(mine.local, "a file on this node is restorable without a fetch");
        assert!(mine.present);
        assert_eq!(mine.size_bytes, 5, "on-disk size wins over the recorded one");

        let theirs = entries.iter().find(|e| e.name == "theirs.bvx").expect("peer backup listed");
        assert!(!theirs.local, "the peer's file needs a cross-node fetch");
        assert!(theirs.present, "this node cannot claim a peer's file is missing");
        assert_eq!(theirs.node.node_id, Some(2));
        assert_eq!(theirs.node.api_addr.as_deref(), Some("https://bv-2:5200"));
    }

    #[tokio::test]
    async fn own_record_without_the_file_is_reported_missing() {
        // The destination was wiped (e.g. an ephemeral container path): the
        // record survives replication, so the listing can say the file is
        // gone instead of silently showing nothing.
        let dir_path = scratch_dir("missing");
        let storage = MemStorage::default();
        let sched = schedule(&dir_path);
        let me = node(1, "bv-1");

        BackupCatalog::new()
            .put(&storage, &record("gone.bvx", &dir_path, me.clone()))
            .await
            .expect("put");

        let (_, entries) = list_backups(&storage, &sched, &me).await.expect("list");
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].present, "our own record with no file on disk is missing");
        assert!(!entries[0].local);
    }

    #[tokio::test]
    async fn uncatalogued_local_files_stay_listed() {
        // Files written before the catalog existed, or dropped in by hand.
        let dir_path = scratch_dir("legacy");
        let storage = MemStorage::default();
        let dir = std::path::Path::new(&dir_path);
        std::fs::write(dir.join("legacy.bvx"), b"x").expect("write");
        std::fs::write(dir.join(".tmp-in-flight.bvx"), b"x").expect("write");
        std::fs::write(dir.join("notes.txt"), b"x").expect("write");

        let me = node(1, "bv-1");
        let (_, entries) = list_backups(&storage, &schedule(&dir_path), &me).await.expect("list");

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["legacy.bvx"], "temp + non-backup files are skipped");
        assert!(entries[0].local && entries[0].present);
        assert_eq!(entries[0].node.node_id, Some(1));
    }

    #[test]
    fn filename_validation_rejects_traversal() {
        assert!(valid_filename("a-20260727T163407Z.bvx"));
        assert!(!valid_filename(""));
        assert!(!valid_filename("../../etc/passwd"));
        assert!(!valid_filename("sub/dir.bvx"));
        assert!(!valid_filename("sub\\dir.bvx"));
    }
}
