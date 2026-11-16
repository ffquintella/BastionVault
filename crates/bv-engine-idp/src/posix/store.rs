//! The workforce-identity store and the serialized allocation path.
//!
//! Every write runs under a process-local mutex plus the storage backend's
//! lock (Raft-replicated on hiqlite, a lock file on the file backend), and
//! allocator state is persisted *before* the records that use an id, so a
//! crash can burn an id but never hand it out twice.

use std::{any::Any, sync::Arc};

use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::{
    allocator::AllocatorState,
    events,
    model::{
        decode_versioned, validate_display_name, validate_entity_id, validate_import_id, validate_login,
        validate_reason, validate_supplementary_gid, IdKind, IdRange, IdentityState, IndexEntry, PosixConfig,
        PosixError, Transition, UidSource, WorkforceIdentity, MAX_SUPPLEMENTARY_GIDS, RECORD_VERSION,
    },
};

/// Name of the storage-backend lock that serializes every write.
pub const STORAGE_LOCK_NAME: &str = "bv-idp/posix";
pub const IDENTITY_PREFIX: &str = "identities/";
const CONFIG_KEY: &str = "config";
const LOGIN_INDEX: &str = "index/login/";
const UID_INDEX: &str = "index/uid/";
const GID_INDEX: &str = "index/gid/";

/// The in-process half of the write lock; one per process, shared by every
/// vault instance in it (writes here are rare admin operations).
static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Both halves of the write lock. Field order is drop order: the backend
/// lock is released before the process-local one.
struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

fn alloc_key(kind: IdKind) -> &'static str {
    match kind {
        IdKind::Uid => "alloc/uid",
        IdKind::Gid => "alloc/gid",
    }
}

fn id_index(kind: IdKind) -> &'static str {
    match kind {
        IdKind::Uid => UID_INDEX,
        IdKind::Gid => GID_INDEX,
    }
}

/// A create-or-update request, already type-checked by the HTTP layer.
#[derive(Debug, Clone, Default)]
pub struct IdentityWrite {
    pub entity_id: String,
    pub login: Option<String>,
    pub uid: Option<u32>,
    pub primary_gid: Option<u32>,
    pub uid_source: Option<UidSource>,
    pub display_name: Option<String>,
    pub gids: Option<Vec<u32>>,
}

/// A partial update of the allocation ranges.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigUpdate {
    pub uid_min: Option<u32>,
    pub uid_max: Option<u32>,
    pub gid_min: Option<u32>,
    pub gid_max: Option<u32>,
}

pub struct PosixStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl PosixStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    async fn write_lock(&self) -> Result<WriteLock, RvError> {
        let local = LOCAL_WRITE_LOCK.lock().await;
        let cluster = self.storage.lock(STORAGE_LOCK_NAME).await?;
        Ok(WriteLock { _cluster: cluster, _local: local })
    }

    async fn get_record<T: DeserializeOwned>(&self, what: &str, key: &str) -> Result<Option<T>, RvError> {
        match self.storage.get(key).await? {
            None => Ok(None),
            Some(entry) => Ok(Some(decode_versioned(what, &entry.value)?)),
        }
    }

    async fn put_record<T: Serialize + Sync>(&self, key: &str, value: &T) -> Result<(), RvError> {
        self.storage.put(&StorageEntry::new(key, value)?).await
    }

    async fn index_owner(&self, prefix: &str, key: &str) -> Result<Option<String>, RvError> {
        let entry: Option<IndexEntry> = self.get_record("index", &format!("{prefix}{key}")).await?;
        Ok(entry.map(|e| e.entity_id))
    }

    async fn put_index(&self, prefix: &str, key: &str, entity_id: &str) -> Result<(), RvError> {
        let entry = IndexEntry { version: RECORD_VERSION, entity_id: entity_id.to_string() };
        self.put_record(&format!("{prefix}{key}"), &entry).await
    }

    // ─── Reads ──────────────────────────────────────────────────

    /// The stored configuration, or `None` before the first write.
    pub async fn stored_config(&self) -> Result<Option<PosixConfig>, RvError> {
        self.get_record("config", CONFIG_KEY).await
    }

    pub async fn config(&self) -> Result<PosixConfig, RvError> {
        Ok(self.stored_config().await?.unwrap_or_default())
    }

    pub async fn allocator(&self, kind: IdKind) -> Result<AllocatorState, RvError> {
        match self.storage.get(alloc_key(kind)).await? {
            None => Ok(AllocatorState::new(kind)),
            Some(entry) => Ok(AllocatorState::decode(kind, &entry.value)?),
        }
    }

    pub async fn get_identity(&self, entity_id: &str) -> Result<Option<WorkforceIdentity>, RvError> {
        validate_entity_id(entity_id)?;
        let rec: Option<WorkforceIdentity> =
            self.get_record("identity", &format!("{IDENTITY_PREFIX}{entity_id}")).await?;
        if let Some(r) = &rec {
            if r.entity_id != entity_id {
                return Err(
                    PosixError::Corrupt(format!("identity record under `{entity_id}` names another entity")).into()
                );
            }
        }
        Ok(rec)
    }

    pub async fn list_identity_ids(&self) -> Result<Vec<String>, RvError> {
        let mut keys: Vec<String> =
            self.storage.list(IDENTITY_PREFIX).await?.into_iter().filter(|k| !k.ends_with('/')).collect();
        keys.sort();
        Ok(keys)
    }

    pub async fn list_identities(&self) -> Result<Vec<WorkforceIdentity>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(IDENTITY_PREFIX, None).await? {
            out.push(decode_versioned::<WorkforceIdentity>("identity", &entry.value)?);
        }
        out.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        Ok(out)
    }

    // ─── Writes ─────────────────────────────────────────────────

    pub async fn put_config(&self, update: ConfigUpdate) -> Result<PosixConfig, RvError> {
        let _lock = self.write_lock().await?;
        let mut cfg = self.config().await?;
        cfg.uid_range = IdRange {
            min: update.uid_min.unwrap_or(cfg.uid_range.min),
            max: update.uid_max.unwrap_or(cfg.uid_range.max),
        };
        cfg.gid_range = IdRange {
            min: update.gid_min.unwrap_or(cfg.gid_range.min),
            max: update.gid_max.unwrap_or(cfg.gid_range.max),
        };
        cfg.uid_range.validate(IdKind::Uid)?;
        cfg.gid_range.validate(IdKind::Gid)?;
        cfg.version = RECORD_VERSION;
        cfg.updated_at = Some(Utc::now());
        self.put_record(CONFIG_KEY, &cfg).await?;
        log::info!(
            target: "idp",
            "{}: uid_range=[{}, {}] gid_range=[{}, {}]",
            events::CONFIG_UPDATE,
            cfg.uid_range.min,
            cfg.uid_range.max,
            cfg.gid_range.min,
            cfg.gid_range.max
        );
        Ok(cfg)
    }

    /// Allocate (or import) an identity, or update the mutable fields of an
    /// existing one. Returns the record and whether it was created.
    pub async fn create_or_update(&self, w: IdentityWrite) -> Result<(WorkforceIdentity, bool), RvError> {
        validate_entity_id(&w.entity_id)?;
        if let Some(name) = &w.display_name {
            validate_display_name(name)?;
        }
        let _lock = self.write_lock().await?;
        match self.get_identity(&w.entity_id).await? {
            Some(existing) => Ok((self.update_locked(existing, w).await?, false)),
            None => Ok((self.create_locked(w).await?, true)),
        }
    }

    async fn update_locked(&self, mut rec: WorkforceIdentity, w: IdentityWrite) -> Result<WorkforceIdentity, RvError> {
        if rec.state == IdentityState::Removed {
            return Err(PosixError::Conflict("identity is removed; its record is frozen".into()).into());
        }
        let immutable = |field: &str| PosixError::Invalid(format!("{field} is immutable once allocated"));
        if w.login.as_deref().is_some_and(|l| l != rec.login) {
            return Err(immutable("login").into());
        }
        if w.uid.is_some_and(|u| u != rec.uid) {
            return Err(immutable("uid").into());
        }
        if w.primary_gid.is_some_and(|g| g != rec.primary_gid) {
            return Err(immutable("primary_gid").into());
        }
        if w.uid_source.is_some_and(|s| s != rec.uid_source) {
            return Err(immutable("uid_source").into());
        }
        if let Some(requested) = &w.gids {
            let mut gid_state = self.allocator(IdKind::Gid).await?;
            let before = gid_state.clone();
            let gids = self.resolve_supplementary(&rec.entity_id, rec.primary_gid, requested, &mut gid_state).await?;
            if gid_state != before {
                self.put_record(alloc_key(IdKind::Gid), &gid_state).await?;
            }
            rec.gids = gids;
        }
        if let Some(name) = w.display_name {
            rec.display_name = name;
        }
        rec.updated_at = Utc::now();
        self.put_record(&format!("{IDENTITY_PREFIX}{}", rec.entity_id), &rec).await?;
        log::info!(target: "idp", "{}: entity_id={} login={}", events::IDENTITY_UPDATE, rec.entity_id, rec.login);
        Ok(rec)
    }

    async fn create_locked(&self, w: IdentityWrite) -> Result<WorkforceIdentity, RvError> {
        let login = w.login.ok_or_else(|| PosixError::Invalid("login is required to allocate an identity".into()))?;
        validate_login(&login)?;
        if let Some(owner) = self.index_owner(LOGIN_INDEX, &login).await? {
            // The same entity may finish an allocation a crash interrupted.
            if owner != w.entity_id {
                return Err(PosixError::Conflict(format!(
                    "login `{login}` belongs to another identity, current or removed; logins are never reused"
                ))
                .into());
            }
        }

        // Pin the defaults on first use so a later change of the built-in
        // defaults cannot move an existing deployment's ranges.
        let cfg = match self.stored_config().await? {
            Some(cfg) => cfg,
            None => {
                let cfg = PosixConfig::default();
                self.put_record(CONFIG_KEY, &cfg).await?;
                cfg
            }
        };
        let mut uid_state = self.allocator(IdKind::Uid).await?;
        let mut gid_state = self.allocator(IdKind::Gid).await?;
        let source = w.uid_source.unwrap_or(UidSource::Vault);

        let (uid, primary_gid) = match source {
            UidSource::Vault => {
                if w.uid.is_some() || w.primary_gid.is_some() {
                    return Err(PosixError::Invalid(
                        "uid and primary_gid may only be supplied with uid_source=imported".into(),
                    )
                    .into());
                }
                let uid = self.allocate(IdKind::Uid, &mut uid_state, &cfg.uid_range).await?;
                // User-private-group convention: gid == uid when that gid is
                // free and above the gid high-water mark.
                let upg_free = cfg.gid_range.contains(uid)
                    && !gid_state.is_taken(uid)
                    && gid_state.high_water.is_none_or(|h| uid > h)
                    && self.index_owner(GID_INDEX, &uid.to_string()).await?.is_none();
                let gid = if upg_free {
                    gid_state.commit_allocation(uid);
                    uid
                } else {
                    self.allocate(IdKind::Gid, &mut gid_state, &cfg.gid_range).await?
                };
                (uid, gid)
            }
            UidSource::Imported => {
                let uid =
                    w.uid.ok_or_else(|| PosixError::Invalid("uid is required when uid_source is imported".into()))?;
                let gid = w.primary_gid.unwrap_or(uid);
                self.claim_import(IdKind::Uid, uid, &mut uid_state).await?;
                self.claim_import(IdKind::Gid, gid, &mut gid_state).await?;
                (uid, gid)
            }
        };

        let gids = match &w.gids {
            Some(requested) => self.resolve_supplementary(&w.entity_id, primary_gid, requested, &mut gid_state).await?,
            None => Vec::new(),
        };

        // Write order is the crash-safety argument: ids are burned before
        // anything refers to them.
        self.put_record(alloc_key(IdKind::Uid), &uid_state).await?;
        self.put_record(alloc_key(IdKind::Gid), &gid_state).await?;
        self.put_index(UID_INDEX, &uid.to_string(), &w.entity_id).await?;
        self.put_index(GID_INDEX, &primary_gid.to_string(), &w.entity_id).await?;
        self.put_index(LOGIN_INDEX, &login, &w.entity_id).await?;

        let now = Utc::now();
        let rec = WorkforceIdentity {
            version: RECORD_VERSION,
            entity_id: w.entity_id,
            login,
            uid,
            primary_gid,
            gids,
            display_name: w.display_name.unwrap_or_default(),
            state: IdentityState::Active,
            uid_source: source,
            allocated_at: now,
            updated_at: now,
            state_changed_at: None,
            state_reason: None,
        };
        self.put_record(&format!("{IDENTITY_PREFIX}{}", rec.entity_id), &rec).await?;
        let event = match source {
            UidSource::Vault => events::IDENTITY_ALLOCATE,
            UidSource::Imported => events::IDENTITY_IMPORT,
        };
        log::info!(
            target: "idp",
            "{event}: entity_id={} login={} uid={} primary_gid={}",
            rec.entity_id,
            rec.login,
            rec.uid,
            rec.primary_gid
        );
        Ok(rec)
    }

    /// Next free id, re-checked against the per-id index so a stale
    /// allocator record (an old read, a damaged `used` set) cannot reissue.
    async fn allocate(&self, kind: IdKind, state: &mut AllocatorState, range: &IdRange) -> Result<u32, RvError> {
        loop {
            let candidate = state.next_free(range)?;
            if self.index_owner(id_index(kind), &candidate.to_string()).await?.is_some() {
                log::warn!(
                    target: "idp",
                    "{} {candidate} is claimed in the index but free in the allocator record; skipping it",
                    kind.as_str()
                );
                state.mark_used(candidate);
                continue;
            }
            state.commit_allocation(candidate);
            return Ok(candidate);
        }
    }

    async fn claim_import(&self, kind: IdKind, id: u32, state: &mut AllocatorState) -> Result<(), RvError> {
        validate_import_id(kind, id)?;
        if state.is_taken(id) || self.index_owner(id_index(kind), &id.to_string()).await?.is_some() {
            return Err(PosixError::Conflict(format!(
                "imported {} {id} collides with an id that is allocated, imported, retired or in use as a group",
                kind.as_str()
            ))
            .into());
        }
        state.mark_used(id);
        Ok(())
    }

    /// Validate supplementary groups and reserve them so the allocator never
    /// hands one out as somebody's private group. A gid that is another
    /// identity's private group (current or retired) is refused.
    async fn resolve_supplementary(
        &self,
        entity_id: &str,
        primary_gid: u32,
        requested: &[u32],
        gid_state: &mut AllocatorState,
    ) -> Result<Vec<u32>, RvError> {
        let mut gids = requested.to_vec();
        gids.sort_unstable();
        gids.dedup();
        gids.retain(|g| *g != primary_gid);
        if gids.len() > MAX_SUPPLEMENTARY_GIDS {
            return Err(PosixError::Invalid(format!("at most {MAX_SUPPLEMENTARY_GIDS} supplementary gids")).into());
        }
        for gid in &gids {
            validate_supplementary_gid(*gid)?;
            if let Some(owner) = self.index_owner(GID_INDEX, &gid.to_string()).await? {
                if owner != entity_id {
                    return Err(PosixError::Conflict(format!(
                        "gid {gid} is the private group of another identity, current or removed"
                    ))
                    .into());
                }
            }
            gid_state.mark_used(*gid);
        }
        Ok(gids)
    }

    /// Apply a lifecycle transition. Removal tombstones the uid and primary
    /// gid before the record changes state.
    pub async fn transition(
        &self,
        entity_id: &str,
        to: IdentityState,
        reason: Option<String>,
    ) -> Result<WorkforceIdentity, RvError> {
        validate_entity_id(entity_id)?;
        let reason = reason.filter(|r| !r.trim().is_empty());
        if let Some(r) = &reason {
            validate_reason(r)?;
        }
        let _lock = self.write_lock().await?;
        let mut rec = self
            .get_identity(entity_id)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no workforce identity for entity `{entity_id}`")))?;
        let transition = rec.state.transition(to)?;
        let event = match transition {
            Transition::NoOp => return Ok(rec),
            Transition::Disable => events::IDENTITY_DISABLE,
            Transition::Reinstate => events::IDENTITY_REINSTATE,
            Transition::Remove => {
                let mut uid_state = self.allocator(IdKind::Uid).await?;
                uid_state.retire(rec.uid);
                self.put_record(alloc_key(IdKind::Uid), &uid_state).await?;
                let mut gid_state = self.allocator(IdKind::Gid).await?;
                gid_state.retire(rec.primary_gid);
                self.put_record(alloc_key(IdKind::Gid), &gid_state).await?;
                events::IDENTITY_REMOVE
            }
        };
        let now = Utc::now();
        rec.state = to;
        rec.state_changed_at = Some(now);
        rec.state_reason = reason;
        rec.updated_at = now;
        self.put_record(&format!("{IDENTITY_PREFIX}{entity_id}"), &rec).await?;
        log::info!(target: "idp", "{event}: entity_id={} login={} uid={}", rec.entity_id, rec.login, rec.uid);
        Ok(rec)
    }
}

#[cfg(test)]
mod tests;
