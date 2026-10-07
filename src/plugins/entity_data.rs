//! Entity-scoped plugin data, seen from the administrator's side
//! (features/self-accounts.md §4.7, Phase 5).
//!
//! Two things live here, neither of which reads a stored *value*:
//!
//! * **Usage counts** for `GET v2/sys/plugins/<name>/entity-data`: how many
//!   records each entity holds under an entity-scoped plugin, found by
//!   *listing* keys. The plugin is never invoked and no value is read, so an
//!   administrator learns that a user holds N accounts and nothing else — no
//!   label, login name, target or secret (Open question 2: counts only).
//! * **The automatic purge and its retry.** When an entity loses its last
//!   alias its plugin data is orphaned secret material, so the identity module
//!   asks the plugin host to purge it. A purge that fails is audited and leaves
//!   a *pending-purge marker*; markers are retried on the next automatic purge
//!   and on every administrator entity-data purge, until the delete succeeds.
//!   A marker is written only for an entity the identity module found with no
//!   alias left, and the identity store never re-attaches an alias to an
//!   existing entity (a recreated principal gets a new one), so a retry
//!   purges without asking again.
//!
//! The record convention the counts rely on is part of the provider contract:
//! a record is a directory `accounts/<id>/` holding a `meta` key. A plugin
//! that stores something else still gets its entities listed (with a count of
//! zero), so the administrator can see and purge them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map};

use super::manifest::StorageScope;
use super::PluginCatalog;
use crate::{
    errors::RvError,
    kernel_api::VaultCtx,
    logical::Operation,
    storage::{Storage, StorageEntry},
};

/// Under the plugin runtime's own `engine/` prefix, which the purge walk skips.
pub const PENDING_PURGE_PREFIX: &str = "core/plugins/engine/pending-purges/";

/// A record of an entity-scoped plugin: `accounts/<id>/meta`.
pub const RECORDS_PREFIX: &str = "accounts/";
pub const RECORD_MARKER: &str = "meta";

/// Markers retried per pass, so one pass cannot turn a failing backend into
/// an unbounded walk inside a principal delete.
pub const MAX_RETRIES_PER_PASS: usize = 16;

// ── usage counts ────────────────────────────────────────────────────────

/// One entity's share of a plugin's data. Counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityUsage {
    pub entity_id: String,
    /// The entity's primary name (or first alias name), from the identity
    /// store, so the administrator can tell who it is. Never plugin data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub accounts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityDataUsage {
    pub entities: Vec<EntityUsage>,
    pub total_accounts: usize,
    pub total_entities: usize,
    /// Automatic purges that failed and wait for a retry (any plugin).
    pub pending_purges: usize,
}

fn dirs(names: Vec<String>) -> impl Iterator<Item = String> {
    names.into_iter().filter_map(|n| n.strip_suffix('/').map(str::to_string))
}

fn is_entity_id(id: &str) -> bool {
    super::runtime::entity_data_root("x", id).is_some()
}

/// Whether anything at all is stored under `prefix`. Listing only; stops at
/// the first leaf. An emptied directory (the file backend keeps it) is not
/// data.
async fn has_any_leaf(storage: &dyn Storage, prefix: &str) -> Result<bool, RvError> {
    let mut stack = vec![prefix.to_string()];
    while let Some(p) = stack.pop() {
        for name in storage.list(&p).await? {
            match name.strip_suffix('/') {
                Some(dir) => stack.push(format!("{p}{dir}/")),
                None => return Ok(true),
            }
        }
    }
    Ok(false)
}

/// `entity_id -> records` for every entity holding data under `plugin`.
/// Listing only: no `get` is ever issued, so no value — secret or not — is
/// read.
pub async fn count_entity_records(storage: &dyn Storage, plugin: &str) -> Result<BTreeMap<String, usize>, RvError> {
    let base = format!("core/plugins/{plugin}/data/entity/");
    let mut out = BTreeMap::new();
    for entity in dirs(storage.list(&base).await?) {
        if !is_entity_id(&entity) {
            continue;
        }
        let root = format!("{base}{entity}/");
        let records_root = format!("{root}{RECORDS_PREFIX}");
        let mut records = 0usize;
        for id in dirs(storage.list(&records_root).await?) {
            if storage.list(&format!("{records_root}{id}/")).await?.iter().any(|k| k == RECORD_MARKER) {
                records += 1;
            }
        }
        if records > 0 || has_any_leaf(storage, &root).await? {
            out.insert(entity, records);
        }
    }
    Ok(out)
}

/// A name for the administrator: the entity's primary name, else its first
/// alias name. `None` when the identity store does not know the entity.
async fn entity_display_name(core: &dyn VaultCtx, entity_id: &str) -> Option<String> {
    let identity = core.identity()?;
    let profile = identity.entity_profile(entity_id).await.ok().flatten()?;
    if !profile.primary_name.trim().is_empty() {
        return Some(profile.primary_name);
    }
    profile.aliases.first().map(|a| a.name.clone()).filter(|n| !n.trim().is_empty())
}

/// The counts behind `GET v2/sys/plugins/<name>/entity-data`. `Ok(None)` when
/// the plugin is not registered or does not declare `storage_scope =
/// "entity"` (the route answers 404).
pub async fn entity_data_usage(core: &dyn VaultCtx, plugin: &str) -> Result<Option<EntityDataUsage>, RvError> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    // The name comes from the request path: refuse anything that could not
    // be a catalog directory before it is used in a storage key.
    if super::runtime::entity_data_root(plugin, "x").is_none() {
        return Ok(None);
    }
    let Some(manifest) = PluginCatalog::new().get_manifest(storage, plugin).await? else {
        return Ok(None);
    };
    if manifest.name != plugin || manifest.capabilities.storage_scope != StorageScope::Entity {
        return Ok(None);
    }
    let counts = count_entity_records(storage, &manifest.name).await?;
    let mut entities = Vec::with_capacity(counts.len());
    for (entity_id, accounts) in counts {
        let display_name = entity_display_name(core, &entity_id).await;
        entities.push(EntityUsage { entity_id, display_name, accounts });
    }
    let total_accounts = entities.iter().map(|e| e.accounts).sum();
    let total_entities = entities.len();
    let pending_purges = pending_purges(storage).await?.len();
    Ok(Some(EntityDataUsage { entities, total_accounts, total_entities, pending_purges }))
}

// ── purge with retry ────────────────────────────────────────────────────

/// `core/plugins/engine/pending-purges/<entity_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPurge {
    pub v: u32,
    pub entity_id: String,
    pub first_failed_at: String,
    pub last_failed_at: String,
    pub attempts: u32,
}

fn marker_key(entity_id: &str) -> String {
    format!("{PENDING_PURGE_PREFIX}{entity_id}")
}

/// Entity ids with a pending purge. Listing only.
pub async fn pending_purges(storage: &dyn Storage) -> Result<Vec<String>, RvError> {
    let mut ids: Vec<String> =
        storage.list(PENDING_PURGE_PREFIX).await?.into_iter().filter(|n| is_entity_id(n)).collect();
    ids.sort();
    Ok(ids)
}

async fn read_marker(storage: &dyn Storage, entity_id: &str) -> Option<PendingPurge> {
    let e = storage.get(&marker_key(entity_id)).await.ok().flatten()?;
    serde_json::from_slice(&e.value).ok()
}

async fn note_failure(storage: &dyn Storage, entity_id: &str, now: &str) -> u32 {
    let marker = match read_marker(storage, entity_id).await {
        Some(mut m) => {
            m.last_failed_at = now.to_string();
            m.attempts = m.attempts.saturating_add(1);
            m
        }
        None => PendingPurge {
            v: 1,
            entity_id: entity_id.to_string(),
            first_failed_at: now.to_string(),
            last_failed_at: now.to_string(),
            attempts: 1,
        },
    };
    let attempts = marker.attempts;
    let written = match serde_json::to_vec(&marker) {
        Ok(value) => storage.put(&StorageEntry { key: marker_key(entity_id), value }).await,
        Err(e) => Err(e.into()),
    };
    if let Err(e) = written {
        // The barrier is failing writes as well as deletes. Nothing else can
        // record the debt, so say so loudly; the admin purge route remains.
        log::error!(
            "could not record a pending purge for entity {entity_id} ({e}); purge it with \
             DELETE v2/sys/plugins/<name>/entity-data/{entity_id}"
        );
    }
    attempts
}

/// Purge every entity-scoped plugin's data for `entity_id`, and keep the
/// marker in step: cleared on success, created or bumped on failure.
/// Returns the purge's own result.
pub async fn purge_and_track(storage: &dyn Storage, entity_id: &str, now: &str) -> Result<(), RvError> {
    match super::provider::purge_entity_tree(storage, entity_id).await {
        Ok(()) => {
            if let Err(e) = storage.delete(&marker_key(entity_id)).await {
                log::warn!("purged entity {entity_id} but could not clear its pending-purge marker: {e}");
            }
            Ok(())
        }
        Err(e) => {
            let attempts = note_failure(storage, entity_id, now).await;
            log::error!("purging the plugin data of entity {entity_id} failed (attempt {attempts}): {e}");
            Err(e)
        }
    }
}

/// Why a purge ran. Recorded in the audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeTrigger {
    /// The identity module removed the entity's last alias.
    LastAliasRemoved,
    /// A pending-purge marker, retried.
    Retry,
}

impl PurgeTrigger {
    fn as_str(self) -> &'static str {
        match self {
            PurgeTrigger::LastAliasRemoved => "last-alias-removed",
            PurgeTrigger::Retry => "pending-purge-retry",
        }
    }
}

/// The audit entry of an automatic purge (no request token: the host does
/// it). Path `sys/plugins/entity-data/<entity_id>`, operation `delete`.
async fn audit_purge(
    core: &dyn VaultCtx,
    entity_id: &str,
    trigger: PurgeTrigger,
    outcome: &str,
    err: Option<&RvError>,
) {
    let mut body = Map::new();
    body.insert("trigger".into(), json!(trigger.as_str()));
    body.insert("outcome".into(), json!(outcome));
    let error = err.map(|e| format!("{e}"));
    crate::audit::emit_sys_audit(
        core,
        "",
        &format!("sys/plugins/entity-data/{entity_id}"),
        Operation::Delete,
        Some(body),
        error.as_deref(),
    )
    .await;
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// The automatic purge for an entity that lost its last alias: purge, audit
/// the outcome, then retry earlier failures. The caller (the identity module)
/// logs a failure and never undoes the principal delete for it.
pub async fn purge_orphaned_entity(core: &dyn VaultCtx, entity_id: &str) -> Result<(), RvError> {
    if !is_entity_id(entity_id) {
        return Err(RvError::ErrRequestInvalid);
    }
    let result = {
        let barrier = core.barrier();
        purge_and_track(barrier.as_storage(), entity_id, &now()).await
    };
    let outcome = if result.is_ok() { "purged" } else { "failed" };
    audit_purge(core, entity_id, PurgeTrigger::LastAliasRemoved, outcome, result.as_ref().err()).await;
    retry_pending_purges(core, Some(entity_id)).await;
    result
}

/// What one retry pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetrySummary {
    pub purged: usize,
    pub failed: usize,
}

/// Retry up to [`MAX_RETRIES_PER_PASS`] pending purges, skipping `skip` (the
/// entity the caller has just tried). Each attempt is audited.
pub async fn retry_pending_purges(core: &dyn VaultCtx, skip: Option<&str>) -> RetrySummary {
    let mut summary = RetrySummary::default();
    let ids = {
        let barrier = core.barrier();
        match pending_purges(barrier.as_storage()).await {
            Ok(ids) => ids,
            Err(e) => {
                log::warn!("could not list pending plugin-data purges: {e}");
                return summary;
            }
        }
    };
    for id in ids.into_iter().filter(|id| Some(id.as_str()) != skip).take(MAX_RETRIES_PER_PASS) {
        let result = {
            let barrier = core.barrier();
            purge_and_track(barrier.as_storage(), &id, &now()).await
        };
        let outcome = if result.is_ok() { "purged" } else { "failed" };
        audit_purge(core, &id, PurgeTrigger::Retry, outcome, result.as_ref().err()).await;
        match result {
            Ok(()) => summary.purged += 1,
            Err(_) => summary.failed += 1,
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use serde_json::Value;

    use super::*;

    /// In-memory storage that counts `get`s and can fail deletes under a
    /// prefix.
    #[derive(Default)]
    struct Mem {
        inner: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
        gets: AtomicUsize,
        fail_deletes_under: std::sync::Mutex<Option<String>>,
        deny_gets: AtomicBool,
    }

    #[async_trait::async_trait]
    impl Storage for Mem {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            let mut out = std::collections::BTreeSet::new();
            for k in g.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    match rest.split_once('/') {
                        Some((d, _)) => out.insert(format!("{d}/")),
                        None => out.insert(rest.to_string()),
                    };
                }
            }
            Ok(out.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            assert!(!self.deny_gets.load(Ordering::SeqCst), "a value was read: {key}");
            let g = self.inner.lock().unwrap();
            Ok(g.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            if let Some(p) = self.fail_deletes_under.lock().unwrap().as_deref() {
                if key.starts_with(p) {
                    return Err(RvError::ErrString("injected delete failure".into()));
                }
            }
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }

    impl Mem {
        fn set(&self, key: &str, value: &str) {
            self.inner.lock().unwrap().insert(key.to_string(), value.as_bytes().to_vec());
        }
        fn has(&self, key: &str) -> bool {
            self.inner.lock().unwrap().contains_key(key)
        }
    }

    const BASE: &str = "core/plugins/self-accounts/data/entity/";

    fn seeded() -> Mem {
        let s = Mem::default();
        for (k, v) in [
            // e1: two accounts (meta, secret, seen).
            ("e1/accounts/sa_a/meta", r#"{"label":"Domain admin","username":"felipe.adm"}"#),
            ("e1/accounts/sa_a/secret", r#"{"password":"S3CRET-ONE"}"#),
            ("e1/accounts/sa_a/seen", r#"{"v":1,"targets":[]}"#),
            ("e1/accounts/sa_b/meta", r#"{"label":"Router","username":"admin"}"#),
            ("e1/accounts/sa_b/secret", r#"{"password":"S3CRET-TWO"}"#),
            // e2: one account, and a secret whose meta is gone (not a record).
            ("e2/accounts/sa_c/meta", r#"{"label":"x"}"#),
            ("e2/accounts/sa_d/secret", r#"{"password":"S3CRET-ORPHAN"}"#),
            // e3: data, but nothing in the record layout.
            ("e3/other/thing", "S3CRET-OTHER"),
        ] {
            s.set(&format!("{BASE}{k}"), v);
        }
        // Another plugin's data and a path trick are not counted here.
        s.set("core/plugins/other/data/entity/e1/accounts/sa_z/meta", "{}");
        s.set(&format!("{BASE}bad.id/accounts/sa_x/meta"), "{}");
        s
    }

    #[tokio::test]
    async fn counts_records_per_entity_by_listing_only() {
        let s = seeded();
        s.deny_gets.store(true, Ordering::SeqCst);
        let counts = count_entity_records(&s, "self-accounts").await.unwrap();
        assert_eq!(s.gets.load(Ordering::SeqCst), 0, "counting must never read a value");
        let want: BTreeMap<String, usize> =
            [("e1".to_string(), 2), ("e2".to_string(), 1), ("e3".to_string(), 0)].into_iter().collect();
        assert_eq!(counts, want);
    }

    #[tokio::test]
    async fn no_data_counts_nothing() {
        let s = Mem::default();
        assert!(count_entity_records(&s, "self-accounts").await.unwrap().is_empty());
        assert!(pending_purges(&s).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_failed_purge_leaves_a_marker_that_a_later_success_clears() {
        let s = seeded();
        *s.fail_deletes_under.lock().unwrap() = Some(format!("{BASE}e1/"));
        assert!(purge_and_track(&s, "e1", "t1").await.is_err());
        assert_eq!(pending_purges(&s).await.unwrap(), vec!["e1".to_string()]);
        assert!(purge_and_track(&s, "e1", "t2").await.is_err());
        let m = read_marker(&s, "e1").await.unwrap();
        assert_eq!((m.attempts, m.first_failed_at.as_str(), m.last_failed_at.as_str()), (2, "t1", "t2"));
        // The marker holds no plugin data.
        let raw = String::from_utf8(s.inner.lock().unwrap()[&marker_key("e1")].clone()).unwrap();
        assert!(!raw.contains("S3CRET"), "{raw}");

        *s.fail_deletes_under.lock().unwrap() = None;
        purge_and_track(&s, "e1", "t3").await.unwrap();
        assert!(pending_purges(&s).await.unwrap().is_empty());
        assert!(!s.has(&format!("{BASE}e1/accounts/sa_a/secret")));
        // Only that entity, across every plugin.
        assert!(!s.has("core/plugins/other/data/entity/e1/accounts/sa_z/meta"));
        assert!(s.has(&format!("{BASE}e2/accounts/sa_c/meta")));
    }

    #[tokio::test]
    async fn markers_are_listed_by_valid_entity_id_only() {
        let s = Mem::default();
        s.set(&format!("{PENDING_PURGE_PREFIX}e9"), "{}");
        s.set(&format!("{PENDING_PURGE_PREFIX}not..valid"), "{}");
        assert_eq!(pending_purges(&s).await.unwrap(), vec!["e9".to_string()]);
    }

    // ── against a real vault: identity, catalog, audit ──────────────────

    use crate::plugins::manifest::{
        Capabilities, CredentialProviderCap, PluginManifest, ProviderSelection, RuntimeKind,
    };
    use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};
    use sha2::{Digest, Sha256};

    fn manifest(name: &str, scope: StorageScope, bin: &[u8]) -> PluginManifest {
        let entity = scope == StorageScope::Entity;
        PluginManifest {
            name: name.into(),
            version: "0.1.0".into(),
            plugin_type: "secret".into(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.3".into(),
            sha256: hex::encode(Sha256::digest(bin)),
            size: bin.len() as u64,
            capabilities: Capabilities {
                storage_prefix: Some(String::new()),
                caller_identity: entity,
                storage_scope: scope,
                credential_provider: entity.then(|| CredentialProviderCap {
                    display_name: "Self-account".into(),
                    selection: ProviderSelection::Operator,
                    protocols: vec!["ssh".into()],
                    secret_kinds: vec!["password".into()],
                }),
                ..Default::default()
            },
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        }
    }

    async fn register(core: &crate::core::Core, name: &str, scope: StorageScope) {
        let bin = format!("placeholder for {name}").into_bytes();
        crate::plugins::verifier::write_accept_unsigned(core.barrier.as_storage(), true).await.unwrap();
        PluginCatalog::new().put(core.barrier.as_storage(), &manifest(name, scope, &bin), &bin).await.unwrap();
    }

    async fn put(core: &crate::core::Core, key: &str, value: &str) {
        core.barrier
            .as_storage()
            .put(&StorageEntry { key: key.into(), value: value.as_bytes().to_vec() })
            .await
            .unwrap();
    }

    async fn login_entity(core: &crate::core::Core, root: &str, user: &str) -> String {
        let obj = |v: Value| v.as_object().cloned();
        test_write_api(core, root, &format!("auth/pass/users/{user}"), true, obj(json!({ "password": "hunter22XX!" })))
            .await
            .unwrap();
        let r = test_write_api(
            core,
            "",
            &format!("auth/pass/login/{user}"),
            true,
            obj(json!({ "password": "hunter22XX!" })),
        )
        .await
        .unwrap()
        .unwrap();
        r.auth.unwrap().metadata.get("entity_id").cloned().unwrap()
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn usage_names_entities_and_refuses_non_entity_plugins() {
        let (_vault, core, root) = new_unseal_test_bastion_vault("entity_data_usage").await;
        test_write_api(core.as_ref(), &root, "sys/auth/pass", true, json!({ "type": "userpass" }).as_object().cloned())
            .await
            .unwrap();
        let alice = login_entity(core.as_ref(), &root, "alice").await;
        register(core.as_ref(), "self-accounts", StorageScope::Entity).await;
        register(core.as_ref(), "plain", StorageScope::Plugin).await;

        let empty = entity_data_usage(core.as_ref(), "self-accounts").await.unwrap().unwrap();
        assert_eq!((empty.total_entities, empty.total_accounts, empty.entities.len()), (0, 0, 0));

        put(core.as_ref(), &format!("{BASE}{alice}/accounts/sa_a/meta"), r#"{"label":"Domain admin"}"#).await;
        put(core.as_ref(), &format!("{BASE}{alice}/accounts/sa_a/secret"), r#"{"password":"S3CRET"}"#).await;
        put(core.as_ref(), &format!("{BASE}ghost/accounts/sa_b/meta"), "{}").await;
        let u = entity_data_usage(core.as_ref(), "self-accounts").await.unwrap().unwrap();
        assert_eq!((u.total_entities, u.total_accounts), (2, 2));
        let a = u.entities.iter().find(|e| e.entity_id == alice).unwrap();
        assert_eq!((a.display_name.as_deref(), a.accounts), (Some("alice"), 1));
        let g = u.entities.iter().find(|e| e.entity_id == "ghost").unwrap();
        assert_eq!(g.display_name, None, "an entity the identity store does not know has no name");
        let text = serde_json::to_string(&u).unwrap();
        assert!(!text.contains("S3CRET") && !text.contains("Domain admin"), "{text}");

        assert!(entity_data_usage(core.as_ref(), "plain").await.unwrap().is_none());
        assert!(entity_data_usage(core.as_ref(), "missing").await.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn an_automatic_purge_retries_earlier_failures() {
        let (_vault, core, _root) = new_unseal_test_bastion_vault("entity_data_retry").await;
        let first = format!("{BASE}orphan-1/accounts/sa_a/secret");
        let second = format!("{BASE}orphan-2/accounts/sa_a/secret");
        let bystander = format!("{BASE}live-1/accounts/sa_a/secret");
        put(core.as_ref(), &first, "S3CRET-1").await;
        put(core.as_ref(), &second, "S3CRET-2").await;
        put(core.as_ref(), &bystander, "S3CRET-LIVE").await;
        // orphan-1's purge failed earlier and left a marker.
        let m = PendingPurge {
            v: 1,
            entity_id: "orphan-1".into(),
            first_failed_at: "t".into(),
            last_failed_at: "t".into(),
            attempts: 1,
        };
        put(core.as_ref(), &marker_key("orphan-1"), &serde_json::to_string(&m).unwrap()).await;

        // orphan-2 loses its last alias: its purge also settles orphan-1.
        purge_orphaned_entity(core.as_ref(), "orphan-2").await.unwrap();
        let storage = core.barrier.as_storage();
        assert!(storage.get(&second).await.unwrap().is_none());
        assert!(storage.get(&first).await.unwrap().is_none(), "the pending purge was retried");
        assert!(storage.get(&bystander).await.unwrap().is_some(), "no other entity is touched");
        assert!(pending_purges(storage).await.unwrap().is_empty());
        // An id that could escape its prefix is refused before anything runs.
        assert!(purge_orphaned_entity(core.as_ref(), "../x").await.is_err());
        assert_eq!(retry_pending_purges(core.as_ref(), None).await, RetrySummary::default());
    }

    /// `GET v2/sys/plugins/<name>/entity-data` over HTTP: admin-only, counts
    /// only, 404 for a plugin without entity-scoped data, v2 only.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn the_usage_route_is_admin_only_and_returns_counts_only() {
        let mut server = crate::test_utils::TestHttpServer::new("entity_data_usage_http", true).await;
        let root = server.root_token.clone();
        let core = server.core.clone();
        register(core.as_ref(), "self-accounts", StorageScope::Entity).await;
        register(core.as_ref(), "plain", StorageScope::Plugin).await;

        // A token with nothing but the baseline `default` policy.
        let (status, created) = server
            .write("auth/token/create", json!({ "policies": ["default"] }).as_object().cloned(), Some(&root))
            .unwrap();
        assert_eq!(status, 200, "{created}");
        let user = created["auth"]["client_token"].as_str().unwrap().to_string();

        server.url_prefix = server.url_prefix.replace("/v1", "/v2");
        let path = "sys/plugins/self-accounts/entity-data";
        let (status, body) = server.read(path, Some(&root)).unwrap();
        assert_eq!(status, 200, "{body}");
        assert_eq!((body["total_entities"].as_u64(), body["total_accounts"].as_u64()), (Some(0), Some(0)), "{body}");
        assert_eq!(body["entities"], json!([]));

        // One entity, one account whose every stored value is distinctive.
        for (k, v) in [
            (
                "e-1/accounts/sa_a/meta",
                r#"{"label":"LABEL-Domain-admin","username":"LOGIN-felipe.adm","applies_to":{"targets":["TARGET.corp.example.com"]}}"#,
            ),
            ("e-1/accounts/sa_a/secret", r#"{"password":"S3CRET-VALUE"}"#),
            ("e-1/accounts/sa_a/seen", r#"{"v":1,"targets":[]}"#),
        ] {
            put(core.as_ref(), &format!("{BASE}{k}"), v).await;
        }
        let (status, body) = server.read(path, Some(&root)).unwrap();
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["entities"], json!([{ "entity_id": "e-1", "accounts": 1 }]), "{body}");
        assert_eq!((body["total_entities"].as_u64(), body["total_accounts"].as_u64()), (Some(1), Some(1)));
        let text = body.to_string();
        for needle in ["S3CRET", "LABEL", "LOGIN", "TARGET", "sa_a"] {
            assert!(!text.contains(needle), "{needle} reached the administrator: {text}");
        }

        // Not for a caller without the admin grant.
        let (status, _) = server.read(path, Some(&user)).unwrap();
        assert_eq!(status, 403);
        // 404 for a plugin without entity-scoped data, and for an unknown one.
        assert_eq!(server.read("sys/plugins/plain/entity-data", Some(&root)).unwrap().0, 404);
        assert_eq!(server.read("sys/plugins/missing/entity-data", Some(&root)).unwrap().0, 404);

        // v2 only: v1 is frozen (no route; the empty 404 body is not JSON).
        server.url_prefix = server.url_prefix.replace("/v2", "/v1");
        assert!(!matches!(server.read(path, Some(&root)), Ok((200, _))));
    }
}
