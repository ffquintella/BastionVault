//! ABI 1.4 admin grants: `sql-gate` and `resource-credentials`
//! (features/sql-browser.md §9.2, §5.4). The manifest key requests; the grant
//! approves. Both are pinned to `Capabilities::canonical_sha256`, so any change
//! to the plugin's capability block voids them until re-approved.

use serde::{Deserialize, Serialize};

use super::manifest::{PluginManifest, ResourceCredentialKind};
use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

/// The record version this host writes and the only one it accepts.
pub const GRANT_RECORD_VERSION: u32 = 1;

/// Which ABI 1.4 grant. Each has its own sibling prefix of
/// `core/plugins/engine/grants/` (a key and a directory of one name cannot
/// coexist on the file backend; see `provider::GRANT_PREFIX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlGrantKind {
    /// `sql_gate = true`: SQL target, authorization and MFA-ticket calls.
    SqlGate,
    /// `resource_credentials = ["sql"]`: credential release.
    ResourceCredentials,
}

impl SqlGrantKind {
    pub const ALL: [SqlGrantKind; 2] = [SqlGrantKind::SqlGate, SqlGrantKind::ResourceCredentials];

    /// The route segment: `v2/sys/plugins/<name>/grants/<segment>`.
    pub fn segment(self) -> &'static str {
        match self {
            SqlGrantKind::SqlGate => "sql-gate",
            SqlGrantKind::ResourceCredentials => "resource-credentials",
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            SqlGrantKind::SqlGate => "core/plugins/engine/sql-gate-grants/",
            SqlGrantKind::ResourceCredentials => "core/plugins/engine/resource-credential-grants/",
        }
    }

    /// Does `manifest` request what this grant approves?
    pub fn requested_by(self, manifest: &PluginManifest) -> bool {
        match self {
            SqlGrantKind::SqlGate => manifest.capabilities.sql_gate,
            SqlGrantKind::ResourceCredentials => {
                manifest.capabilities.requests_resource_credentials(ResourceCredentialKind::Sql)
            }
        }
    }

    fn key(self, name: &str) -> String {
        format!("{}{name}", self.prefix())
    }
}

/// One approval, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Record version ([`GRANT_RECORD_VERSION`]). A record of any other
    /// version is read as absent: an older host never honours a newer grant.
    pub v: u32,
    pub granted_by: String,
    pub granted_at: String,
    /// `Capabilities::canonical_sha256` of the manifest at approval time.
    pub capability_sha256: String,
}

/// `Ok(None)` when never granted. A record that does not parse, or of an
/// unknown version, is read as absent (fail closed).
pub async fn get(storage: &dyn Storage, kind: SqlGrantKind, name: &str) -> Result<Option<CapabilityGrant>, RvError> {
    let Some(entry) = storage.get(&kind.key(name)).await? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice::<CapabilityGrant>(&entry.value).ok().filter(|g| g.v == GRANT_RECORD_VERSION))
}

/// Approve what `manifest` requests. Refuses a plugin that does not request
/// it: an unrequested capability can never be granted.
pub async fn put(
    storage: &dyn Storage,
    kind: SqlGrantKind,
    manifest: &PluginManifest,
    granted_by: &str,
    granted_at: String,
) -> Result<CapabilityGrant, RvError> {
    if !kind.requested_by(manifest) {
        return Err(RvError::ErrString(format!(
            "plugin `{}` does not request the `{}` capability; nothing to grant",
            manifest.name,
            kind.segment()
        )));
    }
    let grant = CapabilityGrant {
        v: GRANT_RECORD_VERSION,
        granted_by: granted_by.to_string(),
        granted_at,
        capability_sha256: manifest.capabilities.canonical_sha256(),
    };
    storage.put(&StorageEntry { key: kind.key(&manifest.name), value: serde_json::to_vec(&grant)? }).await?;
    Ok(grant)
}

/// Revoke. Idempotent.
pub async fn delete(storage: &dyn Storage, kind: SqlGrantKind, name: &str) -> Result<(), RvError> {
    storage.delete(&kind.key(name)).await
}

/// The single "is this grant live?" gate: the active manifest requests it,
/// and a stored approval is pinned to its current capability block. Any read
/// error is "not live".
pub async fn is_live(storage: &dyn Storage, kind: SqlGrantKind, manifest: &PluginManifest) -> bool {
    if !kind.requested_by(manifest) {
        return false;
    }
    match get(storage, kind, &manifest.name).await {
        Ok(Some(g)) => g.capability_sha256 == manifest.capabilities.canonical_sha256(),
        _ => false,
    }
}

/// Fixtures shared by the ABI 1.4 tests in this directory.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::plugins::manifest::RuntimeKind;

    #[derive(Default)]
    pub struct MemStorage {
        inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.keys().filter_map(|k| k.strip_prefix(prefix).map(str::to_string)).collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            Ok(self.inner.lock().unwrap().get(key).map(|v| StorageEntry { key: key.into(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// The §9.3 manifest sketch: a concurrent long-lived SQL plugin.
    pub fn sql_manifest() -> PluginManifest {
        let mut m = PluginManifest {
            name: "dbms-management".into(),
            version: "0.1.0".into(),
            plugin_type: "sql-browser".into(),
            engine_type: None,
            runtime: RuntimeKind::Process,
            abi_version: "1.4".into(),
            sha256: "0".repeat(64),
            size: 1,
            capabilities: Default::default(),
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        };
        let c = &mut m.capabilities;
        c.long_lived = true;
        c.concurrent = true;
        c.caller_identity = true;
        c.audit_emit = true;
        c.sql_gate = true;
        c.resource_credentials = vec![ResourceCredentialKind::Sql];
        m
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{sql_manifest, MemStorage};
    use super::*;

    #[tokio::test]
    async fn grants_are_not_live_until_approved_and_are_independent() {
        let s = MemStorage::default();
        let m = sql_manifest();
        for k in SqlGrantKind::ALL {
            assert!(!is_live(&s, k, &m).await);
        }
        put(&s, SqlGrantKind::SqlGate, &m, "admin", "t".into()).await.unwrap();
        assert!(is_live(&s, SqlGrantKind::SqlGate, &m).await);
        assert!(!is_live(&s, SqlGrantKind::ResourceCredentials, &m).await);
        // Neither touches the network or provider grant records.
        assert!(crate::plugins::grants::get(&s, &m.name).await.unwrap().is_none());
        assert!(crate::plugins::provider::get_grant(&s, &m.name).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn any_change_to_the_capability_block_voids_the_grant() {
        let s = MemStorage::default();
        let m = sql_manifest();
        for k in SqlGrantKind::ALL {
            put(&s, k, &m, "admin", "t".into()).await.unwrap();
        }
        let mut changed = m.clone();
        changed.capabilities.storage_prefix = Some("dbms/".into());
        for k in SqlGrantKind::ALL {
            assert!(is_live(&s, k, &m).await);
            assert!(!is_live(&s, k, &changed).await, "{k:?}");
        }
        // A new version with an identical block keeps the approval.
        let mut bumped = m.clone();
        bumped.version = "0.2.0".into();
        assert!(is_live(&s, SqlGrantKind::SqlGate, &bumped).await);
    }

    #[tokio::test]
    async fn an_unrequested_capability_is_never_granted_nor_live() {
        let s = MemStorage::default();
        let mut m = sql_manifest();
        put(&s, SqlGrantKind::ResourceCredentials, &m, "admin", "t".into()).await.unwrap();
        m.capabilities.resource_credentials.clear();
        assert!(put(&s, SqlGrantKind::ResourceCredentials, &m, "admin", "t".into()).await.is_err());
        assert!(!is_live(&s, SqlGrantKind::ResourceCredentials, &m).await);
    }

    /// Malformed or future-version records fail closed.
    #[tokio::test]
    async fn malformed_and_unknown_version_records_read_as_absent() {
        let s = MemStorage::default();
        let m = sql_manifest();
        let pin = m.capabilities.canonical_sha256();
        let key = SqlGrantKind::SqlGate.key(&m.name);
        for raw in [
            b"not json".to_vec(),
            br#"{"granted_by":"a"}"#.to_vec(),
            serde_json::to_vec(&serde_json::json!({
                "v": 2, "granted_by": "a", "granted_at": "t", "capability_sha256": pin
            }))
            .unwrap(),
            serde_json::to_vec(&serde_json::json!({
                "granted_by": "a", "granted_at": "t", "capability_sha256": pin
            }))
            .unwrap(),
        ] {
            s.put(&StorageEntry { key: key.clone(), value: raw }).await.unwrap();
            assert!(get(&s, SqlGrantKind::SqlGate, &m.name).await.unwrap().is_none());
            assert!(!is_live(&s, SqlGrantKind::SqlGate, &m).await);
        }
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_closes_the_gate() {
        let s = MemStorage::default();
        let m = sql_manifest();
        put(&s, SqlGrantKind::SqlGate, &m, "admin", "t".into()).await.unwrap();
        delete(&s, SqlGrantKind::SqlGate, &m.name).await.unwrap();
        delete(&s, SqlGrantKind::SqlGate, &m.name).await.unwrap();
        assert!(!is_live(&s, SqlGrantKind::SqlGate, &m).await);
    }
}
