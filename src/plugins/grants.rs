//! Admin capability grants — Extensibility v2 (app extensions).
//!
//! Spec: [features/plugin-app-extensions.md](../../features/plugin-app-extensions.md)
//! § "The admin network grant".
//!
//! The network capability is **double-gated**: a plugin's manifest may
//! *request* outbound hosts (`capabilities.app.net.hosts`), but that
//! request grants nothing on its own. An admin must additionally
//! authorize the request at install; that authorization is a
//! server-side record stored here, at
//! `core/plugins/engine/grants/<name>` (sibling of the quarantine
//! markers). Two independent keys must turn before a plugin touches the
//! network.
//!
//! The grant is pinned to a SHA-256 over the manifest's *requested* net
//! block (`capability_sha256`). Any change to the requested capability —
//! even a narrowing — changes the hash and voids the grant until an
//! admin re-approves. This is the anti-"hostile update" guarantee: a new
//! version cannot inherit the previous version's grant.
//!
//! Server ACLs remain the sole authority over vault *data*; this record
//! only governs the client-side `bvx.net_http` enforcer (and, in a
//! later phase, a server-side `bv.net_http`). It never widens what the
//! signed-in user can read.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::manifest::{NetCapabilities, PluginManifest};
use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

/// Storage key prefix for grant records. One key per plugin name.
const PREFIX: &str = "core/plugins/engine/grants/";

fn key(name: &str) -> String {
    format!("{PREFIX}{name}")
}

/// The admin authorization for a plugin's network capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetGrant {
    /// Authorized outbound hosts — a subset of (or equal to) the
    /// manifest's requested `capabilities.app.net.hosts`.
    pub hosts: Vec<String>,
    /// Entity id of the admin who approved the grant.
    pub granted_by: String,
    /// RFC 3339 timestamp of the approval.
    pub granted_at: String,
    /// SHA-256 (hex) over the manifest's *requested* net capability at
    /// approval time. Re-checked on every read; a mismatch means the
    /// requested capability changed and the grant is stale.
    pub capability_sha256: String,
}

/// The full grant record persisted per plugin. A struct (rather than a
/// bare `NetGrant`) so future capability grants slot in without a
/// storage-format migration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginGrants {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetGrant>,
}

/// SHA-256 (hex) over the canonical JSON of a requested net capability.
/// `None` when the plugin requests no network — an unrequested
/// capability can never be granted, so it has no pin.
///
/// A struct serializes deterministically per build, and `hosts` order is
/// author-meaningful and preserved, so this hash is stable for a given
/// request and changes whenever the request changes.
pub fn net_capability_sha256(net: &Option<NetCapabilities>) -> Option<String> {
    let net = net.as_ref()?;
    let bytes = serde_json::to_vec(net).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Read the stored grant record for a plugin. `Ok(None)` when no admin
/// has ever granted anything. A record whose JSON no longer parses is
/// treated as absent (fail-closed) rather than erroring the caller.
pub async fn get(storage: &dyn Storage, name: &str) -> Result<Option<PluginGrants>, RvError> {
    match storage.get(&key(name)).await? {
        None => Ok(None),
        Some(entry) => Ok(serde_json::from_slice(&entry.value).ok()),
    }
}

/// Create or replace the network grant for a plugin.
///
/// Refuses when:
/// - the manifest requests no network capability (nothing to grant);
/// - `granted_hosts` is a **superset** of the manifest's requested hosts
///   — an admin may narrow the request but never widen it.
///
/// The grant's `capability_sha256` pins to the *manifest's* requested
/// net block (author intent), not the possibly-narrower granted set, so
/// the pin invalidates whenever the author changes what they ask for.
pub async fn put_net(
    storage: &dyn Storage,
    name: &str,
    manifest: &PluginManifest,
    granted_hosts: Vec<String>,
    granted_by: &str,
    granted_at: String,
) -> Result<NetGrant, RvError> {
    let requested = manifest.capabilities.app.net.as_ref().ok_or_else(|| {
        RvError::ErrString(format!(
            "plugin `{name}` requests no network capability; nothing to grant"
        ))
    })?;

    let requested_set: std::collections::BTreeSet<&String> = requested.hosts.iter().collect();
    for h in &granted_hosts {
        if !requested_set.contains(h) {
            return Err(RvError::ErrString(format!(
                "grant host `{h}` is not in the plugin's requested allowlist; a grant may narrow but never widen the manifest request"
            )));
        }
    }

    let capability_sha256 = net_capability_sha256(&manifest.capabilities.app.net)
        .expect("net is Some here, so the pin is always computable");

    let grant = NetGrant {
        hosts: granted_hosts,
        granted_by: granted_by.to_string(),
        granted_at,
        capability_sha256,
    };
    let record = PluginGrants { net: Some(grant.clone()) };
    storage
        .put(&StorageEntry {
            key: key(name),
            value: serde_json::to_vec(&record)?,
        })
        .await?;
    Ok(grant)
}

/// Revoke all grants for a plugin. Idempotent — deleting an absent
/// record is not an error.
pub async fn delete(storage: &dyn Storage, name: &str) -> Result<(), RvError> {
    storage.delete(&key(name)).await
}

/// The single "is the network grant live?" gate. Returns the granted
/// hosts iff (a) a grant exists and (b) its `capability_sha256` matches
/// the *active* manifest's current net request. A stale pin (the
/// manifest's net request changed since approval) yields `None` — the
/// plugin is treated as ungranted until an admin re-approves.
///
/// Used both by the active-surfaces aggregator (to decide what to ship
/// to clients) and, in a later phase, by the enforcer itself.
pub async fn active_net_hosts(
    storage: &dyn Storage,
    name: &str,
    active_manifest: &PluginManifest,
) -> Result<Option<Vec<String>>, RvError> {
    let Some(grant) = get(storage, name).await?.and_then(|g| g.net) else {
        return Ok(None);
    };
    let Some(expected) = net_capability_sha256(&active_manifest.capabilities.app.net) else {
        // The active version requests no network — any prior grant is moot.
        return Ok(None);
    };
    if grant.capability_sha256 == expected {
        Ok(Some(grant.hosts))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::AppCapabilities;

    /// Minimal in-memory `Storage` for the grant round-trip tests
    /// (mirrors the catalog's test double).
    #[derive(Default)]
    struct MemStorage {
        inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.keys()
                .filter_map(|k| k.strip_prefix(prefix).map(|r| r.to_string()))
                .collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
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

    fn manifest_with_net(hosts: &[&str]) -> PluginManifest {
        let mut m = PluginManifest {
            name: "webhook-notify".into(),
            version: "1.0.0".into(),
            plugin_type: "secret-engine".into(),
            runtime: Default::default(),
            abi_version: "1.1".into(),
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
        m.capabilities.app = AppCapabilities {
            net: Some(NetCapabilities {
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                https_only: true,
            }),
            ..Default::default()
        };
        m
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let s = MemStorage::default();
        let m = manifest_with_net(&["hooks.example.com", "*.status.example.net"]);
        let grant = put_net(
            &s,
            "webhook-notify",
            &m,
            vec!["hooks.example.com".into()],
            "entity-123",
            "2026-07-09T00:00:00Z".into(),
        )
        .await
        .unwrap();
        assert_eq!(grant.granted_by, "entity-123");
        let stored = get(&s, "webhook-notify").await.unwrap().unwrap();
        assert_eq!(stored.net.unwrap().hosts, vec!["hooks.example.com".to_string()]);
    }

    #[tokio::test]
    async fn refuses_superset_grant() {
        let s = MemStorage::default();
        let m = manifest_with_net(&["hooks.example.com"]);
        let err = put_net(
            &s,
            "webhook-notify",
            &m,
            vec!["hooks.example.com".into(), "evil.example.com".into()],
            "entity-123",
            "2026-07-09T00:00:00Z".into(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:?}").contains("not in the plugin's requested allowlist"));
    }

    #[tokio::test]
    async fn refuses_grant_when_no_net_requested() {
        let s = MemStorage::default();
        let mut m = manifest_with_net(&[]);
        m.capabilities.app.net = None;
        let err = put_net(&s, "p", &m, vec![], "e", "t".into()).await.unwrap_err();
        assert!(format!("{err:?}").contains("no network capability"));
    }

    #[tokio::test]
    async fn active_hosts_honours_pin() {
        let s = MemStorage::default();
        let m = manifest_with_net(&["hooks.example.com", "extra.example.com"]);
        put_net(
            &s,
            "webhook-notify",
            &m,
            vec!["hooks.example.com".into()],
            "e",
            "t".into(),
        )
        .await
        .unwrap();
        // Same manifest → grant is live.
        let live = active_net_hosts(&s, "webhook-notify", &m).await.unwrap();
        assert_eq!(live, Some(vec!["hooks.example.com".to_string()]));

        // A changed net request (even a narrowing) voids the grant.
        let m2 = manifest_with_net(&["hooks.example.com"]);
        let stale = active_net_hosts(&s, "webhook-notify", &m2).await.unwrap();
        assert_eq!(stale, None, "changed capability_sha256 must void the grant");
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let s = MemStorage::default();
        delete(&s, "never-existed").await.unwrap();
        assert!(get(&s, "never-existed").await.unwrap().is_none());
    }

    #[test]
    fn pin_is_none_without_request() {
        assert!(net_capability_sha256(&None).is_none());
    }
}
