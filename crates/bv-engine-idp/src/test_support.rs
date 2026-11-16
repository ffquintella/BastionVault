//! An in-memory `Storage` for the Phase 2 unit tests, with read-failure
//! injection by key prefix.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

#[derive(Default)]
pub struct MemStorage {
    map: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_gets_under: Mutex<Option<String>>,
}

#[maybe_async::maybe_async]
impl Storage for MemStorage {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        let map = self.map.lock().unwrap();
        let mut out: Vec<String> = Vec::new();
        for key in map.keys().filter(|k| k.starts_with(prefix)) {
            let rest = &key[prefix.len()..];
            let child = match rest.find('/') {
                Some(i) => rest[..=i].to_string(),
                None => rest.to_string(),
            };
            if !out.contains(&child) {
                out.push(child);
            }
        }
        Ok(out)
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        tokio::task::yield_now().await;
        if self.fail_gets_under.lock().unwrap().as_deref().is_some_and(|p| key.starts_with(p)) {
            return Err(RvError::ErrString("injected read failure".into()));
        }
        let map = self.map.lock().unwrap();
        Ok(map.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
    }

    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        tokio::task::yield_now().await;
        self.map.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
}

impl MemStorage {
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn raw_put(&self, key: &str, value: &[u8]) {
        self.map.lock().unwrap().insert(key.to_string(), value.to_vec());
    }

    pub fn raw_get(&self, key: &str) -> Option<Vec<u8>> {
        self.map.lock().unwrap().get(key).cloned()
    }

    pub fn fail_gets_under(&self, prefix: Option<&str>) {
        *self.fail_gets_under.lock().unwrap() = prefix.map(str::to_string);
    }

    pub fn count_under(&self, prefix: &str) -> usize {
        self.map.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).count()
    }
}

// ─── Phase 5: a directory, the gate's fakes and the providers' audit ──

pub use federation_fixture::*;

mod federation_fixture {
    use std::collections::HashMap;

    use chrono::Utc;
    use serde_json::{Map, Value};

    use super::*;
    use crate::{
        entitlement::{
            gate::{
                DenyReason, IssueAuditSink, IssueDenied, IssueEvent, IssueGate, IssueGrant, IssueRequest,
                NamespaceLookup,
            },
            model::EntitlementSource,
            store::{BoundNamespace, EntitlementStore, EntitlementWrite, EnvironmentWrite},
        },
        kernel_api::namespace::NamespaceRef,
        logical::Request,
        posix::{
            model::IdentityState,
            store::{IdentityWrite, PosixStore},
        },
        provider::{federation::FederationAudit, Authorizer},
    };

    #[derive(Default)]
    pub struct FakeNamespaces {
        pub map: Mutex<HashMap<String, NamespaceRef>>,
    }

    #[maybe_async::maybe_async]
    impl NamespaceLookup for FakeNamespaces {
        async fn resolve(&self, path: &str) -> Result<Option<NamespaceRef>, RvError> {
            Ok(self.map.lock().unwrap().get(path).cloned())
        }
    }

    /// The gate's `idp.issue` / `idp.issue-denied` events.
    #[derive(Default)]
    pub struct IssueEvents {
        pub events: Mutex<Vec<(&'static str, Map<String, Value>)>>,
    }

    #[maybe_async::maybe_async]
    impl IssueAuditSink for IssueEvents {
        async fn record(&self, name: &'static str, event: &IssueEvent, _req: Option<&Request>) -> Result<(), RvError> {
            self.events.lock().unwrap().push((name, event.fields()?));
            Ok(())
        }
    }

    impl IssueEvents {
        /// `name:provider:reason` of every event so far, then cleared.
        pub fn take(&self) -> Vec<String> {
            let mut events = self.events.lock().unwrap();
            let out = events
                .iter()
                .map(|(n, f)| {
                    format!("{n}:{}:{}", f["provider"].as_str().unwrap_or(""), f["reason"].as_str().unwrap_or("allow"))
                })
                .collect();
            events.clear();
            out
        }
    }

    /// The providers' own events; `refuse` makes one event name fail.
    #[derive(Default)]
    pub struct FedEvents {
        pub events: Mutex<Vec<(&'static str, Map<String, Value>)>>,
        pub refuse: Mutex<Option<&'static str>>,
    }

    #[maybe_async::maybe_async]
    impl FederationAudit for FedEvents {
        async fn record(
            &self,
            name: &'static str,
            fields: Map<String, Value>,
            _req: Option<&Request>,
        ) -> Result<(), RvError> {
            if *self.refuse.lock().unwrap() == Some(name) {
                return Err(RvError::ErrString("injected audit failure".into()));
            }
            self.events.lock().unwrap().push((name, fields));
            Ok(())
        }
    }

    impl FedEvents {
        pub fn take(&self) -> Vec<(&'static str, Map<String, Value>)> {
            std::mem::take(&mut *self.events.lock().unwrap())
        }
    }

    /// A provider that reads the identity instead of asking the gate: the
    /// mutation the "gate is required" tests run against.
    pub struct SkipGate {
        pub posix: Arc<PosixStore>,
    }

    #[maybe_async::maybe_async]
    impl Authorizer for SkipGate {
        async fn check(&self, req: &IssueRequest, _http: Option<&Request>) -> Result<IssueGrant, IssueDenied> {
            let denied = IssueDenied { reason: DenyReason::StoreError };
            let id = self.posix.get_identity(&req.entity_id).await.ok().flatten().ok_or(denied)?;
            Ok(IssueGrant {
                entity_id: id.entity_id,
                login: id.login,
                uid: id.uid,
                primary_gid: id.primary_gid,
                gids: id.gids,
                display_name: id.display_name,
                environment: req.environment.clone(),
                namespace: req.environment.clone(),
                namespace_uuid: String::new(),
                roles: req.roles.clone().unwrap_or_else(|| vec!["ops".into()]),
                policies: Vec::new(),
                not_after: None,
            })
        }
    }

    /// Identities, environments and entitlements behind a real gate.
    pub struct Directory {
        pub posix: Arc<PosixStore>,
        pub authz: Arc<EntitlementStore>,
        pub namespaces: Arc<FakeNamespaces>,
        pub issue_events: Arc<IssueEvents>,
    }

    impl Directory {
        pub fn gate(&self) -> IssueGate {
            IssueGate::new(
                Some(self.posix.clone()),
                Some(self.authz.clone()),
                self.namespaces.clone(),
                self.issue_events.clone(),
            )
        }

        pub fn skip_gate(&self) -> SkipGate {
            SkipGate { posix: self.posix.clone() }
        }
    }

    /// Environments `prod` (roles ops, readonly) and `dev` (ops). Alice
    /// (`e-alice`, uid 80000, "Alice & Co <ops>") holds prod ops+readonly and
    /// dev ops; dora (disabled) and remy (removed) held prod ops; nora holds
    /// nothing.
    #[maybe_async::maybe_async]
    pub async fn directory() -> Directory {
        let posix = Arc::new(PosixStore::new(MemStorage::new_arc() as Arc<dyn Storage>));
        let authz = Arc::new(EntitlementStore::new(MemStorage::new_arc() as Arc<dyn Storage>));
        let namespaces = Arc::new(FakeNamespaces::default());
        for ns in ["prod", "dev"] {
            let r = NamespaceRef { uuid: format!("u-{ns}"), path: ns.into() };
            namespaces.map.lock().unwrap().insert(ns.into(), r);
        }
        for (name, roles) in [("prod", &["ops", "readonly"][..]), ("dev", &["ops"][..])] {
            let w = EnvironmentWrite {
                name: name.into(),
                namespace: Some(BoundNamespace { path: name.into(), uuid: format!("u-{name}") }),
                roles: Some(roles.iter().map(|r| (r.to_string(), vec![format!("{name}-{r}")])).collect()),
                description: None,
            };
            authz.put_environment(w).await.unwrap();
        }
        for (id, login) in [("e-alice", "alice"), ("e-dora", "dora"), ("e-remy", "remy"), ("e-nora", "nora")] {
            let display = (id == "e-alice").then(|| "Alice & Co <ops>".to_string());
            let w = IdentityWrite {
                entity_id: id.into(),
                login: Some(login.into()),
                display_name: display,
                ..Default::default()
            };
            posix.create_or_update(w).await.unwrap();
        }
        let now = Utc::now();
        for (id, env, roles) in [
            ("e-alice", "prod", &["ops", "readonly"][..]),
            ("e-alice", "dev", &["ops"][..]),
            ("e-dora", "prod", &["ops"][..]),
            ("e-remy", "prod", &["ops"][..]),
        ] {
            let grant = EntitlementWrite {
                entity_id: id.into(),
                environment: env.into(),
                roles: roles.iter().map(|r| r.to_string()).collect(),
                not_after: None,
                source: EntitlementSource::Manual,
                granted_by: "root".into(),
            };
            authz.put_entitlement(&posix, grant, now).await.unwrap();
        }
        posix.transition("e-dora", IdentityState::Disabled, None).await.unwrap();
        posix.transition("e-remy", IdentityState::Disabled, None).await.unwrap();
        posix.transition("e-remy", IdentityState::Removed, None).await.unwrap();
        Directory { posix, authz, namespaces, issue_events: Arc::new(IssueEvents::default()) }
    }
}
