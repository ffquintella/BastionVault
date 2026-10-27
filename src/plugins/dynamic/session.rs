//! Per-RPC state shared between the dynamic host and the plugin's host calls.
//!
//! One [`DynamicSession`] lives for one host-to-plugin call. The runtimes hand
//! it to the `dynamic_*` host-call handlers, which record what the plugin
//! asked for (a lease, pool slots) for the host to act on once the call ends.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc, Mutex,
};

use bv_dynamic::{audit::Actor, records::LeaseRequest};
use zeroize::Zeroizing;

use crate::storage::Storage;

/// Plugin events one session may emit through `dynamic_audit_emit`.
pub const MAX_PLUGIN_EVENTS: u32 = 16;

/// Which host-to-plugin call a session belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicVerb {
    Role,
    Generate,
    Renew,
    Revoke,
    RotateRoot,
    Proxy,
}

impl DynamicVerb {
    pub fn op(self) -> &'static str {
        match self {
            Self::Role => "dynamic.role",
            Self::Generate => "dynamic.generate",
            Self::Renew => "dynamic.renew",
            Self::Revoke => "dynamic.revoke",
            Self::RotateRoot => "dynamic.rotate_root",
            Self::Proxy => "proxy",
        }
    }
}

pub struct DynamicSession {
    pub verb: DynamicVerb,
    /// Host-generated id of the mount, scoping pool keys.
    pub mount_id: String,
    /// The mount's own storage view, where the host keeps connection records.
    pub storage: Option<Arc<dyn Storage>>,
    pub role: Option<String>,
    pub connection: Option<String>,
    pub target_identity: Option<String>,
    pub lease_id: Option<String>,
    pub actor: Option<Actor>,
    pub request_id: Option<String>,
    /// Credential material of this call, searched for in plugin audit text.
    secrets: Vec<Zeroizing<String>>,
    lease_request: Mutex<Option<LeaseRequest>>,
    grants: Mutex<Vec<super::pool::HeldGrant>>,
    plugin_events: AtomicU32,
    violated: AtomicBool,
}

impl DynamicSession {
    pub fn new(verb: DynamicVerb, mount_id: &str, storage: Option<Arc<dyn Storage>>) -> Self {
        Self {
            verb,
            mount_id: mount_id.to_string(),
            storage,
            role: None,
            connection: None,
            target_identity: None,
            lease_id: None,
            actor: None,
            request_id: None,
            secrets: Vec::new(),
            lease_request: Mutex::new(None),
            grants: Mutex::new(Vec::new()),
            plugin_events: AtomicU32::new(0),
            violated: AtomicBool::new(false),
        }
    }

    /// Remember a secret so plugin-supplied audit text cannot carry it.
    pub fn with_secret(mut self, secret: &str) -> Self {
        self.secrets.push(Zeroizing::new(secret.to_string()));
        self
    }

    pub fn secrets(&self) -> Vec<&str> {
        self.secrets.iter().map(|s| s.as_str()).collect()
    }

    /// Record the plugin's lease request. Only one per session.
    pub fn set_lease_request(&self, request: LeaseRequest) -> Result<(), &'static str> {
        let mut slot = self.lease_request.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_some() {
            return Err("dynamic_lease_register was already called for this credential");
        }
        *slot = Some(request);
        Ok(())
    }

    pub fn take_lease_request(&self) -> Option<LeaseRequest> {
        self.lease_request.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Count one plugin-emitted event; false once the session's budget is spent.
    pub fn admit_plugin_event(&self) -> bool {
        self.plugin_events.fetch_add(1, Ordering::SeqCst) < MAX_PLUGIN_EVENTS
    }

    /// Keep a pool slot for the rest of the call; released when the session drops.
    pub fn hold_grant(&self, grant: super::pool::HeldGrant) {
        self.grants.lock().unwrap_or_else(|p| p.into_inner()).push(grant);
    }

    pub fn held_grants(&self) -> usize {
        self.grants.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// The plugin made a host call its manifest does not declare.
    pub fn mark_violation(&self) {
        self.violated.store(true, Ordering::SeqCst);
    }

    pub fn violated(&self) -> bool {
        self.violated.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for DynamicSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicSession")
            .field("verb", &self.verb)
            .field("mount_id", &self.mount_id)
            .field("role", &self.role)
            .field("connection", &self.connection)
            .field("target_identity", &self.target_identity)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}
