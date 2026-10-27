//! Per-RPC state shared between the dynamic host and the plugin's host calls.
//!
//! One [`DynamicSession`] lives for one host-to-plugin call. The runtimes hand
//! it to the `dynamic_*` host-call handlers, which record what the plugin
//! asked for (a lease, pool slots) for the host to act on once the call ends.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc, Mutex,
};

use bv_dynamic::{audit::Actor, connector::ExecPlan, records::LeaseRequest};
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
    /// Credential material of this call, searched for in plugin audit text
    /// and redacted from errors. Grows when a plugin presents a connection's
    /// root secret for a host execution.
    secrets: Mutex<Vec<Zeroizing<String>>>,
    /// The statements the host rendered for this call, which a plugin may ask
    /// the host to run once (`dynamic_pool_checkout` with `execute`).
    plan: Mutex<Option<ExecPlan>>,
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
            secrets: Mutex::new(Vec::new()),
            plan: Mutex::new(None),
            lease_request: Mutex::new(None),
            grants: Mutex::new(Vec::new()),
            plugin_events: AtomicU32::new(0),
            violated: AtomicBool::new(false),
        }
    }

    /// Remember a secret so plugin-supplied audit text cannot carry it.
    pub fn with_secret(self, secret: &str) -> Self {
        self.add_secret(secret);
        self
    }

    /// [`Self::with_secret`] on a live session.
    pub fn add_secret(&self, secret: &str) {
        if !secret.is_empty() {
            self.secrets.lock().unwrap_or_else(|p| p.into_inner()).push(Zeroizing::new(secret.to_string()));
        }
    }

    /// A copy of this call's secrets (wiped on drop); `.refs()` for redaction.
    pub fn secrets(&self) -> SecretSet {
        SecretSet(self.secrets.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    /// Attach the statements the host rendered for this call.
    pub fn with_plan(self, plan: ExecPlan) -> Self {
        *self.plan.lock().unwrap_or_else(|p| p.into_inner()) = Some(plan);
        self
    }

    /// The rendered statements, once: a second execution request finds none.
    pub fn take_plan(&self) -> Option<ExecPlan> {
        self.plan.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    pub fn has_plan(&self) -> bool {
        self.plan.lock().unwrap_or_else(|p| p.into_inner()).is_some()
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

    /// Take the held slot `slot` out for a host execution; [`Self::hold_grant`]
    /// puts it back. Dropped instead (and so returned to the pool) when the
    /// execution is cancelled.
    pub fn take_grant(&self, slot: u64) -> Option<super::pool::HeldGrant> {
        let mut grants = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        let at = grants.iter().position(|g| g.id == slot)?;
        Some(grants.swap_remove(at))
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
            .field("secrets", &self.secrets.lock().map(|s| s.len()).unwrap_or(0))
            .field("plan", &self.has_plan())
            .finish_non_exhaustive()
    }
}

/// A copy of a session's secrets. Wiped on drop; no `Debug`.
pub struct SecretSet(Vec<Zeroizing<String>>);

impl SecretSet {
    pub fn refs(&self) -> Vec<&str> {
        self.0.iter().map(|s| s.as_str()).collect()
    }
}
