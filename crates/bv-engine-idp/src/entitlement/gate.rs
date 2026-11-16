//! The issue gate: the single chokepoint every provider runs before it
//! issues an identity credential. It fails closed: each step either proves
//! the next precondition or ends in a deny, and an error of any kind (an
//! unreadable store, a record that does not decode, an unavailable namespace
//! registry, an audit device that refuses the event) is a deny too.

use std::{collections::BTreeSet, sync::Arc};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    errors::RvError,
    kernel_api::{
        namespace::{normalize_path, NamespaceRef},
        VaultCtx,
    },
    logical::Request,
    posix::{
        model::{validate_entity_id, IdentityState},
        store::PosixStore,
    },
};

use super::{
    events,
    model::{normalize_role_list, validate_environment_name, EnvironmentState},
    store::EntitlementStore,
};

/// Longest caller-supplied string an audit event carries; longer values are
/// cut and marked, so a malformed request cannot fill the log.
pub const MAX_EVENT_ARG_LEN: usize = 128;
const MAX_PROVIDER_LEN: usize = 32;

/// Resolves a namespace path to its current uuid. `Ok(None)`: no such
/// namespace. `Err`: the registry could not answer (the gate denies).
// `double_must_use` is on the boxed future `async_trait` generates (as for
// every `maybe_async` trait in the workspace); the attribute is the macro's.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub trait NamespaceLookup: Send + Sync {
    async fn resolve(&self, path: &str) -> Result<Option<NamespaceRef>, RvError>;
}

/// Where `idp.issue` / `idp.issue-denied` go. An error from `record` turns an
/// allow into a deny.
// Same macro-generated `double_must_use` as above.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub trait IssueAuditSink: Send + Sync {
    async fn record(&self, name: &'static str, event: &IssueEvent, req: Option<&Request>) -> Result<(), RvError>;
}

/// The vault's namespace registry. No registry means no environment can be
/// resolved, which is an error, never a fallback to root.
pub struct CtxNamespaceLookup {
    pub ctx: Arc<dyn VaultCtx>,
}

#[maybe_async::maybe_async]
impl NamespaceLookup for CtxNamespaceLookup {
    async fn resolve(&self, path: &str) -> Result<Option<NamespaceRef>, RvError> {
        let Some(registry) = self.ctx.namespaces() else {
            return Err(bv_errors::bv_error_response_status!(
                503,
                "the namespace module is unavailable; environments cannot be resolved"
            ));
        };
        registry.resolve(path).await
    }
}

/// The audit path every engine event uses: one `security` log line, plus an
/// `event` entry on the audit broker when a device is enabled. A broker
/// failure is returned, so the gate fails closed on it.
pub struct BrokerIssueAudit {
    pub ctx: Arc<dyn VaultCtx>,
}

#[maybe_async::maybe_async]
impl IssueAuditSink for BrokerIssueAudit {
    async fn record(&self, name: &'static str, event: &IssueEvent, req: Option<&Request>) -> Result<(), RvError> {
        let fields = event.fields()?;
        // `Value`'s `Display` is compact JSON, so no field can break the line.
        log::info!(target: "security", "{name} {}", Value::Object(fields.clone()));
        let Some(broker) = self.ctx.audit_broker() else {
            return Ok(());
        };
        if !broker.has_devices() {
            return Ok(());
        }
        let mut entry = bv_audit::AuditEntry::event(name, fields, req, broker.hmac_key());
        broker.log(&mut entry).await
    }
}

/// What a provider asks the gate.
#[derive(Debug, Clone, Default)]
pub struct IssueRequest {
    pub entity_id: String,
    pub environment: String,
    /// The roles asked for; `None` means every entitled role.
    pub roles: Option<Vec<String>>,
    /// Namespace of the request being served (`""` = root). A non-root
    /// caller may only reach the environment bound to its own namespace.
    pub caller_namespace: String,
    /// Which provider is asking (`ssh`, `radius`, ...), for the audit record.
    pub provider: String,
}

/// Everything a provider needs to build its assertion, and nothing secret.
#[derive(Debug, Clone, PartialEq)]
pub struct IssueGrant {
    pub entity_id: String,
    pub login: String,
    pub uid: u32,
    pub primary_gid: u32,
    pub gids: Vec<u32>,
    pub display_name: String,
    pub environment: String,
    pub namespace: String,
    pub namespace_uuid: String,
    pub roles: Vec<String>,
    /// Union of the roles' ACL policies in the environment's namespace.
    pub policies: Vec<String>,
    pub not_after: Option<DateTime<Utc>>,
}

/// Why the gate said no. The code is what the audit event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    InvalidRequest,
    StoreUnavailable,
    StoreError,
    NoIdentity,
    IdentityDisabled,
    IdentityRemoved,
    UnknownEnvironment,
    EnvironmentRetired,
    NamespaceUnavailable,
    NamespaceMissing,
    NamespaceReplaced,
    NamespaceMismatch,
    NotEntitled,
    EntitlementExpired,
    RoleNotEntitled,
    UnknownRole,
    AuditFailed,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::StoreUnavailable => "store_unavailable",
            Self::StoreError => "store_error",
            Self::NoIdentity => "no_identity",
            Self::IdentityDisabled => "identity_disabled",
            Self::IdentityRemoved => "identity_removed",
            Self::UnknownEnvironment => "unknown_environment",
            Self::EnvironmentRetired => "environment_retired",
            Self::NamespaceUnavailable => "namespace_unavailable",
            Self::NamespaceMissing => "namespace_missing",
            Self::NamespaceReplaced => "namespace_replaced",
            Self::NamespaceMismatch => "namespace_mismatch",
            Self::NotEntitled => "not_entitled",
            Self::EntitlementExpired => "entitlement_expired",
            Self::RoleNotEntitled => "role_not_entitled",
            Self::UnknownRole => "unknown_role",
            Self::AuditFailed => "audit_failed",
        }
    }

    fn status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::StoreUnavailable | Self::NamespaceUnavailable => 503,
            Self::StoreError | Self::AuditFailed => 500,
            _ => 403,
        }
    }
}

/// A deny. Carries only the reason code; details go to the `idp` log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueDenied {
    pub reason: DenyReason,
}

impl std::fmt::Display for IssueDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity issuance denied: {}", self.reason.as_str())
    }
}

impl From<IssueDenied> for RvError {
    fn from(d: IssueDenied) -> Self {
        RvError::ErrResponseStatus(d.reason.status(), d.to_string())
    }
}

/// The fields of `idp.issue` / `idp.issue-denied`. No field can carry a
/// credential: ids, the login, the uid, role and policy names, timestamps.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IssueEvent {
    /// `allow` or `deny`.
    pub decision: &'static str,
    pub reason: Option<&'static str>,
    pub provider: String,
    pub entity_id: String,
    pub environment: String,
    pub caller_namespace: String,
    pub requested_roles: Option<Vec<String>>,
    pub login: Option<String>,
    pub uid: Option<u32>,
    pub namespace: Option<String>,
    pub roles: Vec<String>,
    pub policies: Vec<String>,
    pub not_after: Option<String>,
}

impl IssueEvent {
    fn for_request(req: &IssueRequest) -> Self {
        Self {
            decision: "deny",
            provider: bounded(&req.provider),
            entity_id: bounded(&req.entity_id),
            environment: bounded(&req.environment),
            caller_namespace: bounded(&req.caller_namespace),
            requested_roles: req
                .roles
                .as_ref()
                .map(|roles| roles.iter().take(super::model::MAX_ROLES_PER_ENTITLEMENT).map(|r| bounded(r)).collect()),
            ..Default::default()
        }
    }

    /// The event as a JSON object.
    pub fn fields(&self) -> Result<Map<String, Value>, RvError> {
        match serde_json::to_value(self)? {
            Value::Object(m) => Ok(m),
            _ => Err(bv_errors::bv_error_string!("idp issue event did not serialize to an object")),
        }
    }
}

/// A caller-supplied value cut to [`MAX_EVENT_ARG_LEN`] characters.
fn bounded(value: &str) -> String {
    if value.chars().count() <= MAX_EVENT_ARG_LEN {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(MAX_EVENT_ARG_LEN).collect();
    cut.push('…');
    cut
}

fn deny(reason: DenyReason) -> IssueDenied {
    IssueDenied { reason }
}

/// Log why a read failed and turn it into a deny.
fn store_failure(what: &str, entity_id: &str, environment: &str, e: &RvError) -> IssueDenied {
    log::warn!(
        target: "idp",
        "{}: cannot read the {what} for entity_id={entity_id} environment={environment}: {e}",
        events::ISSUE_DENIED
    );
    deny(DenyReason::StoreError)
}

fn valid_provider(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PROVIDER_LEN
        && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub struct IssueGate {
    posix: Option<Arc<PosixStore>>,
    authz: Option<Arc<EntitlementStore>>,
    namespaces: Arc<dyn NamespaceLookup>,
    audit: Arc<dyn IssueAuditSink>,
}

#[maybe_async::maybe_async]
impl IssueGate {
    /// `None` for a store means the vault is sealed or not yet initialized:
    /// every evaluation is then denied (`store_unavailable`). Crate-private:
    /// outside callers get the real registry and audit broker through
    /// `IdpModule::issue_gate()`, never a sink of their choosing.
    pub(crate) fn new(
        posix: Option<Arc<PosixStore>>,
        authz: Option<Arc<EntitlementStore>>,
        namespaces: Arc<dyn NamespaceLookup>,
        audit: Arc<dyn IssueAuditSink>,
    ) -> Self {
        Self { posix, authz, namespaces, audit }
    }

    /// Decide, then record the decision. `http` is the request being served,
    /// if any (who and from where; its body is not recorded).
    pub async fn authorize(&self, req: &IssueRequest, http: Option<&Request>) -> Result<IssueGrant, IssueDenied> {
        self.authorize_at(req, http, Utc::now()).await
    }

    /// [`authorize`](Self::authorize) at a given instant (for `not_after`).
    /// Crate-private so no caller can choose the clock an expiry is judged by.
    pub(crate) async fn authorize_at(
        &self,
        req: &IssueRequest,
        http: Option<&Request>,
        now: DateTime<Utc>,
    ) -> Result<IssueGrant, IssueDenied> {
        let mut event = IssueEvent::for_request(req);
        let decision = self.decide(req, now, &mut event).await;
        let denied = match decision {
            Ok(grant) => {
                event.decision = "allow";
                event.roles = grant.roles.clone();
                event.policies = grant.policies.clone();
                event.not_after = grant.not_after.map(|t| t.to_rfc3339());
                match self.audit.record(events::ISSUE, &event, http).await {
                    Ok(()) => return Ok(grant),
                    Err(e) => {
                        // An issuance nobody can attribute is not issued.
                        log::error!(target: "idp", "{}: audit refused the event, denying: {e}", events::ISSUE);
                        deny(DenyReason::AuditFailed)
                    }
                }
            }
            Err(denied) => denied,
        };
        event.decision = "deny";
        event.reason = Some(denied.reason.as_str());
        if let Err(e) = self.audit.record(events::ISSUE_DENIED, &event, http).await {
            log::error!(target: "idp", "{}: audit refused the event: {e}", events::ISSUE_DENIED);
        }
        Err(denied)
    }

    /// The decision itself. Returns early with a deny at the first
    /// precondition that is not proven; there is no default allow.
    async fn decide(
        &self,
        req: &IssueRequest,
        now: DateTime<Utc>,
        event: &mut IssueEvent,
    ) -> Result<IssueGrant, IssueDenied> {
        // Inputs.
        if validate_entity_id(&req.entity_id).is_err()
            || validate_environment_name(&req.environment).is_err()
            || !valid_provider(&req.provider)
        {
            return Err(deny(DenyReason::InvalidRequest));
        }
        let caller_namespace = normalize_path(&req.caller_namespace).map_err(|_| deny(DenyReason::InvalidRequest))?;
        let requested = match &req.roles {
            Some(roles) => Some(normalize_role_list(roles.clone()).map_err(|_| deny(DenyReason::InvalidRequest))?),
            None => None,
        };
        let (Some(posix), Some(authz)) = (self.posix.as_ref(), self.authz.as_ref()) else {
            return Err(deny(DenyReason::StoreUnavailable));
        };
        let (id, env_name) = (req.entity_id.as_str(), req.environment.as_str());

        // Who: an active workforce identity.
        let identity = match posix.get_identity(id).await {
            Ok(Some(identity)) => identity,
            Ok(None) => return Err(deny(DenyReason::NoIdentity)),
            Err(e) => return Err(store_failure("identity", id, env_name, &e)),
        };
        event.login = Some(identity.login.clone());
        event.uid = Some(identity.uid);
        match identity.state {
            IdentityState::Active => {}
            IdentityState::Disabled => return Err(deny(DenyReason::IdentityDisabled)),
            IdentityState::Removed => return Err(deny(DenyReason::IdentityRemoved)),
        }

        // Where: an active environment, still bound to the namespace it was
        // created against, reachable from the caller's namespace.
        let env = match authz.get_environment(env_name).await {
            Ok(Some(env)) => env,
            Ok(None) => return Err(deny(DenyReason::UnknownEnvironment)),
            Err(e) => return Err(store_failure("environment", id, env_name, &e)),
        };
        event.namespace = Some(env.namespace.clone());
        if env.state != EnvironmentState::Active {
            return Err(deny(DenyReason::EnvironmentRetired));
        }
        match self.namespaces.resolve(&env.namespace).await {
            Ok(Some(ns)) if ns.uuid == env.namespace_uuid && ns.path == env.namespace => {}
            Ok(Some(_)) => return Err(deny(DenyReason::NamespaceReplaced)),
            Ok(None) => return Err(deny(DenyReason::NamespaceMissing)),
            Err(e) => {
                log::warn!(target: "idp", "{}: cannot resolve namespace {:?}: {e}", events::ISSUE_DENIED, env.namespace);
                return Err(deny(DenyReason::NamespaceUnavailable));
            }
        }
        if !caller_namespace.is_empty() && caller_namespace != env.namespace {
            return Err(deny(DenyReason::NamespaceMismatch));
        }

        // May they: an unexpired entitlement to this environment.
        let entitlement = match authz.get_entitlement(id, env_name).await {
            Ok(Some(ent)) => ent,
            Ok(None) => return Err(deny(DenyReason::NotEntitled)),
            Err(e) => return Err(store_failure("entitlement", id, env_name, &e)),
        };
        event.not_after = entitlement.not_after.map(|t| t.to_rfc3339());
        if entitlement.not_after.is_some_and(|t| t <= now) {
            return Err(deny(DenyReason::EntitlementExpired));
        }

        // As what: entitled roles, each still defined on the environment.
        let roles = match requested {
            Some(roles) => {
                if roles.iter().any(|r| !entitlement.roles.contains(r)) {
                    return Err(deny(DenyReason::RoleNotEntitled));
                }
                roles
            }
            None => entitlement.roles.clone(),
        };
        if roles.is_empty() {
            return Err(deny(DenyReason::NotEntitled));
        }
        let mut policies = BTreeSet::new();
        for role in &roles {
            let Some(bound) = env.roles.get(role) else {
                return Err(deny(DenyReason::UnknownRole));
            };
            policies.extend(bound.iter().cloned());
        }

        Ok(IssueGrant {
            entity_id: identity.entity_id,
            login: identity.login,
            uid: identity.uid,
            primary_gid: identity.primary_gid,
            gids: identity.gids,
            display_name: identity.display_name,
            environment: env.name,
            namespace: env.namespace,
            namespace_uuid: env.namespace_uuid,
            roles,
            policies: policies.into_iter().collect(),
            not_after: entitlement.not_after,
        })
    }
}

#[cfg(test)]
mod tests;
