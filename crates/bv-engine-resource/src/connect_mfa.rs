//! Connect-time MFA re-validation gate
//! (`features/connect-mfa-and-fido2-ssh.md`).
//!
//! A connection profile marked `require_mfa` may only open a session after
//! the connecting operator has re-proved a second factor. This module owns
//! the three moving parts:
//!
//!   1. **The decision** — [`profile_requires_mfa`] reads the flag off the
//!      stored resource record. It is never taken from the request body, so
//!      a patched client cannot declare itself exempt.
//!   2. **The ticket** — [`ConnectMfaTicketStore`] mints a single-use,
//!      120-second artifact bound to one (principal, namespace, resource,
//!      profile) tuple after a successful step-up.
//!   3. **The guard** — [`enforce`] is the one function every connect path
//!      calls. It short-circuits when the profile is ungated and otherwise
//!      demands and consumes a ticket.
//!
//! The factor ceremony itself lives in the auth backend that owns the
//! factors (`bastion_vault::modules::credential::userpass::path_step_up`); this
//! module only orchestrates it and records the outcome.
//!
//! ## Storage layout (barrier root)
//!
//! ```text
//! connect/mfa-tickets/<hex(sha256(ticket))> -> ConnectMfaTicket (JSON)
//! ```
//!
//! Barrier root rather than the resource mount's view because the brokered
//! path enforces from the `rustion/` mount while the direct path enforces
//! from `resources/` — one record has to be reachable from both, exactly
//! like `bastion_vault::modules::identity::default_account`.
//!
//! Only the SHA-256 of the ticket is persisted. A dump of the barrier
//! yields no redeemable tickets.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::kernel_api::VaultCtx;
use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::{Operation, Request},
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Barrier-root prefix for connect-MFA tickets.
pub const TICKET_PREFIX: &str = "connect/mfa-tickets/";

/// How long a minted ticket stays redeemable. Short on purpose: the ticket
/// exists to link one factor ceremony to one immediately-following connect,
/// not to grant a window of privileged access.
pub const TICKET_TTL_SECS: i64 = 120;

/// A redeemed-once authorization to open a specific gated profile.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConnectMfaTicket {
    /// Auth mount of the principal the ticket was minted for (`userpass/`).
    pub mount: String,
    /// Principal name, lowercased.
    pub principal: String,
    /// Caller's namespace path (`""` = root). Prevents a ticket minted in
    /// one tenant from opening a same-named resource in another.
    #[serde(default)]
    pub namespace: String,
    /// Canonical (lowercase) resource name.
    pub resource: String,
    /// Connection-profile id on that resource.
    pub profile_id: String,
    /// Which factor was proved (`totp` / `fido2`). Recorded so the
    /// `session.open` audit line can say *how* the operator re-validated.
    pub method: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// The tuple a ticket must match to be redeemable. Every field is compared;
/// a mismatch on any one of them is a hard failure, not a warning.
#[derive(Debug, Clone, PartialEq)]
pub struct TicketBinding {
    pub mount: String,
    pub principal: String,
    pub namespace: String,
    pub resource: String,
    pub profile_id: String,
}

/// Why a ticket could not be redeemed. Every variant is a refusal — there is
/// no partial-credit outcome.
#[derive(Debug)]
pub enum TicketError {
    /// No record under that hash: never minted, already consumed, or the
    /// storage entry was reaped.
    Unknown,
    Expired { expires_at: String },
    /// The record exists but was minted for a different principal, tenant,
    /// resource, or profile.
    Mismatch(&'static str),
    Storage(RvError),
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(
                f,
                "connect MFA ticket is unknown or has already been used; \
                 re-run the MFA prompt"
            ),
            Self::Expired { expires_at } => write!(
                f,
                "connect MFA ticket expired at {expires_at}; re-run the MFA prompt"
            ),
            Self::Mismatch(what) => write!(
                f,
                "connect MFA ticket was not issued for this {what}; \
                 re-run the MFA prompt for the profile you are opening"
            ),
            Self::Storage(e) => write!(f, "connect MFA ticket storage error: {e}"),
        }
    }
}

impl From<TicketError> for RvError {
    fn from(e: TicketError) -> Self {
        match e {
            TicketError::Storage(inner) => inner,
            other => bv_error_response_status!(403, &other.to_string()),
        }
    }
}

/// Storage key for a ticket: hex of its SHA-256. The raw ticket is never
/// written down, so the key doubles as the lookup and the verifier.
/// The storage key a ticket hashes to.
///
/// `pub` because the ticket-store tests write a record directly at this key to
/// simulate an expiry, and they had to move to the root crate — they stand up
/// a whole vault. Safe to expose: it takes the ticket the caller already holds
/// and returns the key it hashes to, never the reverse.
pub fn ticket_key(ticket: &str) -> String {
    let digest = Sha256::digest(ticket.as_bytes());
    format!("{TICKET_PREFIX}{}", hex::encode(digest))
}

pub struct ConnectMfaTicketStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl ConnectMfaTicketStore {
    pub fn new(core: &dyn VaultCtx) -> Result<Self, RvError> {
        // The view is rooted at the barrier, and `ticket_key` already carries
        // the full prefix, so the view itself takes an empty prefix.
        Ok(Self { view: Arc::new(BarrierView::new(core.barrier().clone(), "")) })
    }

    /// Mint a ticket for `binding`, proved by `method`. Returns the raw
    /// ticket (the only time it exists in plaintext) alongside the stored
    /// record.
    pub async fn mint(
        &self,
        binding: &TicketBinding,
        method: &str,
    ) -> Result<(String, ConnectMfaTicket), RvError> {
        // Scope the (`!Send`) ThreadRng so it is dropped before the awaits
        // below — otherwise this future stops being `Send` and no handler can
        // call it. Same pattern as the Rustion dispatcher's planning step.
        let ticket = {
            let mut raw = [0u8; 32];
            rand::rng().fill_bytes(&mut raw);
            URL_SAFE_NO_PAD.encode(raw)
        };

        let now = Utc::now();
        let record = ConnectMfaTicket {
            mount: binding.mount.clone(),
            principal: binding.principal.clone(),
            namespace: binding.namespace.clone(),
            resource: binding.resource.clone(),
            profile_id: binding.profile_id.clone(),
            method: method.to_string(),
            issued_at: now.to_rfc3339(),
            expires_at: (now + ChronoDuration::seconds(TICKET_TTL_SECS)).to_rfc3339(),
        };

        let value = serde_json::to_vec(&record)?;
        self.view.put(&StorageEntry { key: ticket_key(&ticket), value }).await?;
        Ok((ticket, record))
    }

    /// Redeem a ticket exactly once.
    ///
    /// **Delete before validate.** The record is removed the moment it is
    /// read, before any field is inspected, so two concurrent redemptions of
    /// the same ticket cannot both proceed — the loser sees
    /// [`TicketError::Unknown`]. A validation failure after the delete is
    /// intentional too: a ticket presented against the wrong profile is
    /// burnt, not retried.
    pub async fn consume(
        &self,
        ticket: &str,
        expect: &TicketBinding,
    ) -> Result<ConnectMfaTicket, TicketError> {
        let ticket = ticket.trim();
        if ticket.is_empty() {
            return Err(TicketError::Unknown);
        }
        let key = ticket_key(ticket);

        let entry = self.view.get(&key).await.map_err(TicketError::Storage)?;
        let Some(entry) = entry else {
            return Err(TicketError::Unknown);
        };
        self.view.delete(&key).await.map_err(TicketError::Storage)?;

        let record: ConnectMfaTicket = serde_json::from_slice(&entry.value)
            .map_err(|e| TicketError::Storage(e.into()))?;

        if record.mount != expect.mount || record.principal != expect.principal {
            return Err(TicketError::Mismatch("principal"));
        }
        if record.namespace != expect.namespace {
            return Err(TicketError::Mismatch("namespace"));
        }
        if record.resource != expect.resource {
            return Err(TicketError::Mismatch("resource"));
        }
        if record.profile_id != expect.profile_id {
            return Err(TicketError::Mismatch("profile"));
        }

        let expires: DateTime<Utc> = DateTime::parse_from_rfc3339(&record.expires_at)
            .map_err(|e| {
                TicketError::Storage(crate::bv_error_string!(&format!(
                    "connect MFA ticket has an unparseable expiry: {e}"
                )))
            })?
            .with_timezone(&Utc);
        if Utc::now() >= expires {
            return Err(TicketError::Expired { expires_at: record.expires_at.clone() });
        }

        Ok(record)
    }

    /// Drop every expired ticket. Cheap enough to run opportunistically;
    /// expiry is enforced on redemption regardless, so this is hygiene
    /// rather than a control.
    pub async fn tidy(&self) -> Result<usize, RvError> {
        let now = Utc::now();
        let mut removed = 0usize;
        for k in self.view.list(TICKET_PREFIX).await? {
            let key = format!("{TICKET_PREFIX}{}", k.trim_end_matches('/'));
            let Some(entry) = self.view.get(&key).await? else { continue };
            let stale = match serde_json::from_slice::<ConnectMfaTicket>(&entry.value) {
                Ok(rec) => DateTime::parse_from_rfc3339(&rec.expires_at)
                    .map(|e| now >= e.with_timezone(&Utc))
                    // An unparseable record can never be redeemed; reap it.
                    .unwrap_or(true),
                Err(_) => true,
            };
            if stale {
                self.view.delete(&key).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

// ── Principal + profile resolution ─────────────────────────────────

/// The calling principal as `(mount, name)`, normalized the way the ticket
/// binding stores it.
///
/// Only userpass tokens carry a second factor, so anything else is refused
/// here rather than being allowed through a gate it can never satisfy. The
/// error names the reason so an operator who gates a profile and then hits
/// it with an AppRole token gets a diagnosis, not a generic denial.
pub fn caller_principal(req: &Request) -> Result<(String, String), RvError> {
    let auth = req.auth.as_ref().ok_or_else(|| {
        bv_error_response_status!(401, "connect MFA requires an authenticated caller")
    })?;
    let mount = auth.metadata.get("mount_path").map(|s| s.as_str()).unwrap_or_default();
    let username = auth.metadata.get("username").map(|s| s.as_str()).unwrap_or_default();

    if username.is_empty() || !mount.starts_with("userpass") {
        return Err(bv_error_response_status!(
            403,
            "this connection profile requires MFA re-validation, which is only \
             available to userpass principals (they are the only ones with a TOTP \
             key or security key on file). Connect with a userpass token, or clear \
             `require_mfa` on the profile."
        ));
    }
    Ok((mount.to_string(), username.to_lowercase()))
}

/// Resolve the caller's namespace to the canonical path used as the ticket's
/// `namespace` binding. `""` means root.
///
/// Mirrors `RustionBackendInner::namespace_sub_request_prefix` but returns
/// the bare path (no trailing slash) so it is a stable comparison key rather
/// than a request prefix.
pub use crate::kernel_api::namespace::caller_namespace;

/// Read one connection profile off a resource record.
///
/// Goes through the router so it works from any mount (the brokered path
/// enforces from `rustion/`), under the server's own authority. Every caller
/// has already had its `connect`/`read` grant on the resource checked — this
/// read is the consequence of that check, not a substitute for it.
///
/// `ns_prefix` is the caller's namespace request prefix (`""` for root,
/// `"tenant-a/"` otherwise).
pub async fn load_profile(
    core: &dyn VaultCtx,
    ns_prefix: &str,
    resource: &str,
    profile_id: &str,
) -> Result<Option<Value>, RvError> {
    let path = format!("{ns_prefix}resources/resources/{resource}");
    let mut sub = Request::new(&path);
    sub.operation = Operation::Read;
    let Some(resp) = core.router().handle_request(&mut sub).await? else {
        return Ok(None);
    };
    let data = resp.data.unwrap_or_default();
    Ok(find_profile(&data, profile_id))
}

/// Pick a profile out of a resource metadata map by id.
pub fn find_profile(meta: &Map<String, Value>, profile_id: &str) -> Option<Value> {
    meta.get("connection_profiles")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find(|p| p.get("id").and_then(|i| i.as_str()) == Some(profile_id)).cloned()
        })
}

/// Whether a profile value carries the gate. Absent / non-boolean ⇒ false,
/// so every profile written before this feature keeps its old behaviour.
///
/// Re-exported from `kernel_api::engines`, where it has to live so a transport
/// engine can read the same flag without naming this module.
pub use crate::kernel_api::engines::profile_gate_flag;

/// Whether *any* connection profile on `resource` carries the gate.
///
/// The fail-closed branch for a caller that opens a session without naming a
/// profile: the gate cannot be evaluated without a profile id, so an
/// un-attributed open against a resource that has any gated profile is refused
/// rather than allowed through. A resource with no gated profiles is
/// unaffected, which keeps every pre-existing caller working unchanged.
///
/// Moved here from the Rustion transport, which is where it was written and
/// where it did not belong: the gate is the resource engine's, and the second
/// transport to need it would otherwise have copied the check.
pub async fn resource_has_gated_profile(
    core: &dyn VaultCtx,
    ns_prefix: &str,
    resource: &str,
) -> Result<bool, RvError> {
    let path = format!("{ns_prefix}resources/resources/{resource}");
    let mut sub = Request::new(&path);
    sub.operation = crate::logical::Operation::Read;
    let Some(resp) = core.router().handle_request(&mut sub).await? else {
        return Ok(false);
    };
    let data = resp.data.unwrap_or_default();
    Ok(data
        .get("connection_profiles")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(profile_gate_flag))
        .unwrap_or(false))
}

/// Whether the named profile on the named resource requires MFA.
///
/// A resource or profile that cannot be found reports `false`: the caller's
/// own "profile not found" handling produces a far better error than a
/// misattributed MFA failure would.
pub async fn profile_requires_mfa(
    core: &dyn VaultCtx,
    ns_prefix: &str,
    resource: &str,
    profile_id: &str,
) -> Result<bool, RvError> {
    Ok(load_profile(core, ns_prefix, resource, profile_id)
        .await?
        .map(|p| profile_gate_flag(&p))
        .unwrap_or(false))
}

// ── The guard ──────────────────────────────────────────────────────

/// The single enforcement point. Every path that produces connect material
/// calls this before doing so.
///
/// - Profile is ungated ⇒ `Ok(None)`, no ticket demanded, no behaviour change.
/// - Profile is gated and `ticket` is a valid, unexpired, correctly-bound,
///   unused ticket ⇒ `Ok(Some(record))` and the ticket is now spent.
/// - Anything else ⇒ `Err`. There is no path through this function that
///   permits a gated connect without a redeemed ticket.
pub async fn enforce(
    core: &dyn VaultCtx,
    req: &Request,
    ns_prefix: &str,
    resource: &str,
    profile_id: &str,
    ticket: Option<&str>,
) -> Result<Option<ConnectMfaTicket>, RvError> {
    if !profile_requires_mfa(core, ns_prefix, resource, profile_id).await? {
        return Ok(None);
    }

    let ticket = ticket.map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| {
        bv_error_response_status!(
            403,
            "mfa_required: this connection profile requires MFA re-validation. \
             Run `resources/v2/connect/mfa/begin` + `/verify` and pass the \
             resulting `connect_ticket`."
        )
    })?;

    let (mount, principal) = caller_principal(req)?;
    let binding = TicketBinding {
        mount,
        principal,
        namespace: caller_namespace(core, req).await?,
        resource: resource.to_string(),
        profile_id: profile_id.to_string(),
    };

    let store = ConnectMfaTicketStore::new(core)?;
    let record = store.consume(ticket, &binding).await?;
    Ok(Some(record))
}

// ── Resource-mount handlers ────────────────────────────────────────

/// Namespace *request prefix* (`""` or `"tenant-a/"`) for sub-requests, as
/// opposed to the bare comparison key [`caller_namespace`] returns.
async fn ns_request_prefix(core: &dyn VaultCtx, req: &Request) -> Result<String, RvError> {
    let ns = caller_namespace(core, req).await?;
    Ok(if ns.is_empty() { String::new() } else { format!("{ns}/") })
}

/// The logical path of the step-up ceremony for the calling principal's own
/// auth mount, in the caller's namespace.
fn step_up_path(ns_prefix: &str, mount: &str, leaf: &str) -> String {
    let m = mount.trim_end_matches('/');
    format!("{ns_prefix}auth/{m}/v2/step-up/{leaf}")
}

impl super::ResourceBackendInner {
    /// Verify the caller may connect to this resource at all before telling
    /// them anything about its profiles.
    ///
    /// The same probe `rustion/v2/session/open` runs — now literally the same
    /// code (`PolicyStore::may_connect_target`) rather than a second copy of
    /// it — and for the same reason: the ACL check the request pipeline
    /// already performed guards *who may call this endpoint*, not *which
    /// resource they may name in the body*.
    ///
    /// The copy this replaced probed only with the identity-less
    /// `explain_capability`, which no share-grantee can pass (scope-gated
    /// rules see no caller, no owner, and no share on a `Request::default()`).
    /// So every share-derived connect was refused here while `session/open`
    /// allowed it — the two gates disagreeing about the same question.
    async fn require_connect_grant(&self, req: &Request, resource: &str) -> Result<(), RvError> {
        if req.auth.is_none() {
            return Err(bv_error_response_status!(401, "no authenticated caller"));
        }
        let policy = self
            .core
            .policy()
            .ok_or_else(|| crate::bv_error_string!("policy module not registered"))?;

        let ns = caller_namespace(&self.core, req).await?;
        let ns_prefix = if ns.is_empty() { String::new() } else { format!("{ns}/") };
        let secret_prefix = format!("{ns_prefix}resources/secrets/{resource}/");

        // The probe resolves owner / share qualifiers off the target, so it
        // needs the namespace on the request, not just in the path.
        let mut probe = req.clone();
        probe.namespace_path = if ns.is_empty() { None } else { Some(ns.clone()) };

        if !policy.may_connect_target(&probe, &secret_prefix).await {
            return Err(RvError::ErrPermissionDenied);
        }
        Ok(())
    }

    /// Shared front half of all three handlers: pull `resource` +
    /// `profile_id` off the body, canonicalize the name, check the connect
    /// grant, and load the profile.
    async fn connect_target(
        &self,
        req: &mut Request,
    ) -> Result<(String, String, Option<Value>), RvError> {
        let raw = req
            .get_data("resource")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bv_error_response_status!(400, "`resource` is required"))?;
        let profile_id = req
            .get_data("profile_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bv_error_response_status!(400, "`profile_id` is required"))?;

        let resource = super::resolve_resource_name(req, &raw).await?;
        self.require_connect_grant(req, &resource).await?;

        // Read the record straight out of this mount's own view — we are the
        // resource backend, no router round trip needed.
        let profile = match req.storage_get(&format!("meta/{resource}")).await? {
            Some(e) => {
                let meta: Map<String, Value> = serde_json::from_slice(&e.value)?;
                find_profile(&meta, &profile_id)
            }
            None => None,
        };
        Ok((resource, profile_id, profile))
    }

    /// `POST resources/v2/connect/mfa/begin`.
    ///
    /// Reports whether this profile is gated and, when it is, which factors
    /// the caller can satisfy it with — plus a FIDO2 assertion challenge if
    /// they hold a security key. An ungated profile returns
    /// `{required: false}` and mints nothing.
    pub async fn handle_connect_mfa_begin(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        let (resource, profile_id, profile) = self.connect_target(req).await?;
        let profile = profile.ok_or_else(|| {
            bv_error_response_status!(
                404,
                &format!("profile `{profile_id}` not found on resource `{resource}`")
            )
        })?;

        let mut data = Map::new();
        data.insert("resource".into(), Value::String(resource));
        data.insert("profile_id".into(), Value::String(profile_id));

        if !profile_gate_flag(&profile) {
            data.insert("required".into(), Value::Bool(false));
            data.insert("methods".into(), Value::Array(Vec::new()));
            return Ok(Some(crate::logical::Response::data_response(Some(data))));
        }
        data.insert("required".into(), Value::Bool(true));

        let (mount, _principal) = caller_principal(req)?;
        let ns_prefix = ns_request_prefix(&self.core, req).await?;

        let mut sub = Request::new(step_up_path(&ns_prefix, &mount, "begin"));
        sub.operation = Operation::Write;
        sub.auth = req.auth.clone();
        sub.client_token = req.client_token.clone();
        sub.data = Some(Map::new());
        let resp = self.core.router().handle_request(&mut sub).await?;
        let step_up = resp.and_then(|r| r.data).unwrap_or_default();

        let methods = step_up.get("methods").cloned().unwrap_or_else(|| Value::Array(Vec::new()));
        let has_factor = methods.as_array().map(|a| !a.is_empty()).unwrap_or(false);
        if !has_factor {
            return Err(bv_error_response_status!(
                403,
                "this connection profile requires MFA re-validation, but you have no \
                 second factor enrolled. Enrol a TOTP key or a security key on your \
                 account, or ask an administrator to clear `require_mfa` on the profile."
            ));
        }
        data.insert("methods".into(), methods);
        if let Some(f) = step_up.get("fido2") {
            data.insert("fido2".into(), f.clone());
        }

        Ok(Some(crate::logical::Response::data_response(Some(data))))
    }

    /// `POST resources/v2/connect/mfa/verify`.
    ///
    /// Runs the factor ceremony and, only on success, mints the ticket. The
    /// ticket is bound here — to the profile the caller named on *this* call
    /// — so a verification for a low-value profile cannot be spent on a
    /// high-value one.
    pub async fn handle_connect_mfa_verify(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        let (resource, profile_id, profile) = self.connect_target(req).await?;
        let profile = profile.ok_or_else(|| {
            bv_error_response_status!(
                404,
                &format!("profile `{profile_id}` not found on resource `{resource}`")
            )
        })?;
        if !profile_gate_flag(&profile) {
            return Err(bv_error_response_status!(
                400,
                "this connection profile does not require MFA re-validation; \
                 no ticket is needed"
            ));
        }

        let method =
            req.get_data("method").ok().and_then(|v| v.as_str().map(|s| s.trim().to_lowercase()));
        let method = method
            .filter(|m| !m.is_empty())
            .ok_or_else(|| bv_error_response_status!(400, "`method` is required"))?;

        let (mount, principal) = caller_principal(req)?;
        let ns_prefix = ns_request_prefix(&self.core, req).await?;

        let mut body = Map::new();
        body.insert("method".into(), Value::String(method.clone()));
        for field in ["totp_code", "credential"] {
            if let Ok(v) = req.get_data(field) {
                body.insert(field.into(), v.clone());
            }
        }

        let mut sub = Request::new(step_up_path(&ns_prefix, &mount, "verify"));
        sub.operation = Operation::Write;
        sub.auth = req.auth.clone();
        sub.client_token = req.client_token.clone();
        sub.data = Some(body);
        // A failed factor propagates as-is: the step-up path returns an error
        // rather than a falsy body, so there is no success-shaped failure to
        // mistake for a pass.
        let resp = self.core.router().handle_request(&mut sub).await?;
        let verified = resp
            .and_then(|r| r.data)
            .and_then(|d| d.get("verified").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if !verified {
            return Err(bv_error_response_status!(403, "second-factor verification failed"));
        }

        let binding = TicketBinding {
            mount,
            principal,
            namespace: caller_namespace(&self.core, req).await?,
            resource: resource.clone(),
            profile_id: profile_id.clone(),
        };
        let store = ConnectMfaTicketStore::new(&self.core)?;
        let (ticket, record) = store.mint(&binding, &method).await?;

        let mut data = Map::new();
        data.insert("connect_ticket".into(), Value::String(ticket));
        data.insert("expires_at".into(), Value::String(record.expires_at));
        data.insert("method".into(), Value::String(record.method));
        data.insert("resource".into(), Value::String(resource));
        data.insert("profile_id".into(), Value::String(profile_id));
        Ok(Some(crate::logical::Response::data_response(Some(data))))
    }

    /// `POST resources/v2/connect/authorize`.
    ///
    /// The direct path's pre-flight. Consumes the ticket for a gated profile
    /// (or confirms none is needed for an ungated one) and returns the
    /// authorization the Tauri host requires before it opens a session
    /// window.
    ///
    /// On a gated profile this is a genuine server-side check — the ticket is
    /// verified and burnt here, not client-side. What it cannot do is stop an
    /// operator who already holds `read` on the resource's secret from
    /// bypassing the GUI entirely; see the feature file's "where it stops"
    /// section. For that operator this call is the audit record.
    pub async fn handle_connect_authorize(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        let (resource, profile_id, profile) = self.connect_target(req).await?;
        let profile = profile.ok_or_else(|| {
            bv_error_response_status!(
                404,
                &format!("profile `{profile_id}` not found on resource `{resource}`")
            )
        })?;

        let mut data = Map::new();
        data.insert("resource".into(), Value::String(resource.clone()));
        data.insert("profile_id".into(), Value::String(profile_id.clone()));

        if !profile_gate_flag(&profile) {
            data.insert("authorized".into(), Value::Bool(true));
            data.insert("mfa_required".into(), Value::Bool(false));
            return Ok(Some(crate::logical::Response::data_response(Some(data))));
        }

        let ticket = req
            .get_data("connect_ticket")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                bv_error_response_status!(
                    403,
                    "mfa_required: this connection profile requires MFA re-validation. \
                     Run `resources/v2/connect/mfa/begin` + `/verify` and pass the \
                     resulting `connect_ticket`."
                )
            })?;

        let (mount, principal) = caller_principal(req)?;
        let binding = TicketBinding {
            mount,
            principal: principal.clone(),
            namespace: caller_namespace(&self.core, req).await?,
            resource: resource.clone(),
            profile_id: profile_id.clone(),
        };
        let store = ConnectMfaTicketStore::new(&self.core)?;
        let record = store.consume(ticket.as_str(), &binding).await?;

        log::info!(
            "connect.mfa.authorized resource={resource} profile={profile_id} \
             principal={principal} method={}",
            record.method
        );

        data.insert("authorized".into(), Value::Bool(true));
        data.insert("mfa_required".into(), Value::Bool(true));
        data.insert("method".into(), Value::String(record.method));
        Ok(Some(crate::logical::Response::data_response(Some(data))))
    }
}

#[cfg(test)]
mod tests {
    //! The pure half of this file's tests: gate flags, profile lookup, the
    //! ticket-key derivation and caller attribution. They need no vault, so
    //! they stayed here when the ones that do moved to the root crate's
    //! `engine_tests`. See roadmaps/workspace-decomposition.md § Phase 3.

    use super::*;
    use crate::logical::Auth;
    use serde_json::{Map, Value};
    #[test]
    fn gate_flag_defaults_off() {
        // A profile written before this feature has no `require_mfa` key.
        let legacy = serde_json::json!({ "id": "p_1", "name": "Default" });
        assert!(!profile_gate_flag(&legacy));

        // An explicit false, and a non-boolean, are both "off".
        assert!(!profile_gate_flag(&serde_json::json!({ "require_mfa": false })));
        assert!(!profile_gate_flag(&serde_json::json!({ "require_mfa": "yes" })));

        assert!(profile_gate_flag(&serde_json::json!({ "require_mfa": true })));
    }

    #[test]
    fn find_profile_matches_on_id() {
        let meta: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "name": "web01",
            "connection_profiles": [
                { "id": "p_1", "name": "Default" },
                { "id": "p_2", "name": "Break-glass", "require_mfa": true }
            ]
        }))
        .unwrap();

        assert!(find_profile(&meta, "p_missing").is_none());
        let p2 = find_profile(&meta, "p_2").unwrap();
        assert!(profile_gate_flag(&p2));
        let p1 = find_profile(&meta, "p_1").unwrap();
        assert!(!profile_gate_flag(&p1));

        // A record with no profiles at all does not panic.
        let empty: Map<String, Value> = Map::new();
        assert!(find_profile(&empty, "p_1").is_none());
    }

    #[test]
    fn ticket_key_is_the_hash_not_the_ticket() {
        let k = ticket_key("some-ticket-value");
        assert!(k.starts_with(TICKET_PREFIX));
        assert!(!k.contains("some-ticket-value"));
        // Deterministic, and distinct per ticket.
        assert_eq!(k, ticket_key("some-ticket-value"));
        assert_ne!(k, ticket_key("some-ticket-valuf"));
    }

    #[test]
    fn caller_principal_rejects_non_userpass_tokens() {
        let mut req = Request::new("resources/v2/connect/mfa/begin");
        assert!(caller_principal(&req).is_err());

        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "approle/".into());
        req.auth = Some(auth);
        assert!(caller_principal(&req).is_err());

        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.metadata.insert("username".into(), "Alice".into());
        req.auth = Some(auth);
        assert_eq!(
            caller_principal(&req).unwrap(),
            ("userpass/".to_string(), "alice".to_string())
        );
    }

}
