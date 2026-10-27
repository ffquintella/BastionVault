//! The invocation in flight, as the host sees it (ABI 1.4,
//! features/sql-browser.md §9.2). Caller-bound host calls are evaluated
//! against the token of the request that reached the plugin's mount; the
//! plugin only ever sees the attested `caller` block.

use std::sync::{Arc, Mutex};

use crate::logical::Request;

/// The caller of one plugin invocation. Built by the host from the routed
/// request, never from anything the plugin sends, and alive only while that
/// invocation runs. Deliberately not `Debug`: it holds the caller's token.
#[derive(Clone)]
pub struct InvocationCaller {
    req: Arc<Request>,
    /// Connect-MFA tickets redeemed during this invocation, as
    /// `(namespace, resource, profile)`; shared by every clone of it.
    mfa_redeemed: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl InvocationCaller {
    /// Snapshot the authority of `req`; `None` without an authenticated
    /// caller. The payload (body, data, storage view, handler, secret) is
    /// dropped: a host call decides on who asks, not on what they sent.
    pub fn from_request(req: &Request) -> Option<Self> {
        req.auth.as_ref()?;
        let mut snapshot = req.clone();
        snapshot.body = None;
        snapshot.data = None;
        snapshot.storage = None;
        snapshot.handler = None;
        snapshot.secret = None;
        snapshot.match_path = None;
        snapshot.mcp_audit = None;
        Some(Self { req: Arc::new(snapshot), mfa_redeemed: Arc::default() })
    }

    /// Record that this invocation redeemed a connect-MFA ticket for
    /// `(namespace, resource, profile)` (`connect_ticket_redeem`).
    pub fn record_mfa_redemption(&self, namespace: &str, resource: &str, profile: &str) {
        let key = (namespace.to_string(), resource.to_string(), profile.to_string());
        self.mfa_redeemed.lock().unwrap_or_else(|p| p.into_inner()).push(key);
    }

    /// Spend one redemption recorded by this invocation for exactly
    /// `(namespace, resource, profile)`. One ticket, one credential release.
    pub fn take_mfa_redemption(&self, namespace: &str, resource: &str, profile: &str) -> bool {
        let mut redeemed = self.mfa_redeemed.lock().unwrap_or_else(|p| p.into_inner());
        match redeemed.iter().position(|(n, r, p)| n == namespace && r == resource && p == profile) {
            Some(i) => {
                redeemed.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// The caller's request, for the policy gate, the connect-MFA gate and
    /// the audit actor.
    pub fn request(&self) -> &Request {
        &self.req
    }

    /// The caller's identity entity, or `""` without one.
    pub fn entity_id(&self) -> String {
        self.req.auth.as_ref().and_then(|a| a.metadata.get("entity_id").cloned()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logical::Auth;

    #[test]
    fn no_caller_without_auth() {
        assert!(InvocationCaller::from_request(&Request::new("dbms/v2/sessions")).is_none());
    }

    #[test]
    fn snapshot_keeps_the_authority_and_drops_the_payload() {
        let mut req = Request::new("dbms/v2/sessions");
        let mut auth = Auth::default();
        auth.metadata.insert("entity_id".into(), "e-1".into());
        req.auth = Some(auth);
        req.client_token = "tok".into();
        req.namespace_path = Some("dti".into());
        let mut body = serde_json::Map::new();
        body.insert("password".into(), serde_json::json!("from-the-body"));
        req.body = Some(body.clone());
        req.data = Some(body);

        let c = InvocationCaller::from_request(&req).unwrap();
        assert_eq!(c.entity_id(), "e-1");
        assert_eq!(c.request().client_token, "tok");
        assert_eq!(c.request().namespace_path.as_deref(), Some("dti"));
        assert!(c.request().body.is_none() && c.request().data.is_none());
    }

    /// A redemption is shared by the invocation's clones, bound to its
    /// exact `(namespace, resource, profile)`, and spent once.
    #[test]
    fn an_mfa_redemption_is_spent_once_and_only_for_its_profile() {
        let mut req = Request::new("dbms/v2/sessions");
        req.auth = Some(Auth::default());
        let c = InvocationCaller::from_request(&req).unwrap();
        let clone = c.clone();
        clone.record_mfa_redemption("", "netrisk-db", "ro");
        assert!(!c.take_mfa_redemption("", "netrisk-db", "rw"));
        assert!(!c.take_mfa_redemption("tenant", "netrisk-db", "ro"));
        assert!(c.take_mfa_redemption("", "netrisk-db", "ro"));
        assert!(!clone.take_mfa_redemption("", "netrisk-db", "ro"), "spent");
        let other = InvocationCaller::from_request(&req).unwrap();
        clone.record_mfa_redemption("", "netrisk-db", "ro");
        assert!(!other.take_mfa_redemption("", "netrisk-db", "ro"), "another invocation never sees it");
    }
}
