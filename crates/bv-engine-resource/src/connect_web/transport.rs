//! The resource's effective Rustion transport policy, enforced by
//! `v2/connect/web/launch` (`features/web-application-connect.md` §12,
//! "Routing").
//!
//! There is no brokered web transport yet (Phase 8), so a `form` launch
//! always puts the credential on the operator's own machine. A resource whose
//! effective transport is `rustion-required` — or whose policy chain carries a
//! lock violation — therefore refuses the launch, exactly as the desktop host's
//! `web_transport_refusal` refuses the window. `direct` and
//! `rustion-preferred` are allowed; a resource with no Rustion policy at any
//! tier resolves to `direct`.
//!
//! The verdict is Rustion's own (`rustion/policy/effective`, the resolver the
//! host reads and `rustion/v2/session/open` applies); this module only reads
//! it. Anything it cannot read as one of the three known transports refuses.
//!
//! **When the resolver is unreachable.** Rustion's policy tiers are not in the
//! `rustion/` mount: `PolicyStore` keeps them in the *system view* under
//! [`RUSTION_POLICY_PREFIX`] (`global`, `type/`, `asset-group/`, `resource/`),
//! and they survive an unmount. The router also reports a mount that is
//! tainted mid-unmount or mid-remount as not found. So a missing mount proves
//! nothing on its own: the launch is allowed only when that prefix holds no
//! record at all, and refused otherwise — or when the
//! prefix cannot be listed.

use serde_json::{Map, Value};

use super::WebRefusal;

/// Where `bv-engine-rustion`'s `PolicyStore` keeps every policy tier, relative
/// to the system view (`crates/bv-engine-rustion/src/policy.rs`:
/// `GLOBAL_POLICY_KEY`, `TYPE_POLICY_SUB_PATH`, `ASSET_GROUP_POLICY_SUB_PATH`,
/// `RESOURCE_POLICY_SUB_PATH`). Read here only to prove the *absence* of
/// policy when the resolver itself cannot be reached; if that store ever moves,
/// this check fails closed (it would find records it cannot resolve, or none
/// where some exist — hence the cross-reference).
pub const RUSTION_POLICY_PREFIX: &str = "rustion/policy/";

/// What the transport policy permits for a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportVerdict {
    /// The resolver answered `direct` or `rustion-preferred`.
    Allowed(&'static str),
    /// The `rustion/` mount is unreachable *and* the system view holds no
    /// Rustion policy record, so no restriction can exist.
    NoRustion,
}

impl TransportVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed(t) => t,
            Self::NoRustion => "none",
        }
    }
}

/// The refusal for a policy that could not be resolved. Never "allowed".
pub fn unavailable(detail: impl Into<String>) -> WebRefusal {
    WebRefusal::new(
        503,
        "transport_policy_unavailable",
        format!(
            "cannot resolve this resource's Rustion transport policy ({}); refusing to release a \
             credential to this machine without it",
            detail.into()
        ),
    )
}

/// Read a `rustion/policy/effective` response.
pub fn evaluate(data: &Map<String, Value>) -> Result<TransportVerdict, WebRefusal> {
    match data.get("lock_violation") {
        None | Some(Value::Null) => {}
        Some(lv) => {
            let detail = lv.get("detail").and_then(Value::as_str).unwrap_or("rustion policy lock violation");
            return Err(WebRefusal::new(403, "transport_policy", format!("rustion policy lock violation: {detail}")));
        }
    }
    match data.get("transport").and_then(Value::as_str) {
        Some("direct") => Ok(TransportVerdict::Allowed("direct")),
        Some("rustion-preferred") => Ok(TransportVerdict::Allowed("rustion-preferred")),
        Some("rustion-required") => Err(WebRefusal::new(
            403,
            "transport_policy",
            "this resource's transport policy is rustion-required, and web sessions cannot be brokered \
             through a Rustion bastion yet; the credential is not released to this machine",
        )),
        // The resolver always names a transport; a missing or unknown one is a
        // verdict this server cannot interpret.
        Some(_) => Err(unavailable("the resolver returned an unknown transport")),
        None => Err(unavailable("the resolver returned no transport")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eval(v: Value) -> Result<TransportVerdict, WebRefusal> {
        evaluate(v.as_object().unwrap())
    }

    #[test]
    fn direct_and_preferred_are_allowed() {
        assert_eq!(eval(json!({ "transport": "direct" })).unwrap(), TransportVerdict::Allowed("direct"));
        assert_eq!(
            eval(json!({ "transport": "rustion-preferred", "lock_violation": null })).unwrap(),
            TransportVerdict::Allowed("rustion-preferred")
        );
    }

    #[test]
    fn required_and_lock_violations_are_refused() {
        let r = eval(json!({ "transport": "rustion-required" })).unwrap_err();
        assert_eq!((r.status, r.code), (403, "transport_policy"));

        // A lock violation refuses whatever the transport — the host's rule.
        let r = eval(json!({
            "transport": "direct",
            "lock_violation": { "locking_tier": "global", "field": "transport", "detail": "tier `resource` set transport=direct" }
        }))
        .unwrap_err();
        assert_eq!((r.status, r.code), (403, "transport_policy"));
        assert!(r.message.contains("tier `resource`"));
        assert_eq!(
            eval(json!({ "transport": "direct", "lock_violation": "yes" })).unwrap_err().code,
            "transport_policy"
        );
    }

    #[test]
    fn an_uninterpretable_verdict_fails_closed() {
        for v in [
            json!({}),
            json!({ "transport": "" }),
            json!({ "transport": "Rustion-Required" }),
            json!({ "transport": 2 }),
        ] {
            let r = eval(v.clone()).unwrap_err();
            assert_eq!((r.status, r.code), (503, "transport_policy_unavailable"), "{v}");
        }
    }
}
