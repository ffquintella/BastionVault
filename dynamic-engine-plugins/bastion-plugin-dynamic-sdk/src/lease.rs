//! Lease registration (`dynamic_lease_register`).
//!
//! The host owns every lease: a generate that does not register exactly one
//! is answered `502` and the identity is revoked. The SDK registers the
//! [`LeaseTerms`] a backend returns from `generate`, once, after the backend
//! succeeded; a backend has no way to register one itself.

use serde_json::{json, Value};

use crate::{secret::contains_secret, DynamicError};

/// Largest serialised `internal` blob the host accepts on a lease.
pub const MAX_INTERNAL_BYTES: usize = 16 * 1024;

/// What the plugin asks the host to lease. Never the credential: `internal`
/// is persisted on the lease and handed back on renew and revoke.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseTerms {
    /// Opaque to the host. Must not contain credential material.
    pub internal: Value,
    /// Seconds; 0 means the role's TTL. The host never goes past the role's.
    pub ttl_secs: u64,
    /// Seconds; 0 means the role's max_ttl.
    pub max_ttl_secs: u64,
    pub renewable: bool,
}

impl LeaseTerms {
    /// A renewable lease for `ttl_secs` with an empty `internal` blob.
    pub fn new(ttl_secs: u64) -> Self {
        Self { internal: Value::Null, ttl_secs, max_ttl_secs: 0, renewable: true }
    }

    pub fn with_internal(mut self, internal: Value) -> Self {
        self.internal = internal;
        self
    }

    /// The `dynamic_lease_register` request, refused when the blob is too big
    /// or carries one of `secrets` (the host would persist it on the lease).
    pub(crate) fn to_params(&self, secrets: &[&str]) -> Result<Value, DynamicError> {
        let blob = serde_json::to_string(&self.internal).map_err(|e| DynamicError::invalid(e.to_string()))?;
        if blob.len() > MAX_INTERNAL_BYTES {
            return Err(DynamicError::invalid(format!("lease internal blob exceeds {MAX_INTERNAL_BYTES} bytes")));
        }
        if contains_secret(&blob, secrets) {
            return Err(DynamicError::invalid("lease internal blob must not carry credential material"));
        }
        Ok(json!({
            "internal": self.internal,
            "ttl_secs": self.ttl_secs,
            "max_ttl_secs": self.max_ttl_secs,
            "renewable": self.renewable,
        }))
    }
}

/// Whether this call registered its lease yet: at most once per generate.
#[derive(Debug, Default)]
pub(crate) struct LeaseSlot {
    registered: bool,
}

impl LeaseSlot {
    /// Claim the one registration; refused if already claimed.
    pub(crate) fn claim(&mut self) -> Result<(), DynamicError> {
        if self.registered {
            return Err(DynamicError::invalid("dynamic_lease_register was already called for this credential"));
        }
        self.registered = true;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn registered(&self) -> bool {
        self.registered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_carry_exactly_the_host_fields() {
        let p = LeaseTerms::new(600).with_internal(json!({"v": 1})).to_params(&[]).unwrap();
        assert_eq!(p, json!({"internal": {"v": 1}, "ttl_secs": 600, "max_ttl_secs": 0, "renewable": true}));
    }

    #[test]
    fn a_blob_holding_the_password_is_refused() {
        let terms = LeaseTerms::new(60).with_internal(json!({"pw": "Zx9-long-password"}));
        assert!(terms.to_params(&["Zx9-long-password"]).is_err());
        let big = LeaseTerms::new(60).with_internal(json!("x".repeat(MAX_INTERNAL_BYTES)));
        assert!(big.to_params(&[]).is_err());
    }

    #[test]
    fn a_slot_is_claimed_once() {
        let mut s = LeaseSlot::default();
        s.claim().unwrap();
        assert!(s.registered());
        assert!(s.claim().is_err());
    }
}
