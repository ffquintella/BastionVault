//! Per-mount ACME storage layout.
//!
//! Everything lives under the PKI mount's per-mount UUID-scoped
//! barrier prefix. Layout:
//!
//! ```text
//! acme/config            # per-mount ACME config (enable flag, role binding)
//! acme/accounts/<id>     # AcmeAccount + JWK (id = jwk thumbprint)
//! acme/orders/<id>       # AcmeOrder
//! acme/authz/<id>        # AcmeAuthz
//! acme/chall/<id>        # AcmeChall
//! acme/nonces/issued     # Vec<String> ring buffer of recently issued nonces
//! acme/orders/<id>/cert  # PEM-encoded leaf chain produced on finalize
//! ```
//!
//! IDs are random URL-safe strings minted at create time (uuid v4 ←
//! base64url; the engine never reuses an id even if the original
//! was deleted).

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CONFIG_KEY: &str = "acme/config";
pub const ACCOUNT_PREFIX: &str = "acme/accounts/";
pub const ORDER_PREFIX: &str = "acme/orders/";
pub const AUTHZ_PREFIX: &str = "acme/authz/";
pub const CHALL_PREFIX: &str = "acme/chall/";
pub const NONCE_KEY: &str = "acme/nonces/issued";

/// Per-mount ACME config. Persisted at `acme/config`. When the
/// engine boots without an existing config, ACME endpoints return
/// `503 acme: not enabled` — the operator opts in by writing this
/// record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// True if ACME is enabled on this mount. Defaults to false on a
    /// fresh write so an operator who creates the config to set
    /// `default_role` doesn't accidentally turn the surface on.
    #[serde(default)]
    pub enabled: bool,
    /// Role used when `finalize` calls into the engine's `pki/sign/<role>`
    /// path. Must already exist on the mount; the engine validates at
    /// `finalize` time, not at config write.
    pub default_role: String,
    /// Issuer ref used when `finalize` signs. Empty = use the mount's
    /// active issuer.
    #[serde(default)]
    pub default_issuer_ref: String,
    /// Hostname the engine advertises in the `directory` response —
    /// the URLs that point back at this server. If empty, the engine
    /// reflects the inbound `Host` header at request time. Pin
    /// explicitly behind a load balancer that doesn't preserve Host.
    #[serde(default)]
    pub external_hostname: String,
    /// Max age of an issued nonce before it falls off the ring buffer.
    /// Defaults to 5 minutes — well under any reasonable client's
    /// retry latency, well over a normal request RTT.
    #[serde(default = "default_nonce_ttl")]
    pub nonce_ttl_secs: u64,
}

fn default_nonce_ttl() -> u64 {
    300
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_role: String::new(),
            default_issuer_ref: String::new(),
            external_hostname: String::new(),
            nonce_ttl_secs: default_nonce_ttl(),
        }
    }
}

/// ACME account record. RFC 8555 §7.1.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    /// `valid` | `deactivated` | `revoked`. Currently only `valid`;
    /// account deactivation lands with the rest of Phase 6.3.
    pub status: String,
    /// Optional contact URLs (`mailto:` typically). RFC 8555 §7.3.
    #[serde(default)]
    pub contact: Vec<String>,
    /// Persisted JWK so subsequent JWS-verify lookups by `kid` find
    /// the right key.
    pub jwk: Value,
    /// Operator-supplied `terms-of-service-agreed`. We surface the
    /// flag so audit reflects what the client claimed; we do not
    /// gate on it (no internal-PKI ToS to display).
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    pub created_at_unix: u64,
}

/// ACME order. RFC 8555 §7.1.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrder {
    /// `pending` | `ready` | `processing` | `valid` | `invalid`.
    pub status: String,
    /// Owning account thumbprint.
    pub account_id: String,
    /// Identifiers requested at `new-order` time.
    pub identifiers: Vec<AcmeIdentifier>,
    /// Authorization ids the client must walk before `finalize`.
    pub authorizations: Vec<String>,
    /// `notBefore` / `notAfter` are not honored in v1 — the role's
    /// TTL drives the cert lifetime. Persisted only for the
    /// response shape.
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    /// Set on `finalize` after successful sign. Empty until then.
    #[serde(default)]
    pub cert_id: String,
    pub expires_at_unix: u64,
    /// Last error surfaced on the order. Cleared on next state-
    /// changing operation. RFC 8555 §6.7 problem-document shape.
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub typ: String,
    pub value: String,
}

/// Authorization for one identifier. RFC 8555 §7.1.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAuthz {
    /// `pending` | `valid` | `invalid` | `deactivated` | `expired` | `revoked`.
    pub status: String,
    pub identifier: AcmeIdentifier,
    pub challenges: Vec<String>,
    pub expires_at_unix: u64,
    /// Owning account thumbprint.
    pub account_id: String,
    /// Owning order id (so the validator can flip the order's state
    /// when the last authz becomes valid).
    pub order_id: String,
}

/// One challenge (HTTP-01, DNS-01, ...). RFC 8555 §7.1.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChall {
    /// `pending` | `processing` | `valid` | `invalid`.
    pub status: String,
    /// `http-01` | `dns-01` | `tls-alpn-01`. Phase 6.1 ships only
    /// `http-01`; `dns-01` and `tls-alpn-01` land in Phase 6.2.
    #[serde(rename = "type")]
    pub typ: String,
    /// Random token the validator looks up under
    /// `/.well-known/acme-challenge/<token>` (HTTP-01) or as a TXT
    /// at `_acme-challenge.<domain>` (DNS-01).
    pub token: String,
    pub authz_id: String,
    pub identifier: AcmeIdentifier,
    /// Set when the validator runs (`validated` field of RFC 8555
    /// §8.3, RFC 3339).
    #[serde(default)]
    pub validated: String,
    #[serde(default)]
    pub error: Option<Value>,
}

// ── Nonce ring buffer ────────────────────────────────────────────

/// We keep a bounded ring buffer rather than per-nonce records so a
/// stuck client can't fill the barrier with stale nonces. 1024 is
/// enough for typical issuance flows; the buffer is FIFO, oldest
/// drops first.
pub const NONCE_RING_CAP: usize = 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NonceRing {
    pub nonces: Vec<String>,
}

impl NonceRing {
    pub fn push(&mut self, nonce: String) {
        if self.nonces.len() >= NONCE_RING_CAP {
            self.nonces.remove(0);
        }
        self.nonces.push(nonce);
    }

    /// Returns true and removes the nonce on hit; false when the
    /// nonce is not in the ring (already consumed, never issued, or
    /// aged out). Single-use semantics — RFC 8555 §6.5.
    pub fn consume(&mut self, nonce: &str) -> bool {
        if let Some(pos) = self.nonces.iter().position(|n| n == nonce) {
            self.nonces.remove(pos);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_ring_consumes_once() {
        let mut r = NonceRing::default();
        r.push("a".into());
        assert!(r.consume("a"));
        assert!(!r.consume("a"));
    }

    #[test]
    fn nonce_ring_caps_at_capacity() {
        let mut r = NonceRing::default();
        for i in 0..(NONCE_RING_CAP + 5) {
            r.push(format!("n{i}"));
        }
        assert_eq!(r.nonces.len(), NONCE_RING_CAP);
        // The first 5 (n0..n4) should have aged out.
        assert!(!r.consume("n0"));
        assert!(r.consume(&format!("n{NONCE_RING_CAP}")));
    }
}
