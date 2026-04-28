//! PKI ACME server endpoints — RFC 8555 (Automated Certificate Management
//! Environment).
//!
//! Phase 6.1 ships the **foundation**: per-mount ACME config, directory
//! listing, replay-nonce ring buffer, JWS request envelope verification
//! (RS256 / ES256 / EdDSA), and the `new-account` + `account/<id>`
//! lifecycle.
//!
//! The full order / authz / finalize state machine — including the
//! HTTP-01 validator, the `finalize` → `pki/sign/<role>` shim, and the
//! `cert/<id>` retrieval endpoint — is the next sub-thread under
//! Phase 6.1 (tracked as 6.1.5 in `features/pki-acme.md`). Phase 6.2
//! (DNS-01, EAB, revoke-cert) and Phase 6.3 (key-change, expiry sweep,
//! rate limiting) follow.
//!
//! ACME paths are unauthenticated at the engine layer — the JWS signature
//! is the auth. The `acme/config` operator-facing path stays authenticated
//! (it's the operator's per-mount setup, not an ACME-protocol endpoint).

pub mod account;
pub mod authz;
pub mod directory;
pub mod jws;
pub mod order;
pub mod path_config;
pub mod storage;

/// Paths that bypass the standard token-auth check; their handlers
/// either run the ACME JWS verification in-handler (every protocol
/// endpoint) or are public-by-design (the directory + new-nonce).
pub const UNAUTH_PATHS: &[&str] = &[
    "acme/directory",
    "acme/new-nonce",
    "acme/new-account",
    "acme/account/*",
    "acme/new-order",
    "acme/order/*",
    "acme/authz/*",
    "acme/chall/*",
    "acme/cert/*",
];

/// Mint a fresh URL-safe identifier for an ACME object (account,
/// order, authz, challenge, certificate). Wrapped here so every
/// caller emits the same URL-safe shape — the engine returns these
/// in `Location` headers and clients interpret them as opaque
/// strings, but a stable shape across types makes audit grep
/// easier and rules out colliding ids across types by accident.
pub fn new_object_id(prefix: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use rand::RngExt;
    let mut bytes = [0u8; 18]; // 144 bits → 24-char b64url; collision-safe for any plausible deployment.
    rand::rng().fill(&mut bytes[..]);
    format!("{prefix}_{}", B64.encode(bytes))
}

/// Mint a Replay-Nonce. Random 144-bit value, URL-safe base64, same
/// shape as object ids but unprefixed.
pub fn new_nonce() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use rand::RngExt;
    let mut bytes = [0u8; 18];
    rand::rng().fill(&mut bytes[..]);
    B64.encode(bytes)
}
