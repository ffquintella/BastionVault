//! Signed unwrap authorization — "the signed part" (spec § Signed Unwrap
//! Authorization).
//!
//! Every `unwrap_data` call for KEK or PQC material is gated by an Ed25519
//! signature produced inside the HSM by the `bv-authz` object. Possession of a
//! wrapped blob plus a storage compromise is therefore never sufficient to
//! release key material: the decrypt decision itself is anchored in the device
//! and recorded as an attributable, replay-resistant (monotonic counter),
//! context-explicit audit event.
//!
//! This module is pure (no I/O): it builds the to-be-signed request, drives the
//! HSM to sign it, verifies the resulting signature, and emits an audit record.
//! Counter persistence and audit-log delivery live in the seal provider, which
//! owns storage and the audit broker.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    hsm::{authz_fingerprint_of, blob::Purpose, context, domain_separated, HsmBackend, HsmObjectId},
};

/// The canonical, replay-resistant description of a single unwrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwrapRequest {
    /// The versioned context string of the material being released.
    pub context: String,
    /// Hex SHA-256 of the wrapped blob bytes being unwrapped.
    pub blob_digest: String,
    pub node_id: String,
    pub epoch: u64,
    /// Strictly-increasing per node; the verifier rejects stale counters.
    pub counter: u64,
    pub purpose: Purpose,
}

impl UnwrapRequest {
    pub fn new(context: impl Into<String>, blob_bytes: &[u8], node_id: impl Into<String>, epoch: u64, counter: u64, purpose: Purpose) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(blob_bytes);
        Self {
            context: context.into(),
            blob_digest: hex::encode(hasher.finalize()),
            node_id: node_id.into(),
            epoch,
            counter,
            purpose,
        }
    }

    /// Deterministic length-prefixed to-be-signed encoding. Domain separated by
    /// a fixed tag; independent of serde field ordering.
    pub fn tbs(&self) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, b: &[u8]) {
            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.extend_from_slice(b);
        }
        let mut out = Vec::new();
        push(&mut out, b"bastionvault/hsm/unwrap-request/v1");
        push(&mut out, self.context.as_bytes());
        push(&mut out, self.blob_digest.as_bytes());
        push(&mut out, self.node_id.as_bytes());
        push(&mut out, &self.epoch.to_be_bytes());
        push(&mut out, &self.counter.to_be_bytes());
        push(&mut out, self.purpose.as_token().as_bytes());
        out
    }
}

/// An [`UnwrapRequest`] plus the HSM-produced Ed25519 signature and the
/// fingerprint of the `bv-authz` key that signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwrapAuthorization {
    pub request: UnwrapRequest,
    /// Hex Ed25519 signature over [`UnwrapRequest::tbs`].
    pub signature: String,
    /// Hex SHA-256 of the signing `bv-authz` verifying key.
    pub authz_fp: String,
}

/// Have the HSM sign an [`UnwrapRequest`] with `bv-authz`, then self-verify the
/// result before returning it. Self-verification catches a mis-provisioned or
/// wrong-type authz object early, at construction rather than release time.
#[maybe_async::maybe_async]
pub async fn sign_authorization(
    backend: &dyn HsmBackend,
    authz_key_id: HsmObjectId,
    request: UnwrapRequest,
) -> Result<UnwrapAuthorization, RvError> {
    let authz_ctx = context::unwrap_authz(&request.node_id, request.purpose.as_token());
    let signature = backend.sign(authz_key_id, &authz_ctx, &request.tbs()).await?;

    let authz_pub = backend.authz_public_key()?;
    let authz_fp = authz_fingerprint_of(&authz_pub);

    let auth = UnwrapAuthorization { request, signature: hex::encode(&signature), authz_fp };
    verify_authorization(&auth, &authz_pub, &auth.request)?;
    Ok(auth)
}

/// Verify a signed authorization against the local `bv-authz` verifying key and
/// the expected request. Enforces field-for-field match (context, node, epoch,
/// purpose, blob digest) and a valid Ed25519 signature over the TBS. Replay
/// (counter) freshness is enforced by the caller, which holds the high-water
/// mark.
pub fn verify_authorization(
    auth: &UnwrapAuthorization,
    authz_public_key: &[u8],
    expected: &UnwrapRequest,
) -> Result<(), RvError> {
    if &auth.request != expected {
        return Err(RvError::ErrHsmAuthzInvalid);
    }
    if auth.authz_fp != authz_fingerprint_of(authz_public_key) {
        return Err(RvError::ErrHsmAuthzInvalid);
    }

    let vk_bytes: [u8; 32] = authz_public_key.try_into().map_err(|_| RvError::ErrHsmAuthzInvalid)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| RvError::ErrHsmAuthzInvalid)?;

    let sig_bytes = hex::decode(&auth.signature).map_err(|_| RvError::ErrHsmAuthzInvalid)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| RvError::ErrHsmAuthzInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);

    // The HSM signs `domain_separated(authz_ctx, tbs)`; reconstruct the same
    // bytes here from the request's own node id and purpose.
    let authz_ctx = context::unwrap_authz(&auth.request.node_id, auth.request.purpose.as_token());
    let signed = domain_separated(&authz_ctx, &auth.request.tbs());
    vk.verify(&signed, &signature).map_err(|_| RvError::ErrHsmAuthzInvalid)
}

/// Structured audit record for a key release. The seal provider forwards this
/// to the audit log so every unwrap is an attributable, HSM-signed event.
pub fn audit_record(auth: &UnwrapAuthorization) -> serde_json::Value {
    serde_json::json!({
        "event": "hsm_unwrap_authorized",
        "context": auth.request.context,
        "purpose": auth.request.purpose.as_token(),
        "node_id": auth.request.node_id,
        "epoch": auth.request.epoch,
        "counter": auth.request.counter,
        "blob_digest": auth.request.blob_digest,
        "authz_fp": auth.authz_fp,
        "signature": auth.signature,
    })
}
