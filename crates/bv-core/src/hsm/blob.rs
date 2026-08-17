//! `BvHsmBlob` — the on-disk envelope for HSM-wrapped key material.
//!
//! The YubiHSM 2 `wrap-data` command performs raw AES-CCM over opaque bytes
//! and takes no external associated data. To bind every wrapped blob to an
//! explicit, domain-separating context (rule 4 of the feature spec) we layer a
//! small, auditable envelope on top of the device primitive:
//!
//! 1. The associated data (context string, purpose, epoch, node id, and the
//!    `bv-authz` verifying-key fingerprint) is captured in [`BlobAad`].
//! 2. Its SHA-256 digest is prepended to the plaintext *before* the device
//!    wraps it, so the binding is inside the AES-CCM ciphertext and can only be
//!    checked after a successful in-HSM unwrap.
//! 3. On unwrap, the caller supplies the [`BlobAad`] it expects; we refuse the
//!    material unless both the cleartext header *and* the digest sealed inside
//!    the ciphertext match it.
//!
//! A blob wrapped under one context therefore can never be unwrapped or
//! accepted under another, and a version bump (`v1` → `v2`) is a fresh context.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::RvError;

/// Wire-format version of [`BvHsmBlob`]. Bumped only on an incompatible change
/// to the envelope; treated as a distinct context (spec § Context Strings).
pub const BV_HSM_BLOB_VERSION: u8 = 1;

/// Length of the SHA-256 AAD digest prefixed to the wrapped plaintext.
const AAD_DIGEST_LEN: usize = 32;

/// Purpose of a wrapped blob. One HSM object and one context per purpose
/// (rule 5): the enum is part of the domain separation, not a cosmetic tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// The barrier KEK protected for auto-unseal.
    BarrierKek,
    /// An ML-KEM-768 seed under hybrid custody.
    PqcKemSeed,
    /// An ML-DSA-65 seed under hybrid custody.
    PqcSigSeed,
    /// A payload carried over the HSM-to-HSM replication channel.
    ReplicationChannel,
}

impl Purpose {
    /// Short, stable token used inside context strings and audit records.
    pub fn as_token(&self) -> &'static str {
        match self {
            Purpose::BarrierKek => "barrier-kek",
            Purpose::PqcKemSeed => "pqc-kem-seed",
            Purpose::PqcSigSeed => "pqc-sig-seed",
            Purpose::ReplicationChannel => "replication-channel",
        }
    }
}

/// Caller-supplied binding for a wrap/unwrap operation. The `authz_fp` is
/// filled in by the backend from its own `bv-authz` object, so callers never
/// have to know the local device's key fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// The full versioned context string (see [`crate::hsm::context`]).
    pub context: String,
    pub purpose: Purpose,
    pub epoch: u64,
    pub node_id: String,
}

impl Context {
    pub fn new(context: impl Into<String>, purpose: Purpose, epoch: u64, node_id: impl Into<String>) -> Self {
        Self { context: context.into(), purpose, epoch, node_id: node_id.into() }
    }
}

/// The authenticated associated data actually sealed into a blob. Equal to a
/// [`Context`] plus the wrapping device's `bv-authz` verifying-key fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobAad {
    pub context: String,
    pub purpose: Purpose,
    pub epoch: u64,
    pub node_id: String,
    /// Hex SHA-256 of the `bv-authz` verifying key of the device that wrapped
    /// this blob. The signed unwrap authorization must verify against this.
    pub authz_fp: String,
}

impl BlobAad {
    pub fn from_context(ctx: &Context, authz_fp: impl Into<String>) -> Self {
        Self {
            context: ctx.context.clone(),
            purpose: ctx.purpose,
            epoch: ctx.epoch,
            node_id: ctx.node_id.clone(),
            authz_fp: authz_fp.into(),
        }
    }

    /// Deterministic length-prefixed encoding, hashed to bind the AAD into the
    /// ciphertext. Not `serde_json` — field ordering and escaping there are not
    /// guaranteed stable across versions, and this digest is a security check.
    fn canonical(&self) -> Vec<u8> {
        fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::new();
        push_field(&mut out, b"bastionvault/hsm/blob-aad/v1");
        push_field(&mut out, self.context.as_bytes());
        push_field(&mut out, self.purpose.as_token().as_bytes());
        push_field(&mut out, &self.epoch.to_be_bytes());
        push_field(&mut out, self.node_id.as_bytes());
        push_field(&mut out, self.authz_fp.as_bytes());
        out
    }

    fn digest(&self) -> [u8; AAD_DIGEST_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical());
        hasher.finalize().into()
    }
}

/// The persisted envelope. `wrapped` is the device output over
/// `aad_digest ‖ plaintext`; nothing in it is decryptable without the HSM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BvHsmBlob {
    pub version: u8,
    /// `"yubihsm2"` | `"mock"` — records which backend produced the blob.
    pub backend_type: String,
    /// The wrap-key object id used, for operator diagnostics and audit.
    pub wrap_key: u16,
    pub aad: BlobAad,
    #[serde(with = "serde_bytes")]
    pub wrapped: Vec<u8>,
}

impl BvHsmBlob {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RvError> {
        let blob: BvHsmBlob = serde_json::from_slice(bytes).map_err(|_| RvError::ErrHsmBlobInvalid)?;
        if blob.version != BV_HSM_BLOB_VERSION {
            return Err(RvError::ErrHsmBlobInvalid);
        }
        Ok(blob)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RvError> {
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("blob serialize failed: {e}")))
    }

    /// Reconstruct the [`Context`] this blob was wrapped under, from its own
    /// AAD header. Safe to trust for the unwrap check: [`open_blob`] compares
    /// the digest sealed *inside* the ciphertext against this AAD, so a
    /// tampered header is caught after the in-HSM unwrap.
    pub fn context(&self) -> Context {
        Context {
            context: self.aad.context.clone(),
            purpose: self.aad.purpose,
            epoch: self.aad.epoch,
            node_id: self.aad.node_id.clone(),
        }
    }
}

/// Seal `plaintext` into a serialized [`BvHsmBlob`]. `raw_wrap` performs the
/// device-side AES-CCM wrap of the given bytes; this helper owns the AAD
/// binding so both backends share identical envelope semantics.
pub fn seal_blob<F>(
    backend_type: &str,
    wrap_key: u16,
    aad: BlobAad,
    plaintext: &[u8],
    raw_wrap: F,
) -> Result<Vec<u8>, RvError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, RvError>,
{
    let digest = aad.digest();
    let mut inner = Zeroizing::new(Vec::with_capacity(AAD_DIGEST_LEN + plaintext.len()));
    inner.extend_from_slice(&digest);
    inner.extend_from_slice(plaintext);
    let wrapped = raw_wrap(inner.as_slice())?;
    let blob = BvHsmBlob { version: BV_HSM_BLOB_VERSION, backend_type: backend_type.to_string(), wrap_key, aad, wrapped };
    blob.to_bytes()
}

/// Open a serialized [`BvHsmBlob`], enforcing that both the cleartext header
/// and the digest sealed inside the ciphertext match `expected_aad`. `raw_unwrap`
/// performs the device-side AES-CCM unwrap. Returns the plaintext in a
/// `Zeroizing` buffer.
pub fn open_blob<F>(bytes: &[u8], expected_aad: &BlobAad, raw_unwrap: F) -> Result<Zeroizing<Vec<u8>>, RvError>
where
    F: FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>,
{
    let blob = BvHsmBlob::from_bytes(bytes)?;
    // Cheap up-front rejection on the cleartext header.
    if &blob.aad != expected_aad {
        return Err(RvError::ErrHsmContextMismatch);
    }
    let inner = raw_unwrap(&blob.wrapped)?;
    if inner.len() < AAD_DIGEST_LEN {
        return Err(RvError::ErrHsmBlobInvalid);
    }
    // Authoritative check: the digest sealed inside the ciphertext must match
    // the caller's expected AAD. Only reachable after a successful in-HSM
    // unwrap, so tampering with the header alone cannot pass.
    let expected_digest = expected_aad.digest();
    if !constant_time_eq(&inner[..AAD_DIGEST_LEN], &expected_digest) {
        return Err(RvError::ErrHsmContextMismatch);
    }
    Ok(Zeroizing::new(inner[AAD_DIGEST_LEN..].to_vec()))
}

/// Constant-time byte comparison for the AAD digest check.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
