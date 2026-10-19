//! `BvHsmBlob` — the on-disk envelope for HSM-wrapped key material.
//!
//! `wrap-data` is raw AES-CCM with no external AAD, so the digest of the
//! [`BlobAad`] is prepended to the plaintext before the device wraps it and is
//! checked after the in-HSM unwrap. v1 binds the creating `node_id`; v2
//! (`features/hsm-pool-ha.md` § Blob format v2) binds the device's `hsm_id`
//! and `authz_alg`. v1 still opens; every new blob is v2.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::RvError;

/// Legacy (pre-T454) blob version: AAD binds `node_id`.
pub const BV_HSM_BLOB_VERSION_V1: u8 = 1;
/// Current blob version: AAD binds `hsm_id` and `authz_alg`.
pub const BV_HSM_BLOB_VERSION_V2: u8 = 2;
/// The version every new wrap produces.
pub const BV_HSM_BLOB_VERSION: u8 = BV_HSM_BLOB_VERSION_V2;

/// Length of the SHA-256 AAD digest prefixed to the wrapped plaintext.
const AAD_DIGEST_LEN: usize = 32;

/// Distinct canonical-encoding tags, so a v1 AAD never collides with a v2 one.
const AAD_TAG_V1: &[u8] = b"bastionvault/hsm/blob-aad/v1";
const AAD_TAG_V2: &[u8] = b"bastionvault/hsm/blob-aad/v2";

/// Upper bound on the serial part of an [`HsmId`]. YubiHSM 2 serials are ten
/// digits and mock serials are `MOCK-` plus twelve hex characters.
const HSM_ID_MAX_SERIAL_LEN: usize = 64;

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

/// Algorithm of a device's `bv-authz` key, bound into every v2 blob AAD.
/// Ed25519 is the only one the backends implement; `ecdsa-p256` is in the
/// format so FIPS-mode devices need no later blob-format change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthzAlg {
    Ed25519,
    EcdsaP256,
}

impl AuthzAlg {
    pub fn as_token(&self) -> &'static str {
        match self {
            AuthzAlg::Ed25519 => "ed25519",
            AuthzAlg::EcdsaP256 => "ecdsa-p256",
        }
    }
}

/// Stable identity of one HSM device: `yubihsm2:<serial>` or `mock:<serial>`.
/// Validated on construction and on deserialization: it is bound into blob
/// AADs and keys blob-set copies, so it must never be ambiguous (an empty
/// serial would make every unidentified device share one id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HsmId(String);

impl HsmId {
    /// Build the id of a device from its backend type and serial.
    pub fn from_parts(backend_type: &str, serial: &str) -> Result<Self, RvError> {
        Self::parse(&format!("{backend_type}:{serial}"))
    }

    pub fn parse(raw: &str) -> Result<Self, RvError> {
        let invalid = |why: &str| RvError::ErrHsm(format!("invalid hsm_id {raw:?}: {why}"));
        let (backend, serial) = raw.split_once(':').ok_or_else(|| invalid("expected <backend>:<serial>"))?;
        if !matches!(backend, "yubihsm2" | "mock") {
            return Err(invalid("unknown backend"));
        }
        if serial.is_empty() {
            return Err(invalid("empty device serial"));
        }
        if serial.len() > HSM_ID_MAX_SERIAL_LEN {
            return Err(invalid("device serial too long"));
        }
        if !serial.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) {
            return Err(invalid("device serial has characters outside [A-Za-z0-9._-]"));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The backend half of the id (`"yubihsm2"` | `"mock"`).
    pub fn backend_type(&self) -> &str {
        self.0.split_once(':').map(|(b, _)| b).unwrap_or_default()
    }
}

impl fmt::Display for HsmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HsmId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        HsmId::parse(&value).map_err(|e| e.to_string())
    }
}

impl From<HsmId> for String {
    fn from(id: HsmId) -> Self {
        id.0
    }
}

/// Caller-supplied binding for a wrap/unwrap operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// The full versioned context string (see [`crate::hsm::context`]).
    pub context: String,
    pub purpose: Purpose,
    pub epoch: u64,
    /// The node the caller acts for. Bound into **v1** AADs only, which is
    /// what a legacy blob is checked against on open. v2 wraps bind the
    /// device's `hsm_id` instead, so this means nothing for a v2 blob.
    pub node_id: String,
}

impl Context {
    pub fn new(context: impl Into<String>, purpose: Purpose, epoch: u64, node_id: impl Into<String>) -> Self {
        Self { context: context.into(), purpose, epoch, node_id: node_id.into() }
    }
}

/// Identity of the device performing a wrap or unwrap. Supplied by the backend
/// itself (see [`crate::hsm::HsmBackend::device_binding`]), never by callers,
/// so a caller cannot claim to be a different device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBinding {
    pub hsm_id: HsmId,
    pub authz_alg: AuthzAlg,
    /// Hex SHA-256 of the device's `bv-authz` verifying key.
    pub authz_fp: String,
}

/// v1 AAD (pre-T454). Field names and order are the persisted v1 format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobAadV1 {
    pub context: String,
    pub purpose: Purpose,
    pub epoch: u64,
    pub node_id: String,
    /// Hex SHA-256 of the `bv-authz` verifying key of the wrapping device.
    pub authz_fp: String,
}

/// v2 AAD: `context ‖ purpose ‖ epoch ‖ hsm_id ‖ authz_alg ‖ authz_fp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobAadV2 {
    pub context: String,
    pub purpose: Purpose,
    pub epoch: u64,
    pub hsm_id: HsmId,
    pub authz_alg: AuthzAlg,
    /// Hex SHA-256 of the `bv-authz` verifying key of the wrapping device.
    pub authz_fp: String,
}

/// The authenticated associated data actually sealed into a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobAad {
    V1(BlobAadV1),
    V2(BlobAadV2),
}

impl BlobAad {
    /// The v1 AAD a legacy blob must carry for `ctx` on a device whose
    /// `bv-authz` fingerprint is `authz_fp`. Used only to *open* v1 blobs.
    pub fn v1_from_context(ctx: &Context, authz_fp: impl Into<String>) -> Self {
        BlobAad::V1(BlobAadV1 {
            context: ctx.context.clone(),
            purpose: ctx.purpose,
            epoch: ctx.epoch,
            node_id: ctx.node_id.clone(),
            authz_fp: authz_fp.into(),
        })
    }

    /// The v2 AAD for `ctx` on `device`.
    pub fn v2_from_context(ctx: &Context, device: &DeviceBinding) -> Self {
        BlobAad::V2(BlobAadV2 {
            context: ctx.context.clone(),
            purpose: ctx.purpose,
            epoch: ctx.epoch,
            hsm_id: device.hsm_id.clone(),
            authz_alg: device.authz_alg,
            authz_fp: device.authz_fp.clone(),
        })
    }

    pub fn version(&self) -> u8 {
        match self {
            BlobAad::V1(_) => BV_HSM_BLOB_VERSION_V1,
            BlobAad::V2(_) => BV_HSM_BLOB_VERSION_V2,
        }
    }

    pub fn context(&self) -> &str {
        match self {
            BlobAad::V1(a) => &a.context,
            BlobAad::V2(a) => &a.context,
        }
    }

    pub fn purpose(&self) -> Purpose {
        match self {
            BlobAad::V1(a) => a.purpose,
            BlobAad::V2(a) => a.purpose,
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            BlobAad::V1(a) => a.epoch,
            BlobAad::V2(a) => a.epoch,
        }
    }

    pub fn authz_fp(&self) -> &str {
        match self {
            BlobAad::V1(a) => &a.authz_fp,
            BlobAad::V2(a) => &a.authz_fp,
        }
    }

    /// The device a v2 blob is bound to; `None` for a v1 blob.
    pub fn hsm_id(&self) -> Option<&HsmId> {
        match self {
            BlobAad::V1(_) => None,
            BlobAad::V2(a) => Some(&a.hsm_id),
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
        match self {
            BlobAad::V1(a) => {
                push_field(&mut out, AAD_TAG_V1);
                push_field(&mut out, a.context.as_bytes());
                push_field(&mut out, a.purpose.as_token().as_bytes());
                push_field(&mut out, &a.epoch.to_be_bytes());
                push_field(&mut out, a.node_id.as_bytes());
                push_field(&mut out, a.authz_fp.as_bytes());
            }
            BlobAad::V2(a) => {
                push_field(&mut out, AAD_TAG_V2);
                push_field(&mut out, a.context.as_bytes());
                push_field(&mut out, a.purpose.as_token().as_bytes());
                push_field(&mut out, &a.epoch.to_be_bytes());
                push_field(&mut out, a.hsm_id.as_str().as_bytes());
                push_field(&mut out, a.authz_alg.as_token().as_bytes());
                push_field(&mut out, a.authz_fp.as_bytes());
            }
        }
        out
    }

    fn digest(&self) -> [u8; AAD_DIGEST_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical());
        hasher.finalize().into()
    }
}

/// Persisted JSON shape of a blob, shared by both versions. Absent optional
/// fields are skipped, so a v1 blob serializes exactly as the pre-T454 code
/// wrote it (`aad.node_id`), and a v2 one carries `hsm_id` + `authz_alg`.
#[derive(Serialize, Deserialize)]
struct BlobWire {
    version: u8,
    backend_type: String,
    wrap_key: u16,
    aad: AadWire,
    #[serde(with = "serde_bytes")]
    wrapped: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct AadWire {
    context: String,
    purpose: Purpose,
    epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hsm_id: Option<HsmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authz_alg: Option<AuthzAlg>,
    authz_fp: String,
}

/// The persisted envelope. `wrapped` is the device output over
/// `aad_digest ‖ plaintext`; nothing in it is decryptable without the HSM.
/// The version is carried by the [`BlobAad`] variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BlobWire", into = "BlobWire")]
pub struct BvHsmBlob {
    /// `"yubihsm2"` | `"mock"` — records which backend produced the blob.
    pub backend_type: String,
    /// The wrap-key object id used, for operator diagnostics and audit.
    pub wrap_key: u16,
    pub aad: BlobAad,
    pub wrapped: Vec<u8>,
}

impl TryFrom<BlobWire> for BvHsmBlob {
    type Error = String;

    fn try_from(w: BlobWire) -> Result<Self, Self::Error> {
        let AadWire { context, purpose, epoch, node_id, hsm_id, authz_alg, authz_fp } = w.aad;
        let aad = match (w.version, node_id, hsm_id, authz_alg) {
            (BV_HSM_BLOB_VERSION_V1, Some(node_id), None, None) => {
                BlobAad::V1(BlobAadV1 { context, purpose, epoch, node_id, authz_fp })
            }
            (BV_HSM_BLOB_VERSION_V2, None, Some(hsm_id), Some(authz_alg)) => {
                if hsm_id.backend_type() != w.backend_type {
                    return Err(format!("blob hsm_id {hsm_id} does not name its backend_type {:?}", w.backend_type));
                }
                BlobAad::V2(BlobAadV2 { context, purpose, epoch, hsm_id, authz_alg, authz_fp })
            }
            (BV_HSM_BLOB_VERSION_V1 | BV_HSM_BLOB_VERSION_V2, ..) => {
                return Err(format!("blob AAD fields do not match blob version {}", w.version))
            }
            (other, ..) => return Err(format!("unsupported HSM blob version {other}")),
        };
        Ok(BvHsmBlob { backend_type: w.backend_type, wrap_key: w.wrap_key, aad, wrapped: w.wrapped })
    }
}

impl From<BvHsmBlob> for BlobWire {
    fn from(b: BvHsmBlob) -> Self {
        let version = b.aad.version();
        let aad = match b.aad {
            BlobAad::V1(a) => AadWire {
                context: a.context,
                purpose: a.purpose,
                epoch: a.epoch,
                node_id: Some(a.node_id),
                hsm_id: None,
                authz_alg: None,
                authz_fp: a.authz_fp,
            },
            BlobAad::V2(a) => AadWire {
                context: a.context,
                purpose: a.purpose,
                epoch: a.epoch,
                node_id: None,
                hsm_id: Some(a.hsm_id),
                authz_alg: Some(a.authz_alg),
                authz_fp: a.authz_fp,
            },
        };
        BlobWire { version, backend_type: b.backend_type, wrap_key: b.wrap_key, aad, wrapped: b.wrapped }
    }
}

impl BvHsmBlob {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RvError> {
        serde_json::from_slice(bytes).map_err(|_| RvError::ErrHsmBlobInvalid)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RvError> {
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("blob serialize failed: {e}")))
    }

    pub fn version(&self) -> u8 {
        self.aad.version()
    }

    /// Reconstruct the [`Context`] this blob was wrapped under, from its own
    /// AAD header. Safe to trust for the unwrap check: [`open_blob`] compares
    /// the digest sealed *inside* the ciphertext against this AAD, so a
    /// tampered header is caught after the in-HSM unwrap. For a v2 blob
    /// `node_id` is empty: v2 does not bind a node.
    pub fn context(&self) -> Context {
        let node_id = match &self.aad {
            BlobAad::V1(a) => a.node_id.clone(),
            BlobAad::V2(_) => String::new(),
        };
        Context {
            context: self.aad.context().to_string(),
            purpose: self.aad.purpose(),
            epoch: self.aad.epoch(),
            node_id,
        }
    }
}

/// Seal `plaintext` into a serialized **v2** [`BvHsmBlob`] bound to `ctx` and
/// `device`. `raw_wrap` performs the device-side AES-CCM wrap; this helper
/// owns the AAD binding so both backends share identical envelope semantics.
pub fn seal_blob<F>(
    backend_type: &str,
    wrap_key: u16,
    ctx: &Context,
    device: &DeviceBinding,
    plaintext: &[u8],
    raw_wrap: F,
) -> Result<Vec<u8>, RvError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, RvError>,
{
    if device.hsm_id.backend_type() != backend_type {
        return Err(RvError::ErrHsm(format!(
            "device hsm_id {} does not belong to backend {backend_type:?}",
            device.hsm_id
        )));
    }
    let aad = BlobAad::v2_from_context(ctx, device);
    let digest = aad.digest();
    let mut inner = Zeroizing::new(Vec::with_capacity(AAD_DIGEST_LEN + plaintext.len()));
    inner.extend_from_slice(&digest);
    inner.extend_from_slice(plaintext);
    let wrapped = raw_wrap(inner.as_slice())?;
    let blob = BvHsmBlob { backend_type: backend_type.to_string(), wrap_key, aad, wrapped };
    blob.to_bytes()
}

/// Open a serialized [`BvHsmBlob`] of either version on `device`. A v1 blob is
/// checked against `ctx` (including `ctx.node_id`). A v2 blob must name
/// `device.hsm_id`, checked **before** `raw_unwrap` runs, so a misrouted copy
/// never reaches the device. Header and sealed digest must both match.
pub fn open_blob<F>(
    bytes: &[u8],
    ctx: &Context,
    device: &DeviceBinding,
    raw_unwrap: F,
) -> Result<Zeroizing<Vec<u8>>, RvError>
where
    F: FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>,
{
    let blob = BvHsmBlob::from_bytes(bytes)?;
    let expected = match &blob.aad {
        BlobAad::V1(_) => BlobAad::v1_from_context(ctx, device.authz_fp.clone()),
        BlobAad::V2(aad) => {
            if aad.hsm_id != device.hsm_id {
                log::warn!(
                    target: "security",
                    "refusing to unwrap: blob wrapped by HSM {} was presented to HSM {}",
                    aad.hsm_id,
                    device.hsm_id
                );
                return Err(RvError::ErrHsmContextMismatch);
            }
            BlobAad::v2_from_context(ctx, device)
        }
    };
    // Cheap up-front rejection on the cleartext header.
    if blob.aad != expected {
        return Err(RvError::ErrHsmContextMismatch);
    }
    let inner = raw_unwrap(&blob.wrapped)?;
    if inner.len() < AAD_DIGEST_LEN {
        return Err(RvError::ErrHsmBlobInvalid);
    }
    // Authoritative check: the digest sealed inside the ciphertext must match
    // the expected AAD. Only reachable after a successful in-HSM unwrap, so
    // tampering with the header alone cannot pass.
    let expected_digest = expected.digest();
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn device(serial: &str) -> DeviceBinding {
        DeviceBinding {
            hsm_id: HsmId::from_parts("mock", serial).unwrap(),
            authz_alg: AuthzAlg::Ed25519,
            authz_fp: format!("fp-{serial}"),
        }
    }

    fn ctx() -> Context {
        Context::new("bastionvault/hsm/v1/barrier-kek/clu", Purpose::BarrierKek, 0, "n1")
    }

    /// An identity "device": the wrap output is its input. Enough to test the
    /// envelope logic, which is all this module owns.
    fn identity_wrap(inner: &[u8]) -> Result<Vec<u8>, RvError> {
        Ok(inner.to_vec())
    }

    fn identity_unwrap(w: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        Ok(Zeroizing::new(w.to_vec()))
    }

    #[test]
    fn hsm_id_validation() {
        assert_eq!(HsmId::from_parts("mock", "MOCK-0a1b").unwrap().as_str(), "mock:MOCK-0a1b");
        assert_eq!(HsmId::parse("yubihsm2:0012345678").unwrap().backend_type(), "yubihsm2");
        for bad in ["", "mock", "mock:", "softhsm:1", "mock:a/b", "mock:a b", "mock:../x", "yubihsm2:\u{0}"] {
            assert!(HsmId::parse(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(HsmId::parse(&format!("mock:{}", "a".repeat(65))).is_err());
        // Deserialization goes through the same validation.
        assert!(serde_json::from_str::<HsmId>("\"mock:\"").is_err());
    }

    #[test]
    fn new_blobs_are_v2_and_bind_hsm_id() {
        let dev = device("A");
        let bytes = seal_blob("mock", 2, &ctx(), &dev, b"kek", identity_wrap).unwrap();
        let blob = BvHsmBlob::from_bytes(&bytes).unwrap();
        assert_eq!(blob.version(), BV_HSM_BLOB_VERSION_V2);
        assert_eq!(blob.aad.hsm_id(), Some(&dev.hsm_id));
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["version"], 2);
        assert_eq!(json["aad"]["hsm_id"], "mock:A");
        assert_eq!(json["aad"]["authz_alg"], "ed25519");
        assert!(json["aad"].get("node_id").is_none(), "v2 AAD must not carry node_id");
    }

    #[test]
    fn v2_opens_on_its_own_device_from_any_node() {
        let dev = device("A");
        let bytes = seal_blob("mock", 2, &ctx(), &dev, b"kek", identity_wrap).unwrap();
        // A different node id: v2 does not bind the node.
        let mut other_node = ctx();
        other_node.node_id = "n2".into();
        let out = open_blob(&bytes, &other_node, &dev, identity_unwrap).unwrap();
        assert_eq!(out.as_slice(), b"kek");
    }

    #[test]
    fn v2_on_another_device_is_refused_before_the_device_is_called() {
        let bytes = seal_blob("mock", 2, &ctx(), &device("A"), b"kek", identity_wrap).unwrap();
        let called = Cell::new(false);
        let err = open_blob(&bytes, &ctx(), &device("B"), |w| {
            called.set(true);
            identity_unwrap(w)
        })
        .unwrap_err();
        assert_eq!(err, RvError::ErrHsmContextMismatch);
        assert!(!called.get(), "the device must not be asked to unwrap a copy that belongs to another HSM");
    }

    #[test]
    fn v2_rejects_authz_alg_or_fingerprint_mismatch() {
        let dev = device("A");
        let bytes = seal_blob("mock", 2, &ctx(), &dev, b"kek", identity_wrap).unwrap();
        let mut ecdsa = dev.clone();
        ecdsa.authz_alg = AuthzAlg::EcdsaP256;
        assert_eq!(open_blob(&bytes, &ctx(), &ecdsa, identity_unwrap).unwrap_err(), RvError::ErrHsmContextMismatch);
        let mut other_fp = dev;
        other_fp.authz_fp = "other".into();
        assert_eq!(open_blob(&bytes, &ctx(), &other_fp, identity_unwrap).unwrap_err(), RvError::ErrHsmContextMismatch);
    }

    #[test]
    fn v2_header_tamper_is_caught_by_the_sealed_digest() {
        let dev = device("A");
        let bytes = seal_blob("mock", 2, &ctx(), &dev, b"kek", identity_wrap).unwrap();
        let mut blob = BvHsmBlob::from_bytes(&bytes).unwrap();
        // Rewrite the cleartext header to another epoch, then ask for that epoch.
        if let BlobAad::V2(a) = &mut blob.aad {
            a.epoch = 9;
        }
        let tampered = blob.to_bytes().unwrap();
        let mut ctx9 = ctx();
        ctx9.epoch = 9;
        assert_eq!(open_blob(&tampered, &ctx9, &dev, identity_unwrap).unwrap_err(), RvError::ErrHsmContextMismatch);
    }

    /// A v1 blob in exactly the pre-T454 wire shape. The fixture under
    /// `seal/testdata/hsm-seal-v1/` holds one produced by the old code itself.
    fn v1_blob_bytes(node_id: &str, authz_fp: &str, plaintext: &[u8]) -> Vec<u8> {
        let aad = BlobAad::V1(BlobAadV1 {
            context: ctx().context,
            purpose: Purpose::BarrierKek,
            epoch: 0,
            node_id: node_id.into(),
            authz_fp: authz_fp.into(),
        });
        let mut inner = aad.digest().to_vec();
        inner.extend_from_slice(plaintext);
        let wire = serde_json::json!({
            "version": 1,
            "backend_type": "mock",
            "wrap_key": 2,
            "aad": {
                "context": ctx().context,
                "purpose": "barrier-kek",
                "epoch": 0,
                "node_id": node_id,
                "authz_fp": authz_fp,
            },
            "wrapped": inner,
        });
        serde_json::to_vec(&wire).unwrap()
    }

    #[test]
    fn v1_still_opens_and_round_trips_its_wire_shape() {
        let dev = device("A");
        let bytes = v1_blob_bytes("n1", &dev.authz_fp, b"legacy-kek");
        let blob = BvHsmBlob::from_bytes(&bytes).unwrap();
        assert_eq!(blob.version(), BV_HSM_BLOB_VERSION_V1);
        assert_eq!(blob.aad.hsm_id(), None);
        // Re-serializing keeps the v1 shape (byte-for-byte against the old
        // writer's field order is checked on the real fixture in seal::hsm::record).
        let reserialized: serde_json::Value = serde_json::from_slice(&blob.to_bytes().unwrap()).unwrap();
        assert_eq!(reserialized, serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());

        let out = open_blob(&bytes, &ctx(), &dev, identity_unwrap).unwrap();
        assert_eq!(out.as_slice(), b"legacy-kek");

        // v1 still binds the node: another node id is refused.
        let mut n2 = ctx();
        n2.node_id = "n2".into();
        assert_eq!(open_blob(&bytes, &n2, &dev, identity_unwrap).unwrap_err(), RvError::ErrHsmContextMismatch);
    }

    #[test]
    fn malformed_or_mixed_version_blobs_are_rejected() {
        let good = seal_blob("mock", 2, &ctx(), &device("A"), b"x", identity_wrap).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&good).unwrap();

        let mut unknown = json.clone();
        unknown["version"] = 3.into();
        assert_eq!(
            BvHsmBlob::from_bytes(&serde_json::to_vec(&unknown).unwrap()).unwrap_err(),
            RvError::ErrHsmBlobInvalid
        );

        // v2 with a node_id, or v1 with an hsm_id, is a confused record.
        let mut mixed = json.clone();
        mixed["aad"]["node_id"] = "n1".into();
        assert!(BvHsmBlob::from_bytes(&serde_json::to_vec(&mixed).unwrap()).is_err());
        let mut v1_with_hsm = json.clone();
        v1_with_hsm["version"] = 1.into();
        assert!(BvHsmBlob::from_bytes(&serde_json::to_vec(&v1_with_hsm).unwrap()).is_err());

        // hsm_id must name the blob's own backend type.
        json["backend_type"] = "yubihsm2".into();
        assert!(BvHsmBlob::from_bytes(&serde_json::to_vec(&json).unwrap()).is_err());

        // Truncated bytes.
        assert!(BvHsmBlob::from_bytes(&good[..good.len() / 2]).is_err());
    }

    #[test]
    fn seal_refuses_a_binding_from_another_backend() {
        let dev = DeviceBinding {
            hsm_id: HsmId::parse("yubihsm2:0012345678").unwrap(),
            authz_alg: AuthzAlg::Ed25519,
            authz_fp: "fp".into(),
        };
        assert!(seal_blob("mock", 2, &ctx(), &dev, b"x", identity_wrap).is_err());
    }

    #[test]
    fn v1_and_v2_aad_encodings_never_collide() {
        let dev = device("A");
        let v1 = BlobAad::v1_from_context(&ctx(), dev.authz_fp.clone());
        let v2 = BlobAad::v2_from_context(&ctx(), &dev);
        assert_ne!(v1.digest(), v2.digest());
    }
}
