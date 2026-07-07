//! Hardware Security Module (HSM) integration.
//!
//! BastionVault anchors its master key, PQC key custody, and critical crypto
//! operations in a per-node YubiHSM 2 (production) or a feature-gated software
//! mock (dev/homolog). The mandated device is the YubiHSM 2; the mock exists
//! only under the `hsm_mock` build feature and refuses to run in production.
//!
//! This module defines the narrow [`HsmBackend`] abstraction, the [`BvHsmBlob`]
//! wrapped-material format, the versioned context strings, and the config
//! resolution shared by both backends. Backend implementations live in
//! [`mock`] (feature `hsm_mock`) and [`yubihsm2`] (feature `hsm_yubihsm2`).
//!
//! See `features/hsm-support.md` for the full design and the non-negotiable
//! security rules this code enforces.

use std::{sync::Arc, time::Duration};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::RvError;

pub mod authz;
pub mod blob;
pub mod context;
pub mod custody;
pub mod derive;
pub mod enroll;
pub mod replicate;

#[cfg(feature = "hsm_mock")]
pub mod mock;
#[cfg(feature = "hsm_yubihsm2")]
pub mod yubihsm2;

pub use blob::{BlobAad, BvHsmBlob, Context, Purpose, BV_HSM_BLOB_VERSION};

/// A YubiHSM 2 object identifier (the device uses 16-bit ids).
pub type HsmObjectId = u16;

/// A key proven — via a YubiHSM 2 attestation certificate chain — to have been
/// generated inside a genuine device and to be non-exportable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedKey {
    pub label: String,
    pub object_id: HsmObjectId,
    /// SEC1/DER/raw public key bytes, algorithm-dependent.
    pub public_key: Vec<u8>,
    /// Device serial recovered from the attestation chain.
    pub serial: String,
    /// True when the attested capability mask has `exportable-under-wrap`
    /// disabled — a precondition for enrollment (spec § Security).
    pub non_exportable: bool,
}

/// Narrow abstraction over the operations BastionVault needs from the HSM.
///
/// Implemented by `YubiHsm2Backend` (feature `hsm_yubihsm2`) and
/// `MockHsmBackend` (feature `hsm_mock`). All private-key material stays inside
/// the device; wrap keys are provisioned without `exportable-under-wrap`.
#[maybe_async::maybe_async]
pub trait HsmBackend: Send + Sync {
    /// `"yubihsm2"` | `"mock"`.
    fn backend_type(&self) -> &str;

    /// Device serial (from attestation / connect). `"mock"` for the mock.
    fn device_serial(&self) -> String;

    /// Ed25519 verifying key of the `bv-authz` object, used to verify signed
    /// unwrap authorizations and to compute the fingerprint baked into blobs.
    fn authz_public_key(&self) -> Result<Vec<u8>, RvError>;

    /// SEC1-uncompressed P-256 public key of the `bv-identity` object.
    fn identity_public_key(&self) -> Result<Vec<u8>, RvError>;

    /// Hex SHA-256 of [`Self::authz_public_key`]. Bound into every blob AAD.
    fn authz_fingerprint(&self) -> Result<String, RvError> {
        Ok(authz_fingerprint_of(&self.authz_public_key()?))
    }

    /// AES-CCM wrap of `plaintext` under the HSM-resident wrap key `key`,
    /// producing a serialized [`BvHsmBlob`] bound to `ctx`.
    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError>;

    /// AES-CCM unwrap of a serialized [`BvHsmBlob`], enforcing that its AAD
    /// matches `ctx` (and the local `bv-authz` fingerprint).
    async fn unwrap_data(&self, key: HsmObjectId, ctx: &Context, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Signature with an HSM-resident key. The object type selects the
    /// algorithm: ECDSA-P256 for `bv-identity`, Ed25519 for `bv-authz`. The
    /// context string is prefixed to the message for domain separation.
    async fn sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError>;

    /// Produce an attestation bundle for an HSM-resident key, proving it was
    /// generated inside a genuine device and is non-exportable. On real
    /// hardware this is the YubiHSM 2 attestation certificate chain; the mock
    /// emits an equivalent test-CA bundle over the same [`AttestedKey`] shape.
    async fn attest(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError>;

    /// Verify an attestation bundle produced by [`Self::attest`] and return the
    /// attested key. The mock simulates this with a test CA.
    async fn verify_attestation(&self, cert_chain: &[u8]) -> Result<AttestedKey, RvError>;

    /// ECDH between the HSM-resident `bv-identity` private key and a peer
    /// P-256 public key (SEC1-uncompressed). Result is the raw shared X coord.
    async fn derive_ecdh(&self, key: HsmObjectId, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Hardware randomness. Augments, never replaces, the host CSPRNG (rule 3).
    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError>;
}

/// Length-prefixed domain separation for HSM signatures. `bv-authz` (Ed25519)
/// and `bv-identity` (ECDSA-P256) both sign these bytes so a signature made
/// under one context can never be replayed under another. Both backends and the
/// authorization verifier build the signed message identically through this.
pub fn domain_separated(ctx: &str, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ctx.len() + msg.len());
    out.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
    out.extend_from_slice(ctx.as_bytes());
    out.extend_from_slice(msg);
    out
}

/// Verify a `bv-identity` ECDSA-P256 signature over `domain_separated(ctx, msg)`.
/// Accepts DER (hardware) or fixed-size (mock) signature encodings.
pub fn verify_identity_signature(public_key: &[u8], ctx: &str, msg: &[u8], sig: &[u8]) -> Result<(), RvError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| RvError::ErrHsmAttestationInvalid("bad identity public key".into()))?;
    let signed = domain_separated(ctx, msg);
    let signature = Signature::from_der(sig)
        .or_else(|_| Signature::from_slice(sig))
        .map_err(|_| RvError::ErrHsmAttestationInvalid("bad identity signature".into()))?;
    vk.verify(&signed, &signature).map_err(|_| RvError::ErrHsmAttestationInvalid("identity signature verify failed".into()))
}

/// Hex SHA-256 fingerprint of a public key.
pub fn authz_fingerprint_of(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

/// Recovery posture chosen at init (spec § Configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    /// Default: no software escrow. Losing every cluster HSM loses the vault.
    None,
    /// Opt-in, init-time-only Shamir ceremony escrow of a recovery wrap key.
    ShamirCeremony,
}

impl RecoveryMode {
    pub fn parse(s: &str) -> Result<Self, RvError> {
        match s {
            "" | "none" => Ok(RecoveryMode::None),
            "shamir-ceremony" => Ok(RecoveryMode::ShamirCeremony),
            other => Err(RvError::ErrHsmConfigInvalid(format!("unknown recovery mode {other:?}"))),
        }
    }
}

/// The five per-node HSM objects (spec § HSM Object Layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsmObjectIds {
    pub auth_key: HsmObjectId,
    pub wrap_barrier: HsmObjectId,
    pub wrap_pqc: HsmObjectId,
    pub identity: HsmObjectId,
    pub authz: HsmObjectId,
}

impl Default for HsmObjectIds {
    fn default() -> Self {
        // Object 1 is the device's default auth key; BastionVault provisions
        // its own objects at fixed, minimal-capability ids from there.
        Self { auth_key: 1, wrap_barrier: 2, wrap_pqc: 3, identity: 4, authz: 5 }
    }
}

/// Fully-resolved HSM seal configuration (env-expanded, defaults applied). The
/// raw HCL shape is parsed in `cli::config` and handed to [`resolve_config`].
#[derive(Clone)]
pub struct ResolvedHsmConfig {
    /// `"yubihsm2"` | `"mock"` — the HCL block label.
    pub backend_type: String,
    /// `yubihsm-connector` URL or `"usb"` (yubihsm2 only).
    pub connector: String,
    pub objects: HsmObjectIds,
    /// Auth-key credential, resolved from `env:VAR` where applicable.
    pub password: Zeroizing<String>,
    pub domains: Vec<u16>,
    pub pqc_key_cache_ttl: Duration,
    pub recovery: RecoveryMode,
    /// File-persisted mock object store (mock only).
    pub state_path: String,
    /// Stable node identity used in context strings and per-node blob routing.
    pub node_id: String,
}

/// Raw, serde-parsed HCL `hsm "<label>" { ... }` block. Kept string-typed and
/// permissive; validation and env-expansion happen in [`resolve_config`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HsmConfigBlock {
    #[serde(default)]
    pub connector: String,
    #[serde(default)]
    pub auth_key_id: u16,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub domains: Vec<u16>,
    #[serde(default)]
    pub pqc_key_cache_ttl: String,
    #[serde(default)]
    pub recovery: String,
    #[serde(default)]
    pub state_path: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub wrap_barrier_key_id: u16,
    #[serde(default)]
    pub wrap_pqc_key_id: u16,
    #[serde(default)]
    pub identity_key_id: u16,
    #[serde(default)]
    pub authz_key_id: u16,
}

/// Parse a `"60s"` / `"500ms"` / `"0"` duration string. Empty ⇒ the default.
fn parse_ttl(s: &str, default: Duration) -> Result<Duration, RvError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(default);
    }
    let invalid = || RvError::ErrHsmConfigInvalid(format!("invalid pqc_key_cache_ttl {s:?}"));
    let (num, mult_ms) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1u64)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1000)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60_000)
    } else {
        (s, 1000)
    };
    let n: u64 = num.trim().parse().map_err(|_| invalid())?;
    Ok(Duration::from_millis(n.saturating_mul(mult_ms)))
}

/// Expand a `env:VAR` reference. Plaintext (non-`env:`) values are returned
/// as-is here; callers reject plaintext outside dev builds.
fn resolve_secret(raw: &str) -> Result<Zeroizing<String>, RvError> {
    if let Some(var) = raw.strip_prefix("env:") {
        let val = std::env::var(var)
            .map_err(|_| RvError::ErrHsmConfigInvalid(format!("env var {var} for HSM password is not set")))?;
        Ok(Zeroizing::new(val))
    } else {
        Ok(Zeroizing::new(raw.to_string()))
    }
}

/// Resolve a raw HCL block (with its label) into a validated config.
pub fn resolve_config(label: &str, raw: &HsmConfigBlock) -> Result<ResolvedHsmConfig, RvError> {
    let backend_type = match label {
        "yubihsm2" | "mock" => label.to_string(),
        other => return Err(RvError::ErrHsmConfigInvalid(format!("unknown HSM backend {other:?}"))),
    };

    let defaults = HsmObjectIds::default();
    let objects = HsmObjectIds {
        auth_key: if raw.auth_key_id != 0 { raw.auth_key_id } else { defaults.auth_key },
        wrap_barrier: if raw.wrap_barrier_key_id != 0 { raw.wrap_barrier_key_id } else { defaults.wrap_barrier },
        wrap_pqc: if raw.wrap_pqc_key_id != 0 { raw.wrap_pqc_key_id } else { defaults.wrap_pqc },
        identity: if raw.identity_key_id != 0 { raw.identity_key_id } else { defaults.identity },
        authz: if raw.authz_key_id != 0 { raw.authz_key_id } else { defaults.authz },
    };

    let password = if backend_type == "yubihsm2" {
        if raw.password.is_empty() {
            return Err(RvError::ErrHsmConfigInvalid("yubihsm2 seal requires a password".into()));
        }
        resolve_secret(&raw.password)?
    } else {
        Zeroizing::new(String::new())
    };

    let domains = if raw.domains.is_empty() { vec![1] } else { raw.domains.clone() };
    let pqc_key_cache_ttl = parse_ttl(&raw.pqc_key_cache_ttl, Duration::from_secs(60))?;
    let recovery = RecoveryMode::parse(&raw.recovery)?;

    let node_id = if raw.node_id.is_empty() {
        // A stable default keeps single-node dev working; clusters must set it.
        hostname_or("node")
    } else {
        raw.node_id.clone()
    };

    Ok(ResolvedHsmConfig {
        backend_type,
        connector: raw.connector.clone(),
        objects,
        password,
        domains,
        pqc_key_cache_ttl,
        recovery,
        state_path: raw.state_path.clone(),
        node_id,
    })
}

fn hostname_or(fallback: &str) -> String {
    std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| fallback.to_string())
}

/// True when the running environment is production, per `BVAULT_ENV` or an
/// explicit config value. Used to refuse the mock backend (spec § guardrails).
pub fn is_production_env() -> bool {
    std::env::var("BVAULT_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false)
}

/// Construct the configured backend. Only compiled backends are available;
/// requesting a backend whose feature is off is a config error, not a panic.
#[maybe_async::maybe_async]
pub async fn new_backend(config: &ResolvedHsmConfig) -> Result<Arc<dyn HsmBackend>, RvError> {
    match config.backend_type.as_str() {
        "mock" => {
            if is_production_env() {
                log::error!(target: "security", "refusing to start: mock HSM backend is not permitted in production");
                return Err(RvError::ErrHsmMockRefusedInProduction);
            }
            #[cfg(feature = "hsm_mock")]
            {
                log::warn!(target: "security", "using the MOCK HSM backend — NO hardware protection; dev/homolog only");
                let backend = mock::MockHsmBackend::open(config).await?;
                Ok(Arc::new(backend))
            }
            #[cfg(not(feature = "hsm_mock"))]
            {
                Err(RvError::ErrHsmConfigInvalid(
                    "mock HSM backend requested but this build lacks the `hsm_mock` feature".into(),
                ))
            }
        }
        "yubihsm2" => {
            #[cfg(feature = "hsm_yubihsm2")]
            {
                let backend = yubihsm2::YubiHsm2Backend::open(config).await?;
                Ok(Arc::new(backend))
            }
            #[cfg(not(feature = "hsm_yubihsm2"))]
            {
                Err(RvError::ErrHsmConfigInvalid(
                    "yubihsm2 backend requested but this build lacks the `hsm_yubihsm2` feature".into(),
                ))
            }
        }
        other => Err(RvError::ErrHsmConfigInvalid(format!("unknown HSM backend {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parsing() {
        assert_eq!(parse_ttl("", Duration::from_secs(60)).unwrap(), Duration::from_secs(60));
        assert_eq!(parse_ttl("0", Duration::from_secs(60)).unwrap(), Duration::from_secs(0));
        assert_eq!(parse_ttl("60s", Duration::from_secs(1)).unwrap(), Duration::from_secs(60));
        assert_eq!(parse_ttl("500ms", Duration::from_secs(1)).unwrap(), Duration::from_millis(500));
        assert_eq!(parse_ttl("2m", Duration::from_secs(1)).unwrap(), Duration::from_secs(120));
        assert!(parse_ttl("abc", Duration::from_secs(1)).is_err());
    }

    #[test]
    fn recovery_parsing() {
        assert_eq!(RecoveryMode::parse("none").unwrap(), RecoveryMode::None);
        assert_eq!(RecoveryMode::parse("").unwrap(), RecoveryMode::None);
        assert_eq!(RecoveryMode::parse("shamir-ceremony").unwrap(), RecoveryMode::ShamirCeremony);
        assert!(RecoveryMode::parse("escrow").is_err());
    }

    #[test]
    fn resolve_rejects_unknown_backend() {
        let raw = HsmConfigBlock::default();
        assert!(resolve_config("softhsm", &raw).is_err());
    }

    #[test]
    fn resolve_yubihsm_requires_password() {
        let raw = HsmConfigBlock::default();
        assert!(resolve_config("yubihsm2", &raw).is_err());
    }

    #[test]
    fn resolve_applies_object_id_defaults() {
        let raw = HsmConfigBlock { node_id: "n1".into(), ..Default::default() };
        let cfg = resolve_config("mock", &raw).unwrap();
        assert_eq!(cfg.objects, HsmObjectIds::default());
        assert_eq!(cfg.domains, vec![1]);
        assert_eq!(cfg.pqc_key_cache_ttl, Duration::from_secs(60));
    }
}
