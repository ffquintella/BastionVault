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

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::RvError;

pub mod admin;
pub mod authz;
pub mod blob;
pub mod blobset;
pub mod ceremony;
pub mod clock;
pub mod context;
pub mod custody;
pub mod custody_store;
pub mod derive;
pub mod enroll;
pub mod node_creds;
pub mod pool;
pub mod repair;
pub mod replicate;

#[cfg(feature = "hsm_mock")]
pub mod mock;
#[cfg(feature = "hsm_yubihsm2")]
pub mod yubihsm2;

pub use blob::{
    AuthzAlg, BlobAad, BvHsmBlob, Context, DeviceBinding, HsmId, Purpose, BV_HSM_BLOB_VERSION, BV_HSM_BLOB_VERSION_V1,
};
pub use blobset::BvHsmBlobSet;
pub use custody_store::{BvHsmHandle, CustodyStore};

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

    /// `<backend_type>:<serial>`, the device identity bound into v2 blobs.
    /// Fails, rather than inventing an id, when the serial is unknown.
    fn hsm_id(&self) -> Result<HsmId, RvError> {
        HsmId::from_parts(self.backend_type(), &self.device_serial())
    }

    /// Algorithm of the `bv-authz` key. Both backends sign with Ed25519.
    fn authz_alg(&self) -> AuthzAlg {
        AuthzAlg::Ed25519
    }

    /// Everything a v2 blob AAD binds about this device.
    fn device_binding(&self) -> Result<DeviceBinding, RvError> {
        Ok(DeviceBinding { hsm_id: self.hsm_id()?, authz_alg: self.authz_alg(), authz_fp: self.authz_fingerprint()? })
    }

    /// AES-CCM wrap of `plaintext` under the HSM-resident wrap key `key`,
    /// producing a serialized v2 [`BvHsmBlob`] bound to `ctx` and this device.
    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError>;

    /// AES-CCM unwrap of a serialized [`BvHsmBlob`] (v1 or v2), enforcing that
    /// its AAD matches `ctx` and this device ([`blob::open_blob`]).
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

    /// ECDH between the HSM-resident P-256 key `key` (`bv-identity` in the
    /// per-node topology) and a peer SEC1-uncompressed public key. Result is
    /// the raw shared X coordinate.
    async fn derive_ecdh(&self, key: HsmObjectId, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Hardware randomness. Augments, never replaces, the host CSPRNG (rule 3).
    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Health probe: the serial the device reports now, through `device-info`
    /// where the backend can send it without a session. An unreachable device
    /// or link is [`RvError::ErrHsmTransport`].
    async fn probe(&self) -> Result<String, RvError>;

    /// Release this client's session slot, if it holds one.
    async fn close_session(&self) -> Result<(), RvError> {
        Ok(())
    }
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
    /// `bv-seed-ecdh` (pool layout, T454 phase 4): the node-usable ECDH key,
    /// so `bv-identity` can stay admin-only. Per-node devices do not have it.
    pub seed_ecdh: HsmObjectId,
}

impl Default for HsmObjectIds {
    fn default() -> Self {
        // Object 1 is the device's default auth key; BastionVault provisions
        // its own objects at fixed, minimal-capability ids from there.
        Self { auth_key: 1, wrap_barrier: 2, wrap_pqc: 3, identity: 4, authz: 5, seed_ecdh: 6 }
    }
}

/// Fully-resolved HSM seal configuration (env-expanded, defaults applied). The
/// raw HCL shape is parsed in `crate::config` and handed to [`resolve_config`].
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
    /// `Some` for `topology = "pool"` (T454); `None` is the per-node topology.
    pub pool: Option<ResolvedPoolConfig>,
    /// Whether `recovery` was written in the config. Pool init refuses an
    /// implicit recovery posture (spec § Barrier KEK, bootstrap at init).
    pub recovery_explicit: bool,
}

impl ResolvedHsmConfig {
    pub fn is_pool(&self) -> bool {
        self.pool.is_some()
    }
}

/// Members a pool has, exactly (spec § Configuration, validation rules).
pub const POOL_MEMBER_COUNT: usize = 2;
/// `min_wrap_copies` when the config leaves it out.
pub const DEFAULT_MIN_WRAP_COPIES: usize = 1;
const MAX_MEMBER_NAME_LEN: usize = 64;

/// One `member "<name>" { ... }` block of a pool, validated. A *bootstrap*
/// entry: after init the seal record's member entry is authoritative, and
/// only `connector` / `state_path` (where this node reaches the device) apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPoolMember {
    pub name: String,
    /// `https://` mTLS gateway (yubihsm2; used from T454 phase 3).
    pub gateway: String,
    /// Local `yubihsm-connector` URL or `usb` (yubihsm2).
    pub connector: String,
    pub serial: String,
    /// File backing the mock device (mock only).
    pub state_path: String,
    pub prefer: bool,
}

impl ResolvedPoolMember {
    pub fn hsm_id(&self, backend_type: &str) -> Result<HsmId, RvError> {
        HsmId::from_parts(backend_type, &self.serial)
    }
}

/// The node's mTLS client identity for the HSM link (consumed by T454 phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLink {
    pub ca_file: String,
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPoolConfig {
    /// 1 (default) or 2: copies a new blob set needs before it is stored.
    pub min_wrap_copies: usize,
    /// Blob sets the repair job re-wraps per second at most.
    pub repair_rate: u32,
    pub credential_dir: String,
    pub link: Option<ResolvedLink>,
    /// Exactly [`POOL_MEMBER_COUNT`], sorted by name.
    pub members: Vec<ResolvedPoolMember>,
}

/// Raw `member "<name>" { ... }` block inside a pool `hsm` block.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HsmMemberBlock {
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub connector: String,
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub state_path: String,
    #[serde(default)]
    pub prefer: bool,
}

/// Raw `link { ... }` block inside a pool `hsm` block.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HsmLinkBlock {
    #[serde(default)]
    pub ca_file: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
}

/// Raw, serde-parsed HCL `hsm "<label>" { ... }` block. Kept string-typed and
/// permissive; validation and env-expansion happen in [`resolve_config`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HsmConfigBlock {
    /// `""` / `"per-node"` (default) or `"pool"`.
    #[serde(default)]
    pub topology: String,
    /// Pool only. `0` means unset (the default, 1).
    #[serde(default)]
    pub min_wrap_copies: u32,
    /// Pool only: where per-node credentials live (T454 phase 4).
    #[serde(default)]
    pub credential_dir: String,
    #[serde(default)]
    pub link: Option<HsmLinkBlock>,
    #[serde(default)]
    pub member: BTreeMap<String, HsmMemberBlock>,
    /// Device-log drain mode (T454 phase 6). Refused until it is implemented.
    #[serde(default)]
    pub device_audit: String,
    /// Pool only: repair job rate, sets per second (default 2).
    #[serde(default)]
    pub repair_rate: Option<u64>,
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
    #[serde(default)]
    pub seed_ecdh_key_id: u16,
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

    refuse_unimplemented_settings(raw)?;
    let pool = match raw.topology.trim() {
        "" | "per-node" => {
            refuse_pool_only_settings(raw)?;
            None
        }
        "pool" => Some(resolve_pool(&backend_type, raw)?),
        other => {
            return Err(RvError::ErrHsmConfigInvalid(format!(
                "unknown HSM topology {other:?}; expected \"per-node\" or \"pool\""
            )))
        }
    };

    let defaults = HsmObjectIds::default();
    let objects = HsmObjectIds {
        auth_key: if raw.auth_key_id != 0 { raw.auth_key_id } else { defaults.auth_key },
        wrap_barrier: if raw.wrap_barrier_key_id != 0 { raw.wrap_barrier_key_id } else { defaults.wrap_barrier },
        wrap_pqc: if raw.wrap_pqc_key_id != 0 { raw.wrap_pqc_key_id } else { defaults.wrap_pqc },
        identity: if raw.identity_key_id != 0 { raw.identity_key_id } else { defaults.identity },
        authz: if raw.authz_key_id != 0 { raw.authz_key_id } else { defaults.authz },
        seed_ecdh: if raw.seed_ecdh_key_id != 0 { raw.seed_ecdh_key_id } else { defaults.seed_ecdh },
    };

    // A pool node authenticates with per-node credentials (resolve_pool
    // refuses `password`), so only the per-node yubihsm2 seal needs one.
    let password = if backend_type == "yubihsm2" && pool.is_none() {
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
    validate_node_id(&node_id)?;

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
        pool,
        recovery_explicit: !raw.recovery.trim().is_empty(),
    })
}

fn config_err(msg: impl Into<String>) -> RvError {
    RvError::ErrHsmConfigInvalid(msg.into())
}

/// `device_audit` configures a job that does not exist yet. An accepted but
/// ignored audit setting would be a silent gap, so it fails.
fn refuse_unimplemented_settings(raw: &HsmConfigBlock) -> Result<(), RvError> {
    if !raw.device_audit.trim().is_empty() {
        return Err(config_err("`device_audit` is not implemented yet (device-log drain, T454 phase 6); remove it"));
    }
    Ok(())
}

/// Pool settings in a per-node block are almost certainly a missing
/// `topology = "pool"`; refusing them beats silently running per-node.
fn refuse_pool_only_settings(raw: &HsmConfigBlock) -> Result<(), RvError> {
    let mut stray = Vec::new();
    if !raw.member.is_empty() {
        stray.push("member");
    }
    if raw.link.is_some() {
        stray.push("link");
    }
    if raw.min_wrap_copies != 0 {
        stray.push("min_wrap_copies");
    }
    if raw.repair_rate.is_some() {
        stray.push("repair_rate");
    }
    if !raw.credential_dir.is_empty() {
        stray.push("credential_dir");
    }
    if stray.is_empty() {
        Ok(())
    } else {
        Err(config_err(format!("{} require topology = \"pool\"", stray.join(", "))))
    }
}

pub(crate) fn validate_member_name(name: &str) -> Result<(), RvError> {
    let ok_chars = name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if name.is_empty() || name.len() > MAX_MEMBER_NAME_LEN || !ok_chars {
        return Err(config_err(format!(
            "HSM pool member name {name:?} must be 1-{MAX_MEMBER_NAME_LEN} characters of [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// Validate a `topology = "pool"` block (spec § Configuration).
fn resolve_pool(backend_type: &str, raw: &HsmConfigBlock) -> Result<ResolvedPoolConfig, RvError> {
    if !raw.password.is_empty() || raw.auth_key_id != 0 {
        return Err(config_err(
            "`password` and `auth_key_id` are not used with topology = \"pool\": each node authenticates to each \
             member with its own credentials from `credential_dir`",
        ));
    }
    if !raw.connector.is_empty() || !raw.state_path.is_empty() {
        return Err(config_err(
            "with topology = \"pool\", set `connector` / `state_path` inside each `member` block, not at the top level",
        ));
    }
    if raw.member.len() != POOL_MEMBER_COUNT {
        return Err(config_err(format!(
            "topology = \"pool\" requires exactly {POOL_MEMBER_COUNT} `member` blocks, found {}",
            raw.member.len()
        )));
    }

    let mut members = Vec::with_capacity(raw.member.len());
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (name, block) in &raw.member {
        validate_member_name(name)?;
        if block.serial.trim().is_empty() {
            return Err(config_err(format!("HSM pool member {name:?} has no `serial`")));
        }
        let member = ResolvedPoolMember {
            name: name.clone(),
            gateway: block.gateway.trim().to_string(),
            connector: block.connector.trim().to_string(),
            serial: block.serial.trim().to_string(),
            state_path: block.state_path.trim().to_string(),
            prefer: block.prefer,
        };
        let hsm_id = member
            .hsm_id(backend_type)
            .map_err(|e| config_err(format!("HSM pool member {name:?} has an invalid `serial`: {e}")))?;
        if !ids.insert(hsm_id.clone()) {
            return Err(config_err(format!("two HSM pool members name the same device {hsm_id}")));
        }
        match backend_type {
            "mock" => {
                if !member.gateway.is_empty() || !member.connector.is_empty() {
                    return Err(config_err(format!(
                        "mock HSM pool member {name:?}: the mock has no link; set `state_path` instead of \
                         `gateway` / `connector`"
                    )));
                }
                if member.state_path.is_empty() {
                    return Err(config_err(format!("mock HSM pool member {name:?} needs a `state_path`")));
                }
                if !paths.insert(member.state_path.clone()) {
                    return Err(config_err(format!(
                        "mock HSM pool members share the state_path {:?}, which would be one device twice",
                        member.state_path
                    )));
                }
            }
            _ => {
                if member.gateway.is_empty() == member.connector.is_empty() {
                    return Err(config_err(format!(
                        "HSM pool member {name:?} needs exactly one of `gateway` and `connector`"
                    )));
                }
                if !member.gateway.is_empty() && !member.gateway.starts_with("https://") {
                    return Err(config_err(format!(
                        "HSM pool member {name:?}: `gateway` must be an https:// (mTLS) URL"
                    )));
                }
                if !member.state_path.is_empty() {
                    return Err(config_err(format!("`state_path` is mock-only (member {name:?})")));
                }
            }
        }
        members.push(member);
    }
    if members.iter().filter(|m| m.prefer).count() > 1 {
        return Err(config_err("at most one HSM pool member may set `prefer = true`"));
    }

    let link = match &raw.link {
        Some(l) => {
            let link = ResolvedLink {
                ca_file: l.ca_file.trim().to_string(),
                cert_file: l.cert_file.trim().to_string(),
                key_file: l.key_file.trim().to_string(),
            };
            if link.ca_file.is_empty() || link.cert_file.is_empty() || link.key_file.is_empty() {
                return Err(config_err("the HSM `link` block needs `ca_file`, `cert_file` and `key_file`"));
            }
            Some(link)
        }
        None => None,
    };
    if link.is_none() && members.iter().any(|m| !m.gateway.is_empty()) {
        return Err(config_err("a `link` block is required when any HSM pool member uses `gateway`"));
    }

    let credential_dir = raw.credential_dir.trim().to_string();
    if backend_type == "yubihsm2" && credential_dir.is_empty() {
        return Err(config_err("a yubihsm2 HSM pool needs `credential_dir` for the node's per-member credentials"));
    }

    let min_wrap_copies = match raw.min_wrap_copies {
        0 => DEFAULT_MIN_WRAP_COPIES,
        n @ (1 | 2) => n as usize,
        other => return Err(config_err(format!("`min_wrap_copies` must be 1 or 2, got {other}"))),
    };

    let repair_rate = match raw.repair_rate {
        None => repair::DEFAULT_REPAIR_RATE,
        Some(n @ 1..=repair::MAX_REPAIR_RATE_U64) => n as u32,
        Some(other) => {
            return Err(config_err(format!(
                "`repair_rate` must be 1 to {} sets per second, got {other}",
                repair::MAX_REPAIR_RATE_U64
            )))
        }
    };

    Ok(ResolvedPoolConfig { min_wrap_copies, repair_rate, credential_dir, link, members })
}

/// Longest node id accepted; generous for FQDN-style ids.
const MAX_NODE_ID_LEN: usize = 128;

/// A node id names the per-node authz counter key
/// (`core/hsm-authz-counter/<node_id>`), so it must be one safe path segment.
pub fn validate_node_id(node_id: &str) -> Result<(), RvError> {
    let ok_chars = node_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if node_id.is_empty() || node_id.len() > MAX_NODE_ID_LEN || !ok_chars || node_id == "." || node_id == ".." {
        return Err(RvError::ErrHsmConfigInvalid(format!(
            "HSM node_id {node_id:?} must be 1-{MAX_NODE_ID_LEN} characters of [A-Za-z0-9._-] and not \".\" or \"..\""
        )));
    }
    Ok(())
}

fn hostname_or(fallback: &str) -> String {
    std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| fallback.to_string())
}

/// True when the running environment is production, per `BVAULT_ENV` or an
/// explicit config value. Used to refuse the mock backend (spec § guardrails).
pub fn is_production_env() -> bool {
    std::env::var("BVAULT_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false)
}

/// The mock backend's guard: no hardware protection, so never in production.
pub fn refuse_mock_in_production() -> Result<(), RvError> {
    if is_production_env() {
        log::error!(target: "security", "refusing to start: mock HSM backend is not permitted in production");
        return Err(RvError::ErrHsmMockRefusedInProduction);
    }
    Ok(())
}

/// One pool member as this node must reach it: the record's name, device and
/// gateway (or, before init, the config's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberTarget {
    pub name: String,
    pub hsm_id: HsmId,
    pub gateway: String,
}

/// How this node reaches pool members: a node client (with this node's
/// credential for the device, when it holds one) or a `bv-admin` session.
pub trait MemberOpener: Send + Sync {
    fn open_client(
        &self,
        target: &MemberTarget,
        credential: Option<admin::NodeCredential>,
    ) -> Result<Arc<dyn HsmBackend>, RvError>;

    fn open_admin(&self, target: &MemberTarget, password: &str) -> Result<Box<dyn admin::HsmAdminSession>, RvError>;
}

/// The production opener: a member is reached through this node's `member`
/// block (mock: its `state_path`). A `yubihsm2` pool needs the HSM link wired
/// into the client, which this build does not have, so it is refused.
pub struct ConfigMemberOpener {
    #[cfg_attr(not(feature = "hsm_mock"), allow(dead_code))]
    config: ResolvedHsmConfig,
    #[cfg_attr(not(feature = "hsm_mock"), allow(dead_code))]
    clock: Arc<dyn clock::Clock>,
    /// One in-process device per `state_path`, so every client and admin
    /// session of this node shares its session table.
    #[cfg(feature = "hsm_mock")]
    devices: std::sync::Mutex<BTreeMap<String, Arc<mock::MockHsmDevice>>>,
}

impl ConfigMemberOpener {
    /// Refuses, up front, a pool this build or environment cannot run.
    pub fn new(config: &ResolvedHsmConfig, clock: Arc<dyn clock::Clock>) -> Result<Self, RvError> {
        match config.backend_type.as_str() {
            "mock" => {
                refuse_mock_in_production()?;
                if cfg!(not(feature = "hsm_mock")) {
                    return Err(RvError::ErrHsmConfigInvalid(
                        "mock HSM backend requested but this build lacks the `hsm_mock` feature".into(),
                    ));
                }
            }
            "yubihsm2" => {
                if cfg!(not(feature = "hsm_yubihsm2")) {
                    return Err(RvError::ErrHsmConfigInvalid(
                        "yubihsm2 backend requested but this build lacks the `hsm_yubihsm2` feature".into(),
                    ));
                }
            }
            other => return Err(RvError::ErrHsmConfigInvalid(format!("unknown HSM backend {other:?}"))),
        }
        Ok(Self {
            config: config.clone(),
            clock,
            #[cfg(feature = "hsm_mock")]
            devices: std::sync::Mutex::new(BTreeMap::new()),
        })
    }

    #[cfg(feature = "hsm_mock")]
    fn mock_device(&self, target: &MemberTarget) -> Result<Arc<mock::MockHsmDevice>, RvError> {
        let pool = self.config.pool.as_ref().ok_or_else(|| config_err("not a pool configuration"))?;
        let block = pool.members.iter().find(|m| m.name == target.name).ok_or_else(|| {
            RvError::ErrHsmTransport(format!(
                "this node's config has no `member \"{}\"` block, and a mock member is reached only through its \
                 `state_path`",
                target.name
            ))
        })?;
        let mut devices = self.devices.lock().map_err(|_| RvError::ErrRwLockWritePoison)?;
        if let Some(device) = devices.get(&block.state_path) {
            return Ok(device.clone());
        }
        let serial = target.hsm_id.as_str().split_once(':').map(|(_, s)| s).unwrap_or_default();
        let device = mock::MockHsmDevice::open(&block.state_path, Some(serial), self.clock.clone())?;
        devices.insert(block.state_path.clone(), device.clone());
        Ok(device)
    }
}

impl ConfigMemberOpener {
    /// Where this node reaches `target` on a YubiHSM 2 pool: its own block's
    /// `connector` (local device), else the record's gateway through the link.
    #[cfg(feature = "hsm_yubihsm2")]
    fn yubihsm2_route(
        &self,
        target: &MemberTarget,
    ) -> Result<(yubihsm::Connector, Option<bv_hsm_link::Relay>), RvError> {
        let pool = self.config.pool.as_ref().ok_or_else(|| config_err("not a pool configuration"))?;
        let block = pool.members.iter().find(|m| m.name == target.name);
        let local = block.map(|b| b.connector.as_str()).unwrap_or_default();
        let gateway = if target.gateway.is_empty() { block.map(|b| b.gateway.as_str()).unwrap_or_default() } else { &target.gateway };
        if local.is_empty() && gateway.is_empty() {
            return Err(RvError::ErrHsmTransport(format!("no connector or gateway for HSM pool member {}", target.name)));
        }
        yubihsm2::member_connector(local, gateway, pool.link.as_ref())
    }
}

impl MemberOpener for ConfigMemberOpener {
    fn open_client(
        &self,
        target: &MemberTarget,
        credential: Option<admin::NodeCredential>,
    ) -> Result<Arc<dyn HsmBackend>, RvError> {
        if self.config.backend_type == "yubihsm2" {
            #[cfg(feature = "hsm_yubihsm2")]
            {
                // A YubiHSM 2 pool never uses a password: no credential, no session.
                let credential = credential.ok_or_else(|| {
                    RvError::ErrHsm(format!(
                        "this node holds no credential for HSM pool member {}; enroll it (`operator hsm bootstrap` \
                         before init, `operator hsm node add` after)",
                        target.name
                    ))
                })?;
                let (connector, relay) = self.yubihsm2_route(target)?;
                let client = yubihsm2::YubiHsm2Backend::open_pool_member(connector, relay, &credential, self.config.objects)?;
                return Ok(Arc::new(client));
            }
            #[cfg(not(feature = "hsm_yubihsm2"))]
            return Err(RvError::ErrHsmConfigInvalid("this build lacks the `hsm_yubihsm2` feature".into()));
        }
        #[cfg(feature = "hsm_mock")]
        {
            let device = self.mock_device(target)?;
            let (node, objects) = (&self.config.node_id, self.config.objects);
            let client = match credential {
                Some(credential) => mock::MockHsmBackend::connect_with_credential(device, node, objects, credential)?,
                None => mock::MockHsmBackend::connect(device, node, objects)?,
            };
            Ok(Arc::new(client))
        }
        #[cfg(not(feature = "hsm_mock"))]
        {
            let _ = (target, credential);
            Err(RvError::ErrHsmConfigInvalid("this build has no mock HSM backend".into()))
        }
    }

    fn open_admin(&self, target: &MemberTarget, password: &str) -> Result<Box<dyn admin::HsmAdminSession>, RvError> {
        if self.config.backend_type == "yubihsm2" {
            #[cfg(feature = "hsm_yubihsm2")]
            {
                let (connector, relay) = self.yubihsm2_route(target)?;
                let session = yubihsm2::YubiHsm2AdminSession::open(connector, relay, password, self.config.objects)?;
                return Ok(Box::new(session));
            }
            #[cfg(not(feature = "hsm_yubihsm2"))]
            return Err(RvError::ErrHsmConfigInvalid("this build lacks the `hsm_yubihsm2` feature".into()));
        }
        #[cfg(feature = "hsm_mock")]
        {
            let device = self.mock_device(target)?;
            Ok(Box::new(device.admin_session(password, self.config.objects)?))
        }
        #[cfg(not(feature = "hsm_mock"))]
        {
            let _ = (target, password);
            Err(RvError::ErrHsmConfigInvalid("this build has no mock HSM backend".into()))
        }
    }
}

/// Construct the configured backend. Only compiled backends are available;
/// requesting a backend whose feature is off is a config error, not a panic.
#[maybe_async::maybe_async]
pub async fn new_backend(config: &ResolvedHsmConfig) -> Result<Arc<dyn HsmBackend>, RvError> {
    match config.backend_type.as_str() {
        "mock" => {
            refuse_mock_in_production()?;
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
    fn resolve_rejects_node_ids_that_are_not_one_path_segment() {
        for bad in ["a/b", "..", ".", "n 1", "x\\y", "\u{0}", "a:b"] {
            let raw = HsmConfigBlock { node_id: bad.into(), ..Default::default() };
            assert!(resolve_config("mock", &raw).is_err(), "{bad:?} must be rejected");
        }
        for good in ["vault-3", "node.example.com", "n_1"] {
            let raw = HsmConfigBlock { node_id: good.into(), ..Default::default() };
            assert!(resolve_config("mock", &raw).is_ok(), "{good:?} must be accepted");
        }
    }

    #[test]
    fn resolve_applies_object_id_defaults() {
        let raw = HsmConfigBlock { node_id: "n1".into(), ..Default::default() };
        let cfg = resolve_config("mock", &raw).unwrap();
        assert_eq!(cfg.objects, HsmObjectIds::default());
        assert_eq!(cfg.domains, vec![1]);
        assert_eq!(cfg.pqc_key_cache_ttl, Duration::from_secs(60));
        assert!(cfg.pool.is_none(), "per-node stays the default");
        assert!(!cfg.recovery_explicit);
    }

    fn mock_member(serial: &str, path: &str) -> HsmMemberBlock {
        HsmMemberBlock { serial: serial.into(), state_path: path.into(), ..Default::default() }
    }

    fn mock_pool() -> HsmConfigBlock {
        let mut raw = HsmConfigBlock { topology: "pool".into(), node_id: "n1".into(), ..Default::default() };
        raw.member.insert("hsm-a".into(), mock_member("MOCK-A", "/tmp/a.json"));
        raw.member.insert("hsm-b".into(), mock_member("MOCK-B", "/tmp/b.json"));
        raw
    }

    fn yubi_pool() -> HsmConfigBlock {
        let mut raw = HsmConfigBlock {
            topology: "pool".into(),
            node_id: "vault-3".into(),
            credential_dir: "/var/lib/bastionvault/hsm".into(),
            link: Some(HsmLinkBlock { ca_file: "ca.pem".into(), cert_file: "n.pem".into(), key_file: "n.key".into() }),
            ..Default::default()
        };
        let gw = |url: &str, serial: &str| HsmMemberBlock {
            gateway: url.into(),
            serial: serial.into(),
            ..Default::default()
        };
        raw.member.insert("hsm-a".into(), gw("https://hsm-a.internal:8250", "0012345678"));
        raw.member.insert("hsm-b".into(), gw("https://hsm-b.internal:8250", "0087654321"));
        raw
    }

    fn rejects(label: &str, raw: &HsmConfigBlock, needle: &str) {
        match resolve_config(label, raw) {
            Err(RvError::ErrHsmConfigInvalid(msg)) => assert!(msg.contains(needle), "{msg:?} lacks {needle:?}"),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("config must be rejected ({needle})"),
        }
    }

    #[test]
    fn pool_config_resolves_with_defaults() {
        let cfg = resolve_config("mock", &mock_pool()).unwrap();
        let pool = cfg.pool.as_ref().unwrap();
        assert_eq!(pool.min_wrap_copies, DEFAULT_MIN_WRAP_COPIES);
        assert_eq!(pool.members.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(), vec!["hsm-a", "hsm-b"]);
        assert_eq!(pool.members[0].hsm_id("mock").unwrap().as_str(), "mock:MOCK-A");

        let cfg = resolve_config("yubihsm2", &yubi_pool()).unwrap();
        assert!(cfg.password.is_empty(), "pool nodes do not use a password");
        assert!(cfg.pool.unwrap().link.is_some());

        let mut two = mock_pool();
        two.min_wrap_copies = 2;
        two.recovery = "none".into();
        let cfg = resolve_config("mock", &two).unwrap();
        assert_eq!(cfg.pool.unwrap().min_wrap_copies, 2);
        assert!(cfg.recovery_explicit);
    }

    #[test]
    fn pool_config_validation_rules() {
        let mut one = mock_pool();
        one.member.remove("hsm-b");
        rejects("mock", &one, "exactly 2");

        let mut no_serial = mock_pool();
        no_serial.member.get_mut("hsm-a").unwrap().serial.clear();
        rejects("mock", &no_serial, "no `serial`");

        let mut bad_serial = mock_pool();
        bad_serial.member.get_mut("hsm-a").unwrap().serial = "a/b".into();
        rejects("mock", &bad_serial, "invalid `serial`");

        let mut same_device = mock_pool();
        same_device.member.get_mut("hsm-b").unwrap().serial = "MOCK-A".into();
        rejects("mock", &same_device, "same device");

        let mut same_path = mock_pool();
        same_path.member.get_mut("hsm-b").unwrap().state_path = "/tmp/a.json".into();
        rejects("mock", &same_path, "state_path");

        let mut mock_gateway = mock_pool();
        mock_gateway.member.get_mut("hsm-a").unwrap().gateway = "https://x:8250".into();
        rejects("mock", &mock_gateway, "no link");

        let mut both = yubi_pool();
        both.member.get_mut("hsm-a").unwrap().connector = "http://127.0.0.1:12345".into();
        rejects("yubihsm2", &both, "exactly one of `gateway` and `connector`");

        let mut neither = yubi_pool();
        neither.member.get_mut("hsm-a").unwrap().gateway.clear();
        rejects("yubihsm2", &neither, "exactly one of `gateway` and `connector`");

        let mut plain_http = yubi_pool();
        plain_http.member.get_mut("hsm-a").unwrap().gateway = "http://hsm-a:8250".into();
        rejects("yubihsm2", &plain_http, "https://");

        let mut no_link = yubi_pool();
        no_link.link = None;
        rejects("yubihsm2", &no_link, "`link` block is required");

        // A node that reaches both devices through local connectors needs no link.
        let mut local = yubi_pool();
        local.link = None;
        for m in local.member.values_mut() {
            m.gateway.clear();
            m.connector = "usb".into();
        }
        resolve_config("yubihsm2", &local).unwrap();

        let mut password = yubi_pool();
        password.password = "env:BVAULT_HSM_PASSWORD".into();
        rejects("yubihsm2", &password, "`password` and `auth_key_id`");
        let mut auth_key = mock_pool();
        auth_key.auth_key_id = 3;
        rejects("mock", &auth_key, "`password` and `auth_key_id`");

        let mut no_creds = yubi_pool();
        no_creds.credential_dir.clear();
        rejects("yubihsm2", &no_creds, "credential_dir");

        let mut copies = mock_pool();
        copies.min_wrap_copies = 3;
        rejects("mock", &copies, "1 or 2");

        let mut prefer = mock_pool();
        prefer.member.values_mut().for_each(|m| m.prefer = true);
        rejects("mock", &prefer, "prefer");

        let mut top_level_path = mock_pool();
        top_level_path.state_path = "/tmp/x.json".into();
        rejects("mock", &top_level_path, "inside each `member` block");

        let mut topology = mock_pool();
        topology.topology = "mesh".into();
        rejects("mock", &topology, "unknown HSM topology");
    }

    #[test]
    fn per_node_refuses_pool_settings_and_unbuilt_jobs() {
        let mut stray = mock_pool();
        stray.topology.clear();
        rejects("mock", &stray, "require topology = \"pool\"");

        let audit = HsmConfigBlock { device_audit: "forced".into(), ..Default::default() };
        rejects("mock", &audit, "device_audit");
        let mut rate = mock_pool();
        rate.topology.clear();
        rate.member.clear();
        rate.repair_rate = Some(2);
        rejects("mock", &rate, "repair_rate");
    }

    #[test]
    fn repair_rate_is_bounded() {
        let mut pool = mock_pool();
        assert_eq!(resolve_config("mock", &pool).unwrap().pool.unwrap().repair_rate, repair::DEFAULT_REPAIR_RATE);
        pool.repair_rate = Some(10);
        assert_eq!(resolve_config("mock", &pool).unwrap().pool.unwrap().repair_rate, 10);
        for bad in [0, repair::MAX_REPAIR_RATE_U64 + 1] {
            pool.repair_rate = Some(bad);
            rejects("mock", &pool, "repair_rate");
        }
    }
}
