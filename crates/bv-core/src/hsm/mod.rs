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
// Yubico chain pinning (T454 phase 7): compiled with the hardware backend,
// and in unit tests, which check it against generated chains.
#[cfg(any(feature = "hsm_yubihsm2", test))]
pub mod attestation;
pub mod authz;
pub mod blob;
pub mod blobset;
pub mod ceremony;
pub mod clock;
pub mod context;
pub mod custody;
pub mod custody_store;
pub mod derive;
pub mod device_audit;
pub mod enroll;
// The phase 7 hardware harness: test tooling, never in a product build.
#[cfg(any(feature = "hsm_hardware_tests", test))]
pub mod hw_validation;
pub mod node_creds;
pub mod pool;
pub mod recovery;
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

    /// Requests this client's HSM link relay forwarded and failed so far
    /// (running totals, for `bv_hsm_link_requests_total`). `None` without a
    /// relay: a local connector or the mock.
    fn link_totals(&self) -> Option<(u64, u64)> {
        None
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
    /// PEM file with the Yubico attestation root and intermediates (yubihsm2
    /// only, T454 phase 7). `None` refuses every YubiHSM 2 attestation.
    pub attestation_roots_file: Option<String>,
}

impl ResolvedHsmConfig {
    pub fn is_pool(&self) -> bool {
        self.pool.is_some()
    }
}

/// The most devices a pool holds: `member` blocks in the config, and members
/// that are not retired in the seal record (spec § Pool of one, R3). One is a
/// pool of one, which runs without redundancy until the second is added.
pub const MAX_POOL_MEMBERS: usize = 2;
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

/// The per-node device a pool node migrates its KEK from (`migrate_from`).
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedMigrateFrom {
    /// `yubihsm-connector` URL or `usb` (yubihsm2).
    pub connector: String,
    /// The mock device's state file (mock).
    pub state_path: String,
    pub auth_key_id: u16,
    /// The per-node auth-key password, from `env:` (yubihsm2 only).
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for ResolvedMigrateFrom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedMigrateFrom")
            .field("connector", &self.connector)
            .field("state_path", &self.state_path)
            .field("auth_key_id", &self.auth_key_id)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPoolConfig {
    /// 1 (default) or 2: copies a new blob set needs before it is stored.
    pub min_wrap_copies: usize,
    /// Blob sets the repair job re-wraps per second at most.
    pub repair_rate: u32,
    pub credential_dir: String,
    pub link: Option<ResolvedLink>,
    /// One to [`MAX_POOL_MEMBERS`], sorted by name.
    pub members: Vec<ResolvedPoolMember>,
    /// The per-node device to migrate the KEK from (`migrate-to-pool`).
    pub migrate_from: Option<ResolvedMigrateFrom>,
    /// The device-log drain (T454 phase 6); `drain` by default.
    pub device_audit: device_audit::DeviceAuditMode,
    /// `acknowledge_single_member_without_recovery`: the operator accepts that
    /// a pool of one without a recovery key is lost with its device. Needed
    /// (only with `recovery = "none"`) to init or migrate onto one member, or
    /// to retire down to one; refused otherwise (spec § Pool of one).
    pub acknowledge_single_member_without_recovery: bool,
}

/// Raw `migrate_from { ... }` block inside a pool `hsm` block.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HsmMigrateFromBlock {
    #[serde(default)]
    pub connector: String,
    #[serde(default)]
    pub state_path: String,
    #[serde(default)]
    pub auth_key_id: u16,
    #[serde(default)]
    pub password: String,
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
    /// Pool only: the per-node device `migrate-to-pool` reads the KEK from.
    #[serde(default)]
    pub migrate_from: Option<HsmMigrateFromBlock>,
    /// Pool only: device-log drain mode, `drain` (default), `forced` or `off`
    /// (refused in production).
    #[serde(default)]
    pub device_audit: String,
    /// Pool only: repair job rate, sets per second (default 2).
    #[serde(default)]
    pub repair_rate: Option<u64>,
    /// Pool only, with `recovery = "none"`: accept a pool of one that is
    /// lost with its single device (spec § Pool of one).
    #[serde(default)]
    pub acknowledge_single_member_without_recovery: bool,
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
    /// yubihsm2 only: the operator's PEM file of Yubico attestation roots
    /// and intermediates, which attestation is pinned to (T454 phase 7).
    #[serde(default)]
    pub attestation_roots_file: String,
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

    let attestation_roots_file = match raw.attestation_roots_file.trim() {
        "" => None,
        _ if backend_type != "yubihsm2" => {
            return Err(config_err(
                "`attestation_roots_file` pins the Yubico attestation chain and is for the yubihsm2 backend only; \
                 the mock attests with its own test CA",
            ))
        }
        path => Some(path.to_string()),
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
        pool,
        recovery_explicit: !raw.recovery.trim().is_empty(),
        attestation_roots_file,
    })
}

fn config_err(msg: impl Into<String>) -> RvError {
    RvError::ErrHsmConfigInvalid(msg.into())
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
    // The drain reads a pool member's log with `bv-auditor`; a per-node device
    // has no such key, so the setting would configure nothing.
    if !raw.device_audit.trim().is_empty() {
        stray.push("device_audit");
    }
    if raw.migrate_from.is_some() {
        stray.push("migrate_from");
    }
    if !raw.credential_dir.is_empty() {
        stray.push("credential_dir");
    }
    if raw.acknowledge_single_member_without_recovery {
        stray.push("acknowledge_single_member_without_recovery");
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
    if raw.member.is_empty() || raw.member.len() > MAX_POOL_MEMBERS {
        return Err(config_err(format!(
            "topology = \"pool\" takes one or {MAX_POOL_MEMBERS} `member` blocks, found {}: a cluster has at most \
             {MAX_POOL_MEMBERS} HSMs, and one is a pool of one (no redundancy; add the second device later with \
             `operator hsm member add`)",
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

    let link = resolve_link(raw.link.as_ref(), &members)?;

    let credential_dir = raw.credential_dir.trim().to_string();
    if backend_type == "yubihsm2" && credential_dir.is_empty() {
        return Err(config_err("a yubihsm2 HSM pool needs `credential_dir` for the node's per-member credentials"));
    }

    let min_wrap_copies = match raw.min_wrap_copies {
        0 => DEFAULT_MIN_WRAP_COPIES,
        n @ (1 | 2) => n as usize,
        other => return Err(config_err(format!("`min_wrap_copies` must be 1 or 2, got {other}"))),
    };
    // Each copy is on a distinct member: a pool of one cannot hold two, and
    // a lower value is never picked for the operator.
    if min_wrap_copies > members.len() {
        return Err(config_err(format!(
            "`min_wrap_copies = {min_wrap_copies}` needs {min_wrap_copies} members, but this pool has {} `member` \
             block(s); a pool of one stores one copy of each set (set min_wrap_copies = 1, or list both members)",
            members.len()
        )));
    }

    // The acknowledgement qualifies `recovery = "none"`, and only that.
    let acknowledge_single_member_without_recovery = raw.acknowledge_single_member_without_recovery;
    if acknowledge_single_member_without_recovery && RecoveryMode::parse(&raw.recovery)? != RecoveryMode::None {
        return Err(config_err(
            "`acknowledge_single_member_without_recovery` accepts a pool of one without a recovery key; it \
             contradicts recovery = \"shamir-ceremony\", which makes one. Remove one of the two",
        ));
    }

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

    let migrate_from = match &raw.migrate_from {
        None => None,
        Some(m) => {
            let from = ResolvedMigrateFrom {
                connector: m.connector.trim().to_string(),
                state_path: m.state_path.trim().to_string(),
                auth_key_id: if m.auth_key_id == 0 { HsmObjectIds::default().auth_key } else { m.auth_key_id },
                password: Zeroizing::new(String::new()),
            };
            let from = match backend_type {
                "mock" if !from.state_path.is_empty() && from.connector.is_empty() && m.password.is_empty() => from,
                "mock" => return Err(config_err("a mock `migrate_from` takes only `state_path`")),
                _ if !from.connector.is_empty() && from.state_path.is_empty() && m.password.starts_with("env:") => {
                    ResolvedMigrateFrom { password: resolve_secret(&m.password)?, ..from }
                }
                _ => {
                    return Err(config_err(
                        "a yubihsm2 `migrate_from` needs `connector` and `password = \"env:VAR\"` (never a literal)",
                    ))
                }
            };
            Some(from)
        }
    };

    let device_audit = device_audit::DeviceAuditMode::parse(&raw.device_audit, is_production_env())?;

    Ok(ResolvedPoolConfig {
        min_wrap_copies,
        repair_rate,
        credential_dir,
        link,
        members,
        migrate_from,
        device_audit,
        acknowledge_single_member_without_recovery,
    })
}

impl ResolvedLink {
    /// The three files by config key, in the order errors name them.
    fn files(&self) -> [(&'static str, &str); 3] {
        [("ca_file", &self.ca_file), ("cert_file", &self.cert_file), ("key_file", &self.key_file)]
    }
}

/// The `link` this node needs to reach `member` through its `gateway`;
/// refused, naming the member, when the node's `hsm` block has none. Config
/// validation calls it for the first `gateway` member block, and the
/// YubiHSM 2 route for any member it reaches through a gateway, which covers
/// one only the seal record names (added later with `member add --gateway`)
/// that config cannot see.
pub(crate) fn link_for_gateway_member<'a>(
    member: &str,
    link: Option<&'a ResolvedLink>,
) -> Result<&'a ResolvedLink, RvError> {
    link.ok_or_else(|| {
        config_err(format!(
            "HSM pool member {member:?} is reached through its `gateway`, so a `link` block is required in this \
             node's `hsm` block: `link {{ ca_file = ..., cert_file = ..., key_file = ... }}` (the CA that issued \
             the gateway's certificate, and this node's client certificate and key)"
        ))
    })
}

/// Validate the pool's `link` block against the members that use it. A
/// `gateway` member needs a complete block; a block that is present is
/// complete and its files readable whether or not a member uses it yet, so a
/// node is never started with a link it could not open.
fn resolve_link(raw: Option<&HsmLinkBlock>, members: &[ResolvedPoolMember]) -> Result<Option<ResolvedLink>, RvError> {
    let gateway_members: Vec<&str> =
        members.iter().filter(|m| !m.gateway.is_empty()).map(|m| m.name.as_str()).collect();
    let Some(raw) = raw else {
        if let Some(first) = gateway_members.first() {
            link_for_gateway_member(first, None)?;
        }
        return Ok(None);
    };
    let link = ResolvedLink {
        ca_file: raw.ca_file.trim().to_string(),
        cert_file: raw.cert_file.trim().to_string(),
        key_file: raw.key_file.trim().to_string(),
    };
    let missing: Vec<&str> = link.files().iter().filter(|(_, path)| path.is_empty()).map(|(key, _)| *key).collect();
    if !missing.is_empty() {
        let missing = missing.iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        let used_by = match gateway_members.as_slice() {
            [] => String::new(),
            [one] => format!(", which HSM pool member {one:?} needs to reach its `gateway`"),
            many => format!(
                ", which HSM pool members {} need to reach their `gateway`",
                many.iter().map(|m| format!("{m:?}")).collect::<Vec<_>>().join(" and ")
            ),
        };
        return Err(config_err(format!(
            "the HSM `link` block is missing {missing}{used_by}; it needs `ca_file`, `cert_file` and `key_file`"
        )));
    }
    for (key, path) in link.files() {
        check_link_file_readable(key, path)?;
    }
    Ok(Some(link))
}

/// A `link` file must be a regular file this process can open, checked at
/// startup so a wrong path or permission is a config error naming the key,
/// not a relay failure the first time a member is reached. The file is
/// opened, never read: the key file is not copied into memory here.
fn check_link_file_readable(key: &str, path: &str) -> Result<(), RvError> {
    let unreadable = |why: String| config_err(format!("the HSM `link` {key} {path:?} is not readable: {why}"));
    let meta = std::fs::metadata(path).map_err(|e| unreadable(e.to_string()))?;
    if !meta.is_file() {
        return Err(unreadable("not a regular file".into()));
    }
    std::fs::File::open(path).map_err(|e| unreadable(e.to_string()))?;
    Ok(())
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

    /// A `bv-auditor` session for the device-log drain (T454 phase 6).
    fn open_auditor(
        &self,
        target: &MemberTarget,
        _credential: &device_audit::AuditorCredential,
    ) -> Result<Box<dyn device_audit::HsmAuditSession>, RvError> {
        Err(RvError::ErrHsm(format!("no bv-auditor access to HSM pool member {} from this node", target.name)))
    }
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
        // Config validation sees only `member` blocks; a member the record
        // alone names is refused here, by name, when this node has no link.
        if local.is_empty() {
            link_for_gateway_member(&target.name, pool.link.as_ref())?;
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
                let roots = self.config.attestation_roots_file.as_deref().map(std::path::PathBuf::from);
                let session =
                    yubihsm2::YubiHsm2AdminSession::open(connector, relay, password, self.config.objects, roots)?;
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

    fn open_auditor(
        &self,
        target: &MemberTarget,
        credential: &device_audit::AuditorCredential,
    ) -> Result<Box<dyn device_audit::HsmAuditSession>, RvError> {
        if self.config.backend_type == "yubihsm2" {
            // Explicit until phase 7: the entry layout and digest chain the
            // drain verifies must be confirmed on a real device first.
            return Err(RvError::ErrHsm(
                "the device-log drain on a YubiHSM 2 is not validated yet (T454 phase 7: confirm the log entry \
                 layout and digest chain on hardware)"
                    .into(),
            ));
        }
        #[cfg(feature = "hsm_mock")]
        {
            let device = self.mock_device(target)?;
            Ok(Box::new(device.auditor_session(credential)?))
        }
        #[cfg(not(feature = "hsm_mock"))]
        {
            let _ = (target, credential);
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

    /// A directory holding three readable placeholder `link` files (startup
    /// only opens them; nothing parses the contents), made once per process.
    fn link_fixture_dir() -> &'static std::path::Path {
        static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("bv-hsm-link-fixture-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            for name in ["ca.pem", "n.pem", "n.key"] {
                std::fs::write(dir.join(name), b"placeholder, not key material\n").unwrap();
            }
            dir
        })
    }

    fn link_file(name: &str) -> String {
        link_fixture_dir().join(name).to_string_lossy().into_owned()
    }

    fn readable_link() -> HsmLinkBlock {
        HsmLinkBlock { ca_file: link_file("ca.pem"), cert_file: link_file("n.pem"), key_file: link_file("n.key") }
    }

    fn yubi_pool() -> HsmConfigBlock {
        let mut raw = HsmConfigBlock {
            topology: "pool".into(),
            node_id: "vault-3".into(),
            credential_dir: "/var/lib/bastionvault/hsm".into(),
            link: Some(readable_link()),
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

    /// The Yubico trust file is a yubihsm2 setting; unset is `None`, which
    /// the attestation verifier refuses, and the mock never takes it.
    #[test]
    fn attestation_roots_file_is_yubihsm2_only() {
        assert_eq!(resolve_config("yubihsm2", &yubi_pool()).unwrap().attestation_roots_file, None);
        let mut raw = yubi_pool();
        raw.attestation_roots_file = " /etc/bastionvault/yubico-attestation.pem ".into();
        let cfg = resolve_config("yubihsm2", &raw).unwrap();
        assert_eq!(cfg.attestation_roots_file.as_deref(), Some("/etc/bastionvault/yubico-attestation.pem"));
        let mut mock = mock_pool();
        mock.attestation_roots_file = "/etc/roots.pem".into();
        rejects("mock", &mock, "yubihsm2 backend only");
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

    /// Spec § Pool of one: one or two `member` blocks, never zero or three.
    #[test]
    fn a_pool_takes_one_or_two_members() {
        let mut one = mock_pool();
        one.member.remove("hsm-b");
        let pool = resolve_config("mock", &one).unwrap().pool.unwrap();
        assert_eq!(pool.members.len(), 1);
        assert_eq!(pool.min_wrap_copies, 1);
        assert!(!pool.acknowledge_single_member_without_recovery, "never on by default");

        let mut none = mock_pool();
        none.member.clear();
        rejects("mock", &none, "one or 2 `member` blocks, found 0");
        let mut three = mock_pool();
        three.member.insert("hsm-c".into(), mock_member("MOCK-C", "/tmp/c.json"));
        rejects("mock", &three, "at most 2 HSMs");

        // Two copies cannot fit on one device, and nothing lowers the value.
        let mut strict_one = one.clone();
        strict_one.min_wrap_copies = 2;
        rejects("mock", &strict_one, "a pool of one stores one copy");
    }

    /// R2: a node on the HSM host reaches it through its loopback connector
    /// with no `link`; a node without a local device needs the mTLS link.
    #[test]
    fn a_pool_of_one_needs_mtls_only_for_a_remote_member() {
        let mut local = yubi_pool();
        local.member.remove("hsm-b");
        local.link = None;
        let a = local.member.get_mut("hsm-a").unwrap();
        a.gateway.clear();
        a.connector = "http://127.0.0.1:12345".into();
        let pool = resolve_config("yubihsm2", &local).unwrap().pool.unwrap();
        assert!(pool.link.is_none());
        assert_eq!(pool.members[0].connector, "http://127.0.0.1:12345");

        let mut remote = yubi_pool();
        remote.member.remove("hsm-b");
        resolve_config("yubihsm2", &remote).unwrap();
        remote.link = None;
        rejects("yubihsm2", &remote, "`link` block is required");
    }

    #[test]
    fn the_single_member_acknowledgement_qualifies_recovery_none_only() {
        let mut ack = mock_pool();
        ack.member.remove("hsm-b");
        ack.recovery = "none".into();
        ack.acknowledge_single_member_without_recovery = true;
        assert!(resolve_config("mock", &ack).unwrap().pool.unwrap().acknowledge_single_member_without_recovery);
        // Implicit recovery is `none` too; init still demands it be explicit.
        ack.recovery.clear();
        resolve_config("mock", &ack).unwrap();

        ack.recovery = "shamir-ceremony".into();
        rejects("mock", &ack, "contradicts recovery = \"shamir-ceremony\"");

        let per_node = HsmConfigBlock {
            node_id: "n".into(),
            acknowledge_single_member_without_recovery: true,
            ..Default::default()
        };
        rejects("mock", &per_node, "acknowledge_single_member_without_recovery require topology = \"pool\"");
    }

    #[test]
    fn pool_config_validation_rules() {
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

    /// A `gateway` member needs a complete `link` block whose files open at
    /// startup; every refusal names the member or key, and nothing degrades
    /// to starting without the link.
    #[test]
    fn gateway_members_need_a_complete_readable_link() {
        // Valid: two gateway members, link files readable; paths kept, trimmed.
        let mut valid = yubi_pool();
        valid.link.as_mut().unwrap().ca_file = format!("  {}  ", link_file("ca.pem"));
        let link = resolve_config("yubihsm2", &valid).unwrap().pool.unwrap().link.unwrap();
        assert_eq!(link.ca_file, link_file("ca.pem"));
        assert_eq!(link.cert_file, link_file("n.pem"));
        assert_eq!(link.key_file, link_file("n.key"));

        // The second device reached through its gateway, the first through
        // the local connector (the first HSM host after `member add`): the
        // refusal names the gateway member.
        let mut second_by_gateway = yubi_pool();
        let a = second_by_gateway.member.get_mut("hsm-a").unwrap();
        a.gateway.clear();
        a.connector = "http://127.0.0.1:12345".into();
        second_by_gateway.link = None;
        rejects("yubihsm2", &second_by_gateway, "HSM pool member \"hsm-b\" is reached through its `gateway`");
        rejects("yubihsm2", &second_by_gateway, "`link` block is required");

        // Incomplete: each missing key is named, with the member that needs it.
        for (key, clear) in [
            ("ca_file", (|l: &mut HsmLinkBlock| l.ca_file.clear()) as fn(&mut HsmLinkBlock)),
            ("cert_file", |l| l.cert_file = "   ".into()),
            ("key_file", |l| l.key_file.clear()),
        ] {
            let mut incomplete = second_by_gateway.clone();
            let mut link = readable_link();
            clear(&mut link);
            incomplete.link = Some(link);
            rejects("yubihsm2", &incomplete, &format!("the HSM `link` block is missing `{key}`"));
            rejects("yubihsm2", &incomplete, "which HSM pool member \"hsm-b\" needs to reach its `gateway`");
        }
        let mut two_missing = yubi_pool();
        two_missing.link = Some(HsmLinkBlock { ca_file: link_file("ca.pem"), ..Default::default() });
        rejects(
            "yubihsm2",
            &two_missing,
            "missing `cert_file`, `key_file`, which HSM pool members \"hsm-a\" and \"hsm-b\"",
        );

        // Unreadable: a missing file and a directory are refused by key and path.
        let absent = link_file("absent.key");
        let mut missing_file = second_by_gateway.clone();
        missing_file.link = Some(HsmLinkBlock { key_file: absent.clone(), ..readable_link() });
        rejects("yubihsm2", &missing_file, &format!("the HSM `link` key_file {absent:?} is not readable"));
        let dir = link_fixture_dir().to_string_lossy().into_owned();
        let mut directory = second_by_gateway.clone();
        directory.link = Some(HsmLinkBlock { ca_file: dir.clone(), ..readable_link() });
        rejects("yubihsm2", &directory, &format!("the HSM `link` ca_file {dir:?} is not readable: not a regular file"));

        // Connector-only with no link is fine; a link that is present is
        // still checked although no member uses it yet.
        let mut connector_only = second_by_gateway.clone();
        let b = connector_only.member.get_mut("hsm-b").unwrap();
        b.gateway.clear();
        b.connector = "usb".into();
        assert!(resolve_config("yubihsm2", &connector_only).unwrap().pool.unwrap().link.is_none());
        let mut unused_incomplete = connector_only.clone();
        unused_incomplete.link = Some(HsmLinkBlock { cert_file: String::new(), ..readable_link() });
        rejects("yubihsm2", &unused_incomplete, "the HSM `link` block is missing `cert_file`; it needs");
        let mut unused_unreadable = connector_only;
        unused_unreadable.link = Some(HsmLinkBlock { cert_file: link_file("absent.pem"), ..readable_link() });
        rejects("yubihsm2", &unused_unreadable, "is not readable");
    }

    /// The runtime route to a member only the seal record names uses the
    /// same refusal, by member name, when this node has no `link` block.
    #[test]
    fn a_record_only_gateway_member_is_refused_by_name_without_a_link() {
        match link_for_gateway_member("hsm-b", None) {
            Err(RvError::ErrHsmConfigInvalid(msg)) => {
                assert!(msg.contains("HSM pool member \"hsm-b\"") && msg.contains("`link` block is required"), "{msg}")
            }
            other => panic!("expected a config refusal, got {:?}", other.map(|_| ())),
        }
        let link = ResolvedLink { ca_file: "c".into(), cert_file: "n".into(), key_file: "k".into() };
        assert_eq!(link_for_gateway_member("hsm-b", Some(&link)).unwrap(), &link);
    }

    #[test]
    fn per_node_refuses_pool_settings() {
        let mut stray = mock_pool();
        stray.topology.clear();
        rejects("mock", &stray, "require topology = \"pool\"");

        // The drain is pool-only: a per-node device has no `bv-auditor`.
        let audit = HsmConfigBlock { device_audit: "forced".into(), ..Default::default() };
        rejects("mock", &audit, "device_audit require topology = \"pool\"");
        let mut rate = mock_pool();
        rate.topology.clear();
        rate.member.clear();
        rate.repair_rate = Some(2);
        rejects("mock", &rate, "repair_rate");
    }

    #[test]
    fn migrate_from_is_pool_only_and_never_a_literal_password() {
        let mut pool = mock_pool();
        pool.migrate_from = Some(HsmMigrateFromBlock { state_path: "/tmp/old.json".into(), ..Default::default() });
        let cfg = resolve_config("mock", &pool).unwrap();
        assert_eq!(cfg.pool.unwrap().migrate_from.unwrap().state_path, "/tmp/old.json");
        pool.migrate_from = Some(HsmMigrateFromBlock { connector: "usb".into(), ..Default::default() });
        rejects("mock", &pool, "only `state_path`");

        let mut yubi = yubi_pool();
        yubi.migrate_from =
            Some(HsmMigrateFromBlock { connector: "usb".into(), password: "hunter2".into(), ..Default::default() });
        rejects("yubihsm2", &yubi, "never a literal");
        std::env::set_var("BV_TEST_MIGRATE_PW", "s3cret");
        yubi.migrate_from = Some(HsmMigrateFromBlock {
            connector: "usb".into(),
            password: "env:BV_TEST_MIGRATE_PW".into(),
            ..Default::default()
        });
        let from = resolve_config("yubihsm2", &yubi).unwrap().pool.unwrap().migrate_from.unwrap();
        assert!(!format!("{from:?}").contains("s3cret"), "never printed");

        let mut per_node = HsmConfigBlock { node_id: "n".into(), ..Default::default() };
        per_node.migrate_from = Some(HsmMigrateFromBlock::default());
        rejects("mock", &per_node, "migrate_from");
    }

    #[test]
    fn device_audit_is_accepted_in_pool_mode_and_defaults_to_drain() {
        use device_audit::DeviceAuditMode;
        let mut pool = mock_pool();
        assert_eq!(resolve_config("mock", &pool).unwrap().pool.unwrap().device_audit, DeviceAuditMode::Drain);
        for (raw, mode) in [("drain", DeviceAuditMode::Drain), ("forced", DeviceAuditMode::Forced)] {
            pool.device_audit = raw.into();
            assert_eq!(resolve_config("mock", &pool).unwrap().pool.unwrap().device_audit, mode);
        }
        // `off` outside production (BVAULT_ENV unset in tests); refused in
        // production by `DeviceAuditMode::parse`, tested in `device_audit`.
        pool.device_audit = "off".into();
        assert_eq!(resolve_config("mock", &pool).unwrap().pool.unwrap().device_audit, DeviceAuditMode::Off);
        pool.device_audit = "sometimes".into();
        rejects("mock", &pool, "`device_audit` must be");
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
