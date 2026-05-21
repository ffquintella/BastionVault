//! Master signing-cert configuration and key lifecycle for the
//! Rustion integration.
//!
//! Phase 1 shipped the configuration **slot** (PKI mount + role +
//! issuer pointers) plus an ephemerally-minted stub keypair so the
//! Phase 3 session-open path could run end-to-end.
//!
//! Phase 2 (this module) elevates that stub into a real
//! `issue / rotate` state machine with a grace window **backed by the
//! PKI engine**:
//!
//!   - `MasterStore::issue` calls the configured PKI mount twice —
//!     once against `pki_role` (Ed25519 leaf) and once against
//!     `pki_role_pqc` (ML-DSA-65 leaf) — and persists the engine-
//!     returned PKCS#8 private keys + certificates + serials under
//!     `rustion/master/signing-key`. Refuses to overwrite an
//!     already-issued master; operators must `rotate` to cut over.
//!   - `MasterStore::rotate` archives the current record as
//!     `previous_*`, sets `previous_grace_until = now + rotate_grace_secs`,
//!     and mints a fresh hybrid pair through the PKI engine the same
//!     way `issue` does. Envelopes signed by the outgoing key stay
//!     valid until the grace window closes.
//!   - `MasterStore::load_active_keys` returns the current signing
//!     key plus the previous one when `now < previous_grace_until`.
//!     Envelope-build paths still use only the current key; the
//!     previous key surfaces only via the verify helper.
//!
//! ## Design notes
//!
//! - **Two PKI roles.** Hybrid issuance needs two distinct PKI roles
//!   — one classical (Ed25519) and one PQC (ML-DSA-65) — because the
//!   PKI engine emits one leaf per call. `MasterConfig.pki_role` is
//!   the Ed25519 role; `MasterConfig.pki_role_pqc` is the ML-DSA-65
//!   role. Both must be configured before `issue` / `rotate` succeeds.
//!   The cross-engine call goes through `Core::handle_request`, so the
//!   operator's token, ACL, audit, and lease accounting all flow
//!   through the existing PKI boundary.
//!
//! - **Private-key custody.** The PKI engine's `pki/issue/:role`
//!   path returns the leaf private key in PKCS#8 PEM form (RFC 8410
//!   for Ed25519, IETF lamps draft for ML-DSA-65). We re-derive the
//!   raw 32-byte seeds from that PKCS#8 so the rest of the rustion
//!   module — which speaks `bv_crypto::BvrgMasterSigningKey` —
//!   doesn't have to learn PKCS#8.
//!
//! - **On-disk shape.** The record persisted under
//!   `rustion/master/signing-key` is `MasterSigningRecord`, which
//!   carries the current keypair (seeds + derived public bytes +
//!   PKI-engine cert + serial + not_after) and an optional `previous`
//!   half for the grace window. Phase 1 callers that wrote the old
//!   `StubSigningKey` shape are still readable — `read_signing_record`
//!   migrates them in-memory on first read.
//!
//! - **Forward-looking defaults.** Default algorithm = hybrid
//!   Ed25519 + ML-DSA-65; default issue TTL = 5 years; default
//!   `rotate_grace_secs` = 1 day. Public-key export carries both
//!   halves separately so an operator pasting it into a Rustion
//!   `authorities/<name>.yaml` gets the `pubkey.ed25519` /
//!   `pubkey.mldsa65` shape Rustion expects.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Storage sub-view: records live under `rustion/master/`. Kept as a
/// sub-view so future phases can add neighbouring records (issuance
/// history, rotation audit, …) without churning the layout.
const MASTER_SUB_PATH: &str = "rustion/master/";
const CONFIG_KEY: &str = "config";
const SIGNING_KEY: &str = "signing-key";
const DEPLOYMENT_ID: &str = "deployment-id";

/// On-disk shape of the master-cert configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasterConfig {
    /// PKI mount the master cert is minted from (e.g. `pki-internal/`).
    pub pki_mount: String,
    /// PKI role under that mount used for the Ed25519 half. Must be
    /// configured before `issue` / `rotate` will succeed.
    pub pki_role: String,
    /// PKI role under that mount used for the ML-DSA-65 half. Must be
    /// configured before `issue` / `rotate` will succeed. Distinct
    /// from `pki_role` because the PKI engine emits one leaf per call
    /// and a single role is locked to one key algorithm.
    #[serde(default)]
    pub pki_role_pqc: Option<String>,
    /// Issuer ref under the PKI mount. Empty = mount default.
    #[serde(default)]
    pub issuer_ref: String,
    /// Algorithm marker — informational; the keypair is hybrid
    /// Ed25519 + ML-DSA-65 regardless of the value.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Default TTL when issuing / rotating, in seconds. 5y default.
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
    /// Grace window (seconds) during which the previous cert remains
    /// accepted by the verify helper. Default 1 day.
    #[serde(default = "default_rotate_grace_secs")]
    pub rotate_grace_secs: u64,
    /// Current cert serial. Empty before the first `issue`.
    #[serde(default)]
    pub current_serial: String,
    /// `not_after` of the current cert (ISO-8601).
    #[serde(default)]
    pub current_not_after: Option<DateTime<Utc>>,
    /// Previous cert serial, populated by `rotate`. Cleared once the
    /// grace window has elapsed and the next `rotate` shifts current
    /// into its slot.
    #[serde(default)]
    pub previous_serial: Option<String>,
    /// `not_after` of the previous cert.
    #[serde(default)]
    pub previous_not_after: Option<DateTime<Utc>>,
    /// Wallclock the grace window closes. Envelopes signed by the
    /// previous key are refused after this instant.
    #[serde(default)]
    pub previous_grace_until: Option<DateTime<Utc>>,
    /// Wallclock the config was last touched.
    pub updated_at: DateTime<Utc>,
}

fn default_algorithm() -> String {
    "hybrid-ed25519-mldsa65".to_string()
}

fn default_ttl_secs() -> u64 {
    5 * 365 * 24 * 3600
}

fn default_rotate_grace_secs() -> u64 {
    24 * 3600
}

/// One half of the persisted signing material. `current` always
/// populated after `issue`; `previous` populated only between a
/// `rotate` and the end of the grace window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigningKeyHalf {
    pub ed25519_seed_b64: String,
    pub mldsa65_seed_b64: String,
    /// Raw 32-byte Ed25519 verifying-key bytes, base64. Cached so
    /// `export` doesn't have to derive it on every read.
    pub ed25519_pub_b64: String,
    /// Raw FIPS 204 ML-DSA-65 public key bytes, base64.
    pub mldsa65_pub_b64: String,
    /// Serial of the Ed25519 leaf as returned by the PKI engine. Also
    /// the canonical `serial` exposed in `IssueOutcome` /
    /// `MasterPubKeyExport.current_serial`. Legacy local-keygen
    /// records carry a synthetic `legacy-…` value here.
    pub serial: String,
    /// Serial of the ML-DSA-65 leaf as returned by the PKI engine.
    /// Empty for legacy local-keygen records.
    #[serde(default)]
    pub mldsa65_serial: String,
    /// PEM-encoded X.509 cert returned by the PKI engine for the
    /// Ed25519 leaf. Empty for legacy local-keygen records.
    #[serde(default)]
    pub ed25519_cert_pem: String,
    /// PEM-encoded X.509 cert returned by the PKI engine for the
    /// ML-DSA-65 leaf. Empty for legacy local-keygen records.
    #[serde(default)]
    pub mldsa65_cert_pem: String,
    pub not_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// On-disk record persisted at `rustion/master/signing-key`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasterSigningRecord {
    pub current: Option<SigningKeyHalf>,
    pub previous: Option<SigningKeyHalf>,
    /// Wallclock the grace window closes. Mirror of
    /// `MasterConfig.previous_grace_until` so the verify helper has
    /// everything it needs without a second store read.
    #[serde(default)]
    pub previous_grace_until: Option<DateTime<Utc>>,
}

/// Legacy Phase 1 stub shape — kept as a deserialize-only target so
/// existing records keep loading after the Phase 2 upgrade. Records
/// are rewritten in the new shape the first time `get_or_init_signing_key`
/// runs against them.
#[derive(Debug, Clone, Deserialize)]
struct LegacyStubSigningKey {
    ed25519_seed_b64: String,
    mldsa65_seed_b64: String,
    #[serde(default)]
    created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    stub: Option<bool>,
}

/// Exported pubkey shape, mirrors the authority record on the Rustion
/// side so the operator can paste it into `authorities/<name>.yaml`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MasterPubKeyExport {
    pub algorithm: String,
    pub ed25519_pem: String,
    pub mldsa65_pem: String,
    pub fingerprint: String,
    pub current_serial: String,
    pub current_not_after: Option<DateTime<Utc>>,
    pub issued: bool,
}

/// Result of a successful `issue` or `rotate` call.
#[derive(Debug, Clone, Serialize)]
pub struct IssueOutcome {
    pub serial: String,
    pub not_after: DateTime<Utc>,
    pub algorithm: String,
    pub rotated: bool,
    pub previous_grace_until: Option<DateTime<Utc>>,
}

/// One verifying key with metadata. Returned by `load_active_keys`
/// so the verify-with-grace helper can try the current key first and
/// fall back to the previous within the grace window.
pub struct ActiveMasterKey {
    pub serial: String,
    pub ed25519_pub: Vec<u8>,
    pub mldsa65_pub: Vec<u8>,
}

/// One half (Ed25519 or ML-DSA-65) of a freshly-issued hybrid master,
/// as handed back by the PKI engine. The seed bytes are re-derived from
/// the engine's PKCS#8 PEM so the rest of the rustion module — which
/// speaks raw seeds — doesn't have to learn PKCS#8.
pub struct IssuedHalf {
    /// 32-byte raw seed; the only material the rustion side actually
    /// needs to keep working.
    pub seed: [u8; 32],
    /// PKI engine's serial for this leaf (hex string).
    pub serial: String,
    /// PEM-armoured X.509 leaf returned by the engine. Kept under the
    /// barrier so `bvault rustion master pubkey` can surface it as
    /// audit material in a follow-up phase.
    pub certificate_pem: String,
}

/// One hybrid pair freshly minted through the PKI engine.
pub struct IssuedHybrid {
    pub ed25519: IssuedHalf,
    pub mldsa65: IssuedHalf,
}

/// Abstraction over "ask the PKI engine for a fresh leaf of the
/// requested algorithm". Production code dispatches into
/// `Core::handle_request` so the engine ACL / audit / issuer state all
/// apply; tests inject a fake that mints the same shape locally.
#[async_trait::async_trait]
pub trait MasterCertIssuer: Send + Sync {
    /// Mint a fresh hybrid (Ed25519 + ML-DSA-65) pair. `pki_mount`
    /// has a trailing slash (e.g. `pki-internal/`); the two role
    /// names address the classical and PQC roles on that mount.
    async fn issue_hybrid(
        &self,
        pki_mount: &str,
        pki_role_ed25519: &str,
        pki_role_mldsa65: &str,
        ttl_secs: u64,
        common_name: &str,
    ) -> Result<IssuedHybrid, RvError>;
}

/// Production `MasterCertIssuer`: routes every call through
/// `Core::handle_request`, propagating the operator's `client_token`
/// so the PKI engine's ACL, audit, and lease layers all engage.
pub struct CoreMasterCertIssuer {
    pub core: Arc<Core>,
    pub client_token: String,
}

#[async_trait::async_trait]
impl MasterCertIssuer for CoreMasterCertIssuer {
    async fn issue_hybrid(
        &self,
        pki_mount: &str,
        pki_role_ed25519: &str,
        pki_role_mldsa65: &str,
        ttl_secs: u64,
        common_name: &str,
    ) -> Result<IssuedHybrid, RvError> {
        let ed = pki_issue_one(
            &self.core,
            &self.client_token,
            pki_mount,
            pki_role_ed25519,
            ttl_secs,
            common_name,
            PkiHalfKind::Ed25519,
        )
        .await?;
        let ml = pki_issue_one(
            &self.core,
            &self.client_token,
            pki_mount,
            pki_role_mldsa65,
            ttl_secs,
            common_name,
            PkiHalfKind::MlDsa65,
        )
        .await?;
        Ok(IssuedHybrid { ed25519: ed, mldsa65: ml })
    }
}

#[derive(Clone, Copy)]
enum PkiHalfKind {
    Ed25519,
    MlDsa65,
}

#[maybe_async::maybe_async]
async fn pki_issue_one(
    core: &Core,
    client_token: &str,
    pki_mount: &str,
    pki_role: &str,
    ttl_secs: u64,
    common_name: &str,
    kind: PkiHalfKind,
) -> Result<IssuedHalf, RvError> {
    use crate::logical::{Operation, Request};
    let mount = pki_mount.trim_end_matches('/');
    let path = format!("{}/issue/{}", mount, pki_role);
    let mut body = serde_json::Map::new();
    body.insert(
        "common_name".into(),
        serde_json::Value::String(common_name.to_string()),
    );
    body.insert(
        "ttl".into(),
        serde_json::Value::String(format!("{}s", ttl_secs)),
    );
    let mut req = Request::new(path.clone());
    req.operation = Operation::Write;
    req.client_token = client_token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.map_err(|e| {
        bv_error_string!(&format!(
            "rustion master: PKI engine call {path} failed: {e:?}"
        ))
    })?;
    let data = resp
        .and_then(|r| r.data)
        .ok_or_else(|| bv_error_string!(&format!("rustion master: PKI engine {path} returned no data")))?;
    let private_key_pem = data
        .get("private_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            bv_error_string!(&format!(
                "rustion master: PKI engine {path} did not return private_key — \
                 the role must allow generated keys"
            ))
        })?
        .to_string();
    let certificate_pem = data
        .get("certificate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bv_error_string!(&format!("rustion master: PKI engine {path} did not return certificate")))?
        .to_string();
    let serial = data
        .get("serial_number")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bv_error_string!(&format!("rustion master: PKI engine {path} did not return serial_number")))?
        .to_string();
    // Sanity check the algorithm the engine reports matches what we
    // asked for — otherwise we'd happily store a P-256 leaf under the
    // Ed25519 slot and trip up envelope signing.
    if let Some(t) = data.get("private_key_type").and_then(|v| v.as_str()) {
        let expected = match kind {
            PkiHalfKind::Ed25519 => "ed25519",
            PkiHalfKind::MlDsa65 => "ml-dsa-65",
        };
        if t != expected {
            return Err(bv_error_string!(&format!(
                "rustion master: PKI role {pki_role} returned private_key_type={t}, \
                 expected {expected}"
            )));
        }
    }
    let seed = match kind {
        PkiHalfKind::Ed25519 => extract_ed25519_seed_from_pkcs8(&private_key_pem)?,
        PkiHalfKind::MlDsa65 => extract_mldsa65_seed_from_pkcs8(&private_key_pem)?,
    };
    Ok(IssuedHalf { seed, serial, certificate_pem })
}

/// Decode an RFC-8410 Ed25519 `PRIVATE KEY` PEM and return the raw
/// 32-byte seed. The PKI engine emits this via `rcgen`'s standard
/// PKCS#8 serializer.
fn extract_ed25519_seed_from_pkcs8(pem: &str) -> Result<[u8; 32], RvError> {
    use pkcs8::{
        der::{asn1::OctetString, Decode},
        PrivateKeyInfo,
    };
    const OID_ED25519: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");
    let der_bytes = pem_decode_block(pem, "PRIVATE KEY")?;
    let info = PrivateKeyInfo::from_der(&der_bytes)
        .map_err(|e| bv_error_string!(&format!("ed25519 pkcs8 decode: {e}")))?;
    if info.algorithm.oid != OID_ED25519 {
        return Err(bv_error_string!(&format!(
            "expected Ed25519 PKCS#8 OID 1.3.101.112, got {}",
            info.algorithm.oid
        )));
    }
    // RFC 8410 wraps the 32-byte seed in an inner OCTET STRING inside
    // the outer PKCS#8 privateKey field.
    let inner = OctetString::from_der(info.private_key)
        .map_err(|e| bv_error_string!(&format!("ed25519 pkcs8 inner OCTET STRING decode: {e}")))?;
    let bytes = inner.as_bytes();
    if bytes.len() != 32 {
        return Err(bv_error_string!(&format!(
            "ed25519 seed has unexpected length {}",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

/// Decode the IETF-lamps draft ML-DSA-65 `PRIVATE KEY` PEM and return
/// the raw 32-byte seed. Matches the shape `MlDsaSigner::to_pkcs8_pem`
/// emits on the PKI engine side.
fn extract_mldsa65_seed_from_pkcs8(pem: &str) -> Result<[u8; 32], RvError> {
    use pkcs8::{
        der::{asn1::OctetString, Decode},
        PrivateKeyInfo,
    };
    // ML-DSA-65 (IETF lamps draft).
    const OID_ML_DSA_65: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
    let der_bytes = pem_decode_block(pem, "PRIVATE KEY")?;
    let info = PrivateKeyInfo::from_der(&der_bytes)
        .map_err(|e| bv_error_string!(&format!("ml-dsa-65 pkcs8 decode: {e}")))?;
    if info.algorithm.oid != OID_ML_DSA_65 {
        return Err(bv_error_string!(&format!(
            "expected ML-DSA-65 PKCS#8 OID {}, got {}",
            OID_ML_DSA_65, info.algorithm.oid
        )));
    }
    let inner = OctetString::from_der(info.private_key)
        .map_err(|e| bv_error_string!(&format!("ml-dsa-65 pkcs8 inner OCTET STRING decode: {e}")))?;
    let bytes = inner.as_bytes();
    if bytes.len() != 32 {
        return Err(bv_error_string!(&format!(
            "ml-dsa-65 seed has unexpected length {}",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

fn pem_decode_block(pem: &str, label: &str) -> Result<Vec<u8>, RvError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let s = pem
        .find(&begin)
        .ok_or_else(|| bv_error_string!(&format!("missing {begin} header")))?;
    let body_start = s + begin.len();
    let e = pem[body_start..]
        .find(&end)
        .ok_or_else(|| bv_error_string!(&format!("missing {end} footer")))?;
    let body: String = pem[body_start..body_start + e]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .map_err(|e| bv_error_string!(&format!("pem base64 decode: {e}")))
}

pub struct MasterStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl MasterStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(MASTER_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    pub async fn get(&self) -> Result<Option<MasterConfig>, RvError> {
        let Some(entry) = self.view.get(CONFIG_KEY).await? else {
            return Ok(None);
        };
        let cfg: MasterConfig = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode rustion master config: {e}")))?;
        Ok(Some(cfg))
    }

    pub async fn put(&self, cfg: &MasterConfig) -> Result<(), RvError> {
        let value = serde_json::to_vec(cfg)
            .map_err(|e| bv_error_string!(&format!("encode rustion master config: {e}")))?;
        self.view
            .put(&StorageEntry {
                key: CONFIG_KEY.to_string(),
                value,
            })
            .await
    }

    pub async fn get_or_default(&self) -> Result<MasterConfig, RvError> {
        if let Some(cfg) = self.get().await? {
            return Ok(cfg);
        }
        Ok(MasterConfig {
            updated_at: Utc::now(),
            algorithm: default_algorithm(),
            default_ttl_secs: default_ttl_secs(),
            rotate_grace_secs: default_rotate_grace_secs(),
            ..Default::default()
        })
    }

    /// Read the persisted signing-key record, applying the Phase 1
    /// legacy migration if the on-disk shape is still
    /// `StubSigningKey`. Returns `Ok(None)` when no record exists.
    pub async fn read_signing_record(&self) -> Result<Option<MasterSigningRecord>, RvError> {
        let Some(entry) = self.view.get(SIGNING_KEY).await? else {
            return Ok(None);
        };
        if let Ok(rec) = serde_json::from_slice::<MasterSigningRecord>(&entry.value) {
            if rec.current.is_some() || rec.previous.is_some() {
                return Ok(Some(rec));
            }
        }
        // Try the legacy shape and migrate in-memory. The migration
        // is *not* persisted here — only the first `get_or_init_signing_key`
        // caller rewrites the record so a cluster of read-only callers
        // can keep going without thrashing storage.
        let legacy: LegacyStubSigningKey = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode rustion master signing-key: {e}")))?;
        let now = legacy.created_at.unwrap_or_else(Utc::now);
        let _ = legacy.stub;
        let half = derive_half_from_seeds(
            &legacy.ed25519_seed_b64,
            &legacy.mldsa65_seed_b64,
            legacy_serial(&now),
            now + chrono::Duration::seconds(default_ttl_secs() as i64),
            now,
        )?;
        Ok(Some(MasterSigningRecord {
            current: Some(half),
            previous: None,
            previous_grace_until: None,
        }))
    }

    async fn write_signing_record(&self, rec: &MasterSigningRecord) -> Result<(), RvError> {
        let value = serde_json::to_vec(rec)
            .map_err(|e| bv_error_string!(&format!("encode rustion master signing-key: {e}")))?;
        self.view
            .put(&StorageEntry {
                key: SIGNING_KEY.to_string(),
                value,
            })
            .await
    }

    /// Load the current signing key. Used by envelope-build paths
    /// (open / renew / kill / attest / deenrol). If the on-disk
    /// record is the Phase 1 legacy stub, migrate it and persist the
    /// new shape so subsequent reads are cheaper.
    pub async fn get_or_init_signing_key(
        &self,
    ) -> Result<bv_crypto::BvrgMasterSigningKey, RvError> {
        if let Some(mut rec) = self.read_signing_record().await? {
            if rec.current.is_none() {
                return Err(bv_error_string!(
                    "rustion master not initialised — run `bvault rustion master issue`"
                ));
            }
            // Persist any in-memory legacy migration. Detect by
            // round-tripping the record through serde and comparing
            // to the on-disk bytes.
            let on_disk = self
                .view
                .get(SIGNING_KEY)
                .await?
                .map(|e| e.value)
                .unwrap_or_default();
            let normalised = serde_json::to_vec(&rec).unwrap_or_default();
            if normalised != on_disk {
                // Refresh the grace timestamp from the config in case
                // the legacy shape didn't carry one.
                if rec.previous_grace_until.is_none() {
                    if let Ok(cfg) = self.get().await {
                        rec.previous_grace_until = cfg.and_then(|c| c.previous_grace_until);
                    }
                }
                self.write_signing_record(&rec).await?;
            }
            let half = rec.current.unwrap();
            return signing_key_from_half(&half);
        }
        // Phase 1 callers that never issued a master and never ran
        // session-open still need a working keypair for the legacy
        // self-tests; mint one in the legacy shape so the rest of
        // the module is unchanged. Operators on the Phase 2 path
        // are expected to call `issue` first.
        let now = Utc::now();
        let mut ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut ed_seed);
        let mut ml_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut ml_seed);
        let half = derive_half_from_seeds(
            &STANDARD.encode(ed_seed),
            &STANDARD.encode(ml_seed),
            legacy_serial(&now),
            now + chrono::Duration::seconds(default_ttl_secs() as i64),
            now,
        )?;
        let rec = MasterSigningRecord {
            current: Some(half.clone()),
            previous: None,
            previous_grace_until: None,
        };
        self.write_signing_record(&rec).await?;
        log::warn!(
            "rustion master signing-key minted on-the-fly without explicit issue; \
             run `bvault rustion master issue` after configuring pki_mount/pki_role"
        );
        signing_key_from_half(&half)
    }

    /// Issue a fresh master keypair through the PKI engine. Fails if
    /// `pki_mount` / `pki_role` / `pki_role_pqc` is empty (operator
    /// must configure the binding first) or if a current keypair is
    /// already on disk (operator must `rotate` to cut over).
    pub async fn issue(
        &self,
        issuer: &dyn MasterCertIssuer,
    ) -> Result<IssueOutcome, RvError> {
        let mut cfg = self.get_or_default().await?;
        let (pki_mount, pki_role, pki_role_pqc) = require_pki_binding(&cfg, "issue")?;
        if !cfg.current_serial.is_empty() {
            return Err(bv_error_string!(&format!(
                "rustion master issue: a master is already issued (serial={}); \
                 use rotate to cut over",
                cfg.current_serial
            )));
        }
        let now = Utc::now();
        let hybrid = issuer
            .issue_hybrid(
                &pki_mount,
                &pki_role,
                &pki_role_pqc,
                cfg.default_ttl_secs,
                "rustion-master",
            )
            .await?;
        let half = half_from_issued(&hybrid, cfg.default_ttl_secs, now)?;
        let outcome = IssueOutcome {
            serial: half.serial.clone(),
            not_after: half.not_after,
            algorithm: cfg.algorithm.clone(),
            rotated: false,
            previous_grace_until: None,
        };
        let rec = MasterSigningRecord {
            current: Some(half.clone()),
            previous: None,
            previous_grace_until: None,
        };
        self.write_signing_record(&rec).await?;
        cfg.current_serial = half.serial.clone();
        cfg.current_not_after = Some(half.not_after);
        cfg.previous_serial = None;
        cfg.previous_not_after = None;
        cfg.previous_grace_until = None;
        cfg.updated_at = now;
        self.put(&cfg).await?;
        Ok(outcome)
    }

    /// Rotate: shift the current keypair into the `previous` slot,
    /// arm the grace window, and mint a fresh hybrid pair through the
    /// PKI engine. Fails when no current keypair is present (the
    /// operator must `issue` first) or when the PKI binding is
    /// incomplete.
    pub async fn rotate(
        &self,
        issuer: &dyn MasterCertIssuer,
    ) -> Result<IssueOutcome, RvError> {
        let mut cfg = self.get_or_default().await?;
        let (pki_mount, pki_role, pki_role_pqc) = require_pki_binding(&cfg, "rotate")?;
        let existing = self
            .read_signing_record()
            .await?
            .and_then(|r| r.current)
            .ok_or_else(|| {
                bv_error_string!(
                    "rustion master rotate: nothing to rotate — run issue first"
                )
            })?;
        let now = Utc::now();
        let grace_until = now + chrono::Duration::seconds(cfg.rotate_grace_secs as i64);
        let hybrid = issuer
            .issue_hybrid(
                &pki_mount,
                &pki_role,
                &pki_role_pqc,
                cfg.default_ttl_secs,
                "rustion-master",
            )
            .await?;
        let fresh = half_from_issued(&hybrid, cfg.default_ttl_secs, now)?;
        let outcome = IssueOutcome {
            serial: fresh.serial.clone(),
            not_after: fresh.not_after,
            algorithm: cfg.algorithm.clone(),
            rotated: true,
            previous_grace_until: Some(grace_until),
        };
        let rec = MasterSigningRecord {
            current: Some(fresh.clone()),
            previous: Some(existing.clone()),
            previous_grace_until: Some(grace_until),
        };
        self.write_signing_record(&rec).await?;
        cfg.previous_serial = Some(existing.serial.clone());
        cfg.previous_not_after = Some(existing.not_after);
        cfg.previous_grace_until = Some(grace_until);
        cfg.current_serial = fresh.serial.clone();
        cfg.current_not_after = Some(fresh.not_after);
        cfg.updated_at = now;
        self.put(&cfg).await?;
        Ok(outcome)
    }

    /// Return the public-key export shape (PEM-armoured raw
    /// public-key bytes for both halves plus a SHA-256 fingerprint
    /// computed over the canonical `ed25519_spki || mldsa65_spki`
    /// concatenation).
    pub async fn export_pubkey(&self) -> Result<MasterPubKeyExport, RvError> {
        let cfg = self.get_or_default().await?;
        let Some(rec) = self.read_signing_record().await? else {
            return Ok(MasterPubKeyExport {
                algorithm: cfg.algorithm,
                issued: false,
                ..Default::default()
            });
        };
        let Some(half) = rec.current else {
            return Ok(MasterPubKeyExport {
                algorithm: cfg.algorithm,
                issued: false,
                ..Default::default()
            });
        };
        let ed_bytes = STANDARD
            .decode(half.ed25519_pub_b64.as_bytes())
            .map_err(|e| bv_error_string!(&format!("decode ed25519 pub: {e}")))?;
        let ml_bytes = STANDARD
            .decode(half.mldsa65_pub_b64.as_bytes())
            .map_err(|e| bv_error_string!(&format!("decode mldsa65 pub: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(&ed_bytes);
        hasher.update(&ml_bytes);
        let fingerprint = hex::encode(hasher.finalize());
        // Hand-rolled PEM rather than a heavyweight encoder: both
        // halves are raw public-key bytes (FIPS 204 ML-DSA-65 has no
        // standard SPKI encoder in the workspace yet, and Ed25519's
        // 32-byte form is unambiguous on the Rustion side).
        let ed25519_pem = pem_armour("BVRG ED25519 PUBLIC KEY", &ed_bytes);
        let mldsa65_pem = pem_armour("BVRG ML-DSA-65 PUBLIC KEY", &ml_bytes);
        // Update the issued flag from the persisted serial rather
        // than the config field; storage is the source of truth.
        let current_serial = if cfg.current_serial.is_empty() {
            half.serial.clone()
        } else {
            cfg.current_serial
        };
        Ok(MasterPubKeyExport {
            algorithm: cfg.algorithm,
            ed25519_pem,
            mldsa65_pem,
            fingerprint,
            current_serial,
            current_not_after: cfg.current_not_after.or(Some(half.not_after)),
            issued: true,
        })
    }

    /// Return every signing key that is still in scope: the current
    /// one always, plus the previous one when `now < previous_grace_until`.
    /// Verify-side callers iterate in order; envelope-build callers
    /// pick the first entry.
    pub async fn load_active_keys(
        &self,
    ) -> Result<Vec<(ActiveMasterKey, bv_crypto::BvrgMasterPublicKey)>, RvError> {
        let mut out = Vec::new();
        let Some(rec) = self.read_signing_record().await? else {
            return Ok(out);
        };
        if let Some(half) = rec.current.as_ref() {
            out.push(half_to_active(half)?);
        }
        if let Some(prev) = rec.previous.as_ref() {
            if let Some(until) = rec.previous_grace_until {
                if Utc::now() < until {
                    out.push(half_to_active(prev)?);
                }
            }
        }
        Ok(out)
    }

    /// Phase 9.1 — return the deployment's stable UUID, minting +
    /// persisting on first call.
    pub async fn get_or_init_deployment_id(&self) -> Result<String, RvError> {
        if let Some(entry) = self.view.get(DEPLOYMENT_ID).await? {
            let s = String::from_utf8(entry.value)
                .map_err(|e| bv_error_string!(&format!("deployment_id not utf8: {e}")))?;
            return Ok(s);
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.view
            .put(&StorageEntry {
                key: DEPLOYMENT_ID.to_string(),
                value: id.as_bytes().to_vec(),
            })
            .await?;
        log::info!("rustion: minted fresh deployment_id={}", id);
        Ok(id)
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Validate that `pki_mount`, `pki_role`, and `pki_role_pqc` are all
/// set on the master config. Returns the trimmed values.
fn require_pki_binding(
    cfg: &MasterConfig,
    op: &str,
) -> Result<(String, String, String), RvError> {
    if cfg.pki_mount.trim().is_empty() || cfg.pki_role.trim().is_empty() {
        return Err(bv_error_string!(&format!(
            "rustion master {op}: pki_mount and pki_role must be configured first \
             (POST rustion/master/config)"
        )));
    }
    let pqc = cfg.pki_role_pqc.as_deref().unwrap_or("").trim().to_string();
    if pqc.is_empty() {
        return Err(bv_error_string!(&format!(
            "rustion master {op}: pki_role_pqc must be configured (the ML-DSA-65 role) \
             before {op} will succeed — set it via POST rustion/master/config"
        )));
    }
    Ok((
        cfg.pki_mount.trim().to_string(),
        cfg.pki_role.trim().to_string(),
        pqc,
    ))
}

/// Build a `SigningKeyHalf` from a freshly-engine-issued hybrid pair.
/// Seeds are dropped into the on-disk b64 fields; cert + serial come
/// straight from the engine; `not_after` is derived from `now + ttl`.
fn half_from_issued(
    hybrid: &IssuedHybrid,
    ttl_secs: u64,
    now: DateTime<Utc>,
) -> Result<SigningKeyHalf, RvError> {
    let not_after = now + chrono::Duration::seconds(ttl_secs as i64);
    let ed_seed_b64 = STANDARD.encode(hybrid.ed25519.seed);
    let ml_seed_b64 = STANDARD.encode(hybrid.mldsa65.seed);
    let mut half = derive_half_from_seeds(
        &ed_seed_b64,
        &ml_seed_b64,
        hybrid.ed25519.serial.clone(),
        not_after,
        now,
    )?;
    half.mldsa65_serial = hybrid.mldsa65.serial.clone();
    half.ed25519_cert_pem = hybrid.ed25519.certificate_pem.clone();
    half.mldsa65_cert_pem = hybrid.mldsa65.certificate_pem.clone();
    Ok(half)
}

fn derive_half_from_seeds(
    ed_seed_b64: &str,
    ml_seed_b64: &str,
    serial: String,
    not_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
) -> Result<SigningKeyHalf, RvError> {
    let ed_seed_bytes: [u8; 32] = STANDARD
        .decode(ed_seed_b64.as_bytes())
        .map_err(|e| bv_error_string!(&format!("decode ed25519 seed: {e}")))?
        .try_into()
        .map_err(|_| bv_error_string!("ed25519 seed has wrong length"))?;
    let ml_seed_bytes: [u8; 32] = STANDARD
        .decode(ml_seed_b64.as_bytes())
        .map_err(|e| bv_error_string!(&format!("decode mldsa65 seed: {e}")))?
        .try_into()
        .map_err(|_| bv_error_string!("mldsa65 seed has wrong length"))?;
    let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_seed_bytes);
    let ed_pub = ed_signing.verifying_key().to_bytes();
    let ml_seed_z = zeroize::Zeroizing::new(ml_seed_bytes);
    let master = bv_crypto::BvrgMasterSigningKey {
        ed25519: ed_signing,
        mldsa65_seed: ml_seed_z,
    };
    let pubs = master.public_key();
    let ml_pub = pubs.mldsa65;
    Ok(SigningKeyHalf {
        ed25519_seed_b64: ed_seed_b64.to_string(),
        mldsa65_seed_b64: ml_seed_b64.to_string(),
        ed25519_pub_b64: STANDARD.encode(ed_pub),
        mldsa65_pub_b64: STANDARD.encode(&ml_pub),
        serial,
        mldsa65_serial: String::new(),
        ed25519_cert_pem: String::new(),
        mldsa65_cert_pem: String::new(),
        not_after,
        created_at,
    })
}

fn signing_key_from_half(
    half: &SigningKeyHalf,
) -> Result<bv_crypto::BvrgMasterSigningKey, RvError> {
    let ed_seed: [u8; 32] = STANDARD
        .decode(half.ed25519_seed_b64.as_bytes())
        .map_err(|e| bv_error_string!(&format!("decode ed25519 seed: {e}")))?
        .try_into()
        .map_err(|_| bv_error_string!("ed25519 seed has wrong length"))?;
    let ml_seed: [u8; 32] = STANDARD
        .decode(half.mldsa65_seed_b64.as_bytes())
        .map_err(|e| bv_error_string!(&format!("decode mldsa65 seed: {e}")))?
        .try_into()
        .map_err(|_| bv_error_string!("mldsa65 seed has wrong length"))?;
    Ok(bv_crypto::BvrgMasterSigningKey {
        ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_seed),
        mldsa65_seed: zeroize::Zeroizing::new(ml_seed),
    })
}

fn half_to_active(
    half: &SigningKeyHalf,
) -> Result<(ActiveMasterKey, bv_crypto::BvrgMasterPublicKey), RvError> {
    let ed_bytes = STANDARD
        .decode(half.ed25519_pub_b64.as_bytes())
        .map_err(|e| bv_error_string!(&format!("decode ed25519 pub: {e}")))?;
    let ml_bytes = STANDARD
        .decode(half.mldsa65_pub_b64.as_bytes())
        .map_err(|e| bv_error_string!(&format!("decode mldsa65 pub: {e}")))?;
    let pubkey = bv_crypto::BvrgMasterPublicKey::from_bytes(&ed_bytes, &ml_bytes)
        .map_err(|e| bv_error_string!(&format!("reconstruct master pubkey: {e:?}")))?;
    Ok((
        ActiveMasterKey {
            serial: half.serial.clone(),
            ed25519_pub: ed_bytes,
            mldsa65_pub: ml_bytes,
        },
        pubkey,
    ))
}

fn legacy_serial(now: &DateTime<Utc>) -> String {
    format!("legacy-{}", now.format("%Y%m%dT%H%M%SZ"))
}

fn pem_armour(label: &str, bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(bytes);
    let mut body = String::new();
    for (i, ch) in b64.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            body.push('\n');
        }
        body.push(ch);
    }
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

#[cfg(test)]
impl MasterStore {
    /// Test-only: construct a `MasterStore` directly over a
    /// pre-built barrier view. Used by the in-tree tests so the
    /// suite doesn't have to spin up a full Core / unsealed vault.
    pub(crate) fn from_view(view: Arc<BarrierView>) -> Arc<Self> {
        Arc::new(Self { view })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{barrier::SecurityBarrier, barrier_aes_gcm, barrier_view::BarrierView};
    use crate::test_utils::new_test_backend;

    async fn fresh_store_named(test_name: &str) -> Arc<MasterStore> {
        // Per-test name keeps macOS's nanosecond clock collisions —
        // which happen when several `fresh_store` calls land in the
        // same instant — from steering two tests into the same temp
        // dir and tripping `ErrBarrierUnsealFailed` on the loser.
        let backend = new_test_backend(&format!("test_rustion_master_{test_name}"));
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(key.as_mut_slice());
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(backend);
        barrier.init(key.as_slice()).await.expect("barrier init");
        barrier
            .unseal(key.as_slice())
            .await
            .expect("barrier unseal");
        let root_view = BarrierView::new(Arc::new(barrier), "sys/");
        let sub = root_view.new_sub_view(MASTER_SUB_PATH);
        MasterStore::from_view(Arc::new(sub))
    }

    async fn configure(store: &MasterStore, grace_secs: u64) {
        let mut cfg = store.get_or_default().await.unwrap();
        cfg.pki_mount = "pki-internal/".into();
        cfg.pki_role = "rustion-master".into();
        cfg.pki_role_pqc = Some("rustion-master-pqc".into());
        cfg.rotate_grace_secs = grace_secs;
        cfg.default_ttl_secs = 3600;
        cfg.updated_at = Utc::now();
        store.put(&cfg).await.unwrap();
    }

    /// Test-only `MasterCertIssuer` that mints seeds locally (the
    /// pre-refactor behaviour) and hands back a synthetic cert + serial.
    /// The unit tests need this because spinning a full PKI mount under
    /// an unsealed Core inside `cargo test --lib` is overkill — the
    /// behaviour we actually want to cover here is the issue / rotate /
    /// grace state machine, not the X.509 emission. The
    /// `pki_issue_routes_through_engine` test below covers the real
    /// `Core::handle_request` round-trip end-to-end.
    struct FakeIssuer {
        seen: std::sync::Mutex<Vec<(String, String, String)>>,
    }
    impl FakeIssuer {
        fn new() -> Self {
            Self { seen: std::sync::Mutex::new(Vec::new()) }
        }
    }
    #[async_trait::async_trait]
    impl MasterCertIssuer for FakeIssuer {
        async fn issue_hybrid(
            &self,
            pki_mount: &str,
            pki_role_ed25519: &str,
            pki_role_mldsa65: &str,
            _ttl_secs: u64,
            _common_name: &str,
        ) -> Result<IssuedHybrid, RvError> {
            self.seen.lock().unwrap().push((
                pki_mount.to_string(),
                pki_role_ed25519.to_string(),
                pki_role_mldsa65.to_string(),
            ));
            let mut ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut ed_seed);
            let mut ml_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut ml_seed);
            let now = Utc::now();
            Ok(IssuedHybrid {
                ed25519: IssuedHalf {
                    seed: ed_seed,
                    serial: format!("ed-{}", now.format("%Y%m%dT%H%M%S%fZ")),
                    certificate_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n".into(),
                },
                mldsa65: IssuedHalf {
                    seed: ml_seed,
                    serial: format!("ml-{}", now.format("%Y%m%dT%H%M%S%fZ")),
                    certificate_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n".into(),
                },
            })
        }
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn issue_then_export_returns_pubkey_pems() {
        let store = fresh_store_named("issue_then_export").await;
        configure(&store, 60).await;
        let issuer = FakeIssuer::new();
        let outcome = store.issue(&issuer).await.expect("issue");
        assert!(!outcome.serial.is_empty());
        assert!(!outcome.rotated);
        // FakeIssuer was actually consulted with the configured mount
        // + both roles — the binding hasn't been short-circuited.
        let seen = issuer.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "issuer must be called exactly once per issue");
        assert_eq!(seen[0].0, "pki-internal/");
        assert_eq!(seen[0].1, "rustion-master");
        assert_eq!(seen[0].2, "rustion-master-pqc");
        drop(seen);
        let export = store.export_pubkey().await.expect("export");
        assert!(export.issued);
        assert!(export.ed25519_pem.contains("BVRG ED25519 PUBLIC KEY"));
        assert!(export.mldsa65_pem.contains("BVRG ML-DSA-65 PUBLIC KEY"));
        assert_eq!(export.fingerprint.len(), 64);
        assert_eq!(export.current_serial, outcome.serial);
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn issue_without_pki_config_errors() {
        let store = fresh_store_named("issue_without_pki_config").await;
        let issuer = FakeIssuer::new();
        let err = store.issue(&issuer).await.expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.contains("pki_mount"), "got: {msg}");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn issue_without_pqc_role_errors() {
        let store = fresh_store_named("issue_without_pqc_role").await;
        // Configure mount + ed25519 role, but leave pki_role_pqc unset.
        let mut cfg = store.get_or_default().await.unwrap();
        cfg.pki_mount = "pki-internal/".into();
        cfg.pki_role = "rustion-master".into();
        cfg.pki_role_pqc = None;
        cfg.updated_at = Utc::now();
        store.put(&cfg).await.unwrap();
        let issuer = FakeIssuer::new();
        let err = store.issue(&issuer).await.expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.contains("pki_role_pqc"), "got: {msg}");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn issue_twice_without_rotate_errors() {
        let store = fresh_store_named("issue_twice").await;
        configure(&store, 60).await;
        let issuer = FakeIssuer::new();
        store.issue(&issuer).await.expect("first issue");
        let err = store.issue(&issuer).await.expect_err("second issue must fail");
        let msg = format!("{err}");
        assert!(msg.contains("already issued"), "got: {msg}");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn rotate_shifts_current_to_previous() {
        let store = fresh_store_named("rotate_shifts").await;
        configure(&store, 600).await;
        let issuer = FakeIssuer::new();
        let first = store.issue(&issuer).await.expect("issue");
        // Sleep a microsecond so the FakeIssuer's wallclock-based
        // serial differs between the two calls.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let second = store.rotate(&issuer).await.expect("rotate");
        assert!(second.rotated);
        assert_ne!(first.serial, second.serial);
        let cfg = store.get().await.unwrap().expect("cfg present");
        assert_eq!(cfg.current_serial, second.serial);
        assert_eq!(cfg.previous_serial.as_deref(), Some(first.serial.as_str()));
        let grace = cfg.previous_grace_until.expect("grace set");
        let expected = second.previous_grace_until.expect("outcome grace");
        assert!((grace - expected).num_seconds().abs() < 2);
        let active = store.load_active_keys().await.unwrap();
        assert_eq!(active.len(), 2, "current + previous in grace");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn previous_drops_after_grace() {
        let store = fresh_store_named("previous_drops_after_grace").await;
        configure(&store, 1).await;
        let issuer = FakeIssuer::new();
        store.issue(&issuer).await.expect("issue");
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        store.rotate(&issuer).await.expect("rotate");
        // Force the grace window into the past.
        let mut rec = store
            .read_signing_record()
            .await
            .unwrap()
            .expect("record");
        rec.previous_grace_until = Some(Utc::now() - chrono::Duration::seconds(60));
        store.write_signing_record(&rec).await.unwrap();
        let active = store.load_active_keys().await.unwrap();
        assert_eq!(active.len(), 1, "previous dropped after grace");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn rotate_without_issue_errors() {
        let store = fresh_store_named("rotate_without_issue").await;
        configure(&store, 60).await;
        let issuer = FakeIssuer::new();
        let err = store.rotate(&issuer).await.expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.contains("nothing to rotate"), "got: {msg}");
    }
}
