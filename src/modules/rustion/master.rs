//! Master signing-cert configuration and key lifecycle for the
//! Rustion integration.
//!
//! Phase 1 shipped the configuration **slot** (PKI mount + role +
//! issuer pointers) plus an ephemerally-minted stub keypair so the
//! Phase 3 session-open path could run end-to-end.
//!
//! Phase 2 (this module) elevates that stub into a real
//! `issue / rotate` state machine with a grace window:
//!
//!   - `MasterStore::issue` mints a fresh hybrid Ed25519 + ML-DSA-65
//!     keypair, allocates a serial, and persists the record under
//!     `rustion/master/signing-key` alongside the public halves and
//!     `not_after`. Refuses to overwrite an already-issued master —
//!     the operator must `rotate` to cut over.
//!   - `MasterStore::rotate` archives the current record as
//!     `previous_*`, sets `previous_grace_until = now + rotate_grace_secs`,
//!     and mints a fresh keypair as the new current. Envelopes signed
//!     by the outgoing key stay valid until the grace window closes.
//!   - `MasterStore::load_active_keys` returns the current signing
//!     key plus the previous one when `now < previous_grace_until`.
//!     Envelope-build paths still use only the current key; the
//!     previous key surfaces only via the verify helper.
//!
//! ## Design notes
//!
//! - **Single PKI role.** The configured `pki_role` is a single
//!   deployment marker on the master config. We do **not** add a
//!   parallel `pki_role_pqc` or extend the PKI role schema with a
//!   hybrid attribute in this phase. The actual cert emission round
//!   trip via the PKI engine — issuing a real X.509 leaf with a
//!   server-stored binding — is wired in alongside the cluster-
//!   replicated master story (Phase 9). For Phase 2 the keypair is
//!   generated locally under the encrypted barrier view and tagged
//!   with a synthetic serial; the `pki_mount` / `pki_role` slots
//!   gate `issue` so an operator cannot mint a master before
//!   configuring the eventual PKI binding.
//!
//! - **On-disk shape.** The record persisted under
//!   `rustion/master/signing-key` is `MasterSigningRecord`, which
//!   carries the current keypair (seeds + derived public bytes +
//!   serial + not_after) and an optional `previous` half for the
//!   grace window. Phase 1 callers that wrote the old
//!   `StubSigningKey` shape are still readable — `get_or_init_signing_key`
//!   migrates them in place on first read.
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
    /// PKI role under that mount.
    pub pki_role: String,
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
    pub serial: String,
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

    /// Issue a fresh master keypair. Fails if `pki_mount` /
    /// `pki_role` is empty (operator must configure the binding
    /// first) or if a current keypair is already on disk (operator
    /// must `rotate` to cut over).
    pub async fn issue(&self) -> Result<IssueOutcome, RvError> {
        let mut cfg = self.get_or_default().await?;
        if cfg.pki_mount.trim().is_empty() || cfg.pki_role.trim().is_empty() {
            return Err(bv_error_string!(
                "rustion master issue: pki_mount and pki_role must be configured first \
                 (POST rustion/master/config)"
            ));
        }
        if !cfg.current_serial.is_empty() {
            return Err(bv_error_string!(&format!(
                "rustion master issue: a master is already issued (serial={}); \
                 use rotate to cut over",
                cfg.current_serial
            )));
        }
        let now = Utc::now();
        let half = mint_fresh_half(cfg.default_ttl_secs, now)?;
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
    /// arm the grace window, and mint a new current. Fails when no
    /// current keypair is present (the operator must `issue` first).
    pub async fn rotate(&self) -> Result<IssueOutcome, RvError> {
        let mut cfg = self.get_or_default().await?;
        if cfg.pki_mount.trim().is_empty() || cfg.pki_role.trim().is_empty() {
            return Err(bv_error_string!(
                "rustion master rotate: pki_mount and pki_role must be configured first"
            ));
        }
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
        let fresh = mint_fresh_half(cfg.default_ttl_secs, now)?;
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

fn mint_fresh_half(default_ttl_secs: u64, now: DateTime<Utc>) -> Result<SigningKeyHalf, RvError> {
    let mut ed_seed = [0u8; 32];
    rand::rng().fill_bytes(&mut ed_seed);
    let mut ml_seed = [0u8; 32];
    rand::rng().fill_bytes(&mut ml_seed);
    let serial = mint_serial(&now);
    let not_after = now + chrono::Duration::seconds(default_ttl_secs as i64);
    derive_half_from_seeds(
        &STANDARD.encode(ed_seed),
        &STANDARD.encode(ml_seed),
        serial,
        not_after,
        now,
    )
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

fn mint_serial(now: &DateTime<Utc>) -> String {
    let mut rand_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut rand_bytes);
    format!(
        "{}-{}",
        now.format("%Y%m%dT%H%M%SZ"),
        hex::encode(rand_bytes)
    )
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

    async fn fresh_store() -> Arc<MasterStore> {
        let backend = new_test_backend("test_rustion_master");
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
        cfg.rotate_grace_secs = grace_secs;
        cfg.default_ttl_secs = 3600;
        cfg.updated_at = Utc::now();
        store.put(&cfg).await.unwrap();
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn issue_then_export_returns_pubkey_pems() {
        let store = fresh_store().await;
        configure(&store, 60).await;
        let outcome = store.issue().await.expect("issue");
        assert!(!outcome.serial.is_empty());
        assert!(!outcome.rotated);
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
        let store = fresh_store().await;
        let err = store.issue().await.expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.contains("pki_mount"), "got: {msg}");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn issue_twice_without_rotate_errors() {
        let store = fresh_store().await;
        configure(&store, 60).await;
        store.issue().await.expect("first issue");
        let err = store.issue().await.expect_err("second issue must fail");
        let msg = format!("{err}");
        assert!(msg.contains("already issued"), "got: {msg}");
    }

    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn rotate_shifts_current_to_previous() {
        let store = fresh_store().await;
        configure(&store, 600).await;
        let first = store.issue().await.expect("issue");
        let second = store.rotate().await.expect("rotate");
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
        let store = fresh_store().await;
        configure(&store, 1).await;
        store.issue().await.expect("issue");
        store.rotate().await.expect("rotate");
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
        let store = fresh_store().await;
        configure(&store, 60).await;
        let err = store.rotate().await.expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.contains("nothing to rotate"), "got: {msg}");
    }
}
