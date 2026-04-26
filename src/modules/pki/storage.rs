//! Sealed storage layout for the PKI engine.
//!
//! Storage keys (all live under the engine's mount inside the barrier):
//!
//! ```text
//! ca/cert        # PEM of the active CA certificate
//! ca/key         # PEM of the active CA private key (PKCS#8)
//! ca/meta        # JSON metadata (algorithm, common name, etc.)
//! certs/<hex>    # JSON cert record indexed by serial (lowercase hex, no `:`)
//! crl/state      # JSON CRL state (crl_number + revoked serial set)
//! crl/cached     # Last-built CRL PEM bytes
//! config/urls    # JSON config: issuing_certs / crl_distribution_points
//! config/crl     # JSON config: expiry duration, disable flag
//! ```
//!
//! Cert bodies are stored as PEM (UTF-8) inside their JSON envelope rather than
//! raw DER — keeps the storage layer auditable in plaintext (the *barrier*
//! handles the actual confidentiality).

use serde::{Deserialize, Serialize};

use crate::{errors::RvError, logical::Request, storage::StorageEntry};

// Legacy singleton paths (Phases 1–5.1). Read-only after the lazy
// migration in [`super::issuers`] runs on first use of any multi-issuer
// helper. New writes always go through the per-issuer paths.
pub const KEY_CA_CERT: &str = "ca/cert";
pub const KEY_CA_KEY: &str = "ca/key";
pub const KEY_CA_META: &str = "ca/meta";
pub const KEY_CRL_STATE: &str = "crl/state";
pub const KEY_CRL_CACHED: &str = "crl/cached";
pub const KEY_CONFIG_URLS: &str = "config/urls";
pub const KEY_CONFIG_CRL: &str = "config/crl";
pub const KEY_CONFIG_AUTO_TIDY: &str = "config/auto-tidy";
pub const KEY_TIDY_STATUS: &str = "tidy/status";

// Multi-issuer paths (Phase 5.2).
pub const KEY_ISSUERS_INDEX: &str = "issuers/index";
pub const KEY_CONFIG_ISSUERS: &str = "config/issuers";

pub fn issuer_cert_key(id: &str) -> String { format!("issuers/{id}/cert") }
pub fn issuer_key_key(id: &str) -> String { format!("issuers/{id}/key") }
pub fn issuer_meta_key(id: &str) -> String { format!("issuers/{id}/meta") }
pub fn issuer_crl_state_key(id: &str) -> String { format!("crl/issuer/{id}/state") }
pub fn issuer_crl_cached_key(id: &str) -> String { format!("crl/issuer/{id}/cached") }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssuersIndex {
    /// Map of issuer_id (uuid) → human-readable name. Names must be unique
    /// within a mount; the engine enforces that on `add_issuer`.
    pub by_id: std::collections::BTreeMap<String, String>,
}

impl IssuersIndex {
    pub fn name_to_id(&self, name: &str) -> Option<String> {
        self.by_id.iter().find_map(|(id, n)| if n == name { Some(id.clone()) } else { None })
    }

    /// Resolve an `issuer_ref` (either UUID or name) against this index.
    pub fn resolve(&self, reference: &str) -> Option<String> {
        if self.by_id.contains_key(reference) {
            return Some(reference.to_string());
        }
        self.name_to_id(reference)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssuersConfig {
    /// UUID of the default issuer for this mount. `pki/ca`, `pki/crl`,
    /// and `pki/issue/:role` (when no `issuer_ref` is given) all route to
    /// this issuer.
    pub default_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMetadata {
    pub key_type: String,
    pub key_bits: u32,
    pub common_name: String,
    pub serial_hex: String,
    pub created_at_unix: u64,
    pub not_after_unix: i64,
    /// What kind of CA the operator installed at this mount. Tracked so
    /// `sys/internal/ui/mounts` and admin tooling can render
    /// "intermediate-CA mount waiting for signed cert" without re-parsing
    /// the cert. `#[serde(default)]` keeps Phase 1–4 records readable.
    #[serde(default)]
    pub ca_kind: CaKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaKind {
    /// `pki/root/generate/*` — the engine generated a self-signed root.
    #[default]
    Root,
    /// `pki/intermediate/set-signed` — the engine generated the keypair
    /// and the operator installed an externally-signed cert.
    Intermediate,
    /// `pki/config/ca` — the operator imported an externally-generated
    /// CA bundle wholesale.
    Imported,
}

/// Stored alongside the active CA when an intermediate-CA generation is in
/// flight: the engine has produced a keypair, returned a CSR, and is
/// waiting on `pki/intermediate/set-signed` to install the issuer's
/// counter-signed cert. Until that arrives, `ca/cert` is absent and issue
/// calls fail with `ErrPkiCaNotConfig`, which is the right behaviour.
pub const KEY_CA_PENDING_KEY: &str = "ca/pending/key";
pub const KEY_CA_PENDING_CSR: &str = "ca/pending/csr";
pub const KEY_CA_PENDING_META: &str = "ca/pending/meta";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingIntermediate {
    pub key_type: String,
    pub key_bits: u32,
    pub common_name: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertRecord {
    pub serial_hex: String,
    pub certificate_pem: String,
    pub issued_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
    /// Unix timestamp of the certificate's NotAfter, captured at issue time
    /// so [`super::path_tidy`] can sweep expired records without re-parsing
    /// the stored PEM. `#[serde(default)]` keeps deserialization
    /// backwards-compatible with records written before Phase 4.
    #[serde(default)]
    pub not_after_unix: i64,
    /// Phase 5.2: which issuer (UUID) signed this cert. Empty string means
    /// "the mount's default issuer" — that's what records written before
    /// 5.2 deserialize to. The CRL builder uses this to group revocations
    /// by issuer when the mount has more than one.
    #[serde(default)]
    pub issuer_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrlState {
    pub crl_number: u64,
    /// Hex-encoded serial -> revocation time (unix seconds).
    pub revoked: Vec<RevokedSerial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedSerial {
    pub serial_hex: String,
    pub revoked_at_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UrlsConfig {
    #[serde(default)]
    pub issuing_certificates: Vec<String>,
    #[serde(default)]
    pub crl_distribution_points: Vec<String>,
    #[serde(default)]
    pub ocsp_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlConfig {
    /// CRL `next_update` window, in seconds. Vault default is 72h.
    pub expiry_seconds: u64,
    pub disable: bool,
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self { expiry_seconds: 72 * 3600, disable: false }
    }
}

/// Configuration for the periodic tidy job.
///
/// Phase 4 ships the *config endpoint* (so operators can persist their
/// preference) but defers the actual scheduler — the values here are read
/// only by an on-demand `pki/tidy` invocation today. A follow-up will wire
/// a tokio task that fires at `interval_seconds` and runs the same handler
/// the operator can call manually.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTidyConfig {
    pub enabled: bool,
    /// How often the periodic tidy fires. Vault default is 12 hours.
    pub interval_seconds: u64,
    /// Sweep certs from `certs/<serial>` whose NotAfter has passed.
    pub tidy_cert_store: bool,
    /// Sweep entries from the CRL revoked-list whose certs have already
    /// expired (the operating thinking is: an expired cert no longer needs
    /// to appear in a CRL because verifiers reject it on date alone).
    pub tidy_revoked_certs: bool,
    /// Wait this long *after* a record's NotAfter before deleting, so a
    /// brief operator window remains for forensic inspection. Vault default
    /// is 72 hours.
    pub safety_buffer_seconds: u64,
}

impl Default for AutoTidyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: 12 * 3600,
            tidy_cert_store: true,
            tidy_revoked_certs: true,
            safety_buffer_seconds: 72 * 3600,
        }
    }
}

/// Snapshot of the most recent tidy run, surfaced via `pki/tidy-status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TidyStatus {
    pub last_run_at_unix: u64,
    pub last_run_duration_ms: u64,
    pub certs_deleted: u64,
    pub revoked_entries_deleted: u64,
    pub safety_buffer_seconds: u64,
    pub source: String,
}

pub fn serial_to_hex(serial: &[u8]) -> String {
    let mut s = String::with_capacity(serial.len() * 2);
    for b in serial {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn cert_storage_key(serial_hex: &str) -> String {
    format!("certs/{serial_hex}")
}

#[maybe_async::maybe_async]
pub async fn put_json<T: Serialize>(req: &Request, key: &str, value: &T) -> Result<(), RvError> {
    let bytes = serde_json::to_vec(value)?;
    let entry = StorageEntry { key: key.to_string(), value: bytes };
    req.storage_put(&entry).await
}

#[maybe_async::maybe_async]
pub async fn get_json<T: for<'de> Deserialize<'de>>(
    req: &Request,
    key: &str,
) -> Result<Option<T>, RvError> {
    match req.storage_get(key).await? {
        Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
        None => Ok(None),
    }
}

#[maybe_async::maybe_async]
pub async fn put_string(req: &Request, key: &str, value: &str) -> Result<(), RvError> {
    let entry = StorageEntry { key: key.to_string(), value: value.as_bytes().to_vec() };
    req.storage_put(&entry).await
}

#[maybe_async::maybe_async]
pub async fn get_string(req: &Request, key: &str) -> Result<Option<String>, RvError> {
    match req.storage_get(key).await? {
        Some(e) => Ok(Some(String::from_utf8(e.value).map_err(|e| RvError::ErrString(e.to_string()))?)),
        None => Ok(None),
    }
}
