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

pub const KEY_CA_CERT: &str = "ca/cert";
pub const KEY_CA_KEY: &str = "ca/key";
pub const KEY_CA_META: &str = "ca/meta";
pub const KEY_CRL_STATE: &str = "crl/state";
pub const KEY_CRL_CACHED: &str = "crl/cached";
pub const KEY_CONFIG_URLS: &str = "config/urls";
pub const KEY_CONFIG_CRL: &str = "config/crl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMetadata {
    pub key_type: String,
    pub key_bits: u32,
    pub common_name: String,
    pub serial_hex: String,
    pub created_at_unix: u64,
    pub not_after_unix: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertRecord {
    pub serial_hex: String,
    pub certificate_pem: String,
    pub issued_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
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
