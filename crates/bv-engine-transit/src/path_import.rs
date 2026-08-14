//! BYOK import flow — `transit_byok` feature.
//!
//! Three endpoints make up the flow:
//!
//!   * `POST /v1/transit/wrapping_key`
//!     Returns the per-mount ML-KEM-768 wrapping public key. The
//!     mount lazily generates the wrapping keypair on first call;
//!     subsequent calls return the same value. The private half
//!     never leaves the barrier.
//!
//!   * `POST /v1/transit/keys/:name/import`
//!     Caller has already encapsulated against the wrapping public
//!     key and HKDF'd a 32-byte symmetric key client-side. Body
//!     supplies `key_type`, the wrapped (KEM-encapsulated) datakey
//!     blob, and optional `derived` / `convergent_encryption` /
//!     `exportable` flags. Engine decapsulates with its private
//!     wrapping key, verifies the recovered key length matches the
//!     declared key_type, and stores the result as version 1 of a
//!     fresh policy under `name`.
//!
//!   * `POST /v1/transit/keys/:name/import_version`
//!     Same shape as `/import` but appends as `latest_version + 1`
//!     to an existing key. `key_type` must match the existing
//!     policy's `key_type` (refuses an attempt to type-mutate an
//!     existing key under cover of a fresh version).
//!
//! The wrapped-blob format is the same `bvault:vN:pqc:ml-kem-768:<b64>`
//! framing the engine itself emits via `/datakey/wrapped/wrap`, so a
//! caller who has access to the wrapping key's *public* half can
//! produce the input blob with any FIPS 203 implementation (Rust
//! `ml-kem`, OpenQuantumSafe `liboqs`, etc.) as long as it follows
//! the same HKDF derivation: `HKDF-SHA-256(shared_secret, info=
//! "bvault-transit-datakey")` to a 32-byte key.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{ciphertext, ml_kem, sym},
    keytype::KeyType,
    policy::{KeyPolicy, KeyVersion},
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

/// Storage key for the per-mount BYOK wrapping keypair. One per
/// mount UUID; persisted barrier-encrypted like everything else.
const WRAPPING_KEY_PATH: &str = "wrapping/ml-kem-768";

const WRAPPING_HELP: &str = "Return the per-mount ML-KEM-768 BYOK wrapping public key. Lazily generated on first call.";
const IMPORT_HELP: &str = "Import an externally-generated symmetric key as version 1 of a new key. The wrapped blob must be ML-KEM-768 encapsulated against /wrapping_key.";
const IMPORT_VERSION_HELP: &str = "Append a wrapped, externally-generated key as the next version of an existing key.";

#[derive(serde::Serialize, serde::Deserialize)]
struct WrappingKey {
    secret: Vec<u8>,
    public: Vec<u8>,
}

impl TransitBackend {
    pub fn wrapping_key_path(&self) -> Path {
        let h_read = self.inner.clone();
        let h_write = self.inner.clone();
        new_path!({
            pattern: r"wrapping_key",
            operations: [
                {op: Operation::Read,  handler: h_read.handle_wrapping_key},
                {op: Operation::Write, handler: h_write.handle_wrapping_key}
            ],
            help: WRAPPING_HELP
        })
    }

    pub fn import_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)/import",
            fields: {
                "name":          { field_type: FieldType::Str, required: true, description: "Key name." },
                "key_type":      { field_type: FieldType::Str, default: "chacha20-poly1305", description: "Algorithm of the imported key." },
                "ciphertext":    { field_type: FieldType::Str, default: "", description: "ML-KEM-768 wrapped key blob (`bvault:vN:pqc:ml-kem-768:<b64>` framing)." },
                "derived":       { field_type: FieldType::Bool, default: false, description: "Per-context subkey derivation. Symmetric AEAD only." },
                "convergent_encryption": { field_type: FieldType::Bool, default: false, description: "Deterministic nonce. Requires derived=true." },
                "exportable":    { field_type: FieldType::Bool, default: false, description: "Allow export. Sticky once-false." },
                "deletion_allowed": { field_type: FieldType::Bool, default: false, description: "Allow DELETE." }
            },
            operations: [{op: Operation::Write, handler: h.handle_import}],
            help: IMPORT_HELP
        })
    }

    pub fn import_version_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)/import_version",
            fields: {
                "name":       { field_type: FieldType::Str, required: true, description: "Existing key name." },
                "ciphertext": { field_type: FieldType::Str, default: "", description: "ML-KEM-768 wrapped key blob." }
            },
            operations: [{op: Operation::Write, handler: h.handle_import_version}],
            help: IMPORT_VERSION_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    /// Return the wrapping public key, generating the keypair on
    /// first call. We use `Operation::Read` *and* `Write` for this
    /// path so a `transit-user` token (which has no `update` on
    /// `wrapping_key`) can still pull the public key — the lazy-init
    /// then runs under whichever operator first hit the endpoint.
    pub async fn handle_wrapping_key(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let wk = self.load_or_create_wrapping_key(req).await?;
        let mut data = Map::new();
        data.insert("public_key".into(), Value::String(B64.encode(&wk.public)));
        data.insert("algorithm".into(), Value::String("ml-kem-768".into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_import(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let kt = KeyType::parse(&take_or(req, "key_type", "chacha20-poly1305"))?;
        if !kt.is_symmetric_aead() && kt != KeyType::Hmac {
            return Err(RvError::ErrString(format!(
                "BYOK import currently supports symmetric-AEAD and hmac keys only; got {}",
                kt.as_str()
            )));
        }
        if self.get_policy(req, &name).await?.is_some() {
            return Err(RvError::ErrString(format!(
                "key `{name}` already exists; use /import_version to add a wrapped version"
            )));
        }

        let derived = take_bool(req, "derived", false);
        let convergent_encryption = take_bool(req, "convergent_encryption", false);
        let exportable = take_bool(req, "exportable", false);
        let deletion_allowed = take_bool(req, "deletion_allowed", false);
        if (derived || convergent_encryption) && !kt.is_symmetric_aead() {
            return Err(RvError::ErrString(format!(
                "derived / convergent_encryption are AEAD-only; {} does not support them",
                kt.as_str()
            )));
        }
        if convergent_encryption && !derived {
            return Err(RvError::ErrString(
                "convergent_encryption=true requires derived=true".into(),
            ));
        }

        let material = self.unwrap_imported_key(req, kt).await?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let v1 = KeyVersion {
            version: 1,
            created_at: now,
            material,
            pk: Vec::new(),
        };
        let mut p = KeyPolicy::new(name, kt, v1);
        p.exportable = exportable;
        p.deletion_allowed = deletion_allowed;
        p.derived = derived;
        p.convergent_encryption = convergent_encryption;
        self.put_policy(req, &p).await?;
        Ok(Some(Response::data_response(Some(super::path_keys::render_metadata(&p)))))
    }

    pub async fn handle_import_version(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let mut p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        let material = self.unwrap_imported_key(req, p.key_type).await?;
        let next = p.latest_version + 1;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        p.versions.insert(
            next,
            KeyVersion {
                version: next,
                created_at: now,
                material,
                pk: Vec::new(),
            },
        );
        p.latest_version = next;
        self.put_policy(req, &p).await?;
        Ok(Some(Response::data_response(Some(super::path_keys::render_metadata(&p)))))
    }

    async fn load_or_create_wrapping_key(
        &self,
        req: &mut Request,
    ) -> Result<WrappingKey, RvError> {
        if let Some(e) = req.storage_get(WRAPPING_KEY_PATH).await? {
            return Ok(serde_json::from_slice(&e.value)?);
        }
        let (sk, pk) = ml_kem::generate_keypair()?;
        let wk = WrappingKey { secret: sk, public: pk };
        req.storage_put(&StorageEntry {
            key: WRAPPING_KEY_PATH.to_string(),
            value: serde_json::to_vec(&wk)?,
        })
        .await?;
        Ok(wk)
    }

    /// Decapsulate the caller-supplied wrapped blob with this mount's
    /// private wrapping key, validate the recovered key length
    /// matches the declared key_type, and return the raw key bytes.
    async fn unwrap_imported_key(
        &self,
        req: &mut Request,
        kt: KeyType,
    ) -> Result<Vec<u8>, RvError> {
        let ct_str = take_str(req, "ciphertext");
        let framed = ciphertext::parse(&ct_str)?;
        if framed.pqc_algo.as_deref() != Some("ml-kem-768") {
            return Err(RvError::ErrString(format!(
                "BYOK wrapping requires ml-kem-768 framing; got {:?}",
                framed.pqc_algo
            )));
        }
        let wk = self.load_or_create_wrapping_key(req).await?;
        let dk = ml_kem::decapsulate_datakey(&wk.secret, &framed.bytes)?;
        // The unwrap derives a 32-byte key. AEAD + HMAC both want
        // 32 bytes, so no length adjustment needed today. If a
        // future key type wants a different length, this is the
        // single place to reject the wrong size.
        let expected_len = match kt {
            KeyType::Chacha20Poly1305 => sym::CHACHA_KEY_LEN,
            KeyType::Hmac => 32,
            other => {
                return Err(RvError::ErrString(format!(
                    "BYOK import does not currently support {}",
                    other.as_str()
                )))
            }
        };
        if dk.len() != expected_len {
            return Err(RvError::ErrString(format!(
                "BYOK unwrap recovered {} bytes but {} expects {}",
                dk.len(),
                kt.as_str(),
                expected_len
            )));
        }
        Ok(dk)
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn take_or(req: &Request, key: &str, default: &str) -> String {
    let s = take_str(req, key);
    if s.is_empty() { default.to_string() } else { s }
}

fn take_bool(req: &Request, key: &str, default: bool) -> bool {
    req.get_data(key).ok().and_then(|v| v.as_bool()).unwrap_or(default)
}
