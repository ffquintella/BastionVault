//! `/v1/transit/keys/:name` CRUD + `/config` + `/rotate` + `/trim`,
//! plus `LIST /v1/transit/keys`.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{ed25519, ml_dsa, ml_kem, sym},
    keytype::KeyType,
    policy::{KeyPolicy, KeyVersion},
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const KEYS_HELP: &str = r#"
Manage transit keys. POST creates a key with a `key_type` (one of
chacha20-poly1305, hmac, ed25519, ml-kem-768, ml-dsa-44, ml-dsa-65,
ml-dsa-87). GET returns metadata (and the public key for asymmetric
types). DELETE refuses unless `deletion_allowed = true`.
"#;

const KEYS_LIST_HELP: &str = "List configured transit key names.";

const ROTATE_HELP: &str = "Append a new version to the named key. Encrypt / sign use the latest; decrypt / verify try every version >= min_decryption_version.";
const CONFIG_HELP: &str = "Update min_decryption_version, min_available_version, deletion_allowed.";
const TRIM_HELP: &str = "Drop versions below min_available_version. Refused if any retained version is below min_decryption_version.";

impl TransitBackend {
    pub fn keys_path(&self) -> Path {
        let read = self.inner.clone();
        let write = self.inner.clone();
        let delete = self.inner.clone();
        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":     { field_type: FieldType::Str, required: true, description: "Key name." },
                "key_type": { field_type: FieldType::Str, default: "chacha20-poly1305", description: "Algorithm. See key_type table." },
                "exportable":       { field_type: FieldType::Bool, default: false, description: "Allow export of raw key material via /export. Sticky once-false." },
                "deletion_allowed": { field_type: FieldType::Bool, default: false, description: "Allow DELETE. Default-closed; flip via /config." },
                "derived":          { field_type: FieldType::Bool, default: false, description: "Per-context subkey derivation via HKDF. Symmetric AEAD only." },
                "convergent_encryption": { field_type: FieldType::Bool, default: false, description: "Deterministic nonce from `HMAC(key, plaintext || context)`. Requires `derived = true`." }
            },
            operations: [
                {op: Operation::Read,   handler: read.handle_key_read},
                {op: Operation::Write,  handler: write.handle_key_create},
                {op: Operation::Delete, handler: delete.handle_key_delete}
            ],
            help: KEYS_HELP
        })
    }

    pub fn keys_list_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/?$",
            operations: [{op: Operation::List, handler: h.handle_keys_list}],
            help: KEYS_LIST_HELP
        })
    }

    pub fn rotate_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)/rotate",
            fields: { "name": { field_type: FieldType::Str, required: true, description: "Key name." } },
            operations: [{op: Operation::Write, handler: h.handle_key_rotate}],
            help: ROTATE_HELP
        })
    }

    pub fn config_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)/config",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Key name." },
                "min_decryption_version": { field_type: FieldType::Int, default: 0, description: "Refuse decrypt of versions below this. 0 = leave unchanged." },
                "min_available_version":  { field_type: FieldType::Int, default: 0, description: "Drop-zone for /trim. 0 = leave unchanged." },
                "deletion_allowed":       { field_type: FieldType::Bool, default: false, description: "Allow DELETE on the key." }
            },
            operations: [{op: Operation::Write, handler: h.handle_key_config}],
            help: CONFIG_HELP
        })
    }

    pub fn trim_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)/trim",
            fields: { "name": { field_type: FieldType::Str, required: true, description: "Key name." } },
            operations: [{op: Operation::Write, handler: h.handle_key_trim}],
            help: TRIM_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub async fn handle_keys_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = self.list_policies(req).await?;
        Ok(Some(Response::list_response(&keys)))
    }

    pub async fn handle_key_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        match self.get_policy(req, &name).await? {
            Some(p) => Ok(Some(Response::data_response(Some(render_metadata(&p))))),
            None => Ok(None),
        }
    }

    pub async fn handle_key_create(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        if name.is_empty() {
            return Err(RvError::ErrString("name is required".into()));
        }

        // Idempotent re-create: if the key already exists with the
        // same key_type, return its current metadata. Different
        // key_type → reject (operators must DELETE explicitly first).
        let kt = KeyType::parse(&take_or(req, "key_type", "chacha20-poly1305"))?;
        if let Some(existing) = self.get_policy(req, &name).await? {
            if existing.key_type != kt {
                return Err(RvError::ErrString(format!(
                    "key `{name}` already exists with type {}; refusing to recreate as {}",
                    existing.key_type.as_str(),
                    kt.as_str()
                )));
            }
            return Ok(Some(Response::data_response(Some(render_metadata(&existing)))));
        }

        let exportable = take_bool(req, "exportable", false);
        let deletion_allowed = take_bool(req, "deletion_allowed", false);
        let derived = take_bool(req, "derived", false);
        let convergent_encryption = take_bool(req, "convergent_encryption", false);

        // Derived / convergent are AEAD-only. ML-KEM ciphertexts are
        // randomised by the FIPS 203 spec; HMAC keys have no nonce
        // to derive in the first place; ML-DSA signatures aren't an
        // encryption primitive at all. We refuse the combination at
        // create time so an operator who set the flag against the
        // wrong key type doesn't get a runtime surprise on the first
        // /encrypt call.
        if (derived || convergent_encryption) && !kt.is_symmetric_aead() {
            return Err(RvError::ErrString(format!(
                "derived / convergent_encryption are symmetric-AEAD only; {} does not support them",
                kt.as_str()
            )));
        }
        if convergent_encryption && !derived {
            return Err(RvError::ErrString(
                "convergent_encryption=true requires derived=true (the per-context subkey is what makes the deterministic nonce safe)".into(),
            ));
        }

        let v1 = mint_version(kt, 1)?;
        let mut p = KeyPolicy::new(name.clone(), kt, v1);
        p.exportable = exportable;
        p.deletion_allowed = deletion_allowed;
        p.derived = derived;
        p.convergent_encryption = convergent_encryption;

        self.put_policy(req, &p).await?;
        Ok(Some(Response::data_response(Some(render_metadata(&p)))))
    }

    pub async fn handle_key_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        if !p.deletion_allowed {
            return Err(RvError::ErrString(
                "deletion_allowed is false; flip it via /keys/<name>/config first".into(),
            ));
        }
        self.delete_policy(req, &name).await?;
        Ok(None)
    }

    pub async fn handle_key_rotate(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let mut p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        let next = p.latest_version + 1;
        let v = mint_version(p.key_type, next)?;
        p.versions.insert(next, v);
        p.latest_version = next;
        self.put_policy(req, &p).await?;
        Ok(Some(Response::data_response(Some(render_metadata(&p)))))
    }

    pub async fn handle_key_config(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let mut p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;

        let mdv = take_int(req, "min_decryption_version", 0) as u32;
        if mdv > 0 {
            if mdv > p.latest_version {
                return Err(RvError::ErrString(format!(
                    "min_decryption_version {mdv} exceeds latest_version {}",
                    p.latest_version
                )));
            }
            p.min_decryption_version = mdv;
        }
        let mav = take_int(req, "min_available_version", 0) as u32;
        if mav > 0 {
            if mav > p.min_decryption_version {
                return Err(RvError::ErrString(format!(
                    "min_available_version {mav} would discard versions still below min_decryption_version {}",
                    p.min_decryption_version
                )));
            }
            p.min_available_version = mav;
        }
        if let Ok(v) = req.get_data("deletion_allowed") {
            if let Some(b) = v.as_bool() {
                p.deletion_allowed = b;
            }
        }
        // exportable is sticky-once-false: never re-enable.
        self.put_policy(req, &p).await?;
        Ok(Some(Response::data_response(Some(render_metadata(&p)))))
    }

    pub async fn handle_key_trim(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let mut p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        let mav = p.min_available_version;
        let before = p.versions.len();
        p.versions.retain(|v, _| *v >= mav);
        if p.versions.is_empty() {
            return Err(RvError::ErrString(
                "trim would leave the key with no versions; raise min_available_version more conservatively".into(),
            ));
        }
        let dropped = before - p.versions.len();
        self.put_policy(req, &p).await?;
        let mut data = render_metadata(&p);
        data.insert("dropped_versions".into(), Value::Number(dropped.into()));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Construct one fresh key version of the given algorithm.
pub fn mint_version(kt: KeyType, version: u32) -> Result<KeyVersion, RvError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (material, pk) = match kt {
        KeyType::Chacha20Poly1305 => (sym::generate_aead_key(kt)?, Vec::new()),
        KeyType::Hmac => (sym::generate_hmac_key(), Vec::new()),
        KeyType::Ed25519 => {
            let (seed, pk) = ed25519::generate_keypair();
            (seed, pk)
        }
        KeyType::MlKem768 => {
            let (sk, pk) = ml_kem::generate_keypair()?;
            (sk, pk)
        }
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
            let (seed, pk) = ml_dsa::generate_keypair(kt)?;
            (seed, pk)
        }
        #[cfg(feature = "transit_pqc_hybrid")]
        KeyType::HybridEd25519MlDsa65 => {
            super::crypto::hybrid::generate_signing_keypair()?
        }
        #[cfg(feature = "transit_pqc_hybrid")]
        KeyType::HybridX25519MlKem768 => {
            super::crypto::hybrid::generate_kem_keypair()?
        }
    };
    Ok(KeyVersion { version, created_at: now, material, pk })
}

/// Public-side key metadata. Never includes secret material.
pub fn render_metadata(p: &KeyPolicy) -> Map<String, Value> {
    let mut data = Map::new();
    data.insert("name".into(), Value::String(p.name.clone()));
    data.insert("type".into(), Value::String(p.key_type.as_str().into()));
    data.insert("latest_version".into(), Value::Number(p.latest_version.into()));
    data.insert(
        "min_decryption_version".into(),
        Value::Number(p.min_decryption_version.into()),
    );
    data.insert(
        "min_available_version".into(),
        Value::Number(p.min_available_version.into()),
    );
    data.insert("deletion_allowed".into(), Value::Bool(p.deletion_allowed));
    data.insert("exportable".into(), Value::Bool(p.exportable));
    data.insert("derived".into(), Value::Bool(p.derived));
    data.insert(
        "convergent_encryption".into(),
        Value::Bool(p.convergent_encryption),
    );

    // Asymmetric types: surface per-version public keys (base64-encoded
    // raw bytes — the wire format depends on the algorithm: 32-byte
    // raw Ed25519 pubkey, 1184-byte ML-KEM-768 EK, 1312/1952/2592-byte
    // ML-DSA pubkey). The framing matches `bv_crypto`'s canonical
    // serde output.
    if p.key_type.has_public_material() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let mut keys = Map::new();
        for (v, kv) in &p.versions {
            let mut entry = Map::new();
            entry.insert("public_key".into(), Value::String(B64.encode(&kv.pk)));
            entry.insert("creation_time".into(), Value::Number(kv.created_at.into()));
            keys.insert(v.to_string(), Value::Object(entry));
        }
        data.insert("keys".into(), Value::Object(keys));
    } else {
        let mut keys = Map::new();
        for (v, kv) in &p.versions {
            keys.insert(v.to_string(), Value::Number(kv.created_at.into()));
        }
        data.insert("keys".into(), Value::Object(keys));
    }
    data
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

fn take_int(req: &Request, key: &str, default: i64) -> i64 {
    req.get_data(key).ok().and_then(|v| v.as_i64()).unwrap_or(default)
}

fn take_bool(req: &Request, key: &str, default: bool) -> bool {
    req.get_data(key).ok().and_then(|v| v.as_bool()).unwrap_or(default)
}
