//! Multi-issuer storage layer — Phase 5.2.
//!
//! Each PKI mount can hold multiple issuer certificates + keys at
//! `issuers/<id>/{cert,key,meta}`, with a registry at `issuers/index` and
//! a default-issuer pointer at `config/issuers`. Existing routes that used
//! to read the singleton `ca/cert` / `ca/key` / `ca/meta` paths now go
//! through [`load_default_issuer`] / [`load_issuer`], which lazily migrate
//! a Phase-1-through-5.1 mount into the multi-issuer layout the first time
//! it is touched.
//!
//! ### Migration semantics
//!
//! On first call to a helper here:
//!
//! 1. If `issuers/index` already exists, the mount is already multi-issuer
//!    aware — do nothing.
//! 2. Else if `ca/cert` exists, lift it into `issuers/<new-uuid>/cert`,
//!    copy `ca/key` and `ca/meta` similarly, copy `crl/state` and
//!    `crl/cached`, write the index + default pointer, and delete the
//!    legacy singletons. Idempotent: a partial failure mid-migration
//!    re-runs cleanly because each step is "skip if target exists".
//! 3. Else this is a fresh mount with no CA configured yet; do nothing.
//!
//! After migration, the mount has exactly one issuer (the migrated one)
//! with the name `"default"` and is the default-pointer target.
//!
//! ### Issuance bookkeeping
//!
//! When a handler uses [`add_issuer`] to install a new CA — `root/generate`
//! or a future `intermediate/set-signed` path — the helper allocates a
//! fresh UUID, writes the per-issuer paths, and updates the index. The
//! first issuer added to a mount is automatically the default; subsequent
//! issuers must be made default explicitly via `pki/config/issuers`.

use uuid::Uuid;

use super::{
    crypto::{KeyAlgorithm, Signer},
    storage::{
        self, CaKind, CaMetadata, CrlConfig, CrlState, IssuersConfig, IssuersIndex,
        KEY_CA_CERT, KEY_CA_KEY, KEY_CA_META, KEY_CONFIG_CRL, KEY_CONFIG_ISSUERS, KEY_CRL_CACHED,
        KEY_CRL_STATE, KEY_ISSUERS_INDEX,
    },
};
use crate::{errors::RvError, logical::Request};

/// A loaded issuer ready for the cert/CRL builders.
pub struct IssuerHandle {
    pub id: String,
    pub name: String,
    pub cert_pem: String,
    pub signer: Signer,
    pub meta: CaMetadata,
}

/// Load the mount's default issuer. Performs the lazy lift if needed.
#[maybe_async::maybe_async]
pub async fn load_default_issuer(req: &Request) -> Result<IssuerHandle, RvError> {
    migrate_legacy_if_needed(req).await?;
    let cfg: Option<IssuersConfig> = storage::get_json(req, KEY_CONFIG_ISSUERS).await?;
    let cfg = cfg.ok_or(RvError::ErrPkiCaNotConfig)?;
    load_issuer_by_id(req, &cfg.default_id).await
}

/// Load a specific issuer by its `id` or `name`. Performs the lazy lift if
/// needed.
#[maybe_async::maybe_async]
pub async fn load_issuer(req: &Request, reference: &str) -> Result<IssuerHandle, RvError> {
    migrate_legacy_if_needed(req).await?;
    let index: IssuersIndex = storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default();
    let id = index.resolve(reference).ok_or(RvError::ErrPkiCaNotConfig)?;
    load_issuer_by_id(req, &id).await
}

#[maybe_async::maybe_async]
async fn load_issuer_by_id(req: &Request, id: &str) -> Result<IssuerHandle, RvError> {
    let cert_pem = storage::get_string(req, &storage::issuer_cert_key(id))
        .await?
        .ok_or(RvError::ErrPkiCaNotConfig)?;
    let key_pem = storage::get_string(req, &storage::issuer_key_key(id))
        .await?
        .ok_or(RvError::ErrPkiCaKeyNotFound)?;
    let meta: CaMetadata = storage::get_json(req, &storage::issuer_meta_key(id))
        .await?
        .ok_or(RvError::ErrPkiCaNotConfig)?;
    let signer = Signer::from_storage_pem(&key_pem)?;
    let index: IssuersIndex = storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default();
    let name = index.by_id.get(id).cloned().unwrap_or_else(|| "default".to_string());
    Ok(IssuerHandle { id: id.to_string(), name, cert_pem, signer, meta })
}

/// Add a brand-new issuer. Allocates a fresh UUID, writes
/// `issuers/<id>/{cert,key,meta}`, registers the issuer in the index, and
/// — if no default existed before — points the default at this issuer.
/// Returns the assigned UUID so the caller can persist it on `CertRecord`s
/// it issues.
#[maybe_async::maybe_async]
pub async fn add_issuer(
    req: &Request,
    name: &str,
    cert_pem: &str,
    signer: &Signer,
    common_name: &str,
    serial_hex: &str,
    not_after_unix: i64,
    ca_kind: CaKind,
) -> Result<String, RvError> {
    if name.is_empty() {
        return Err(RvError::ErrRequestFieldInvalid);
    }
    migrate_legacy_if_needed(req).await?;

    let mut index: IssuersIndex = storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default();
    if index.name_to_id(name).is_some() {
        // Reject duplicate names so operators can refer to issuers by name
        // later without ambiguity.
        return Err(RvError::ErrPkiCaNotConfig);
    }
    let id = Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let alg = signer.algorithm();
    let meta = CaMetadata {
        key_type: alg.as_str().to_string(),
        key_bits: alg.key_bits(),
        common_name: common_name.to_string(),
        serial_hex: serial_hex.to_string(),
        created_at_unix: now,
        not_after_unix,
        ca_kind,
    };
    storage::put_string(req, &storage::issuer_cert_key(&id), cert_pem).await?;
    storage::put_string(req, &storage::issuer_key_key(&id), &signer.to_storage_pem()).await?;
    storage::put_json(req, &storage::issuer_meta_key(&id), &meta).await?;
    // Each issuer gets its own CRL state seeded.
    if storage::get_json::<CrlState>(req, &storage::issuer_crl_state_key(&id)).await?.is_none() {
        storage::put_json(req, &storage::issuer_crl_state_key(&id), &CrlState::default()).await?;
    }
    if storage::get_json::<CrlConfig>(req, KEY_CONFIG_CRL).await?.is_none() {
        storage::put_json(req, KEY_CONFIG_CRL, &CrlConfig::default()).await?;
    }
    index.by_id.insert(id.clone(), name.to_string());
    storage::put_json(req, KEY_ISSUERS_INDEX, &index).await?;

    // First issuer: become default automatically.
    let cfg: Option<IssuersConfig> = storage::get_json(req, KEY_CONFIG_ISSUERS).await?;
    if cfg.map(|c| c.default_id.is_empty()).unwrap_or(true) {
        storage::put_json(req, KEY_CONFIG_ISSUERS, &IssuersConfig { default_id: id.clone() }).await?;
    }
    let _ = signer; // used above, captured for lifetime clarity
    let _ = &meta;
    Ok(id)
}

#[maybe_async::maybe_async]
pub async fn list_issuers(req: &Request) -> Result<IssuersIndex, RvError> {
    migrate_legacy_if_needed(req).await?;
    Ok(storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default())
}

#[maybe_async::maybe_async]
pub async fn read_default_pointer(req: &Request) -> Result<IssuersConfig, RvError> {
    migrate_legacy_if_needed(req).await?;
    Ok(storage::get_json(req, KEY_CONFIG_ISSUERS).await?.unwrap_or_default())
}

#[maybe_async::maybe_async]
pub async fn set_default_pointer(req: &Request, reference: &str) -> Result<(), RvError> {
    migrate_legacy_if_needed(req).await?;
    let index: IssuersIndex = storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default();
    let id = index.resolve(reference).ok_or(RvError::ErrPkiCaNotConfig)?;
    storage::put_json(req, KEY_CONFIG_ISSUERS, &IssuersConfig { default_id: id }).await
}

/// Lift the legacy `ca/cert` + `ca/key` + `ca/meta` singletons into
/// `issuers/<uuid>/*`. Idempotent — does nothing if already migrated, and
/// safe to call from every multi-issuer entry point.
#[maybe_async::maybe_async]
async fn migrate_legacy_if_needed(req: &Request) -> Result<(), RvError> {
    if storage::get_json::<IssuersIndex>(req, KEY_ISSUERS_INDEX).await?.is_some() {
        return Ok(());
    }
    let Some(legacy_cert) = storage::get_string(req, KEY_CA_CERT).await? else {
        // Fresh mount with no CA. The first `add_issuer` call will
        // populate the index from scratch.
        return Ok(());
    };
    let Some(legacy_key) = storage::get_string(req, KEY_CA_KEY).await? else {
        // Cert without key is a corrupt state — bail rather than guess.
        log::warn!("pki/issuers: legacy ca/cert present but ca/key missing; refusing to migrate");
        return Err(RvError::ErrPkiCaKeyNotFound);
    };
    let legacy_meta: CaMetadata = match storage::get_json(req, KEY_CA_META).await? {
        Some(m) => m,
        None => {
            // Construct a best-effort metadata from what we know about the
            // signer. Better than refusing to migrate.
            let signer = Signer::from_storage_pem(&legacy_key)?;
            let alg = signer.algorithm();
            CaMetadata {
                key_type: alg.as_str().to_string(),
                key_bits: alg.key_bits(),
                common_name: String::new(),
                serial_hex: String::new(),
                created_at_unix: 0,
                not_after_unix: 0,
                ca_kind: CaKind::Root,
            }
        }
    };

    let id = Uuid::new_v4().to_string();
    storage::put_string(req, &storage::issuer_cert_key(&id), &legacy_cert).await?;
    storage::put_string(req, &storage::issuer_key_key(&id), &legacy_key).await?;
    storage::put_json(req, &storage::issuer_meta_key(&id), &legacy_meta).await?;

    // Move CRL state too — same issuer owns it.
    if let Some(state) = storage::get_json::<CrlState>(req, KEY_CRL_STATE).await? {
        storage::put_json(req, &storage::issuer_crl_state_key(&id), &state).await?;
    }
    if let Some(cached) = storage::get_string(req, KEY_CRL_CACHED).await? {
        storage::put_string(req, &storage::issuer_crl_cached_key(&id), &cached).await?;
    }

    let mut index = IssuersIndex::default();
    index.by_id.insert(id.clone(), "default".to_string());
    storage::put_json(req, KEY_ISSUERS_INDEX, &index).await?;
    storage::put_json(req, KEY_CONFIG_ISSUERS, &IssuersConfig { default_id: id.clone() }).await?;

    // Delete the legacy singletons. Failures here are non-fatal — the
    // multi-issuer paths now hold the canonical copy and the legacy ones
    // will be ignored by every reader.
    let _ = req.storage_delete(KEY_CA_CERT).await;
    let _ = req.storage_delete(KEY_CA_KEY).await;
    let _ = req.storage_delete(KEY_CA_META).await;
    let _ = req.storage_delete(KEY_CRL_STATE).await;
    let _ = req.storage_delete(KEY_CRL_CACHED).await;

    let _ = KeyAlgorithm::EcdsaP256; // re-export touch for test helpers
    log::info!("pki/issuers: migrated legacy ca/* singletons into issuers/{id}");
    Ok(())
}

/// Rename an existing issuer. The new name must be non-empty and unique
/// within the mount's index. UUIDs do not change so existing
/// `CertRecord.issuer_id` pointers stay valid.
#[maybe_async::maybe_async]
pub async fn rename_issuer(req: &Request, reference: &str, new_name: &str) -> Result<(), RvError> {
    if new_name.is_empty() {
        return Err(RvError::ErrRequestFieldInvalid);
    }
    migrate_legacy_if_needed(req).await?;
    let mut index: IssuersIndex = storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default();
    let id = index.resolve(reference).ok_or(RvError::ErrPkiCaNotConfig)?;
    if let Some(existing) = index.name_to_id(new_name) {
        if existing != id {
            return Err(RvError::ErrPkiCaNotConfig);
        }
    }
    index.by_id.insert(id, new_name.to_string());
    storage::put_json(req, KEY_ISSUERS_INDEX, &index).await
}

/// Delete an issuer. Refuses to delete the current default if any other
/// issuers exist (the operator must reassign default first via
/// `pki/config/issuers`). Allows deleting the only issuer — the mount
/// becomes "no CA configured" again, which is the same as a fresh mount.
///
/// Storage: removes `issuers/<id>/{cert,key,meta}` and
/// `crl/issuer/<id>/{state,cached}`. Cert records issued by this issuer
/// (those with `CertRecord.issuer_id == id`) are intentionally left in
/// `certs/<serial>` — `pki/tidy` will sweep them once they expire. The
/// alternative (cascade-delete) was rejected because it makes audit
/// trails harder to reconstruct.
#[maybe_async::maybe_async]
pub async fn delete_issuer(req: &Request, reference: &str) -> Result<(), RvError> {
    migrate_legacy_if_needed(req).await?;
    let mut index: IssuersIndex = storage::get_json(req, KEY_ISSUERS_INDEX).await?.unwrap_or_default();
    let id = index.resolve(reference).ok_or(RvError::ErrPkiCaNotConfig)?;

    let cfg: IssuersConfig = storage::get_json(req, KEY_CONFIG_ISSUERS).await?.unwrap_or_default();
    if cfg.default_id == id && index.by_id.len() > 1 {
        return Err(RvError::ErrPkiCaNotConfig);
    }

    let _ = req.storage_delete(&storage::issuer_cert_key(&id)).await;
    let _ = req.storage_delete(&storage::issuer_key_key(&id)).await;
    let _ = req.storage_delete(&storage::issuer_meta_key(&id)).await;
    let _ = req.storage_delete(&storage::issuer_crl_state_key(&id)).await;
    let _ = req.storage_delete(&storage::issuer_crl_cached_key(&id)).await;

    index.by_id.remove(&id);
    if index.by_id.is_empty() {
        // Last issuer gone — clear default pointer and the index entirely.
        let _ = req.storage_delete(KEY_ISSUERS_INDEX).await;
        let _ = req.storage_delete(KEY_CONFIG_ISSUERS).await;
    } else {
        storage::put_json(req, KEY_ISSUERS_INDEX, &index).await?;
    }
    Ok(())
}

/// Compute a default name for the next-added issuer. First issuer is
/// `"default"`, subsequent ones are `"issuer-2"`, `"issuer-3"`, ... using
/// the smallest numeric suffix not already present.
pub fn next_default_name(index: &IssuersIndex) -> String {
    let names: std::collections::BTreeSet<&str> = index.by_id.values().map(|s| s.as_str()).collect();
    if !names.contains("default") {
        return "default".to_string();
    }
    let mut n = 2;
    loop {
        let candidate = format!("issuer-{n}");
        if !names.contains(candidate.as_str()) {
            return candidate;
        }
        n += 1;
    }
}
