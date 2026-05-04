//! Managed key store — Phase L1 of the PKI key-management + lifecycle
//! initiative. See [features/pki-key-management-and-lifecycle.md].
//!
//! Each PKI mount keeps an inventory of private keys at three storage
//! prefixes:
//!
//! ```text
//! keys/<key_id>            -- KeyEntry JSON (private key PEM is sealed by the barrier)
//! key-names/<name>         -- pointer file: a single line carrying the key_id
//! key-refs/<key_id>        -- KeyRefs JSON: issuer_ids + cert_serials currently bound
//! ```
//!
//! Layout choice: separate prefixes keep `storage_list("keys/")` returning
//! only ids; the name-pointer and refs files don't pollute the listing.
//!
//! Phase L1 scope: generate / import / list / read / delete. Reuse on
//! issuance (L2) and issuer-bound generation (L3) read these entries via
//! `load_key` in later phases — refs management lives here so those phases
//! drop in without changing storage shape.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    crypto::{KeyAlgorithm, Signer},
    pqc::MlDsaSigner,
};
use crate::{errors::RvError, logical::Request};

pub fn key_storage_key(id: &str) -> String {
    format!("keys/{id}")
}

pub fn name_pointer_key(name: &str) -> String {
    format!("key-names/{name}")
}

pub fn refs_storage_key(id: &str) -> String {
    format!("key-refs/{id}")
}

/// Provenance of a [`KeyEntry`] — surfaced over the API and useful for
/// audit and ops tooling.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    #[default]
    Generated,
    Imported,
}

impl KeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Imported => "imported",
        }
    }
}

/// A managed private key stored under the PKI mount's barrier.
///
/// `private_key_pem` is the engine-internal storage form (PKCS#8 for
/// classical keys, the `BV PQC SIGNER` envelope for ML-DSA — same shape
/// `Signer::from_storage_pem` already round-trips). The barrier handles
/// confidentiality at rest; this struct never escapes the engine in
/// serialised form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    /// Operator-friendly alias. Empty when no name was supplied at
    /// generate / import time.
    #[serde(default)]
    pub name: String,
    /// Algorithm tag in the same string form roles use (`"rsa"`, `"ec"`,
    /// `"ed25519"`, `"ml-dsa-65"`, …).
    pub key_type: String,
    /// Bit size for RSA / ECDSA. `0` for Ed25519 / ML-DSA, matching the
    /// convention `KeyAlgorithm::key_bits` already uses.
    pub key_bits: u32,
    /// SubjectPublicKeyInfo PEM of the key's public half. Safe to return
    /// over the API on read.
    pub public_key_pem: String,
    /// Engine-internal storage PEM of the private key. Never emitted over
    /// the API directly — only the `exported`-mode generate response and
    /// the import echo path can choose to surface a caller-facing PKCS#8
    /// form, and they go through [`Signer::to_pkcs8_pem`].
    pub private_key_pem: String,
    /// `true` when the operator chose `generate/exported` — meaning the
    /// engine returned the private key once at generation time. The
    /// engine still keeps a copy under the barrier so the key can be
    /// reused for renewal (L2). `false` for `generate/internal` and for
    /// imports.
    #[serde(default)]
    pub exported: bool,
    pub source: KeySource,
    pub created_at_unix: u64,
}

impl KeyEntry {
    pub fn algorithm(&self) -> Result<KeyAlgorithm, RvError> {
        KeyAlgorithm::from_role(&self.key_type, self.key_bits)
    }
}

/// Reference set tracked alongside a [`KeyEntry`]. Updated by future
/// phases when an issuer or a cert is bound to a managed key, and by
/// this module's `delete_key` to refuse deletion while non-empty.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyRefs {
    #[serde(default)]
    pub issuer_ids: BTreeSet<String>,
    #[serde(default)]
    pub cert_serials: BTreeSet<String>,
}

impl KeyRefs {
    pub fn is_empty(&self) -> bool {
        self.issuer_ids.is_empty() && self.cert_serials.is_empty()
    }
}

/// Create a managed-key entry mirroring an existing [`Signer`]'s
/// material. Used by [`super::issuers::add_issuer`] to produce a
/// shadow entry in the `pki/keys/*` store every time an issuer is
/// minted, so the operator sees the issuer's backing key in the GUI
/// Keys tab and can pin it via `key_ref` on subsequent issuance.
///
/// The shadow entry stores the *same* PKCS#8 / `BV PQC SIGNER` PEM
/// the issuer holds at `issuers/<id>/key`. That's a deliberate
/// duplicate of the private material, both copies barrier-encrypted.
/// We accept the storage cost for a single source of truth at the
/// API level; a future refactor can collapse the issuer's key
/// storage onto the managed-key entry directly.
///
/// `name` doesn't have to be unique — the caller decides whether to
/// disambiguate. The function returns the persisted entry so the
/// caller can pull `entry.id` out for binding records.
#[maybe_async::maybe_async]
pub async fn create_managed_key_from_signer(
    req: &Request,
    signer: &Signer,
    name: &str,
    source: KeySource,
) -> Result<KeyEntry, RvError> {
    if !name.is_empty() {
        ensure_name_free(req, name).await?;
    }
    persist_new_key(req, signer, name, false, source).await
}

/// Generate a fresh managed key under `alg`, persist it, and return the
/// stored [`KeyEntry`] alongside the [`Signer`] handle the caller can
/// use immediately (so `generate/exported` doesn't have to reload from
/// storage to emit the PKCS#8 PEM).
#[maybe_async::maybe_async]
pub async fn generate_managed_key(
    req: &Request,
    alg: KeyAlgorithm,
    name: &str,
    exported: bool,
) -> Result<(KeyEntry, Signer), RvError> {
    if !name.is_empty() {
        ensure_name_free(req, name).await?;
    }
    let signer = Signer::generate(alg)?;
    let entry = persist_new_key(req, &signer, name, exported, KeySource::Generated).await?;
    Ok((entry, signer))
}

/// Import an operator-supplied PEM and persist it as a managed key.
///
/// Accepts:
/// - PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) for RSA / ECDSA / Ed25519
///   and the IETF-lamps draft layout for ML-DSA seeds.
/// - The engine-internal `BV PQC SIGNER` envelope for ML-DSA (so an
///   operator who exported a key from another BastionVault mount can
///   re-import it without the lossy PKCS#8 round-trip).
///
/// Rejects RSA keys whose modulus is shorter than 2048 bits. Other
/// algorithms have no analogous "weak size" knob — EC curve choice is
/// already constrained by [`KeyAlgorithm::from_role`], Ed25519 is
/// fixed-size, ML-DSA carries its security level in the OID.
#[maybe_async::maybe_async]
pub async fn import_managed_key(
    req: &Request,
    pem: &str,
    name: &str,
) -> Result<(KeyEntry, Signer), RvError> {
    if !name.is_empty() {
        ensure_name_free(req, name).await?;
    }
    // RSA strength gate sits *before* the lenient `Signer::from_storage_pem`
    // path: that helper falls back to RSA-2048+SHA256 with only a warn for
    // non-standard modulus sizes, which would silently smuggle a 1024-bit
    // key into the store. Pre-check rejects sub-2048 RSA cleanly.
    reject_weak_rsa(pem.trim())?;
    let signer = Signer::from_storage_pem(pem.trim()).map_err(|e| {
        // Surface a helpful message — `from_storage_pem` returns
        // `ErrPkiKeyTypeInvalid` for both "not a PEM we recognise" and
        // "recognised but malformed". The operator sees one or the other.
        match e {
            RvError::ErrPkiKeyTypeInvalid => RvError::ErrString(
                "import_key: PEM did not parse as a supported private key format \
                 (PKCS#8 RSA / ECDSA / Ed25519, ML-DSA PKCS#8, or BV PQC envelope)"
                    .into(),
            ),
            other => other,
        }
    })?;

    let entry = persist_new_key(req, &signer, name, false, KeySource::Imported).await?;
    Ok((entry, signer))
}

/// List managed key ids stored under this mount.
#[maybe_async::maybe_async]
pub async fn list_keys(req: &Request) -> Result<Vec<String>, RvError> {
    req.storage_list("keys/").await
}

/// Resolve an operator-supplied reference (UUID or name) to the
/// underlying [`KeyEntry`]. Returns `Ok(None)` when neither prefix
/// matches.
#[maybe_async::maybe_async]
pub async fn load_key(req: &Request, reference: &str) -> Result<Option<KeyEntry>, RvError> {
    if reference.is_empty() {
        return Ok(None);
    }
    if let Some(entry) = read_key_by_id(req, reference).await? {
        return Ok(Some(entry));
    }
    let id = match read_name_pointer(req, reference).await? {
        Some(id) => id,
        None => return Ok(None),
    };
    read_key_by_id(req, &id).await
}

/// Read the reference set for a key by id. Returns the empty set when
/// no refs file exists yet, which is the normal state for a key that
/// hasn't been bound to an issuer or used to issue any cert.
#[maybe_async::maybe_async]
pub async fn load_refs(req: &Request, id: &str) -> Result<KeyRefs, RvError> {
    let refs: Option<KeyRefs> =
        super::storage::get_json(req, &refs_storage_key(id)).await?;
    Ok(refs.unwrap_or_default())
}

/// Append a cert-serial reference to the refs file for `key_id`. Used by
/// `pki/issue/:role` and `pki/sign/:role` (Phase L2) when a managed key
/// was pinned via `key_ref`, so `delete_key` can refuse while bindings
/// remain. Idempotent — re-recording the same serial is a no-op.
#[maybe_async::maybe_async]
pub async fn add_cert_ref(req: &Request, key_id: &str, serial_hex: &str) -> Result<(), RvError> {
    let mut refs = load_refs(req, key_id).await?;
    if refs.cert_serials.insert(serial_hex.to_string()) {
        super::storage::put_json(req, &refs_storage_key(key_id), &refs).await?;
    }
    Ok(())
}

/// Remove a cert-serial reference from the refs file for `key_id`. Used
/// by `pki/revoke` (Phase L3) so a managed key can be deleted once all
/// the certs it bound have been revoked. Idempotent — removing an
/// absent serial is a no-op.
#[maybe_async::maybe_async]
pub async fn remove_cert_ref(req: &Request, key_id: &str, serial_hex: &str) -> Result<(), RvError> {
    let mut refs = load_refs(req, key_id).await?;
    if refs.cert_serials.remove(serial_hex) {
        super::storage::put_json(req, &refs_storage_key(key_id), &refs).await?;
    }
    Ok(())
}

/// Bind an issuer to a managed key (Phase L3). Recorded so
/// `delete_key` can refuse while any issuer is still using the key, and
/// so an operator can audit which issuers depend on which managed keys.
#[maybe_async::maybe_async]
pub async fn add_issuer_ref(req: &Request, key_id: &str, issuer_id: &str) -> Result<(), RvError> {
    let mut refs = load_refs(req, key_id).await?;
    if refs.issuer_ids.insert(issuer_id.to_string()) {
        super::storage::put_json(req, &refs_storage_key(key_id), &refs).await?;
    }
    Ok(())
}

/// Decode `entry.public_key_pem` (a `PUBLIC KEY` PEM block) back to its
/// SubjectPublicKeyInfo DER. Used by `pki/sign/:role` to assert that a
/// CSR's SPKI matches the pinned managed key.
pub fn entry_spki_der(entry: &KeyEntry) -> Result<Vec<u8>, RvError> {
    let parsed = pem::parse(entry.public_key_pem.as_bytes()).map_err(|_| {
        RvError::ErrString("managed-key entry has malformed public_key_pem".into())
    })?;
    if parsed.tag() != "PUBLIC KEY" {
        return Err(RvError::ErrString(format!(
            "managed-key entry: expected `PUBLIC KEY` PEM block, got `{}`",
            parsed.tag()
        )));
    }
    Ok(parsed.contents().to_vec())
}

/// Delete a managed key by id (or name). Refuses if the refs file
/// records any active issuer or unexpired cert binding to this key —
/// the operator must rotate or revoke first.
#[maybe_async::maybe_async]
pub async fn delete_key(req: &Request, reference: &str) -> Result<(), RvError> {
    delete_key_inner(req, reference, false).await
}

/// Force-delete a managed key, ignoring outstanding *cert* bindings.
///
/// Since the legacy `issuers/<id>/key` migration shim
/// (see [`super::issuers::load_issuer`]) deletes the issuer's own
/// private-key copy after mirroring it into the managed-key store,
/// the managed-key entry is the **only** copy of the issuer's signing
/// material on a migrated mount. Force-deleting a key that still
/// backs an issuer would silently brick that issuer (no revoke, no
/// CRL rebuild, no further issuance). To preserve operational
/// safety, `force_delete_key` continues to **refuse** when
/// `KeyRefs.issuer_ids` is non-empty — the operator must remove the
/// referring issuers first via `DELETE pki/issuer/<ref>`. Force only
/// bypasses cert-level bindings; cert records keep working after the
/// binding is dropped because cert reads are independent of the
/// signing key.
#[maybe_async::maybe_async]
pub async fn force_delete_key(req: &Request, reference: &str) -> Result<(), RvError> {
    delete_key_inner(req, reference, true).await
}

#[maybe_async::maybe_async]
async fn delete_key_inner(req: &Request, reference: &str, force: bool) -> Result<(), RvError> {
    let entry = load_key(req, reference).await?.ok_or_else(|| {
        RvError::ErrString(format!("delete_key: no managed key found for `{reference}`"))
    })?;
    let refs = load_refs(req, &entry.id).await?;
    // Issuer bindings always block: the managed-key entry is the live
    // signing material for the bound issuer(s) once the legacy
    // shim has run. Dropping it here would brick those issuers — refuse
    // even under `force=true`. Cert bindings are softer: the cert
    // records survive the binding being dropped, so `force` is allowed
    // to clear them.
    if !refs.issuer_ids.is_empty() {
        let mut ids: Vec<&str> = refs.issuer_ids.iter().map(|s| s.as_str()).collect();
        ids.sort_unstable();
        return Err(RvError::ErrString(format!(
            "delete_key: key `{}` still backs issuer(s) [{}]; remove those issuers first via \
             DELETE pki/issuer/<ref> before deleting the key",
            entry.id,
            ids.join(", ")
        )));
    }
    if !refs.cert_serials.is_empty() && !force {
        return Err(RvError::ErrString(format!(
            "delete_key: key `{}` is bound to {} certificate(s); \
             revoke them first or pass force=true to drop the binding record",
            entry.id,
            refs.cert_serials.len()
        )));
    }
    if !entry.name.is_empty() {
        req.storage_delete(&name_pointer_key(&entry.name)).await?;
    }
    req.storage_delete(&refs_storage_key(&entry.id)).await?;
    req.storage_delete(&key_storage_key(&entry.id)).await?;
    Ok(())
}

// ────────────────────────── internals ──────────────────────────

#[maybe_async::maybe_async]
async fn read_key_by_id(req: &Request, id: &str) -> Result<Option<KeyEntry>, RvError> {
    super::storage::get_json::<KeyEntry>(req, &key_storage_key(id)).await
}

#[maybe_async::maybe_async]
async fn read_name_pointer(req: &Request, name: &str) -> Result<Option<String>, RvError> {
    super::storage::get_string(req, &name_pointer_key(name)).await
}

#[maybe_async::maybe_async]
async fn ensure_name_free(req: &Request, name: &str) -> Result<(), RvError> {
    if read_name_pointer(req, name).await?.is_some() {
        return Err(RvError::ErrPkiKeyNameAlreadyExist);
    }
    Ok(())
}

#[maybe_async::maybe_async]
async fn persist_new_key(
    req: &Request,
    signer: &Signer,
    name: &str,
    exported: bool,
    source: KeySource,
) -> Result<KeyEntry, RvError> {
    let id = Uuid::new_v4().to_string();
    let alg = signer.algorithm();
    let public_key_pem = match signer {
        Signer::Classical(cs) => cs.public_key_pem(),
        Signer::MlDsa(ml) => ml_dsa_public_pem(ml)?,
        #[cfg(feature = "pki_pqc_composite")]
        Signer::Composite(_) => {
            // Composite SPKI export is non-standard while the IETF draft
            // moves; fall back to the storage envelope so the public half
            // is at least round-trippable. Issuer-binding (L3) will
            // prefer composite-aware paths.
            signer.to_storage_pem()
        }
    };
    let entry = KeyEntry {
        id: id.clone(),
        name: name.to_string(),
        key_type: alg.as_str().to_string(),
        key_bits: alg.key_bits(),
        public_key_pem,
        private_key_pem: signer.to_storage_pem(),
        exported,
        source,
        created_at_unix: now_unix(),
    };

    super::storage::put_json(req, &key_storage_key(&id), &entry).await?;
    if !name.is_empty() {
        super::storage::put_string(req, &name_pointer_key(name), &id).await?;
    }
    // Initialise an empty refs file so future writers can read-modify-
    // write without a "key exists but refs missing" race.
    super::storage::put_json(req, &refs_storage_key(&id), &KeyRefs::default()).await?;
    Ok(entry)
}

fn ml_dsa_public_pem(signer: &MlDsaSigner) -> Result<String, RvError> {
    use x509_cert::der::{asn1::BitString, Encode};
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    // Build a `SubjectPublicKeyInfo` carrying the ML-DSA OID and the raw
    // public key bytes, then wrap the DER in a `PUBLIC KEY` PEM block.
    // The OID table is the one that already lives in [`super::pqc`].
    let alg_id = AlgorithmIdentifierOwned { oid: signer.level().oid(), parameters: None };
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: alg_id,
        subject_public_key: BitString::from_bytes(signer.public_key())
            .map_err(|_| RvError::ErrPkiInternal)?,
    };
    let der = spki.to_der().map_err(|_| RvError::ErrPkiInternal)?;
    Ok(pem::encode(&pem::Pem::new("PUBLIC KEY", der)))
}

/// Reject RSA private keys with a modulus shorter than 2048 bits before
/// they can reach the lenient `Signer::from_storage_pem` path. Non-RSA
/// PEMs (or unparseable input) are passed through — the regular signer
/// path will produce a clear error for those.
fn reject_weak_rsa(pem: &str) -> Result<(), RvError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    // Try every shape an operator might bring: PKCS#8 PEM, PKCS#1 PEM
    // (`-----BEGIN RSA PRIVATE KEY-----`), and PKCS#1 DER under a
    // PKCS#8 label (XCA xca-import wraps every decrypted blob as
    // PRIVATE KEY regardless of inner format). Whichever parses
    // first wins; modulus is identical across all three.
    let priv_key = if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(pem) {
        k
    } else if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(pem) {
        k
    } else if let Ok(parsed) = pem::parse(pem.trim()) {
        match RsaPrivateKey::from_pkcs1_der(parsed.contents()) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        }
    } else {
        return Ok(());
    };
    let bits = priv_key.size() * 8;
    if bits < 2048 {
        return Err(RvError::ErrString(format!(
            "import_key: RSA modulus is {bits} bits; minimum accepted is 2048"
        )));
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
