//! `pki/cert/<serial>/export` and `pki/issuer/<ref>/export`.
//!
//! Two destination formats today: PEM bundle and PKCS#7. Both encode
//! the cert + chain; PEM additionally supports inlining the bound
//! managed key when the operator asks for it AND the key was minted
//! `exportable=true` AND the caller's policy permits the export path.
//!
//! Export gating layers (in order of evaluation):
//!
//! 1. Policy ACL on the path (handled by Vault's ACL layer before the
//!    handler runs — see `docs/policies/pki-*.hcl` for the sample
//!    role definitions).
//! 2. `KeyEntry.exportable` — pinned at create / import time and
//!    *read-only*. Even root cannot flip it. The single override is
//!    `mode=backup`, which bypasses the flag but forces the response
//!    payload to be encrypted at the format level (PKCS#12 only,
//!    follow-up PR — for now `mode=backup` is rejected with PEM /
//!    PKCS#7 because they're plaintext).
//! 3. Issuer rule — `pki/issuer/<ref>/export` *never* emits the
//!    private key, regardless of `exportable` or `mode`. The API
//!    just doesn't accept `include_private_key` here.
//!
//! Mode `mode=backup` semantics:
//!   * Bypasses `KeyEntry.exportable=false` (so an operator running a
//!     vault-wide backup can save an encrypted copy of every key,
//!     including non-exportable ones).
//!   * Refuses any `format` that doesn't carry encryption — today
//!     only PKCS#12 qualifies, so PEM / PKCS#7 reject `mode=backup`.
//!     Until PKCS#12 lands, `mode=backup` is wired but always errors;
//!     the route shape stays stable so the GUI doesn't break on the
//!     follow-up.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use base64::Engine as _;

use super::{
    export::{build_pkcs12, pem_bundle, pkcs7_certs_only, ExportBundle, ExportFormat},
    issuers, keys, storage, PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn cert_export_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"cert/(?P<serial>[0-9a-fA-F:\-]+)/export$",
            fields: {
                "serial": { field_type: FieldType::Str, required: true, description: "Hex serial number of the cert (with or without colons)." },
                "format": { field_type: FieldType::Str, default: "pem", description: "`pem` (default) | `pkcs7` | `pkcs12`." },
                "include_private_key": { field_type: FieldType::Bool, default: false, description: "Include the bound managed key in the response. Only honoured when (a) the cert has a bound managed key, (b) the key was minted with `exportable=true`, and (c) `format` carries the key (PEM and PKCS#12 only — PKCS#7 has no key slot)." },
                "mode": { field_type: FieldType::Str, default: "normal", description: "`normal` (default) honours the per-key `exportable` flag. `backup` bypasses the flag but requires an encrypted format (PKCS#12)." },
                "password": { field_type: FieldType::Str, default: "", description: "PKCS#12 envelope password. Required when `format=pkcs12` (also serves as the file's encryption key on import)." }
            },
            operations: [{op: Operation::Read, handler: r.export_cert}],
            help: "Export a leaf certificate (and optionally its bound managed key) in PEM, PKCS#7, or PKCS#12 format."
        })
    }

    pub fn issuer_export_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"issuer/(?P<issuer_ref>[\w\-]+)/export$",
            fields: {
                "issuer_ref": { field_type: FieldType::Str, required: true, description: "Issuer ID (UUID) or name." },
                "format": { field_type: FieldType::Str, default: "pem", description: "`pem` (default) | `pkcs7` | `pkcs12`. PKCS#12 carries the cert + chain only (issuer keys are never exported on this route)." },
                "include_chain": { field_type: FieldType::Bool, default: true, description: "When true (default), include the issuer's parent chain in the output." },
                "password": { field_type: FieldType::Str, default: "", description: "PKCS#12 envelope password. Required when `format=pkcs12`." }
            },
            operations: [{op: Operation::Read, handler: r.export_issuer}],
            help: "Export the issuer certificate (public material). The private key is never included on this route — even with the right policy and even in backup mode."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn export_cert(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let serial = req
            .get_data("serial")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let serial_hex = serial
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();

        let format_str = req
            .get_data_or_default("format")?
            .as_str()
            .unwrap_or("pem")
            .to_string();
        let format = ExportFormat::parse(&format_str)?;

        let include_private_key = req
            .get_data_or_default("include_private_key")?
            .as_bool()
            .unwrap_or(false);

        let mode = req
            .get_data_or_default("mode")?
            .as_str()
            .unwrap_or("normal")
            .to_string();
        let backup_mode = match mode.as_str() {
            "" | "normal" => false,
            "backup" => true,
            other => {
                return Err(RvError::ErrString(format!(
                    "export: unknown mode `{other}` (accepted: normal, backup)"
                )));
            }
        };

        let password = req
            .get_data_or_default("password")?
            .as_str()
            .unwrap_or("")
            .to_string();

        // PKCS#7 doesn't carry private keys.
        if include_private_key && matches!(format, ExportFormat::Pkcs7) {
            return Err(RvError::ErrString(
                "export: PKCS#7 cannot carry a private key; pick format=pem or pkcs12"
                    .into(),
            ));
        }
        // PKCS#12 requires a password (it's the file's encryption key).
        if matches!(format, ExportFormat::Pkcs12) && password.is_empty() {
            return Err(RvError::ErrString(
                "export: PKCS#12 requires a password to encrypt the bag".into(),
            ));
        }
        // Backup mode bypasses the per-key `exportable` flag, but only
        // for encrypted formats — i.e. PKCS#12. PEM / PKCS#7 plaintext
        // would defeat the point of the read-only flag.
        if backup_mode && !matches!(format, ExportFormat::Pkcs12) {
            return Err(RvError::ErrString(
                "export: mode=backup requires an encrypted format (PKCS#12)"
                    .into(),
            ));
        }

        // Cert lookup — error cleanly when the serial doesn't exist.
        let record: storage::CertRecord = storage::get_json(
            req,
            &storage::cert_storage_key(&serial_hex),
        )
        .await?
        .ok_or_else(|| {
            RvError::ErrString(format!(
                "export: no cert at serial `{serial_hex}`"
            ))
        })?;

        // Build the issuer chain when we can. Chain construction
        // requires a known issuer; orphan certs (imported via
        // `pki/certs/import` or `csr/set-signed`) skip this step.
        let chain_pems = build_chain_for_record(req, &record).await?;

        // Resolve the bound managed key when the caller asked for it.
        // Three preconditions in order:
        //   (1) record has a bound key_id (legacy / orphan certs may not),
        //   (2) the key entry exists,
        //   (3) `entry.exportable == true` (or `backup_mode`, which we
        //       already rejected above for PEM, so unreachable today).
        let private_key_pem: Option<String> = if include_private_key {
            if record.key_id.is_empty() {
                return Err(RvError::ErrString(
                    "export: cert has no bound managed key — re-issue with \
                     `key_ref` (Phase L2) or import a fresh cert+key bundle"
                        .into(),
                ));
            }
            let entry = keys::load_key(req, &record.key_id).await?.ok_or_else(|| {
                RvError::ErrString(format!(
                    "export: bound managed key `{}` is missing",
                    record.key_id
                ))
            })?;
            if !entry.exportable && !backup_mode {
                return Err(RvError::ErrString(
                    "export: bound managed key was minted with `exportable=false`; \
                     this is read-only and cannot be flipped. Use `mode=backup` for \
                     an encrypted backup envelope, or re-issue with a key minted \
                     `exportable=true`."
                        .into(),
                ));
            }
            // Re-emit through the signer so the on-wire form is the
            // standard caller-facing PKCS#8 PEM (the storage envelope
            // is engine-internal — see `Signer::to_storage_pem`).
            let signer = super::crypto::Signer::from_storage_pem(&entry.private_key_pem)?;
            Some(signer.to_pkcs8_pem()?.to_string())
        } else {
            None
        };

        let bundle = match format {
            ExportFormat::Pem => pem_bundle(
                &record.certificate_pem,
                &chain_pems,
                private_key_pem.as_deref(),
            ),
            ExportFormat::Pkcs7 => {
                pkcs7_certs_only(&record.certificate_pem, &chain_pems)?
            }
            ExportFormat::Pkcs12 => build_pkcs12(
                &record.certificate_pem,
                &chain_pems,
                private_key_pem.as_deref(),
                &password,
            )?,
        };

        Ok(Some(Response::data_response(Some(bundle_to_data(
            &bundle,
            &serial_hex,
            include_private_key,
            backup_mode,
        )))))
    }

    pub async fn export_issuer(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let issuer_ref = req
            .get_data("issuer_ref")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();

        let format_str = req
            .get_data_or_default("format")?
            .as_str()
            .unwrap_or("pem")
            .to_string();
        let format = ExportFormat::parse(&format_str)?;

        let include_chain = req
            .get_data_or_default("include_chain")?
            .as_bool()
            .unwrap_or(true);

        let password = req
            .get_data_or_default("password")?
            .as_str()
            .unwrap_or("")
            .to_string();
        if matches!(format, ExportFormat::Pkcs12) && password.is_empty() {
            return Err(RvError::ErrString(
                "export: PKCS#12 requires a password to encrypt the bag".into(),
            ));
        }

        let issuer = issuers::load_issuer(req, &issuer_ref).await?;

        let chain_pems: Vec<String> = if include_chain {
            issuers::build_issuer_chain(req, &issuer).await?
        } else {
            Vec::new()
        };

        // Issuer route never emits the private key, regardless of
        // body params or mode. The API just doesn't accept those
        // knobs here (see `issuer_export_path` field set), and the
        // PKCS#12 path is forced through with `private_key_pem=None`.
        let bundle = match format {
            ExportFormat::Pem => pem_bundle(&issuer.cert_pem, &chain_pems, None),
            ExportFormat::Pkcs7 => {
                pkcs7_certs_only(&issuer.cert_pem, &chain_pems)?
            }
            ExportFormat::Pkcs12 => {
                build_pkcs12(&issuer.cert_pem, &chain_pems, None, &password)?
            }
        };

        let mut data: Map<String, Value> = Map::new();
        data.insert("issuer_id".into(), json!(issuer.id));
        data.insert("issuer_name".into(), json!(issuer.name));
        data.insert("format".into(), json!(format_label(&bundle)));
        data.insert("filename_extension".into(), json!(bundle.extension));
        data.insert("body".into(), json!(encode_body(&bundle)));
        data.insert("body_encoding".into(), json!(body_encoding(&bundle)));
        data.insert("includes_private_key".into(), json!(false));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Choose the wire encoding for the export body based on the format.
/// Text formats (PEM, PEM-armored PKCS#7) ship as UTF-8; PKCS#12 is
/// raw DER bytes and must be base64'd to fit the JSON response.
fn encode_body(bundle: &ExportBundle) -> String {
    if bundle.format.is_binary() {
        base64::engine::general_purpose::STANDARD.encode(&bundle.body)
    } else {
        String::from_utf8_lossy(&bundle.body).into_owned()
    }
}

fn body_encoding(bundle: &ExportBundle) -> &'static str {
    if bundle.format.is_binary() {
        "base64"
    } else {
        "utf8"
    }
}

#[maybe_async::maybe_async]
async fn build_chain_for_record(
    req: &Request,
    record: &storage::CertRecord,
) -> Result<Vec<String>, RvError> {
    if record.is_orphaned || record.issuer_id.is_empty() {
        return Ok(Vec::new());
    }
    // Try to load the named issuer. If it's gone (deleted between
    // issuance and export, edge case but possible), we fall back to
    // an empty chain rather than refusing the export entirely —
    // the leaf cert itself is still useful.
    match issuers::load_issuer(req, &record.issuer_id).await {
        Ok(handle) => issuers::build_issuer_chain(req, &handle).await,
        Err(_) => Ok(Vec::new()),
    }
}

fn bundle_to_data(
    bundle: &ExportBundle,
    serial_hex: &str,
    include_private_key: bool,
    backup_mode: bool,
) -> Map<String, Value> {
    let mut data: Map<String, Value> = Map::new();
    data.insert("serial_number".into(), json!(serial_hex));
    data.insert("format".into(), json!(format_label(bundle)));
    data.insert("filename_extension".into(), json!(bundle.extension));
    data.insert("body".into(), json!(encode_body(bundle)));
    data.insert("body_encoding".into(), json!(body_encoding(bundle)));
    data.insert("includes_private_key".into(), json!(include_private_key));
    data.insert("backup_mode".into(), json!(backup_mode));
    data
}

fn format_label(bundle: &ExportBundle) -> &'static str {
    match bundle.format {
        ExportFormat::Pem => "pem",
        ExportFormat::Pkcs7 => "pkcs7",
        ExportFormat::Pkcs12 => "pkcs12",
    }
}

#[allow(dead_code)]
fn _ctx_keep_alive(_c: Arc<Context>) {}
