//! `pki/config/{ca,urls,crl}`.
//!
//! `config/ca` (POST a CA cert + private key bundle) is exposed as a stub for
//! Phase 1 — the operator-facing flow today is `root/generate/internal`.
//! Lifecycle import lands with the intermediate / set-signed work in Phase 2.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};
use x509_cert::der::Decode;

use super::{
    crypto::Signer,
    storage::{self, CaKind, CaMetadata, CrlConfig, CrlState, UrlsConfig, KEY_CA_CERT, KEY_CA_KEY,
              KEY_CA_META, KEY_CONFIG_CRL, KEY_CONFIG_URLS, KEY_CRL_STATE},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn config_ca_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"config/ca$",
            fields: {
                "pem_bundle": { field_type: FieldType::Str, required: true,
                    description: "PEM bundle: a private key plus one or more CERTIFICATE blocks (the leaf-most cert is treated as the CA)." }
            },
            operations: [{op: Operation::Write, handler: r.import_config_ca}],
            help: "Import an externally-generated CA cert + private key bundle."
        })
    }

    pub fn config_urls_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"config/urls$",
            fields: {
                "issuing_certificates": { field_type: FieldType::CommaStringSlice, default: "", description: "AIA issuing-cert URLs." },
                "crl_distribution_points": { field_type: FieldType::CommaStringSlice, default: "", description: "CRL DP URLs." },
                "ocsp_servers": { field_type: FieldType::CommaStringSlice, default: "", description: "OCSP responder URLs." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_config_urls},
                {op: Operation::Write, handler: rw.write_config_urls}
            ],
            help: "Configure issuer URLs embedded in issued certs."
        })
    }

    pub fn config_crl_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"config/crl$",
            fields: {
                "expiry": { field_type: FieldType::Str, default: "72h", description: "CRL next_update window (e.g. 72h)." },
                "disable": { field_type: FieldType::Bool, default: false, description: "Disable CRL generation." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_config_crl},
                {op: Operation::Write, handler: rw.write_config_crl}
            ],
            help: "Configure CRL behaviour."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn read_config_urls(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg: UrlsConfig = storage::get_json(req, KEY_CONFIG_URLS).await?.unwrap_or_default();
        let data = serde_json::to_value(&cfg)?;
        Ok(Some(Response::data_response(data.as_object().cloned())))
    }

    pub async fn write_config_urls(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg = UrlsConfig {
            issuing_certificates: req.get_data_or_default("issuing_certificates")?
                .as_comma_string_slice().unwrap_or_default(),
            crl_distribution_points: req.get_data_or_default("crl_distribution_points")?
                .as_comma_string_slice().unwrap_or_default(),
            ocsp_servers: req.get_data_or_default("ocsp_servers")?
                .as_comma_string_slice().unwrap_or_default(),
        };
        storage::put_json(req, KEY_CONFIG_URLS, &cfg).await?;
        Ok(None)
    }

    pub async fn read_config_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg: CrlConfig = storage::get_json(req, KEY_CONFIG_CRL).await?.unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("expiry".into(), json!(format!("{}s", cfg.expiry_seconds)));
        data.insert("disable".into(), json!(cfg.disable));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_config_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let expiry_str = req.get_data_or_default("expiry")?.as_str().unwrap_or("72h").to_string();
        let expiry = humantime::parse_duration(&expiry_str).map_err(|_| RvError::ErrRequestFieldInvalid)?;
        let disable = req.get_data_or_default("disable")?.as_bool().unwrap_or(false);
        let cfg = CrlConfig { expiry_seconds: expiry.as_secs(), disable };
        storage::put_json(req, KEY_CONFIG_CRL, &cfg).await?;
        Ok(None)
    }

    /// `pki/config/ca` — import a CA bundle (private key + cert(s)) the
    /// operator generated externally (e.g. on an offline root). The bundle
    /// is a PEM concatenation; the engine takes the first CERTIFICATE block
    /// as the CA's own cert and the first PRIVATE KEY block as its key,
    /// validates that the cert's SubjectPublicKeyInfo matches the keypair,
    /// then installs both.
    pub async fn import_config_ca(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if storage::get_string(req, KEY_CA_CERT).await?.is_some() {
            // Refuse to silently clobber an existing CA. Operators who want
            // to rotate must explicitly delete the existing one first.
            return Err(RvError::ErrPkiCaNotConfig);
        }

        let bundle = req.get_data("pem_bundle")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let (cert_pem, key_pem) = split_pem_bundle(&bundle)?;

        // Round-trip the key through the unified Signer so we exercise the
        // same parser used by the rest of the engine. Today this only
        // accepts classical PKCS#8 — PQC import is a follow-up since the
        // PKCS#8 wrapping for ML-DSA seeds is not yet standardised.
        let signer = Signer::from_storage_pem(&key_pem)?;
        let Signer::Classical(classical) = &signer else {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        };

        // Validate: the cert's pubkey must match the imported keypair.
        let cert_der = super::csr::decode_pem_or_der(&cert_pem)?;
        let cert = x509_cert::Certificate::from_der(&cert_der)
            .map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let cert_pk_bits = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        use rcgen::PublicKeyData;
        if cert_pk_bits != classical.key_pair().der_bytes() {
            return Err(RvError::ErrPkiCertKeyMismatch);
        }

        // Persist + bootstrap CRL state.
        storage::put_string(req, KEY_CA_CERT, &cert_pem).await?;
        storage::put_string(req, KEY_CA_KEY, &signer.to_storage_pem()).await?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let serial_hex = storage::serial_to_hex(cert.tbs_certificate.serial_number.as_bytes());
        // The DN's `Display` impl renders `CN=foo,O=bar,...`; pluck CN out.
        let dn_str = cert.tbs_certificate.subject.to_string();
        let common_name = dn_str
            .split(',')
            .find_map(|piece| piece.trim().strip_prefix("CN=").map(|v| v.to_string()))
            .unwrap_or_default();
        storage::put_json(
            req,
            KEY_CA_META,
            &CaMetadata {
                key_type: classical.algorithm().as_str().to_string(),
                key_bits: classical.algorithm().key_bits(),
                common_name,
                serial_hex,
                created_at_unix: now,
                not_after_unix: cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64,
                ca_kind: CaKind::Imported,
            },
        )
        .await?;
        if storage::get_json::<CrlState>(req, KEY_CRL_STATE).await?.is_none() {
            storage::put_json(req, KEY_CRL_STATE, &CrlState::default()).await?;
        }
        if storage::get_json::<CrlConfig>(req, KEY_CONFIG_CRL).await?.is_none() {
            storage::put_json(req, KEY_CONFIG_CRL, &CrlConfig::default()).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("imported_issuers".into(), json!([]));
        data.insert("imported_keys".into(), json!([]));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Pull the first `CERTIFICATE` and the first `PRIVATE KEY`-flavoured PEM
/// block out of a bundle. We don't try to be clever about chains beyond the
/// first cert — Phase 5 single-issuer scope.
fn split_pem_bundle(bundle: &str) -> Result<(String, String), RvError> {
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut current_label: Option<String> = None;
    let mut current_buf = String::new();

    for line in bundle.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
            let label = rest.trim_end_matches('-').to_string();
            current_label = Some(label);
            current_buf.clear();
            current_buf.push_str(line);
            current_buf.push('\n');
            continue;
        }
        if trimmed.starts_with("-----END ") {
            current_buf.push_str(line);
            current_buf.push('\n');
            if let Some(label) = current_label.take() {
                if label == "CERTIFICATE" && cert.is_none() {
                    cert = Some(current_buf.clone());
                } else if (label.contains("PRIVATE KEY") || label == "BV PQC SIGNER") && key.is_none() {
                    key = Some(current_buf.clone());
                }
            }
            current_buf.clear();
            continue;
        }
        if current_label.is_some() {
            current_buf.push_str(line);
            current_buf.push('\n');
        }
    }

    match (cert, key) {
        (Some(c), Some(k)) => Ok((c, k)),
        _ => Err(RvError::ErrPkiPemBundleInvalid),
    }
}
