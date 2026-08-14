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
    storage::{self, CaKind, CrlConfig, UrlsConfig, KEY_CA_CERT, KEY_CA_KEY,
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
                    description: "PEM bundle: one or more CA CERTIFICATE blocks, optionally with a single private key. If a key is present, the certificate it matches becomes a signing issuer; every other CA cert is imported as a key-less (trust/chain) issuer. With no key, all CA certs import as key-less trust anchors." },
                "issuer_name": { field_type: FieldType::Str, default: "", description: "Name for the signing issuer (the cert matching the private key). Key-less chain certs are named from their CN. Empty = next-default-name." }
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

    /// `pki/config/ca` — import an externally-generated CA bundle.
    ///
    /// The bundle is a PEM concatenation of **one or more CA
    /// certificates** and an **optional** single private key:
    ///
    /// * If a key is present it must match exactly one certificate in the
    ///   bundle; that cert becomes a full **signing issuer** (backed by a
    ///   managed key). Every *other* CA cert imports as a **key-less**
    ///   issuer — a trust/chain anchor that resolves `ca_chain` but can't
    ///   sign. This is how an operator imports "intermediate + its root"
    ///   or "root + a cross-signed root" in one shot.
    /// * With **no key**, all CA certs import as key-less trust anchors.
    ///
    /// Certificate order in the paste is irrelevant — the key match (not
    /// position) decides the signing issuer, and the chain is resolved by
    /// Subject/Issuer DN at read time via `build_issuer_chain`. Non-CA
    /// (leaf) certs are rejected; those belong at `pki/certs/import`.
    /// Re-importing a cert already present at the mount (by serial) is a
    /// no-op skip, so a shared root pasted across imports doesn't collide.
    pub async fn import_config_ca(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let bundle = req.get_data("pem_bundle")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let requested_name = req.get_data_or_default("issuer_name")?.as_str().unwrap_or("").to_string();

        let (cert_pems, key_pem) = split_ca_bundle(&bundle)?;
        if cert_pems.is_empty() {
            return Err(RvError::ErrResponseStatus(
                400,
                "config/ca: no CERTIFICATE block found in the PEM bundle. Paste at least one \
                 CA certificate (and, to import a signing issuer, its private key)."
                    .into(),
            ));
        }

        // Parse every cert up front so a bad block fails fast with its
        // position, and so we know each cert's CA-ness, serial, CN and
        // public key before we mutate any storage.
        let mut certs: Vec<ParsedCaCert> = Vec::with_capacity(cert_pems.len());
        for (i, pem) in cert_pems.iter().enumerate() {
            certs.push(ParsedCaCert::parse(pem, i)?);
        }

        // Every cert in a `config/ca` import must be a CA. A leaf slipped
        // into the paste is almost always a mistake (a fullchain.pem with
        // the server cert on top); reject it with a pointer to the right
        // route rather than silently promoting or dropping it.
        for c in &certs {
            if !c.is_ca {
                return Err(RvError::ErrResponseStatus(
                    400,
                    format!(
                        "config/ca: certificate #{} ({}) is not a CA (BasicConstraints cA=true \
                         required). Remove leaf certs from the bundle; import them via pki/certs/import.",
                        c.index + 1,
                        c.describe()
                    ),
                ));
            }
        }

        // Resolve the private key (if any) to its owning cert. The match
        // — not paste order — decides which cert becomes the signing
        // issuer, so operators can paste chains in any order.
        let mut signer: Option<Signer> = None;
        let mut signing_idx: Option<usize> = None;
        if let Some(key_pem) = &key_pem {
            // Same parser the rest of the engine uses. Classical only for
            // now — PQC import is a follow-up (unstable PKCS#8 seed wrap).
            let parsed_signer = Signer::from_storage_pem(key_pem)?;
            let Signer::Classical(classical) = &parsed_signer else {
                return Err(RvError::ErrPkiKeyTypeInvalid);
            };
            use rcgen::PublicKeyData;
            let key_pub = classical.key_pair().der_bytes();
            signing_idx = certs.iter().position(|c| c.spki_raw == key_pub);
            if signing_idx.is_none() {
                return Err(RvError::ErrResponseStatus(
                    400,
                    "config/ca: the private key in the bundle does not match any certificate \
                     in it. Check you pasted the key that belongs to one of these CA certs."
                        .into(),
                ));
            }
            signer = Some(parsed_signer);
        }

        // Import each cert. Track names chosen this call so multiple
        // key-less certs from the same paste don't collide before their
        // index writes are visible to each other.
        let mut used_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut imported_issuers: Vec<String> = Vec::new();
        let mut imported_keys: Vec<String> = Vec::new();
        let mut chain_out: Vec<Value> = Vec::new();
        let mut primary: Option<(String, String)> = None;

        for c in &certs {
            let is_signing = Some(c.index) == signing_idx;

            // Idempotent skip: cert already at this mount (by serial).
            if let Some((id, name)) =
                super::issuers::find_issuer_by_serial(req, &c.serial_hex).await?
            {
                used_names.insert(name.clone());
                chain_out.push(c.chain_entry(&id, &name, is_signing, true));
                if is_signing {
                    primary = Some((id, name));
                }
                continue;
            }

            let name = self
                .choose_issuer_name(req, &requested_name, is_signing, c, &used_names)
                .await?;
            used_names.insert(name.clone());

            let id = if is_signing {
                // move the owned signer into `add_issuer` (borrowed there)
                let s = signer.take().expect("signing_idx implies a parsed signer");
                let id = super::issuers::add_issuer(
                    req,
                    &name,
                    &c.pem,
                    &s,
                    &c.common_name,
                    &c.serial_hex,
                    c.not_after_unix,
                    CaKind::Imported,
                    None,
                )
                .await?;
                imported_keys.push(id.clone());
                id
            } else {
                super::issuers::add_issuer_keyless(
                    req,
                    &name,
                    &c.pem,
                    &c.common_name,
                    &c.serial_hex,
                    c.not_after_unix,
                    CaKind::Imported,
                )
                .await?
            };

            imported_issuers.push(id.clone());
            chain_out.push(c.chain_entry(&id, &name, is_signing, false));
            if is_signing {
                primary = Some((id, name));
            }
        }

        if storage::get_json::<CrlConfig>(req, KEY_CONFIG_CRL).await?.is_none() {
            storage::put_json(req, KEY_CONFIG_CRL, &CrlConfig::default()).await?;
        }

        // The "primary" issuer for response purposes is the signing one
        // if we imported a key; otherwise the root (self-signed) cert, so
        // a certs-only trust import still reports a sensible anchor.
        let primary = primary.or_else(|| {
            chain_out
                .iter()
                .find(|e| e.get("self_signed").and_then(Value::as_bool).unwrap_or(false))
                .or_else(|| chain_out.first())
                .and_then(|e| {
                    Some((
                        e.get("issuer_id")?.as_str()?.to_string(),
                        e.get("issuer_name")?.as_str()?.to_string(),
                    ))
                })
        });

        let mut data: Map<String, Value> = Map::new();
        data.insert("imported_issuers".into(), json!(imported_issuers));
        data.insert("imported_keys".into(), json!(imported_keys));
        if let Some((id, name)) = &primary {
            data.insert("issuer_id".into(), json!(id));
            data.insert("issuer_name".into(), json!(name));
        }
        // Per-cert map so the GUI can render the imported hierarchy as a
        // tree (subject/issuer links) and annotate which node is the
        // signing issuer vs a key-less trust anchor.
        data.insert("chain".into(), json!(chain_out));
        let _ = (KEY_CA_CERT, KEY_CA_KEY, KEY_CA_META, KEY_CRL_STATE);
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Pick a unique issuer name for one cert in a `config/ca` import.
    /// The signing issuer honours the operator's `issuer_name` (or the
    /// mount's next-default when blank); key-less chain certs are named
    /// from their CN, slugified, with a numeric suffix on collision.
    async fn choose_issuer_name(
        &self,
        req: &mut Request,
        requested_name: &str,
        is_signing: bool,
        cert: &ParsedCaCert,
        used: &std::collections::BTreeSet<String>,
    ) -> Result<String, RvError> {
        let index = super::issuers::list_issuers(req).await?;
        let taken = |n: &str| index.name_to_id(n).is_some() || used.contains(n);

        if is_signing && !requested_name.is_empty() {
            // Honour the explicit request verbatim; add_issuer will still
            // reject it if it collides, surfacing a clear message.
            return Ok(requested_name.to_string());
        }

        let base = if is_signing {
            super::issuers::next_default_name(&index)
        } else {
            let slug = slugify_cn(&cert.common_name);
            if slug.is_empty() { "ca".to_string() } else { slug }
        };
        if !taken(&base) {
            return Ok(base);
        }
        // Disambiguate: try `<base>-<serial8>`, then `<base>-2`, `-3`, ...
        let short_serial: String = cert.serial_hex.chars().take(8).collect();
        let candidate = format!("{base}-{short_serial}");
        if !short_serial.is_empty() && !taken(&candidate) {
            return Ok(candidate);
        }
        for n in 2.. {
            let candidate = format!("{base}-{n}");
            if !taken(&candidate) {
                return Ok(candidate);
            }
        }
        unreachable!("counter search always terminates")
    }
}

/// A parsed CA certificate from a `config/ca` bundle, with the derived
/// facts the import handler needs to validate and register it.
struct ParsedCaCert {
    /// Position in the pasted bundle (0-based), for error messages.
    index: usize,
    /// Canonical single-block PEM for this cert.
    pem: String,
    /// Raw `subjectPublicKey` bits, for key↔cert matching.
    spki_raw: Vec<u8>,
    is_ca: bool,
    self_signed: bool,
    common_name: String,
    subject_dn: String,
    issuer_dn: String,
    serial_hex: String,
    not_after_unix: i64,
}

impl ParsedCaCert {
    fn parse(pem_block: &str, index: usize) -> Result<Self, RvError> {
        let cert_der = super::csr::decode_pem_or_der(pem_block)?;
        let cert = x509_cert::Certificate::from_der(&cert_der)
            .map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let spki_raw = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let subject_dn = cert.tbs_certificate.subject.to_string();
        let issuer_dn = cert.tbs_certificate.issuer.to_string();
        let common_name = subject_dn
            .split(',')
            .find_map(|piece| piece.trim().strip_prefix("CN=").map(|v| v.to_string()))
            .unwrap_or_default();
        let serial_hex = storage::serial_to_hex(cert.tbs_certificate.serial_number.as_bytes());
        let not_after_unix =
            cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64;
        Ok(ParsedCaCert {
            index,
            // Re-emit canonical PEM so downstream reads round-trip cleanly.
            pem: pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone())),
            spki_raw,
            is_ca: cert_claims_ca(pem_block),
            self_signed: subject_dn == issuer_dn,
            common_name,
            subject_dn,
            issuer_dn,
            serial_hex,
            not_after_unix,
        })
    }

    /// Human label for error messages: `CN=… ` when present, else the
    /// full subject DN, else the serial.
    fn describe(&self) -> String {
        if !self.common_name.is_empty() {
            format!("CN={}", self.common_name)
        } else if !self.subject_dn.is_empty() {
            self.subject_dn.clone()
        } else {
            format!("serial {}", self.serial_hex)
        }
    }

    fn chain_entry(&self, issuer_id: &str, issuer_name: &str, is_signing: bool, skipped: bool) -> Value {
        json!({
            "issuer_id": issuer_id,
            "issuer_name": issuer_name,
            "common_name": self.common_name,
            "subject": self.subject_dn,
            "issuer": self.issuer_dn,
            "serial": self.serial_hex,
            "self_signed": self.self_signed,
            "has_key": is_signing,
            "keyless": !is_signing,
            "skipped": skipped,
        })
    }
}

/// Turn a certificate CN into a storage-safe issuer name slug: lowercase,
/// non-alphanumeric runs collapsed to `-`, trimmed. The issuer name regex
/// is `[\w\-]+`, so this keeps names routable.
fn slugify_cn(cn: &str) -> String {
    let mut out = String::with_capacity(cn.len());
    let mut prev_dash = false;
    for ch in cn.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Split a `config/ca` bundle into **all** its `CERTIFICATE` blocks (in
/// paste order) and the **first** private-key block, if any. Unlike the
/// old single-cert splitter, this keeps every cert so chains and trust
/// bundles import whole; the caller decides which cert the key matches.
///
/// Returns `(cert_pems, key_pem)`. An empty cert list / absent key are
/// both valid here — the handler produces the actionable error, so a
/// caller can tell "no cert" from "no key" apart.
fn split_ca_bundle(bundle: &str) -> Result<(Vec<String>, Option<String>), RvError> {
    let mut certs: Vec<String> = Vec::new();
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
                if label == "CERTIFICATE" {
                    certs.push(current_buf.clone());
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

    Ok((certs, key))
}

/// Read the cert's `BasicConstraints` extension and return `true` when
/// `cA = true` is asserted. Used by `pki/config/ca` to refuse a leaf
/// cert masquerading as an issuer; an intermediate (signed by another
/// CA) passes this check the same way a self-signed root does, so the
/// engine accepts both shapes.
fn cert_claims_ca(cert_pem: &str) -> bool {
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::FromDer;
    let der = match pem::parse(cert_pem.as_bytes()) {
        Ok(p) => p.into_contents(),
        Err(_) => return false,
    };
    let parsed = match x509_parser::certificate::X509Certificate::from_der(&der) {
        Ok((_, p)) => p,
        Err(_) => return false,
    };
    for ext in parsed.tbs_certificate.extensions() {
        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            return bc.ca;
        }
    }
    false
}
