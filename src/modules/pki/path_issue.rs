//! `pki/issue/:role` — generate a fresh keypair and issue a leaf cert.
//!
//! `pki/sign/:role` and `pki/sign-verbatim` are stubbed for Phase 1: CSR
//! parsing requires plumbing through `x509-parser` to reconstruct an `rcgen`
//! `PublicKey`, which lands in a follow-up so the Phase 1 surface stays
//! reviewable.

use std::{collections::HashMap, sync::Arc, time::Duration};

use humantime::parse_duration;
use serde_json::{json, Map, Value};

use super::{
    crypto::{AlgorithmClass, KeyAlgorithm, Signer},
    keys::{self, KeyEntry},
    path_roles::RoleEntry,
    storage::{self, CertRecord},
    x509::{self, SubjectInput},
    x509_pqc,
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn issue_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"issue/(?P<role>\w[\w-]*\w)",
            fields: {
                "role": { field_type: FieldType::Str, required: true, description: "Role name." },
                "common_name": { field_type: FieldType::Str, required: true, description: "Subject CN." },
                "alt_names": { field_type: FieldType::Str, default: "", description: "Comma-separated DNS / IP SANs." },
                "ip_sans": { field_type: FieldType::Str, default: "", description: "Comma-separated IP SANs." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to sign with; empty = role pin or mount default." },
                "key_ref": { field_type: FieldType::Str, default: "", description: "Managed key ID or name to pin (Phase L2). Requires role.allow_key_reuse=true." }
            },
            operations: [{op: Operation::Write, handler: r.issue_cert}],
            help: "Issue a certificate against the named role."
        })
    }

    pub fn sign_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign/(?P<role>\w[\w-]*\w)",
            fields: {
                "role": { field_type: FieldType::Str, required: true, description: "Role name." },
                "csr": { field_type: FieldType::Str, required: true, description: "PEM- or DER-encoded PKCS#10 CSR." },
                "common_name": { field_type: FieldType::Str, default: "", description: "Override CN if role.use_csr_common_name is false." },
                "alt_names": { field_type: FieldType::Str, default: "", description: "Override SANs if role.use_csr_sans is false." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to sign with; empty = role pin or mount default." },
                "key_ref": { field_type: FieldType::Str, default: "", description: "Managed key ID or name the CSR's SPKI must match (Phase L2). Requires role.allow_key_reuse=true." }
            },
            operations: [{op: Operation::Write, handler: r.sign_csr_role}],
            help: "Sign a CSR against the named role."
        })
    }

    pub fn sign_verbatim_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-verbatim$",
            fields: {
                "csr": { field_type: FieldType::Str, required: true, description: "PEM- or DER-encoded PKCS#10 CSR." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to sign with; empty = mount default." }
            },
            operations: [{op: Operation::Write, handler: r.sign_csr_verbatim}],
            help: "Sign a CSR using exactly the subject and SANs from the request."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn issue_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data("role")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let role = self.get_role(req, &role_name).await?
            .ok_or(RvError::ErrPkiRoleNotFound)?;

        let common_name = req.get_data("common_name")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        x509::validate_common_name(&role, &common_name)?;

        let alt_str = req.get_data_or_default("alt_names")?.as_str().unwrap_or("").to_string();
        let (mut alt_dns, mut alt_ips) = x509::split_alt_names(&alt_str);
        let ip_str = req.get_data_or_default("ip_sans")?.as_str().unwrap_or("").to_string();
        let (extra_dns, extra_ips) = x509::split_alt_names(&ip_str);
        alt_dns.extend(extra_dns);
        alt_ips.extend(extra_ips);
        if !role.allow_ip_sans && !alt_ips.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }
        // Phase L4: validate every DNS SAN against the same emission
        // policy as the CN.
        for dns in &alt_dns {
            x509::validate_dns_name(&role, dns)?;
        }

        let requested_ttl = parse_optional_ttl(req, "ttl")?;
        let mut ttl = role.effective_ttl(requested_ttl);

        // Phase 5.2: pick the issuer to sign with, in this priority order:
        //   1. `issuer_ref` from the request body (operator override),
        //   2. `role.issuer_ref` (role-level pin),
        //   3. mount default.
        let request_issuer_ref = req.get_data_or_default("issuer_ref")?.as_str().unwrap_or("").to_string();
        let issuer = if !request_issuer_ref.is_empty() {
            super::issuers::load_issuer(req, &request_issuer_ref).await?
        } else if !role.issuer_ref.is_empty() {
            super::issuers::load_issuer(req, &role.issuer_ref).await?
        } else {
            super::issuers::load_default_issuer(req).await?
        };
        // Phase 5.5: gate on the issuer's `usages.issuing_certificates`
        // bit so an issuer locked down to CRL-signing-only can't be
        // hijacked into issuing leaves.
        super::issuers::require_issuing(&issuer)?;
        // Phase L4: clamp leaf TTL to the issuer's remaining lifetime
        // so the resulting cert's NotAfter never exceeds the chain.
        let (clamped_ttl, _was_clamped) = super::issuers::clamp_ttl_to_issuer(&issuer, ttl)?;
        ttl = clamped_ttl;
        let ca_cert_pem = issuer.cert_pem.clone();
        // Phase L3: snapshot the chain for this issuer so the response
        // carries `ca_chain` consistently across `issue/sign/ACME`.
        let ca_chain = super::issuers::build_issuer_chain(req, &issuer).await?;
        let ca_signer = issuer.signer;
        let issuer_id = issuer.id.clone();

        let role_alg = role.algorithm()?;

        // Mixed-chain rejection (Phase 2). A PQC role must run on a PQC CA,
        // and a classical role must run on a classical CA. The spec exposes
        // an `--allow-mixed-chain` opt-in for migration scenarios; that knob
        // lands in a follow-up so the default-secure behaviour is shipped
        // first. Without it, the engine fails closed.
        if role_alg.class() != ca_signer.algorithm().class() {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }

        // Phase L2: optional `key_ref` pins the leaf to a managed key
        // from `pki/keys/*` so renewals can carry the same private key.
        // Default-secure: roles must opt in via `allow_key_reuse`, and an
        // optional `allowed_key_refs` allow-list narrows which managed
        // keys are acceptable. Empty `key_ref` falls through to the
        // legacy "generate fresh" path.
        let request_key_ref = req
            .get_data_or_default("key_ref")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();
        let pinned_key: Option<KeyEntry> = if request_key_ref.is_empty() {
            None
        } else {
            Some(resolve_pinned_key(req, &role, &request_key_ref, role_alg).await?)
        };
        let leaf_signer = match &pinned_key {
            Some(entry) => Signer::from_storage_pem(&entry.private_key_pem)?,
            None => Signer::generate(role_alg)?,
        };

        let subject = SubjectInput { common_name, alt_names: alt_dns, ip_sans: alt_ips };
        let (cert_pem, serial_bytes) = match (role_alg.class(), &ca_signer, &leaf_signer) {
            (AlgorithmClass::Classical, Signer::Classical(ca), Signer::Classical(leaf)) => {
                let (cert, serial) = x509::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem)?;
                (cert.pem(), serial)
            }
            (AlgorithmClass::Pqc, Signer::MlDsa(ca), Signer::MlDsa(leaf)) => {
                x509_pqc::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem)?
            }
            #[cfg(feature = "pki_pqc_composite")]
            (AlgorithmClass::Composite, Signer::Composite(ca), Signer::Composite(leaf)) => {
                super::x509_composite::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem)?
            }
            // Mixed cases were already screened above; this arm is here to
            // make the compiler happy without falling through silently.
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        // Return PKCS#8 to the caller (Phase 5.3). The leaf's private key
        // is *not* stored anywhere on the engine side — it lives only in
        // this response — so there's no storage-vs-API split here.
        let leaf_key_pem = leaf_signer.to_pkcs8_pem()?;

        let serial_hex = storage::serial_to_hex(&serial_bytes);

        // Persist the cert (unless the role opts out) so revoke can find it
        // and the CRL builder can include it.
        if !role.no_store {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Capture NotAfter so Phase 4's tidy sweep can identify expired
            // records without re-parsing the PEM. `ttl` came from the role +
            // request body and was already used to build the cert above, so
            // adding it to `now` reproduces the in-cert NotAfter to within a
            // millisecond — close enough for tidy decisions that include a
            // safety buffer.
            let not_after_unix = (now as i64).saturating_add(ttl.as_secs() as i64);
            let record = CertRecord {
                serial_hex: serial_hex.clone(),
                certificate_pem: cert_pem.clone(),
                issued_at_unix: now,
                revoked_at_unix: None,
                not_after_unix,
                issuer_id: issuer_id.clone(),
                is_orphaned: false,
                source: String::new(),
                key_id: pinned_key.as_ref().map(|e| e.id.clone()).unwrap_or_default(),
            };
            storage::put_json(req, &storage::cert_storage_key(&serial_hex), &record).await?;
        }

        // Phase L2: if the leaf was bound to a managed key, record the
        // issued serial in that key's refs file so `delete_key` can
        // refuse while bindings remain. Done after the cert record is
        // persisted so the engine never carries a "key references cert
        // X" link without a corresponding cert record.
        if let Some(entry) = &pinned_key {
            keys::add_cert_ref(req, &entry.id, &serial_hex).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(cert_pem));
        data.insert("issuing_ca".into(), json!(ca_cert_pem));
        data.insert("ca_chain".into(), json!(ca_chain));
        data.insert("private_key".into(), json!(leaf_key_pem));
        data.insert("private_key_type".into(), json!(role.algorithm()?.as_str()));
        data.insert("serial_number".into(), json!(serial_hex));
        data.insert("issuer_id".into(), json!(issuer_id));
        if let Some(entry) = &pinned_key {
            data.insert("key_id".into(), json!(entry.id));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `pki/sign/:role` — sign a client-supplied CSR, applying the role's
    /// constraints. Phase 5: supports classical CAs only. PQC and composite
    /// CAs reject CSR-based signing for now (the engine still generates
    /// PQC keypairs server-side via `pki/issue`).
    pub async fn sign_csr_role(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data("role")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let role = self.get_role(req, &role_name).await?.ok_or(RvError::ErrPkiRoleNotFound)?;

        let csr_input = req.get_data("csr")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let parsed = super::csr::parse_and_verify(&csr_input)?;

        // Phase L2: optional `key_ref` asserts the CSR's SPKI matches a
        // managed key on this mount. The cert content is unchanged by
        // pinning (the public key in the cert still comes from the CSR);
        // the assertion is what lets the engine record a managed-key
        // binding for the issued serial. Default-secure: roles must
        // opt in via `allow_key_reuse`.
        let request_key_ref = req
            .get_data_or_default("key_ref")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();
        let pinned_key: Option<KeyEntry> = if request_key_ref.is_empty() {
            None
        } else {
            let role_alg = role.algorithm()?;
            let entry = resolve_pinned_key(req, &role, &request_key_ref, role_alg).await?;
            let entry_spki = keys::entry_spki_der(&entry)?;
            if entry_spki != parsed.spki_der {
                return Err(RvError::ErrString(
                    "sign_csr: CSR SubjectPublicKeyInfo does not match the pinned managed key".into(),
                ));
            }
            Some(entry)
        };

        // Decide CN + SANs based on role policy. `use_csr_common_name` /
        // `use_csr_sans` are Vault-parity knobs that let an operator force
        // the values from the request body even when the CSR is signed by
        // someone the engine implicitly trusts (e.g. a Kubernetes node).
        let common_name = if role.use_csr_common_name {
            parsed.common_name.clone().unwrap_or_default()
        } else {
            req.get_data_or_default("common_name")?.as_str().unwrap_or("").to_string()
        };
        if common_name.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }
        x509::validate_common_name(&role, &common_name)?;

        let (mut alt_dns, mut alt_ips) = if role.use_csr_sans {
            (parsed.requested_dns_sans.clone(), parsed.requested_ip_sans.clone())
        } else {
            let alt_str = req.get_data_or_default("alt_names")?.as_str().unwrap_or("").to_string();
            x509::split_alt_names(&alt_str)
        };
        if !role.allow_ip_sans && !alt_ips.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }
        // Phase L4: validate every DNS SAN against the role policy. The
        // CN was already checked above. We dedupe the CN out of alt_dns
        // afterwards so a CN that survives validation is not re-checked.
        for dns in &alt_dns {
            x509::validate_dns_name(&role, dns)?;
        }
        // De-dup CN out of alt_dns (rcgen treats SAN list as authoritative).
        alt_dns.retain(|d| d != &common_name);
        // No-op kept to silence warnings if `alt_ips` ends up unused on a
        // future role with `allow_ip_sans = false` and no IPs.
        let _ = &mut alt_ips;

        let requested_ttl = parse_optional_ttl(req, "ttl")?;
        let mut ttl = role.effective_ttl(requested_ttl);

        // Same issuer-resolution priority as `issue_cert`:
        //   request body > role-level pin > mount default.
        let request_issuer_ref = req.get_data_or_default("issuer_ref")?.as_str().unwrap_or("").to_string();
        let issuer = if !request_issuer_ref.is_empty() {
            super::issuers::load_issuer(req, &request_issuer_ref).await?
        } else if !role.issuer_ref.is_empty() {
            super::issuers::load_issuer(req, &role.issuer_ref).await?
        } else {
            super::issuers::load_default_issuer(req).await?
        };
        super::issuers::require_issuing(&issuer)?;
        // Phase L4: clamp leaf TTL to the issuer's remaining lifetime.
        let (clamped_ttl, _was_clamped) = super::issuers::clamp_ttl_to_issuer(&issuer, ttl)?;
        ttl = clamped_ttl;
        let ca_cert_pem = issuer.cert_pem.clone();
        let ca_chain = super::issuers::build_issuer_chain(req, &issuer).await?;
        let ca_signer = issuer.signer;
        let issuer_id = issuer.id.clone();

        let subject =
            super::x509::SubjectInput { common_name: common_name.clone(), alt_names: alt_dns, ip_sans: alt_ips };

        // Dispatch on (CSR class, CA class). Mixed-chain rejection is the
        // same default-secure rule as Phase 2's `pki/issue`: a PQC CA can
        // only sign a PQC CSR, classical can only sign classical.
        use super::csr::CsrAlgClass;
        let (cert_pem, serial_bytes) = match (&parsed.algorithm_class, &ca_signer) {
            (CsrAlgClass::Classical, Signer::Classical(ca_classical)) => {
                let (cert, serial) = x509::build_leaf_from_spki(
                    &role, &subject, ttl, &parsed.spki_der, ca_classical, &ca_cert_pem,
                )?;
                (cert.pem(), serial)
            }
            (CsrAlgClass::MlDsa(level), Signer::MlDsa(ca_ml)) => {
                super::x509_pqc::build_leaf_from_pqc_spki(
                    &role,
                    &subject,
                    ttl,
                    &parsed.raw_public_key,
                    *level,
                    ca_ml,
                    &ca_cert_pem,
                )?
            }
            // Mixed CSR / CA classes — refuse to issue.
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        let serial_hex = storage::serial_to_hex(&serial_bytes);

        if !role.no_store {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let not_after_unix = (now as i64).saturating_add(ttl.as_secs() as i64);
            let record = CertRecord {
                serial_hex: serial_hex.clone(),
                certificate_pem: cert_pem.clone(),
                issued_at_unix: now,
                revoked_at_unix: None,
                not_after_unix,
                issuer_id: issuer_id.clone(),
                is_orphaned: false,
                source: String::new(),
                key_id: pinned_key.as_ref().map(|e| e.id.clone()).unwrap_or_default(),
            };
            storage::put_json(req, &storage::cert_storage_key(&serial_hex), &record).await?;
        }

        // Phase L2: record the binding when a managed key was pinned.
        if let Some(entry) = &pinned_key {
            keys::add_cert_ref(req, &entry.id, &serial_hex).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(cert_pem));
        data.insert("issuing_ca".into(), json!(ca_cert_pem));
        data.insert("ca_chain".into(), json!(ca_chain));
        data.insert("serial_number".into(), json!(serial_hex));
        data.insert("issuer_id".into(), json!(issuer_id));
        if let Some(entry) = &pinned_key {
            data.insert("key_id".into(), json!(entry.id));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `pki/sign-verbatim` — sign the CSR's subject and SANs as-is, no role
    /// constraints. Useful for service-mesh control planes that have already
    /// authorised the request out-of-band. The TTL still gets clamped to
    /// the engine's max so a runaway request can't issue a 100-year cert.
    pub async fn sign_csr_verbatim(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let csr_input = req.get_data("csr")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let parsed = super::csr::parse_and_verify(&csr_input)?;

        let common_name = parsed.common_name.clone().unwrap_or_default();
        if common_name.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }

        let requested_ttl = parse_optional_ttl(req, "ttl")?;
        // No role: cap at 30 days to match Vault's sign-verbatim default
        // ceiling. Operators who want longer should use `sign/:role`.
        let max = std::time::Duration::from_secs(30 * 24 * 3600);
        let mut ttl = match requested_ttl {
            Some(d) if !d.is_zero() => std::cmp::min(d, max),
            _ => max,
        };

        // sign-verbatim takes the same `issuer_ref` knob as sign/:role.
        let request_issuer_ref = req.get_data_or_default("issuer_ref")?.as_str().unwrap_or("").to_string();
        let issuer = if !request_issuer_ref.is_empty() {
            super::issuers::load_issuer(req, &request_issuer_ref).await?
        } else {
            super::issuers::load_default_issuer(req).await?
        };
        super::issuers::require_issuing(&issuer)?;
        // Phase L4: clamp TTL to issuer's remaining lifetime even on
        // sign-verbatim (no role gate, but the chain rule still holds).
        let (clamped_ttl, _was_clamped) = super::issuers::clamp_ttl_to_issuer(&issuer, ttl)?;
        ttl = clamped_ttl;
        let ca_cert_pem = issuer.cert_pem.clone();
        let ca_chain = super::issuers::build_issuer_chain(req, &issuer).await?;
        let ca_signer = issuer.signer;
        let issuer_id = issuer.id.clone();

        // Synthesize a permissive role: server+client EKUs, no CN
        // restrictions. The CSR-supplied SANs flow through unmodified.
        let role = super::path_roles::RoleEntry {
            ttl,
            max_ttl: ttl,
            not_before_duration: std::time::Duration::from_secs(30),
            key_type: "ec".to_string(),
            allow_any_name: true,
            allow_ip_sans: true,
            server_flag: true,
            client_flag: true,
            ..Default::default()
        };

        let mut alt_dns = parsed.requested_dns_sans.clone();
        alt_dns.retain(|d| d != &common_name);
        let subject = super::x509::SubjectInput {
            common_name: common_name.clone(),
            alt_names: alt_dns,
            ip_sans: parsed.requested_ip_sans.clone(),
        };

        // Same class-match dispatch as `sign_csr_role`. PQC CSR + PQC CA →
        // PQC builder; classical + classical → rcgen builder; mixed →
        // reject (default-secure). Phase 5.1 closes the gap that PQC roles
        // could `issue` but not sign a CSR.
        use super::csr::CsrAlgClass;
        let (cert_pem, serial_bytes) = match (&parsed.algorithm_class, &ca_signer) {
            (CsrAlgClass::Classical, Signer::Classical(ca_classical)) => {
                let (cert, serial) = x509::build_leaf_from_spki(
                    &role, &subject, ttl, &parsed.spki_der, ca_classical, &ca_cert_pem,
                )?;
                (cert.pem(), serial)
            }
            (CsrAlgClass::MlDsa(level), Signer::MlDsa(ca_ml)) => {
                super::x509_pqc::build_leaf_from_pqc_spki(
                    &role,
                    &subject,
                    ttl,
                    &parsed.raw_public_key,
                    *level,
                    ca_ml,
                    &ca_cert_pem,
                )?
            }
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        let serial_hex = storage::serial_to_hex(&serial_bytes);

        // sign-verbatim records get persisted unconditionally (Vault parity)
        // so they show up in revocation flows.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = CertRecord {
            serial_hex: serial_hex.clone(),
            certificate_pem: cert_pem.clone(),
            issued_at_unix: now,
            revoked_at_unix: None,
            not_after_unix: (now as i64).saturating_add(ttl.as_secs() as i64),
            issuer_id: issuer_id.clone(),
            is_orphaned: false,
            source: String::new(),
            key_id: String::new(),
        };
        storage::put_json(req, &storage::cert_storage_key(&serial_hex), &record).await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(cert_pem));
        data.insert("issuing_ca".into(), json!(ca_cert_pem));
        data.insert("ca_chain".into(), json!(ca_chain));
        data.insert("serial_number".into(), json!(serial_hex));
        data.insert("issuer_id".into(), json!(issuer_id));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Resolve and authorise an operator-supplied `key_ref` against the role
/// policy and the managed key store. Used by `pki/issue/:role` and
/// `pki/sign/:role` for Phase-L2 key reuse.
///
/// Errors:
/// - `ErrPkiKeyOperationInvalid` — role has `allow_key_reuse = false`
///   or the key isn't on the role's allow-list.
/// - `ErrPkiKeyTypeInvalid` — the managed key's algorithm doesn't match
///   the role's algorithm.
/// - `ErrString("...")` — the key reference doesn't resolve.
#[maybe_async::maybe_async]
async fn resolve_pinned_key(
    req: &Request,
    role: &RoleEntry,
    key_ref: &str,
    role_alg: KeyAlgorithm,
) -> Result<KeyEntry, RvError> {
    if !role.allow_key_reuse {
        return Err(RvError::ErrPkiKeyOperationInvalid);
    }
    let entry = keys::load_key(req, key_ref)
        .await?
        .ok_or_else(|| RvError::ErrString(format!(
            "key_ref `{key_ref}` does not resolve to a managed key on this mount"
        )))?;

    if !role.allowed_key_refs.is_empty() {
        // Match against either the resolved id or the user-supplied
        // alias; both are stable identifiers an operator might write
        // into the allow-list.
        let allowed = role.allowed_key_refs.iter().any(|allowed_ref| {
            allowed_ref == &entry.id
                || (!entry.name.is_empty() && allowed_ref == &entry.name)
        });
        if !allowed {
            return Err(RvError::ErrPkiKeyOperationInvalid);
        }
    }

    let entry_alg = entry.algorithm()?;
    if entry_alg != role_alg {
        return Err(RvError::ErrPkiKeyTypeInvalid);
    }
    Ok(entry)
}

fn parse_optional_ttl(req: &Request, key: &str) -> Result<Option<Duration>, RvError> {
    let v = req.get_data_or_default(key)?;
    let s = v.as_str().unwrap_or("");
    if s.is_empty() {
        return Ok(None);
    }
    parse_duration(s).map(Some).map_err(|_| RvError::ErrRequestFieldInvalid)
}
