//! `pki/issue/:role` — generate a fresh keypair and issue a leaf cert.
//!
//! `pki/sign/:role` and `pki/sign-verbatim` live here too, but only as
//! request adapters: the decisions and the certificate building both sit in
//! [`super::sign_flow`], so the inbound sign-request queue's dry run
//! ([`super::path_sign_request`]) evaluates the identical code rather than a
//! copy of it.

use std::{collections::HashMap, sync::Arc, time::Duration};

use humantime::parse_duration;
use serde_json::{json, Map, Value};

use super::{
    crypto::{AlgorithmClass, KeyAlgorithm, Signer},
    keys::{self, KeyEntry},
    path_roles::RoleEntry,
    sign_flow::{SignArgs, SignMode, SignPlan},
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
                "key_ref": { field_type: FieldType::Str, default: "", description: "Managed key ID or name to pin (Phase L2). Requires role.allow_key_reuse=true." },
                "upn_sans": { field_type: FieldType::Str, default: "", description: "Comma-separated UPNs emitted as otherName SANs for AD smart-card logon. Requires role.allow_upn_sans=true." },
                "email_sans": { field_type: FieldType::Str, default: "", description: "Comma-separated email addresses emitted as rfc822Name SANs (S/MIME). Requires role.allow_email_sans=true." },
                "ad_sid": { field_type: FieldType::Str, default: "", description: "AD account SID for the strong-mapping extension (KB5014754). Empty = role default. Requires role.allow_ad_sid=true." }
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
                "key_ref": { field_type: FieldType::Str, default: "", description: "Managed key ID or name the CSR's SPKI must match (Phase L2). Requires role.allow_key_reuse=true." },
                "upn_sans": { field_type: FieldType::Str, default: "", description: "Comma-separated UPNs emitted as otherName SANs for AD smart-card logon. Requires role.allow_upn_sans=true." },
                "email_sans": { field_type: FieldType::Str, default: "", description: "rfc822Name SAN override, for roles with use_csr_sans=false. Requires role.allow_email_sans=true." },
                "ad_sid": { field_type: FieldType::Str, default: "", description: "AD account SID for the strong-mapping extension (KB5014754). Empty = role default. Requires role.allow_ad_sid=true." }
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
        let ca_signer = super::issuers::take_signer(issuer.signer, &issuer.name)?;
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

        let (upn_sans, ad_sid) = resolve_ad_smartcard_input(req, &role)?;
        // S/MIME rfc822Name SANs. Closed by default and refused loudly
        // rather than dropped, same as the AD knobs above.
        let email_raw = req.get_data_or_default("email_sans")?.as_str().unwrap_or("").to_string();
        let email_sans = super::email_san::resolve_email_sans(&role, &email_raw)?;
        let urls = load_issuance_urls(req).await?;
        let subject =
            SubjectInput { common_name, alt_names: alt_dns, ip_sans: alt_ips, upn_sans, email_sans, ad_sid };
        let (cert_pem, serial_bytes) = match (role_alg.class(), &ca_signer, &leaf_signer) {
            (AlgorithmClass::Classical, Signer::Classical(ca), Signer::Classical(leaf)) => {
                let (cert, serial) = x509::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem, &urls)?;
                (cert.pem(), serial)
            }
            (AlgorithmClass::Pqc, Signer::MlDsa(ca), Signer::MlDsa(leaf)) => {
                x509_pqc::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem, &urls)?
            }
            #[cfg(feature = "pki_pqc_composite")]
            (AlgorithmClass::Composite, Signer::Composite(ca), Signer::Composite(leaf)) => {
                super::x509_composite::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem, &urls)?
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
        let args = sign_args_from_request(req)?;
        let plan = self.plan_sign(req, &SignMode::Role(role_name), &args).await?;
        self.sign_response(req, plan).await
    }

    /// `pki/sign-verbatim` — sign the CSR's subject and SANs as-is, no role
    /// constraints. Useful for service-mesh control planes that have already
    /// authorised the request out-of-band. The TTL still gets clamped to
    /// the engine's max so a runaway request can't issue a 100-year cert.
    pub async fn sign_csr_verbatim(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let args = sign_args_from_request(req)?;
        let plan = self.plan_sign(req, &SignMode::Verbatim, &args).await?;
        self.sign_response(req, plan).await
    }

    /// Execute a plan and shape the `certificate` / `issuing_ca` /
    /// `ca_chain` / `serial_number` / `issuer_id` response every signing
    /// path has returned since Phase 5.
    async fn sign_response(
        &self,
        req: &Request,
        plan: SignPlan,
    ) -> Result<Option<Response>, RvError> {
        for warning in &plan.warnings {
            log::debug!("pki/sign: {warning}");
        }
        let outcome = self.execute_sign(req, plan).await?;
        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(outcome.certificate));
        data.insert("issuing_ca".into(), json!(outcome.issuing_ca));
        data.insert("ca_chain".into(), json!(outcome.ca_chain));
        data.insert("serial_number".into(), json!(outcome.serial_hex));
        data.insert("issuer_id".into(), json!(outcome.issuer_id));
        if !outcome.key_id.is_empty() {
            data.insert("key_id".into(), json!(outcome.key_id));
        }
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
pub(crate) async fn resolve_pinned_key(
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

/// Load the mount's `config/urls` and project it into the subset the
/// certificate builders embed.
///
/// Returns the default (empty) value when the mount never configured
/// URLs, so certificates are unchanged for every deployment that hasn't
/// opted in. AD smart-card logon wants a reachable CDP so the domain
/// controller has a revocation source for the logon certificate.
#[maybe_async::maybe_async]
pub(crate) async fn load_issuance_urls(req: &Request) -> Result<x509::IssuanceUrls, RvError> {
    let cfg: storage::UrlsConfig =
        storage::get_json(req, storage::KEY_CONFIG_URLS).await?.unwrap_or_default();
    Ok(x509::IssuanceUrls {
        crl_distribution_points: cfg
            .crl_distribution_points
            .into_iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect(),
    })
}

/// Resolve the AD smart-card knobs (`upn_sans`, `ad_sid`) for one
/// issue/sign request against the role's policy.
///
/// Both are closed by default and fail loudly rather than silently
/// dropping: if a caller asks for a UPN SAN on a role that doesn't permit
/// one, they get an error instead of a certificate that looks fine but
/// will never authenticate against AD.
///
/// `ad_sid` resolution order is request body > role default > absent.
fn resolve_ad_smartcard_input(
    req: &Request,
    role: &RoleEntry,
) -> Result<(Vec<String>, Option<String>), RvError> {
    let upn_raw = req.get_data_or_default("upn_sans")?.as_str().unwrap_or("").to_string();
    let sid_raw = req.get_data_or_default("ad_sid")?.as_str().unwrap_or("").to_string();
    resolve_ad_smartcard(role, &upn_raw, &sid_raw)
}

/// The body of [`resolve_ad_smartcard_input`], over plain strings, so the
/// inbound sign-request queue ([`super::path_sign_request`]) can apply the
/// identical policy to a body whose field names it owns.
pub(crate) fn resolve_ad_smartcard(
    role: &RoleEntry,
    upn_raw: &str,
    sid_raw: &str,
) -> Result<(Vec<String>, Option<String>), RvError> {
    let mut upn_sans: Vec<String> = Vec::new();
    for candidate in upn_raw.split(',') {
        let upn = candidate.trim();
        if upn.is_empty() {
            continue;
        }
        super::ad_ext::validate_upn(role, upn)?;
        if !upn_sans.iter().any(|existing| existing == upn) {
            upn_sans.push(upn.to_string());
        }
    }

    let requested_sid = sid_raw.trim().to_string();
    let sid_source = if !requested_sid.is_empty() {
        Some(requested_sid)
    } else if !role.ad_sid.trim().is_empty() {
        Some(role.ad_sid.trim().to_string())
    } else {
        None
    };
    let ad_sid = match sid_source {
        Some(sid) => {
            super::ad_ext::validate_ad_sid(role, &sid)?;
            Some(super::ad_ext::normalize_ad_sid(&sid))
        }
        None => None,
    };

    Ok((upn_sans, ad_sid))
}

fn parse_optional_ttl(req: &Request, key: &str) -> Result<Option<Duration>, RvError> {
    let v = req.get_data_or_default(key)?;
    let s = v.as_str().unwrap_or("");
    if s.is_empty() {
        return Ok(None);
    }
    parse_duration(s).map(Some).map_err(|_| RvError::ErrRequestFieldInvalid)
}

/// Collect the signing knobs from a request body into a [`SignArgs`].
///
/// Every field is optional here rather than at this layer's edge: the two
/// `sign` paths declare different subsets (`sign-verbatim` has no
/// `key_ref` / `common_name` / `alt_names` / AD fields), and
/// [`super::sign_flow`] is where "not accepted in this mode" is decided and
/// reported. A field the path does not declare reads as unset; a field
/// declared with the wrong JSON type still errors.
fn sign_args_from_request(req: &Request) -> Result<SignArgs, RvError> {
    Ok(SignArgs {
        csr: optional_str_field(req, "csr")?,
        common_name: optional_str_field(req, "common_name")?,
        alt_names: optional_str_field(req, "alt_names")?,
        ttl: optional_str_field(req, "ttl")?,
        issuer_ref: optional_str_field(req, "issuer_ref")?,
        key_ref: optional_str_field(req, "key_ref")?,
        upn_sans: optional_str_field(req, "upn_sans")?,
        email_sans: optional_str_field(req, "email_sans")?,
        ad_sid: optional_str_field(req, "ad_sid")?,
    })
}

fn optional_str_field(req: &Request, key: &str) -> Result<String, RvError> {
    match req.get_data_or_default(key) {
        Ok(v) => Ok(v.as_str().unwrap_or("").to_string()),
        // The matched path does not declare this field — unset, not an error.
        Err(RvError::ErrRequestNoDataField) => Ok(String::new()),
        Err(e) => Err(e),
    }
}
