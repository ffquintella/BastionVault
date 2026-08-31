//! Shared decide-then-build pipeline behind every path that signs a
//! caller-supplied CSR: `pki/sign/:role`, `pki/sign-verbatim`, and the
//! inbound sign-request queue's `preflight` / `approve`
//! ([`super::path_sign_request`]).
//!
//! The split exists so a **dry run cannot drift from the real thing**.
//! [`PkiBackendInner::plan_sign`] performs every decision and every policy
//! check — role lookup, CN/SAN policy, IP-SAN gate, managed-key pin,
//! issuer resolution, the `issuing_certificates` usage bit, the TTL clamp
//! to the issuer's remaining lifetime, and the PQC/classical class match —
//! and touches no signing key. [`PkiBackendInner::execute_sign`] takes that
//! plan and mints the certificate.
//!
//! `preflight` runs `plan_sign` and reports; `approve` and the two
//! pre-existing `sign` paths run `plan_sign` then `execute_sign`. There is
//! exactly one implementation of "would this be allowed, and what would it
//! produce".
//!
//! Ordering note: the two `plan_*` functions deliberately reproduce the
//! order in which the pre-split handlers raised their errors (role lookup
//! before CSR parse on the role path, CSR parse first on verbatim), so an
//! existing client sees the same error for the same bad request.

use std::{net::IpAddr, time::Duration};

use humantime::parse_duration;

use super::{
    crypto::{KeyAlgorithm, Signer},
    csr::{self, CsrAlgClass, ParsedCsr},
    issuers::{self, IssuerHandle},
    keys::{self, KeyEntry},
    path_issue::{load_issuance_urls, resolve_ad_smartcard, resolve_pinned_key},
    path_roles::RoleEntry,
    storage::{self, CertRecord},
    x509::{self, SubjectInput},
    x509_pqc, PkiBackendInner,
};
use crate::{errors::RvError, logical::Request};

/// `pki/sign-verbatim`'s ceiling when the caller names no TTL. Matches
/// Vault's 30-day default for the role-less path.
const VERBATIM_MAX_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Which policy applies to this signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignMode {
    /// Sign under a named role: the role's domain policy, TTL bounds,
    /// KU/EKU set and locked DN fields all apply.
    Role(String),
    /// Take the subject and SANs exactly as the CSR states them. **No
    /// role policy applies** — no `allowed_domains`, no `allow_ip_sans`
    /// gate. Reachable only through paths the operator's policy grants.
    Verbatim,
}

impl SignMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Role(_) => "role",
            Self::Verbatim => "verbatim",
        }
    }

    pub fn role_name(&self) -> &str {
        match self {
            Self::Role(name) => name,
            Self::Verbatim => "",
        }
    }
}

/// Everything a caller may say about one signing request. Deliberately
/// plain data rather than a `&Request`: the inbound queue supplies the CSR
/// from storage and the rest from a body whose field names differ from
/// `pki/sign/:role`'s.
#[derive(Debug, Clone, Default)]
pub struct SignArgs {
    pub csr: String,
    /// CN override. Consulted only when the role sets
    /// `use_csr_common_name = false`; ignored on verbatim.
    pub common_name: String,
    /// SAN override, comma-separated DNS names and IPs. Consulted only
    /// when the role sets `use_csr_sans = false`; ignored on verbatim.
    pub alt_names: String,
    /// Human duration (`720h`). Empty = the role's default TTL, or the
    /// 30-day ceiling on verbatim.
    pub ttl: String,
    pub issuer_ref: String,
    /// Managed key the CSR's SPKI must match. Requires
    /// `role.allow_key_reuse`; rejected outright on verbatim.
    pub key_ref: String,
    pub upn_sans: String,
    /// rfc822Name override, comma-separated. Consulted only when the role
    /// sets `use_csr_sans = false`; ignored on verbatim (where the CSR's
    /// own rfc822Names carry through instead).
    pub email_sans: String,
    pub ad_sid: String,
}

/// A fully decided, not-yet-executed signing request.
///
/// Reaching this struct means every check passed: producing it is the
/// authorisation decision, and [`PkiBackendInner::execute_sign`] does no
/// policy work of its own. The private fields carry the issuer handle
/// (and therefore its signing key), which is why they are not public —
/// a `SignPlan` is not something to hand around.
pub struct SignPlan {
    pub mode: &'static str,
    pub role_name: String,
    pub common_name: String,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<IpAddr>,
    pub upn_sans: Vec<String>,
    pub email_sans: Vec<String>,
    pub ad_sid: Option<String>,
    pub ttl: Duration,
    /// True when the issuer's own `NotAfter` cut the requested TTL short.
    pub ttl_clamped: bool,
    pub not_after_unix: i64,
    pub issuer_id: String,
    pub issuer_name: String,
    pub issuer_not_after_unix: i64,
    /// The CSR's key, as `rsa-2048` / `ec-p256` / `ml-dsa-65` / …
    pub key_description: String,
    /// Managed key id when `key_ref` pinned one, else empty.
    pub key_id: String,
    /// Legal-but-notable observations for the operator. Never a reason to
    /// refuse — anything that should refuse returns `Err` instead.
    pub warnings: Vec<String>,
    role: RoleEntry,
    parsed: ParsedCsr,
    pinned_key: Option<KeyEntry>,
    issuer: IssuerHandle,
    store_cert: bool,
}

impl SignPlan {
    fn subject(&self) -> SubjectInput {
        SubjectInput {
            common_name: self.common_name.clone(),
            alt_names: self.dns_sans.clone(),
            ip_sans: self.ip_sans.clone(),
            upn_sans: self.upn_sans.clone(),
            email_sans: self.email_sans.clone(),
            ad_sid: self.ad_sid.clone(),
        }
    }
}

/// What a completed signature yields.
pub struct SignOutcome {
    pub certificate: String,
    pub issuing_ca: String,
    pub ca_chain: Vec<String>,
    pub serial_hex: String,
    pub issuer_id: String,
    pub key_id: String,
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    /// Decide a signing request without touching a signing key.
    pub async fn plan_sign(
        &self,
        req: &Request,
        mode: &SignMode,
        args: &SignArgs,
    ) -> Result<SignPlan, RvError> {
        match mode {
            SignMode::Role(role_name) => self.plan_sign_role(req, role_name, args).await,
            SignMode::Verbatim => self.plan_sign_verbatim(req, args).await,
        }
    }

    async fn plan_sign_role(
        &self,
        req: &Request,
        role_name: &str,
        args: &SignArgs,
    ) -> Result<SignPlan, RvError> {
        let role = self.get_role(req, role_name).await?.ok_or(RvError::ErrPkiRoleNotFound)?;
        if args.csr.trim().is_empty() {
            return Err(RvError::ErrRequestFieldNotFound);
        }
        let parsed = csr::parse_and_verify(&args.csr)?;
        let mut warnings: Vec<String> = Vec::new();

        // Phase L2 key pinning: the CSR's SPKI must match the managed key
        // the caller named. The cert content is unchanged by pinning; the
        // assertion is what lets the engine record a managed-key binding
        // for the issued serial.
        let key_ref = args.key_ref.trim();
        let pinned_key: Option<KeyEntry> = if key_ref.is_empty() {
            None
        } else {
            let role_alg = role.algorithm()?;
            let entry = resolve_pinned_key(req, &role, key_ref, role_alg).await?;
            let entry_spki = keys::entry_spki_der(&entry)?;
            if entry_spki != parsed.spki_der {
                return Err(RvError::ErrString(
                    "sign_csr: CSR SubjectPublicKeyInfo does not match the pinned managed key"
                        .into(),
                ));
            }
            Some(entry)
        };

        // `use_csr_common_name` / `use_csr_sans` are Vault-parity knobs
        // that let an operator force the values from the request body even
        // when the CSR is signed by someone the engine implicitly trusts.
        let common_name = if role.use_csr_common_name {
            parsed.common_name.clone().unwrap_or_default()
        } else {
            if parsed.common_name.is_some() {
                warnings.push(format!(
                    "role `{role_name}` sets use_csr_common_name=false: the CSR's CN is ignored and the request's `common_name` is used"
                ));
            }
            args.common_name.clone()
        };
        if common_name.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }
        x509::validate_common_name(&role, &common_name)?;

        let (mut dns_sans, ip_sans, csr_email_sans) = if role.use_csr_sans {
            (
                parsed.requested_dns_sans.clone(),
                parsed.requested_ip_sans.clone(),
                parsed.requested_email_sans.clone(),
            )
        } else {
            let requested = parsed.requested_dns_sans.len()
                + parsed.requested_ip_sans.len()
                + parsed.requested_email_sans.len();
            if requested > 0 {
                warnings.push(format!(
                    "role `{role_name}` sets use_csr_sans=false: {requested} SAN(s) requested by the CSR are dropped"
                ));
            }
            let (dns, ips) = x509::split_alt_names(&args.alt_names);
            (dns, ips, Vec::new())
        };
        if !role.allow_ip_sans && !ip_sans.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }

        // rfc822Name SANs come from the CSR when the role honours CSR
        // SANs and from the request body otherwise — never from both, so
        // there is one answer to "where did this address come from".
        // Either way the role decides, and an address it will not permit
        // is an error: a CSR that asks for an S/MIME identity and gets
        // back a certificate without one is the silent drop this gate
        // exists to remove.
        let email_sans = if role.use_csr_sans {
            if !args.email_sans.trim().is_empty() {
                return Err(RvError::ErrResponseStatus(
                    400,
                    format!(
                        "sign: role `{role_name}` sets use_csr_sans=true, so rfc822Name SANs come from the CSR; the request's `email_sans` would be ignored"
                    ),
                ));
            }
            super::email_san::validate_email_list(&role, &csr_email_sans)?
        } else {
            super::email_san::resolve_email_sans(&role, &args.email_sans)?
        };
        for dns in &dns_sans {
            x509::validate_dns_name(&role, dns)?;
        }
        // De-dup CN out of the SAN list (rcgen treats it as authoritative).
        dns_sans.retain(|d| d != &common_name);

        let requested_ttl = parse_ttl(&args.ttl)?;
        let ttl = role.effective_ttl(requested_ttl);

        // Issuer priority: request body > role-level pin > mount default.
        let issuer = self
            .resolve_issuer(req, &args.issuer_ref, &role.issuer_ref)
            .await?;
        let (ttl, ttl_clamped) = issuers::clamp_ttl_to_issuer(&issuer, ttl)?;
        if ttl_clamped {
            warnings.push(format!(
                "TTL clamped to issuer `{}`'s remaining lifetime ({}s)",
                issuer.name,
                ttl.as_secs()
            ));
        }

        let (upn_sans, ad_sid) = resolve_ad_smartcard(&role, &args.upn_sans, &args.ad_sid)?;

        // The role's `key_type` describes the keypair `pki/issue/:role`
        // would generate. Signing a foreign CSR has never enforced it —
        // the key is the requester's — so this is a warning, not a gate.
        let key_description = csr::describe_spki(&parsed.spki_der);
        if let Ok(role_alg) = role.algorithm() {
            let role_description = role_key_description(role_alg);
            if role_description != key_description {
                warnings.push(format!(
                    "CSR key is `{key_description}` but role `{role_name}` specifies `{role_description}`; sign/:role does not enforce the role key type on a caller-supplied CSR"
                ));
            }
        }

        self.finish_plan(FinishPlan {
            mode: "role",
            role_name: role_name.to_string(),
            role,
            parsed,
            common_name,
            dns_sans,
            ip_sans,
            upn_sans,
            email_sans,
            ad_sid,
            ttl,
            ttl_clamped,
            key_description,
            pinned_key,
            issuer,
            warnings,
        })
    }

    async fn plan_sign_verbatim(
        &self,
        req: &Request,
        args: &SignArgs,
    ) -> Result<SignPlan, RvError> {
        if args.csr.trim().is_empty() {
            return Err(RvError::ErrRequestFieldNotFound);
        }
        let parsed = csr::parse_and_verify(&args.csr)?;

        let common_name = parsed.common_name.clone().unwrap_or_default();
        if common_name.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }

        // Verbatim has no role to gate a key pin or an AD identity claim
        // against. Both fail loudly rather than being silently dropped.
        if !args.key_ref.trim().is_empty() {
            return Err(RvError::ErrResponseStatus(
                400,
                "sign: `key_ref` needs a role to authorise it (role.allow_key_reuse); it is not accepted in verbatim mode".into(),
            ));
        }
        if !args.upn_sans.trim().is_empty() || !args.ad_sid.trim().is_empty() {
            return Err(RvError::ErrResponseStatus(
                400,
                "sign: `upn_sans` / `ad_sid` need a role to authorise them; they are not accepted in verbatim mode".into(),
            ));
        }
        if !args.email_sans.trim().is_empty() {
            return Err(RvError::ErrResponseStatus(
                400,
                "sign: `email_sans` needs a role to authorise it (role.allow_email_sans); it is not accepted in verbatim mode — put the rfc822Name in the CSR instead".into(),
            ));
        }

        let requested_ttl = parse_ttl(&args.ttl)?;
        let ttl = match requested_ttl {
            Some(d) if !d.is_zero() => std::cmp::min(d, VERBATIM_MAX_TTL),
            _ => VERBATIM_MAX_TTL,
        };

        let issuer = self.resolve_issuer(req, &args.issuer_ref, "").await?;
        let (ttl, ttl_clamped) = issuers::clamp_ttl_to_issuer(&issuer, ttl)?;

        let mut warnings = vec![
            "verbatim mode bypasses role policy: the subject and SANs are taken from the CSR with no allowed_domains / allow_ip_sans check".to_string(),
        ];
        if ttl_clamped {
            warnings.push(format!(
                "TTL clamped to issuer `{}`'s remaining lifetime ({}s)",
                issuer.name,
                ttl.as_secs()
            ));
        }

        // A permissive synthetic role: server+client EKUs, no name
        // restrictions, TTL fixed at what we just computed.
        let role = RoleEntry {
            ttl,
            max_ttl: ttl,
            not_before_duration: Duration::from_secs(30),
            key_type: "ec".to_string(),
            allow_any_name: true,
            allow_ip_sans: true,
            // Verbatim carries whatever the CSR states; the SAN set was
            // decided above, so this only documents that the synthetic
            // role imposes no email policy of its own.
            allow_email_sans: true,
            server_flag: true,
            client_flag: true,
            ..Default::default()
        };

        let mut dns_sans = parsed.requested_dns_sans.clone();
        dns_sans.retain(|d| d != &common_name);
        let ip_sans = parsed.requested_ip_sans.clone();
        // Verbatim means verbatim: an rfc822Name in the CSR reaches the
        // certificate, as the DNS and IP names already did. Dropping it
        // here while honouring the rest would be the one silent
        // subtraction in a path whose contract is "as stated".
        let email_sans = parsed.requested_email_sans.clone();
        let key_description = csr::describe_spki(&parsed.spki_der);

        self.finish_plan(FinishPlan {
            mode: "verbatim",
            role_name: String::new(),
            role,
            parsed,
            common_name,
            dns_sans,
            ip_sans,
            // sign-verbatim deliberately carries no AD smart-card
            // material: there is no role to gate it, and an
            // unauthenticated identity claim is exactly what the SID
            // extension must never be.
            upn_sans: Vec::new(),
            email_sans,
            ad_sid: None,
            ttl,
            ttl_clamped,
            key_description,
            pinned_key: None,
            issuer,
            warnings,
        })
    }

    /// The tail both plans share: the class match against the CA, the
    /// keyless-issuer check, and the derived `NotAfter`.
    fn finish_plan(&self, p: FinishPlan) -> Result<SignPlan, RvError> {
        // Mixed-chain rejection: a PQC CSR needs a PQC CA and a classical
        // CSR a classical CA. Checked here rather than only at build time
        // so a dry run reports it instead of an operator discovering it on
        // the signing call.
        let Some(signer) = p.issuer.signer.as_ref() else {
            return Err(issuers::keyless_signing_error(&p.issuer.name));
        };
        let class_ok = matches!(
            (&p.parsed.algorithm_class, signer),
            (CsrAlgClass::Classical, Signer::Classical(_)) | (CsrAlgClass::MlDsa(_), Signer::MlDsa(_))
        );
        if !class_ok {
            log::warn!(
                "pki/sign: CSR key class ({}) cannot be signed by issuer {} ({})",
                p.key_description,
                p.issuer.name,
                p.issuer.id
            );
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }

        let now = now_unix();
        let store_cert = p.mode == "verbatim" || !p.role.no_store;
        Ok(SignPlan {
            mode: p.mode,
            role_name: p.role_name,
            common_name: p.common_name,
            dns_sans: p.dns_sans,
            ip_sans: p.ip_sans,
            upn_sans: p.upn_sans,
            email_sans: p.email_sans,
            ad_sid: p.ad_sid,
            ttl: p.ttl,
            ttl_clamped: p.ttl_clamped,
            not_after_unix: now.saturating_add(p.ttl.as_secs() as i64),
            issuer_id: p.issuer.id.clone(),
            issuer_name: p.issuer.name.clone(),
            issuer_not_after_unix: p.issuer.meta.not_after_unix,
            key_description: p.key_description,
            key_id: p.pinned_key.as_ref().map(|e| e.id.clone()).unwrap_or_default(),
            warnings: p.warnings,
            role: p.role,
            parsed: p.parsed,
            pinned_key: p.pinned_key,
            issuer: p.issuer,
            store_cert,
        })
    }

    async fn resolve_issuer(
        &self,
        req: &Request,
        request_ref: &str,
        role_ref: &str,
    ) -> Result<IssuerHandle, RvError> {
        let issuer = if !request_ref.trim().is_empty() {
            issuers::load_issuer(req, request_ref.trim()).await?
        } else if !role_ref.trim().is_empty() {
            issuers::load_issuer(req, role_ref.trim()).await?
        } else {
            issuers::load_default_issuer(req).await?
        };
        // Gate on the issuer's `usages.issuing_certificates` bit so an
        // issuer locked down to CRL-signing-only can't be hijacked into
        // issuing leaves.
        issuers::require_issuing(&issuer)?;
        Ok(issuer)
    }

    /// Mint the certificate a [`SignPlan`] describes. Performs no policy
    /// checks — producing the plan was the decision.
    pub async fn execute_sign(
        &self,
        req: &Request,
        plan: SignPlan,
    ) -> Result<SignOutcome, RvError> {
        let ca_cert_pem = plan.issuer.cert_pem.clone();
        let ca_chain = issuers::build_issuer_chain(req, &plan.issuer).await?;
        let issuer_id = plan.issuer.id.clone();
        let issuer_name = plan.issuer.name.clone();
        let subject = plan.subject();
        let ca_signer = issuers::take_signer(plan.issuer.signer, &issuer_name)?;
        let urls = load_issuance_urls(req).await?;

        let (cert_pem, serial_bytes) = match (&plan.parsed.algorithm_class, &ca_signer) {
            (CsrAlgClass::Classical, Signer::Classical(ca_classical)) => {
                let (cert, serial) = x509::build_leaf_from_spki(
                    &plan.role,
                    &subject,
                    plan.ttl,
                    &plan.parsed.spki_der,
                    ca_classical,
                    &ca_cert_pem,
                    &urls,
                )?;
                (cert.pem(), serial)
            }
            (CsrAlgClass::MlDsa(level), Signer::MlDsa(ca_ml)) => x509_pqc::build_leaf_from_pqc_spki(
                &plan.role,
                &subject,
                plan.ttl,
                &plan.parsed.raw_public_key,
                *level,
                ca_ml,
                &ca_cert_pem,
                &urls,
            )?,
            // Unreachable: `finish_plan` already rejected a mixed chain.
            // Kept as a hard stop rather than an `unreachable!()` so a
            // future signer variant fails closed.
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        let serial_hex = storage::serial_to_hex(&serial_bytes);

        if plan.store_cert {
            let now = now_unix();
            let record = CertRecord {
                serial_hex: serial_hex.clone(),
                certificate_pem: cert_pem.clone(),
                issued_at_unix: now as u64,
                revoked_at_unix: None,
                not_after_unix: now.saturating_add(plan.ttl.as_secs() as i64),
                issuer_id: issuer_id.clone(),
                is_orphaned: false,
                source: String::new(),
                key_id: plan.key_id.clone(),
            };
            storage::put_json(req, &storage::cert_storage_key(&serial_hex), &record).await?;
        }

        // Record the managed-key binding so a later `pki/key/<id>` delete
        // refuses while this cert is live.
        if let Some(entry) = &plan.pinned_key {
            keys::add_cert_ref(req, &entry.id, &serial_hex).await?;
        }

        Ok(SignOutcome {
            certificate: cert_pem,
            issuing_ca: ca_cert_pem,
            ca_chain,
            serial_hex,
            issuer_id,
            key_id: plan.key_id,
        })
    }
}

/// Intermediate bundle handed to `finish_plan`. Exists only to keep that
/// function's signature honest instead of a dozen positional parameters.
struct FinishPlan {
    mode: &'static str,
    role_name: String,
    role: RoleEntry,
    parsed: ParsedCsr,
    common_name: String,
    dns_sans: Vec<String>,
    ip_sans: Vec<IpAddr>,
    upn_sans: Vec<String>,
    email_sans: Vec<String>,
    ad_sid: Option<String>,
    ttl: Duration,
    ttl_clamped: bool,
    key_description: String,
    pinned_key: Option<KeyEntry>,
    issuer: IssuerHandle,
    warnings: Vec<String>,
}

/// Render a role's configured algorithm the same way [`csr::describe_spki`]
/// renders a CSR's, so the two can be compared for the preflight warning.
fn role_key_description(alg: KeyAlgorithm) -> String {
    match alg.as_str() {
        "rsa" => format!("rsa-{}", alg.key_bits()),
        "ec" => format!("ec-p{}", alg.key_bits()),
        other => other.to_string(),
    }
}

fn parse_ttl(raw: &str) -> Result<Option<Duration>, RvError> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    parse_duration(s).map(Some).map_err(|_| RvError::ErrRequestFieldInvalid)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
