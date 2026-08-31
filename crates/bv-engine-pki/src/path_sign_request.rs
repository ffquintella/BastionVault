//! `pki/sign-request/*` — the **inbound** CSR queue.
//!
//! [`super::path_csr`] is the outgoing direction: the engine builds a CSR
//! and an upstream CA signs it. This module is the reverse, and the case
//! that actually needs a queue: someone else built a CSR, *we* are the CA,
//! and an operator has to decide whether to sign it, under which role, and
//! with what subject — or refuse it on the record.
//!
//! Endpoints:
//!
//! - `WRITE  /v2/pki/sign-request/import`            → park a CSR as `pending`
//! - `LIST   /v2/pki/sign-request`                   → request ids
//! - `READ   /v2/pki/sign-request/<id>`              → record + decision
//! - `WRITE  /v2/pki/sign-request/<id>/preflight`    → dry run, no signature
//! - `WRITE  /v2/pki/sign-request/<id>/approve`      → sign it under a role
//! - `WRITE  /v2/pki/sign-request/<id>/approve-verbatim` → sign it as-is
//! - `WRITE  /v2/pki/sign-request/<id>/reject`       → refuse it, with a reason
//! - `DELETE /v2/pki/sign-request/<id>`              → drop the record
//!
//! Three properties are deliberate:
//!
//! 1. **Import verifies the CSR's self-signature** ([`super::csr`]) before
//!    persisting anything. Parking a CSR whose holder is unproven would
//!    invite an operator to approve it later on the strength of it being
//!    "already in the queue".
//! 2. **Preflight and approve run one implementation.** Both go through
//!    [`super::sign_flow::SignPlan`]; the dry run stops after the plan and
//!    the approval executes it. A preflight that said "allowed" and an
//!    approve that then failed policy would be worse than no preflight.
//!    Verbatim approval is a *separate path*, not a flag, so a policy that
//!    grants role-approval does not thereby grant a policy-free signature.
//! 3. **A decision is terminal.** `signed` and `rejected` records stay put
//!    until deleted, and neither can be re-decided. The queue exists so a
//!    refusal leaves a trace; silently reopening one would defeat that.
//!
//! See features/pki-inbound-sign-requests.md.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};
use uuid::Uuid;

use super::{
    csr,
    sign_flow::{SignArgs, SignMode, SignPlan},
    storage::{self, sign_request_status, SignRequestRecord, SIGN_REQUEST_FORMAT_VERSION},
    x509, PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

/// Caps on operator-supplied free text and on the CSR itself. A sign
/// request is attacker-influenced input that lands in barrier storage and
/// then in a GUI list; nothing here needs to be large.
const MAX_CSR_BYTES: usize = 64 * 1024;
const MAX_REQUESTER_CHARS: usize = 256;
const MAX_NOTES_CHARS: usize = 4096;
const MAX_REASON_CHARS: usize = 4096;
/// Ceiling on *undecided* requests per mount. Import is an authenticated
/// operation, but it is the one write in this module a token can hold
/// without any signing capability — so it must not be able to grow the
/// mount's storage without bound, and the duplicate scan below is linear
/// in this number. Decided requests do not count: they are the audit
/// trail, and deleting them is the operator's call.
const MAX_PENDING_REQUESTS: usize = 500;

impl PkiBackend {
    pub fn sign_request_import_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-request/import$",
            fields: {
                "csr": { field_type: FieldType::Str, required: true, description: "PEM- or DER-encoded PKCS#10 CSR to park for a decision." },
                "requester": { field_type: FieldType::Str, default: "", description: "Who asked for this certificate. Free text, recorded on the request." },
                "notes": { field_type: FieldType::Str, default: "", description: "Ticket reference or context for the approver." },
                "suggested_role": { field_type: FieldType::Str, default: "", description: "Role the importer suggests. Advisory only — the approver picks the role that applies." },
                "allow_duplicate": { field_type: FieldType::Bool, default: false, description: "Accept a CSR whose public key already has a pending request. Off by default so a resend cannot create a second approvable copy." }
            },
            operations: [{op: Operation::Write, handler: r.sign_request_import}],
            help: "Import an externally generated CSR as a pending sign request."
        })
    }

    pub fn sign_request_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-request/?$",
            operations: [{op: Operation::List, handler: r.sign_request_list}],
            help: "List inbound sign-request ids."
        })
    }

    pub fn sign_request_item_path(&self) -> Path {
        let rr = self.inner.clone();
        let rd = self.inner.clone();
        new_path!({
            pattern: r"sign-request/(?P<request_id>[\w\-]+)$",
            fields: {
                "request_id": { field_type: FieldType::Str, required: true, description: "Sign-request id." }
            },
            operations: [
                {op: Operation::Read, handler: rr.sign_request_read},
                {op: Operation::Delete, handler: rd.sign_request_delete}
            ],
            help: "Read or delete one inbound sign request."
        })
    }

    pub fn sign_request_preflight_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-request/(?P<request_id>[\w\-]+)/preflight$",
            fields: {
                "request_id": { field_type: FieldType::Str, required: true, description: "Sign-request id." },
                "mode": { field_type: FieldType::Str, default: "", description: "`role`, `verbatim`, or empty to evaluate verbatim plus every role on the mount." },
                "role": { field_type: FieldType::Str, default: "", description: "Role to evaluate. Empty with mode=role evaluates every role." },
                "common_name": { field_type: FieldType::Str, default: "", description: "CN override, for roles with use_csr_common_name=false." },
                "alt_names": { field_type: FieldType::Str, default: "", description: "SAN override, for roles with use_csr_sans=false." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to sign with; empty = role pin or mount default." },
                "key_ref": { field_type: FieldType::Str, default: "", description: "Managed key the CSR's SPKI must match. Requires role.allow_key_reuse." },
                "upn_sans": { field_type: FieldType::Str, default: "", description: "UPN otherName SANs. Requires role.allow_upn_sans." },
                "email_sans": { field_type: FieldType::Str, default: "", description: "rfc822Name SAN override, for roles with use_csr_sans=false. Requires role.allow_email_sans." },
                "ad_sid": { field_type: FieldType::Str, default: "", description: "AD account SID for the strong-mapping extension. Requires role.allow_ad_sid." }
            },
            operations: [{op: Operation::Write, handler: r.sign_request_preflight}],
            help: "Dry-run a sign request: report what would be issued, and which roles would refuse it."
        })
    }

    pub fn sign_request_approve_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-request/(?P<request_id>[\w\-]+)/approve$",
            fields: {
                "request_id": { field_type: FieldType::Str, required: true, description: "Sign-request id." },
                "role": { field_type: FieldType::Str, default: "", description: "Role to sign under. Required — role policy applies; for a policy-free signature use `approve-verbatim`." },
                "common_name": { field_type: FieldType::Str, default: "", description: "CN override, for roles with use_csr_common_name=false." },
                "alt_names": { field_type: FieldType::Str, default: "", description: "SAN override, for roles with use_csr_sans=false." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to sign with; empty = role pin or mount default." },
                "key_ref": { field_type: FieldType::Str, default: "", description: "Managed key the CSR's SPKI must match. Requires role.allow_key_reuse." },
                "upn_sans": { field_type: FieldType::Str, default: "", description: "UPN otherName SANs. Requires role.allow_upn_sans." },
                "email_sans": { field_type: FieldType::Str, default: "", description: "rfc822Name SAN override, for roles with use_csr_sans=false. Requires role.allow_email_sans." },
                "ad_sid": { field_type: FieldType::Str, default: "", description: "AD account SID for the strong-mapping extension. Requires role.allow_ad_sid." }
            },
            operations: [{op: Operation::Write, handler: r.sign_request_approve}],
            help: "Approve a pending sign request under a role and issue the certificate."
        })
    }

    /// Verbatim approval is a **separate path on purpose**. It bypasses
    /// role policy, so a policy that grants `sign-request/+/approve`
    /// (sign what a role permits) must not thereby grant a policy-free
    /// signature — exactly the split `pki/sign/:role` and
    /// `pki/sign-verbatim` have always had.
    pub fn sign_request_approve_verbatim_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-request/(?P<request_id>[\w\-]+)/approve-verbatim$",
            fields: {
                "request_id": { field_type: FieldType::Str, required: true, description: "Sign-request id." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL, capped at 30 days for the role-less path." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to sign with; empty = mount default." }
            },
            operations: [{op: Operation::Write, handler: r.sign_request_approve_verbatim}],
            help: "Approve a pending sign request verbatim — subject and SANs taken from the CSR, bypassing role policy."
        })
    }

    pub fn sign_request_reject_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-request/(?P<request_id>[\w\-]+)/reject$",
            fields: {
                "request_id": { field_type: FieldType::Str, required: true, description: "Sign-request id." },
                "reason": { field_type: FieldType::Str, required: true, description: "Why the request is refused. Required — a rejection with no reason is not a record." }
            },
            operations: [{op: Operation::Write, handler: r.sign_request_reject}],
            help: "Refuse a pending sign request, recording the reason."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn sign_request_import(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let csr_input = req
            .get_data("csr")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .trim()
            .to_string();
        if csr_input.is_empty() {
            return Err(RvError::ErrRequestFieldInvalid);
        }
        if csr_input.len() > MAX_CSR_BYTES {
            return Err(RvError::ErrResponseStatus(
                400,
                format!("sign-request/import: CSR exceeds {MAX_CSR_BYTES} bytes"),
            ));
        }

        // Verify before persisting: a CSR whose self-signature does not
        // check out is refused outright rather than parked.
        let parsed = csr::parse_and_verify(&csr_input)?;
        let common_name = parsed.common_name.clone().unwrap_or_default();
        let spki_sha256 = csr::spki_fingerprint(&parsed.spki_der);

        let allow_duplicate = req
            .get_data_or_default("allow_duplicate")?
            .as_bool()
            .unwrap_or(false);
        let pending = self.scan_pending(req, &spki_sha256).await?;
        if pending.count >= MAX_PENDING_REQUESTS {
            return Err(RvError::ErrResponseStatus(
                429,
                format!(
                    "sign-request/import: {MAX_PENDING_REQUESTS} requests are already awaiting a decision on this mount; decide or delete some before importing more"
                ),
            ));
        }
        if !allow_duplicate {
            if let Some(existing) = pending.same_key {
                return Err(RvError::ErrResponseStatus(
                    409,
                    format!(
                        "sign-request/import: request `{existing}` is already pending for this public key; decide it first, or pass allow_duplicate=true"
                    ),
                ));
            }
        }

        let requester = truncate(
            req.get_data_or_default("requester")?.as_str().unwrap_or("").trim(),
            MAX_REQUESTER_CHARS,
        );
        let notes = truncate(
            req.get_data_or_default("notes")?.as_str().unwrap_or("").trim(),
            MAX_NOTES_CHARS,
        );
        let suggested_role = req
            .get_data_or_default("suggested_role")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();

        let record = SignRequestRecord {
            version: SIGN_REQUEST_FORMAT_VERSION,
            id: Uuid::new_v4().to_string(),
            status: sign_request_status::PENDING.to_string(),
            csr_pem: csr_input,
            subject_dn: parsed.subject_dn.clone(),
            common_name,
            dns_sans: parsed.requested_dns_sans.clone(),
            ip_sans: parsed.requested_ip_sans.iter().map(|ip| ip.to_string()).collect(),
            email_sans: parsed.requested_email_sans.clone(),
            key_description: csr::describe_spki(&parsed.spki_der),
            spki_sha256,
            requester,
            notes,
            suggested_role,
            created_at_unix: now_unix(),
            imported_by: caller_identity(req),
            ..Default::default()
        };
        storage::put_json(req, &storage::sign_request_storage_key(&record.id), &record).await?;
        log::info!(
            "pki/sign-request: imported {} (cn `{}`, key {}) by {}",
            record.id,
            record.common_name,
            record.key_description,
            record.imported_by
        );

        Ok(Some(Response::data_response(Some(record_summary(&record)))))
    }

    pub async fn sign_request_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let ids = req.storage_list(storage::KEY_PREFIX_SIGN_REQUEST).await?;
        Ok(Some(Response::list_response(&ids)))
    }

    pub async fn sign_request_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = request_id(req)?;
        let Some(record) = self.load_sign_request(req, &id).await? else {
            return Ok(None);
        };
        let mut data = record_summary(&record);
        data.insert("csr".into(), json!(record.csr_pem));
        if !record.certificate_pem.is_empty() {
            data.insert("certificate".into(), json!(record.certificate_pem));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn sign_request_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = request_id(req)?;
        let key = storage::sign_request_storage_key(&id);
        if req.storage_get(&key).await?.is_none() {
            return Ok(None);
        }
        req.storage_delete(&key).await?;
        log::info!("pki/sign-request: deleted {id} by {}", caller_identity(req));
        Ok(None)
    }

    /// Dry run. Never mutates the record and never touches a signing key
    /// beyond loading the issuer the plan resolves to.
    pub async fn sign_request_preflight(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = request_id(req)?;
        let record = self
            .load_sign_request(req, &id)
            .await?
            .ok_or_else(|| not_found(&id))?;
        let args = args_from_request(req, &record.csr_pem)?;
        let mode_raw = req.get_data_or_default("mode")?.as_str().unwrap_or("").trim().to_string();
        let role_raw = req.get_data_or_default("role")?.as_str().unwrap_or("").trim().to_string();

        // Which combinations to evaluate:
        //   explicit mode+role  → just that one
        //   mode=role, no role  → every role
        //   nothing             → verbatim + every role, so the operator
        //                         sees the whole decision surface at once.
        let mut modes: Vec<SignMode> = Vec::new();
        match mode_raw.as_str() {
            "verbatim" => modes.push(SignMode::Verbatim),
            "role" if !role_raw.is_empty() => modes.push(SignMode::Role(role_raw.clone())),
            "role" => modes.extend(self.all_role_modes(req).await?),
            "" if !role_raw.is_empty() => modes.push(SignMode::Role(role_raw.clone())),
            "" => {
                modes.push(SignMode::Verbatim);
                modes.extend(self.all_role_modes(req).await?);
            }
            other => {
                return Err(RvError::ErrResponseStatus(
                    400,
                    format!("sign-request/preflight: unknown mode `{other}`; expected `role` or `verbatim`"),
                ))
            }
        }

        let mut verdicts: Vec<Value> = Vec::with_capacity(modes.len());
        for mode in &modes {
            verdicts.push(self.verdict(req, mode, &args).await);
        }

        let mut data = record_summary(&record);
        data.insert("verdicts".into(), json!(verdicts));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn sign_request_approve(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role = field(req, "role")?;
        if role.is_empty() {
            return Err(RvError::ErrResponseStatus(
                400,
                "sign-request/approve: `role` is required; use `approve-verbatim` to sign without a role".into(),
            ));
        }
        self.sign_request_decide(req, SignMode::Role(role), "approve").await
    }

    pub async fn sign_request_approve_verbatim(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.sign_request_decide(req, SignMode::Verbatim, "approve-verbatim").await
    }

    /// The body both approval paths share. `action` only shapes the error
    /// text on an already-decided request.
    async fn sign_request_decide(
        &self,
        req: &mut Request,
        mode: SignMode,
        action: &str,
    ) -> Result<Option<Response>, RvError> {
        let id = request_id(req)?;
        let mut record = self
            .load_sign_request(req, &id)
            .await?
            .ok_or_else(|| not_found(&id))?;
        require_pending(&record, action)?;

        let args = args_from_request(req, &record.csr_pem)?;

        let plan = self.plan_sign(req, &mode, &args).await?;
        for warning in &plan.warnings {
            log::info!("pki/sign-request {id}: {warning}");
        }
        let mode_label = plan.mode;
        let role_name = plan.role_name.clone();
        // Kept for the response: the plan is consumed by `execute_sign`,
        // and an approver wants to see what they just authorised.
        let ttl_seconds = plan.ttl.as_secs();
        let not_after = plan.not_after_unix;
        let warnings = plan.warnings.clone();
        let outcome = self.execute_sign(req, plan).await?;

        record.status = sign_request_status::SIGNED.to_string();
        record.decided_at_unix = now_unix();
        record.decided_by = caller_identity(req);
        record.sign_mode = mode_label.to_string();
        record.role_name = role_name;
        record.serial_number = outcome.serial_hex.clone();
        record.issuer_id = outcome.issuer_id.clone();
        record.certificate_pem = outcome.certificate.clone();
        storage::put_json(req, &storage::sign_request_storage_key(&id), &record).await?;
        log::info!(
            "pki/sign-request: approved {id} in {mode_label} mode → serial {} (issuer {}) by {}",
            record.serial_number,
            record.issuer_id,
            record.decided_by
        );

        let mut data = record_summary(&record);
        data.insert("certificate".into(), json!(outcome.certificate));
        data.insert("issuing_ca".into(), json!(outcome.issuing_ca));
        data.insert("ca_chain".into(), json!(outcome.ca_chain));
        data.insert("ttl_seconds".into(), json!(ttl_seconds));
        data.insert("not_after".into(), json!(not_after));
        data.insert("warnings".into(), json!(warnings));
        if !outcome.key_id.is_empty() {
            data.insert("key_id".into(), json!(outcome.key_id));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn sign_request_reject(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = request_id(req)?;
        let mut record = self
            .load_sign_request(req, &id)
            .await?
            .ok_or_else(|| not_found(&id))?;
        require_pending(&record, "reject")?;

        let reason = req
            .get_data("reason")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .trim()
            .to_string();
        if reason.is_empty() {
            return Err(RvError::ErrResponseStatus(
                400,
                "sign-request/reject: `reason` is required".into(),
            ));
        }

        record.status = sign_request_status::REJECTED.to_string();
        record.decided_at_unix = now_unix();
        record.decided_by = caller_identity(req);
        record.reject_reason = truncate(&reason, MAX_REASON_CHARS);
        storage::put_json(req, &storage::sign_request_storage_key(&id), &record).await?;
        log::info!(
            "pki/sign-request: rejected {id} by {} — {}",
            record.decided_by,
            record.reject_reason
        );

        Ok(Some(Response::data_response(Some(record_summary(&record)))))
    }

    // ── helpers ──────────────────────────────────────────────────────

    async fn load_sign_request(
        &self,
        req: &Request,
        id: &str,
    ) -> Result<Option<SignRequestRecord>, RvError> {
        storage::get_json(req, &storage::sign_request_storage_key(id)).await
    }

    /// One pass over the queue: how many requests are undecided, and
    /// whether one of them already carries this SPKI fingerprint.
    async fn scan_pending(
        &self,
        req: &Request,
        fingerprint: &str,
    ) -> Result<PendingScan, RvError> {
        let mut scan = PendingScan::default();
        for id in req.storage_list(storage::KEY_PREFIX_SIGN_REQUEST).await? {
            let Some(record) = self.load_sign_request(req, &id).await? else {
                continue;
            };
            if record.status != sign_request_status::PENDING {
                continue;
            }
            scan.count += 1;
            if scan.same_key.is_none() && record.spki_sha256 == fingerprint {
                scan.same_key = Some(record.id);
            }
        }
        Ok(scan)
    }

    async fn all_role_modes(&self, req: &Request) -> Result<Vec<SignMode>, RvError> {
        let mut modes: Vec<SignMode> = req
            .storage_list("role/")
            .await?
            .into_iter()
            .filter(|name| !name.is_empty())
            .map(SignMode::Role)
            .collect();
        modes.sort_by(|a, b| a.role_name().cmp(b.role_name()));
        Ok(modes)
    }

    /// Plan one (mode, args) combination and render the verdict. A refusal
    /// is a *result*, not an error: preflight's job is to report every
    /// outcome in one response.
    async fn verdict(&self, req: &Request, mode: &SignMode, args: &SignArgs) -> Value {
        let mut out = Map::new();
        out.insert("mode".into(), json!(mode.label()));
        out.insert("role".into(), json!(mode.role_name()));
        match self.plan_sign(req, mode, args).await {
            Ok(plan) => {
                out.insert("allowed".into(), json!(true));
                merge_plan(&mut out, &plan);
            }
            Err(e) => {
                out.insert("allowed".into(), json!(false));
                out.insert("reason".into(), json!(e.to_string()));
                out.insert("hints".into(), json!(self.refusal_hints(req, mode, args).await));
            }
        }
        Value::Object(out)
    }

    /// Diagnostics for a refused verdict.
    ///
    /// These call the *same* validators the plan called, one input at a
    /// time, purely to name which value the role rejected — several of the
    /// engine's policy errors (`ErrPkiDataInvalid`) carry no detail, and
    /// "PKI data is invalid" is not an answer an operator can act on.
    /// Nothing here gates anything: [`Self::plan_sign`] already decided.
    async fn refusal_hints(&self, req: &Request, mode: &SignMode, args: &SignArgs) -> Vec<String> {
        let mut hints = Vec::new();
        let SignMode::Role(role_name) = mode else {
            return hints;
        };
        let Ok(Some(role)) = self.get_role(req, role_name).await else {
            return hints;
        };
        let Ok(parsed) = csr::parse_and_verify(&args.csr) else {
            return hints;
        };

        let common_name = if role.use_csr_common_name {
            parsed.common_name.clone().unwrap_or_default()
        } else {
            args.common_name.clone()
        };
        if common_name.is_empty() {
            hints.push(if role.use_csr_common_name {
                "the CSR carries no CN and the role reads the CN from the CSR (use_csr_common_name=true)".to_string()
            } else {
                "the role ignores the CSR's CN (use_csr_common_name=false) and no `common_name` was supplied".to_string()
            });
        } else if x509::validate_common_name(&role, &common_name).is_err() {
            hints.push(format!(
                "common name `{common_name}` is not permitted by role `{role_name}` (allow_any_name={}, allow_subdomains={}, allow_bare_domains={}, allowed_domains={:?})",
                role.allow_any_name,
                role.allow_subdomains,
                role.allow_bare_domains,
                role.allowed_domains
            ));
        }

        let (dns_sans, ip_sans) = if role.use_csr_sans {
            (parsed.requested_dns_sans.clone(), parsed.requested_ip_sans.clone())
        } else {
            x509::split_alt_names(&args.alt_names)
        };
        for dns in &dns_sans {
            if x509::validate_dns_name(&role, dns).is_err() {
                hints.push(format!(
                    "DNS SAN `{dns}` is not permitted by role `{role_name}`"
                ));
            }
        }
        if !role.allow_ip_sans && !ip_sans.is_empty() {
            hints.push(format!(
                "role `{role_name}` sets allow_ip_sans=false but {} IP SAN(s) were requested",
                ip_sans.len()
            ));
        }
        if !args.key_ref.trim().is_empty() && !role.allow_key_reuse {
            hints.push(format!(
                "role `{role_name}` sets allow_key_reuse=false, so `key_ref` is refused"
            ));
        }
        if !args.upn_sans.trim().is_empty() && !role.allow_upn_sans {
            hints.push(format!(
                "role `{role_name}` sets allow_upn_sans=false, so `upn_sans` is refused"
            ));
        }
        // rfc822Name SANs: from the CSR when the role honours CSR SANs,
        // from the body otherwise. Both are refused by a role that does
        // not permit them — reported here so the dry run says why rather
        // than the operator discovering it on approve.
        let requested_emails = if role.use_csr_sans {
            parsed.requested_email_sans.clone()
        } else {
            args.email_sans
                .split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect()
        };
        if !requested_emails.is_empty() && !role.allow_email_sans {
            hints.push(format!(
                "role `{role_name}` sets allow_email_sans=false, so the {} rfc822Name SAN(s) requested are refused",
                requested_emails.len()
            ));
        }
        for addr in &requested_emails {
            if role.allow_email_sans && super::email_san::validate_email(&role, addr).is_err() {
                hints.push(format!(
                    "rfc822Name SAN `{addr}` is not permitted by role `{role_name}`"
                ));
            }
        }
        if role.use_csr_sans && !args.email_sans.trim().is_empty() {
            hints.push(format!(
                "role `{role_name}` sets use_csr_sans=true, so the request's `email_sans` would be ignored and is refused"
            ));
        }
        hints
    }
}

#[derive(Default)]
struct PendingScan {
    /// Undecided requests on this mount.
    count: usize,
    /// Id of an undecided request with the same public key, if any.
    same_key: Option<String>,
}

/// Project a plan into the verdict / approval response.
fn merge_plan(out: &mut Map<String, Value>, plan: &SignPlan) {
    out.insert("common_name".into(), json!(plan.common_name));
    out.insert("dns_sans".into(), json!(plan.dns_sans));
    out.insert(
        "ip_sans".into(),
        json!(plan.ip_sans.iter().map(|ip| ip.to_string()).collect::<Vec<_>>()),
    );
    out.insert("upn_sans".into(), json!(plan.upn_sans));
    out.insert("email_sans".into(), json!(plan.email_sans));
    out.insert("ad_sid".into(), json!(plan.ad_sid.clone().unwrap_or_default()));
    out.insert("ttl_seconds".into(), json!(plan.ttl.as_secs()));
    out.insert("ttl_clamped".into(), json!(plan.ttl_clamped));
    out.insert("not_after".into(), json!(plan.not_after_unix));
    out.insert("issuer_id".into(), json!(plan.issuer_id));
    out.insert("issuer_name".into(), json!(plan.issuer_name));
    out.insert("issuer_not_after".into(), json!(plan.issuer_not_after_unix));
    out.insert("key_description".into(), json!(plan.key_description));
    out.insert("key_id".into(), json!(plan.key_id));
    out.insert("warnings".into(), json!(plan.warnings));
}

/// The record fields every response carries. The CSR PEM and the issued
/// certificate are added only by the endpoints that should return them.
fn record_summary(record: &SignRequestRecord) -> Map<String, Value> {
    let mut data = Map::new();
    data.insert("request_id".into(), json!(record.id));
    data.insert("status".into(), json!(record.status));
    data.insert("subject_dn".into(), json!(record.subject_dn));
    data.insert("common_name".into(), json!(record.common_name));
    data.insert("dns_sans".into(), json!(record.dns_sans));
    data.insert("ip_sans".into(), json!(record.ip_sans));
    data.insert("email_sans".into(), json!(record.email_sans));
    data.insert("key_description".into(), json!(record.key_description));
    data.insert("spki_sha256".into(), json!(record.spki_sha256));
    data.insert("requester".into(), json!(record.requester));
    data.insert("notes".into(), json!(record.notes));
    data.insert("suggested_role".into(), json!(record.suggested_role));
    data.insert("created_at".into(), json!(record.created_at_unix));
    data.insert("imported_by".into(), json!(record.imported_by));
    data.insert("decided_at".into(), json!(record.decided_at_unix));
    data.insert("decided_by".into(), json!(record.decided_by));
    data.insert("reject_reason".into(), json!(record.reject_reason));
    data.insert("sign_mode".into(), json!(record.sign_mode));
    data.insert("role".into(), json!(record.role_name));
    data.insert("serial_number".into(), json!(record.serial_number));
    data.insert("issuer_id".into(), json!(record.issuer_id));
    data
}

/// Build [`SignArgs`] from an approve/preflight body, with the CSR coming
/// from the stored record rather than the caller — the queue's whole point
/// is that the artefact under decision is the one that was imported.
fn args_from_request(req: &Request, csr_pem: &str) -> Result<SignArgs, RvError> {
    Ok(SignArgs {
        csr: csr_pem.to_string(),
        common_name: field(req, "common_name")?,
        alt_names: field(req, "alt_names")?,
        ttl: field(req, "ttl")?,
        issuer_ref: field(req, "issuer_ref")?,
        key_ref: field(req, "key_ref")?,
        upn_sans: field(req, "upn_sans")?,
        email_sans: field(req, "email_sans")?,
        ad_sid: field(req, "ad_sid")?,
    })
}

/// Read one optional string field. `approve-verbatim` declares only the
/// two knobs a role-less signature can honour, so a field it does not
/// declare reads as unset here and [`super::sign_flow`] is what refuses a
/// role-only knob that was actually supplied.
fn field(req: &Request, key: &str) -> Result<String, RvError> {
    match req.get_data_or_default(key) {
        Ok(v) => Ok(v.as_str().unwrap_or("").trim().to_string()),
        Err(RvError::ErrRequestNoDataField) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

fn request_id(req: &Request) -> Result<String, RvError> {
    Ok(req
        .get_data("request_id")?
        .as_str()
        .ok_or(RvError::ErrRequestFieldInvalid)?
        .to_string())
}

fn require_pending(record: &SignRequestRecord, action: &str) -> Result<(), RvError> {
    if record.status == sign_request_status::PENDING {
        return Ok(());
    }
    Err(RvError::ErrResponseStatus(
        409,
        format!(
            "sign-request/{action}: request `{}` is already `{}` and cannot be decided again; delete it to remove the record",
            record.id, record.status
        ),
    ))
}

fn not_found(id: &str) -> RvError {
    RvError::ErrResponseStatus(404, format!("sign-request: no request with id `{id}`"))
}

/// Best-effort caller identity, matching the KV engine's convention:
/// userpass' `username` metadata, then the token display name, then
/// `unknown` for a root token or an unresolved auth.
fn caller_identity(req: &Request) -> String {
    if let Some(auth) = req.auth.as_ref() {
        if let Some(u) = auth.metadata.get("username") {
            if !u.is_empty() {
                return u.clone();
            }
        }
        if !auth.display_name.is_empty() {
            return auth.display_name.clone();
        }
    }
    "unknown".to_string()
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
