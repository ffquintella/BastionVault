//! Machine enrolment records and the admin lifecycle routes (Phase 1).
//!
//! Routes (all root/sudo-gated except `login`):
//! - `POST   register`                      — admin pre-registers a SPIFFE ID → `pending`.
//! - `LIST   machines`                      — enumerate machines with summaries.
//! - `GET    machines/{id}`                 — show one record.
//! - `DELETE machines/{id}`                 — forget a record.
//! - `POST   machines/{id}/approve`         — approve with policies + ttl.
//! - `POST   machines/{id}/reject`          — reject with a reason.
//! - `POST   machines/{id}/revoke`          — revoke an approved machine.
//! - `POST   login`                         — **stubbed** until Phase 2.
//!
//! `{id}` is the [`machine_id`] (BLAKE3 hex) of the SPIFFE ID, as returned by
//! `register` / `LIST` — a raw SPIFFE ID can't be a single path segment.

use std::{collections::HashMap, sync::Arc, time::Duration};

use serde_json::{json, Map, Value};

use super::{machine_id, now_unix, status, verify::verify_child_token, FerroGateBackend, FerroGateBackendInner, MachineEntry};
use crate::{
    context::Context,
    errors::RvError,
    logical::{
        field::FieldTrait, Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response,
    },
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const MACHINE_PREFIX: &str = "machine/";

fn machine_key(id: &str) -> String {
    format!("{MACHINE_PREFIX}{id}")
}

/// Caller-facing summary of a machine record (no secrets — there are none).
fn summarize(id: &str, m: &MachineEntry) -> Value {
    json!({
        "id": id,
        "spiffe_id": m.spiffe_id,
        "status": m.status,
        "policies": m.policies,
        "ttl_seconds": m.ttl_seconds,
        "ek_cert_sha384": m.ek_cert_sha384,
        "policy_id": m.policy_id,
        "parent_svid": m.parent_svid,
        "first_seen_at": m.first_seen_at,
        "approved_at": m.approved_at,
        "approver": m.approver,
        "last_login_at": m.last_login_at,
        "last_login_ip": m.last_login_ip,
        "reject_reason": m.reject_reason,
        "comment": m.comment,
    })
}

impl FerroGateBackend {
    pub fn register_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"register$",
            fields: {
                "spiffe_id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "SPIFFE ID to pre-register, e.g. spiffe://ferrogate.prod/host/<uuid>."
                },
                "comment": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Optional free-text note."
                }
            },
            operations: [
                {op: Operation::Write, handler: r.register_machine}
            ],
            help: r#"Admin pre-registration of a machine by SPIFFE ID (creates a pending record)."#
        })
    }

    pub fn machines_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"machines/?$",
            operations: [
                {op: Operation::List, handler: r.list_machines}
            ],
            help: r#"List enrolled machines with status and attestation summary."#
        })
    }

    pub fn machine_path(&self) -> Path {
        let read_ref = self.inner.clone();
        let del_ref = self.inner.clone();
        new_path!({
            pattern: r"machines/(?P<id>[0-9a-f]{64})$",
            fields: {
                "id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Machine handle (BLAKE3 hex of the SPIFFE ID)."
                }
            },
            operations: [
                {op: Operation::Read, handler: read_ref.show_machine},
                {op: Operation::Delete, handler: del_ref.delete_machine}
            ],
            help: r#"Show or forget a single machine record."#
        })
    }

    pub fn machine_approve_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"machines/(?P<id>[0-9a-f]{64})/approve$",
            fields: {
                "id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Machine handle."
                },
                "policies": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: "Policies to grant tokens this machine mints."
                },
                "ttl_seconds": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Token TTL (seconds); 0 uses the config default."
                },
                "comment": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Optional approval note."
                }
            },
            operations: [
                {op: Operation::Write, handler: r.approve_machine}
            ],
            help: r#"Approve a machine and attach its policy set."#
        })
    }

    pub fn machine_reject_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"machines/(?P<id>[0-9a-f]{64})/reject$",
            fields: {
                "id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Machine handle."
                },
                "reason": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Reason for rejection."
                }
            },
            operations: [
                {op: Operation::Write, handler: r.reject_machine}
            ],
            help: r#"Reject a pending machine."#
        })
    }

    pub fn machine_revoke_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"machines/(?P<id>[0-9a-f]{64})/revoke$",
            fields: {
                "id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Machine handle."
                }
            },
            operations: [
                {op: Operation::Write, handler: r.revoke_machine}
            ],
            help: r#"Revoke an approved machine."#
        })
    }

    pub fn login_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"login/?$",
            fields: {
                "token": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "FerroGate-issued, DPoP-bound child token (compact JWS)."
                },
                "dpop": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "DPoP proof JWS (RFC 9449). Preferred via the 'DPoP' header; this body field is a fallback for non-browser clients."
                }
            },
            operations: [
                {op: Operation::Write, handler: r.login}
            ],
            help: r#"Authenticate a machine using a FerroGate-issued child token (+ DPoP proof)."#
        })
    }
}

#[maybe_async::maybe_async]
impl FerroGateBackendInner {
    pub async fn get_machine(&self, req: &mut Request, id: &str) -> Result<Option<MachineEntry>, RvError> {
        match req.storage_get(&machine_key(id)).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(entry.value.as_slice())?)),
            None => Ok(None),
        }
    }

    pub async fn set_machine(&self, req: &mut Request, id: &str, m: &MachineEntry) -> Result<(), RvError> {
        let entry = StorageEntry::new(&machine_key(id), m)?;
        req.storage_put(&entry).await
    }

    /// Best-effort display name of the requesting administrator.
    fn approver_name(req: &Request) -> String {
        req.auth
            .as_ref()
            .map(|a| a.display_name.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "admin".to_string())
    }

    fn id_from(req: &Request) -> Result<String, RvError> {
        let v = req.get_data("id")?;
        Ok(v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string())
    }

    pub async fn register_machine(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let spiffe_id = req.get_data("spiffe_id")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        if !spiffe_id.starts_with("spiffe://") {
            return Ok(Some(Response::error_response("spiffe_id must be a spiffe:// URI")));
        }
        let id = machine_id(&spiffe_id);

        // Idempotent: an existing record is returned untouched.
        if let Some(existing) = self.get_machine(req, &id).await? {
            let mut data = Map::new();
            data.insert("id".to_string(), Value::String(id));
            data.insert("spiffe_id".to_string(), Value::String(existing.spiffe_id));
            data.insert("status".to_string(), Value::String(existing.status));
            return Ok(Some(Response::data_response(Some(data))));
        }

        let comment = req.get_data("comment").ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let m = MachineEntry {
            spiffe_id: spiffe_id.clone(),
            status: status::PENDING.to_string(),
            first_seen_at: now_unix(),
            comment,
            ..Default::default()
        };
        self.set_machine(req, &id, &m).await?;

        let mut data = Map::new();
        data.insert("id".to_string(), Value::String(id));
        data.insert("spiffe_id".to_string(), Value::String(spiffe_id));
        data.insert("status".to_string(), Value::String(status::PENDING.to_string()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn list_machines(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let ids = req.storage_list(MACHINE_PREFIX).await?;
        let mut machines = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(m) = self.get_machine(req, id).await? {
                machines.push(summarize(id, &m));
            }
        }
        let mut data = Map::new();
        data.insert("keys".to_string(), Value::Array(ids.into_iter().map(Value::String).collect()));
        data.insert("machines".to_string(), Value::Array(machines));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn show_machine(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = Self::id_from(req)?;
        match self.get_machine(req, &id).await? {
            Some(m) => {
                let data = summarize(&id, &m).as_object().cloned().ok_or(RvError::ErrResponseDataInvalid)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_machine(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = Self::id_from(req)?;
        req.storage_delete(&machine_key(&id)).await?;
        Ok(None)
    }

    pub async fn approve_machine(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = Self::id_from(req)?;
        let Some(mut m) = self.get_machine(req, &id).await? else {
            return Ok(Some(Response::error_response("unknown machine")));
        };

        if let Ok(v) = req.get_data("policies") {
            m.policies = v.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("ttl_seconds") {
            m.ttl_seconds = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?.max(0) as u64;
        }
        if let Ok(v) = req.get_data("comment") {
            if let Some(c) = v.as_str() {
                m.comment = c.to_string();
            }
        }
        m.status = status::APPROVED.to_string();
        m.approved_at = now_unix();
        m.approver = Self::approver_name(req);
        m.reject_reason.clear();
        self.set_machine(req, &id, &m).await?;
        Ok(None)
    }

    pub async fn reject_machine(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = Self::id_from(req)?;
        let Some(mut m) = self.get_machine(req, &id).await? else {
            return Ok(Some(Response::error_response("unknown machine")));
        };
        m.status = status::REJECTED.to_string();
        m.reject_reason =
            req.get_data("reason").ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        self.set_machine(req, &id, &m).await?;
        Ok(None)
    }

    pub async fn revoke_machine(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = Self::id_from(req)?;
        let Some(mut m) = self.get_machine(req, &id).await? else {
            return Ok(Some(Response::error_response("unknown machine")));
        };
        // Phase 1 flips status only; active-token revocation through the lease
        // manager lands once login mints tokens (Phase 3+).
        m.status = status::REVOKED.to_string();
        self.set_machine(req, &id, &m).await?;
        Ok(None)
    }

    /// Source IP of the calling client, best-effort (resolved client IP if a
    /// trusted proxy set it, else the socket peer).
    fn source_ip(req: &Request) -> String {
        req.connection
            .as_ref()
            .map(|c| {
                if c.peer_addr_derived.is_empty() {
                    c.peer_addr.clone()
                } else {
                    c.peer_addr_derived.clone()
                }
            })
            .unwrap_or_default()
    }

    /// Authenticate a machine. Verifies the FerroGate child token (signature +
    /// DPoP sender-constraint) against the configured trust anchor, then applies
    /// the admin-approval gate keyed on the token's SPIFFE ID:
    /// approved → mint a token; unknown → record `pending` and deny;
    /// pending/rejected/revoked → deny.
    pub async fn login(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?;

        let token = req.get_data("token")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();

        // DPoP proof: prefer the RFC 9449 header (plumbed by the HTTP layer),
        // fall back to a `dpop` body field for non-browser clients / tests.
        let dpop = req
            .headers
            .as_ref()
            .and_then(|h| h.get("dpop").or_else(|| h.get("DPoP")))
            .cloned()
            .or_else(|| req.get_data("dpop").ok().and_then(|v| v.as_str().map(str::to_string)));

        let verified = match verify_child_token(&config, &token, dpop.as_deref(), now_unix()) {
            Ok(v) => v,
            Err(reason) => {
                log::warn!(target: "security", "ferrogate login rejected: {reason}");
                return Ok(Some(Response::error_response(&reason)));
            }
        };

        let spiffe_id = verified.claims.iss.clone();
        let id = machine_id(&spiffe_id);
        let ip = Self::source_ip(req);

        let machine = self.get_machine(req, &id).await?;
        match machine {
            Some(mut m) if m.status == status::APPROVED => {
                m.last_login_at = now_unix();
                m.last_login_ip = ip;
                if m.parent_svid.is_empty() {
                    m.parent_svid = verified.claims.ferrogate.parent_svid.clone();
                }
                self.set_machine(req, &id, &m).await?;

                let ttl = if m.ttl_seconds > 0 { m.ttl_seconds } else { config.default_token_ttl };
                let mut auth = Auth {
                    lease: Lease {
                        ttl: Duration::from_secs(ttl),
                        renewable: ttl > 0,
                        ..Default::default()
                    },
                    display_name: spiffe_id.clone(),
                    policies: m.policies.clone(),
                    token_policies: m.policies.clone(),
                    ..Default::default()
                };
                auth.metadata.insert("spiffe_id".to_string(), spiffe_id);
                auth.metadata.insert("mount_path".to_string(), "ferrogate/".to_string());
                auth.metadata.insert("ferrogate_kid".to_string(), verified.kid);
                Ok(Some(Response { auth: Some(auth), ..Response::default() }))
            }
            Some(m) if m.status == status::PENDING => {
                Ok(Some(Response::error_response("enrolment_pending: awaiting administrator approval")))
            }
            Some(m) if m.status == status::REJECTED => {
                Ok(Some(Response::error_response("enrolment_rejected")))
            }
            Some(m) if m.status == status::REVOKED => {
                Ok(Some(Response::error_response("machine_revoked")))
            }
            Some(_) => Ok(Some(Response::error_response("enrolment_pending"))),
            None => {
                // First sighting of an attested-but-unauthorized machine: record
                // it as pending so it surfaces in the admin queue, then deny.
                let m = MachineEntry {
                    spiffe_id,
                    status: status::PENDING.to_string(),
                    first_seen_at: now_unix(),
                    last_login_ip: ip,
                    parent_svid: verified.claims.ferrogate.parent_svid.clone(),
                    ..Default::default()
                };
                self.set_machine(req, &id, &m).await?;
                Ok(Some(Response::error_response("enrolment_pending: awaiting administrator approval")))
            }
        }
    }
}
