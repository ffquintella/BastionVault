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

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{machine_id, now_unix, status, FerroGateBackend, FerroGateBackendInner, MachineEntry};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
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
                    required: false,
                    description: "FerroGate-issued child token or SVID (JWS)."
                }
            },
            operations: [
                {op: Operation::Write, handler: r.login}
            ],
            help: r#"Authenticate a machine using a FerroGate-issued token (not yet implemented)."#
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

    pub async fn login(&self, _b: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        // Phase 2 wires the FerroGate reference verifiers (ferro-child-verify /
        // ferro-svid-verify) and the enrolment state machine.
        Ok(Some(Response::error_response(
            "ferrogate login is not implemented yet (Phase 2): token verification not wired",
        )))
    }
}
