//! `/v1/ssh/roles/:name` and `/v1/ssh/roles` — role CRUD + LIST.
//!
//! Field schema mirrors the spec in `features/ssh-secret-engine.md`
//! § "CA-Mode Roles". Phase 1 ships only the CA-mode subset; OTP
//! fields (`cidr_list`, `port`, …) get added in Phase 2 alongside
//! their own handler.

use std::{collections::HashMap, sync::Arc, time::Duration};

use humantime::parse_duration;
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    policy::{RoleEntry, ROLE_PREFIX},
    SshBackend, SshBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const ROLE_HELP: &str = r#"
Manage roles. A role configures *what kind of certificate the engine
will sign*: which usernames may appear in `valid principals`, what
critical options and extensions are allowed, and the default / max
TTL. Name must match `\w[\w-]*\w`.
"#;

const ROLES_LIST_HELP: &str = "List all configured roles.";

impl SshBackend {
    pub fn roles_path(&self) -> Path {
        let read_handler = self.inner.clone();
        let write_handler = self.inner.clone();
        let delete_handler = self.inner.clone();

        new_path!({
            pattern: r"roles/(?P<name>\w[\w-]*\w)",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Role name." },
                "key_type": { field_type: FieldType::Str, default: "ca", description: "Mode marker. Phase 1: only `ca`." },
                "algorithm_signer": { field_type: FieldType::Str, default: "ssh-ed25519", description: "Signing algorithm. Phase 1: only `ssh-ed25519`." },
                "cert_type": { field_type: FieldType::Str, default: "user", description: "`user` or `host`." },
                "allowed_users": { field_type: FieldType::Str, default: "", description: "Comma-separated principals. `*` = any." },
                "default_user": { field_type: FieldType::Str, default: "", description: "Username used when the caller omits `valid_principals`." },
                "allowed_extensions": { field_type: FieldType::Str, default: "", description: "Comma-separated whitelist of caller-requestable extensions." },
                "default_extensions": { field_type: FieldType::Map, default: "", description: "Always-on extensions." },
                "allowed_critical_options": { field_type: FieldType::Str, default: "", description: "Comma-separated whitelist of caller-requestable critical options." },
                "default_critical_options": { field_type: FieldType::Map, default: "", description: "Always-on critical options." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Default validity (e.g. `30m`)." },
                "max_ttl": { field_type: FieldType::Str, default: "", description: "Hard cap on per-call TTL." },
                "not_before_duration": { field_type: FieldType::Str, default: "", description: "Backdate seconds applied to `valid_after` for clock skew." },
                "key_id_format": { field_type: FieldType::Str, default: "", description: "Template for the cert's `key id` field." },
                "cidr_list": { field_type: FieldType::Str, default: "", description: "OTP mode: comma-separated CIDRs the OTP is valid for." },
                "exclude_cidr_list": { field_type: FieldType::Str, default: "", description: "OTP mode: CIDRs to subtract from `cidr_list`." },
                "port": { field_type: FieldType::Int, default: 22, description: "OTP mode: default SSH port surfaced to the helper / UI." },
                "pqc_only": { field_type: FieldType::Bool, default: false, description: "PQC mode: reject sign requests where the client key is classical, even if the CA is PQC. Forces an end-to-end PQC chain." }
            },
            operations: [
                {op: Operation::Read, handler: read_handler.handle_role_read},
                {op: Operation::Write, handler: write_handler.handle_role_write},
                {op: Operation::Delete, handler: delete_handler.handle_role_delete}
            ],
            help: ROLE_HELP
        })
    }

    pub fn roles_list_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"roles/?$",
            operations: [
                {op: Operation::List, handler: h.handle_roles_list}
            ],
            help: ROLES_LIST_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl SshBackendInner {
    pub async fn get_role(
        &self,
        req: &Request,
        name: &str,
    ) -> Result<Option<RoleEntry>, RvError> {
        let key = format!("{ROLE_PREFIX}{name}");
        match req.storage_get(&key).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn handle_role_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        match self.get_role(req, &name).await? {
            Some(role) => {
                let data = serde_json::to_value(&role)?
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_role_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();

        // Start from the existing role on update, defaults on create.
        // This preserves fields the caller didn't supply on a partial
        // update (matches Vault's behaviour).
        let mut role = self.get_role(req, &name).await?.unwrap_or_default();

        if let Ok(v) = req.get_data("key_type") {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    role.key_type = s.to_string();
                }
            }
        }
        // Phases 1 + 2 implement `ca` and `otp`. Anything else is
        // typo-or-future and gets rejected at write time so a typoed
        // `key_type` doesn't silently behave like "ca".
        if role.key_type != "ca" && role.key_type != "otp" {
            return Err(RvError::ErrString(format!(
                "key_type must be `ca` or `otp`, got `{}`",
                role.key_type
            )));
        }

        if let Ok(v) = req.get_data("algorithm_signer") {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    role.algorithm_signer = s.to_string();
                }
            }
        }
        if let Ok(v) = req.get_data("cert_type") {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    role.cert_type = s.to_string();
                }
            }
        }
        if role.cert_type != "user" && role.cert_type != "host" {
            return Err(RvError::ErrString(format!(
                "cert_type must be `user` or `host`, got `{}`",
                role.cert_type
            )));
        }

        for (key, target) in [
            ("allowed_users", &mut role.allowed_users),
            ("default_user", &mut role.default_user),
            ("allowed_extensions", &mut role.allowed_extensions),
            ("allowed_critical_options", &mut role.allowed_critical_options),
            ("key_id_format", &mut role.key_id_format),
        ] {
            if let Ok(v) = req.get_data(key) {
                if let Some(s) = v.as_str() {
                    *target = s.to_string();
                }
            }
        }

        // Map-valued fields. The field framework decodes `Map`
        // descriptors into `Value::Object`; anything else (e.g. the
        // operator passes a JSON string) we treat as "leave alone".
        for (key, target) in [
            ("default_extensions", &mut role.default_extensions),
            ("default_critical_options", &mut role.default_critical_options),
        ] {
            if let Ok(v) = req.get_data(key) {
                if let Value::Object(obj) = v {
                    target.clear();
                    for (k, val) in obj {
                        if let Some(s) = val.as_str() {
                            target.insert(k, s.to_string());
                        }
                    }
                }
            }
        }

        // Duration fields. Empty string preserves the existing value
        // (the field default is `""`, so a partial update doesn't
        // wipe a previously-set TTL by accident).
        if let Some(d) = parse_duration_field(req, "ttl")? {
            role.ttl = d;
        }
        if let Some(d) = parse_duration_field(req, "max_ttl")? {
            role.max_ttl = d;
        }
        if let Some(d) = parse_duration_field(req, "not_before_duration")? {
            role.not_before_duration = d;
        }

        // OTP-mode fields. `cidr_list` / `exclude_cidr_list` get
        // validated here so an operator who mistypes a CIDR finds out
        // at role-create time, not at the first `creds` call.
        for (key, target) in [
            ("cidr_list", &mut role.cidr_list),
            ("exclude_cidr_list", &mut role.exclude_cidr_list),
        ] {
            if let Ok(v) = req.get_data(key) {
                if let Some(s) = v.as_str() {
                    for piece in s.split(',') {
                        let p = piece.trim();
                        if p.is_empty() { continue; }
                        if p.parse::<ipnetwork::IpNetwork>().is_err() {
                            return Err(RvError::ErrString(format!(
                                "{key}: `{p}` is not a valid CIDR (e.g. `10.0.0.0/24`)"
                            )));
                        }
                    }
                    *target = s.to_string();
                }
            }
        }
        if let Ok(v) = req.get_data("port") {
            if let Some(n) = v.as_i64() {
                if !(1..=65_535).contains(&n) {
                    return Err(RvError::ErrString(format!(
                        "port must be 1..=65535, got {n}"
                    )));
                }
                role.port = n as u16;
            }
        }

        if let Ok(v) = req.get_data("pqc_only") {
            if let Some(b) = v.as_bool() {
                role.pqc_only = b;
            }
        }

        // OTP roles need at least one allowed CIDR — refusing the
        // write here surfaces the misconfiguration immediately rather
        // than rejecting every `creds` call later with a less
        // actionable "ip not allowed" error.
        if role.key_type == "otp" && role.cidr_list.trim().is_empty() {
            return Err(RvError::ErrString(
                "otp roles require a non-empty cidr_list".into(),
            ));
        }

        // Persist.
        let bytes = serde_json::to_vec(&role)?;
        req.storage_put(&StorageEntry {
            key: format!("{ROLE_PREFIX}{name}"),
            value: bytes,
        })
        .await?;
        Ok(None)
    }

    pub async fn handle_role_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        req.storage_delete(&format!("{ROLE_PREFIX}{name}")).await?;
        Ok(None)
    }

    pub async fn handle_roles_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list(ROLE_PREFIX).await?;
        Ok(Some(Response::list_response(&keys)))
    }
}

/// Read a duration-string field. Empty / missing returns `Ok(None)`
/// so the caller leaves the existing value untouched. Invalid syntax
/// returns a per-field error (mirroring the PKI engine's pattern, so
/// operator-typed `30m` vs. `30` doesn't fail with a generic message).
fn parse_duration_field(req: &Request, key: &str) -> Result<Option<Duration>, RvError> {
    let v = match req.get_data(key) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let s = v.as_str().unwrap_or("");
    if s.trim().is_empty() {
        return Ok(None);
    }
    match parse_duration(s) {
        Ok(d) => Ok(Some(d)),
        Err(e) => Err(RvError::ErrString(format!(
            "{key}: '{s}' is not a valid duration ({e}); use a unit suffix like '30m' or '1h'"
        ))),
    }
}
