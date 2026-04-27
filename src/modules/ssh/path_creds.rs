//! `/v1/ssh/creds/:role` (mint OTP) and `/v1/ssh/verify` (consume OTP).
//!
//! Phase 2 surface — the OTP mode of the engine. The CA-mode flow
//! (Phase 1) lives in `path_sign.rs` and shares no storage with this
//! file. An operator deploying both modes side-by-side just creates
//! two roles with different `key_type` markers.
//!
//! The plaintext OTP exists in three places, and only three: the
//! response body of `creds`, the helper's `verify` request body, and
//! transient memory for the verify-time hashing. Storage stores the
//! SHA-256 only.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    otp::{generate_otp, hash_otp},
    policy::{OtpEntry, DEFAULT_OTP_TTL, OTP_PREFIX},
    SshBackend, SshBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const CREDS_HELP: &str = r#"
Mint a one-time password (OTP) for a single SSH session against the
named role. Returned `key` is the OTP; the bv-ssh-helper on the target
host POSTs it back to `/v1/ssh/verify` to authorize the login.
"#;

const VERIFY_HELP: &str = r#"
Validate and consume an OTP. Returns the role's canonical username and
target IP / port so the helper can complete the PAM dance. The OTP is
deleted on the first successful verify; subsequent calls fail.
"#;

impl SshBackend {
    pub fn creds_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"creds/(?P<role>\w[\w-]*\w)",
            fields: {
                "role": { field_type: FieldType::Str, required: true, description: "OTP role name." },
                "ip": { field_type: FieldType::Str, required: true, description: "Target host IP. Must fall in the role's `cidr_list`." },
                "username": { field_type: FieldType::Str, default: "", description: "Login username; empty falls back to the role's `default_user`." },
                "ttl": { field_type: FieldType::Str, default: "", description: "OTP validity (e.g. `2m`). Empty = engine default." }
            },
            operations: [
                {op: Operation::Write, handler: h.handle_creds}
            ],
            help: CREDS_HELP
        })
    }

    pub fn verify_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"verify",
            fields: {
                "otp": { field_type: FieldType::Str, required: true, description: "OTP returned by `creds`." }
            },
            operations: [
                {op: Operation::Write, handler: h.handle_verify}
            ],
            help: VERIFY_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl SshBackendInner {
    pub async fn handle_creds(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req
            .get_data("role")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let ip_str = req
            .get_data("ip")?
            .as_str()
            .ok_or_else(|| RvError::ErrString("ip is required".into()))?
            .to_string();
        let username_in = req
            .get_data("username")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let role = self
            .get_role(req, &role_name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown role `{role_name}`")))?;

        if role.key_type != "otp" {
            return Err(RvError::ErrString(format!(
                "role `{role_name}` is `{}`, not `otp`; use /sign for CA-mode roles",
                role.key_type
            )));
        }

        let ip: std::net::IpAddr = ip_str.parse().map_err(|e| {
            RvError::ErrString(format!("ip `{ip_str}` is not a valid IP address: {e}"))
        })?;
        if !role.ip_allowed(ip) {
            return Err(RvError::ErrString(format!(
                "ip `{ip_str}` is not in role's cidr_list (or is excluded)"
            )));
        }

        // username: caller pick, then role.default_user, else error.
        let username = if !username_in.is_empty() {
            username_in
        } else if !role.default_user.is_empty() {
            role.default_user.clone()
        } else {
            return Err(RvError::ErrString(
                "no username supplied and role has no default_user".into(),
            ));
        };

        // TTL: caller-supplied (humantime) → role.ttl → engine
        // default. Capped at role.max_ttl so an operator who set both
        // can rely on the cap actually doing something.
        let req_ttl_str = req
            .get_data("ttl")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let mut ttl = if req_ttl_str.trim().is_empty() {
            if role.ttl.is_zero() { DEFAULT_OTP_TTL } else { role.ttl }
        } else {
            humantime::parse_duration(&req_ttl_str).map_err(|e| {
                RvError::ErrString(format!(
                    "ttl: '{req_ttl_str}' is not a valid duration ({e}); use a unit suffix like '2m'"
                ))
            })?
        };
        if !role.max_ttl.is_zero() && ttl > role.max_ttl {
            ttl = role.max_ttl;
        }

        // Generate + persist (hash only).
        let (plaintext, hash_hex) = generate_otp()?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| RvError::ErrString(format!("system clock pre-epoch: {e}")))?;
        let expires_at = now.saturating_add(ttl).as_secs();

        let entry = OtpEntry {
            role: role_name.clone(),
            ip: ip_str.clone(),
            username: username.clone(),
            port: role.port,
            expires_at,
        };
        let bytes = serde_json::to_vec(&entry)?;
        req.storage_put(&StorageEntry {
            key: format!("{OTP_PREFIX}{hash_hex}"),
            value: bytes,
        })
        .await?;

        let mut data = Map::new();
        data.insert("key".into(), Value::String(plaintext));
        data.insert("key_type".into(), Value::String("otp".into()));
        data.insert("username".into(), Value::String(username));
        data.insert("ip".into(), Value::String(ip_str));
        data.insert("port".into(), Value::Number(role.port.into()));
        data.insert("ttl".into(), Value::Number(ttl.as_secs().into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_verify(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let otp = req
            .get_data("otp")?
            .as_str()
            .ok_or_else(|| RvError::ErrString("otp is required".into()))?
            .to_string();
        if otp.is_empty() {
            return Err(RvError::ErrString("otp is required".into()));
        }

        let hash_hex = hash_otp(&otp);
        let key = format!("{OTP_PREFIX}{hash_hex}");

        // Storage probe is keyed by hash, not by OTP — there is no
        // user-controlled scan loop here that an attacker could
        // time-side-channel against the corpus of live OTPs.
        let entry_bytes = match req.storage_get(&key).await? {
            Some(e) => e.value,
            None => {
                return Err(RvError::ErrString("invalid or expired otp".into()));
            }
        };
        let entry: OtpEntry = serde_json::from_slice(&entry_bytes)?;

        // Single-use: delete first, then act on the snapshot. If the
        // delete fails after a successful read we'd rather return an
        // error to the helper (which retries / refuses login) than
        // mark a still-live OTP as consumed and risk a double-use.
        req.storage_delete(&key).await?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| RvError::ErrString(format!("system clock pre-epoch: {e}")))?
            .as_secs();
        if now > entry.expires_at {
            return Err(RvError::ErrString("invalid or expired otp".into()));
        }

        let mut data = Map::new();
        data.insert("username".into(), Value::String(entry.username));
        data.insert("ip".into(), Value::String(entry.ip));
        data.insert("role_name".into(), Value::String(entry.role));
        data.insert("port".into(), Value::Number(entry.port.into()));
        Ok(Some(Response::data_response(Some(data))))
    }
}

