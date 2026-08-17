//! `/v1/totp/code/:name` — generate-mode `GET` and provider-mode `POST` (validate).
//!
//! Per Vault parity: a generate-mode key serves codes via `GET`, while
//! a provider-mode key validates a caller-supplied code via `POST`.
//! Calling the wrong verb on the wrong mode is a clear error rather
//! than a no-op so an integration mistake surfaces at the first call.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    backend::{code_hash, UsedEntry},
    crypto::{ct_eq, hotp, step_for, totp},
    TotpBackend, TotpBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const CODE_HELP: &str = r#"
TOTP code endpoint.

  * GET /v1/totp/code/:name  — generate-mode keys: return the current
    6/8-digit code.
  * POST /v1/totp/code/:name {"code":"…"} — provider-mode keys:
    validate a caller-supplied code, return {"valid": bool}.
"#;

impl TotpBackend {
    pub fn code_path(&self) -> Path {
        let read_handler = self.inner.clone();
        let write_handler = self.inner.clone();

        new_path!({
            pattern: r"code/(?P<name>\w[\w-]*\w)",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Key name." },
                "code": { field_type: FieldType::Str, default: "", description: "Code to validate (provider-mode POST only)." }
            },
            operations: [
                {op: Operation::Read,  handler: read_handler.handle_code_read},
                {op: Operation::Write, handler: write_handler.handle_code_write}
            ],
            help: CODE_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TotpBackendInner {
    pub async fn handle_code_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let policy = self
            .get_key(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown totp key `{name}`")))?;

        if !policy.generate {
            return Err(RvError::ErrString(
                "this key is provider-mode; POST a `code` to validate, not GET".into(),
            ));
        }

        let now = unix_now()?;
        let code = totp(&policy.key, now, policy.algorithm, policy.digits, policy.period);
        let mut data = Map::new();
        data.insert("code".into(), Value::String(code));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_code_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let candidate = req
            .get_data("code")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if candidate.is_empty() {
            return Err(RvError::ErrString("`code` is required".into()));
        }

        let policy = self
            .get_key(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown totp key `{name}`")))?;

        if policy.generate {
            return Err(RvError::ErrString(
                "this key is generate-mode; GET the code, do not POST".into(),
            ));
        }

        let now = unix_now()?;
        let centre = step_for(now, policy.period);

        // Try centre, then ±1, ±2, … up to ±skew. The order doesn't
        // affect correctness (constant-time compare) but starting at
        // the centre means the typical fresh-code path returns
        // earliest.
        let mut matched_step: Option<u64> = None;
        for off in 0..=policy.skew as i64 {
            for sign in if off == 0 { &[0i64][..] } else { &[-1i64, 1][..] } {
                let step = centre as i64 + sign * off;
                if step < 0 {
                    continue;
                }
                let step = step as u64;
                let expect = hotp(&policy.key, step, policy.algorithm, policy.digits);
                if ct_eq(&expect, &candidate) {
                    matched_step = Some(step);
                    break;
                }
            }
            if matched_step.is_some() {
                break;
            }
        }

        let mut data = Map::new();
        let valid = match matched_step {
            None => false,
            Some(step) => {
                if policy.replay_check {
                    if self.get_used(req, &name, step).await?.is_some() {
                        // Same step+code presented before; reject.
                        false
                    } else {
                        let entry = UsedEntry {
                            step,
                            code_hash: code_hash(&candidate),
                            written_at: now,
                        };
                        self.put_used(req, &name, &entry).await?;
                        // Opportunistic sweep keeps the index bounded
                        // without an explicit tidy endpoint.
                        let _ = self.sweep_key_replay(req, &name, &policy, now).await;
                        true
                    }
                } else {
                    true
                }
            }
        };
        data.insert("valid".into(), Value::Bool(valid));
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn unix_now() -> Result<u64, RvError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| RvError::ErrString(format!("system clock pre-epoch: {e}")))
}
