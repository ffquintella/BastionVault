//! `READ` / `WRITE /v1/cert-lifecycle/scheduler/config` — Phase L6.
//!
//! The scheduler is opt-in per mount. Reading the config returns the
//! stored values minus `client_token`; the token is write-only over
//! the API surface so it isn't echoed back to lower-privileged
//! readers. To rotate, write a new value (empty string clears it).

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    storage::{self, SchedulerConfig, KEY_SCHEDULER_CONFIG},
    CertLifecycleBackend, CertLifecycleBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl CertLifecycleBackend {
    pub fn scheduler_config_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"scheduler/config$",
            fields: {
                "enabled":              { field_type: FieldType::Bool, default: false, description: "Whether the scheduler is active for this mount." },
                "tick_interval_seconds":{ field_type: FieldType::Int,  default: 30,    description: "How often the scheduler ticks (clamped to >= 30s at runtime)." },
                "client_token":         { field_type: FieldType::Str,  default: "",    description: "Token the scheduler dispatches PKI calls under. Empty disables." },
                "base_backoff_seconds": { field_type: FieldType::Int,  default: 60,    description: "First backoff after a failure (seconds)." },
                "max_backoff_seconds":  { field_type: FieldType::Int,  default: 3600,  description: "Cap on the doubled backoff (seconds)." }
            },
            operations: [
                {op: Operation::Read,  handler: rr.read_scheduler_config},
                {op: Operation::Write, handler: rw.write_scheduler_config}
            ],
            help: "Read or update the cert-lifecycle scheduler config for this mount."
        })
    }
}

#[maybe_async::maybe_async]
impl CertLifecycleBackendInner {
    pub async fn read_scheduler_config(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg: SchedulerConfig =
            storage::get_json(req, KEY_SCHEDULER_CONFIG).await?.unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("enabled".into(), json!(cfg.enabled));
        data.insert("tick_interval_seconds".into(), json!(cfg.tick_interval_seconds));
        // The token itself is *not* returned. We surface only whether
        // it has been configured so an operator can audit the
        // scheduler's readiness without leaking the credential.
        data.insert("client_token_set".into(), json!(!cfg.client_token.is_empty()));
        data.insert("base_backoff_seconds".into(), json!(cfg.base_backoff_seconds));
        data.insert("max_backoff_seconds".into(), json!(cfg.max_backoff_seconds));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_scheduler_config(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let existing: SchedulerConfig =
            storage::get_json(req, KEY_SCHEDULER_CONFIG).await?.unwrap_or_default();

        let enabled = req
            .get_data_or_default("enabled")?
            .as_bool()
            .unwrap_or(existing.enabled);
        let tick_interval_seconds = req
            .get_data_or_default("tick_interval_seconds")?
            .as_u64()
            .unwrap_or(existing.tick_interval_seconds);
        // `client_token` is a write-only field: missing in the request
        // body means "preserve". An explicit empty string clears it.
        let client_token = match req.get_data("client_token").ok().and_then(|v| v.as_str().map(|s| s.to_string())) {
            Some(s) => s,
            None => existing.client_token.clone(),
        };
        let base_backoff_seconds = req
            .get_data_or_default("base_backoff_seconds")?
            .as_u64()
            .unwrap_or(existing.base_backoff_seconds);
        let max_backoff_seconds = req
            .get_data_or_default("max_backoff_seconds")?
            .as_u64()
            .unwrap_or(existing.max_backoff_seconds);

        if enabled && client_token.is_empty() {
            return Err(RvError::ErrString(
                "cert-lifecycle/scheduler: enabled=true requires a non-empty client_token".into(),
            ));
        }

        let cfg = SchedulerConfig {
            enabled,
            tick_interval_seconds: tick_interval_seconds.max(30),
            client_token,
            base_backoff_seconds: base_backoff_seconds.max(1),
            max_backoff_seconds: max_backoff_seconds.max(1),
        };
        storage::put_json(req, KEY_SCHEDULER_CONFIG, &cfg).await?;
        Ok(None)
    }
}
