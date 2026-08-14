//! `READ /v1/cert-lifecycle/state/<name>` — Phase L5.
//!
//! Returns the renewer's bookkeeping for a target: most-recent serial,
//! NotAfter, last attempt timestamps, last error. Useful both for
//! operators verifying a target is healthy and for the future
//! scheduler (L6) deciding when to fire next.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    storage::{self, TargetState},
    CertLifecycleBackend, CertLifecycleBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl CertLifecycleBackend {
    pub fn target_state_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"state/(?P<name>\w[\w-]*\w)$",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Target name." }
            },
            operations: [{op: Operation::Read, handler: r.read_state}],
            help: "Read the renewer's state for a target."
        })
    }
}

#[maybe_async::maybe_async]
impl CertLifecycleBackendInner {
    pub async fn read_state(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let state: TargetState = storage::get_json(req, &storage::state_storage_key(&name))
            .await?
            .unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("name".into(), json!(name));
        data.insert("current_serial".into(), json!(state.current_serial));
        data.insert("current_not_after".into(), json!(state.current_not_after_unix));
        data.insert("last_renewal".into(), json!(state.last_renewal_unix));
        data.insert("last_attempt".into(), json!(state.last_attempt_unix));
        data.insert("last_error".into(), json!(state.last_error));
        data.insert("next_attempt".into(), json!(state.next_attempt_unix));
        data.insert("failure_count".into(), json!(state.failure_count));
        Ok(Some(Response::data_response(Some(data))))
    }
}
