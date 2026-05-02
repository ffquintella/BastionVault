//! `WRITE /v1/cert-lifecycle/renew/<name>` — Phase L5.
//!
//! Manual renewal: load the target, dispatch an `pki/issue/<role>`
//! call into the configured PKI mount via `Core::handle_request`,
//! deliver the resulting cert / key / chain to the target's address,
//! and update the target's state.
//!
//! Failures are recorded in `state.last_error` and a
//! `state.failure_count` counter so the operator (and the L6
//! scheduler) can see a target is unhealthy without having to inspect
//! logs. On success the failure counter resets to 0.
//!
//! Phase L5 supports `kind = file`. Other kinds reject at write-time
//! in `path_targets`, so the renew handler can assume File here.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};
use x509_parser::prelude::FromDer;

use super::{
    delivery::{registry_key_for, CertBundle, DeliveryReceipt},
    storage::{self, KeyPolicy, Target, TargetState},
    CertLifecycleBackend, CertLifecycleBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl CertLifecycleBackend {
    pub fn renew_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"renew/(?P<name>\w[\w-]*\w)$",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Target name." }
            },
            operations: [{op: Operation::Write, handler: r.renew_target}],
            help: "Trigger a renewal for the named target."
        })
    }
}

#[maybe_async::maybe_async]
impl CertLifecycleBackendInner {
    pub async fn renew_target(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();

        let target: Target = storage::get_json(req, &storage::target_storage_key(&name))
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!("cert-lifecycle: target `{name}` not found"))
            })?;

        // Snapshot the calling token; the sub-request inherits it so the
        // PKI mount enforces the same policy boundary.
        let token = req.client_token.clone();
        let now = unix_now();

        // Carry forward the existing state for the failure-count
        // counter and to preserve `current_*` if the renewal fails.
        let mut state: TargetState =
            storage::get_json(req, &storage::state_storage_key(&name)).await?.unwrap_or_default();
        state.last_attempt_unix = now;

        let outcome = match perform_renewal(self, &target, &token).await {
            Ok(issued) => match deliver(self, &target, &issued) {
                Ok(receipt) => {
                    state.current_serial = issued.serial.clone();
                    state.current_not_after_unix = issued.not_after_unix;
                    state.last_renewal_unix = now;
                    state.last_error.clear();
                    state.failure_count = 0;
                    Ok((issued, receipt))
                }
                Err(e) => Err(format!("delivery failed: {e}")),
            },
            Err(e) => Err(format!("issuance failed: {e}")),
        };

        match outcome {
            Ok((issued, receipt)) => {
                storage::put_json(req, &storage::state_storage_key(&name), &state).await?;
                let mut data: Map<String, Value> = Map::new();
                data.insert("name".into(), json!(name));
                data.insert("serial_number".into(), json!(issued.serial));
                data.insert("not_after".into(), json!(issued.not_after_unix));
                data.insert("delivered_to".into(), json!(receipt.destination));
                data.insert("delivery_kind".into(), json!(target.kind.as_str()));
                if !receipt.note.is_empty() {
                    data.insert("delivery_note".into(), json!(receipt.note));
                }
                Ok(Some(Response::data_response(Some(data))))
            }
            Err(msg) => {
                state.last_error = msg.clone();
                state.failure_count = state.failure_count.saturating_add(1);
                storage::put_json(req, &storage::state_storage_key(&name), &state).await?;
                Err(RvError::ErrString(format!(
                    "cert-lifecycle: renew of `{name}` failed: {msg}"
                )))
            }
        }
    }
}

/// What [`perform_renewal`] hands back on success — the materialised
/// cert + key the renewer needs to deliver, plus the metadata recorded
/// in `TargetState`.
struct RenewedCert {
    certificate_pem: String,
    private_key_pem: String,
    chain_pems: Vec<String>,
    serial: String,
    not_after_unix: i64,
}

/// Dispatch a `pki/issue/<role>` call into the configured PKI mount and
/// return the parsed response shape.
#[maybe_async::maybe_async]
async fn perform_renewal(
    backend: &CertLifecycleBackendInner,
    target: &Target,
    token: &str,
) -> Result<RenewedCert, RvError> {
    let alt_names_csv = target.alt_names.join(",");
    let ip_sans_csv = target.ip_sans.join(",");

    let mut body: Map<String, Value> = Map::new();
    body.insert("common_name".into(), json!(target.common_name));
    if !alt_names_csv.is_empty() {
        body.insert("alt_names".into(), json!(alt_names_csv));
    }
    if !ip_sans_csv.is_empty() {
        body.insert("ip_sans".into(), json!(ip_sans_csv));
    }
    if !target.ttl.is_empty() {
        body.insert("ttl".into(), json!(target.ttl));
    }
    if matches!(target.key_policy, KeyPolicy::Reuse) {
        body.insert("key_ref".into(), json!(target.key_ref));
    }

    let mut sub_req =
        Request::new(&format!("{}/issue/{}", target.pki_mount.trim_end_matches('/'), target.role_ref));
    sub_req.operation = Operation::Write;
    sub_req.client_token = token.to_string();
    sub_req.body = Some(body);

    let resp = backend.core.handle_request(&mut sub_req).await?;
    let data = resp
        .and_then(|r| r.data)
        .ok_or_else(|| RvError::ErrString("cert-lifecycle: PKI returned empty response".into()))?;

    let certificate_pem = string_field(&data, "certificate")?;
    let private_key_pem = string_field(&data, "private_key")?;
    let serial = string_field(&data, "serial_number")?;

    let chain_pems = match data.get("ca_chain") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    };

    // Pull NotAfter directly from the cert so state stays self-
    // consistent even if the role's TTL field disagrees with what
    // got signed (e.g. clamped to issuer NotAfter in L4).
    let not_after_unix = parse_not_after(&certificate_pem)?;

    Ok(RenewedCert {
        certificate_pem,
        private_key_pem,
        chain_pems,
        serial,
        not_after_unix,
    })
}

/// Phase L7: dispatch the renewal to a registered
/// [`CertDeliveryPlugin`](super::delivery::CertDeliveryPlugin) keyed
/// by `target.kind`. Replaces the L5 hardcoded match. The registry is
/// held on `CertLifecycleBackendInner` and seeded with the engine's
/// built-in `file` + `http-push` plugins at module construction.
fn deliver(
    backend: &CertLifecycleBackendInner,
    target: &Target,
    issued: &RenewedCert,
) -> Result<DeliveryReceipt, String> {
    let key = registry_key_for(&target.kind);
    let plugin = backend
        .deliverers
        .get(key)
        .ok_or_else(|| format!("no deliverer registered for kind `{key}`"))?;
    let bundle = CertBundle {
        certificate_pem: issued.certificate_pem.clone(),
        private_key_pem: issued.private_key_pem.clone(),
        chain_pems: issued.chain_pems.clone(),
        serial: issued.serial.clone(),
    };
    plugin.deliver(target, &bundle)
}

fn string_field(data: &Map<String, Value>, key: &str) -> Result<String, RvError> {
    data.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            RvError::ErrString(format!(
                "cert-lifecycle: PKI response missing `{key}` field"
            ))
        })
}

fn parse_not_after(cert_pem: &str) -> Result<i64, RvError> {
    let der = pem::parse(cert_pem.as_bytes())
        .map_err(|e| RvError::ErrString(format!("cert-lifecycle: cert PEM parse failed: {e}")))?
        .into_contents();
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| RvError::ErrString("cert-lifecycle: cert DER parse failed".into()))?;
    Ok(parsed.tbs_certificate.validity.not_after.timestamp())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
