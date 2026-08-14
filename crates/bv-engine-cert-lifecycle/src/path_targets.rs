//! Target inventory CRUD — Phase L5.
//!
//! - `LIST   /v1/cert-lifecycle/targets`         → `{"keys": [<name>, ...]}`
//! - `READ   /v1/cert-lifecycle/targets/<name>`  → Target JSON
//! - `WRITE  /v1/cert-lifecycle/targets/<name>`  → upsert
//! - `DELETE /v1/cert-lifecycle/targets/<name>`  → remove (also clears state)

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    storage::{self, KeyPolicy, Target, TargetKind},
    CertLifecycleBackend, CertLifecycleBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl CertLifecycleBackend {
    pub fn targets_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"targets/?$",
            operations: [{op: Operation::List, handler: r.list_targets}],
            help: "List managed cert-lifecycle target names."
        })
    }

    pub fn target_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        let rd = self.inner.clone();
        new_path!({
            pattern: r"targets/(?P<name>\w[\w-]*\w)$",
            fields: {
                "name":         { field_type: FieldType::Str, required: true, description: "Target name." },
                "kind":         { field_type: FieldType::Str, default: "file", description: "Consumer kind (`file` only in Phase L5)." },
                "address":      { field_type: FieldType::Str, default: "", description: "For kind=file, an existing directory the renewer writes cert.pem / key.pem / chain.pem into." },
                "pki_mount":    { field_type: FieldType::Str, default: "pki", description: "PKI mount path the renewer calls into." },
                "role_ref":     { field_type: FieldType::Str, default: "", description: "Role name on the PKI mount." },
                "common_name":  { field_type: FieldType::Str, default: "", description: "CN to request at issuance." },
                "alt_names":    { field_type: FieldType::CommaStringSlice, default: "", description: "Comma-separated DNS SANs." },
                "ip_sans":      { field_type: FieldType::CommaStringSlice, default: "", description: "Comma-separated IP SANs." },
                "ttl":          { field_type: FieldType::Str, default: "", description: "Optional cert TTL (duration string). Empty = role default." },
                "key_policy":   { field_type: FieldType::Str, default: "rotate", description: "rotate | reuse | agent-generates." },
                "key_ref":      { field_type: FieldType::Str, default: "", description: "Managed key ID/name when key_policy=reuse." },
                "renew_before": { field_type: FieldType::Str, default: "168h", description: "How long before NotAfter the L6 scheduler should renew." }
            },
            operations: [
                {op: Operation::Read,   handler: rr.read_target},
                {op: Operation::Write,  handler: rw.write_target},
                {op: Operation::Delete, handler: rd.delete_target}
            ],
            help: "Manage a cert-lifecycle target."
        })
    }
}

#[maybe_async::maybe_async]
impl CertLifecycleBackendInner {
    pub async fn list_targets(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let names = req.storage_list("targets/").await?;
        Ok(Some(Response::list_response(&names)))
    }

    pub async fn read_target(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = require_name(req)?;
        let entry: Option<Target> = storage::get_json(req, &storage::target_storage_key(&name)).await?;
        match entry {
            Some(t) => Ok(Some(Response::data_response(target_to_data(&t).into()))),
            None => Ok(None),
        }
    }

    pub async fn write_target(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = require_name(req)?;
        let kind_raw = req.get_data_or_default("kind")?.as_str().unwrap_or("file").to_string();
        let kind = TargetKind::from_str(&kind_raw)?;
        let address = req.get_data_or_default("address")?.as_str().unwrap_or("").to_string();
        let pki_mount = {
            let v = req.get_data_or_default("pki_mount")?.as_str().unwrap_or("").to_string();
            if v.is_empty() { "pki".to_string() } else { v }
        };
        let role_ref = req.get_data_or_default("role_ref")?.as_str().unwrap_or("").to_string();
        let common_name = req.get_data_or_default("common_name")?.as_str().unwrap_or("").to_string();
        let alt_names = req
            .get_data_or_default("alt_names")?
            .as_comma_string_slice()
            .unwrap_or_default();
        let ip_sans = req
            .get_data_or_default("ip_sans")?
            .as_comma_string_slice()
            .unwrap_or_default();
        let ttl = req.get_data_or_default("ttl")?.as_str().unwrap_or("").to_string();
        let key_policy_raw = req
            .get_data_or_default("key_policy")?
            .as_str()
            .unwrap_or("rotate")
            .to_string();
        let key_policy = KeyPolicy::from_str(&key_policy_raw)?;
        let key_ref = req.get_data_or_default("key_ref")?.as_str().unwrap_or("").to_string();
        let renew_before = {
            let v = req.get_data_or_default("renew_before")?.as_str().unwrap_or("").to_string();
            if v.is_empty() { "168h".to_string() } else { v }
        };

        // Up-front sanity checks. These produce clear errors at write
        // time rather than a confusing failure mid-renew.
        if role_ref.is_empty() {
            return Err(RvError::ErrString("cert-lifecycle: `role_ref` is required".into()));
        }
        if common_name.is_empty() {
            return Err(RvError::ErrString("cert-lifecycle: `common_name` is required".into()));
        }
        if address.is_empty() {
            return Err(RvError::ErrString(format!(
                "cert-lifecycle: `address` is required for kind={} (file: existing directory; http-push: http(s) URL)",
                kind.as_str(),
            )));
        }
        if matches!(kind, TargetKind::HttpPush)
            && !(address.starts_with("http://") || address.starts_with("https://"))
        {
            return Err(RvError::ErrString(
                "cert-lifecycle: kind=http-push requires `address` to be an http(s) URL".into(),
            ));
        }
        if matches!(key_policy, KeyPolicy::Reuse) && key_ref.is_empty() {
            return Err(RvError::ErrString(
                "cert-lifecycle: `key_ref` is required when key_policy=reuse".into(),
            ));
        }
        if matches!(key_policy, KeyPolicy::AgentGenerates) {
            return Err(RvError::ErrString(
                "cert-lifecycle: key_policy=agent-generates is not implemented in Phase L5".into(),
            ));
        }

        // Preserve `created_at_unix` on update; first write gets a
        // fresh timestamp.
        let created_at_unix = match storage::get_json::<Target>(
            req,
            &storage::target_storage_key(&name),
        )
        .await?
        {
            Some(existing) => existing.created_at_unix,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        let target = Target {
            name: name.clone(),
            kind,
            address,
            pki_mount,
            role_ref,
            common_name,
            alt_names,
            ip_sans,
            ttl,
            key_policy,
            key_ref,
            renew_before,
            created_at_unix,
        };
        storage::put_json(req, &storage::target_storage_key(&name), &target).await?;
        Ok(None)
    }

    pub async fn delete_target(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = require_name(req)?;
        // Remove both the inventory entry and any persisted state so
        // a re-creation starts from a clean slate.
        req.storage_delete(&storage::target_storage_key(&name)).await?;
        let _ = req.storage_delete(&storage::state_storage_key(&name)).await;
        Ok(None)
    }
}

fn require_name(req: &Request) -> Result<String, RvError> {
    let name = req
        .get_data("name")?
        .as_str()
        .ok_or(RvError::ErrRequestFieldInvalid)?
        .to_string();
    if name.is_empty() {
        return Err(RvError::ErrRequestNoDataField);
    }
    Ok(name)
}

pub(super) fn target_to_data(target: &Target) -> Map<String, Value> {
    let mut data: Map<String, Value> = Map::new();
    data.insert("name".into(), json!(target.name));
    data.insert("kind".into(), json!(target.kind.as_str()));
    data.insert("address".into(), json!(target.address));
    data.insert("pki_mount".into(), json!(target.pki_mount));
    data.insert("role_ref".into(), json!(target.role_ref));
    data.insert("common_name".into(), json!(target.common_name));
    data.insert("alt_names".into(), json!(target.alt_names));
    data.insert("ip_sans".into(), json!(target.ip_sans));
    if !target.ttl.is_empty() {
        data.insert("ttl".into(), json!(target.ttl));
    }
    data.insert("key_policy".into(), json!(target.key_policy.as_str()));
    if !target.key_ref.is_empty() {
        data.insert("key_ref".into(), json!(target.key_ref));
    }
    data.insert("renew_before".into(), json!(target.renew_before));
    data.insert("created_at".into(), json!(target.created_at_unix));
    data
}
