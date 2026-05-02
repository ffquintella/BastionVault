//! Routes for the multi-issuer registry — Phase 5.2.
//!
//! - `LIST   /v1/pki/issuers` → `{"keys": [<id>, ...], "key_info": {<id>: {"name": ...}}}`
//! - `READ   /v1/pki/issuer/:ref` → cert + metadata for a specific issuer
//! - `WRITE  /v1/pki/issuer/:ref` → rename
//! - `DELETE /v1/pki/issuer/:ref` → remove (with default-pointer guard)
//! - `READ   /v1/pki/config/issuers` → `{"default": "<id>", "default_name": "<name>"}`
//! - `WRITE  /v1/pki/config/issuers` → set default (`{"default": "<id-or-name>"}`)

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{issuers, PkiBackend, PkiBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn issuers_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"issuers/?$",
            operations: [{op: Operation::List, handler: r.list_issuers}],
            help: "List the issuers configured on this mount."
        })
    }

    pub fn issuer_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        let rd = self.inner.clone();
        new_path!({
            pattern: r"issuer/(?P<ref>[\w\-]+)",
            fields: {
                "ref": { field_type: FieldType::Str, required: true, description: "Issuer ID (UUID) or name." },
                "issuer_name": { field_type: FieldType::Str, default: "", description: "(Write) New name for the issuer." },
                "usage": { field_type: FieldType::CommaStringSlice, default: "",
                    description: "(Write) Comma-separated list of usages this issuer is allowed: `issuing-certificates`, `crl-signing`, `ocsp-signing`. Empty = leave existing usages unchanged." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_issuer},
                {op: Operation::Write, handler: rw.write_issuer},
                {op: Operation::Delete, handler: rd.delete_issuer}
            ],
            help: "Read, rename, change usages on, or delete a specific issuer."
        })
    }

    pub fn issuer_chain_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"issuer/(?P<ref>[\w\-]+)/chain$",
            fields: {
                "ref": { field_type: FieldType::Str, required: true, description: "Issuer ID (UUID) or name." }
            },
            operations: [{op: Operation::Read, handler: r.read_issuer_chain}],
            help: "Read the issuer chain (leaf-issuer → root) for the named issuer."
        })
    }

    pub fn config_issuers_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"config/issuers$",
            fields: {
                "default": { field_type: FieldType::Str, default: "", description: "Issuer ID or name to mark as the mount default." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_config_issuers},
                {op: Operation::Write, handler: rw.write_config_issuers}
            ],
            help: "Read or update the mount's default-issuer pointer."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn list_issuers(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let index = issuers::list_issuers(req).await?;
        let cfg = issuers::read_default_pointer(req).await.unwrap_or_default();
        let keys: Vec<String> = index.by_id.keys().cloned().collect();
        let mut key_info: Map<String, Value> = Map::new();
        for (id, name) in &index.by_id {
            let mut entry: Map<String, Value> = Map::new();
            entry.insert("name".into(), json!(name));
            entry.insert("is_default".into(), json!(cfg.default_id == *id));
            key_info.insert(id.clone(), Value::Object(entry));
        }
        let mut data: Map<String, Value> = Map::new();
        data.insert("keys".into(), json!(keys));
        data.insert("key_info".into(), Value::Object(key_info));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn read_issuer_chain(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let reference = req
            .get_data("ref")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let issuer = issuers::load_issuer(req, &reference).await?;
        let chain = issuers::build_issuer_chain(req, &issuer).await?;
        let bundle: String = chain.join("");
        let mut data: Map<String, Value> = Map::new();
        data.insert("issuer_id".into(), json!(issuer.id));
        data.insert("issuer_name".into(), json!(issuer.name));
        data.insert("ca_chain".into(), json!(chain));
        data.insert("certificate_bundle".into(), json!(bundle));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn read_issuer(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let reference = req.get_data("ref")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let issuer = issuers::load_issuer(req, &reference).await?;
        let cfg = issuers::read_default_pointer(req).await.unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("issuer_id".into(), json!(issuer.id.clone()));
        data.insert("issuer_name".into(), json!(issuer.name));
        data.insert("certificate".into(), json!(issuer.cert_pem));
        data.insert("key_type".into(), json!(issuer.meta.key_type));
        data.insert("common_name".into(), json!(issuer.meta.common_name));
        data.insert("not_after".into(), json!(issuer.meta.not_after_unix));
        data.insert("ca_kind".into(), json!(format!("{:?}", issuer.meta.ca_kind).to_lowercase()));
        data.insert("is_default".into(), json!(cfg.default_id == issuer.id));
        // Phase 5.5: surface the effective usages so an operator can
        // confirm what an issuer is allowed to do.
        data.insert("usage".into(), json!(issuer.usages.to_names()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_issuer(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        use crate::logical::field::FieldTrait;
        let reference = req.get_data("ref")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let new_name = req.get_data_or_default("issuer_name")?.as_str().unwrap_or("").to_string();
        let usage_names = req
            .get_data_or_default("usage")?
            .as_comma_string_slice()
            .unwrap_or_default();

        // Empty-everything is a no-op (pure read) — error rather than
        // silently succeed so the operator knows the request did nothing.
        if new_name.is_empty() && usage_names.is_empty() {
            return Err(RvError::ErrRequestFieldInvalid);
        }
        if !new_name.is_empty() {
            issuers::rename_issuer(req, &reference, &new_name).await?;
        }
        if !usage_names.is_empty() {
            let usages = super::storage::IssuerUsages::from_names(&usage_names)
                .map_err(|_| RvError::ErrRequestFieldInvalid)?;
            issuers::set_issuer_usages(req, &reference, usages).await?;
        }
        Ok(None)
    }

    pub async fn delete_issuer(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let reference = req.get_data("ref")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        issuers::delete_issuer(req, &reference).await?;
        Ok(None)
    }

    pub async fn read_config_issuers(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = issuers::read_default_pointer(req).await.unwrap_or_default();
        let index = issuers::list_issuers(req).await.unwrap_or_default();
        let default_name = index.by_id.get(&cfg.default_id).cloned().unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("default".into(), json!(cfg.default_id));
        data.insert("default_name".into(), json!(default_name));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_config_issuers(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let target = req.get_data_or_default("default")?.as_str().unwrap_or("").to_string();
        if target.is_empty() {
            return Err(RvError::ErrRequestFieldInvalid);
        }
        issuers::set_default_pointer(req, &target).await?;
        Ok(None)
    }
}
