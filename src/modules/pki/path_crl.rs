//! `pki/crl[/pem]` and `pki/crl/rotate`.
//!
//! Phase 5.2: CRL state is per-issuer. `read_crl` and `rotate_crl` operate
//! on the *mount default* issuer; clients that need a specific issuer's
//! CRL use `pki/issuer/:ref/crl` (also added in this phase).

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    issuers,
    path_revoke::rebuild_crl_for_issuer,
    storage::{self, CrlState},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn crl_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"crl(/pem)?$",
            operations: [{op: Operation::Read, handler: r.read_crl}],
            help: "Fetch the default issuer's CRL."
        })
    }

    pub fn crl_rotate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"crl/rotate$",
            operations: [{op: Operation::Write, handler: r.rotate_crl}],
            help: "Force a CRL rebuild + crl_number bump on the default issuer."
        })
    }

    pub fn issuer_crl_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"issuer/(?P<ref>[\w\-]+)/crl(/pem)?$",
            fields: {
                "ref": { field_type: FieldType::Str, required: true, description: "Issuer ID or name." }
            },
            operations: [{op: Operation::Read, handler: r.read_issuer_crl}],
            help: "Fetch a specific issuer's CRL."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn read_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let issuer = issuers::load_default_issuer(req).await?;
        crl_response(req, &issuer).await
    }

    pub async fn read_issuer_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let reference = req.get_data("ref")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let issuer = issuers::load_issuer(req, &reference).await?;
        crl_response(req, &issuer).await
    }

    pub async fn rotate_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let issuer = issuers::load_default_issuer(req).await?;
        let crl_state_key = storage::issuer_crl_state_key(&issuer.id);
        let mut state: CrlState = storage::get_json(req, &crl_state_key).await?.unwrap_or_default();
        state.crl_number = state.crl_number.saturating_add(1);
        storage::put_json(req, &crl_state_key, &state).await?;
        let pem = rebuild_crl_for_issuer(req, &issuer).await?;
        let mut data: Map<String, Value> = Map::new();
        data.insert("crl".into(), json!(pem));
        data.insert("crl_number".into(), json!(state.crl_number));
        data.insert("issuer_id".into(), json!(issuer.id));
        Ok(Some(Response::data_response(Some(data))))
    }
}

#[maybe_async::maybe_async]
async fn crl_response(req: &Request, issuer: &super::issuers::IssuerHandle) -> Result<Option<Response>, RvError> {
    let cached_key = storage::issuer_crl_cached_key(&issuer.id);
    let pem = match storage::get_string(req, &cached_key).await? {
        Some(p) => p,
        None => rebuild_crl_for_issuer(req, issuer).await?,
    };
    let mut data: Map<String, Value> = Map::new();
    data.insert("crl".into(), json!(pem));
    data.insert("issuer_id".into(), json!(issuer.id.clone()));
    Ok(Some(Response::data_response(Some(data))))
}
