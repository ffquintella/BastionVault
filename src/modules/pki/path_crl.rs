//! `pki/crl[/pem]` and `pki/crl/rotate`.
//!
//! `read_crl` returns the cached CRL when present; otherwise it rebuilds on
//! demand so a fresh mount with no revocations still returns an empty,
//! signed CRL. `rotate_crl` forces a rebuild and bumps `crl_number`.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    path_revoke::rebuild_crl,
    storage::{self, CrlState, KEY_CRL_CACHED, KEY_CRL_STATE},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Operation, Path, PathOperation, Request, Response},
    new_path, new_path_internal,
};

impl PkiBackend {
    pub fn crl_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"crl(/pem)?$",
            operations: [{op: Operation::Read, handler: r.read_crl}],
            help: "Fetch the current CRL."
        })
    }

    pub fn crl_rotate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"crl/rotate$",
            operations: [{op: Operation::Write, handler: r.rotate_crl}],
            help: "Force a CRL rebuild + crl_number bump."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn read_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let pem = match storage::get_string(req, KEY_CRL_CACHED).await? {
            Some(p) => p,
            None => rebuild_crl(req).await?,
        };
        let mut data: Map<String, Value> = Map::new();
        data.insert("crl".into(), json!(pem));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn rotate_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut state: CrlState = storage::get_json(req, KEY_CRL_STATE).await?.unwrap_or_default();
        state.crl_number = state.crl_number.saturating_add(1);
        storage::put_json(req, KEY_CRL_STATE, &state).await?;
        let pem = rebuild_crl(req).await?;
        let mut data: Map<String, Value> = Map::new();
        data.insert("crl".into(), json!(pem));
        data.insert("crl_number".into(), json!(state.crl_number));
        Ok(Some(Response::data_response(Some(data))))
    }
}
