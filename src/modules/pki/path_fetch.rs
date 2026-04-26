//! `pki/cert/:serial`, `pki/ca[/pem]`, `pki/ca_chain` — read-only fetch endpoints.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    storage::{self, CertRecord, KEY_CA_CERT},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn fetch_cert_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"cert/(?P<serial>[0-9a-fA-F:\-]+)",
            fields: {
                "serial": { field_type: FieldType::Str, required: true, description: "Cert serial (hex)." }
            },
            operations: [{op: Operation::Read, handler: r.read_cert}],
            help: "Fetch a previously issued certificate by serial."
        })
    }

    pub fn fetch_ca_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"ca(/pem)?$",
            operations: [{op: Operation::Read, handler: r.read_ca}],
            help: "Fetch the active CA certificate."
        })
    }

    pub fn fetch_ca_chain_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"ca_chain$",
            operations: [{op: Operation::Read, handler: r.read_ca}],
            help: "Fetch the CA chain (Phase 1: root only)."
        })
    }

    pub fn list_certs_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"certs/?$",
            operations: [{op: Operation::List, handler: r.list_certs}],
            help: "List issued certificate serials."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn read_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let serial_raw = req.get_data("serial")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let serial_hex = normalize_serial_hex(&serial_raw);
        let key = storage::cert_storage_key(&serial_hex);
        let record: Option<CertRecord> = storage::get_json(req, &key).await?;
        let record = record.ok_or(RvError::ErrPkiCertNotFound)?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(record.certificate_pem));
        data.insert("serial_number".into(), json!(record.serial_hex));
        data.insert("issued_at".into(), json!(record.issued_at_unix));
        if let Some(t) = record.revoked_at_unix {
            data.insert("revoked_at".into(), json!(t));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn read_ca(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let pem = storage::get_string(req, KEY_CA_CERT).await?
            .ok_or(RvError::ErrPkiCaNotConfig)?;
        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(pem));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn list_certs(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list("certs/").await?;
        Ok(Some(Response::list_response(&keys)))
    }
}

fn normalize_serial_hex(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase()
}
