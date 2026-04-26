//! `pki/config/{ca,urls,crl}`.
//!
//! `config/ca` (POST a CA cert + private key bundle) is exposed as a stub for
//! Phase 1 — the operator-facing flow today is `root/generate/internal`.
//! Lifecycle import lands with the intermediate / set-signed work in Phase 2.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    storage::{self, CrlConfig, UrlsConfig, KEY_CONFIG_CRL, KEY_CONFIG_URLS},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn config_ca_stub(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"config/ca$",
            operations: [{op: Operation::Write, handler: r.unsupported}],
            help: "(Phase 2) Import an externally generated CA bundle."
        })
    }

    pub fn config_urls_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"config/urls$",
            fields: {
                "issuing_certificates": { field_type: FieldType::CommaStringSlice, default: "", description: "AIA issuing-cert URLs." },
                "crl_distribution_points": { field_type: FieldType::CommaStringSlice, default: "", description: "CRL DP URLs." },
                "ocsp_servers": { field_type: FieldType::CommaStringSlice, default: "", description: "OCSP responder URLs." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_config_urls},
                {op: Operation::Write, handler: rw.write_config_urls}
            ],
            help: "Configure issuer URLs embedded in issued certs."
        })
    }

    pub fn config_crl_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"config/crl$",
            fields: {
                "expiry": { field_type: FieldType::Str, default: "72h", description: "CRL next_update window (e.g. 72h)." },
                "disable": { field_type: FieldType::Bool, default: false, description: "Disable CRL generation." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_config_crl},
                {op: Operation::Write, handler: rw.write_config_crl}
            ],
            help: "Configure CRL behaviour."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn read_config_urls(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg: UrlsConfig = storage::get_json(req, KEY_CONFIG_URLS).await?.unwrap_or_default();
        let data = serde_json::to_value(&cfg)?;
        Ok(Some(Response::data_response(data.as_object().cloned())))
    }

    pub async fn write_config_urls(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg = UrlsConfig {
            issuing_certificates: req.get_data_or_default("issuing_certificates")?
                .as_comma_string_slice().unwrap_or_default(),
            crl_distribution_points: req.get_data_or_default("crl_distribution_points")?
                .as_comma_string_slice().unwrap_or_default(),
            ocsp_servers: req.get_data_or_default("ocsp_servers")?
                .as_comma_string_slice().unwrap_or_default(),
        };
        storage::put_json(req, KEY_CONFIG_URLS, &cfg).await?;
        Ok(None)
    }

    pub async fn read_config_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg: CrlConfig = storage::get_json(req, KEY_CONFIG_CRL).await?.unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("expiry".into(), json!(format!("{}s", cfg.expiry_seconds)));
        data.insert("disable".into(), json!(cfg.disable));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_config_crl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let expiry_str = req.get_data_or_default("expiry")?.as_str().unwrap_or("72h").to_string();
        let expiry = humantime::parse_duration(&expiry_str).map_err(|_| RvError::ErrRequestFieldInvalid)?;
        let disable = req.get_data_or_default("disable")?.as_bool().unwrap_or(false);
        let cfg = CrlConfig { expiry_seconds: expiry.as_secs(), disable };
        storage::put_json(req, KEY_CONFIG_CRL, &cfg).await?;
        Ok(None)
    }
}
