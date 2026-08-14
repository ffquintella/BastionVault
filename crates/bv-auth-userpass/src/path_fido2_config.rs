//! FIDO2 relying party configuration, stored within the userpass backend.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};

use super::{UserPassBackend, UserPassBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const FIDO2_CONFIG_KEY: &str = "fido2_config";

/// FIDO2 relying party configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fido2Config {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

impl UserPassBackend {
    pub fn fido2_config_path(&self) -> Path {
        let ref1 = self.inner.clone();
        let ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"fido2/config",
            fields: {
                "rp_id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Relying Party ID (e.g. example.com)."
                },
                "rp_origin": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Relying Party origin URL (e.g. https://example.com)."
                },
                "rp_name": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Relying Party display name."
                }
            },
            operations: [
                {op: Operation::Read, handler: ref1.fido2_read_config},
                {op: Operation::Write, handler: ref2.fido2_write_config}
            ],
            help: r#"Configure the FIDO2/WebAuthn relying party settings for this userpass mount."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    pub async fn get_fido2_config(&self, req: &Request) -> Result<Option<Fido2Config>, RvError> {
        let entry = req.storage_get(FIDO2_CONFIG_KEY).await?;
        match entry {
            Some(e) => {
                let config: Fido2Config = serde_json::from_slice(&e.value)?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    pub async fn fido2_read_config(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_fido2_config(req).await?;
        match config {
            Some(c) => {
                let data = serde_json::to_value(&c)?;
                Ok(Some(Response::data_response(data.as_object().cloned())))
            }
            None => Ok(None),
        }
    }

    pub async fn fido2_write_config(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let rp_id = req.get_data("rp_id")?.as_str().unwrap().to_string();
        let rp_origin = req.get_data("rp_origin")?.as_str().unwrap().to_string();
        let rp_name = req
            .get_data_or_default("rp_name")?
            .as_str()
            .unwrap_or("BastionVault")
            .to_string();

        let config = Fido2Config { rp_id, rp_origin, rp_name };
        let entry = StorageEntry::new(FIDO2_CONFIG_KEY, &config)?;
        req.storage_put(&entry).await?;

        Ok(None)
    }
}
