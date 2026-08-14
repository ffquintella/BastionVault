//! FIDO2 relying party configuration path.

use std::{collections::HashMap, sync::Arc};

use super::{Fido2Backend, Fido2BackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::types::Fido2Config;

const CONFIG_KEY: &str = "config";

impl Fido2Backend {
    pub fn config_path(&self) -> Path {
        let ref1 = self.inner.clone();
        let ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"config",
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
                {op: Operation::Read, handler: ref1.read_config},
                {op: Operation::Write, handler: ref2.write_config}
            ],
            help: r#"Configure the FIDO2/WebAuthn relying party settings."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl Fido2BackendInner {
    pub async fn get_config(&self, req: &Request) -> Result<Option<Fido2Config>, RvError> {
        let entry = req.storage_get(CONFIG_KEY).await?;
        match entry {
            Some(e) => {
                let config: Fido2Config = serde_json::from_slice(&e.value)?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    pub async fn read_config(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?;
        match config {
            Some(c) => {
                let data = serde_json::to_value(&c)?;
                Ok(Some(Response::data_response(data.as_object().cloned())))
            }
            None => Ok(None),
        }
    }

    pub async fn write_config(
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
        let entry = StorageEntry::new(CONFIG_KEY, &config)?;
        req.storage_put(&entry).await?;

        Ok(None)
    }
}
