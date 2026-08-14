//! Per-user FIDO2 credential management (read info / delete keys).

use std::{collections::HashMap, sync::Arc};

use super::{UserPassBackend, UserPassBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl UserPassBackend {
    pub fn fido2_credentials_path(&self) -> Path {
        let ref1 = self.inner.clone();
        let ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"users/(?P<username>\w[\w-]+\w)/fido2$",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to manage FIDO2 keys for."
                }
            },
            operations: [
                {op: Operation::Read, handler: ref1.fido2_read_credentials},
                {op: Operation::Delete, handler: ref2.fido2_delete_credentials}
            ],
            help: r#"Read FIDO2 key info or remove all FIDO2 keys for a user (re-enables password login)."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    pub async fn fido2_read_credentials(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req.get_data("username")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_lowercase();

        let user_entry = self.get_user(req, &username).await?;
        match user_entry {
            Some(entry) => {
                let count = entry.get_passkeys().map(|v| v.len()).unwrap_or(0);
                let mut data = serde_json::Map::new();
                data.insert("username".into(), serde_json::Value::String(username));
                data.insert("registered_keys".into(), serde_json::Value::Number(count.into()));
                data.insert("fido2_enabled".into(), serde_json::Value::Bool(entry.fido2_enabled));
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn fido2_delete_credentials(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req.get_data("username")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_lowercase();

        let mut user_entry = match self.get_user(req, &username).await? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        user_entry.credentials_json = String::new();
        user_entry.fido2_enabled = false;
        self.set_user(req, &username, &user_entry).await?;

        // Clean up any pending challenge state
        let _ = req.storage_delete(&format!("challenge/reg/{username}")).await;
        let _ = req.storage_delete(&format!("challenge/auth/{username}")).await;

        Ok(None)
    }
}
