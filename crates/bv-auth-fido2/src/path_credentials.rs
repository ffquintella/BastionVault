//! FIDO2 credential CRUD paths.

use std::{collections::HashMap, sync::Arc};

use serde_json::Value;

use super::{Fido2Backend, Fido2BackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
    utils::token_util::token_fields,
};

use super::types::UserCredentialEntry;

impl Fido2Backend {
    pub fn credentials_path(&self) -> Path {
        let ref1 = self.inner.clone();
        let ref2 = self.inner.clone();
        let ref3 = self.inner.clone();

        let mut path = new_path!({
            pattern: r"credentials/(?P<username>\w[\w-]+\w)",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username of the credential holder."
                },
                "policies": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Comma-separated list of policies."
                },
                "ttl": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "TTL for tokens issued on login."
                },
                "max_ttl": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "Max TTL for tokens issued on login."
                }
            },
            operations: [
                {op: Operation::Read, handler: ref1.read_credential},
                {op: Operation::Write, handler: ref2.write_credential},
                {op: Operation::Delete, handler: ref3.delete_credential}
            ],
            help: r#"Manage FIDO2 user credential entries (policies, TTL). Actual key registration is done via the register/* endpoints."#
        });

        path.fields.extend(token_fields());
        path
    }

    pub fn credential_list_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"credentials/?",
            operations: [
                {op: Operation::List, handler: ref1.list_credentials}
            ],
            help: r#"List all users with registered FIDO2 credentials."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl Fido2BackendInner {
    pub async fn get_user_credentials(
        &self,
        req: &Request,
        username: &str,
    ) -> Result<Option<UserCredentialEntry>, RvError> {
        let key = format!("credential/{}", username.to_lowercase());
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let user_entry: UserCredentialEntry = serde_json::from_slice(&e.value)?;
                Ok(Some(user_entry))
            }
            None => Ok(None),
        }
    }

    pub async fn set_user_credentials(
        &self,
        req: &Request,
        username: &str,
        entry: &UserCredentialEntry,
    ) -> Result<(), RvError> {
        let key = format!("credential/{}", username.to_lowercase());
        let storage_entry = StorageEntry::new(&key, entry)?;
        req.storage_put(&storage_entry).await
    }

    pub async fn read_credential(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();

        let entry = self.get_user_credentials(req, &username).await?;
        match entry {
            Some(e) => {
                let mut data = serde_json::Map::new();
                data.insert("username".to_string(), Value::String(e.username.clone()));
                data.insert(
                    "policies".to_string(),
                    Value::String(e.policies.join(", ")),
                );
                data.insert("ttl".to_string(), Value::Number(e.ttl.as_secs().into()));
                data.insert("max_ttl".to_string(), Value::Number(e.max_ttl.as_secs().into()));

                // Count credentials without exposing key material.
                let count = e.get_passkeys().map(|v| v.len()).unwrap_or(0);
                data.insert("registered_keys".to_string(), Value::Number(count.into()));

                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn write_credential(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();

        let mut entry = self.get_user_credentials(req, &username).await?
            .unwrap_or_else(|| UserCredentialEntry {
                username: username.clone(),
                ..Default::default()
            });

        if let Ok(policies_value) = req.get_data("policies") {
            if let Some(policies_str) = policies_value.as_str() {
                entry.policies = policies_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        if let Ok(ttl_value) = req.get_data("ttl") {
            if let Some(ttl) = ttl_value.as_u64() {
                entry.ttl = std::time::Duration::from_secs(ttl);
            }
        }

        if let Ok(max_ttl_value) = req.get_data("max_ttl") {
            if let Some(max_ttl) = max_ttl_value.as_u64() {
                entry.max_ttl = std::time::Duration::from_secs(max_ttl);
            }
        }

        // Parse token_* fields from the flattened TokenParams.
        let _ = entry.parse_token_fields(req);

        self.set_user_credentials(req, &username, &entry).await?;
        Ok(None)
    }

    pub async fn delete_credential(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();
        let key = format!("credential/{}", username);
        req.storage_delete(&key).await?;
        Ok(None)
    }

    pub async fn list_credentials(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let credentials = req.storage_list("credential/").await?;
        Ok(Some(Response::list_response(&credentials)))
    }
}
