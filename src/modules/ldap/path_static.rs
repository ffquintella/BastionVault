//! `/v1/openldap/static-role` CRUD + `/static-cred/:name` + `/rotate-role/:name`.
//!
//! A static role binds one DN to a rotation cadence. The current
//! cleartext password is persisted at `static-cred/<name>` so
//! reads return immediately without touching the directory.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    client,
    policy::{StaticCred, StaticRole, STATIC_CRED_PREFIX, STATIC_ROLE_PREFIX},
    LdapBackend, LdapBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const ROLE_HELP: &str =
    "Static role: binds a single DN to a rotation policy. POST creates / updates; GET reads metadata; DELETE removes the role + cached credential.";
const CRED_HELP: &str = "Read the current cleartext password for the static role.";
const ROTATE_HELP: &str = "Generate a fresh password, write it to the directory, and persist as the new current credential.";
const LIST_HELP: &str = "List configured static-role names.";

impl LdapBackend {
    pub fn static_role_path(&self) -> Path {
        let read = self.inner.clone();
        let write = self.inner.clone();
        let delete = self.inner.clone();
        new_path!({
            pattern: r"static-role/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":             { field_type: FieldType::Str,  required: true, description: "Role name." },
                "dn":               { field_type: FieldType::Str,  default: "", description: "Full DN of the managed account." },
                "username":         { field_type: FieldType::Str,  default: "", description: "Short login name." },
                "rotation_period":  { field_type: FieldType::Int,  default: 0, description: "Auto-rotation cadence in seconds. 0 = manual rotation only." },
                "password_policy":  { field_type: FieldType::Str,  default: "", description: "Per-role generator override." }
            },
            operations: [
                {op: Operation::Read,   handler: read.handle_role_read},
                {op: Operation::Write,  handler: write.handle_role_write},
                {op: Operation::Delete, handler: delete.handle_role_delete}
            ],
            help: ROLE_HELP
        })
    }

    pub fn static_role_list_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"static-role/?$",
            operations: [{op: Operation::List, handler: h.handle_role_list}],
            help: LIST_HELP
        })
    }

    pub fn static_cred_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"static-cred/(?P<name>\w[\w-]*\w)",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Role name." }
            },
            operations: [{op: Operation::Read, handler: h.handle_cred_read}],
            help: CRED_HELP
        })
    }

    pub fn rotate_role_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"rotate-role/(?P<name>\w[\w-]*\w)",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Role name." }
            },
            operations: [{op: Operation::Write, handler: h.handle_rotate_role}],
            help: ROTATE_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl LdapBackendInner {
    pub async fn get_role(
        &self,
        req: &Request,
        name: &str,
    ) -> Result<Option<StaticRole>, RvError> {
        match req.storage_get(&format!("{STATIC_ROLE_PREFIX}{name}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn put_role(
        &self,
        req: &mut Request,
        name: &str,
        role: &StaticRole,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(role)?;
        req.storage_put(&StorageEntry {
            key: format!("{STATIC_ROLE_PREFIX}{name}"),
            value: bytes,
        })
        .await
    }

    pub async fn get_cred(
        &self,
        req: &Request,
        name: &str,
    ) -> Result<Option<StaticCred>, RvError> {
        match req.storage_get(&format!("{STATIC_CRED_PREFIX}{name}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn put_cred(
        &self,
        req: &mut Request,
        name: &str,
        cred: &StaticCred,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(cred)?;
        req.storage_put(&StorageEntry {
            key: format!("{STATIC_CRED_PREFIX}{name}"),
            value: bytes,
        })
        .await
    }

    pub async fn handle_role_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        match self.get_role(req, &name).await? {
            None => Ok(None),
            Some(role) => {
                let mut data = Map::new();
                data.insert("dn".into(), Value::String(role.dn));
                data.insert("username".into(), Value::String(role.username));
                data.insert(
                    "rotation_period".into(),
                    Value::Number(role.rotation_period.as_secs().into()),
                );
                data.insert("password_policy".into(), Value::String(role.password_policy));
                Ok(Some(Response::data_response(Some(data))))
            }
        }
    }

    pub async fn handle_role_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        if name.is_empty() {
            return Err(RvError::ErrString("name is required".into()));
        }
        let dn = take_str(req, "dn");
        let username = take_str(req, "username");
        if dn.is_empty() {
            return Err(RvError::ErrString("dn is required".into()));
        }
        if username.is_empty() {
            return Err(RvError::ErrString("username is required".into()));
        }
        let rotation_secs = req
            .get_data("rotation_period")
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let role = StaticRole {
            dn,
            username,
            rotation_period: std::time::Duration::from_secs(rotation_secs),
            password_policy: take_str(req, "password_policy"),
        };
        self.put_role(req, &name, &role).await?;
        Ok(None)
    }

    pub async fn handle_role_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let _ = req.storage_delete(&format!("{STATIC_ROLE_PREFIX}{name}")).await;
        let _ = req.storage_delete(&format!("{STATIC_CRED_PREFIX}{name}")).await;
        Ok(None)
    }

    pub async fn handle_role_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list(STATIC_ROLE_PREFIX).await?;
        Ok(Some(Response::list_response(&keys)))
    }

    pub async fn handle_cred_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let role = self
            .get_role(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown role `{name}`")))?;
        let cred = self
            .get_cred(req, &name)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!(
                    "role `{name}` has not been rotated yet; POST /rotate-role/{name} to mint a password"
                ))
            })?;

        let mut data = Map::new();
        data.insert("username".into(), Value::String(role.username));
        data.insert("dn".into(), Value::String(role.dn));
        data.insert("password".into(), Value::String(cred.password));
        data.insert(
            "last_vault_rotation_unix".into(),
            Value::Number(cred.last_vault_rotation_unix.into()),
        );
        let next = if role.rotation_period.is_zero() {
            None
        } else {
            let next = cred
                .last_vault_rotation_unix
                .saturating_add(role.rotation_period.as_secs());
            let now = unix_now();
            Some(next.saturating_sub(now))
        };
        if let Some(t) = next {
            data.insert("ttl_secs".into(), Value::Number(t.into()));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_rotate_role(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let role = self
            .get_role(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown role `{name}`")))?;
        let cfg = self
            .load_config(req)
            .await?
            .ok_or_else(|| RvError::ErrString("ldap engine not configured".into()))?;

        let new_password = super::password::generate(super::password::DEFAULT_LENGTH);

        // Directory-first, storage-second. If the storage write
        // fails after a successful LDAP modify, the next call will
        // surface the divergence on the next bind probe — see the
        // spec § "Rotation Atomicity".
        let mut ldap = client::bind(&cfg)
            .await
            .map_err(|e| RvError::ErrString(format!("rotate-role: bind: {e}")))?;
        client::set_password(&mut ldap, &cfg, &role.dn, &new_password)
            .await
            .map_err(|e| RvError::ErrString(format!("rotate-role: write: {e}")))?;
        let _ = ldap.unbind().await;

        let cred = StaticCred {
            password: new_password.clone(),
            last_vault_rotation_unix: unix_now(),
        };
        self.put_cred(req, &name, &cred).await?;

        let mut data = Map::new();
        data.insert("username".into(), Value::String(role.username));
        data.insert("dn".into(), Value::String(role.dn));
        data.insert("password".into(), Value::String(new_password));
        data.insert(
            "last_vault_rotation_unix".into(),
            Value::Number(cred.last_vault_rotation_unix.into()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
