//! `/v1/openldap/config` CRUD + `/v1/openldap/rotate-root`.

use std::{collections::HashMap, sync::Arc};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    client,
    config::{DirectoryType, LdapConfig, TlsMinVersion, CONFIG_KEY, DEFAULT_REQUEST_TIMEOUT},
    LdapBackend, LdapBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const CONFIG_HELP: &str = r#"
Configure the connection to the directory server. One config per
mount. `bindpass` is barrier-encrypted; reads redact it. Plain
`ldap://` requires either `starttls = true` or both
`insecure_tls = true` + `acknowledge_insecure_tls = true`.
"#;

const ROTATE_ROOT_HELP: &str = r#"
Generate a fresh password, write it to the directory under the
configured `binddn`, and persist the new value as the engine's
bind password. Use this on a schedule to rotate the engine's own
service account.
"#;

impl LdapBackend {
    pub fn config_path(&self) -> Path {
        let read = self.inner.clone();
        let write = self.inner.clone();
        let delete = self.inner.clone();
        new_path!({
            pattern: r"config",
            fields: {
                "url":              { field_type: FieldType::Str,  default: "", description: "`ldap://` or `ldaps://` URL." },
                "binddn":           { field_type: FieldType::Str,  default: "", description: "DN used to authenticate." },
                "bindpass":         { field_type: FieldType::Str,  default: "", description: "Bind password (write-only on read)." },
                "userdn":           { field_type: FieldType::Str,  default: "", description: "Search base for short-name lookups." },
                "directory_type":   { field_type: FieldType::Str,  default: "openldap", description: "`openldap` (default) or `active_directory`." },
                "password_policy":  { field_type: FieldType::Str,  default: "", description: "Optional generator-policy reference. Phase 1 ignores this; the built-in policy is always used." },
                "request_timeout":  { field_type: FieldType::Int,  default: 10, description: "LDAP request timeout in seconds." },
                "starttls":         { field_type: FieldType::Bool, default: false, description: "Issue a StartTLS upgrade after `ldap://` connect." },
                "client_tls_cert":  { field_type: FieldType::Str,  default: "", description: "Client cert PEM for mTLS." },
                "client_tls_key":   { field_type: FieldType::Str,  default: "", description: "Client key PEM for mTLS." },
                "tls_min_version":  { field_type: FieldType::Str,  default: "tls12", description: "`tls12` or `tls13`." },
                "insecure_tls":     { field_type: FieldType::Bool, default: false, description: "Disable cert validation. Refused without `acknowledge_insecure_tls`." },
                "acknowledge_insecure_tls": { field_type: FieldType::Bool, default: false, description: "Operator confirmation that `insecure_tls = true` is intentional." },
                "userattr":         { field_type: FieldType::Str,  default: "cn", description: "Attribute matched against short usernames." }
            },
            operations: [
                {op: Operation::Read,   handler: read.handle_config_read},
                {op: Operation::Write,  handler: write.handle_config_write},
                {op: Operation::Delete, handler: delete.handle_config_delete}
            ],
            help: CONFIG_HELP
        })
    }

    pub fn rotate_root_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"rotate-root",
            operations: [{op: Operation::Write, handler: h.handle_rotate_root}],
            help: ROTATE_ROOT_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl LdapBackendInner {
    pub async fn load_config(&self, req: &Request) -> Result<Option<LdapConfig>, RvError> {
        match req.storage_get(CONFIG_KEY).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn save_config(&self, req: &mut Request, cfg: &LdapConfig) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(cfg)?;
        req.storage_put(&StorageEntry {
            key: CONFIG_KEY.to_string(),
            value: bytes,
        })
        .await
    }

    pub async fn handle_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        match self.load_config(req).await? {
            None => Ok(None),
            Some(cfg) => {
                let r = cfg.redacted();
                let mut data = Map::new();
                data.insert("url".into(), Value::String(r.url));
                data.insert("binddn".into(), Value::String(r.binddn));
                data.insert("userdn".into(), Value::String(r.userdn));
                data.insert(
                    "directory_type".into(),
                    Value::String(match r.directory_type {
                        DirectoryType::OpenLdap => "openldap".into(),
                        DirectoryType::ActiveDirectory => "active_directory".into(),
                    }),
                );
                data.insert("password_policy".into(), Value::String(r.password_policy));
                data.insert(
                    "request_timeout".into(),
                    Value::Number(r.request_timeout.as_secs().into()),
                );
                data.insert("starttls".into(), Value::Bool(r.starttls));
                data.insert(
                    "tls_min_version".into(),
                    Value::String(match r.tls_min_version {
                        TlsMinVersion::Tls12 => "tls12".into(),
                        TlsMinVersion::Tls13 => "tls13".into(),
                    }),
                );
                data.insert("insecure_tls".into(), Value::Bool(r.insecure_tls));
                data.insert("userattr".into(), Value::String(r.userattr));
                // bindpass + client_tls_key already stripped by `redacted()`.
                Ok(Some(Response::data_response(Some(data))))
            }
        }
    }

    pub async fn handle_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let existing = self.load_config(req).await?;

        let bindpass_in = take_str(req, "bindpass");
        let bindpass = if bindpass_in.is_empty() {
            existing
                .as_ref()
                .map(|c| c.bindpass.clone())
                .unwrap_or_default()
        } else {
            bindpass_in
        };

        let cfg = LdapConfig {
            url: take_or(req, "url", existing.as_ref().map(|c| c.url.as_str()).unwrap_or("")),
            binddn: take_or(req, "binddn", existing.as_ref().map(|c| c.binddn.as_str()).unwrap_or("")),
            bindpass,
            userdn: take_or(req, "userdn", existing.as_ref().map(|c| c.userdn.as_str()).unwrap_or("")),
            directory_type: DirectoryType::parse(&take_str(req, "directory_type"))
                .map_err(RvError::ErrString)?,
            password_policy: take_str(req, "password_policy"),
            request_timeout: std::time::Duration::from_secs(
                req.get_data("request_timeout")
                    .ok()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT.as_secs()),
            ),
            client_tls_cert: take_str(req, "client_tls_cert"),
            client_tls_key: take_str(req, "client_tls_key"),
            tls_min_version: TlsMinVersion::parse(&take_str(req, "tls_min_version"))
                .map_err(RvError::ErrString)?,
            insecure_tls: take_bool(req, "insecure_tls", false),
            userattr: take_or(req, "userattr", "cn"),
            starttls: take_bool(req, "starttls", false),
        };
        let acknowledge = take_bool(req, "acknowledge_insecure_tls", false);

        cfg.validate(acknowledge).map_err(RvError::ErrString)?;
        self.save_config(req, &cfg).await?;
        Ok(None)
    }

    pub async fn handle_config_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.storage_delete(CONFIG_KEY).await?;
        Ok(None)
    }

    pub async fn handle_rotate_root(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut cfg = self
            .load_config(req)
            .await?
            .ok_or_else(|| RvError::ErrString("ldap engine not configured".into()))?;

        let new_password = super::password::generate(super::password::DEFAULT_LENGTH);

        // Bind with the *current* password, then write the new one
        // to the bind DN. Directory-write-first is essential: if we
        // wrote storage first and the LDAP write failed, the engine
        // would be unable to bind on the next call.
        let mut ldap = client::bind(&cfg)
            .await
            .map_err(|e| RvError::ErrString(format!("rotate-root: bind: {e}")))?;
        client::set_password(&mut ldap, &cfg, &cfg.binddn, &new_password)
            .await
            .map_err(|e| RvError::ErrString(format!("rotate-root: write: {e}")))?;

        cfg.bindpass = new_password;
        self.save_config(req, &cfg).await?;
        let _ = ldap.unbind().await;
        Ok(None)
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn take_or(req: &Request, key: &str, default: &str) -> String {
    let s = take_str(req, key);
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

fn take_bool(req: &Request, key: &str, default: bool) -> bool {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}
