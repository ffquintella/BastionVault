//! `pki/acme/config` — operator-facing per-mount ACME enable + role
//! binding. **Authenticated** (Vault-token-gated; not in the
//! `unauth_paths` list). Distinct from the protocol-level
//! `acme/directory` etc which are unauthenticated and rely on JWS.

use std::{collections::HashMap, sync::Arc};

use serde_json::{Map, Value};

use super::storage::{AcmeConfig, CONFIG_KEY};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{PkiBackend, PkiBackendInner};

const HELP: &str = r#"
Configure ACME for this PKI mount. Operator-facing; the ACME
protocol endpoints (`acme/directory`, `acme/new-nonce`, `acme/new-account`,
...) are JWS-authenticated and unauthenticated at the engine layer.

  * `enabled` (bool)        — when false the protocol endpoints
                              return `not enabled`. Default false on
                              fresh mount; the operator opts in.
  * `default_role` (string) — required. Used by `finalize` when it
                              calls into `pki/sign/<role>` (Phase 6.1.5).
  * `default_issuer_ref`    — issuer that signs ACME-issued leaves;
                              empty = mount's active issuer.
  * `external_hostname`     — explicit hostname for directory URLs.
                              Empty = reflect the inbound `Host`
                              header. Pin behind a load balancer
                              that doesn't preserve `Host`.
  * `nonce_ttl_secs`        — replay-nonce ring-buffer max age
                              (default 300).
"#;

impl PkiBackend {
    pub fn acme_config_path(&self) -> Path {
        let read = self.inner.clone();
        let write = self.inner.clone();
        let delete = self.inner.clone();
        new_path!({
            pattern: r"acme/config$",
            fields: {
                "enabled":             { field_type: FieldType::Bool, default: false,  description: "Enable the ACME protocol endpoints on this mount." },
                "default_role":        { field_type: FieldType::Str,  default: "",     description: "Role used by `finalize` (must already exist on the mount)." },
                "default_issuer_ref":  { field_type: FieldType::Str,  default: "",     description: "Issuer that signs ACME-issued leaves; empty = mount's active issuer." },
                "external_hostname":   { field_type: FieldType::Str,  default: "",     description: "Hostname advertised in the directory URLs; empty = reflect inbound Host." },
                "nonce_ttl_secs":      { field_type: FieldType::Int,  default: 300,    description: "Replay-Nonce ring-buffer max age." },
                "dns_resolvers":       { field_type: FieldType::Str,  default: "",     description: "Comma-separated pinned DNS resolvers (`<ip>` or `<ip>:<port>`) for DNS-01; empty = system resolver." },
                "eab_required":        { field_type: FieldType::Bool, default: false,  description: "Require External Account Binding on `new-account` (Phase 6.2)." },
                "rate_window_secs":    { field_type: FieldType::Int,  default: 3600,   description: "Sliding-window length for per-account new-order rate limiting (seconds). 0 disables." },
                "rate_orders_per_window": { field_type: FieldType::Int, default: 300,  description: "Max new-order calls per account within the window. 0 disables." }
            },
            operations: [
                {op: Operation::Read,   handler: read.handle_acme_config_read},
                {op: Operation::Write,  handler: write.handle_acme_config_write},
                {op: Operation::Delete, handler: delete.handle_acme_config_delete}
            ],
            help: HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn load_acme_config(
        &self,
        req: &Request,
    ) -> Result<Option<AcmeConfig>, RvError> {
        match req.storage_get(CONFIG_KEY).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn save_acme_config(
        &self,
        req: &mut Request,
        cfg: &AcmeConfig,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(cfg)?;
        req.storage_put(&StorageEntry {
            key: CONFIG_KEY.to_string(),
            value: bytes,
        })
        .await
    }

    pub async fn handle_acme_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        let mut data = Map::new();
        data.insert("enabled".into(), Value::Bool(cfg.enabled));
        data.insert("default_role".into(), Value::String(cfg.default_role));
        data.insert(
            "default_issuer_ref".into(),
            Value::String(cfg.default_issuer_ref),
        );
        data.insert(
            "external_hostname".into(),
            Value::String(cfg.external_hostname),
        );
        data.insert(
            "nonce_ttl_secs".into(),
            Value::Number(cfg.nonce_ttl_secs.into()),
        );
        data.insert(
            "dns_resolvers".into(),
            Value::Array(
                cfg.dns_resolvers
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        data.insert("eab_required".into(), Value::Bool(cfg.eab_required));
        data.insert(
            "rate_window_secs".into(),
            Value::Number(cfg.rate_window_secs.into()),
        );
        data.insert(
            "rate_orders_per_window".into(),
            Value::Number(cfg.rate_orders_per_window.into()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_acme_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let existing = self.load_acme_config(req).await?.unwrap_or_default();

        let enabled = req
            .get_data("enabled")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(existing.enabled);
        let default_role = req
            .get_data("default_role")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or(existing.default_role);
        let default_issuer_ref = req
            .get_data("default_issuer_ref")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or(existing.default_issuer_ref);
        let external_hostname = req
            .get_data("external_hostname")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or(existing.external_hostname);
        let nonce_ttl_secs = req
            .get_data("nonce_ttl_secs")
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(existing.nonce_ttl_secs);
        let dns_resolvers = match req.get_data("dns_resolvers").ok().and_then(|v| v.as_str().map(|s| s.to_string())) {
            Some(s) if !s.is_empty() => s
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
            Some(_) => existing.dns_resolvers,
            None => existing.dns_resolvers,
        };
        let eab_required = req
            .get_data("eab_required")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(existing.eab_required);
        let rate_window_secs = req
            .get_data("rate_window_secs")
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(existing.rate_window_secs);
        let rate_orders_per_window = req
            .get_data("rate_orders_per_window")
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(existing.rate_orders_per_window);

        if enabled && default_role.trim().is_empty() {
            return Err(RvError::ErrString(
                "acme: enabled = true requires default_role".into(),
            ));
        }

        let cfg = AcmeConfig {
            enabled,
            default_role,
            default_issuer_ref,
            external_hostname,
            nonce_ttl_secs,
            dns_resolvers,
            eab_required,
            rate_window_secs,
            rate_orders_per_window,
        };
        self.save_acme_config(req, &cfg).await?;
        Ok(None)
    }

    pub async fn handle_acme_config_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.storage_delete(CONFIG_KEY).await?;
        Ok(None)
    }
}
