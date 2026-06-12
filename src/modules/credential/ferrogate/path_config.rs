//! Trust-anchor configuration for the FerroGate auth backend (Phase 1).
//!
//! `auth/ferrogate/config` records how BastionVault locates and trusts
//! FerroGate's composite verification keys (the SPIFFE trust domain, the
//! expected audience, the JWKS source, and the bootstrap knobs). All fields are
//! public key material or policy knobs — none is a secret — but the path is
//! root/sudo-gated regardless.

use std::{collections::HashMap, sync::Arc};

use super::{FerroGateBackend, FerroGateBackendInner, FerroGateConfig};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const CONFIG_KEY: &str = "config";

impl FerroGateBackend {
    pub fn config_path(&self) -> Path {
        let read_ref = self.inner.clone();
        let write_ref = self.inner.clone();

        new_path!({
            pattern: r"config$",
            fields: {
                "trust_domain": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "FerroGate SPIFFE trust domain, e.g. 'ferrogate.prod'."
                },
                "expected_audience": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "This vault's audience, matched against a child token's 'aud'."
                },
                "jwks_source": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "How to obtain FerroGate keys: 'static_jwks' or 'cmis_grpc'."
                },
                "cmis_endpoint": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "CMIS gRPC endpoint (when jwks_source = cmis_grpc). Ignored when cmis_srv is set."
                },
                "cmis_srv": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "DNS SRV owner name for a CMIS HA cluster (e.g. _ferrogate-prod._tcp.example.com). When set, the mount resolves it and fails over across all advertised nodes; takes precedence over cmis_endpoint."
                },
                "cmis_spki_pins": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: "SHA-384 SPKI pins (hex) for the CMIS server certificate."
                },
                "static_jwks": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Pinned JWK set JSON (when jwks_source = static_jwks)."
                },
                "accept_svid": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Accept a host SVID presented directly (weaker; no per-request DPoP)."
                },
                "clock_leeway_secs": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Clock leeway in seconds for token nbf/exp checks."
                },
                "default_token_ttl": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Default minted-token TTL (seconds) when an approval sets none."
                },
                "cmis_tls_enable": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Use hybrid PQ-TLS to reach CMIS; false = plaintext (dev/loopback only)."
                },
                "cmis_same_host": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "CMIS runs on the same machine as this server: try host-local aliases (host.containers.internal, loopback) before the configured endpoint."
                },
                "jwks_refresh_secs": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Seconds a fetched CMIS JWKS is cached before refresh."
                },
                "login_rate_limit_per_min": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Per-source-IP login attempts per minute (0 = unlimited)."
                },
                "bootstrap_root_auto_approve": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Auto-approve the first machine that logs in with a root token."
                },
                "bootstrap_policies": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: "Policies granted to the auto-approved first machine."
                },
                "require_user_token": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Require a user_token on login and intersect its policies with the machine's (combined machine+user auth)."
                },
                "require_machine_identity": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Server-enforced: when true, EVERY authenticated request must present a FerroGate machine-bound token (or a root token). Clients discover this via auth/ferrogate/requirement and cannot bypass it."
                },
                "mia_environment": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "MIA environment selector for this deployment (clients read mia-<env>.toml). Advertised via auth/ferrogate/requirement; empty = the default mia.toml."
                }
            },
            operations: [
                {op: Operation::Read, handler: read_ref.read_config},
                {op: Operation::Write, handler: write_ref.write_config}
            ],
            help: r#"Configure the FerroGate trust anchor (keys, audience, bootstrap behaviour)."#
        })
    }

    /// Unauthenticated discovery endpoint. Lets a client learn, before login,
    /// whether this server mandates FerroGate machine identity (and the
    /// audience/trust-domain it expects) so the connect flow can run the
    /// machine gate from the server's answer rather than a local toggle.
    /// Returns only non-secret policy knobs.
    pub fn requirement_path(&self) -> Path {
        let read_ref = self.inner.clone();
        new_path!({
            pattern: r"requirement$",
            operations: [
                {op: Operation::Read, handler: read_ref.read_requirement}
            ],
            help: r#"Report whether this server requires FerroGate machine identity (unauthenticated)."#
        })
    }
}

#[maybe_async::maybe_async]
impl FerroGateBackendInner {
    /// Load the stored config, or the defaults if none has been written yet.
    pub async fn get_config(&self, req: &mut Request) -> Result<FerroGateConfig, RvError> {
        match req.storage_get(CONFIG_KEY).await? {
            Some(entry) => Ok(serde_json::from_slice(entry.value.as_slice())?),
            None => Ok(FerroGateConfig::default()),
        }
    }

    /// Persist the config.
    pub async fn set_config(&self, req: &mut Request, config: &FerroGateConfig) -> Result<(), RvError> {
        let entry = StorageEntry::new(CONFIG_KEY, config)?;
        req.storage_put(&entry).await
    }

    pub async fn read_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?;
        let value = serde_json::to_value(&config)?;
        let data = value.as_object().cloned().ok_or(RvError::ErrResponseDataInvalid)?;
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        // Merge provided fields onto the existing config so partial updates work.
        let mut config = self.get_config(req).await?;

        if let Ok(v) = req.get_data("trust_domain") {
            config.trust_domain = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        }
        if let Ok(v) = req.get_data("expected_audience") {
            config.expected_audience = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        }
        if let Ok(v) = req.get_data("jwks_source") {
            let src = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
            if src != super::jwks_source::STATIC && src != super::jwks_source::CMIS_GRPC {
                return Ok(Some(Response::error_response(
                    "jwks_source must be 'static_jwks' or 'cmis_grpc'",
                )));
            }
            config.jwks_source = src;
        }
        if let Ok(v) = req.get_data("cmis_endpoint") {
            config.cmis_endpoint = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        }
        if let Ok(v) = req.get_data("cmis_srv") {
            config.cmis_srv = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        }
        if let Ok(v) = req.get_data("cmis_spki_pins") {
            config.cmis_spki_pins = v.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("static_jwks") {
            config.static_jwks = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        }
        if let Ok(v) = req.get_data("accept_svid") {
            config.accept_svid = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("clock_leeway_secs") {
            config.clock_leeway_secs = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("default_token_ttl") {
            let ttl = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
            config.default_token_ttl = ttl.max(0) as u64;
        }
        if let Ok(v) = req.get_data("cmis_tls_enable") {
            config.cmis_tls_enable = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("cmis_same_host") {
            config.cmis_same_host = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("jwks_refresh_secs") {
            config.jwks_refresh_secs = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("login_rate_limit_per_min") {
            config.login_rate_limit_per_min = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?.max(0) as u32;
        }
        if let Ok(v) = req.get_data("bootstrap_root_auto_approve") {
            config.bootstrap_root_auto_approve = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("bootstrap_policies") {
            config.bootstrap_policies = v.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("require_user_token") {
            config.require_user_token = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("require_machine_identity") {
            config.require_machine_identity = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("mia_environment") {
            let env = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.trim().to_string();
            // Same charset rule as the MIA's own environment validation: the
            // value is advertised to clients which turn it into a
            // `mia-<env>.toml` file name, so it must never carry path syntax.
            if !env.is_empty()
                && !env.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            {
                return Ok(Some(Response::error_response(
                    "mia_environment is invalid: use only letters, digits, '.', '-', '_'",
                )));
            }
            if env == "." || env == ".." {
                return Ok(Some(Response::error_response("mia_environment is not a valid environment name")));
            }
            config.mia_environment = env;
        }

        self.set_config(req, &config).await?;

        // Mirror the enforcement flag to the system view + in-memory fast path
        // so the token layer can gate every request without a storage read.
        self.core
            .set_require_machine_identity(config.require_machine_identity)
            .await?;

        Ok(None)
    }

    /// Unauthenticated handler: report whether this server requires FerroGate
    /// machine identity, plus the audience/trust-domain a client should target.
    pub async fn read_requirement(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?;
        let mut data = serde_json::Map::new();
        data.insert("require_machine_identity".to_string(), serde_json::Value::Bool(config.require_machine_identity));
        data.insert("expected_audience".to_string(), serde_json::Value::String(config.expected_audience));
        data.insert("trust_domain".to_string(), serde_json::Value::String(config.trust_domain));
        data.insert("mia_environment".to_string(), serde_json::Value::String(config.mia_environment));
        Ok(Some(Response::data_response(Some(data))))
    }
}
