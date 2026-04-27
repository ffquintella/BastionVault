//! `pki/roles/:name` — role CRUD.
//!
//! Mirrors the Vault PKI engine role schema for fields that Phase 1 actually
//! consumes during issuance. Phase 2 will extend this with PQC `key_type`
//! values (`ml-dsa-65`, etc.) and the `pqc_only` knob.

use std::{collections::HashMap, sync::Arc, time::Duration};

use better_default::Default;
use humantime::parse_duration;
use serde::{Deserialize, Serialize};

use super::{crypto::KeyAlgorithm, PkiBackend, PkiBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
    utils::{deserialize_duration, serialize_duration},
};

const DEFAULT_TTL: Duration = Duration::from_secs(30 * 24 * 3600); // 30d
const DEFAULT_MAX_TTL: Duration = Duration::from_secs(90 * 24 * 3600); // 90d

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleEntry {
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    #[default(DEFAULT_TTL)]
    pub ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    #[default(DEFAULT_MAX_TTL)]
    pub max_ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    #[default(Duration::from_secs(30))]
    pub not_before_duration: Duration,
    #[default("ec".to_string())]
    pub key_type: String,
    pub key_bits: u32,
    pub signature_bits: u32,
    #[default(true)]
    pub allow_localhost: bool,
    pub allow_bare_domains: bool,
    pub allow_subdomains: bool,
    #[default(true)]
    pub allow_any_name: bool,
    #[default(true)]
    pub allow_ip_sans: bool,
    #[default(true)]
    pub server_flag: bool,
    #[default(true)]
    pub client_flag: bool,
    #[default(true)]
    pub use_csr_sans: bool,
    #[default(true)]
    pub use_csr_common_name: bool,
    pub key_usage: Vec<String>,
    pub ext_key_usage: Vec<String>,
    pub country: String,
    pub province: String,
    pub locality: String,
    pub organization: String,
    pub ou: String,
    pub no_store: bool,
    pub generate_lease: bool,
    /// Phase 5.2: pin issuance to a specific issuer (by ID or name). Empty
    /// = use the mount default. The runtime priority is request body
    /// `issuer_ref` > role `issuer_ref` > mount default. `#[serde(default)]`
    /// keeps roles persisted before 5.2 readable.
    #[serde(default)]
    pub issuer_ref: String,
}

impl RoleEntry {
    pub fn algorithm(&self) -> Result<KeyAlgorithm, RvError> {
        KeyAlgorithm::from_role(&self.key_type, self.key_bits)
    }

    pub fn effective_ttl(&self, requested: Option<Duration>) -> Duration {
        let base = match requested {
            Some(d) if !d.is_zero() => d,
            _ => self.ttl,
        };
        std::cmp::min(base, self.max_ttl)
    }
}

impl PkiBackend {
    pub fn roles_path(&self) -> Path {
        let r1 = self.inner.clone();
        let r2 = self.inner.clone();
        let r3 = self.inner.clone();

        new_path!({
            pattern: r"roles/(?P<name>\w[\w-]*\w)",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Role name." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Default lease TTL." },
                "max_ttl": { field_type: FieldType::Str, default: "", description: "Maximum lease TTL." },
                "key_type": { field_type: FieldType::Str, default: "ec", description: "rsa | ec | ed25519 | ml-dsa-44 | ml-dsa-65 | ml-dsa-87." },
                "key_bits": { field_type: FieldType::Int, default: 0, description: "Key size in bits (0 = default)." },
                "signature_bits": { field_type: FieldType::Int, default: 0, description: "Signature hash size." },
                "allow_localhost": { field_type: FieldType::Bool, default: true, description: "Allow localhost CN." },
                "allow_any_name": { field_type: FieldType::Bool, default: true, description: "Allow any CN." },
                "allow_ip_sans": { field_type: FieldType::Bool, default: true, description: "Allow IP SANs." },
                "allow_subdomains": { field_type: FieldType::Bool, default: false, description: "Allow subdomain CNs." },
                "allow_bare_domains": { field_type: FieldType::Bool, default: false, description: "Allow bare domain CNs." },
                "server_flag": { field_type: FieldType::Bool, default: true, description: "Set ServerAuth EKU." },
                "client_flag": { field_type: FieldType::Bool, default: true, description: "Set ClientAuth EKU." },
                "use_csr_sans": { field_type: FieldType::Bool, default: true, description: "Use SANs from CSR." },
                "use_csr_common_name": { field_type: FieldType::Bool, default: true, description: "Use CN from CSR." },
                "key_usage": { field_type: FieldType::CommaStringSlice, default: "DigitalSignature,KeyEncipherment", description: "Key usage names." },
                "ext_key_usage": { field_type: FieldType::CommaStringSlice, default: "", description: "Extended key usage names." },
                "country": { field_type: FieldType::Str, default: "", description: "Subject Country." },
                "province": { field_type: FieldType::Str, default: "", description: "Subject Province." },
                "locality": { field_type: FieldType::Str, default: "", description: "Subject Locality." },
                "organization": { field_type: FieldType::Str, default: "", description: "Subject Organization." },
                "ou": { field_type: FieldType::Str, default: "", description: "Subject OU." },
                "no_store": { field_type: FieldType::Bool, default: false, description: "Skip persisting issued certs." },
                "generate_lease": { field_type: FieldType::Bool, default: false, description: "Attach a Vault lease to issued certs." },
                "not_before_duration": { field_type: FieldType::Int, default: 30, description: "Backdate seconds for NotBefore." },
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Pin issuance to a specific issuer (ID or name). Empty = mount default." }
            },
            operations: [
                {op: Operation::Read, handler: r1.read_role},
                {op: Operation::Write, handler: r2.write_role},
                {op: Operation::Delete, handler: r3.delete_role}
            ],
            help: "Manage PKI roles."
        })
    }

    pub fn roles_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"roles/?$",
            operations: [{op: Operation::List, handler: r.list_roles}],
            help: "List PKI roles."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn get_role(&self, req: &Request, name: &str) -> Result<Option<RoleEntry>, RvError> {
        let entry = req.storage_get(&format!("role/{name}")).await?;
        match entry {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn read_role(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        match self.get_role(req, &name).await? {
            Some(role) => {
                let data = serde_json::to_value(&role)?;
                Ok(Some(Response::data_response(data.as_object().cloned())))
            }
            None => Ok(None),
        }
    }

    pub async fn write_role(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();

        let key_type = req.get_data_or_default("key_type")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let key_bits = req.get_data_or_default("key_bits")?.as_u64()
            .ok_or(RvError::ErrRequestFieldInvalid)? as u32;
        // Validate up-front so misconfigured roles fail at write time, not
        // mid-issuance. `KeyAlgorithm::from_role` is the single source of truth.
        KeyAlgorithm::from_role(&key_type, key_bits)?;

        let signature_bits = req.get_data_or_default("signature_bits")?.as_u64()
            .ok_or(RvError::ErrRequestFieldInvalid)? as u32;

        let ttl = parse_opt_duration(req, "ttl", DEFAULT_TTL)?;
        let max_ttl = parse_opt_duration(req, "max_ttl", DEFAULT_MAX_TTL)?;

        let role = RoleEntry {
            ttl,
            max_ttl,
            not_before_duration: Duration::from_secs(
                req.get_data_or_default("not_before_duration")?.as_u64().unwrap_or(30),
            ),
            key_type,
            key_bits,
            signature_bits,
            allow_localhost: bool_or(req, "allow_localhost", true)?,
            allow_bare_domains: bool_or(req, "allow_bare_domains", false)?,
            allow_subdomains: bool_or(req, "allow_subdomains", false)?,
            allow_any_name: bool_or(req, "allow_any_name", true)?,
            allow_ip_sans: bool_or(req, "allow_ip_sans", true)?,
            server_flag: bool_or(req, "server_flag", true)?,
            client_flag: bool_or(req, "client_flag", true)?,
            use_csr_sans: bool_or(req, "use_csr_sans", true)?,
            use_csr_common_name: bool_or(req, "use_csr_common_name", true)?,
            key_usage: req.get_data_or_default("key_usage")?.as_comma_string_slice().unwrap_or_default(),
            ext_key_usage: req.get_data_or_default("ext_key_usage")?.as_comma_string_slice().unwrap_or_default(),
            country: str_or(req, "country")?,
            province: str_or(req, "province")?,
            locality: str_or(req, "locality")?,
            organization: str_or(req, "organization")?,
            ou: str_or(req, "ou")?,
            no_store: bool_or(req, "no_store", false)?,
            generate_lease: bool_or(req, "generate_lease", false)?,
            issuer_ref: str_or(req, "issuer_ref")?,
        };

        let entry = StorageEntry::new(format!("role/{name}").as_str(), &role)?;
        req.storage_put(&entry).await?;
        Ok(None)
    }

    pub async fn delete_role(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        if name.is_empty() {
            return Err(RvError::ErrRequestNoDataField);
        }
        req.storage_delete(&format!("role/{name}")).await?;
        Ok(None)
    }

    pub async fn list_roles(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list("role/").await?;
        Ok(Some(Response::list_response(&keys)))
    }
}

fn bool_or(req: &Request, key: &str, default: bool) -> Result<bool, RvError> {
    Ok(req.get_data_or_default(key)?.as_bool().unwrap_or(default))
}

fn str_or(req: &Request, key: &str) -> Result<String, RvError> {
    Ok(req.get_data_or_default(key)?.as_str().unwrap_or("").to_string())
}

fn parse_opt_duration(req: &Request, key: &str, default: Duration) -> Result<Duration, RvError> {
    let v = req.get_data_or_default(key)?;
    let s = v.as_str().unwrap_or("");
    if s.is_empty() {
        return Ok(default);
    }
    parse_duration(s).map_err(|e| {
        RvError::ErrString(format!(
            "{key}: '{s}' is not a valid duration ({e}); use a unit suffix like '720h' or '5m'"
        ))
    })
}
