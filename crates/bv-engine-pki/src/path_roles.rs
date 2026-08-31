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
use bv_storage::StorageEntry;
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
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
    /// Phase L2: opt-in to private-key reuse on issuance. When `false`
    /// (the default), `pki/issue/:role` and `pki/sign/:role` reject any
    /// `key_ref` request body. When `true`, callers may pin to a managed
    /// key from `pki/keys/*` so renewals carry the same private key.
    /// Pinning extends the exposure window of a key — leave this off
    /// unless the operational tradeoff is understood.
    #[serde(default)]
    pub allow_key_reuse: bool,
    /// Phase L2: optional allow-list of managed keys this role may pin
    /// to. Each entry is a key ID or name. Empty list with
    /// `allow_key_reuse = true` means "any managed key on this mount is
    /// acceptable". `#[serde(default)]` keeps pre-L2 roles readable.
    #[serde(default)]
    pub allowed_key_refs: Vec<String>,
    /// Phase L4: list of parent domains this role may issue under. Used
    /// in conjunction with `allow_subdomains`, `allow_bare_domains`,
    /// and `allow_glob_domains` to constrain CN + DNS SANs. Ignored
    /// when `allow_any_name = true` (the legacy fully-permissive
    /// mode). Empty list with `allow_any_name = false` means "no DNS
    /// names accepted at all" — combined with `allow_localhost` /
    /// `allow_ip_sans` for fully locked-down service-mesh roles.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Phase L4: when `true`, entries in `allowed_domains` may contain
    /// `*` glob patterns matching one or more characters within a
    /// single label. E.g. `*-prod.example.com` accepts
    /// `web-prod.example.com`. Default `false` (literal match plus
    /// `allow_subdomains`-controlled child labels).
    #[serde(default)]
    pub allow_glob_domains: bool,
    /// Phase L4: per-role kill-switch for the ACME server endpoints.
    /// When `false`, `pki/acme/new-order` against this role rejects
    /// regardless of `acme/config`. Defaults to `true` for backwards
    /// compatibility — pre-L4 roles deserialise to `acme_enabled =
    /// true` via the serde + `better_default` defaults.
    #[serde(default = "default_acme_enabled")]
    #[default(true)]
    pub acme_enabled: bool,
    /// AD smart-card logon: allow `upn_sans` on issue/sign, emitting the
    /// UPN as a `subjectAltName` `otherName` (OID 1.3.6.1.4.1.311.20.2.3).
    /// This is the identifier the KDC maps to an AD account, so it is
    /// closed by default — a role that does not need Windows logon should
    /// never widen its SAN surface. `#[serde(default)]` keeps roles
    /// persisted before this field readable.
    #[serde(default)]
    pub allow_upn_sans: bool,
    /// Optional allow-list of UPN realms this role may issue for (e.g.
    /// `corp.example.com`). Matched case-insensitively against the part
    /// after the `@`; subdomains are *not* implied. Empty list with
    /// `allow_upn_sans = true` means "any realm".
    #[serde(default)]
    pub allowed_upn_domains: Vec<String>,
    /// S/MIME: allow `email_sans` on issue/sign/csr-generate, emitting the
    /// address as an `rfc822Name` `subjectAltName`. This is the identifier
    /// a mail client binds to a mailbox, so an organisation-trusted CA
    /// that emits one on request can mint a signing certificate for
    /// anyone's address — closed by default. `#[serde(default)]` keeps
    /// roles persisted before this field readable.
    #[serde(default)]
    pub allow_email_sans: bool,
    /// Optional allow-list of mail domains this role may issue for (the
    /// part after the `@`). Matched case-insensitively and exactly;
    /// subdomains are *not* implied. Empty list with
    /// `allow_email_sans = true` means "any domain".
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// Extra Extended Key Usage OIDs in dotted-decimal form, appended to
    /// whatever `ext_key_usage` / `server_flag` / `client_flag` produce.
    /// Needed for Windows smart-card logon
    /// (`1.3.6.1.4.1.311.20.2.2`), which has no RFC 5280 name. Validated
    /// at role-write time so a typo cannot reach an issued certificate.
    #[serde(default)]
    pub ext_key_usage_oids: Vec<String>,
    /// AD smart-card logon: allow the `szOID_NTDS_CA_SECURITY_EXT` SID
    /// extension (OID 1.3.6.1.4.1.311.25.2) to be emitted. Required for
    /// KB5014754 strong certificate mapping on any domain controller
    /// patched past September 2025. Closed by default — the extension
    /// asserts an identity claim that AD trusts, so it must be
    /// deliberately enabled.
    #[serde(default)]
    pub allow_ad_sid: bool,
    /// Role-level default SID emitted when a request omits `ad_sid`. Lets
    /// an operator pin a role to one account (a service identity, say)
    /// without the caller having to know the SID. Ignored unless
    /// `allow_ad_sid = true`; a request-body `ad_sid` overrides it.
    #[serde(default)]
    pub ad_sid: String,
}

fn default_acme_enabled() -> bool {
    true
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
                "issuer_ref": { field_type: FieldType::Str, default: "", description: "Pin issuance to a specific issuer (ID or name). Empty = mount default." },
                "allow_key_reuse": { field_type: FieldType::Bool, default: false, description: "Allow callers to pin a managed key via key_ref on issue/sign (Phase L2). Default false (closed)." },
                "allowed_key_refs": { field_type: FieldType::CommaStringSlice, default: "", description: "Allow-list of managed key IDs/names this role may pin to. Empty + allow_key_reuse=true means any." },
                "allowed_domains": { field_type: FieldType::CommaStringSlice, default: "", description: "Phase L4: allowed parent domains for CN / DNS SANs (used with allow_subdomains / allow_bare_domains / allow_glob_domains). Ignored when allow_any_name=true." },
                "allow_glob_domains": { field_type: FieldType::Bool, default: false, description: "Phase L4: entries in allowed_domains may contain `*` glob patterns within a label." },
                "acme_enabled": { field_type: FieldType::Bool, default: true, description: "Phase L4: per-role ACME kill-switch. Default true." },
                "allow_upn_sans": { field_type: FieldType::Bool, default: false, description: "Allow UPN otherName SANs (OID 1.3.6.1.4.1.311.20.2.3) for AD smart-card logon. Default false (closed)." },
                "allowed_upn_domains": { field_type: FieldType::CommaStringSlice, default: "", description: "Allow-list of UPN realms (the part after `@`). Empty + allow_upn_sans=true means any realm." },
                "allow_email_sans": { field_type: FieldType::Bool, default: false, description: "Allow rfc822Name (email) SANs for S/MIME. Default false (closed)." },
                "allowed_email_domains": { field_type: FieldType::CommaStringSlice, default: "", description: "Allow-list of mail domains (the part after `@`), matched exactly and case-insensitively. Empty + allow_email_sans=true means any domain." },
                "ext_key_usage_oids": { field_type: FieldType::CommaStringSlice, default: "", description: "Extra EKU OIDs in dotted-decimal form, e.g. 1.3.6.1.4.1.311.20.2.2 (Smart Card Logon). Validated at write time." },
                "allow_ad_sid": { field_type: FieldType::Bool, default: false, description: "Allow the AD SID extension (OID 1.3.6.1.4.1.311.25.2) required for KB5014754 strong mapping. Default false (closed)." },
                "ad_sid": { field_type: FieldType::Str, default: "", description: "Default SID emitted when a request omits `ad_sid` (e.g. S-1-5-21-...-512). Requires allow_ad_sid=true." }
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

        // AD smart-card knobs. Validate the OIDs and the default SID here
        // so a malformed role fails at write time — an EKU typo or a
        // mistyped SID that only surfaced at issuance would produce a
        // certificate Windows silently refuses, which is a miserable
        // thing to debug from the client side.
        let ext_key_usage_oids: Vec<String> = req
            .get_data_or_default("ext_key_usage_oids")?
            .as_comma_string_slice()
            .unwrap_or_default();
        for oid in &ext_key_usage_oids {
            super::ad_ext::parse_oid_arcs(oid).map_err(|e| {
                RvError::ErrString(format!("ext_key_usage_oids: {e}"))
            })?;
        }
        let ext_key_usage: Vec<String> =
            req.get_data_or_default("ext_key_usage")?.as_comma_string_slice().unwrap_or_default();
        // `ext_key_usage` also accepts raw OIDs. Validate those here too so
        // both channels fail at the same point; unknown *names* stay
        // lenient (skipped at issuance), preserving behaviour for roles
        // already in storage.
        for entry in &ext_key_usage {
            let trimmed = entry.trim();
            if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                super::ad_ext::parse_oid_arcs(trimmed)
                    .map_err(|e| RvError::ErrString(format!("ext_key_usage: {e}")))?;
            }
        }
        let allow_ad_sid = bool_or(req, "allow_ad_sid", false)?;
        let ad_sid_raw = str_or(req, "ad_sid")?;
        let ad_sid = if ad_sid_raw.trim().is_empty() {
            String::new()
        } else {
            if !allow_ad_sid {
                return Err(RvError::ErrString(
                    "ad_sid is set but allow_ad_sid is false — enable allow_ad_sid or clear ad_sid".into(),
                ));
            }
            let probe = RoleEntry { allow_ad_sid: true, ..Default::default() };
            super::ad_ext::validate_ad_sid(&probe, ad_sid_raw.trim())?;
            super::ad_ext::normalize_ad_sid(&ad_sid_raw)
        };

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
            ext_key_usage,
            country: str_or(req, "country")?,
            province: str_or(req, "province")?,
            locality: str_or(req, "locality")?,
            organization: str_or(req, "organization")?,
            ou: str_or(req, "ou")?,
            no_store: bool_or(req, "no_store", false)?,
            generate_lease: bool_or(req, "generate_lease", false)?,
            issuer_ref: str_or(req, "issuer_ref")?,
            allow_key_reuse: bool_or(req, "allow_key_reuse", false)?,
            allowed_key_refs: req
                .get_data_or_default("allowed_key_refs")?
                .as_comma_string_slice()
                .unwrap_or_default(),
            allowed_domains: req
                .get_data_or_default("allowed_domains")?
                .as_comma_string_slice()
                .unwrap_or_default(),
            allow_glob_domains: bool_or(req, "allow_glob_domains", false)?,
            acme_enabled: bool_or(req, "acme_enabled", true)?,
            allow_upn_sans: bool_or(req, "allow_upn_sans", false)?,
            allowed_upn_domains: req
                .get_data_or_default("allowed_upn_domains")?
                .as_comma_string_slice()
                .unwrap_or_default(),
            allow_email_sans: bool_or(req, "allow_email_sans", false)?,
            allowed_email_domains: req
                .get_data_or_default("allowed_email_domains")?
                .as_comma_string_slice()
                .unwrap_or_default(),
            ext_key_usage_oids,
            allow_ad_sid,
            ad_sid,
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
