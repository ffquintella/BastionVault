//! `pki/issue/:role` — generate a fresh keypair and issue a leaf cert.
//!
//! `pki/sign/:role` and `pki/sign-verbatim` are stubbed for Phase 1: CSR
//! parsing requires plumbing through `x509-parser` to reconstruct an `rcgen`
//! `PublicKey`, which lands in a follow-up so the Phase 1 surface stays
//! reviewable.

use std::{collections::HashMap, sync::Arc, time::Duration};

use humantime::parse_duration;
use serde_json::{json, Map, Value};

use super::{
    crypto::{AlgorithmClass, Signer},
    storage::{self, CertRecord, KEY_CA_CERT, KEY_CA_KEY},
    x509::{self, SubjectInput},
    x509_pqc,
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn issue_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"issue/(?P<role>\w[\w-]*\w)",
            fields: {
                "role": { field_type: FieldType::Str, required: true, description: "Role name." },
                "common_name": { field_type: FieldType::Str, required: true, description: "Subject CN." },
                "alt_names": { field_type: FieldType::Str, default: "", description: "Comma-separated DNS / IP SANs." },
                "ip_sans": { field_type: FieldType::Str, default: "", description: "Comma-separated IP SANs." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested TTL." }
            },
            operations: [{op: Operation::Write, handler: r.issue_cert}],
            help: "Issue a certificate against the named role."
        })
    }

    pub fn sign_role_stub(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign/(?P<role>\w[\w-]*\w)",
            operations: [{op: Operation::Write, handler: r.unsupported}],
            help: "(Phase 1.1) Sign a CSR against the named role."
        })
    }

    pub fn sign_verbatim_stub(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sign-verbatim$",
            operations: [{op: Operation::Write, handler: r.unsupported}],
            help: "(Phase 1.1) Sign a CSR verbatim."
        })
    }

}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn issue_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data("role")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let role = self.get_role(req, &role_name).await?
            .ok_or(RvError::ErrPkiRoleNotFound)?;

        let common_name = req.get_data("common_name")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        x509::validate_common_name(&role, &common_name)?;

        let alt_str = req.get_data_or_default("alt_names")?.as_str().unwrap_or("").to_string();
        let (mut alt_dns, mut alt_ips) = x509::split_alt_names(&alt_str);
        let ip_str = req.get_data_or_default("ip_sans")?.as_str().unwrap_or("").to_string();
        let (extra_dns, extra_ips) = x509::split_alt_names(&ip_str);
        alt_dns.extend(extra_dns);
        alt_ips.extend(extra_ips);
        if !role.allow_ip_sans && !alt_ips.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }

        let requested_ttl = parse_optional_ttl(req, "ttl")?;
        let ttl = role.effective_ttl(requested_ttl);

        // Load the CA. Phase 1 supports a single issuer per mount; the same
        // assumption holds in Phase 2.
        let ca_cert_pem = storage::get_string(req, KEY_CA_CERT).await?
            .ok_or(RvError::ErrPkiCaNotConfig)?;
        let ca_key_pem = storage::get_string(req, KEY_CA_KEY).await?
            .ok_or(RvError::ErrPkiCaKeyNotFound)?;
        let ca_signer = Signer::from_storage_pem(&ca_key_pem)?;

        let role_alg = role.algorithm()?;

        // Mixed-chain rejection (Phase 2). A PQC role must run on a PQC CA,
        // and a classical role must run on a classical CA. The spec exposes
        // an `--allow-mixed-chain` opt-in for migration scenarios; that knob
        // lands in a follow-up so the default-secure behaviour is shipped
        // first. Without it, the engine fails closed.
        if role_alg.class() != ca_signer.algorithm().class() {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }

        // Generate the leaf keypair using the role's algorithm.
        let leaf_signer = Signer::generate(role_alg)?;

        let subject = SubjectInput { common_name, alt_names: alt_dns, ip_sans: alt_ips };
        let (cert_pem, serial_bytes) = match (role_alg.class(), &ca_signer, &leaf_signer) {
            (AlgorithmClass::Classical, Signer::Classical(ca), Signer::Classical(leaf)) => {
                let (cert, serial) = x509::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem)?;
                (cert.pem(), serial)
            }
            (AlgorithmClass::Pqc, Signer::MlDsa(ca), Signer::MlDsa(leaf)) => {
                x509_pqc::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem)?
            }
            #[cfg(feature = "pki_pqc_composite")]
            (AlgorithmClass::Composite, Signer::Composite(ca), Signer::Composite(leaf)) => {
                super::x509_composite::build_leaf(&role, &subject, ttl, leaf, ca, &ca_cert_pem)?
            }
            // Mixed cases were already screened above; this arm is here to
            // make the compiler happy without falling through silently.
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        let leaf_key_pem = leaf_signer.to_storage_pem();

        let serial_hex = storage::serial_to_hex(&serial_bytes);

        // Persist the cert (unless the role opts out) so revoke can find it
        // and the CRL builder can include it.
        if !role.no_store {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Capture NotAfter so Phase 4's tidy sweep can identify expired
            // records without re-parsing the PEM. `ttl` came from the role +
            // request body and was already used to build the cert above, so
            // adding it to `now` reproduces the in-cert NotAfter to within a
            // millisecond — close enough for tidy decisions that include a
            // safety buffer.
            let not_after_unix = (now as i64).saturating_add(ttl.as_secs() as i64);
            let record = CertRecord {
                serial_hex: serial_hex.clone(),
                certificate_pem: cert_pem.clone(),
                issued_at_unix: now,
                revoked_at_unix: None,
                not_after_unix,
            };
            storage::put_json(req, &storage::cert_storage_key(&serial_hex), &record).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(cert_pem));
        data.insert("issuing_ca".into(), json!(ca_cert_pem));
        data.insert("private_key".into(), json!(leaf_key_pem));
        data.insert("private_key_type".into(), json!(role.algorithm()?.as_str()));
        data.insert("serial_number".into(), json!(serial_hex));
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn parse_optional_ttl(req: &Request, key: &str) -> Result<Option<Duration>, RvError> {
    let v = req.get_data_or_default(key)?;
    let s = v.as_str().unwrap_or("");
    if s.is_empty() {
        return Ok(None);
    }
    parse_duration(s).map(Some).map_err(|_| RvError::ErrRequestFieldInvalid)
}
