use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use humantime::parse_duration;
use openssl::asn1::Asn1Time;
use serde_json::{json, Map, Value};

use super::{util, PkiBackend, PkiBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal, utils,
};

impl PkiBackend {
    pub fn issue_path(&self) -> Path {
        let pki_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"issue/(?P<role>\w[\w-]+\w)",
            fields: {
                "role": {
                    field_type: FieldType::Str,
                    description: "The desired role with configuration for this request"
                },
                "common_name": {
                    field_type: FieldType::Str,
                    description: r#"
        The requested common name; if you want more than one, specify the alternative names in the alt_names map"#
                },
                "alt_names": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
        The requested Subject Alternative Names, if any, in a comma-delimited list"#
                },
                "ip_sans": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"The requested IP SANs, if any, in a comma-delimited list"#
                },
                "ttl": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"Specifies requested Time To Live"#
                }
            },
            operations: [
                {op: Operation::Write, handler: pki_backend_ref.issue_cert}
            ],
            help: r#"
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.
                "#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn issue_cert(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role = self.get_role(req, req.get_data("role")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?).await?;
        if role.is_none() {
            return Err(RvError::ErrPkiRoleNotFound);
        }
        let role_entry = role.unwrap();

        let ca_bundle = self.fetch_ca_bundle(req).await?;
        let not_before = SystemTime::now() - Duration::from_secs(10);
        let mut not_after = not_before + parse_duration("30d").unwrap();

        if let Ok(ttl_value) = req.get_data("ttl") {
            let ttl = ttl_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;
            let ttl_dur = parse_duration(ttl)?;
            let req_ttl_not_after_dur = SystemTime::now() + ttl_dur;
            let req_ttl_not_after =
                Asn1Time::from_unix(req_ttl_not_after_dur.duration_since(UNIX_EPOCH)?.as_secs() as i64)?;
            let ca_not_after = ca_bundle.certificate.not_after();
            match ca_not_after.compare(&req_ttl_not_after) {
                Ok(ret) => {
                    if ret == std::cmp::Ordering::Less {
                        return Err(RvError::ErrRequestInvalid);
                    }
                    not_after = req_ttl_not_after_dur;
                }
                Err(err) => {
                    return Err(RvError::OpenSSL { source: err });
                }
            }
        }

        // Build the Certificate (subject name + SANs) via the shared utility, then
        // override not_before/not_after with the CA-TTL-checked values computed above.
        let mut cert = util::generate_certificate(&role_entry, req)?;
        cert.not_before = not_before;
        cert.not_after = not_after;

        let cert_bundle = cert.to_cert_bundle(Some(&ca_bundle.certificate), Some(&ca_bundle.private_key))?;

        if !role_entry.no_store {
            let serial_number_hex = cert_bundle.serial_number.replace(':', "-").to_lowercase();
            self.store_cert(req, &serial_number_hex, &cert_bundle.certificate).await?;
        }

        let cert_expiration = utils::asn1time_to_timestamp(cert_bundle.certificate.not_after().to_string().as_str())?;
        let ca_chain_pem: String = cert_bundle
            .ca_chain
            .iter()
            .map(|x509| x509.to_pem().unwrap())
            .map(|pem| String::from_utf8_lossy(&pem).to_string())
            .collect::<Vec<String>>()
            .join("");

        let resp_data = json!({
            "expiration": cert_expiration,
            "issuing_ca": String::from_utf8_lossy(&ca_bundle.certificate.to_pem()?),
            "ca_chain": ca_chain_pem,
            "certificate": String::from_utf8_lossy(&cert_bundle.certificate.to_pem()?),
            "private_key": String::from_utf8_lossy(&cert_bundle.private_key.private_key_to_pem_pkcs8()?),
            "private_key_type": cert_bundle.private_key_type.clone(),
            "serial_number": cert_bundle.serial_number.clone(),
        })
        .as_object()
        .cloned();

        if role_entry.generate_lease {
            let mut secret_data: Map<String, Value> = Map::new();
            secret_data.insert("serial_number".to_string(), Value::String(cert_bundle.serial_number.clone()));

            let mut resp = backend.secret("pki").unwrap().response(resp_data, Some(secret_data));
            let secret = resp.secret.as_mut().unwrap();

            let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;

            secret.lease.ttl = Duration::from_secs(cert_expiration as u64) - now_timestamp;
            secret.lease.renewable = true;

            Ok(Some(resp))
        } else {
            Ok(Some(Response::data_response(resp_data)))
        }
    }
}
