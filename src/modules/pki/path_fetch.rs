use std::{collections::HashMap, sync::Arc};

use serde_json::json;

use super::{PkiBackend, PkiBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
    utils::cert::CertBundle,
};

#[maybe_async::maybe_async]
impl PkiBackend {
    pub fn fetch_ca_path(&self) -> Path {
        let pki_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: "ca(/pem)?",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_ca}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }

    pub fn fetch_crl_path(&self) -> Path {
        let pki_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: "crl(/pem)?",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_crl}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }

    pub fn fetch_cert_path(&self) -> Path {
        let pki_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"cert/(?P<serial>[0-9A-Fa-f-:]+)",
            fields: {
                "serial": {
                    field_type: FieldType::Str,
                    description: "Certificate serial number, in colon- or hyphen-separated octal"
                }
            },
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_cert}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }

    pub fn fetch_cert_crl_path(&self) -> Path {
        let pki_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: "cert/crl",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_cert_crl}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_fetch_cert_bundle(&self, cert_bundle: &CertBundle) -> Result<Option<Response>, RvError> {
        let ca_chain_pem = crate::utils::cert::certificate_chain_pem_string(&cert_bundle.ca_chain, true)?;
        let resp_data = json!({
            "ca_chain": ca_chain_pem,
            "certificate": crate::utils::cert::certificate_pem_string(&cert_bundle.certificate)?,
            "serial_number": cert_bundle.serial_number.clone(),
        })
        .as_object()
        .cloned();

        Ok(Some(Response::data_response(resp_data)))
    }

    pub async fn read_path_fetch_ca(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let ca_bundle = self.fetch_ca_bundle(req).await?;
        self.handle_fetch_cert_bundle(&ca_bundle).await
    }

    pub async fn read_path_fetch_crl(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub async fn read_path_fetch_cert(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let serial_number_value = req.get_data("serial")?;
        let serial_number = serial_number_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;
        let serial_number_hex = serial_number.replace(':', "-").to_lowercase();
        let cert_der = self.fetch_cert_der(req, &serial_number_hex).await?;
        let ca_bundle = self.fetch_ca_bundle(req).await?;

        let mut ca_chain_pem = crate::utils::cert::certificate_chain_pem_string(&ca_bundle.ca_chain, true)?;

        ca_chain_pem.push_str(&crate::utils::cert::certificate_pem_string(&ca_bundle.certificate)?);

        let resp_data = json!({
            "ca_chain": ca_chain_pem,
            "certificate": crate::utils::cert::certificate_pem_string_from_der(&cert_der)?,
            "serial_number": serial_number,
        })
        .as_object()
        .cloned();

        Ok(Some(Response::data_response(resp_data)))
    }

    pub async fn read_path_fetch_cert_crl(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub async fn fetch_cert_der(&self, req: &Request, serial_number: &str) -> Result<Vec<u8>, RvError> {
        let entry = req.storage_get(format!("certs/{serial_number}").as_str()).await?;
        if entry.is_none() {
            return Err(RvError::ErrPkiCertNotFound);
        }

        Ok(entry.unwrap().value)
    }

    pub async fn store_cert_der(&self, req: &Request, serial_number: &str, value: Vec<u8>) -> Result<(), RvError> {
        let entry = StorageEntry { key: format!("certs/{serial_number}"), value };
        req.storage_put(&entry).await?;
        Ok(())
    }

    pub async fn delete_cert(&self, req: &Request, serial_number: &str) -> Result<(), RvError> {
        req.storage_delete(format!("certs/{serial_number}").as_str()).await?;
        Ok(())
    }
}
