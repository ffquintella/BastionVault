//! TLS configuration builder for [`RemoteBackend`](crate::RemoteBackend).
//!
//! Ported from `bastion_vault::api::client::TLSConfigBuilder` so the
//! client crate doesn't depend on the server. Same behaviour: PEM
//! material on disk or in memory, optional client mTLS, optional
//! `insecure` toggle that disables verification (for self-signed
//! dev/test setups — never production).

use std::{fs, path::PathBuf, sync::Arc};

use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig};

use crate::error::ClientError;

#[derive(Default, Clone)]
pub struct TLSConfigBuilder {
    pub server_ca_pem: Option<Vec<u8>>,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub tls_server_name: Option<String>,
    pub insecure: bool,
}

#[derive(Clone)]
pub struct ClientTlsConfig {
    pub(crate) tls_config: TlsConfig,
}

impl TLSConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_server_ca_path(mut self, path: &PathBuf) -> Result<Self, ClientError> {
        self.server_ca_pem = Some(fs::read(path)?);
        Ok(self)
    }

    pub fn with_server_ca_pem(mut self, pem: &str) -> Self {
        self.server_ca_pem = Some(pem.as_bytes().to_vec());
        self
    }

    pub fn with_client_cert_path(
        mut self,
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<Self, ClientError> {
        self.client_cert_pem = Some(fs::read(cert_path)?);
        self.client_key_pem = Some(fs::read(key_path)?);
        Ok(self)
    }

    pub fn with_client_cert_pem(mut self, cert_pem: &str, key_pem: &str) -> Self {
        self.client_cert_pem = Some(cert_pem.as_bytes().to_vec());
        self.client_key_pem = Some(key_pem.as_bytes().to_vec());
        self
    }

    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    pub fn build(self) -> Result<ClientTlsConfig, ClientError> {
        let mut tls_builder = TlsConfig::builder();

        if self.insecure {
            log::debug!("bv-client: TLS verification disabled");
            tls_builder = tls_builder.disable_verification(true);
        } else if let Some(server_ca) = &self.server_ca_pem {
            let root_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(server_ca)
                .filter_map(|item| match item {
                    Ok(PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            tls_builder = tls_builder.root_certs(RootCerts::Specific(Arc::new(root_certs)));
        }

        if let (Some(cert_pem), Some(key_pem)) = (&self.client_cert_pem, &self.client_key_pem) {
            let client_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(cert_pem)
                .filter_map(|item| match item {
                    Ok(PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            let client_key = PrivateKey::from_pem(key_pem)
                .map_err(|e| ClientError::tls(e.to_string()))?;
            tls_builder = tls_builder
                .client_cert(Some(ClientCert::new_with_certs(&client_certs, client_key)));
        }

        Ok(ClientTlsConfig { tls_config: tls_builder.build() })
    }
}
