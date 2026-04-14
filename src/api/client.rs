use std::{collections::HashMap, fs, path::PathBuf, sync::Arc, time::Duration};

use better_default::Default;
use serde_json::{Map, Value};
use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};

use super::HttpResponse;
use crate::errors::RvError;

#[derive(Clone)]
pub struct TLSConfig {
    tls_config: TlsConfig,
}

#[derive(Default, Clone)]
pub struct TLSConfigBuilder {
    pub server_ca_pem: Option<Vec<u8>>,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub tls_server_name: Option<String>,
    pub insecure: bool,
}

#[derive(Default, Clone)]
pub struct Client {
    #[default("https://127.0.0.1:8200".into())]
    pub address: String,
    pub token: String,
    #[default(HashMap::new())]
    pub headers: HashMap<String, String>,
    pub tls_config: Option<TLSConfig>,
    #[default(ureq::Agent::new_with_defaults())]
    pub http_client: ureq::Agent,
    #[default(1)]
    pub api_version: u8,
}

impl TLSConfigBuilder {
    pub fn new() -> Self {
        TLSConfigBuilder::default()
    }

    pub fn with_server_ca_path(mut self, server_ca_path: &PathBuf) -> Result<Self, RvError> {
        let cert_data = fs::read(server_ca_path)?;
        self.server_ca_pem = Some(cert_data);
        Ok(self)
    }

    pub fn with_server_ca_pem(mut self, server_ca_pem: &str) -> Self {
        self.server_ca_pem = Some(server_ca_pem.as_bytes().to_vec());
        self
    }

    pub fn with_client_cert_path(
        mut self,
        client_cert_path: &PathBuf,
        client_key_path: &PathBuf,
    ) -> Result<Self, RvError> {
        let cert_data = fs::read(client_cert_path)?;
        self.client_cert_pem = Some(cert_data);

        let key_data = fs::read(client_key_path)?;
        self.client_key_pem = Some(key_data);

        Ok(self)
    }

    pub fn with_client_cert_pem(mut self, client_cert_pem: &str, client_key_pem: &str) -> Self {
        self.client_cert_pem = Some(client_cert_pem.as_bytes().to_vec());
        self.client_key_pem = Some(client_key_pem.as_bytes().to_vec());

        self
    }

    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;

        self
    }

    pub fn build(self) -> Result<TLSConfig, RvError> {
        let mut tls_builder = TlsConfig::builder();

        if self.insecure {
            log::debug!("Certificate verification disabled");
            tls_builder = tls_builder.disable_verification(true);
        } else if let Some(server_ca) = &self.server_ca_pem {
            let root_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(server_ca)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            tls_builder = tls_builder.root_certs(RootCerts::Specific(Arc::new(root_certs)));
        }

        if let (Some(client_cert_pem), Some(client_key_pem)) = (&self.client_cert_pem, &self.client_key_pem) {
            let client_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(client_cert_pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            let client_key = PrivateKey::from_pem(client_key_pem)
                .map_err(|e| RvError::ErrResponse(e.to_string()))?;
            tls_builder = tls_builder.client_cert(Some(ClientCert::new_with_certs(&client_certs, client_key)));
        }

        Ok(TLSConfig { tls_config: tls_builder.build() })
    }
}

impl Client {
    pub fn new() -> Self {
        Client::default()
    }

    pub fn with_addr(mut self, addr: &str) -> Self {
        self.address = addr.into();
        self
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = token.into();
        self
    }

    pub fn with_tls_config(mut self, tls_config: TLSConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    pub fn with_api_version(mut self, version: u8) -> Self {
        self.api_version = version;
        self
    }

    pub fn api_prefix(&self) -> &str {
        match self.api_version {
            2 => "/v2",
            _ => "/v1",
        }
    }

    pub fn add_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn build(mut self) -> Self {
        let mut config_builder = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .allow_non_standard_methods(true);

        if let Some(tls_config) = &self.tls_config {
            config_builder = config_builder.tls_config(tls_config.tls_config.clone());
        }

        self.http_client = config_builder.build().new_agent();
        self
    }

    pub fn request<S: Into<String>>(
        &self,
        method: &str,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<HttpResponse, RvError> {
        let path = path.into();
        let url = if path.starts_with('/') {
            format!("{}{}", self.address, path)
        } else {
            format!("{}/{}", self.address, path)
        };
        log::debug!("request url: {url}, method: {method}");

        let method_upper = method.to_uppercase();
        let build_request = |builder: http::request::Builder| -> http::request::Builder {
            let builder = builder.header("Accept", "application/json");
            if !path.ends_with("/login") {
                builder.header("X-BastionVault-Token", &self.token)
            } else {
                builder
            }
        };

        let mut ret = HttpResponse { method: method.to_string(), url: url.clone(), ..Default::default() };

        let response_result = if let Some(send_data) = data {
            let body = serde_json::to_vec(&send_data)?;
            let req = build_request(
                http::Request::builder()
                    .method(method_upper.as_str())
                    .uri(&url)
                    .header("Content-Type", "application/json"),
            )
            .body(body)?;
            self.http_client.run(req)
        } else {
            let req = build_request(http::Request::builder().method(method_upper.as_str()).uri(&url))
                .body(())?;
            self.http_client.run(req)
        };

        match response_result {
            Ok(mut response) => {
                ret.response_status = response.status().as_u16();
                if ret.response_status == 204 {
                    return Ok(ret.clone());
                }
                let json: Value = response.body_mut().read_json()?;
                ret.response_data = Some(json);
                Ok(ret.clone())
            }
            Err(e) => {
                log::error!("Request failed: {e}");
                Err(RvError::UreqError { source: e })
            }
        }
    }

    pub fn request_list<S: Into<String>>(&self, path: S) -> Result<HttpResponse, RvError> {
        self.request("LIST", path, None)
    }

    pub fn request_read<S: Into<String>>(&self, path: S) -> Result<HttpResponse, RvError> {
        self.request("GET", path, None)
    }

    pub fn request_get<S: Into<String>>(&self, path: S) -> Result<HttpResponse, RvError> {
        self.request("GET", path, None)
    }

    pub fn request_write<S: Into<String>>(
        &self,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<HttpResponse, RvError> {
        self.request("POST", path, data)
    }

    pub fn request_put<S: Into<String>>(
        &self,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<HttpResponse, RvError> {
        self.request("PUT", path, data)
    }

    pub fn request_delete<S: Into<String>>(
        &self,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<HttpResponse, RvError> {
        self.request("DELETE", path, data)
    }
}
