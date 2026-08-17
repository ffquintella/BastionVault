//! The in-process HTTP test harness: [`TestHttpServer`] stands up a real
//! actix `App` over a real [`Core`], on a real port, and drives it over the
//! wire with `ureq`.
//!
//! It lived in `bastion_vault::test_utils` until Phase 4, and it is the reason
//! that module named `crate::http` at all. It cannot stay there: the actix
//! `App` it builds is configured by [`crate::init_service`], so the harness
//! has to sit on the same side of the split as the routes it serves.
//!
//! The rest of `test_utils` — `new_test_bastion_vault`, the seal helpers, the
//! `test_*_api` request helpers — stays in `bastion_vault` behind that crate's
//! `test-support` feature, which this module's feature turns on. Root-crate
//! tests reach `TestHttpServer` through a `#[cfg(test)]` re-export in
//! `bastion_vault::test_utils`, so none of their ~50 call sites changed.
//!
//! Gated behind the `test-support` feature: it spawns threads, binds ports and
//! shells out to the `bvault` binary, none of which belongs in a shipped build.
//! Same arrangement `bv-storage` uses for its backend fixtures (Phase 1).

use std::{
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Barrier, RwLock},
    thread,
    time::Duration,
};

use actix_web::{
    dev::Server,
    middleware::{self, from_fn},
    web, App, HttpResponse, HttpServer,
};
use bv_metrics::{manager::MetricsManager, system_metrics::SystemMetrics};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde_json::{json, Map, Value};
use tokio::sync::oneshot;
use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};

use bastion_vault::{
    api::{client::TLSConfigBuilder, Client},
    bv_error_response, bv_error_string,
    config::Config,
    core::{Core, SealConfig},
    errors::RvError,
    storage::Backend,
    test_utils::{
        get_project_binary_path, new_test_bastion_vault, new_unseal_test_bastion_vault,
        unseal_test_bastion_vault_core,
    },
    utils::rustls::OptionalClientAuthVerifier,
    BastionVault,
};

use crate::{client_ip::TrustedProxies, init_service, middleware::metrics::metrics_midleware, request_on_connect_handler};

#[derive(Debug, Clone)]
pub struct TestTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct TestTlsClientAuth {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

pub struct TestHttpServer {
    pub name: String,
    pub binary_path: String,
    pub mount_path: String,
    pub core: Arc<Core>,
    pub root_token: String,
    pub token: String,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub cert_dir: String,
    pub tls_enable: bool,
    pub listen_addr: String,
    pub url_prefix: String,
    pub stop_tx: Option<oneshot::Sender<()>>,
    pub thread: Option<thread::JoinHandle<()>>,
}

#[maybe_async::maybe_async]
impl TestHttpServer {
    pub async fn new(name: &str, tls_enable: bool) -> Self {
        
        let seal_config = SealConfig { secret_shares: 10, secret_threshold: 5 };
        let mut test_http_server = TestHttpServer::new_without_init(name, tls_enable);

        let core = test_http_server.core.clone();
        let init_result = core.init(&seal_config).await;
        println!("init_result: {:?}", init_result);
        let init_result = init_result.unwrap();

        let mut keys: Vec<Vec<u8>> = Vec::new();

        for i in 0..seal_config.secret_threshold {
            keys.push(init_result.secret_shares[i as usize].clone());
        }

        let k: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();

        let result = unseal_test_bastion_vault_core(core.as_ref(), &k).await;
        assert!(result);

        let root_token = init_result.root_token.clone();
        println!("root_token: {:?}", root_token);

        test_http_server.root_token = root_token;

        test_http_server
    }

    pub fn new_without_init(name: &str, _tls_enable: bool) -> Self {
        let barrier = Arc::new(Barrier::new(2));
        let (stop_tx, stop_rx) = oneshot::channel();
        let bvault = new_test_bastion_vault(name);
        let core = bvault.core.load().clone();

        let scheme = "http";
        let ca_cert_pem = "".into();
        let ca_key_pem = "".into();
        let server_cert_pem = "".into();
        let server_key_pem = "".into();
        let test_tls_config = None;
        let cert_dir = "".into();

        // TLS test certificate generation was removed with OpenSSL; fall back to plaintext
        let tls_enable = false;
        let _ = tls_enable;

        let (server, listen_addr) = new_test_http_server(core.clone(), test_tls_config).unwrap();
        let server_thread = start_test_http_server(server, barrier.clone(), stop_rx);

        barrier.wait();

        let url_prefix = format!("{}://{}/v1", scheme, listen_addr);

        Self {
            name: name.to_string(),
            binary_path: get_project_binary_path(),
            core,
            root_token: "".into(),
            token: "".into(),
            tls_enable,
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            cert_dir,
            listen_addr,
            url_prefix,
            mount_path: "".into(),
            stop_tx: Some(stop_tx),
            thread: Some(server_thread),
        }
    }

    pub fn new_with_backend(backend: Arc<dyn Backend>, _tls_enable: bool) -> Self {
        let config = Config::default();
        let barrier = Arc::new(Barrier::new(2));
        let (stop_tx, stop_rx) = oneshot::channel();
        let bvault = BastionVault::new(backend, Some(&config)).unwrap();
        let core = bvault.core.load().clone();

        let scheme = "http";
        let ca_cert_pem = "".into();
        let ca_key_pem = "".into();
        let server_cert_pem = "".into();
        let server_key_pem = "".into();
        let test_tls_config = None;
        let cert_dir = "".into();

        // TLS test certificate generation was removed with OpenSSL; fall back to plaintext
        let tls_enable = false;
        let _ = tls_enable;

        let (server, listen_addr) = new_test_http_server(core.clone(), test_tls_config).unwrap();
        let server_thread = start_test_http_server(server, barrier.clone(), stop_rx);

        barrier.wait();

        let url_prefix = format!("{}://{}/v1", scheme, listen_addr);

        Self {
            name: "".into(),
            binary_path: get_project_binary_path(),
            core,
            root_token: "".into(),
            token: "".into(),
            tls_enable,
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            cert_dir,
            listen_addr,
            url_prefix,
            mount_path: "".into(),
            stop_tx: Some(stop_tx),
            thread: Some(server_thread),
        }
    }

    pub async fn new_with_prometheus(name: &str, _tls_enable: bool) -> Self {
        let barrier = Arc::new(Barrier::new(2));
        let (stop_tx, stop_rx) = oneshot::channel();
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault(name).await;

        let scheme = "http";
        let ca_cert_pem = "".into();
        let ca_key_pem = "".into();
        let server_cert_pem = "".into();
        let server_key_pem = "".into();
        let test_tls_config = None;
        let cert_dir = "".into();

        // TLS test certificate generation was removed with OpenSSL; fall back to plaintext
        let tls_enable = false;
        let _ = tls_enable;

        let collection_interval: u64 = 15;
        let metrics_manager = MetricsManager::new(collection_interval);
        // Per-plugin counters live above the metrics substrate, so the
        // assembly point registers them. See `bv_metrics::manager`.
        metrics_manager.register_collector(bastion_vault::plugins::metrics::register);
        let metrics_manager = Arc::new(RwLock::new(metrics_manager));
        let system_metrics = metrics_manager.read().unwrap().system_metrics.clone();

        let (server, listen_addr) =
            new_test_http_server_with_prometheus(core.clone(), metrics_manager, test_tls_config).unwrap();
        let server_thread = start_test_http_server_with_prometheus(server, barrier.clone(), stop_rx, system_metrics);

        barrier.wait();

        let url_prefix = format!("{}://{}", scheme, listen_addr);

        Self {
            name: name.to_string(),
            binary_path: get_project_binary_path(),
            core,
            root_token,
            token: "".into(),
            tls_enable,
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            cert_dir,
            listen_addr,
            url_prefix,
            mount_path: "".into(),
            stop_tx: Some(stop_tx),
            thread: Some(server_thread),
        }
    }

    pub fn mount(&mut self, path: &str, mtype: &str) -> Result<(u16, Value), RvError> {
        let data = json!({
            "type": mtype,
        })
        .as_object()
        .cloned();
        let (status, resp) = self.write(&format!("sys/mounts/{}", path), data, None)?;
        if status == 200 || status == 204 {
            self.mount_path = path.into();
        }

        Ok((status, resp))
    }

    pub fn mount_auth(&mut self, path: &str, atype: &str) -> Result<(u16, Value), RvError> {
        let data = json!({
            "type": atype,
        })
        .as_object()
        .cloned();
        let (status, resp) = self.write(&format!("sys/auth/{}", path), data, None)?;
        if status == 200 || status == 204 {
            self.mount_path = path.into();
        }

        Ok((status, resp))
    }

    pub fn login(
        &self,
        path: &str,
        data: Option<Map<String, Value>>,
        tls_client_auth: Option<TestTlsClientAuth>,
    ) -> Result<(u16, Value), RvError> {
        self.request("POST", path, data, None, tls_client_auth)
    }

    pub fn list(&self, path: &str, token: Option<&str>) -> Result<(u16, Value), RvError> {
        self.request("LIST", path, None, token, None)
    }

    pub fn read(&self, path: &str, token: Option<&str>) -> Result<(u16, Value), RvError> {
        self.request("GET", path, None, token, None)
    }

    pub fn write(
        &self,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
    ) -> Result<(u16, Value), RvError> {
        self.request("POST", path, data, token, None)
    }

    pub fn delete(
        &self,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
    ) -> Result<(u16, Value), RvError> {
        self.request("DELETE", path, data, token, None)
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
        tls_client_auth: Option<TestTlsClientAuth>,
    ) -> Result<(u16, Value), RvError> {
        self.request_with_headers(method, path, data, token, tls_client_auth, &[])
    }

    /// Like [`Self::request`] but with caller-supplied extra request headers
    /// (e.g. `X-BastionVault-Namespace` to exercise multi-tenancy routing).
    pub fn request_with_headers(
        &self,
        method: &str,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
        tls_client_auth: Option<TestTlsClientAuth>,
        extra_headers: &[(&str, &str)],
    ) -> Result<(u16, Value), RvError> {
        let url = format!("{}/{}", self.url_prefix, path);
        println!("request url: {}, method: {}", url, method);
        let tk = token.unwrap_or(&self.root_token);
        let agent = if self.tls_enable {
            let mut tls_builder = TlsConfig::builder();
            if let Some(client_auth) = tls_client_auth {
                let root_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(client_auth.ca_pem.as_bytes())
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();
                tls_builder = tls_builder.root_certs(RootCerts::Specific(Arc::new(root_certs)));

                let client_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(client_auth.cert_pem.as_bytes())
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();
                let client_key = PrivateKey::from_pem(client_auth.key_pem.as_bytes())
                    .map_err(|e| bv_error_response!("client key format invalid: {}", e))?;
                tls_builder = tls_builder.client_cert(Some(ClientCert::new_with_certs(&client_certs, client_key)));
            } else {
                let root_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(self.ca_cert_pem.as_bytes())
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();
                tls_builder = tls_builder.root_certs(RootCerts::Specific(Arc::new(root_certs)));
            }

            ureq::Agent::config_builder()
                .timeout_connect(Some(Duration::from_secs(10)))
                .timeout_global(Some(Duration::from_secs(30)))
                .http_status_as_error(false)
                .allow_non_standard_methods(true)
                .tls_config(tls_builder.build())
                .build()
                .new_agent()
        } else {
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .allow_non_standard_methods(true)
                .build()
                .new_agent()
        };

        let method_upper = method.to_uppercase();
        let mut req_builder = ::http::Request::builder()
            .method(method_upper.as_str())
            .uri(&url)
            .header("Accept", "application/json");
        if !path.ends_with("/login") {
            req_builder = req_builder.header("X-BastionVault-Token", tk);
        }
        for (name, value) in extra_headers {
            req_builder = req_builder.header(*name, *value);
        }

        let response_result = if let Some(send_data) = data {
            let body = serde_json::to_vec(&send_data)?;
            let req = req_builder.header("Content-Type", "application/json").body(body)?;
            agent.run(req)
        } else {
            let req = req_builder.body(())?;
            agent.run(req)
        };

        match response_result {
            Ok(mut response) => {
                let status = response.status().as_u16();
                if status == 204 {
                    return Ok((status, json!("")));
                }
                let json: Value = response.body_mut().read_json()?;
                Ok((status, json))
            }
            Err(e) => {
                println!("Request failed: {e}");
                Err(RvError::UreqError { source: e })
            }
        }
    }

    pub fn request_prometheus(
        &self,
        method: &str,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
        tls_client_auth: Option<TestTlsClientAuth>,
    ) -> Result<(u16, Value), RvError> {
        let url = format!("{}/{}", self.url_prefix, path);
        println!("request url: {}, method: {}", url, method);
        let tk = token.unwrap_or(&self.root_token);
        let agent = if self.tls_enable {
            let mut tls_builder = TlsConfig::builder();
            if let Some(client_auth) = tls_client_auth {
                let root_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(client_auth.ca_pem.as_bytes())
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();
                tls_builder = tls_builder.root_certs(RootCerts::Specific(Arc::new(root_certs)));

                let client_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(client_auth.cert_pem.as_bytes())
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();
                let client_key = PrivateKey::from_pem(client_auth.key_pem.as_bytes())
                    .map_err(|e| bv_error_response!("client key format invalid: {}", e))?;
                tls_builder = tls_builder.client_cert(Some(ClientCert::new_with_certs(&client_certs, client_key)));
            } else {
                let root_certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(self.ca_cert_pem.as_bytes())
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();
                tls_builder = tls_builder.root_certs(RootCerts::Specific(Arc::new(root_certs)));
            }

            ureq::Agent::config_builder()
                .timeout_connect(Some(Duration::from_secs(10)))
                .timeout_global(Some(Duration::from_secs(30)))
                .http_status_as_error(false)
                .allow_non_standard_methods(true)
                .tls_config(tls_builder.build())
                .build()
                .new_agent()
        } else {
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .allow_non_standard_methods(true)
                .build()
                .new_agent()
        };

        let method_upper = method.to_uppercase();
        let mut req_builder = ::http::Request::builder()
            .method(method_upper.as_str())
            .uri(&url)
            .header("Accept", "application/json");
        if !path.ends_with("/login") {
            req_builder = req_builder.header("X-BastionVault-Token", tk);
        }

        let response_result = if let Some(send_data) = data {
            let body = serde_json::to_vec(&send_data)?;
            let req = req_builder.header("Content-Type", "application/json").body(body)?;
            agent.run(req)
        } else {
            let req = req_builder.body(())?;
            agent.run(req)
        };

        match response_result {
            Ok(mut response) => {
                let status = response.status().as_u16();
                if status == 204 {
                    return Ok((status, json!("")));
                }
                let text = response.body_mut().read_to_string()?;
                let wrapped_json = json!({"metrics":text});
                Ok((status, wrapped_json))
            }
            Err(e) => {
                println!("Request failed: {e}");
                Err(RvError::UreqError { source: e })
            }
        }
    }

    pub fn cli(&self, commands: &[&str], args: &[&str]) -> Result<String, RvError> {
        self.cli_with_input(commands, args, None)
    }

    pub fn cli_with_input(&self, commands: &[&str], args: &[&str], input: Option<&str>) -> Result<String, RvError> {
        let mut cmd = Command::new(&self.binary_path);

        for command in commands {
            cmd.arg(command);
        }

        if self.tls_enable {
            cmd.arg(format!("--address=https://{}", self.listen_addr));
            cmd.arg(format!("--ca-cert={}/ca.crt", self.cert_dir));
            cmd.arg(format!("--client-cert={}/server.crt", self.cert_dir));
            cmd.arg(format!("--client-key={}/key.pem", self.cert_dir));
            cmd.arg("--tls-skip-verify");
        } else {
            cmd.arg(format!("--address=http://{}", self.listen_addr));
        }

        for arg in args {
            cmd.arg(arg);
        }

        cmd.env("VAULT_TOKEN", &self.token);

        println!("cmd: {}, args: {:?}", self.binary_path, cmd.get_args());

        let ret = if let Some(input_value) = input {
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(input_value.as_bytes())?;
            drop(stdin);
            child.wait_with_output()
        } else {
            cmd.output()
        };

        match ret {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok(stdout.into_owned())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Err(bv_error_string!(format!("{}{}", stdout, stderr)))
                }
            }
            Err(e) => Err(bv_error_string!(format!("Failed to execute command: {e}"))),
        }
    }

    pub fn client(&self) -> Result<Client, RvError> {
        let mut client = Client::new().with_token(&self.token);

        if self.tls_enable {
            let mut tls_config_builder = TLSConfigBuilder::new().with_insecure(true);

            tls_config_builder =
                tls_config_builder.with_server_ca_path(&PathBuf::from(&format!("{}/ca.crt", self.cert_dir)))?;

            tls_config_builder = tls_config_builder.with_client_cert_path(
                &PathBuf::from(&format!("{}/server.crt", self.cert_dir)),
                &PathBuf::from(&format!("{}/key.pem", self.cert_dir)),
            )?;

            let tls_config = tls_config_builder.build()?;

            client = client.with_addr(&format!("https://{}", self.listen_addr)).with_tls_config(tls_config);
        } else {
            client = client.with_addr(&format!("http://{}", self.listen_addr));
        }

        Ok(client.build())
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            tx.send(()).expect("Failed to send stop signal.");
        }

        if let Some(thread) = self.thread.take() {
            thread.join().expect("Failed to join thread.");
        }
    }
}
pub fn new_test_http_server(core: Arc<Core>, tls_config: Option<TestTlsConfig>) -> Result<(Server, String), RvError> {
    // Tests run with no trusted proxies — direct-exposure semantics,
    // matching the production default. Phase 1.5 hookup, mirrors
    // src/cli/command/server.rs.
    let trusted_proxies = web::Data::new(TrustedProxies::default());
    let mut http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(core.clone()))
            .app_data(trusted_proxies.clone())
            .app_data(web::Data::new(bastion_vault::exchange::PreviewStore::default()))
            .configure(init_service)
            .default_service(web::to(HttpResponse::NotFound))
    })
    .on_connect(request_on_connect_handler);

    if let Some(tls) = tls_config {
        let tls_config = build_test_rustls_server_config(&tls)?;
        http_server = http_server.bind_rustls_0_23("127.0.0.1:0", tls_config)?;
    } else {
        http_server = http_server.bind("127.0.0.1:0")?;
    }

    let addr_info = http_server.addrs().first().unwrap().to_string();

    println!("HTTP Server is running at {}", addr_info);

    Ok((http_server.run(), addr_info))
}

pub fn new_test_http_server_with_prometheus(
    core: Arc<Core>,
    metrics_manager: Arc<RwLock<MetricsManager>>,
    tls_config: Option<TestTlsConfig>,
) -> Result<(Server, String), RvError> {
    let trusted_proxies = web::Data::new(TrustedProxies::default());
    let mut http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(from_fn(metrics_midleware))
            .app_data(web::Data::new(core.clone()))
            .app_data(web::Data::new(metrics_manager.clone()))
            .app_data(trusted_proxies.clone())
            .app_data(web::Data::new(bastion_vault::exchange::PreviewStore::default()))
            .configure(init_service)
            .default_service(web::to(HttpResponse::NotFound))
    })
    .on_connect(request_on_connect_handler);

    if let Some(tls) = tls_config {
        let tls_config = build_test_rustls_server_config(&tls)?;
        http_server = http_server.bind_rustls_0_23("127.0.0.1:0", tls_config)?;
    } else {
        http_server = http_server.bind("127.0.0.1:0")?;
    }

    let addr_info = http_server.addrs().first().unwrap().to_string();

    println!("HTTP Server is running at {}", addr_info);

    Ok((http_server.run(), addr_info))
}

fn build_test_rustls_server_config(tls: &TestTlsConfig) -> Result<rustls::ServerConfig, RvError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_chain = load_test_rustls_cert_chain(Path::new(&tls.cert_path))?;
    let private_key = load_test_rustls_private_key(Path::new(&tls.key_path))?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(OptionalClientAuthVerifier::new()))
        .with_single_cert(cert_chain, private_key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn load_test_rustls_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, RvError> {
    let cert_pem = fs::read(path)?;
    Ok(CertificateDer::pem_slice_iter(&cert_pem).collect::<Result<Vec<_>, _>>()?)
}

fn load_test_rustls_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, RvError> {
    let key_pem = fs::read(path)?;
    PrivateKeyDer::from_pem_slice(&key_pem).map_err(|err| {
        log::error!("no usable private key in {}: {err}", path.display());
        RvError::ErrConfigLoadFailed
    })
}

pub fn start_test_http_server(
    server: Server,
    barrier: Arc<Barrier>,
    stop_rx: oneshot::Receiver<()>,
) -> thread::JoinHandle<()> {
    let server_thread = thread::spawn(move || {
        let sys = actix_web::rt::System::new();

        let server_future = async {
            server.await.unwrap();
        };

        let stop_future = async {
            stop_rx.await.ok();
        };

        barrier.wait();

        sys.block_on(async {
            tokio::select! {
                _ = server_future => {},
                _ = stop_future => {
                    actix_rt::System::current().stop();
                }
            }
        });

        sys.run().unwrap();
        println!("HTTP Server has stopped.");
    });

    server_thread
}

pub fn start_test_http_server_with_prometheus(
    server: Server,
    barrier: Arc<Barrier>,
    stop_rx: oneshot::Receiver<()>,
    system_metrics: Arc<SystemMetrics>,
) -> thread::JoinHandle<()> {
    let server_thread = thread::spawn(move || {
        let sys = actix_web::rt::System::new();

        let server_future = async {
            server.await.unwrap();
        };

        let stop_future = async {
            stop_rx.await.ok();
        };

        let system_metrics_fucture = async {
            system_metrics.start_collecting().await;
        };

        barrier.wait();

        sys.block_on(async {
            tokio::select! {
                _ = server_future => {},
                _ = system_metrics_fucture => {},
                _ = stop_future => {
                    actix_rt::System::current().stop();
                }
            }
        });

        sys.run().unwrap();
        println!("HTTP Server has stopped.");
    });

    server_thread
}