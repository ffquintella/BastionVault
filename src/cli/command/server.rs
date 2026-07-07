use std::{
    default::Default,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use actix_web::{
    middleware::{self, from_fn},
    web, App, HttpResponse, HttpServer,
};
use anyhow::format_err;
use clap::Parser;
use derive_more::Deref;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use rustls_pemfile::{certs, private_key};
use sysexits::ExitCode;

use crate::{
    cli::{command, config, config::TlsVersion},
    errors::RvError,
    http,
    metrics::{manager::MetricsManager, middleware::metrics_midleware},
    storage,
    utils::rustls::OptionalClientAuthVerifier,
    BastionVault, EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_LOAD_CONFIG_FAILURE, EXIT_CODE_OK,
};

pub const WORK_DIR_PATH_DEFAULT: &str = "/tmp/bastion_vault";

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"This command starts a BastionVault server that responds to API requests. By default,
BastionVault will start in a "sealed" state. The BastionVault cluster must be initialized
before use, usually by the "bvault operator init" command. Each BastionVault server must
also be unsealed using the "bvault operator unseal" command or the API before the
server can respond to requests.

The recommended storage backend for production is "hiqlite", which provides built-in
Raft-based replication and high availability. The "file" backend is intended for
development only and does not support replication or failover.

Start a production server:

  $ bvault server --config=/etc/bvault/config.hcl

Example configurations are available in the config/ directory:

  config/dev.hcl         - Development (file backend, no TLS)
  config/single-node.hcl - Single-node hiqlite with TLS
  config/ha-cluster.hcl  - Multi-node HA cluster with hiqlite"#
)]
pub struct Server {
    #[deref]
    #[command(flatten, next_help_heading = "Command Options")]
    command_options: command::CommandOptions,
}

impl Server {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(config_path) = &self.config {
            return match self.main(config_path) {
                Ok(_) => EXIT_CODE_OK,
                Err(e) => {
                    println!("server error: {e:?}");
                    std::process::exit(EXIT_CODE_LOAD_CONFIG_FAILURE as i32);
                }
            };
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }

    pub fn main(&self, config_path: &PathBuf) -> Result<(), RvError> {
        // Stamp the process start time exactly once. Read back from
        // `crate::server_info::started_at()` by the `/sys/info`
        // handler and the GUI's Server Info dialog.
        crate::server_info::record_start_now();
        let config = config::load_config(&config_path.to_string_lossy())?;

        if config.storage.len() != 1 {
            return Err(RvError::ErrConfigStorageNotFound);
        }

        if config.listener.len() != 1 {
            return Err(RvError::ErrConfigListenerNotFound);
        }

        // Stage process-plugin executables in the operator-configured
        // directory (if any). The default OS temp dir is often `noexec`
        // in hardened containers, which breaks process-runtime plugins.
        // The `BV_PLUGIN_RUNTIME_DIR` env var still overrides this at
        // runtime; here we honour the config-file value.
        if !config.plugin_runtime_dir.is_empty() {
            crate::plugins::set_plugin_runtime_dir(config.plugin_runtime_dir.as_str());
            if let Err(e) = fs::create_dir_all(config.plugin_runtime_dir.as_str()) {
                log::warn!(
                    "could not create plugin_runtime_dir {}: {e}",
                    config.plugin_runtime_dir
                );
            }
        }

        env::set_var("RUST_LOG", config.log_level.as_str());
        // Custom file-fanout logger: `operations.log` gets every
        // record at or above `log_level`; `security.log` gets the
        // subset whose target is `security` (seal/unseal, login
        // failures, policy denials). When `log_dir` is empty we fall
        // back to stderr only and skip the audit-log auto-bootstrap.
        if let Err(e) = crate::logging::init(crate::logging::LogConfig {
            level: config.log_level.as_str(),
            log_dir: config.log_dir.as_str(),
            log_to_stderr: config.log_to_stderr,
            rotate_size_bytes: config
                .log_rotate_size_mb
                .saturating_mul(1024 * 1024),
            rotate_keep: config.log_rotate_keep,
        }) {
            eprintln!("logging init failed: {e}. Falling back to env_logger.");
            env_logger::init();
        }

        let (_, storage) = config.storage.iter().next().unwrap();
        let (_, listener) = config.listener.iter().next().unwrap();

        let listener = listener.clone();

        let mut work_dir = WORK_DIR_PATH_DEFAULT.to_string();
        if !config.work_dir.is_empty() {
            work_dir.clone_from(&config.work_dir);
        }

        if !Path::new(work_dir.as_str()).exists() {
            log::info!("create work_dir: {work_dir}");
            fs::create_dir_all(work_dir.as_str())?;
        }

        #[cfg(not(windows))]
        if config.daemon {
            // start daemon
            let log_path = format!("{work_dir}/bastion_vault.log");
            let mut pid_path = config.pid_file.clone();
            if !config.pid_file.starts_with('/') {
                pid_path = work_dir.clone() + pid_path.as_str();
            }

            let mut user = "onbody".to_owned();
            if !config.daemon_user.is_empty() {
                user.clone_from(&config.daemon_user);
            }

            let mut group = "onbody".to_owned();
            if !config.daemon_group.is_empty() {
                group.clone_from(&config.daemon_group);
            }

            let log_file = std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .truncate(false)
                .open(log_path)
                .unwrap();

            let daemonize = daemonize::Daemonize::new()
                .working_directory(work_dir.as_str())
                .user(user.as_str())
                .group(group.as_str())
                .umask(0o027)
                .stdout(log_file.try_clone().unwrap())
                .stderr(log_file)
                .pid_file(pid_path.clone())
                .chown_pid_file(true)
                .privileged_action(|| log::info!("Start bastion_vault server daemon"));

            match daemonize.start() {
                Ok(_) => {
                    let pid = std::fs::read_to_string(pid_path)?;
                    log::info!("The bastion_vault server daemon process started successfully, pid is {pid}");
                    log::debug!("run user: {user}, group: {group}");
                }
                Err(e) => log::error!("Error, {e}"),
            }
        }

        log::debug!("config_path: {}, work_dir_path: {}", config_path.to_string_lossy(), work_dir.as_str());

        let server = actix_rt::System::new();

        if storage.stype == "file" {
            log::warn!(
                "Using the \"file\" storage backend. This is intended for development only \
                 and does not support replication or high availability. \
                 For production, use \"hiqlite\" storage. See config/single-node.hcl or config/ha-cluster.hcl."
            );
        }

        // Use the async backend constructor so `obfuscate_keys = true`
        // on a `file` target can bootstrap its salt against the
        // wrapped provider. Sync `new_backend` would silently drop
        // the flag with a warning. Run on a small current-thread
        // runtime — the async work is one storage round-trip; the
        // long-lived runtime is the actix system below.
        let backend = {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for backend bootstrap");
            rt.block_on(async {
                storage::new_backend_async(storage.stype.as_str(), &storage.config).await
            })
            .expect("backend init")
        };

        let metrics_manager = Arc::new(RwLock::new(MetricsManager::new(config.collection_interval)));
        let system_metrics = metrics_manager.read().unwrap().system_metrics.clone();

        let bvault = BastionVault::new(backend, Some(&config))?;
        let core = bvault.core.load().clone();

        // HSM seal: if the config declares an `hsm "..."` block, open the
        // backend, install the auto-unseal seal provider, and attempt to
        // unseal without operator shares. Fail-closed — any error leaves the
        // vault sealed and is logged loudly; the process still starts so the
        // condition is diagnosable (an invalid *config*, by contrast, aborts
        // startup rather than silently falling back to Shamir).
        match config.resolve_hsm() {
            Ok(Some(hsm_cfg)) => {
                let physical = core.physical.clone();
                let hsm_core = core.clone();
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime for HSM bootstrap");
                let result = rt.block_on(async {
                    let backend = crate::hsm::new_backend(&hsm_cfg).await?;
                    log::info!(
                        target: "security",
                        "HSM seal backend `{}` (serial {}) online",
                        backend.backend_type(),
                        backend.device_serial()
                    );
                    let provider = std::sync::Arc::new(crate::seal::hsm::HsmSealProvider::new(
                        backend,
                        physical,
                        hsm_cfg.clone(),
                    ));
                    hsm_core.set_seal_provider(provider);
                    if hsm_core.inited().await? {
                        hsm_core.auto_unseal().await
                    } else {
                        log::info!(
                            target: "security",
                            "HSM seal configured; vault not initialized — `operator init` will wrap the KEK under the HSM"
                        );
                        Ok(false)
                    }
                });
                match result {
                    Ok(true) => log::info!(target: "security", "HSM auto-unseal succeeded"),
                    Ok(false) => {}
                    Err(e) => log::error!(
                        target: "security",
                        "HSM auto-unseal failed; vault remains sealed: {e}"
                    ),
                }
            }
            Ok(None) => {}
            Err(e) => {
                log::error!("invalid HSM seal configuration: {e}");
                return Err(e);
            }
        }

        // Phase 1.5: parse BASTIONVAULT_TRUSTED_PROXIES once at start.
        // Bad CIDRs are logged at warn level but do not abort the
        // server — operators expect tail-of-startup config issues to
        // surface in logs, not crash the process during a rolling
        // restart. Parsing always returns a usable (possibly empty)
        // TrustedProxies; an empty set means "no proxy promotion,"
        // which is the safe default.
        let (trusted_proxies, bad_cidrs) = http::client_ip::TrustedProxies::from_env();
        for bad in &bad_cidrs {
            log::warn!(
                "BASTIONVAULT_TRUSTED_PROXIES: ignoring entry `{bad}` (not a valid CIDR)"
            );
        }
        if !trusted_proxies.is_empty() {
            log::info!(
                "BASTIONVAULT_TRUSTED_PROXIES active — X-Forwarded-For / Forwarded headers \
                 will be promoted for connections originating from configured CIDRs"
            );
        }
        // Phase 1.5: parse BASTIONVAULT_PROXY_PROTOCOL. The acceptor
        // wiring is not landed yet (the parser lives in
        // src/http/proxy_protocol.rs but isn't intercepting
        // connections); for now we just validate the env var so an
        // invalid value fails loudly at startup instead of silently
        // doing nothing.
        match http::proxy_protocol::ProxyProtocolMode::from_env() {
            Ok(http::proxy_protocol::ProxyProtocolMode::Off) => {}
            Ok(mode) => {
                log::warn!(
                    "BASTIONVAULT_PROXY_PROTOCOL={mode:?} requested, but the acceptor \
                     wiring is not yet active (Phase 1.5 ships the parser only). \
                     Use BASTIONVAULT_TRUSTED_PROXIES + X-Forwarded-For meanwhile."
                );
            }
            Err(e) => {
                log::error!("invalid BASTIONVAULT_PROXY_PROTOCOL: {e}");
            }
        }
        let trusted_proxies = web::Data::new(trusted_proxies);

        let mut http_server = HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::default())
                .wrap(from_fn(metrics_midleware))
                .app_data(web::Data::new(core.clone()))
                .app_data(web::Data::new(metrics_manager.clone()))
                .app_data(trusted_proxies.clone())
                .configure(http::init_service)
                .default_service(web::to(HttpResponse::NotFound))
        })
        .on_connect(http::request_on_connect_handler);

        log::info!(
            "start listen, addr: {}, tls_disable: {}, tls_disable_client_certs: {}",
            listener.address,
            listener.tls_disable,
            listener.tls_disable_client_certs
        );

        if listener.tls_disable {
            http_server = http_server.bind(listener.address)?;
        } else {
            let rustls_config = build_rustls_server_config(&listener)?;
            publish_ca_for_local_clients(&listener);
            http_server = http_server.bind_rustls_0_23(listener.address, rustls_config)?;
        }

        log::info!("bastion_vault server starts, waiting for request...");

        server.block_on(async {
            tokio::spawn(async {
                system_metrics.start_collecting().await;
            });
            http_server.run().await
        })?;
        let _ = server.run();

        Ok(())
    }
}

fn build_rustls_server_config(listener: &config::Listener) -> Result<ServerConfig, RvError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_chain = load_rustls_cert_chain(Path::new(&listener.tls_cert_file))?;
    let private_key = load_rustls_private_key(Path::new(&listener.tls_key_file))?;
    let versions = rustls_versions(listener.tls_min_version, listener.tls_max_version)?;

    let builder = ServerConfig::builder_with_protocol_versions(versions.as_slice());
    let mut config = if listener.tls_require_and_verify_client_cert {
        let ca_file = Path::new(&listener.tls_client_ca_file);
        if listener.tls_client_ca_file.is_empty() {
            log::error!("tls_client_ca_file is required when tls_require_and_verify_client_cert is enabled");
            return Err(RvError::ErrConfigLoadFailed);
        }

        let client_roots = load_rustls_root_store(ca_file)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| RvError::ErrConfigLoadFailed)?;
        builder.with_client_cert_verifier(verifier).with_single_cert(cert_chain, private_key)?
    } else if listener.tls_disable_client_certs {
        builder.with_no_client_auth().with_single_cert(cert_chain, private_key)?
    } else {
        builder
            .with_client_cert_verifier(Arc::new(OptionalClientAuthVerifier::new()))
            .with_single_cert(cert_chain, private_key)?
    };

    log::info!("tls_cipher_suites (rustls): {}", listener.tls_cipher_suites);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn rustls_versions(
    min: TlsVersion,
    max: TlsVersion,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, RvError> {
    if min == TlsVersion::Tls13 && max == TlsVersion::Tls12 {
        log::error!("invalid TLS version range");
        return Err(RvError::ErrConfigLoadFailed);
    }

    let versions = match (min, max) {
        (TlsVersion::Tls12, TlsVersion::Tls12) => vec![&rustls::version::TLS12],
        (TlsVersion::Tls13, TlsVersion::Tls13) => vec![&rustls::version::TLS13],
        (TlsVersion::Tls12, TlsVersion::Tls13) => vec![&rustls::version::TLS13, &rustls::version::TLS12],
        _ => {
            log::error!("rustls server mode only supports tls12 and tls13");
            return Err(RvError::ErrConfigLoadFailed)
        }
    };

    Ok(versions)
}

/// Publish the serving certificate to `tls_publish_ca_path` (if configured)
/// so local CLI invocations can find it as a trust anchor — see
/// `HttpOptions::client_at` in the CLI for the discovery side. Failures here
/// are logged but never block server start: the path is a convenience, not a
/// dependency.
fn publish_ca_for_local_clients(listener: &config::Listener) {
    let dest = listener.tls_publish_ca_path.trim();
    if dest.is_empty() {
        return;
    }
    let dest = Path::new(dest);
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(parent) {
                log::warn!("tls_publish_ca_path: cannot create {}: {}", parent.display(), e);
                return;
            }
        }
    }
    match fs::copy(&listener.tls_cert_file, dest) {
        Ok(_) => log::info!(
            "published serving cert to {} for local CLI trust",
            dest.display()
        ),
        Err(e) => log::warn!(
            "tls_publish_ca_path: failed to copy {} -> {}: {}",
            listener.tls_cert_file,
            dest.display(),
            e
        ),
    }
}

fn load_rustls_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, RvError> {
    let cert_pem = fs::read(path).map_err(|err| format_err!("unable to read proxy cert {} - {}", path.display(), err))?;
    let mut reader = cert_pem.as_slice();
    Ok(certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn load_rustls_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, RvError> {
    let key_pem = fs::read(path).map_err(|err| format_err!("unable to read proxy key {} - {}", path.display(), err))?;
    let mut reader = key_pem.as_slice();
    private_key(&mut reader)?.ok_or_else(|| {
        log::error!("no private key found in {}", path.display());
        RvError::ErrConfigLoadFailed
    })
}

fn load_rustls_root_store(path: &Path) -> Result<RootCertStore, RvError> {
    let ca_pem = fs::read(path).map_err(|err| format_err!("unable to read client CA {} - {}", path.display(), err))?;
    let mut reader = ca_pem.as_slice();
    let cert_chain = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    let mut roots = RootCertStore::empty();
    for cert in cert_chain {
        roots.add(cert)?;
    }
    Ok(roots)
}
