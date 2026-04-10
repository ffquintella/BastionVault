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
before use, usually by the "rvault operator init" command. Each BastionVault server must
also be unsealed using the "rvault operator unseal" command or the API before the
server can respond to requests.

Start a server with a configuration file:

  $ rvault server --config=/etc/rvault/config.hcl"#
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
        let config = config::load_config(&config_path.to_string_lossy())?;

        if config.storage.len() != 1 {
            return Err(RvError::ErrConfigStorageNotFound);
        }

        if config.listener.len() != 1 {
            return Err(RvError::ErrConfigListenerNotFound);
        }

        env::set_var("RUST_LOG", config.log_level.as_str());
        env_logger::init();

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

        let backend = storage::new_backend(storage.stype.as_str(), &storage.config).unwrap();

        let metrics_manager = Arc::new(RwLock::new(MetricsManager::new(config.collection_interval)));
        let system_metrics = metrics_manager.read().unwrap().system_metrics.clone();

        let rvault = BastionVault::new(backend, Some(&config))?;
        let core = rvault.core.load().clone();

        let mut http_server = HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::default())
                .wrap(from_fn(metrics_midleware))
                .app_data(web::Data::new(core.clone()))
                .app_data(web::Data::new(metrics_manager.clone()))
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
    let _ = rustls::crypto::ring::default_provider().install_default();

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
