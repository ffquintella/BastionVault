//! `bvault hsm-gateway`: the mTLS gateway in front of a localhost
//! `yubihsm-connector` on an HSM host (features/hsm-pool-ha.md § HSM link).
//! It is not a vault: no storage, no tokens. The work is in `bv-hsm-link`.

use std::path::PathBuf;

use bv_hsm_link::{Gateway, GatewaySettings};
use clap::Parser;
use sysexits::ExitCode;

use crate::{
    errors::RvError, logging, EXIT_CODE_LOAD_CONFIG_FAILURE, EXIT_CODE_OK, EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY,
};

#[derive(Parser)]
#[command(
    about = "Run the mTLS HSM gateway in front of a localhost yubihsm-connector",
    long_about = r#"Run the HSM pool gateway on a host with a YubiHSM 2. It listens with mutual TLS,
admits only client certificates that chain to client_ca_file and carry a DNS SAN
equal to one of allowed_clients, and forwards POST /connector/api and
GET /connector/status bodies verbatim to the connector on loopback.

  $ bvault hsm-gateway --config /etc/bastionvault/hsm-gateway.hcl

hsm_gateway {
  listen             = "0.0.0.0:8250"
  connector          = "http://127.0.0.1:12345"
  tls_cert_file      = "/etc/bastionvault/hsm-link/hsm-a.pem"
  tls_key_file       = "/etc/bastionvault/hsm-link/hsm-a.key"
  client_ca_file     = "/etc/bastionvault/hsm-link/ca.pem"
  allowed_clients    = ["vault-1", "vault-2", "vault-3"]
  max_rps_per_client = 50
}"#
)]
pub struct HsmGateway {
    /// Path to the gateway's HCL configuration file.
    #[arg(long, value_name = "path")]
    config: PathBuf,

    /// Log filter (`info`, `debug`, `info,bv_hsm_link=debug`, ...). Logs go to stderr.
    #[arg(long, value_name = "level", default_value = "info", env = "BVAULT_HSM_GATEWAY_LOG_LEVEL")]
    log_level: String,
}

impl HsmGateway {
    pub fn execute(&mut self) -> ExitCode {
        // Configuration is read and validated before anything listens, and a
        // bad file stops the process with the reason instead of starting.
        let config = match GatewaySettings::load(&self.config).and_then(GatewaySettings::into_config) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("hsm-gateway: {e}");
                return EXIT_CODE_LOAD_CONFIG_FAILURE;
            }
        };
        if let Err(e) = logging::init(logging::LogConfig {
            level: &self.log_level,
            log_dir: "",
            log_to_stderr: true,
            rotate_size_bytes: 0,
            rotate_keep: 0,
        }) {
            eprintln!("hsm-gateway: logging init failed: {e}");
        }
        match run(config) {
            Ok(()) => EXIT_CODE_OK,
            Err(e) => {
                log::error!("hsm-gateway: {e}");
                eprintln!("hsm-gateway: {e}");
                EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY
            }
        }
    }
}

fn run(config: bv_hsm_link::GatewayConfig) -> Result<(), RvError> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let gateway = Gateway::bind(config).await?;
        gateway.serve(shutdown_signal()).await
    })
}

/// Ctrl-C, or SIGTERM on unix (systemd's stop).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                log::warn!("hsm-gateway: cannot watch SIGTERM ({e}); stopping on Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    log::info!("hsm-gateway: shutting down");
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: crate::Commands,
    }

    #[test]
    fn the_subcommand_requires_a_config_path() {
        let parsed = Wrapper::try_parse_from(["bvault", "hsm-gateway", "--config", "/etc/gw.hcl"]).unwrap();
        match parsed.command {
            crate::Commands::HsmGateway(g) => {
                assert_eq!(g.config, PathBuf::from("/etc/gw.hcl"));
                assert_eq!(g.log_level, "info");
            }
            _ => panic!("parsed as another subcommand"),
        }
        assert!(Wrapper::try_parse_from(["bvault", "hsm-gateway"]).is_err());
    }

    #[test]
    fn an_invalid_config_exits_with_the_config_failure_code() {
        let dir = std::env::temp_dir().join(format!("bv-hsm-gateway-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway.hcl");
        std::fs::write(
            &path,
            r#"hsm_gateway {
  listen          = "0.0.0.0:8250"
  connector       = "http://10.0.0.5:12345"
  tls_cert_file   = "c.pem"
  tls_key_file    = "k.pem"
  client_ca_file  = "ca.pem"
  allowed_clients = ["vault-1"]
}"#,
        )
        .unwrap();
        let mut command = HsmGateway { config: path, log_level: "info".into() };
        assert_eq!(command.execute(), EXIT_CODE_LOAD_CONFIG_FAILURE);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
