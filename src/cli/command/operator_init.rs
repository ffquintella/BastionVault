use clap::Parser;
use derive_more::Deref;
use sysexits::ExitCode;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
    http::sys::InitRequest,
    bv_error_string, EXIT_CODE_OK,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Initializes a BastionVault server. Initialization is the process by which BastionVault's storage
backend is prepared to receive data. Since BastionVault servers share the same storage backend
in HA mode, you only need to initialize one BastionVault to initialize the storage backend.

During initialization, BastionVault generates an in-memory root key and applies Shamir's secret
sharing algorithm to disassemble that root key into a configuration number of key shares such
that a configurable subset of those key shares must come together to regenerate the root key.
These keys are often called "unseal keys" in BastionVault's documentation.

When the server is configured with an HSM seal (auto-unseal), the root key is wrapped
under the HSM and no unseal keys are produced, so no parameters are needed.

This command cannot be run against an already-initialized BastionVault cluster.

Initialize a vault with an HSM seal (no parameters needed):

  $ bvault operator init

Initialize a Shamir-sealed vault, specifying key-shares and key-threshold:

  $ bvault operator init \
      -key-shares=3 \
      -key-threshold=2"#
)]
pub struct Init {
    #[arg(
        long,
        next_line_help = true,
        value_name = "int",
        long_help = r#"Number of key shares to split the generated root key into. This is the
number of "unseal keys" to generate. Required for a Shamir-sealed vault;
omit for an HSM (auto-unseal) vault."#
    )]
    key_shares: Option<u8>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "int",
        long_help = r#"Number of key shares required to reconstruct the root key. This must be
less than or equal to -key-shares. Required for a Shamir-sealed vault;
omit for an HSM (auto-unseal) vault."#
    )]
    key_threshold: Option<u8>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Init {
    #[inline]
    fn execute(&mut self) -> ExitCode {
        match self.main() {
            Ok(_) => EXIT_CODE_OK,
            Err(e) => {
                eprintln!("Error: {e}");
                // TODO
                std::process::exit(2);
            }
        }
    }

    fn main(&self) -> Result<(), RvError> {
        // Both flags are optional so an HSM-sealed (auto-unseal) vault can be
        // initialized bare; the server rejects a bare init on a Shamir seal.
        match (self.key_shares, self.key_threshold) {
            (Some(shares), Some(threshold)) if threshold > shares => {
                return Err(bv_error_string!("invalid seal configuration: threshold cannot be larger than shares"));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(bv_error_string!("--key-shares and --key-threshold must be provided together"));
            }
            _ => {}
        }

        let client = self.client()?;
        let sys = client.sys();

        let init_req = InitRequest { secret_shares: self.key_shares, secret_threshold: self.key_threshold };

        match sys.init(&init_req) {
            Ok(ret) => {
                if ret.response_status == 200 {
                    self.output.print_value(ret.response_data.as_ref().unwrap(), true)?;
                } else if ret.response_status == 204 {
                    println!("ok");
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use serde_json::Value;
    use zeroize::Zeroizing;

    use crate::{
        core::SealConfig,
        errors::RvError,
        seal::SealProvider,
        test_utils::TestHttpServer,
    };

    /// Minimal auto-unseal seal provider so the init path can be exercised
    /// without a real (or mock-feature-gated) HSM backend.
    struct AutoUnsealStub;

    #[maybe_async::maybe_async]
    impl SealProvider for AutoUnsealStub {
        fn seal_type(&self) -> &str {
            "hsm"
        }

        fn requires_shares(&self) -> bool {
            false
        }

        async fn init_kek(&self, _kek: &[u8], _seal_config: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
            Ok(Zeroizing::new(Vec::new()))
        }

        async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
            Err(RvError::ErrBarrierUnsealing)
        }
    }

    #[test]
    fn test_cli_operator_init_auto_unseal_no_params() {
        let test_http_server = TestHttpServer::new_without_init("test_cli_operator_init_auto_unseal_no_params", true);
        test_http_server.core.set_seal_provider(Arc::new(AutoUnsealStub));

        // bvault operator init  (no --key-shares / --key-threshold)
        let ret = test_http_server.cli(&["operator", "init"], &["--format=raw"]);
        assert!(ret.is_ok(), "bare operator init must succeed on an auto-unseal vault: {ret:?}");
        let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
        let init_result = ret.as_object().unwrap();
        assert!(init_result["keys"].as_array().unwrap().is_empty(), "auto-unseal init returns no unseal keys");
        assert!(!init_result["root_token"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_cli_operator_init_shamir_requires_params() {
        let test_http_server = TestHttpServer::new_without_init("test_cli_operator_init_shamir_requires_params", true);

        // Bare init against the default Shamir seal must be rejected by the server.
        let ret = test_http_server.cli(&["operator", "init"], &["--format=raw"]);
        let output = match ret {
            Ok(out) => out,
            Err(e) => e.to_string(),
        };
        assert!(
            output.contains("secret_shares"),
            "bare init on a shamir seal must report the missing parameters, got: {output}"
        );

        // Passing only one of the two flags is a client-side error.
        let ret = test_http_server.cli(&["operator", "init"], &["--format=raw", "--key-shares=5"]);
        let output = match ret {
            Ok(out) => out,
            Err(e) => e.to_string(),
        };
        assert!(output.contains("must be provided together"), "got: {output}");
    }

    #[test]
    fn test_cli_operator_init() {
        let test_http_server = TestHttpServer::new_without_init("test_cli_operator_init", true);

        // bvault operator init
        let ret = test_http_server.cli(&["operator", "init"], &["--format=raw", "--key-shares=5", "--key-threshold=3"]);
        assert!(ret.is_ok());
        let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
        let init_result = ret.as_object().unwrap();

        // bvault status
        let ret = test_http_server.cli(&["status"], &["--format=json"]);
        let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
        let status_result = ret.as_object().unwrap();
        assert_eq!(init_result["keys"].as_array().unwrap().len(), status_result["threshold"]);
    }
}
