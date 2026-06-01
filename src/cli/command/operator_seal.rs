use clap::Parser;
use derive_more::Deref;
use sysexits::ExitCode;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
    EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Seals the BastionVault server. Sealing tells the BastionVault server to stop responding
to any operations until it is unsealed. When sealed, the BastionVault server discards
its in-memory root key to unlock the data, so it is physically blocked from responding
to operations unsealed.

If an unseal is in progress, sealing the Vault will reset the unsealing process. Users
will have to re-enter their portions of the root key again.

This command does nothing if the BastionVault server is already sealed.

Seal the BastionVault server:

  $ bvault operator seal"#
)]
pub struct Seal {
    #[arg(long, help = "Operate only on the connected node, not the whole cluster")]
    local: bool,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for Seal {
    #[inline]
    fn execute(&mut self) -> ExitCode {
        match self.main() {
            Ok(_) => EXIT_CODE_OK,
            Err(e) => {
                eprintln!("Error: {e}");
                EXIT_CODE_INSUFFICIENT_PARAMS
            }
        }
    }

    #[inline]
    fn main(&self) -> Result<(), RvError> {
        // Seal state is per-node, so seal every node in the cluster.
        // `cluster_clients` returns one client per discovered node (or
        // just the connected node for --local / literal URLs).
        let targets = self.cluster_clients(self.local)?;
        let multi = targets.len() > 1;
        let mut ok = 0usize;
        for (url, client) in &targets {
            if multi {
                print!("==> {url} ");
            }
            match client.sys().seal() {
                Ok(_) => {
                    println!("Success! BastionVault is sealed.");
                    ok += 1;
                }
                Err(e) => eprintln!("Error sealing {url}: {e}"),
            }
        }
        if multi {
            println!("\nSealed {ok}/{} nodes", targets.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use serde_json::Value;

    use crate::test_utils::TestHttpServer;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_cli_operator_seal() {
        let test_http_server = TestHttpServer::new("test_cli_operator_seal", true).await;

        // bvault status
        let ret = test_http_server.cli(&["status"], &["--format=raw"]);
        let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
        let status_result = ret.as_object().unwrap();
        assert_eq!(status_result["sealed"], false);

        // bvault operator seal
        let ret = test_http_server.cli(&["operator", "seal"], &[]);
        assert_eq!(ret, Ok("Success! BastionVault is sealed.\n".into()));

        // bvault status
        let ret = test_http_server.cli(&["status"], &["--format=raw"]);
        let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
        let status_result = ret.as_object().unwrap();
        assert_eq!(status_result["sealed"], true);
    }
}
