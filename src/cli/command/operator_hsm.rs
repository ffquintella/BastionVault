use clap::{Parser, Subcommand};
use derive_more::Deref;
use sysexits::ExitCode;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
    EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK,
};

/// `bvault operator hsm <subcommand>` — inspect the HSM seal.
///
/// Enrollment and epoch rotation are cluster-coordinated operations driven by
/// the server against a live peer set; only the read-only `status` verb is
/// exposed over the CLI today. See `features/hsm-support.md`.
#[derive(Parser)]
#[command(author, version, about = "Inspect the HSM seal (features/hsm-support.md)")]
pub struct Hsm {
    #[command(subcommand)]
    command: HsmCommands,
}

#[derive(Subcommand)]
pub enum HsmCommands {
    /// Show the HSM seal status: backend, device serial, cluster epoch,
    /// enrolled-node count, and recovery posture.
    Status(HsmStatus),
}

impl Hsm {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        match &mut self.command {
            HsmCommands::Status(c) => c.execute(),
        }
    }
}

#[derive(Parser, Deref)]
#[command(author, version, about = "Show the HSM seal status")]
pub struct HsmStatus {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for HsmStatus {
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
        let client = self.client()?;
        let resp = client.sys().hsm_status()?;
        let body = resp.response_data.clone().unwrap_or(serde_json::Value::Null);
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into()));
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_utils::TestHttpServer;

    /// With no `hsm` seal configured, the status endpoint reports the classic
    /// Shamir provider (auto_unseal = false) and the current seal state.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_hsm_status_defaults_to_shamir() {
        // `new_with_prometheus` uses a version-less URL prefix so a `v2/…`
        // path resolves to `/v2/…` (plain `new` prepends `/v1`).
        let server = TestHttpServer::new_with_prometheus("test_hsm_status_defaults_to_shamir", true).await;
        let resp = server.read("v2/sys/hsm/status", Some(&server.root_token)).unwrap().1;
        assert_eq!(resp.get("type").and_then(|v| v.as_str()), Some("shamir"));
        assert_eq!(resp.get("auto_unseal").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(resp.get("sealed").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(resp.get("initialized").and_then(|v| v.as_bool()), Some(true));
    }
}
