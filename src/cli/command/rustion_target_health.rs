use clap::Parser;
use derive_more::Deref;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = "Cached health for every enrolled Rustion target",
    long_about = r#"Print the background-pinger's cached health view across every enrolled
Rustion target: status (up/degraded/down/unknown), last-ok timestamp,
last error, EWMA p50 latency, consecutive-failure count, Rustion
version, active session count.

  $ bvault rustion target health"#
)]
pub struct RustionTargetHealth {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionTargetHealth {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let resp = client.logical().read("rustion/targets/health")?;
        if resp.response_status == 200 {
            if let Some(data) = resp.response_data.as_ref() {
                self.output.print_value(data, true)?;
            }
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}
