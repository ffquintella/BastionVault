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
    about = "Force an immediate health probe against a Rustion target",
    long_about = r#"Run a synchronous probe against one Rustion target (`GET /v1/health`)
and return the fresh health record. Same routine the background
pinger runs on its 30-second tick — useful right after enrolment or
after editing an endpoint when you don't want to wait for the next
tick.

Omit `--id` to force a sweep across every enabled target.

  $ bvault rustion target test --id rt_abcd1234
  $ bvault rustion target test                  # full sweep"#
)]
pub struct RustionTargetTest {
    /// Target id to probe. Omit for a full sweep across every enabled
    /// target.
    #[arg(long)]
    id: Option<String>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionTargetTest {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let path = match &self.id {
            Some(id) => format!("rustion/targets/{id}/probe"),
            None => "rustion/targets/probe".to_string(),
        };
        let resp = client.logical().write(&path, None)?;
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
