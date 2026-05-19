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
    about = "Read a single Rustion target record",
    long_about = r#"Fetch the full record for one Rustion bastion target — endpoint,
pinned hybrid pubkey, tags, enabled flag, and timestamps.

  $ bvault rustion target read --id rt_abcd1234"#
)]
pub struct RustionTargetRead {
    /// Target id allocated by the registry on first enrolment.
    #[arg(long)]
    id: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionTargetRead {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let path = format!("rustion/targets/{}", self.id);
        let resp = client.logical().read(&path)?;
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
