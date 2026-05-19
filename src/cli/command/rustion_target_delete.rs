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
    about = "Remove a Rustion target from the registry",
    long_about = r#"Delete a Rustion bastion target. The dispatcher refuses to delete a
target that has active sessions; drain the sessions first by flipping
`--disabled` on the target and waiting for them to expire.

  $ bvault rustion target delete --id rt_abcd1234"#
)]
pub struct RustionTargetDelete {
    /// Target id to delete.
    #[arg(long)]
    id: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionTargetDelete {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let path = format!("rustion/targets/{}", self.id);
        let resp = client.logical().delete(&path, None)?;
        if resp.response_status == 200 || resp.response_status == 204 {
            println!("Success! Rustion target deleted: {}", self.id);
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}
