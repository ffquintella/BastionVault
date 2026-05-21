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
    about = "Rotate the master signing keypair with a grace window",
    long_about = r#"Mint a fresh hybrid Ed25519 + ML-DSA-65 master keypair, archive the
current keypair as `previous`, and arm a grace window
(`rotate_grace_secs`, default 1 day) during which envelopes signed
by the outgoing key are still accepted by the verify path.

After the grace window closes, the previous key is dropped from the
verify set and any envelope signed by it is refused.

  $ bvault rustion master rotate
  $ bvault rustion master export       # re-publish to Rustion authorities"#
)]
pub struct RustionMasterRotate {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionMasterRotate {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let resp = client.logical().write("rustion/master/rotate", None)?;
        if resp.response_status == 200 || resp.response_status == 204 {
            if let Some(data) = resp.response_data.as_ref() {
                self.output.print_value(data, true)?;
            }
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}
