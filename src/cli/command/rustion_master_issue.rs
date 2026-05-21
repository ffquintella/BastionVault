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
    about = "Issue the master signing keypair (Phase 2 lifecycle)",
    long_about = r#"Mint the hybrid Ed25519 + ML-DSA-65 master keypair that signs Rustion
session-grant envelopes. Refuses to overwrite an existing master —
use `bvault rustion master rotate` to cut over to a fresh keypair
with a grace window.

Requires `pki_mount` and `pki_role` to be set on the master config
slot (`bvault rustion master read` to verify, set them via the
`rustion/master/config` API).

  $ bvault rustion master issue
  $ bvault rustion master export   # paste pubkey into Rustion authority record"#
)]
pub struct RustionMasterIssue {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionMasterIssue {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let resp = client.logical().write("rustion/master/issue", None)?;
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
