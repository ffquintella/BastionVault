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
    about = "Read the master-cert configuration slot",
    long_about = r#"Show the configured PKI mount / role / issuer used to mint and rotate
the master signing cert that authenticates session-grant envelopes
to enrolled Rustion bastions, plus the current cert serial and
`not_after` once one has been issued.

  $ bvault rustion master read"#
)]
pub struct RustionMasterRead {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionMasterRead {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let resp = client.logical().read("rustion/master/config")?;
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
