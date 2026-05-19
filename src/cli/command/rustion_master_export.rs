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
    about = "Export the master public key (one-shot enrolment on Rustion)",
    long_about = r#"Print the master public key in the shape Rustion's authority records
expect: separate `ed25519` and `mldsa65` halves plus a SHA-256
fingerprint. Paste the two pubkey halves into
`authorities/<name>.yaml` on each enrolled Rustion bastion.

Before the master cert has been issued, this command returns the
algorithm marker but empty pubkey halves and `issued = false`. Phase 2
adds the issue + rotate flow that populates the real key material.

  $ bvault rustion master export
  $ bvault rustion master export --format yaml      # ready to paste"#
)]
pub struct RustionMasterExport {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionMasterExport {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let resp = client.logical().read("rustion/master/pubkey")?;
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
