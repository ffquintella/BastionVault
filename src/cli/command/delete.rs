use clap::Parser;
use derive_more::Deref;

use crate::{
    bv_error_string,
    cli::{
        command::{self, CommandExecutor},
        kv_util,
    },
    errors::RvError,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Deletes secrets and configuration from BastionVault at the given path. The behavior
of "delete" is delegated to the backend corresponding to the given path.

Remove data in the status secret backend:

  $ vault delete secret/my-secret"#
)]
pub struct Delete {
    #[arg(next_line_help = false, value_name = "PATH")]
    path: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Delete {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let logical = client.logical();

        let actual_path = match kv_util::is_kv_v2(&client, &self.path) {
            Ok((mount_path, true)) => {
                let remainder = self.path.trim_start_matches(&mount_path);
                format!("{}data/{}", mount_path, remainder)
            }
            _ => self.path.clone(),
        };

        match logical.delete(&actual_path, None) {
            Ok(ret) => {
                if ret.response_status == 200 || ret.response_status == 204 {
                    println!("Success! Data deleted (if it existed) at: {}", self.path);
                } else {
                    ret.print_debug_info();
                    return Err(bv_error_string!("Unkonwn"));
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
