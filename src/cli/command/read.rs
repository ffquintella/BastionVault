use clap::Parser;
use derive_more::Deref;

use crate::{
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
    about = r#"Reads data from BastionVault at the given path. This can be used to read secrets,
generate dynamic credentials, get configuration details, and more.

Read a secret from the static secrets engine:

  $ bvault read secret/my-secret

For a full list of examples and paths, please see the documentation that
corresponds to the secrets engine in use."#
)]
pub struct Read {
    #[arg(next_line_help = false, value_name = "PATH", help = r#"The path of secret."#)]
    path: String,

    #[arg(
        long = "env",
        value_name = "ENV",
        help = "Environment selector. Returns the secret's base values merged with this \
                environment's overrides. Required when the secret's ACL policy lists `env` \
                under required_parameters."
    )]
    env: Option<String>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::LogicalOutputOptions,
}

impl CommandExecutor for Read {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let logical = client.logical();

        let mut actual_path = match kv_util::is_kv_v2(&client, &self.path) {
            Ok((mount_path, true)) => {
                let remainder = self.path.trim_start_matches(&mount_path);
                format!("{}data/{}", mount_path, remainder)
            }
            _ => self.path.clone(),
        };

        // Carry the environment selector as a query parameter; the server lifts
        // it into the request data so the ACL check and KV engine both see it.
        if let Some(env) = self.env.as_deref().filter(|s| !s.is_empty()) {
            actual_path = format!("{actual_path}?env={env}");
        }

        match logical.read(&actual_path) {
            Ok(ret) => {
                if ret.response_status == 200 {
                    self.output.print_data(ret.response_data.as_ref().unwrap(), self.output.field.as_deref())?;
                } else if ret.response_status == 204 {
                    println!("ok");
                } else if ret.response_status == 404 {
                    println!("No value found at {}", self.path);
                    return Err(RvError::ErrRequestNoData);
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
