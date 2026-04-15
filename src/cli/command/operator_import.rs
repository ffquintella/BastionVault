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
    about = "Import secrets from a JSON export file",
    long_about = r#"Imports secrets from a JSON export file into a vault mount. The vault must
be unsealed. Requires a root token.

Import secrets:

  $ bvault operator import --mount secret/ --input export.json

Import with overwrite of existing keys:

  $ bvault operator import --mount secret/ --input export.json --force"#
)]
pub struct Import {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    /// Mount path to import into (e.g., "secret/").
    #[arg(long)]
    mount: String,

    /// Input file path for the JSON export.
    #[arg(long, short)]
    input: String,

    /// Overwrite existing keys. Without this flag, conflicts are skipped.
    #[arg(long, default_value = "false")]
    force: bool,
}

impl CommandExecutor for Import {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        let data = std::fs::read_to_string(&self.input)?;
        let body: serde_json::Value = serde_json::from_str(&data)?;

        let mut payload = body.as_object().cloned().unwrap_or_default();
        payload.insert("force".to_string(), serde_json::Value::Bool(self.force));

        match sys.import_secrets(&self.mount, Some(payload)) {
            Ok(ret) => {
                if ret.response_status == 200 || ret.response_status == 204 {
                    println!("Import complete from {}", self.input);
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
