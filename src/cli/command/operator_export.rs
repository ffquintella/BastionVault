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
    about = "Export decrypted secrets from a vault subtree",
    long_about = r#"Exports secrets from a mount/prefix as decrypted JSON. The vault must be
unsealed. Requires a root token.

WARNING: The output file contains PLAINTEXT SECRETS. Encrypt it before
storing or transferring.

Export all secrets under a prefix:

  $ bvault operator export --mount secret/ --prefix myapp/ --output export.json

Export an entire mount:

  $ bvault operator export --mount secret/ --output export.json"#
)]
pub struct Export {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    /// Mount path (e.g., "secret/").
    #[arg(long)]
    mount: String,

    /// Key prefix to export (e.g., "myapp/"). Defaults to "" (entire mount).
    #[arg(long, default_value = "")]
    prefix: String,

    /// Output file path for the JSON export.
    #[arg(long, short)]
    output: String,
}

impl CommandExecutor for Export {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        let path = format!("{}{}", self.mount, self.prefix);
        match sys.export_secrets(&path) {
            Ok(ret) => {
                if ret.response_status == 200 {
                    let body = ret.response_data.unwrap_or(serde_json::Value::Null);
                    let json = serde_json::to_string_pretty(&body)?;
                    std::fs::write(&self.output, json.as_bytes())?;
                    eprintln!(
                        "WARNING: Export file contains PLAINTEXT SECRETS. Encrypt it before storing."
                    );
                    println!("Export written to {}", self.output);
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
