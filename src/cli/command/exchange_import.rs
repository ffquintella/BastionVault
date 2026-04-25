//! `bvault exchange import` — apply a `.bvx` (or plaintext JSON) document
//! via the `/v1/sys/exchange/import` endpoint.

use clap::Parser;
use derive_more::Deref;
use serde_json::json;
use zeroize::Zeroize;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = "Import a vault subset from a .bvx (or plaintext JSON) file",
    long_about = r#"Reads a `.bvx` or plaintext JSON document and applies it against the
target vault. Conflicts (target path exists with different bytes) are
resolved according to --conflict-policy.

Passwords are read from stdin (one line) or interactively if a TTY is
attached. The CLI does not accept a `--password=` flag.

Examples:

  $ bvault exchange import --input myapp.bvx
  $ bvault exchange import --input myapp.bvx --conflict-policy rename
  $ bvault exchange import --input plain.json --format json --allow-plaintext"#
)]
pub struct ExchangeImport {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    /// Input file path.
    #[arg(long, short)]
    input: String,

    /// Input format. One of: `bvx` (default), `json`.
    #[arg(long, default_value = "bvx")]
    format: String,

    /// Allow plaintext JSON import. Required when --format json.
    #[arg(long, default_value = "false")]
    allow_plaintext: bool,

    /// Conflict policy. One of: `skip` (default), `overwrite`, `rename`.
    #[arg(long = "conflict-policy", default_value = "skip")]
    conflict_policy: String,

    /// Run a preview classification without writing. Returns the per-item
    /// new/identical/conflict breakdown plus a token. With --apply the
    /// returned token is consumed in a follow-up call to write the items.
    #[arg(long, default_value = "false")]
    preview: bool,
}

fn read_password_for_import(format: &str) -> Result<Option<String>, RvError> {
    if format != "bvx" {
        return Ok(None);
    }
    use std::io::IsTerminal;
    let pw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Import password (will not echo): ")
            .map_err(|_| RvError::ErrRequestInvalid)?
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|_| RvError::ErrRequestInvalid)?;
        buf.trim_end_matches(['\r', '\n']).to_string()
    };
    Ok(Some(pw))
}

impl CommandExecutor for ExchangeImport {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let file_bytes = std::fs::read(&self.input)?;
        let file_str = String::from_utf8(file_bytes).map_err(|_| RvError::ErrRequestInvalid)?;

        let mut password = read_password_for_import(&self.format)?;

        let mut body = serde_json::Map::new();
        body.insert("file".to_string(), json!(file_str));
        body.insert("format".to_string(), json!(self.format));
        body.insert("allow_plaintext".to_string(), json!(self.allow_plaintext));
        body.insert("conflict_policy".to_string(), json!(self.conflict_policy));
        if let Some(ref p) = password {
            body.insert("password".to_string(), json!(p));
        }

        let client = self.client()?;
        let sys = client.sys();

        let ret = if self.preview {
            sys.exchange_preview(body)
        } else {
            sys.exchange_import(body)
        }
        .map_err(|e| {
            eprintln!("{e}");
            RvError::ErrRequestInvalid
        })?;

        if let Some(ref mut p) = password {
            p.zeroize();
        }

        if ret.response_status != 200 {
            ret.print_debug_info();
            return Err(RvError::ErrRequestInvalid);
        }

        let data = ret.response_data.unwrap_or(serde_json::Value::Null);
        println!("{}", serde_json::to_string_pretty(&data)?);
        Ok(())
    }
}
