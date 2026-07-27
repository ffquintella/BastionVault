//! `bvault exchange export` — produce a `.bvx` (or plaintext JSON)
//! document via the `/v1/sys/exchange/export` endpoint.

use base64::Engine;
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
    about = "Export a vault subset as a portable JSON or password-encrypted .bvx file",
    long_about = r#"Produces a `bvx.v1` document covering one or more KV mounts/paths and
writes it to disk. Two output formats:

  * --format bvx    (default) -- Argon2id + XChaCha20-Poly1305 password-
                                 encrypted file. The recipient decrypts with
                                 the same password.

  * --format json   -- plaintext JSON. Refused unless --allow-plaintext is
                       set; the default is encrypted to avoid the foot-gun
                       where someone exports `secret/dev/...` thinking it's
                       safe and the file ends up in Slack.

Passwords are read from stdin (one line) or interactively if a TTY is
attached. The CLI does not accept a `--password=` flag.

Scope is either a list of --scope selectors or one of the whole-vault modes:

  * --full             -- everything the caller can read in the namespace the
                          request targets (the root namespace unless the token
                          is bound elsewhere).

  * --all-namespaces   -- the same sweep run once per namespace, each tenant
                          packed into its own bundle inside the document. Root
                          operation; restoring it needs each namespace to exist
                          on the destination vault.

Examples:

  $ bvault exchange export --scope kv:secret/myapp/ --output myapp.bvx
  $ bvault exchange export --scope kv:secret/team-a/ --scope kv:secret/team-b/ \
      --comment "weekly snapshot" --output bundle.bvx
  $ bvault exchange export --full --output vault-full-export.bvx
  $ bvault exchange export --all-namespaces --output deployment.bvx"#
)]
pub struct ExchangeExport {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    /// Scope selector. Repeatable. Format: `kv:<mount>/<path>` (e.g.
    /// `kv:secret/myapp/`). For now only KV selectors are wired; resource
    /// and group selectors are reserved in the schema and emit an
    /// "unresolved" warning if used.
    #[arg(long = "scope", value_name = "kv:<mount>/<path>", action = clap::ArgAction::Append)]
    scope: Vec<String>,

    /// Export everything the caller can read in the targeted namespace,
    /// instead of a hand-listed scope. Mutually exclusive with --scope.
    #[arg(long, conflicts_with_all = ["scope", "all_namespaces"])]
    full: bool,

    /// Export everything in *every* namespace of the deployment (root
    /// operation). Mutually exclusive with --scope and --full.
    #[arg(long = "all-namespaces", conflicts_with = "scope")]
    all_namespaces: bool,

    /// Output file path.
    #[arg(long, short)]
    output: String,

    /// Output format. One of: `bvx` (default), `json`.
    #[arg(long, default_value = "bvx")]
    format: String,

    /// Allow plaintext JSON export. Required when --format json.
    #[arg(long, default_value = "false")]
    allow_plaintext: bool,

    /// Optional comment embedded in the `.bvx` envelope's `comment` field.
    #[arg(long)]
    comment: Option<String>,
}

fn parse_scope(scope: &[String]) -> Result<Vec<serde_json::Value>, RvError> {
    let mut out = Vec::with_capacity(scope.len());
    for s in scope {
        let (kind, rest) = s.split_once(':').ok_or(RvError::ErrRequestInvalid)?;
        match kind {
            "kv" => {
                let (mount, path) = match rest.find('/') {
                    Some(idx) => {
                        let (m, p) = rest.split_at(idx + 1);
                        (m.to_string(), p.to_string())
                    }
                    None => (format!("{rest}/"), String::new()),
                };
                out.push(json!({"type":"kv_path","mount":mount,"path":path}));
            }
            "resource" => out.push(json!({"type":"resource","id":rest})),
            "asset_group" => out.push(json!({"type":"asset_group","id":rest})),
            "resource_group" => out.push(json!({"type":"resource_group","id":rest})),
            _ => return Err(RvError::ErrRequestInvalid),
        }
    }
    Ok(out)
}

fn read_password_for_export(format: &str) -> Result<Option<String>, RvError> {
    if format != "bvx" {
        return Ok(None);
    }
    use std::io::IsTerminal;
    let pw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Export password (will not echo): ")
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

impl CommandExecutor for ExchangeExport {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        // Whole-vault modes carry no selectors; the resolver enumerates. A
        // selective export with an empty list would produce an empty document,
        // so refuse it rather than write one.
        let kind = if self.all_namespaces {
            "all_namespaces"
        } else if self.full {
            "full"
        } else {
            "selective"
        };
        let include = parse_scope(&self.scope)?;
        if kind == "selective" && include.is_empty() {
            eprintln!("no scope selected: pass --scope, --full, or --all-namespaces");
            return Err(RvError::ErrRequestInvalid);
        }

        let mut password = read_password_for_export(&self.format)?;

        let mut body = serde_json::Map::new();
        body.insert("format".to_string(), json!(self.format));
        body.insert(
            "scope".to_string(),
            json!({ "kind": kind, "include": include }),
        );
        body.insert("allow_plaintext".to_string(), json!(self.allow_plaintext));
        if let Some(ref c) = self.comment {
            body.insert("comment".to_string(), json!(c));
        }
        if let Some(ref p) = password {
            body.insert("password".to_string(), json!(p));
        }

        let client = self.client()?;
        let sys = client.sys();
        let ret = sys.exchange_export(body).map_err(|e| {
            eprintln!("{e}");
            RvError::ErrRequestInvalid
        })?;

        // Zeroise our local password copy regardless of what the server did.
        if let Some(ref mut p) = password {
            p.zeroize();
        }

        if ret.response_status != 200 {
            ret.print_debug_info();
            return Err(RvError::ErrRequestInvalid);
        }

        let data = ret.response_data.unwrap_or(serde_json::Value::Null);
        let b64 = data
            .get("file_b64")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrRequestInvalid)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| RvError::ErrRequestInvalid)?;
        std::fs::write(&self.output, &bytes)?;
        println!(
            "Wrote {} bytes to {} (format={})",
            bytes.len(),
            self.output,
            self.format
        );
        Ok(())
    }
}
