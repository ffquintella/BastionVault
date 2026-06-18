//! `bvault exchange verify` — offline integrity + structural validation of a
//! `.bvx` (or plaintext JSON) backup file.
//!
//! Runs entirely locally: no vault, barrier, or network. Point it at a file
//! written by `exchange export` / the scheduled-export runner (e.g. anything
//! under a `LocalPath` destination such as `/backups`) and it confirms the
//! file decrypts, parses as a `bvx.v1` document, every embedded file blob
//! still matches its recorded SHA-256, and the backup is not empty.

use clap::Parser;
use zeroize::Zeroize;

use crate::{
    cli::command::CommandExecutor,
    errors::RvError,
    exchange::{verify_backup_bytes, VerifyReport},
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Verify the integrity of a .bvx (or plaintext JSON) backup file",
    long_about = r#"Offline integrity + structural check for a backup file produced by
`exchange export` or a scheduled export. No running vault or network is
needed — run it directly against the export destination (e.g. /backups).

Checks performed:
  * envelope decrypts under the password (AEAD authenticity — .bvx only)
  * payload parses as a bvx.v1 document with the expected schema tag
  * every embedded file blob re-hashes to its recorded sha256 + size
  * the document is non-empty (a backup that captured nothing FAILS)

Passwords are read from stdin (one line) or interactively if a TTY is
attached. The CLI does not accept a `--password=` flag. Exit code is 0
when the backup verifies, 1 otherwise.

Examples:

  $ bvault exchange verify --input /backups/<id>-<ts>.bvx
  $ bvault exchange verify --input export.json --format json
  $ bvault exchange verify --input nightly.bvx --json | jq .ok"#
)]
pub struct ExchangeVerify {
    /// Input file path.
    #[arg(long, short)]
    input: String,

    /// Input format. One of: `auto` (default, detects `.bvx` vs JSON),
    /// `bvx`, `json`.
    #[arg(long, default_value = "auto")]
    format: String,

    /// Emit the report as JSON instead of a human-readable summary.
    #[arg(long, default_value = "false")]
    json: bool,
}

/// Read a password when the file is (or might be) an encrypted `.bvx`.
/// `auto`/`bvx` formats may need one; `json` never does.
fn read_password_if_needed(format: &str, looks_encrypted: bool) -> Result<Option<String>, RvError> {
    if format == "json" || (format == "auto" && !looks_encrypted) {
        return Ok(None);
    }
    use std::io::IsTerminal;
    let pw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Backup password (will not echo): ")
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

/// Cheap sniff for the `BVX` envelope so `auto` only prompts for a password
/// when the file is actually encrypted.
fn looks_like_envelope(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("magic").and_then(|m| m.as_str()).map(|s| s == "BVX"))
        .unwrap_or(false)
}

fn print_human(report: &VerifyReport, path: &str) {
    let verdict = if report.ok { "OK" } else { "FAILED" };
    println!("Backup verification: {verdict}");
    println!("  file:        {path}");
    println!("  format:      {}", report.format);
    if report.format == "bvx" {
        println!("  decrypted:   {}", report.decrypted);
    }
    if let Some(ts) = &report.created_at {
        println!("  created_at:  {ts}");
    }
    println!("  exported_at: {}", report.exported_at);
    println!("  schema:      {} ({})", report.schema_tag, if report.schema_ok { "ok" } else { "UNRECOGNIZED" });
    println!("  scope:       {}", report.scope_kind);
    if let Some(c) = &report.comment {
        println!("  comment:     {c}");
    }
    println!("  items:       {} total", report.total_items);
    println!(
        "                 kv={} resources={} files={} asset_groups={} resource_groups={}",
        report.counts.kv,
        report.counts.resources,
        report.counts.files,
        report.counts.asset_groups,
        report.counts.resource_groups,
    );
    println!("  files checked: {}", report.files_checked);
    if !report.file_issues.is_empty() {
        println!("  file integrity issues:");
        for issue in &report.file_issues {
            let name = issue.name.as_deref().unwrap_or("?");
            println!("    - {} ({name}): {}", issue.id, issue.problem);
        }
    }
    if !report.warnings.is_empty() {
        println!("  warnings:");
        for w in &report.warnings {
            println!("    - {w}");
        }
    }
}

impl CommandExecutor for ExchangeVerify {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        if !matches!(self.format.as_str(), "auto" | "bvx" | "json") {
            eprintln!("--format must be one of: auto, bvx, json");
            return Err(RvError::ErrRequestInvalid);
        }

        let bytes = std::fs::read(&self.input)?;
        let looks_encrypted = looks_like_envelope(&bytes);
        if self.format == "json" && looks_encrypted {
            eprintln!("file looks like an encrypted .bvx but --format json was given");
            return Err(RvError::ErrRequestInvalid);
        }

        let mut password = read_password_if_needed(&self.format, looks_encrypted)?;
        let report = verify_backup_bytes(&bytes, password.as_deref());
        if let Some(ref mut p) = password {
            p.zeroize();
        }
        let report = report?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_human(&report, &self.input);
        }

        if report.ok {
            Ok(())
        } else {
            // Non-zero exit without an extra "Error:" line; the report above
            // already explains why.
            std::process::exit(1);
        }
    }
}
