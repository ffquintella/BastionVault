//! `bvault exchange` — top-level subcommand grouping for the import /
//! export module. See `features/import-export-module.md`.

use clap::{Parser, Subcommand};
use sysexits::ExitCode;

use crate::{cli::command::CommandExecutor, EXIT_CODE_INSUFFICIENT_PARAMS};

use super::{exchange_export, exchange_import};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Portable, password-encrypted import/export of vault subsets",
    long_about = r#"Produces and consumes `bvx.v1` JSON documents describing a selected
subset of vault data, with an optional Argon2id + XChaCha20-Poly1305
password-encrypted `.bvx` envelope.

Distinct from `operator backup` / `operator restore`:

  * `operator backup` is the operator-level full-vault disaster-recovery
    primitive (BVBK binary, HMAC'd against the audit-device key,
    restorable only on the same vault's barrier).

  * `exchange export` / `exchange import` is the user-level portable
    primitive (password-encrypted, restorable on any BastionVault
    instance with the password)."#
)]
pub struct Exchange {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Export(exchange_export::ExchangeExport),
    Import(exchange_import::ExchangeImport),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Export(c) => c.execute(),
            Commands::Import(c) => c.execute(),
        }
    }
}

impl Exchange {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }
        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
