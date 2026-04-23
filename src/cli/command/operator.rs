use clap::{Parser, Subcommand};
use sysexits::ExitCode;

use super::{
    operator_cloud_target_connect, operator_export, operator_import, operator_init, operator_seal,
    operator_unseal,
};
#[cfg(not(feature = "sync_handler"))]
use super::{operator_backup, operator_migrate, operator_restore};
use crate::{cli::command::CommandExecutor, EXIT_CODE_INSUFFICIENT_PARAMS};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Perform operator-specific tasks",
    long_about = r#"This command groups subcommands for operators interacting with BastionVault.
Most users will not need to interact with these commands.

Initialize a new BastionVault server:

  $ bvault operator init

Unseals the BastionVault server:

  $ bvault operator unseal

Seals the BastionVault server:

  $ bvault operator seal

Migrate data between storage backends:

  $ bvault operator migrate --source-type file --source-config path=./old \
      --dest-type hiqlite --dest-config data_dir=./new --dest-config node_id=1 \
      --dest-config secret_raft=secret1234567890 --dest-config secret_api=secret1234567890"#
)]
pub struct Operator {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Init(operator_init::Init),
    Seal(operator_seal::Seal),
    Unseal(operator_unseal::Unseal),
    #[cfg(not(feature = "sync_handler"))]
    Migrate(operator_migrate::Migrate),
    #[cfg(not(feature = "sync_handler"))]
    Backup(operator_backup::Backup),
    #[cfg(not(feature = "sync_handler"))]
    Restore(operator_restore::Restore),
    Export(operator_export::Export),
    Import(operator_import::Import),
    /// OAuth consent flow for cloud storage targets (OneDrive,
    /// Google Drive, Dropbox). See `features/cloud-storage-backend.md`.
    #[command(name = "cloud-target")]
    CloudTarget(CloudTarget),
}

/// Grouping wrapper so we can hang `connect` (and future verbs like
/// `disconnect` / `refresh-now`) under `cloud-target`.
#[derive(Parser)]
pub struct CloudTarget {
    #[command(subcommand)]
    command: CloudTargetCommands,
}

#[derive(Subcommand)]
pub enum CloudTargetCommands {
    Connect(operator_cloud_target_connect::CloudTargetConnect),
}

impl CloudTarget {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        match &mut self.command {
            CloudTargetCommands::Connect(c) => c.execute(),
        }
    }
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Init(init) => init.execute(),
            Commands::Seal(seal) => seal.execute(),
            Commands::Unseal(unseal) => unseal.execute(),
            #[cfg(not(feature = "sync_handler"))]
            Commands::Migrate(migrate) => migrate.execute(),
            #[cfg(not(feature = "sync_handler"))]
            Commands::Backup(backup) => backup.execute(),
            #[cfg(not(feature = "sync_handler"))]
            Commands::Restore(restore) => restore.execute(),
            Commands::Export(export) => export.execute(),
            Commands::Import(import) => import.execute(),
            Commands::CloudTarget(c) => c.execute(),
        }
    }
}

impl Operator {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
