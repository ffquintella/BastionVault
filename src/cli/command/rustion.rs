use clap::{Parser, Subcommand};
use sysexits::ExitCode;

use super::{
    rustion_master_export, rustion_master_issue, rustion_master_read, rustion_master_rotate,
    rustion_target_add, rustion_target_delete, rustion_target_health, rustion_target_list,
    rustion_target_read, rustion_target_test,
};
use crate::{cli::command::CommandExecutor, EXIT_CODE_INSUFFICIENT_PARAMS};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Manage the Rustion bastion integration",
    long_about = r#"Manage the enrolled Rustion bastion instances, their health, and the
master signing-cert configuration BastionVault uses to authenticate
session-grant envelopes.

Enrol a new Rustion bastion:

  $ bvault rustion target add --name eu-prod-1 \
      --endpoint rustion-eu-1.internal:9443 \
      --ed25519 <base64> --mldsa65 <base64>

List enrolled bastions:

  $ bvault rustion target list

Cached health for every target (background-poller view):

  $ bvault rustion target health

Force an immediate probe against one target:

  $ bvault rustion target test --id rt_<id>

Read the master-cert configuration slot:

  $ bvault rustion master read

Export the master public key (paste this into a Rustion authority record):

  $ bvault rustion master export"#
)]
pub struct Rustion {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage enrolled Rustion target instances.
    Target(Target),
    /// Master signing-cert configuration + pubkey export.
    Master(Master),
}

#[derive(Parser)]
pub struct Target {
    #[command(subcommand)]
    command: Option<TargetCommands>,
}

#[derive(Subcommand)]
pub enum TargetCommands {
    Add(rustion_target_add::RustionTargetAdd),
    List(rustion_target_list::RustionTargetList),
    Read(rustion_target_read::RustionTargetRead),
    Test(rustion_target_test::RustionTargetTest),
    Health(rustion_target_health::RustionTargetHealth),
    Delete(rustion_target_delete::RustionTargetDelete),
}

#[derive(Parser)]
pub struct Master {
    #[command(subcommand)]
    command: Option<MasterCommands>,
}

#[derive(Subcommand)]
pub enum MasterCommands {
    Read(rustion_master_read::RustionMasterRead),
    Export(rustion_master_export::RustionMasterExport),
    /// Issue the master signing keypair (Phase 2 lifecycle).
    Issue(rustion_master_issue::RustionMasterIssue),
    /// Rotate the master signing keypair with a grace window.
    Rotate(rustion_master_rotate::RustionMasterRotate),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Target(t) => t.execute(),
            Commands::Master(m) => m.execute(),
        }
    }
}

impl Target {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            TargetCommands::Add(c) => c.execute(),
            TargetCommands::List(c) => c.execute(),
            TargetCommands::Read(c) => c.execute(),
            TargetCommands::Test(c) => c.execute(),
            TargetCommands::Health(c) => c.execute(),
            TargetCommands::Delete(c) => c.execute(),
        }
    }
}

impl Master {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            MasterCommands::Read(c) => c.execute(),
            MasterCommands::Export(c) => c.execute(),
            MasterCommands::Issue(c) => c.execute(),
            MasterCommands::Rotate(c) => c.execute(),
        }
    }
}

impl Rustion {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }
        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
