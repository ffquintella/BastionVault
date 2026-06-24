use clap::{Parser, Subcommand};
use sysexits::ExitCode;

use super::{ssh_broker_policy_get, ssh_broker_policy_set};
use crate::{cli::command::CommandExecutor, EXIT_CODE_INSUFFICIENT_PARAMS};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Manage the SSH login-class (broker) policy",
    long_about = r#"Manage the global SSH login-class default. A resource pinned to
`brokered` accepts only per-connect minted SSH credentials (CA-signed
cert or OTP) from the SSH engine — no static SSH credential may be
attached. Per-resource-type / per-asset-group / per-resource tiers are
edited through the resource, type, and asset-group editors.

Read the global login-class default:

  $ bvault ssh-broker policy get

Pin every resource to brokered and lock it against lower tiers:

  $ bvault ssh-broker policy set --login-class brokered --lock"#
)]
pub struct SshBroker {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Global login-class default + lock.
    Policy(Policy),
}

#[derive(Parser)]
pub struct Policy {
    #[command(subcommand)]
    command: Option<PolicyCommands>,
}

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// Read the global login-class default + lock.
    Get(ssh_broker_policy_get::SshBrokerPolicyGet),
    /// Set the global login-class default + lock (root-gated).
    Set(ssh_broker_policy_set::SshBrokerPolicySet),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Policy(p) => p.execute(),
        }
    }
}

impl Policy {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            PolicyCommands::Get(c) => c.execute(),
            PolicyCommands::Set(c) => c.execute(),
        }
    }
}

impl SshBroker {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }
        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
