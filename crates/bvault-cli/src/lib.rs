//! `bvault`, the BastionVault command-line client, and the `bvault server`
//! command that starts the server up.
//!
//! # Where it sits
//!
//! Tier 4 of the workspace decomposition, above both [`bastion_vault`] and
//! [`bv_server`]. It was `bastion_vault::cli` until Phase 4, which is 111 of
//! the last 300 commits' worth of churn sitting inside the library's
//! compilation unit — every `bvault read` flag edit recompiled the vault.
//!
//! It also owns the actix wrap site: [`command::server`] is the one place that
//! assembles an `App` out of `bv_server`'s routes and middleware, which is why
//! this crate and `bv-server` had to be extracted together. Leaving `src/cli`
//! in the library while `src/http` moved above it would have been a dependency
//! cycle, not a layering choice.
//!
//! See roadmaps/workspace-decomposition.md § Phase 4.

use clap::{Parser, Subcommand};
use sysexits::ExitCode;

// The library, under the names this code has always spelled them. Private:
// none of it leaks into this crate's public API, and every one of these
// resolves the `crate::<name>::` paths the moved files still use. Same alias
// preamble the Phase 3 engine crates carry, two tiers up.
use bastion_vault::{
    api, backup, config, errors, exchange, hsm, kernel_api, logging, logical, metrics, modules,
    plugins, seal, server_info, storage, utils,
};

// Re-exported rather than aliased: the call sites spell these `crate::VERSION`
// and `crate::EXIT_CODE_*`, at this crate's root, because that is where they
// were when this was `bastion_vault::cli`.
pub use bastion_vault::{
    bv_error_response, bv_error_string, BastionVault, EXIT_CODE_INSUFFICIENT_PARAMS,
    EXIT_CODE_LOAD_CONFIG_FAILURE, EXIT_CODE_OK, EXIT_CODE_SERVER_ABORTED,
    EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY, VERSION,
};

use crate::command::CommandExecutor;

pub mod command;
pub mod kv_util;
pub mod util;

/// The fixtures this crate's command tests use, gathered under the name they
/// had when these files lived in the root crate. `TestHttpServer` comes from
/// `bv-server` and the rest from `bastion_vault`'s `test-support` feature —
/// see roadmaps/workspace-decomposition.md § Phase 4.
/// `operator_init`'s test `SealProvider` stub names `crate::core::SealConfig`.
#[cfg(test)]
use bastion_vault::core;

#[cfg(test)]
mod test_utils {
    #[allow(unused_imports)]
    pub use bastion_vault::test_utils::*;
    pub use bv_server::test_support::TestHttpServer;
}

#[derive(Parser)]
#[command(
    // Pinned, not inferred. clap derives the app name from `CARGO_PKG_NAME`,
    // which Phase 4 changed from `bastion_vault` to `bvault-cli` — so
    // `bvault --version` would have started printing a package name no
    // operator has ever typed. It prints the binary's name instead.
    name = "bvault",
    version = VERSION,
    disable_help_subcommand = true,
    about = "A secure and high performance secret management software that is compatible with Hashicorp Vault."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Server(command::server::Server),
    Status(command::status::Status),
    Operator(command::operator::Operator),
    Cluster(command::cluster::Cluster),
    Read(command::read::Read),
    Write(command::write::Write),
    Delete(command::delete::Delete),
    List(command::list::List),
    Login(command::login::Login),
    Auth(command::auth::Auth),
    Policy(command::policy::Policy),
    Secrets(command::secrets::Secrets),
    Exchange(command::exchange::Exchange),
    Rustion(command::rustion::Rustion),
    SshBroker(command::ssh_broker::SshBroker),
    #[cfg(unix)]
    Ferrogate(command::ferrogate::Ferrogate),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Server(server) => server.execute(),
            Commands::Status(status) => status.execute(),
            Commands::Operator(operator) => operator.execute(),
            Commands::Cluster(cluster) => cluster.execute(),
            Commands::Read(read) => read.execute(),
            Commands::Write(write) => write.execute(),
            Commands::Delete(delete) => delete.execute(),
            Commands::List(list) => list.execute(),
            Commands::Login(login) => login.execute(),
            Commands::Auth(auth) => auth.execute(),
            Commands::Policy(policy) => policy.execute(),
            Commands::Secrets(secrets) => secrets.execute(),
            Commands::Exchange(exchange) => exchange.execute(),
            Commands::Rustion(rustion) => rustion.execute(),
            Commands::SshBroker(ssh_broker) => ssh_broker.execute(),
            #[cfg(unix)]
            Commands::Ferrogate(ferrogate) => ferrogate.execute(),
        }
    }
}

impl Cli {
    /// Do real jobs.
    #[inline]
    pub fn run(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
