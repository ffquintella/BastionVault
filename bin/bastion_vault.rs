//! This is the 'application' part of BastionVault.
//! The code here will be built into a binary (with a main function which utilizes the
//! `bastion_vault::cli` module to run the application).

use std::process::ExitCode;

use bastion_vault::cli::Cli;
use clap::{CommandFactory, Parser};

fn main() -> ExitCode {
    let mut cli = Cli::parse();

    let ret = cli.run();
    if !ret.is_success() {
        Cli::command().print_long_help().unwrap();
    }

    ret.into()
}
