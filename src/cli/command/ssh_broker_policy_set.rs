use clap::Parser;
use derive_more::Deref;
use serde_json::{Map, Value};

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = "Set the global SSH login-class default (root-gated)",
    long_about = r#"Set the deployment-wide SSH login-class default and lock. Root-gated.

  # Default every resource to brokered, locked against lower tiers:
  $ bvault ssh-broker policy set --login-class brokered --lock

  # Relax back to shared-credential, unlocked:
  $ bvault ssh-broker policy set --login-class shared-credential --no-lock"#
)]
pub struct SshBrokerPolicySet {
    /// Login-class default: `shared-credential` or `brokered`.
    #[arg(long, value_name = "CLASS")]
    login_class: Option<String>,

    /// Lock the default against lower tiers (resource owners cannot
    /// weaken a locked `brokered` back to `shared-credential`).
    #[arg(long, conflicts_with = "no_lock")]
    lock: bool,

    /// Explicitly clear the lock.
    #[arg(long = "no-lock", conflicts_with = "lock")]
    no_lock: bool,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for SshBrokerPolicySet {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let mut body = Map::new();
        if let Some(lc) = &self.login_class {
            body.insert(
                "login_class_default".into(),
                Value::String(lc.clone()),
            );
        }
        // Only send the lock field when the operator was explicit, so a
        // bare `set --login-class ...` doesn't silently clear an existing
        // lock.
        if self.lock {
            body.insert("login_class_lock".into(), Value::Bool(true));
        } else if self.no_lock {
            body.insert("login_class_lock".into(), Value::Bool(false));
        }
        let resp = client
            .logical()
            .write("ssh-broker/policy/global", Some(body))?;
        if resp.response_status == 200 {
            if let Some(data) = resp.response_data.as_ref() {
                self.output.print_value(data, true)?;
            }
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}
