use clap::Parser;
use derive_more::Deref;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = "Gracefully leave the cluster and shut down this node",
    long_about = r#"Gracefully shuts down this BastionVault node and removes it from the Raft
cluster. The node will attempt to transfer its data and leave cleanly.

This command should be run on the node that is leaving. Other cluster
members will continue operating after the node departs.

WARNING: This will shut down the vault server on this node.

Leave the cluster:

  $ bvault cluster leave"#
)]
pub struct ClusterLeave {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for ClusterLeave {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.cluster_leave() {
            Ok(ret) => {
                if ret.response_status == 200 || ret.response_status == 204 {
                    println!("Node is leaving the cluster and shutting down.");
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
