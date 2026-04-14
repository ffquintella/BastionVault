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
    about = "Remove a node from the cluster",
    long_about = r#"Removes a node from the BastionVault Raft cluster. This command must be
run against the cluster leader. Use this when a node has failed and cannot
leave gracefully on its own.

Remove a failed node:

  $ bvault cluster remove-node --node-id 3

Demote a node to learner (non-voting) instead of fully removing it:

  $ bvault cluster remove-node --node-id 3 --stay-as-learner"#
)]
pub struct ClusterRemoveNode {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    /// The node ID to remove from the cluster.
    #[arg(long, value_name = "int")]
    node_id: u64,

    /// Demote to learner instead of fully removing.
    #[arg(long, default_value = "false")]
    stay_as_learner: bool,
}

impl CommandExecutor for ClusterRemoveNode {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.cluster_remove_node(self.node_id, self.stay_as_learner) {
            Ok(ret) => {
                if ret.response_status == 200 || ret.response_status == 204 {
                    if self.stay_as_learner {
                        println!("Node {} demoted to learner.", self.node_id);
                    } else {
                        println!("Node {} removed from the cluster.", self.node_id);
                    }
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
