use clap::{Parser, Subcommand};
use sysexits::ExitCode;

use super::{cluster_failover, cluster_leader, cluster_leave, cluster_members, cluster_remove_node, cluster_status};
use crate::{cli::command::CommandExecutor, EXIT_CODE_INSUFFICIENT_PARAMS};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Manage the BastionVault cluster",
    long_about = r#"This command groups subcommands for inspecting and managing a BastionVault
cluster running with the hiqlite storage backend.

Show cluster health and Raft state:

  $ bvault cluster status

Show which node is the current leader:

  $ bvault cluster leader

List all cluster members:

  $ bvault cluster members

Remove a failed node from the cluster:

  $ bvault cluster remove-node --node-id 3

Gracefully leave the cluster and shut down this node:

  $ bvault cluster leave"#
)]
pub struct Cluster {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Status(cluster_status::ClusterStatus),
    Leader(cluster_leader::ClusterLeader),
    Members(cluster_members::ClusterMembers),
    Leave(cluster_leave::ClusterLeave),
    Failover(cluster_failover::ClusterFailover),
    #[command(name = "remove-node")]
    RemoveNode(cluster_remove_node::ClusterRemoveNode),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Status(status) => status.execute(),
            Commands::Leader(leader) => leader.execute(),
            Commands::Members(members) => members.execute(),
            Commands::Leave(leave) => leave.execute(),
            Commands::Failover(failover) => failover.execute(),
            Commands::RemoveNode(remove_node) => remove_node.execute(),
        }
    }
}

impl Cluster {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
