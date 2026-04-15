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
    about = "Trigger a leader step-down to initiate a new election",
    long_about = r#"Triggers a leader step-down on the current leader node, causing the Raft
cluster to elect a new leader. This is useful for planned maintenance or
load balancing.

This command must be run against the current leader node. If run against
a follower, it will return an error.

Trigger a failover:

  $ bvault cluster failover"#
)]
pub struct ClusterFailover {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for ClusterFailover {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.cluster_failover() {
            Ok(ret) => {
                if ret.response_status == 200 || ret.response_status == 204 {
                    println!("Leader step-down triggered. A new leader election is in progress.");
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
