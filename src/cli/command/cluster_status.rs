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
    about = "Display the cluster status including Raft health and leader information",
    long_about = r#"Prints the current cluster status for a BastionVault server running with
the hiqlite storage backend. Shows whether the cluster is healthy, which
node is the leader, and detailed Raft metrics.

For non-clustered backends (file, mysql), reports that clustering is not active.

Display cluster status:

  $ bvault cluster status"#
)]
pub struct ClusterStatus {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for ClusterStatus {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.cluster_status() {
            Ok(ret) => {
                if ret.response_status == 200 {
                    if let Some(data) = ret.response_data.as_ref() {
                        self.output.print_value(data, true)?;
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
