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
    about = "List cluster members and their Raft roles",
    long_about = r#"Lists all nodes in the BastionVault cluster when using the hiqlite storage
backend. Shows the Raft metrics which include voter status and node addresses.

For non-clustered backends, reports that clustering is not active.

List cluster members:

  $ bvault cluster members"#
)]
pub struct ClusterMembers {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for ClusterMembers {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.cluster_status() {
            Ok(ret) => {
                if ret.response_status == 200 {
                    if let Some(data) = ret.response_data.as_ref() {
                        let obj = data.as_object();
                        if let Some(obj) = obj {
                            let cluster = obj.get("cluster").and_then(|v| v.as_bool()).unwrap_or(false);
                            if !cluster {
                                let storage_type =
                                    obj.get("storage_type").and_then(|v| v.as_str()).unwrap_or("unknown");
                                println!(
                                    "Clustering is not active. Storage backend: {storage_type}"
                                );
                                return Ok(());
                            }

                            // Extract raft_metrics which contains membership info
                            if let Some(metrics) = obj.get("raft_metrics") {
                                self.output.print_value(metrics, true)?;
                            } else {
                                self.output.print_value(data, true)?;
                            }
                        }
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
