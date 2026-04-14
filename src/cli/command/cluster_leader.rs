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
    about = "Display the current cluster leader",
    long_about = r#"Shows whether this node is the Raft leader and reports the cluster health.
Uses the /v1/sys/health endpoint which is unauthenticated.

Display leader info:

  $ bvault cluster leader"#
)]
pub struct ClusterLeader {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for ClusterLeader {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.health() {
            Ok(ret) => {
                if let Some(data) = ret.response_data.as_ref() {
                    let obj = data.as_object();
                    if let Some(obj) = obj {
                        let standby = obj.get("standby").and_then(|v| v.as_bool()).unwrap_or(false);
                        let healthy = obj.get("cluster_healthy").and_then(|v| v.as_bool()).unwrap_or(true);

                        let leader_value = serde_json::json!({
                            "is_leader": !standby,
                            "cluster_healthy": healthy,
                        });
                        self.output.print_value(&leader_value, true)?;
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
