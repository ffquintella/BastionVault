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
    about = r#"Prints the current state of BastionVault including whether it is sealed and if HA
mode is enabled. This command prints regardless of whether the Vault is sealed."#
)]
pub struct Status {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Status {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.seal_status() {
            Ok(ret) => {
                if ret.response_status == 200 {
                    let status_data = ret.response_data.as_ref().unwrap();
                    let status = status_data.as_object().unwrap();
                    let mut status_value = serde_json::json!({
                        "sealed": status["sealed"],
                        "total_shares": status["n"],
                        "threshold": status["t"],
                        "progress": status["progress"],
                    });

                    // Append cluster health info if available
                    if let Ok(health_ret) = sys.health() {
                        if health_ret.response_status == 200 || health_ret.response_status == 429 || health_ret.response_status == 503 {
                            if let Some(health_data) = health_ret.response_data.as_ref() {
                                if let Some(health) = health_data.as_object() {
                                    if let Some(obj) = status_value.as_object_mut() {
                                        if let Some(standby) = health.get("standby") {
                                            obj.insert("standby".to_string(), standby.clone());
                                        }
                                        if let Some(cluster_healthy) = health.get("cluster_healthy") {
                                            obj.insert("cluster_healthy".to_string(), cluster_healthy.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    self.output.print_value(&status_value, true)?;
                } else if ret.response_status == 204 {
                    println!("ok");
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        Ok(())
    }
}
