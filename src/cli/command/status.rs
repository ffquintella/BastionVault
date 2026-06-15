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
    about = "Prints the current state of the BastionVault daemon",
    long_about = r#"Prints the current state of the BastionVault daemon: its version, whether it is
sealed or unsealed, the storage cluster mode (single vs clustered) and -- when
clustered -- this node's id and whether it is the Raft leader.

This command prints regardless of whether the Vault is sealed. If the daemon is
not reachable, an error is reported and the command exits non-zero.

  $ bvault status"#
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

        let mut status: Map<String, Value> = Map::new();

        // `/sys/info` doubles as our reachability probe: a transport error here
        // means the daemon isn't listening, so report that and bail.
        match sys.info() {
            Ok(ret) if ret.response_status == 200 => {
                status.insert("daemon".to_string(), Value::String("running".to_string()));
                if let Some(info) = ret.response_data.as_ref().and_then(|d| d.as_object()) {
                    if let Some(v) = info.get("version") {
                        status.insert("version".to_string(), v.clone());
                    }
                    // `/sys/info` carries the authoritative seal/init state even
                    // before the vault is initialized (when `/sys/seal-status`
                    // errors out), so source `sealed`/`initialized` from here.
                    if let Some(v) = info.get("initialized") {
                        status.insert("initialized".to_string(), v.clone());
                    }
                    if let Some(v) = info.get("sealed") {
                        status.insert("sealed".to_string(), v.clone());
                    }
                    if let Some(v) = info.get("uptime_seconds") {
                        status.insert("uptime_seconds".to_string(), v.clone());
                    }
                }
            }
            Ok(ret) => {
                ret.print_debug_info();
                return Err(RvError::ErrResponse("unexpected response from /sys/info".to_string()));
            }
            Err(e) => {
                eprintln!("BastionVault daemon is not reachable at {}: {e}", self.address_raw());
                return Err(e);
            }
        }

        // Key-share counts + unseal progress. Only present once the vault has
        // been initialized; the endpoint errors otherwise, so missing fields
        // here are expected for a fresh vault.
        if let Ok(ret) = sys.seal_status() {
            if ret.response_status == 200 {
                if let Some(seal) = ret.response_data.as_ref().and_then(|d| d.as_object()) {
                    if let Some(v) = seal.get("n") {
                        status.insert("total_shares".to_string(), v.clone());
                    }
                    if let Some(v) = seal.get("t") {
                        status.insert("threshold".to_string(), v.clone());
                    }
                    if let Some(v) = seal.get("progress") {
                        status.insert("unseal_progress".to_string(), v.clone());
                    }
                }
            }
        }

        // Cluster mode + this node's Raft role.
        if let Ok(ret) = sys.cluster_status() {
            if ret.response_status == 200 {
                if let Some(cluster) = ret.response_data.as_ref().and_then(|d| d.as_object()) {
                    let clustered = cluster.get("cluster").and_then(Value::as_bool).unwrap_or(false);
                    status.insert(
                        "cluster_mode".to_string(),
                        Value::String(if clustered { "clustered" } else { "single" }.to_string()),
                    );
                    if let Some(v) = cluster.get("storage_type") {
                        status.insert("storage_type".to_string(), v.clone());
                    }
                    if clustered {
                        if let Some(v) = cluster.get("node_id") {
                            status.insert("node_id".to_string(), v.clone());
                        }
                        if let Some(v) = cluster.get("is_leader") {
                            status.insert("is_leader".to_string(), v.clone());
                        }
                        if let Some(v) = cluster.get("cluster_healthy") {
                            status.insert("cluster_healthy".to_string(), v.clone());
                        }
                    }
                }
            }
        }

        self.output.print_value(&Value::Object(status), true)?;
        Ok(())
    }
}
