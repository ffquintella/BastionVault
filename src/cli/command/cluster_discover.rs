//! `bvault cluster discover <cluster-name>` — diagnostic-only
//! probe of a cluster's SRV records + `/sys/health`. Prints the
//! ranked candidate table without actually connecting to any node,
//! so operators can sanity-check "why did the client pick that
//! node" before flipping a real session over.

use clap::Parser;

use crate::cli::command::{self, CommandExecutor};
use crate::errors::RvError;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Resolve a cluster's SRV records and rank nodes by /sys/health, without connecting",
    long_about = r#"Run the same SRV-based discovery + health-probe pipeline the client
uses on every connect, and print the scored candidate table.

Useful for answering "which node will the client land on?" or
debugging a misconfigured SRV record set without flipping a real
session over.

Probe a cluster:

  $ bvault cluster discover --address vault.corp.example

Probe over a TLS deployment using the system trust store:

  $ bvault cluster discover --address vault.corp.example --ca-cert /etc/ssl/certs/internal.pem

Ranking rules (lower is better, in order):

  1. SRV priority is a hard floor.
  2. Within a priority bucket, leader beats follower.
  3. Within the same (priority, state), lower RTT wins.
  4. Final tiebreak: higher SRV weight wins.

Sealed / uninitialized / unreachable nodes are filtered out before
ranking. The minority side of a `cluster_id` disagreement is dropped
so a stale SRV pointing at a decommissioned cluster can't win."#
)]
pub struct ClusterDiscover {
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for ClusterDiscover {
    fn main(&self) -> Result<(), RvError> {
        let probes = self
            .http_options
            .probe_cluster()
            .map_err(RvError::ErrString)?;

        let chosen = bv_client::health::pick(&probes);

        println!(
            "Cluster: {}\n",
            self.http_options.address_raw()
        );

        // Compact header — width tuned for default 80-col terminals.
        // The Target column is the bulkiest field so it gets the
        // slack; everything else is right-aligned for skimming.
        println!(
            "{:<40} {:>4} {:>4} {:<14} {:>8}  {}",
            "Target", "Pri", "Wt", "State", "RTT(ms)", "Cluster ID"
        );
        println!("{}", "-".repeat(80));
        for p in &probes {
            let target = format!(
                "{}://{}:{}",
                p.candidate.scheme, p.candidate.target, p.candidate.port
            );
            let state = match &p.state {
                bv_client::health::NodeState::ActiveLeader => "leader".to_string(),
                bv_client::health::NodeState::Follower => "follower".to_string(),
                bv_client::health::NodeState::Sealed => "sealed".to_string(),
                bv_client::health::NodeState::Uninitialized => "uninitialized".to_string(),
                bv_client::health::NodeState::Unreachable(why) => format!("err: {why}"),
            };
            let cid = p.cluster_id.as_deref().unwrap_or("-");
            println!(
                "{:<40} {:>4} {:>4} {:<14} {:>8}  {}",
                truncate(&target, 40),
                p.candidate.priority,
                p.candidate.weight,
                truncate(&state, 14),
                p.rtt_ms,
                truncate(cid, 24),
            );
        }
        println!();

        match chosen {
            Some(s) => println!(
                "Picked: {} ({:?}, {} ms)",
                s.candidate.url(),
                s.state,
                s.rtt_ms,
            ),
            None => println!("Picked: (none — no healthy node)"),
        }
        Ok(())
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}
