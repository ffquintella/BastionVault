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
    about = "Enrol a new Rustion bastion target",
    long_about = r#"Register a Rustion bastion instance with BastionVault. Both halves of
the hybrid public key are required — a classical-only enrolment is
rejected as a downgrade attack.

The name must be unique per deployment. IDs are derived deterministically
from the lowercased name, so accidentally repeating an enrolment via
the CLI + GUI lands on the same record.

  $ bvault rustion target add \
      --name eu-prod-1 \
      --endpoint rustion-eu-1.internal:9443 \
      --ed25519 MCowBQYDK2VwAyEA... \
      --mldsa65 MIIH..."#
)]
pub struct RustionTargetAdd {
    /// Operator-visible name, unique per deployment (case-insensitive).
    #[arg(long)]
    name: String,

    /// Control-plane endpoint, `host:port`. TLS-only.
    #[arg(long)]
    endpoint: String,

    /// Base64 SPKI of the Ed25519 half of the Rustion identity keypair.
    #[arg(long)]
    ed25519: String,

    /// Base64 raw FIPS 204 ML-DSA-65 public key.
    #[arg(long)]
    mldsa65: String,

    /// Base64 raw FIPS 203 ML-KEM-768 public key — used to encrypt
    /// session-grant envelopes to this Rustion instance. Get it from
    /// `rustion control-plane identity export --kem` on the Rustion
    /// side.
    #[arg(long = "kem-pubkey")]
    kem_pubkey: String,

    /// Free-form description shown in the GUI.
    #[arg(long, default_value = "")]
    description: String,

    /// Comma-separated tags (e.g. `region=eu-west-1,zone=pci`).
    #[arg(long, default_value = "")]
    tags: String,

    /// Disable the target on enrolment; the dispatcher skips it
    /// regardless of health until re-enabled.
    #[arg(long)]
    disabled: bool,

    /// Optional: relative directory under the Rustion recordings root
    /// for diagnostics.
    #[arg(long, default_value = "")]
    default_recording_dir: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for RustionTargetAdd {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let mut body = Map::new();
        body.insert("name".into(), Value::String(self.name.clone()));
        body.insert("endpoint".into(), Value::String(self.endpoint.clone()));
        body.insert(
            "public_key_ed25519".into(),
            Value::String(self.ed25519.clone()),
        );
        body.insert(
            "public_key_mldsa65".into(),
            Value::String(self.mldsa65.clone()),
        );
        body.insert(
            "kem_public_key".into(),
            Value::String(self.kem_pubkey.clone()),
        );
        body.insert(
            "description".into(),
            Value::String(self.description.clone()),
        );
        if !self.tags.is_empty() {
            body.insert("tags".into(), Value::String(self.tags.clone()));
        }
        body.insert("enabled".into(), Value::Bool(!self.disabled));
        body.insert(
            "default_recording_dir".into(),
            Value::String(self.default_recording_dir.clone()),
        );

        let resp = client.logical().write("rustion/targets", Some(body))?;
        if resp.response_status == 200 {
            if let Some(data) = resp.response_data.as_ref() {
                self.output.print_value(data, true)?;
            }
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}
