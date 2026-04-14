use std::collections::HashMap;

use clap::Parser;
use serde_json::Value;

use crate::{
    cli::command::CommandExecutor,
    errors::RvError,
    storage,
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Migrate data between storage backends",
    long_about = r#"Copies all encrypted data from one storage backend to another. Data is
copied as raw encrypted bytes, so the same unseal keys work after migration.

The vault must be sealed during migration to prevent concurrent writes.

Migrate from file backend to hiqlite:

  $ bvault operator migrate \
      --source-type file --source-config path=/var/lib/bvault/old-data \
      --dest-type hiqlite \
      --dest-config data_dir=/var/lib/bvault/new-data \
      --dest-config node_id=1 \
      --dest-config secret_raft=my_raft_secret_16ch \
      --dest-config secret_api=my_api_secret_16chr

Migrate from mysql to hiqlite:

  $ bvault operator migrate \
      --source-type mysql --source-config connection_url=mysql://root:pass@localhost/vault \
      --dest-type hiqlite \
      --dest-config data_dir=/var/lib/bvault/data \
      --dest-config node_id=1 \
      --dest-config secret_raft=my_raft_secret_16ch \
      --dest-config secret_api=my_api_secret_16chr"#
)]
pub struct Migrate {
    /// Source backend type (file, mysql, hiqlite).
    #[arg(long)]
    source_type: String,

    /// Source backend config as key=value pairs. Can be specified multiple times.
    #[arg(long = "source-config", value_name = "key=value", action = clap::ArgAction::Append)]
    source_config: Vec<String>,

    /// Destination backend type (file, mysql, hiqlite).
    #[arg(long)]
    dest_type: String,

    /// Destination backend config as key=value pairs. Can be specified multiple times.
    #[arg(long = "dest-config", value_name = "key=value", action = clap::ArgAction::Append)]
    dest_config: Vec<String>,
}

fn parse_config_pairs(pairs: &[String]) -> Result<HashMap<String, Value>, RvError> {
    let mut conf = HashMap::new();
    for pair in pairs {
        let (key, val) = pair.split_once('=').ok_or_else(|| {
            RvError::ErrConfigLoadFailed
        })?;
        // Try to parse as number first, then as string
        let value = if let Ok(n) = val.parse::<u64>() {
            Value::Number(n.into())
        } else if val == "true" {
            Value::Bool(true)
        } else if val == "false" {
            Value::Bool(false)
        } else {
            Value::String(val.to_string())
        };
        conf.insert(key.to_string(), value);
    }
    Ok(conf)
}

impl CommandExecutor for Migrate {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let source_conf = parse_config_pairs(&self.source_config)?;
        let dest_conf = parse_config_pairs(&self.dest_config)?;

        println!("Creating source backend ({})...", self.source_type);
        let source = storage::new_backend(&self.source_type, &source_conf)?;

        println!("Creating destination backend ({})...", self.dest_type);
        let dest = storage::new_backend(&self.dest_type, &dest_conf)?;

        println!("Starting migration from {} to {}...", self.source_type, self.dest_type);

        let result = match tokio::runtime::Handle::try_current() {
            Ok(_handle) => std::thread::scope(|s| {
                let source = source.clone();
                let dest = dest.clone();
                let handle = s.spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async { storage::migrate::migrate_backend(&source, &dest).await })
                });
                handle.join().unwrap()
            }),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async { storage::migrate::migrate_backend(&source, &dest).await })
            }
        }?;

        println!(
            "Migration complete: {} entries copied, {} entries skipped.",
            result.entries_copied, result.entries_skipped
        );

        Ok(())
    }
}
