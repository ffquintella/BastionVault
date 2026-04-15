use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

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
    about = "Restore vault data from a backup file",
    long_about = r#"Restores all vault data from a backup file. The HMAC is verified before
any data is written. The vault must be sealed during restore.

WARNING: This overwrites existing data in the destination backend.

Restore from a backup:

  $ bvault operator restore --input /path/to/backup.bvbk \
      --backend-type hiqlite \
      --backend-config data_dir=/var/lib/bvault/data \
      --backend-config node_id=1 \
      --backend-config secret_raft=my_raft_secret_16ch \
      --backend-config secret_api=my_api_secret_16chr \
      --hmac-key <hex-encoded-hmac-key>"#
)]
pub struct Restore {
    /// Input path for the backup file.
    #[arg(long, short)]
    input: String,

    /// Backend type to restore into (file, mysql, hiqlite).
    #[arg(long)]
    backend_type: String,

    /// Backend config as key=value pairs. Can be specified multiple times.
    #[arg(long = "backend-config", value_name = "key=value", action = clap::ArgAction::Append)]
    backend_config: Vec<String>,

    /// Hex-encoded HMAC key for backup integrity verification.
    #[arg(long)]
    hmac_key: String,
}

fn parse_config_pairs(pairs: &[String]) -> Result<HashMap<String, Value>, RvError> {
    let mut conf = HashMap::new();
    for pair in pairs {
        let (key, val) = pair.split_once('=').ok_or(RvError::ErrConfigLoadFailed)?;
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

impl CommandExecutor for Restore {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let conf = parse_config_pairs(&self.backend_config)?;
        let hmac_key = hex::decode(&self.hmac_key)
            .map_err(|_| RvError::ErrBackupHmacFailed)?;

        println!("Creating backend ({})...", self.backend_type);
        let backend = storage::new_backend(&self.backend_type, &conf)?;

        let file = File::open(&self.input)?;
        let mut reader = BufReader::new(file);

        println!("Verifying and restoring from {}...", self.input);

        let result = match tokio::runtime::Handle::try_current() {
            Ok(_) => std::thread::scope(|s| {
                let backend = backend.clone();
                let hmac_key = hmac_key.clone();
                let handle = s.spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        crate::backup::restore::restore_backup(
                            backend.as_ref(),
                            &hmac_key,
                            &mut reader,
                        ).await
                    })
                });
                handle.join().unwrap()
            }),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async {
                    crate::backup::restore::restore_backup(
                        backend.as_ref(),
                        &hmac_key,
                        &mut reader,
                    ).await
                })
            }
        }?;

        println!("Restore complete: {result} entries restored from {}", self.input);
        Ok(())
    }
}
