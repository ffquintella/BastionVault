use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;

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
    about = "Create a backup of all vault data",
    long_about = r#"Creates a point-in-time backup of all vault data as encrypted blobs.
The backup file contains raw encrypted data with HMAC integrity verification.

The vault must be sealed during backup for consistency. The same unseal keys
are required to restore from this backup.

Create a backup:

  $ bvault operator backup --output /path/to/backup.bvbk \
      --backend-type file --backend-config path=/var/lib/bvault/data \
      --hmac-key <hex-encoded-hmac-key>

Create a compressed backup:

  $ bvault operator backup --output /path/to/backup.bvbk --compress \
      --backend-type file --backend-config path=/var/lib/bvault/data \
      --hmac-key <hex-encoded-hmac-key>"#
)]
pub struct Backup {
    /// Output path for the backup file.
    #[arg(long, short)]
    output: String,

    /// Backend type to read from (file, mysql, hiqlite).
    #[arg(long)]
    backend_type: String,

    /// Backend config as key=value pairs. Can be specified multiple times.
    #[arg(long = "backend-config", value_name = "key=value", action = clap::ArgAction::Append)]
    backend_config: Vec<String>,

    /// Hex-encoded HMAC key for backup integrity.
    #[arg(long)]
    hmac_key: String,

    /// Enable zstd compression for entry values.
    #[arg(long, default_value = "false")]
    compress: bool,
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

impl CommandExecutor for Backup {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let conf = parse_config_pairs(&self.backend_config)?;
        let hmac_key = hex::decode(&self.hmac_key)
            .map_err(|_| RvError::ErrBackupHmacFailed)?;

        println!("Creating backend ({})...", self.backend_type);
        let backend = storage::new_backend(&self.backend_type, &conf)?;

        let file = File::create(&self.output)?;
        let mut writer = BufWriter::new(file);

        println!("Starting backup to {}...", self.output);

        let result = match tokio::runtime::Handle::try_current() {
            Ok(_) => std::thread::scope(|s| {
                let backend = backend.clone();
                let hmac_key = hmac_key.clone();
                let compress = self.compress;
                let handle = s.spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        crate::backup::create::create_backup(
                            backend.as_ref(),
                            &hmac_key,
                            &mut writer,
                            compress,
                        ).await
                    })
                });
                handle.join().unwrap()
            }),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async {
                    crate::backup::create::create_backup(
                        backend.as_ref(),
                        &hmac_key,
                        &mut writer,
                        self.compress,
                    ).await
                })
            }
        }?;

        println!("Backup complete: {result} entries written to {}", self.output);
        Ok(())
    }
}
