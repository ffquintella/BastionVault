use std::collections::HashMap;
use std::sync::Arc;

use bastion_vault::core::SealConfig;
use bastion_vault::storage::new_backend;
use bastion_vault::BastionVault;
use serde_json::Value;

use crate::error::CommandError;
use crate::secure_store;

/// Returns the data directory for the embedded vault.
pub fn data_dir() -> Result<std::path::PathBuf, CommandError> {
    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .ok_or("Cannot determine home directory")?;
    Ok(base.join(".bastion_vault_gui").join("data"))
}

/// Check if a vault has been previously initialized.
pub fn is_initialized() -> Result<bool, CommandError> {
    let dir = data_dir()?;
    // The barrier init marker file indicates an initialized vault.
    Ok(dir.exists() && dir.join("_barrier").exists())
}

/// Create a new embedded vault, initialize it, and store keys in the OS keychain.
/// Returns the root token.
pub async fn init_embedded() -> Result<String, CommandError> {
    let dir = data_dir()?;
    std::fs::create_dir_all(&dir)?;

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));

    let backend = new_backend("file", &conf).map_err(|e| CommandError::from(e))?;
    let vault = BastionVault::new(backend, None).map_err(|e| CommandError::from(e))?;

    let seal_config = SealConfig {
        secret_shares: 1,
        secret_threshold: 1,
    };

    let init_result = vault.init(&seal_config).await.map_err(|e| CommandError::from(e))?;

    // Store the unseal key and root token in the OS keychain.
    let unseal_key_hex = hex::encode(&init_result.secret_shares[0]);
    let root_token = init_result.root_token.clone();
    secure_store::store_unseal_key(&unseal_key_hex)?;
    secure_store::store_root_token(&root_token)?;

    // Unseal immediately.
    let key_bytes = &init_result.secret_shares[0];
    vault.unseal(&[key_bytes.as_slice()]).await.map_err(|e| CommandError::from(e))?;

    Ok(root_token)
}

/// Open and unseal an existing embedded vault using keys from the OS keychain.
pub async fn open_embedded() -> Result<Arc<BastionVault>, CommandError> {
    let dir = data_dir()?;

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));

    let backend = new_backend("file", &conf).map_err(|e| CommandError::from(e))?;
    let vault = BastionVault::new(backend, None).map_err(|e| CommandError::from(e))?;

    let unseal_key_hex = secure_store::get_unseal_key()?
        .ok_or("No unseal key found in keychain. Was the vault initialized?")?;
    let unseal_key = hex::decode(&unseal_key_hex)
        .map_err(|_| CommandError::from("Invalid unseal key in keychain"))?;

    vault.unseal(&[&unseal_key]).await.map_err(|e| CommandError::from(e))?;

    Ok(Arc::new(vault))
}

/// Seal the vault.
pub async fn seal_vault(vault: &BastionVault) -> Result<(), CommandError> {
    vault.core.load().seal().await.map_err(|e| CommandError::from(e))
}
