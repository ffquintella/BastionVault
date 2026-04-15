use keyring::Entry;

use crate::error::CommandError;

const SERVICE: &str = "bastion-vault-gui";

fn entry(key: &str) -> Result<Entry, CommandError> {
    Entry::new(SERVICE, key).map_err(|e| CommandError::from(format!("Keychain entry error: {e}")))
}

pub fn store_unseal_key(key: &str) -> Result<(), CommandError> {
    entry("unseal-key")?.set_password(key)?;
    Ok(())
}

pub fn get_unseal_key() -> Result<Option<String>, CommandError> {
    match entry("unseal-key")?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn store_root_token(token: &str) -> Result<(), CommandError> {
    entry("root-token")?.set_password(token)?;
    Ok(())
}

pub fn get_root_token() -> Result<Option<String>, CommandError> {
    match entry("root-token")?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
