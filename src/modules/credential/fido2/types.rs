//! FIDO2 data types for storage.

use std::time::Duration;

use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::utils::{
    deserialize_duration, serialize_duration,
    token_util::TokenParams,
};

/// FIDO2 relying party configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fido2Config {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

/// A user's FIDO2 credential entry stored in vault storage.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Deref, DerefMut)]
pub struct UserCredentialEntry {
    pub username: String,
    pub policies: Vec<String>,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub max_ttl: Duration,
    #[serde(flatten, default)]
    #[deref]
    #[deref_mut]
    pub token_params: TokenParams,
    /// Serialized passkey credentials (JSON-encoded Vec<Passkey>).
    #[serde(default)]
    pub credentials_json: String,
}

impl UserCredentialEntry {
    /// Deserialize the stored passkey credentials.
    pub fn get_passkeys(&self) -> Result<Vec<Passkey>, serde_json::Error> {
        if self.credentials_json.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&self.credentials_json)
    }

    /// Serialize and store passkey credentials.
    pub fn set_passkeys(&mut self, passkeys: &[Passkey]) -> Result<(), serde_json::Error> {
        self.credentials_json = serde_json::to_string(passkeys)?;
        Ok(())
    }
}
