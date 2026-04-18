use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    /// Username (or display name) of the token that created this version.
    /// `#[serde(default)]` keeps older on-disk metadata deserializable.
    #[serde(default)]
    pub username: String,
    /// "create" for the first version, "update" for subsequent versions,
    /// "restore" when the version is a copy of an earlier version.
    #[serde(default)]
    pub operation: String,
}

impl VersionMetadata {
    pub fn is_soft_deleted(&self) -> bool {
        !self.deletion_time.is_empty() && !self.destroyed
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub current_version: u64,
    pub oldest_version: u64,
    pub max_versions: u64,
    pub cas_required: bool,
    pub delete_version_after: String,
    pub created_time: String,
    pub updated_time: String,
    pub versions: HashMap<String, VersionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub max_versions: u64,
    pub cas_required: bool,
    pub delete_version_after: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_versions: 0,
            cas_required: false,
            delete_version_after: "0s".to_string(),
        }
    }
}
