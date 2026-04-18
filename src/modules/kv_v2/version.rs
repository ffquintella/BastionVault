use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionData {
    pub data: Map<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    /// Username (or display name) of the token that created this version.
    #[serde(default)]
    pub username: String,
    /// "create" | "update" | "restore".
    #[serde(default)]
    pub operation: String,
}
