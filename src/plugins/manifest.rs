//! Plugin manifest.
//!
//! The manifest is a small JSON document the operator pins on registration.
//! It declares the plugin's identity, runtime, and capability footprint —
//! the trust contract.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    /// In-process wasmtime sandbox. The default and (for v1) only runtime.
    Wasm,
    /// Out-of-process subprocess via `tonic` over a UDS / named pipe.
    /// Reserved; refused at registration time until Phase 2 ships.
    Process,
}

impl Default for RuntimeKind {
    fn default() -> Self {
        Self::Wasm
    }
}

/// Capability surface declared by the plugin author and pinned by the
/// operator at registration. v1 enforces only `log_emit`; the rest are
/// reserved keys that future runtime versions will gate on.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Capabilities {
    /// May the plugin emit log lines via `bv_log`? Default: true.
    #[serde(default = "default_true")]
    pub log_emit: bool,
    /// (Reserved.) Storage prefix the plugin may read/write under.
    #[serde(default)]
    pub storage_prefix: Option<String>,
    /// (Reserved.) May the plugin emit audit events?
    #[serde(default)]
    pub audit_emit: bool,
    /// (Reserved.) Allowed Transit key handles.
    #[serde(default)]
    pub allowed_keys: Vec<String>,
    /// (Reserved, process-runtime only.) Allowed outbound hosts.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Top-level manifest. Stored barrier-encrypted alongside the WASM bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    /// User-visible category — `secret-engine`, `auth-backend`,
    /// `database`, etc. Free-form in v1; future versions may gate on it.
    #[serde(default)]
    pub plugin_type: String,
    #[serde(default)]
    pub runtime: RuntimeKind,
    /// Major.minor `PluginService` ABI version the plugin targets.
    #[serde(default = "default_abi_version")]
    pub abi_version: String,
    /// SHA-256 of the binary, hex-encoded. Recomputed on load and
    /// compared against this field so a tampered binary on the storage
    /// backend is detected immediately.
    pub sha256: String,
    /// Size of the binary in bytes. Cross-check against the stored bytes.
    pub size: u64,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub description: String,
}

fn default_abi_version() -> String {
    "1.0".to_string()
}

impl PluginManifest {
    /// Validate static invariants. Does not touch storage.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.name.trim().is_empty() {
            return Err("manifest.name is required");
        }
        if self.version.trim().is_empty() {
            return Err("manifest.version is required");
        }
        if !self.sha256.chars().all(|c| c.is_ascii_hexdigit()) || self.sha256.len() != 64 {
            return Err("manifest.sha256 must be 64 hex chars");
        }
        if !self.abi_version.starts_with("1.") {
            // v1 host only knows how to talk to v1.x plugins; future major
            // bumps will add a compatibility window per the spec.
            return Err("manifest.abi_version must start with \"1.\"");
        }
        match self.runtime {
            RuntimeKind::Wasm => Ok(()),
            RuntimeKind::Process => Err("process runtime is reserved (Phase 2)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PluginManifest {
        PluginManifest {
            name: "bv-plugin-totp".to_string(),
            version: "0.1.0".to_string(),
            plugin_type: "secret-engine".to_string(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".to_string(),
            sha256: "0".repeat(64),
            size: 1024,
            capabilities: Capabilities::default(),
            description: "TOTP secret engine".to_string(),
        }
    }

    #[test]
    fn validates_well_formed_manifest() {
        assert!(fixture().validate().is_ok());
    }

    #[test]
    fn rejects_bad_sha256() {
        let mut m = fixture();
        m.sha256 = "deadbeef".to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_process_runtime() {
        let mut m = fixture();
        m.runtime = RuntimeKind::Process;
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_future_abi_major() {
        let mut m = fixture();
        m.abi_version = "2.0".to_string();
        assert!(m.validate().is_err());
    }
}
