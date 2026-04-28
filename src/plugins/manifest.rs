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

/// One operator-settable config knob the plugin declares in its
/// manifest. The GUI renders a form from this; the host stores the
/// resulting key→value map at `core/plugins/<name>/config`; the plugin
/// reads values at run-time via `bv.config_get`.
///
/// Values cross the host/plugin boundary as **UTF-8 strings**. Numeric
/// / boolean / select-of-options fields are still strings on the wire
/// — the plugin parses. This keeps the host import surface minimal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigField {
    /// Stable key the plugin reads via `bv.config_get(key)`. Required
    /// to be a valid identifier (no whitespace, no slashes).
    pub name: String,
    pub kind: ConfigFieldKind,
    /// Human-readable label rendered as the form field's `<label>`.
    /// Defaults to `name` if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional helper text rendered under the input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// When true, the GUI refuses to save a config that leaves this
    /// field unset.
    #[serde(default)]
    pub required: bool,
    /// Default value shown in the form, applied if the operator hasn't
    /// written a value yet. String for every kind; the GUI parses for
    /// non-string kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// For `Select` kind: the allowed options.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFieldKind {
    /// Plain text input.
    String,
    /// Integer input. Stored as a base-10 string; the plugin parses.
    Int,
    /// Checkbox. Stored as `"true"` / `"false"`.
    Bool,
    /// Password-style input. Same storage as `String` (barrier-
    /// encrypted at rest like every other vault state) but the GUI
    /// masks it and the host never returns the value in
    /// `GET /v1/sys/plugins/<name>/config` responses — only a
    /// `"<set>"` placeholder.
    Secret,
    /// Dropdown. The `options` list constrains the set of valid values.
    Select,
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
    /// Phase 5.3: when `runtime = "process"`, opt into the long-lived
    /// supervised runtime. The host spawns one persistent child per
    /// plugin name, reuses it across invocations, and restarts it on
    /// crash with exponential backoff. Default `false` keeps the
    /// existing single-shot semantics — fresh process per invoke —
    /// so existing plugins (including the SDK reference plugins in
    /// `plugins-ext/`) keep working unchanged.
    ///
    /// Plugins that opt in must implement the long-lived dispatch
    /// protocol: receive `Init` once, then a stream of `invoke`
    /// messages each producing one `invoke_done`. Plugin authors
    /// targeting this mode use `bastion_plugin_sdk::run_long_lived()`
    /// (the `register!` macro emits a single-shot loop).
    #[serde(default)]
    pub long_lived: bool,
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
    /// Operator-configurable knobs the plugin reads at run-time via
    /// `bv.config_get`. The GUI renders a form from this schema; the
    /// host persists the resulting key→value map at
    /// `core/plugins/<name>/config`. Empty when the plugin needs no
    /// config — older manifests without this field still parse
    /// cleanly thanks to `serde(default)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_schema: Vec<ConfigField>,
    /// Phase 5.2: ML-DSA-65 signature over `binary || canonical_manifest_json`,
    /// hex-encoded. Empty when the plugin is unsigned (only loadable
    /// when `accept_unsigned = true` is configured on the plugin
    /// engine; logged at WARN). The catalog verifies the signature
    /// against `signing_key` at registration *and* every load.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Phase 5.2: name of the publisher key that signed this plugin.
    /// Must appear in the operator-configured publisher allowlist.
    /// Stored as a free-form identifier (typically the publisher's
    /// short name like `"acme-corp"`); the allowlist maps it to the
    /// hex-encoded ML-DSA-65 public-key bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_key: String,
}

fn default_abi_version() -> String {
    "1.0".to_string()
}

/// The current host-supported `PluginService` ABI major/minor.
/// Bumped per the spec at most once per release. Plugins targeting
/// `(major, ≤ HOST_ABI_MINOR)` are accepted; cross-major mismatches
/// are refused with a compatibility-matrix link in the error.
pub const HOST_ABI_MAJOR: u32 = 1;
pub const HOST_ABI_MINOR: u32 = 0;

/// Phase 5.4 — parse `"major.minor"` from a manifest. Returns
/// `Err(_)` for any non-numeric or missing component so a typo'd
/// version field never silently coerces to `(0, 0)`.
pub fn parse_abi(s: &str) -> Result<(u32, u32), String> {
    let (major, minor) = s
        .split_once('.')
        .ok_or_else(|| format!("abi_version `{s}` is not in `MAJOR.MINOR` form"))?;
    let major: u32 = major
        .parse()
        .map_err(|e| format!("abi_version major `{major}` is not a u32 ({e})"))?;
    let minor: u32 = minor
        .parse()
        .map_err(|e| format!("abi_version minor `{minor}` is not a u32 ({e})"))?;
    Ok((major, minor))
}

/// Phase 5.4 — host-side compatibility check. Accepts plugins with
/// the same major and a minor `≤ HOST_ABI_MINOR`. Cross-major or
/// future-minor versions return a clear error with a pointer to the
/// host's supported version. This is the host's promise to plugin
/// authors: a `(1, 0)` plugin keeps working until the host bumps to
/// `(2, *)`, at which point the spec commits to a one-release window
/// where the previous major still loads behind a feature flag.
pub fn check_abi_compatibility(plugin_abi: &str) -> Result<(), String> {
    let (maj, min) = parse_abi(plugin_abi)?;
    if maj != HOST_ABI_MAJOR {
        return Err(format!(
            "plugin abi_version `{plugin_abi}` (major {maj}) is not compatible with host \
             PluginService major {HOST_ABI_MAJOR}; see features/plugin-system.md \
             § \"Versioning\" for the migration window"
        ));
    }
    if min > HOST_ABI_MINOR {
        return Err(format!(
            "plugin abi_version `{plugin_abi}` (minor {min}) is newer than host minor {HOST_ABI_MINOR}; \
             upgrade BastionVault before loading this plugin"
        ));
    }
    Ok(())
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
            RuntimeKind::Wasm | RuntimeKind::Process => {}
        }
        for field in &self.config_schema {
            if field.name.trim().is_empty()
                || field.name.contains(char::is_whitespace)
                || field.name.contains('/')
                || field.name.contains("..")
            {
                return Err("config_schema field has invalid name");
            }
            if matches!(field.kind, ConfigFieldKind::Select) && field.options.is_empty() {
                return Err("config_schema field of kind=select must declare options");
            }
        }
        Ok(())
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
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
        }
    }

    #[test]
    fn validates_well_formed_manifest() {
        assert!(fixture().validate().is_ok());
    }

    /// Phase 5.4 — host-side ABI compatibility check.
    #[test]
    fn abi_compatibility_accepts_same_major_lower_minor() {
        assert!(super::check_abi_compatibility("1.0").is_ok());
    }

    #[test]
    fn abi_compatibility_rejects_cross_major() {
        let err = super::check_abi_compatibility("2.0").unwrap_err();
        assert!(err.contains("major 2"));
        assert!(err.contains("major 1"));
    }

    #[test]
    fn abi_compatibility_rejects_future_minor() {
        let err = super::check_abi_compatibility("1.999").unwrap_err();
        assert!(err.contains("minor 999"));
    }

    #[test]
    fn abi_compatibility_rejects_malformed() {
        assert!(super::check_abi_compatibility("not-a-version").is_err());
        assert!(super::check_abi_compatibility("1").is_err());
        assert!(super::check_abi_compatibility("1.x").is_err());
    }

    #[test]
    fn rejects_bad_sha256() {
        let mut m = fixture();
        m.sha256 = "deadbeef".to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn accepts_process_runtime() {
        let mut m = fixture();
        m.runtime = RuntimeKind::Process;
        // Process runtime was reserved in Phase 1; Phase 2 lights it
        // up. Validation should now succeed.
        assert!(m.validate().is_ok());
    }

    #[test]
    fn rejects_future_abi_major() {
        let mut m = fixture();
        m.abi_version = "2.0".to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_invalid_config_field_name() {
        let mut m = fixture();
        m.config_schema.push(ConfigField {
            name: "bad name with spaces".to_string(),
            kind: ConfigFieldKind::String,
            label: None,
            description: None,
            required: false,
            default: None,
            options: vec![],
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_select_without_options() {
        let mut m = fixture();
        m.config_schema.push(ConfigField {
            name: "algo".to_string(),
            kind: ConfigFieldKind::Select,
            label: None,
            description: None,
            required: false,
            default: None,
            options: vec![],
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn accepts_well_formed_config_schema() {
        let mut m = fixture();
        m.config_schema.push(ConfigField {
            name: "endpoint_url".to_string(),
            kind: ConfigFieldKind::String,
            label: Some("Endpoint URL".to_string()),
            description: Some("Where the plugin POSTs results".to_string()),
            required: true,
            default: None,
            options: vec![],
        });
        m.config_schema.push(ConfigField {
            name: "algorithm".to_string(),
            kind: ConfigFieldKind::Select,
            label: None,
            description: None,
            required: false,
            default: Some("sha256".to_string()),
            options: vec!["sha1".to_string(), "sha256".to_string(), "sha512".to_string()],
        });
        assert!(m.validate().is_ok());
    }
}
