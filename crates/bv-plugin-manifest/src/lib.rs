//! Shared plugin manifest types and the **canonical signing-message**
//! construction.
//!
//! This crate is the single source of truth for both ends of the plugin
//! signing handshake:
//!
//! * `bv-plugin-pack` (the signer) deserialises a `plugin.toml` into
//!   [`PluginManifest`], stamps `sha256`/`size`, and signs
//!   [`signing_message`].
//! * the host verifier (`bastion_vault::plugins::verifier`) deserialises
//!   the registered/loaded manifest into the *same* [`PluginManifest`]
//!   and re-derives [`signing_message`] to check the signature — at
//!   registration *and* on every reload.
//!
//! Because both sides share this type **and** this function, the signed
//! message is byte-identical by construction. The canonicalisation sorts
//! object keys recursively, so the signature is also invariant to the
//! order in which struct fields happen to serialise — a future field
//! reorder can't silently invalidate already-signed bundles.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    /// In-process wasmtime sandbox. The default and (for v1) only runtime.
    #[default]
    Wasm,
    /// Out-of-process subprocess via `tonic` over a UDS / named pipe.
    /// Reserved; refused at registration time until Phase 2 ships.
    Process,
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

    /// Extensibility v2 (app extensions): programmatic app-module
    /// capabilities — dynamic menus, plugin windows, the vault-API
    /// bridge, and network. All fields default off, so a v1 plugin (no
    /// `app` block) is byte-identical to before. Every field
    /// participates in the catalog's capability-widening guard, and the
    /// `net` request additionally requires a separate admin grant at
    /// install (see `bastion_vault::plugins::grants`). A non-default
    /// `app` block requires `abi_version` minor ≥ 1 (`"1.1"`).
    ///
    /// `skip_serializing_if` omits a default (v1) app block from the
    /// canonical signing message, so **already-signed v1 plugins keep
    /// verifying** — same discipline as `surface` / `client_assets`.
    /// Only a plugin that actually declares an app capability changes
    /// its own signed bytes.
    #[serde(default, skip_serializing_if = "AppCapabilities::is_default")]
    pub app: AppCapabilities,
}

/// Extensibility v2: the app-module capability surface. Requesting a
/// capability here is necessary but, for `net`, not sufficient — the
/// admin grant is the second key (see `features/plugin-app-extensions.md`
/// § "The admin network grant").
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppCapabilities {
    /// Enables `bvx.menu_upsert` / `bvx.menu_remove`.
    #[serde(default)]
    pub dynamic_menus: bool,
    /// Enables `bvx.window_*`. `max_open` caps concurrently-open plugin
    /// windows; the host clamps to ≤ [`MAX_PLUGIN_WINDOWS`]. `0` (the
    /// default) disables windows entirely.
    #[serde(default)]
    pub windows: WindowsCapabilities,
    /// Enables `bvx.api_request`. Each entry must start with `{mount}`,
    /// contain no `..`, and not be absolute — the same rules as surface
    /// bindings. Empty (default) disables the vault-API bridge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_paths: Vec<String>,
    /// Requests the network capability. `None` (default) means the
    /// plugin never touches the network. A `Some` request is pinned at
    /// registration but only usable after an admin grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetCapabilities>,
}

impl AppCapabilities {
    /// True when the plugin declares *any* app-module capability. Used
    /// to gate the `abi_version` minor requirement: a plugin that ships
    /// an `app` block must target ABI `1.1`.
    pub fn is_declared(&self) -> bool {
        self.dynamic_menus
            || self.windows.max_open > 0
            || !self.api_paths.is_empty()
            || self.net.is_some()
    }

    /// `true` when this is the default (no-op) app block — used as the
    /// `skip_serializing_if` predicate so a v1 plugin's canonical
    /// signing message is unchanged by this field's existence.
    pub fn is_default(&self) -> bool {
        !self.is_declared()
    }
}

/// Window capability. `max_open` is the hard cap on concurrently-open
/// plugin windows this plugin may hold.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsCapabilities {
    #[serde(default)]
    pub max_open: u32,
}

/// Network capability request. The `hosts` allowlist is validated at
/// registration with the same rules as `allowed_hosts`; the admin grant
/// is pinned to a SHA-256 over this struct so any change (even a
/// narrowing) voids the grant until re-approved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetCapabilities {
    /// Requested outbound host allowlist. No bare `*`, no ports,
    /// wildcard only as the leading label (`*.example.com`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// When `true` (default), the client enforcer refuses plain `http`.
    #[serde(default = "default_true")]
    pub https_only: bool,
}

/// Host hard cap on a plugin's concurrently-open windows. `max_open`
/// values above this are refused at registration.
pub const MAX_PLUGIN_WINDOWS: u32 = 4;

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
    /// Phase 5.2: ML-DSA-65 signature over `signing_message`,
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

    /// Plugin Extensibility v1: surface manifest reference. Present
    /// when the plugin ships a `surface.json` declaring menus / pages
    /// / forms for the GUI. Validated against the bundled bytes at
    /// registration. Absent for v1 plugins, which keep working
    /// unchanged via the existing admin-only Plugins page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<SurfaceRef>,

    /// Plugin Extensibility v1: client-side assets the plugin ships
    /// (today: form-hook WASM modules). Each entry is content-addressed
    /// by `sha256` and fetched by clients via the per-version asset
    /// endpoint. Empty for plugins with no client-side hooks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_assets: Vec<ClientAssetRef>,
}

/// Plugin Extensibility v1: pointer to the plugin's `surface.json`.
/// The hash gets verified at registration and on every catalog read so
/// the surface a client receives matches what the operator pinned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceRef {
    /// `surface.json`'s `schema_version`. Mirrored on the manifest so
    /// the catalog can refuse a too-new surface without parsing the
    /// JSON. Bumped per the central [`bv_plugin_surface`] crate.
    pub schema_version: u32,
    /// SHA-256 of the surface JSON bytes, hex-encoded. The catalog
    /// recomputes on read; a mismatch is treated as tampering.
    pub sha256: String,
    /// Size of the surface JSON in bytes.
    pub size: u64,
}

/// Plugin Extensibility v1: declaration of one client-side asset.
/// Today only `kind = "form-hook"` is honoured by the GUI; future
/// kinds (e.g. `"icon"`, `"css-token"`) will be added behind a schema
/// version bump on the surface, not the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAssetRef {
    pub name: String,
    pub kind: String,
    pub sha256: String,
    pub size: u64,
}

fn default_abi_version() -> String {
    "1.0".to_string()
}

/// The current host-supported `PluginService` ABI major/minor.
/// Bumped per the spec at most once per release. Plugins targeting
/// `(major, ≤ HOST_ABI_MINOR)` are accepted; cross-major mismatches
/// are refused with a compatibility-matrix link in the error.
pub const HOST_ABI_MAJOR: u32 = 1;
/// Bumped to `1` for Extensibility v2 (app extensions): the additive
/// `bvx.*` host surface. Plugins that declare `capabilities.app` target
/// `abi_version = "1.1"`; older hosts (minor 0) refuse them cleanly via
/// [`check_abi_compatibility`] — the intended downgrade behavior.
pub const HOST_ABI_MINOR: u32 = 1;

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
        if let Some(s) = &self.surface {
            if s.sha256.len() != 64 || !s.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("surface.sha256 must be 64 hex chars");
            }
            if s.schema_version > bv_plugin_surface::CURRENT_SCHEMA_VERSION {
                return Err("surface.schema_version is newer than this host supports");
            }
        }
        let mut asset_names = std::collections::BTreeSet::new();
        let mut app_module_count = 0usize;
        for a in &self.client_assets {
            if a.name.trim().is_empty() || a.name.contains('/') || a.name.contains("..") {
                return Err("client_assets entry has invalid name");
            }
            if !asset_names.insert(a.name.clone()) {
                return Err("client_assets entries must have unique names");
            }
            if a.sha256.len() != 64 || !a.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("client_assets entry sha256 must be 64 hex chars");
            }
            // Extensibility v2: at most one app-module WASM asset per
            // plugin version.
            if a.kind == "app-module" {
                app_module_count += 1;
                if app_module_count > 1 {
                    return Err("at most one client_assets entry may have kind=\"app-module\"");
                }
            }
        }
        self.validate_app_capabilities()?;
        Ok(())
    }

    /// Extensibility v2: static invariants on the `capabilities.app`
    /// block. Coarse, `&'static str`-message checks layered under the
    /// catalog's authoritative (rich-message) validation — this also
    /// runs in the `bv-plugin-pack` signer, so a malformed app manifest
    /// is caught before it is ever signed. Rules mirror surface
    /// bindings (`api_paths`) and `allowed_hosts` (`net.hosts`).
    fn validate_app_capabilities(&self) -> Result<(), &'static str> {
        let app = &self.capabilities.app;
        if !app.is_declared() {
            return Ok(());
        }
        // A declared app block requires the v2 ABI minor.
        let (_maj, min) = parse_abi(&self.abi_version)
            .map_err(|_| "abi_version must be MAJOR.MINOR")?;
        if min < 1 {
            return Err("capabilities.app requires abi_version minor >= 1 (\"1.1\")");
        }
        if app.windows.max_open > MAX_PLUGIN_WINDOWS {
            return Err("capabilities.app.windows.max_open exceeds the host cap (4)");
        }
        for p in &app.api_paths {
            if p.is_empty()
                || !p.starts_with("{mount}")
                || p.contains("..")
                || p.starts_with('/')
            {
                return Err(
                    "capabilities.app.api_paths entry must start with {mount}, be relative, and not contain ..",
                );
            }
        }
        if let Some(net) = &app.net {
            for h in &net.hosts {
                let t = h.trim();
                if t.is_empty() || t == "*" || t.contains(':') {
                    return Err(
                        "capabilities.app.net.hosts entry must be a non-empty host without a port and not bare `*`",
                    );
                }
            }
        }
        Ok(())
    }
}

/// Construct the canonical message a publisher signs and the host
/// verifies: `sha256(binary) || canonical_manifest_json`, where the
/// canonical manifest JSON is [`PluginManifest`] with the `signature`
/// field cleared, serialised with **object keys sorted recursively**.
///
/// Hashing the binary first keeps the message a fixed prefix size even
/// for large WASM modules. Sorting keys makes the message independent
/// of serde field-declaration order, so the signer and verifier agree
/// even across struct refactors — the property whose absence made
/// otherwise-valid signatures fail before this crate existed.
pub fn signing_message(manifest: &PluginManifest, binary: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(binary);
    let bin_digest = h.finalize();

    let mut clone = manifest.clone();
    clone.signature.clear();
    // `to_value` runs the normal Serialize impl (honouring
    // skip_serializing_if), then `write_canonical` re-emits it with
    // sorted keys — independent of whether serde_json was compiled
    // with the `preserve_order` feature anywhere in the tree.
    let value = serde_json::to_value(&clone).expect("PluginManifest always serialises");
    let mut canonical = String::new();
    write_canonical(&value, &mut canonical);

    let mut out = Vec::with_capacity(bin_digest.len() + canonical.len());
    out.extend_from_slice(&bin_digest);
    out.extend_from_slice(canonical.as_bytes());
    out
}

/// Emit `value` as compact JSON with object keys sorted lexicographically
/// at every level. Array order is preserved (it is semantically
/// meaningful, e.g. `config_schema`).
fn write_canonical(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Reuse serde_json's string escaping for the key.
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(e, out);
            }
            out.push(']');
        }
        // Scalars: serde_json already emits a canonical form.
        other => out.push_str(&other.to_string()),
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
            surface: None,
            client_assets: vec![],
        }
    }

    #[test]
    fn validates_well_formed_manifest() {
        assert!(fixture().validate().is_ok());
    }

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
    fn accepts_manifest_with_surface() {
        let mut m = fixture();
        m.surface = Some(SurfaceRef {
            schema_version: 1,
            sha256: "0".repeat(64),
            size: 256,
        });
        m.client_assets.push(ClientAssetRef {
            name: "form-hooks.wasm".to_string(),
            kind: "form-hook".to_string(),
            sha256: "1".repeat(64),
            size: 4096,
        });
        m.validate().unwrap();
    }

    #[test]
    fn rejects_bad_surface_sha256() {
        let mut m = fixture();
        m.surface = Some(SurfaceRef {
            schema_version: 1,
            sha256: "deadbeef".to_string(),
            size: 0,
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_too_new_surface_schema_version() {
        let mut m = fixture();
        m.surface = Some(SurfaceRef {
            schema_version: 999,
            sha256: "0".repeat(64),
            size: 0,
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_client_asset_names() {
        let mut m = fixture();
        m.client_assets.push(ClientAssetRef {
            name: "h.wasm".to_string(),
            kind: "form-hook".to_string(),
            sha256: "0".repeat(64),
            size: 1,
        });
        m.client_assets.push(ClientAssetRef {
            name: "h.wasm".to_string(),
            kind: "form-hook".to_string(),
            sha256: "1".repeat(64),
            size: 1,
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_client_asset_name_with_slash() {
        let mut m = fixture();
        m.client_assets.push(ClientAssetRef {
            name: "../escape.wasm".to_string(),
            kind: "form-hook".to_string(),
            sha256: "0".repeat(64),
            size: 1,
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn legacy_manifest_round_trips_without_new_fields() {
        let json = r#"{
            "name": "old-plugin",
            "version": "0.1.0",
            "plugin_type": "secret-engine",
            "runtime": "wasm",
            "abi_version": "1.0",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "size": 1024
        }"#;
        let m: PluginManifest = serde_json::from_str(json).unwrap();
        assert!(m.surface.is_none());
        assert!(m.client_assets.is_empty());
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

    // ── canonical signing-message tests ──

    #[test]
    fn signing_message_ignores_signature_field() {
        let bin = b"plugin-bytes";
        let mut a = fixture();
        let mut b = fixture();
        b.signature = "deadbeef".into(); // cleared internally before canonicalising
        assert_eq!(signing_message(&a, bin), signing_message(&b, bin));
        // sanity: the message actually depends on the binary
        a.name = "other".into();
        assert_ne!(signing_message(&a, bin), signing_message(&b, bin));
    }

    #[test]
    fn signing_message_is_key_sorted_and_stable() {
        let m = fixture();
        let msg = signing_message(&m, b"x");
        // The canonical JSON begins right after the 32-byte sha256.
        let json = std::str::from_utf8(&msg[32..]).unwrap();
        // Keys are sorted: abi_version is the first object key.
        assert!(json.starts_with("{\"abi_version\":"));
        // long_lived is always present (it is part of the shared type),
        // which is exactly what the pack tool now emits too.
        assert!(json.contains("\"long_lived\":false"));
    }

    // ── Extensibility v2: capabilities.app tests ──

    fn app_fixture() -> PluginManifest {
        let mut m = fixture();
        m.abi_version = "1.1".to_string();
        m.capabilities.app = AppCapabilities {
            dynamic_menus: true,
            windows: WindowsCapabilities { max_open: 2 },
            api_paths: vec!["{mount}/".to_string()],
            net: Some(NetCapabilities {
                hosts: vec!["hooks.example.com".to_string(), "*.status.example.net".to_string()],
                https_only: true,
            }),
        };
        m
    }

    #[test]
    fn accepts_well_formed_app_block() {
        app_fixture().validate().unwrap();
    }

    #[test]
    fn rejects_app_block_with_v1_abi() {
        let mut m = app_fixture();
        m.abi_version = "1.0".to_string();
        let err = m.validate().unwrap_err();
        assert!(err.contains("abi_version minor"));
    }

    #[test]
    fn rejects_absolute_api_path() {
        let mut m = app_fixture();
        m.capabilities.app.api_paths = vec!["/etc/passwd".to_string()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_api_path_with_dotdot() {
        let mut m = app_fixture();
        m.capabilities.app.api_paths = vec!["{mount}/../other".to_string()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_api_path_not_under_mount() {
        let mut m = app_fixture();
        m.capabilities.app.api_paths = vec!["secret/other".to_string()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_bare_wildcard_net_host() {
        let mut m = app_fixture();
        m.capabilities.app.net.as_mut().unwrap().hosts = vec!["*".to_string()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_net_host_with_port() {
        let mut m = app_fixture();
        m.capabilities.app.net.as_mut().unwrap().hosts = vec!["host.example.com:443".to_string()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_windows_over_cap() {
        let mut m = app_fixture();
        m.capabilities.app.windows.max_open = MAX_PLUGIN_WINDOWS + 1;
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_two_app_module_assets() {
        let mut m = app_fixture();
        m.client_assets.push(ClientAssetRef {
            name: "a.wasm".into(),
            kind: "app-module".into(),
            sha256: "0".repeat(64),
            size: 1,
        });
        m.client_assets.push(ClientAssetRef {
            name: "b.wasm".into(),
            kind: "app-module".into(),
            sha256: "1".repeat(64),
            size: 1,
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn legacy_manifest_has_default_app_block() {
        let json = r#"{
            "name": "old-plugin",
            "version": "0.1.0",
            "abi_version": "1.0",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "size": 1024
        }"#;
        let m: PluginManifest = serde_json::from_str(json).unwrap();
        assert!(m.capabilities.app.is_default());
        assert!(!m.capabilities.app.is_declared());
        m.validate().unwrap();
    }

    #[test]
    fn default_app_block_omitted_from_signing_message() {
        // A v1 plugin (default app block) must produce the same
        // canonical signing message as before this field existed —
        // otherwise every already-signed v1 plugin would fail
        // re-verification on load.
        let m = fixture();
        let msg = signing_message(&m, b"x");
        let json = std::str::from_utf8(&msg[32..]).unwrap();
        assert!(!json.contains("\"app\""), "default app block must be omitted: {json}");
    }

    #[test]
    fn declared_app_block_present_in_signing_message() {
        let m = app_fixture();
        let msg = signing_message(&m, b"x");
        let json = std::str::from_utf8(&msg[32..]).unwrap();
        assert!(json.contains("\"app\""));
        assert!(json.contains("\"dynamic_menus\":true"));
    }

    #[test]
    fn signing_message_invariant_to_binary_only_via_hash_prefix() {
        let m = fixture();
        let m1 = signing_message(&m, b"aaaa");
        let m2 = signing_message(&m, b"bbbb");
        // Different binaries → different 32-byte prefix, identical tail.
        assert_ne!(&m1[..32], &m2[..32]);
        assert_eq!(&m1[32..], &m2[32..]);
    }
}
