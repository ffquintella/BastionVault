//! This module defines and handles the config file options for BastionVault application.
//! For instance, the IP address and port for the BastionVault to listen on is handled in this
//! module.
//!
//! It used to live at `cli::config`, which was never accurate: [`Config`] is
//! the *server's* configuration model, and [`BastionVault::new`] takes one.
//! `core.rs`, `modules::auth`, `src/http` and `test_utils` all name it, so
//! leaving it under `cli` would have pinned the whole command-line layer into
//! the library's compilation unit. See
//! roadmaps/workspace-decomposition.md § Phase 4.
//!
//! [`BastionVault::new`]: crate::BastionVault::new

use std::{collections::HashMap, fmt, fs, path::Path};

use better_default::Default;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::Value;

use crate::{cache::CacheConfig, errors::RvError, storage::BarrierType};

/// Supported TLS protocol versions for the listener.
///
/// `rustls` only supports TLS 1.2 and 1.3; any older value in a config file
/// is rejected at deserialization time.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// A struct that contains several configurable options of BastionVault server
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(deserialize_with = "validate_listener")]
    pub listener: HashMap<String, Listener>,
    #[serde(deserialize_with = "validate_storage")]
    pub storage: HashMap<String, Storage>,
    #[serde(default)]
    pub api_addr: String,
    #[serde(default)]
    pub log_format: String,
    /// `RUST_LOG`-style filter. A bare level sets the global ceiling
    /// (`"info"`); `target=level` tokens quiet noisy dependencies by
    /// prefix, e.g. `"info,hiqlite=warn"` to silence the hiqlite raft
    /// WebSocket logs while keeping everything else at info.
    #[serde(default)]
    pub log_level: String,
    /// Directory the server writes structured log files into:
    /// `operations.log`, `security.log`, and `audit.log`. Empty
    /// disables file logging (logs go to stderr only). The audit log
    /// is bootstrapped on first unseal via the audit broker.
    #[serde(default)]
    pub log_dir: String,
    /// Also mirror operational + security logs to stderr. Defaults
    /// to true so foreground/dev runs stay readable; flip to false
    /// in production when you only want the on-disk files.
    #[serde(default = "default_bool_true", deserialize_with = "parse_bool_string")]
    #[default(true)]
    pub log_to_stderr: bool,
    /// Per-file rotation threshold in megabytes. When an individual
    /// log file (operations / security / audit) reaches this size it
    /// is renamed to `<name>.1`, prior `.1` shifts to `.2`, etc.,
    /// keeping `log_rotate_keep` historical copies. `0` → use the
    /// built-in default (100 MiB).
    #[serde(default)]
    pub log_rotate_size_mb: u64,
    /// Number of rotated copies to keep per stream. `0` → use the
    /// built-in default (5).
    #[serde(default)]
    pub log_rotate_keep: u32,
    #[serde(default)]
    pub pid_file: String,
    #[serde(default)]
    pub work_dir: String,
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub daemon: bool,
    #[serde(default)]
    pub daemon_user: String,
    #[serde(default)]
    pub daemon_group: String,
    #[serde(default = "default_collection_interval")]
    pub collection_interval: u64,
    #[serde(default = "default_hmac_level")]
    pub mount_entry_hmac_level: MountEntryHMACLevel,
    #[serde(default = "default_mounts_monitor_interval")]
    #[default(5)]
    pub mounts_monitor_interval: u64,
    #[serde(default = "default_barrier_type")]
    pub barrier_type: BarrierType,
    #[serde(default)]
    pub cache: CacheConfig,
    /// Hard cap on operations per batch request. `0` means use the
    /// built-in default (`http::batch::DEFAULT_BATCH_MAX_OPERATIONS`).
    /// Operators can raise or lower this to match their expected
    /// workload — a single batch occupies one request thread for the
    /// duration of all its operations.
    #[serde(default)]
    pub batch_max_operations: usize,
    /// Hard cap on batch request body size in bytes. Applied as the
    /// actix `PayloadConfig` limit on the batch route. `0` means use the
    /// built-in default of 32 MiB.
    #[serde(default)]
    pub batch_max_body_size: usize,
    /// Directory the process-plugin runtime stages plugin executables in
    /// before spawning them. The OS temp dir (`/tmp`) is frequently
    /// mounted `noexec` in hardened containers, which makes `execve` of a
    /// process-runtime plugin (e.g. `xca-import`) fail with `EACCES` —
    /// surfacing to the GUI as a generic invoke error. Point this at a
    /// writable, exec-allowed directory (e.g. `/var/lib/bvault/plugin-run`);
    /// the server creates it on first use. Empty uses the OS temp dir.
    /// Overridable at runtime via the `BV_PLUGIN_RUNTIME_DIR` environment
    /// variable, which takes precedence over this value.
    #[serde(default)]
    pub plugin_runtime_dir: String,
    /// Optional HSM seal block: `hsm "yubihsm2" { ... }` or `hsm "mock" { ... }`.
    /// The map is keyed by the block label (the backend type). At most one
    /// entry is permitted; more than one is a config error. Absent ⇒ the
    /// classic operator-driven Shamir unseal. See `features/hsm-support.md`.
    #[serde(default)]
    pub hsm: HashMap<String, crate::hsm::HsmConfigBlock>,
    /// Optional `dos { ... }` block seeding the IP-based DoS-protection
    /// thresholds on first unseal. Once an operator edits the thresholds
    /// through `v2/sys/dos/config`, the barrier-persisted value takes
    /// precedence on every subsequent unseal. Absent ⇒ built-in secure
    /// defaults ([`crate::dos::DosConfig::default`]).
    #[serde(default)]
    pub dos: Option<crate::dos::DosConfig>,
    /// Optional `metrics { ... }` block controlling who may scrape the
    /// Prometheus endpoint. Absent ⇒ every scrape must present a token
    /// with `read` on `sys/metrics`.
    #[serde(default)]
    pub metrics: MetricsAccessConfig,
    /// Optional `mcp { ... }` block (features/mcp-access.md). Absent ⇒
    /// `/v2/mcp` and `/v2/mcp/token` are compiled in but refuse every
    /// request (`enabled` defaults false).
    #[serde(default)]
    pub mcp: McpConfig,
    /// The file that declared the `mcp` block, set by the loader; `None` when
    /// no file did. Not part of the config language: it is what lets
    /// [`Config::merge`] tell "the second file leaves `mcp` out" (keep the
    /// first file's block) from "both files declare it" (refuse), which the
    /// block's `#[serde(default)]` alone cannot.
    #[serde(skip)]
    pub(crate) mcp_declared_in: Option<String>,
}

/// `mcp { ... }` — transport settings for the `/v2/mcp` endpoint. These
/// govern what the process binds and how it terminates TLS for that one
/// route, so they belong with the listener rather than in the barrier-
/// persisted runtime policy (`sys/mcp/config`, `crates/bv-kernel/.../mcp.rs`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct McpConfig {
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub enabled: bool,
    /// RFC 8707 resource identifier, e.g.
    /// `https://vault.example.com:8200/v2/mcp`. Required when `enabled`;
    /// advertised in the `/.well-known/oauth-protected-resource/v2/mcp`
    /// PRM document.
    #[serde(default)]
    pub canonical_url: String,
    /// Exact origins allowed to call `/v2/mcp` with a browser-style
    /// `Origin` header. Empty means only non-browser clients (no `Origin`
    /// header at all) are accepted.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Refuse a connection whose negotiated TLS key-exchange group is not
    /// the hybrid post-quantum group. The negotiated group is not yet carried
    /// out of the TLS layer (see `bv-server`'s `TlsClientInfo`), so this
    /// build cannot verify it: while the flag is set, `/v2/mcp` refuses to
    /// serve (503 `mcp_hybrid_kex_unverifiable`) instead of silently ignoring
    /// the requirement.
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub require_hybrid_kex: bool,
    /// Serve `/v2/mcp` over a `tls_disable = true` listener anyway, only
    /// when that listener's bound address is loopback.
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub allow_plaintext_loopback: bool,
    /// Body size cap in bytes. `0` means use the built-in default
    /// (256 KiB), which is also the ceiling: a larger value is clamped to it.
    #[serde(default)]
    pub max_request_bytes: usize,
    /// Per-call timeout in seconds. `0` means use the built-in default
    /// (30s). A call that exceeds it answers `mcp_tool_timeout`.
    #[serde(default)]
    pub tool_timeout_secs: u64,
    /// RFC 9728 PRM `authorization_servers`. Unused until Phase 7
    /// (external/enterprise authorization); declared now so the config
    /// shape does not change shape later.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// `mcp { brokered_sessions { … } }` (`features/mcp-brokered-sessions.md`
    /// §12). Absent ⇒ the block's defaults, which are **off**: an old config
    /// parses unchanged and opens no session.
    #[serde(default)]
    pub brokered_sessions: BrokeredSessionsConfig,
}

/// Protocols `mcp.brokered_sessions.protocols` may list.
pub const BROKERED_SESSION_PROTOCOLS: &[&str] = &["ssh", "web", "rdp"];

/// Ceilings of `mcp.brokered_sessions` (§11 "Limits"). A configured value
/// above one, or zero, refuses to load: a limit is a security bound, so it is
/// never clamped in silence.
pub const BROKERED_MAX_CONCURRENT_CEILING: u32 = 32;
pub const BROKERED_RATE_PER_BINDING_PER_MIN_CEILING: u32 = 60;
pub const BROKERED_CALL_TIMEOUT_SECS_CEILING: u64 = 120;
pub const BROKERED_MAX_OUTPUT_BYTES_CEILING: u64 = 262_144;

/// `mcp { brokered_sessions { … } }` — the server-side switch for agent
/// sessions to resources, and the limits that bound them. Every session call
/// needs `enabled`, its protocol in `protocols`, *and* the runtime switch
/// `sys/mcp/config.brokered_sessions_enabled`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BrokeredSessionsConfig {
    /// The static server switch. Off unless set.
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub enabled: bool,
    /// Subset of `["ssh", "web", "rdp"]`. Unlisted protocols are refused.
    #[serde(default)]
    pub protocols: Vec<String>,
    /// The destination allow-list. `None` (the key absent) means the built-in
    /// default, RFC 1918 plus `fc00::/7`; a list **replaces** that default
    /// and is not merged with it, and an empty list allows no destination.
    /// Loopback, link-local, multicast and the vault's own addresses are
    /// denied whatever is listed: an entry overlapping them is accepted with a
    /// startup warning and has no effect. A runtime value in
    /// `sys/mcp/config` replaces this one in turn.
    #[serde(default)]
    pub allowed_target_cidrs: Option<Vec<String>>,
    /// Concurrent sessions on this node. 1..=32.
    #[serde(default = "default_brokered_max_concurrent")]
    #[default(4)]
    pub max_concurrent: u32,
    /// Session calls per binding per minute, per node. 1..=60.
    #[serde(default = "default_brokered_rate_per_binding_per_min")]
    #[default(6)]
    pub rate_per_binding_per_min: u32,
    /// Call timeout for SSH and web sessions, seconds. 1..=120.
    #[serde(default = "default_brokered_call_timeout_secs")]
    #[default(20)]
    pub call_timeout_secs: u64,
    /// Call timeout for RDP sessions, seconds. 1..=120.
    #[serde(default = "default_brokered_rdp_call_timeout_secs")]
    #[default(45)]
    pub rdp_call_timeout_secs: u64,
    /// Output bytes returned to the model per call (SSH stdout+stderr
    /// jointly). 1..=262144.
    #[serde(default = "default_brokered_max_output_bytes")]
    #[default(65_536)]
    pub max_output_bytes: u64,
    #[serde(default)]
    pub ssh: BrokeredSshConfig,
}

/// `mcp { brokered_sessions { ssh { … } } }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BrokeredSshConfig {
    /// The vault's egress addresses, written into a brokered certificate's
    /// `source-address` critical option. Empty ⇒ the option is omitted.
    #[serde(default)]
    pub cert_source_addresses: Vec<String>,
}

fn default_brokered_max_concurrent() -> u32 {
    4
}

fn default_brokered_rate_per_binding_per_min() -> u32 {
    6
}

fn default_brokered_call_timeout_secs() -> u64 {
    20
}

fn default_brokered_rdp_call_timeout_secs() -> u64 {
    45
}

fn default_brokered_max_output_bytes() -> u64 {
    65_536
}

fn brokered_bound_err(key: &str, value: u64, ceiling: u64) -> RvError {
    RvError::ErrString(format!("mcp.brokered_sessions.{key} = {value} is out of range: it must be 1..={ceiling}"))
}

impl BrokeredSessionsConfig {
    /// Check every value; on success return the warnings the block earns
    /// (an `allowed_target_cidrs` entry overlapping an always-denied class).
    /// The first invalid value refuses the whole config, naming the key and,
    /// for a list, the entry.
    pub fn validate(&self) -> Result<Vec<String>, RvError> {
        for p in &self.protocols {
            if !BROKERED_SESSION_PROTOCOLS.contains(&p.as_str()) {
                return Err(RvError::ErrString(format!(
                    "mcp.brokered_sessions.protocols: {p:?} is not one of {BROKERED_SESSION_PROTOCOLS:?}"
                )));
            }
        }
        let bounded: [(&str, u64, u64); 5] = [
            ("max_concurrent", self.max_concurrent.into(), BROKERED_MAX_CONCURRENT_CEILING.into()),
            (
                "rate_per_binding_per_min",
                self.rate_per_binding_per_min.into(),
                BROKERED_RATE_PER_BINDING_PER_MIN_CEILING.into(),
            ),
            ("call_timeout_secs", self.call_timeout_secs, BROKERED_CALL_TIMEOUT_SECS_CEILING),
            ("rdp_call_timeout_secs", self.rdp_call_timeout_secs, BROKERED_CALL_TIMEOUT_SECS_CEILING),
            ("max_output_bytes", self.max_output_bytes, BROKERED_MAX_OUTPUT_BYTES_CEILING),
        ];
        for (key, value, ceiling) in bounded {
            if value == 0 || value > ceiling {
                return Err(brokered_bound_err(key, value, ceiling));
            }
        }
        for entry in &self.ssh.cert_source_addresses {
            if !bv_utils::destination_policy::is_address_or_cidr(entry) {
                return Err(RvError::ErrString(format!(
                    "mcp.brokered_sessions.ssh.cert_source_addresses: {entry:?} is not an address or CIDR"
                )));
            }
        }
        let warnings = match &self.allowed_target_cidrs {
            Some(entries) => {
                bv_utils::destination_policy::parse_target_cidrs(entries)
                    .map_err(|e| RvError::ErrString(format!("mcp.brokered_sessions.{e}")))?
                    .warnings
            }
            None => Vec::new(),
        };
        Ok(warnings.into_iter().map(|w| format!("mcp.brokered_sessions.{w}")).collect())
    }

    /// The warnings to log once the logger is up. Empty for an invalid block,
    /// which `load_config` has already refused.
    pub fn startup_warnings(&self) -> Vec<String> {
        self.validate().unwrap_or_default()
    }
}

/// `metrics { ... }` — access control for the `/metrics` scrape endpoint.
///
/// The endpoint is token-authorized (ACL path `sys/metrics`) for every
/// caller that is not covered by one of the two IP allowances below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MetricsAccessConfig {
    /// Serve `/metrics` without a token to loopback and to the IPs of
    /// the configured cluster `nodes` — the same predicate that gates
    /// `sys/cluster-status`, judged on the socket peer so no header can
    /// forge it. Defaults to `true`: it is what lets a node-local
    /// scrape, and a scrape of a *sealed* node (no barrier ⇒ no token
    /// validation), work without credential plumbing. Set `false` for
    /// strict token-only scraping.
    #[serde(default = "default_bool_true", deserialize_with = "parse_bool_string")]
    #[default(true)]
    pub allow_cluster_local: bool,
    /// Additional CIDRs whose requests may scrape `/metrics` without a
    /// token, e.g. `["10.20.0.0/16"]` for a monitoring subnet. Empty by
    /// default. Matched against the trusted-proxy-aware client IP
    /// (`BASTIONVAULT_TRUSTED_PROXIES`), so an untrusted
    /// `X-Forwarded-For` cannot forge an allowlisted source.
    /// Unparseable entries are logged and dropped — never treated as a
    /// wildcard.
    #[serde(default)]
    pub allow_unauthenticated_cidrs: Vec<String>,
}

/// Re-exported from `bv-kernel-api`, where it moved in Phase 3.
///
/// It is an operator setting parsed from this file's config, but the mount
/// table is what enforces it and [`VaultCtx::mount_entry_hmac_level`] is what
/// hands it out — both of which sit below the CLI in the crate graph.
///
/// [`VaultCtx::mount_entry_hmac_level`]: crate::kernel_api::VaultCtx::mount_entry_hmac_level
pub use bv_kernel_api::MountEntryHMACLevel;

fn default_hmac_level() -> MountEntryHMACLevel {
    MountEntryHMACLevel::None
}

fn default_collection_interval() -> u64 {
    15
}

fn default_mounts_monitor_interval() -> u64 {
    5
}

fn default_barrier_type() -> BarrierType {
    BarrierType::Chacha20Poly1305
}

/// A struct that contains several configurable options for networking stuffs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    #[serde(default)]
    pub ltype: String,
    pub address: String,
    #[serde(default = "default_bool_true", deserialize_with = "parse_bool_string")]
    pub tls_disable: bool,
    #[serde(default)]
    pub tls_cert_file: String,
    #[serde(default)]
    pub tls_key_file: String,
    #[serde(default)]
    pub tls_client_ca_file: String,
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub tls_disable_client_certs: bool,
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub tls_require_and_verify_client_cert: bool,
    #[serde(
        default = "default_tls_min_version",
        serialize_with = "serialize_tls_version",
        deserialize_with = "deserialize_tls_version"
    )]
    pub tls_min_version: TlsVersion,
    #[serde(
        default = "default_tls_max_version",
        serialize_with = "serialize_tls_version",
        deserialize_with = "deserialize_tls_version"
    )]
    pub tls_max_version: TlsVersion,
    #[serde(default = "default_tls_cipher_suites")]
    pub tls_cipher_suites: String,
    /// Optional path where the server publishes its serving certificate (PEM)
    /// on startup, so local CLI invocations can pick it up as a trust anchor
    /// without `--tls-skip-verify` or an explicit `--ca-cert` on every call.
    /// Empty disables publishing. The CLI reads `/etc/bvault/ca.pem` and
    /// `~/.bvault/ca.pem` by default — point this at one of those (or a path
    /// you bind-mount out of a container) to opt in.
    #[serde(default)]
    pub tls_publish_ca_path: String,
}

/// A struct that contains several configurable options for storage stuffs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Storage {
    #[serde(default)]
    pub stype: String,
    #[serde(flatten)]
    pub config: HashMap<String, Value>,
}

static STORAGE_TYPE_KEYWORDS: &[&str] = &["file", "mysql", "hiqlite"];

fn default_bool_true() -> bool {
    true
}

fn parse_bool_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Value = Deserialize::deserialize(deserializer)?;
    match value {
        Value::Bool(b) => Ok(b),
        Value::String(s) => match s.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(serde::de::Error::custom("Invalid value for bool")),
        },
        _ => Err(serde::de::Error::custom("Invalid value for bool")),
    }
}

fn default_tls_min_version() -> TlsVersion {
    TlsVersion::Tls12
}

fn default_tls_max_version() -> TlsVersion {
    TlsVersion::Tls13
}

fn default_tls_cipher_suites() -> String {
    "HIGH:!PSK:!SRP:!3DES".to_string()
}

fn serialize_tls_version<S>(version: &TlsVersion, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match *version {
        TlsVersion::Tls12 => serializer.serialize_str("tls12"),
        TlsVersion::Tls13 => serializer.serialize_str("tls13"),
    }
}

fn deserialize_tls_version<'de, D>(deserializer: D) -> Result<TlsVersion, D::Error>
where
    D: Deserializer<'de>,
{
    struct TlsVersionVisitor;

    impl Visitor<'_> for TlsVersionVisitor {
        type Value = TlsVersion;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("\"tls12\" or \"tls13\"")
        }

        fn visit_str<E>(self, value: &str) -> Result<TlsVersion, E>
        where
            E: de::Error,
        {
            match value {
                "tls12" => Ok(TlsVersion::Tls12),
                "tls13" => Ok(TlsVersion::Tls13),
                "tls10" | "tls11" => Err(E::custom(format!("TLS version {value} is not supported; use tls12 or tls13"))),
                _ => Err(E::custom(format!("unexpected TLS version: {value}"))),
            }
        }
    }

    deserializer.deserialize_str(TlsVersionVisitor)
}

fn validate_storage<'de, D>(deserializer: D) -> Result<HashMap<String, Storage>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let storage: HashMap<String, Storage> = Deserialize::deserialize(deserializer)?;

    for key in storage.keys() {
        if !STORAGE_TYPE_KEYWORDS.contains(&key.as_str()) {
            return Err(serde::de::Error::custom("Invalid storage key"));
        }
    }

    Ok(storage)
}

fn validate_listener<'de, D>(deserializer: D) -> Result<HashMap<String, Listener>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let listeners: HashMap<String, Listener> = Deserialize::deserialize(deserializer)?;

    for (key, listener) in &listeners {
        if key != "tcp" {
            return Err(serde::de::Error::custom("Invalid listener key"));
        }

        if !listener.tls_disable && (listener.tls_cert_file.is_empty() || listener.tls_key_file.is_empty()) {
            return Err(serde::de::Error::custom(
                "when tls_disable is false, tls_cert_file and tls_key_file must be configured",
            ));
        }

        if !listener.tls_disable && listener.tls_require_and_verify_client_cert && listener.tls_disable_client_certs {
            return Err(serde::de::Error::custom(
                "'tls_disable_client_certs' and 'tls_require_and_verify_client_cert' are mutually exclusive",
            ));
        }
    }

    Ok(listeners)
}

impl Config {
    /// Resolve the optional `hsm "<label>" { ... }` block into a validated,
    /// env-expanded seal config. `Ok(None)` when no HSM seal is configured;
    /// an error when more than one block is present or the block is invalid.
    pub fn resolve_hsm(&self) -> Result<Option<crate::hsm::ResolvedHsmConfig>, RvError> {
        if self.hsm.is_empty() {
            return Ok(None);
        }
        if self.hsm.len() > 1 {
            return Err(RvError::ErrHsmConfigInvalid(
                "at most one `hsm` seal block may be configured".into(),
            ));
        }
        let (label, block) = self.hsm.iter().next().expect("len checked above");
        Ok(Some(crate::hsm::resolve_config(label, block)?))
    }

    /// Fold `other` (a later file of a config directory) into `self`.
    ///
    /// Scalars follow "a set value in the later file wins"; `listener`,
    /// `storage` and `hsm` are unioned by label; `dos` is replaced whole.
    ///
    /// The `mcp` block is security policy (TLS and origin requirements, the
    /// brokered-session switch and its destination allow-list), so it is
    /// declared in **exactly one** file: the file that declares it supplies
    /// the whole block, and a second file declaring it too is refused with an
    /// error naming both files. A field-by-field merge was rejected: a later
    /// file could not switch a boolean back off (an absent key and `false`
    /// read the same), and an allow-list would have to be either unioned
    /// (widened) or replaced depending on file order.
    pub fn merge(&mut self, other: Config) -> Result<(), RvError> {
        match (&self.mcp_declared_in, other.mcp_declared_in) {
            (Some(first), Some(second)) => {
                return Err(RvError::ErrString(format!(
                    "the `mcp` block is declared in both {first} and {second}; declare it in exactly one file of the config directory"
                )));
            }
            (None, Some(second)) => {
                self.mcp = other.mcp;
                self.mcp_declared_in = Some(second);
            }
            (_, None) => {}
        }

        self.listener.extend(other.listener);
        self.storage.extend(other.storage);
        self.hsm.extend(other.hsm);
        if !other.api_addr.is_empty() {
            self.api_addr = other.api_addr;
        }

        if !other.log_format.is_empty() {
            self.log_format = other.log_format;
        }

        if !other.log_level.is_empty() {
            self.log_level = other.log_level;
        }

        if !other.pid_file.is_empty() {
            self.pid_file = other.pid_file;
        }

        if other.mount_entry_hmac_level != MountEntryHMACLevel::None {
            self.mount_entry_hmac_level = other.mount_entry_hmac_level;
        }

        if other.barrier_type != BarrierType::Chacha20Poly1305 {
            self.barrier_type = other.barrier_type;
        }

        if !other.plugin_runtime_dir.is_empty() {
            self.plugin_runtime_dir = other.plugin_runtime_dir;
        }

        if other.dos.is_some() {
            self.dos = other.dos;
        }

        self.cache.merge(other.cache);
        Ok(())
    }
}

pub fn load_config(path: &str) -> Result<Config, RvError> {
    let f = Path::new(path);
    if f.is_dir() {
        load_config_dir(path)
    } else if f.is_file() {
        load_config_file(path)
    } else {
        Err(RvError::ErrConfigPathInvalid)
    }
}

fn load_config_dir(dir: &str) -> Result<Config, RvError> {
    log::debug!("load_config_dir: {dir}");
    let mut paths: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Some(ext) = path.extension() {
                if ext == "hcl" || ext == "json" {
                    let filename = path.to_string_lossy().into_owned();
                    paths.push(filename);
                }
            }
        }
    }

    // Merge in file-name order, so "the later file wins" names the same file
    // on every filesystem: `read_dir` order is unspecified.
    paths.sort();

    let mut result: Option<Config> = None;

    for path in paths {
        log::debug!("load_config_dir path: {path}");
        let config = load_config_file(&path)?;
        match result.as_mut() {
            None => result = Some(config),
            Some(merged) => merged.merge(config)?,
        }
    }

    result.ok_or(RvError::ErrConfigLoadFailed)
}

fn load_config_file(path: &str) -> Result<Config, RvError> {
    log::debug!("load_config_file: {path}");
    let text = fs::read_to_string(path)?;

    // Parsed a second time, untyped, only to learn whether the file declares
    // an `mcp` block at all (see `Config::mcp_declared_in`).
    let (mut config, declares_mcp): (Config, bool) = if path.ends_with(".hcl") {
        let body = hcl::parse(&text)?;
        let declares = body.attributes().any(|a| a.key() == "mcp") || body.blocks().any(|b| b.identifier() == "mcp");
        (hcl::from_str(&text)?, declares)
    } else if path.ends_with(".json") {
        let value: Value = serde_json::from_str(&text)?;
        (serde_json::from_str(&text)?, value.get("mcp").is_some())
    } else {
        return Err(RvError::ErrConfigPathInvalid);
    };
    if declares_mcp {
        config.mcp_declared_in = Some(path.to_string());
    }
    set_config_type_field(&mut config)?;
    check_config(&config)?;
    Ok(config)
}

fn set_config_type_field(config: &mut Config) -> Result<(), RvError> {
    config.storage.iter_mut().for_each(|(key, value)| value.stype.clone_from(key));
    config.listener.iter_mut().for_each(|(key, value)| value.ltype.clone_from(key));
    Ok(())
}

fn check_config(config: &Config) -> Result<(), RvError> {
    if config.storage.len() != 1 {
        return Err(RvError::ErrConfigStorageNotFound);
    }

    if config.listener.len() != 1 {
        return Err(RvError::ErrConfigListenerNotFound);
    }

    // Refuses an invalid `mcp.brokered_sessions` block at load, naming the
    // key and entry; its warnings are logged at startup, once the logger is
    // up (`BrokeredSessionsConfig::startup_warnings`).
    config.mcp.brokered_sessions.validate()?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::{env, fs, io::prelude::*};

    use super::*;
    // `TEST_DIR` originates in `bv-storage`'s fixtures; the root crate's
    // `test_utils` only ever re-exported it, and that module is above this
    // crate now. Named at its source instead.
    use bv_storage::test_support::TEST_DIR;

    fn write_file(path: &str, config: &str) -> Result<(), RvError> {
        let mut file = fs::File::create(path)?;

        file.write_all(config.as_bytes())?;

        file.flush()?;

        Ok(())
    }

    #[test]
    fn test_load_config() {
        let dir = env::temp_dir().join(TEST_DIR).join("test_load_config");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let file_path = dir.join("config.hcl");
        let path = file_path.to_str().unwrap_or("config.hcl");

        let hcl_config_str = r#"
            storage "file" {
              path    = "./vault/data"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
            }

            api_addr = "http://127.0.0.1:8200"
            log_level = "debug"
            log_format = "{date} {req.path}"
            pid_file = "/tmp/bastion_vault.pid"
        "#;

        assert!(write_file(path, hcl_config_str).is_ok());

        let config = load_config(path);
        assert!(config.is_ok());
        let hcl_config = config.unwrap();
        println!("hcl config: {:?}", hcl_config);

        let json_config_str = r#"{
            "storage": {
                "file": {
                    "path": "./vault/data"
                }
            },
            "listener": {
                "tcp": {
                    "address": "127.0.0.1:8200"
                }
            },
            "api_addr": "http://127.0.0.1:8200",
            "log_level": "debug",
            "log_format": "{date} {req.path}",
            "pid_file": "/tmp/bastion_vault.pid"
        }"#;

        let file_path = dir.join("config.json");
        let path = file_path.to_str().unwrap_or("config.json");
        assert!(write_file(path, json_config_str).is_ok());

        let config = load_config(path);
        assert!(config.is_ok());
        let json_config = config.unwrap();
        println!("json config: {:?}", json_config);

        let hcl_config_value = serde_json::to_value(&hcl_config);
        assert!(hcl_config_value.is_ok());
        let hcl_config_value: Value = hcl_config_value.unwrap();

        let json_config_value = serde_json::to_value(&json_config);
        assert!(json_config_value.is_ok());
        let json_config_value: Value = json_config_value.unwrap();
        assert_eq!(hcl_config_value, json_config_value);

        assert_eq!(json_config.listener.len(), 1);
        assert_eq!(json_config.storage.len(), 1);
        assert_eq!(json_config.api_addr.as_str(), "http://127.0.0.1:8200");
        assert_eq!(json_config.log_format.as_str(), "{date} {req.path}");
        assert_eq!(json_config.log_level.as_str(), "debug");
        assert_eq!(json_config.pid_file.as_str(), "/tmp/bastion_vault.pid");
        assert_eq!(json_config.work_dir.as_str(), "");
        assert!(!json_config.daemon);
        assert_eq!(json_config.daemon_user.as_str(), "");
        assert_eq!(json_config.daemon_group.as_str(), "");
        assert_eq!(json_config.mount_entry_hmac_level, MountEntryHMACLevel::None);
        assert_eq!(json_config.barrier_type, BarrierType::Chacha20Poly1305);

        let (_, listener) = json_config.listener.iter().next().unwrap();
        assert!(listener.tls_disable);
        assert_eq!(listener.ltype.as_str(), "tcp");
        assert_eq!(listener.address.as_str(), "127.0.0.1:8200");

        let (_, storage) = json_config.storage.iter().next().unwrap();
        assert_eq!(storage.stype.as_str(), "file");
        assert_eq!(storage.config.len(), 1);
        let (_, path) = storage.config.iter().next().unwrap();
        assert_eq!(path.as_str(), Some("./vault/data"));
    }

    #[test]
    fn test_load_config_dir() {
        let dir = env::temp_dir().join(TEST_DIR).join("test_load_config_dir");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let file_path = dir.join("config1.hcl");
        let path = file_path.to_str().unwrap_or("config1.hcl");

        let hcl_config_str = r#"
            storage "file" {
              path    = "./vault/data"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
              tls_disable = "true"
            }

            api_addr = "http://127.0.0.1:8200"
            log_level = "debug"
            log_format = "{date} {req.path}"
            pid_file = "/tmp/bastion_vault.pid"
            mount_entry_hmac_level = "compat"
        "#;

        assert!(write_file(path, hcl_config_str).is_ok());

        let file_path = dir.join("config2.hcl");
        let path = file_path.to_str().unwrap_or("config2.hcl");

        let hcl_config_str = r#"
            storage "file" {
              address    = "127.0.0.1:8899"
            }

            listener "tcp" {
              address     = "127.0.0.1:8800"
              tls_disable = true
            }

            log_level = "info"
            barrier_type = "chacha20-poly1305"
        "#;

        assert!(write_file(path, hcl_config_str).is_ok());

        let config = load_config(dir.to_str().unwrap());
        println!("config: {:?}", config);
        assert!(config.is_ok());
        let hcl_config = config.unwrap();
        println!("hcl config: {:?}", hcl_config);
        assert_eq!(hcl_config.mount_entry_hmac_level, MountEntryHMACLevel::Compat);
        assert_eq!(hcl_config.barrier_type, BarrierType::Chacha20Poly1305);

        let (_, listener) = hcl_config.listener.iter().next().unwrap();
        assert!(listener.tls_disable);
    }

    #[test]
    fn test_load_config_tls() {
        let dir = env::temp_dir().join(TEST_DIR).join("test_load_config_tls");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let file_path = dir.join("config.hcl");
        let path = file_path.to_str().unwrap_or("config.hcl");

        let hcl_config_str = r#"
            storage "file" {
              path    = "./vault/data"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
              tls_disable = false
              tls_cert_file = "./cert/test.crt"
              tls_key_file = "./cert/test.key"
              tls_client_ca_file = "./cert/ca.pem"
              tls_min_version = "tls12"
              tls_max_version = "tls13"
            }

            api_addr = "http://127.0.0.1:8200"
            log_level = "debug"
            log_format = "{date} {req.path}"
            pid_file = "/tmp/bastion_vault.pid"
            mount_entry_hmac_level = "high"
        "#;

        assert!(write_file(path, hcl_config_str).is_ok());

        let config = load_config(path);
        assert!(config.is_ok());
        let hcl_config = config.unwrap();
        println!("hcl config: {:?}", hcl_config);

        assert_eq!(hcl_config.listener.len(), 1);
        assert_eq!(hcl_config.storage.len(), 1);
        assert_eq!(hcl_config.api_addr.as_str(), "http://127.0.0.1:8200");
        assert_eq!(hcl_config.log_format.as_str(), "{date} {req.path}");
        assert_eq!(hcl_config.log_level.as_str(), "debug");
        assert_eq!(hcl_config.pid_file.as_str(), "/tmp/bastion_vault.pid");
        assert_eq!(hcl_config.work_dir.as_str(), "");
        assert!(!hcl_config.daemon);
        assert_eq!(hcl_config.daemon_user.as_str(), "");
        assert_eq!(hcl_config.daemon_group.as_str(), "");
        assert_eq!(hcl_config.mount_entry_hmac_level, MountEntryHMACLevel::High);

        let (_, listener) = hcl_config.listener.iter().next().unwrap();
        assert_eq!(listener.ltype.as_str(), "tcp");
        assert_eq!(listener.address.as_str(), "127.0.0.1:8200");
        assert!(!listener.tls_disable);
        assert_eq!(listener.tls_cert_file.as_str(), "./cert/test.crt");
        assert_eq!(listener.tls_key_file.as_str(), "./cert/test.key");
        assert_eq!(listener.tls_client_ca_file.as_str(), "./cert/ca.pem");
        assert!(!listener.tls_disable_client_certs);
        assert!(!listener.tls_require_and_verify_client_cert);
        assert_eq!(listener.tls_min_version, TlsVersion::Tls12);
        assert_eq!(listener.tls_max_version, TlsVersion::Tls13);

        let (_, storage) = hcl_config.storage.iter().next().unwrap();
        assert_eq!(storage.stype.as_str(), "file");
        assert_eq!(storage.config.len(), 1);
        let (_, path) = storage.config.iter().next().unwrap();
        assert_eq!(path.as_str(), Some("./vault/data"));
    }

    #[test]
    fn test_load_config_with_chacha_barrier_type() {
        let dir = env::temp_dir().join(TEST_DIR).join("test_load_config_with_chacha_barrier_type");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let file_path = dir.join("config.json");
        let path = file_path.to_str().unwrap_or("config.json");

        let json_config_str = r#"{
            "storage": {
                "file": {
                    "path": "./vault/data"
                }
            },
            "listener": {
                "tcp": {
                    "address": "127.0.0.1:8200"
                }
            },
            "barrier_type": "chacha20-poly1305"
        }"#;

        assert!(write_file(path, json_config_str).is_ok());

        let config = load_config(path);
        assert!(config.is_ok());
        let json_config = config.unwrap();
        assert_eq!(json_config.barrier_type, BarrierType::Chacha20Poly1305);
    }

    /// A config with no `metrics` block keeps the shipped default
    /// (cluster-local waived, nothing else), and an explicit block is
    /// parsed — including turning the cluster-local waiver off, which is
    /// the strict token-only posture.
    #[test]
    fn test_load_config_metrics_block() {
        let dir = env::temp_dir().join(TEST_DIR).join("test_load_config_metrics");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let base = r#"
            storage "file" {
              path    = "./vault/data"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
            }
        "#;

        let file_path = dir.join("default.hcl");
        let path = file_path.to_str().unwrap();
        assert!(write_file(path, base).is_ok());
        let config = load_config(path).unwrap();
        assert!(config.metrics.allow_cluster_local);
        assert!(config.metrics.allow_unauthenticated_cidrs.is_empty());

        let with_block = format!(
            r#"{base}
            metrics {{
              allow_cluster_local = false
              allow_unauthenticated_cidrs = ["10.20.0.0/16", "::1/128"]
            }}
        "#
        );
        let file_path = dir.join("explicit.hcl");
        let path = file_path.to_str().unwrap();
        assert!(write_file(path, &with_block).is_ok());
        let config = load_config(path).unwrap();
        assert!(!config.metrics.allow_cluster_local);
        assert_eq!(
            config.metrics.allow_unauthenticated_cidrs,
            vec!["10.20.0.0/16".to_string(), "::1/128".to_string()]
        );
    }

    const BROKERED_BASE: &str = r#"
        storage "file" {
          path    = "./vault/data"
        }

        listener "tcp" {
          address     = "127.0.0.1:8200"
        }
    "#;

    fn load_str(dir_name: &str, file: &str, body: &str) -> Result<Config, RvError> {
        let dir = env::temp_dir().join(TEST_DIR).join(dir_name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(file);
        write_file(path.to_str().unwrap(), body).unwrap();
        load_config(path.to_str().unwrap())
    }

    /// An old config — no `mcp` block, or one without `brokered_sessions` —
    /// parses unchanged, with sessions off and the spec's defaults.
    #[test]
    fn test_old_config_parses_with_brokered_sessions_off() {
        let config = load_str("bs_old_none", "c.hcl", BROKERED_BASE).unwrap();
        let bs = &config.mcp.brokered_sessions;
        assert_eq!(bs, &BrokeredSessionsConfig::default());
        assert!(!bs.enabled);
        assert!(bs.protocols.is_empty());
        assert_eq!(bs.allowed_target_cidrs, None, "absent means the built-in default list");
        assert_eq!(
            (
                bs.max_concurrent,
                bs.rate_per_binding_per_min,
                bs.call_timeout_secs,
                bs.rdp_call_timeout_secs,
                bs.max_output_bytes
            ),
            (4, 6, 20, 45, 65_536)
        );
        assert!(bs.ssh.cert_source_addresses.is_empty());
        assert!(bs.startup_warnings().is_empty());

        let with_mcp =
            format!("{BROKERED_BASE}\nmcp {{\n  enabled = true\n  canonical_url = \"https://v/v2/mcp\"\n}}\n");
        let config = load_str("bs_old_mcp", "c.hcl", &with_mcp).unwrap();
        assert!(config.mcp.enabled);
        assert_eq!(config.mcp.brokered_sessions, BrokeredSessionsConfig::default());

        // The JSON form, too.
        let json = r#"{"storage":{"file":{"path":"./d"}},"listener":{"tcp":{"address":"127.0.0.1:8200"}},"mcp":{"enabled":true}}"#;
        let config = load_str("bs_old_json", "c.json", json).unwrap();
        assert_eq!(config.mcp.brokered_sessions, BrokeredSessionsConfig::default());
    }

    #[test]
    fn test_brokered_sessions_block_parses_and_replaces_the_default_list() {
        let body = format!(
            r#"{BROKERED_BASE}
            mcp {{
              enabled = true
              brokered_sessions {{
                enabled                  = true
                protocols                = ["ssh"]
                allowed_target_cidrs     = ["10.20.0.0/16", "2001:db8::/32"]
                max_concurrent           = 8
                rate_per_binding_per_min = 10
                call_timeout_secs        = 30
                rdp_call_timeout_secs    = 60
                max_output_bytes         = 131072
                ssh {{
                  cert_source_addresses = ["203.0.113.7", "203.0.113.0/24"]
                }}
              }}
            }}
        "#
        );
        let config = load_str("bs_full", "c.hcl", &body).unwrap();
        let bs = &config.mcp.brokered_sessions;
        assert!(bs.enabled);
        assert_eq!(bs.protocols, vec!["ssh".to_string()]);
        assert_eq!(
            bs.allowed_target_cidrs,
            Some(vec!["10.20.0.0/16".to_string(), "2001:db8::/32".to_string()]),
            "a configured list replaces the default; it is not merged with it"
        );
        assert_eq!(
            (
                bs.max_concurrent,
                bs.rate_per_binding_per_min,
                bs.call_timeout_secs,
                bs.rdp_call_timeout_secs,
                bs.max_output_bytes
            ),
            (8, 10, 30, 60, 131_072)
        );
        assert_eq!(bs.ssh.cert_source_addresses.len(), 2);

        // An empty list is a list: no destination at all.
        let empty = format!("{BROKERED_BASE}\nmcp {{\n brokered_sessions {{\n allowed_target_cidrs = []\n }}\n}}\n");
        let config = load_str("bs_empty_list", "c.hcl", &empty).unwrap();
        assert_eq!(config.mcp.brokered_sessions.allowed_target_cidrs, Some(vec![]));
    }

    fn brokered_block(inner: &str) -> String {
        format!("{BROKERED_BASE}\nmcp {{\n  brokered_sessions {{\n    {inner}\n  }}\n}}\n")
    }

    #[test]
    fn test_brokered_sessions_invalid_values_refuse_to_load() {
        for (name, inner, needle) in [
            ("bs_bad_cidr", r#"allowed_target_cidrs = ["10.0.0.0/8", "10.0.0.300/8"]"#, "\"10.0.0.300/8\""),
            ("bs_bare_ip", r#"allowed_target_cidrs = ["10.0.0.5"]"#, "\"10.0.0.5\""),
            ("bs_host_bits", r#"allowed_target_cidrs = ["10.0.0.1/8"]"#, "host bits"),
            ("bs_protocol", r#"protocols = ["ssh", "telnet"]"#, "telnet"),
            ("bs_conc_zero", "max_concurrent = 0", "max_concurrent"),
            ("bs_conc_high", "max_concurrent = 33", "max_concurrent"),
            ("bs_rate_high", "rate_per_binding_per_min = 61", "rate_per_binding_per_min"),
            ("bs_timeout_high", "call_timeout_secs = 121", "call_timeout_secs"),
            ("bs_rdp_timeout_high", "rdp_call_timeout_secs = 121", "rdp_call_timeout_secs"),
            ("bs_output_high", "max_output_bytes = 262145", "max_output_bytes"),
            ("bs_cert_src", "ssh {\n cert_source_addresses = [\"egress.example\"]\n }", "cert_source_addresses"),
        ] {
            let err = load_str(name, "c.hcl", &brokered_block(inner)).unwrap_err().to_string();
            assert!(err.contains(needle), "{name}: {err}");
        }
        // The ceilings themselves are accepted.
        let at_ceiling = brokered_block(
            "max_concurrent = 32\n rate_per_binding_per_min = 60\n call_timeout_secs = 120\n rdp_call_timeout_secs = 120\n max_output_bytes = 262144",
        );
        assert!(load_str("bs_ceiling", "c.hcl", &at_ceiling).is_ok());
    }

    /// An entry overlapping an always-denied class is accepted, with a
    /// startup warning naming it.
    #[test]
    fn test_brokered_sessions_always_denied_overlap_warns() {
        let body = brokered_block(r#"allowed_target_cidrs = ["10.0.0.0/8", "169.254.169.254/32", "127.0.0.0/8"]"#);
        let config = load_str("bs_overlap", "c.hcl", &body).unwrap();
        let warnings = config.mcp.brokered_sessions.startup_warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("169.254.169.254/32") && warnings[0].contains("link-local"), "{warnings:?}");
        assert!(warnings[1].contains("127.0.0.0/8") && warnings[1].contains("loopback"), "{warnings:?}");
        assert!(warnings.iter().all(|w| w.starts_with("mcp.brokered_sessions.allowed_target_cidrs")));
    }

    /// Writes `files` (name, body) into a fresh directory and loads it as a
    /// config directory.
    fn load_dir(dir_name: &str, files: &[(&str, &str)]) -> (Result<Config, RvError>, std::path::PathBuf) {
        let dir = env::temp_dir().join(TEST_DIR).join(dir_name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            write_file(dir.join(name).to_str().unwrap(), body).unwrap();
        }
        (load_config(dir.to_str().unwrap()), dir)
    }

    const NARROW_MCP: &str = r#"
        mcp {
          enabled       = true
          canonical_url = "https://v/v2/mcp"
          brokered_sessions {
            enabled              = true
            protocols            = ["ssh"]
            allowed_target_cidrs = ["10.20.0.0/16"]
          }
        }
    "#;

    /// Regression: `Config::merge` used to ignore `mcp`, so a directory
    /// config whose `mcp` block sat in any file but the first loaded one
    /// dropped it — brokered sessions and a narrower destination list
    /// included — without a word. The block now comes from whichever file
    /// declares it, in either position.
    #[test]
    fn test_config_dir_keeps_the_mcp_block_from_the_file_that_declares_it() {
        let with_mcp = format!("{BROKERED_BASE}{NARROW_MCP}");
        // `b-mcp.hcl` merges after `a-base.hcl` (file-name order).
        for (dir_name, files) in [
            ("merge_mcp_second", [("a-base.hcl", BROKERED_BASE), ("b-mcp.hcl", with_mcp.as_str())]),
            ("merge_mcp_first", [("a-mcp.hcl", with_mcp.as_str()), ("b-base.hcl", BROKERED_BASE)]),
        ] {
            let (config, _) = load_dir(dir_name, &files);
            let config = config.unwrap_or_else(|e| panic!("{dir_name}: {e}"));
            assert!(config.mcp.enabled, "{dir_name}");
            let bs = &config.mcp.brokered_sessions;
            assert!(bs.enabled, "{dir_name}");
            assert_eq!(bs.protocols, vec!["ssh".to_string()], "{dir_name}");
            assert_eq!(bs.allowed_target_cidrs, Some(vec!["10.20.0.0/16".to_string()]), "{dir_name}");
        }

        // JSON files take part the same way.
        let json_mcp = r#"{"storage":{"file":{"path":"./d"}},"listener":{"tcp":{"address":"127.0.0.1:8200"}},
            "mcp":{"brokered_sessions":{"allowed_target_cidrs":["192.168.7.0/24"]}}}"#;
        let (config, _) = load_dir("merge_mcp_json", &[("a-base.hcl", BROKERED_BASE), ("b.json", json_mcp)]);
        assert_eq!(
            config.unwrap().mcp.brokered_sessions.allowed_target_cidrs,
            Some(vec!["192.168.7.0/24".to_string()])
        );
    }

    /// Two files declaring `mcp` are refused, naming both, whatever the
    /// blocks hold — even an empty block, which could otherwise not be told
    /// from an absent one. The error is the same on every filesystem.
    #[test]
    fn test_config_dir_refuses_mcp_declared_twice() {
        let narrow = format!("{BROKERED_BASE}{NARROW_MCP}");
        let other = format!("{BROKERED_BASE}\nmcp {{\n  enabled = false\n}}\n");
        let empty = format!("{BROKERED_BASE}\nmcp {{}}\n");
        let json_mcp = r#"{"storage":{"file":{"path":"./d"}},"listener":{"tcp":{"address":"127.0.0.1:8200"}},"mcp":{}}"#;
        for (dir_name, files) in [
            ("merge_mcp_twice", vec![("a.hcl", narrow.as_str()), ("b.hcl", other.as_str())]),
            ("merge_mcp_twice_same", vec![("a.hcl", narrow.as_str()), ("b.hcl", narrow.as_str())]),
            ("merge_mcp_twice_empty", vec![("a.hcl", narrow.as_str()), ("b.hcl", empty.as_str())]),
            ("merge_mcp_twice_json", vec![("a.hcl", narrow.as_str()), ("b.json", json_mcp)]),
            ("merge_mcp_twice_mid", vec![("a.hcl", narrow.as_str()), ("b.hcl", BROKERED_BASE), ("c.hcl", other.as_str())]),
        ] {
            let (config, dir) = load_dir(dir_name, &files);
            let err = config.expect_err(dir_name).to_string();
            let first = dir.join(files[0].0).to_string_lossy().into_owned();
            let second = dir.join(files[files.len() - 1].0).to_string_lossy().into_owned();
            assert!(err.contains("`mcp` block is declared in both"), "{dir_name}: {err}");
            assert!(
                err.find(&first).is_some_and(|i| err.find(&second).is_some_and(|j| i < j)),
                "{dir_name}: names both files in order: {err}"
            );
        }
    }

    /// A single-file config records which file declared `mcp` and merges
    /// nothing; a directory where no file declares it gets the defaults.
    #[test]
    fn test_config_mcp_declaration_is_tracked_per_file() {
        let config = load_str("merge_single", "c.hcl", &format!("{BROKERED_BASE}{NARROW_MCP}")).unwrap();
        assert!(config.mcp_declared_in.as_deref().is_some_and(|p| p.ends_with("c.hcl")));
        assert!(load_str("merge_single_none", "c.hcl", BROKERED_BASE).unwrap().mcp_declared_in.is_none());

        let (config, _) = load_dir("merge_none", &[("a.hcl", BROKERED_BASE), ("b.hcl", BROKERED_BASE)]);
        let config = config.unwrap();
        assert_eq!(config.mcp, McpConfig::default());
        assert!(config.mcp_declared_in.is_none());
    }

    #[test]
    fn test_load_config_hiqlite() {
        let dir = env::temp_dir().join(TEST_DIR).join("test_load_config_hiqlite");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let file_path = dir.join("config.hcl");
        let path = file_path.to_str().unwrap_or("config.hcl");

        let hcl_config_str = r#"
            storage "hiqlite" {
              data_dir    = "/var/lib/bvault/data"
              node_id     = 1
              secret_raft = "raft_secret_1234567"
              secret_api  = "api_secret_12345678"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
            }

            api_addr = "http://127.0.0.1:8200"
        "#;

        assert!(write_file(path, hcl_config_str).is_ok());

        let config = load_config(path);
        assert!(config.is_ok());
        let hcl_config = config.unwrap();

        assert_eq!(hcl_config.storage.len(), 1);
        let (_, storage) = hcl_config.storage.iter().next().unwrap();
        assert_eq!(storage.stype.as_str(), "hiqlite");
        assert_eq!(storage.config.get("data_dir").and_then(|v| v.as_str()), Some("/var/lib/bvault/data"));
        assert_eq!(storage.config.get("node_id").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(storage.config.get("secret_raft").and_then(|v| v.as_str()), Some("raft_secret_1234567"));
        assert_eq!(storage.config.get("secret_api").and_then(|v| v.as_str()), Some("api_secret_12345678"));
    }
}
