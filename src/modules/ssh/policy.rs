//! On-disk types for the SSH engine's CA configuration and role catalog.
//!
//! Phase 1 supports only the **CA mode**: BastionVault holds an SSH CA
//! keypair, operators register roles that constrain how client public
//! keys get signed, and `sign/:role` returns an OpenSSH client cert.
//! OTP mode (Phase 2) and PQC algorithms (Phase 3) extend this file
//! later; today only `algorithm = "ssh-ed25519"` is implemented.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};

use crate::utils::{deserialize_duration, serialize_duration};

/// Keys for the SSH engine inside its mount's barrier view.
pub const CA_CONFIG_KEY: &str = "config/ca";
pub const ROLE_PREFIX: &str = "role/";
/// OTP entries (Phase 2). Keyed by the hex-encoded SHA-256 of the
/// generated OTP — the plaintext OTP itself is never persisted, so a
/// barrier compromise doesn't leak in-flight credentials, only their
/// pre-image hashes.
pub const OTP_PREFIX: &str = "otp/";

/// Default validity for an OTP. Short — the OTP is meant to live just
/// long enough for the user to paste it into ssh and the helper to
/// validate; a longer window enlarges the replay surface for nothing.
pub const DEFAULT_OTP_TTL: Duration = Duration::from_secs(2 * 60);

/// Default certificate validity. Mirrors Vault's SSH engine default
/// (`30m` on `sign`) — small enough that a leaked cert ages out fast,
/// large enough for a typical interactive session.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 60);
/// Default upper bound. `1h` matches the most conservative shape the
/// spec calls "useful for short-lived bastion sessions". Operators
/// who need longer set `max_ttl` explicitly when creating the role.
pub const DEFAULT_MAX_TTL: Duration = Duration::from_secs(60 * 60);
/// Backdate window for client/server clock skew on `valid_after`.
pub const DEFAULT_NOT_BEFORE: Duration = Duration::from_secs(30);

/// Persisted CA configuration. The private key is stored in OpenSSH
/// format (the same encoding `ssh-keygen -t ed25519` produces) so the
/// `ssh-key` crate's `PrivateKey::from_openssh` round-trips cleanly.
/// The barrier provides at-rest encryption — the engine never persists
/// raw bytes, only what flows through `req.storage_put`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaConfig {
    /// Wire algorithm name (e.g. `"ssh-ed25519"`). Phase 1: only
    /// Ed25519. The field is kept on disk so future phases can add
    /// algorithm-aware decisions on read without touching the format.
    pub algorithm: String,
    /// Armored OpenSSH private key (PEM-like, BEGIN OPENSSH PRIVATE
    /// KEY block). Sensitive — only ever read via `req.storage_get`
    /// (barrier-decrypted) and immediately handed to `ssh-key`.
    pub private_key_openssh: String,
    /// Single-line OpenSSH public key (`ssh-ed25519 AAAA… ca@bvault`).
    /// Persisted alongside the private key so `GET /v1/ssh/config/ca`
    /// and `GET /v1/ssh/public_key` are fast — they don't need to
    /// re-derive from the private key on every read.
    pub public_key_openssh: String,
}

/// Persisted role definition. Phase 1 fields only — the spec calls
/// out a longer list (PQC, identity templating, OTP fields, …)
/// that lands in later phases. `serde(default)` on every field
/// keeps roles forward-compatible: a role written today will still
/// deserialize cleanly after later additions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleEntry {
    /// Mode marker. Only `"ca"` is implemented in Phase 1; OTP comes
    /// later. Stored even though it's the only valid value today so
    /// the route handlers can reject already-persisted OTP roles
    /// gracefully when Phase 2 lands without a hard-coded migration.
    #[serde(default = "default_key_type")]
    pub key_type: String,

    /// What CA key signs the cert. Phase 1: only `"ssh-ed25519"`.
    /// The field is parsed at sign time, so an operator who creates
    /// a role with an unsupported algo fails at sign time with a
    /// clear error, not at role-write time — keeps the surface
    /// stable when Phase 3 adds RSA / ECDSA / ML-DSA support.
    #[serde(default = "default_algorithm_signer")]
    pub algorithm_signer: String,

    /// `"user"` or `"host"`. Default `"user"` — the common case.
    /// `host` certs use a different cert-type byte in the OpenSSH
    /// TBS encoding; the sign handler honours this.
    #[serde(default = "default_cert_type")]
    pub cert_type: String,

    /// Comma-separated list of usernames the cert may declare in
    /// `valid principals`. `"*"` allows any. Empty rejects the sign
    /// request at policy-check time.
    #[serde(default)]
    pub allowed_users: String,

    /// Username put into `valid principals` if the caller doesn't
    /// pick one. Empty + caller-supplied none = sign rejected.
    #[serde(default)]
    pub default_user: String,

    /// Comma-separated whitelist of `extensions` the caller may
    /// request (e.g. `"permit-pty,permit-port-forwarding"`).
    /// Anything outside the list is silently dropped from the
    /// signed cert. Empty list = no caller-supplied extensions
    /// allowed (only `default_extensions` are emitted).
    #[serde(default)]
    pub allowed_extensions: String,

    /// Always-on extensions. Merged with the (filtered)
    /// caller-supplied set; caller-supplied wins on key collision
    /// to allow per-call overrides within the whitelist.
    #[serde(default)]
    pub default_extensions: BTreeMap<String, String>,

    /// Comma-separated whitelist of `critical_options`
    /// (e.g. `"force-command,source-address"`).
    #[serde(default)]
    pub allowed_critical_options: String,

    /// Always-on critical options. Same merge rules as
    /// `default_extensions`.
    #[serde(default)]
    pub default_critical_options: BTreeMap<String, String>,

    /// Default validity. `effective_ttl` clamps to `max_ttl`.
    #[serde(
        default = "default_ttl",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub ttl: Duration,

    /// Hard cap. Per-call `ttl` requests above this are clamped down.
    #[serde(
        default = "default_max_ttl",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub max_ttl: Duration,

    /// Backdate seconds applied to the cert's `valid_after` so a
    /// small clock skew between vault and target host doesn't
    /// reject a freshly-issued cert.
    #[serde(
        default = "default_not_before",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub not_before_duration: Duration,

    /// Template for the cert's `key id` field. Substitution happens
    /// at sign time (Phase 1: literal — templating is Phase 3 alongside
    /// the existing PKI policy templater). The default makes the cert
    /// audit-traceable to the role and (eventually) the calling identity.
    #[serde(default = "default_key_id_format")]
    pub key_id_format: String,

    // ── OTP-mode fields (Phase 2) ─────────────────────────────────
    //
    // These only apply when `key_type == "otp"`. Empty / zero values
    // are fine for CA-mode roles — the validators in `path_roles.rs`
    // refuse to write a role where the field set contradicts the
    // declared mode.
    /// Comma-separated list of CIDRs the OTP is valid for. The
    /// caller-supplied `ip` on `creds` is matched against this set.
    /// Empty = the role refuses to mint OTPs (deny by default).
    #[serde(default)]
    pub cidr_list: String,

    /// Comma-separated CIDRs to subtract from `cidr_list`. Useful for
    /// "10.0.0.0/16 except the management subnet" patterns.
    #[serde(default)]
    pub exclude_cidr_list: String,

    /// Default SSH port; the helper logs / surfaces this to the user.
    /// `0` = "use the system default of 22"; persisted explicitly
    /// rather than papered over so an operator who really wants a
    /// non-22 port can audit it on the role read.
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for RoleEntry {
    fn default() -> Self {
        Self {
            key_type: default_key_type(),
            algorithm_signer: default_algorithm_signer(),
            cert_type: default_cert_type(),
            allowed_users: String::new(),
            default_user: String::new(),
            allowed_extensions: String::new(),
            default_extensions: BTreeMap::new(),
            allowed_critical_options: String::new(),
            default_critical_options: BTreeMap::new(),
            ttl: default_ttl(),
            max_ttl: default_max_ttl(),
            not_before_duration: default_not_before(),
            key_id_format: default_key_id_format(),
            cidr_list: String::new(),
            exclude_cidr_list: String::new(),
            port: default_port(),
        }
    }
}

impl RoleEntry {
    /// Clamp a caller-requested duration against `max_ttl`. `None` (or
    /// zero) falls back to `ttl`. Exposed as a method so the sign
    /// handler doesn't reach into the struct's fields directly.
    pub fn effective_ttl(&self, requested: Option<Duration>) -> Duration {
        let base = match requested {
            Some(d) if !d.is_zero() => d,
            _ => self.ttl,
        };
        std::cmp::min(base, self.max_ttl)
    }

    /// Comma-list helper: parse `allowed_users` / `allowed_extensions`
    /// / `allowed_critical_options` into a sorted-deduped vec.
    /// `"*"` is preserved as a single-element list — callers detect
    /// it and short-circuit to "any allowed".
    pub fn allowed_users_list(&self) -> Vec<String> {
        comma_split(&self.allowed_users)
    }

    pub fn allowed_extensions_list(&self) -> Vec<String> {
        comma_split(&self.allowed_extensions)
    }

    pub fn allowed_critical_options_list(&self) -> Vec<String> {
        comma_split(&self.allowed_critical_options)
    }

    /// Returns true if `ip` falls inside `cidr_list` and outside
    /// `exclude_cidr_list`. An empty `cidr_list` is treated as
    /// "deny everything" rather than "allow everything" — the OTP
    /// flow's whole job is to constrain a credential to a known set
    /// of hosts, so the safer default at the empty-string boundary
    /// is closed.
    pub fn ip_allowed(&self, ip: std::net::IpAddr) -> bool {
        let allow: Vec<std::net::IpAddr> = vec![ip];
        let allowed_nets = parse_cidrs(&self.cidr_list);
        let excluded_nets = parse_cidrs(&self.exclude_cidr_list);
        if allowed_nets.is_empty() {
            return false;
        }
        let in_allow = allow.iter().any(|a| allowed_nets.iter().any(|n| n.contains(*a)));
        let in_exclude = excluded_nets.iter().any(|n| n.contains(ip));
        in_allow && !in_exclude
    }
}

/// Comma-separated list of CIDRs → parsed networks. Skips invalid
/// entries silently (the role-write path validates them up front, so
/// anything that lands here has already been sanity-checked).
fn parse_cidrs(s: &str) -> Vec<ipnetwork::IpNetwork> {
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<ipnetwork::IpNetwork>().ok())
        .collect()
}

/// Persisted OTP record. Stored at `otp/<sha256-hex>` — the plaintext
/// OTP never lands on disk, only its SHA-256, so a barrier compromise
/// doesn't leak in-flight credentials. Verify hashes the inbound OTP
/// and looks up by hash-key directly, which makes the storage probe
/// constant-time per entry rather than scanning every record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpEntry {
    /// Role the OTP was minted under — needed by `verify` to surface
    /// the canonical username back to the helper.
    pub role: String,
    /// Target host IP the user is dialling. The helper passes this
    /// back through `verify`'s response so the PAM stack can compare
    /// against the connection's source identity.
    pub ip: String,
    /// Username the helper should log the user in as.
    pub username: String,
    /// Default port from the role (or override). Surfaced for the
    /// helper / UI; not enforced.
    pub port: u16,
    /// Unix-seconds expiry. `verify` rejects after this point even
    /// if the entry hasn't been swept yet.
    pub expires_at: u64,
}

fn default_key_type() -> String {
    "ca".to_string()
}
fn default_algorithm_signer() -> String {
    "ssh-ed25519".to_string()
}
fn default_cert_type() -> String {
    "user".to_string()
}
fn default_ttl() -> Duration {
    DEFAULT_TTL
}
fn default_max_ttl() -> Duration {
    DEFAULT_MAX_TTL
}
fn default_not_before() -> Duration {
    DEFAULT_NOT_BEFORE
}
fn default_key_id_format() -> String {
    "vault-{{role}}-{{token_display_name}}".to_string()
}
fn default_port() -> u16 {
    22
}

fn comma_split(s: &str) -> Vec<String> {
    let mut out: Vec<String> = s
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_default_has_safe_values() {
        let r = RoleEntry::default();
        assert_eq!(r.key_type, "ca");
        assert_eq!(r.algorithm_signer, "ssh-ed25519");
        assert_eq!(r.cert_type, "user");
        assert_eq!(r.ttl, DEFAULT_TTL);
        assert_eq!(r.max_ttl, DEFAULT_MAX_TTL);
        assert_eq!(r.not_before_duration, DEFAULT_NOT_BEFORE);
        assert!(r.default_extensions.is_empty());
        assert!(r.default_critical_options.is_empty());
    }

    #[test]
    fn effective_ttl_clamps_above_max() {
        let r = RoleEntry::default();
        assert_eq!(
            r.effective_ttl(Some(Duration::from_secs(99 * 3600))),
            r.max_ttl,
            "requests above max_ttl must clamp down"
        );
    }

    #[test]
    fn effective_ttl_falls_back_when_requested_zero() {
        let r = RoleEntry::default();
        assert_eq!(r.effective_ttl(None), r.ttl);
        assert_eq!(r.effective_ttl(Some(Duration::ZERO)), r.ttl);
    }

    #[test]
    fn comma_split_normalises() {
        let r = RoleEntry {
            allowed_users: "alice, bob, ,alice ,carol".to_string(),
            ..Default::default()
        };
        assert_eq!(
            r.allowed_users_list(),
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
    }

    #[test]
    fn role_serde_round_trip_keeps_fields() {
        let mut original = RoleEntry::default();
        original.allowed_users = "alice".to_string();
        original
            .default_extensions
            .insert("permit-pty".into(), "".into());
        let bytes = serde_json::to_vec(&original).unwrap();
        let back: RoleEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.allowed_users, "alice");
        assert_eq!(back.default_extensions.get("permit-pty"), Some(&"".to_string()));
    }
}
