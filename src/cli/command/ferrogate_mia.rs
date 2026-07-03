//! Client side of the FerroGate MIA helper API + DPoP proof construction,
//! used by the `bvault ferrogate` subcommands.
//!
//! The MIA (Machine Identity Agent) exposes a local Unix-domain socket
//! ([`DEFAULT_MIA_SOCKET`] by default) speaking a length-delimited CBOR
//! request/response protocol: a 4-byte big-endian length prefix followed by a
//! CBOR body. We send a [`HelperReq`] and receive a [`HelperResp`] carrying a
//! short-lived, DPoP-bound child token. This module re-declares that wire
//! schema (mirroring `mia::helper::proto`) and speaks it over a blocking
//! `std` socket — the CLI has no async runtime.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

/// Last-resort MIA helper socket path — MIA's `mia setup` wizard default for
/// this OS.
///
/// The socket location is operator-configurable in the MIA's `mia.toml`, so a
/// fixed path inevitably drifts (it did: MIA ≥0.18 moved the macOS default out
/// of `/var/run`). The authoritative value is whatever the installed MIA is
/// configured with — [`resolve_mia_socket`] reads that. This constant is only
/// the fallback used when neither the env override nor any `mia.toml` specifies
/// a socket, and mirrors MIA's per-OS wizard default
/// (`ferrogate/crates/mia/src/setup.rs`).
#[cfg(target_os = "macos")]
pub const DEFAULT_MIA_SOCKET: &str = "/Library/Application Support/FerroGate/run/mia.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_MIA_SOCKET: &str = "/run/ferrogate/mia.sock";

/// Resolve the MIA helper socket path for the default environment. Equivalent
/// to [`resolve_mia_socket_for(None)`](resolve_mia_socket_for).
#[must_use]
pub fn resolve_mia_socket() -> String {
    resolve_mia_socket_for(None)
}

/// Resolve the MIA helper socket path by asking the installed MIA where it is
/// configured to listen, mirroring MIA's own precedence
/// (`ferrogate/crates/mia/src/config.rs`):
///
/// 1. the `FERROGATE_HELPER_SOCKET` environment override (highest) — honoured
///    only for the default environment, since it names one explicit socket and
///    MIA treats `--config`/explicit overrides and `--environment` as mutually
///    exclusive;
/// 2. `[helper].socket` from the first config file that exists and sets it — for
///    the default environment `$FERROGATE_CONFIG`, then the per-OS system path,
///    then the per-user path; for a named environment the system then per-user
///    `mia-<env>.toml`;
/// 3. [`DEFAULT_MIA_SOCKET`] (MIA's wizard default) when nothing else applies.
///
/// `environment` selects which config file the MIA wrote: `None` ⇒ `mia.toml`,
/// `Some("hml")` ⇒ `mia-hml.toml`. This keeps the GUI/CLI in step with whatever
/// the host's config says instead of hard-coding a path that breaks whenever
/// MIA's default moves or an operator points the socket elsewhere.
#[must_use]
pub fn resolve_mia_socket_for(environment: Option<&str>) -> String {
    // The global socket override names one explicit socket; honour it for the
    // default environment only, so selecting an environment actually reads that
    // environment's `[helper].socket`.
    if environment.is_none() {
        if let Some(s) = env_socket_override() {
            return s;
        }
    }
    if let Some(s) = mia_config_socket(environment) {
        return s;
    }
    DEFAULT_MIA_SOCKET.to_string()
}

/// `FERROGATE_HELPER_SOCKET`, if set to a non-blank value.
fn env_socket_override() -> Option<String> {
    std::env::var("FERROGATE_HELPER_SOCKET").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `[helper].socket` from the first MIA config file (in MIA's discovery order)
/// that exists and sets it.
fn mia_config_socket(environment: Option<&str>) -> Option<String> {
    mia_config_candidates(environment).iter().find_map(|p| read_helper_socket(p))
}

/// The base config filename for an environment selector, mirroring FerroGate
/// MIA's own `config_filename`: `None` ⇒ `mia.toml`, `Some("hml")` ⇒
/// `mia-hml.toml`. The name must already have passed [`validate_environment`].
fn config_filename(environment: Option<&str>) -> String {
    match environment {
        Some(env) => format!("mia-{env}.toml"),
        None => "mia.toml".to_string(),
    }
}

/// Validate an environment selector, mirroring MIA's `validate_environment`. The
/// name becomes part of a config filename (`mia-<env>.toml`), so it must be a
/// safe single path component: non-empty, neither `.` nor `..`, and limited to
/// ASCII letters, digits, `.`, `-`, and `_` — so it can neither inject a path
/// separator nor traverse out of the config directory.
pub fn validate_environment(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("environment name must not be empty".to_string());
    }
    if name == "." || name == ".." {
        return Err(format!("environment name `{name}` is not a valid environment"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return Err(format!("environment name `{name}` is invalid: use only letters, digits, '.', '-', '_'"));
    }
    Ok(())
}

/// MIA's config-file discovery order for `environment`: for the default
/// environment `$FERROGATE_CONFIG` (an explicit single file, default-only),
/// then the system path, then the per-user path; for a named environment the
/// system then per-user `mia-<env>.toml`.
fn mia_config_candidates(environment: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(3);
    if environment.is_none() {
        if let Some(p) = std::env::var_os("FERROGATE_CONFIG").filter(|s| !s.is_empty()) {
            out.push(PathBuf::from(p));
        }
    }
    out.push(system_config_path(environment));
    if let Some(p) = user_config_path(environment) {
        out.push(p);
    }
    out
}

/// The OS-idiomatic *system* config directory (`mia setup` writes here as root):
/// macOS `/Library/Application Support/FerroGate`, else `/etc/ferrogate`.
#[cfg(target_os = "macos")]
fn system_config_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/FerroGate")
}
#[cfg(not(target_os = "macos"))]
fn system_config_dir() -> PathBuf {
    PathBuf::from("/etc/ferrogate")
}

/// The OS-idiomatic *per-user* config directory, or `None` if no home/config
/// var resolves: macOS `~/Library/Application Support/FerroGate`, else
/// `$XDG_CONFIG_HOME/ferrogate` (or `~/.config/ferrogate`).
#[cfg(target_os = "macos")]
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .map(|h| PathBuf::from(h).join("Library/Application Support/FerroGate"))
}
#[cfg(not(target_os = "macos"))]
fn user_config_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(x).join("ferrogate"));
    }
    std::env::var_os("HOME").filter(|s| !s.is_empty()).map(|h| PathBuf::from(h).join(".config/ferrogate"))
}

fn system_config_path(environment: Option<&str>) -> PathBuf {
    system_config_dir().join(config_filename(environment))
}
fn user_config_path(environment: Option<&str>) -> Option<PathBuf> {
    user_config_dir().map(|d| d.join(config_filename(environment)))
}

/// Discover the MIA environment selectors installed on this host by scanning the
/// system and per-user config directories for `mia-<env>.toml` files. Returns
/// the sorted, de-duplicated environment names (never including the default
/// `mia.toml`, which is selected by passing `None`/an empty environment). Names
/// that would not pass [`validate_environment`] are skipped.
#[must_use]
pub fn list_environments() -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for dir in [Some(system_config_dir()), user_config_dir()].into_iter().flatten() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(env) = name.strip_prefix("mia-").and_then(|s| s.strip_suffix(".toml")) {
                if validate_environment(env).is_ok() {
                    set.insert(env.to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Parse `path` as MIA's TOML config and return a non-blank `[helper].socket`.
fn read_helper_socket(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let doc = text.parse::<toml::Table>().ok()?;
    let sock = doc.get("helper")?.as_table()?.get("socket")?.as_str()?.trim();
    (!sock.is_empty()).then(|| sock.to_string())
}

// ── ferrogate mount auto-configuration ─────────────────────────────────────
//
// Everything a BastionVault `ferrogate` mount needs to trust this host's MIA is
// already on disk once the MIA is installed: the CMIS endpoint + SPKI pin live
// in `mia.toml`, and the trust domain is carried in the signed allowlist. The
// only thing the verifier still needs — the composite JWKS — is served by that
// same CMIS. `build_autoconfig` gathers all of it so the operator does not have
// to hand-copy any of these fields.

/// CMIS coordinates discovered from the installed MIA's `mia.toml` `[cmis]`
/// block — the endpoint + pin a `ferrogate` mount needs to reach the same CMIS
/// the MIA trusts.
#[derive(Debug, Clone)]
pub struct CmisDiscovery {
    /// CMIS host:port for a literal `[cmis].endpoint`, scheme stripped
    /// (BastionVault's gRPC fetcher re-adds it). Empty when CMIS is advertised
    /// via a DNS SRV record (see [`srv`](Self::srv)), which is passed through to
    /// the mount and resolved at fetch time (not here).
    pub endpoint: String,
    /// DNS SRV owner name from `[cmis].srv` (e.g. `_ferrogate._tcp.example.com`)
    /// — how a CMIS HA cluster is advertised. Mutually exclusive with a literal
    /// `endpoint`.
    pub srv: Option<String>,
    /// Lowercase-hex SHA-384 SPKI pin of the CMIS certificate (empty for an
    /// `http://` dev endpoint).
    pub spki_pin: String,
    /// Dial CMIS over (PQ-)TLS. `false` only for a plaintext `http://` endpoint;
    /// an SRV source is always TLS.
    pub tls_enable: bool,
}

/// Read `[cmis].endpoint` + `spki_pin` for the default environment. Equivalent
/// to [`read_cmis_config_for(None)`](read_cmis_config_for).
#[must_use]
pub fn read_cmis_config() -> Option<CmisDiscovery> {
    read_cmis_config_for(None)
}

/// Read `[cmis].endpoint` + `spki_pin` from the first MIA config file found for
/// `environment` (same discovery order as [`resolve_mia_socket_for`]). `None` if
/// no config sets a CMIS endpoint.
#[must_use]
pub fn read_cmis_config_for(environment: Option<&str>) -> Option<CmisDiscovery> {
    mia_config_candidates(environment).iter().find_map(|p| read_cmis(p))
}

fn read_cmis(path: &Path) -> Option<CmisDiscovery> {
    let text = std::fs::read_to_string(path).ok()?;
    let doc = text.parse::<toml::Table>().ok()?;
    let cmis = doc.get("cmis")?.as_table()?;
    let spki_pin = cmis.get("spki_pin").and_then(toml::Value::as_str).unwrap_or("").trim().to_string();

    // A literal `endpoint` is a single static server; `srv` advertises one or
    // more CMIS nodes via a DNS SRV record (an HA cluster). They are mutually
    // exclusive in `mia.toml`; a literal endpoint takes precedence here.
    let endpoint = cmis.get("endpoint").and_then(toml::Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    if let Some(raw) = endpoint {
        let tls_enable = !raw.starts_with("http://");
        let endpoint = raw
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        return Some(CmisDiscovery { endpoint, srv: None, spki_pin, tls_enable });
    }
    let srv = cmis.get("srv").and_then(toml::Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    if let Some(srv) = srv {
        // SRV is always dialed over (PQ-)TLS — there is no plaintext SRV path.
        return Some(CmisDiscovery { endpoint: String::new(), srv: Some(srv.to_string()), spki_pin, tls_enable: true });
    }
    None
}

/// Read the trust domain from the local signed allowlist for the default
/// environment. Equivalent to
/// [`read_allowlist_trust_domain_for(None)`](read_allowlist_trust_domain_for).
#[must_use]
pub fn read_allowlist_trust_domain() -> Option<String> {
    read_allowlist_trust_domain_for(None)
}

/// Read `[allowlist].path` from the `environment`'s `mia.toml`, decode the
/// signed CBOR allowlist, and return its `trust_domain`. This is the most
/// reliable local source of the trust domain: unlike reading it from a minted
/// token's SPIFFE `iss`, it does not require the caller to already be
/// allowlisted.
#[must_use]
pub fn read_allowlist_trust_domain_for(environment: Option<&str>) -> Option<String> {
    let path = mia_config_candidates(environment).iter().find_map(|p| read_allowlist_path(p))?;
    let bytes = std::fs::read(&path).ok()?;
    // Envelope: { body, signature }; trust_domain is a field of the inner body
    // (itself CBOR). The MIA serializes `body` as a `Vec<u8>`, which ciborium
    // encodes as an array of integers rather than a CBOR byte string — handle
    // both forms. We only read trust_domain (non-secret policy, used to prefill
    // the config form); signature verification is the MIA's job.
    let outer: ciborium::value::Value = ciborium::from_reader(&bytes[..]).ok()?;
    let body = cbor_to_bytes(cbor_get(&outer, "body")?)?;
    let inner: ciborium::value::Value = ciborium::from_reader(&body[..]).ok()?;
    let td = cbor_get(&inner, "trust_domain")?.as_text()?.trim().to_string();
    (!td.is_empty()).then_some(td)
}

fn read_allowlist_path(path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(path).ok()?;
    let doc = text.parse::<toml::Table>().ok()?;
    let p = doc.get("allowlist")?.as_table()?.get("path")?.as_str()?.trim();
    (!p.is_empty()).then(|| PathBuf::from(p))
}

/// Look up a string-keyed entry in a CBOR map `Value`.
fn cbor_get<'a>(v: &'a ciborium::value::Value, key: &str) -> Option<&'a ciborium::value::Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, val)| val)
}

/// Coerce a CBOR `Value` that holds a byte sequence into `Vec<u8>`, accepting
/// both a CBOR byte string and an array of small integers (how ciborium encodes
/// a serde `Vec<u8>`).
fn cbor_to_bytes(v: &ciborium::value::Value) -> Option<Vec<u8>> {
    if let Some(b) = v.as_bytes() {
        return Some(b.clone());
    }
    v.as_array()?
        .iter()
        .map(|e| e.as_integer().and_then(|i| u8::try_from(i).ok()))
        .collect()
}

/// A completed BastionVault `ferrogate` mount configuration derived from the
/// installed MIA, ready to write to `auth/<mount>/config`. Serializes to the
/// exact field names the config endpoint accepts.
#[derive(Debug, Clone, Serialize)]
pub struct FerrogateAutoConfig {
    /// Trust domain (from the signed allowlist); empty if it could not be read.
    pub trust_domain: String,
    /// This vault's audience — operator-supplied; cannot be derived from the MIA.
    pub expected_audience: String,
    /// Always `cmis_grpc`: keys are fetched + refreshed from CMIS.
    pub jwks_source: String,
    /// CMIS host:port for a literal `[cmis].endpoint` (from `mia.toml`); empty
    /// when CMIS is advertised via SRV (see `cmis_srv`).
    pub cmis_endpoint: String,
    /// DNS SRV owner name from `[cmis].srv` (from `mia.toml`), passed through
    /// verbatim so the mount resolves it and fails over across all advertised
    /// nodes — mirroring the MIA. Empty when a literal endpoint is used.
    pub cmis_srv: String,
    /// CMIS SPKI pin(s) (from `mia.toml`).
    pub cmis_spki_pins: Vec<String>,
    /// Dial CMIS over (PQ-)TLS.
    pub cmis_tls_enable: bool,
    /// The composite JWKS fetched live from CMIS — surfaced so the operator can
    /// eyeball the keys this config will trust. Not written to the mount (the
    /// `cmis_grpc` source fetches it itself); informational only.
    pub fetched_jwks: String,
    /// `kid`s present in the fetched JWKS (sanity-check against token headers).
    pub jwks_kids: Vec<String>,
    /// Non-fatal notes (e.g. trust domain not discoverable locally).
    pub warnings: Vec<String>,
}

/// Build a completed `ferrogate` mount config from the installed MIA: CMIS
/// endpoint + pin from `mia.toml`, trust domain from the signed allowlist, and
/// the live composite JWKS fetched from CMIS over the pinned (PQ-)TLS channel
/// (reusing BastionVault's own CMIS gRPC client, so the fetch path is exactly
/// the one the running mount will use). `expected_audience` is operator-supplied
/// — it identifies this vault and cannot come from the MIA.
pub async fn build_autoconfig(
    expected_audience: String,
    environment: Option<&str>,
) -> Result<FerrogateAutoConfig, String> {
    use crate::modules::credential::ferrogate::{cmis, jwks_source, FerroGateConfig};

    let cfg_name = config_filename(environment);
    let disc = read_cmis_config_for(environment).ok_or_else(|| {
        format!(
            "no CMIS endpoint found in {cfg_name} ([cmis].endpoint or [cmis].srv) — is the \
             FerroGate MIA installed on this host{}?",
            environment.map(|e| format!(" for environment `{e}`")).unwrap_or_default()
        )
    })?;
    if disc.tls_enable && disc.spki_pin.is_empty() {
        return Err(format!(
            "{cfg_name} configures CMIS over TLS but has no [cmis].spki_pin; cannot verify CMIS"
        ));
    }

    let mut warnings = Vec::new();

    // CMIS may be advertised by a DNS SRV record (an HA cluster) rather than a
    // literal endpoint. Pass the SRV name through verbatim so the mount
    // resolves it at every fetch and fails over across all advertised nodes —
    // mirroring the MIA. (Storing a single resolved node here would pin the
    // mount to one cluster member, unable to fail over if that node's cert
    // diverged from the shared SPKI pin — the failure this autofill caused.)
    let (cmis_endpoint, cmis_srv) = if disc.endpoint.is_empty() {
        let srv = disc.srv.clone().unwrap_or_default();
        warnings.push(format!(
            "CMIS advertised via SRV {srv}; the mount resolves it on each fetch and fails over \
             across all advertised nodes (mirrors the MIA)"
        ));
        (String::new(), srv)
    } else {
        (disc.endpoint.clone(), String::new())
    };

    let trust_domain = read_allowlist_trust_domain_for(environment).unwrap_or_else(|| {
        warnings.push(
            "could not read trust_domain from the local allowlist; set it manually if your \
             deployment pins one"
                .to_string(),
        );
        String::new()
    });

    let pins: Vec<String> = if disc.spki_pin.is_empty() { Vec::new() } else { vec![disc.spki_pin.clone()] };
    let probe = FerroGateConfig {
        cmis_endpoint: cmis_endpoint.clone(),
        cmis_srv: cmis_srv.clone(),
        cmis_spki_pins: pins.clone(),
        cmis_tls_enable: disc.tls_enable,
        ..FerroGateConfig::default()
    };
    let fetched_jwks = cmis::fetch_jwks_json(&probe, "").await?;

    let jwks_kids = match ferro_child_verify::JwkSet::from_json(&fetched_jwks) {
        Ok(set) => set.keys.into_iter().map(|k| k.kid).collect::<Vec<_>>(),
        Err(e) => {
            warnings.push(format!("fetched JWKS did not parse as a composite key set: {e}"));
            Vec::new()
        }
    };
    if jwks_kids.is_empty() {
        warnings.push("CMIS returned no usable keys in its JWKS".to_string());
    }

    Ok(FerrogateAutoConfig {
        trust_domain,
        expected_audience,
        jwks_source: jwks_source::CMIS_GRPC.to_string(),
        cmis_endpoint,
        cmis_srv,
        cmis_spki_pins: pins,
        cmis_tls_enable: disc.tls_enable,
        fetched_jwks,
        jwks_kids,
        warnings,
    })
}

/// Largest frame we will read or write (matches the MIA's `MAX_FRAME_LEN`).
const MAX_FRAME_LEN: usize = 64 * 1024;

/// A token request to the MIA. Mirrors `mia::helper::proto::HelperReq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperReq {
    pub audience: String,
    pub dpop_jkt: String,
    pub ttl_secs: u32,
}

/// A minted child token. Mirrors `mia::helper::proto::ChildToken`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildToken {
    pub jws: String,
    pub exp: i64,
}

/// Refusal opcodes. Mirrors `mia::helper::proto::ErrorCode`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    PermissionDenied,
    NoHostSvid,
    CrlStale,
    MalformedRequest,
    RateLimited,
    Internal,
}

impl ErrorCode {
    /// Operator-facing explanation of the refusal, with a pointer to where to
    /// look next (the raw opcode alone is not actionable from the GUI/CLI).
    pub fn describe(self) -> &'static str {
        match self {
            Self::PermissionDenied => {
                "this caller is not on the MIA's local allowlist (review the host's allowlist in CMIS)"
            }
            Self::NoHostSvid => {
                "the MIA has no host SVID yet (host attestation to CMIS has not completed; check the MIA log)"
            }
            Self::CrlStale => {
                "its revocation list (CRL) from CMIS is stale — the MIA fails closed; check that CMIS is reachable and publishing a fresh CRL"
            }
            Self::MalformedRequest => "it could not parse the request (client/MIA version mismatch?)",
            Self::RateLimited => "the request was rate-limited",
            Self::Internal => "it hit an internal error (check the MIA log)",
        }
    }
}

/// The MIA's reply. Mirrors `mia::helper::proto::HelperResp` (externally tagged).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperResp {
    Token(ChildToken),
    Error { code: ErrorCode, retry_after: Option<u32> },
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// An ephemeral DPoP key (RFC 9449). The CLI generates one per invocation,
/// tells the MIA its thumbprint so the minted token is bound to it, then signs
/// a DPoP proof per HTTP request with the private half.
pub struct DpopKey {
    signing: SigningKey,
    /// base64url of the Ed25519 public key `x` coordinate (the JWK `x`).
    x_b64url: String,
}

impl DpopKey {
    /// Generate a fresh Ed25519 DPoP key.
    pub fn generate() -> Self {
        let seed: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&seed);
        let x_b64url = b64(signing.verifying_key().as_bytes());
        Self { signing, x_b64url }
    }

    /// RFC 7638 JWK thumbprint (`cnf.jkt`) — must equal the value the MIA
    /// embeds in the child token's `cnf`.
    pub fn jkt(&self) -> String {
        ferro_child_verify::jwk_thumbprint_ed25519(&self.x_b64url)
    }

    /// Build a DPoP proof JWS binding this request to `(htm, htu)`.
    pub fn proof(&self, htm: &str, htu: &str) -> String {
        let jti: [u8; 16] = rand::random();
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": self.x_b64url },
        });
        let claims = serde_json::json!({
            "jti": hex::encode(jti),
            "htm": htm,
            "htu": htu,
            "iat": now_unix(),
        });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&sig.to_bytes()))
    }
}

/// Request a child token from the MIA for `audience`, bound to `dpop_jkt`.
pub fn request_child_token(
    socket_path: &str,
    audience: &str,
    dpop_jkt: &str,
    ttl_secs: u32,
) -> Result<ChildToken, String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        format!("ferrogate_mia_unavailable: cannot connect to the MIA helper socket at {socket_path}: {e}")
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let req = HelperReq { audience: audience.to_string(), dpop_jkt: dpop_jkt.to_string(), ttl_secs };
    let mut body = Vec::with_capacity(256);
    ciborium::into_writer(&req, &mut body).map_err(|e| format!("cbor encode: {e}"))?;
    let len = u32::try_from(body.len()).map_err(|_| "request too large".to_string())?;
    stream.write_all(&len.to_be_bytes()).map_err(|e| format!("write: {e}"))?;
    stream.write_all(&body).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read: {e}"))?;
    let rlen = u32::from_be_bytes(len_buf) as usize;
    if rlen > MAX_FRAME_LEN {
        return Err(format!("MIA response frame too large: {rlen} bytes"));
    }
    let mut rbody = vec![0u8; rlen];
    stream.read_exact(&mut rbody).map_err(|e| format!("read: {e}"))?;
    let resp: HelperResp = ciborium::from_reader(&rbody[..]).map_err(|e| format!("cbor decode: {e}"))?;

    match resp {
        HelperResp::Token(t) => Ok(t),
        HelperResp::Error { code, retry_after } => {
            let hint = retry_after.map(|s| format!(" (retry after {s}s)")).unwrap_or_default();
            Err(format!("MIA refused: {}{hint}", code.describe()))
        }
    }
}

/// Decode (without verifying) the claims segment of a compact JWS and return
/// the requested string field — used by `whoami` to read the local SPIFFE id
/// from a freshly minted token.
pub fn jws_claim_str(jws: &str, field: &str) -> Option<String> {
    let seg = jws.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(seg).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get(field)?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_child_verify::{verify_dpop_proof, DpopExpectation};

    #[test]
    fn dpop_proof_verifies_against_ferrogate_verifier() {
        // The CLI's DPoP proof + thumbprint must satisfy the same verifier the
        // server uses (ferro-child-verify), or login would always fail.
        let key = DpopKey::generate();
        let jkt = key.jkt();
        let htu = "https://vault.example.com";
        let proof = key.proof("POST", htu);
        let expect = DpopExpectation { htm: "POST", htu, max_age_secs: 300 };
        let ok = verify_dpop_proof(&proof, &expect, now_unix(), 60).expect("DPoP proof verifies");
        assert_eq!(ok.jkt, jkt, "proof thumbprint must equal jkt()");
    }

    #[test]
    fn helper_frames_roundtrip_cbor() {
        // Lock the wire format against mia::helper::proto.
        let req = HelperReq {
            audience: "https://vault.example.com".into(),
            dpop_jkt: "abc".into(),
            ttl_secs: 300,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let back: HelperReq = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back.audience, req.audience);

        let resp = HelperResp::Token(ChildToken { jws: "a.b.c".into(), exp: 42 });
        let mut rbuf = Vec::new();
        ciborium::into_writer(&resp, &mut rbuf).unwrap();
        let rback: HelperResp = ciborium::from_reader(&rbuf[..]).unwrap();
        assert!(matches!(rback, HelperResp::Token(t) if t.exp == 42));
    }

    #[test]
    fn every_error_code_has_an_operator_facing_description() {
        // The string surfaced to the GUI/CLI must be the human-readable
        // `describe()` text, not the raw enum variant name. Guard every
        // variant so a future opcode can't silently fall back to `{code:?}`.
        for code in [
            ErrorCode::PermissionDenied,
            ErrorCode::NoHostSvid,
            ErrorCode::CrlStale,
            ErrorCode::MalformedRequest,
            ErrorCode::RateLimited,
            ErrorCode::Internal,
        ] {
            let msg = code.describe();
            assert!(!msg.is_empty(), "{code:?} has no description");
            // The raw variant name must not leak into the operator message.
            assert!(
                !msg.contains(&format!("{code:?}")),
                "describe() for {code:?} leaks the raw variant name: {msg}"
            );
        }
        // Spot-check the CrlStale wording the GUI toast renders.
        assert!(ErrorCode::CrlStale
            .describe()
            .contains("revocation list (CRL) from CMIS is stale"));
    }

    #[test]
    fn read_cmis_strips_scheme_and_sets_tls() {
        let dir = std::env::temp_dir().join("bv_mia_cmis_test");
        std::fs::create_dir_all(&dir).unwrap();

        let https = dir.join("https.toml");
        std::fs::write(
            &https,
            "[cmis]\nendpoint = 'https://cmis.example.com:8443/'\nspki_pin = 'abc123'\n",
        )
        .unwrap();
        let d = read_cmis(&https).expect("parses");
        assert_eq!(d.endpoint, "cmis.example.com:8443", "scheme + trailing slash stripped");
        assert_eq!(d.spki_pin, "abc123");
        assert!(d.tls_enable, "https ⇒ TLS");

        let http = dir.join("http.toml");
        std::fs::write(&http, "[cmis]\nendpoint = 'http://localhost:9000'\n").unwrap();
        let d = read_cmis(&http).expect("parses");
        assert_eq!(d.endpoint, "localhost:9000");
        assert!(!d.tls_enable, "http ⇒ plaintext");
        assert!(d.spki_pin.is_empty());

        // SRV-advertised CMIS (HA cluster): no literal endpoint, but a `srv`
        // owner name + pin. Endpoint is left empty for later DNS resolution;
        // SRV always implies TLS.
        let srv = dir.join("srv.toml");
        std::fs::write(
            &srv,
            "[cmis]\nsrv = '_ferrogate-hml._tcp.esi.fgv.br'\nspki_pin = 'deadbeef'\n",
        )
        .unwrap();
        let d = read_cmis(&srv).expect("parses");
        assert!(d.endpoint.is_empty(), "srv source leaves endpoint unresolved");
        assert_eq!(d.srv.as_deref(), Some("_ferrogate-hml._tcp.esi.fgv.br"));
        assert_eq!(d.spki_pin, "deadbeef");
        assert!(d.tls_enable, "srv ⇒ TLS");

        // A literal endpoint wins over srv when both are (mis)configured.
        let both = dir.join("both.toml");
        std::fs::write(
            &both,
            "[cmis]\nendpoint = 'https://cmis.example.com:8443'\nsrv = '_x._tcp.example.com'\nspki_pin = 'abc'\n",
        )
        .unwrap();
        let d = read_cmis(&both).expect("parses");
        assert_eq!(d.endpoint, "cmis.example.com:8443");
        assert!(d.srv.is_none(), "literal endpoint takes precedence");

        // No [cmis] table ⇒ None.
        let none = dir.join("none.toml");
        std::fs::write(&none, "log = 'info'\n").unwrap();
        assert!(read_cmis(&none).is_none());

        // [cmis] present but neither endpoint nor srv ⇒ None.
        let empty = dir.join("empty.toml");
        std::fs::write(&empty, "[cmis]\nspki_pin = 'abc'\n").unwrap();
        assert!(read_cmis(&empty).is_none());
    }

    #[test]
    fn config_filename_suffixes_environment() {
        // Default ⇒ plain mia.toml; a selector ⇒ mia-<env>.toml. Must match the
        // file the MIA's own `mia setup --environment <env>` writes.
        assert_eq!(config_filename(None), "mia.toml");
        assert_eq!(config_filename(Some("hml")), "mia-hml.toml");
        assert_eq!(config_filename(Some("prod")), "mia-prod.toml");
    }

    #[test]
    fn validate_environment_rejects_unsafe_names() {
        // Mirrors MIA's rules: the name becomes a filename component, so a path
        // separator or traversal must be refused before it reaches the disk.
        for ok in ["hml", "prod", "staging-2", "us.east", "a_b"] {
            assert!(validate_environment(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", ".", "..", "a/b", "a b", "../etc", "x\\y", "a:b"] {
            assert!(validate_environment(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn read_helper_socket_parses_mia_toml() {
        // Mirrors a real `mia setup`-written config: the socket lives under
        // `[helper].socket`, which MIA ≥0.18 places outside /var/run.
        let dir = std::env::temp_dir().join("bv_mia_cfg_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mia.toml");
        std::fs::write(
            &path,
            "log = 'info'\n\n[helper]\nsocket = '/Library/Application Support/FerroGate/run/mia.sock'\nsocket_mode = '660'\n",
        )
        .unwrap();
        assert_eq!(
            read_helper_socket(&path).as_deref(),
            Some("/Library/Application Support/FerroGate/run/mia.sock")
        );

        // No [helper].socket ⇒ no path (helper API disabled).
        let none_path = dir.join("nohelper.toml");
        std::fs::write(&none_path, "log = 'info'\n").unwrap();
        assert_eq!(read_helper_socket(&none_path), None);

        // Missing file ⇒ None, never an error.
        assert_eq!(read_helper_socket(&dir.join("does-not-exist.toml")), None);
    }
}
