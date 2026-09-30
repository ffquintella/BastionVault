//! The local MCP pairing store (`features/mcp-access.md` §3).
//!
//! Records *which clients the operator approved, and with what scope*. It
//! never holds a token: the MCP-bound token lives in `bvault mcp serve`'s
//! memory for the pairing's TTL and is not written anywhere.
//!
//! On disk: `$XDG_CONFIG_HOME/bvault/mcp-pairings.json` (else
//! `~/.config/bvault/...`), mode 0600, in a 0700 directory. The records are
//! sealed in a [`KemDemEnvelopeV1`] (ML-KEM-768 + ChaCha20-Poly1305), the same
//! scheme the GUI keystore uses -- deliberately not a second one.
//!
//! Honest limit: a headless CLI has no OS keychain or hardware token to
//! protect the decapsulation key, so it sits in the same 0600 file. The
//! envelope buys tamper detection and one format across the product; file
//! permissions remain the confidentiality boundary, and a store that is
//! readable by anyone else is refused rather than used.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bv_crypto::{KemDemEnvelopeV1, KemProvider, MlKem768Provider, SymmetricKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use bv_errors::RvError;

fn err(message: impl Into<String>) -> RvError {
    RvError::ErrString(message.into())
}

const STORE_VERSION: u32 = 1;
const RECORD_VERSION: u32 = 1;
/// Binds the envelope to this file format so a sealed blob from another
/// BastionVault feature cannot be dropped in as a pairing store.
const AAD: &[u8] = b"bastionvault/mcp-pairings/v1";
/// A pairing the operator approved is good for this long unless revoked
/// first (spec §3 default).
pub const DEFAULT_PAIRING_LIFETIME_SECS: u64 = 30 * 24 * 3600;
/// Default lifetime of the MCP-bound token minted for a pairing (spec §1).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 8 * 3600;
pub const MAX_TOKEN_TTL_SECS: u64 = 24 * 3600;

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Stdio,
    Uds,
    LoopbackHttp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Stdio => "stdio",
            Transport::Uds => "uds",
            Transport::LoopbackHttp => "loopback-http",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRecord {
    #[serde(default = "record_version")]
    pub version: u32,
    pub id: String,
    pub client_name: String,
    pub client_version: String,
    /// The uid on the far end of a Unix socket; `None` for stdio (the client
    /// is the parent process) and loopback HTTP (authenticated by token).
    pub peer_uid: Option<u32>,
    pub transport: String,
    /// Hex BLAKE3 of the bearer handed to a loopback-HTTP client. The bearer
    /// itself is shown once, at pairing time, and never stored.
    pub pairing_token_hash: Option<String>,
    pub tool_allowlist: Vec<String>,
    pub path_scope: Vec<String>,
    pub reveal_allowed: bool,
    pub destructive_allowed: bool,
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    pub ttl_secs: u64,
    pub approved_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: u64,
}

fn record_version() -> u32 {
    RECORD_VERSION
}

impl PairingRecord {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    kem_public_key: String,
    kem_secret_key: String,
    envelope: KemDemEnvelopeV1,
}

/// Non-secret tools an operator can approve without a second thought: the
/// read-only ones that cannot return a secret value.
pub fn default_tool_allowlist() -> Vec<String> {
    crate::catalogue::catalogue().iter().filter(|t| t.read_only && !t.is_reveal).map(|t| t.name.to_string()).collect()
}

fn random_hex(bytes: usize) -> String {
    debug_assert!(bytes <= 32);
    let key = SymmetricKey::generate();
    hex::encode(&key.as_bytes().as_slice()[..bytes])
}

/// `[a-z0-9-]{32}` -- valid for the vault's `pairing.id` rule.
pub fn new_pairing_id() -> String {
    random_hex(16)
}

/// The bearer a loopback-HTTP client presents: 256 random bits.
pub fn new_pairing_token() -> String {
    random_hex(32)
}

pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

pub fn find_matching<'a>(
    records: &'a [PairingRecord],
    client_name: &str,
    peer_uid: Option<u32>,
    transport: Transport,
    now: u64,
) -> Option<&'a PairingRecord> {
    records.iter().find(|r| {
        !r.is_expired(now)
            && r.client_name == client_name
            && r.peer_uid == peer_uid
            && r.transport == transport.as_str()
    })
}

pub fn find_by_token_hash<'a>(records: &'a [PairingRecord], hash: &str, now: u64) -> Option<&'a PairingRecord> {
    records.iter().find(|r| {
        !r.is_expired(now)
            && r.transport == Transport::LoopbackHttp.as_str()
            && r.pairing_token_hash.as_deref() == Some(hash)
    })
}

pub struct PairingStore {
    path: PathBuf,
}

impl PairingStore {
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> Result<PathBuf, RvError> {
        let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(xdg) => PathBuf::from(xdg),
            None => {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| err("cannot locate a config directory: set XDG_CONFIG_HOME or HOME"))?;
                PathBuf::from(home).join(".config")
            }
        };
        Ok(base.join("bvault").join("mcp-pairings.json"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_file(&self) -> Result<Option<StoreFile>, RvError> {
        if !self.path.exists() {
            return Ok(None);
        }
        ensure_private(&self.path)?;
        let raw = fs::read(&self.path)?;
        let file: StoreFile = serde_json::from_slice(&raw)
            .map_err(|e| err(format!("{} is not a pairing store: {e}", self.path.display())))?;
        if file.version != STORE_VERSION {
            return Err(err(format!(
                "{} is pairing store version {}, this bvault understands version {STORE_VERSION}",
                self.path.display(),
                file.version
            )));
        }
        Ok(Some(file))
    }

    pub fn load(&self) -> Result<Vec<PairingRecord>, RvError> {
        let Some(file) = self.read_file()? else {
            return Ok(Vec::new());
        };
        let secret = Zeroizing::new(B64.decode(&file.kem_secret_key).map_err(|_| err("pairing store key is corrupt"))?);
        let plaintext = file
            .envelope
            .open(&MlKem768Provider, &secret, AAD)
            .map_err(|_| err("pairing store is corrupt or has been tampered with"))?;
        serde_json::from_slice(&plaintext).map_err(|_| err("pairing store contents are corrupt"))
    }

    pub fn save(&self, records: &[PairingRecord]) -> Result<(), RvError> {
        let provider = MlKem768Provider;
        let (public, secret) = match self.read_file()? {
            Some(f) => {
                (B64.decode(&f.kem_public_key).map_err(|_| err("pairing store key is corrupt"))?, f.kem_secret_key)
            }
            None => {
                let kp = provider
                    .generate_keypair()
                    .map_err(|e| err(format!("could not generate pairing store key: {e:?}")))?;
                (kp.public_key().to_vec(), B64.encode(kp.secret_key()))
            }
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(records)?);
        let envelope = KemDemEnvelopeV1::seal(&provider, &public, AAD, &plaintext)
            .map_err(|e| err(format!("could not seal pairing store: {e:?}")))?;
        let file =
            StoreFile { version: STORE_VERSION, kem_public_key: B64.encode(&public), kem_secret_key: secret, envelope };
        write_private(&self.path, &serde_json::to_vec_pretty(&file)?)
    }

    pub fn add(&self, record: PairingRecord) -> Result<(), RvError> {
        let mut records = self.load()?;
        records.push(record);
        self.save(&records)
    }

    /// Pairing the same `(client, uid, transport)` again replaces the old
    /// grant rather than stacking a second one beside it -- otherwise an
    /// expired or superseded scope could be matched first.
    pub fn upsert(&self, record: PairingRecord) -> Result<(), RvError> {
        let mut records = self.load()?;
        records.retain(|r| {
            !(r.client_name == record.client_name && r.peer_uid == record.peer_uid && r.transport == record.transport)
        });
        records.push(record);
        self.save(&records)
    }

    pub fn remove(&self, id: &str) -> Result<Option<PairingRecord>, RvError> {
        let mut records = self.load()?;
        let Some(pos) = records.iter().position(|r| r.id == id) else {
            return Ok(None);
        };
        let removed = records.remove(pos);
        self.save(&records)?;
        Ok(Some(removed))
    }

    pub fn touch(&self, id: &str, now: u64) -> Result<(), RvError> {
        let mut records = self.load()?;
        if let Some(r) = records.iter_mut().find(|r| r.id == id) {
            r.last_used_at = now;
            self.save(&records)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn ensure_private(path: &Path) -> Result<(), RvError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(err(format!(
            "{} is accessible to other users (mode {:o}); refusing to use it -- run `chmod 600 {}`",
            path.display(),
            mode & 0o777,
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private(_path: &Path) -> Result<(), RvError> {
    Ok(())
}

pub fn create_private_dir(dir: &Path) -> Result<(), RvError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    Ok(())
}

/// Atomic, owner-only replace: the temp file is created 0600 (never widened
/// afterwards) and renamed over the target, so a reader never sees a partial
/// or briefly-world-readable store.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), RvError> {
    let dir = path.parent().ok_or_else(|| err("pairing store path has no parent directory"))?;
    create_private_dir(dir)?;
    let tmp = path.with_extension("json.tmp");
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, name: &str, uid: Option<u32>, transport: Transport) -> PairingRecord {
        PairingRecord {
            version: RECORD_VERSION,
            id: id.to_string(),
            client_name: name.to_string(),
            client_version: "1.0".to_string(),
            peer_uid: uid,
            transport: transport.as_str().to_string(),
            pairing_token_hash: None,
            tool_allowlist: vec!["bv_whoami".to_string()],
            path_scope: vec!["secret/metadata/ai/*".to_string()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            approved_at: 100,
            expires_at: Some(1_000),
            last_used_at: 100,
        }
    }

    fn temp_store(name: &str) -> (PairingStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("bvault-mcp-pairing-{name}-{}", new_pairing_id()));
        (PairingStore::at(dir.join("mcp-pairings.json")), dir)
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let (store, _dir) = temp_store("missing");
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let (store, dir) = temp_store("roundtrip");
        store.add(record("a", "claude-desktop", None, Transport::Stdio)).unwrap();
        store.add(record("b", "cursor", Some(501), Transport::Uds)).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].peer_uid, Some(501));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn upsert_replaces_the_same_client_and_keeps_others() {
        let (store, dir) = temp_store("upsert");
        store.upsert(record("a", "claude", Some(501), Transport::Uds)).unwrap();
        store.upsert(record("b", "cursor", Some(501), Transport::Uds)).unwrap();
        let mut renewed = record("c", "claude", Some(501), Transport::Uds);
        renewed.path_scope = vec!["narrower/*".to_string()];
        store.upsert(renewed).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|r| r.id == "c" && r.path_scope == vec!["narrower/*".to_string()]));
        assert!(!loaded.iter().any(|r| r.id == "a"), "the superseded grant is gone");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn remove_deletes_only_that_record() {
        let (store, dir) = temp_store("remove");
        store.add(record("a", "x", None, Transport::Stdio)).unwrap();
        store.add(record("b", "y", None, Transport::Stdio)).unwrap();
        assert_eq!(store.remove("a").unwrap().unwrap().id, "a");
        assert!(store.remove("a").unwrap().is_none());
        assert_eq!(store.load().unwrap()[0].id, "b");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn plaintext_records_are_not_visible_on_disk() {
        let (store, dir) = temp_store("sealed");
        store.add(record("a", "super-distinctive-client-name", None, Transport::Stdio)).unwrap();
        let raw = fs::read_to_string(store.path()).unwrap();
        assert!(!raw.contains("super-distinctive-client-name"), "records must be sealed, not stored as JSON");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (store, dir) = temp_store("tamper");
        store.add(record("a", "x", None, Transport::Stdio)).unwrap();
        let mut file: StoreFile = serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
        file.envelope.payload_ciphertext[0] ^= 0xff;
        fs::write(store.path(), serde_json::to_vec(&file).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(store.load().is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn store_and_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = temp_store("modes");
        store.add(record("a", "x", None, Transport::Stdio)).unwrap();
        assert_eq!(fs::metadata(store.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(dir.clone()).unwrap().permissions().mode() & 0o777, 0o700);
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_store_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = temp_store("unsafe-mode");
        store.add(record("a", "x", None, Transport::Stdio)).unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
        let err = store.load().unwrap_err().to_string();
        assert!(err.contains("accessible to other users"), "{err}");
        assert!(store.save(&[]).is_err(), "must not silently rewrite an unsafe store either");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn find_matching_requires_name_uid_transport_and_unexpired() {
        let records = vec![record("a", "claude", Some(501), Transport::Uds)];
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, 500).is_some());
        assert!(find_matching(&records, "other", Some(501), Transport::Uds, 500).is_none());
        assert!(find_matching(&records, "claude", Some(502), Transport::Uds, 500).is_none());
        assert!(find_matching(&records, "claude", Some(501), Transport::Stdio, 500).is_none());
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, 1_000).is_none(), "expired");
    }

    #[test]
    fn token_lookup_is_by_hash_and_only_for_loopback_http() {
        let token = new_pairing_token();
        let mut http = record("h", "web", None, Transport::LoopbackHttp);
        http.pairing_token_hash = Some(hash_token(&token));
        let mut uds = record("u", "sock", Some(1), Transport::Uds);
        uds.pairing_token_hash = Some(hash_token(&token));
        let records = vec![uds, http];
        assert_eq!(find_by_token_hash(&records, &hash_token(&token), 500).unwrap().id, "h");
        assert!(find_by_token_hash(&records, &hash_token("wrong"), 500).is_none());
    }

    #[test]
    fn generated_ids_satisfy_the_vault_rule_and_are_unique() {
        let a = new_pairing_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert_ne!(a, new_pairing_id());
        assert_eq!(new_pairing_token().len(), 64);
    }

    #[test]
    fn default_allowlist_excludes_reveal_and_write_tools() {
        let tools = default_tool_allowlist();
        assert!(tools.contains(&"bv_kv_read_metadata".to_string()));
        for forbidden in ["bv_kv_read", "bv_transit_decrypt", "bv_totp_code", "bv_kv_write", "bv_pki_issue"] {
            assert!(!tools.contains(&forbidden.to_string()), "{forbidden} must not be in the default grant");
        }
    }
}
