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

// One vault per pairing (T548): see `PairingRecord::vault_id` and
// features/mcp-access.md §3 "Vault binding".

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
/// Version 2 (T548) added `vault_id`. Every record is written at this
/// version; [`MIN_RECORD_VERSION`]..=this is read.
pub const RECORD_VERSION: u32 = 2;
/// Version 1: written before pairings were bound to a vault. Read, never
/// matched until re-bound.
pub const MIN_RECORD_VERSION: u32 = 1;
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
    /// The operator let this client open brokered sessions
    /// (`features/mcp-brokered-sessions.md` §9). Absent in a record written
    /// before sessions existed, which reads as "no sessions".
    #[serde(default)]
    pub connect_allowed: bool,
    /// Recorded for the vault's exchange rule and for display. Never an off
    /// switch: the gatekeeper confirms every session call whatever this
    /// says, and the exchange always asserts `true`.
    #[serde(default)]
    pub confirm_connect: bool,
    pub ttl_secs: u64,
    pub approved_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: u64,
    /// The namespace the operator narrowed this pairing's tokens to when
    /// approving it (T457 Phase 2): a request the vault re-validates at each
    /// exchange. Absent (every record written before it existed): the
    /// tokens follow the operator's session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The vault this pairing was approved for: that vault's MCP identity
    /// (`sys/mcp/token` with `vault_identity`, T548). `None` on a record
    /// written before pairings were bound to a vault: such a record is
    /// "unassigned", never matched and never exchanged, until the operator
    /// re-binds it ([`PairingStore::rebind`]) or revokes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
}

/// A record that does not say is read as the oldest format: absent never
/// claims a newer one's guarantees.
fn record_version() -> u32 {
    MIN_RECORD_VERSION
}

impl PairingRecord {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }

    /// Approved for exactly this vault. An unassigned record is bound to no
    /// vault, and an empty identity matches nothing.
    pub fn is_bound_to(&self, vault_id: &str) -> bool {
        !vault_id.is_empty() && self.vault_id.as_deref() == Some(vault_id)
    }
}

/// `[a-z0-9-]{1,64}`: what a vault identity looks like (the vault generates a
/// lowercase UUID). Anything else is refused, never compared.
pub fn valid_vault_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Refuses a store whose records this build cannot read faithfully: a
/// version outside [`MIN_RECORD_VERSION`]..=[`RECORD_VERSION`] (rewriting it
/// would drop whatever a newer build added), a version-1 record that claims a
/// vault (no such writer existed), or a vault identity that is not one.
fn check_records(records: &[PairingRecord]) -> Result<(), RvError> {
    for r in records {
        if !(MIN_RECORD_VERSION..=RECORD_VERSION).contains(&r.version) {
            return Err(err(format!(
                "pairing store holds a record of version {}; this bvault reads versions {MIN_RECORD_VERSION} to \
                 {RECORD_VERSION} (was it written by a newer bvault?)",
                r.version
            )));
        }
        match r.vault_id.as_deref() {
            Some(_) if r.version < 2 => {
                return Err(err("pairing store holds a version-1 record that names a vault; the store is corrupt"))
            }
            Some(v) if !valid_vault_id(v) => {
                return Err(err("pairing store holds a record with a malformed vault identity; the store is corrupt"))
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    kem_public_key: String,
    kem_secret_key: String,
    envelope: KemDemEnvelopeV1,
}

/// Non-secret tools an operator can approve without a second thought: the
/// read-only ones that cannot return a secret value and open no session.
/// `bv_resource_web_fetch` is read-only by HTTP semantics but open-world: it
/// is granted only in the separate brokered-sessions step, with
/// `connect_allowed`, never by default
/// (`features/mcp-brokered-sessions.md` §9).
pub fn default_tool_allowlist() -> Vec<String> {
    crate::catalogue::catalogue()
        .iter()
        .filter(|t| t.read_only && !t.is_reveal && !t.open_world && !crate::catalogue::OPT_IN_TOOLS.contains(&t.name))
        .map(|t| t.name.to_string())
        .collect()
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

/// The unexpired pairing for this client, peer and transport that was
/// approved for `vault_id` -- the vault the caller serves. A pairing approved
/// for another vault, or never bound to one, is not a match.
pub fn find_matching<'a>(
    records: &'a [PairingRecord],
    client_name: &str,
    peer_uid: Option<u32>,
    transport: Transport,
    vault_id: &str,
    now: u64,
) -> Option<&'a PairingRecord> {
    records.iter().find(|r| {
        !r.is_expired(now)
            && r.is_bound_to(vault_id)
            && r.client_name == client_name
            && r.peer_uid == peer_uid
            && r.transport == transport.as_str()
    })
}

/// The unexpired loopback-HTTP pairing whose bearer hashes to `hash`, if it
/// was approved for `vault_id`. A bearer from a pairing for another vault, or
/// an unassigned one, authenticates nobody here.
pub fn find_by_token_hash<'a>(
    records: &'a [PairingRecord],
    hash: &str,
    vault_id: &str,
    now: u64,
) -> Option<&'a PairingRecord> {
    records.iter().find(|r| {
        !r.is_expired(now)
            && r.is_bound_to(vault_id)
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
        let records: Vec<PairingRecord> =
            serde_json::from_slice(&plaintext).map_err(|_| err("pairing store contents are corrupt"))?;
        check_records(&records)?;
        Ok(records)
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
        // Write-new: every record at the current format. An unassigned one
        // stays unassigned (`vault_id` absent); only `rebind` assigns it.
        let current: Vec<PairingRecord> =
            records.iter().cloned().map(|r| PairingRecord { version: RECORD_VERSION, ..r }).collect();
        check_records(&current)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&current)?);
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

    /// Pairing the same `(client, uid, transport)` with the same vault again
    /// replaces the old grant rather than stacking a second one beside it --
    /// otherwise an expired or superseded scope could be matched first. The
    /// same client's grant for another vault, and an unassigned record, are
    /// kept: each is the operator's own decision about its own vault.
    pub fn upsert(&self, record: PairingRecord) -> Result<(), RvError> {
        let mut records = self.load()?;
        records.retain(|r| !same_slot(r, &record));
        records.push(record);
        self.save(&records)
    }

    /// Binds the unassigned record `id` to `vault_id` -- the operator's
    /// explicit decision, made against the vault they are signed in to; never
    /// done implicitly. Refused for a record already bound to another vault
    /// (pair the client with that vault instead), and when the same client
    /// already has a grant for `vault_id` (one would shadow the other). The
    /// grant, its expiry and its loopback bearer are kept as they were.
    pub fn rebind(&self, id: &str, vault_id: &str) -> Result<PairingRecord, RvError> {
        if !valid_vault_id(vault_id) {
            return Err(err("cannot bind a pairing to a malformed vault identity"));
        }
        let mut records = self.load()?;
        let pos = records.iter().position(|r| r.id == id).ok_or_else(|| err(format!("no pairing with id `{id}`")))?;
        match records[pos].vault_id.as_deref() {
            Some(bound) if bound == vault_id => return Ok(records[pos].clone()),
            Some(_) => {
                return Err(err(format!(
                    "pairing `{id}` is bound to another vault; it cannot be moved -- pair the client with this vault instead"
                )))
            }
            None => {}
        }
        let mut rebound = records[pos].clone();
        rebound.vault_id = Some(vault_id.to_string());
        rebound.version = RECORD_VERSION;
        if let Some(existing) = records.iter().find(|r| r.id != id && same_slot(r, &rebound)) {
            return Err(err(format!(
                "`{}` is already paired with this vault (pairing id {}); revoke one of the two first",
                existing.client_name, existing.id
            )));
        }
        records[pos] = rebound.clone();
        self.save(&records)?;
        Ok(rebound)
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

/// One grant per client, peer, transport and vault.
fn same_slot(a: &PairingRecord, b: &PairingRecord) -> bool {
    a.client_name == b.client_name && a.peer_uid == b.peer_uid && a.transport == b.transport && a.vault_id == b.vault_id
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
    use serde_json::{json, Value};

    use super::*;

    const VAULT_A: &str = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0";
    const VAULT_B: &str = "11111111-2222-4333-8444-555555555555";

    fn record(id: &str, name: &str, uid: Option<u32>, transport: Transport) -> PairingRecord {
        PairingRecord {
            version: RECORD_VERSION,
            vault_id: Some(VAULT_A.to_string()),
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
            connect_allowed: false,
            confirm_connect: false,
            ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            approved_at: 100,
            expires_at: Some(1_000),
            last_used_at: 100,
            namespace: None,
        }
    }

    /// T457 Phase 2: a record written before narrowing existed follows the
    /// operator's session (no `namespace`), a narrowed one round-trips, and a
    /// record that never narrowed is written exactly as before.
    #[test]
    fn a_record_without_a_namespace_follows_the_session() {
        let plain = record("a", "claude", None, Transport::Stdio);
        let written = serde_json::to_value(&plain).unwrap();
        assert!(written.get("namespace").is_none(), "nothing new on disk for a record that did not narrow");
        let read: PairingRecord = serde_json::from_value(written).unwrap();
        assert_eq!(read.namespace, None);

        let mut narrowed = record("b", "claude", None, Transport::Stdio);
        narrowed.namespace = Some("dti/esi".to_string());
        let back: PairingRecord = serde_json::from_value(serde_json::to_value(&narrowed).unwrap()).unwrap();
        assert_eq!(back, narrowed);
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

    /// A record written before brokered sessions existed reads with them
    /// off, and one that allows them round-trips.
    #[test]
    fn a_record_without_the_session_fields_reads_with_sessions_off() {
        let mut old = serde_json::to_value(record("a", "claude", None, Transport::Stdio)).unwrap();
        let obj = old.as_object_mut().unwrap();
        obj.remove("connect_allowed");
        obj.remove("confirm_connect");
        let read: PairingRecord = serde_json::from_value(old).unwrap();
        assert!(!read.connect_allowed && !read.confirm_connect);

        let mut current = record("b", "claude", None, Transport::Stdio);
        current.connect_allowed = true;
        current.confirm_connect = true;
        let back: PairingRecord = serde_json::from_value(serde_json::to_value(&current).unwrap()).unwrap();
        assert_eq!(back, current);
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
    fn find_matching_requires_name_uid_transport_vault_and_unexpired() {
        let records = vec![record("a", "claude", Some(501), Transport::Uds)];
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, VAULT_A, 500).is_some());
        assert!(find_matching(&records, "other", Some(501), Transport::Uds, VAULT_A, 500).is_none());
        assert!(find_matching(&records, "claude", Some(502), Transport::Uds, VAULT_A, 500).is_none());
        assert!(find_matching(&records, "claude", Some(501), Transport::Stdio, VAULT_A, 500).is_none());
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, VAULT_A, 1_000).is_none(), "expired");
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, "", 500).is_none(), "no vault");
    }

    #[test]
    fn token_lookup_is_by_hash_and_only_for_loopback_http() {
        let token = new_pairing_token();
        let mut http = record("h", "web", None, Transport::LoopbackHttp);
        http.pairing_token_hash = Some(hash_token(&token));
        let mut uds = record("u", "sock", Some(1), Transport::Uds);
        uds.pairing_token_hash = Some(hash_token(&token));
        let records = vec![uds, http];
        assert_eq!(find_by_token_hash(&records, &hash_token(&token), VAULT_A, 500).unwrap().id, "h");
        assert!(find_by_token_hash(&records, &hash_token("wrong"), VAULT_A, 500).is_none());
    }

    /// T548 regression: the store is per user, so a pairing approved while
    /// serving vault A was accepted by vault B. It must not be, by client
    /// identity or by bearer.
    #[test]
    fn a_pairing_approved_for_one_vault_is_not_matched_for_another() {
        let token = new_pairing_token();
        let mut http = record("h", "web", None, Transport::LoopbackHttp);
        http.pairing_token_hash = Some(hash_token(&token));
        let records = vec![record("a", "claude", Some(501), Transport::Uds), http];
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, VAULT_B, 500).is_none());
        assert!(find_by_token_hash(&records, &hash_token(&token), VAULT_B, 500).is_none());
        assert!(find_matching(&records, "claude", Some(501), Transport::Uds, VAULT_A, 500).is_some());
        assert!(find_by_token_hash(&records, &hash_token(&token), VAULT_A, 500).is_some());
    }

    /// Seals `plaintext` as the store's contents exactly as written, so a
    /// test can plant a record a current build would never write.
    fn seal_raw(store: &PairingStore, plaintext: &[u8]) {
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let envelope = KemDemEnvelopeV1::seal(&MlKem768Provider, kp.public_key(), AAD, plaintext).unwrap();
        let file = StoreFile {
            version: STORE_VERSION,
            kem_public_key: B64.encode(kp.public_key()),
            kem_secret_key: B64.encode(kp.secret_key()),
            envelope,
        };
        write_private(store.path(), &serde_json::to_vec(&file).unwrap()).unwrap();
    }

    /// A record exactly as a version-1 build wrote it: no `vault_id`.
    fn legacy_json(id: &str, name: &str) -> Value {
        let mut v = serde_json::to_value(record(id, name, Some(501), Transport::Uds)).unwrap();
        v["version"] = json!(1);
        v.as_object_mut().unwrap().remove("vault_id");
        v
    }

    /// T548: a record written before vaults were named loads, lists and
    /// round-trips (written as version 2, still unassigned), but is matched
    /// for no vault -- not even the one serving when it is read.
    #[test]
    fn a_legacy_record_loads_and_round_trips_but_is_never_matched() {
        let (store, dir) = temp_store("legacy");
        seal_raw(&store, &serde_json::to_vec(&json!([legacy_json("old", "claude")])).unwrap());
        let loaded = store.load().unwrap();
        assert_eq!((loaded.len(), loaded[0].version, loaded[0].vault_id.as_deref()), (1, 1, None));
        for vault in [VAULT_A, VAULT_B] {
            assert!(find_matching(&loaded, "claude", Some(501), Transport::Uds, vault, 500).is_none());
        }

        // Saving it (any write does) keeps it unassigned: never auto-bound.
        store.touch("old", 600).unwrap();
        let reread = store.load().unwrap();
        assert_eq!((reread[0].version, reread[0].vault_id.as_deref()), (RECORD_VERSION, None));
        assert_eq!(reread[0].last_used_at, 600);
        assert!(find_matching(&reread, "claude", Some(501), Transport::Uds, VAULT_A, 700).is_none());

        // A new approval for vault A sits beside it; the legacy one is kept
        // for the operator to re-bind or revoke.
        store.upsert(record("new", "claude", Some(501), Transport::Uds)).unwrap();
        let both = store.load().unwrap();
        assert_eq!(both.len(), 2);
        assert_eq!(find_matching(&both, "claude", Some(501), Transport::Uds, VAULT_A, 700).unwrap().id, "new");
        fs::remove_dir_all(dir).ok();
    }

    /// T548: re-binding is explicit and one-way: it makes the record usable
    /// in exactly the chosen vault, never moves a bound one, and never
    /// creates a second grant for a slot that already has one.
    #[test]
    fn rebinding_makes_a_legacy_record_usable_only_in_the_chosen_vault() {
        let (store, dir) = temp_store("rebind");
        seal_raw(&store, &serde_json::to_vec(&json!([legacy_json("old", "claude")])).unwrap());

        assert!(store.rebind("old", "Not A Vault!").is_err(), "a malformed identity is refused");
        assert!(store.rebind("missing", VAULT_B).is_err());
        let rebound = store.rebind("old", VAULT_B).unwrap();
        assert_eq!((rebound.vault_id.as_deref(), rebound.version), (Some(VAULT_B), RECORD_VERSION));
        let loaded = store.load().unwrap();
        assert!(find_matching(&loaded, "claude", Some(501), Transport::Uds, VAULT_B, 500).is_some());
        assert!(find_matching(&loaded, "claude", Some(501), Transport::Uds, VAULT_A, 500).is_none());

        assert_eq!(store.rebind("old", VAULT_B).unwrap().id, "old", "idempotent for its own vault");
        let moved = store.rebind("old", VAULT_A).unwrap_err().to_string();
        assert!(moved.contains("another vault"), "{moved}");

        // A second legacy record for the same client cannot shadow the grant.
        let mut both = vec![legacy_json("old2", "claude")];
        both.push(serde_json::to_value(store.load().unwrap().remove(0)).unwrap());
        seal_raw(&store, &serde_json::to_vec(&both).unwrap());
        let clash = store.rebind("old2", VAULT_B).unwrap_err().to_string();
        assert!(clash.contains("already paired with this vault"), "{clash}");
        assert!(store.load().unwrap().iter().any(|r| r.id == "old2" && r.vault_id.is_none()), "left unassigned");
        fs::remove_dir_all(dir).ok();
    }

    /// T548: a record this build cannot read faithfully refuses the store
    /// rather than being dropped or rewritten without its newer fields.
    #[test]
    fn unknown_versions_and_malformed_vault_identities_are_refused() {
        let (store, dir) = temp_store("versions");
        let mut newer = serde_json::to_value(record("n", "x", None, Transport::Stdio)).unwrap();
        newer["version"] = json!(RECORD_VERSION + 1);
        let mut zero = serde_json::to_value(record("z", "x", None, Transport::Stdio)).unwrap();
        zero["version"] = json!(0);
        let mut v1_with_vault = legacy_json("v1", "x");
        v1_with_vault["vault_id"] = json!(VAULT_A);
        let mut bad_vault = serde_json::to_value(record("b", "x", None, Transport::Stdio)).unwrap();
        bad_vault["vault_id"] = json!("../../etc");
        let mut not_a_string = serde_json::to_value(record("s", "x", None, Transport::Stdio)).unwrap();
        not_a_string["vault_id"] = json!(7);
        for (label, bad) in [
            ("newer", newer),
            ("zero", zero),
            ("v1 with vault", v1_with_vault),
            ("bad vault", bad_vault),
            ("not a string", not_a_string),
        ] {
            seal_raw(&store, &serde_json::to_vec(&json!([bad])).unwrap());
            assert!(store.load().is_err(), "{label}");
        }
        seal_raw(&store, b"{\"not\": \"a list\"}");
        assert!(store.load().is_err());

        // A record with no `version` at all reads as the oldest format.
        let mut unversioned = legacy_json("u", "x");
        unversioned.as_object_mut().unwrap().remove("version");
        seal_raw(&store, &serde_json::to_vec(&json!([unversioned])).unwrap());
        assert_eq!(store.load().unwrap()[0].version, MIN_RECORD_VERSION);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_bound_record_round_trips_and_names_its_vault_on_disk() {
        let written = serde_json::to_value(record("a", "claude", None, Transport::Stdio)).unwrap();
        assert_eq!(written["vault_id"], json!(VAULT_A));
        assert_eq!(written["version"], json!(RECORD_VERSION));
        let back: PairingRecord = serde_json::from_value(written).unwrap();
        assert!(back.is_bound_to(VAULT_A) && !back.is_bound_to(VAULT_B) && !back.is_bound_to(""));
    }

    #[test]
    fn upsert_keeps_the_same_clients_grant_for_another_vault() {
        let (store, dir) = temp_store("upsert-vaults");
        store.upsert(record("a", "claude", Some(501), Transport::Uds)).unwrap();
        let mut in_b = record("b", "claude", Some(501), Transport::Uds);
        in_b.vault_id = Some(VAULT_B.to_string());
        store.upsert(in_b).unwrap();
        assert_eq!(store.load().unwrap().len(), 2, "one grant per vault");
        store.upsert(record("a2", "claude", Some(501), Transport::Uds)).unwrap();
        let ids: Vec<String> = store.load().unwrap().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["b".to_string(), "a2".to_string()], "vault A's grant replaced, vault B's kept");
        fs::remove_dir_all(dir).ok();
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
        // Opt-in tools are read-only but granted only by ticking them.
        for opt_in in crate::catalogue::OPT_IN_TOOLS {
            assert!(!tools.contains(&opt_in.to_string()), "{opt_in} must not be in the default grant");
        }
        // Session tools are never in it, the read-only web fetch included.
        for session_tool in ["bv_resource_ssh_exec", "bv_resource_web_fetch"] {
            assert!(!tools.contains(&session_tool.to_string()), "{session_tool} must not be in the default grant");
        }
    }
}
