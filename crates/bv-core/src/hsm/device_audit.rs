//! Device audit log drain primitives (T454 phase 6): the `device_audit` mode,
//! the `bv-auditor` credential, device log entries and their digest chain, and
//! the cursor a drain resumes from. The drain itself is
//! `HsmSealProvider::drain_device_logs`. Spec: `features/hsm-pool-ha.md` § Audit.

use std::fmt;

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        admin::{ADMIN_AUTH_KEY_ID, FACTORY_AUTH_KEY_ID},
        blob::HsmId,
        ceremony::NodeEnrollment,
    },
    storage::{Backend as PhysicalBackend, BackendEntry, Storage, StorageEntry},
};

/// `bv-auditor`'s authentication key id (spec § HSM object layout, object 8).
pub const AUDITOR_AUTH_KEY_ID: u16 = 8;
/// Bytes of the random `bv-auditor` credential.
pub const AUDITOR_KEY_LEN: usize = 32;
/// Entries a device log holds (circular unless forced audit is on).
pub const DEVICE_LOG_CAPACITY: usize = 62;
/// How often the drain runs while the vault is unsealed.
pub const DEVICE_AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// The cluster lock that keeps two drains apart.
pub const HSM_DEVICE_AUDIT_LOCK: &str = "hsm-device-audit";
/// Physical keyspace of the per-member drain cursors (no secret in them).
pub const AUDIT_CURSOR_PREFIX: &str = "core/hsm/audit-cursor/";
/// Barrier keyspace of the per-member `bv-auditor` credentials.
pub const AUDITOR_CREDENTIAL_PREFIX: &str = "core/hsm/auditor/";

const RECORD_VERSION: u8 = 1;

/// `device_audit` in a pool `hsm` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceAuditMode {
    /// Default: the device log is drained into the audit log every 5 s.
    #[default]
    Drain,
    /// As `drain`, and the device refuses loggable commands while its log is
    /// full (`LOG_FULL`): no unlogged command, at the price of availability.
    Forced,
    /// No drain. Refused in production.
    Off,
}

impl DeviceAuditMode {
    pub fn parse(raw: &str, production: bool) -> Result<Self, RvError> {
        match raw.trim() {
            "" | "drain" => Ok(Self::Drain),
            "forced" => Ok(Self::Forced),
            "off" if production => Err(RvError::ErrHsmConfigInvalid(
                "`device_audit = \"off\"` is refused in production: the device log would never be drained".into(),
            )),
            "off" => Ok(Self::Off),
            other => Err(RvError::ErrHsmConfigInvalid(format!(
                "`device_audit` must be \"drain\", \"forced\" or \"off\", got {other:?}"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Drain => "drain",
            Self::Forced => "forced",
            Self::Off => "off",
        }
    }
}

/// The `bv-auditor` credential for one device. Never printed; zeroized.
#[derive(Clone)]
pub struct AuditorCredential {
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AuditorCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditorCredential").field("key", &"<redacted>").finish()
    }
}

impl AuditorCredential {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new(vec![0u8; AUDITOR_KEY_LEN]);
        rand::rng().fill_bytes(key.as_mut_slice());
        Self { key }
    }

    pub fn from_key(key: Zeroizing<Vec<u8>>) -> Result<Self, RvError> {
        if key.len() != AUDITOR_KEY_LEN {
            return Err(RvError::ErrHsm(format!("a bv-auditor credential is {AUDITOR_KEY_LEN} bytes")));
        }
        Ok(Self { key })
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// YubiHSM 2 command codes the drain names in events (the rest print as hex).
pub fn command_name(code: u8) -> String {
    let name = match code {
        0x03 => "create-session",
        0x04 => "authenticate-session",
        0x44 => "put-authentication-key",
        0x4d => "get-log-entries",
        0x4e => "get-object-info",
        0x4f => "set-option",
        0x51 => "get-pseudo-random",
        0x54 => "get-public-key",
        0x56 => "sign-ecdsa",
        0x57 => "derive-ecdh",
        0x58 => "delete-object",
        0x5b => "generate-wrap-key",
        0x64 => "sign-attestation-certificate",
        0x67 => "set-log-index",
        0x68 => "wrap-data",
        0x69 => "unwrap-data",
        0x6a => "sign-eddsa",
        _ => return format!("{code:#04x}"),
    };
    name.to_string()
}

/// A device status byte of 0x00: success. The YubiHSM 2 writes it as the
/// result of its boot entries (phase 7 capture).
pub const DEVICE_RESULT_OK: u8 = 0x00;

/// One device log entry: the 16 data bytes the device chains and the
/// truncated SHA-256 digest that links it to the entry before. Layout and
/// chain are confirmed on a YubiHSM 2 by `testdata/yubihsm2-log-0036470559.json`
/// (spec § Phase 7 findings); a first drain anchors on the oldest entry
/// unverified, because the first entry after a reset chains from no value
/// in the log. `result` is the device's byte: see [`log_result_from_yubihsm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLogEntry {
    pub index: u16,
    pub command: u8,
    pub length: u16,
    pub session_key: u16,
    pub target_key: u16,
    pub second_key: u16,
    pub result: u8,
    pub systick: u32,
    pub digest: [u8; 16],
}

impl DeviceLogEntry {
    /// The entry's data as the device lays it out (big-endian, 16 bytes):
    /// index u16, command u8, length u16, session key u16, target key u16,
    /// second key u16, result u8, systick u32. The byte order and the chain
    /// are confirmed on hardware (see the type's documentation); which of the
    /// three key fields is which is confirmed only once a device logs a
    /// command, which a factory device with command audit off does not.
    pub fn data(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..2].copy_from_slice(&self.index.to_be_bytes());
        out[2] = self.command;
        out[3..5].copy_from_slice(&self.length.to_be_bytes());
        out[5..7].copy_from_slice(&self.session_key.to_be_bytes());
        out[7..9].copy_from_slice(&self.target_key.to_be_bytes());
        out[9..11].copy_from_slice(&self.second_key.to_be_bytes());
        out[11] = self.result;
        out[12..16].copy_from_slice(&self.systick.to_be_bytes());
        out
    }

    /// `SHA-256(data ‖ previous digest)[..16]`.
    pub fn chained_digest(&self, previous: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.data());
        hasher.update(previous);
        let full = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }
}

/// The device's result byte from yubihsm 0.42's `response::Code::to_u8()`.
/// That crate decodes device status bytes 0x00..=0x13 through a fallback that
/// re-encodes them as `0x75 - byte` (a boot entry's 0x00 reads 0x75), and
/// every other byte it accepts as itself; this undoes it. Its direct reading
/// of 0x62..=0x75 (host-side codes no device logs) collides: such a byte
/// would come back changed and break the digest chain, a gap, never a pass.
pub fn log_result_from_yubihsm(encoded: u8) -> u8 {
    match encoded {
        0x62..=0x75 => 0x75 - encoded,
        other => other,
    }
}

/// What `get-log-entries` returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceLog {
    pub unlogged_boot: u16,
    pub unlogged_auth: u16,
    pub entries: Vec<DeviceLogEntry>,
}

/// A session authenticated with `bv-auditor`: read and acknowledge the log.
#[maybe_async::maybe_async]
pub trait HsmAuditSession: Send + Sync {
    fn hsm_id(&self) -> Result<HsmId, RvError>;
    async fn get_log_entries(&self) -> Result<DeviceLog, RvError>;
    /// Acknowledge every entry up to `index` (`set-log-index`): in forced
    /// mode this is what frees the log for new commands.
    async fn set_log_index(&self, index: u16) -> Result<(), RvError>;
    /// Release the session slot (spec § Session budget: one for the drain).
    async fn close(&self) -> Result<(), RvError> {
        Ok(())
    }
}

/// Where a member's drain stopped: the last verified entry and the device's
/// unlogged-event counters, at `core/hsm/audit-cursor/<hsm_id>`. Physical
/// storage, no secret: an index, a digest the device prints anyway, counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCursor {
    pub version: u8,
    pub hsm_id: HsmId,
    pub last_index: u16,
    /// Hex of the last verified entry's digest.
    pub last_digest: String,
    pub unlogged_boot: u16,
    pub unlogged_auth: u16,
    pub drained_at: u64,
    /// The node that wrote the cursor. Another node finding a cursor younger
    /// than [`DEVICE_AUDIT_INTERVAL`] skips that member, so the cluster drains
    /// each device about once per interval rather than once per node.
    #[serde(default)]
    pub drained_by: String,
}

/// The outcome of checking one `get-log-entries` answer against the cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedLog {
    /// Entries after the cursor, in order.
    pub new_entries: Vec<DeviceLogEntry>,
    /// Each index jump, chain break or unlogged-event increase, described.
    pub gaps: Vec<String>,
}

/// Index `b` comes after `a` in the device's wrapping 16-bit numbering.
fn after(a: u16, b: u16) -> bool {
    let d = b.wrapping_sub(a);
    d != 0 && d < 0x8000
}

/// Check `log` against `cursor`. With the cursor's entry still in the log
/// (same digest), the entries after it are new and each must chain from the
/// one before. With it rolled out of the buffer and every entry later, the
/// oldest must chain from the cursor (else an index jump: overwritten before
/// the drain). Anything else is a reset or rewrite, and every entry is new.
/// Each jump, break, reset or counter change is a gap, never silent.
pub fn verify_log(
    cursor: Option<&AuditCursor>,
    log: &DeviceLog,
) -> Result<(VerifiedLog, Option<(u16, [u8; 16])>), RvError> {
    let mut out = VerifiedLog::default();
    let (start, mut previous) = match cursor {
        // The first drain anchors on the oldest entry it can see.
        None => (0, None),
        Some(c) => {
            let digest: [u8; 16] = hex::decode(&c.last_digest)
                .ok()
                .and_then(|d| d.try_into().ok())
                .ok_or_else(|| RvError::ErrHsm(format!("the audit cursor for {} is corrupt", c.hsm_id)))?;
            if (log.unlogged_boot, log.unlogged_auth) != (c.unlogged_boot, c.unlogged_auth) {
                let why = if log.unlogged_boot < c.unlogged_boot || log.unlogged_auth < c.unlogged_auth {
                    "the device's unlogged-event counters went back (device reset)"
                } else {
                    "the device reports unlogged events"
                };
                out.gaps.push(format!(
                    "{why}: boot {} -> {}, authentication {} -> {}",
                    c.unlogged_boot, log.unlogged_boot, c.unlogged_auth, log.unlogged_auth
                ));
            }
            match log.entries.iter().position(|e| e.index == c.last_index) {
                Some(pos) if log.entries[pos].digest == digest => (pos + 1, Some((c.last_index, digest))),
                Some(_) => {
                    out.gaps.push(format!(
                        "the device log no longer holds the drained entry {} (reset or rewritten); every entry is \
                         treated as new",
                        c.last_index
                    ));
                    (0, None)
                }
                None if log.entries.iter().all(|e| after(c.last_index, e.index)) => (0, Some((c.last_index, digest))),
                None => {
                    out.gaps.push(format!(
                        "the device log restarted below the drained entry {}; every entry is treated as new",
                        c.last_index
                    ));
                    (0, None)
                }
            }
        }
    };
    for entry in &log.entries[start..] {
        if let Some((last, digest)) = previous {
            if entry.index != last.wrapping_add(1) {
                out.gaps.push(format!("index jump {last} -> {}", entry.index));
            } else if entry.chained_digest(&digest) != entry.digest {
                out.gaps.push(format!("digest chain break at entry {}", entry.index));
            }
        }
        out.new_entries.push(*entry);
        previous = Some((entry.index, entry.digest));
    }
    Ok((out, previous))
}

/// Who ran a logged command: a fixed key's role, the node an enrollment maps
/// a node key to on this device (live first: a revoked slot may be reused),
/// or the bare id.
pub fn actor_of(session_key: u16, hsm_id: &HsmId, enrollments: &[NodeEnrollment]) -> String {
    match session_key {
        ADMIN_AUTH_KEY_ID => "bv-admin".into(),
        AUDITOR_AUTH_KEY_ID => "bv-auditor".into(),
        FACTORY_AUTH_KEY_ID => "factory-key".into(),
        key => {
            let holds = |e: &&NodeEnrollment| e.auth_keys.get(hsm_id) == Some(&key);
            let live = enrollments.iter().filter(|e| e.revoked.is_none()).find(holds);
            match live.or_else(|| enrollments.iter().find(holds)) {
                Some(e) if e.revoked.is_some() => format!("node {} (revoked)", e.node_id),
                Some(e) => format!("node {}", e.node_id),
                None => format!("auth key {key:#06x}"),
            }
        }
    }
}

/// The `hsm.device_log` detail of one entry. Names and numbers only.
pub fn describe(entry: &DeviceLogEntry, actor: &str) -> String {
    let ok = entry.result == 0x80 | entry.command || entry.result == DEVICE_RESULT_OK;
    let result = if ok { "ok".to_string() } else { format!("error({:#04x})", entry.result) };
    format!(
        "index={} command={} auth_key={:#06x} actor={actor} target={:#06x} result={result} systick={}",
        entry.index,
        command_name(entry.command),
        entry.session_key,
        entry.target_key,
        entry.systick
    )
}

fn member_key(hsm_id: &HsmId) -> String {
    hsm_id.as_str().replace(':', "_")
}

#[maybe_async::maybe_async]
pub async fn read_cursor(physical: &dyn PhysicalBackend, hsm_id: &HsmId) -> Result<Option<AuditCursor>, RvError> {
    let Some(entry) = physical.get(&format!("{AUDIT_CURSOR_PREFIX}{}", member_key(hsm_id))).await? else {
        return Ok(None);
    };
    let cursor: AuditCursor = serde_json::from_slice(&entry.value)
        .map_err(|e| RvError::ErrHsm(format!("the audit cursor for {hsm_id} is corrupt: {e}")))?;
    if cursor.version != RECORD_VERSION || cursor.hsm_id != *hsm_id {
        return Err(RvError::ErrHsm(format!("the audit cursor for {hsm_id} names another version or device")));
    }
    Ok(Some(cursor))
}

#[maybe_async::maybe_async]
pub async fn write_cursor(physical: &dyn PhysicalBackend, cursor: &AuditCursor) -> Result<(), RvError> {
    let value = serde_json::to_vec(cursor).map_err(|e| RvError::ErrHsm(format!("audit cursor encode: {e}")))?;
    physical.put(&BackendEntry { key: format!("{AUDIT_CURSOR_PREFIX}{}", member_key(&cursor.hsm_id)), value }).await
}

impl AuditCursor {
    pub fn new(hsm_id: &HsmId, last: (u16, [u8; 16]), log: &DeviceLog, drained_at: u64, drained_by: &str) -> Self {
        Self {
            version: RECORD_VERSION,
            hsm_id: hsm_id.clone(),
            last_index: last.0,
            last_digest: hex::encode(last.1),
            unlogged_boot: log.unlogged_boot,
            unlogged_auth: log.unlogged_auth,
            drained_at,
            drained_by: drained_by.to_string(),
        }
    }

    /// Another node drained this member less than an interval ago.
    pub fn fresh_from_another_node(&self, node_id: &str, now: u64) -> bool {
        self.drained_by != node_id && now.saturating_sub(self.drained_at) < DEVICE_AUDIT_INTERVAL.as_secs()
    }
}

#[derive(Serialize, Deserialize)]
struct StoredAuditor {
    version: u8,
    hsm_id: HsmId,
    /// Hex of the credential; wiped when the record is dropped.
    key: String,
}

impl Drop for StoredAuditor {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// The `bv-auditor` credential for `hsm_id`, from the barrier (the drain runs
/// only while unsealed, so it never needs one in the clear on disk).
#[maybe_async::maybe_async]
pub async fn read_auditor(barrier: &dyn Storage, hsm_id: &HsmId) -> Result<Option<AuditorCredential>, RvError> {
    let Some(mut entry) = barrier.get(&format!("{AUDITOR_CREDENTIAL_PREFIX}{}", member_key(hsm_id))).await? else {
        return Ok(None);
    };
    let parsed = serde_json::from_slice::<StoredAuditor>(&entry.value);
    zeroize::Zeroize::zeroize(&mut entry.value);
    let stored = parsed.map_err(|_| RvError::ErrHsm(format!("the bv-auditor credential for {hsm_id} is corrupt")))?;
    if stored.version != RECORD_VERSION || stored.hsm_id != *hsm_id {
        return Err(RvError::ErrHsm(format!("the bv-auditor credential for {hsm_id} names another device")));
    }
    let key =
        Zeroizing::new(hex::decode(&stored.key).map_err(|_| RvError::ErrHsm("bv-auditor key is not hex".into()))?);
    AuditorCredential::from_key(key).map(Some)
}

#[maybe_async::maybe_async]
pub async fn write_auditor(
    barrier: &dyn Storage,
    hsm_id: &HsmId,
    credential: &AuditorCredential,
) -> Result<(), RvError> {
    let stored = StoredAuditor { version: RECORD_VERSION, hsm_id: hsm_id.clone(), key: hex::encode(credential.key()) };
    // The barrier encrypts the value; this is the one plaintext copy handed to it.
    let value = serde_json::to_vec(&stored).map_err(|e| RvError::ErrHsm(format!("bv-auditor record encode: {e}")))?;
    let entry = StorageEntry { key: format!("{AUDITOR_CREDENTIAL_PREFIX}{}", member_key(hsm_id)), value };
    let written = barrier.put(&entry).await;
    let mut entry = entry;
    zeroize::Zeroize::zeroize(&mut entry.value);
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(start: u16, n: u16, mut prev: [u8; 16]) -> Vec<DeviceLogEntry> {
        (0..n)
            .map(|i| {
                let mut e = DeviceLogEntry {
                    index: start.wrapping_add(i),
                    command: 0x68,
                    length: 40,
                    session_key: 0x100,
                    target_key: 2,
                    second_key: 0xffff,
                    result: 0x80 | 0x68,
                    systick: 1000 + u32::from(i),
                    digest: [0; 16],
                };
                e.digest = e.chained_digest(&prev);
                prev = e.digest;
                e
            })
            .collect()
    }

    fn id() -> HsmId {
        HsmId::from_parts("mock", "A").unwrap()
    }

    #[test]
    fn modes_parse_and_off_is_refused_in_production() {
        assert_eq!(DeviceAuditMode::parse("", false).unwrap(), DeviceAuditMode::Drain);
        assert_eq!(DeviceAuditMode::parse("forced", true).unwrap(), DeviceAuditMode::Forced);
        assert_eq!(DeviceAuditMode::parse("off", false).unwrap(), DeviceAuditMode::Off);
        assert!(DeviceAuditMode::parse("off", true).is_err());
        assert!(DeviceAuditMode::parse("sometimes", false).is_err());
    }

    #[test]
    fn a_continuous_chain_verifies_and_resumes_from_the_cursor() {
        let entries = chain(1, 5, [0; 16]);
        let log = DeviceLog { entries: entries.clone(), ..Default::default() };
        let (first, last) = verify_log(None, &log).unwrap();
        assert_eq!((first.new_entries.len(), first.gaps.len()), (5, 0));
        let cursor = AuditCursor::new(&id(), last.unwrap(), &log, 1, "n1");
        assert_eq!(cursor.last_index, 5);

        let mut more = entries.clone();
        more.extend(chain(6, 3, entries[4].digest));
        let (next, last) = verify_log(Some(&cursor), &DeviceLog { entries: more, ..Default::default() }).unwrap();
        assert_eq!(next.new_entries.iter().map(|e| e.index).collect::<Vec<_>>(), vec![6, 7, 8]);
        assert!(next.gaps.is_empty(), "{:?}", next.gaps);
        assert_eq!(last.unwrap().0, 8);
    }

    #[test]
    fn jumps_breaks_and_unlogged_events_are_gaps_never_silent() {
        let entries = chain(1, 3, [0; 16]);
        let cursor = AuditCursor::new(&id(), (3, entries[2].digest), &DeviceLog::default(), 1, "n1");

        // Overflow: entries 4..=9 were overwritten before the drain ran.
        let jumped = chain(10, 2, [7; 16]);
        let (v, _) = verify_log(Some(&cursor), &DeviceLog { entries: jumped, ..Default::default() }).unwrap();
        assert_eq!(v.gaps, vec!["index jump 3 -> 10".to_string()]);
        assert_eq!(v.new_entries.len(), 2, "the entries after the gap are still verified and kept");

        // The cursor's entry rolled out, but nothing was lost: no gap.
        let rolled = chain(4, 2, entries[2].digest);
        let (v, _) = verify_log(Some(&cursor), &DeviceLog { entries: rolled, ..Default::default() }).unwrap();
        assert!(v.gaps.is_empty() && v.new_entries.len() == 2, "{v:?}");

        let mut tampered = chain(4, 2, entries[2].digest);
        tampered[0].result = 0x01;
        let (v, _) = verify_log(Some(&cursor), &DeviceLog { entries: tampered, ..Default::default() }).unwrap();
        assert_eq!(v.gaps, vec!["digest chain break at entry 4".to_string()]);

        let unlogged = DeviceLog { unlogged_auth: 2, ..Default::default() };
        let (v, _) = verify_log(Some(&cursor), &unlogged).unwrap();
        assert!(v.gaps[0].contains("unlogged"), "{:?}", v.gaps);

        let mut corrupt = cursor.clone();
        corrupt.last_digest = "zz".into();
        assert!(verify_log(Some(&corrupt), &DeviceLog::default()).is_err());
    }

    #[test]
    fn a_reset_or_rewritten_log_is_a_gap_and_nothing_is_skipped() {
        let entries = chain(1, 50, [0; 16]);
        let log = DeviceLog { entries: entries[40..].to_vec(), ..Default::default() };
        let cursor = AuditCursor::new(&id(), (50, entries[49].digest), &log, 1, "n1");

        // Power cycle: the index restarts at 1, below the cursor.
        let restarted = DeviceLog { entries: chain(1, 3, [0; 16]), unlogged_boot: 0, ..Default::default() };
        let (v, last) = verify_log(Some(&cursor), &restarted).unwrap();
        assert!(v.gaps[0].contains("restarted below the drained entry 50"), "{:?}", v.gaps);
        assert_eq!(v.new_entries.len(), 3, "every entry of the new log is drained");
        assert_eq!(last.unwrap().0, 3);

        // Same index as the cursor, another digest: rewritten, not resumed.
        let rewritten = chain(48, 4, [9; 16]);
        let (v, _) = verify_log(Some(&cursor), &DeviceLog { entries: rewritten, ..Default::default() }).unwrap();
        assert!(v.gaps[0].contains("no longer holds the drained entry 50"), "{:?}", v.gaps);
        assert_eq!(v.new_entries.len(), 4);

        // Counters that go back are a reset too.
        let mut counted = cursor.clone();
        counted.unlogged_boot = 3;
        let (v, _) = verify_log(Some(&counted), &DeviceLog::default()).unwrap();
        assert!(v.gaps[0].contains("went back"), "{:?}", v.gaps);
    }

    #[test]
    fn indexes_wrap_around() {
        let entries = chain(0xfffe, 4, [0; 16]);
        assert_eq!(entries.iter().map(|e| e.index).collect::<Vec<_>>(), vec![0xfffe, 0xffff, 0, 1]);
        let cursor = AuditCursor::new(&id(), (0xffff, entries[1].digest), &DeviceLog::default(), 1, "n1");
        let (v, last) = verify_log(Some(&cursor), &DeviceLog { entries, ..Default::default() }).unwrap();
        assert_eq!(v.new_entries.iter().map(|e| e.index).collect::<Vec<_>>(), vec![0, 1]);
        assert!(v.gaps.is_empty() && last.unwrap().0 == 1);
    }

    #[test]
    fn cursors_name_their_node_and_actors_map_to_nodes() {
        let cursor = AuditCursor::new(&id(), (1, [0; 16]), &DeviceLog::default(), 100, "n1");
        assert!(!cursor.fresh_from_another_node("n1", 101), "a node never skips its own drain");
        assert!(cursor.fresh_from_another_node("n2", 101));
        assert!(!cursor.fresh_from_another_node("n2", 100 + DEVICE_AUDIT_INTERVAL.as_secs()));
        // A cursor written before `drained_by` existed reads as nobody's.
        let mut old = serde_json::to_value(&cursor).unwrap();
        old.as_object_mut().unwrap().remove("drained_by");
        let old: AuditCursor = serde_json::from_value(old).unwrap();
        assert!(old.drained_by.is_empty());

        assert_eq!(actor_of(2, &id(), &[]), "bv-admin");
        assert_eq!(actor_of(AUDITOR_AUTH_KEY_ID, &id(), &[]), "bv-auditor");
        assert_eq!(actor_of(0x105, &id(), &[]), "auth key 0x0105");
        let entry = chain(1, 1, [0; 16])[0];
        let text = describe(&entry, "node n1");
        assert!(text.contains("command=wrap-data") && text.contains("result=ok") && text.contains("actor=node n1"));
    }

    /// The phase 7 capture from a factory-state YubiHSM 2, as the harness
    /// first recorded it (provenance in the file).
    const REAL_LOG: &str = include_str!("testdata/yubihsm2-log-0036470559.json");

    #[derive(Deserialize)]
    struct RealFixture {
        capture: RealCapture,
    }

    #[derive(Deserialize)]
    struct RealCapture {
        unlogged_boot: u16,
        unlogged_auth: u16,
        entries: Vec<DeviceLogEntry>,
    }

    fn recorded_log() -> DeviceLog {
        let real: RealFixture = serde_json::from_str(REAL_LOG).unwrap();
        let c = real.capture;
        DeviceLog { unlogged_boot: c.unlogged_boot, unlogged_auth: c.unlogged_auth, entries: c.entries }
    }

    /// The log as the device wrote it: the recorded results decoded back.
    fn real_log() -> DeviceLog {
        let mut log = recorded_log();
        for e in &mut log.entries {
            e.result = log_result_from_yubihsm(e.result);
        }
        log
    }

    fn indexes(entries: &[DeviceLogEntry]) -> Vec<u16> {
        entries.iter().map(|e| e.index).collect()
    }

    fn gaps(log: &DeviceLog) -> Vec<String> {
        verify_log(None, log).unwrap().0.gaps
    }

    #[test]
    fn the_real_yubihsm2_log_verifies_link_by_link() {
        let log = real_log();
        assert_eq!(indexes(&log.entries), (1..=8).collect::<Vec<_>>());
        assert!(log.entries[1..].iter().all(|e| e.command == 0 && e.result == DEVICE_RESULT_OK && e.systick == 0));
        // Entry 2's data, byte for byte, and every link recomputed.
        assert_eq!(hex::encode(log.entries[1].data()), "0002000000ffff000000000000000000");
        for pair in log.entries.windows(2) {
            assert_eq!(pair[1].chained_digest(&pair[0].digest), pair[1].digest, "entry {}", pair[1].index);
        }
        let (v, last) = verify_log(None, &log).unwrap();
        assert!(v.gaps.is_empty(), "{:?}", v.gaps);
        assert_eq!(indexes(&v.new_entries), (1..=8).collect::<Vec<_>>());
        assert_eq!(last, Some((8, log.entries[7].digest)));
        // The first entry chains from a value the log does not hold.
        assert_ne!(log.entries[0].chained_digest(&[0; 16]), log.entries[0].digest);
        assert_ne!(log.entries[0].chained_digest(&[0xff; 16]), log.entries[0].digest);
        // A boot entry is a success, not an error.
        assert!(describe(&log.entries[1], "boot").contains("result=ok"));
    }

    #[test]
    fn the_capture_as_first_recorded_breaks_every_link() {
        // Regression: the result bytes as yubihsm's re-encoding left them
        // (0x75 for the device's 0x00) are what the first run reported.
        let recorded = recorded_log();
        assert!(recorded.entries[1..].iter().all(|e| e.result == 0x75));
        assert_eq!(gaps(&recorded), (2..=8).map(|i| format!("digest chain break at entry {i}")).collect::<Vec<_>>());
    }

    #[test]
    fn the_real_log_resumes_from_a_cursor_and_reports_tampering() {
        let log = real_log();
        let cursor = AuditCursor::new(&id(), (4, log.entries[3].digest), &log, 1, "n1");
        let (v, last) = verify_log(Some(&cursor), &log).unwrap();
        assert!(v.gaps.is_empty(), "{:?}", v.gaps);
        assert_eq!((indexes(&v.new_entries), last.unwrap().0), (vec![5, 6, 7, 8], 8));

        // A changed field breaks the link into that entry only.
        let mut changed = log.clone();
        changed.entries[4].systick = 1;
        assert_eq!(gaps(&changed), vec!["digest chain break at entry 5".to_string()]);
        // A changed digest breaks the links into and out of it.
        let mut digest = log.clone();
        digest.entries[4].digest[0] ^= 1;
        assert_eq!(gaps(&digest), vec!["digest chain break at entry 5", "digest chain break at entry 6"]);
        // Reordered.
        let mut swapped = log.clone();
        swapped.entries.swap(4, 5);
        assert_eq!(gaps(&swapped), vec!["index jump 4 -> 6", "index jump 6 -> 5", "index jump 5 -> 7"]);
        // Dropped.
        let mut dropped = log.clone();
        dropped.entries.remove(4);
        assert_eq!(gaps(&dropped), vec!["index jump 4 -> 6"]);
        // Dropped and renumbered to hide it: every renumbered link breaks.
        let mut hidden = dropped.clone();
        for e in &mut hidden.entries[4..] {
            e.index -= 1;
        }
        assert_eq!(
            gaps(&hidden),
            vec!["digest chain break at entry 5", "digest chain break at entry 6", "digest chain break at entry 7"]
        );
        // A cursor whose entry the log holds with another digest is a rewrite.
        let mut stale = cursor.clone();
        stale.last_digest = hex::encode([0u8; 16]);
        let (v, _) = verify_log(Some(&stale), &log).unwrap();
        assert!(v.gaps[0].contains("no longer holds the drained entry 4"), "{:?}", v.gaps);
        assert_eq!(v.new_entries.len(), 8, "every entry is drained again, none skipped");
    }

    #[test]
    fn result_bytes_outside_the_yubihsm_fallback_pass_through() {
        assert_eq!(log_result_from_yubihsm(0x75), 0x00);
        assert_eq!(log_result_from_yubihsm(0x62), 0x13);
        for byte in (0x00..0x62).chain(0x76..=0xff) {
            assert_eq!(log_result_from_yubihsm(byte), byte);
        }
    }

    /// Pins the yubihsm crate's decoding: an upgrade that changes it fails here.
    #[cfg(feature = "hsm_yubihsm2")]
    #[test]
    fn yubihsm_result_codes_decode_back_to_the_device_byte() {
        use serde::de::value::{Error, U8Deserializer};
        use yubihsm::{command, response::Code};
        let crate_reads = |raw: u8| Code::deserialize(U8Deserializer::<Error>::new(raw)).map(Code::to_u8).unwrap();
        // The phase 7 finding: a boot entry's 0x00 comes back as 0x75.
        assert_eq!(crate_reads(0x00), 0x75);
        // Device status bytes, the error command and every success byte.
        let success = (0u8..=0x7f).filter(|c| command::Code::from_u8(*c).is_ok()).map(|c| 0x80 | c);
        for raw in (0x00..=0x13).chain([0x7f]).chain(success) {
            assert_eq!(log_result_from_yubihsm(crate_reads(raw)), raw, "{raw:#04x}");
        }
        // The collision the decoding documents.
        assert_eq!(crate_reads(0x75), crate_reads(0x00));
    }

    #[test]
    fn the_auditor_credential_never_prints() {
        let c = AuditorCredential::generate();
        assert!(!format!("{c:?}").contains(&hex::encode(c.key())));
        assert!(AuditorCredential::from_key(Zeroizing::new(vec![1; 3])).is_err());
    }
}
