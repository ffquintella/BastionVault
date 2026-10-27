//! T454 phase 7 hardware validation: the harness's logic, apart from the
//! device, so it is unit-tested without one. The device half is [`device`]
//! (feature `hsm_hardware_tests`), the driver is `tests/hsm_pool_hardware.rs`
//! and the operator runbook is `docs/hsm.md` § Phase 7 hardware validation.
//! It never resets a device, updates firmware, enables FIPS mode or sets an
//! audit option: the only writes are `provision` and one test node key.

#[cfg(feature = "hsm_hardware_tests")]
pub mod device;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        admin::FACTORY_PASSWORD,
        attestation::{format_serial, parse_serial, CertificateSummary},
        device_audit::{verify_log, DeviceLog, DeviceLogEntry},
    },
};

/// `1` runs the suite; anything else (or unset) skips it.
pub const ENV_ENABLE: &str = "BVAULT_TEST_YUBIHSM_POOL";
/// Comma-separated serials of the two devices the run may touch, nothing else.
pub const ENV_SERIALS: &str = "BVAULT_TEST_YUBIHSM_SERIALS";
/// `snapshot` (default), `validate` or `compare`.
pub const ENV_STEP: &str = "BVAULT_TEST_YUBIHSM_STEP";
/// Stop after this step (inclusive), e.g. `preflight`.
pub const ENV_UNTIL: &str = "BVAULT_TEST_YUBIHSM_UNTIL";
/// `1` opens the gate before `provision`; required for any write.
pub const ENV_ALLOW_WRITES: &str = "BVAULT_TEST_YUBIHSM_ALLOW_WRITES";
pub const ENV_OUT_DIR: &str = "BVAULT_TEST_YUBIHSM_OUT";
pub const ENV_CONNECTOR_BIN: &str = "BVAULT_TEST_YUBIHSM_CONNECTOR";
pub const ENV_PORT_BASE: &str = "BVAULT_TEST_YUBIHSM_PORT_BASE";
pub const ENV_FACTORY_PASSWORD: &str = "BVAULT_TEST_YUBIHSM_FACTORY_PASSWORD";
pub const ENV_ADMIN_PASSWORD: &str = "BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD";
pub const ENV_ATTESTATION_ROOTS: &str = "BVAULT_TEST_YUBICO_ATTESTATION_ROOTS";
pub const ENV_LATENCY_ITERATIONS: &str = "BVAULT_TEST_YUBIHSM_LATENCY_ITERATIONS";

const DEFAULT_PORT_BASE: u16 = 12345;
const DEFAULT_LATENCY_ITERATIONS: usize = 20;
const MAX_LATENCY_ITERATIONS: usize = 1000;
/// The two devices of a pool, exactly.
pub const DEVICES: usize = 2;
pub const SNAPSHOT_FORMAT: u32 = 1;
/// Written once by the `snapshot` step and never replaced.
pub const BEFORE_SNAPSHOT_FILE: &str = "snapshot-before.json";

/// Each `compare` run keeps its own "after" snapshot.
pub fn after_snapshot_file(taken_at_unix: u64) -> String {
    format!("snapshot-after-{taken_at_unix}.json")
}

pub fn harness_error(why: impl fmt::Display) -> RvError {
    RvError::ErrHsm(format!("phase 7 harness: {why}"))
}

/// A password from the environment: zeroized on drop, never printed.
pub struct EnvSecret(Zeroizing<String>);

impl fmt::Debug for EnvSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnvSecret(<redacted>)")
    }
}

impl EnvSecret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// The factory key's password: the variable, else the published default.
pub fn factory_password(get: impl Fn(&str) -> Option<String>) -> EnvSecret {
    EnvSecret(Zeroizing::new(get(ENV_FACTORY_PASSWORD).filter(|v| !v.is_empty()).unwrap_or(FACTORY_PASSWORD.into())))
}

/// The test `bv-admin` password `provision` installs: required, never the
/// factory one, only from the environment.
pub fn admin_password(get: impl Fn(&str) -> Option<String>) -> Result<EnvSecret, RvError> {
    let value = Zeroizing::new(get(ENV_ADMIN_PASSWORD).unwrap_or_default());
    if value.is_empty() {
        return Err(harness_error(format!("{ENV_ADMIN_PASSWORD} must hold the test bv-admin password")));
    }
    if value.as_str() == FACTORY_PASSWORD || Some(value.as_str()) == get(ENV_FACTORY_PASSWORD).as_deref() {
        return Err(harness_error(format!("{ENV_ADMIN_PASSWORD} must differ from the factory password")));
    }
    Ok(EnvSecret(value))
}

/// Which invocation this is. Each runs a fixed, ordered list of [`Step`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Read-only: record the "before" snapshot and run the preflight.
    Snapshot,
    /// The run: re-check the before state, then (gated) provision and test.
    Validate,
    /// After the physical reset, read-only: snapshot again and diff.
    Compare,
}

impl Mode {
    pub fn parse(text: &str) -> Result<Self, RvError> {
        match text.trim() {
            "" | "snapshot" => Ok(Mode::Snapshot),
            "validate" => Ok(Mode::Validate),
            "compare" => Ok(Mode::Compare),
            other => {
                refuse_forbidden(other)?;
                Err(harness_error(format!("{ENV_STEP}={other:?}: expected snapshot, validate or compare")))
            }
        }
    }
}

/// What a step does to a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    /// Nothing on a device, or reads only (the device log still counts the
    /// session).
    ReadOnly,
    /// Device commands that create or delete no object (wrap, sign, ECDH).
    Uses,
    /// Creates or deletes objects. Behind [`ENV_ALLOW_WRITES`].
    Writes,
}

/// One harness step, in the order the modes run them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    StartConnectors,
    Snapshot,
    Preflight,
    /// The device still reads exactly as the saved "before" snapshot.
    MatchBefore,
    SaveSnapshot,
    LoadAnchors,
    Provision,
    Attest,
    EnrollTestNode,
    DualWrap,
    Relay,
    Latency,
    RevokeTestNode,
    ResetInstructions,
}

const ALL_STEPS: &[Step] = &[
    Step::StartConnectors,
    Step::Snapshot,
    Step::Preflight,
    Step::MatchBefore,
    Step::SaveSnapshot,
    Step::LoadAnchors,
    Step::Provision,
    Step::Attest,
    Step::EnrollTestNode,
    Step::DualWrap,
    Step::Relay,
    Step::Latency,
    Step::RevokeTestNode,
    Step::ResetInstructions,
];

const SNAPSHOT_STEPS: &[Step] = &[Step::StartConnectors, Step::Snapshot, Step::Preflight, Step::SaveSnapshot];
const VALIDATE_STEPS: &[Step] = &[
    Step::StartConnectors,
    Step::Snapshot,
    Step::MatchBefore,
    Step::Preflight,
    Step::LoadAnchors,
    Step::Provision,
    Step::Attest,
    Step::EnrollTestNode,
    Step::DualWrap,
    Step::Relay,
    Step::Latency,
    Step::RevokeTestNode,
    Step::ResetInstructions,
];
/// The "after" snapshot is saved before it is judged, so a failed comparison
/// still leaves its evidence on disk.
const COMPARE_STEPS: &[Step] =
    &[Step::StartConnectors, Step::Snapshot, Step::SaveSnapshot, Step::Preflight, Step::MatchBefore];

/// Operations the harness never performs, and why; asking for one by name is
/// refused with the reason instead of "unknown step".
const FORBIDDEN: &[(&str, &str)] = &[
    ("reset", "a device is reset only by the operator, physically (rim pressed for 10 s while inserting it)"),
    ("factory-reset", "a device is reset only by the operator, physically (rim pressed for 10 s while inserting it)"),
    ("firmware", "firmware updates are irreversible and out of scope for phase 7"),
    ("firmware-update", "firmware updates are irreversible and out of scope for phase 7"),
    ("fips", "FIPS mode is a separate, explicitly approved step (features/hsm-pool-ha.md)"),
    ("fips-mode", "FIPS mode is a separate, explicitly approved step (features/hsm-pool-ha.md)"),
    ("command-audit", "enforced (fix) command audit may survive only a reset; it is a separate, approved step"),
    ("force-audit", "forced audit is confirmed in a separate, approved step"),
    ("audit-fix", "enforced (fix) command audit may survive only a reset; it is a separate, approved step"),
    ("production-provision", "the run ends one step before the production provision, which the operator runs"),
];

fn refuse_forbidden(name: &str) -> Result<(), RvError> {
    match FORBIDDEN.iter().find(|(n, _)| *n == name) {
        Some((n, why)) => Err(harness_error(format!("the harness never runs {n:?}: {why}"))),
        None => Ok(()),
    }
}

impl Step {
    pub fn name(&self) -> &'static str {
        match self {
            Step::StartConnectors => "connectors",
            Step::Snapshot => "snapshot",
            Step::Preflight => "preflight",
            Step::MatchBefore => "match-before",
            Step::SaveSnapshot => "save-snapshot",
            Step::LoadAnchors => "anchors",
            Step::Provision => "provision",
            Step::Attest => "attest",
            Step::EnrollTestNode => "enroll-test-node",
            Step::DualWrap => "dual-wrap",
            Step::Relay => "relay",
            Step::Latency => "latency",
            Step::RevokeTestNode => "revoke-test-node",
            Step::ResetInstructions => "reset-instructions",
        }
    }

    pub fn effect(&self) -> Effect {
        match self {
            Step::Provision | Step::EnrollTestNode | Step::RevokeTestNode => Effect::Writes,
            Step::DualWrap | Step::Relay | Step::Latency => Effect::Uses,
            _ => Effect::ReadOnly,
        }
    }

    pub fn parse(text: &str) -> Result<Self, RvError> {
        let text = text.trim();
        refuse_forbidden(text)?;
        ALL_STEPS.iter().copied().find(|s| s.name() == text).ok_or_else(|| {
            let names: Vec<_> = ALL_STEPS.iter().map(Step::name).collect();
            harness_error(format!("unknown step {text:?}; steps are {}", names.join(", ")))
        })
    }
}

/// The steps `mode` runs, cut after `until`, refused as a whole when any of
/// them writes and the gate is closed: the plan never silently stops short.
pub fn plan(mode: Mode, until: Option<Step>, allow_writes: bool) -> Result<Vec<Step>, RvError> {
    let all = match mode {
        Mode::Snapshot => SNAPSHOT_STEPS,
        Mode::Validate => VALIDATE_STEPS,
        Mode::Compare => COMPARE_STEPS,
    };
    let steps = match until {
        None => all.to_vec(),
        Some(last) => {
            let at = all.iter().position(|s| *s == last).ok_or_else(|| {
                harness_error(format!("{ENV_UNTIL}={} is not a step of {mode:?}", last.name()))
            })?;
            all[..=at].to_vec()
        }
    };
    if let Some(first) = steps.iter().find(|s| s.effect() == Effect::Writes) {
        if !allow_writes {
            return Err(harness_error(format!(
                "step {:?} writes to the devices; set {ENV_ALLOW_WRITES}=1 to allow it, or {ENV_UNTIL}=anchors to \
                 stop before it",
                first.name()
            )));
        }
    }
    Ok(steps)
}

/// The two serials the run may touch. Any other device is refused before a
/// single authenticated command reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialAllowlist(BTreeSet<u32>);

impl SerialAllowlist {
    pub fn parse(text: &str) -> Result<Self, RvError> {
        let mut set = BTreeSet::new();
        for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let serial = parse_serial(part).map_err(|e| harness_error(format!("{ENV_SERIALS}: {e}")))?;
            if serial == 0 || !set.insert(serial) {
                return Err(harness_error(format!("{ENV_SERIALS}: {part:?} is zero or listed twice")));
            }
        }
        if set.len() != DEVICES {
            return Err(harness_error(format!(
                "{ENV_SERIALS} must name exactly {DEVICES} devices (the pool), got {}",
                set.len()
            )));
        }
        Ok(Self(set))
    }

    pub fn serials(&self) -> Vec<u32> {
        self.0.iter().copied().collect()
    }

    pub fn check(&self, serial: u32, seen_by: &str) -> Result<(), RvError> {
        if self.0.contains(&serial) {
            Ok(())
        } else {
            Err(harness_error(format!(
                "{seen_by} reports serial {}, which is not in {ENV_SERIALS}; refusing to touch it",
                format_serial(serial)
            )))
        }
    }
}

/// Everything the driver reads from the environment, except passwords,
/// which are read by the step that needs them.
#[derive(Debug, Clone)]
pub struct HarnessEnv {
    pub mode: Mode,
    pub until: Option<Step>,
    pub allow_writes: bool,
    pub serials: SerialAllowlist,
    pub out_dir: PathBuf,
    pub connector_bin: PathBuf,
    pub port_base: u16,
    pub attestation_roots: Option<PathBuf>,
    pub latency_iterations: usize,
}

impl HarnessEnv {
    /// `Ok(None)` unless [`ENV_ENABLE`] is exactly `1`: the suite is skipped.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, RvError> {
        if get(ENV_ENABLE).as_deref() != Some("1") {
            return Ok(None);
        }
        let mode = Mode::parse(&get(ENV_STEP).unwrap_or_default())?;
        let until = get(ENV_UNTIL).filter(|v| !v.trim().is_empty()).map(|v| Step::parse(&v)).transpose()?;
        let allow_writes = match get(ENV_ALLOW_WRITES).as_deref().map(str::trim) {
            None | Some("") | Some("0") => false,
            Some("1") => true,
            Some(other) => return Err(harness_error(format!("{ENV_ALLOW_WRITES}={other:?}: expected 1 or unset"))),
        };
        let serials = SerialAllowlist::parse(
            &get(ENV_SERIALS).ok_or_else(|| harness_error(format!("{ENV_SERIALS} is required (two serials)")))?,
        )?;
        let out_dir = PathBuf::from(
            get(ENV_OUT_DIR).ok_or_else(|| harness_error(format!("{ENV_OUT_DIR} is required (a directory)")))?,
        );
        let connector_bin = PathBuf::from(get(ENV_CONNECTOR_BIN).unwrap_or_else(|| "yubihsm-connector".into()));
        let port_base = match get(ENV_PORT_BASE) {
            None => DEFAULT_PORT_BASE,
            Some(v) => v
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p >= 1024 && *p < u16::MAX)
                .ok_or_else(|| harness_error(format!("{ENV_PORT_BASE}={v:?}: expected a port 1024-65534")))?,
        };
        let attestation_roots = get(ENV_ATTESTATION_ROOTS).filter(|v| !v.trim().is_empty()).map(PathBuf::from);
        let latency_iterations = match get(ENV_LATENCY_ITERATIONS) {
            None => DEFAULT_LATENCY_ITERATIONS,
            Some(v) => v.trim().parse::<usize>().ok().filter(|n| (1..=MAX_LATENCY_ITERATIONS).contains(n)).ok_or_else(
                || harness_error(format!("{ENV_LATENCY_ITERATIONS}={v:?}: expected 1-{MAX_LATENCY_ITERATIONS}")),
            )?,
        };
        Ok(Some(Self {
            mode,
            until,
            allow_writes,
            serials,
            out_dir,
            connector_bin,
            port_base,
            attestation_roots,
            latency_iterations,
        }))
    }

    pub fn from_env() -> Result<Option<Self>, RvError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Connector port of the `index`th device (allow-list order).
    pub fn port(&self, index: usize) -> Result<u16, RvError> {
        u16::try_from(index)
            .ok()
            .and_then(|i| self.port_base.checked_add(i))
            .ok_or_else(|| harness_error("connector port out of range"))
    }
}

/// `yubihsm-connector` arguments: loopback only, one device by serial.
pub fn connector_args(serial: u32, port: u16) -> Vec<String> {
    vec!["--listen".into(), format!("127.0.0.1:{port}"), "--serial".into(), format_serial(serial)]
}

/// `GET /connector/status` as `key=value` lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorStatus {
    pub status: String,
    pub serial: Option<String>,
    pub version: Option<String>,
}

pub fn parse_connector_status(body: &str) -> ConnectorStatus {
    let mut out = ConnectorStatus::default();
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key.trim() {
            "status" => out.status = value,
            "serial" => out.serial = Some(value),
            "version" => out.version = Some(value),
            _ => {}
        }
    }
    out
}

impl ConnectorStatus {
    /// The connector must be up and, when it names a device, name `serial`.
    /// A connector that names none (`*`) is not refused here; the
    /// authenticated `device-info` serial is checked right after.
    pub fn require(&self, serial: u32) -> Result<(), RvError> {
        if self.status != "OK" {
            return Err(harness_error(format!("connector status is {:?}, not OK", self.status)));
        }
        match self.serial.as_deref().map(str::trim) {
            None | Some("") | Some("*") => Ok(()),
            Some(reported) => match parse_serial(reported) {
                Ok(s) if s == serial => Ok(()),
                _ => Err(harness_error(format!(
                    "the connector for {} reports device {reported:?}; refusing it",
                    format_serial(serial)
                ))),
            },
        }
    }
}

/// A value the snapshot could read, or why it could not; an unreadable
/// value is reported by [`compare_pools`] as unverified, never as equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
pub enum Reading<T> {
    Read(T),
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotObject {
    pub id: u16,
    pub object_type: String,
    pub label: String,
    pub algorithm: String,
    pub capabilities: String,
    pub delegated: String,
    pub domains: String,
    pub origin: String,
    /// Bumped when an object with this id and type is deleted and recreated;
    /// a change is reported as a note, not a difference.
    pub sequence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSnapshot {
    pub total_records: u16,
    pub free_records: u16,
    pub total_pages: u16,
    pub free_pages: u16,
    pub page_size: u16,
}

/// One device, read with the factory key only. No secret: serials,
/// options, object metadata and a public certificate's summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    pub serial: u32,
    pub firmware: String,
    pub algorithms: Vec<String>,
    pub storage: StorageSnapshot,
    pub force_audit: Reading<String>,
    pub command_audit: Reading<BTreeMap<String, String>>,
    pub algorithm_toggle: Reading<BTreeMap<String, String>>,
    pub objects: Vec<SnapshotObject>,
    pub device_attestation_certificate: Reading<CertificateSummary>,
    /// Informational, never compared: every session adds log entries.
    pub device_log: Reading<DeviceLogCapture>,
    /// Informational, never compared: every session adds log entries.
    pub log_used: u8,
    pub log_capacity: u8,
    pub connector_version: Option<String>,
}

/// The device log as a snapshot read it (`get-log-entries` with the factory
/// key: a read), and what [`verify_log`] makes of it with no cursor. This is
/// the on-device evidence for the entry layout and digest chain that
/// `hsm::device_audit` assumes; the YubiHSM 2 drain stays refused until it
/// is reviewed. Never compared between snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLogCapture {
    pub unlogged_boot: u16,
    pub unlogged_auth: u16,
    pub entries: Vec<DeviceLogEntry>,
    /// Index jumps and digest-chain breaks; empty means every entry chains
    /// from the one before as `DeviceLogEntry::data` lays it out.
    pub chain_gaps: Vec<String>,
}

impl DeviceLogCapture {
    pub fn new(log: DeviceLog) -> Result<Self, RvError> {
        let (verified, _) = verify_log(None, &log)?;
        Ok(Self {
            unlogged_boot: log.unlogged_boot,
            unlogged_auth: log.unlogged_auth,
            entries: log.entries,
            chain_gaps: verified.gaps,
        })
    }

    /// One line for the run's output.
    pub fn summary(&self) -> String {
        match (self.entries.len(), self.chain_gaps.as_slice()) {
            (n, _) if n < 2 => format!("{n} log entries, too few to check the digest chain"),
            (n, []) => format!("{n} log entries, digest chain verified"),
            (n, gaps) => format!("{n} log entries, {} chain gap(s): {}", gaps.len(), gaps.join("; ")),
        }
    }
}

/// Both devices at one point in time, as saved to the output directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolSnapshot {
    pub format: u32,
    pub label: String,
    pub taken_at_unix: u64,
    /// Keyed by the ten-digit serial.
    pub devices: BTreeMap<String, DeviceSnapshot>,
}

impl PoolSnapshot {
    pub fn new(label: &str, taken_at_unix: u64, devices: Vec<DeviceSnapshot>) -> Self {
        let devices = devices.into_iter().map(|d| (format_serial(d.serial), d)).collect();
        Self { format: SNAPSHOT_FORMAT, label: label.into(), taken_at_unix, devices }
    }

    pub fn load(path: &Path) -> Result<Self, RvError> {
        let bytes = std::fs::read(path).map_err(|e| harness_error(format!("cannot read {}: {e}", path.display())))?;
        let snapshot: Self = serde_json::from_slice(&bytes)
            .map_err(|e| harness_error(format!("{} is not a phase 7 snapshot: {e}", path.display())))?;
        if snapshot.format != SNAPSHOT_FORMAT {
            return Err(harness_error(format!("{}: unsupported snapshot format {}", path.display(), snapshot.format)));
        }
        Ok(snapshot)
    }

    /// Write the snapshot; an existing file is never replaced, so the
    /// "before" record cannot be overwritten by a later run.
    pub fn save_new(&self, path: &Path) -> Result<(), RvError> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| harness_error(e.to_string()))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| harness_error(format!("cannot create {} (it must not exist yet): {e}", path.display())))?;
        std::io::Write::write_all(&mut file, &json).map_err(|e| harness_error(format!("{}: {e}", path.display())))
    }
}

/// The provision preflight: factory key 1 present and nothing else.
pub fn preflight(device: &DeviceSnapshot) -> Result<(), RvError> {
    let serial = format_serial(device.serial);
    let is_factory_key = |o: &SnapshotObject| o.id == 1 && o.object_type == "authentication-key";
    if !device.objects.iter().any(is_factory_key) {
        return Err(harness_error(format!(
            "{serial}: the factory authentication key 0x0001 is missing, so the device is not in factory state \
             (reset it physically first)"
        )));
    }
    let others: Vec<String> = device
        .objects
        .iter()
        .filter(|o| !is_factory_key(o))
        .map(|o| format!("{:#06x} {} {:?}", o.id, o.object_type, o.label))
        .collect();
    if !others.is_empty() {
        return Err(harness_error(format!(
            "{serial}: holds {} object(s) besides the factory key ({}); refusing a device not in factory state",
            others.len(),
            others.join(", ")
        )));
    }
    Ok(())
}

/// What two snapshots disagree on. `differences` fail the comparison;
/// `unverified` fields could not be read on one side and need the operator's
/// manual read (`docs/hsm.md`); `notes` are expected changes, shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SnapshotComparison {
    pub differences: Vec<String>,
    pub unverified: Vec<String>,
    pub notes: Vec<String>,
}

impl SnapshotComparison {
    pub fn is_identical(&self) -> bool {
        self.differences.is_empty()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let section = |out: &mut String, title: &str, items: &[String]| {
            out.push_str(&format!("{title}: {}\n", if items.is_empty() { "none" } else { "" }));
            for item in items {
                out.push_str(&format!("  - {item}\n"));
            }
        };
        section(&mut out, "differences", &self.differences);
        section(&mut out, "unverified (read these by hand)", &self.unverified);
        section(&mut out, "notes", &self.notes);
        out.push_str("ignored: device log and its counters, connector version, timestamps\n");
        out
    }
}

fn compare_reading<T: PartialEq + fmt::Debug>(
    out: &mut SnapshotComparison,
    what: &str,
    before: &Reading<T>,
    after: &Reading<T>,
) {
    match (before, after) {
        (Reading::Read(b), Reading::Read(a)) if b == a => {}
        (Reading::Read(b), Reading::Read(a)) => out.differences.push(format!("{what}: {b:?} -> {a:?}")),
        (b, a) => {
            let why = |r: &Reading<T>| match r {
                Reading::Read(_) => "read".to_string(),
                Reading::Unavailable(why) => format!("unavailable ({why})"),
            };
            out.unverified.push(format!("{what}: before {}, after {}", why(b), why(a)));
        }
    }
}

fn compare_devices(out: &mut SnapshotComparison, serial: &str, before: &DeviceSnapshot, after: &DeviceSnapshot) {
    let mut strict = |field: &str, b: String, a: String| {
        if b != a {
            out.differences.push(format!("{serial} {field}: {b} -> {a}"));
        }
    };
    strict("serial", before.serial.to_string(), after.serial.to_string());
    strict("firmware", before.firmware.clone(), after.firmware.clone());
    strict("algorithms", format!("{:?}", before.algorithms), format!("{:?}", after.algorithms));
    strict("storage", format!("{:?}", before.storage), format!("{:?}", after.storage));
    compare_reading(out, &format!("{serial} force-audit"), &before.force_audit, &after.force_audit);
    compare_reading(out, &format!("{serial} command-audit"), &before.command_audit, &after.command_audit);
    compare_reading(out, &format!("{serial} algorithm-toggle"), &before.algorithm_toggle, &after.algorithm_toggle);
    compare_reading(
        out,
        &format!("{serial} device attestation certificate"),
        &before.device_attestation_certificate,
        &after.device_attestation_certificate,
    );
    let key = |o: &SnapshotObject| (o.id, o.object_type.clone());
    let b: BTreeMap<_, _> = before.objects.iter().map(|o| (key(o), o)).collect();
    let a: BTreeMap<_, _> = after.objects.iter().map(|o| (key(o), o)).collect();
    for (k, ob) in &b {
        match a.get(k) {
            None => out.differences.push(format!("{serial} object {:#06x} {} is gone", k.0, k.1)),
            Some(oa) => {
                let mut ob_cmp = (*ob).clone();
                ob_cmp.sequence = oa.sequence;
                if &ob_cmp != *oa {
                    out.differences.push(format!("{serial} object {:#06x} {}: {ob:?} -> {oa:?}", k.0, k.1));
                } else if ob.sequence != oa.sequence {
                    out.notes.push(format!(
                        "{serial} object {:#06x} {} sequence {} -> {} (deleted and recreated)",
                        k.0, k.1, ob.sequence, oa.sequence
                    ));
                }
            }
        }
    }
    for (k, oa) in &a {
        if !b.contains_key(k) {
            out.differences.push(format!("{serial} new object {:#06x} {} {:?}", k.0, k.1, oa.label));
        }
    }
}

/// Diff two pool snapshots field by field (spec: "the expected difference is
/// none"). The device log, its counters, timestamps and the connector
/// version are ignored.
pub fn compare_pools(before: &PoolSnapshot, after: &PoolSnapshot) -> SnapshotComparison {
    let mut out = SnapshotComparison::default();
    for (serial, b) in &before.devices {
        match after.devices.get(serial) {
            None => out.differences.push(format!("{serial} is missing from the {} snapshot", after.label)),
            Some(a) => compare_devices(&mut out, serial, b, a),
        }
    }
    for serial in after.devices.keys() {
        if !before.devices.contains_key(serial) {
            out.differences.push(format!("{serial} is not in the {} snapshot", before.label));
        }
    }
    out
}

/// Timings per (member, operation).
#[derive(Debug, Clone, Default)]
pub struct LatencySamples(BTreeMap<(String, String), Vec<Duration>>);

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LatencyRow {
    pub member: String,
    pub op: String,
    pub n: usize,
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Nearest-rank percentile of sorted samples.
fn percentile(sorted: &[Duration], p: usize) -> Duration {
    let rank = (p * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

impl LatencySamples {
    pub fn record(&mut self, member: &str, op: &str, took: Duration) {
        self.0.entry((member.to_string(), op.to_string())).or_default().push(took);
    }

    pub fn rows(&self) -> Vec<LatencyRow> {
        self.0
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|((member, op), v)| {
                let mut sorted = v.clone();
                sorted.sort();
                let total: Duration = sorted.iter().sum();
                LatencyRow {
                    member: member.clone(),
                    op: op.clone(),
                    n: sorted.len(),
                    min_ms: ms(sorted[0]),
                    p50_ms: ms(percentile(&sorted, 50)),
                    p95_ms: ms(percentile(&sorted, 95)),
                    max_ms: ms(sorted[sorted.len() - 1]),
                    mean_ms: ms(total) / sorted.len() as f64,
                }
            })
            .collect()
    }

    /// A Markdown table for `docs/hsm.md`.
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("| Member | Operation | n | min ms | p50 ms | p95 ms | max ms | mean ms |\n");
        out.push_str("|---|---|---|---|---|---|---|---|\n");
        for r in self.rows() {
            out.push_str(&format!(
                "| {} | {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |\n",
                r.member, r.op, r.n, r.min_ms, r.p50_ms, r.p95_ms, r.max_ms, r.mean_ms
            ));
        }
        out
    }
}

/// What the operator does after a validate run, printed by the driver: the
/// harness never resets a device and stops before the production provision.
pub fn reset_instructions(serials: &[u32], out_dir: &Path) -> String {
    let list: Vec<String> = serials.iter().map(|s| format_serial(*s)).collect();
    format!(
        "PHASE 7 STOPS HERE. The devices are provisioned with TEST credentials and must be reset by hand.\n\
         For each device ({list}), one at a time:\n  \
           1. unplug it;\n  \
           2. press and hold the metal rim while inserting it, and keep pressing for at least 10 seconds;\n  \
           3. release; it now holds only the factory key and its factory options.\n\
         Then run the read-only comparison against {before}:\n  \
           BVAULT_TEST_YUBIHSM_POOL=1 BVAULT_TEST_YUBIHSM_STEP=compare \\\n    \
             BVAULT_TEST_YUBIHSM_SERIALS={csv} BVAULT_TEST_YUBIHSM_OUT={out} \\\n    \
             cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture\n\
         The production `provision` is the next step after a clean comparison; this harness never runs it.\n\
         Until then a reset device answers the public factory password: keep it off shared hosts.",
        list = list.join(", "),
        before = out_dir.join(BEFORE_SNAPSHOT_FILE).display(),
        csv = list.join(","),
        out = out_dir.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u32 = 36_470_559;
    const B: u32 = 36_470_560;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    fn factory_device(serial: u32) -> DeviceSnapshot {
        DeviceSnapshot {
            serial,
            firmware: "2.4.1".into(),
            algorithms: vec!["rsa-pkcs1-sha256".into(), "ec-p256".into()],
            storage: StorageSnapshot {
                total_records: 256,
                free_records: 255,
                total_pages: 1024,
                free_pages: 1023,
                page_size: 126,
            },
            force_audit: Reading::Read("off".into()),
            command_audit: Reading::Read(BTreeMap::from([("0x01".into(), "off".into())])),
            algorithm_toggle: Reading::Unavailable("not readable through yubihsm 0.42".into()),
            objects: vec![SnapshotObject {
                id: 1,
                object_type: "authentication-key".into(),
                label: "DEFAULT AUTHKEY CHANGE THIS ASAP".into(),
                algorithm: "YubicoAes".into(),
                capabilities: "0x7fffffffffffffff".into(),
                delegated: "0x7fffffffffffffff".into(),
                domains: "0xffff".into(),
                origin: "Imported".into(),
                sequence: 0,
            }],
            device_attestation_certificate: Reading::Read(CertificateSummary {
                sha256: "ab".repeat(32),
                subject: "CN=YubiHSM Attestation".into(),
                issuer: "CN=Yubico".into(),
                not_before: "2024".into(),
                not_after: "2071".into(),
            }),
            device_log: Reading::Unavailable("not read in this test".into()),
            log_used: 9,
            log_capacity: 62,
            connector_version: Some("3.0.7".into()),
        }
    }

    fn pool(label: &str, devices: Vec<DeviceSnapshot>) -> PoolSnapshot {
        PoolSnapshot::new(label, 0, devices)
    }

    #[test]
    fn the_suite_is_skipped_unless_enabled_with_1() {
        assert!(HarnessEnv::from_lookup(env(&[])).unwrap().is_none(), "unset");
        for off in ["0", "true", "yes", ""] {
            let lookup = [(ENV_ENABLE, off), (ENV_SERIALS, "36470559,36470560"), (ENV_OUT_DIR, "/tmp/p7")];
            assert!(HarnessEnv::from_lookup(env(&lookup)).unwrap().is_none(), "{off:?}");
        }
        let lookup = [(ENV_ENABLE, "1"), (ENV_SERIALS, "36470559,36470560"), (ENV_OUT_DIR, "/tmp/p7")];
        let cfg = HarnessEnv::from_lookup(env(&lookup)).unwrap().unwrap();
        assert_eq!((cfg.mode, cfg.allow_writes, cfg.port_base), (Mode::Snapshot, false, 12345));
        assert_eq!((cfg.port(0).unwrap(), cfg.port(1).unwrap()), (12345, 12346), "one port per device");
        assert_eq!(cfg.serials.serials(), vec![A, B]);
        assert_eq!(cfg.latency_iterations, 20);

        // Enabled but incomplete or ambiguous: refused, never defaulted.
        assert!(HarnessEnv::from_lookup(env(&[(ENV_ENABLE, "1"), (ENV_OUT_DIR, "/tmp")])).is_err(), "no serials");
        assert!(HarnessEnv::from_lookup(env(&[(ENV_ENABLE, "1"), (ENV_SERIALS, "36470559,36470560")])).is_err());
        let gate = [(ENV_ENABLE, "1"), (ENV_SERIALS, "36470559,36470560"), (ENV_OUT_DIR, "/t"), (ENV_ALLOW_WRITES, "yes")];
        assert!(HarnessEnv::from_lookup(env(&gate)).unwrap_err().to_string().contains(ENV_ALLOW_WRITES));
    }

    #[test]
    fn the_allowlist_takes_exactly_the_two_devices() {
        let list = SerialAllowlist::parse(" 0036470559, 36470560 ").unwrap();
        assert_eq!(list.serials(), vec![A, B]);
        list.check(A, "device-info").unwrap();
        let err = list.check(12_345_678, "device-info").unwrap_err().to_string();
        assert!(err.contains("0012345678") && err.contains("refusing"), "{err}");
        for bad in ["36470559", "36470559,36470559", "36470559,36470560,1", "36470559,x", "0,36470559", ""] {
            assert!(SerialAllowlist::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn steps_run_from_least_to_most_destructive_behind_the_gate() {
        for mode in [Mode::Snapshot, Mode::Compare] {
            let steps = plan(mode, None, false).unwrap();
            assert!(steps.iter().all(|s| s.effect() == Effect::ReadOnly), "{mode:?} is read-only: {steps:?}");
        }
        // Validate: read-only first, then the gate, provision the first write.
        let steps = plan(Mode::Validate, None, true).unwrap();
        let first_write = steps.iter().position(|s| s.effect() == Effect::Writes).unwrap();
        assert_eq!(steps[first_write], Step::Provision);
        assert!(steps[..first_write].iter().all(|s| s.effect() == Effect::ReadOnly), "{steps:?}");
        assert!(steps[..first_write].contains(&Step::MatchBefore) && steps[..first_write].contains(&Step::LoadAnchors));
        assert_eq!(steps.last(), Some(&Step::ResetInstructions), "every run ends with the reset instructions");

        // The gate is closed by default; the whole plan is refused, not cut.
        let err = plan(Mode::Validate, None, false).unwrap_err().to_string();
        assert!(err.contains(ENV_ALLOW_WRITES) && err.contains("provision"), "{err}");
        // ...but a validate run stopped before the first write needs no gate.
        let steps = plan(Mode::Validate, Some(Step::LoadAnchors), false).unwrap();
        assert_eq!(steps.last(), Some(&Step::LoadAnchors));
        assert!(plan(Mode::Validate, Some(Step::Provision), false).is_err());
        assert!(plan(Mode::Snapshot, Some(Step::Provision), true).is_err(), "not a step of snapshot");
    }

    #[test]
    fn forbidden_operations_are_refused_by_name() {
        for name in ["reset", "firmware-update", "fips-mode", "command-audit", "audit-fix", "production-provision"] {
            let err = Step::parse(name).unwrap_err().to_string();
            assert!(err.contains("never runs"), "{name}: {err}");
            assert!(Mode::parse(name).unwrap_err().to_string().contains("never runs"), "{name}");
        }
        for step in ALL_STEPS {
            assert_eq!(Step::parse(step.name()).unwrap(), *step);
            assert!(FORBIDDEN.iter().all(|(n, _)| *n != step.name()));
        }
        assert!(Step::parse("bogus").unwrap_err().to_string().contains("unknown step"));
    }

    #[test]
    fn preflight_accepts_only_the_factory_key() {
        preflight(&factory_device(A)).unwrap();
        let mut provisioned = factory_device(A);
        provisioned.objects.push(SnapshotObject {
            id: 2,
            object_type: "authentication-key".into(),
            label: "bv-admin".into(),
            ..provisioned.objects[0].clone()
        });
        let err = preflight(&provisioned).unwrap_err().to_string();
        assert!(err.contains("1 object(s)") && err.contains("bv-admin"), "{err}");
        let mut empty = factory_device(A);
        empty.objects.clear();
        assert!(preflight(&empty).unwrap_err().to_string().contains("factory authentication key 0x0001 is missing"));
        // Id 1 of another type is not the factory key.
        let mut wrong = factory_device(A);
        wrong.objects[0].object_type = "wrap-key".into();
        assert!(preflight(&wrong).is_err());
    }

    #[test]
    fn identical_snapshots_compare_clean_and_changes_are_named() {
        let before = pool("before", vec![factory_device(A), factory_device(B)]);
        let mut after = before.clone();
        after.label = "after".into();
        for d in after.devices.values_mut() {
            d.log_used = 3; // a reset clears the log; ignored
            d.connector_version = Some("3.0.8".into());
        }
        let cmp = compare_pools(&before, &after);
        assert!(cmp.is_identical(), "{}", cmp.render());
        assert_eq!(cmp.unverified.len(), 2, "algorithm-toggle cannot be read on either device");
        assert!(cmp.render().contains("differences: none"));

        let mut changed = after.clone();
        let d = changed.devices.get_mut("0036470559").unwrap();
        d.force_audit = Reading::Read("on".into());
        d.storage.free_records = 248;
        d.objects[0].sequence = 1;
        d.objects.push(SnapshotObject { id: 3, object_type: "wrap-key".into(), ..d.objects[0].clone() });
        let cmp = compare_pools(&before, &changed);
        assert!(!cmp.is_identical());
        let all = cmp.differences.join("\n");
        assert!(all.contains("force-audit") && all.contains("storage") && all.contains("new object 0x0003"), "{all}");
        assert!(cmp.notes.iter().any(|n| n.contains("sequence 0 -> 1")), "{:?}", cmp.notes);

        // The device log differs on every read and is never compared.
        let mut logged = after.clone();
        logged.devices.get_mut("0036470559").unwrap().device_log =
            Reading::Read(DeviceLogCapture::new(chained_log(3)).unwrap());
        assert!(compare_pools(&before, &logged).is_identical());

        let mut missing = after.clone();
        missing.devices.remove("0036470560");
        assert!(compare_pools(&before, &missing).differences.iter().any(|d| d.contains("0036470560 is missing")));

        // Unreadable on one side is unverified, never "equal".
        let mut unread = after.clone();
        unread.devices.get_mut("0036470559").unwrap().command_audit = Reading::Unavailable("protocol error".into());
        let cmp = compare_pools(&before, &unread);
        assert!(cmp.is_identical() && cmp.unverified.iter().any(|u| u.contains("command-audit")));
    }

    /// `n` entries chained as `hsm::device_audit` expects the device to.
    fn chained_log(n: u16) -> DeviceLog {
        let mut entries: Vec<DeviceLogEntry> = Vec::new();
        let mut previous = [0u8; 16];
        for index in 1..=n {
            let mut e = DeviceLogEntry {
                index,
                command: 0x06, // device-info
                length: 0,
                session_key: 1,
                target_key: 0,
                second_key: 0,
                result: 0x86,
                systick: u32::from(index) * 100,
                digest: [0; 16],
            };
            e.digest = e.chained_digest(&previous);
            previous = e.digest;
            entries.push(e);
        }
        DeviceLog { unlogged_boot: 0, unlogged_auth: 0, entries }
    }

    #[test]
    fn the_device_log_capture_reports_the_digest_chain() {
        let good = DeviceLogCapture::new(chained_log(5)).unwrap();
        assert!(good.chain_gaps.is_empty(), "{:?}", good.chain_gaps);
        assert_eq!(good.summary(), "5 log entries, digest chain verified");

        let mut log = chained_log(5);
        log.entries[3].digest[0] ^= 0xff;
        let broken = DeviceLogCapture::new(log).unwrap();
        assert!(broken.summary().contains("chain gap") && broken.chain_gaps[0].contains("entry 4"), "{broken:?}");

        let mut log = chained_log(4);
        log.entries.remove(1);
        assert!(DeviceLogCapture::new(log).unwrap().chain_gaps[0].contains("index jump"));
        assert!(DeviceLogCapture::new(chained_log(1)).unwrap().summary().contains("too few"));

        // It survives the snapshot's JSON round trip.
        let json = serde_json::to_string(&good).unwrap();
        assert_eq!(serde_json::from_str::<DeviceLogCapture>(&json).unwrap(), good);
    }

    #[test]
    fn snapshots_round_trip_and_are_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("bv-phase7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(BEFORE_SNAPSHOT_FILE);
        let _ = std::fs::remove_file(&path);
        let snap = pool("before", vec![factory_device(A), factory_device(B)]);
        snap.save_new(&path).unwrap();
        assert_eq!(PoolSnapshot::load(&path).unwrap(), snap);
        assert!(snap.save_new(&path).unwrap_err().to_string().contains("must not exist"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connector_invocation_and_status() {
        assert_eq!(connector_args(A, 12346), ["--listen", "127.0.0.1:12346", "--serial", "0036470559"]);
        let st = parse_connector_status("status=OK\nserial=0036470559\nversion=3.0.7\npid=1\nport=12346\n");
        assert_eq!(st.version.as_deref(), Some("3.0.7"));
        st.require(A).unwrap();
        assert!(st.require(B).unwrap_err().to_string().contains("refusing"));
        parse_connector_status("status=OK\nserial=*\n").require(A).unwrap();
        assert!(parse_connector_status("status=NO_DEVICE\n").require(A).is_err());
    }

    #[test]
    fn latency_rows_and_table() {
        let mut s = LatencySamples::default();
        for ms in 1..=20u64 {
            s.record("hsm-a", "wrap", Duration::from_millis(ms));
        }
        s.record("hsm-b", "authz-sign", Duration::from_millis(105));
        let rows = s.rows();
        let wrap = rows.iter().find(|r| r.op == "wrap").unwrap();
        assert_eq!((wrap.n, wrap.min_ms, wrap.p50_ms, wrap.p95_ms, wrap.max_ms), (20, 1.0, 10.0, 19.0, 20.0));
        assert!((wrap.mean_ms - 10.5).abs() < 1e-9);
        let table = s.to_markdown();
        assert!(table.contains("| hsm-b | authz-sign | 1 | 105.0 |"), "{table}");
    }

    #[test]
    fn passwords_come_from_the_environment_and_never_print() {
        assert_eq!(factory_password(env(&[])).expose(), FACTORY_PASSWORD);
        let admin = admin_password(env(&[(ENV_ADMIN_PASSWORD, "t3st-admin-pw")])).unwrap();
        assert!(!format!("{admin:?}").contains("t3st"), "redacted");
        assert!(admin_password(env(&[])).is_err());
        assert!(admin_password(env(&[(ENV_ADMIN_PASSWORD, FACTORY_PASSWORD)])).is_err());
        let text = reset_instructions(&[A, B], Path::new("/tmp/p7"));
        assert!(text.contains("10 seconds") && text.contains("STEP=compare") && text.contains("0036470559,0036470560"));
        assert!(!text.contains("t3st-admin-pw"));
    }
}
