//! The device half of the phase 7 harness (feature `hsm_hardware_tests`):
//! connector processes, the factory-key snapshot (reads only), and the
//! timed operations. Nothing here resets a device, updates firmware, enables
//! FIPS mode or sets an audit option. Passwords arrive as [`EnvSecret`]s and
//! go only into `Credentials`; no message or log line carries one.

use std::{
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use yubihsm::{audit::AuditOption, connector::HttpConfig, Client, Connector, Credentials};

use super::{
    connector_args, harness_error, parse_connector_status, ConnectorStatus, DeviceLogCapture, DeviceSnapshot,
    EnvSecret, LatencySamples, Reading, SnapshotObject, StorageSnapshot,
};
use crate::{
    errors::RvError,
    hsm::{
        admin::FACTORY_AUTH_KEY_ID,
        attestation::{certificate_summary, format_serial},
        authz::{sign_authorization, UnwrapRequest},
        blob::{Context, Purpose},
        context,
        derive::{derive_pqc_key_material, PqcKeyKind},
        device_audit::{DeviceLog, DeviceLogEntry},
        yubihsm2::{device_attestation_certificate, YubiHsm2Backend},
        HsmBackend, HsmObjectIds,
    },
};

/// The test cluster and node the validate run wraps under. Nothing named
/// here survives the run: the devices are reset afterwards.
pub const TEST_CLUSTER: &str = "phase7-hardware-validation";
pub const TEST_NODE: &str = "phase7-test";
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_STATUS_BYTES: u64 = 64 * 1024;

fn device_error(what: &'static str) -> impl Fn(yubihsm::client::Error) -> RvError {
    move |e| harness_error(format!("{what}: {e}"))
}

/// One `yubihsm-connector` for one device, on its own loopback port; killed
/// on drop, so a failing run never leaves a connector behind.
pub struct ConnectorProcess {
    child: Child,
    pub serial: u32,
    pub port: u16,
    pub status: ConnectorStatus,
}

impl ConnectorProcess {
    /// Start the connector with `--serial`, wait for its status page, and
    /// refuse it if the page names another device. Its output goes to
    /// `connector-<serial>.log` in `log_dir` (the connector never sees a
    /// password: sessions are end-to-end encrypted).
    pub fn spawn(bin: &Path, serial: u32, port: u16, log_dir: &Path) -> Result<Self, RvError> {
        let probe = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
            harness_error(format!("port {port} is not free ({e}); stop any running yubihsm-connector first"))
        })?;
        drop(probe);
        let log_path = log_dir.join(format!("connector-{}.log", format_serial(serial)));
        let log = File::create(&log_path).map_err(|e| harness_error(format!("{}: {e}", log_path.display())))?;
        let log_err = log.try_clone().map_err(|e| harness_error(format!("{}: {e}", log_path.display())))?;
        let child = Command::new(bin)
            .args(connector_args(serial, port))
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .map_err(|e| harness_error(format!("cannot start {}: {e}", bin.display())))?;
        let mut process = Self { child, serial, port, status: ConnectorStatus::default() };
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Some(code) = process.child.try_wait().map_err(|e| harness_error(e.to_string()))? {
                return Err(harness_error(format!(
                    "the connector for {} exited ({code}); see {}",
                    format_serial(serial),
                    log_path.display()
                )));
            }
            if let Ok(status) = fetch_status(port) {
                if status.status == "OK" {
                    status.require(serial)?;
                    process.status = status;
                    return Ok(process);
                }
            }
            if Instant::now() > deadline {
                return Err(harness_error(format!(
                    "the connector for {} did not report OK within {}s; see {}",
                    format_serial(serial),
                    READY_TIMEOUT.as_secs(),
                    log_path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn connector(&self) -> Connector {
        Connector::http(&HttpConfig { addr: "127.0.0.1".into(), port: self.port, ..HttpConfig::default() })
    }

    /// A session with the factory key. Used only by the read-only steps.
    pub fn open_factory(&self, password: &EnvSecret) -> Result<Client, RvError> {
        let credentials = Credentials::from_password(FACTORY_AUTH_KEY_ID, password.expose().as_bytes());
        Client::open(self.connector(), credentials, false).map_err(device_error("factory-key session"))
    }
}

impl Drop for ConnectorProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `GET /connector/status` over loopback; no session, no credential.
pub fn fetch_status(port: u16) -> Result<ConnectorStatus, RvError> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream =
        TcpStream::connect_timeout(&addr, STATUS_TIMEOUT).map_err(|e| harness_error(format!("status: {e}")))?;
    stream.set_read_timeout(Some(STATUS_TIMEOUT)).map_err(|e| harness_error(e.to_string()))?;
    write!(stream, "GET /connector/status HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n")
        .map_err(|e| harness_error(format!("status: {e}")))?;
    let mut response = String::new();
    stream
        .take(MAX_STATUS_BYTES)
        .read_to_string(&mut response)
        .map_err(|e| harness_error(format!("status: {e}")))?;
    let body = response.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or_default();
    Ok(parse_connector_status(body))
}

fn audit_name(option: AuditOption) -> String {
    match option {
        AuditOption::Off => "off",
        AuditOption::On => "on",
        AuditOption::Fix => "fix",
    }
    .into()
}

fn reading<T>(result: Result<T, yubihsm::client::Error>) -> Reading<T> {
    match result {
        Ok(value) => Reading::Read(value),
        Err(e) => Reading::Unavailable(e.to_string()),
    }
}

/// The read-only snapshot of one device through a factory-key session:
/// device info, storage, audit options, every object's metadata and the
/// device attestation certificate's summary. Sends no write command.
pub fn read_snapshot(client: &Client, status: &ConnectorStatus) -> Result<DeviceSnapshot, RvError> {
    let info = client.device_info().map_err(device_error("device-info"))?;
    let storage = client.get_storage_info().map_err(device_error("get-storage-info"))?;
    let mut objects = Vec::new();
    for entry in client.list_objects(&[]).map_err(device_error("list-objects"))? {
        let o = client.get_object_info(entry.object_id, entry.object_type).map_err(device_error("get-object-info"))?;
        objects.push(SnapshotObject {
            id: entry.object_id,
            object_type: o.object_type.to_string(),
            label: o.label.to_string(),
            algorithm: format!("{:?}", o.algorithm),
            capabilities: format!("{:#018x}", o.capabilities.bits()),
            delegated: format!("{:#018x}", o.delegated_capabilities.bits()),
            domains: format!("{:#06x}", o.domains.bits()),
            origin: format!("{:?}", o.origin),
            sequence: o.sequence,
        });
    }
    let command_audit = reading(client.get_commands_audit_options()).map_or_unavailable(|options| {
        options.into_iter().map(|c| (format!("{:#04x}", c.command_type().to_u8()), audit_name(c.audit_option()))).collect()
    });
    let device_attestation_certificate = match device_attestation_certificate(client) {
        Ok(der) => match certificate_summary(&der) {
            Ok(summary) => Reading::Read(summary),
            Err(e) => Reading::Unavailable(e.to_string()),
        },
        Err(e) => Reading::Unavailable(e.to_string()),
    };
    // `get-log-entries` reads; it never acknowledges (`set-log-index`).
    let device_log = match client.get_log_entries() {
        Ok(log) => {
            let entries = log
                .entries
                .into_iter()
                .map(|e| DeviceLogEntry {
                    index: e.item,
                    command: e.cmd.to_u8(),
                    length: e.length,
                    session_key: e.session_key,
                    target_key: e.target_key,
                    second_key: e.second_key,
                    result: e.result.to_u8(),
                    systick: e.tick,
                    digest: e.digest.0,
                })
                .collect();
            let log = DeviceLog {
                unlogged_boot: log.unlogged_boot_events,
                unlogged_auth: log.unlogged_auth_events,
                entries,
            };
            match DeviceLogCapture::new(log) {
                Ok(capture) => Reading::Read(capture),
                Err(e) => Reading::Unavailable(e.to_string()),
            }
        }
        Err(e) => Reading::Unavailable(e.to_string()),
    };
    Ok(DeviceSnapshot {
        serial: info.serial_number.to_string().parse().map_err(|_| harness_error("unparsable device serial"))?,
        firmware: format!("{}.{}.{}", info.major_version, info.minor_version, info.build_version),
        algorithms: info.algorithms.iter().map(|a| format!("{a:?}")).collect(),
        storage: StorageSnapshot {
            total_records: storage.total_records,
            free_records: storage.free_records,
            total_pages: storage.total_pages,
            free_pages: storage.free_pages,
            page_size: storage.page_size,
        },
        force_audit: reading(client.get_force_audit_option()).map_or_unavailable(audit_name),
        command_audit,
        algorithm_toggle: Reading::Unavailable(
            "yubihsm 0.42 cannot send get-option algorithm-toggle (tag 0x04); read it with yubihsm-shell".into(),
        ),
        objects,
        device_attestation_certificate,
        device_log,
        log_used: info.log_store_used,
        log_capacity: info.log_store_capacity,
        connector_version: status.version.clone(),
    })
}

trait MapReading<T> {
    fn map_or_unavailable<U>(self, f: impl FnOnce(T) -> U) -> Reading<U>;
}

impl<T> MapReading<T> for Reading<T> {
    fn map_or_unavailable<U>(self, f: impl FnOnce(T) -> U) -> Reading<U> {
        match self {
            Reading::Read(v) => Reading::Read(f(v)),
            Reading::Unavailable(why) => Reading::Unavailable(why),
        }
    }
}

/// A fixed P-256 point standing in for the cluster binding key, so the
/// timed key creation runs the same device ECDH as custody `create`.
fn binding_point() -> Result<Vec<u8>, RvError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::from_slice(&[0x07; 32]).map_err(|e| harness_error(e.to_string()))?;
    Ok(secret.public_key().to_encoded_point(false).as_bytes().to_vec())
}

/// The barrier-KEK context the validate run wraps under.
pub fn test_context() -> Context {
    Context::new(context::barrier_kek(TEST_CLUSTER), Purpose::BarrierKek, 1, TEST_NODE)
}

/// Open a pool member client with the test node's credential.
pub fn open_member(
    connector: Connector,
    relay: Option<bv_hsm_link::Relay>,
    credential: &crate::hsm::admin::NodeCredential,
    objects: HsmObjectIds,
) -> Result<YubiHsm2Backend, RvError> {
    YubiHsm2Backend::open_pool_member(connector, relay, credential, objects)
}

/// Time the four operations the session budget rests on, `iterations`
/// times each, on one member: a signed unwrap authorization (`bv-authz`),
/// a 32-byte wrap and unwrap (`bv-wrap-barrier`), and a custody key
/// creation's device work (random, ECDH with `bv-seed-ecdh`, wrap).
#[maybe_async::maybe_async]
pub async fn measure(
    backend: &dyn HsmBackend,
    member: &str,
    objects: &HsmObjectIds,
    iterations: usize,
    samples: &mut LatencySamples,
) -> Result<(), RvError> {
    let ctx = test_context();
    let secret = [0x42u8; 32];
    let binding = binding_point()?;
    let kind = PqcKeyKind::MlKem768;
    let pqc_ctx = Context::new(kind.seed_context(TEST_CLUSTER, 1), kind.purpose(), 1, TEST_NODE);
    for i in 0..iterations {
        let started = Instant::now();
        let blob = backend.wrap_data(objects.wrap_barrier, &ctx, &secret).await?;
        samples.record(member, "wrap", started.elapsed());

        // As unseal does: authorize this blob's release, then unwrap it.
        let counter = i as u64 + 1;
        let request = UnwrapRequest::new(ctx.context.clone(), &blob, TEST_NODE, 1, counter, Purpose::BarrierKek);
        let started = Instant::now();
        sign_authorization(backend, objects.authz, request).await?;
        samples.record(member, "authz-sign", started.elapsed());

        let started = Instant::now();
        let plain = backend.unwrap_data(objects.wrap_barrier, &ctx, &blob).await?;
        samples.record(member, "unwrap", started.elapsed());
        if plain.as_slice() != secret {
            return Err(harness_error(format!("{member}: unwrap returned other bytes than were wrapped")));
        }

        let started = Instant::now();
        let material = derive_pqc_key_material(backend, TEST_CLUSTER, 1, kind, &binding, objects.seed_ecdh).await?;
        backend.wrap_data(objects.wrap_pqc, &pqc_ctx, &material.seed).await?;
        samples.record(member, "create-key", started.elapsed());
    }
    Ok(())
}
