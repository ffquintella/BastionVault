//! T454 phase 7: validation on two real YubiHSM 2 devices. Compiled only with
//! `--features hsm_hardware_tests`, skipped unless BVAULT_TEST_YUBIHSM_POOL=1,
//! and refuses any device not in BVAULT_TEST_YUBIHSM_SERIALS. The operator
//! runbook (environment, the three invocations, the physical reset) is
//! `docs/hsm.md` § Phase 7 hardware validation; the logic is unit-tested in
//! `bv_core::hsm::hw_validation`.
#![cfg(not(feature = "sync_handler"))]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bv_core::hsm::{
    admin::{node_auth_key_id, HsmAdminSession, NodeCredential},
    attestation::{format_serial, YubicoTrustAnchors},
    blob::BvHsmBlob,
    ceremony::{verify_member, AttestationBundle},
    hw_validation::{
        after_snapshot_file, compare_pools, device, factory_password, harness_error, plan, preflight,
        reset_instructions, HarnessEnv, LatencySamples, Mode, PoolSnapshot, Reading, Step, BEFORE_SNAPSHOT_FILE,
        ENV_ENABLE,
    },
    yubihsm2::{self, YubiHsm2AdminSession, YubiHsm2Backend},
    HsmBackend, HsmObjectIds,
};
use bv_errors::RvError;
use bv_hsm_link::{
    ConnectorUrl, Gateway, GatewayConfig, GatewayLimits, GatewayUrl, LinkTls, Relay, RelayConfig, RelayLimits,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose};
use yubihsm::{connector::HttpConfig, Connector};

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), RvError> {
    let json = serde_json::to_vec_pretty(value).map_err(|e| harness_error(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| harness_error(format!("{}: {e}", path.display())))
}

/// One verified property of the hardware. A failed check does not stop the
/// run (each run costs a physical reset), but fails the test at the end.
#[derive(serde::Serialize)]
struct Check {
    name: String,
    passed: bool,
    detail: String,
}

struct Run {
    env: HarnessEnv,
    objects: HsmObjectIds,
    connectors: Vec<device::ConnectorProcess>,
    snapshot: Option<PoolSnapshot>,
    anchors: Option<PathBuf>,
    bundles: BTreeMap<u32, AttestationBundle>,
    credential: Option<NodeCredential>,
    checks: Vec<Check>,
    samples: LatencySamples,
    /// Set before the first write: from then on, every exit prints the reset.
    wrote: bool,
}

impl Run {
    fn check(&mut self, name: impl Into<String>, result: Result<String, String>) {
        let (passed, detail) = match result {
            Ok(detail) => (true, detail),
            Err(detail) => (false, detail),
        };
        let name = name.into();
        println!("    [{}] {name}: {detail}", if passed { "pass" } else { "FAIL" });
        self.checks.push(Check { name, passed, detail });
    }

    fn admin_session(&self, index: usize) -> Result<YubiHsm2AdminSession, RvError> {
        let admin = bv_core::hsm::hw_validation::admin_password(env_lookup)?;
        let c = &self.connectors[index];
        YubiHsm2AdminSession::open(c.connector(), None, admin.expose(), self.objects, self.anchors.clone())
    }

    fn credential(&self) -> Result<&NodeCredential, RvError> {
        self.credential.as_ref().ok_or_else(|| harness_error("no test node credential (enroll-test-node did not run)"))
    }

    fn member(&self, index: usize) -> Result<YubiHsm2Backend, RvError> {
        device::open_member(self.connectors[index].connector(), None, self.credential()?, self.objects)
    }

    async fn step(&mut self, step: Step) -> Result<(), RvError> {
        match step {
            Step::StartConnectors => {
                for (i, serial) in self.env.serials.serials().into_iter().enumerate() {
                    let port = self.env.port(i)?;
                    let c = device::ConnectorProcess::spawn(&self.env.connector_bin, serial, port, &self.env.out_dir)?;
                    println!("    connector for {} on {} ({:?})", format_serial(serial), c.url(), c.status);
                    self.connectors.push(c);
                }
            }
            Step::Snapshot => {
                let factory = factory_password(env_lookup);
                let mut devices = Vec::new();
                for c in &self.connectors {
                    let client = c.open_factory(&factory)?;
                    let snapshot = device::read_snapshot(&client, &c.status)?;
                    self.env.serials.check(snapshot.serial, "device-info")?;
                    let log = match &snapshot.device_log {
                        Reading::Read(capture) => capture.summary(),
                        Reading::Unavailable(why) => format!("device log not read: {why}"),
                    };
                    println!("    {}: {log}", format_serial(snapshot.serial));
                    if snapshot.serial != c.serial {
                        return Err(harness_error(format!(
                            "the connector for {} reached device {}",
                            format_serial(c.serial),
                            format_serial(snapshot.serial)
                        )));
                    }
                    devices.push(snapshot);
                }
                let label = if self.env.mode == Mode::Compare { "after" } else { "now" };
                self.snapshot = Some(PoolSnapshot::new(label, now_unix(), devices));
            }
            Step::Preflight => {
                for d in self.snapshot()?.devices.values() {
                    preflight(d)?;
                    println!("    {} is in factory state (factory key 0x0001 only)", format_serial(d.serial));
                }
            }
            Step::SaveSnapshot => {
                let snapshot = self.snapshot()?.clone();
                let file = match self.env.mode {
                    Mode::Compare => after_snapshot_file(snapshot.taken_at_unix),
                    _ => BEFORE_SNAPSHOT_FILE.to_string(),
                };
                let mut labelled = snapshot;
                labelled.label = if self.env.mode == Mode::Compare { "after".into() } else { "before".into() };
                labelled.save_new(&self.env.out_dir.join(&file))?;
                println!("    saved {}", self.env.out_dir.join(&file).display());
            }
            Step::MatchBefore => {
                let before = PoolSnapshot::load(&self.env.out_dir.join(BEFORE_SNAPSHOT_FILE))?;
                let comparison = compare_pools(&before, self.snapshot()?);
                println!("{}", comparison.render());
                write_json(&self.env.out_dir.join(format!("comparison-{}.json", now_unix())), &comparison)?;
                if !comparison.is_identical() {
                    return Err(harness_error("the devices do not read as the before snapshot"));
                }
            }
            Step::LoadAnchors => {
                let path = self.env.attestation_roots.clone().ok_or_else(|| {
                    harness_error(format!(
                        "{}: {}",
                        bv_core::hsm::hw_validation::ENV_ATTESTATION_ROOTS,
                        bv_core::hsm::attestation::anchors_not_configured()
                    ))
                })?;
                let anchors = YubicoTrustAnchors::load(&path)?;
                println!("    Yubico roots in {}: {:?}", anchors.source(), anchors.root_fingerprints());
                self.anchors = Some(path);
            }
            Step::Provision => {
                let factory = factory_password(env_lookup);
                let admin = bv_core::hsm::hw_validation::admin_password(env_lookup)?;
                for i in 0..self.connectors.len() {
                    let (url, serial) = (self.connectors[i].url(), self.connectors[i].serial);
                    self.wrote = true;
                    let bundle =
                        yubihsm2::provision(&url, factory.expose(), admin.expose(), &self.objects, false).await?;
                    if bundle.serial != format_serial(serial) {
                        return Err(harness_error(format!("provision on {url} produced a bundle for {}", bundle.serial)));
                    }
                    write_json(&self.env.out_dir.join(format!("bundle-{}.json", bundle.serial)), &bundle)?;
                    println!("    provisioned {}", bundle.serial);
                    self.bundles.insert(serial, bundle);
                }
            }
            Step::Attest => self.attest().await?,
            Step::EnrollTestNode => {
                let credential = NodeCredential::generate(node_auth_key_id(0)?)?;
                for i in 0..self.connectors.len() {
                    let session = self.admin_session(i)?;
                    session.put_node_auth_key(&format!("bv-node-{}", device::TEST_NODE), &credential).await?;
                }
                println!("    test node key {:#06x} on both devices", credential.auth_key_id());
                self.credential = Some(credential);
            }
            Step::DualWrap => self.dual_wrap().await?,
            Step::Relay => self.relay().await?,
            Step::Latency => {
                for i in 0..self.connectors.len() {
                    let backend = self.member(i)?;
                    let label = format_serial(self.connectors[i].serial);
                    let iterations = self.env.latency_iterations;
                    let result =
                        device::measure(&backend, &label, &self.objects, iterations, &mut self.samples).await;
                    self.check(format!("latency {label}"), result.map(|_| format!("{iterations} rounds")).map_err(|e| e.to_string()));
                }
                let table = self.samples.to_markdown();
                println!("{table}");
                std::fs::write(self.env.out_dir.join("latency.md"), &table)
                    .map_err(|e| harness_error(e.to_string()))?;
                write_json(&self.env.out_dir.join("latency.json"), &self.samples.rows())?;
            }
            Step::RevokeTestNode => {
                let id = self.credential()?.auth_key_id();
                for i in 0..self.connectors.len() {
                    let serial = format_serial(self.connectors[i].serial);
                    let deleted = self.admin_session(i)?.delete_node_auth_key(id).await;
                    self.check(
                        format!("revoke test node on {serial}"),
                        match deleted {
                            Ok(true) => Ok("deleted".into()),
                            Ok(false) => Err("the key was already gone".into()),
                            Err(e) => Err(e.to_string()),
                        },
                    );
                    let refused = self.member(i).is_err();
                    self.check(
                        format!("revoked credential refused by {serial}"),
                        if refused { Ok("device refuses the session".into()) } else { Err("session opened".into()) },
                    );
                }
            }
            Step::ResetInstructions => {
                let text = reset_instructions(&self.env.serials.serials(), &self.env.out_dir);
                println!("\n{text}\n");
                std::fs::write(self.env.out_dir.join("RESET-REQUIRED.txt"), text)
                    .map_err(|e| harness_error(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<&PoolSnapshot, RvError> {
        self.snapshot.as_ref().ok_or_else(|| harness_error("no snapshot taken"))
    }

    /// `verify_member` (pinned chain, challenge, layout) on each device, the
    /// details of each attested key, and a bundle presented to the wrong device.
    async fn attest(&mut self) -> Result<(), RvError> {
        let mut report = BTreeMap::new();
        for i in 0..self.connectors.len() {
            let serial = self.connectors[i].serial;
            let bundle = self.bundles.get(&serial).cloned().ok_or_else(|| harness_error("no bundle"))?;
            let session = self.admin_session(i)?;
            let verified = verify_member(&session, &bundle, &self.objects).await;
            self.check(
                format!("attest {}", bundle.serial),
                verified.map(|v| format!("{} fingerprints {:?}", v.hsm_id, v.attestation_fps)).map_err(|e| e.to_string()),
            );
            for (what, hex_value) in [
                ("identity", &bundle.identity_attestation),
                ("authz", &bundle.authz_attestation),
                ("seed-ecdh", &bundle.seed_ecdh_attestation),
            ] {
                let chain = hex::decode(hex_value).map_err(|e| harness_error(e.to_string()))?;
                let detail = match session.verify_pinned(&chain, SystemTime::now()) {
                    Ok(a) => serde_json::json!({
                        "serial": a.serial, "object_id": a.object_id, "label": a.label, "origin": a.origin,
                        "capabilities": format!("{:#018x}", a.capabilities), "domains": format!("{:#06x}", a.domains),
                        "firmware": a.firmware, "algorithm": format!("{:?}", a.algorithm),
                        "device_certificate_sha256": a.device_certificate_sha256, "root_sha256": a.root_sha256,
                    }),
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                };
                report.insert(format!("{}/{what}", bundle.serial), detail);
            }
            // The other device's bundle must not verify on this device.
            if let Some(other) = self.bundles.iter().find(|(s, _)| **s != serial).map(|(_, b)| b.clone()) {
                let crossed = verify_member(&session, &other, &self.objects).await;
                self.check(
                    format!("bundle {} refused by {}", other.serial, bundle.serial),
                    match crossed {
                        Ok(_) => Err("accepted".into()),
                        Err(e) => Ok(e.to_string()),
                    },
                );
            }
        }
        write_json(&self.env.out_dir.join("attestations.json"), &report)
    }

    /// Dual-wrap on both devices with the test node key, and the device
    /// facts phase 2 left open (the unwrap MAC failure code, domain 2).
    async fn dual_wrap(&mut self) -> Result<(), RvError> {
        let ctx = device::test_context();
        let secret = [0x5au8; 32];
        let a = self.member(0)?;
        let b = self.member(1)?;
        let blob_a = a.wrap_data(self.objects.wrap_barrier, &ctx, &secret).await?;
        let blob_b = b.wrap_data(self.objects.wrap_barrier, &ctx, &secret).await?;
        for (name, backend, blob) in [("a", &a, &blob_a), ("b", &b, &blob_b)] {
            let opened = backend.unwrap_data(self.objects.wrap_barrier, &ctx, blob).await;
            self.check(
                format!("dual-wrap round trip on {name} ({})", backend.device_serial()),
                match opened {
                    Ok(p) if p.as_slice() == secret => Ok("unwrapped what was wrapped".into()),
                    Ok(_) => Err("unwrapped other bytes".into()),
                    Err(e) => Err(e.to_string()),
                },
            );
        }
        let crossed = a.unwrap_data(self.objects.wrap_barrier, &ctx, &blob_b).await;
        self.check(
            "a copy for one device is refused by the other",
            match crossed {
                Err(e) => Ok(e.to_string()),
                Ok(_) => Err("opened".into()),
            },
        );
        let mut tampered = BvHsmBlob::from_bytes(&blob_a)?;
        if let Some(last) = tampered.wrapped.last_mut() {
            *last ^= 0x01;
        }
        let tampered = a.unwrap_data(self.objects.wrap_barrier, &ctx, &tampered.to_bytes()?).await;
        self.check(
            "a tampered copy fails as a crypto failure (device INVALID_DATA -> ErrHsmContextMismatch)",
            match tampered {
                Err(RvError::ErrHsmContextMismatch) => Ok("ErrHsmContextMismatch".into()),
                Err(other) => Err(format!("got {other} instead; fix map_unwrap in hsm/yubihsm2.rs")),
                Ok(_) => Err("opened".into()),
            },
        );
        let identity = a.sign(self.objects.identity, "phase7-domain-check", b"x").await;
        self.check(
            "a node key cannot sign with bv-identity (domain 2)",
            match identity {
                Err(e) => Ok(e.to_string()),
                Ok(_) => Err("signed".into()),
            },
        );
        Ok(())
    }

    /// Each device through a real gateway and relay (mTLS, throwaway CA),
    /// as a node without a local device reaches it, with its own timings.
    async fn relay(&mut self) -> Result<(), RvError> {
        let pki = LinkPki::new();
        for i in 0..self.connectors.len() {
            let serial = format_serial(self.connectors[i].serial);
            let result = self.relay_one(&pki, i).await;
            self.check(format!("relay to {serial}"), result.map_err(|e| e.to_string()));
        }
        Ok(())
    }

    async fn relay_one(&mut self, pki: &LinkPki, index: usize) -> Result<String, RvError> {
        let c = &self.connectors[index];
        let label = format!("{} via relay", format_serial(c.serial));
        let (server_cert, server_key) = pki.leaf(&["127.0.0.1"]);
        let gateway = GatewayThread::start(GatewayConfig {
            listen: "127.0.0.1:0".parse().map_err(|_| harness_error("listen address"))?,
            connector: ConnectorUrl::parse(&c.url())?,
            tls: LinkTls::from_pem(server_cert, server_key, pki.ca_pem.clone()),
            allowed_clients: vec![device::TEST_NODE.to_string()],
            max_rps_per_client: 1000,
            limits: GatewayLimits::default(),
        })?;
        let (node_cert, node_key) = pki.leaf(&[device::TEST_NODE]);
        let relay = Relay::start(RelayConfig {
            gateway: GatewayUrl::parse(&format!("https://127.0.0.1:{}", gateway.gateway.local_addr().port()))?,
            tls: LinkTls::from_pem(node_cert, node_key, pki.ca_pem.clone()),
            limits: RelayLimits::default(),
        })?;
        let http = HttpConfig { addr: "127.0.0.1".into(), port: relay.local_addr().port(), ..HttpConfig::default() };
        let credential = self.credential()?.clone();
        let backend = device::open_member(Connector::http(&http), Some(relay), &credential, self.objects)?;
        let iterations = self.env.latency_iterations;
        device::measure(&backend, &label, &self.objects, iterations, &mut self.samples).await?;
        Ok(format!("{iterations} rounds through the gateway; stats {:?}", gateway.gateway.stats()))
    }
}

/// The gateway on its own thread and runtime. The harness drives the
/// devices with blocking `yubihsm` calls from the test's runtime, which
/// could otherwise leave a gateway task spawned there unpolled (as the
/// relay already runs on its own thread). Stopped and joined on drop.
struct GatewayThread {
    gateway: Arc<Gateway>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl GatewayThread {
    fn start(config: GatewayConfig) -> Result<Self, RvError> {
        let (ready, bound) = std::sync::mpsc::channel::<Result<Arc<Gateway>, RvError>>();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("phase7-gateway".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        let _ = ready.send(Err(harness_error(format!("gateway runtime: {e}"))));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let gateway = match Gateway::bind(config).await {
                        Ok(gateway) => Arc::new(gateway),
                        Err(e) => {
                            let _ = ready.send(Err(e));
                            return;
                        }
                    };
                    let _ = ready.send(Ok(gateway.clone()));
                    let served = gateway
                        .serve(async {
                            let _ = stopped.await;
                        })
                        .await;
                    if let Err(e) = served {
                        eprintln!("    phase 7 gateway stopped with an error: {e}");
                    }
                });
            })
            .map_err(|e| harness_error(format!("gateway thread: {e}")))?;
        let gateway = bound.recv().map_err(|_| harness_error("the gateway thread exited before binding"))??;
        Ok(Self { gateway, stop: Some(stop), thread: Some(thread) })
    }
}

impl Drop for GatewayThread {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A throwaway link CA for the relay step; nothing of it is written to disk.
struct LinkPki {
    ca_pem: String,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl LinkPki {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "phase7 link CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("ca key")).expect("ca");
        Self { ca_pem: issuer.pem(), issuer }
    }

    fn leaf(&self, sans: &[&str]) -> (String, String) {
        let key = KeyPair::generate().expect("leaf key");
        let params = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).expect("leaf");
        let cert = params.signed_by(&key, &*self.issuer).expect("leaf cert");
        (cert.pem(), key.serialize_pem())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hsm_pool_hardware() {
    let env = match HarnessEnv::from_env() {
        Ok(None) => {
            eprintln!("skipped: set {ENV_ENABLE}=1 to run the phase 7 hardware suite (docs/hsm.md)");
            return;
        }
        Ok(Some(env)) => env,
        Err(e) => panic!("{e}"),
    };
    let steps = plan(env.mode, env.until, env.allow_writes).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&env.out_dir).unwrap_or_else(|e| panic!("{}: {e}", env.out_dir.display()));
    println!("phase 7 {:?}: {:?}", env.mode, steps.iter().map(Step::name).collect::<Vec<_>>());
    let mut run = Run {
        env,
        objects: HsmObjectIds::default(),
        connectors: Vec::new(),
        snapshot: None,
        anchors: None,
        bundles: BTreeMap::new(),
        credential: None,
        checks: Vec::new(),
        samples: LatencySamples::default(),
        wrote: false,
    };
    for step in steps {
        println!("==> {}", step.name());
        if let Err(e) = run.step(step).await {
            if run.wrote {
                println!("\n{}\n", reset_instructions(&run.env.serials.serials(), &run.env.out_dir));
            }
            panic!("phase 7 step {:?} failed: {e}", step.name());
        }
    }
    let _ = write_json(&run.env.out_dir.join(format!("checks-{}.json", now_unix())), &run.checks);
    let failed: Vec<&str> = run.checks.iter().filter(|c| !c.passed).map(|c| c.name.as_str()).collect();
    assert!(failed.is_empty(), "phase 7 checks failed: {failed:?} (details above and in checks-*.json)");
}
