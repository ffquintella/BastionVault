//! Production YubiHSM 2 backend (feature `hsm_yubihsm2`).
//!
//! Implements [`HsmBackend`] over the pure-Rust `yubihsm` crate (v0.42), using
//! the HTTP connector (`yubihsm-connector`) or direct USB. All private key
//! material stays inside the device; wrap keys are provisioned without
//! `exportable-under-wrap` (enrollment, Phase 3).
//!
//! # Build & test caveat
//!
//! This module compiles only with the `hsm_yubihsm2` feature, which pulls the
//! `yubihsm` crate and its `libusb` link dependency. It talks to a physical
//! device and therefore cannot be exercised in unit tests or CI without
//! hardware (the `BVAULT_TEST_YUBIHSM=1` integration suite covers it). The
//! mock backend (`hsm_mock`) exercises the shared blob/authz/seal code paths.
//!
//! The signature and wrap constructions here are byte-for-byte compatible with
//! [`crate::hsm::mock`] where it matters for a homogeneous cluster: `bv-authz`
//! signs `domain_separated(ctx, msg)` with pure Ed25519, and wrap blobs use the
//! shared [`crate::hsm::blob`] envelope over the device's AES-CCM `wrap-data`.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::SystemTime,
};

use bv_hsm_link::{GatewayUrl, LinkTls, Relay, RelayConfig, RelayLimits};
use sha2::{Digest, Sha256};
use yubihsm::{
    asymmetric,
    audit::AuditOption,
    connector::{HttpConfig, UsbConfig},
    object, wrap, Capability, Client, Connector, Credentials, Domain,
};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        admin::{
            node_slot_of, verify_layout, HsmAdminSession, NodeCredential, ObjectInfo, ObjectKind, ADMIN_AUTH_KEY_ID,
            FACTORY_AUTH_KEY_ID,
        },
        attestation::{self, AttestedKeyAlgorithm, ExpectedKey, YubiHsmAttestation, YubicoTrustAnchors},
        blob::{open_blob, seal_blob, Context, HsmId},
        ceremony::AttestationBundle,
        device_audit::{
            log_result_from_yubihsm, AuditorCredential, DeviceLog, DeviceLogEntry, HsmAuditSession, AUDITOR_AUTH_KEY_ID,
        },
        domain_separated, AttestedKey, HsmBackend, HsmObjectId, HsmObjectIds, ResolvedHsmConfig, ResolvedLink,
    },
};

/// The device attestation certificate: opaque object 0, signed by Yubico.
/// Reading it needs `get-opaque`, which only the factory key holds in the
/// pool layout, so `provision` reads it before deleting that key.
pub const DEVICE_ATTESTATION_CERT_ID: u16 = 0;

/// Read the device attestation certificate (opaque object 0).
pub fn device_attestation_certificate(client: &Client) -> Result<Vec<u8>, RvError> {
    client.get_opaque(DEVICE_ATTESTATION_CERT_ID).map_err(device_certificate_unreadable)
}

fn device_certificate_unreadable(e: yubihsm::client::Error) -> RvError {
    RvError::ErrHsmAttestationInvalid(format!("cannot read the device attestation certificate (opaque object 0): {e}"))
}

/// An attestation as bundles carry it: the attested key's certificate
/// followed by the device certificate, both DER.
fn attestation_chain(key_certificate: Vec<u8>, device_certificate: &[u8]) -> Vec<u8> {
    let mut chain = key_certificate;
    chain.extend_from_slice(device_certificate);
    chain
}

/// The trust file, or the refusal that says how to configure one.
fn load_anchors(path: Option<&Path>) -> Result<YubicoTrustAnchors, RvError> {
    YubicoTrustAnchors::load(path.ok_or_else(attestation::anchors_not_configured)?)
}

/// The three attested objects `provision` generates, with the exact domain,
/// capabilities and algorithm each gets. Provisioning and attestation
/// verification both read this table, so they cannot drift apart.
pub fn attested_layout(
    objects: &HsmObjectIds,
) -> [(HsmObjectId, &'static str, Domain, Capability, asymmetric::Algorithm); 3] {
    [
        (objects.identity, "bv-identity", Domain::DOM2, Capability::SIGN_ECDSA, asymmetric::Algorithm::EcP256),
        (objects.seed_ecdh, "bv-seed-ecdh", Domain::DOM1, Capability::DERIVE_ECDH, asymmetric::Algorithm::EcP256),
        (objects.authz, "bv-authz", Domain::DOM1, Capability::SIGN_EDDSA, asymmetric::Algorithm::Ed25519),
    ]
}

/// What the attestation of object `object_id` on device `serial` must say.
pub fn expected_attested_key(
    objects: &HsmObjectIds,
    object_id: HsmObjectId,
    serial: u32,
) -> Result<ExpectedKey<'static>, RvError> {
    let (_, label, domains, capabilities, algorithm) =
        attested_layout(objects).into_iter().find(|entry| entry.0 == object_id).ok_or_else(|| {
            RvError::ErrHsmAttestationInvalid(format!(
                "object {object_id:#06x} is not one of the attested pool keys (bv-identity, bv-seed-ecdh, bv-authz)"
            ))
        })?;
    let algorithm = match algorithm {
        asymmetric::Algorithm::EcP256 => AttestedKeyAlgorithm::EcP256,
        asymmetric::Algorithm::Ed25519 => AttestedKeyAlgorithm::Ed25519,
        _ => AttestedKeyAlgorithm::Other,
    };
    Ok(ExpectedKey { serial, object_id, label, capabilities: capabilities.bits(), domains: domains.bits(), algorithm })
}

fn exportable(attested: &YubiHsmAttestation) -> bool {
    let caps = Capability::from_bits_retain(attested.capabilities);
    caps.intersects(Capability::EXPORTABLE_UNDER_WRAP | Capability::EXPORT_WRAPPED)
}

/// Map a `yubihsm` client error to an opaque HSM error (never leak device
/// internals or key material through the message). The class matters to the
/// pool: transport and session failures and `SESSIONS_FULL` fail over; a
/// device error does too; nothing here is reported as a cryptographic failure.
fn map_yubi(e: yubihsm::client::Error) -> RvError {
    use yubihsm::client::ErrorKind;
    if e.device_error() == Some(yubihsm::device::ErrorKind::SessionsFull) {
        return RvError::ErrHsmSessionsFull;
    }
    match e.kind() {
        ErrorKind::ConnectorError | ErrorKind::ClosedSessionError | ErrorKind::CreateFailed => {
            RvError::ErrHsmTransport(format!("yubihsm: {e}"))
        }
        // The connector dropped a kept-alive HTTP connection (typically one that
        // sat idle) and the crate reports it as a protocol error. It is a link
        // failure, not a device one: the pool must count it and retry.
        _ if is_connector_drop(&e.to_string()) => RvError::ErrHsmTransport(format!("yubihsm: {e}")),
        _ => RvError::ErrHsm(format!("yubihsm: {e}")),
    }
}

/// True for the `yubihsm` crate's rendering of a connector that closed or cut
/// the HTTP response (`bad response from connector: error reading response`).
fn is_connector_drop(message: &str) -> bool {
    message.contains("bad response from connector")
}

/// `unwrap-data` on a blob whose AES-CCM tag does not verify. The device
/// reports it as `INVALID_DATA`; to be confirmed on hardware (T454 phase 7).
/// It is a cryptographic failure, so a pool never fails over on it.
fn map_unwrap(e: yubihsm::client::Error) -> RvError {
    if e.device_error() == Some(yubihsm::device::ErrorKind::InvalidData) {
        return RvError::ErrHsmContextMismatch;
    }
    map_yubi(e)
}

/// An idempotent device call, retried once after a connector drop only.
/// `yubihsm-connector` closes an idle keep-alive connection after ~5 s and the
/// pool probes every 10 s; the crate then drops that connection and session,
/// so a `reconnect = true` client retries on fresh ones. Other errors and a
/// second drop return unchanged. Never for calls that create/delete/reset.
fn retry_stale_connection<T>(
    serial: &str,
    op: &str,
    mut call: impl FnMut() -> Result<T, yubihsm::client::Error>,
) -> Result<T, yubihsm::client::Error> {
    match call() {
        Err(e) if is_connector_drop(&e.to_string()) => {
            log::debug!(target: "security", "YubiHSM 2 {serial}: {op}: connector dropped an idle connection ({e}); retrying once");
            call()
        }
        result => result,
    }
}

pub struct YubiHsm2Backend {
    // `yubihsm::Client` is internally synchronized but not `Sync` for all
    // operations; guard it so the `Send + Sync` HsmBackend contract holds.
    client: Mutex<Client>,
    objects: HsmObjectIds,
    serial: String,
    /// Ed25519 verifying key bytes (32) of `bv-authz`, cached at open.
    authz_pub: Vec<u8>,
    /// SEC1-uncompressed P-256 public key (65 bytes, 0x04-prefixed) of
    /// `bv-identity`, cached at open. Empty for a pool member client, whose
    /// domain-1 node key cannot read the domain-2 identity.
    identity_pub: Vec<u8>,
    /// The Yubico trust file attestations are pinned to (`None` refuses).
    attestation_roots: Option<PathBuf>,
    /// The loopback relay to the member's gateway; after `client`, so the
    /// client is dropped first.
    _relay: Option<Relay>,
}

impl YubiHsm2Backend {
    #[maybe_async::maybe_async]
    pub async fn open(config: &ResolvedHsmConfig) -> Result<Self, RvError> {
        let connector = local_connector(&config.connector)?;

        let credentials = Credentials::from_password(config.objects.auth_key, config.password.as_bytes());
        let client = Client::open(connector, credentials, true).map_err(map_yubi)?;

        // Cache identity/authz public keys. YubiHSM returns EC public keys as
        // the raw 64-byte X‖Y point; prepend the SEC1 uncompressed tag so the
        // bytes parse as a p256 public key everywhere else in the codebase.
        let authz_pub = client.get_public_key(config.objects.authz).map_err(map_yubi)?.as_ref().to_vec();
        let identity_raw = client.get_public_key(config.objects.identity).map_err(map_yubi)?.as_ref().to_vec();
        let identity_pub = to_sec1_uncompressed(&identity_raw);

        // The serial is part of the device's `hsm_id`, which every v2 blob
        // binds, so an unreadable serial is an error rather than "".
        let serial = client.device_info().map(|i| i.serial_number.to_string()).map_err(map_yubi)?;

        Ok(Self {
            client: Mutex::new(client),
            objects: config.objects,
            serial,
            authz_pub,
            identity_pub,
            attestation_roots: config.attestation_roots_file.as_deref().map(PathBuf::from),
            _relay: None,
        })
    }

    fn client(&self) -> Result<std::sync::MutexGuard<'_, Client>, RvError> {
        self.client.lock().map_err(|_| RvError::ErrRwLockWritePoison)
    }
}

#[maybe_async::maybe_async]
impl HsmBackend for YubiHsm2Backend {
    fn backend_type(&self) -> &str {
        "yubihsm2"
    }

    /// The relay's forwarded / failed totals (`bv_hsm_link_requests_total`).
    fn link_totals(&self) -> Option<(u64, u64)> {
        self._relay.as_ref().map(|relay| {
            let stats = relay.stats();
            (stats.requests_forwarded, stats.requests_failed)
        })
    }

    fn device_serial(&self) -> String {
        self.serial.clone()
    }

    fn authz_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.authz_pub.clone())
    }

    fn identity_public_key(&self) -> Result<Vec<u8>, RvError> {
        if self.identity_pub.is_empty() {
            return Err(RvError::ErrHsm("bv-identity is in domain 2; a node session cannot read it".into()));
        }
        Ok(self.identity_pub.clone())
    }

    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
        let device = self.device_binding()?;
        let client = self.client()?;
        seal_blob("yubihsm2", key, ctx, &device, plaintext, |inner| {
            let msg = retry_stale_connection(&self.serial, "wrap-data", || client.wrap_data(key, inner.to_vec()))
                .map_err(map_yubi)?;
            Ok(msg.into_vec())
        })
    }

    async fn unwrap_data(
        &self,
        key: HsmObjectId,
        ctx: &Context,
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let device = self.device_binding()?;
        let client = self.client()?;
        open_blob(wrapped, ctx, &device, |w| {
            let msg = wrap::Message::from_vec(w.to_vec()).map_err(|_| RvError::ErrHsmBlobInvalid)?;
            let pt = retry_stale_connection(&self.serial, "unwrap-data", || client.unwrap_data(key, msg.clone()))
                .map_err(map_unwrap)?;
            Ok(Zeroizing::new(pt))
        })
    }

    async fn sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        let signed = domain_separated(ctx, msg);
        let client = self.client()?;
        if key == self.objects.authz {
            // bv-authz: pure Ed25519 over the domain-separated bytes.
            let sig =
                retry_stale_connection(&self.serial, "sign-eddsa", || client.sign_ed25519(key, signed.as_slice()))
                    .map_err(map_yubi)?;
            Ok(sig.to_bytes().to_vec())
        } else {
            // bv-identity: ECDSA-P256 over SHA-256(domain-separated bytes),
            // signed via the device's raw-prehash path. Returns DER.
            let digest = Sha256::digest(&signed).to_vec();
            retry_stale_connection(&self.serial, "sign-ecdsa", || client.sign_ecdsa_prehash_raw(key, digest.as_slice()))
                .map_err(map_yubi)
        }
    }

    /// The key's attestation certificate (signed by the device's default
    /// attestation key) followed by the device certificate (object 0), so the
    /// verifier can walk to the Yubico root. Fails, rather than emitting a
    /// leaf alone, when this auth key cannot read object 0.
    async fn attest(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        let client = self.client()?;
        let device =
            retry_stale_connection(&self.serial, "get-opaque", || client.get_opaque(DEVICE_ATTESTATION_CERT_ID))
                .map_err(device_certificate_unreadable)?;
        let cert = retry_stale_connection(&self.serial, "sign-attestation-certificate", || {
            client.sign_attestation_certificate(key, None)
        })
        .map_err(map_yubi)?;
        Ok(attestation_chain(cert.into_vec(), &device))
    }

    /// Per-node attestation (S17 enrollment): the chain is pinned to the
    /// Yubico trust file and the key must have been generated on the device.
    /// The per-node layout has no fixed profile, so capabilities are only
    /// reported (`non_exportable`); the pool's admin session checks them.
    async fn verify_attestation(&self, cert_chain: &[u8]) -> Result<AttestedKey, RvError> {
        let anchors = load_anchors(self.attestation_roots.as_deref())?;
        let attested = attestation::verify_chain(&anchors, cert_chain, SystemTime::now()).inspect_err(|e| {
            log::error!(target: "security", "YubiHSM 2 attestation refused: {e}");
        })?;
        Ok(AttestedKey {
            label: attested.label.clone(),
            object_id: attested.object_id,
            serial: attestation::format_serial(attested.serial),
            non_exportable: !exportable(&attested),
            public_key: attested.public_key,
        })
    }

    async fn derive_ecdh(&self, key: HsmObjectId, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let point = yubihsm::ecdh::UncompressedPoint::from_bytes(peer_pub.to_vec())
            .ok_or_else(|| RvError::ErrHsm("bad ECDH peer key".into()))?;
        let client = self.client()?;
        let shared = retry_stale_connection(&self.serial, "derive-ecdh", || client.derive_ecdh(key, point.clone()))
            .map_err(map_yubi)?;
        // The shared secret is the X coordinate of the resulting point (32
        // bytes), matching the mock's `raw_secret_bytes`.
        Ok(Zeroizing::new(extract_x_coordinate(shared.as_ref())))
    }

    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let client = self.client()?;
        let random = retry_stale_connection(&self.serial, "get-pseudo-random", || client.get_pseudo_random(len));
        Ok(Zeroizing::new(random.map_err(map_yubi)?))
    }

    /// `yubihsm` 0.42 sends `device-info` inside the client's session; the
    /// session-free probe through the HSM link arrives with T454 phase 3.
    /// The probe interval outlives the connector's keep-alive, so a drop is
    /// retried once ([`retry_stale_connection`]) before the pool sees it.
    async fn probe(&self) -> Result<String, RvError> {
        let client = self.client()?;
        retry_stale_connection(&self.serial, "device-info", || client.device_info())
            .map(|i| i.serial_number.to_string())
            .map_err(map_yubi)
    }
}

/// Ensure an EC public key is in SEC1 uncompressed form (`0x04 ‖ X ‖ Y`).
fn to_sec1_uncompressed(raw: &[u8]) -> Vec<u8> {
    if raw.len() == 65 && raw[0] == 0x04 {
        raw.to_vec()
    } else if raw.len() == 64 {
        let mut v = Vec::with_capacity(65);
        v.push(0x04);
        v.extend_from_slice(raw);
        v
    } else {
        raw.to_vec()
    }
}

/// Extract the 32-byte X coordinate (the ECDH shared secret) from an
/// uncompressed or raw point representation.
fn extract_x_coordinate(point: &[u8]) -> Vec<u8> {
    if point.len() == 65 && point[0] == 0x04 {
        point[1..33].to_vec()
    } else if point.len() >= 32 {
        point[..32].to_vec()
    } else {
        point.to_vec()
    }
}

// --- HSM pool (T454 phase 4). Compiled by `make check-hsm`; unverified on
// hardware until phase 7. ---

/// A local connector: `usb`, or `http://host:port` / `host:port`.
pub fn local_connector(raw: &str) -> Result<Connector, RvError> {
    if raw.eq_ignore_ascii_case("usb") {
        return Ok(Connector::usb(&UsbConfig::default()));
    }
    let mut http = HttpConfig::default();
    let hostport = raw.trim_start_matches("http://").trim_start_matches("https://");
    if let Some((host, port)) = hostport.rsplit_once(':') {
        http.addr = host.to_string();
        http.port =
            port.parse().map_err(|_| RvError::ErrHsmConfigInvalid(format!("invalid connector port in {raw:?}")))?;
    } else {
        http.addr = hostport.to_string();
    }
    Ok(Connector::http(&http))
}

/// How this node reaches one pool member: its local connector when the
/// member block names one, else a loopback relay to the member's mTLS gateway
/// (one relay per client: the relay serves one local connection at a time).
pub fn member_connector(
    local: &str,
    gateway: &str,
    link: Option<&ResolvedLink>,
) -> Result<(Connector, Option<Relay>), RvError> {
    if !local.is_empty() {
        return Ok((local_connector(local)?, None));
    }
    let link = link.ok_or_else(|| {
        RvError::ErrHsmConfigInvalid("a pool member reached through a gateway needs the `link` block".into())
    })?;
    let tls = LinkTls::from_files(Path::new(&link.cert_file), Path::new(&link.key_file), Path::new(&link.ca_file))?;
    let relay =
        Relay::start(RelayConfig { gateway: GatewayUrl::parse(gateway)?, tls, limits: RelayLimits::default() })?;
    let http = HttpConfig { addr: "127.0.0.1".into(), port: relay.local_addr().port(), ..HttpConfig::default() };
    Ok((Connector::http(&http), Some(relay)))
}

impl YubiHsm2Backend {
    /// A pool member client authenticated with this node's credential. A
    /// node key is domain 1, so `bv-identity` (domain 2) is never read.
    pub fn open_pool_member(
        connector: Connector,
        relay: Option<Relay>,
        credential: &NodeCredential,
        objects: HsmObjectIds,
    ) -> Result<Self, RvError> {
        let key = yubihsm::authentication::Key::from_slice(credential.key())
            .map_err(|e| RvError::ErrHsm(format!("node credential: {e}")))?;
        let client =
            Client::open(connector, Credentials::new(credential.auth_key_id(), key), true).map_err(map_yubi)?;
        let authz_pub = client.get_public_key(objects.authz).map_err(map_yubi)?.as_ref().to_vec();
        let serial = client.device_info().map(|i| i.serial_number.to_string()).map_err(map_yubi)?;
        Ok(Self {
            client: Mutex::new(client),
            objects,
            serial,
            authz_pub,
            identity_pub: Vec::new(),
            // A member client never attests; the admin session does.
            attestation_roots: None,
            _relay: relay,
        })
    }
}

/// Capability names as the device documents them (the `yubihsm` crate's
/// spelling: `set-option` for `PUT_OPTION`), one per bit, so the layout check
/// and the bv-admin capability check compare names. A bit the crate cannot
/// name is reported as `unmapped:<bit>`, so an exact comparison fails on it.
fn capability_names(caps: Capability) -> Vec<String> {
    caps.iter()
        .map(|flag| {
            // `Display` errs on a bit it has no name for; never `to_string()`,
            // which would panic on that.
            let mut name = String::new();
            match std::fmt::write(&mut name, format_args!("{flag}")) {
                Ok(()) => name,
                Err(_) => format!("unmapped:{:#x}", flag.bits()),
            }
        })
        .collect()
}

/// `bv-admin` as `provision` creates it. `PUT_OPTION` (`set-option`) is for
/// the forced-audit option (T454 phase 6); a device provisioned before it was
/// added lacks it, which `admin_capability_check` reports.
fn admin_capabilities() -> Capability {
    Capability::DELETE_ASYMMETRIC_KEY
        | Capability::DELETE_AUTHENTICATION_KEY
        | Capability::DELETE_WRAP_KEY
        | Capability::GENERATE_ASYMMETRIC_KEY
        | Capability::GENERATE_WRAP_KEY
        | Capability::PUT_AUTHENTICATION_KEY
        | Capability::PUT_OPTION
        | Capability::SIGN_ATTESTATION_CERTIFICATE
        | Capability::SIGN_ECDSA
}

/// `bv-auditor` (auth key 8) on a YubiHSM 2: `get-log-entries` only. The
/// device has no `set-log-index` capability (neither `yubihsm` 0.42's
/// `Capability` nor Yubico's capability list names one, and Yubico's command
/// reference says Set Log Index needs "no specific capabilities"), so this one
/// bit is the whole read-and-acknowledge role. That a key holding only it can
/// `set-log-index` is unverified on hardware (T454 phase 7).
pub fn auditor_capabilities() -> Capability {
    Capability::GET_LOG_ENTRIES
}

fn node_capabilities() -> Capability {
    Capability::WRAP_DATA
        | Capability::UNWRAP_DATA
        | Capability::SIGN_EDDSA
        | Capability::DERIVE_ECDH
        | Capability::GET_PSEUDO_RANDOM
}

/// What `bv-admin` may hand on: exactly the capabilities of the objects it
/// creates (node keys, `bv-identity`, `bv-auditor`), so it can never mint an
/// exportable object. A new key's capabilities must all be in the creating
/// key's delegated set (Yubico, Put Authentication Key), which is why a device
/// provisioned before `bv-auditor` existed cannot create it, and why no key in
/// the layout can widen bv-admin: what it creates is bounded by this set.
fn admin_delegated() -> Capability {
    node_capabilities() | Capability::SIGN_ECDSA | auditor_capabilities()
}

/// A refused device command, with the step that failed. The class
/// `map_yubi` gives (transport, sessions full, device) is kept.
fn refused(step: &str, e: yubihsm::client::Error) -> RvError {
    match map_yubi(e) {
        RvError::ErrHsm(why) => RvError::ErrHsm(format!("{step}: {why}")),
        other => other,
    }
}

/// The `bv-auditor` credential as a YubiHSM 2 authentication key (AES-128
/// encryption key ‖ AES-128 MAC key). The error never repeats the key.
fn auditor_key(credential: &AuditorCredential) -> Result<yubihsm::authentication::Key, RvError> {
    yubihsm::authentication::Key::from_slice(credential.key())
        .map_err(|_| RvError::ErrHsm("the bv-auditor credential is not a YubiHSM 2 authentication key".into()))
}

fn label(text: &str) -> Result<object::Label, RvError> {
    object::Label::from_bytes(text.as_bytes()).map_err(|e| RvError::ErrHsm(format!("object label {text:?}: {e}")))
}

fn is_not_found(e: &yubihsm::client::Error) -> bool {
    e.device_error() == Some(yubihsm::device::ErrorKind::ObjectNotFound)
}

/// A `bv-admin` session on a YubiHSM 2.
pub struct YubiHsm2AdminSession {
    client: Mutex<Client>,
    serial: String,
    objects: HsmObjectIds,
    /// The Yubico trust file attestations are pinned to (`None` refuses).
    attestation_roots: Option<PathBuf>,
    _relay: Option<Relay>,
}

impl YubiHsm2AdminSession {
    pub fn open(
        connector: Connector,
        relay: Option<Relay>,
        password: &str,
        objects: HsmObjectIds,
        attestation_roots: Option<PathBuf>,
    ) -> Result<Self, RvError> {
        let credentials = Credentials::from_password(ADMIN_AUTH_KEY_ID, password.as_bytes());
        let client = Client::open(connector, credentials, false).map_err(map_yubi)?;
        let serial = client.device_info().map(|i| i.serial_number.to_string()).map_err(map_yubi)?;
        Ok(Self { client: Mutex::new(client), serial, objects, attestation_roots, _relay: relay })
    }

    /// The pinned check behind [`HsmAdminSession::verify_attestation`]: the
    /// chain reaches a root in the trust file, the key was generated on this
    /// very device (serial), and its object id, label, domains, capabilities
    /// and algorithm are exactly what `provision` creates for that object.
    pub fn verify_pinned(&self, chain: &[u8], now: SystemTime) -> Result<YubiHsmAttestation, RvError> {
        let anchors = load_anchors(self.attestation_roots.as_deref())?;
        let attested = attestation::verify_chain(&anchors, chain, now)?;
        let serial = attestation::parse_serial(&self.serial)?;
        attested.require(&expected_attested_key(&self.objects, attested.object_id, serial)?)?;
        if exportable(&attested) {
            return Err(RvError::ErrHsmAttestationInvalid(format!("{} carries an export capability", attested.label)));
        }
        Ok(attested)
    }

    fn client(&self) -> Result<std::sync::MutexGuard<'_, Client>, RvError> {
        self.client.lock().map_err(|_| RvError::ErrRwLockWritePoison)
    }
}

#[maybe_async::maybe_async]
impl HsmAdminSession for YubiHsm2AdminSession {
    fn hsm_id(&self) -> Result<HsmId, RvError> {
        HsmId::from_parts("yubihsm2", &self.serial)
    }

    async fn object_info(&self, kind: ObjectKind, id: u16) -> Result<Option<ObjectInfo>, RvError> {
        let object_type = match kind {
            ObjectKind::WrapKey => object::Type::WrapKey,
            ObjectKind::AsymmetricKey => object::Type::AsymmetricKey,
            ObjectKind::AuthenticationKey => object::Type::AuthenticationKey,
        };
        match self.client()?.get_object_info(id, object_type) {
            Ok(info) => Ok(Some(ObjectInfo {
                id,
                kind,
                label: info.label.to_string(),
                capabilities: capability_names(info.capabilities),
                delegated: capability_names(info.delegated_capabilities),
            })),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(map_yubi(e)),
        }
    }

    async fn auth_key_ids(&self) -> Result<Vec<u16>, RvError> {
        let filter = [object::Filter::Type(object::Type::AuthenticationKey)];
        Ok(self.client()?.list_objects(&filter).map_err(map_yubi)?.into_iter().map(|e| e.object_id).collect())
    }

    async fn put_node_auth_key(&self, label_text: &str, credential: &NodeCredential) -> Result<(), RvError> {
        node_slot_of(credential.auth_key_id())?;
        let key = yubihsm::authentication::Key::from_slice(credential.key())
            .map_err(|e| RvError::ErrHsm(format!("node credential: {e}")))?;
        self.client()?
            .put_authentication_key(
                credential.auth_key_id(),
                label(label_text)?,
                Domain::DOM1,
                node_capabilities(),
                Capability::empty(),
                yubihsm::authentication::Algorithm::YubicoAes,
                key,
            )
            .map_err(map_yubi)?;
        Ok(())
    }

    async fn generate_wrap_key(&self, id: HsmObjectId, label_text: &str) -> Result<(), RvError> {
        let wrap = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        self.client()?
            .generate_wrap_key(
                id,
                label(label_text)?,
                Domain::DOM1,
                wrap,
                Capability::empty(),
                wrap::Algorithm::Aes256Ccm,
            )
            .map_err(map_yubi)?;
        Ok(())
    }

    async fn delete_wrap_key(&self, id: HsmObjectId) -> Result<bool, RvError> {
        match self.client()?.delete_object(id, object::Type::WrapKey) {
            Ok(()) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(map_yubi(e)),
        }
    }

    async fn delete_node_auth_key(&self, auth_key_id: u16) -> Result<bool, RvError> {
        node_slot_of(auth_key_id)?;
        match self.client()?.delete_object(auth_key_id, object::Type::AuthenticationKey) {
            Ok(()) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(map_yubi(e)),
        }
    }

    async fn public_key(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        let raw = self.client()?.get_public_key(key).map_err(map_yubi)?.as_ref().to_vec();
        // EC P-256 keys come back as X ‖ Y; Ed25519 as the 32-byte key.
        Ok(if raw.len() == 64 { to_sec1_uncompressed(&raw) } else { raw })
    }

    async fn identity_sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        if key != self.objects.identity {
            return Err(RvError::ErrHsm(format!("an admin session signs only with bv-identity, not object {key}")));
        }
        let digest = Sha256::digest(domain_separated(ctx, msg)).to_vec();
        self.client()?.sign_ecdsa_prehash_raw(key, digest).map_err(map_yubi)
    }

    /// Pinned to the operator's Yubico trust file ([`Self::verify_pinned`]);
    /// refused outright when none is configured. `verify_member` then checks
    /// the key against the bundle and the device's own public key.
    async fn verify_attestation(&self, chain: &[u8]) -> Result<AttestedKey, RvError> {
        let attested = self.verify_pinned(chain, SystemTime::now()).inspect_err(|e| {
            log::error!(target: "security", "YubiHSM 2 {} attestation refused: {e}", self.serial);
        })?;
        log::info!(
            target: "security",
            "YubiHSM 2 {} attested {} (object {:#06x}) to Yubico root {}",
            self.serial, attested.label, attested.object_id, attested.root_sha256
        );
        Ok(AttestedKey {
            label: attested.label,
            object_id: attested.object_id,
            public_key: attested.public_key,
            serial: self.serial.clone(),
            non_exportable: true,
        })
    }

    async fn close(&self) -> Result<(), RvError> {
        Ok(())
    }

    /// Replace `bv-auditor`: auth key 8, [`auditor_capabilities`], domain 1,
    /// nothing delegated, `YubicoAes` with the credential. Implemented from
    /// Yubico's command reference and the mock; unverified on hardware.
    async fn put_auditor_auth_key(&self, credential: &AuditorCredential) -> Result<(), RvError> {
        // Read-only first. A bv-admin from an older `provision` cannot
        // delegate `get-log-entries`, and the device would refuse the put
        // after the delete below; refuse before writing anything instead.
        self.admin_capability_check().await?.require_auditor()?;
        let hsm_id = self.hsm_id()?;
        let key = auditor_key(credential)?;
        let client = self.client()?;
        // Replace is delete, then put. Yubico's reference does not say whether
        // `put-authentication-key` on an id in use overwrites or fails (the
        // device has an OBJECT_EXISTS status, 0x11; `yubihsm`'s own MockHsm
        // overwrites), so neither is relied on. A failure in between leaves no
        // key 8: the drain stops authenticating, nothing new is stored (the
        // caller stores after this returns), and the next admin repair
        // installs one.
        match client.delete_object(AUDITOR_AUTH_KEY_ID, object::Type::AuthenticationKey) {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(refused(&format!("{hsm_id}: deleting the old bv-auditor (auth key 8)"), e)),
        }
        client
            .put_authentication_key(
                AUDITOR_AUTH_KEY_ID,
                label("bv-auditor")?,
                Domain::DOM1,
                auditor_capabilities(),
                Capability::empty(),
                yubihsm::authentication::Algorithm::YubicoAes,
                key,
            )
            .map_err(|e| refused(&format!("{hsm_id}: creating bv-auditor (put-authentication-key, auth key 8)"), e))?;
        Ok(())
    }

    /// The device's force-audit option: `On` or `Off`, never `Fix` (Yubico:
    /// enabled until a factory reset). Implemented from the `yubihsm` crate
    /// and Yubico's command reference; unverified on hardware. Refused first,
    /// without writing, when bv-admin lacks `set-option`: Yubico's reference
    /// says Set Option needs no capability, but a device whose bv-admin
    /// predates the drain cannot install `bv-auditor` either, and forced
    /// audit on a log nobody drains would stop the device once it fills.
    async fn set_forced_audit(&self, on: bool) -> Result<(), RvError> {
        self.admin_capability_check().await?.require_forced_audit()?;
        let hsm_id = self.hsm_id()?;
        let option = if on { AuditOption::On } else { AuditOption::Off };
        self.client()?
            .set_force_audit_option(option)
            .map_err(|e| refused(&format!("{hsm_id}: set-option force-audit {}", if on { "on" } else { "off" }), e))
    }
}

/// A `bv-auditor` session on a YubiHSM 2 (T454 phase 6): read and acknowledge
/// the device log. Implemented from Yubico's command reference, the `yubihsm`
/// crate and the mock; unverified on hardware (T454 phase 7).
///
/// `yubihsm` 0.42 has no public way to send `CloseSession` from a `Client`, so
/// [`HsmAuditSession::close`] only drops the host side and the device frees
/// the slot on its 30 s idle expiry.
pub struct YubiHsm2AuditSession {
    client: Mutex<Client>,
    serial: String,
    /// After `client`, so the client is dropped first.
    _relay: Option<Relay>,
}

impl YubiHsm2AuditSession {
    /// Authenticate as auth key 8 and read the serial the drain checks the
    /// member's `hsm_id` against. Fails when the credential does not
    /// authenticate, which is how a repair finds a stale one.
    pub fn open(connector: Connector, relay: Option<Relay>, credential: &AuditorCredential) -> Result<Self, RvError> {
        let key = auditor_key(credential)?;
        // No reconnect: the client keeps no copy of the credential once the
        // session is up, and a session the device expired fails that drain
        // tick (the next tick opens a new one) rather than re-authenticating.
        let client = Client::open(connector, Credentials::new(AUDITOR_AUTH_KEY_ID, key), false).map_err(map_yubi)?;
        let serial = client.device_info().map(|i| i.serial_number.to_string()).map_err(map_yubi)?;
        Ok(Self { client: Mutex::new(client), serial, _relay: relay })
    }

    fn client(&self) -> Result<std::sync::MutexGuard<'_, Client>, RvError> {
        self.client.lock().map_err(|_| RvError::ErrRwLockWritePoison)
    }
}

#[maybe_async::maybe_async]
impl HsmAuditSession for YubiHsm2AuditSession {
    fn hsm_id(&self) -> Result<HsmId, RvError> {
        HsmId::from_parts("yubihsm2", &self.serial)
    }

    /// The fields as the device lays them out (`DeviceLogEntry::data`), with
    /// the result byte the device wrote: the digest covers that byte, not
    /// `yubihsm`'s re-encoding of it (`log_result_from_yubihsm`). An entry
    /// whose command byte `yubihsm` 0.42 does not know fails the whole read
    /// in the crate, which the drain reports as a failure, never a skip.
    async fn get_log_entries(&self) -> Result<DeviceLog, RvError> {
        let log = self.client()?.get_log_entries().map_err(|e| refused("get-log-entries", e))?;
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
                result: log_result_from_yubihsm(e.result.to_u8()),
                systick: e.tick,
                digest: e.digest.0,
            })
            .collect();
        Ok(DeviceLog { unlogged_boot: log.unlogged_boot_events, unlogged_auth: log.unlogged_auth_events, entries })
    }

    async fn set_log_index(&self, index: u16) -> Result<(), RvError> {
        self.client()?.set_log_index(index).map_err(|e| refused(&format!("set-log-index {index}"), e))
    }
}

/// `bvault operator hsm provision` on a YubiHSM 2 (spec § Provision a
/// device), through its local connector: from factory state, read the
/// device attestation certificate, create `bv-admin` and the layout, delete
/// factory key 1, return the bundle. Validated on hardware by T454 phase 7.
#[maybe_async::maybe_async]
pub async fn provision(
    connector: &str,
    factory_password: &str,
    admin_password: &str,
    objects: &HsmObjectIds,
    adopt: bool,
) -> Result<AttestationBundle, RvError> {
    if admin_password.is_empty() {
        return Err(RvError::ErrHsm("the bv-admin password must not be empty".into()));
    }
    let mut device_certificate = None;
    if !adopt {
        let factory = Credentials::from_password(FACTORY_AUTH_KEY_ID, factory_password.as_bytes());
        let client = Client::open(local_connector(connector)?, factory, false).map_err(map_yubi)?;
        // Read-only, before any write: a device whose certificate cannot be
        // read could never be attested, so it is left untouched.
        device_certificate = Some(device_attestation_certificate(&client)?);
        let present = client.list_objects(&[]).map_err(map_yubi)?;
        let factory_state = present.len() == 1
            && present[0].object_id == FACTORY_AUTH_KEY_ID
            && present[0].object_type == object::Type::AuthenticationKey;
        if !factory_state {
            return Err(RvError::ErrHsm(format!(
                "the YubiHSM 2 holds {} objects, not only factory key 1; refusing to provision it (--adopt accepts a \
                 device whose layout verifies)",
                present.len()
            )));
        }
        client
            .put_authentication_key(
                ADMIN_AUTH_KEY_ID,
                label("bv-admin")?,
                Domain::DOM1 | Domain::DOM2,
                admin_capabilities(),
                admin_delegated(),
                yubihsm::authentication::Algorithm::YubicoAes,
                yubihsm::authentication::Key::derive_from_password(admin_password.as_bytes()),
            )
            .map_err(map_yubi)?;
        let wrap = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        for (id, name) in [(objects.wrap_barrier, "bv-wrap-barrier"), (objects.wrap_pqc, "bv-wrap-pqc")] {
            client
                .generate_wrap_key(
                    id,
                    label(name)?,
                    Domain::DOM1,
                    wrap,
                    Capability::empty(),
                    wrap::Algorithm::Aes256Ccm,
                )
                .map_err(map_yubi)?;
        }
        for (id, name, domain, caps, algorithm) in attested_layout(objects) {
            client.generate_asymmetric_key(id, label(name)?, domain, caps, algorithm).map_err(map_yubi)?;
        }
    }
    let session = YubiHsm2AdminSession::open(local_connector(connector)?, None, admin_password, *objects, None)?;
    if !adopt {
        session.client()?.delete_object(FACTORY_AUTH_KEY_ID, object::Type::AuthenticationKey).map_err(map_yubi)?;
    }
    verify_layout(&session, objects).await?;
    // `--adopt` has no factory key; `bv-admin` lacks `get-opaque` in the pool
    // layout, so this is refused there, explicitly, rather than emitting a
    // bundle without the device certificate that could never be attested.
    let device_certificate = match device_certificate {
        Some(der) => der,
        None => device_attestation_certificate(&*session.client()?).map_err(|e| {
            RvError::ErrHsmAttestationInvalid(format!(
                "{e}; `--adopt` cannot produce an attestable bundle on this device, reset it and provision it from \
                 factory state"
            ))
        })?,
    };
    let attest = |id: HsmObjectId| -> Result<Vec<u8>, RvError> {
        let key_certificate = session.client()?.sign_attestation_certificate(id, None).map_err(map_yubi)?;
        Ok(attestation_chain(key_certificate.into_vec(), &device_certificate))
    };
    let bundle =
        AttestationBundle::new("yubihsm2", &session.serial, "", &attest(objects.identity)?, &attest(objects.authz)?)
            .with_seed_ecdh(&attest(objects.seed_ecdh)?);
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_dropped_connector_connection_is_a_link_failure() {
        assert!(super::is_connector_drop("protocol error: bad response from connector: error reading response"));
        assert!(!super::is_connector_drop("device error: invalid data"));
    }

    use super::*;

    /// What attestation must say is the provision table, in the bit values
    /// Yubico's attestation extensions carry (sign-ecdsa 0x80, sign-eddsa
    /// 0x100, derive-ecdh 0x800; domain n is bit n-1). AES wrap keys have no
    /// attestation; `verify_member` checks them by `get-object-info`.
    #[test]
    fn the_attested_profile_is_the_provision_layout() {
        let objects = HsmObjectIds::default();
        let profile = |id: HsmObjectId| {
            let e = expected_attested_key(&objects, id, 36_470_559).unwrap();
            assert_eq!((e.serial, e.object_id), (36_470_559, id));
            (e.label, e.capabilities, e.domains, e.algorithm)
        };
        assert_eq!(profile(objects.identity), ("bv-identity", 0x80, 0x0002, AttestedKeyAlgorithm::EcP256));
        assert_eq!(profile(objects.seed_ecdh), ("bv-seed-ecdh", 0x800, 0x0001, AttestedKeyAlgorithm::EcP256));
        assert_eq!(profile(objects.authz), ("bv-authz", 0x100, 0x0001, AttestedKeyAlgorithm::Ed25519));
        for wrap_key in [objects.wrap_barrier, objects.wrap_pqc] {
            assert!(expected_attested_key(&objects, wrap_key, 1).is_err(), "{wrap_key:#x}");
        }
    }

    /// The bits a device receives, pinned: a `yubihsm` upgrade that renumbers
    /// them fails here rather than on a device.
    #[test]
    fn the_drain_capabilities_and_option_values_are_the_wire_values() {
        assert_eq!(auditor_capabilities().bits(), 0x0100_0000, "get-log-entries");
        assert_eq!(Capability::PUT_OPTION.bits(), 0x0002_0000, "set-option");
        assert_eq!((AuditOption::Off.to_u8(), AuditOption::On.to_u8()), (0x00, 0x01));
        assert_eq!(capability_names(auditor_capabilities()), vec!["get-log-entries"]);
    }

    use crate::hsm::admin::AdminCapabilityCheck;

    /// bv-admin's object info as the device would report these masks.
    fn admin_info(capabilities: Capability, delegated: Capability) -> ObjectInfo {
        ObjectInfo {
            id: ADMIN_AUTH_KEY_ID,
            kind: ObjectKind::AuthenticationKey,
            label: "bv-admin".into(),
            capabilities: capability_names(capabilities),
            delegated: capability_names(delegated),
        }
    }

    fn check(capabilities: Capability, delegated: Capability) -> AdminCapabilityCheck {
        let hsm_id = HsmId::from_parts("yubihsm2", "36470559").unwrap();
        AdminCapabilityCheck::evaluate(&hsm_id, &admin_info(capabilities, delegated))
    }

    /// A newly provisioned bv-admin passes the shared check (the device's
    /// names are the check's names); it still delegates nothing that exports
    /// nor anything that would widen an admin, and bv-auditor can do nothing
    /// but read the log.
    #[test]
    fn a_new_bv_admin_can_install_the_auditor_and_never_mints_an_exportable_key() {
        let new = check(admin_capabilities(), admin_delegated());
        assert!(new.can_install_auditor && new.can_set_forced_audit, "{new:?}");
        let export = Capability::EXPORTABLE_UNDER_WRAP | Capability::EXPORT_WRAPPED;
        assert!(!admin_delegated().intersects(export));
        let widening = Capability::PUT_OPTION
            | Capability::PUT_AUTHENTICATION_KEY
            | Capability::DELETE_AUTHENTICATION_KEY
            | Capability::CHANGE_AUTHENTICATION_KEY
            | Capability::RESET_DEVICE;
        assert!(!admin_delegated().intersects(widening));
        assert_eq!(auditor_capabilities(), Capability::GET_LOG_ENTRIES);
        // The layout the mock models is the one provision writes.
        let mut provisioned = capability_names(admin_delegated());
        provisioned.sort();
        assert_eq!(provisioned, crate::hsm::admin::AuthKeyRole::Admin.delegated());
    }

    /// Regression: a bv-admin with the masks an earlier `provision` wrote
    /// (no `set-option`, delegated = node capabilities and `sign-ecdsa`) is
    /// refused for both writes, before any write, naming each missing bit.
    #[test]
    fn a_bv_admin_provisioned_before_the_drain_is_refused_explicitly() {
        let old = check(admin_capabilities() - Capability::PUT_OPTION, node_capabilities() | Capability::SIGN_ECDSA);
        assert!(!old.can_install_auditor && !old.can_set_forced_audit, "{old:?}");
        assert_eq!(old.auditor_missing, vec!["delegated get-log-entries"]);
        assert_eq!(old.forced_audit_missing, vec!["capability set-option"]);
        let err = old.require_auditor().unwrap_err();
        assert!(matches!(err, RvError::ErrHsm(_)), "never a transport failure: {err:?}");
        let text = err.to_string();
        for part in ["36470559", "provisioned before the device-log drain", "get-log-entries", "cannot be changed"] {
            assert!(text.contains(part), "{part:?} missing from {text}");
        }
    }

    /// Every bit the crate names comes back by its documented name; a bit it
    /// cannot name is reported, never dropped and never a panic.
    #[test]
    fn capability_names_cover_every_bit() {
        assert_eq!(
            capability_names(Capability::PUT_AUTHENTICATION_KEY | Capability::PUT_OPTION),
            vec!["put-authentication-key", "set-option"]
        );
        let unknown = Capability::from_bits_retain(0x8000_0000_0000);
        assert_eq!(capability_names(unknown), vec!["unmapped:0x800000000000"]);
        assert_eq!(capability_names(Capability::WRAP_DATA | Capability::UNWRAP_DATA).len(), 2);
    }

    #[test]
    fn the_auditor_credential_is_a_device_key_and_refusals_name_their_step() {
        let credential = AuditorCredential::from_key(Zeroizing::new(vec![0x5a; 32])).unwrap();
        assert!(auditor_key(&credential).is_ok(), "32 bytes is a YubiHSM 2 authentication key");
        let err = refused("step", yubihsm::client::ErrorKind::ProtocolError.into());
        assert!(matches!(&err, RvError::ErrHsm(why) if why == "step: yubihsm: protocol error"), "{err:?}");
        // A transport failure keeps its class, so the pool still counts it.
        let err = refused("step", yubihsm::client::ErrorKind::ConnectorError.into());
        assert!(matches!(err, RvError::ErrHsmTransport(_)), "{err:?}");
    }

    /// No trust file configured: refused, naming the setting.
    #[test]
    fn attestation_is_refused_without_a_trust_file() {
        let err = load_anchors(None).unwrap_err().to_string();
        assert!(err.contains("attestation_roots_file"), "{err}");
        let err = load_anchors(Some(Path::new("/nonexistent/yubico-attestation.pem"))).unwrap_err().to_string();
        assert!(err.contains("/nonexistent/yubico-attestation.pem"), "{err}");
    }

    /// The chain the crate builds when the connector closed the kept-alive
    /// connection: a connector `ResponseError` under two protocol errors.
    fn connector_drop() -> yubihsm::client::Error {
        let connector = yubihsm::connector::ErrorKind::ResponseError.context("error reading response");
        yubihsm::session::Error::from(yubihsm::connector::Error::from(connector)).into()
    }

    /// A status the device returned, wrapped as `Session::send_command` does.
    fn device_refusal(kind: yubihsm::device::ErrorKind) -> yubihsm::client::Error {
        yubihsm::session::Error::from(kind).into()
    }

    /// Runs `retry_stale_connection` over scripted outcomes, counting attempts;
    /// an attempt beyond the script panics.
    fn scripted(outcomes: Vec<Result<u32, yubihsm::client::Error>>) -> (Result<u32, yubihsm::client::Error>, usize) {
        let mut outcomes = outcomes.into_iter();
        let mut attempts = 0;
        let result = retry_stale_connection("36470559", "test", || {
            attempts += 1;
            outcomes.next().expect("an attempt beyond the scripted outcomes")
        });
        (result, attempts)
    }

    #[test]
    fn a_connector_drop_is_retried_once_on_a_fresh_connection() {
        let drop = connector_drop();
        assert_eq!(
            drop.to_string(),
            "protocol error: protocol error: bad response from connector: error reading response"
        );
        assert!(matches!(map_yubi(connector_drop()), RvError::ErrHsmTransport(_)));
        let (result, attempts) = scripted(vec![Err(drop), Ok(7)]);
        assert_eq!((result.unwrap(), attempts), (7, 2));
    }

    /// A connector that drops twice in a row is an outage the pool must see.
    #[test]
    fn a_second_connector_drop_is_a_transport_failure_and_never_a_third_attempt() {
        let (result, attempts) = scripted(vec![Err(connector_drop()), Err(connector_drop()), Ok(7)]);
        assert_eq!(attempts, 2);
        let err = map_yubi(result.unwrap_err());
        assert!(
            matches!(&err, RvError::ErrHsmTransport(why) if why.contains("bad response from connector")),
            "{err:?}"
        );
        // The retried attempt's own error keeps its class.
        let (result, attempts) =
            scripted(vec![Err(connector_drop()), Err(device_refusal(yubihsm::device::ErrorKind::SessionsFull))]);
        assert_eq!(attempts, 2);
        assert!(matches!(map_yubi(result.unwrap_err()), RvError::ErrHsmSessionsFull));
    }

    /// The pool-facing class of a mapped error.
    fn class(e: &RvError) -> &'static str {
        match e {
            RvError::ErrHsm(_) => "device",
            RvError::ErrHsmSessionsFull => "sessions-full",
            RvError::ErrHsmTransport(_) => "transport",
            RvError::ErrHsmContextMismatch => "context-mismatch",
            _ => "other",
        }
    }

    /// Includes a connector that refuses the connection: a real outage, not a
    /// stale socket, so it fails over at once rather than being retried.
    #[test]
    fn errors_other_than_a_connector_drop_are_never_retried() {
        use yubihsm::{client::ErrorKind, device::ErrorKind as Device};
        let refused = yubihsm::connector::ErrorKind::ConnectionFailed.context("connection refused");
        let cases: Vec<(yubihsm::client::Error, &str)> = vec![
            (ErrorKind::AuthenticationError.into(), "device"),
            (device_refusal(Device::AuthenticationFailed), "device"),
            (device_refusal(Device::InsufficientPermissions), "device"),
            (device_refusal(Device::SessionsFull), "sessions-full"),
            (ErrorKind::ProtocolError.into(), "device"),
            (yubihsm::connector::Error::from(refused).into(), "transport"),
        ];
        for (error, expected) in cases {
            let text = error.to_string();
            let (result, attempts) = scripted(vec![Err(error), Ok(7)]);
            assert_eq!(attempts, 1, "{text} was retried");
            let mapped = map_yubi(result.unwrap_err());
            assert_eq!(class(&mapped), expected, "{text} mapped to {mapped:?}");
        }
    }

    /// Regression: a blob whose tag does not verify stays a context mismatch,
    /// attempted once, so a pool never fails over or replays on it.
    #[test]
    fn an_unwrap_tag_failure_is_never_retried() {
        let (result, attempts) = scripted(vec![Err(device_refusal(yubihsm::device::ErrorKind::InvalidData)), Ok(7)]);
        assert_eq!(attempts, 1);
        assert!(matches!(map_unwrap(result.unwrap_err()), RvError::ErrHsmContextMismatch));
        let (result, attempts) =
            scripted(vec![Err(connector_drop()), Err(device_refusal(yubihsm::device::ErrorKind::InvalidData))]);
        assert_eq!(attempts, 2);
        assert!(matches!(map_unwrap(result.unwrap_err()), RvError::ErrHsmContextMismatch));
    }
}
