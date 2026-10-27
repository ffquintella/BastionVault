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
        domain_separated, AttestedKey, HsmBackend, HsmObjectId, HsmObjectIds, ResolvedHsmConfig, ResolvedLink,
    },
};

/// The device attestation certificate: opaque object 0, signed by Yubico.
/// Reading it needs `get-opaque`, which only the factory key holds in the
/// pool layout, so `provision` reads it before deleting that key.
pub const DEVICE_ATTESTATION_CERT_ID: u16 = 0;

/// Read the device attestation certificate (opaque object 0).
pub fn device_attestation_certificate(client: &Client) -> Result<Vec<u8>, RvError> {
    client.get_opaque(DEVICE_ATTESTATION_CERT_ID).map_err(|e| {
        RvError::ErrHsmAttestationInvalid(format!(
            "cannot read the device attestation certificate (opaque object 0): {e}"
        ))
    })
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
    Ok(ExpectedKey {
        serial,
        object_id,
        label,
        capabilities: capabilities.bits(),
        domains: domains.bits(),
        algorithm,
    })
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
        _ => RvError::ErrHsm(format!("yubihsm: {e}")),
    }
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
            let msg = client.wrap_data(key, inner.to_vec()).map_err(map_yubi)?;
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
            let pt = client.unwrap_data(key, msg).map_err(map_unwrap)?;
            Ok(Zeroizing::new(pt))
        })
    }

    async fn sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        let signed = domain_separated(ctx, msg);
        let client = self.client()?;
        if key == self.objects.authz {
            // bv-authz: pure Ed25519 over the domain-separated bytes.
            let sig = client.sign_ed25519(key, signed).map_err(map_yubi)?;
            Ok(sig.to_bytes().to_vec())
        } else {
            // bv-identity: ECDSA-P256 over SHA-256(domain-separated bytes),
            // signed via the device's raw-prehash path. Returns DER.
            let digest = Sha256::digest(&signed).to_vec();
            client.sign_ecdsa_prehash_raw(key, digest).map_err(map_yubi)
        }
    }

    /// The key's attestation certificate (signed by the device's default
    /// attestation key) followed by the device certificate (object 0), so the
    /// verifier can walk to the Yubico root. Fails, rather than emitting a
    /// leaf alone, when this auth key cannot read object 0.
    async fn attest(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        let client = self.client()?;
        let device = device_attestation_certificate(&client)?;
        let cert = client.sign_attestation_certificate(key, None).map_err(map_yubi)?;
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
        let shared = client.derive_ecdh(key, point).map_err(map_yubi)?;
        // The shared secret is the X coordinate of the resulting point (32
        // bytes), matching the mock's `raw_secret_bytes`.
        Ok(Zeroizing::new(extract_x_coordinate(shared.as_ref())))
    }

    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let client = self.client()?;
        Ok(Zeroizing::new(client.get_pseudo_random(len).map_err(map_yubi)?))
    }

    /// `yubihsm` 0.42 sends `device-info` inside the client's session; the
    /// session-free probe through the HSM link arrives with T454 phase 3.
    async fn probe(&self) -> Result<String, RvError> {
        let client = self.client()?;
        client.device_info().map(|i| i.serial_number.to_string()).map_err(map_yubi)
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

/// Capability names as the layout check spells them; any other bit is
/// reported as `unmapped:<bits>` so an exact comparison fails on it.
fn capability_names(caps: Capability) -> Vec<String> {
    let known = [
        (Capability::WRAP_DATA, "wrap-data"),
        (Capability::UNWRAP_DATA, "unwrap-data"),
        (Capability::EXPORTABLE_UNDER_WRAP, "exportable-under-wrap"),
        (Capability::EXPORT_WRAPPED, "export-wrapped"),
        (Capability::SIGN_ECDSA, "sign-ecdsa"),
        (Capability::SIGN_EDDSA, "sign-eddsa"),
        (Capability::DERIVE_ECDH, "derive-ecdh"),
        (Capability::GET_PSEUDO_RANDOM, "get-pseudo-random"),
        (Capability::SIGN_ATTESTATION_CERTIFICATE, "sign-attestation-certificate"),
    ];
    let mut out = Vec::new();
    let mut rest = caps;
    for (flag, name) in known {
        if caps.contains(flag) {
            out.push(name.to_string());
            rest.remove(flag);
        }
    }
    if !rest.is_empty() {
        out.push(format!("unmapped:{:#x}", rest.bits()));
    }
    out
}

fn admin_capabilities() -> Capability {
    Capability::DELETE_ASYMMETRIC_KEY
        | Capability::DELETE_AUTHENTICATION_KEY
        | Capability::DELETE_WRAP_KEY
        | Capability::GENERATE_ASYMMETRIC_KEY
        | Capability::GENERATE_WRAP_KEY
        | Capability::PUT_AUTHENTICATION_KEY
        | Capability::SIGN_ATTESTATION_CERTIFICATE
        | Capability::SIGN_ECDSA
}

fn node_capabilities() -> Capability {
    Capability::WRAP_DATA
        | Capability::UNWRAP_DATA
        | Capability::SIGN_EDDSA
        | Capability::DERIVE_ECDH
        | Capability::GET_PSEUDO_RANDOM
}

/// What `bv-admin` may hand on: exactly the capabilities of the objects it
/// creates, so it can never mint an exportable object.
fn admin_delegated() -> Capability {
    node_capabilities() | Capability::SIGN_ECDSA
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
            .generate_wrap_key(id, label(label_text)?, Domain::DOM1, wrap, Capability::empty(), wrap::Algorithm::Aes256Ccm)
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

    /// No trust file configured: refused, naming the setting.
    #[test]
    fn attestation_is_refused_without_a_trust_file() {
        let err = load_anchors(None).unwrap_err().to_string();
        assert!(err.contains("attestation_roots_file"), "{err}");
        let err = load_anchors(Some(Path::new("/nonexistent/yubico-attestation.pem"))).unwrap_err().to_string();
        assert!(err.contains("/nonexistent/yubico-attestation.pem"), "{err}");
    }
}
