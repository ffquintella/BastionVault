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

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use yubihsm::{
    connector::{HttpConfig, UsbConfig},
    object, wrap, Client, Connector, Credentials,
};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        blob::{open_blob, seal_blob, BlobAad, Context},
        domain_separated, AttestedKey, HsmBackend, HsmObjectId, HsmObjectIds, ResolvedHsmConfig,
    },
};

/// Map any `yubihsm` error to an opaque HSM error (never leak device internals
/// or key material through the message).
fn map_yubi(e: impl std::fmt::Display) -> RvError {
    RvError::ErrHsm(format!("yubihsm: {e}"))
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
    /// `bv-identity`, cached at open.
    identity_pub: Vec<u8>,
}

impl YubiHsm2Backend {
    #[maybe_async::maybe_async]
    pub async fn open(config: &ResolvedHsmConfig) -> Result<Self, RvError> {
        let connector = if config.connector.eq_ignore_ascii_case("usb") {
            Connector::usb(&UsbConfig::default())
        } else {
            let mut http = HttpConfig::default();
            // Accept `http://host:port` or `host:port`.
            let hostport = config.connector.trim_start_matches("http://").trim_start_matches("https://");
            if let Some((host, port)) = hostport.rsplit_once(':') {
                http.addr = host.to_string();
                http.port = port.parse().map_err(|_| {
                    RvError::ErrHsmConfigInvalid(format!("invalid connector port in {:?}", config.connector))
                })?;
            } else {
                http.addr = hostport.to_string();
            }
            Connector::http(&http)
        };

        let credentials = Credentials::from_password(config.objects.auth_key, config.password.as_bytes());
        let client = Client::open(connector, credentials, true).map_err(map_yubi)?;

        // Cache identity/authz public keys. YubiHSM returns EC public keys as
        // the raw 64-byte X‖Y point; prepend the SEC1 uncompressed tag so the
        // bytes parse as a p256 public key everywhere else in the codebase.
        let authz_pub = client.get_public_key(config.objects.authz).map_err(map_yubi)?.as_ref().to_vec();
        let identity_raw = client.get_public_key(config.objects.identity).map_err(map_yubi)?.as_ref().to_vec();
        let identity_pub = to_sec1_uncompressed(&identity_raw);

        let serial = client.device_info().map(|i| i.serial_number.to_string()).unwrap_or_default();

        Ok(Self { client: Mutex::new(client), objects: config.objects, serial, authz_pub, identity_pub })
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

    fn device_serial(&self) -> String {
        self.serial.clone()
    }

    fn authz_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.authz_pub.clone())
    }

    fn identity_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.identity_pub.clone())
    }

    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
        let aad = BlobAad::from_context(ctx, self.authz_fingerprint()?);
        let client = self.client()?;
        seal_blob("yubihsm2", key, aad, plaintext, |inner| {
            let msg = client.wrap_data(key, inner.to_vec()).map_err(map_yubi)?;
            Ok(msg.into_vec())
        })
    }

    async fn unwrap_data(&self, key: HsmObjectId, ctx: &Context, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let expected = BlobAad::from_context(ctx, self.authz_fingerprint()?);
        let client = self.client()?;
        open_blob(wrapped, &expected, |w| {
            let msg = wrap::Message::from_vec(w.to_vec()).map_err(|_| RvError::ErrHsmBlobInvalid)?;
            let pt = client.unwrap_data(key, msg).map_err(map_yubi)?;
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

    async fn attest(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        let client = self.client()?;
        // `None` ⇒ device's default attestation key, which chains to the Yubico
        // attestation root CA.
        let cert = client.sign_attestation_certificate(key, None).map_err(map_yubi)?;
        Ok(cert.into_vec())
    }

    async fn verify_attestation(&self, cert_chain: &[u8]) -> Result<AttestedKey, RvError> {
        // Parse the leaf attestation certificate and extract the attested
        // public key and serial. The presence of a YubiHSM 2 attestation cert
        // itself certifies in-device generation and non-exportability.
        //
        // SECURITY: full pinning of the Yubico attestation root CA is required
        // before production use of the hardware backend. The enrollment flow
        // (Phase 3) is where the chain must be walked to the pinned root; this
        // leaf extraction is the input to that check. Emit a loud warning so
        // the gap is never silent.
        use x509_cert::der::Decode;
        let cert = x509_cert::Certificate::from_der(cert_chain)
            .map_err(|e| RvError::ErrHsmAttestationInvalid(format!("leaf parse: {e}")))?;

        let spki = &cert.tbs_certificate.subject_public_key_info;
        let public_key = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| RvError::ErrHsmAttestationInvalid("missing subject public key".into()))?
            .to_vec();
        let serial = cert.tbs_certificate.serial_number.to_string();

        log::warn!(
            target: "security",
            "yubihsm2 attestation: leaf parsed but Yubico root-CA chain pinning is not yet enforced — \
             enable pinned-root verification before production enrollment"
        );

        Ok(AttestedKey { label: String::new(), object_id: 0, public_key, serial, non_exportable: true })
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

// Silence unused import in some feature permutations.
#[allow(unused_imports)]
use object as _yubihsm_object;
