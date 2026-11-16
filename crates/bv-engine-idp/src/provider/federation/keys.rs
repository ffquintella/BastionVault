//! RSA signing keys of the SAML IdP and the OIDC OP. One key ring per
//! protocol, behind the barrier, created on first use under the storage
//! lock (so two nodes never mint two first keys) and never replaced on a
//! read error. Rotation keeps the retired key published for an overlap.

use std::{any::Any, fmt, sync::Arc};

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rand::SystemRandom,
    rsa::{KeyPair, KeySize},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    errors::RvError,
    posix::model::{decode_versioned, PosixError, RECORD_VERSION},
    storage::{Storage, StorageEntry},
};

/// RSASSA-PKCS1-v1_5 with SHA-256: XML-DSig `rsa-sha256` and JWS `RS256`.
pub const ALG_RS256: &str = "RS256";
const KEY_SIZE: KeySize = KeySize::Rsa3072;
const CERT_VALIDITY_YEARS: i32 = 10;
pub const DEFAULT_OVERLAP_SECS: u64 = 24 * 3600;
pub const MIN_OVERLAP_SECS: u64 = 3600;
pub const MAX_OVERLAP_SECS: u64 = 30 * 24 * 3600;
/// Keys a ring may hold: the current one plus retired ones still published.
pub const MAX_KEYS: usize = 8;

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn internal(what: &str) -> RvError {
    log::error!(target: "idp", "signing key: {what}");
    bv_errors::bv_error_response_status!(500, &format!("signing key: {what}"))
}

/// One RSA key. `Debug` never prints the private key; dropping it zeroizes
/// the encoded copy.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKey {
    /// RFC 7638 JWK thumbprint (SHA-256, base64url): fixed by the key.
    pub kid: String,
    pub alg: String,
    /// Public modulus and exponent (base64url), kept so the unauthenticated
    /// JWKS never decodes the private key.
    pub n: String,
    pub e: String,
    /// PKCS#8 DER, standard base64. Never returned by any read path.
    pub pkcs8: String,
    /// Self-signed certificate around the public key (SAML metadata).
    pub cert_pem: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
    /// A retired key stays in metadata and the JWKS until then.
    pub publish_until: Option<DateTime<Utc>>,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("created_at", &self.created_at)
            .field("retired_at", &self.retired_at)
            .finish_non_exhaustive()
    }
}

fn thumbprint(n: &str, e: &str) -> String {
    // RFC 7638 §3.2: the required members, lexicographic order, no spaces.
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    B64URL.encode(Sha256::digest(canonical.as_bytes()))
}

fn public_components(kp: &KeyPair) -> (String, String) {
    let public = kp.public_key();
    let n = B64URL.encode(public.modulus().big_endian_without_leading_zero());
    let e = B64URL.encode(public.exponent().big_endian_without_leading_zero());
    (n, e)
}

fn self_signed_cert(pkcs8: &[u8], common_name: &str, now: DateTime<Utc>) -> Result<String, RvError> {
    use rcgen::{date_time_ymd, CertificateParams, DnType, IsCa, KeyUsagePurpose, SerialNumber, PKCS_RSA_SHA256};
    use rustls::pki_types::PrivatePkcs8KeyDer;

    let der = PrivatePkcs8KeyDer::from(pkcs8);
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &PKCS_RSA_SHA256)
        .map_err(|_| internal("cannot load the generated key into the certificate builder"))?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let (y, m, d) = (now.year(), now.month() as u8, now.day() as u8);
    params.not_before = date_time_ymd(y, m, d);
    // 28 rather than the day of month: every month has one.
    params.not_after = date_time_ymd(y + CERT_VALIDITY_YEARS, m, d.min(28));
    let serial: [u8; 16] = {
        use rand::RngExt;
        let mut s = [0u8; 16];
        rand::rng().fill(&mut s[..]);
        s[0] &= 0x7f;
        s
    };
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let cert = params.self_signed(&key).map_err(|_| internal("cannot self-sign the certificate"))?;
    Ok(cert.pem())
}

impl SigningKey {
    /// A fresh RSA-3072 key and its self-signed certificate.
    pub fn generate(common_name: &str, now: DateTime<Utc>) -> Result<Self, RvError> {
        let kp = KeyPair::generate(KEY_SIZE).map_err(|_| internal("RSA key generation failed"))?;
        let der: Pkcs8V1Der<'static> = kp.as_der().map_err(|_| internal("cannot encode the key"))?;
        let pkcs8 = Zeroizing::new(der.as_ref().to_vec());
        let (n, e) = public_components(&kp);
        let cert_pem = self_signed_cert(&pkcs8, common_name, now)?;
        Ok(Self {
            kid: thumbprint(&n, &e),
            alg: ALG_RS256.to_string(),
            n,
            e,
            pkcs8: B64.encode(&pkcs8[..]),
            cert_pem,
            created_at: now,
            retired_at: None,
            publish_until: None,
        })
    }

    fn key_pair(&self) -> Result<KeyPair, RvError> {
        let der = Zeroizing::new(B64.decode(&self.pkcs8).map_err(|_| internal("stored key is not base64"))?);
        KeyPair::from_pkcs8(&der).map_err(|_| internal("stored key does not decode"))
    }

    /// RSASSA-PKCS1-v1_5 SHA-256 over `msg`.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        let kp = self.key_pair()?;
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut sig).map_err(|_| internal("signing failed"))?;
        Ok(sig)
    }

    /// The public JWK (RFC 7517) for the JWKS.
    pub fn public_jwk(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("kty".into(), "RSA".into());
        m.insert("use".into(), "sig".into());
        m.insert("alg".into(), self.alg.clone().into());
        m.insert("kid".into(), self.kid.clone().into());
        m.insert("n".into(), self.n.clone().into());
        m.insert("e".into(), self.e.clone().into());
        m
    }

    /// The certificate's DER, base64, as `<ds:X509Certificate>` carries it.
    pub fn cert_base64(&self) -> String {
        self.cert_pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect()
    }

    pub fn is_published(&self, now: DateTime<Utc>) -> bool {
        match (self.retired_at, self.publish_until) {
            (None, _) => true,
            (Some(_), Some(until)) => now < until,
            (Some(_), None) => false,
        }
    }

    /// What an admin read shows: no private key.
    pub fn to_map(&self, now: DateTime<Utc>) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("kid".into(), self.kid.clone().into());
        m.insert("alg".into(), self.alg.clone().into());
        m.insert("current".into(), self.retired_at.is_none().into());
        m.insert("published".into(), self.is_published(now).into());
        m.insert("created_at".into(), self.created_at.to_rfc3339().into());
        m.insert("retired_at".into(), self.retired_at.map(|t| t.to_rfc3339()).into());
        m.insert("publish_until".into(), self.publish_until.map(|t| t.to_rfc3339()).into());
        m.insert("certificate".into(), self.cert_pem.clone().into());
        m
    }
}

/// The keys of one protocol: exactly one current key, plus retired keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRing {
    pub version: u32,
    pub keys: Vec<SigningKey>,
}

impl KeyRing {
    fn validate(&self) -> Result<(), PosixError> {
        let current = self.keys.iter().filter(|k| k.retired_at.is_none()).count();
        let bad_key = |k: &SigningKey| k.alg != ALG_RS256 || k.kid != thumbprint(&k.n, &k.e);
        if current != 1 || self.keys.len() > MAX_KEYS || self.keys.iter().any(bad_key) {
            return Err(PosixError::Corrupt("stored signing key ring is inconsistent".into()));
        }
        Ok(())
    }

    pub fn current(&self) -> Result<&SigningKey, PosixError> {
        self.keys
            .iter()
            .find(|k| k.retired_at.is_none())
            .ok_or_else(|| PosixError::Corrupt("signing key ring has no current key".into()))
    }

    /// The current key first, then retired keys still in their overlap.
    pub fn published(&self, now: DateTime<Utc>) -> Vec<&SigningKey> {
        let mut out: Vec<&SigningKey> = self.keys.iter().filter(|k| k.retired_at.is_none()).collect();
        out.extend(self.keys.iter().filter(|k| k.retired_at.is_some() && k.is_published(now)));
        out
    }
}

/// Write-lock halves, field order is drop order.
struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

pub struct KeyRingStore {
    storage: Arc<dyn Storage>,
    key: &'static str,
    lock_name: &'static str,
    common_name: &'static str,
}

#[maybe_async::maybe_async]
impl KeyRingStore {
    pub fn new(
        storage: Arc<dyn Storage>,
        key: &'static str,
        lock_name: &'static str,
        common_name: &'static str,
    ) -> Self {
        Self { storage, key, lock_name, common_name }
    }

    async fn write_lock(&self) -> Result<WriteLock, RvError> {
        let local = LOCAL_WRITE_LOCK.lock().await;
        let cluster = self.storage.lock(self.lock_name).await?;
        Ok(WriteLock { _cluster: cluster, _local: local })
    }

    /// The stored ring, if any. A record that does not decode is an error,
    /// never a reason to mint a replacement.
    pub async fn load(&self) -> Result<Option<KeyRing>, RvError> {
        let Some(entry) = self.storage.get(self.key).await? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(entry.value);
        let ring: KeyRing = decode_versioned("signing key ring", &bytes)?;
        ring.validate()?;
        Ok(Some(ring))
    }

    async fn put(&self, ring: &KeyRing) -> Result<(), RvError> {
        let mut entry = StorageEntry::new(self.key, ring)?;
        let result = self.storage.put(&entry).await;
        entry.value.zeroize();
        result
    }

    /// The ring, created with one key on first use.
    pub async fn ensure(&self, now: DateTime<Utc>) -> Result<KeyRing, RvError> {
        if let Some(ring) = self.load().await? {
            return Ok(ring);
        }
        let _lock = self.write_lock().await?;
        if let Some(ring) = self.load().await? {
            return Ok(ring);
        }
        let ring = KeyRing { version: RECORD_VERSION, keys: vec![SigningKey::generate(self.common_name, now)?] };
        self.put(&ring).await?;
        log::info!(target: "security", "idp signing key created: ring={} kid={}", self.key, ring.keys[0].kid);
        Ok(ring)
    }

    /// A new current key; the old one stays published for `overlap_secs`.
    /// Retired keys past their overlap are dropped.
    pub async fn rotate(&self, overlap_secs: u64, now: DateTime<Utc>) -> Result<KeyRing, RvError> {
        if !(MIN_OVERLAP_SECS..=MAX_OVERLAP_SECS).contains(&overlap_secs) {
            return Err(PosixError::Invalid(format!(
                "overlap must lie within [{MIN_OVERLAP_SECS}, {MAX_OVERLAP_SECS}] seconds"
            ))
            .into());
        }
        let overlap = chrono::Duration::seconds(i64::try_from(overlap_secs).unwrap_or(i64::MAX));
        let _lock = self.write_lock().await?;
        let mut keys = match self.load().await? {
            Some(ring) => ring.keys.clone(),
            None => Vec::new(),
        };
        keys.retain(|k| k.retired_at.is_none() || k.is_published(now));
        for k in keys.iter_mut().filter(|k| k.retired_at.is_none()) {
            k.retired_at = Some(now);
            k.publish_until = Some(now + overlap);
        }
        let fresh = SigningKey::generate(self.common_name, now)?;
        let kid = fresh.kid.clone();
        keys.insert(0, fresh);
        if keys.len() > MAX_KEYS {
            return Err(PosixError::Conflict(format!(
                "at most {MAX_KEYS} keys may be published at once; wait for a retired key's overlap to end"
            ))
            .into());
        }
        let ring = KeyRing { version: RECORD_VERSION, keys };
        ring.validate()?;
        self.put(&ring).await?;
        log::info!(target: "security", "idp signing key rotated: ring={} kid={kid} overlap_secs={overlap_secs}", self.key);
        Ok(ring)
    }
}
