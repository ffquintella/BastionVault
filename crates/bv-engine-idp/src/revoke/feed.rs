//! The deny feed (features/identity-provider.md §4): every identity that is
//! not active and every revoked, unexpired certificate serial, with a
//! version that only moves up. Signed with `bv_crypto`'s composite
//! Ed25519 + ML-DSA-65 detached signature; a verifier needs both halves.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bv_crypto::bvrg::{sign_detached_hybrid, verify_detached_hybrid, BvrgMasterPublicKey, BvrgMasterSigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::RvError;

pub const FEED_FORMAT: &str = "bv-idp-deny-feed";
pub const FEED_FORMAT_VERSION: u32 = 1;
pub const FEED_ALGORITHM: &str = "ed25519+ml-dsa-65";
/// Signed before the payload, so a feed signature is never valid for any
/// other message the same key could sign.
const SIGNING_CONTEXT: &[u8] = b"bv-idp-deny-feed/v1\0";
/// Largest payload a verifier accepts.
pub const MAX_FEED_BYTES: usize = 8 * 1024 * 1024;
const ED25519_PUBLIC_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedIdentity {
    pub entity_id: String,
    pub login: String,
    pub uid: u32,
    /// `disabled` or `removed`.
    pub state: String,
    /// Unix seconds of the last state change, when recorded.
    pub since: Option<i64>,
}

/// The signed payload. Field order is the serialization order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyFeed {
    pub format: String,
    pub format_version: u32,
    pub feed_version: u64,
    pub generated_at: i64,
    pub identities: Vec<DeniedIdentity>,
    /// 16 lower-case hex digits each, sorted.
    pub revoked_serials: Vec<String>,
}

impl DenyFeed {
    pub fn denies(&self, entity_id: &str, login: &str, uid: u32) -> bool {
        self.identities.iter().any(|d| d.entity_id == entity_id || d.login == login || d.uid == uid)
    }

    pub fn revokes_serial(&self, serial: u64) -> bool {
        let hex = format!("{serial:016x}");
        self.revoked_serials.binary_search(&hex).is_ok()
    }
}

/// What the version is bound to: the content, without version or time.
pub fn content_digest(identities: &[DeniedIdentity], serials: &[String]) -> Result<String, RvError> {
    let bytes = serde_json::to_vec(&(identities, serials))?;
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a feed was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    Malformed(&'static str),
    BadSignature,
    UnsupportedFormat,
    /// A version below the highest one already accepted.
    Rollback {
        accepted: u64,
        offered: u64,
    },
    Stale {
        age_secs: i64,
    },
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "deny feed is malformed: {what}"),
            Self::BadSignature => f.write_str("deny feed signature does not verify"),
            Self::UnsupportedFormat => f.write_str("deny feed format or format version is not supported"),
            Self::Rollback { accepted, offered } => {
                write!(f, "deny feed version {offered} is below the accepted version {accepted}")
            }
            Self::Stale { age_secs } => write!(f, "deny feed is {age_secs}s old"),
        }
    }
}

/// The verification key a host pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPublicKey {
    pub ed25519: [u8; ED25519_PUBLIC_LEN],
    pub mldsa65: Vec<u8>,
}

impl FeedPublicKey {
    fn to_bvrg(&self) -> Result<BvrgMasterPublicKey, FeedError> {
        BvrgMasterPublicKey::from_bytes(&self.ed25519, &self.mldsa65).map_err(|_| FeedError::Malformed("public key"))
    }

    /// First 16 bytes of SHA-256 over both halves, hex.
    pub fn key_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.ed25519);
        h.update(&self.mldsa65);
        hex_lower(&h.finalize()[..16])
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("algorithm".into(), FEED_ALGORITHM.into());
        m.insert("key_id".into(), self.key_id().into());
        m.insert("ed25519".into(), B64.encode(self.ed25519).into());
        m.insert("mldsa65".into(), B64.encode(&self.mldsa65).into());
        m
    }

    /// Parse what [`to_map`](Self::to_map) produced (a host's pinned key file).
    pub fn from_value(v: &Value) -> Result<Self, FeedError> {
        let field = |k: &str| v.get(k).and_then(Value::as_str).ok_or(FeedError::Malformed("public key field"));
        if field("algorithm")? != FEED_ALGORITHM {
            return Err(FeedError::UnsupportedFormat);
        }
        let ed = B64.decode(field("ed25519")?).map_err(|_| FeedError::Malformed("ed25519 key encoding"))?;
        let ed25519: [u8; ED25519_PUBLIC_LEN] =
            ed.try_into().map_err(|_| FeedError::Malformed("ed25519 key length"))?;
        let mldsa65 = B64.decode(field("mldsa65")?).map_err(|_| FeedError::Malformed("ml-dsa-65 key encoding"))?;
        let key = Self { ed25519, mldsa65 };
        key.to_bvrg()?;
        Ok(key)
    }
}

/// The private half of the feed key. Both seeds are wiped on drop (the
/// Ed25519 key by `ed25519-dalek`, the ML-DSA seed by `Zeroizing`).
pub struct FeedSigner {
    key: BvrgMasterSigningKey,
}

impl FeedSigner {
    pub fn generate() -> Result<Self, RvError> {
        let key = BvrgMasterSigningKey::generate()
            .map_err(|e| bv_errors::bv_error_string!(&format!("cannot generate the deny-feed key: {e}")))?;
        Ok(Self { key })
    }

    pub fn from_seeds(ed25519_seed: &[u8; 32], mldsa65_seed: &[u8; bv_crypto::ML_DSA_65_SEED_LEN]) -> Self {
        let mut seed = Zeroizing::new([0u8; bv_crypto::ML_DSA_65_SEED_LEN]);
        seed.copy_from_slice(mldsa65_seed);
        let key =
            BvrgMasterSigningKey { ed25519: ed25519_dalek::SigningKey::from_bytes(ed25519_seed), mldsa65_seed: seed };
        Self { key }
    }

    /// Both seeds, for storage behind the barrier only.
    pub(crate) fn seeds(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; bv_crypto::ML_DSA_65_SEED_LEN]>) {
        (Zeroizing::new(self.key.ed25519.to_bytes()), Zeroizing::new(*self.key.mldsa65_seed))
    }

    pub fn public_key(&self) -> FeedPublicKey {
        let public = self.key.public_key();
        FeedPublicKey { ed25519: public.ed25519.to_bytes(), mldsa65: public.mldsa65 }
    }

    pub fn sign(&self, feed: &DenyFeed) -> Result<SignedFeed, RvError> {
        self.sign_payload(serde_json::to_vec(feed)?, feed.feed_version)
    }

    /// Crate-private: tests sign payloads a verifier must still refuse.
    pub(crate) fn sign_payload(&self, payload: Vec<u8>, feed_version: u64) -> Result<SignedFeed, RvError> {
        let signature = sign_detached_hybrid(&self.key, &signing_input(&payload))
            .map_err(|e| bv_errors::bv_error_string!(&format!("cannot sign the deny feed: {e}")))?;
        Ok(SignedFeed { payload, signature, feed_version })
    }
}

fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNING_CONTEXT.len() + payload.len());
    msg.extend_from_slice(SIGNING_CONTEXT);
    msg.extend_from_slice(payload);
    msg
}

/// A signed feed as served: the exact payload bytes and the signature.
#[derive(Debug, Clone)]
pub struct SignedFeed {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub feed_version: u64,
}

impl SignedFeed {
    /// `feed_version` here is a convenience copy; a verifier uses the one
    /// inside the signed payload.
    pub fn to_map(&self, key: &FeedPublicKey) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("feed".into(), B64.encode(&self.payload).into());
        m.insert("signature".into(), B64.encode(&self.signature).into());
        m.insert("algorithm".into(), FEED_ALGORITHM.into());
        m.insert("key_id".into(), key.key_id().into());
        m.insert("feed_version".into(), self.feed_version.into());
        m
    }
}

/// Verify a served feed and refuse a version below `accepted_version`.
/// Signature first, then the payload is parsed; nothing unsigned is read.
pub fn verify_feed(
    feed_b64: &str,
    signature_b64: &str,
    key: &FeedPublicKey,
    accepted_version: u64,
) -> Result<DenyFeed, FeedError> {
    if feed_b64.len() > MAX_FEED_BYTES.div_ceil(3) * 4 {
        return Err(FeedError::Malformed("feed exceeds the size limit"));
    }
    let payload = B64.decode(feed_b64.trim()).map_err(|_| FeedError::Malformed("feed encoding"))?;
    let signature = B64.decode(signature_b64.trim()).map_err(|_| FeedError::Malformed("signature encoding"))?;
    verify_detached_hybrid(&signing_input(&payload), &signature, &key.to_bvrg()?)
        .map_err(|_| FeedError::BadSignature)?;
    let feed: DenyFeed = serde_json::from_slice(&payload).map_err(|_| FeedError::Malformed("payload"))?;
    if feed.format != FEED_FORMAT || feed.format_version != FEED_FORMAT_VERSION {
        return Err(FeedError::UnsupportedFormat);
    }
    if !feed.revoked_serials.windows(2).all(|w| w[0] < w[1]) {
        return Err(FeedError::Malformed("revoked serials are not sorted and unique"));
    }
    if feed.feed_version < accepted_version {
        return Err(FeedError::Rollback { accepted: accepted_version, offered: feed.feed_version });
    }
    Ok(feed)
}

/// Refuse a feed generated more than `max_age_secs` before `now`.
pub fn check_fresh(feed: &DenyFeed, now: i64, max_age_secs: i64) -> Result<(), FeedError> {
    let age_secs = now.saturating_sub(feed.generated_at);
    if age_secs > max_age_secs {
        return Err(FeedError::Stale { age_secs });
    }
    Ok(())
}
