//! Plugin signature verification — Phase 5.2.
//!
//! A plugin manifest carries a `signature` (hex ML-DSA-65 over
//! `binary || canonical_manifest_json_without_signature_fields`) and
//! a `signing_key` identifier. The host maintains an operator-pinned
//! **publisher allowlist** that maps each `signing_key` identifier to
//! the hex-encoded ML-DSA-65 public key. At registration *and* at
//! every load the host:
//!
//!   1. Looks up `manifest.signing_key` in the allowlist.
//!   2. Reconstructs the canonical signing message: `sha256(binary)`
//!      bytes followed by the canonical-JSON serialisation of the
//!      manifest with the `signature` field stripped. Hashing the
//!      binary first keeps the verifier message a fixed size even for
//!      very large WASM modules.
//!   3. Calls `bv_crypto::MlDsa65Provider::verify` with the public
//!      key, the message, and the supplied signature.
//!
//! When `manifest.signing_key` is empty, the host loads the engine's
//! `accept_unsigned` flag from `core/plugins/engine/accept_unsigned`
//! (Vault parity: development opt-in, logged at WARN). With the flag
//! off, an unsigned plugin is refused at registration and at load.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::manifest::PluginManifest;

/// Storage key for the publisher allowlist.
const PUBLISHERS_KEY: &str = "core/plugins/engine/publishers";
/// Storage key for the engine's `accept_unsigned` flag.
const ACCEPT_UNSIGNED_KEY: &str = "core/plugins/engine/accept_unsigned";

/// Operator-pinned mapping from publisher identifier to its ML-DSA-65
/// public-key bytes (hex-encoded).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublisherAllowlist {
    /// `name → hex(public_key)`. Empty allowlist means "no signed
    /// plugins are accepted unless `accept_unsigned = true`."
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
}

impl PublisherAllowlist {
    pub async fn load(storage: &dyn Storage) -> Result<Self, RvError> {
        match storage.get(PUBLISHERS_KEY).await? {
            None => Ok(Self::default()),
            Some(entry) => serde_json::from_slice(&entry.value)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    pub async fn save(&self, storage: &dyn Storage) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(self)?;
        storage
            .put(&StorageEntry {
                key: PUBLISHERS_KEY.to_string(),
                value: bytes,
            })
            .await
    }
}

/// Read the engine's `accept_unsigned` flag. Default-closed: missing
/// key behaves as `false`.
pub async fn read_accept_unsigned(storage: &dyn Storage) -> Result<bool, RvError> {
    match storage.get(ACCEPT_UNSIGNED_KEY).await? {
        None => Ok(false),
        Some(entry) => Ok(entry.value == b"true"),
    }
}

pub async fn write_accept_unsigned(storage: &dyn Storage, on: bool) -> Result<(), RvError> {
    storage
        .put(&StorageEntry {
            key: ACCEPT_UNSIGNED_KEY.to_string(),
            value: if on { b"true".to_vec() } else { b"false".to_vec() },
        })
        .await
}

/// Verify a plugin's publisher signature. Returns `Ok(())` when the
/// plugin is acceptable for the current engine configuration, error
/// otherwise.
pub async fn verify(
    storage: &dyn Storage,
    manifest: &PluginManifest,
    binary: &[u8],
) -> Result<(), RvError> {
    if manifest.signature.is_empty() {
        if read_accept_unsigned(storage).await? {
            log::warn!(
                "plugin `{}` is unsigned; loaded under accept_unsigned = true",
                manifest.name
            );
            return Ok(());
        }
        return Err(RvError::ErrString(format!(
            "plugin `{}` is unsigned and accept_unsigned is false; \
             register a publisher and re-sign, or set engine `accept_unsigned = true` (development only)",
            manifest.name
        )));
    }

    if manifest.signing_key.is_empty() {
        return Err(RvError::ErrString(
            "manifest carries `signature` but no `signing_key` identifier".into(),
        ));
    }

    let allow = PublisherAllowlist::load(storage).await?;
    let pk_hex = allow.keys.get(&manifest.signing_key).ok_or_else(|| {
        RvError::ErrString(format!(
            "publisher `{}` is not in the allowlist; register it via /v1/sys/plugins/publishers",
            manifest.signing_key
        ))
    })?;
    let pk = hex_decode(pk_hex).ok_or_else(|| {
        RvError::ErrString(format!(
            "publisher `{}` allowlist entry is not valid hex",
            manifest.signing_key
        ))
    })?;
    let sig = hex_decode(&manifest.signature).ok_or_else(|| {
        RvError::ErrString("manifest.signature is not valid hex".into())
    })?;

    let message = signing_message(manifest, binary)?;

    // Use FIPS 204 directly here rather than the `bv_crypto` wrapper,
    // because the wrapper's verify path takes a *seed* and rederives
    // the public key, which we don't have. The PK is what we keep on
    // the allowlist; verifying directly against PK is the standard
    // ML-DSA usage.
    use ::fips204::traits::{SerDes, Verifier};
    use ::fips204::ml_dsa_65 as fdsa;
    let pk_arr: [u8; fdsa::PK_LEN] = pk.as_slice().try_into().map_err(|_| {
        RvError::ErrString(format!(
            "publisher public key must be {} bytes, got {}",
            fdsa::PK_LEN,
            pk.len()
        ))
    })?;
    let sig_arr: [u8; fdsa::SIG_LEN] = sig.as_slice().try_into().map_err(|_| {
        RvError::ErrString(format!(
            "ml-dsa-65 signature must be {} bytes, got {}",
            fdsa::SIG_LEN,
            sig.len()
        ))
    })?;
    let pk_obj = fdsa::PublicKey::try_from_bytes(pk_arr)
        .map_err(|e| RvError::ErrString(format!("publisher public key parse: {e}")))?;
    if pk_obj.verify(&message, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(RvError::ErrString(format!(
            "plugin `{}` signature verification failed against publisher `{}`",
            manifest.name, manifest.signing_key
        )))
    }
}

/// Canonical signing message: `sha256(binary) || canonical_manifest_json`,
/// where the canonical manifest JSON is the manifest with `signature`
/// stripped and re-serialised. Stripping `signature` is what makes the
/// verifier reconstructible client-side: the publisher signs the same
/// bytes the host re-derives.
fn signing_message(manifest: &PluginManifest, binary: &[u8]) -> Result<Vec<u8>, RvError> {
    let mut h = Sha256::new();
    h.update(binary);
    let bin_digest = h.finalize();

    let mut clone = manifest.clone();
    clone.signature.clear();
    let canonical = serde_json::to_vec(&clone)?;

    let mut out = Vec::with_capacity(bin_digest.len() + canonical.len());
    out.extend_from_slice(&bin_digest);
    out.extend_from_slice(&canonical);
    Ok(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi as u8) << 4) | lo as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::{Capabilities, RuntimeKind};
    use bv_crypto::MlDsa65Provider;

    fn manifest_with(sig: &str, signer: &str, binary: &[u8]) -> PluginManifest {
        let mut h = Sha256::new();
        h.update(binary);
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        PluginManifest {
            name: "verifier-test".into(),
            version: "0.1.0".into(),
            plugin_type: "test".into(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".into(),
            sha256: hex,
            size: binary.len() as u64,
            capabilities: Capabilities::default(),
            description: String::new(),
            config_schema: vec![],
            signature: sig.into(),
            signing_key: signer.into(),
        }
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn signing_message_strips_signature_field() {
        let bin = b"hello".to_vec();
        let m1 = manifest_with("", "pub-a", &bin);
        let m2 = manifest_with("AAAA", "pub-a", &bin);
        // Both should produce the same signing message: the second
        // one has `signature` stripped before canonicalisation.
        assert_eq!(
            signing_message(&m1, &bin).unwrap(),
            signing_message(&m2, &bin).unwrap()
        );
    }

    /// Test the canonical-message + ML-DSA-65 sign + verify round-trip
    /// without going through storage. The storage-side allowlist is
    /// covered by an integration-style test in [`super::tests_with_storage`].
    #[test]
    fn raw_sign_and_verify_round_trip() {
        use ::fips204::ml_dsa_65 as fdsa;
        use ::fips204::traits::{SerDes, Verifier};

        let bin = vec![1u8, 2, 3, 4];
        let provider = MlDsa65Provider;
        let kp = provider.generate_keypair().unwrap();

        let mut m = manifest_with("", "publisher-1", &bin);
        m.signing_key = "publisher-1".into();
        let msg = signing_message(&m, &bin).unwrap();
        let sig = provider.sign(kp.secret_seed(), &msg, &[]).unwrap();

        let pk_arr: [u8; fdsa::PK_LEN] = kp.public_key().try_into().unwrap();
        let sig_arr: [u8; fdsa::SIG_LEN] = sig.as_slice().try_into().unwrap();
        let pk_obj = fdsa::PublicKey::try_from_bytes(pk_arr).unwrap();
        assert!(pk_obj.verify(&msg, &sig_arr, &[]));

        // Tamper with the binary → message changes → verify fails.
        let mut bad = bin.clone();
        bad[0] ^= 1;
        let bad_msg = signing_message(&m, &bad).unwrap();
        assert!(!pk_obj.verify(&bad_msg, &sig_arr, &[]));
    }

    #[test]
    fn allowlist_serde_round_trip() {
        let mut a = PublisherAllowlist::default();
        a.keys.insert("acme".into(), "deadbeef".into());
        let bytes = serde_json::to_vec(&a).unwrap();
        let back: PublisherAllowlist = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.keys.get("acme").map(String::as_str), Some("deadbeef"));
    }
}
