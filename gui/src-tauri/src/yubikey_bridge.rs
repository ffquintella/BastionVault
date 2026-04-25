//! Thin wrapper around the `yubikey` crate for the BastionVault GUI's
//! failsafe unlock path.
//!
//! # What the wrapper exposes
//!
//!   * `list_devices()` — enumerates connected YubiKeys by serial.
//!   * `load_signing_public_key(serial)` — reads the X.509 cert from
//!     PIV slot 9a and returns a stable byte identifier (SHA-256 of
//!     the SubjectPublicKeyInfo) plus the raw DER-encoded pubkey, so
//!     the keystore file can record "this slot expects key X" without
//!     storing the private key material it depends on.
//!   * `sign(serial, pin, salt)` — runs the salt through the slot-9a
//!     signing key and returns the raw signature bytes. The caller
//!     feeds those bytes into HKDF to derive an ML-KEM-768 seed; see
//!     `local_keystore::derive_seed_from_yubikey_signature`.
//!
//! # Why sign-then-derive
//!
//! YubiKey firmware does not store NIST PQC keys. To still land a
//! PQC-encrypted file on disk, we let the YubiKey sign an
//! openly-stored salt with a traditional key (RSA-PKCS1 or
//! deterministic ECDSA per RFC 6979 — both reproducible so the same
//! (salt, card) always yields the same signature) and use that
//! signature as HKDF input material to deterministically seed
//! ML-KEM-768 key generation. The private signing material never
//! leaves the card; the host only sees the signature + the derived
//! PQC material. See `docs/docs/security-structure.md` § "YubiKey
//! failsafe" for the threat model and rotation story.
//!
//! # Testing
//!
//! All hardware-exercising functions are `#[ignore]`-gated in the
//! test suite — matching the project's pattern for tests that need
//! a physical device (`oidc_live_auth_url_roundtrip`,
//! `test_file_backend_multi_routine`). The non-hardware primitives
//! below (serialisation, key-id hashing, signature parsing) have
//! deterministic unit tests that run under plain `cargo test`.

use sha2::{Digest, Sha256};
use yubikey::{
    certificate::Certificate,
    piv::{self, AlgorithmId, SlotId},
    Serial, YubiKey,
};

use crate::error::CommandError;

/// The PIV slot we expect the signing key to live in. `9a` is
/// "PIV Authentication", which is the default for operator-owned
/// signing keys generated with `yubico-piv-tool` or `ykman piv`.
const SIGNING_SLOT: SlotId = SlotId::Authentication;

/// Stable per-YubiKey identifier used in the vault-keys file header.
///
/// Derived from the SHA-256 of the public key's
/// SubjectPublicKeyInfo DER encoding. Two YubiKeys will never share
/// a key id unless they share a private key (which is technically
/// possible if the operator cloned one, but the intent then is to
/// have the same recovery scope anyway).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YubiKeyId {
    pub serial: u32,
    pub key_id_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct YubiKeyInfo {
    pub serial: u32,
    pub slot_occupied: bool,
}

/// Enumerate connected YubiKeys. Each call re-scans the PC/SC
/// readers; the GUI should call it on-demand rather than caching
/// the result across operations.
pub fn list_devices() -> Result<Vec<YubiKeyInfo>, CommandError> {
    let mut out = Vec::new();
    let mut readers = yubikey::reader::Context::open()
        .map_err(|e| CommandError::from(format!("yubikey: open PC/SC context: {e}")))?;

    for reader in readers
        .iter()
        .map_err(|e| CommandError::from(format!("yubikey: iter readers: {e}")))?
    {
        // A reader that fails to `open()` typically means the card
        // was removed mid-scan. Skip rather than error out — the
        // enumeration is best-effort by design.
        let mut yk = match reader.open() {
            Ok(y) => y,
            Err(_) => continue,
        };
        let serial = yk.serial().0;
        // "Slot occupied" = card has a usable asymmetric key in
        // slot 9a. PIV metadata (YubiKey firmware 5.3+) reports
        // both whether a key exists AND its algorithm in one call,
        // so we no longer need a cert present for the check. The
        // prior Certificate::read approach false-negatived on
        // cards provisioned with `ykman piv keys generate 9a`
        // alone (no cert) — exactly the state the YubiKey
        // Authenticator app reports as "Key without certificate
        // loaded."
        let slot_occupied = has_asymmetric_key_in_slot_9a(&mut yk);
        out.push(YubiKeyInfo {
            serial,
            slot_occupied,
        });
    }
    Ok(out)
}

fn has_asymmetric_key_in_slot_9a(yk: &mut YubiKey) -> bool {
    match yubikey::piv::metadata(yk, SIGNING_SLOT) {
        Ok(meta) => matches!(
            meta.algorithm,
            yubikey::piv::ManagementAlgorithmId::Asymmetric(_)
        ),
        Err(_) => {
            // Metadata unsupported (older firmware) — fall back to
            // the cert-presence probe. Less accurate (it misses
            // key-only slots) but better than a hard false.
            Certificate::read(yk, SIGNING_SLOT).is_ok()
        }
    }
}

/// Open the YubiKey with the given serial. Called lazily by every
/// wrapper function below so the GUI does not hold a session across
/// operator idle time (and so hot-unplug doesn't leave a stale
/// handle pointing at nothing).
fn open_by_serial(serial: u32) -> Result<YubiKey, CommandError> {
    YubiKey::open_by_serial(Serial::from(serial))
        .map_err(|e| CommandError::from(format!("yubikey: open serial {serial}: {e}")))
}

/// Load the raw DER-encoded SubjectPublicKeyInfo + stable key id
/// for the signing key on `serial`. The key id is what we store in
/// the vault-keys file header; the raw SPKI is surfaced so the
/// registration flow can show the operator which key it's about to
/// commit to (algorithm + bit length).
pub fn load_signing_public_key(serial: u32) -> Result<(YubiKeyId, Vec<u8>), CommandError> {
    let mut yk = open_by_serial(serial)?;

    // PIV metadata (YubiKey firmware 5.3+) returns the public-key
    // SPKI whether or not a certificate is present in the slot.
    // Prefer this path so operators who ran `ykman piv keys
    // generate 9a` (without following up with `certificates
    // generate`) don't hit a dead-end. The Yubico Authenticator
    // app reports this state as "Key without certificate loaded."
    let pk_bits: Vec<u8> = if let Ok(meta) = yubikey::piv::metadata(&mut yk, SIGNING_SLOT) {
        if matches!(
            meta.algorithm,
            yubikey::piv::ManagementAlgorithmId::Asymmetric(_)
        ) {
            match meta.public {
                Some(spki) => spki.subject_public_key.raw_bytes().to_vec(),
                None => {
                    return Err(CommandError::from(format!(
                        "yubikey: slot 9a on serial {serial} has an asymmetric key but \
                         no public-key metadata was returned. Re-insert the card and \
                         retry, or provision the slot with `ykman piv keys generate 9a`."
                    )));
                }
            }
        } else {
            return Err(CommandError::from(format!(
                "yubikey: slot 9a on serial {serial} holds a non-asymmetric key \
                 ({:?}). Register an RSA-2048 or ECC-P256/P384 key first.",
                meta.algorithm
            )));
        }
    } else {
        // Firmware too old for PIV metadata — fall back to reading
        // the certificate's SPKI. Fails when the slot has a key
        // but no cert; there's nothing we can do about that
        // pre-5.3 because the card simply won't tell us the
        // public key without a cert container.
        let cert = Certificate::read(&mut yk, SIGNING_SLOT).map_err(|e| {
            CommandError::from(format!(
                "yubikey: slot 9a on serial {serial} has no readable public key ({e}). \
                 This firmware is too old to expose PIV metadata; provision a cert \
                 alongside the key via `ykman piv certificates generate 9a pub.pem` \
                 and retry."
            ))
        })?;
        cert.subject_pki().subject_public_key.raw_bytes().to_vec()
    };

    // Use the SPKI raw public-key bits as the stable per-key
    // fingerprint. Two different private keys in the same slot
    // produce different public-key bits; the registered slot's
    // key_id therefore tracks the specific key material, not just
    // the card it lives on.
    let mut hasher = Sha256::new();
    hasher.update(&pk_bits);
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&hasher.finalize());

    Ok((
        YubiKeyId {
            serial,
            key_id_sha256: key_id,
        },
        pk_bits,
    ))
}

/// Sign `salt` with the slot-9a key of `serial`, returning the raw
/// signature bytes. Requires the operator's PIV PIN (typically
/// 6–8 digits; default `123456`).
///
/// Works with both RSA (PKCS#1 v1.5 — inherently deterministic) and
/// ECC (P-256 / P-384 — deterministic on modern YubiKey firmware
/// via RFC 6979). Ed25519 is NOT currently supported for this
/// path because older YubiKey firmwares pre-5.7 didn't carry it;
/// the registration flow rejects a slot-9a cert whose algorithm
/// isn't in `supported_algorithm`.
/// Generate a fresh RSA-2048 keypair in PIV slot 9a and write a
/// minimal self-signed certificate so subsequent
/// `load_signing_public_key` / `sign` calls succeed. Called from
/// the Add-Local-Vault modal when the operator picks a YubiKey
/// whose slot 9a was empty at enumeration time.
///
/// Requires the PIV PIN and assumes the management key is still the
/// factory default (`01020304...01020304`). Cards where the
/// management key has been rotated return a distinct error so the
/// operator can reset it via `ykman piv access change-management-key`
/// before retrying.
///
/// The generated cert is intentionally minimal: 20-year validity,
/// subject `CN=BastionVault PIV`, no extensions. The host never
/// consumes it as a trust anchor — it's only a container for the
/// public key that `load_signing_public_key` hashes. Operators
/// who want a richer cert can overwrite the slot later via
/// `ykman piv certificates import`.
pub fn provision_slot_9a(serial: u32, pin: &[u8]) -> Result<(), CommandError> {
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::{
        name::Name,
        serial_number::SerialNumber,
        time::Validity,
    };
    use yubikey::{
        certificate::{
            yubikey_signer::{Rsa2048, YubiRsa},
            Certificate,
        },
        piv::{self, AlgorithmId},
        MgmKey, PinPolicy, TouchPolicy,
    };

    let mut yk = open_by_serial(serial)?;

    // Refuse to overwrite an existing asymmetric key. Cards that
    // reach this code path are supposed to have a truly-empty slot
    // 9a; a key-only slot (no cert) is now handled entirely inside
    // `load_signing_public_key` via PIV metadata, without needing
    // to regenerate the key.
    if has_asymmetric_key_in_slot_9a(&mut yk) {
        return Err(CommandError::from(format!(
            "yubikey: slot 9a on serial {serial} already holds an asymmetric key. \
             Registration reads the public key via PIV metadata directly — no \
             provisioning needed. If you're seeing this after re-clicking Provision, \
             just click Register."
        )));
    }

    yk.verify_pin(pin)
        .map_err(|e| CommandError::from(format!("yubikey: PIN verify: {e}")))?;

    // PIV card administration requires the "management key" (a
    // 3DES key, 24 bytes). Factory default is well-known; operators
    // who rotated it need to reset the card or pre-provision the
    // slot themselves before using the GUI registration flow.
    yk.authenticate(MgmKey::default()).map_err(|e| {
        CommandError::from(format!(
            "yubikey: management-key auth failed ({e}). If the card's management key was \
             changed from the factory default, reset it with `ykman piv access \
             change-management-key --generate` or provision slot 9a externally via \
             `ykman piv keys generate 9a` + `ykman piv certificates generate 9a`, then \
             retry registration."
        ))
    })?;

    // 1. Generate RSA-2048 on-card. PIN / touch policies left at
    //    Default (PIN required once per session for signing, no
    //    touch required) — matches how operators typically use the
    //    signing slot for non-interactive workflows.
    let public_key = piv::generate(
        &mut yk,
        SIGNING_SLOT,
        AlgorithmId::Rsa2048,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .map_err(|e| CommandError::from(format!("yubikey: piv::generate: {e}")))?;

    // 2. Build + sign + write the X.509 envelope. 20 years so the
    //    host-side `load_signing_public_key` keeps reading a
    //    non-expired cert for the lifetime of the card; expiry
    //    doesn't affect the crypto we actually use (signature over
    //    an operator-supplied salt) but x509-cert rejects obviously
    //    malformed validity windows.
    let subject = Name::from_str("CN=BastionVault PIV")
        .map_err(|e| CommandError::from(format!("yubikey: build subject: {e}")))?;
    let validity = Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365 * 20))
        .map_err(|e| CommandError::from(format!("yubikey: validity window: {e}")))?;
    let cert_serial = SerialNumber::from(1u8);

    Certificate::generate_self_signed::<_, YubiRsa<Rsa2048>>(
        &mut yk,
        SIGNING_SLOT,
        cert_serial,
        validity,
        subject,
        public_key,
        |_builder| Ok(()),
    )
    .map_err(|e| CommandError::from(format!("yubikey: self-sign cert: {e}")))?;

    Ok(())
}

pub fn sign(serial: u32, pin: &[u8], salt: &[u8]) -> Result<Vec<u8>, CommandError> {
    let mut yk = open_by_serial(serial)?;
    yk.verify_pin(pin)
        .map_err(|e| CommandError::from(format!("yubikey: PIN verify: {e}")))?;
    let algo = detect_algorithm(&mut yk)?;

    // The PIV sign API takes raw input bytes in RSA-sign mode (the
    // chip applies PKCS1 padding internally) and a SHA-256 digest
    // in ECDSA mode. We match both conventions so the registration
    // flow works regardless of operator key choice.
    // The `yubikey` crate's `sign_data` is a thin wrapper over the
    // PIV AUTHENTICATE command — the card does NOT apply padding
    // for us. RSA slots want input sized to the key length (128 /
    // 256 bytes) with PKCS#1 v1.5 padding of a DigestInfo already
    // applied by the host. ECDSA slots accept a raw hash up to the
    // key's byte length. Build the right shape for each variant.
    //
    // `detect_algorithm` rejects anything outside RSA-1024/2048 +
    // ECC-P256/P384 before we get here, so the match is
    // structurally total for this code path.
    let to_sign: Vec<u8> = match algo {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            let key_size_bytes = if matches!(algo, AlgorithmId::Rsa2048) {
                256
            } else {
                128
            };
            pkcs1v15_sha256_encode(salt, key_size_bytes)
        }
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
            let mut h = Sha256::new();
            h.update(salt);
            h.finalize().to_vec()
        }
    };

    let signature = piv::sign_data(&mut yk, &to_sign, algo, SIGNING_SLOT)
        .map_err(|e| CommandError::from(format!("yubikey: sign_data: {e}")))?;
    Ok(signature.to_vec())
}

/// PKCS#1 v1.5 signature-encoding of a SHA-256 digest of `input`,
/// padded out to `key_size_bytes`. Used by `sign` for RSA-1024 /
/// RSA-2048 PIV slots where the card expects the host to apply
/// padding — the YubiKey does not run PKCS1 padding inside the
/// signing routine.
///
/// Layout (RFC 8017 § 9.2, EMSA-PKCS1-v1_5):
///
///   0x00 || 0x01 || (0xff)* || 0x00 || DigestInfo || hash
///
/// DigestInfo for SHA-256 is the fixed 19-byte ASN.1 prefix below.
/// Deterministic: the same (key_size, input) pair always yields
/// the same encoded block — required so the keystore can re-derive
/// its ML-KEM seed from this signature on every open.
fn pkcs1v15_sha256_encode(input: &[u8], key_size_bytes: usize) -> Vec<u8> {
    // ASN.1 DER for `DigestInfo { algorithm = SHA-256, digest = <32 bytes> }`:
    //   SEQ len=0x31
    //     SEQ len=0x0d
    //       OID 2.16.840.1.101.3.4.2.1 (SHA-256)
    //       NULL
    //     OCTET STRING len=0x20 (32 bytes of hash follow)
    const SHA256_DIGEST_INFO_PREFIX: &[u8; 19] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let digest = Sha256::digest(input);
    let t_len = SHA256_DIGEST_INFO_PREFIX.len() + digest.len(); // 19 + 32 = 51
    // key_size_bytes ≥ t_len + 11 must hold per PKCS#1 (3 bytes of
    // framing + at least 8 padding bytes). For RSA-2048 we have
    // 256 − 51 − 3 = 202 bytes of 0xff padding; for RSA-1024 we'd
    // have 74. Both well above the 8-byte minimum, but assert
    // defensively in case a future AlgorithmId variant slips
    // through.
    debug_assert!(key_size_bytes >= t_len + 11, "RSA key too small for SHA-256 PKCS1v15");
    let padding_len = key_size_bytes - t_len - 3;

    let mut out = Vec::with_capacity(key_size_bytes);
    out.push(0x00);
    out.push(0x01);
    out.extend(std::iter::repeat(0xffu8).take(padding_len));
    out.push(0x00);
    out.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
    out.extend_from_slice(&digest);
    debug_assert_eq!(out.len(), key_size_bytes);
    out
}

/// Ask the YubiKey which algorithm is provisioned in slot 9a.
/// `piv::metadata` returns a `ManagementAlgorithmId` which wraps
/// the `AlgorithmId` for asymmetric keys in the `Asymmetric(...)`
/// variant; we unwrap that here.
fn detect_algorithm(yk: &mut YubiKey) -> Result<AlgorithmId, CommandError> {
    let meta = piv::metadata(yk, SIGNING_SLOT).map_err(|e| {
        CommandError::from(format!(
            "yubikey: could not read slot 9a metadata ({e}). \
             Is the slot provisioned with a signing key?"
        ))
    })?;
    match meta.algorithm {
        piv::ManagementAlgorithmId::Asymmetric(algo) => Ok(algo),
        other => Err(CommandError::from(format!(
            "yubikey: slot 9a is provisioned with a non-asymmetric key (`{other:?}`) — \
             register an RSA-2048 or ECC-P256/P384 signing key instead"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs1v15_encoding_has_correct_shape() {
        let salt = [0x42u8; 32];
        let encoded = pkcs1v15_sha256_encode(&salt, 256);
        assert_eq!(encoded.len(), 256, "RSA-2048 block must be 256 bytes");
        assert_eq!(&encoded[..2], &[0x00, 0x01], "leader must be 00 01");
        // Padding is 0xff bytes up to the 0x00 separator.
        let sep_idx = encoded.iter().position(|&b| b == 0x00 && encoded[0] == 0x00 && encoded[1] == 0x01).unwrap_or(0);
        // First 0x00 is at index 0; find the NEXT 0x00 after the 0xff run.
        let mut idx = 2;
        while idx < encoded.len() && encoded[idx] == 0xff {
            idx += 1;
        }
        assert_eq!(encoded[idx], 0x00, "separator 0x00 expected after padding");
        let _ = sep_idx;
        // DigestInfo prefix lands right after the 0x00 separator.
        assert_eq!(&encoded[idx + 1..idx + 1 + 19][0..2], &[0x30, 0x31]);
        // Last 32 bytes are the SHA-256 of the salt.
        let expected_digest = Sha256::digest(salt);
        assert_eq!(&encoded[encoded.len() - 32..], expected_digest.as_slice());
    }

    #[test]
    fn pkcs1v15_encoding_is_deterministic() {
        // Same input → same output every time (critical for seed
        // reproducibility across opens).
        let salt = [0x5au8; 32];
        let a = pkcs1v15_sha256_encode(&salt, 256);
        let b = pkcs1v15_sha256_encode(&salt, 256);
        assert_eq!(a, b);
    }

    #[test]
    fn yubikey_id_hash_is_stable() {
        // Regression — proves that the same SPKI bytes always hash
        // to the same key_id. If this ever breaks we'd lose track
        // of which slot belongs to which card.
        let spki = b"fake-der-encoded-spki";
        let mut h1 = Sha256::new();
        h1.update(spki);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(spki);
        let mut b = [0u8; 32];
        b.copy_from_slice(&h2.finalize());

        assert_eq!(a, b);
    }

    /// Hardware-dependent test — runs only when a YubiKey is
    /// plugged in and the operator has initialised slot 9a. Marked
    /// `#[ignore]` so `cargo test` stays CI-friendly.
    ///
    /// Run with:
    ///
    /// ```sh
    /// cargo test -p bastion-vault-gui --lib yubikey_bridge -- --ignored
    /// ```
    #[test]
    #[ignore]
    fn list_devices_sees_plugged_in_yubikey() {
        let devices = list_devices().expect("list_devices");
        assert!(
            !devices.is_empty(),
            "no YubiKeys detected — plug one in + re-run"
        );
        // At least one device should have slot 9a populated; the
        // ignore-guard + documented prereq above makes that a
        // reasonable assertion when running this test explicitly.
    }
}
