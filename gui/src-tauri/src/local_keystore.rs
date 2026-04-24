//! Per-vault keystore with PQC envelope + multi-unlock-path support.
//!
//! Fixes the "switch vault overwrites the keychain" bug and adds two
//! defence-in-depth layers:
//!
//!   * An ML-KEM-768 PQC envelope around the on-disk file, so a
//!     quantum adversary who captures the ciphertext cannot later
//!     decrypt it even if the symmetric master key leaks.
//!
//!   * Multiple registered *unlock slots* (keychain-anchored and/or
//!     YubiKey-anchored) — any one slot is enough to open the file,
//!     so spare YubiKeys serve as failsafe recovery paths without
//!     introducing a new single point of failure.
//!
//! # On-disk layout (v2)
//!
//! ```text
//!   MAGIC       4 bytes   "BVK\x02"
//!   HEADER_LEN  4 bytes   big-endian u32
//!   HEADER      <HEADER_LEN> bytes  (serde_json of `FileHeaderV2`)
//!   NONCE       12 bytes  random ChaCha20-Poly1305 nonce
//!   CIPHERTEXT  rest      ChaCha20-Poly1305(content_key, nonce, plaintext)
//! ```
//!
//! The header holds one or more *slots*, each independently capable
//! of unlocking the `content_key`. Per slot:
//!
//!   - `kind` — `"keychain"` or `"yubikey"`.
//!   - `ek` — base64-encoded ML-KEM-768 encapsulation key. Lets the
//!     `save` path re-encapsulate the content key without needing
//!     that slot's physical credential (so saves work with any one
//!     of the registered slots present).
//!   - `kem_ct` — base64 ML-KEM ciphertext produced against `ek`.
//!   - `wrap_nonce` — 12-byte AEAD nonce.
//!   - `wrapped_content_key` — AEAD-wrapped 32-byte content key,
//!     keyed by HKDF(KEM-shared-secret).
//!   - Plus kind-specific metadata: YubiKey slots carry `serial`,
//!     `key_id` (SHA-256 of SPKI pubkey bits), and a 32-byte `salt`.
//!
//! # Seed derivation
//!
//! ML-KEM-768 keygen needs a 64-byte seed. For each unlock method
//! we derive it deterministically:
//!
//!   * **Keychain**: 32-byte Local Key from the OS keychain →
//!     HKDF-SHA-256 → 64-byte seed with context
//!     `"bastion-vault / kem-seed-v1 / keychain"`.
//!   * **YubiKey**: raw signature bytes over the slot's salt (RSA-
//!     PKCS1v15 is deterministic, ECDSA with RFC-6979 is deterministic)
//!     → HKDF-SHA-256 → 64-byte seed with context
//!     `"bastion-vault / kem-seed-v1 / yubikey"`.
//!
//! The signature never leaves memory; the derived seed is used once
//! per open to re-construct the ML-KEM keypair and then zeroised on
//! drop. See `docs/docs/security-structure.md` for the full threat
//! model.
//!
//! # Migration
//!
//! v1 files (`BVK\x01`, direct Local-Key AEAD) are read transparently
//! and re-saved in v2 format on the next write. Legacy single-slot
//! keychain entries are still migrated into the v2 file per the
//! earlier commit, indexed under `last_used_id`.

use std::{
    fs,
    io::Write,
    path::PathBuf,
};

use bv_crypto::{KemProvider, MlKem768Provider, ML_KEM_768_SEED_LEN};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::CommandError;

// ── Constants ──────────────────────────────────────────────────────

const SERVICE: &str = "bastion-vault-gui";
const LOCAL_KEY_ENTRY: &str = "local-master-key";
const KEYS_FILE_NAME: &str = "vault-keys.enc";
const MAGIC_V1: &[u8; 4] = b"BVK\x01";
const MAGIC_V2: &[u8; 4] = b"BVK\x02";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const YUBIKEY_SALT_LEN: usize = 32;

const HKDF_INFO_KEYCHAIN_SEED: &[u8] = b"bastion-vault / kem-seed-v1 / keychain";
const HKDF_INFO_YUBIKEY_SEED: &[u8] = b"bastion-vault / kem-seed-v1 / yubikey";
const HKDF_INFO_WRAP_KEY: &[u8] = b"bastion-vault / content-key-wrap-v1";

// ── Public data model ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeys {
    pub unseal_key_hex: String,
    pub root_token: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileContents {
    version: u8,
    vaults: std::collections::BTreeMap<String, VaultKeys>,
}

/// File-header schema. Everything above the AEAD payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileHeaderV2 {
    version: u8,
    slots: Vec<SlotHeader>,
}

/// Per-slot header record. `kind`-specific extras are flattened into
/// the same JSON object — untagged so the fields can be consumed by
/// a single deserialiser pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SlotHeader {
    kind: SlotKind,
    /// Base64 ML-KEM-768 encapsulation key ("public key"). Stored
    /// so `save_contents` can re-encapsulate without touching the
    /// slot's underlying credential.
    ek: String,
    /// Base64 ML-KEM-768 ciphertext targeted at `ek`.
    kem_ct: String,
    /// Base64 AEAD nonce used to wrap the content key with the
    /// KEM-derived secret.
    wrap_nonce: String,
    /// Base64 AEAD ciphertext + tag wrapping the 32-byte content key.
    wrapped_content_key: String,
    /// Only present on `yubikey` slots. Serial number of the card
    /// this slot is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    yk_serial: Option<u32>,
    /// Only present on `yubikey` slots. SHA-256 of the SPKI public
    /// key bits, base64-encoded. Host-side check that the key
    /// material behind the card slot didn't change between
    /// registration and open — if it did, the card was
    /// re-provisioned and should be re-registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    yk_key_id: Option<String>,
    /// Only present on `yubikey` slots. Openly-stored random salt;
    /// the card signs it to produce the KEM seed input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    yk_salt: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SlotKind {
    Keychain,
    Yubikey,
}

// ── File path resolution ───────────────────────────────────────────

fn keys_file_path() -> Result<PathBuf, CommandError> {
    let root = if let Ok(overridden) = std::env::var("BV_GUI_DATA_DIR_OVERRIDE") {
        PathBuf::from(overridden)
    } else {
        let base = dirs::data_local_dir()
            .or_else(dirs::home_dir)
            .ok_or("Cannot determine home directory")?;
        base.join(".bastion_vault_gui")
    };
    if !root.exists() {
        fs::create_dir_all(&root).map_err(|e| {
            CommandError::from(format!("create data dir {root:?}: {e}"))
        })?;
    }
    Ok(root.join(KEYS_FILE_NAME))
}

// ── Local-key (OS keychain) helpers ────────────────────────────────

fn load_or_create_local_key() -> Result<[u8; KEY_LEN], CommandError> {
    let entry = keyring::Entry::new(SERVICE, LOCAL_KEY_ENTRY)
        .map_err(|e| CommandError::from(format!("keyring entry: {e}")))?;
    match entry.get_password() {
        Ok(hex_str) => {
            let decoded = hex::decode(hex_str.trim()).map_err(|e| {
                CommandError::from(format!(
                    "local-master-key in keychain is not valid hex: {e}"
                ))
            })?;
            if decoded.len() != KEY_LEN {
                return Err(CommandError::from(format!(
                    "local-master-key in keychain has wrong length: \
                     got {} bytes, expected {KEY_LEN}",
                    decoded.len()
                )));
            }
            let mut out = [0u8; KEY_LEN];
            out.copy_from_slice(&decoded);
            Ok(out)
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; KEY_LEN];
            rand::rng().fill_bytes(&mut key);
            entry
                .set_password(&hex::encode(key))
                .map_err(|e| CommandError::from(format!("keyring store: {e}")))?;
            Ok(key)
        }
        Err(e) => Err(CommandError::from(format!("keyring read: {e}"))),
    }
}

// ── Seed derivation ────────────────────────────────────────────────

/// Derive a 64-byte ML-KEM-768 seed from the keychain-stored Local Key.
fn seed_from_keychain() -> Result<[u8; ML_KEM_768_SEED_LEN], CommandError> {
    let key = load_or_create_local_key()?;
    let hk = Hkdf::<Sha256>::new(None, &key);
    let mut seed = [0u8; ML_KEM_768_SEED_LEN];
    hk.expand(HKDF_INFO_KEYCHAIN_SEED, &mut seed).map_err(|e| {
        CommandError::from(format!("hkdf expand (keychain): {e}"))
    })?;
    Ok(seed)
}

/// Derive a 64-byte ML-KEM-768 seed from a YubiKey signature over
/// the slot's openly-stored salt. Deterministic because RSA-PKCS1v15
/// and RFC-6979 ECDSA signatures are both deterministic — the same
/// (card, salt) pair always produces the same seed.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn seed_from_yubikey_signature(
    signature: &[u8],
    salt: &[u8],
) -> Result<[u8; ML_KEM_768_SEED_LEN], CommandError> {
    // HKDF salt is the openly-stored salt; IKM is the signature.
    // That way a captured file + known salt still isn't enough —
    // the attacker also needs the private key that produced the
    // signature (which never leaves the YubiKey).
    let hk = Hkdf::<Sha256>::new(Some(salt), signature);
    let mut seed = [0u8; ML_KEM_768_SEED_LEN];
    hk.expand(HKDF_INFO_YUBIKEY_SEED, &mut seed).map_err(|e| {
        CommandError::from(format!("hkdf expand (yubikey): {e}"))
    })?;
    Ok(seed)
}

/// Derive a 32-byte AEAD key from the KEM-shared-secret for
/// wrapping / unwrapping the content key.
fn wrap_key_from_shared_secret(ss: &[u8]) -> Result<[u8; KEY_LEN], CommandError> {
    let hk = Hkdf::<Sha256>::new(None, ss);
    let mut k = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO_WRAP_KEY, &mut k)
        .map_err(|e| CommandError::from(format!("hkdf wrap-key: {e}")))?;
    Ok(k)
}

// ── Envelope seal / open ───────────────────────────────────────────

/// Build a fresh v2 envelope from the plaintext JSON and the
/// currently-registered slots. Re-runs on every save; content key
/// is freshly random each time so two consecutive saves don't share
/// payload ciphertext.
fn seal_v2(plaintext: &[u8], slot_seeds: &[SlotSealInput]) -> Result<Vec<u8>, CommandError> {
    if slot_seeds.is_empty() {
        return Err(CommandError::from(
            "local_keystore: at least one unlock slot required".to_string(),
        ));
    }

    // 1. Generate the one content key that protects the payload.
    let mut content_key = [0u8; KEY_LEN];
    rand::rng().fill_bytes(&mut content_key);

    // 2. Encrypt the payload once.
    let mut payload_nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut payload_nonce);
    let cipher = ChaCha20Poly1305::new((&content_key).into());
    let payload_ct = cipher
        .encrypt(Nonce::from_slice(&payload_nonce), plaintext)
        .map_err(|e| CommandError::from(format!("aead encrypt payload: {e}")))?;

    // 3. For each slot: KEM-encapsulate to its public key, use the
    //    shared secret to wrap the content key.
    let provider = MlKem768Provider;
    let mut slots = Vec::with_capacity(slot_seeds.len());
    for input in slot_seeds {
        let (kem_ct, shared_secret) = provider
            .encapsulate(&input.encapsulation_key)
            .map_err(|e| {
                CommandError::from(format!("ml-kem encapsulate: {e}"))
            })?;
        let wrap_key = wrap_key_from_shared_secret(shared_secret.as_bytes())?;
        let mut wrap_nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut wrap_nonce);
        let cipher = ChaCha20Poly1305::new((&wrap_key).into());
        let wrapped = cipher
            .encrypt(Nonce::from_slice(&wrap_nonce), content_key.as_ref())
            .map_err(|e| CommandError::from(format!("aead wrap content key: {e}")))?;

        slots.push(SlotHeader {
            kind: input.kind,
            ek: base64_encode(&input.encapsulation_key),
            kem_ct: base64_encode(kem_ct.as_bytes()),
            wrap_nonce: base64_encode(&wrap_nonce),
            wrapped_content_key: base64_encode(&wrapped),
            yk_serial: input.yk_serial,
            yk_key_id: input.yk_key_id.clone(),
            yk_salt: input.yk_salt.clone(),
        });
    }

    // Zeroise the in-memory content key — the copy in `cipher`
    // above is not externally accessible but a stack-local clone
    // would be. AEAD ciphers consume the key by value, so we rely
    // on stack unwinding to drop them after their last use.
    for b in &mut content_key {
        *b = 0;
    }

    let header = FileHeaderV2 { version: 2, slots };
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| CommandError::from(format!("serialise header: {e}")))?;

    let mut out =
        Vec::with_capacity(MAGIC_V2.len() + 4 + header_json.len() + NONCE_LEN + payload_ct.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&payload_nonce);
    out.extend_from_slice(&payload_ct);
    Ok(out)
}

/// Try each slot in turn until one successfully unwraps the content
/// key. Errors carry the slot count that was tried so operators can
/// tell whether a failure means "credential wrong" vs. "slot state
/// corrupted."
fn open_v2(blob: &[u8]) -> Result<Vec<u8>, CommandError> {
    let (header, payload_nonce, payload_ct) = parse_v2(blob)?;
    let provider = MlKem768Provider;

    let mut last_err: Option<CommandError> = None;
    for (i, slot) in header.slots.iter().enumerate() {
        match try_open_slot(slot, &provider, payload_nonce, payload_ct) {
            Ok(plain) => return Ok(plain),
            Err(e) => {
                // Slot-open failures are noisy: every Tauri command
                // that reaches the keystore will hit the same bad
                // slot and retry the whole open sequence. Dedupe
                // by hashing the (slot-kind, error-string) pair
                // and only printing the first time we see each
                // combination in this process. Operators still
                // get a breadcrumb when running from a terminal;
                // the "same error seven times per page load" noise
                // is gone.
                let tag = format!("{:?}:{e}", slot.kind);
                log_once(&tag, || {
                    eprintln!(
                        "local_keystore: slot {i} ({:?}) failed to open: {e}",
                        slot.kind
                    )
                });
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        CommandError::from(
            "local_keystore: no unlock slots available to open the file".to_string(),
        )
    }))
}

fn try_open_slot(
    slot: &SlotHeader,
    provider: &MlKem768Provider,
    payload_nonce: &[u8; NONCE_LEN],
    payload_ct: &[u8],
) -> Result<Vec<u8>, CommandError> {
    let seed = match slot.kind {
        SlotKind::Keychain => seed_from_keychain()?,
        SlotKind::Yubikey => derive_yubikey_seed_for_slot(slot)?,
    };
    let keypair = provider
        .keypair_from_seed(&seed)
        .map_err(|e| CommandError::from(format!("ml-kem keygen from seed: {e}")))?;
    let kem_ct = base64_decode(&slot.kem_ct)?;
    let shared_secret = provider
        .decapsulate(keypair.secret_key(), &kem_ct)
        .map_err(|e| CommandError::from(format!("ml-kem decapsulate: {e}")))?;

    let wrap_key = wrap_key_from_shared_secret(shared_secret.as_bytes())?;
    let wrap_nonce = base64_decode(&slot.wrap_nonce)?;
    let wrapped = base64_decode(&slot.wrapped_content_key)?;
    if wrap_nonce.len() != NONCE_LEN {
        return Err(CommandError::from("slot wrap_nonce wrong length".to_string()));
    }
    let cipher = ChaCha20Poly1305::new((&wrap_key).into());
    let content_key_vec = cipher
        .decrypt(Nonce::from_slice(&wrap_nonce), wrapped.as_slice())
        .map_err(|e| {
            // This is the most common "something is wrong with the
            // local keystore" path: the KEM seed we derived from
            // the current OS keychain entry doesn't match what was
            // used to seal the file. Happens when the keychain
            // entry gets wiped between runs (OS credential-manager
            // cleanup, uninstall/reinstall, moving the profile
            // across machines). The cloud bucket's own data is
            // unaffected — only the cached unseal key is — so the
            // remediation is to reset the local keystore and
            // re-enter the vault's unseal key on next open.
            CommandError::from(format!(
                "local keystore: unable to unwrap the cached content key \
                 with this machine's Local Key ({e}). The keychain entry \
                 `local-master-key` no longer matches the one that sealed \
                 the file — most likely the OS keychain was wiped between \
                 runs. Vault data on disk / in the cloud is unaffected; \
                 run `Settings → Reset local key cache` and re-enter the \
                 vault's unseal key on next open."
            ))
        })?;
    if content_key_vec.len() != KEY_LEN {
        return Err(CommandError::from(format!(
            "unwrapped content key has wrong length: {} bytes",
            content_key_vec.len()
        )));
    }
    let mut content_key = [0u8; KEY_LEN];
    content_key.copy_from_slice(&content_key_vec);

    let payload_cipher = ChaCha20Poly1305::new((&content_key).into());
    let plain = payload_cipher
        .decrypt(Nonce::from_slice(payload_nonce), payload_ct)
        .map_err(|e| CommandError::from(format!("aead decrypt payload: {e}")))?;

    for b in &mut content_key {
        *b = 0;
    }
    Ok(plain)
}

fn derive_yubikey_seed_for_slot(
    slot: &SlotHeader,
) -> Result<[u8; ML_KEM_768_SEED_LEN], CommandError> {
    let serial = slot.yk_serial.ok_or_else(|| {
        CommandError::from("yubikey slot missing `yk_serial`".to_string())
    })?;
    let salt_b64 = slot
        .yk_salt
        .as_ref()
        .ok_or_else(|| CommandError::from("yubikey slot missing `yk_salt`".to_string()))?;
    let salt = base64_decode(salt_b64)?;
    // The PIN is supplied through a thread-local set by the command
    // layer right before `open`; this keeps the keystore core free
    // of GUI-specific prompting logic. A missing PIN means the
    // caller didn't set one — surface as a distinct error so the
    // UI can prompt.
    let pin = current_yubikey_pin().ok_or_else(|| {
        CommandError::from(
            "yubikey slot requires PIN — call `set_yubikey_pin` before open".to_string(),
        )
    })?;
    let sig = crate::yubikey_bridge::sign(serial, pin.as_bytes(), &salt)?;

    // Verify the SPKI-fingerprint still matches the registered
    // one, so a re-provisioned card surfaces as a mismatch error
    // rather than silently producing a wrong seed.
    if let Some(expected_key_id) = &slot.yk_key_id {
        let (id, _spki) = crate::yubikey_bridge::load_signing_public_key(serial)?;
        let current_key_id = base64_encode(&id.key_id_sha256);
        if &current_key_id != expected_key_id {
            return Err(CommandError::from(format!(
                "yubikey: slot {serial}'s key fingerprint changed — re-register the card"
            )));
        }
    }

    seed_from_yubikey_signature(&sig, &salt)
}

fn parse_v2(blob: &[u8]) -> Result<(FileHeaderV2, &[u8; NONCE_LEN], &[u8]), CommandError> {
    if blob.len() < MAGIC_V2.len() + 4 + NONCE_LEN {
        return Err(CommandError::from(
            "local_keystore: file truncated".to_string(),
        ));
    }
    if &blob[..MAGIC_V2.len()] != MAGIC_V2 {
        return Err(CommandError::from(
            "local_keystore: wrong magic for v2".to_string(),
        ));
    }
    let header_len = u32::from_be_bytes([
        blob[MAGIC_V2.len()],
        blob[MAGIC_V2.len() + 1],
        blob[MAGIC_V2.len() + 2],
        blob[MAGIC_V2.len() + 3],
    ]) as usize;
    let header_start = MAGIC_V2.len() + 4;
    let header_end = header_start + header_len;
    if blob.len() < header_end + NONCE_LEN {
        return Err(CommandError::from(
            "local_keystore: header length runs off end of file".to_string(),
        ));
    }
    let header: FileHeaderV2 =
        serde_json::from_slice(&blob[header_start..header_end]).map_err(|e| {
            CommandError::from(format!("parse v2 header: {e}"))
        })?;

    // Split the payload_nonce off into a fixed-size slice ref so
    // the caller can pass it straight to ChaCha's nonce type.
    let nonce_array: &[u8; NONCE_LEN] = blob[header_end..header_end + NONCE_LEN]
        .try_into()
        .map_err(|_| CommandError::from("nonce slice sizing bug".to_string()))?;
    let payload_ct = &blob[header_end + NONCE_LEN..];
    Ok((header, nonce_array, payload_ct))
}

// ── v1 backward-compat ─────────────────────────────────────────────

fn decrypt_v1(blob: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, CommandError> {
    if blob.len() < MAGIC_V1.len() + NONCE_LEN {
        return Err(CommandError::from(
            "v1 file truncated".to_string(),
        ));
    }
    if &blob[..MAGIC_V1.len()] != MAGIC_V1 {
        return Err(CommandError::from(
            "v1 file has unrecognised magic".to_string(),
        ));
    }
    let nonce_start = MAGIC_V1.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, &blob[nonce_end..])
        .map_err(|e| CommandError::from(format!("v1 AEAD decrypt: {e}")))
}

// ── Load + save (version-aware) ────────────────────────────────────

fn load_contents() -> Result<FileContents, CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(FileContents {
            version: 1,
            vaults: Default::default(),
        });
    }
    let blob = fs::read(&path)
        .map_err(|e| CommandError::from(format!("read {path:?}: {e}")))?;

    if blob.starts_with(MAGIC_V2) {
        let plaintext = open_v2(&blob)?;
        let parsed: FileContents = serde_json::from_slice(&plaintext)
            .map_err(|e| CommandError::from(format!("parse vault-keys JSON: {e}")))?;
        return Ok(parsed);
    }

    if blob.starts_with(MAGIC_V1) {
        // Legacy direct-AEAD format. Decrypt with the local key and
        // let the next save upgrade it to v2.
        let key = load_or_create_local_key()?;
        let plaintext = decrypt_v1(&blob, &key)?;
        let parsed: FileContents = serde_json::from_slice(&plaintext)
            .map_err(|e| CommandError::from(format!("parse vault-keys JSON (v1): {e}")))?;
        return Ok(parsed);
    }

    Err(CommandError::from(
        "vault-keys file has unrecognised magic header".to_string(),
    ))
}

fn save_contents(contents: &FileContents) -> Result<(), CommandError> {
    let plaintext = serde_json::to_vec(contents)
        .map_err(|e| CommandError::from(format!("serialize vault-keys JSON: {e}")))?;
    let slot_seeds = build_slot_seal_inputs()?;
    let blob = seal_v2(&plaintext, &slot_seeds)?;

    // tmp-then-rename so a crash mid-write can't leave the file in
    // a state that locks every vault out.
    let path = keys_file_path()?;
    let tmp = path.with_extension("enc.tmp");
    let mut f = fs::File::create(&tmp)
        .map_err(|e| CommandError::from(format!("create {tmp:?}: {e}")))?;
    f.write_all(&blob)
        .map_err(|e| CommandError::from(format!("write {tmp:?}: {e}")))?;
    f.sync_all()
        .map_err(|e| CommandError::from(format!("sync {tmp:?}: {e}")))?;
    drop(f);
    fs::rename(&tmp, &path)
        .map_err(|e| CommandError::from(format!("rename {tmp:?} → {path:?}: {e}")))?;
    Ok(())
}

/// Build the list of slots to include on a save. We always include
/// a keychain slot (the default, primary path). Each registered
/// YubiKey extends the list; loaded on-demand from `registered_yk`.
fn build_slot_seal_inputs() -> Result<Vec<SlotSealInput>, CommandError> {
    let mut slots = Vec::new();

    // Keychain slot: derive the seed, generate the PQC keypair,
    // keep the encapsulation key for re-seal.
    let seed = seed_from_keychain()?;
    let provider = MlKem768Provider;
    let keypair = provider
        .keypair_from_seed(&seed)
        .map_err(|e| CommandError::from(format!("ml-kem keypair for keychain slot: {e}")))?;
    slots.push(SlotSealInput {
        kind: SlotKind::Keychain,
        encapsulation_key: keypair.public_key().to_vec(),
        yk_serial: None,
        yk_key_id: None,
        yk_salt: None,
    });

    // YubiKey slots: read back from the existing file header so we
    // re-include every registered card. Each slot already has its
    // `ek` persisted; we don't need the card to be present at save
    // time. Missing file → no YubiKey slots registered yet.
    if let Some(existing) = load_existing_yubikey_slots()? {
        for slot in existing {
            slots.push(slot);
        }
    }
    Ok(slots)
}

fn load_existing_yubikey_slots() -> Result<Option<Vec<SlotSealInput>>, CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let blob = fs::read(&path)
        .map_err(|e| CommandError::from(format!("read {path:?}: {e}")))?;
    if !blob.starts_with(MAGIC_V2) {
        return Ok(None);
    }
    let (header, _, _) = parse_v2(&blob)?;
    let mut out = Vec::new();
    for slot in header.slots {
        if slot.kind == SlotKind::Yubikey {
            let ek = base64_decode(&slot.ek)?;
            out.push(SlotSealInput {
                kind: SlotKind::Yubikey,
                encapsulation_key: ek,
                yk_serial: slot.yk_serial,
                yk_key_id: slot.yk_key_id,
                yk_salt: slot.yk_salt,
            });
        }
    }
    Ok(Some(out))
}

#[derive(Debug, Clone)]
struct SlotSealInput {
    kind: SlotKind,
    encapsulation_key: Vec<u8>,
    yk_serial: Option<u32>,
    yk_key_id: Option<String>,
    yk_salt: Option<String>,
}

// ── YubiKey PIN stash (set before open) ────────────────────────────

use std::sync::Mutex;
static YK_PIN: Mutex<Option<String>> = Mutex::new(None);

/// Set the PIV PIN for the current open attempt. Cleared by the
/// command layer after use so the PIN does not linger in memory
/// beyond the ceremony that required it.
pub fn set_yubikey_pin(pin: String) {
    if let Ok(mut g) = YK_PIN.lock() {
        *g = Some(pin);
    }
}

pub fn clear_yubikey_pin() {
    if let Ok(mut g) = YK_PIN.lock() {
        if let Some(mut p) = g.take() {
            // Zeroise the released String's bytes best-effort.
            unsafe {
                let bytes = p.as_bytes_mut();
                for b in bytes {
                    *b = 0;
                }
            }
        }
    }
}

fn current_yubikey_pin() -> Option<String> {
    YK_PIN.lock().ok().and_then(|g| g.clone())
}

// ── Public per-vault API ───────────────────────────────────────────

pub fn get_unseal_key(vault_id: &str) -> Result<Option<String>, CommandError> {
    migrate_legacy_if_needed(vault_id)?;
    let contents = load_contents()?;
    Ok(contents
        .vaults
        .get(vault_id)
        .map(|k| k.unseal_key_hex.clone()))
}

pub fn store_unseal_key(vault_id: &str, unseal_key_hex: &str) -> Result<(), CommandError> {
    if vault_id.trim().is_empty() {
        return Err(CommandError::from(
            "store_unseal_key: vault_id must be non-empty".to_string(),
        ));
    }
    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }
    let entry = contents.vaults.entry(vault_id.to_string()).or_insert(VaultKeys {
        unseal_key_hex: String::new(),
        root_token: String::new(),
        created_at: now_unix(),
    });
    entry.unseal_key_hex = unseal_key_hex.to_string();
    save_contents(&contents)
}

pub fn get_root_token(vault_id: &str) -> Result<Option<String>, CommandError> {
    migrate_legacy_if_needed(vault_id)?;
    let contents = load_contents()?;
    Ok(contents
        .vaults
        .get(vault_id)
        .map(|k| k.root_token.clone()))
}

pub fn store_root_token(vault_id: &str, root_token: &str) -> Result<(), CommandError> {
    if vault_id.trim().is_empty() {
        return Err(CommandError::from(
            "store_root_token: vault_id must be non-empty".to_string(),
        ));
    }
    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }
    let entry = contents.vaults.entry(vault_id.to_string()).or_insert(VaultKeys {
        unseal_key_hex: String::new(),
        root_token: String::new(),
        created_at: now_unix(),
    });
    entry.root_token = root_token.to_string();
    save_contents(&contents)
}

pub fn remove_vault(vault_id: &str) -> Result<(), CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(());
    }
    let mut contents = load_contents()?;
    if contents.vaults.remove(vault_id).is_none() {
        return Ok(());
    }
    if contents.vaults.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    save_contents(&contents)
}

/// Blow away the whole keystore file + the local key. Only called
/// from the test suite today; kept `pub` behind `#[allow(dead_code)]`
/// so a future "Full Reset" command can reach it without the
/// visibility gymnastics of moving tests-only API into a separate
/// module.
#[allow(dead_code)]
pub fn wipe_all() -> Result<(), CommandError> {
    if let Ok(path) = keys_file_path() {
        let _ = fs::remove_file(path);
    }
    if let Ok(entry) = keyring::Entry::new(SERVICE, LOCAL_KEY_ENTRY) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

// ── YubiKey slot management (Phase 2 public API) ───────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RegisteredYubiKey {
    pub serial: u32,
    pub key_id: String,
    pub registered_at: u64,
}

/// Enumerate the YubiKey slots currently persisted in the file.
pub fn list_registered_yubikeys() -> Result<Vec<RegisteredYubiKey>, CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let blob = fs::read(&path)
        .map_err(|e| CommandError::from(format!("read {path:?}: {e}")))?;
    if !blob.starts_with(MAGIC_V2) {
        return Ok(Vec::new());
    }
    let (header, _, _) = parse_v2(&blob)?;
    let mut out = Vec::new();
    for slot in header.slots {
        if slot.kind == SlotKind::Yubikey {
            if let (Some(serial), Some(key_id)) = (slot.yk_serial, slot.yk_key_id) {
                out.push(RegisteredYubiKey {
                    serial,
                    key_id,
                    registered_at: 0,
                });
            }
        }
    }
    Ok(out)
}

/// Register a new YubiKey as an additional unlock slot. Requires
/// the PIN for the slot-9a signing key so we can derive the ML-KEM
/// keypair deterministically and verify the roundtrip before
/// committing the slot to disk.
pub fn register_yubikey(serial: u32, pin: String) -> Result<RegisteredYubiKey, CommandError> {
    // Load the current file so we re-encrypt with the new slot
    // alongside the existing ones. Empty keystore → start a new file.
    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }

    // Fetch the YubiKey's SPKI fingerprint so we can detect
    // re-provisioning later. Also proves the card is reachable
    // before we go through the PIN ceremony.
    let (id, _pk) = crate::yubikey_bridge::load_signing_public_key(serial)?;

    // Fresh salt per registration. Stored openly next to the kem_ct;
    // security rests on the card's private key.
    let mut salt = [0u8; YUBIKEY_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    // Prove the PIN + salt combo actually produces a usable seed
    // before committing — otherwise a typo in the PIN would land
    // us a slot that no one can open.
    let sig = crate::yubikey_bridge::sign(serial, pin.as_bytes(), &salt)?;
    let seed = seed_from_yubikey_signature(&sig, &salt)?;
    let provider = MlKem768Provider;
    let keypair = provider
        .keypair_from_seed(&seed)
        .map_err(|e| CommandError::from(format!("ml-kem keypair for yubikey slot: {e}")))?;

    // Append the slot-as-intended to the existing file and re-save.
    // `save_contents` will re-include every currently-registered
    // slot, so this call-order stays correct regardless of where
    // we sit in the file lifecycle.
    set_yubikey_pin(pin);
    let key_id_b64 = base64_encode(&id.key_id_sha256);
    let salt_b64 = base64_encode(&salt);

    // Inject the slot into the existing file header by round-
    // tripping the contents through `save_contents` after having
    // written the slot record via the standard seal path. The
    // simplest way is to do a direct seal: build slot-seal-inputs
    // manually including the new yubikey entry + the existing ones.
    let mut slot_seeds = build_slot_seal_inputs()?;
    slot_seeds.push(SlotSealInput {
        kind: SlotKind::Yubikey,
        encapsulation_key: keypair.public_key().to_vec(),
        yk_serial: Some(serial),
        yk_key_id: Some(key_id_b64.clone()),
        yk_salt: Some(salt_b64),
    });

    let plaintext = serde_json::to_vec(&contents)
        .map_err(|e| CommandError::from(format!("serialise vault-keys JSON: {e}")))?;
    let blob = seal_v2(&plaintext, &slot_seeds)?;
    let path = keys_file_path()?;
    let tmp = path.with_extension("enc.tmp");
    let mut f = fs::File::create(&tmp)
        .map_err(|e| CommandError::from(format!("create {tmp:?}: {e}")))?;
    f.write_all(&blob)
        .map_err(|e| CommandError::from(format!("write {tmp:?}: {e}")))?;
    f.sync_all()
        .map_err(|e| CommandError::from(format!("sync {tmp:?}: {e}")))?;
    drop(f);
    fs::rename(&tmp, &path)
        .map_err(|e| CommandError::from(format!("rename {tmp:?} → {path:?}: {e}")))?;

    // Don't leave the PIN sitting in the static after a successful
    // registration — the caller's session is done with it.
    clear_yubikey_pin();

    // `contents` was loaded up-top so the migration path had its
    // mut binding; nothing mutates it on the happy path, and the
    // encrypted payload we just wrote above is derived from it
    // verbatim. Drop the binding here to silence the unused-mut
    // lint without the earlier self-assignment hack.
    drop(contents);
    Ok(RegisteredYubiKey {
        serial,
        key_id: key_id_b64,
        registered_at: now_unix(),
    })
}

/// Remove a YubiKey slot by serial. Refuses to remove the LAST
/// unlock slot when no keychain slot exists — the operator would
/// be locked out.
pub fn remove_yubikey(serial: u32) -> Result<(), CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(());
    }
    let contents = load_contents()?;
    let blob = fs::read(&path)
        .map_err(|e| CommandError::from(format!("read {path:?}: {e}")))?;
    if !blob.starts_with(MAGIC_V2) {
        return Ok(());
    }
    let (header, _, _) = parse_v2(&blob)?;
    let has_keychain = header.slots.iter().any(|s| s.kind == SlotKind::Keychain);
    let yk_count = header
        .slots
        .iter()
        .filter(|s| s.kind == SlotKind::Yubikey)
        .count();
    if !has_keychain && yk_count <= 1 {
        return Err(CommandError::from(
            "local_keystore: refusing to remove the last unlock slot".to_string(),
        ));
    }

    // Rebuild seal inputs minus the target serial, then re-save.
    let mut keep = Vec::new();
    // Keychain slot is always added by `build_slot_seal_inputs`;
    // don't manually append it here.
    for slot in header.slots {
        if slot.kind == SlotKind::Yubikey && slot.yk_serial == Some(serial) {
            continue;
        }
        if slot.kind == SlotKind::Yubikey {
            let ek = base64_decode(&slot.ek)?;
            keep.push(SlotSealInput {
                kind: SlotKind::Yubikey,
                encapsulation_key: ek,
                yk_serial: slot.yk_serial,
                yk_key_id: slot.yk_key_id,
                yk_salt: slot.yk_salt,
            });
        }
    }
    // Prepend the fresh keychain slot.
    let seed = seed_from_keychain()?;
    let provider = MlKem768Provider;
    let keypair = provider
        .keypair_from_seed(&seed)
        .map_err(|e| CommandError::from(format!("ml-kem keypair: {e}")))?;
    let mut seeds = vec![SlotSealInput {
        kind: SlotKind::Keychain,
        encapsulation_key: keypair.public_key().to_vec(),
        yk_serial: None,
        yk_key_id: None,
        yk_salt: None,
    }];
    seeds.extend(keep);

    let plaintext = serde_json::to_vec(&contents)
        .map_err(|e| CommandError::from(format!("serialise vault-keys JSON: {e}")))?;
    let blob = seal_v2(&plaintext, &seeds)?;
    let tmp = path.with_extension("enc.tmp");
    let mut f = fs::File::create(&tmp)
        .map_err(|e| CommandError::from(format!("create {tmp:?}: {e}")))?;
    f.write_all(&blob)
        .map_err(|e| CommandError::from(format!("write {tmp:?}: {e}")))?;
    f.sync_all()
        .map_err(|e| CommandError::from(format!("sync {tmp:?}: {e}")))?;
    drop(f);
    fs::rename(&tmp, &path)
        .map_err(|e| CommandError::from(format!("rename {tmp:?} → {path:?}: {e}")))?;
    Ok(())
}

// ── Migration path ─────────────────────────────────────────────────

fn migrate_legacy_if_needed(vault_id: &str) -> Result<(), CommandError> {
    use crate::secure_store;
    let legacy_unseal = secure_store::get_unseal_key()?;
    let legacy_token = secure_store::get_root_token()?;
    if legacy_unseal.is_none() && legacy_token.is_none() {
        return Ok(());
    }
    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }
    let already = contents.vaults.contains_key(vault_id);
    if !already {
        let entry = contents
            .vaults
            .entry(vault_id.to_string())
            .or_insert(VaultKeys {
                unseal_key_hex: String::new(),
                root_token: String::new(),
                created_at: now_unix(),
            });
        if let Some(k) = legacy_unseal {
            entry.unseal_key_hex = k;
        }
        if let Some(t) = legacy_token {
            entry.root_token = t;
        }
        save_contents(&contents)?;
    }
    let _ = secure_store::delete_all_keys();
    Ok(())
}

// ── Small helpers ──────────────────────────────────────────────────

/// Dedupe diagnostic log output: call `body` the first time we see
/// `tag`, no-op on subsequent calls with the same `tag`. Keeps the
/// set bounded by dropping entries once the process has accumulated
/// a lot of distinct errors — at that point the specific
/// de-duplication matters less than not holding onto every bad
/// state string forever.
fn log_once<F: FnOnce()>(tag: &str, body: F) {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    if let Ok(mut set) = seen.lock() {
        if set.len() >= 128 {
            set.clear();
        }
        if set.insert(tag.to_string()) {
            body();
        }
    } else {
        body();
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, CommandError> {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CommandError::from(format!("base64 decode: {e}")))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// The tests below share the OS keychain entry `local-master-key`.
    /// Running them in parallel produces races where one test's
    /// `wipe_all()` evicts another test's just-written key and
    /// corrupts its still-in-flight save. Serialise them through
    /// this mutex — `cargo test -- --test-threads=1` would work too
    /// but this way the file stays self-contained.
    static KEYSTORE_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    fn with_isolated_data_dir<F: FnOnce() -> R, R>(f: F) -> R {
        let tmp = tempdir_path("bv-keystore-test");
        let prev = std::env::var("BV_GUI_DATA_DIR_OVERRIDE").ok();
        std::env::set_var("BV_GUI_DATA_DIR_OVERRIDE", tmp.to_str().unwrap());
        let r = f();
        match prev {
            Some(v) => std::env::set_var("BV_GUI_DATA_DIR_OVERRIDE", v),
            None => std::env::remove_var("BV_GUI_DATA_DIR_OVERRIDE"),
        }
        let _ = fs::remove_dir_all(&tmp);
        r
    }

    fn tempdir_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        p.push(format!("{tag}-{}", hex::encode(random)));
        p
    }

    #[test]
    fn v2_seal_open_roundtrips_with_keychain_only_slot() {
        // Lock + isolate AT THE TEST BOUNDARY so the keychain
        // entry we mint is stable for the whole seal-then-open
        // ceremony. Acquiring the lock inside a helper that also
        // enters with_isolated_data_dir deadlocks.
        let _guard = KEYSTORE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_isolated_data_dir(|| {
            let _ = wipe_all();
            // Prime the keychain so seed_from_keychain inside
            // try_open_slot reads the same bytes we sealed under.
            let seed = seed_from_keychain().unwrap();
            let provider = MlKem768Provider;
            let keypair = provider.keypair_from_seed(&seed).unwrap();
            let slots = vec![SlotSealInput {
                kind: SlotKind::Keychain,
                encapsulation_key: keypair.public_key().to_vec(),
                yk_serial: None,
                yk_key_id: None,
                yk_salt: None,
            }];
            let sealed = seal_v2(b"hello world", &slots).unwrap();
            assert_eq!(&sealed[..4], MAGIC_V2);
            let recovered = open_v2(&sealed).unwrap();
            assert_eq!(&recovered, b"hello world");
            let _ = wipe_all();
        });
    }

    #[test]
    fn per_vault_isolation_still_works() {
        let _guard = KEYSTORE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_isolated_data_dir(|| {
            let _ = wipe_all();
            store_unseal_key("vault-a", "aaaa1111").unwrap();
            store_unseal_key("vault-b", "bbbb2222").unwrap();
            assert_eq!(
                get_unseal_key("vault-a").unwrap().as_deref(),
                Some("aaaa1111")
            );
            assert_eq!(
                get_unseal_key("vault-b").unwrap().as_deref(),
                Some("bbbb2222")
            );
            remove_vault("vault-a").unwrap();
            assert!(get_unseal_key("vault-a").unwrap().is_none());
            assert_eq!(
                get_unseal_key("vault-b").unwrap().as_deref(),
                Some("bbbb2222")
            );
            remove_vault("vault-b").unwrap();
            let _ = wipe_all();
        });
    }

    #[test]
    fn v1_file_is_readable_and_auto_upgrades_on_next_write() {
        let _guard = KEYSTORE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_isolated_data_dir(|| {
            let _ = wipe_all();
            // Hand-craft a v1 file so we can prove the migration path.
            let key = load_or_create_local_key().unwrap();
            let contents = FileContents {
                version: 1,
                vaults: [(
                    "legacy".to_string(),
                    VaultKeys {
                        unseal_key_hex: "deadbeef".to_string(),
                        root_token: "tok-legacy".to_string(),
                        created_at: 0,
                    },
                )]
                .into_iter()
                .collect(),
            };
            let plaintext = serde_json::to_vec(&contents).unwrap();
            let mut nonce = [0u8; NONCE_LEN];
            rand::rng().fill_bytes(&mut nonce);
            let cipher = ChaCha20Poly1305::new((&key).into());
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
                .unwrap();
            let mut v1 = Vec::with_capacity(4 + NONCE_LEN + ct.len());
            v1.extend_from_slice(MAGIC_V1);
            v1.extend_from_slice(&nonce);
            v1.extend_from_slice(&ct);
            let path = keys_file_path().unwrap();
            fs::write(&path, &v1).unwrap();

            // Read the legacy file via the normal public API.
            assert_eq!(
                get_unseal_key("legacy").unwrap().as_deref(),
                Some("deadbeef")
            );

            // Trigger a write — the next save produces a v2 file.
            store_unseal_key("legacy", "newvalue").unwrap();
            let on_disk = fs::read(&path).unwrap();
            assert_eq!(&on_disk[..4], MAGIC_V2);
            assert_eq!(
                get_unseal_key("legacy").unwrap().as_deref(),
                Some("newvalue")
            );
            let _ = wipe_all();
        });
    }

    #[test]
    fn yubikey_seed_is_reproducible() {
        let salt = [0x5au8; 32];
        let sig = b"test-signature-bytes";
        let a = seed_from_yubikey_signature(sig, &salt).unwrap();
        let b = seed_from_yubikey_signature(sig, &salt).unwrap();
        assert_eq!(a, b);
        // Different salt → different seed.
        let c = seed_from_yubikey_signature(sig, &[0xa5u8; 32]).unwrap();
        assert_ne!(a, c);
        // Different signature → different seed.
        let d = seed_from_yubikey_signature(b"other-sig", &salt).unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn wrong_magic_rejected() {
        // Must be ≥ MAGIC_V2.len() + 4 + NONCE_LEN (20 bytes) so the
        // size check doesn't short-circuit into "truncated" before
        // the magic is compared. Pad with junk to hit the threshold.
        let mut blob = Vec::with_capacity(32);
        blob.extend_from_slice(b"BVK\x99");
        blob.extend_from_slice(&[0u8; 28]);
        let err = parse_v2(&blob).unwrap_err();
        assert!(
            format!("{err}").contains("magic"),
            "expected `magic` in error, got: {err}"
        );
    }

    #[test]
    fn truncated_file_rejected() {
        let err = parse_v2(b"BV").unwrap_err();
        assert!(format!("{err}").contains("truncated"));
    }
}
