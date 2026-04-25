//! Tauri commands exposing the YubiKey failsafe surface to the GUI.
//!
//! Three operations wire up to the Settings page:
//!
//!   * `yubikey_list_devices` — scan the PC/SC readers and return
//!     the plugged-in YubiKeys. The UI uses this both on the
//!     registration ceremony ("pick which card to enrol") and on
//!     the removal list ("here are the cards currently registered
//!     vs. physically present").
//!
//!   * `yubikey_register` — enrol a connected card as an additional
//!     unlock slot on the vault-keys file. Takes the PIV PIN;
//!     signs a fresh random salt to prove the PIN is valid and to
//!     produce the ML-KEM keypair's seed. Commits the new slot
//!     only after the signature + keygen roundtrip succeeds.
//!
//!   * `yubikey_list_registered` — read the slots currently
//!     persisted in the file so the UI can list them.
//!
//!   * `yubikey_remove` — drop a registered slot. Refuses to remove
//!     the last slot (that would permanently lock the file).
//!
//! All commands return small, Serialize-able DTOs so the TypeScript
//! bindings stay stable across Phase-2 iterations of the crate
//! selection.

use serde::Serialize;

use crate::error::CmdResult;

#[derive(Serialize, Debug, Clone)]
pub struct YubiKeyDeviceInfo {
    pub serial: u32,
    pub slot_occupied: bool,
}

#[tauri::command]
pub async fn yubikey_list_devices() -> CmdResult<Vec<YubiKeyDeviceInfo>> {
    // PC/SC enumeration is synchronous and cheap; wrapping in
    // `spawn_blocking` would add latency without buying anything.
    let devices = crate::yubikey_bridge::list_devices()?;
    Ok(devices
        .into_iter()
        .map(|d| YubiKeyDeviceInfo {
            serial: d.serial,
            slot_occupied: d.slot_occupied,
        })
        .collect())
}

#[derive(Serialize, Debug, Clone)]
pub struct RegisteredYubiKeyDto {
    pub serial: u32,
    pub key_id: String,
    pub registered_at: u64,
}

#[tauri::command]
pub async fn yubikey_list_registered() -> CmdResult<Vec<RegisteredYubiKeyDto>> {
    let entries = crate::local_keystore::list_registered_yubikeys()?;
    Ok(entries
        .into_iter()
        .map(|e| RegisteredYubiKeyDto {
            serial: e.serial,
            key_id: e.key_id,
            registered_at: e.registered_at,
        })
        .collect())
}

/// Provision PIV slot 9a on the given card: generate RSA-2048,
/// self-sign a minimal X.509, write both. Invoked from the
/// Add-Local-Vault / Settings YubiKey flows when the operator
/// picks a card whose slot 9a was empty at enumeration time.
/// Requires the PIN and assumes the factory-default management
/// key — surfaces a descriptive error if it was rotated.
#[tauri::command]
pub async fn yubikey_provision_slot_9a(serial: u32, pin: String) -> CmdResult<()> {
    crate::yubikey_bridge::provision_slot_9a(serial, pin.as_bytes())?;
    Ok(())
}

#[tauri::command]
pub async fn yubikey_register(
    serial: u32,
    pin: String,
    require: Option<bool>,
) -> CmdResult<RegisteredYubiKeyDto> {
    let reg =
        crate::local_keystore::register_yubikey(serial, pin, require.unwrap_or(false))?;
    Ok(RegisteredYubiKeyDto {
        serial: reg.serial,
        key_id: reg.key_id,
        registered_at: reg.registered_at,
    })
}

/// Re-enable the OS-keychain unlock path on a keystore that
/// previously dropped it (via `yubikey_register(..., require=true)`).
/// Idempotent — no-op when a keychain slot is already present.
#[tauri::command]
pub async fn yubikey_enable_keychain_slot() -> CmdResult<()> {
    crate::local_keystore::enable_keychain_slot()?;
    Ok(())
}

/// Whether the keystore currently has a keychain unlock slot
/// enrolled. Used by the Settings page to show the active posture
/// and offer the "Re-enable keychain unlock" recovery button.
#[tauri::command]
pub async fn yubikey_keychain_slot_present() -> CmdResult<bool> {
    Ok(crate::local_keystore::keychain_slot_present()?)
}

#[tauri::command]
pub async fn yubikey_remove(serial: u32) -> CmdResult<()> {
    crate::local_keystore::remove_yubikey(serial)?;
    Ok(())
}

/// Cache the operator-supplied PIN in the keystore's internal
/// stash so the next vault-open operation can reach the YubiKey
/// without a round-trip back up to the GUI for the same ceremony.
/// Paired with `yubikey_clear_pin` — the caller is responsible for
/// clearing it after the open completes.
#[tauri::command]
pub async fn yubikey_set_pin(pin: String) -> CmdResult<()> {
    crate::local_keystore::set_yubikey_pin(pin);
    Ok(())
}

#[tauri::command]
pub async fn yubikey_clear_pin() -> CmdResult<()> {
    crate::local_keystore::clear_yubikey_pin();
    Ok(())
}
