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

#[tauri::command]
pub async fn yubikey_register(
    serial: u32,
    pin: String,
) -> CmdResult<RegisteredYubiKeyDto> {
    let reg = crate::local_keystore::register_yubikey(serial, pin)?;
    Ok(RegisteredYubiKeyDto {
        serial: reg.serial,
        key_id: reg.key_id,
        registered_at: reg.registered_at,
    })
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
