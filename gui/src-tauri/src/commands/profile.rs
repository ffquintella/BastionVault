//! Self-service profile commands — what the *signed-in* operator may change
//! about their own account without an administrator.
//!
//! Every command here targets a `sys/identity/…/self` route. The server
//! resolves the principal from the request token, so none of these can reach
//! another user's record and none of them take a username argument. Contrast
//! `commands/users.rs`, which is the admin surface and addresses principals by
//! `(mount, username)` with a root token.
//!
//! See `features/self-service-profile.md`.

use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

const PROFILE_SELF: &str = "sys/identity/profile/self";
const PROFILE_SELF_PASSWORD: &str = "sys/identity/profile/self/password";
const PROFILE_SELF_CONTACT: &str = "sys/identity/profile/self/contact";
const DEFAULT_ACCOUNT_SELF: &str = "sys/identity/default-account/self";

/// The caller's own per-OS default resource accounts. The stored Windows RDP
/// password is never carried to the frontend — only its presence.
#[derive(Serialize, Default)]
pub struct MyDefaultAccount {
    pub mount: String,
    pub name: String,
    pub linux: String,
    pub macos: String,
    pub windows: String,
    pub has_windows_password: bool,
    pub updated_at: String,
}

/// The signed-in operator's profile, as the Profile page renders it.
///
/// The `can_*` flags come from the server rather than being inferred in the
/// UI: whether a password can be changed depends on how the token was minted
/// (userpass vs AppRole/OIDC/root) and on account state (disabled, FIDO2-only),
/// none of which the frontend can see on its own.
#[derive(Serialize, Default)]
pub struct MyProfile {
    pub username: String,
    pub display_name: String,
    pub entity_id: String,
    /// Real auth mount that issued the token (e.g. `auth/pass/`); empty when
    /// the token did not come from a userpass login.
    pub auth_mount: String,
    pub auth_method: String,
    pub policies: Vec<String>,
    pub email: String,
    pub phone: String,
    pub disabled: bool,
    pub fido2_enabled: bool,
    pub totp_mfa_enabled: bool,
    pub can_change_password: bool,
    pub can_edit_contact: bool,
    pub can_edit_default_account: bool,
    pub default_account: MyDefaultAccount,
}

fn str_at(data: Option<&Map<String, Value>>, key: &str) -> String {
    data.and_then(|d| d.get(key)).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn bool_at(data: Option<&Map<String, Value>>, key: &str) -> bool {
    data.and_then(|d| d.get(key)).and_then(|v| v.as_bool()).unwrap_or(false)
}

#[tauri::command]
pub async fn get_my_profile(state: State<'_, AppState>) -> CmdResult<MyProfile> {
    let resp = make_request(&state, Operation::Read, PROFILE_SELF.to_string(), None).await?;
    let data = resp.and_then(|r| r.data);
    let d = data.as_ref();

    let account = d
        .and_then(|m| m.get("default_account"))
        .and_then(|v| v.as_object())
        .cloned();
    let a = account.as_ref();

    Ok(MyProfile {
        username: str_at(d, "username"),
        display_name: str_at(d, "display_name"),
        entity_id: str_at(d, "entity_id"),
        auth_mount: str_at(d, "auth_mount"),
        auth_method: str_at(d, "auth_method"),
        policies: d
            .and_then(|m| m.get("policies"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|p| p.as_str().map(String::from)).collect()
            })
            .unwrap_or_default(),
        email: str_at(d, "email"),
        phone: str_at(d, "phone"),
        disabled: bool_at(d, "disabled"),
        fido2_enabled: bool_at(d, "fido2_enabled"),
        totp_mfa_enabled: bool_at(d, "totp_mfa_enabled"),
        can_change_password: bool_at(d, "can_change_password"),
        can_edit_contact: bool_at(d, "can_edit_contact"),
        can_edit_default_account: bool_at(d, "can_edit_default_account"),
        default_account: MyDefaultAccount {
            mount: str_at(a, "mount"),
            name: str_at(a, "name"),
            linux: str_at(a, "linux"),
            macos: str_at(a, "macos"),
            windows: str_at(a, "windows"),
            has_windows_password: bool_at(a, "has_windows_password"),
            updated_at: str_at(a, "updated_at"),
        },
    })
}

/// Change the signed-in operator's own password. The server re-authenticates
/// with `current_password`, so a stolen token alone cannot rotate it.
#[tauri::command]
pub async fn change_my_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("current_password".to_string(), Value::String(current_password));
    body.insert("new_password".to_string(), Value::String(new_password));
    make_request(&state, Operation::Write, PROFILE_SELF_PASSWORD.to_string(), Some(body)).await?;
    Ok(())
}

/// Update the signed-in operator's own contact details. `None` for a field
/// leaves the stored value alone; `Some("")` clears it.
#[tauri::command]
pub async fn update_my_contact(
    state: State<'_, AppState>,
    email: Option<String>,
    phone: Option<String>,
) -> CmdResult<()> {
    let mut body = Map::new();
    if let Some(v) = email {
        body.insert("email".to_string(), Value::String(v));
    }
    if let Some(v) = phone {
        body.insert("phone".to_string(), Value::String(v));
    }
    make_request(&state, Operation::Write, PROFILE_SELF_CONTACT.to_string(), Some(body)).await?;
    Ok(())
}

/// Set the signed-in operator's own default resource accounts.
///
/// Every field is write-preserve server-side: `None` keeps the stored value,
/// `Some("")` clears it. The GUI sends `None` for `windows_password` unless the
/// operator typed a new one or asked to clear it, so re-saving the form does
/// not wipe a password they never see.
#[tauri::command]
pub async fn set_my_default_account(
    state: State<'_, AppState>,
    linux: Option<String>,
    macos: Option<String>,
    windows: Option<String>,
    windows_password: Option<String>,
) -> CmdResult<()> {
    let mut body = Map::new();
    for (key, value) in [
        ("linux", linux),
        ("macos", macos),
        ("windows", windows),
        ("windows_password", windows_password),
    ] {
        if let Some(v) = value {
            body.insert(key.to_string(), Value::String(v));
        }
    }
    make_request(&state, Operation::Write, DEFAULT_ACCOUNT_SELF.to_string(), Some(body)).await?;
    Ok(())
}
