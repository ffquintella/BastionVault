//! Tauri command for SMB connection profiles (features/smb-connect.md).
//!
//! `session_open_smb` opens the SFTP dual-pane window over an SMB share. It
//! reuses the connect path's building blocks — profile lookup, the Rustion
//! transport policy, the SSH login class, connect-time MFA, and the RDP
//! password resolver (`secret`, `ldap`, `default-account`) — and differs:

//! * **Password sources only.** NTLM needs a username and a password;
//!   `pki`, `ssh-engine`, `fido2` and `provider` are refused before
//!   anything is resolved.
//! * **Direct only.** Rustion has no SMB relay: a `rustion` profile or a
//!   `rustion-required` policy is refused, never silently dialled direct.
//! * **No host key.** The server is identified by the NTLM exchange and the
//!   signed session (signing required, `session::smb`).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, State};

use super::connect::{
    collect_policy_hints, find_profile, is_connect_layer_error, now_rfc3339, open_context, profile_host_candidates,
    profile_username, read_effective_login_class, read_effective_policy, read_resource_meta, record_recent_session,
    record_session_open, resolve_rdp_credential, resolve_session_layout, run_cleanup, spawn_own_session_window,
    OperatorCredential, SessionProtocolTag,
};
use super::connect_provider::{dial_in_order, DialFailure};
use crate::error::{CmdResult, CommandError};
use crate::session::{
    self,
    attachments::SessionDescriptor,
    rdp::RdpCredential,
    smb::{self as smb_session, ntlm_identity, parse_smb_profile, SmbOpenArgs, SmbOpenOutcome},
    ssh::CONNECT_TIMEOUT,
    workspace::Placement,
};
use crate::state::AppState;

/// The SMB port when the profile does not override it.
pub const DEFAULT_SMB_PORT: u16 = 445;

#[derive(Deserialize)]
pub struct SmbOpenRequest {
    pub resource_name: String,
    pub profile_id: String,
    /// LDAP operator-bind, or a `default-account` with no stored password.
    #[serde(default)]
    pub operator_credential: Option<OperatorCredential>,
    /// Single-use connect-time MFA ticket.
    #[serde(default)]
    pub connect_ticket: Option<String>,
}

#[derive(Serialize)]
pub struct SmbOpenResponse {
    pub token: String,
    pub closed_event: String,
    pub window_label: String,
}

/// The credential sources an SMB login can use: those that yield a
/// username and a password.
const SMB_CREDENTIAL_SOURCES: &[&str] = &["secret", "ldap", "default-account"];

/// Refuse a credential source NTLM cannot use, before anything is resolved.
fn check_smb_credential_source(kind: &str) -> Result<(), String> {
    if SMB_CREDENTIAL_SOURCES.contains(&kind) {
        return Ok(());
    }
    Err(match kind {
        "provider" => "SMB profiles can't use a credential provider yet; pick a stored secret, LDAP or the connecting \
                       user's default account"
            .to_string(),
        "pki" | "ssh-engine" | "fido2" | "none" => format!(
            "the `{kind}` credential source cannot authenticate an SMB session (NTLM needs a username and a \
             password); pick a stored secret, LDAP or the connecting user's default account"
        ),
        "" => "SMB profile has no credential source".to_string(),
        other => format!("unknown credential source `{other}`"),
    })
}

/// SMB has no bastion route. A profile pinned to Rustion, a policy lock
/// violation, or a `rustion-required` transport is refused; anything else
/// dials direct (`rustion-preferred` falls back, logged by the caller).
fn smb_transport_refusal(profile_kind: Option<&str>, transport: &str, lock_violation: Option<&str>) -> Option<String> {
    if profile_kind == Some("rustion") {
        return Some(
            "SMB profiles cannot be brokered through a Rustion bastion; set the profile's transport to direct".into(),
        );
    }
    if let Some(detail) = lock_violation {
        return Some(format!("rustion policy lock violation: {detail}"));
    }
    if transport == "rustion-required" {
        return Some(
            "rustion-required policy: an SMB session cannot be brokered through a Rustion bastion (Rustion has no \
             SMB relay). Refusing to dial direct."
                .into(),
        );
    }
    None
}

/// The SSH login class, applied to SMB: a `brokered` resource takes only
/// logins minted per connect by the SSH engine, which an SMB password never
/// is — so SMB is refused there rather than let a static password through.
fn smb_login_class_refusal(
    resource_name: &str,
    login_class: &str,
    login_class_source: &str,
    lock_violation: Option<&str>,
) -> Option<String> {
    if login_class != "brokered" {
        return None;
    }
    if let Some(detail) = lock_violation {
        return Some(format!("login_class_locked: {detail}"));
    }
    Some(format!(
        "brokered_requires_ssh_engine: resource `{resource_name}` is brokered (login_class via tier \
         `{login_class_source}`); every login to it must be minted per connect by the SSH engine, which an SMB \
         session cannot use. Refusing the SMB session."
    ))
}

fn smb_port(profile: &Value) -> u16 {
    profile
        .get("target_port")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_SMB_PORT)
}

/// Open an SMB profile in its own dual-pane window. That window calls the
/// `sftp_*` commands, which dispatch on the session's kind; the password
/// never reaches it.
#[tauri::command]
pub async fn session_open_smb(
    state: State<'_, AppState>,
    app: AppHandle,
    request: SmbOpenRequest,
) -> CmdResult<SmbOpenResponse> {
    let opened_in = open_context(&state, None).await?;
    let meta = read_resource_meta(&state, &request.resource_name).await?;
    let profile = find_profile(&meta, &request.profile_id).ok_or_else(|| {
        CommandError::from(format!(
            "profile `{}` not found on resource `{}`",
            request.profile_id, request.resource_name
        ))
    })?;
    session::ProfileProtocol::require(&profile, session::ProfileProtocol::Smb).map_err(CommandError::from)?;
    // Own window, always.
    let (_, layout_prefs) = resolve_session_layout(Some(Placement::OwnWindow))?;
    let smb = parse_smb_profile(&profile).map_err(CommandError::from)?;
    let kind = profile.pointer("/credential_source/kind").and_then(Value::as_str).unwrap_or("");
    check_smb_credential_source(kind).map_err(CommandError::from)?;

    let host_candidates = profile_host_candidates(&profile, &meta);
    if host_candidates.is_empty() {
        return Err(CommandError::from(
            "resource has no hostname or ip_address; set one or override target_host on the profile".to_string(),
        ));
    }
    let port = smb_port(&profile);
    let primary_target_host = host_candidates.first().cloned().unwrap_or_default();

    // Transport and login class are settled before the MFA ticket is burnt
    // or a credential resolved (an LDAP library check-out would otherwise be
    // left checked out: its cleanup only runs with a session).
    let (resource_id, resource_type, asset_group_ids) =
        collect_policy_hints(&state, &request.resource_name, &meta).await;
    let effective = read_effective_policy(&state, &resource_id, &resource_type, &asset_group_ids).await?;
    if let Some(refusal) = smb_transport_refusal(
        profile.get("kind").and_then(Value::as_str),
        &effective.transport,
        effective.lock_violation.as_deref(),
    ) {
        return Err(CommandError::from(refusal));
    }
    if effective.transport == "rustion-preferred" && !effective.bastions.is_empty() {
        log::warn!(
            "resource-connect/smb: rustion-preferred but Rustion has no SMB relay; dialling `{}` direct",
            request.resource_name
        );
    }
    let login_class = read_effective_login_class(&state, &resource_id, &resource_type, &asset_group_ids).await?;
    if let Some(refusal) = smb_login_class_refusal(
        &request.resource_name,
        &login_class.login_class,
        &login_class.login_class_source,
        login_class.lock_violation.as_deref(),
    ) {
        return Err(CommandError::from(refusal));
    }

    // Connect-time MFA: the ticket is redeemed before any credential is
    // resolved, exactly as on the SSH and RDP direct paths.
    super::connect_mfa::authorize_direct(
        &state,
        &request.resource_name,
        &request.profile_id,
        request.connect_ticket.as_deref(),
    )
    .await?;
    let resolved =
        resolve_rdp_credential(&state, &request.resource_name, &profile, request.operator_credential.as_ref(), "SMB")
            .await?;
    let on_close = resolved.on_close;
    let password = match resolved.credential {
        RdpCredential::Password(p) if !p.is_empty() => p,
        _ => {
            if let Some(c) = on_close {
                run_cleanup(&state, c).await;
            }
            return Err(CommandError::from(
                "an SMB login needs a password; the credential source gave none".to_string(),
            ));
        }
    };
    let login = resolved.effective_username.unwrap_or_else(|| profile_username(&profile));
    if login.is_empty() {
        if let Some(c) = on_close {
            run_cleanup(&state, c).await;
        }
        return Err(CommandError::from(
            "SMB profile has no username (set profile.username, use a secret with a `username` field, LDAP, or the \
             connecting user's default account)"
                .to_string(),
        ));
    }
    let (username, domain) = ntlm_identity(&login, resolved.domain, smb.domain.as_deref());

    if let Err(e) = record_session_open(
        &state,
        &request.resource_name,
        &request.profile_id,
        "smb",
        "direct",
        &primary_target_host,
        port,
    )
    .await
    {
        if let Some(c) = on_close {
            run_cleanup(&state, c).await;
        }
        return Err(e);
    }
    let dialled = dial_in_order("smb", &host_candidates, port, |host| {
        let app = app.clone();
        let state = &state;
        let args = SmbOpenArgs {
            host: host.clone(),
            port,
            share: smb.share.clone(),
            username: username.clone(),
            domain: domain.clone(),
            password: password.clone(),
            label: format!("smb {username}@{host}:{port}/{}", smb.share),
            on_close: on_close.clone(),
        };
        async move {
            match tokio::time::timeout(CONNECT_TIMEOUT, smb_session::open_smb_session(app, state, args)).await {
                Ok(Ok(o)) => Ok(o),
                Ok(Err(e)) => Err(DialFailure { network_layer: is_connect_layer_error(&e), message: e }),
                Err(_) => Err(DialFailure {
                    message: format!(
                        "smb: connect+auth to {host}:{port} timed out after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    ),
                    network_layer: true,
                }),
            }
        }
    })
    .await;
    drop(password);
    let (host, outcome): (String, SmbOpenOutcome) = match dialled {
        Ok(v) => v,
        Err(e) => {
            // No session took the LDAP library account: check it back in.
            if let Some(c) = on_close {
                run_cleanup(&state, c).await;
            }
            return Err(e);
        }
    };
    let label = format!("smb {username}@{host}:{port}/{}", smb.share);
    log::info!(
        target: "audit",
        "session.open: resource={} protocol=smb transport=direct login_class={} login_class_source={} \
         login_class_chain=[{}] share={} signing=required token={} host={}:{}",
        request.resource_name,
        login_class.login_class,
        login_class.login_class_source,
        login_class.login_class_chain.join(","),
        smb.share,
        outcome.token,
        host,
        port,
    );

    let descriptor = SessionDescriptor {
        token: outcome.token.clone(),
        protocol: session::ProfileProtocol::Smb,
        label: label.clone(),
        resource_name: request.resource_name.clone(),
        profile_id: request.profile_id.clone(),
        stdout_event: None,
        closed_event: outcome.closed_event.clone(),
        resize_event: None,
        cursor_event: None,
        width: None,
        height: None,
        opened_at: now_rfc3339(),
        placement: Placement::OwnWindow,
        pane_ref: None,
        namespace: opened_in.namespace.clone(),
        vault_id: opened_in.vault_id.clone(),
    };
    let window_label = spawn_own_session_window(&app, &state, descriptor, &layout_prefs).await?;
    log::info!("resource-connect/smb: session for {label} rendered in window {window_label}");

    let _ = record_recent_session(&state, &request.resource_name, &profile, SessionProtocolTag::Smb).await;

    Ok(SmbOpenResponse { token: outcome.token, closed_event: outcome.closed_event, window_label })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// NTLM needs a username and a password: only the password sources
    /// launch; the others fail closed before anything is resolved.
    #[test]
    fn only_password_sources_can_open_an_smb_session() {
        for ok in ["secret", "ldap", "default-account"] {
            assert!(check_smb_credential_source(ok).is_ok(), "{ok}");
        }
        for bad in ["pki", "ssh-engine", "fido2", "provider", "none", "", "kerberos"] {
            assert!(check_smb_credential_source(bad).is_err(), "{bad}");
        }
        assert!(check_smb_credential_source("provider").unwrap_err().contains("credential provider"));
    }

    /// There is no bastion path for SMB: a Rustion profile, a lock violation
    /// and `rustion-required` are refused, never dialled direct.
    #[test]
    fn smb_is_refused_wherever_a_bastion_is_required() {
        assert!(smb_transport_refusal(Some("rustion"), "", None).is_some());
        assert!(smb_transport_refusal(None, "rustion-required", None).unwrap().contains("Refusing to dial direct"));
        assert!(smb_transport_refusal(Some("direct"), "", Some("tier locked")).unwrap().contains("lock violation"));
        assert_eq!(smb_transport_refusal(None, "rustion-preferred", None), None);
        assert_eq!(smb_transport_refusal(Some("direct"), "direct", None), None);
        assert_eq!(smb_transport_refusal(None, "", None), None);
    }

    /// A brokered resource never takes a static SMB password.
    #[test]
    fn a_brokered_resource_refuses_smb() {
        let e = smb_login_class_refusal("fs01", "brokered", "type", None).unwrap();
        assert!(e.starts_with("brokered_requires_ssh_engine") && e.contains("fs01"), "{e}");
        assert!(smb_login_class_refusal("fs01", "brokered", "type", Some("x"))
            .unwrap()
            .starts_with("login_class_locked"));
        assert_eq!(smb_login_class_refusal("fs01", "shared-credential", "default", None), None);
    }

    #[test]
    fn the_port_defaults_to_445() {
        assert_eq!(smb_port(&json!({})), 445);
        assert_eq!(smb_port(&json!({ "target_port": 1445 })), 1445);
        assert_eq!(smb_port(&json!({ "target_port": 0 })), 445);
        assert_eq!(smb_port(&json!({ "target_port": 70000 })), 445);
    }
}
