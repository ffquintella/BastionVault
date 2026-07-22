//! Tauri commands for the Resource Connect SSH/RDP session windows.
//!
//! Phase 3 ships SSH with the **Secret** credential source.
//! The credential resolver runs entirely on the Rust side: the
//! frontend supplies (resource_name, secret_id, profile_id); the
//! command pulls the secret out of barrier-encrypted storage,
//! resolves the credential into [`session::ssh::SshCredential`],
//! and feeds it straight to russh. The credential bytes never
//! cross the IPC boundary back to the JS layer.

use std::collections::HashMap;

use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder};
use zeroize::Zeroizing;

use crate::error::{CmdResult, CommandError};
use crate::session::{
    self,
    ssh::{open_ssh_session, SshCredential, SshOpenArgs, SshOpenOutcome, CONNECT_TIMEOUT},
    SshControl,
};
use crate::state::AppState;

// Resource module is mounted at `resources/`; the engine itself
// nests records under `resources/resources/<name>` and secrets
// under `resources/secrets/<name>/<key>`. We carry only the mount
// prefix here so each call site can pick the right sub-path —
// matches the convention in `commands/resources.rs` (which uses
// the same `RESOURCE_MOUNT = "resources/"`).
const RESOURCE_MOUNT: &str = "resources/";

#[derive(Deserialize)]
pub struct SshOpenRequest {
    /// Resource name the profile lives on. Used to load the
    /// metadata + the secret.
    pub resource_name: String,
    /// Profile id — resolves protocol/target/user/credential
    /// source. The host re-reads the profile from the resource
    /// rather than trusting any client-side copy of it.
    pub profile_id: String,
    /// Optional operator-supplied credential payload. Required
    /// only for `LdapBindMode::Operator` profiles, where the
    /// frontend pops a prompt before calling open and forwards
    /// the typed username/password through this field.
    #[serde(default)]
    pub operator_credential: Option<OperatorCredential>,
}

#[derive(Deserialize, Default)]
pub struct OperatorCredential {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SshOpenResponse {
    pub token: String,
    pub stdout_event: String,
    pub closed_event: String,
    pub window_label: String,
}

#[tauri::command]
pub async fn session_open_ssh(
    state: State<'_, AppState>,
    app: AppHandle,
    request: SshOpenRequest,
) -> CmdResult<SshOpenResponse> {
    // Load the resource metadata.
    let meta = read_resource_meta(&state, &request.resource_name).await?;

    // Resolve the profile.
    let profile = find_profile(&meta, &request.profile_id).ok_or_else(|| {
        CommandError::from(format!(
            "profile `{}` not found on resource `{}`",
            request.profile_id, request.resource_name
        ))
    })?;

    // Compute the effective target, user, port from the profile +
    // resource metadata defaults.
    let host_candidates = profile_host_candidates(&profile, &meta);
    if host_candidates.is_empty() {
        return Err(CommandError::from(
            "resource has no hostname or ip_address; set one or override target_host on the profile".to_string(),
        ));
    }
    let port = profile_port(&profile);
    let username = profile_username(&profile);
    // Allow empty here; LDAP sources can supply the username via
    // `effective_username`. We re-validate after resolution.
    let host_key_fingerprint = profile.get("host_key_pin").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Pick the resource's first host candidate as the policy's
    // `target_host` — what the bastion dials after consuming the ticket.
    // The resource's full candidate list still applies on the direct path.
    let primary_target_host = host_candidates.first().cloned().unwrap_or_default();

    // For secret-backed credentials, prefer server-side resolution through
    // `rustion/v2/session/open`: BastionVault resolves and injects the
    // secret, so a connect-only operator (capability `connect` but not
    // `read`) can still open a brokered session — the GUI never reads the
    // credential on this path. Returns `Direct` when the policy doesn't
    // route through a bastion, in which case we fall back to the
    // client-side resolution path below (Secret + LDAP / SSH-engine / PKI).
    let credential_source = profile.get("credential_source").cloned().unwrap_or(Value::Null);
    let credential_source_kind = credential_source.get("kind").and_then(|v| v.as_str()).unwrap_or("");

    // `secret` and `ssh-engine` sources resolve server-side on the v2
    // path: BastionVault either injects the stored secret (`secret`) or
    // mints + signs an ephemeral cert (`ssh-engine`, brokered) and seals
    // it into the envelope — the GUI never holds the credential. When the
    // policy doesn't route through a bastion, `open_rustion_session_v2_ssh`
    // returns `Direct` and we fall back to the client-side path below
    // (which mints locally for a direct dial).
    let v2_route: Option<ConnectRoute> = if credential_source_kind == "secret" || credential_source_kind == "ssh-engine"
    {
        let r = open_rustion_session_v2_ssh(
            &state,
            &request.resource_name,
            &meta,
            &profile,
            &primary_target_host,
            port,
            &username,
            &credential_source,
        )
        .await?;
        match r {
            ConnectRoute::Rustion { .. } => Some(r),
            ConnectRoute::Direct => None,
        }
    } else {
        None
    };

    // `credential` is `Some` only on the client-side path (direct dials and
    // non-secret kinds). The v2 server-side path dials the bastion with the
    // ticket and never resolves a target credential locally.
    // Carries the resolved login-class + minted-artifact details so the
    // direct-path `session.open` audit line (below) can stamp
    // `login_class` / `ssh_engine_mode` / `cert_serial` / the resolved
    // tier chain. Left `None` on the v2 server-side path (the rustion
    // module stamps those fields server-side).
    let mut session_audit: Option<(EffectiveLoginClassView, Option<EngineMint>)> = None;
    let (route, credential, username, on_close): (
        ConnectRoute,
        Option<SshCredential>,
        String,
        Option<crate::session::SessionCleanup>,
    ) = if let Some(r) = v2_route {
        (r, None, username, None)
    } else {
        let (resolved, lc) = resolve_ssh_credential(
            &state,
            &request.resource_name,
            &profile,
            &meta,
            request.operator_credential.as_ref(),
        )
        .await?;
        let cred = resolved.credential;
        session_audit = Some((lc, resolved.engine_mint));
        // LDAP profiles can override the profile's username with the one the
        // cred resolver returned (static_role / library set returns the
        // canonical service-account username).
        let username = resolved.effective_username.unwrap_or(username);
        if username.is_empty() {
            return Err(CommandError::from(
                "SSH profile has no username (set profile.username or use an LDAP credential source)".to_string(),
            ));
        }
        let route = resolve_ssh_connect_route(
            &state,
            &request.resource_name,
            &meta,
            &profile,
            &primary_target_host,
            port,
            &username,
            &cred,
        )
        .await?;
        (route, Some(cred), username, resolved.on_close)
    };

    // When the policy routes through a bastion, replace the dial inputs:
    // the operator connects to bastion_host:bastion_port as user
    // `operator` with the ticket as the SSH password. The bastion has
    // its own host key, so the resource's `host_key_pin` no longer
    // applies — we pin the *bastion's* host key instead, using the
    // fingerprint discovered from `GET /v1/listeners` and stored on the
    // target record (`bastion_pin`). Empty means the bastion advertised
    // no fingerprint (pre-v2 listener schema); the SSH dialler then logs
    // an unpinned-TOFU warning rather than failing, matching the direct
    // path's posture for an unset pin.
    let (host_candidates, port, username_for_dial, credential_for_dial, host_key_fingerprint, rustion_label) =
        match &route {
            ConnectRoute::Direct => {
                let cred = credential
                    .clone()
                    .ok_or_else(|| CommandError::from("direct dial requires a resolved credential".to_string()))?;
                (host_candidates, port, username.clone(), cred, host_key_fingerprint, None)
            }
            ConnectRoute::Rustion { bastion_host, bastion_port, ticket, bastion_name, bastion_pin, .. } => {
                if bastion_pin.is_empty() {
                    log::warn!(
                        "resource-connect/ssh: bastion `{}` advertised no host-key fingerprint \
                     — dialling unpinned (TOFU). Run `rustion_target_refresh_listeners` against \
                     a Rustion ≥ listener-schema-v2 to enable pinning.",
                        bastion_name
                    );
                }
                log::info!(
                    "resource-connect/ssh: routing through Rustion bastion `{}` ({}:{}) host-key-pin={}",
                    bastion_name,
                    bastion_host,
                    bastion_port,
                    if bastion_pin.is_empty() { "none" } else { bastion_pin.as_str() }
                );
                (
                    vec![bastion_host.clone()],
                    *bastion_port,
                    "operator".to_string(),
                    SshCredential::Password(Zeroizing::new(ticket.clone())),
                    bastion_pin.clone(),
                    Some(bastion_name.clone()),
                )
            }
        };

    // Walk the host candidates in order (IP before hostname when
    // both are set on the resource). Fall back to the next candidate
    // only on network-layer failures — auth rejections short-circuit
    // so we don't burn auth attempts on every candidate.
    let username = username_for_dial;
    let credential = credential_for_dial;
    let (chosen_host, outcome): (String, SshOpenOutcome) = {
        let mut last_err: Option<String> = None;
        let mut found: Option<(String, SshOpenOutcome)> = None;
        for (idx, host) in host_candidates.iter().enumerate() {
            let is_last = idx + 1 == host_candidates.len();
            let label = format!("ssh {username}@{host}:{port}");
            let res = tokio::time::timeout(
                CONNECT_TIMEOUT,
                open_ssh_session(
                    app.clone(),
                    &state,
                    SshOpenArgs {
                        host: host.clone(),
                        port,
                        username: username.clone(),
                        credential: credential.clone(),
                        host_key_fingerprint: host_key_fingerprint.clone(),
                        label: label.clone(),
                        on_close: on_close.clone(),
                    },
                ),
            )
            .await;
            match res {
                Ok(Ok(o)) => {
                    found = Some((host.clone(), o));
                    break;
                }
                Ok(Err(e)) => {
                    if !is_last && is_connect_layer_error(&e) {
                        log::warn!(
                            "resource-connect/ssh: candidate {host}:{port} failed at network layer ({e}); trying next"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(CommandError::from(e));
                }
                Err(_) => {
                    let msg =
                        format!("ssh: connect+auth to {host}:{port} timed out after {}s", CONNECT_TIMEOUT.as_secs());
                    if !is_last {
                        log::warn!("resource-connect/ssh: {msg}; trying next candidate");
                        last_err = Some(msg);
                        continue;
                    }
                    return Err(CommandError::from(msg));
                }
            }
        }
        found
            .ok_or_else(|| CommandError::from(last_err.unwrap_or_else(|| "ssh: no host candidates succeeded".into())))?
    };
    let host = chosen_host;
    let label = match &rustion_label {
        Some(name) => format!(
            "ssh {target_user}@{target_host}:{target_port} via rustion[{name}]",
            target_user = profile_username(&profile),
            target_host = primary_target_host,
            target_port = profile_port(&profile),
        ),
        None => format!("ssh {username}@{host}:{port}"),
    };

    // Direct-path `session.open` audit line. Stamps the resolved login
    // class, the SSH-engine mode, and the minted cert serial so a brokered
    // session and the `ssh/sign` issuance row that authorized it are
    // joinable (the Rustion path stamps the equivalent fields server-side).
    if let Some((lc, mint)) = &session_audit {
        let (mode, serial) = match mint {
            Some(m) => (m.mode.as_str(), m.cert_serial.as_deref().unwrap_or("")),
            None => ("", ""),
        };
        log::info!(
            target: "audit",
            "session.open: resource={} login_class={} login_class_source={} \
             ssh_engine_mode={} cert_serial={} login_class_chain=[{}] token={} host={}:{}",
            request.resource_name,
            lc.login_class,
            lc.login_class_source,
            mode,
            serial,
            lc.login_class_chain.join(","),
            outcome.token,
            host,
            port,
        );
    }

    // Phase 7.4: stash the Rustion lifecycle bundle keyed by the
    // local SSH token so the spawned window can drive renew + kill.
    if let ConnectRoute::Rustion {
        bastion_id,
        bastion_name,
        session_id,
        correlation_id,
        expires_at,
        max_renewals,
        ..
    } = &route
    {
        state.rustion_session_bundles.lock().await.insert(
            outcome.token.clone(),
            crate::state::RustionSessionBundle {
                session_id: session_id.clone(),
                bastion_id: bastion_id.clone(),
                bastion_name: bastion_name.clone(),
                correlation_id: correlation_id.clone(),
                expires_at: expires_at.clone(),
                max_renewals: *max_renewals,
                protocol: "ssh".to_string(),
            },
        );
    }

    // Spawn the SessionSshWindow into a new WebviewWindow. The
    // window's React route claims the session via the token + the
    // event channel names returned in `outcome`.
    let window_label = format!("ssh-{}", outcome.token);
    // We use HashRouter on the frontend, so the route fragment
    // sits inside the URL hash. Tauri's WebviewUrl::App takes a
    // path relative to the app's index — `index.html#/path` gets
    // the React router to match `/path`.
    let url = format!(
        "index.html#/session/ssh?token={}&stdout={}&closed={}&label={}",
        urlencoding::encode(&outcome.token),
        urlencoding::encode(&outcome.stdout_event),
        urlencoding::encode(&outcome.closed_event),
        urlencoding::encode(&label),
    );
    let win = WebviewWindowBuilder::new(&app, &window_label, WebviewUrl::App(url.into()))
        .title(format!("BastionVault — {label}"))
        .inner_size(900.0, 540.0)
        .resizable(true)
        .build()
        .map_err(|e| CommandError::from(format!("spawn window: {e}")))?;
    // Hook the close button so the operator x'ing the window
    // tears down the SSH session as a side-effect.
    let token_for_close = outcome.token.clone();
    let app_for_close = app.clone();
    win.on_window_event(move |ev| {
        if let tauri::WindowEvent::CloseRequested { .. } = ev {
            let token = token_for_close.clone();
            let app = app_for_close.clone();
            tauri::async_runtime::spawn(async move {
                let s = app.state::<AppState>();
                let _ = session::ssh::send_control(&s, &token, SshControl::Close).await;
                let cleanup = session::ssh::drop_session(&s, &token).await;
                if let Some(c) = cleanup {
                    let s2 = app.state::<AppState>();
                    run_cleanup(&s2, c).await;
                }
                log::info!("resource-connect/ssh: window-close → session drop {token}");
            });
        }
    });

    log::info!("resource-connect/ssh: spawned window {window_label} for {label}");

    let _ = record_recent_session(&state, &request.resource_name, &profile, SessionProtocolTag::Ssh).await;

    Ok(SshOpenResponse {
        token: outcome.token,
        stdout_event: outcome.stdout_event,
        closed_event: outcome.closed_event,
        window_label,
    })
}

#[derive(Deserialize)]
pub struct SshInputRequest {
    pub token: String,
    /// Base64-encoded keystroke bytes.
    pub bytes_b64: String,
}

#[tauri::command]
pub async fn session_input(state: State<'_, AppState>, request: SshInputRequest) -> CmdResult<()> {
    let bytes = session::ssh::decode_b64(&request.bytes_b64).map_err(CommandError::from)?;
    session::ssh::send_control(&state, &request.token, SshControl::Data(bytes)).await.map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct SshResizeRequest {
    pub token: String,
    pub cols: u16,
    pub rows: u16,
}

#[tauri::command]
pub async fn session_resize(state: State<'_, AppState>, request: SshResizeRequest) -> CmdResult<()> {
    session::ssh::send_control(&state, &request.token, SshControl::Resize { cols: request.cols, rows: request.rows })
        .await
        .map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct RdpOpenRequest {
    pub resource_name: String,
    pub profile_id: String,
    /// Same operator-bind credential channel as
    /// `SshOpenRequest::operator_credential`. Required for
    /// `LdapBindMode::Operator` profiles only.
    #[serde(default)]
    pub operator_credential: Option<OperatorCredential>,
}

#[derive(Serialize)]
pub struct RdpOpenResponse {
    pub token: String,
    pub frame_event: String,
    pub closed_event: String,
    pub resize_event: String,
    pub window_label: String,
    pub width: u16,
    pub height: u16,
}

/// Open an RDP session window. Phase 4 ships the surface; the
/// transport itself is stubbed pending an `ironrdp` upstream that
/// stops pinning `=crypto-common 0.2.0-rc.4` against our existing
/// `digest 0.11` stack. The window opens regardless so an operator
/// can see exactly what's in flight; the body shows the dep-blocker
/// banner with a link to the spec.
#[tauri::command]
pub async fn session_open_rdp(
    state: State<'_, AppState>,
    app: AppHandle,
    request: RdpOpenRequest,
) -> CmdResult<RdpOpenResponse> {
    let meta = read_resource_meta(&state, &request.resource_name).await?;
    let profile = find_profile(&meta, &request.profile_id).ok_or_else(|| {
        CommandError::from(format!(
            "profile `{}` not found on resource `{}`",
            request.profile_id, request.resource_name
        ))
    })?;
    let host_candidates = profile_host_candidates(&profile, &meta);
    if host_candidates.is_empty() {
        return Err(CommandError::from(
            "resource has no hostname or ip_address; set one or override target_host on the profile".to_string(),
        ));
    }
    let port = profile.get("target_port").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()).unwrap_or(3389);
    let username = profile_username(&profile);
    // For RDP we don't fail when the profile username is empty
    // — LDAP credential sources supply it. The check after
    // resolution catches the case where every source path is also
    // empty.

    let resolved =
        resolve_rdp_credential(&state, &request.resource_name, &profile, request.operator_credential.as_ref()).await?;
    let username = resolved.effective_username.unwrap_or(username);
    if username.is_empty() {
        return Err(CommandError::from(
            "RDP profile has no username (set profile.username, supply via the LDAP credential source, or use a Secret with a `username` field)"
                .to_string(),
        ));
    }
    let on_close = resolved.on_close;
    let credential = resolved.credential;
    let domain = resolved.domain;
    let aggressive_performance = profile.get("rdp_aggressive_performance").and_then(|v| v.as_bool()).unwrap_or(false);

    // Phase 7.4 — consult the Rustion policy resolver. Mirrors the SSH
    // path: when transport requires (or prefers) a bastion AND the
    // credential is rdp-password, route session/open at Rustion and
    // dial the bastion with `mstshash=<ticket>` as the X.224 routing
    // token. Smartcard credentials under `rustion-required` fail closed
    // (the bastion's `rdp-cert` PKINIT path is tracked separately).
    let primary_target_host = host_candidates.first().cloned().unwrap_or_default();
    let route = resolve_rdp_connect_route(
        &state,
        &request.resource_name,
        &meta,
        &profile,
        &primary_target_host,
        port,
        &username,
        &credential,
    )
    .await?;

    let (
        host_candidates,
        port,
        username_for_dial,
        credential_for_dial,
        domain_for_dial,
        routing_token,
        rustion_label,
        tls_pin_for_dial,
    ) = match &route {
        ConnectRoute::Direct => (
            host_candidates,
            port,
            username.clone(),
            credential.clone(),
            domain.clone(),
            None,
            None,
            // Direct RDP keeps its existing behaviour (no bastion pin);
            // resource-level RDP TLS pinning is out of scope here.
            None,
        ),
        ConnectRoute::Rustion { bastion_host, bastion_port, ticket, bastion_name, bastion_pin, .. } => {
            if bastion_pin.is_empty() {
                log::warn!(
                    "resource-connect/rdp: bastion `{}` advertised no TLS fingerprint — \
                     dialling without pin verification. Run `rustion_target_refresh_listeners` \
                     against a Rustion ≥ listener-schema-v2 to enable pinning.",
                    bastion_name
                );
            }
            log::info!(
                "resource-connect/rdp: routing through Rustion bastion `{}` ({}:{}) tls-pin={}",
                bastion_name,
                bastion_host,
                bastion_port,
                if bastion_pin.is_empty() { "none" } else { bastion_pin.as_str() }
            );
            (
                vec![bastion_host.clone()],
                *bastion_port,
                // Bastion ignores the X.224 user; supply a label that
                // makes the recording metadata legible.
                "rustion-operator".to_string(),
                // The credential field is unused on the wire for
                // ticketed sessions (TLS-only path, no client-side
                // CredSSP, bastion drives upstream auth from the
                // envelope). Pass an empty password so the connector
                // can fill its Credentials slot.
                session::rdp::RdpCredential::Password(Zeroizing::new(String::new())),
                None,
                Some(format!("mstshash={ticket}")),
                Some(bastion_name.clone()),
                (!bastion_pin.is_empty()).then(|| bastion_pin.clone()),
            )
        }
    };
    let username = username_for_dial;
    let credential = credential_for_dial;
    let domain = domain_for_dial;

    // Walk the host candidates in order — IP first when present,
    // hostname as fallback. Only network-layer failures fall through
    // to the next candidate.
    let (host, outcome) = {
        let mut last_err: Option<String> = None;
        let mut found: Option<(String, session::rdp::RdpOpenOutcome)> = None;
        for (idx, host) in host_candidates.iter().enumerate() {
            let is_last = idx + 1 == host_candidates.len();
            let label = format!("rdp {username}@{host}:{port}");
            let res = session::rdp::open_rdp_session(
                app.clone(),
                &state,
                session::rdp::RdpOpenArgs {
                    host: host.clone(),
                    port,
                    username: username.clone(),
                    credential: credential.clone(),
                    domain: domain.clone(),
                    label,
                    on_close: on_close.clone(),
                    aggressive_performance,
                    routing_token: routing_token.clone(),
                    tls_pin_sha256: tls_pin_for_dial.clone(),
                },
            )
            .await;
            match res {
                Ok(o) => {
                    found = Some((host.clone(), o));
                    break;
                }
                Err(e) => {
                    if !is_last && is_connect_layer_error(&e) {
                        log::warn!(
                            "resource-connect/rdp: candidate {host}:{port} failed at network layer ({e}); trying next"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(CommandError::from(e));
                }
            }
        }
        found
            .ok_or_else(|| CommandError::from(last_err.unwrap_or_else(|| "rdp: no host candidates succeeded".into())))?
    };
    let label = match &rustion_label {
        Some(name) => format!(
            "rdp {target_user}@{target_host}:{target_port} via rustion[{name}]",
            target_user = profile_username(&profile),
            target_host = primary_target_host,
            target_port =
                profile.get("target_port").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()).unwrap_or(3389),
        ),
        None => format!("rdp {username}@{host}:{port}"),
    };

    // Phase 7.4: stash the Rustion lifecycle bundle keyed by the
    // local RDP token so the spawned window can drive renew + kill.
    if let ConnectRoute::Rustion {
        bastion_id,
        bastion_name,
        session_id,
        correlation_id,
        expires_at,
        max_renewals,
        ..
    } = &route
    {
        state.rustion_session_bundles.lock().await.insert(
            outcome.token.clone(),
            crate::state::RustionSessionBundle {
                session_id: session_id.clone(),
                bastion_id: bastion_id.clone(),
                bastion_name: bastion_name.clone(),
                correlation_id: correlation_id.clone(),
                expires_at: expires_at.clone(),
                max_renewals: *max_renewals,
                protocol: "rdp".to_string(),
            },
        );
    }

    let window_label = format!("rdp-{}", outcome.token);
    let url = format!(
        "index.html#/session/rdp?token={}&frame={}&closed={}&resize={}&label={}&w={}&h={}",
        urlencoding::encode(&outcome.token),
        urlencoding::encode(&outcome.frame_event),
        urlencoding::encode(&outcome.closed_event),
        urlencoding::encode(&outcome.resize_event),
        urlencoding::encode(&label),
        outcome.width,
        outcome.height,
    );
    let win = WebviewWindowBuilder::new(&app, &window_label, WebviewUrl::App(url.into()))
        .title(format!("BastionVault — {label}"))
        .inner_size((outcome.width as f64) + 8.0, (outcome.height as f64) + 50.0)
        .resizable(true)
        .build()
        .map_err(|e| CommandError::from(format!("spawn window: {e}")))?;
    let token_for_close = outcome.token.clone();
    let app_for_close = app.clone();
    win.on_window_event(move |ev| {
        if let tauri::WindowEvent::CloseRequested { .. } = ev {
            let token = token_for_close.clone();
            let app = app_for_close.clone();
            tauri::async_runtime::spawn(async move {
                let s = app.state::<AppState>();
                let _ = session::rdp::send_control(&s, &token, session::rdp::RdpControl::Close).await;
                let cleanup = session::rdp::drop_session(&s, &token).await;
                if let Some(c) = cleanup {
                    let s2 = app.state::<AppState>();
                    run_cleanup(&s2, c).await;
                }
            });
        }
    });

    let _ = record_recent_session(&state, &request.resource_name, &profile, SessionProtocolTag::Rdp).await;

    Ok(RdpOpenResponse {
        token: outcome.token,
        frame_event: outcome.frame_event,
        closed_event: outcome.closed_event,
        resize_event: outcome.resize_event,
        window_label,
        width: outcome.width,
        height: outcome.height,
    })
}

#[derive(Deserialize)]
pub struct RdpInputMouseRequest {
    pub token: String,
    pub x: u16,
    pub y: u16,
    /// Empty for moves; "down" / "up" for clicks.
    pub button: Option<String>,
    pub button_index: Option<u8>,
}

#[tauri::command]
pub async fn session_input_rdp_mouse(state: State<'_, AppState>, request: RdpInputMouseRequest) -> CmdResult<()> {
    let ctl = match (request.button.as_deref(), request.button_index) {
        (Some("down"), Some(idx)) => {
            session::rdp::RdpControl::PointerButton { button_index: idx, pressed: true, x: request.x, y: request.y }
        }
        (Some("up"), Some(idx)) => {
            session::rdp::RdpControl::PointerButton { button_index: idx, pressed: false, x: request.x, y: request.y }
        }
        _ => session::rdp::RdpControl::PointerMove { x: request.x, y: request.y },
    };
    session::rdp::send_control(&state, &request.token, ctl).await.map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct RdpInputKeyRequest {
    pub token: String,
    pub js_code: String,
    pub pressed: bool,
}

#[tauri::command]
pub async fn session_input_rdp_key(state: State<'_, AppState>, request: RdpInputKeyRequest) -> CmdResult<()> {
    session::rdp::send_control(
        &state,
        &request.token,
        session::rdp::RdpControl::Key { js_code: request.js_code, pressed: request.pressed },
    )
    .await
    .map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct RdpInputResizeRequest {
    pub token: String,
    pub width: u16,
    pub height: u16,
}

#[tauri::command]
pub async fn session_input_rdp_resize(state: State<'_, AppState>, request: RdpInputResizeRequest) -> CmdResult<()> {
    session::rdp::send_control(
        &state,
        &request.token,
        session::rdp::RdpControl::Resize { width: request.width, height: request.height },
    )
    .await
    .map_err(CommandError::from)
}

struct ResolvedRdpCredential {
    credential: session::rdp::RdpCredential,
    /// LDAP bind modes return the canonical username; the caller
    /// swaps it in over the profile's username field.
    effective_username: Option<String>,
    /// LDAP operator-bind can encode `DOMAIN\username` or
    /// `user@realm` — we surface the parsed domain part here so
    /// the RDP connector can put it in the right slot.
    domain: Option<String>,
    on_close: Option<crate::session::SessionCleanup>,
}

async fn resolve_rdp_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
    operator_credential: Option<&OperatorCredential>,
) -> Result<ResolvedRdpCredential, CommandError> {
    let cs = profile
        .get("credential_source")
        .ok_or_else(|| CommandError::from("profile is missing credential_source".to_string()))?;
    let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    match kind {
        "secret" => {
            let secret_id = cs
                .get("secret_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::from("credential_source.secret_id is required"))?;
            let path = format!("{RESOURCE_MOUNT}secrets/{resource_name}/{secret_id}");
            let resp = make_request(state, Operation::Read, path, None).await?;
            let data: HashMap<String, Value> =
                resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
            let password = data.get("password").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
            if password.is_empty() {
                return Err(CommandError::from(format!(
                    "secret `{secret_id}` carries no `password` field — RDP CredSSP requires a password"
                )));
            }
            Ok(ResolvedRdpCredential {
                credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
                effective_username: data
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .filter(|s| !s.is_empty()),
                domain: None,
                on_close: None,
            })
        }
        "ldap" => {
            let ldap_mount = ldap_mount_prefix(cs)?;
            let bind_mode = cs.get("bind_mode").and_then(|v| v.as_str()).unwrap_or("operator");
            match bind_mode {
                "operator" => {
                    let oc = operator_credential.ok_or_else(|| {
                        CommandError::from(
                            "ldap bind_mode = operator requires operator_credential on the open request".to_string(),
                        )
                    })?;
                    if oc.username.is_empty() || oc.password.is_empty() {
                        return Err(CommandError::from(
                            "operator-supplied LDAP credential must carry both username and password".to_string(),
                        ));
                    }
                    let (effective_user, domain) = split_domain_user(&oc.username);
                    let _ = ldap_mount;
                    Ok(ResolvedRdpCredential {
                        credential: session::rdp::RdpCredential::Password(Zeroizing::new(oc.password.clone())),
                        effective_username: Some(effective_user),
                        domain,
                        on_close: None,
                    })
                }
                "static_role" => {
                    let role = cs.get("static_role").and_then(|v| v.as_str()).ok_or_else(|| {
                        CommandError::from(
                            "ldap bind_mode = static_role requires credential_source.static_role".to_string(),
                        )
                    })?;
                    let path = format!("{ldap_mount}static-cred/{role}");
                    let resp = make_request(state, Operation::Read, path, None).await?;
                    let data: HashMap<String, Value> =
                        resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
                    let username = data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!("ldap static-cred/{role} missing `username`")))?
                        .to_string();
                    let password = data
                        .get("password")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!("ldap static-cred/{role} missing `password`")))?
                        .to_string();
                    let (effective_user, domain) = split_domain_user(&username);
                    Ok(ResolvedRdpCredential {
                        credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
                        effective_username: Some(effective_user),
                        domain,
                        on_close: None,
                    })
                }
                "library_set" => {
                    let set = cs.get("library_set").and_then(|v| v.as_str()).ok_or_else(|| {
                        CommandError::from(
                            "ldap bind_mode = library_set requires credential_source.library_set".to_string(),
                        )
                    })?;
                    let path = format!("{ldap_mount}library/{set}/check-out");
                    let resp = make_request(state, Operation::Write, path, None).await?;
                    let data: HashMap<String, Value> =
                        resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
                    let username = data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!("ldap library/{set}/check-out missing `username`")))?
                        .to_string();
                    let password = data
                        .get("password")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!("ldap library/{set}/check-out missing `password`")))?
                        .to_string();
                    let lease_id = data
                        .get("lease_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!("ldap library/{set}/check-out missing `lease_id`")))?
                        .to_string();
                    let (effective_user, domain) = split_domain_user(&username);
                    Ok(ResolvedRdpCredential {
                        credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
                        effective_username: Some(effective_user),
                        domain,
                        on_close: Some(crate::session::SessionCleanup {
                            kind: crate::session::SessionCleanupKind::LdapLibraryCheckIn {
                                ldap_mount: ldap_mount.trim_end_matches('/').to_string(),
                                library_set: set.to_string(),
                                lease_id,
                            },
                        }),
                    })
                }
                other => Err(CommandError::from(format!("unknown ldap bind_mode `{other}`"))),
            }
        }
        "pki" => {
            let issued = issue_pki_credential(state, resource_name, cs).await?;
            let certificate_der = pem_body_to_der(&issued.certificate, "CERTIFICATE")?;
            let private_key_der = pem_body_to_der(&issued.private_key, "PRIVATE KEY")
                // RSA private keys often come in PEM-wrapped
                // PKCS#1 form (`-----BEGIN RSA PRIVATE KEY-----`)
                // — accept both forms and let the IronRDP
                // connector's PKCS#8/PKCS#1 fallback sort it out.
                .or_else(|_| pem_body_to_der(&issued.private_key, "RSA PRIVATE KEY"))?;
            log::info!(
                "resource-connect/rdp: pki/issue produced cert (serial {}) — wiring as CredSSP smartcard",
                issued.serial_number
            );
            Ok(ResolvedRdpCredential {
                credential: session::rdp::RdpCredential::SmartCard(session::rdp::SmartCardCredential {
                    certificate_der,
                    private_key_der,
                    // Synthetic PIN — the PIV emulator inside
                    // sspi-rs accepts any non-empty value
                    // since there's no hardware to enforce it.
                    pin: "0000".to_string(),
                }),
                effective_username: None, // smart-card cred carries the UPN itself
                domain: None,
                on_close: None,
            })
        }
        "default-account" => {
            // The login user is the connecting operator's default Windows
            // account, resolved server-side (the typed username, if any, is
            // ignored — the account is authoritative). The password comes from
            // the operator's stored Windows password when set; otherwise it is
            // prompted at connect (same operator-credential channel LDAP
            // operator-bind uses).
            let accounts = fetch_self_default_accounts(state).await?;
            let username = accounts.windows.trim().to_string();
            if username.is_empty() {
                return Err(CommandError::from(
                    "default-account credential source: the connecting user has no default \
                     Windows account configured. Set it under Users → Edit User → Default \
                     Resource Account."
                        .to_string(),
                ));
            }
            let password = if !accounts.windows_password.is_empty() {
                accounts.windows_password.clone()
            } else if let Some(oc) = operator_credential.filter(|o| !o.password.is_empty()) {
                oc.password.clone()
            } else {
                return Err(CommandError::from(
                    "default-account RDP needs a password: set a stored Windows password under \
                     Users → Edit User → Default Resource Account, or supply one at connect."
                        .to_string(),
                ));
            };
            let (effective_user, domain) = split_domain_user(&username);
            Ok(ResolvedRdpCredential {
                credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
                effective_username: Some(effective_user),
                domain,
                on_close: None,
            })
        }
        other => Err(CommandError::from(format!("credential source `{other}` lands in a later phase"))),
    }
}

/// Split `DOMAIN\\user` or `user@realm` into `(user, Some(domain))`,
/// otherwise return `(input, None)`. RDP CredSSP wants domain in
/// its own field, even though most servers tolerate the combined
/// form.
fn split_domain_user(input: &str) -> (String, Option<String>) {
    if let Some((domain, user)) = input.split_once('\\') {
        if !domain.is_empty() && !user.is_empty() {
            return (user.to_string(), Some(domain.to_string()));
        }
    }
    if let Some((user, realm)) = input.rsplit_once('@') {
        if !user.is_empty() && !realm.is_empty() {
            return (user.to_string(), Some(realm.to_string()));
        }
    }
    (input.to_string(), None)
}

#[derive(Deserialize)]
pub struct SshCloseRequest {
    pub token: String,
}

/// Phase 7.4: surface the Rustion lifecycle bundle the host stashed at
/// open time. The spawned session window calls this on mount; a
/// non-null return drives the renew + kill UI. Direct sessions return
/// `None`.
#[derive(Serialize)]
pub struct SessionRustionInfo {
    pub session_id: String,
    pub bastion_id: String,
    pub bastion_name: String,
    pub correlation_id: String,
    pub expires_at: String,
    pub max_renewals: u32,
    pub protocol: String,
}

#[derive(Deserialize)]
pub struct SessionRustionInfoRequest {
    pub token: String,
}

#[tauri::command]
pub async fn session_rustion_info(
    state: State<'_, AppState>,
    request: SessionRustionInfoRequest,
) -> CmdResult<Option<SessionRustionInfo>> {
    let bundles = state.rustion_session_bundles.lock().await;
    Ok(bundles.get(&request.token).map(|b| SessionRustionInfo {
        session_id: b.session_id.clone(),
        bastion_id: b.bastion_id.clone(),
        bastion_name: b.bastion_name.clone(),
        correlation_id: b.correlation_id.clone(),
        expires_at: b.expires_at.clone(),
        max_renewals: b.max_renewals,
        protocol: b.protocol.clone(),
    }))
}

/// The resolved effective SSH login class for a resource — drives the
/// Connection-tab brokered badge / resolution chip and gates the profile
/// editor's credential-source choices.
#[derive(serde::Serialize, Clone)]
pub struct ResourceLoginClassInfo {
    pub login_class: String,
    pub login_class_source: String,
    pub login_class_chain: Vec<String>,
    pub locked_at_tier: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct ResourceLoginClassRequest {
    pub resource_name: String,
}

#[tauri::command]
pub async fn resource_login_class(
    state: State<'_, AppState>,
    request: ResourceLoginClassRequest,
) -> CmdResult<ResourceLoginClassInfo> {
    let meta = read_resource_meta(&state, &request.resource_name).await?;
    let (rid, rtype, ags) = collect_policy_hints(&state, &request.resource_name, &meta).await;
    let lc = read_effective_login_class(&state, &rid, &rtype, &ags).await?;
    Ok(ResourceLoginClassInfo {
        login_class: lc.login_class,
        login_class_source: lc.login_class_source,
        login_class_chain: lc.login_class_chain,
        locked_at_tier: lc.lock_violation,
    })
}

#[tauri::command]
pub async fn session_close(state: State<'_, AppState>, request: SshCloseRequest) -> CmdResult<()> {
    // Best-effort fan-out: we don't know whether the token names
    // an SSH or RDP session, so try both. The mismatched one
    // returns an error we ignore. drop_session removes either kind
    // and yields any captured cleanup hook.
    let _ = session::ssh::send_control(&state, &request.token, SshControl::Close).await;
    let _ = session::rdp::send_control(&state, &request.token, session::rdp::RdpControl::Close).await;
    let cleanup_ssh = session::ssh::drop_session(&state, &request.token).await;
    let cleanup_rdp = session::rdp::drop_session(&state, &request.token).await;
    if let Some(c) = cleanup_ssh.or(cleanup_rdp) {
        run_cleanup(&state, c).await;
    }
    Ok(())
}

/// Execute a session-close cleanup hook. LDAP library check-in is
/// the only kind today; failures log a warning and swallow the
/// error — the alternative would be to fail the close and leave
/// the session record dangling, which is worse.
async fn run_cleanup(state: &State<'_, AppState>, cleanup: crate::session::SessionCleanup) {
    match cleanup.kind {
        crate::session::SessionCleanupKind::LdapLibraryCheckIn { ldap_mount, library_set, lease_id } => {
            let path = format!("{ldap_mount}/library/{library_set}/check-in");
            let mut body = Map::new();
            body.insert("lease_id".into(), Value::String(lease_id.clone()));
            match make_request(state, Operation::Write, path, Some(body)).await {
                Ok(_) => log::info!(
                    "resource-connect: ldap library check-in ok (mount={ldap_mount} set={library_set} lease={lease_id})"
                ),
                Err(e) => log::warn!(
                    "resource-connect: ldap library check-in failed (mount={ldap_mount} set={library_set} lease={lease_id}): {e:?}"
                ),
            }
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────

use base64::Engine;

use super::make_request;

const RUSTION_MOUNT: &str = "rustion/";

/// Phase 9.3: resolved dial coordinates for a Rustion-mediated session.
/// Returned by [`resolve_bastion_dial_coords`]. The session/open call
/// echoes the listener's `{host, port}` but is unreliable when the
/// bastion is bound to an unspecified address; this function applies
/// a deterministic three-tier preference:
///
///   1. **Stored listener info on the target record** (preferred). BV
///      pulls this at enrolment time via `rustion_target_refresh_listeners`
///      → `GET /v1/listeners` on the bastion. When present, both host
///      and port come from this source; we never trust the per-session
///      echo over a value the operator's enrolment validated.
///   2. **Per-session `host` returned by `session/open`**, when it's a
///      specified (non-`0.0.0.0` / non-`::`) value. Backward-compat
///      path for deployments running an older Rustion that doesn't
///      ship `/v1/listeners`.
///   3. **Host portion of the target's `endpoint`** (last-ditch).
///      Combined with the per-session port. Used when neither (1) nor
///      (2) yields a usable host but the session/open response carried
///      a port.
///
/// Returns `(host, port, pin)` so the dial uses a coherent set from a
/// single source rather than mixing host from (3) with port from (2)
/// which could resolve to a stale listener after a config change. `pin`
/// is the protocol's discovered transport-identity pin off the target
/// record (`ssh_host_key_fingerprint` for SSH, `rdp_tls_pin_sha256` for
/// RDP), empty when the bastion advertised none.
async fn resolve_bastion_dial_coords(
    state: &State<'_, AppState>,
    bastion_id: &str,
    protocol: BastionProtocol,
    returned_host: &str,
    returned_port: u16,
) -> (String, u16, String) {
    fn is_unspecified(h: &str) -> bool {
        let t = h.trim();
        t.is_empty() || t == "0.0.0.0" || t == "::" || t == "[::]" || t == "*"
    }
    let target = if bastion_id.is_empty() {
        None
    } else {
        match make_request(state, Operation::Read, format!("{RUSTION_MOUNT}targets/{bastion_id}"), None).await {
            Ok(r) => r.and_then(|x| x.data),
            Err(e) => {
                log::warn!(
                    "resource-connect: bastion `{bastion_id}` target lookup failed \
                     ({e:?}); will fall back to session/open echo"
                );
                None
            }
        }
    };

    // Protocol's discovered transport pin off the target record. Read
    // once here so every return path carries it alongside host/port.
    let pin = target
        .as_ref()
        .map(|data| {
            let key = match protocol {
                BastionProtocol::Ssh => "ssh_host_key_fingerprint",
                BastionProtocol::Rdp => "rdp_tls_pin_sha256",
            };
            data.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
        })
        .unwrap_or_default();

    // Tier 1: discovered listener-info on the target record.
    if let Some(ref data) = target {
        let (host_key, port_key) = match protocol {
            BastionProtocol::Ssh => ("ssh_listener_host", "ssh_listener_port"),
            BastionProtocol::Rdp => ("rdp_listener_host", "rdp_listener_port"),
        };
        let stored_host = data.get(host_key).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let stored_port = data.get(port_key).and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()).unwrap_or(0);
        if !is_unspecified(&stored_host) && stored_port != 0 {
            log::info!(
                "resource-connect: bastion `{bastion_id}` using stored listener coords \
                 {protocol:?} {stored_host}:{stored_port} (synced_at={})",
                data.get("listeners_synced_at").and_then(|v| v.as_str()).unwrap_or("never")
            );
            return (stored_host, stored_port, pin);
        }
    }

    // Tier 2: the session/open echo, when its host is specified.
    if !is_unspecified(returned_host) {
        return (returned_host.to_string(), returned_port, pin);
    }

    // Tier 3: endpoint-host fallback. The session/open port still wins
    // — it's the SSH/RDP proxy port, distinct from the control-plane
    // port we'd strip off the endpoint.
    if let Some(data) = target {
        let endpoint = data.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let host_only = if endpoint.starts_with('[') {
            endpoint
                .strip_prefix('[')
                .and_then(|s| s.split_once(']'))
                .map(|(h, _)| h.to_string())
                .unwrap_or(endpoint.clone())
        } else if let Some((h, _)) = endpoint.rsplit_once(':') {
            h.to_string()
        } else {
            endpoint.clone()
        };
        if !host_only.is_empty() && !is_unspecified(&host_only) {
            log::info!(
                "resource-connect: bastion `{bastion_id}` advertised dial host \
                 `{returned_host}`; substituting `{host_only}` from target endpoint \
                 (run `rustion_target_refresh_listeners` to discover the canonical host)"
            );
            return (host_only, returned_port, pin);
        }
        log::warn!(
            "resource-connect: bastion `{bastion_id}` endpoint `{endpoint}` yields no \
             usable dial host; keeping `{returned_host}` and the dial will likely fail"
        );
    }
    (returned_host.to_string(), returned_port, pin)
}

#[derive(Debug, Clone, Copy)]
enum BastionProtocol {
    Ssh,
    Rdp,
}

/// Outcome of consulting the Rustion policy resolver before a Connect.
/// Returned by [`resolve_connect_route`].
enum ConnectRoute {
    /// Effective policy is `transport=direct` (or empty) — keep the
    /// existing in-app dial against the resource's host candidates.
    Direct,
    /// Effective policy requires (or prefers, with bastions available)
    /// routing through a Rustion bastion. The session/open call has
    /// already happened; the caller dials `bastion_host:bastion_port`
    /// as user `operator` with `ticket` as the SSH password (or for
    /// RDP, with the ticket in the mstshash routing-token cookie).
    Rustion {
        bastion_host: String,
        bastion_port: u16,
        ticket: String,
        /// Surface in the session window label so the operator sees
        /// which bastion is in the path.
        bastion_name: String,
        /// Lifecycle handle Rustion bound to this session: identifies
        /// the bastion-side slot for renew + kill. Plumbed into
        /// `AppState::rustion_session_bundles` keyed by the local
        /// session token so the spawned window can drive auto-renew.
        bastion_id: String,
        session_id: String,
        correlation_id: String,
        expires_at: String,
        max_renewals: u32,
        /// Protocol transport-identity pin discovered off the target
        /// record: SSH host-key fingerprint (`SHA256:…`) for the SSH
        /// path, TLS leaf digest (`sha256:…`) for RDP. Empty when the
        /// bastion advertised none — the dialler then stays unpinned.
        bastion_pin: String,
    },
}

/// Build the policy resolver hints from a resource record.
///
/// `resource_id` is the resource's name (the policy store keys
/// per-resource overrides by hostname / id). `resource_type` comes
/// from the meta record. Asset-group ids come from the
/// `resource-group/by-resource/<name>` index — that's the same
/// lookup the Resources page uses for its Groups chip, so the
/// resolver sees exactly what the operator sees.
async fn collect_policy_hints(
    state: &State<'_, AppState>,
    resource_name: &str,
    meta: &Map<String, Value>,
) -> (String, String, Vec<String>) {
    let resource_id = resource_name.to_string();
    let resource_type = meta.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut asset_group_ids: Vec<String> = Vec::new();
    let path = format!("resource-group/by-resource/{resource_name}");
    if let Ok(resp) = make_request(state, Operation::Read, path, None).await {
        if let Some(arr) = resp.and_then(|r| r.data).and_then(|d| d.get("groups").cloned()).and_then(|v| match v {
            Value::Array(a) => Some(a),
            _ => None,
        }) {
            for g in arr {
                if let Some(s) = g.as_str() {
                    asset_group_ids.push(s.to_string());
                }
            }
        }
    }
    (resource_id, resource_type, asset_group_ids)
}

/// Resolved policy verdict for the connect path. Mirrors the relevant
/// subset of the server's `EffectivePolicy`. The `Default` (empty
/// transport, no bastions) reads as "no Rustion policy applies" — every
/// route resolver treats that as a plain direct dial.
#[derive(Default)]
struct EffectivePolicyView {
    transport: String,
    bastions: Vec<String>,
    recording: String,
    lock_violation: Option<String>,
}

/// True when a backend error is an HTTP 403 / permission-denied. The
/// remote backend surfaces `"HTTP 403: Permission denied"`; the embedded
/// backend surfaces `RvError::ErrPermissionDenied`'s display. Matches the
/// frontend `isPermissionDenied` classifier so both layers agree.
fn is_permission_denied(e: &CommandError) -> bool {
    let msg = e.message.to_ascii_lowercase();
    msg.contains("403") || msg.contains("permission denied")
}

async fn read_effective_policy(
    state: &State<'_, AppState>,
    resource_id: &str,
    resource_type: &str,
    asset_group_ids: &[String],
) -> Result<EffectivePolicyView, CommandError> {
    let mut body = Map::new();
    if !resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(resource_id.to_string()));
    }
    if !resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(resource_type.to_string()));
    }
    if !asset_group_ids.is_empty() {
        body.insert(
            "asset_group_ids".into(),
            Value::Array(asset_group_ids.iter().cloned().map(Value::String).collect()),
        );
    }
    let resp = match make_request(state, Operation::Write, format!("{RUSTION_MOUNT}policy/effective"), Some(body)).await
    {
        Ok(resp) => resp,
        // A caller who can reach the resource and read its secret but
        // lacks read on the global `rustion/` policy surface — the common
        // read-only share-grantee case — gets a 403 here. The effective
        // policy is only a routing hint: the real boundaries are still
        // enforced server-side (brokering on `rustion/v2/session/open`,
        // the credential read on `resources/secrets/...`). So treat
        // permission-denied as "no Rustion policy is visible to me" and
        // fall through to a direct dial instead of aborting Connect.
        // Other errors (network, 500, lock-violation payloads) still
        // propagate.
        Err(e) if is_permission_denied(&e) => return Ok(EffectivePolicyView::default()),
        Err(e) => return Err(e),
    };
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let transport = data.get("transport").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let bastions = data
        .get("bastions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let recording = data.get("recording").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let lock_violation = data.get("lock_violation").and_then(|v| match v {
        Value::Object(m) => {
            Some(m.get("detail").and_then(|d| d.as_str()).unwrap_or("rustion policy lock violation").to_string())
        }
        _ => None,
    });
    Ok(EffectivePolicyView { transport, bastions, recording, lock_violation })
}

/// Resolved SSH login-class verdict for the connect path. Mirrors the
/// `ssh-broker/policy/effective` response.
struct EffectiveLoginClassView {
    login_class: String,
    login_class_source: String,
    /// Per-tier class contributions, in resolution order (for the
    /// `login_class_chain` audit field).
    login_class_chain: Vec<String>,
    lock_violation: Option<String>,
}

/// Resolve the effective SSH login class (`shared-credential` |
/// `brokered`) for a resource by calling `ssh-broker/policy/effective`.
/// Defaults to `shared-credential` when the broker policy is unset, so a
/// deployment that never configures brokering is unaffected.
async fn read_effective_login_class(
    state: &State<'_, AppState>,
    resource_id: &str,
    resource_type: &str,
    asset_group_ids: &[String],
) -> Result<EffectiveLoginClassView, CommandError> {
    let mut body = Map::new();
    if !resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(resource_id.to_string()));
    }
    if !resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(resource_type.to_string()));
    }
    if !asset_group_ids.is_empty() {
        body.insert(
            "asset_group_ids".into(),
            Value::Array(asset_group_ids.iter().cloned().map(Value::String).collect()),
        );
    }
    // Tolerate a policy-service error (e.g. an upgraded vault that never
    // mounted `ssh-broker/`): default to `shared-credential`. The
    // authoritative brokered control is the server-side *attach-time*
    // guard (resource module, PolicyStore-direct), which a missing mount
    // does not affect — a brokered resource simply can't hold a static
    // SSH credential in the first place, so the direct-path dial has
    // nothing to fall back to.
    let resp = match make_request(state, Operation::Write, "ssh-broker/policy/effective".to_string(), Some(body)).await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!("ssh-broker/policy/effective unavailable ({e:?}); defaulting login_class to shared-credential");
            return Ok(EffectiveLoginClassView {
                login_class: "shared-credential".to_string(),
                login_class_source: "default".to_string(),
                login_class_chain: Vec::new(),
                lock_violation: None,
            });
        }
    };
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let login_class = data.get("login_class").and_then(|v| v.as_str()).unwrap_or("shared-credential").to_string();
    let login_class_source = data.get("login_class_source").and_then(|v| v.as_str()).unwrap_or("default").to_string();
    let login_class_chain = data
        .get("login_class_chain")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let lock_violation = data.get("lock_violation").and_then(|v| match v {
        Value::Object(m) => {
            Some(m.get("detail").and_then(|d| d.as_str()).unwrap_or("ssh login_class lock violation").to_string())
        }
        _ => None,
    });
    Ok(EffectiveLoginClassView { login_class, login_class_source, login_class_chain, lock_violation })
}

/// Decide whether to dial direct or route through Rustion. When the
/// effective policy is `rustion-required` or `rustion-preferred` with
/// a non-empty bastion set, this calls `rustion/session/open` and
/// returns the ticket bundle. The caller substitutes those values
/// into the SSH dial.
///
/// Fail-closed rules:
///   - `transport=rustion-required` with a credential kind the bastion
///     proxy doesn't yet support (anything other than ssh-password)
///     returns an error rather than dialing direct.
///   - A `lock_violation` from the resolver short-circuits before
///     anything is dialed (matches the server's own 403 behaviour on
///     session/open).
#[allow(clippy::too_many_arguments)]
async fn resolve_ssh_connect_route(
    state: &State<'_, AppState>,
    resource_name: &str,
    meta: &Map<String, Value>,
    profile: &Value,
    target_host: &str,
    target_port: u16,
    target_user: &str,
    credential: &SshCredential,
) -> Result<ConnectRoute, CommandError> {
    const BASTION_PROTOCOL: BastionProtocol = BastionProtocol::Ssh;
    let (resource_id, resource_type, asset_group_ids) = collect_policy_hints(state, resource_name, meta).await;
    let effective = read_effective_policy(state, &resource_id, &resource_type, &asset_group_ids).await?;

    if let Some(detail) = effective.lock_violation {
        return Err(CommandError::from(format!("rustion policy lock violation: {detail}")));
    }

    let prefer_rustion = match effective.transport.as_str() {
        "rustion-required" => true,
        "rustion-preferred" => !effective.bastions.is_empty(),
        _ => false,
    };
    if !prefer_rustion {
        return Ok(ConnectRoute::Direct);
    }

    // SSH credentials brokered through the bastion, matching the
    // server-side `session/open` contract (and the rustion-ssh e2e
    // harness):
    //   - ssh-password: material = password bytes
    //   - ssh-key:      material = private-key PEM
    //   - ssh-cert:     material = ephemeral private-key PEM, plus the
    //                   signed OpenSSH certificate text in `credential_cert`
    // The operator's own SSH client only ever presents the one-shot
    // ticket — it never sees the target credential for any kind.
    //
    // An encrypted private key still can't be brokered: there's no
    // passphrase field on the wire, so the bastion couldn't decrypt it.
    // It fails closed under rustion-required to avoid a silent bypass;
    // under rustion-preferred we log + fall back to direct, where the
    // local dialler can prompt/decrypt.
    struct BrokeredCred {
        kind: &'static str,
        /// Base64: password bytes (ssh-password) or private-key PEM
        /// (ssh-key / ssh-cert).
        material_b64: String,
        /// Signed OpenSSH certificate text — ssh-cert only.
        cert: Option<String>,
    }
    let encode = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let cred = match credential {
        SshCredential::Password(p) => {
            BrokeredCred { kind: "ssh-password", material_b64: encode(p.as_bytes()), cert: None }
        }
        SshCredential::PrivateKey { pem, passphrase } => {
            if passphrase.is_some() {
                if effective.transport == "rustion-required" {
                    return Err(CommandError::from(
                        "rustion-required policy: passphrase-protected SSH private keys can't be \
                         brokered through the bastion (no passphrase channel on the wire). Use an \
                         unencrypted key, an SSH certificate, or a password credential. Refusing \
                         to dial direct."
                            .to_string(),
                    ));
                }
                log::warn!(
                    "resource-connect/ssh: rustion-preferred but SSH key is passphrase-protected; \
                     falling back to direct dial"
                );
                return Ok(ConnectRoute::Direct);
            }
            BrokeredCred { kind: "ssh-key", material_b64: encode(pem.as_bytes()), cert: None }
        }
        SshCredential::Cert { pem, cert_openssh } => {
            BrokeredCred { kind: "ssh-cert", material_b64: encode(pem.as_bytes()), cert: Some(cert_openssh.clone()) }
        }
    };

    let ttl_secs = profile.get("ttl_secs").and_then(|v| v.as_u64()).and_then(|n| u32::try_from(n).ok()).unwrap_or(3600);
    let max_renewals =
        profile.get("max_renewals").and_then(|v| v.as_u64()).and_then(|n| u8::try_from(n).ok()).unwrap_or(3);
    let recording = if effective.recording.is_empty() { "always".to_string() } else { effective.recording.clone() };

    let mut body = Map::new();
    body.insert("target_host".into(), Value::String(target_host.to_string()));
    body.insert("target_port".into(), Value::Number(target_port.into()));
    body.insert("target_protocol".into(), Value::String("ssh".to_string()));
    body.insert("credential_kind".into(), Value::String(cred.kind.to_string()));
    body.insert("credential_username".into(), Value::String(target_user.to_string()));
    body.insert("credential_material".into(), Value::String(cred.material_b64));
    if let Some(cert) = cred.cert {
        body.insert("credential_cert".into(), Value::String(cert));
    }
    body.insert("ttl_secs".into(), Value::Number(ttl_secs.into()));
    body.insert("max_renewals".into(), Value::Number(max_renewals.into()));
    body.insert("recording".into(), Value::String(recording));
    if !effective.bastions.is_empty() {
        body.insert("bastions".into(), Value::Array(effective.bastions.iter().cloned().map(Value::String).collect()));
    }
    if !resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(resource_id));
    }
    if !resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(resource_type));
    }
    if !asset_group_ids.is_empty() {
        body.insert("asset_group_ids".into(), Value::Array(asset_group_ids.into_iter().map(Value::String).collect()));
    }
    let resp = make_request(state, Operation::Write, format!("{RUSTION_MOUNT}session/open"), Some(body))
        .await
        .map_err(|e| CommandError::from(format!("rustion session/open failed: {e:?}")))?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    parse_rustion_ticket_bundle(state, data, BASTION_PROTOCOL, max_renewals as u32).await
}

/// Parse the `{session_id, host, port, ticket, …}` bundle returned by
/// `rustion/session/open` (v1) or `rustion/v2/session/open` into a
/// [`ConnectRoute::Rustion`]. Shared by both routes so the dial-coord
/// resolution, validation, and field extraction stay identical.
async fn parse_rustion_ticket_bundle(
    state: &State<'_, AppState>,
    data: Map<String, Value>,
    protocol: BastionProtocol,
    max_renewals: u32,
) -> Result<ConnectRoute, CommandError> {
    let returned_host = data.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let bastion_port = data.get("port").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()).unwrap_or(0);
    let ticket = data.get("ticket").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let bastion_name = data.get("bastion_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let bastion_id = data.get("bastion_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Phase 9.3: prefer the stored listener coords (set at enrolment by
    // `rustion_target_refresh_listeners`) over the session/open echo, and
    // fall back to the target endpoint host when neither is usable.
    let bastion_port_in = bastion_port;
    let (bastion_host, bastion_port, bastion_pin) =
        resolve_bastion_dial_coords(state, &bastion_id, protocol, &returned_host, bastion_port_in).await;
    if bastion_host.is_empty() || bastion_port == 0 || ticket.is_empty() {
        return Err(CommandError::from("rustion session/open returned an incomplete ticket bundle".to_string()));
    }
    let session_id = data.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let correlation_id = data.get("correlation_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let expires_at = data.get("expires_at").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(ConnectRoute::Rustion {
        bastion_host,
        bastion_port,
        ticket,
        bastion_name,
        bastion_id,
        session_id,
        correlation_id,
        expires_at,
        max_renewals,
        bastion_pin,
    })
}

/// Connect-only SSH path: open a Rustion session by sending a credential
/// **reference** (`credential_source`) to `rustion/v2/session/open` so
/// BastionVault resolves and injects the secret server-side. The GUI never
/// reads the secret, so an operator with `connect` (but not `read`) on the
/// resource can still launch a session. Returns [`ConnectRoute::Direct`]
/// when the policy does not route through a bastion — the caller then falls
/// back to the client-side resolution path.
#[allow(clippy::too_many_arguments)]
async fn open_rustion_session_v2_ssh(
    state: &State<'_, AppState>,
    resource_name: &str,
    meta: &Map<String, Value>,
    profile: &Value,
    target_host: &str,
    target_port: u16,
    target_user: &str,
    credential_source: &Value,
) -> Result<ConnectRoute, CommandError> {
    const BASTION_PROTOCOL: BastionProtocol = BastionProtocol::Ssh;
    let (resource_id, resource_type, asset_group_ids) = collect_policy_hints(state, resource_name, meta).await;
    let effective = read_effective_policy(state, &resource_id, &resource_type, &asset_group_ids).await?;

    if let Some(detail) = effective.lock_violation {
        return Err(CommandError::from(format!("rustion policy lock violation: {detail}")));
    }

    let prefer_rustion = match effective.transport.as_str() {
        "rustion-required" => true,
        "rustion-preferred" => !effective.bastions.is_empty(),
        _ => false,
    };
    if !prefer_rustion {
        // Policy didn't select a bastion; the caller resolves the
        // credential client-side and dials direct.
        return Ok(ConnectRoute::Direct);
    }

    let ttl_secs = profile.get("ttl_secs").and_then(|v| v.as_u64()).and_then(|n| u32::try_from(n).ok()).unwrap_or(3600);
    let max_renewals =
        profile.get("max_renewals").and_then(|v| v.as_u64()).and_then(|n| u8::try_from(n).ok()).unwrap_or(3);
    let recording = if effective.recording.is_empty() { "always".to_string() } else { effective.recording.clone() };

    let mut body = Map::new();
    // The reference, not the material — BastionVault resolves it.
    body.insert("resource_name".into(), Value::String(resource_name.to_string()));
    body.insert("credential_source".into(), credential_source.clone());
    body.insert("target_host".into(), Value::String(target_host.to_string()));
    body.insert("target_port".into(), Value::Number(target_port.into()));
    body.insert("target_protocol".into(), Value::String("ssh".to_string()));
    body.insert("credential_kind".into(), Value::String("ssh-password".to_string()));
    // May be empty; the server fills it from the secret's `username` field.
    body.insert("credential_username".into(), Value::String(target_user.to_string()));
    body.insert("ttl_secs".into(), Value::Number(ttl_secs.into()));
    body.insert("max_renewals".into(), Value::Number(max_renewals.into()));
    body.insert("recording".into(), Value::String(recording));
    if !effective.bastions.is_empty() {
        body.insert("bastions".into(), Value::Array(effective.bastions.iter().cloned().map(Value::String).collect()));
    }
    if !resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(resource_id));
    }
    if !resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(resource_type));
    }
    if !asset_group_ids.is_empty() {
        body.insert("asset_group_ids".into(), Value::Array(asset_group_ids.into_iter().map(Value::String).collect()));
    }

    let resp = make_request(state, Operation::Write, format!("{RUSTION_MOUNT}v2/session/open"), Some(body))
        .await
        .map_err(|e| CommandError::from(format!("rustion v2 session/open failed: {e:?}")))?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    parse_rustion_ticket_bundle(state, data, BASTION_PROTOCOL, max_renewals as u32).await
}

/// RDP analogue of [`resolve_ssh_connect_route`]. Same shape; differs in:
///   - `target_protocol` is `rdp` on the rustion envelope;
///   - `rdp-password` sends the password as `credential_material`;
///   - `rdp-cert` (smart-card) sends the certificate DER as
///     `credential_material` plus the DER private key + PIN as
///     `credential_key` / `credential_pin`. The bastion drives the
///     upstream Kerberos PKINIT / SPNEGO CredSSP exchange with the
///     smart-card identity (Rustion `bv_credssp_kerberos`, sspi-backed).
#[allow(clippy::too_many_arguments)]
async fn resolve_rdp_connect_route(
    state: &State<'_, AppState>,
    resource_name: &str,
    meta: &Map<String, Value>,
    profile: &Value,
    target_host: &str,
    target_port: u16,
    target_user: &str,
    credential: &session::rdp::RdpCredential,
) -> Result<ConnectRoute, CommandError> {
    const BASTION_PROTOCOL: BastionProtocol = BastionProtocol::Rdp;
    let (resource_id, resource_type, asset_group_ids) = collect_policy_hints(state, resource_name, meta).await;
    let effective = read_effective_policy(state, &resource_id, &resource_type, &asset_group_ids).await?;

    if let Some(detail) = effective.lock_violation {
        return Err(CommandError::from(format!("rustion policy lock violation: {detail}")));
    }

    let prefer_rustion = match effective.transport.as_str() {
        "rustion-required" => true,
        "rustion-preferred" => !effective.bastions.is_empty(),
        _ => false,
    };
    if !prefer_rustion {
        return Ok(ConnectRoute::Direct);
    }

    // Both rdp-password and rdp-cert (smart-card) route through the
    // bastion. For rdp-password the bastion drives upstream NLA via
    // NTLMv2 (`bv_credssp`); for rdp-cert it drives Kerberos PKINIT /
    // SPNEGO CredSSP with the operator's smart-card identity
    // (`bv_credssp_kerberos`, sspi-backed). The operator's own RDP
    // client only ever presents the one-shot ticket — it never sees the
    // target credential either way.
    struct BrokeredCred {
        kind: &'static str,
        /// Base64: password bytes (rdp-password) or certificate DER
        /// (rdp-cert).
        material_b64: String,
        /// Base64 DER private key — rdp-cert only.
        key_b64: Option<String>,
        /// Smart-card PIN — rdp-cert only.
        pin: Option<String>,
    }
    let cred = match credential {
        session::rdp::RdpCredential::Password(p) => BrokeredCred {
            kind: "rdp-password",
            material_b64: base64::engine::general_purpose::STANDARD.encode(p.as_bytes()),
            key_b64: None,
            pin: None,
        },
        session::rdp::RdpCredential::SmartCard(sc) => BrokeredCred {
            kind: "rdp-cert",
            material_b64: base64::engine::general_purpose::STANDARD.encode(&sc.certificate_der),
            key_b64: Some(base64::engine::general_purpose::STANDARD.encode(&sc.private_key_der)),
            pin: Some(sc.pin.clone()),
        },
    };

    let ttl_secs = profile.get("ttl_secs").and_then(|v| v.as_u64()).and_then(|n| u32::try_from(n).ok()).unwrap_or(3600);
    let max_renewals =
        profile.get("max_renewals").and_then(|v| v.as_u64()).and_then(|n| u8::try_from(n).ok()).unwrap_or(3);
    let recording = if effective.recording.is_empty() { "always".to_string() } else { effective.recording.clone() };

    let mut body = Map::new();
    body.insert("target_host".into(), Value::String(target_host.to_string()));
    body.insert("target_port".into(), Value::Number(target_port.into()));
    body.insert("target_protocol".into(), Value::String("rdp".to_string()));
    body.insert("credential_kind".into(), Value::String(cred.kind.to_string()));
    body.insert("credential_username".into(), Value::String(target_user.to_string()));
    body.insert("credential_material".into(), Value::String(cred.material_b64));
    if let Some(key_b64) = cred.key_b64 {
        body.insert("credential_key".into(), Value::String(key_b64));
    }
    if let Some(pin) = cred.pin {
        body.insert("credential_pin".into(), Value::String(pin));
    }
    body.insert("ttl_secs".into(), Value::Number(ttl_secs.into()));
    body.insert("max_renewals".into(), Value::Number(max_renewals.into()));
    body.insert("recording".into(), Value::String(recording));
    if !effective.bastions.is_empty() {
        body.insert("bastions".into(), Value::Array(effective.bastions.iter().cloned().map(Value::String).collect()));
    }
    if !resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(resource_id));
    }
    if !resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(resource_type));
    }
    if !asset_group_ids.is_empty() {
        body.insert("asset_group_ids".into(), Value::Array(asset_group_ids.into_iter().map(Value::String).collect()));
    }
    let resp = make_request(state, Operation::Write, format!("{RUSTION_MOUNT}session/open"), Some(body))
        .await
        .map_err(|e| CommandError::from(format!("rustion session/open failed: {e:?}")))?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    parse_rustion_ticket_bundle(state, data, BASTION_PROTOCOL, max_renewals as u32).await
}

async fn read_resource_meta(state: &State<'_, AppState>, name: &str) -> Result<Map<String, Value>, CommandError> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");
    let resp = make_request(state, Operation::Read, path, None).await?;
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

fn find_profile(meta: &Map<String, Value>, profile_id: &str) -> Option<Value> {
    meta.get("connection_profiles")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|p| p.get("id").and_then(|i| i.as_str()) == Some(profile_id)).cloned())
}

/// Ordered list of host candidates to try when opening a session.
///
/// Preference order:
///   1. Profile `target_host` override (operator-set; trumps everything).
///   2. Resource `ip_address` (avoids DNS, fastest path).
///   3. Resource `hostname` (DNS fallback).
///
/// Duplicates are dropped so a profile that pins `target_host` to
/// the same value as the resource's IP doesn't double-try.
fn profile_host_candidates(profile: &Value, meta: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        if !s.is_empty() && !out.iter().any(|h| h == s) {
            out.push(s.to_string());
        }
    };
    if let Some(s) = profile.get("target_host").and_then(|v| v.as_str()) {
        push(s);
    }
    if let Some(s) = meta.get("ip_address").and_then(|v| v.as_str()) {
        push(s);
    }
    if let Some(s) = meta.get("hostname").and_then(|v| v.as_str()) {
        push(s);
    }
    out
}

/// Heuristic: did the open fail at the network layer (DNS / TCP / TLS)
/// rather than at auth / protocol layer? Only network failures justify
/// falling back to the next host candidate — re-trying after an auth
/// rejection would just lock the account on the next host.
fn is_connect_layer_error(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.starts_with("connect ")
        || e.contains("tcp connect")
        || e.contains("parse/resolve")
        || e.contains("dns lookup")
        || e.contains("tls upgrade")
        || e.contains("connect_begin")
}

fn profile_port(profile: &Value) -> u16 {
    profile.get("target_port").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()).unwrap_or(22)
}

fn profile_username(profile: &Value) -> String {
    profile.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// What the SSH engine minted for a brokered session. Populated only by
/// the `ssh-engine` resolvers; used to stamp `ssh_engine_mode` +
/// `cert_serial` on the direct-path `session.open` audit line so a
/// session and the `ssh/sign` issuance row that authorized it are
/// joinable.
#[derive(Default, Clone)]
struct EngineMint {
    /// `ca` | `otp` (the brokered mode used).
    mode: String,
    /// Hex serial of the minted cert (`ca` mode only).
    cert_serial: Option<String>,
}

struct ResolvedSshCredential {
    credential: SshCredential,
    /// When the resolver knows the canonical username (e.g.
    /// LDAP static-role / library check-out returns one), the
    /// caller swaps it in over the profile's username.
    effective_username: Option<String>,
    /// LDAP library check-out registers a cleanup hook here so
    /// `session_close` can return the account to the pool.
    on_close: Option<crate::session::SessionCleanup>,
    /// Set by the `ssh-engine` resolvers (brokered minting); `None` for
    /// static / ldap / pki sources.
    engine_mint: Option<EngineMint>,
}

async fn resolve_ssh_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
    meta: &Map<String, Value>,
    operator_credential: Option<&OperatorCredential>,
) -> Result<(ResolvedSshCredential, EffectiveLoginClassView), CommandError> {
    let cs = profile
        .get("credential_source")
        .ok_or_else(|| CommandError::from("profile is missing credential_source".to_string()))?;
    let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");

    // Brokered login-class enforcement (direct path). If the resource
    // resolves to `brokered`, every SSH login must be minted per-connect
    // from the SSH engine; a `secret` (or any non-ssh-engine) source is
    // rejected fail-closed — never silently downgraded.
    let (rid, rtype, ags) = collect_policy_hints(state, resource_name, meta).await;
    let lc = read_effective_login_class(state, &rid, &rtype, &ags).await?;
    if lc.login_class == "brokered" {
        if let Some(detail) = lc.lock_violation.as_ref() {
            return Err(CommandError::from(format!("login_class_locked: {detail}")));
        }
        // `default-account` is itself a brokered SSH-engine mint (it only swaps
        // the role's principal for the connecting operator's default account),
        // so it satisfies the brokered requirement alongside `ssh-engine`.
        if kind != "ssh-engine" && kind != "default-account" {
            return Err(CommandError::from(format!(
                "brokered_requires_ssh_engine: resource `{resource_name}` is brokered \
                 (login_class via tier `{}`); its connection profile must use an \
                 `ssh-engine` (or `default-account`) credential source, not `{}`. Every \
                 SSH login to a brokered resource is minted per-connect from the SSH engine.",
                lc.login_class_source,
                if kind.is_empty() { "(unset)" } else { kind }
            )));
        }
    }

    let resolved = match kind {
        "secret" => resolve_secret_ssh(state, resource_name, cs).await,
        "ldap" => resolve_ldap_ssh(state, cs, operator_credential).await,
        "pki" => resolve_pki_ssh(state, resource_name, cs).await,
        "ssh-engine" => resolve_ssh_engine_ssh(state, profile, meta, cs).await,
        "default-account" => resolve_default_account_ssh(state, profile, meta, cs).await,
        other => Err(CommandError::from(format!("unknown credential source `{other}`"))),
    }?;
    Ok((resolved, lc))
}

/// The connecting operator's default resource accounts, fetched from
/// `sys/identity/default-account/self`. The endpoint resolves the principal
/// from the request token server-side, so the GUI can never claim another
/// operator's account. Empty fields mean "unconfigured".
struct SelfDefaultAccounts {
    linux: String,
    macos: String,
    windows: String,
    /// Optional stored Windows RDP password (the caller's own — revealed only on
    /// the caller-scoped `self` path). Empty ⇒ prompt for it at connect.
    windows_password: String,
}

async fn fetch_self_default_accounts(state: &State<'_, AppState>) -> Result<SelfDefaultAccounts, CommandError> {
    let resp = make_request(state, Operation::Read, "sys/identity/default-account/self".to_string(), None).await?;
    let data: HashMap<String, Value> = resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
    let field = |k: &str| data.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    Ok(SelfDefaultAccounts {
        linux: field("linux"),
        macos: field("macos"),
        windows: field("windows"),
        // Passwords are not trimmed — they may legitimately contain whitespace.
        windows_password: data.get("windows_password").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    })
}

/// Resolve the connecting operator's default login name for a target OS family.
/// `os_type` is the resource's structured OS (`linux` / `macos` / `windows` /
/// `bsd` / `unix` / unset); BSD/Unix/unknown fall back to the Linux account.
/// Fails closed with an operator-facing message when no account is set for that
/// family — never silently substitutes a profile username.
async fn resolve_default_account(state: &State<'_, AppState>, os_type: &str) -> Result<String, CommandError> {
    let accounts = fetch_self_default_accounts(state).await?;
    let account = match os_type {
        "windows" => accounts.windows,
        "macos" => accounts.macos,
        _ => accounts.linux,
    };
    if account.is_empty() {
        let family = match os_type {
            "windows" => "Windows",
            "macos" => "macOS",
            _ => "Linux",
        };
        return Err(CommandError::from(format!(
            "default-account credential source: the connecting user has no default {family} \
             account configured. Set it under Users → Edit User → Default Resource Account."
        )));
    }
    Ok(account)
}

/// Read the resource's structured OS family for default-account resolution.
fn resource_os_type(meta: &Map<String, Value>) -> String {
    meta.get("os_type").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Resolve a `default-account` SSH source: brokers a credential from the SSH
/// engine exactly like `ssh-engine`, but the login principal is the connecting
/// operator's default account for the resource's OS rather than a profile
/// username. The `credential_source` carries the same `ssh_mount` / `ssh_role`
/// / `mode` fields as `ssh-engine`.
async fn resolve_default_account_ssh(
    state: &State<'_, AppState>,
    profile: &Value,
    meta: &Map<String, Value>,
    cs: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
    let account = resolve_default_account(state, &resource_os_type(meta)).await?;

    // Inject the resolved account as the profile username so the ssh-engine
    // resolver mints the cert (`valid_principals`) / OTP for the right login.
    let mut patched = profile.clone();
    if let Some(obj) = patched.as_object_mut() {
        obj.insert("username".to_string(), Value::String(account.clone()));
    }
    let mut resolved = resolve_ssh_engine_ssh(state, &patched, meta, cs).await?;
    // Force the dial username to the resolved account: CA mode returns
    // `effective_username = None` (the role enforces principals), but for the
    // default-account source the operator's account *is* the login user.
    resolved.effective_username = Some(account);
    Ok(resolved)
}

/// Resolve an `ssh-engine` source. Two working modes today:
///
/// - `ca`: generate a fresh Ed25519 keypair in-process, ask the bound
///   SSH engine to sign the public half via `<mount>sign/<role>`, and
///   present `(key, cert)` to russh via `authenticate_openssh_cert`.
///   The target's `sshd` must trust the BV CA pubkey via
///   `TrustedUserCAKeys`. Both halves of the credential are ephemeral
///   to this session and zeroized on drop.
/// - `otp`: mint a one-time password via `<mount>creds/<role>` with
///   the resolved target IP + username, present it to russh as a
///   password. The target host must run `bv-ssh-helper` for the OTP
///   to validate at PAM time. Caller-supplied `username` overrides
///   the role's `default_user`.
///
/// `pqc` mode is rejected at this layer — russh's `ssh-key` dep does
/// not yet support `ssh-mldsa65@openssh.com` cert auth, so we can't
/// hand the protocol library a credential it knows how to use. The
/// SSH engine still mints PQC certs for out-of-app consumers.
async fn resolve_ssh_engine_ssh(
    state: &State<'_, AppState>,
    profile: &Value,
    meta: &Map<String, Value>,
    cs: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
    let ssh_mount = ssh_engine_mount_prefix(cs)?;
    let ssh_role = cs
        .get("ssh_role")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::from("credential_source.ssh_role is required"))?
        .to_string();
    let mode = cs.get("mode").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("ca");

    match mode {
        "ca" => sign_ssh_engine_ca(state, &ssh_mount, &ssh_role, profile).await,
        "otp" => mint_ssh_engine_otp(state, &ssh_mount, &ssh_role, profile, meta).await,
        "pqc" => Err(CommandError::from(
            "ssh-engine pqc mode is not supported by the in-app SSH client today \
             (russh's ssh-key dep does not yet implement ssh-mldsa65@openssh.com \
             cert auth); use a PQC-aware standalone client against ssh/sign/<role>"
                .to_string(),
        )),
        other => Err(CommandError::from(format!("credential_source.mode `{other}` is not one of ca | otp | pqc"))),
    }
}

fn ssh_engine_mount_prefix(cs: &Value) -> Result<String, CommandError> {
    let raw = cs
        .get("ssh_mount")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| CommandError::from("credential_source.ssh_mount is required"))?;
    if raw.is_empty() {
        return Err(CommandError::from("credential_source.ssh_mount must not be empty".to_string()));
    }
    Ok(format!("{}/", raw.trim_end_matches('/')))
}

async fn sign_ssh_engine_ca(
    state: &State<'_, AppState>,
    ssh_mount: &str,
    ssh_role: &str,
    profile: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
    use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};

    // Ephemeral Ed25519 keypair — never persisted; lives in
    // memory for the duration of the session and zeroizes on drop
    // via Zeroizing<String> wrappers below. ssh-key's `PrivateKey::random`
    // wants a `rand_core::CryptoRng` 0.10; the gui otherwise uses rand
    // 0.9, so we pull `rand_v10` solely for this call site.
    let private_key = PrivateKey::random(&mut rand_v10::rng(), Algorithm::Ed25519)
        .map_err(|e| CommandError::from(format!("generate ephemeral ssh keypair: {e}")))?;
    let public_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| CommandError::from(format!("serialize ephemeral pubkey: {e}")))?;
    let private_openssh = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| CommandError::from(format!("serialize ephemeral private key: {e}")))?;

    // Ask the SSH engine to sign it. We don't override the role's
    // ttl / extensions — operators tune those on the role itself.
    // `valid_principals` is left to the role's `default_user`.
    let mut body = Map::new();
    body.insert("public_key".into(), Value::String(public_openssh));
    if let Some(user) = profile.get("username").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        body.insert("valid_principals".into(), Value::String(user.to_string()));
    }

    let path = format!("{ssh_mount}sign/{ssh_role}");
    let resp = make_request(state, Operation::Write, path, Some(body)).await?;
    let data: HashMap<String, Value> = resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
    let signed_key = data
        .get("signed_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::from(format!("ssh/{ssh_role} sign response missing `signed_key`")))?
        .to_string();
    // Capture the cert serial so the session can be joined to the
    // `ssh/sign` issuance audit row.
    let cert_serial = data.get("serial_number").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from);

    Ok(ResolvedSshCredential {
        credential: SshCredential::Cert { pem: Zeroizing::new(private_openssh.to_string()), cert_openssh: signed_key },
        // CA-mode roles enforce `valid_principals` themselves; don't
        // second-guess the profile's username here.
        effective_username: None,
        on_close: None,
        engine_mint: Some(EngineMint { mode: "ca".into(), cert_serial }),
    })
}

async fn mint_ssh_engine_otp(
    state: &State<'_, AppState>,
    ssh_mount: &str,
    ssh_role: &str,
    profile: &Value,
    meta: &Map<String, Value>,
) -> Result<ResolvedSshCredential, CommandError> {
    // The OTP record is keyed on the target IP — the helper on the
    // target host validates `(otp, ip)` against the vault, so the IP
    // we mint with must match the IP the operator will actually
    // connect to. Prefer the profile override, then the resource's
    // ip_address. Hostnames are not accepted: the SSH engine
    // requires a parseable IpAddr at mint time.
    let target_ip = profile
        .get("target_host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| meta.get("ip_address").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
        .ok_or_else(|| {
            CommandError::from(
                "ssh-engine OTP mode needs an IP — set the resource's ip_address \
                 (or override target_host on the profile with an IP literal)"
                    .to_string(),
            )
        })?
        .to_string();
    // Reject hostnames up front with a clear message rather than
    // letting the engine bounce a vague parse error back.
    if target_ip.parse::<std::net::IpAddr>().is_err() {
        return Err(CommandError::from(format!(
            "ssh-engine OTP target `{target_ip}` is not an IP literal; OTP mode \
             matches against the role's cidr_list and requires a numeric address"
        )));
    }

    let mut body = Map::new();
    body.insert("ip".into(), Value::String(target_ip));
    if let Some(user) = profile.get("username").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        body.insert("username".into(), Value::String(user.to_string()));
    }

    let path = format!("{ssh_mount}creds/{ssh_role}");
    let resp = make_request(state, Operation::Write, path, Some(body)).await?;
    let data: HashMap<String, Value> = resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
    let otp = data
        .get("key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::from(format!("ssh/{ssh_role} creds response missing `key`")))?
        .to_string();
    let effective_username = data.get("username").and_then(|v| v.as_str()).map(String::from).filter(|s| !s.is_empty());

    Ok(ResolvedSshCredential {
        credential: SshCredential::Password(Zeroizing::new(otp)),
        effective_username,
        on_close: None,
        engine_mint: Some(EngineMint { mode: "otp".into(), cert_serial: None }),
    })
}

/// Resolve a PKI-source profile for SSH: call `pki/issue/<role>`
/// against the bound PKI mount with the resource hostname as the
/// requested CN, then feed the returned `private_key` PEM to
/// russh as a publickey credential. The cert itself is delivered
/// alongside (operators using x509-cert-auth servers like Tectia
/// drop it on the host; everyone else relies on the public key
/// being in `authorized_keys`).
///
/// The cert is **short-lived** by virtue of the PKI role's
/// `max_ttl` — operators get the lifecycle benefit (auto-rotation
/// per session) even when the SSH server treats the credential
/// as a plain key.
async fn resolve_pki_ssh(
    state: &State<'_, AppState>,
    resource_name: &str,
    cs: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
    let issued = issue_pki_credential(state, resource_name, cs).await?;
    Ok(ResolvedSshCredential {
        credential: SshCredential::PrivateKey { pem: Zeroizing::new(issued.private_key), passphrase: None },
        // Don't override the profile.username — the PKI cert's CN
        // is the hostname, not the OS user the operator wants to
        // log in as. Profile.username stays authoritative.
        effective_username: None,
        on_close: None,
        engine_mint: None,
    })
}

/// Pulled out so the SSH and RDP paths share the issue-call
/// shape. `certificate` / `issuing_ca` / `serial_number` are kept
/// alongside `private_key` so the future RDP CredSSP smartcard
/// path can wrap them as a synthetic PIV credential without
/// re-issuing.
#[allow(dead_code)]
struct PkiIssued {
    certificate: String,
    private_key: String,
    issuing_ca: String,
    serial_number: String,
}

async fn issue_pki_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    cs: &Value,
) -> Result<PkiIssued, CommandError> {
    let pki_mount = pki_mount_prefix(cs)?;
    let pki_role = cs
        .get("pki_role")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::from("credential_source.pki_role is required"))?;
    // Default CN: the resource's hostname (or ip_address fallback).
    // Operators with non-DNS subjects can override via the role's
    // CSR / template.
    let meta = read_resource_meta(state, resource_name).await?;
    let cn = meta
        .get("hostname")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| meta.get("ip_address").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
        .map(String::from)
        .unwrap_or_else(|| resource_name.to_string());

    let mut body = Map::new();
    body.insert("common_name".into(), Value::String(cn));
    if let Some(alt) = cs.get("alt_names").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        body.insert("alt_names".into(), Value::String(alt.to_string()));
    }
    if let Some(ttl) = cs.get("cert_ttl_secs").and_then(|v| v.as_u64()).filter(|n| *n > 0) {
        body.insert("ttl".into(), Value::String(format!("{ttl}s")));
    }

    let path = format!("{pki_mount}issue/{pki_role}");
    let resp = make_request(state, Operation::Write, path, Some(body)).await?;
    let data: HashMap<String, Value> = resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
    let private_key = data
        .get("private_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from(format!("pki/{pki_role} issue response missing `private_key`")))?
        .to_string();
    let certificate = data
        .get("certificate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from(format!("pki/{pki_role} issue response missing `certificate`")))?
        .to_string();
    let issuing_ca = data.get("issuing_ca").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
    let serial_number = data.get("serial_number").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
    Ok(PkiIssued { certificate, private_key, issuing_ca, serial_number })
}

/// Decode a PEM block into the underlying DER bytes. We don't
/// pull in a full PEM crate for this; the format is trivial and
/// we already control both producers (the in-tree PKI engine).
/// Returns `Err` if the expected `BEGIN <label>` marker isn't
/// found or the base64 body fails to decode.
fn pem_body_to_der(pem: &str, label: &str) -> Result<Vec<u8>, CommandError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).ok_or_else(|| CommandError::from(format!("pem: missing `{begin}`")))? + begin.len();
    let stop = pem.find(&end).ok_or_else(|| CommandError::from(format!("pem: missing `{end}`")))?;
    if stop <= start {
        return Err(CommandError::from(format!("pem: malformed `{label}`")));
    }
    let body: String = pem[start..stop].chars().filter(|c| !c.is_ascii_whitespace()).collect();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(body.as_bytes()).map_err(|e| CommandError::from(format!("pem: base64 decode `{label}`: {e}")))
}

fn pki_mount_prefix(cs: &Value) -> Result<String, CommandError> {
    let raw = cs
        .get("pki_mount")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| CommandError::from("credential_source.pki_mount is required"))?;
    if raw.is_empty() {
        return Err(CommandError::from("credential_source.pki_mount must not be empty".to_string()));
    }
    let trimmed = raw.trim_end_matches('/');
    Ok(format!("{trimmed}/"))
}

async fn resolve_secret_ssh(
    state: &State<'_, AppState>,
    resource_name: &str,
    cs: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
    let secret_id = cs
        .get("secret_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from("credential_source.secret_id is required"))?;
    let path = format!("{RESOURCE_MOUNT}secrets/{resource_name}/{secret_id}");
    let resp = make_request(state, Operation::Read, path, None).await?;
    let data: HashMap<String, Value> = resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();

    let private_key = data.get("private_key").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
    let passphrase = data.get("passphrase").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
    let password = data.get("password").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();

    let credential = if !private_key.is_empty() {
        SshCredential::PrivateKey {
            pem: Zeroizing::new(private_key),
            passphrase: if passphrase.is_empty() { None } else { Some(Zeroizing::new(passphrase)) },
        }
    } else if !password.is_empty() {
        SshCredential::Password(Zeroizing::new(password))
    } else {
        return Err(CommandError::from(format!(
            "secret `{secret_id}` carries no `password` or `private_key` field — Connect can't authenticate"
        )));
    };
    Ok(ResolvedSshCredential {
        credential,
        effective_username: data.get("username").and_then(|v| v.as_str()).map(String::from).filter(|s| !s.is_empty()),
        on_close: None,
        engine_mint: None,
    })
}

/// Resolve an LDAP-source profile to an SSH-shaped credential.
///
/// Three sub-modes:
///   - `operator` — operator types user+password into a frontend
///     prompt; we forward verbatim. (We don't run an extra
///     simple-bind validation here; the SSH server itself will
///     bounce bad creds back to the operator.)
///   - `static_role` — internal request to the bound LDAP mount's
///     `/static-cred/<role>` endpoint pulls the vault-managed
///     username + password.
///   - `library_set` — internal request to
///     `/library/<set>/check-out`; we register a session-close
///     hook that calls `/library/<set>/check-in` with the
///     captured `lease_id`.
async fn resolve_ldap_ssh(
    state: &State<'_, AppState>,
    cs: &Value,
    operator_credential: Option<&OperatorCredential>,
) -> Result<ResolvedSshCredential, CommandError> {
    let ldap_mount = ldap_mount_prefix(cs)?;
    let bind_mode = cs.get("bind_mode").and_then(|v| v.as_str()).unwrap_or("operator");
    match bind_mode {
        "operator" => {
            let oc = operator_credential.ok_or_else(|| {
                CommandError::from(
                    "ldap bind_mode = operator requires operator_credential on the open request".to_string(),
                )
            })?;
            if oc.username.is_empty() || oc.password.is_empty() {
                return Err(CommandError::from(
                    "operator-supplied LDAP credential must carry both username and password".to_string(),
                ));
            }
            // We don't run an extra LDAP simple-bind validation
            // here — adding one would double the round-trip on
            // every connect and the SSH server validates these
            // against AD anyway. If operator demand calls for an
            // explicit pre-flight, it's a one-line addition that
            // hits the existing `ldap/check-connection` style
            // path on the bound mount.
            let _ = ldap_mount;
            Ok(ResolvedSshCredential {
                credential: SshCredential::Password(Zeroizing::new(oc.password.clone())),
                effective_username: Some(oc.username.clone()),
                on_close: None,
                engine_mint: None,
            })
        }
        "static_role" => {
            let role = cs.get("static_role").and_then(|v| v.as_str()).ok_or_else(|| {
                CommandError::from("ldap bind_mode = static_role requires credential_source.static_role".to_string())
            })?;
            let path = format!("{ldap_mount}static-cred/{role}");
            let resp = make_request(state, Operation::Read, path, None).await?;
            let data: HashMap<String, Value> =
                resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
            let username = data
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::from(format!("ldap static-cred/{role} missing `username`")))?
                .to_string();
            let password = data
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::from(format!("ldap static-cred/{role} missing `password`")))?
                .to_string();
            Ok(ResolvedSshCredential {
                credential: SshCredential::Password(Zeroizing::new(password)),
                effective_username: Some(username),
                on_close: None,
                engine_mint: None,
            })
        }
        "library_set" => {
            let set = cs.get("library_set").and_then(|v| v.as_str()).ok_or_else(|| {
                CommandError::from("ldap bind_mode = library_set requires credential_source.library_set".to_string())
            })?;
            let path = format!("{ldap_mount}library/{set}/check-out");
            let resp = make_request(state, Operation::Write, path, None).await?;
            let data: HashMap<String, Value> =
                resp.and_then(|r| r.data).map(|m| m.into_iter().collect()).unwrap_or_default();
            let username = data
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::from(format!("ldap library/{set}/check-out missing `username`")))?
                .to_string();
            let password = data
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::from(format!("ldap library/{set}/check-out missing `password`")))?
                .to_string();
            let lease_id = data
                .get("lease_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::from(format!("ldap library/{set}/check-out missing `lease_id`")))?
                .to_string();
            Ok(ResolvedSshCredential {
                credential: SshCredential::Password(Zeroizing::new(password)),
                effective_username: Some(username),
                on_close: Some(crate::session::SessionCleanup {
                    kind: crate::session::SessionCleanupKind::LdapLibraryCheckIn {
                        ldap_mount: ldap_mount.trim_end_matches('/').to_string(),
                        library_set: set.to_string(),
                        lease_id,
                    },
                }),
                engine_mint: None,
            })
        }
        other => Err(CommandError::from(format!(
            "unknown ldap bind_mode `{other}` (expected operator / static_role / library_set)"
        ))),
    }
}

/// Mount-path prefix for an LDAP credential source. Always ends
/// with `/`. The profile field is operator-typed, so we trim
/// stray whitespace and ensure exactly one trailing slash.
fn ldap_mount_prefix(cs: &Value) -> Result<String, CommandError> {
    let raw = cs
        .get("ldap_mount")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| CommandError::from("credential_source.ldap_mount is required"))?;
    if raw.is_empty() {
        return Err(CommandError::from("credential_source.ldap_mount must not be empty".to_string()));
    }
    let trimmed = raw.trim_end_matches('/');
    Ok(format!("{trimmed}/"))
}

// ── Recently-connected list (Phase 7) ──────────────────────────────

/// Cap on the persisted recently-connected list. Keeps the
/// resource record bounded — every operator who clicks Connect
/// appends one entry, so without a cap a long-lived production
/// host's metadata would grow without bound.
const RECENT_SESSIONS_CAP: usize = 10;

#[derive(Copy, Clone)]
enum SessionProtocolTag {
    Ssh,
    Rdp,
}

impl SessionProtocolTag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
        }
    }
}

/// Append a recently-connected entry on the resource's metadata
/// record. Best-effort: a failed write logs at WARN and is
/// otherwise swallowed — losing a recently-connected entry is
/// far less bad than failing the actual session-open after the
/// transport is already up.
async fn record_recent_session(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
    protocol: SessionProtocolTag,
) -> Result<(), CommandError> {
    let mut meta = read_resource_meta(state, resource_name).await?;
    let mut recent: Vec<Value> = meta.get("recent_sessions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let actor = caller_display(state).await;
    let entry = serde_json::json!({
        "ts": now_rfc3339(),
        "profile_id": profile.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        "profile_name": profile.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        "actor": actor,
        "protocol": protocol.as_str(),
    });
    recent.insert(0, entry); // newest first
    if recent.len() > RECENT_SESSIONS_CAP {
        recent.truncate(RECENT_SESSIONS_CAP);
    }
    meta.insert("recent_sessions".into(), Value::Array(recent));
    let path = format!("{RESOURCE_MOUNT}resources/{resource_name}");
    let _ = make_request(state, Operation::Write, path, Some(meta)).await.map_err(|e| {
        log::warn!("resource-connect: record_recent_session for `{resource_name}` failed: {e:?}");
        e
    });
    Ok(())
}

fn now_rfc3339() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let tm = libc_time_breakdown(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", tm.year, tm.mon, tm.mday, tm.hour, tm.minute, tm.second)
}

struct BrokenDownTime {
    year: i32,
    mon: u32,
    mday: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

/// Tiny gmtime breakdown so we don't pull `time` / `chrono` for
/// one timestamp formatter. Good enough for the year range we
/// care about (1970..2099). Mirrors the same approach the
/// resource module uses in its history-log path.
fn libc_time_breakdown(unix: i64) -> BrokenDownTime {
    let mut secs = unix.max(0) as u64;
    let second = (secs % 60) as u32;
    secs /= 60;
    let minute = (secs % 60) as u32;
    secs /= 60;
    let hour = (secs % 24) as u32;
    let mut days = secs / 24;
    let mut year = 1970i32;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = [31u64, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 1u32;
    for &dm in &months {
        if days < dm {
            break;
        }
        days -= dm;
        mon += 1;
    }
    BrokenDownTime { year, mon, mday: days as u32 + 1, hour, minute, second }
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

async fn caller_display(state: &State<'_, AppState>) -> String {
    match make_request(state, Operation::Read, "auth/token/lookup-self".to_string(), None).await {
        Ok(Some(resp)) => {
            let data = resp.data.unwrap_or_default();
            data.get("display_name")
                .and_then(|v| v.as_str())
                .or_else(|| data.get("entity_id").and_then(|v| v.as_str()))
                .or_else(|| data.get("id").and_then(|v| v.as_str()))
                .unwrap_or("unknown")
                .to_string()
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_matches_remote_and_embedded_shapes() {
        // Remote backend (RemoteBackend → HTTP).
        assert!(is_permission_denied(&CommandError::from("HTTP 403: Permission denied")));
        // Embedded backend (RvError::ErrPermissionDenied display).
        assert!(is_permission_denied(&CommandError::from("permission denied")));
        // Case-insensitive.
        assert!(is_permission_denied(&CommandError::from("Permission Denied")));
    }

    #[test]
    fn permission_denied_ignores_unrelated_errors() {
        assert!(!is_permission_denied(&CommandError::from("HTTP 500: internal error")));
        assert!(!is_permission_denied(&CommandError::from("node `h` is unavailable: reset")));
        assert!(!is_permission_denied(&CommandError::from("404 not found")));
    }

    #[test]
    fn effective_policy_default_reads_as_direct() {
        // The fall-through value returned when the caller can't read the
        // rustion policy surface must route as a plain direct dial: empty
        // transport (→ `prefer_rustion` is false at every resolver), no
        // bastions, and no spurious lock violation.
        let v = EffectivePolicyView::default();
        assert!(v.transport.is_empty());
        assert!(v.bastions.is_empty());
        assert!(v.recording.is_empty());
        assert!(v.lock_violation.is_none());
    }
}
