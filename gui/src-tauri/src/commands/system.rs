use bv_client::Operation;
use serde::Serialize;
use serde_json::Value;
use tauri::State;

use crate::embedded;
use crate::error::{CmdResult, CommandError};
use crate::state::{AppState, RemoteProfile};

#[derive(Serialize)]
pub struct InitResponse {
    pub root_token: String,
    /// Hex-encoded unseal key — surfaced to the GUI so the
    /// post-init success screen can prompt the operator to back
    /// it up out-of-band. Without this material a future wiped
    /// keystore + sealed vault is unrecoverable; with it, the
    /// operator can paste it back via the InitPage's
    /// "Recover with your unseal key" panel.
    pub unseal_key_hex: String,
}

#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub sealed: bool,
    pub has_vault: bool,
}

#[tauri::command]
pub async fn init_vault(state: State<'_, AppState>) -> CmdResult<InitResponse> {
    // Hold the vault mutex for the entire init so concurrent invocations
    // -- e.g. React StrictMode in dev firing a click handler's effect
    // twice -- serialize and the loser sees an already-initialized vault
    // instead of trying to open a second hiqlite instance over the same
    // on-disk lockfile.
    let mut vault_guard = state.vault.lock().await;
    if vault_guard.is_some() {
        return Err("Vault already initialized in this session".into());
    }
    // init_embedded returns the already-unsealed vault. We stash it into
    // app state directly -- reopening the backend right after init would
    // collide with its still-held lockfile (hiqlite) or be wasteful (file).
    let outcome = embedded::init_embedded().await?;
    let root_token = outcome.root_token.clone();
    let unseal_key_hex = outcome.unseal_key_hex.clone();
    let vault_arc = outcome.vault.clone();
    *vault_guard = Some(outcome.vault);
    drop(vault_guard);
    #[cfg(feature = "embedded_vault")]
    {
        *state.backend.lock().await = Some(std::sync::Arc::new(
            crate::backend::EmbeddedBackend::new(vault_arc),
        ));
    }
    #[cfg(not(feature = "embedded_vault"))]
    let _ = vault_arc;
    *state.token.lock().await = Some(root_token.clone());

    Ok(InitResponse {
        root_token,
        unseal_key_hex,
    })
}

#[tauri::command]
pub async fn open_vault(state: State<'_, AppState>) -> CmdResult<()> {
    // Idempotent: if something (e.g. a double-fired StrictMode effect)
    // already opened the vault, return success without touching storage.
    // Holding the mutex across open_embedded serializes concurrent calls.
    let mut vault_guard = state.vault.lock().await;
    if vault_guard.is_some() {
        return Ok(());
    }
    let vault = embedded::open_embedded().await?;
    let vault_arc = vault.clone();
    *vault_guard = Some(vault);
    drop(vault_guard);
    #[cfg(feature = "embedded_vault")]
    {
        *state.backend.lock().await = Some(std::sync::Arc::new(
            crate::backend::EmbeddedBackend::new(vault_arc),
        ));
    }
    #[cfg(not(feature = "embedded_vault"))]
    let _ = vault_arc;

    // Restore the per-vault root token the init flow stashed under
    // this profile's id. Keeps the post-open session alive without
    // a re-login in the single-operator / local-install case.
    let vault_id = crate::embedded::current_vault_id();
    if let Some(token) = crate::local_keystore::get_root_token(&vault_id)? {
        *state.token.lock().await = Some(token);
    }

    Ok(())
}

/// Outcome of a seal attempt: aggregate status + per-node breakdown.
/// `nodes` has one entry for embedded / single-node remote, and one per
/// member for a discovered cluster (seal is fanned out cluster-wide).
#[derive(Serialize)]
pub struct SealOutcome {
    pub status: VaultStatus,
    pub nodes: Vec<crate::commands::connection::NodeSealResult>,
}

/// Seal the vault. Backend-gated: the caller must hold a policy
/// granting `update` on `sys/seal`, which in the shipped policy set
/// is only the `root` token. Before this gate was added, any
/// authenticated user could seal the vault from the dashboard.
///
/// The authorization check routes through `PolicyStore::can_operate`,
/// which replays the same per-target resolution the request pipeline
/// uses in `post_auth`. It is not a UI-only hide: even a hand-crafted
/// Tauri call with a low-privilege token is rejected here.
///
/// In remote mode seal state is per-node, so the command is fanned out
/// to *every* node of the connected cluster (mirroring
/// `bvault operator seal`) — the server applies the same `sys/seal`
/// Write policy check per node. A literal-URL profile targets just the
/// one node.
#[tauri::command]
pub async fn seal_vault(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<SealOutcome> {
    #[cfg(feature = "embedded_vault")]
    {
        use bastion_vault::logical::Operation as ServerOp;
        use bastion_vault::modules::{auth::AuthModule, policy::PolicyModule};

        let vault_guard = state.vault.lock().await;
        if let Some(vault) = vault_guard.as_ref() {
            let core = vault.core.load();
            let token = state.token.lock().await.clone().unwrap_or_default();
            if token.is_empty() {
                return Err("Authentication required to seal the vault".into());
            }

            // Resolve the token → Auth, then probe `sys/seal` Write.
            // This is an embedded-only optimisation: it short-circuits
            // an unauthorized seal client-side rather than letting the
            // request travel through the dispatcher only to be rejected.
            // Even a hand-crafted Tauri call with a low-privilege token
            // is rejected here.
            let auth_module = core
                .module_manager
                .get_module::<AuthModule>("auth")
                .ok_or("auth module unavailable")?;
            let token_store = auth_module
                .token_store
                .load_full()
                .ok_or("token store unavailable")?;

            let auth = token_store
                .check_token("sys/seal", &token)
                .await
                .map_err(CommandError::from)?
                .ok_or("invalid or expired token")?;

            let policy_module = core
                .module_manager
                .get_module::<PolicyModule>("policy")
                .ok_or("policy module unavailable")?;
            let policy_store = policy_module.policy_store.load();

            if !policy_store
                .can_operate(&auth, "sys/seal", ServerOp::Write)
                .await
            {
                return Err("Permission denied: caller lacks `update` on sys/seal".into());
            }

            embedded::seal_vault(vault).await?;
            *state.backend.lock().await = None;
            drop(vault_guard);
            crate::plugin_apps::teardown_all(&app, &state).await;
            return Ok(SealOutcome {
                status: VaultStatus { initialized: true, sealed: true, has_vault: true },
                nodes: vec![crate::commands::connection::NodeSealResult {
                    address: "embedded".to_string(),
                    sealed: Some(true),
                    progress: None,
                    threshold: None,
                    error: None,
                }],
            });
        }
    }

    // Remote mode: fan the seal out across the whole cluster.
    {
        let token = state.token.lock().await.clone().unwrap_or_default();
        if token.is_empty() {
            return Err("Authentication required to seal the vault".into());
        }
        let profile = state.remote_profile.lock().await.clone();
        if let Some(profile) = profile {
            let nodes =
                crate::commands::connection::remote_seal_fanout(&profile, &token).await?;
            // If no node could be sealed, surface the first failure as a
            // hard error so the caller sees why (e.g. permission denied).
            let sealed_count = nodes.iter().filter(|n| n.sealed == Some(true)).count();
            if sealed_count == 0 {
                let msg = nodes
                    .iter()
                    .find_map(|n| n.error.clone())
                    .unwrap_or_else(|| "Seal failed on all nodes".to_string());
                return Err(CommandError::from(msg));
            }
            // At least one node sealed → drop the cached backend handle so
            // the next request re-establishes rather than reusing a handle
            // pointed at a now-sealed node.
            *state.backend.lock().await = None;
            crate::plugin_apps::teardown_all(&app, &state).await;
            return Ok(SealOutcome {
                status: VaultStatus { initialized: true, sealed: true, has_vault: true },
                nodes,
            });
        }
    }

    Err(CommandError::from("No vault available to seal".to_string()))
}

/// Resolve the unseal key for an embedded vault. The operator-supplied
/// `provided` hex string wins when present; otherwise we fall back to
/// the key the init/recovery flow cached in the local keystore for the
/// currently-active profile. Validates hex shape before decoding so a
/// typo surfaces here rather than as an opaque barrier error.
#[cfg(feature = "embedded_vault")]
fn resolve_embedded_unseal_key(provided: Option<&str>) -> CmdResult<Vec<u8>> {
    let hex_key = match provided.map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => k.to_string(),
        None => {
            let vault_id = crate::embedded::current_vault_id();
            crate::local_keystore::get_unseal_key(&vault_id)?.ok_or_else(|| {
                CommandError::from(
                    "No unseal key supplied and none cached on this device for the active vault"
                        .to_string(),
                )
            })?
        }
    };
    let trimmed = hex_key.trim();
    if !trimmed.len().is_multiple_of(2) || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("unseal key is not valid hex".into());
    }
    hex::decode(trimmed).map_err(|_| CommandError::from("unseal key is not valid hex".to_string()))
}

/// Outcome of an unseal attempt: the aggregate `status` the UI keys off
/// plus a per-node breakdown. `status.sealed` stays true while *any*
/// targeted node is still sealed, so the operator keeps feeding shares
/// until the whole cluster crosses the threshold. `nodes` has a single
/// entry for embedded / single-node remote, and one entry per member
/// for a discovered cluster.
#[derive(Serialize)]
pub struct UnsealOutcome {
    pub status: VaultStatus,
    pub nodes: Vec<crate::commands::connection::NodeSealResult>,
}

/// Unseal the vault and return the resulting status + per-node breakdown.
///
/// Embedded mode: `seal_vault` leaves the in-process `BastionVault`
/// handle parked in `AppState` (only the `Backend` handle is torn
/// down), so we re-apply the unseal key to the same barrier and
/// rebuild the `EmbeddedBackend` the dispatcher reads through. The key
/// comes from `unseal_key_hex` when the operator pastes one, otherwise
/// from the local-keystore cache that init seeded — so the common case
/// (operator who set up this machine) is a one-click unseal.
///
/// Remote mode: seal state is per-node, so the share is fanned out to
/// *every* node of the connected cluster — mirroring
/// `bvault operator unseal` — discovering the roster via SRV for a
/// cluster-name profile, or hitting just the one node for a literal URL.
/// The key is required here. Multi-share (t-of-n) setups need each share
/// submitted in turn; the aggregate `sealed` stays true until every node
/// is open, so the dialog keeps prompting for the next share.
#[tauri::command]
pub async fn unseal_vault(
    state: State<'_, AppState>,
    unseal_key_hex: Option<String>,
) -> CmdResult<UnsealOutcome> {
    #[cfg(feature = "embedded_vault")]
    {
        let vault_guard = state.vault.lock().await;
        if let Some(vault) = vault_guard.as_ref() {
            if vault.core.load().sealed() {
                let key = resolve_embedded_unseal_key(unseal_key_hex.as_deref())?;
                let opened = vault
                    .unseal(&[key.as_slice()])
                    .await
                    .map_err(CommandError::from)?;
                if !opened {
                    return Err(
                        "Unseal failed: the key did not match this vault".into(),
                    );
                }
            }
            let core = vault.core.load();
            let initialized = core.inited().await.unwrap_or(false);
            let sealed = core.sealed();
            // Rebuild the backend handle `seal_vault` cleared so the
            // dispatcher can serve requests again.
            if !sealed {
                let vault_arc = vault.clone();
                drop(vault_guard);
                *state.backend.lock().await = Some(std::sync::Arc::new(
                    crate::backend::EmbeddedBackend::new(vault_arc),
                ));
            }
            return Ok(UnsealOutcome {
                status: VaultStatus { initialized, sealed, has_vault: true },
                nodes: vec![crate::commands::connection::NodeSealResult {
                    address: "embedded".to_string(),
                    sealed: Some(sealed),
                    progress: None,
                    threshold: None,
                    error: None,
                }],
            });
        }
    }

    // Remote mode: fan the share out across the whole cluster.
    {
        let key = unseal_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or("An unseal key is required to unseal a remote vault")?
            .to_string();
        let profile = state.remote_profile.lock().await.clone();
        if let Some(profile) = profile {
            let nodes =
                crate::commands::connection::remote_unseal_fanout(&profile, &key).await?;
            return Ok(remote_fanout_outcome(nodes));
        }
    }

    Err(CommandError::from(
        "No vault available to unseal".to_string(),
    ))
}

/// Fold a per-node unseal fan-out result into the aggregate
/// [`UnsealOutcome`]. The cluster counts as sealed while any node we
/// reached still reports sealed, OR any node errored (we can't confirm
/// it crossed the threshold). A node that answered with a seal state is,
/// by definition, initialized.
fn remote_fanout_outcome(
    nodes: Vec<crate::commands::connection::NodeSealResult>,
) -> UnsealOutcome {
    let sealed = nodes
        .iter()
        .any(|n| n.sealed.unwrap_or(true) || n.error.is_some());
    let initialized = nodes.iter().any(|n| n.sealed.is_some());
    UnsealOutcome {
        status: VaultStatus { initialized, sealed, has_vault: true },
        nodes,
    }
}

/// Unseal a remote cluster identified by an explicit profile, WITHOUT a
/// prior `connect_remote`.
///
/// When every node of a cluster is sealed, the connect flow fails at
/// cluster discovery ("no healthy node found") *before*
/// `state.remote_profile` is ever populated — so the regular
/// [`unseal_vault`] path has no target. The Get-Started / Connect screen
/// calls this with the profile straight from the saved list, letting the
/// operator unseal the cluster and then retry the connection. The fan-out
/// runs its own SRV discovery and reaches sealed/unreachable nodes,
/// identical to the connected path; the key is required.
#[tauri::command]
pub async fn remote_unseal_profile(
    profile: RemoteProfile,
    unseal_key_hex: String,
) -> CmdResult<UnsealOutcome> {
    let key = unseal_key_hex.trim();
    if key.is_empty() {
        return Err("An unseal key is required to unseal a remote vault".into());
    }
    let nodes = crate::commands::connection::remote_unseal_fanout(&profile, key).await?;
    Ok(remote_fanout_outcome(nodes))
}

#[tauri::command]
pub async fn get_vault_status(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    // Embedded mode: probe `Core` directly. `Core::sealed()` /
    // `inited()` are the in-process truth — no HTTP roundtrip needed.
    {
        let vault_guard = state.vault.lock().await;
        if let Some(vault) = vault_guard.as_ref() {
            let core = vault.core.load();
            let initialized = core.inited().await.unwrap_or(false);
            let sealed = core.sealed();
            return Ok(VaultStatus { initialized, sealed, has_vault: true });
        }
    }

    // Remote mode: ask the server. `sys/seal-status` is wired into
    // the HTTP layer (not the logical engine pipeline), so it's not
    // reachable via the Backend trait's `Operation::Read` dispatch —
    // we go through the legacy `Client::sys().seal_status()` for
    // now. (Phase 3 will replace this with a `bv_client::RemoteBackend`
    // sys-helper once `state.remote_client` is dropped.)
    {
        let client_guard = state.remote_client.lock().await;
        if let Some(client) = client_guard.as_ref() {
            let resp = client.sys().seal_status().map_err(|e| {
                CommandError::from(format!("sys/seal-status failed: {e}"))
            })?;
            let body = resp
                .response_data
                .as_ref()
                .and_then(|v| v.as_object())
                .ok_or("sys/seal-status: empty response body")?;
            // The server response is a flat object — `{sealed, t, n,
            // progress}`. `initialized` isn't on this endpoint, but
            // an unsealable response means the vault has been
            // initialized at least once, so derive it from the
            // presence of a non-zero share count `n`.
            let sealed = body.get("sealed").and_then(|v| v.as_bool()).unwrap_or(true);
            let n = body.get("n").and_then(|v| v.as_u64()).unwrap_or(0);
            return Ok(VaultStatus {
                initialized: n > 0,
                sealed,
                has_vault: true,
            });
        }
    }

    // No backend at all — chooser screen, freshly-disconnected, etc.
    Ok(VaultStatus {
        initialized: embedded::is_initialized().unwrap_or(false),
        sealed: true,
        has_vault: false,
    })
}

/// Server identity + lifecycle facts surfaced by the GUI's "Server
/// Info" dialog. Mirrors the `/v1/sys/info` HTTP response with an
/// extra `connection_kind` / `endpoint` pair so the dialog can show
/// "Embedded (this process)" alongside the version stamp without
/// extra plumbing on the JS side.
#[derive(Serialize, Default)]
pub struct ServerInfo {
    pub connection_kind: String,
    pub endpoint: String,
    pub version: String,
    pub started_at: String,
    pub uptime_seconds: i64,
    pub initialized: bool,
    pub sealed: bool,
    pub storage_type: String,
}

#[tauri::command]
pub async fn get_server_info(state: State<'_, AppState>) -> CmdResult<ServerInfo> {
    // Embedded mode: the GUI hosts the Core in-process. The
    // server_info helpers (started_at / uptime_seconds / version)
    // returned the *current* values for whatever code is running
    // inside this binary, so we report them directly without an
    // HTTP roundtrip. Storage_type is inferred from the active
    // backend handle when we have one.
    {
        let vault_guard = state.vault.lock().await;
        if let Some(vault) = vault_guard.as_ref() {
            let core = vault.core.load();
            let initialized = core.inited().await.unwrap_or(false);
            let sealed = core.sealed();
            let storage_type = {
                #[cfg(feature = "storage_hiqlite")]
                {
                    use bastion_vault::storage::hiqlite::HiqliteBackend;
                    let backend_any =
                        core.physical.as_ref() as &dyn std::any::Any;
                    if backend_any.downcast_ref::<HiqliteBackend>().is_some() {
                        "hiqlite".to_string()
                    } else {
                        "unknown".to_string()
                    }
                }
                #[cfg(not(feature = "storage_hiqlite"))]
                {
                    "unknown".to_string()
                }
            };
            return Ok(ServerInfo {
                connection_kind: "embedded".to_string(),
                endpoint: "embedded".to_string(),
                version: bastion_vault::server_info::version().to_string(),
                started_at: bastion_vault::server_info::started_at().to_rfc3339(),
                uptime_seconds: bastion_vault::server_info::uptime_seconds(),
                initialized,
                sealed,
                storage_type,
            });
        }
    }

    // Remote mode: ask the server. `/v1/sys/info` is the
    // authoritative source — version is the server's, not the GUI
    // binary's, so a mixed-version operator setup shows the truth.
    {
        let client_guard = state.remote_client.lock().await;
        if let Some(client) = client_guard.as_ref() {
            let endpoint = client.address.clone();
            let resp = client.sys().info().map_err(|e| {
                CommandError::from(format!("sys/info failed: {e}"))
            })?;
            let body = resp
                .response_data
                .as_ref()
                .and_then(|v| v.as_object())
                .ok_or("sys/info: empty response body")?;
            fn s(o: &serde_json::Map<String, Value>, k: &str) -> String {
                o.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
            }
            return Ok(ServerInfo {
                connection_kind: "remote".to_string(),
                endpoint,
                version: s(body, "version"),
                started_at: s(body, "started_at"),
                uptime_seconds: body
                    .get("uptime_seconds")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                initialized: body
                    .get("initialized")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                sealed: body
                    .get("sealed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
                storage_type: s(body, "storage_type"),
            });
        }
    }

    // No backend at all — chooser screen, etc.
    Err(CommandError::from("no active server connection".to_string()))
}

/// Blow away the local keystore — the encrypted file that caches
/// per-vault unseal keys + root tokens alongside the OS keychain
/// entry that seals it. Leaves ALL vault data intact (the actual
/// secrets live in the storage backend, encrypted by the barrier
/// under the unseal key; this command only clears the local
/// convenience cache).
///
/// Used as a recovery escape hatch when the local keystore file is
/// unreadable — typically because the OS keychain entry was wiped
/// between runs, leaving the ML-KEM keypair that sealed the file
/// non-derivable. The operator re-enters each vault's unseal key
/// on next open to repopulate the cache.
#[tauri::command]
pub async fn reset_local_keystore(state: State<'_, AppState>) -> CmdResult<()> {
    // Drop the in-process vault handle + cached token too — they
    // reference the now-invalid local keystore state.
    *state.vault.lock().await = None;
    *state.backend.lock().await = None;
    *state.token.lock().await = None;
    crate::local_keystore::wipe_all()?;
    Ok(())
}

/// Operator-supplied recovery for an opaque local keystore. Wipes
/// the current cache (in case it's unreadable) and re-seeds it
/// with the unseal key the operator has stored elsewhere (paper
/// backup, password manager, etc.). After this call succeeds the
/// normal `open_vault` path can unseal using the re-populated
/// cache. Scoped to the currently-active vault profile —
/// multi-vault operators run the flow once per profile.
///
/// `unseal_key_hex` is the hex-encoded unseal key as shown at init
/// time. Length + hex validity are checked before touching state.
#[tauri::command]
pub async fn recover_unseal_key(
    state: State<'_, AppState>,
    unseal_key_hex: String,
) -> CmdResult<()> {
    let trimmed = unseal_key_hex.trim();
    if trimmed.is_empty() {
        return Err("unseal key is required".into());
    }
    // The embedded-vault init writes a 32-byte key, i.e. 64 hex
    // chars. We reject anything else up-front rather than letting
    // the downstream unseal fail with an opaque error.
    if !trimmed.len().is_multiple_of(2) {
        return Err("unseal key hex string has odd length".into());
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("unseal key is not valid hex".into());
    }

    // Drop the active vault + token first so the keystore update
    // doesn't race an in-flight session.
    *state.vault.lock().await = None;
    *state.backend.lock().await = None;
    *state.token.lock().await = None;

    // Wipe then re-seal so the old cache's ML-KEM material
    // doesn't linger next to the operator-supplied key.
    crate::local_keystore::wipe_all()?;

    let vault_id = crate::embedded::current_vault_id();
    crate::local_keystore::store_unseal_key(&vault_id, trimmed)?;
    Ok(())
}

/// Close the active embedded-vault handle without touching the
/// on-disk data, keychain, or saved preferences. Used by the
/// Switch-vault flow so the AppState slot is free for a subsequent
/// `open_vault` to drop in a different profile (embedded's
/// `build_backend` reads `last_used_id` from preferences, so swapping
/// the profile is a `set_last_used_vault` + close + open sequence).
///
/// Intentionally does NOT clear `state.token` — the GUI caches
/// per-vault tokens in its auth store so it can restore the session
/// on the target vault without a full re-login if the stashed token
/// is still valid. The token IS cleared on the Rust side later by
/// the open path when the new vault comes up; or on explicit sign-out.
#[tauri::command]
pub async fn disconnect_vault(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    *state.vault.lock().await = None;
    *state.backend.lock().await = None;
    *state.token.lock().await = None;
    crate::plugin_apps::teardown_all(&app, &state).await;
    Ok(())
}

#[tauri::command]
pub async fn reset_vault(state: State<'_, AppState>) -> CmdResult<()> {
    use crate::preferences::{self, VaultSpec};

    // Drop the active vault + session first so we don't race with
    // ongoing reads during the wipe.
    *state.vault.lock().await = None;
    *state.backend.lock().await = None;
    *state.token.lock().await = None;

    // Drop the per-vault entry for the currently-active profile
    // (the one whose data we're about to nuke) plus any legacy
    // single-slot keychain residue. Other vaults' entries stay
    // intact so this action is scoped to the one being reset.
    //
    // Best-effort: if the keystore is unreadable (the exact
    // scenario that put the operator on the Destroy-and-Reset
    // path in the first place) `remove_vault` now falls back to
    // `wipe_all`, but even if both fail we keep going — the cloud
    // bucket wipe below is what the operator actually came here
    // for. Failing out of the whole command on a keystore I/O
    // error used to leave the bucket intact and the button
    // appearing to "do nothing."
    let vault_id = crate::embedded::current_vault_id();
    if let Err(e) = crate::local_keystore::remove_vault(&vault_id) {
        eprintln!(
            "reset: keystore remove_vault(`{vault_id}`) failed: {e}. \
             Forcing a full keystore wipe and continuing."
        );
        let _ = crate::local_keystore::wipe_all();
    }
    if let Err(e) = crate::secure_store::delete_all_keys() {
        eprintln!("reset: legacy keychain cleanup failed: {e}. Continuing.");
    }

    // Branch on the active profile's spec. Cloud vaults live in a
    // bucket / drive and require a backend-level wipe — just
    // removing the local data dir (which is what earlier revisions
    // did) left the bucket intact, so the next open saw
    // "initialized" again and the user's Reset button appeared to
    // do nothing. Local profiles continue to delete their data dir.
    let profile = preferences::load().ok().and_then(|p| p.default_profile().cloned());
    match profile.as_ref().map(|p| &p.spec) {
        Some(VaultSpec::Cloud { .. }) => {
            // Build the cloud backend the same way `open_vault`
            // would, then enumerate every key and delete it. This
            // wipes barrier markers, keyring, and all logical paths
            // in one pass.
            wipe_cloud_backend().await?;
        }
        Some(VaultSpec::Remote { .. }) => {
            // Reset-vault against a remote server doesn't make
            // sense here — the operator does that server-side.
            // We've already cleared the local session state, which
            // is all this command can legitimately touch.
        }
        _ => {
            // Local (or no profile configured at all) — delete the
            // effective data directory. Honours per-profile custom
            // `data_dir` overrides that `build_backend` applies.
            let dir = active_local_data_dir()?;
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    crate::error::CommandError::from(format!("Failed to remove vault data: {e}"))
                })?;
            }
        }
    }

    Ok(())
}

/// Enumerate every object stored under the active cloud profile and
/// issue a backend-level `delete` for each. Run under a fresh
/// backend handle — the active vault is already closed by the
/// caller, so building one here doesn't race with an in-flight
/// session. Empty enumeration is a no-op, which is the expected
/// state after a successful reset.
async fn wipe_cloud_backend() -> Result<(), crate::error::CommandError> {
    // `backend` is `Arc<dyn Backend>`; trait methods resolve through
    // the trait object directly, no `use Backend` needed.
    let backend = crate::embedded::build_backend().await?;

    // BFS-style walk: start at "" (the provider's root) and recurse
    // into any directory-shaped entries (trailing "/"). Leaf entries
    // get deleted; directories get expanded. This handles Hiqlite's
    // flat-key layout and cloud targets' virtual-hierarchy view
    // identically.
    let mut queue: Vec<String> = vec![String::new()];
    let mut deleted = 0usize;
    while let Some(prefix) = queue.pop() {
        let entries = match backend.list(&prefix).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "reset: cloud list(`{prefix}`) failed: {e} — continuing best-effort"
                );
                continue;
            }
        };
        for entry in entries {
            let full = format!("{prefix}{entry}");
            if entry.ends_with('/') {
                queue.push(full);
            } else {
                match backend.delete(&full).await {
                    Ok(()) => {
                        deleted += 1;
                    }
                    Err(e) => {
                        // Best-effort: don't abort the whole wipe
                        // on one stubborn object. Operators who see
                        // repeated resets not fully clearing the
                        // bucket can check the log + use their
                        // provider's console to remove the rest.
                        eprintln!(
                            "reset: cloud delete(`{full}`) failed: {e} — continuing"
                        );
                    }
                }
            }
        }
    }
    eprintln!("reset: cloud backend wipe complete ({deleted} object(s) removed)");
    Ok(())
}

/// Resolve the data directory that would be used by the currently-
/// active local profile. Mirrors the effective-dir logic in
/// `embedded::build_backend`: honours the profile's custom
/// `data_dir` override, falls back to the canonical per-kind
/// default otherwise.
fn active_local_data_dir() -> Result<std::path::PathBuf, crate::error::CommandError> {
    use crate::embedded::{data_dir, data_dir_for, StorageKind};
    use crate::preferences::{self, VaultSpec};

    if let Ok(prefs) = preferences::load() {
        if let Some(profile) = prefs.default_profile() {
            if let VaultSpec::Local { data_dir: dir, storage_kind } = &profile.spec {
                if let Some(custom) = dir.as_ref().filter(|s| !s.is_empty()) {
                    return Ok(std::path::PathBuf::from(custom));
                }
                let kind = match storage_kind.as_str() {
                    "hiqlite" => StorageKind::Hiqlite,
                    _ => StorageKind::File,
                };
                return data_dir_for(kind);
            }
        }
    }
    data_dir()
}

#[derive(Serialize)]
pub struct MountInfo {
    pub path: String,
    pub mount_type: String,
    pub description: String,
}

/// List the secret-engine mounts the caller is authorized to see.
///
/// Routes through `sys/internal/ui/mounts`, which runs through the
/// full auth + policy pipeline on the backend: the ACL gates each
/// mount entry via `has_mount_access`. An earlier revision read the
/// router's mount table directly, which leaked every mount to every
/// authenticated caller regardless of their policies — felipe with
/// only `default` would still see `secret/`, `resources/`, etc. on
/// the dashboard. Don't reintroduce that: the backend filter is the
/// source of truth.
#[tauri::command]
pub async fn list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<MountInfo>> {
    let map = read_ui_mounts(&state, "secret").await?;
    Ok(mount_map_to_info(&map))
}

/// Same as `list_mounts` but for auth-method mounts. Pulls the
/// `auth` half of the `sys/internal/ui/mounts` response.
#[tauri::command]
pub async fn list_auth_methods(state: State<'_, AppState>) -> CmdResult<Vec<MountInfo>> {
    let map = read_ui_mounts(&state, "auth").await?;
    Ok(mount_map_to_info(&map))
}

/// Read the seal / HSM posture from `v2/sys/hsm/status`.
///
/// The response is intentionally polymorphic: a Shamir seal returns only
/// `type` / `auto_unseal` / `sealed` / `initialized`, while the HSM seal
/// provider adds the backend, device serial, cluster epoch, enrolled-node
/// count, and recovery mode. We forward the server's `data` map verbatim
/// (never any secret material — the server guarantees that) so the GUI can
/// render whatever fields are present without this command needing to track
/// the seal-provider schema. Routes through the Backend trait so it works in
/// both embedded and remote mode.
#[tauri::command]
pub async fn hsm_status(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp = crate::commands::make_request(
        &state,
        Operation::Read,
        "sys/hsm/status".to_string(),
        None,
    )
    .await?;
    let data = resp
        .and_then(|r| r.data)
        .ok_or("sys/hsm/status returned no data")?;
    Ok(Value::Object(data))
}

/// Read `sys/internal/ui/mounts` through the full request pipeline
/// so the ACL filter applies, and return the map under the given
/// top-level field (`"secret"` or `"auth"`).
async fn read_ui_mounts(
    state: &State<'_, AppState>,
    field: &str,
) -> Result<serde_json::Map<String, Value>, CommandError> {
    let resp = crate::commands::make_request(
        state,
        Operation::Read,
        "sys/internal/ui/mounts".to_string(),
        None,
    )
    .await?;

    let data = resp
        .and_then(|r| r.data)
        .ok_or("sys/internal/ui/mounts returned no data")?;
    let map = data
        .get(field)
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    Ok(map)
}

/// Convert the `{path -> {type, description, ...}}` payload used by
/// `sys/internal/ui/mounts` into the flat `Vec<MountInfo>` the
/// frontend expects.
/// One row of the unified audit trail. Mirrors the shape of the
/// server's `/v2/sys/audit/events` response so the frontend can
/// render it directly. `changed_fields` is empty for policies (where
/// only raw-HCL before/after is tracked) and populated for group
/// changes.
#[derive(Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub user: String,
    pub op: String,
    pub category: String,
    pub target: String,
    pub changed_fields: Vec<String>,
    pub summary: String,
}

#[tauri::command]
pub async fn list_audit_events(
    state: State<'_, AppState>,
    from: String,
    to: String,
    limit: Option<u32>,
) -> CmdResult<Vec<AuditEvent>> {
    // The handler parses these from `req.data` after field resolution;
    // for Read it populates from the body, so stuff them there.
    let mut body = serde_json::Map::new();
    if !from.is_empty() {
        body.insert("from".into(), Value::String(from));
    }
    if !to.is_empty() {
        body.insert("to".into(), Value::String(to));
    }
    if let Some(l) = limit {
        body.insert("limit".into(), Value::Number(l.into()));
    }
    let body = if body.is_empty() { None } else { Some(body) };

    let resp = crate::commands::make_request(
        &state,
        Operation::Read,
        "sys/audit/events".to_string(),
        body,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let arr = data.get("events").and_then(|v| v.as_array()).cloned();
    let out = arr
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(AuditEvent {
                ts: o.get("ts").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                user: o.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                op: o.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                category: o
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                target: o
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                changed_fields: o
                    .get("changed_fields")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                summary: o
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect();
    Ok(out)
}

// ── Dashboard summary ──────────────────────────────────────────────
//
// One-shot operational snapshot for the GUI Dashboard landing page.
// Routes through the Backend trait (`make_request`) so it works in
// both embedded and remote mode. Counts are computed server-side,
// ACL- and namespace-scoped, so the dashboard makes a single call
// instead of fanning out N list requests.

#[derive(Serialize, Default)]
pub struct DashboardSeal {
    pub sealed: bool,
    pub initialized: bool,
}

#[derive(Serialize, Default)]
pub struct DashboardCounts {
    pub secret_mounts: u64,
    pub auth_mounts: u64,
    pub policies: u64,
    pub entities: u64,
}

#[derive(Serialize, Default)]
pub struct DashboardSummary {
    pub version: String,
    pub namespace: String,
    pub seal: DashboardSeal,
    pub counts: DashboardCounts,
    pub audit_24h_total: u64,
    pub audit_24h_denied: u64,
    pub audit_24h_write_failures: u64,
    pub failed_logins_1h: u64,
}

#[tauri::command]
pub async fn dashboard_summary(state: State<'_, AppState>) -> CmdResult<DashboardSummary> {
    let resp = crate::commands::make_request(
        &state,
        Operation::Read,
        "sys/dashboard/summary".to_string(),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();

    let counts = data.get("counts").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let seal = data.get("seal").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let audit = data.get("audit_24h").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let attention = data.get("attention").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let u = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    let b = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(|v| v.as_bool()).unwrap_or(false);

    Ok(DashboardSummary {
        version: data.get("version").and_then(|v| v.as_str()).unwrap_or("1").to_string(),
        namespace: data.get("namespace").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        seal: DashboardSeal {
            sealed: b(&seal, "sealed"),
            initialized: b(&seal, "initialized"),
        },
        counts: DashboardCounts {
            secret_mounts: u(&counts, "secret_mounts"),
            auth_mounts: u(&counts, "auth_mounts"),
            policies: u(&counts, "policies"),
            entities: u(&counts, "entities"),
        },
        audit_24h_total: u(&audit, "total"),
        audit_24h_denied: u(&audit, "denied"),
        audit_24h_write_failures: u(&audit, "write_failures"),
        failed_logins_1h: u(&attention, "failed_logins_1h"),
    })
}

// ── SSO discovery + admin toggle ───────────────────────────────────
//
// `sys/sso/providers` is unauthenticated on the backend so the login
// page can fetch the list before the user has a token. `sys/sso/settings`
// is root-gated — only an operator with a sudo token flips the
// global enable bit.

#[derive(Serialize, Debug, Clone)]
pub struct SsoProvider {
    pub mount: String,
    pub name: String,
    pub kind: String,
}

#[derive(Serialize, Debug)]
pub struct SsoProvidersResult {
    pub enabled: bool,
    pub providers: Vec<SsoProvider>,
}

/// Read the unauth discovery endpoint. Used by the login page to
/// decide whether the SSO tab is shown at all.
#[tauri::command]
pub async fn list_sso_providers(state: State<'_, AppState>) -> CmdResult<SsoProvidersResult> {
    let data = read_sys_path(&state, "sys/sso/providers", /* authed = */ false).await?;
    let enabled = data
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let providers = data
        .get("providers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(SsoProvider {
                mount: o.get("mount")?.as_str()?.to_string(),
                name: o
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                kind: o
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect();
    Ok(SsoProvidersResult { enabled, providers })
}

#[tauri::command]
pub async fn get_sso_settings(state: State<'_, AppState>) -> CmdResult<bool> {
    let data = read_sys_path(&state, "sys/sso/settings", /* authed = */ true).await?;
    Ok(data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
}

#[tauri::command]
pub async fn set_sso_settings(
    state: State<'_, AppState>,
    enabled: bool,
) -> CmdResult<()> {
    let mut body = serde_json::Map::new();
    body.insert("enabled".into(), Value::Bool(enabled));
    crate::commands::make_request(
        &state,
        Operation::Write,
        "sys/sso/settings".to_string(),
        Some(body),
    )
    .await?;
    Ok(())
}

async fn read_sys_path(
    state: &State<'_, AppState>,
    path: &str,
    authed: bool,
) -> Result<serde_json::Map<String, Value>, CommandError> {
    let resp = if authed {
        crate::commands::make_request(state, Operation::Read, path.to_string(), None).await?
    } else {
        crate::commands::dispatch_with_token(
            state,
            Operation::Read,
            path.to_string(),
            None,
            "",
        )
        .await?
    };
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

fn mount_map_to_info(map: &serde_json::Map<String, Value>) -> Vec<MountInfo> {
    let mut out: Vec<MountInfo> = map
        .iter()
        .map(|(path, v)| MountInfo {
            path: path.clone(),
            mount_type: v
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            description: v
                .get("description")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}
