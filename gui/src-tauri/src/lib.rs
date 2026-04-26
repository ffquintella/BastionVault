mod commands;
mod embedded;
mod error;
mod preferences;
mod local_keystore;
mod secure_store;
mod yubikey_bridge;
mod state;

use state::AppState;

/// Disable WebView2 form-autofill features so typed secret values are not
/// persisted to Chromium's Web Data SQLite cache. Defense-in-depth paired
/// with the frontend `SecretInput` component and the Chromium-flag env var
/// set in `run()`. Called from the Tauri `setup` hook once the WebView2
/// controller is available.
#[cfg(target_os = "windows")]
fn harden_webview_autofill(window: &tauri::WebviewWindow) -> Result<(), Box<dyn std::error::Error>> {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings6;
    use windows::core::Interface;

    window.with_webview(|webview| unsafe {
        let controller = webview.controller();
        let core = match controller.CoreWebView2() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("harden_webview_autofill: CoreWebView2 unavailable: {e}");
                return;
            }
        };
        let settings = match core.Settings() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("harden_webview_autofill: Settings unavailable: {e}");
                return;
            }
        };
        match settings.cast::<ICoreWebView2Settings6>() {
            Ok(settings6) => {
                if let Err(e) = settings6.SetIsGeneralAutofillEnabled(false) {
                    eprintln!("harden_webview_autofill: SetIsGeneralAutofillEnabled failed: {e}");
                }
                if let Err(e) = settings6.SetIsPasswordAutosaveEnabled(false) {
                    eprintln!("harden_webview_autofill: SetIsPasswordAutosaveEnabled failed: {e}");
                }
            }
            Err(e) => {
                eprintln!(
                    "harden_webview_autofill: ICoreWebView2Settings6 not supported on this \
                     runtime (WebView2 SDK too old): {e}"
                );
            }
        }
    })?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Best-effort Chromium-flag disable for autofill-related features. Runs
    // before Tauri initializes WebView2 so the runtime picks it up at launch.
    // The authoritative hardening happens in `harden_webview_autofill` below.
    #[cfg(target_os = "windows")]
    {
        const EXTRA_ARGS: &str =
            "--disable-features=AutofillServerCommunication,AutofillEnableAccountWalletStorage";
        // Preserve any pre-existing value the user set.
        match std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") {
            Ok(existing) if !existing.is_empty() => {
                std::env::set_var(
                    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                    format!("{existing} {EXTRA_ARGS}"),
                );
            }
            _ => {
                std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", EXTRA_ARGS);
            }
        }
    }

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        // `dialog` exposes OS-native file / directory pickers; the
        // Add Local Vault modal uses the directory picker so the
        // operator can browse to the storage location instead of
        // typing the full path.
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .setup(|app| {
            #[cfg(target_os = "windows")]
            {
                use tauri::Manager;
                if let Some(window) = app.get_webview_window("main") {
                    if let Err(e) = harden_webview_autofill(&window) {
                        eprintln!("WebView2 autofill hardening failed: {e}");
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = app;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Cloud storage targets (OAuth consent orchestration)
            commands::cloud_target::cloud_target_start_connect,
            commands::cloud_target::cloud_target_complete_connect,
            commands::cloud_target::cloud_target_cancel_connect,
            // Cloud Vault (embedded vault backed by a cloud target)
            commands::cloud_target::set_cloud_vault_config,
            commands::cloud_target::clear_cloud_vault_config,
            commands::cloud_target::get_cloud_vault_config,
            commands::cloud_target::suggest_credentials_ref_path,
            commands::cloud_target::save_s3_credentials,
            commands::cloud_target::get_oauth_redirect_uri,
            commands::cloud_target::save_pasted_token,
            // OIDC login flow (embedded or remote vault)
            commands::oidc::oidc_login_start,
            commands::oidc::oidc_login_complete,
            commands::oidc::oidc_login_cancel,
            // Saved vault profiles (multi-vault chooser)
            commands::vaults::list_vault_profiles,
            commands::vaults::add_vault_profile,
            commands::vaults::update_vault_profile,
            commands::vaults::remove_vault_profile,
            commands::vaults::set_last_used_vault,
            commands::vaults::clear_last_used_vault,
            commands::vaults::get_vault_profile,
            commands::vaults::get_default_local_data_dir,
            // Connection
            commands::connection::get_mode,
            commands::connection::set_mode,
            commands::connection::is_vault_initialized,
            commands::connection::get_remote_profile,
            commands::connection::connect_remote,
            commands::connection::disconnect_remote,
            commands::connection::get_remote_status,
            commands::connection::remote_login_token,
            commands::connection::remote_login_userpass,
            commands::connection::load_preferences,
            commands::connection::save_preferences,
            commands::connection::get_password_policy,
            commands::connection::set_password_policy,
            // System
            commands::system::init_vault,
            commands::system::open_vault,
            commands::system::seal_vault,
            commands::system::reset_vault,
            commands::system::reset_local_keystore,
            commands::system::recover_unseal_key,
            commands::system::disconnect_vault,
            commands::system::get_vault_status,
            commands::system::list_mounts,
            commands::system::list_auth_methods,
            commands::system::list_audit_events,
            commands::system::list_sso_providers,
            commands::system::get_sso_settings,
            commands::system::set_sso_settings,
            commands::sso_admin::sso_admin_list,
            commands::sso_admin::sso_admin_get,
            commands::sso_admin::sso_admin_create,
            commands::sso_admin::sso_admin_update,
            commands::sso_admin::sso_admin_delete,
            commands::sso_admin::sso_admin_callback_hints,
            commands::yubikey::yubikey_list_devices,
            commands::yubikey::yubikey_list_registered,
            commands::yubikey::yubikey_provision_slot_9a,
            commands::yubikey::yubikey_register,
            commands::yubikey::yubikey_remove,
            commands::yubikey::yubikey_enable_keychain_slot,
            commands::yubikey::yubikey_keychain_slot_present,
            commands::yubikey::yubikey_set_pin,
            commands::yubikey::yubikey_clear_pin,
            // Auth
            commands::auth::login_token,
            commands::auth::login_userpass,
            commands::auth::get_current_token,
            commands::auth::logout,
            // Exchange (import / export module)
            commands::exchange::exchange_export,
            commands::exchange::exchange_preview,
            commands::exchange::exchange_apply,
            // Scheduled exports
            commands::scheduled_exports::scheduled_exports_list,
            commands::scheduled_exports::scheduled_exports_create,
            commands::scheduled_exports::scheduled_exports_update,
            commands::scheduled_exports::scheduled_exports_delete,
            commands::scheduled_exports::scheduled_exports_runs,
            commands::scheduled_exports::scheduled_exports_run_now,
            // Plugins
            commands::plugins::plugins_list,
            commands::plugins::plugins_get,
            commands::plugins::plugins_register,
            commands::plugins::plugins_delete,
            commands::plugins::plugins_invoke,
            commands::plugins::plugins_get_config,
            commands::plugins::plugins_set_config,
            commands::plugins::plugins_versions,
            commands::plugins::plugins_activate_version,
            commands::plugins::plugins_delete_version,
            commands::plugins::plugins_reload,
            // Secrets
            commands::secrets::list_secrets,
            commands::secrets::read_secret,
            commands::secrets::write_secret,
            commands::secrets::delete_secret,
            commands::secrets::list_secret_versions,
            commands::secrets::read_secret_version,
            commands::secrets::mount_engine,
            commands::secrets::unmount_engine,
            commands::secrets::enable_auth_method,
            commands::secrets::disable_auth_method,
            // Users
            commands::users::list_users,
            commands::users::get_user,
            commands::users::create_user,
            commands::users::update_user,
            commands::users::delete_user,
            // Policies
            commands::policies::list_policies,
            commands::policies::read_policy,
            commands::policies::write_policy,
            commands::policies::delete_policy,
            commands::policies::list_policy_history,
            // Resources
            commands::resources::resource_types_read,
            commands::resources::resource_types_write,
            commands::resources::list_resources,
            commands::resources::read_resource,
            commands::resources::write_resource,
            commands::resources::delete_resource,
            commands::resources::list_resource_secrets,
            commands::resources::read_resource_secret,
            commands::resources::write_resource_secret,
            commands::resources::delete_resource_secret,
            commands::resources::list_resource_history,
            commands::resources::list_resource_secret_versions,
            commands::resources::read_resource_secret_version,
            // File Resources
            commands::files::list_files,
            commands::files::read_file_meta,
            commands::files::read_file_content,
            commands::files::create_file,
            commands::files::update_file_content,
            commands::files::delete_file,
            commands::files::list_file_history,
            commands::files::list_file_sync_targets,
            commands::files::write_file_sync_target,
            commands::files::delete_file_sync_target,
            commands::files::push_file_sync_target,
            commands::files::list_file_versions,
            commands::files::read_file_version_content,
            commands::files::restore_file_version,
            // AppRole
            commands::approle::list_approles,
            commands::approle::read_approle,
            commands::approle::write_approle,
            commands::approle::delete_approle,
            commands::approle::read_role_id,
            commands::approle::generate_secret_id,
            commands::approle::list_secret_id_accessors,
            commands::approle::lookup_secret_id_accessor,
            commands::approle::destroy_secret_id_accessor,
            // Identity groups
            commands::groups::list_groups,
            commands::groups::read_group,
            commands::groups::write_group,
            commands::groups::delete_group,
            commands::groups::list_group_history,
            // Asset groups (resources + KV secrets)
            commands::asset_groups::list_asset_groups,
            commands::asset_groups::read_asset_group,
            commands::asset_groups::write_asset_group,
            commands::asset_groups::delete_asset_group,
            commands::asset_groups::list_asset_group_history,
            commands::asset_groups::asset_groups_for_resource,
            commands::asset_groups::asset_groups_for_secret,
            // Per-user scoping: entity, owner, sharing, transfer
            commands::sharing::get_entity_self,
            commands::sharing::list_entity_aliases,
            commands::sharing::get_kv_owner,
            commands::sharing::get_resource_owner,
            commands::sharing::list_shares_for_grantee,
            commands::sharing::list_shares_for_target,
            commands::sharing::put_share,
            commands::sharing::delete_share,
            commands::sharing::transfer_kv_owner,
            commands::sharing::transfer_resource_owner,
            commands::sharing::transfer_asset_group_owner,
            // FIDO2
            commands::fido2_native::fido2_native_register,
            commands::fido2_native::fido2_native_login,
            commands::fido2_native::fido2_submit_pin,
            commands::fido2::fido2_config_read,
            commands::fido2::fido2_config_write,
            commands::fido2::fido2_register_begin,
            commands::fido2::fido2_register_complete,
            commands::fido2::fido2_login_begin,
            commands::fido2::fido2_login_complete,
            commands::fido2::fido2_list_credentials,
            commands::fido2::fido2_delete_credential,
        ]);

    #[cfg(all(debug_assertions, feature = "mcp_local_dev"))]
    let builder = {
        if matches!(std::env::var("BASTION_TAURI_MCP").as_deref(), Ok("1")) {
            builder.plugin(
                tauri_plugin_mcp_bridge::Builder::new()
                    .bind_address("127.0.0.1")
                    .build(),
            )
        } else {
            builder
        }
    };

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
