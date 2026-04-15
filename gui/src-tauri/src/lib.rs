mod commands;
mod embedded;
mod error;
mod preferences;
mod secure_store;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
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
            // System
            commands::system::init_vault,
            commands::system::open_vault,
            commands::system::seal_vault,
            commands::system::reset_vault,
            commands::system::get_vault_status,
            commands::system::list_mounts,
            commands::system::list_auth_methods,
            // Auth
            commands::auth::login_token,
            commands::auth::login_userpass,
            commands::auth::get_current_token,
            commands::auth::logout,
            // Secrets
            commands::secrets::list_secrets,
            commands::secrets::read_secret,
            commands::secrets::write_secret,
            commands::secrets::delete_secret,
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
            // Resources
            commands::resources::list_resources,
            commands::resources::read_resource,
            commands::resources::write_resource,
            commands::resources::delete_resource,
            commands::resources::list_resource_secrets,
            commands::resources::read_resource_secret,
            commands::resources::write_resource_secret,
            commands::resources::delete_resource_secret,
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
            // FIDO2
            commands::fido2_native::fido2_native_register,
            commands::fido2_native::fido2_native_login,
            commands::fido2::fido2_config_read,
            commands::fido2::fido2_config_write,
            commands::fido2::fido2_register_begin,
            commands::fido2::fido2_register_complete,
            commands::fido2::fido2_login_begin,
            commands::fido2::fido2_login_complete,
            commands::fido2::fido2_list_credentials,
            commands::fido2::fido2_delete_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
