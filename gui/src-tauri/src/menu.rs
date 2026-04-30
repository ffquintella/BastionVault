//! Native application menu (File / Application / About).
//!
//! Attached to the main window in `lib.rs::run` via
//! [`build_main_menu`] + [`handle_menu_event`]. Session windows
//! (SSH / RDP) don't get this menu — they're spawned without one.
//!
//! Items that can't be expressed as predefined Tauri items emit a
//! Tauri event (`menu:<id>`) that the React side listens for; the
//! React layer already owns the auth + navigation state, so it's
//! the right place to react to "Sign Out" without re-implementing
//! the auth-store reset on the Rust side.

use tauri::menu::{AboutMetadataBuilder, Menu, MenuBuilder, MenuItem, PredefinedMenuItem, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tauri_plugin_shell::ShellExt;

const REPO_URL: &str = "https://github.com/ffquintella/BastionVault";

/// Build the menu for the main window. Each submenu's id space is
/// flat (Tauri matches by id at event time), so we prefix with the
/// section to avoid collisions if the menu grows.
pub fn build_main_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    // File → Backup submenu (Export / Restore). Both items emit
    // `menu:backup-*` events the React layer turns into a password
    // prompt + native dialog. Root-policy gating happens server-side
    // in the `backup_export` / `backup_restore` Tauri commands.
    let backup_export = MenuItem::with_id(
        app,
        "file.backup.export",
        "Export…",
        true,
        None::<&str>,
    )?;
    let backup_restore = MenuItem::with_id(
        app,
        "file.backup.restore",
        "Restore…",
        true,
        None::<&str>,
    )?;
    let backup = SubmenuBuilder::new(app, "Backup")
        .item(&backup_export)
        .item(&backup_restore)
        .build()?;

    // File ----------------------------------------------------------------
    let sign_out = MenuItem::with_id(app, "file.sign-out", "Sign Out", true, None::<&str>)?;
    let file = SubmenuBuilder::new(app, "File")
        .item(&backup)
        .separator()
        .item(&sign_out)
        .separator()
        .item(&PredefinedMenuItem::quit(app, Some("Quit"))?)
        .build()?;

    // Application ---------------------------------------------------------
    let reload = MenuItem::with_id(
        app,
        "app.reload",
        "Reload",
        true,
        Some("CmdOrCtrl+R"),
    )?;
    let toggle_full = MenuItem::with_id(
        app,
        "app.toggle-fullscreen",
        "Toggle Fullscreen",
        true,
        Some("F11"),
    )?;
    let app_menu = SubmenuBuilder::new(app, "Application")
        .item(&reload)
        .item(&toggle_full)
        .build()?;

    // About ---------------------------------------------------------------
    let about_meta = AboutMetadataBuilder::new()
        .name(Some("BastionVault"))
        .version(Some(env!("CARGO_PKG_VERSION")))
        .copyright(Some("BastionVault contributors"))
        .website(Some(REPO_URL))
        .website_label(Some("github.com/ffquintella/BastionVault"))
        .build();
    let about_predef = PredefinedMenuItem::about(app, Some("About BastionVault"), Some(about_meta))?;
    let open_repo = MenuItem::with_id(
        app,
        "about.open-repo",
        "Open GitHub Repository",
        true,
        None::<&str>,
    )?;
    let about = SubmenuBuilder::new(app, "About")
        .item(&about_predef)
        .item(&open_repo)
        .build()?;

    MenuBuilder::new(app)
        .item(&file)
        .item(&app_menu)
        .item(&about)
        .build()
}

/// Dispatch a menu event. Emits `menu:<id>` to the frontend for any
/// item the React layer should handle (sign-out), and handles the
/// rest natively so the operator gets immediate feedback even if the
/// frontend is mid-navigation.
pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match id {
        "file.sign-out" => {
            // The auth store + router live on the React side; emit
            // an event the top-level component listens for.
            let _ = app.emit("menu:sign-out", ());
        }
        "file.backup.export" => {
            let _ = app.emit("menu:backup-export", ());
        }
        "file.backup.restore" => {
            let _ = app.emit("menu:backup-restore", ());
        }
        "app.reload" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.eval("window.location.reload()");
            }
        }
        "app.toggle-fullscreen" => {
            if let Some(win) = app.get_webview_window("main") {
                let next = !win.is_fullscreen().unwrap_or(false);
                let _ = win.set_fullscreen(next);
            }
        }
        "about.open-repo" => {
            // `Shell::open` is deprecated in favour of
            // `tauri-plugin-opener`; pulling that plugin in just to
            // launch one URL would also need an ACL/manifest update,
            // so we silence the warning here. Switch over the day we
            // adopt the opener plugin app-wide.
            #[allow(deprecated)]
            let _ = app.shell().open(REPO_URL, None);
        }
        _ => {}
    }
}
