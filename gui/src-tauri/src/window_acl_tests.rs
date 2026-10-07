//! The per-window app-command ACL (T110, features/session-workspace.md).
//!
//! `build.rs` hands Tauri an app manifest listing every registered command,
//! which turns Tauri's ACL on for app commands: a webview may call one only
//! if a capability matching its window (or webview) label grants
//! `allow-<command>`. These tests resolve the shipped capability files the
//! way Tauri 2.11 does (`RuntimeAuthority::resolve_access`: a capability
//! applies when a `windows` glob matches the window label or a `webviews`
//! glob matches the webview label; sets expand recursively) and pin what
//! each window gets:
//!
//! * `main` (and `plugin-*`) — every registered command, as before the
//!   manifest existed; the main window's plugin permissions unchanged;
//! * a session's own window, the Session Workspace and a replay window —
//!   exactly the commands `session.html` calls in that window
//!   (`gui/src/test/sessionBundle.test.ts` checks the frontend side of the
//!   same sets), and none of the vault's secret, credential or admin
//!   commands;
//! * a web session's toolbar — its three commands; the remote webview —
//!   nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

use crate::commands::connect_web::capability_isolation_tests::{files_under, glob_match};

#[path = "../build_support/app_commands.rs"]
mod app_commands;

const TOKEN: &str = "sess_0123456789abcdef0123456789abcdef";

/// What the session windows may call, pinned. A change here is a change to
/// a security boundary: it belongs in the same commit as the frontend code
/// that needs it, the set in `permissions/window-sets.json`, and the spec.
const SESSION_WINDOW: &[&str] = &[
    "get_session_workspace_prefs",
    "rustion_session_kill",
    "rustion_session_renew",
    "session_attach_rdp_frames",
    "session_close",
    "session_heartbeat",
    "session_input",
    "session_input_rdp_key",
    "session_input_rdp_mouse",
    "session_input_rdp_resize",
    "session_input_rdp_wheel",
    "session_move",
    "session_resize",
    "session_rustion_info",
];

/// The workspace: everything above, plus the listing, the saved layout,
/// and the normal connect path its palette and restore use.
const WORKSPACE_EXTRA: &[&str] = &[
    "connect_mfa_begin",
    "connect_mfa_verify_fido2",
    "connect_mfa_verify_totp",
    "list_resources",
    "read_resource",
    "resource_types_read",
    "session_layout_forget",
    "session_layout_get",
    "session_layout_save",
    "session_list_open",
    "session_open_rdp",
    "session_open_ssh",
    "session_open_web",
];

const REPLAY_WINDOW: &[&str] = &[
    "rustion_recording_blob",
    "rustion_recording_blob_chunk",
    "rustion_recording_read",
    "rustion_recording_replay_log",
];

const WEB_TOOLBAR: &[&str] = &["web_chrome_disconnect", "web_chrome_relogin", "web_chrome_state"];

/// Commands no session window may ever reach: the vault token and logins,
/// secret and credential reads, resource and policy writes, admin and
/// export surfaces, and the main-window-only session controls. Each is
/// outside every session set today; listing them makes a widening that
/// reaches one fail by name, not just as a set mismatch.
const NEVER_IN_A_SESSION_WINDOW: &[&str] = &[
    "get_current_token",
    "login_token",
    "login_userpass",
    "remote_login_token",
    "remote_login_userpass",
    "logout",
    "token_status",
    "list_secrets",
    "read_secret",
    "write_secret",
    "read_resource_secret",
    "list_resource_secrets",
    "write_resource",
    "delete_resource",
    "read_file_content",
    "read_local_file_b64",
    "totp_get_code",
    "ldap_read_static_cred",
    "ldap_check_out",
    "ssh_creds",
    "ssh_sign",
    "pki_issue_cert",
    "pki_export_cert",
    "backup_export",
    "exchange_export",
    "write_policy",
    "plugins_invoke",
    "save_preferences",
    "set_session_workspace_prefs",
    "session_workspace_open",
    "session_attach",
    "session_detach",
    "rustion_open_replay_window",
    "fido2_submit_pin",
];

/// The main window's plugin permissions before T110, unchanged by it.
const MAIN_PLUGIN_PERMISSIONS: &[&str] = &[
    "core:default",
    "core:window:allow-close",
    "core:window:allow-minimize",
    "core:window:allow-set-fullscreen",
    "core:window:allow-start-dragging",
    "core:window:allow-toggle-maximize",
    "dialog:allow-open",
    "dialog:allow-save",
    "shell:allow-open",
];

fn manifest_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn registered() -> Vec<String> {
    let lib_rs = std::fs::read_to_string(manifest_path("src/lib.rs")).unwrap();
    app_commands::registered_commands(&lib_rs).unwrap()
}

/// The shipped capabilities and the app's permission sets, as Tauri reads
/// them.
struct Acl {
    /// `(source file, capability)`.
    capabilities: Vec<(String, Value)>,
    /// Set identifier → its permissions.
    sets: BTreeMap<String, Vec<String>>,
    /// `allow-<slug>` → command, for every registered command.
    allows: BTreeMap<String, String>,
}

impl Acl {
    fn load() -> Self {
        let mut capabilities = Vec::new();
        let mut files = Vec::new();
        files_under(&manifest_path("capabilities"), &mut files);
        for file in files {
            let value = read_json(&file);
            let source = file.display().to_string();
            // The dev-only MCP bridge capability (written by build.rs under
            // `mcp_local_dev`, never shipped) grants a plugin permission to
            // `main` / `ssh-*` / `rdp-*`. Leave it out so these tests pin the
            // shipped ACL in a dev build too; `capability_isolation_tests`
            // still checks it.
            if value.get("identifier").and_then(Value::as_str) == Some("mcp-bridge") {
                continue;
            }
            match value.get("capabilities").and_then(Value::as_array) {
                Some(list) => capabilities.extend(list.iter().map(|c| (source.clone(), c.clone()))),
                None => capabilities.push((source, value)),
            }
        }

        // Every permission file the app manifest picks up, minus Tauri's
        // per-command `allow-`/`deny-` files (modelled by `allows`).
        let mut sets = BTreeMap::new();
        let mut files = Vec::new();
        files_under(&manifest_path("permissions"), &mut files);
        for file in files {
            let path = file.display().to_string();
            if file.components().any(|c| c.as_os_str() == "autogenerated" || c.as_os_str() == "schemas") {
                continue;
            }
            assert_eq!(
                file.extension().and_then(|e| e.to_str()),
                Some("json"),
                "{path}: non-JSON permission file — teach window_acl_tests to parse it"
            );
            let value = read_json(&file);
            assert!(value.get("permission").is_none(), "{path}: inline permissions — model them here first");
            for set in value["set"].as_array().unwrap_or_else(|| panic!("{path}: no `set` list")) {
                let id = set["identifier"].as_str().unwrap().to_string();
                let perms = set["permissions"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string());
                assert!(sets.insert(id.clone(), perms.collect()).is_none(), "{path}: set `{id}` defined twice");
            }
        }

        let allows = registered().into_iter().map(|c| (app_commands::allow_permission(&c), c)).collect();
        Acl { capabilities, sets, allows }
    }

    /// App commands a permission identifier grants (sets expanded).
    fn expand(&self, permission: &str, out: &mut BTreeSet<String>) {
        assert!(!permission.contains(':'), "plugin permission `{permission}` inside an app set");
        if let Some(command) = self.allows.get(permission) {
            out.insert(command.clone());
        } else if let Some(set) = self.sets.get(permission) {
            for p in set {
                self.expand(p, out);
            }
        } else {
            panic!("`{permission}` is neither a registered command's allow permission nor an app set");
        }
    }

    fn matching<'a>(&'a self, window: &'a str, webview: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.capabilities.iter().map(|(_, cap)| cap).filter(move |cap| {
            let any = |key: &str, label: &str| {
                cap.get(key)
                    .and_then(Value::as_array)
                    .is_some_and(|list| list.iter().any(|p| glob_match(p.as_str().unwrap(), label)))
            };
            any("windows", window) || any("webviews", webview)
        })
    }

    /// The app commands a webview may call: those of every capability
    /// matching its window or webview label.
    fn app_commands(&self, window: &str, webview: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for cap in self.matching(window, webview) {
            for p in cap["permissions"].as_array().unwrap() {
                let p = p.as_str().unwrap();
                if !p.contains(':') {
                    self.expand(p, &mut out);
                }
            }
        }
        out
    }

    /// The plugin (`core:`, `shell:`, …) permissions a webview gets.
    fn plugin_permissions(&self, window: &str, webview: &str) -> BTreeSet<String> {
        self.matching(window, webview)
            .flat_map(|cap| cap["permissions"].as_array().unwrap().iter())
            .map(|p| p.as_str().unwrap().to_string())
            .filter(|p| p.contains(':'))
            .collect()
    }

    fn window(&self, label: &str) -> BTreeSet<String> {
        self.app_commands(label, label)
    }
}

fn set_of(lists: &[&[&str]]) -> BTreeSet<String> {
    lists.iter().flat_map(|l| l.iter()).map(|s| s.to_string()).collect()
}

fn session_window_labels() -> Vec<String> {
    vec![format!("ssh-{TOKEN}"), format!("rdp-{TOKEN}")]
}

#[test]
fn the_command_list_is_read_from_the_handler() {
    let commands = registered();
    for known in ["session_input", "session_open_ssh", "read_secret", "get_current_token", "web_chrome_state"] {
        assert!(commands.iter().any(|c| c == known), "{known} missing from the parsed list");
    }
}

#[test]
fn the_parser_refuses_what_it_cannot_read() {
    let ok = "x.invoke_handler(tauri::generate_handler![\n  // c [1]\n  a::b_c,\n  d,\n]);";
    assert_eq!(app_commands::registered_commands(ok).unwrap(), ["b_c", "d"]);
    for bad in [
        "tauri::generate_handler![ #[cfg(x)] a::b ]",
        "tauri::generate_handler![ a::b, a::b ]",
        "tauri::generate_handler![ a::B ]",
        "tauri::generate_handler![ /* a */ a::b ]",
        "tauri::generate_handler![ m!(x) ]",
        "tauri::generate_handler![ a::b",
        "tauri::generate_handler![ ]",
        "no handler here",
        "tauri::generate_handler![a] tauri::generate_handler![b]",
    ] {
        assert!(app_commands::registered_commands(bad).is_err(), "accepted: {bad}");
    }
    assert_eq!(app_commands::allow_permission("session_open_ssh"), "allow-session-open-ssh");
}

/// build.rs writes the main window's set from the same list.
#[test]
fn the_generated_set_is_every_registered_command() {
    let acl = Acl::load();
    let generated = acl.sets.get("app-all-commands").expect("permissions/generated/app-all-commands.json");
    let expected: Vec<String> = registered().iter().map(|c| app_commands::allow_permission(c)).collect();
    assert_eq!(generated, &expected);
}

#[test]
fn the_main_window_keeps_every_command_and_its_plugin_permissions() {
    let acl = Acl::load();
    let all: BTreeSet<String> = registered().into_iter().collect();
    assert_eq!(acl.window("main"), all);
    assert_eq!(acl.plugin_permissions("main", "main"), set_of(&[MAIN_PLUGIN_PERMISSIONS]));
}

/// Unchanged by T110 and not narrowed here: a plugin window loads the full
/// vault UI (`index.html#/plugin/…`). Narrowing it is a separate change.
#[test]
fn plugin_windows_keep_every_command() {
    let acl = Acl::load();
    let all: BTreeSet<String> = registered().into_iter().collect();
    assert_eq!(acl.window("plugin-acme-main"), all);
}

#[test]
fn a_session_window_gets_exactly_its_set() {
    let acl = Acl::load();
    for label in session_window_labels() {
        assert_eq!(acl.window(&label), set_of(&[SESSION_WINDOW]), "{label}");
        let plugin = acl.plugin_permissions(&label, &label);
        assert_eq!(plugin, set_of(&[&["core:event:allow-listen", "core:event:allow-unlisten"]]), "{label}");
    }
}

#[test]
fn the_workspace_gets_exactly_its_set() {
    let acl = Acl::load();
    let label = crate::session::workspace::WORKSPACE_WINDOW_LABEL;
    assert_eq!(acl.window(label), set_of(&[SESSION_WINDOW, WORKSPACE_EXTRA]));
    assert_eq!(
        acl.plugin_permissions(label, label),
        set_of(&[&["core:event:allow-listen", "core:event:allow-unlisten", "core:window:allow-close"]])
    );
}

#[test]
fn a_replay_window_gets_exactly_its_set() {
    let acl = Acl::load();
    assert_eq!(acl.window("replay-rec_01"), set_of(&[REPLAY_WINDOW]));
    assert!(acl.plugin_permissions("replay-rec_01", "replay-rec_01").is_empty());
}

#[test]
fn the_web_toolbar_gets_its_three_commands_and_the_remote_webview_nothing() {
    let acl = Acl::load();
    let window = format!("{}{TOKEN}", crate::session::web::WINDOW_LABEL_PREFIX);
    let toolbar = crate::session::web_chrome::chrome_label(TOKEN);
    assert_eq!(acl.app_commands(&window, &toolbar), set_of(&[WEB_TOOLBAR]));
    assert!(acl.plugin_permissions(&window, &toolbar).is_empty());
    assert!(acl.app_commands(&window, &window).is_empty());
    assert!(acl.plugin_permissions(&window, &window).is_empty());
}

#[test]
fn no_session_window_reaches_a_sensitive_command() {
    let acl = Acl::load();
    let all: BTreeSet<String> = registered().into_iter().collect();
    let mut labels = session_window_labels();
    labels.push(crate::session::workspace::WORKSPACE_WINDOW_LABEL.to_string());
    labels.push("replay-rec_01".to_string());
    for label in labels {
        let granted = acl.window(&label);
        for command in NEVER_IN_A_SESSION_WINDOW {
            assert!(all.contains(*command), "`{command}` is no longer registered — update this list");
            assert!(!granted.contains(*command), "{label} may call `{command}`");
        }
    }
}

#[test]
fn an_unknown_window_gets_nothing() {
    let acl = Acl::load();
    for label in ["evil", "workspace", "session-workspace2", "sessions", "replay", "ssh", "web-x"] {
        assert!(acl.window(label).is_empty(), "{label}");
        assert!(acl.plugin_permissions(label, label).is_empty(), "{label}");
    }
}

/// Tauri 2.11 refuses a command in *every* window as soon as any capability
/// denies it (`resolve_access` checks `denied_commands.get(cmd)` without the
/// window), so a `deny-` meant to narrow a session window would cut the
/// main window off too. Narrow by omission only.
#[test]
fn no_capability_or_set_uses_a_deny_permission() {
    let acl = Acl::load();
    for (source, cap) in &acl.capabilities {
        for p in cap["permissions"].as_array().unwrap() {
            let p = p.as_str().unwrap();
            assert!(!p.contains("deny-"), "{source}: `{p}`");
        }
    }
    for (id, perms) in &acl.sets {
        for p in perms {
            assert!(!p.starts_with("deny-"), "set `{id}`: `{p}`");
        }
    }
}

/// Every window that renders a session or a recording loads the
/// session-only bundle, at a route that bundle mounts.
#[test]
fn session_windows_load_the_session_page_at_a_session_route() {
    use crate::session::attachments::SessionDescriptor;
    use crate::session::workspace::{Placement, SESSION_PAGE, WORKSPACE_WINDOW_URL};
    use crate::session::ProfileProtocol;

    let app = std::fs::read_to_string(manifest_path("../src/sessionApp/SessionApp.tsx")).unwrap();
    let mounted = |route: &str| app.contains(&format!("path: \"{route}\""));

    let descriptor = |protocol| SessionDescriptor {
        token: TOKEN.into(),
        protocol,
        label: "op@host".into(),
        resource_name: "web01".into(),
        profile_id: "cp_1".into(),
        stdout_event: Some("out".into()),
        closed_event: "closed".into(),
        resize_event: Some("resize".into()),
        cursor_event: Some("cursor".into()),
        width: Some(1024),
        height: Some(768),
        opened_at: "2026-10-07T12:00:00Z".into(),
        placement: Placement::OwnWindow,
        pane_ref: None,
        namespace: String::new(),
        vault_id: "v1".into(),
    };
    let urls = [
        (WORKSPACE_WINDOW_URL.to_string(), "/workspace"),
        (crate::commands::connect::own_window_url(&descriptor(ProfileProtocol::Ssh)), "/session/ssh"),
        (crate::commands::connect::own_window_url(&descriptor(ProfileProtocol::Rdp)), "/session/rdp"),
        (crate::commands::rustion::replay_window_url("rec_01", Some(5)), "/session-replay"),
    ];
    for (url, route) in urls {
        let (page, fragment) = url.split_once('#').unwrap();
        assert_eq!(page, SESSION_PAGE, "{url}");
        let path = fragment.split('?').next().unwrap();
        assert_eq!(path, route, "{url}");
        assert!(mounted(route), "session.html does not mount {route}");
    }

    // The page exists, is a build entry, and loads the session bundle.
    let html = std::fs::read_to_string(manifest_path(&format!("../{SESSION_PAGE}"))).unwrap();
    assert!(html.contains("src=\"/src/sessionApp/main.tsx\""), "{SESSION_PAGE} does not load the session entry");
    let vite = std::fs::read_to_string(manifest_path("../vite.config.ts")).unwrap();
    assert!(vite.contains(&format!("\"./{SESSION_PAGE}\"")), "vite.config.ts does not build {SESSION_PAGE}");
}

/// The model above against Tauri's own resolver, on the exact inputs the
/// build handed `generate_context!` (`OUT_DIR`): for every registered
/// command and every kind of window, Tauri allows it exactly when the model
/// says so — and the plugin commands the session windows use are allowed,
/// while the ones they do not use are not.
#[test]
fn tauri_resolves_the_same_acl_from_the_build_inputs() {
    use tauri::utils::acl::capability::Capability;
    use tauri::utils::acl::manifest::Manifest;
    use tauri::utils::acl::resolved::Resolved;
    use tauri::utils::acl::ExecutionContext;
    use tauri::utils::platform::Target;

    let out = Path::new(env!("OUT_DIR"));
    let read = |name: &str| std::fs::read_to_string(out.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    let manifests: BTreeMap<String, Manifest> = serde_json::from_str(&read("acl-manifests.json")).unwrap();
    let capabilities: BTreeMap<String, Capability> = serde_json::from_str(&read("capabilities.json")).unwrap();
    let resolved = Resolved::resolve(&manifests, capabilities, Target::current()).unwrap();

    // The app ACL is on, and nothing is denied anywhere (see
    // `no_capability_or_set_uses_a_deny_permission`).
    assert!(resolved.has_app_acl);
    assert!(resolved.denied_commands.is_empty(), "{:?}", resolved.denied_commands.keys());

    // `RuntimeAuthority::resolve_access` for a local origin.
    let allowed = |command: &str, window: &str, webview: &str| {
        resolved.allowed_commands.get(command).is_some_and(|list| {
            list.iter().any(|c| {
                c.context == ExecutionContext::Local
                    && (c.webviews.iter().any(|p| p.matches(webview)) || c.windows.iter().any(|p| p.matches(window)))
            })
        })
    };

    let acl = Acl::load();
    let web_window = format!("{}{TOKEN}", crate::session::web::WINDOW_LABEL_PREFIX);
    let toolbar = crate::session::web_chrome::chrome_label(TOKEN);
    let mut views: Vec<(String, String)> = ["main", "plugin-acme-main", "session-workspace", "replay-rec_01", "evil"]
        .iter()
        .map(|l| (l.to_string(), l.to_string()))
        .collect();
    views.extend(session_window_labels().into_iter().map(|l| (l.clone(), l)));
    views.push((web_window.clone(), web_window.clone()));
    views.push((web_window.clone(), toolbar.clone()));
    for command in registered() {
        for (window, webview) in &views {
            assert_eq!(
                allowed(&command, window, webview),
                acl.app_commands(window, webview).contains(&command),
                "`{command}` for window `{window}` / webview `{webview}`"
            );
        }
    }

    for label in session_window_labels() {
        assert!(allowed("plugin:event|listen", &label, &label));
        assert!(allowed("plugin:event|unlisten", &label, &label));
        for denied in ["plugin:window|close", "plugin:event|emit", "plugin:shell|open", "plugin:dialog|open"] {
            assert!(!allowed(denied, &label, &label), "{label}: {denied}");
        }
    }
    let ws = crate::session::workspace::WORKSPACE_WINDOW_LABEL;
    assert!(allowed("plugin:event|listen", ws, ws));
    assert!(allowed("plugin:window|close", ws, ws));
    for denied in ["plugin:event|emit", "plugin:shell|open", "plugin:window|set_title", "plugin:webview|create_webview"] {
        assert!(!allowed(denied, ws, ws), "{denied}");
    }
    for denied in ["plugin:event|listen", "plugin:window|close"] {
        assert!(!allowed(denied, "replay-rec_01", "replay-rec_01"), "{denied}");
        assert!(!allowed(denied, &web_window, &toolbar), "toolbar: {denied}");
    }
    // The main window keeps its plugin surface.
    for kept in ["plugin:event|listen", "plugin:window|close", "plugin:shell|open", "plugin:dialog|save"] {
        assert!(allowed(kept, "main", "main"), "{kept}");
    }
}
