use std::path::Path;

fn main() {
    // The `tauri-plugin-mcp-bridge` plugin is feature-gated behind
    // `mcp_local_dev` (see CLAUDE.md / agent.md "Local Tauri MCP
    // Bridge"). When the feature is *off*, the plugin isn't compiled
    // in and its permission schema (`mcp-bridge:default`) isn't
    // discoverable — referencing it from a capability file would
    // fail the Tauri build. So the bridge's capability lives in a
    // separate file that we materialize only under the dev feature
    // and delete otherwise, keeping a single source of truth in this
    // crate.
    let cap_path = Path::new("capabilities").join("mcp-bridge.json");
    if cfg!(feature = "mcp_local_dev") {
        let body = r#"{
  "$schema": "https://raw.githubusercontent.com/nicerdicer/tauri-docs/refs/heads/v2/tooling/cli/schema.json",
  "identifier": "mcp-bridge",
  "description": "Local Tauri MCP bridge — dev-only. Gated by the `mcp_local_dev` Cargo feature and `BASTION_TAURI_MCP=1` at runtime.",
  "local": true,
  "windows": ["main", "ssh-*", "rdp-*"],
  "permissions": ["mcp-bridge:default"]
}
"#;
        // Write only if contents differ so we don't bump mtime and
        // re-run Tauri's permission resolver on every build.
        let needs_write = match std::fs::read_to_string(&cap_path) {
            Ok(existing) => existing != body,
            Err(_) => true,
        };
        if needs_write {
            std::fs::write(&cap_path, body).expect("write mcp-bridge capability");
        }
    } else if cap_path.exists() {
        std::fs::remove_file(&cap_path).expect("remove stale mcp-bridge capability");
    }
    println!("cargo:rerun-if-changed=build.rs");

    tauri_build::build();
}
