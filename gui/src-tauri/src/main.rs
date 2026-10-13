#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `--mcp-stdio`: an AI assistant launched this binary as its MCP server.
    // Relay to the running app's socket and exit -- no window, no Tauri.
    if let Some(code) = bastion_vault_gui::mcp_stdio_relay(std::env::args_os().collect()) {
        std::process::exit(code);
    }
    bastion_vault_gui::run();
}
