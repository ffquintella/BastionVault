//! The app commands this crate registers, read from the
//! `tauri::generate_handler![…]` list in `src/lib.rs` (T110,
//! features/session-workspace.md).
//!
//! Shared by `build.rs`, which hands the list to Tauri as the app's ACL
//! manifest, and by the crate's own tests (`window_acl_tests`), which check
//! the capabilities against the same list. Deriving it from the handler
//! list — rather than keeping a second copy — is what keeps the main
//! window's grant equal to "every registered command": a command added to
//! `generate_handler!` is allowed for `main` and refused everywhere else
//! until a session set names it.
//!
//! The parser is deliberately strict. Anything in the list other than
//! `path::to::command,` entries and `//` comments — an attribute, a block
//! comment, a macro — is an error naming the item, so a change to the list
//! that this code cannot read fails the build instead of silently dropping
//! a command from the ACL (which would make it unreachable from every
//! window).

/// The marker that opens the handler list in `src/lib.rs`.
const HANDLER_OPEN: &str = "tauri::generate_handler![";

/// Every command name in the `generate_handler!` list of `lib_rs`, in
/// order: the last path segment of each entry, which is the name Tauri
/// registers and the frontend `invoke`s.
pub fn registered_commands(lib_rs: &str) -> Result<Vec<String>, String> {
    let mut opens = lib_rs.match_indices(HANDLER_OPEN);
    let (start, _) = opens.next().ok_or_else(|| format!("`{HANDLER_OPEN}` not found in src/lib.rs"))?;
    if opens.next().is_some() {
        return Err(format!("more than one `{HANDLER_OPEN}` in src/lib.rs"));
    }
    // The list's code, comments stripped, up to the closing `]`. Scanned a
    // line at a time so a `]` inside a comment does not end it.
    let mut code = String::new();
    let mut closed = false;
    for line in lib_rs[start + HANDLER_OPEN.len()..].lines() {
        let line = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        let (line, end) = match line.find(']') {
            Some(i) => (&line[..i], true),
            None => (line, false),
        };
        if line.contains("/*") || line.contains('#') || line.contains('[') || line.contains('!') {
            return Err(format!(
                "unsupported syntax in the `generate_handler!` list: `{}` — teach build_support/app_commands.rs \
                 to read it",
                line.trim()
            ));
        }
        code.push_str(line);
        code.push('\n');
        if end {
            closed = true;
            break;
        }
    }
    if !closed {
        return Err("unterminated `generate_handler![` list".to_string());
    }

    let mut commands: Vec<String> = Vec::new();
    for item in code.split(',') {
        let path = item.trim();
        if path.is_empty() {
            continue;
        }
        let segments: Vec<&str> = path.split("::").map(str::trim).collect();
        if segments.iter().any(|s| !is_identifier(s)) {
            return Err(format!("`{path}` in the `generate_handler!` list is not a plain path"));
        }
        let name = segments.last().copied().unwrap_or_default();
        // Tauri derives the permission identifiers `allow-<name>` /
        // `deny-<name>` with `_` → `-`, and identifiers are lowercase ASCII.
        if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(format!("command `{name}` is not lowercase snake_case"));
        }
        if commands.iter().any(|c| c == name) {
            return Err(format!("command `{name}` is registered twice"));
        }
        commands.push(name.to_string());
    }
    if commands.is_empty() {
        return Err("the `generate_handler!` list is empty".to_string());
    }
    Ok(commands)
}

/// `allow-<command>`: the permission Tauri generates for an app command.
pub fn allow_permission(command: &str) -> String {
    format!("allow-{}", command.replace('_', "-"))
}

fn is_identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
