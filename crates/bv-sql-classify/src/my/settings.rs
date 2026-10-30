//! MySQL / MariaDB session variables: which `SET`s are harmless, which need
//! `sql_admin`, and which never run because they change how the classifier
//! must lex the next statement or lift the read-only guard (§4.2, §4.3,
//! §5.3). Variable names are case-insensitive, as the server's are.

use crate::model::{Reason, SqlCapability};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    Allowed,
    Admin,
    Lexer,
    ReadOnlyGuard,
}

/// Variables that change how the server lexes later statements or encodes
/// what it returns: the classifier and the value decoder depend on them.
const LEXER_AFFECTING: &[&str] = &[
    "sql_mode",
    "character_set_client",
    "character_set_connection",
    "character_set_results",
    "collation_connection",
    "names",
    "character set",
    "charset",
];

/// The read-only guard the plugin sets at connect time (§5.3).
const READ_ONLY_GUARD: &[&str] = &["transaction_read_only", "tx_read_only"];

/// Session variables any SQL user may change. None of them affects lexing,
/// privileges, integrity checks, logging or the guards.
const ALLOWED: &[&str] = &[
    "time_zone",
    "transaction_isolation",
    "tx_isolation",
    "lc_time_names",
    "group_concat_max_len",
    "div_precision_increment",
    "sql_safe_updates",
    "sql_select_limit",
    "sql_notes",
    "sql_warnings",
    "sql_big_selects",
];

/// The variable name as the server looks it up: `@@`, a scope prefix
/// (`session.`, `local.`) and case removed. `None` for a global scope.
pub(crate) fn session_name(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let name = lower.strip_prefix("@@").unwrap_or(&lower);
    for global in ["global.", "persist.", "persist_only."] {
        if name.starts_with(global) {
            return None;
        }
    }
    let name = name.strip_prefix("session.").or_else(|| name.strip_prefix("local.")).unwrap_or(name);
    Some(name.to_string())
}

pub(crate) fn classify(name: &str) -> Setting {
    let name = name.to_ascii_lowercase();
    if LEXER_AFFECTING.contains(&name.as_str()) {
        Setting::Lexer
    } else if READ_ONLY_GUARD.contains(&name.as_str()) {
        Setting::ReadOnlyGuard
    } else if ALLOWED.contains(&name.as_str()) {
        Setting::Allowed
    } else {
        Setting::Admin
    }
}

/// The capability a session-scope change needs, or why it is refused.
/// Global changes (`GLOBAL`, `PERSIST`) are `sql_admin` whatever the name:
/// they do not reach the session that makes them.
pub(crate) fn requirement(name: &str, global: bool) -> Result<SqlCapability, Reason> {
    if global {
        return Ok(SqlCapability::Admin);
    }
    match classify(name) {
        Setting::Allowed => Ok(SqlCapability::Select),
        Setting::Admin => Ok(SqlCapability::Admin),
        Setting::Lexer => Err(Reason::LexerSettingChange),
        Setting::ReadOnlyGuard => Err(Reason::ReadOnlyGuardChange),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_scopes() {
        assert_eq!(session_name("@@SESSION.SQL_MODE").as_deref(), Some("sql_mode"));
        assert_eq!(session_name("@@local.time_zone").as_deref(), Some("time_zone"));
        assert_eq!(session_name("@@sql_mode").as_deref(), Some("sql_mode"));
        assert_eq!(session_name("Sql_Mode").as_deref(), Some("sql_mode"));
        assert_eq!(session_name("@@global.sql_mode"), None);
        assert_eq!(session_name("@@persist_only.x"), None);
        assert_eq!(classify("SQL_MODE"), Setting::Lexer);
        assert_eq!(classify("tx_read_only"), Setting::ReadOnlyGuard);
        assert_eq!(classify("time_zone"), Setting::Allowed);
        assert_eq!(classify("foreign_key_checks"), Setting::Admin);
        assert_eq!(classify("autocommit"), Setting::Admin);
        assert_eq!(requirement("sql_mode", true), Ok(SqlCapability::Admin));
        assert_eq!(requirement("sql_mode", false), Err(Reason::LexerSettingChange));
        assert_eq!(requirement("transaction_read_only", false), Err(Reason::ReadOnlyGuardChange));
    }
}
