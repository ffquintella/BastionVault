//! Session settings: which `SET`s are harmless, which need `sql_admin`, and
//! which are never allowed because they would change how the classifier
//! must lex the next statement or lift the read-only guard (§4.2, §4.3,
//! §5.3). Setting names are case-insensitive, as the server's are.

use crate::model::{Reason, SqlCapability};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    /// Allow-listed: `sql_select` on `sql/server`.
    Allowed,
    /// Any other setting: `sql_admin` on `sql/server`.
    Admin,
    /// Never: changes how statements are lexed.
    Lexer,
    /// Never: changes the read-only transaction guard.
    ReadOnlyGuard,
}

/// Settings that change how the server lexes later statements. A statement
/// that sets one would desynchronise the classifier from the server.
const LEXER_AFFECTING: &[&str] = &["standard_conforming_strings", "backslash_quote", "client_encoding"];

/// The read-only guard the plugin sets at connect time (§5.3).
const READ_ONLY_GUARD: &[&str] = &["default_transaction_read_only", "transaction_read_only"];

/// Session settings any SQL user may change (§4.2's allow-list, PostgreSQL
/// part). None of them affects lexing, privileges or the guards.
const ALLOWED: &[&str] = &[
    "search_path",
    "timezone",
    "datestyle",
    "intervalstyle",
    "application_name",
    "extra_float_digits",
    "bytea_output",
    "client_min_messages",
    "transaction_isolation",
    "default_transaction_isolation",
];

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

/// The capability a setting change needs, or why it is refused.
pub(crate) fn requirement(name: &str) -> Result<SqlCapability, Reason> {
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
    fn names_are_case_insensitive() {
        assert_eq!(classify("Standard_Conforming_Strings"), Setting::Lexer);
        assert_eq!(classify("SEARCH_PATH"), Setting::Allowed);
        assert_eq!(classify("Default_Transaction_Read_Only"), Setting::ReadOnlyGuard);
        assert_eq!(classify("statement_timeout"), Setting::Admin);
        assert_eq!(classify("role"), Setting::Admin);
    }
}
