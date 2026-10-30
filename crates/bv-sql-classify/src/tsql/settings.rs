//! SQL Server `SET` options: which are harmless, which need `sql_admin`,
//! and which never run because they change how the classifier must read the
//! next statement (§4.2, §4.3). Option names are case-insensitive.

use crate::model::{Reason, SqlCapability};

/// Options that change what `"…"` means (`ANSI_DEFAULTS` turns
/// `QUOTED_IDENTIFIER` on with the rest of the ANSI group).
const LEXER_AFFECTING: &[&str] = &["quoted_identifier", "ansi_defaults"];

/// Options any SQL user may change: output, locking waits, date reading and
/// statistics. None changes lexing, privileges, logging or what a later
/// statement runs as.
const ALLOWED: &[&str] = &[
    "nocount",
    "dateformat",
    "datefirst",
    "language",
    "lock_timeout",
    "deadlock_priority",
    "textsize",
    "xact_abort",
    "arithabort",
    "arithignore",
    "ansi_warnings",
    "ansi_nulls",
    "ansi_padding",
    "ansi_null_dflt_on",
    "ansi_null_dflt_off",
    "concat_null_yields_null",
    "numeric_roundabort",
    "statistics",
    "rowcount",
];

/// The capability one session option change needs, or why it is refused.
/// Unknown options are `sql_admin` (`IDENTITY_INSERT`, `CONTEXT_INFO`,
/// `IMPLICIT_TRANSACTIONS`, `FMTONLY`, `SHOWPLAN_*` …).
pub(crate) fn requirement(name: &str) -> Result<SqlCapability, Reason> {
    let name = name.to_ascii_lowercase();
    if LEXER_AFFECTING.contains(&name.as_str()) {
        Err(Reason::LexerSettingChange)
    } else if ALLOWED.contains(&name.as_str()) {
        Ok(SqlCapability::Select)
    } else {
        Ok(SqlCapability::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        assert_eq!(requirement("QUOTED_IDENTIFIER"), Err(Reason::LexerSettingChange));
        assert_eq!(requirement("Ansi_Defaults"), Err(Reason::LexerSettingChange));
        assert_eq!(requirement("NOCOUNT"), Ok(SqlCapability::Select));
        assert_eq!(requirement("implicit_transactions"), Ok(SqlCapability::Admin));
        assert_eq!(requirement("context_info"), Ok(SqlCapability::Admin));
    }
}
