//! `ALTER SESSION SET` parameters: which are harmless, which need
//! `sql_admin`, and which never run (§4.2, §4.3). No Oracle session
//! parameter changes how the classifier must lex the next statement, so
//! none is refused for that; `CONTAINER` is refused because it moves the
//! session off the service the credential and the paths are bound to.

use crate::model::{Reason, SqlCapability};

/// The capability one parameter change needs, or why it is refused. `name`
/// is the parameter as written, unquoted text lower-cased by the caller.
/// `CURRENT_SCHEMA` (the caller re-reads it after), `NLS_*`, `TIME_ZONE`
/// and `ISOLATION_LEVEL` change name defaults, formats, comparisons or
/// locking, never lexing or identifier case: `sql_select`. Everything else
/// (`EDITION`, `EVENTS`, `SQL_TRACE`, hidden `"_…"` parameters, optimizer
/// and diagnostic settings) is `sql_admin`.
pub(crate) fn requirement(name: &str, quoted: bool) -> Result<SqlCapability, Reason> {
    let lower = name.to_ascii_lowercase();
    if lower == "container" {
        return Err(Reason::SessionScopeChange);
    }
    let allowed =
        matches!(lower.as_str(), "current_schema" | "time_zone" | "isolation_level") || lower.starts_with("nls_");
    if allowed && !quoted {
        Ok(SqlCapability::Select)
    } else {
        Ok(SqlCapability::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters() {
        assert_eq!(requirement("container", false), Err(Reason::SessionScopeChange));
        assert_eq!(requirement("CONTAINER", true), Err(Reason::SessionScopeChange));
        for p in ["current_schema", "NLS_DATE_FORMAT", "nls_sort", "time_zone", "isolation_level"] {
            assert_eq!(requirement(p, false), Ok(SqlCapability::Select), "{p}");
        }
        for p in ["edition", "events", "sql_trace", "optimizer_mode", "statistics_level"] {
            assert_eq!(requirement(p, false), Ok(SqlCapability::Admin), "{p}");
        }
        assert_eq!(requirement("_hidden_param", true), Ok(SqlCapability::Admin));
        assert_eq!(requirement("NLS_SORT", true), Ok(SqlCapability::Admin));
    }
}
