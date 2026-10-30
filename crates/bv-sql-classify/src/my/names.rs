//! Canonical MySQL / MariaDB names (features/sql-browser.md §3.2, §4.4).
//!
//! The catalog is always `def`; the schema is the database. Quoting does not
//! change case: database and table names compare as written when
//! `lower_case_table_names` is 0 and in lower case otherwise; routine names
//! always compare case-insensitively.

// A name whose folding the server could do differently (non-ASCII under
// folding) is refused rather than guessed (§4.4: a name that cannot be
// normalized unambiguously matches no object-scoped rule).

use sqlparser::ast::{Ident, ObjectName, ObjectNamePart};

use crate::model::{NameContext, ObjectKind, ObjectRef, Reason};

pub(crate) struct Names<'a> {
    pub ctx: &'a NameContext,
    /// `lower_case_table_names` is 1 or 2.
    pub fold_tables: bool,
    /// The server is MariaDB (sequences, its function table).
    pub mariadb: bool,
}

/// The text of one identifier as written: unquoted or backtick-quoted.
pub(crate) fn raw_ident(id: &Ident) -> Result<&str, Reason> {
    if id.value.is_empty() {
        return Err(Reason::UnresolvableName);
    }
    match id.quote_style {
        None | Some('`') => Ok(&id.value),
        Some(_) => Err(Reason::UnsupportedConstruct),
    }
}

impl Names<'_> {
    /// A database or table name in canonical case.
    pub fn table_part(&self, s: &str) -> Result<String, Reason> {
        if s.is_empty() || s.len() > 64 * 4 {
            return Err(Reason::UnresolvableName);
        }
        if !self.fold_tables {
            return Ok(s.to_string());
        }
        if !s.is_ascii() {
            return Err(Reason::UnresolvableName);
        }
        Ok(s.to_ascii_lowercase())
    }

    /// A routine name in canonical case (always case-insensitive).
    pub fn routine_part(&self, s: &str) -> Result<String, Reason> {
        if s.is_empty() || !s.is_ascii() {
            return Err(Reason::UnresolvableName);
        }
        Ok(s.to_ascii_lowercase())
    }

    /// The raw parts of a dotted name, refusing a reserved word the parser
    /// took for a name (the server would never read it so).
    pub fn raw_parts<'n>(&self, name: &'n ObjectName) -> Result<Vec<&'n str>, Reason> {
        name.0
            .iter()
            .map(|p| match p {
                ObjectNamePart::Identifier(id) => {
                    if id.quote_style.is_none() && reserved(&id.value.to_ascii_lowercase()) {
                        return Err(Reason::ReservedWordAsName);
                    }
                    raw_ident(id)
                }
                ObjectNamePart::Function(_) => Err(Reason::UnresolvableName),
            })
            .collect()
    }

    /// `[db.]name` from raw parts. An unqualified name is in the current
    /// database; with none selected the server refuses, and so does this.
    pub fn resolve_raw(&self, kind: ObjectKind, parts: &[&str]) -> Result<ObjectRef, Reason> {
        let canon = |s: &str| match kind {
            ObjectKind::Routine => self.routine_part(s),
            _ => self.table_part(s),
        };
        let (schema, name) = match parts {
            [n] => (self.ctx.current_schema.clone().ok_or(Reason::UnresolvableName)?, canon(n)?),
            [db, n] => (self.table_part(db)?, canon(n)?),
            _ => return Err(Reason::UnresolvableName),
        };
        Ok(ObjectRef { kind, catalog: self.ctx.current_catalog.clone(), schema: Some(schema), name })
    }

    pub fn object(&self, kind: ObjectKind, name: &ObjectName) -> Result<ObjectRef, Reason> {
        self.resolve_raw(kind, &self.raw_parts(name)?)
    }

    /// The database part of a `USE`, `SHOW … FROM db` or `db.*`.
    pub fn database(&self, raw: &str) -> Result<String, Reason> {
        self.table_part(raw)
    }
}

/// MySQL 8.0 / MariaDB reserved words that can stand where the parser looks
/// for a table or routine name. Quoted, they are names; unquoted, the
/// server never reads them as one, so a parse that does is wrong.
const RESERVED: &[&str] = &[
    "accessible",
    "add",
    "all",
    "alter",
    "analyze",
    "and",
    "as",
    "asc",
    "before",
    "between",
    "both",
    "by",
    "call",
    "cascade",
    "case",
    "change",
    "check",
    "collate",
    "column",
    "condition",
    "constraint",
    "continue",
    "convert",
    "create",
    "cross",
    "cume_dist",
    "current_date",
    "current_time",
    "current_timestamp",
    "current_user",
    "cursor",
    "database",
    "databases",
    "declare",
    "default",
    "delayed",
    "delete",
    "dense_rank",
    "desc",
    "describe",
    "distinct",
    "distinctrow",
    "div",
    "drop",
    "dual",
    "each",
    "else",
    "elseif",
    "empty",
    "enclosed",
    "escaped",
    "except",
    "exists",
    "exit",
    "explain",
    "false",
    "fetch",
    "first_value",
    "for",
    "force",
    "foreign",
    "from",
    "fulltext",
    "generated",
    "get",
    "grant",
    "group",
    "grouping",
    "groups",
    "having",
    "high_priority",
    "if",
    "ignore",
    "in",
    "index",
    "infile",
    "inner",
    "inout",
    "insert",
    "interval",
    "intersect",
    "into",
    "is",
    "iterate",
    "join",
    "json_table",
    "key",
    "keys",
    "kill",
    "lag",
    "last_value",
    "lateral",
    "lead",
    "leading",
    "leave",
    "left",
    "like",
    "limit",
    "linear",
    "lines",
    "load",
    "localtime",
    "localtimestamp",
    "lock",
    "loop",
    "low_priority",
    "match",
    "modifies",
    "natural",
    "not",
    "no_write_to_binlog",
    "nth_value",
    "ntile",
    "null",
    "of",
    "on",
    "optimize",
    "option",
    "optionally",
    "or",
    "order",
    "out",
    "outer",
    "outfile",
    "over",
    "partition",
    "percent_rank",
    "primary",
    "procedure",
    "purge",
    "range",
    "rank",
    "read",
    "reads",
    "recursive",
    "references",
    "regexp",
    "release",
    "rename",
    "repeat",
    "replace",
    "require",
    "resignal",
    "restrict",
    "return",
    "returning",
    "revoke",
    "right",
    "rlike",
    "row",
    "row_number",
    "rows",
    "schema",
    "schemas",
    "select",
    "sensitive",
    "separator",
    "set",
    "show",
    "signal",
    "spatial",
    "specific",
    "sql",
    "sql_big_result",
    "sql_calc_found_rows",
    "sql_small_result",
    "ssl",
    "starting",
    "stored",
    "straight_join",
    "system",
    "table",
    "terminated",
    "then",
    "to",
    "trailing",
    "trigger",
    "true",
    "undo",
    "union",
    "unique",
    "unlock",
    "update",
    "usage",
    "use",
    "using",
    "utc_date",
    "utc_time",
    "utc_timestamp",
    "values",
    "virtual",
    "when",
    "where",
    "while",
    "window",
    "with",
    "write",
    "xor",
];

pub(crate) fn reserved(word: &str) -> bool {
    RESERVED.contains(&word)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(fold: bool, db: Option<&str>) -> (NameContext, bool) {
        (NameContext::mysql(db.map(str::to_string)), fold)
    }

    #[test]
    fn folding_follows_lower_case_table_names() {
        let (ctx, _) = n(false, Some("App"));
        let keep = Names { ctx: &ctx, fold_tables: false, mariadb: false };
        let r = keep.resolve_raw(ObjectKind::Relation, &["Users"]).unwrap();
        assert_eq!((r.catalog.as_str(), r.schema.as_deref(), r.name.as_str()), ("def", Some("App"), "Users"));
        let fold = Names { ctx: &ctx, fold_tables: true, mariadb: false };
        let r = fold.resolve_raw(ObjectKind::Relation, &["Sales", "Users"]).unwrap();
        assert_eq!((r.schema.as_deref(), r.name.as_str()), (Some("sales"), "users"));
        // Routine names compare without case either way.
        let r = keep.resolve_raw(ObjectKind::Routine, &["Fn"]).unwrap();
        assert_eq!(r.name, "fn");
        // Non-ASCII under folding is not guessed.
        assert_eq!(fold.resolve_raw(ObjectKind::Relation, &["Ação"]), Err(Reason::UnresolvableName));
        assert!(keep.resolve_raw(ObjectKind::Relation, &["Ação"]).is_ok());
    }

    #[test]
    fn unqualified_needs_a_current_database() {
        let (ctx, _) = n(false, None);
        let names = Names { ctx: &ctx, fold_tables: false, mariadb: false };
        assert_eq!(names.resolve_raw(ObjectKind::Relation, &["t"]), Err(Reason::UnresolvableName));
        assert!(names.resolve_raw(ObjectKind::Relation, &["db", "t"]).is_ok());
        assert_eq!(names.resolve_raw(ObjectKind::Relation, &["a", "b", "c"]), Err(Reason::UnresolvableName));
    }
}
