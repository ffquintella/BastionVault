//! Canonical Oracle names (features/sql-browser.md §3.2, §4.4). A path is
//! `<service>/<SCHEMA>/<OBJECT>`. Unquoted names fold to ASCII upper case,
//! as the server folds them; quoted names are kept exactly.

// An unquoted name holding non-ASCII is refused: the server upper-cases it
// with its own character-set rules, which this crate cannot follow, and a
// deny rule must not be dodged by a spelling that folds differently. A name
// over 128 bytes is an error to the server, so it is refused, never cut.

// Unqualified names: a new object goes to the current schema; an existing
// one is left to the caller (`schema: None`), which resolves it as the
// server does, through the current schema, then a `PUBLIC` synonym.

use sqlparser::ast::{Ident, ObjectName, ObjectNamePart};

use crate::model::{NameContext, ObjectKind, ObjectRef, Reason};

/// Oracle's identifier limit, in bytes (12.2 and later).
pub(crate) const MAX_NAME_BYTES: usize = 128;

/// One part of a dotted name, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    pub text: String,
    pub quoted: bool,
}

impl Part {
    pub fn unquoted(s: &str) -> Self {
        Self { text: s.to_string(), quoted: false }
    }

    pub fn quoted(s: &str) -> Self {
        Self { text: s.to_string(), quoted: true }
    }

    /// The canonical form: unquoted upper-cased (ASCII only), quoted as is.
    pub fn canon(&self) -> Result<String, Reason> {
        canon(&self.text, self.quoted)
    }

    /// The unquoted text, lower-cased, for keyword and table look-ups.
    /// `None` for a quoted part, which is never a keyword.
    pub fn keyword(&self) -> Option<String> {
        (!self.quoted).then(|| self.text.to_ascii_lowercase())
    }
}

/// One name in canonical form.
pub(crate) fn canon(s: &str, quoted: bool) -> Result<String, Reason> {
    if s.is_empty() || s.len() > MAX_NAME_BYTES || s.chars().any(char::is_control) {
        return Err(Reason::UnresolvableName);
    }
    if quoted {
        return Ok(s.to_string());
    }
    if !s.is_ascii() || s.starts_with('$') {
        return Err(Reason::UnresolvableName);
    }
    Ok(s.to_ascii_uppercase())
}

/// A parsed identifier as a [`Part`].
pub(crate) fn ident_part(id: &Ident) -> Result<Part, Reason> {
    match id.quote_style {
        None => Ok(Part::unquoted(&id.value)),
        Some('"') => Ok(Part::quoted(&id.value)),
        Some(_) => Err(Reason::UnsupportedConstruct),
    }
}

/// An unquoted reserved word where the parser took a name: the server
/// never reads it so.
pub(crate) fn reserved_ident(id: &Ident) -> bool {
    id.quote_style.is_none() && reserved(&id.value.to_ascii_lowercase())
}

pub(crate) struct Names<'a> {
    pub ctx: &'a NameContext,
}

impl Names<'_> {
    pub fn catalog(&self) -> String {
        self.ctx.current_catalog.clone()
    }

    /// Where a new unqualified object goes. The context value is already
    /// canonical (`SYS_CONTEXT` reports it so).
    fn current_schema(&self) -> Result<String, Reason> {
        match self.ctx.current_schema.as_deref() {
            Some(s) if !s.is_empty() && s.len() <= MAX_NAME_BYTES => Ok(s.to_string()),
            _ => Err(Reason::UnresolvableName),
        }
    }

    /// A schema written in the statement. `PUBLIC` is reachable only
    /// through synonyms, never as a qualifier.
    fn schema(&self, p: &Part) -> Result<String, Reason> {
        let s = p.canon()?;
        if !p.quoted && s == "PUBLIC" {
            return Err(Reason::UnresolvableName);
        }
        Ok(s)
    }

    /// An existing object named by `parts`.
    pub fn existing(&self, kind: ObjectKind, parts: &[Part]) -> Result<ObjectRef, Reason> {
        let (schema, name) = match parts {
            [n] => (None, n),
            [s, n] => (Some(self.schema(s)?), n),
            _ => return Err(Reason::UnresolvableName),
        };
        Ok(ObjectRef { kind, catalog: self.catalog(), schema, name: name.canon()? })
    }

    /// A new object: an unqualified name goes to the current schema.
    pub fn new_object(&self, kind: ObjectKind, parts: &[Part]) -> Result<ObjectRef, Reason> {
        match parts {
            [n] => {
                Ok(ObjectRef { kind, catalog: self.catalog(), schema: Some(self.current_schema()?), name: n.canon()? })
            }
            _ => self.existing(kind, parts),
        }
    }

    /// A routine in a known schema (`SYS` for the supplied packages).
    pub fn in_schema(&self, kind: ObjectKind, schema: &str, name: &Part) -> Result<ObjectRef, Reason> {
        Ok(ObjectRef { kind, catalog: self.catalog(), schema: Some(schema.to_string()), name: name.canon()? })
    }

    /// The parts of a parsed name, refusing a reserved word the parser took
    /// for a name.
    pub fn parts(&self, name: &ObjectName) -> Result<Vec<Part>, Reason> {
        name.0
            .iter()
            .map(|p| match p {
                ObjectNamePart::Identifier(id) => {
                    if reserved_ident(id) {
                        return Err(Reason::ReservedWordAsName);
                    }
                    ident_part(id)
                }
                ObjectNamePart::Function(_) => Err(Reason::UnresolvableName),
            })
            .collect()
    }
}

/// `DUAL` (or `SYS.DUAL`): the one-row table every `SELECT … FROM dual`
/// reads. It is treated as no object at all, like `SELECT 1` elsewhere.
pub(crate) fn is_dual(parts: &[Part]) -> bool {
    let up = |p: &Part| p.canon().ok();
    match parts {
        [n] => up(n).as_deref() == Some("DUAL"),
        [s, n] => up(s).as_deref() == Some("SYS") && up(n).as_deref() == Some("DUAL"),
        _ => false,
    }
}

/// Oracle's reserved words (`V$RESERVED_WORDS` with `RESERVED = 'Y'`, and
/// the SQL Language Reference's list), sorted. Unquoted, the server never
/// reads one as a name.
const RESERVED: &[&str] = &[
    "access",
    "add",
    "all",
    "alter",
    "and",
    "any",
    "as",
    "asc",
    "audit",
    "between",
    "by",
    "char",
    "check",
    "cluster",
    "column",
    "comment",
    "compress",
    "connect",
    "create",
    "current",
    "date",
    "decimal",
    "default",
    "delete",
    "desc",
    "distinct",
    "drop",
    "else",
    "exclusive",
    "exists",
    "file",
    "float",
    "for",
    "from",
    "grant",
    "group",
    "having",
    "identified",
    "immediate",
    "in",
    "increment",
    "index",
    "initial",
    "insert",
    "integer",
    "intersect",
    "into",
    "is",
    "level",
    "like",
    "lock",
    "long",
    "maxextents",
    "minus",
    "mlslabel",
    "mode",
    "modify",
    "noaudit",
    "nocompress",
    "not",
    "nowait",
    "null",
    "number",
    "of",
    "offline",
    "on",
    "online",
    "option",
    "or",
    "order",
    "pctfree",
    "prior",
    "public",
    "raw",
    "rename",
    "resource",
    "revoke",
    "row",
    "rowid",
    "rownum",
    "rows",
    "select",
    "session",
    "set",
    "share",
    "size",
    "smallint",
    "start",
    "successful",
    "synonym",
    "sysdate",
    "table",
    "then",
    "to",
    "trigger",
    "uid",
    "union",
    "unique",
    "update",
    "user",
    "validate",
    "values",
    "varchar",
    "varchar2",
    "view",
    "whenever",
    "where",
    "with",
];

pub(crate) fn reserved(word: &str) -> bool {
    RESERVED.binary_search(&word).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(ctx: &NameContext) -> Names<'_> {
        Names { ctx }
    }

    #[test]
    fn the_reserved_list_is_sorted_for_binary_search() {
        assert!(RESERVED.windows(2).all(|w| w[0] < w[1]));
        assert!(reserved("minus") && reserved("rownum") && !reserved("dual") && !reserved("users"));
    }

    #[test]
    fn unquoted_names_fold_to_upper_case_and_quoted_ones_are_kept() {
        let ctx = NameContext::oracle("FREEPDB1", "APP");
        let n = names(&ctx);
        let r = n.existing(ObjectKind::Relation, &[Part::unquoted("hr"), Part::unquoted("Emp")]).unwrap();
        assert_eq!((r.catalog.as_str(), r.schema.as_deref(), r.name.as_str()), ("FREEPDB1", Some("HR"), "EMP"));
        let r = n.existing(ObjectKind::Relation, &[Part::quoted("Mixed Case")]).unwrap();
        assert_eq!((r.schema, r.name.as_str()), (None, "Mixed Case"));
        // New unqualified objects go to the current schema.
        let r = n.new_object(ObjectKind::Relation, &[Part::unquoted("t")]).unwrap();
        assert_eq!((r.schema.as_deref(), r.name.as_str()), (Some("APP"), "T"));
    }

    #[test]
    fn names_that_cannot_be_folded_or_are_too_long_are_refused() {
        assert_eq!(canon("ação", false), Err(Reason::UnresolvableName));
        assert_eq!(canon("ação", true).as_deref(), Ok("ação"));
        assert_eq!(canon(&"x".repeat(128), false).map(|s| s.len()), Ok(128));
        assert_eq!(canon(&"x".repeat(129), false), Err(Reason::UnresolvableName));
        // 64 two-byte characters plus one more: 130 bytes, refused.
        assert_eq!(canon(&"é".repeat(65), true), Err(Reason::UnresolvableName));
        assert_eq!(canon("a\u{1}b", true), Err(Reason::UnresolvableName));
        let ctx = NameContext::oracle("PDB", "APP");
        let n = names(&ctx);
        let three = [Part::unquoted("a"), Part::unquoted("b"), Part::unquoted("c")];
        assert_eq!(n.existing(ObjectKind::Relation, &three), Err(Reason::UnresolvableName));
        let public = [Part::unquoted("public"), Part::unquoted("t")];
        assert_eq!(n.existing(ObjectKind::Relation, &public), Err(Reason::UnresolvableName));
        assert!(is_dual(&[Part::unquoted("Dual")]) && is_dual(&[Part::unquoted("sys"), Part::quoted("DUAL")]));
        assert!(!is_dual(&[Part::quoted("dual")]) && !is_dual(&[Part::unquoted("hr"), Part::unquoted("dual")]));
    }
}
