//! Canonical PostgreSQL names (features/sql-browser.md §4.4).
//!
//! Unquoted identifiers fold to lower case (ASCII only, as the server does
//! for a UTF-8 database); quoted ones are kept. Both are truncated to
//! `max_identifier_length` bytes on a character boundary, as the server
//! truncates them, so the path checked is the object the server will use.

use sqlparser::ast::{Ident, ObjectName, ObjectNamePart};

use crate::model::{NameContext, ObjectKind, ObjectRef, Reason};

/// Schema a temporary object is created in. The real name is per backend
/// (`pg_temp_3`); `pg_temp` is how a statement can address it.
pub(crate) const TEMP_SCHEMA: &str = "pg_temp";

pub(crate) struct Names<'a> {
    pub ctx: &'a NameContext,
}

impl Names<'_> {
    pub fn truncate(&self, mut s: String) -> String {
        let max = self.ctx.max_identifier_length;
        if s.len() > max {
            let mut cut = max;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
        }
        s
    }

    /// One identifier in canonical form.
    pub fn ident(&self, id: &Ident) -> Result<String, Reason> {
        match id.quote_style {
            None => Ok(self.truncate(id.value.to_ascii_lowercase())),
            Some('"') => Ok(self.truncate(id.value.clone())),
            Some(_) => Err(Reason::UnsupportedConstruct),
        }
    }

    /// Every part of a dotted name, canonical.
    pub fn parts(&self, name: &ObjectName) -> Result<Vec<String>, Reason> {
        name.0
            .iter()
            .map(|p| match p {
                ObjectNamePart::Identifier(id) => self.ident(id),
                ObjectNamePart::Function(_) => Err(Reason::UnresolvableName),
            })
            .collect()
    }

    fn build(
        &self,
        kind: ObjectKind,
        mut parts: Vec<String>,
        unqualified_schema: Option<String>,
    ) -> Result<ObjectRef, Reason> {
        if parts.iter().any(String::is_empty) {
            return Err(Reason::UnresolvableName);
        }
        let name = parts.pop().ok_or(Reason::UnresolvableName)?;
        let (catalog, schema) = match parts.len() {
            0 => (self.ctx.current_catalog.clone(), unqualified_schema),
            1 => (self.ctx.current_catalog.clone(), parts.pop()),
            2 => {
                let schema = parts.pop();
                (parts.pop().ok_or(Reason::UnresolvableName)?, schema)
            }
            _ => return Err(Reason::UnresolvableName),
        };
        Ok(ObjectRef { kind, catalog, schema, name })
    }

    /// `parts`, refusing an unquoted word the server could never take as a
    /// name of this kind: there the parser has misread the statement.
    fn name_parts(&self, kind: ObjectKind, name: &ObjectName) -> Result<Vec<String>, Reason> {
        for p in &name.0 {
            if let ObjectNamePart::Identifier(id) = p {
                if id.quote_style.is_none() && reserved_for(kind, &id.value.to_ascii_lowercase()) {
                    return Err(Reason::ReservedWordAsName);
                }
            }
        }
        self.parts(name)
    }

    /// A reference to an object that must already exist. An unqualified name
    /// keeps `schema: None`: the caller resolves it through the catalog.
    pub fn existing(&self, kind: ObjectKind, name: &ObjectName) -> Result<ObjectRef, Reason> {
        self.build(kind, self.name_parts(kind, name)?, None)
    }

    /// An existing object named by already-canonical parts.
    pub fn existing_parts(&self, kind: ObjectKind, parts: Vec<String>) -> Result<ObjectRef, Reason> {
        self.build(kind, parts, None)
    }

    /// A new object. Unqualified, it goes to `pg_temp` when temporary and to
    /// `current_schema()` otherwise; with no current schema the server
    /// refuses the statement, and so does the classifier.
    pub fn new_object(&self, kind: ObjectKind, name: &ObjectName, temporary: bool) -> Result<ObjectRef, Reason> {
        self.new_object_parts(kind, self.name_parts(kind, name)?, temporary)
    }

    pub fn new_object_parts(&self, kind: ObjectKind, parts: Vec<String>, temporary: bool) -> Result<ObjectRef, Reason> {
        if parts.len() == 1 {
            let schema = if temporary {
                TEMP_SCHEMA.to_string()
            } else {
                self.ctx.current_schema.clone().ok_or(Reason::UnresolvableName)?
            };
            return self.build(kind, parts, Some(schema));
        }
        if temporary && parts.len() >= 2 && parts[parts.len() - 2] != TEMP_SCHEMA {
            // `CREATE TEMP TABLE s.t` is an error unless `s` is pg_temp.
            return Err(Reason::UnresolvableName);
        }
        self.build(kind, parts, None)
    }

    /// A name written inside a string literal, as `regclass` input reads it
    /// (`nextval('public."Seq"')`). A numeric OID cannot be resolved here.
    pub fn in_string(&self, kind: ObjectKind, s: &str) -> Result<ObjectRef, Reason> {
        let parts = split_qualified(s).ok_or(Reason::UnresolvableName)?;
        if parts.len() == 1 && parts[0].bytes().all(|b| b.is_ascii_digit()) {
            return Err(Reason::UnresolvableName);
        }
        let parts = parts.into_iter().map(|p| self.truncate(p)).collect();
        self.build(kind, parts, None)
    }

    /// May an unqualified function or operator be taken as the built-in?
    /// Only when `pg_catalog` is searched before every user schema.
    pub fn catalog_first(&self) -> bool {
        self.ctx.search_path.iter().find(|s| !s.starts_with("pg_temp")).is_some_and(|s| s == "pg_catalog")
    }
}

/// PostgreSQL's fully reserved keywords (`reserved_keyword` in `gram.y`):
/// never a table, column, function or type name unless quoted.
const RESERVED: &[&str] = &[
    "all",
    "analyse",
    "analyze",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "asymmetric",
    "both",
    "case",
    "cast",
    "check",
    "collate",
    "column",
    "constraint",
    "create",
    "current_catalog",
    "current_date",
    "current_role",
    "current_time",
    "current_timestamp",
    "current_user",
    "default",
    "deferrable",
    "desc",
    "distinct",
    "do",
    "else",
    "end",
    "except",
    "false",
    "fetch",
    "for",
    "foreign",
    "from",
    "grant",
    "group",
    "having",
    "in",
    "initially",
    "intersect",
    "into",
    "lateral",
    "leading",
    "limit",
    "localtime",
    "localtimestamp",
    "not",
    "null",
    "offset",
    "on",
    "only",
    "or",
    "order",
    "placing",
    "primary",
    "references",
    "returning",
    "select",
    "session_user",
    "some",
    "symmetric",
    "system_user",
    "table",
    "then",
    "to",
    "trailing",
    "true",
    "union",
    "unique",
    "user",
    "using",
    "variadic",
    "when",
    "where",
    "window",
    "with",
];

/// `type_func_name_keyword`: may name a function or a type, never a table.
const TYPE_FUNC_NAME: &[&str] = &[
    "authorization",
    "binary",
    "collation",
    "concurrently",
    "cross",
    "current_schema",
    "freeze",
    "full",
    "ilike",
    "inner",
    "is",
    "isnull",
    "join",
    "left",
    "like",
    "natural",
    "notnull",
    "outer",
    "overlaps",
    "right",
    "similar",
    "tablesample",
    "verbose",
];

/// Reserved words the grammar itself turns into function calls.
const SQL_VALUE_FUNCTIONS: &[&str] = &[
    "current_catalog",
    "current_date",
    "current_role",
    "current_time",
    "current_timestamp",
    "current_user",
    "localtime",
    "localtimestamp",
    "session_user",
    "system_user",
    "user",
    "array",
];

fn reserved_for(kind: ObjectKind, word: &str) -> bool {
    let reserved = RESERVED.contains(&word);
    match kind {
        ObjectKind::Relation | ObjectKind::Sequence | ObjectKind::Index | ObjectKind::Collation => {
            reserved || TYPE_FUNC_NAME.contains(&word)
        }
        ObjectKind::Routine => reserved && !SQL_VALUE_FUNCTIONS.contains(&word),
        ObjectKind::Type => reserved,
    }
}

/// PostgreSQL `SplitIdentifierString(name, '.')`: dotted parts, each quoted
/// (`""` escapes a quote, case kept) or unquoted (ASCII lower-cased),
/// whitespace allowed around them. `None` for anything malformed.
fn split_qualified(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            chars.next();
        }
        let mut part = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next()? {
                    '"' if chars.peek() == Some(&'"') => {
                        chars.next();
                        part.push('"');
                    }
                    '"' => break,
                    c => part.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == '.' || c.is_ascii_whitespace() || c == '"' {
                    break;
                }
                part.push(c.to_ascii_lowercase());
                chars.next();
            }
        }
        if part.is_empty() {
            return None;
        }
        out.push(part);
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            chars.next();
        }
        match chars.next() {
            None => return Some(out),
            Some('.') => continue,
            Some(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regclass_strings_split_like_the_server() {
        assert_eq!(split_qualified("Public.Seq").unwrap(), vec!["public", "seq"]);
        assert_eq!(split_qualified(" public . \"My.Seq\"\"x\" ").unwrap(), vec!["public", "My.Seq\"x"]);
        for bad in ["", "a.", ".a", "a b", "\"a", "a..b", "\"\""] {
            assert!(split_qualified(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn identifiers_truncate_on_a_character_boundary() {
        let ctx = NameContext { max_identifier_length: 4, ..NameContext::postgres("db", None, vec![]) };
        let n = Names { ctx: &ctx };
        assert_eq!(n.truncate("abcdef".into()), "abcd");
        assert_eq!(n.truncate("abçd".into()), "abç");
        assert_eq!(n.truncate("açãe".into()), "aç");
    }

    #[test]
    fn catalog_first_ignores_temp_schemas_only() {
        let mk = |p: &[&str]| NameContext::postgres("db", None, p.iter().map(|s| s.to_string()).collect());
        assert!(Names { ctx: &mk(&["pg_temp_3", "pg_catalog", "public"]) }.catalog_first());
        assert!(!Names { ctx: &mk(&["public", "pg_catalog"]) }.catalog_first());
        assert!(!Names { ctx: &mk(&[]) }.catalog_first());
    }
}
