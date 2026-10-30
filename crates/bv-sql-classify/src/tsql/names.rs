//! Canonical SQL Server names (features/sql-browser.md §3.2, §4.4). A path
//! is `<database>/<schema>/<object>`. Quoting never changes a name; how two
//! spellings compare is the collation's business, so names are folded only
//! where the collation folds exactly as ASCII case folding does.

// Anything else is refused rather than guessed: a deny rule on `App` must
// not be dodged by writing `APP`, a full-width `Ａpp` or `Ap\u{200b}p`.

// Unqualified names: a new object goes to the default schema; an existing
// one is looked up in the default schema, then `dbo`. When those coincide
// the classifier fills the schema in, otherwise the caller resolves the
// name through the catalog (`schema: None`). `#temp` tables live in
// `tempdb`; four-part names reach a linked server and never run.

use sqlparser::ast::{Ident, ObjectName, ObjectNamePart};

use crate::model::{NameContext, NameMatch, ObjectKind, ObjectRef, Reason, MSSQL_DEFAULT_SCHEMA, MSSQL_TEMP_CATALOG};

/// SQL Server's `sysname` limit, in characters.
pub(crate) const MAX_NAME_CHARS: usize = 128;

pub(crate) struct Names<'a> {
    pub ctx: &'a NameContext,
    /// Schema and object names: the database collation.
    pub names: NameMatch,
    /// Database names: the server collation.
    pub catalogs: NameMatch,
}

/// One name in canonical form under `m`.
pub(crate) fn canon(m: NameMatch, s: &str) -> Result<String, Reason> {
    if s.is_empty() || s.chars().count() > MAX_NAME_CHARS {
        return Err(Reason::UnresolvableName);
    }
    let printable_ascii = s.bytes().all(|b| (0x20..0x7f).contains(&b));
    match m {
        NameMatch::Exact if s.chars().any(char::is_control) => Err(Reason::UnresolvableName),
        NameMatch::Exact => Ok(s.to_string()),
        NameMatch::AsciiCaseSensitive if printable_ascii => Ok(s.to_string()),
        NameMatch::AsciiCaseInsensitive if printable_ascii => Ok(s.to_ascii_lowercase()),
        _ => Err(Reason::UnresolvableName),
    }
}

/// The text of one identifier as written: unquoted, bracketed or
/// double-quoted (sqlparser has already undone the doubling).
pub(crate) fn raw_ident(id: &Ident) -> Result<&str, Reason> {
    match id.quote_style {
        None | Some('[') | Some('"') => Ok(&id.value),
        Some(_) => Err(Reason::UnsupportedConstruct),
    }
}

/// An unquoted reserved keyword where the parser took a name: the server
/// never reads it so (it may be the start of the next statement).
pub(crate) fn reserved_ident(id: &Ident) -> bool {
    id.quote_style.is_none() && reserved(&id.value.to_ascii_lowercase())
}

/// What a dotted name refers to.
pub(crate) enum Resolved {
    Object(ObjectRef),
    /// `@table_variable`: local to the batch, not a catalog object.
    Variable,
}

impl Names<'_> {
    pub fn catalog(&self, raw: &str) -> Result<String, Reason> {
        canon(self.catalogs, raw)
    }

    /// The session's database, canonical.
    pub fn current_catalog(&self) -> Result<String, Reason> {
        self.catalog(&self.ctx.current_catalog)
    }

    pub fn part(&self, raw: &str) -> Result<String, Reason> {
        canon(self.names, raw)
    }

    /// The raw parts of a dotted name, refusing a reserved word the parser
    /// took for a name. `db..t` keeps its empty middle part.
    pub fn raw_parts<'n>(&self, name: &'n ObjectName) -> Result<Vec<&'n str>, Reason> {
        name.0
            .iter()
            .map(|p| match p {
                ObjectNamePart::Identifier(id) => {
                    if reserved_ident(id) {
                        return Err(Reason::ReservedWordAsName);
                    }
                    raw_ident(id)
                }
                ObjectNamePart::Function(_) => Err(Reason::UnresolvableName),
            })
            .collect()
    }

    /// The schema of an existing unqualified name: filled in only when the
    /// default schema and `dbo` coincide (`search_path` of one).
    fn unqualified_schema(&self) -> Result<Option<String>, Reason> {
        match self.ctx.search_path.as_slice() {
            [only] => Ok(Some(self.part(only)?)),
            _ => Ok(None),
        }
    }

    fn temp(&self, kind: ObjectKind, name: &str) -> Result<ObjectRef, Reason> {
        Ok(ObjectRef {
            kind,
            catalog: MSSQL_TEMP_CATALOG.to_string(),
            schema: Some(MSSQL_DEFAULT_SCHEMA.to_string()),
            name: self.part(name)?,
        })
    }

    /// An existing object named by `parts`.
    pub fn resolve_raw(&self, kind: ObjectKind, parts: &[&str]) -> Result<Resolved, Reason> {
        let obj = |catalog: String, schema: Option<String>, name: &str| -> Result<Resolved, Reason> {
            Ok(Resolved::Object(ObjectRef { kind, catalog, schema, name: self.part(name)? }))
        };
        match parts {
            [n] if n.starts_with('@') => Ok(Resolved::Variable),
            [n] if n.starts_with('#') => Ok(Resolved::Object(self.temp(kind, n)?)),
            [n] => obj(self.current_catalog()?, self.unqualified_schema()?, n),
            [s, n] if !s.is_empty() => obj(self.current_catalog()?, Some(self.part(s)?), n),
            [d, s, n] if !d.is_empty() && s.is_empty() => obj(self.catalog(d)?, None, n),
            [d, s, n] if !d.is_empty() => obj(self.catalog(d)?, Some(self.part(s)?), n),
            // `server.db.schema.object`: a linked server, refused as the
            // other remote access (`OPENQUERY`, §4.2) is.
            [_, _, _, _] => Err(Reason::ServerFileOrOsAccess),
            _ => Err(Reason::UnresolvableName),
        }
    }

    /// An existing object, refusing a table variable.
    pub fn existing(&self, kind: ObjectKind, parts: &[&str]) -> Result<ObjectRef, Reason> {
        match self.resolve_raw(kind, parts)? {
            Resolved::Object(o) => Ok(o),
            Resolved::Variable => Err(Reason::UnsupportedConstruct),
        }
    }

    /// A new object: an unqualified name goes to the default schema.
    pub fn new_object(&self, kind: ObjectKind, parts: &[&str]) -> Result<ObjectRef, Reason> {
        match parts {
            [n] if n.starts_with('#') => self.temp(kind, n),
            [n] if n.starts_with('@') => Err(Reason::UnsupportedConstruct),
            [n] => {
                let schema = self.ctx.current_schema.as_deref().ok_or(Reason::UnresolvableName)?;
                Ok(ObjectRef {
                    kind,
                    catalog: self.current_catalog()?,
                    schema: Some(self.part(schema)?),
                    name: self.part(n)?,
                })
            }
            _ => self.existing(kind, parts),
        }
    }

    pub fn object(&self, kind: ObjectKind, name: &ObjectName) -> Result<Resolved, Reason> {
        self.resolve_raw(kind, &self.raw_parts(name)?)
    }

    /// The database of a `USE`.
    pub fn database(&self, raw: &str) -> Result<String, Reason> {
        self.catalog(raw)
    }
}

/// SQL Server's reserved keywords (Transact-SQL reference, "Reserved
/// keywords"), sorted. Unquoted, the server never reads one as a name.
const RESERVED: &[&str] = &[
    "add",
    "all",
    "alter",
    "and",
    "any",
    "as",
    "asc",
    "authorization",
    "backup",
    "begin",
    "between",
    "break",
    "browse",
    "bulk",
    "by",
    "cascade",
    "case",
    "check",
    "checkpoint",
    "close",
    "clustered",
    "coalesce",
    "collate",
    "column",
    "commit",
    "compute",
    "constraint",
    "contains",
    "containstable",
    "continue",
    "convert",
    "create",
    "cross",
    "current",
    "current_date",
    "current_time",
    "current_timestamp",
    "current_user",
    "cursor",
    "database",
    "dbcc",
    "deallocate",
    "declare",
    "default",
    "delete",
    "deny",
    "desc",
    "disk",
    "distinct",
    "distributed",
    "double",
    "drop",
    "dump",
    "else",
    "end",
    "errlvl",
    "escape",
    "except",
    "exec",
    "execute",
    "exists",
    "exit",
    "external",
    "fetch",
    "file",
    "fillfactor",
    "for",
    "foreign",
    "freetext",
    "freetexttable",
    "from",
    "full",
    "function",
    "goto",
    "grant",
    "group",
    "having",
    "holdlock",
    "identity",
    "identity_insert",
    "identitycol",
    "if",
    "in",
    "index",
    "inner",
    "insert",
    "intersect",
    "into",
    "is",
    "join",
    "key",
    "kill",
    "left",
    "like",
    "lineno",
    "load",
    "merge",
    "national",
    "nocheck",
    "nonclustered",
    "not",
    "null",
    "nullif",
    "of",
    "off",
    "offsets",
    "on",
    "open",
    "opendatasource",
    "openquery",
    "openrowset",
    "openxml",
    "option",
    "or",
    "order",
    "outer",
    "over",
    "percent",
    "pivot",
    "plan",
    "precision",
    "primary",
    "print",
    "proc",
    "procedure",
    "public",
    "raiserror",
    "read",
    "readtext",
    "reconfigure",
    "references",
    "replication",
    "restore",
    "restrict",
    "return",
    "revert",
    "revoke",
    "right",
    "rollback",
    "rowcount",
    "rowguidcol",
    "rule",
    "save",
    "schema",
    "securityaudit",
    "select",
    "semantickeyphrasetable",
    "semanticsimilaritydetailstable",
    "semanticsimilaritytable",
    "session_user",
    "set",
    "setuser",
    "shutdown",
    "some",
    "statistics",
    "system_user",
    "table",
    "tablesample",
    "textsize",
    "then",
    "to",
    "top",
    "tran",
    "transaction",
    "trigger",
    "truncate",
    "try_convert",
    "tsequal",
    "union",
    "unique",
    "unpivot",
    "update",
    "updatetext",
    "use",
    "user",
    "values",
    "varying",
    "view",
    "waitfor",
    "when",
    "where",
    "while",
    "with",
    "writetext",
];

pub(crate) fn reserved(word: &str) -> bool {
    RESERVED.binary_search(&word).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(ctx: &NameContext, m: NameMatch) -> Names<'_> {
        Names { ctx, names: m, catalogs: m }
    }

    fn obj(r: Result<Resolved, Reason>) -> ObjectRef {
        match r {
            Ok(Resolved::Object(o)) => o,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn the_reserved_list_is_sorted_for_binary_search() {
        assert!(RESERVED.windows(2).all(|w| w[0] < w[1]));
        assert!(reserved("checkpoint") && reserved("exec") && !reserved("throw") && !reserved("users"));
    }

    #[test]
    fn folding_follows_the_collation() {
        let ctx = NameContext::mssql("App", Some("dbo".into()));
        let ci = names(&ctx, NameMatch::AsciiCaseInsensitive);
        let r = obj(ci.resolve_raw(ObjectKind::Relation, &["Sales", "Users"]));
        assert_eq!((r.catalog.as_str(), r.schema.as_deref(), r.name.as_str()), ("app", Some("sales"), "users"));
        let cs = names(&ctx, NameMatch::AsciiCaseSensitive);
        let r = obj(cs.resolve_raw(ObjectKind::Relation, &["Users"]));
        assert_eq!((r.catalog.as_str(), r.schema.as_deref(), r.name.as_str()), ("App", Some("dbo"), "Users"));
        // Beyond ASCII only a binary collation compares exactly.
        for m in [NameMatch::AsciiCaseInsensitive, NameMatch::AsciiCaseSensitive] {
            for bad in ["Ação", "Ａpp", "Ap\u{200b}p", "a\u{1}b"] {
                assert_eq!(canon(m, bad), Err(Reason::UnresolvableName), "{bad:?}");
            }
        }
        assert_eq!(canon(NameMatch::Exact, "Ação").as_deref(), Ok("Ação"));
        assert_eq!(canon(NameMatch::Exact, &"x".repeat(129)), Err(Reason::UnresolvableName));
    }

    #[test]
    fn unqualified_names_need_one_lookup_schema() {
        let dbo = NameContext::mssql("app", Some("dbo".into()));
        let n = names(&dbo, NameMatch::AsciiCaseInsensitive);
        assert_eq!(obj(n.resolve_raw(ObjectKind::Relation, &["t"])).schema.as_deref(), Some("dbo"));
        // Default schema `sales`: `t` may be sales.t or dbo.t; the caller resolves.
        let sales = NameContext::mssql("app", Some("sales".into()));
        let n = names(&sales, NameMatch::AsciiCaseInsensitive);
        assert_eq!(obj(n.resolve_raw(ObjectKind::Relation, &["t"])).schema, None);
        assert_eq!(n.new_object(ObjectKind::Relation, &["t"]).unwrap().schema.as_deref(), Some("sales"));
        assert_eq!(obj(n.resolve_raw(ObjectKind::Relation, &["db2", "", "t"])).schema, None);
        let t = n.new_object(ObjectKind::Relation, &["#tmp"]).unwrap();
        assert_eq!((t.catalog.as_str(), t.schema.as_deref(), t.name.as_str()), ("tempdb", Some("dbo"), "#tmp"));
        assert!(matches!(n.resolve_raw(ObjectKind::Relation, &["@tv"]), Ok(Resolved::Variable)));
        assert!(matches!(
            n.resolve_raw(ObjectKind::Relation, &["srv", "db", "dbo", "t"]),
            Err(Reason::ServerFileOrOsAccess)
        ));
    }
}
