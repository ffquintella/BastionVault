//! Statements classified from their tokens, before the parser sees them.
//!
//! Phase 0 found these outside sqlparser's PostgreSQL coverage (`DO`,
//! maintenance commands) or only worth one rule (`GRANT`, roles, databases:
//! `sql_admin` whatever the details). Each has a strict grammar; anything
//! else in the statement makes it unclassifiable, never a guess.

use super::analyze::{check_language, Analysis};
use super::lexer::{RawStatement, StrKind, TokKind};
use super::names::Names;
use super::settings;
use crate::model::{ObjectKind, Reason, SqlCapability as Cap, SqlTarget, StatementKind as Kind};

#[derive(Debug, Clone)]
enum T {
    /// Unquoted word, lower-cased.
    Word(String),
    /// Quoted identifier, unescaped.
    Quoted(String),
    /// A string literal of a form whose content needs no decoding.
    Str,
    Number,
    Punct(u8),
}

struct Cur<'a, 'c> {
    toks: Vec<T>,
    i: usize,
    names: &'a Names<'c>,
}

impl Cur<'_, '_> {
    fn peek(&self) -> Option<&T> {
        self.toks.get(self.i)
    }

    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(T::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn word_at(&self, k: usize) -> Option<&str> {
        match self.toks.get(self.i + k) {
            Some(T::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn eat(&mut self, w: &str) -> bool {
        if self.peek_word() == Some(w) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_punct(&mut self, c: u8) -> bool {
        if matches!(self.peek(), Some(T::Punct(p)) if *p == c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn done(&self) -> bool {
        self.i >= self.toks.len()
    }

    fn end(&self) -> Result<(), Reason> {
        if self.done() {
            Ok(())
        } else {
            Err(Reason::UnsupportedConstruct)
        }
    }

    /// `name [. name [. name]]`, canonical parts.
    fn name(&mut self) -> Option<Vec<String>> {
        let mut parts = Vec::new();
        loop {
            let part = match self.peek()? {
                T::Word(w) => w.clone(),
                T::Quoted(q) => q.clone(),
                _ => return None,
            };
            self.i += 1;
            parts.push(self.names.truncate(part));
            if !self.eat_punct(b'.') {
                return Some(parts);
            }
        }
    }

    /// `( name [value] {, name [value]} )` with names from `allowed`.
    fn options(&mut self, allowed: &[&str]) -> Result<(), Reason> {
        if !self.eat_punct(b'(') {
            return Ok(());
        }
        loop {
            let Some(name) = self.peek_word().map(str::to_string) else { return Err(Reason::UnsupportedConstruct) };
            if !allowed.contains(&name.as_str()) {
                return Err(Reason::UnsupportedConstruct);
            }
            self.i += 1;
            if matches!(self.peek(), Some(T::Word(_) | T::Number | T::Str)) {
                self.i += 1;
            }
            if self.eat_punct(b')') {
                return Ok(());
            }
            if !self.eat_punct(b',') {
                return Err(Reason::UnsupportedConstruct);
            }
        }
    }

    /// `name [ ( col {, col} ) ] {, …}`; empty is allowed.
    fn table_list(&mut self) -> Result<Vec<Vec<String>>, Reason> {
        let mut out = Vec::new();
        if self.done() {
            return Ok(out);
        }
        loop {
            out.push(self.name().ok_or(Reason::UnsupportedConstruct)?);
            if self.eat_punct(b'(') {
                loop {
                    self.name().ok_or(Reason::UnsupportedConstruct)?;
                    if self.eat_punct(b')') {
                        break;
                    }
                    if !self.eat_punct(b',') {
                        return Err(Reason::UnsupportedConstruct);
                    }
                }
            }
            if !self.eat_punct(b',') {
                return Ok(out);
            }
        }
    }
}

fn admin(kind: Kind) -> Result<Analysis, Reason> {
    Ok(Analysis::with(kind, Cap::Admin, SqlTarget::Server))
}

fn maintenance(names: &Names<'_>, kind: ObjectKind, tables: Vec<Vec<String>>) -> Result<Analysis, Reason> {
    let mut a = Analysis::new(Kind::Maintenance);
    if tables.is_empty() {
        a.required.insert((Cap::Alter, SqlTarget::Server));
    }
    for t in tables {
        let r = names.existing_parts(kind, t)?;
        a.required.insert((Cap::Alter, SqlTarget::Object(r)));
    }
    Ok(a)
}

/// Words skipped between `CREATE`/`ALTER`/`DROP` and the object type.
const MODIFIERS: &[&str] =
    &["or", "replace", "temp", "temporary", "unlogged", "trusted", "procedural", "global", "local"];

/// Object types whose create / alter / drop is `sql_admin` (§4.2: roles,
/// databases, server configuration, replication, and the objects that change
/// how every other statement resolves or which code the server loads).
const ADMIN_OBJECTS: &[&str] = &[
    "role",
    "user",
    "group",
    "database",
    "extension",
    "server",
    "foreign",
    "subscription",
    "publication",
    "event",
    "language",
    "cast",
    "conversion",
    "operator",
    "access",
    "transform",
    "rule",
    "default",
    "owned",
];

/// `Some` when the statement is one this module decides; `None` sends it to
/// the parser.
pub(crate) fn classify(text: &str, stmt: &RawStatement, names: &Names<'_>) -> Option<Result<Analysis, Reason>> {
    let mut toks = Vec::new();
    for t in stmt.tokens.iter().filter(|t| !t.is_comment()) {
        let s = &text[t.start..t.end];
        toks.push(match t.kind {
            TokKind::Word => T::Word(s.to_ascii_lowercase()),
            TokKind::QuotedIdent => T::Quoted(s[1..s.len() - 1].replace("\"\"", "\"")),
            TokKind::Str(StrKind::Plain | StrKind::Escape) | TokKind::DollarStr => T::Str,
            TokKind::Str(_) | TokKind::Param | TokKind::LineComment | TokKind::BlockComment => T::Punct(0),
            TokKind::Number => T::Number,
            TokKind::Punct(c) => T::Punct(c),
        });
    }
    let mut c = Cur { toks, i: 0, names };
    let first = c.peek_word()?.to_string();
    let second = c.word_at(1).map(str::to_string);
    let result = match first.as_str() {
        "load" => Err(Reason::ServerFileOrOsAccess),
        "do" => {
            c.i += 1;
            do_block(&mut c, text, stmt)
        }
        "vacuum" | "analyze" | "analyse" => {
            c.i += 1;
            vacuum(&mut c, first == "vacuum")
        }
        "reindex" => {
            c.i += 1;
            reindex(&mut c)
        }
        "cluster" => {
            c.i += 1;
            cluster(&mut c)
        }
        "refresh" => {
            c.i += 1;
            refresh(&mut c)
        }
        "checkpoint" => {
            c.i += 1;
            c.options(&["flush_unlogged", "mode"]).and_then(|()| c.end()).and_then(|()| admin(Kind::Admin))
        }
        "abort" => {
            c.i += 1;
            let _ = c.eat("work") || c.eat("transaction");
            if c.eat("and") {
                let _ = c.eat("no");
                if !c.eat("chain") {
                    return Some(Err(Reason::UnsupportedConstruct));
                }
            }
            c.end().map(|()| Analysis { tx_control: true, ..Analysis::new(Kind::TxRollback) })
        }
        "move" => {
            let ok =
                c.toks[1..].iter().all(|t| matches!(t, T::Word(_) | T::Quoted(_) | T::Number | T::Punct(b'-' | b'+')));
            if ok {
                Ok(Analysis::with(Kind::FetchCursor, Cap::Select, SqlTarget::Server))
            } else {
                Err(Reason::UnsupportedConstruct)
            }
        }
        "grant" | "revoke" | "reassign" | "import" => admin(Kind::Admin),
        "security" if second.as_deref() == Some("label") => admin(Kind::Admin),
        "prepare" if second.as_deref() == Some("transaction") => admin(Kind::Admin),
        "commit" | "rollback" if second.as_deref() == Some("prepared") => admin(Kind::Admin),
        "create" | "alter" | "drop" => {
            c.i += 1;
            while c.peek_word().is_some_and(|w| MODIFIERS.contains(&w)) {
                c.i += 1;
            }
            match c.peek_word() {
                Some("tablespace") if first == "create" => Err(Reason::ServerFileOrOsAccess),
                Some("tablespace") => admin(Kind::Admin),
                Some("system") if first == "alter" => {
                    c.i += 1;
                    alter_system(&mut c)
                }
                Some("sequence") if first == "alter" => {
                    c.i += 1;
                    alter_simple(&mut c, ObjectKind::Sequence)
                }
                Some("view") if first == "alter" => {
                    c.i += 1;
                    alter_simple(&mut c, ObjectKind::Relation)
                }
                Some("materialized") if first == "alter" && c.word_at(1) == Some("view") => {
                    c.i += 2;
                    alter_simple(&mut c, ObjectKind::Relation)
                }
                Some(w) if ADMIN_OBJECTS.contains(&w) => admin(Kind::Admin),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(result)
}

/// `DO [LANGUAGE lang] body [LANGUAGE lang]`: opaque `sql_execute`.
fn do_block(c: &mut Cur<'_, '_>, text: &str, stmt: &RawStatement) -> Result<Analysis, Reason> {
    let code: Vec<_> = stmt.tokens.iter().filter(|t| !t.is_comment()).collect();
    let mut language = None;
    let mut body = false;
    while !c.done() {
        if c.eat("language") {
            let tok = code.get(c.i).ok_or(Reason::UnsupportedConstruct)?;
            let lang = match tok.kind {
                TokKind::Word => text[tok.start..tok.end].to_ascii_lowercase(),
                TokKind::QuotedIdent => text[tok.start + 1..tok.end - 1].replace("\"\"", "\""),
                TokKind::Str(StrKind::Plain) => text[tok.start + 1..tok.end - 1].replace("''", "'"),
                _ => return Err(Reason::UnsupportedConstruct),
            };
            if language.replace(lang).is_some() {
                return Err(Reason::UnsupportedConstruct);
            }
            c.i += 1;
        } else if !body && matches!(c.peek(), Some(T::Str)) {
            body = true;
            c.i += 1;
        } else {
            return Err(Reason::UnsupportedConstruct);
        }
    }
    if !body {
        return Err(Reason::UnsupportedConstruct);
    }
    check_language(language.as_deref().unwrap_or("plpgsql"))?;
    let mut a = Analysis::with(Kind::Do, Cap::Execute, SqlTarget::Server);
    a.opaque = true;
    Ok(a)
}

const VACUUM_OPTIONS: &[&str] = &[
    "full",
    "freeze",
    "verbose",
    "analyze",
    "analyse",
    "disable_page_skipping",
    "skip_locked",
    "index_cleanup",
    "process_main",
    "process_toast",
    "truncate",
    "parallel",
    "skip_database_stats",
    "only_database_stats",
    "buffer_usage_limit",
];

fn vacuum(c: &mut Cur<'_, '_>, is_vacuum: bool) -> Result<Analysis, Reason> {
    c.options(VACUUM_OPTIONS)?;
    let flags: &[&str] = if is_vacuum { &["full", "freeze", "verbose", "analyze", "analyse"] } else { &["verbose"] };
    while c.peek_word().is_some_and(|w| flags.contains(&w)) && !matches!(c.toks.get(c.i + 1), Some(T::Punct(b'.'))) {
        c.i += 1;
    }
    let tables = c.table_list()?;
    c.end()?;
    maintenance(c.names, ObjectKind::Relation, tables)
}

fn reindex(c: &mut Cur<'_, '_>) -> Result<Analysis, Reason> {
    c.options(&["verbose", "concurrently"])?;
    let what = c.peek_word().map(str::to_string).ok_or(Reason::UnsupportedConstruct)?;
    c.i += 1;
    let _ = c.eat("concurrently");
    let name = if c.done() { None } else { Some(c.name().ok_or(Reason::UnsupportedConstruct)?) };
    c.end()?;
    match (what.as_str(), name) {
        ("index", Some(n)) => maintenance(c.names, ObjectKind::Index, vec![n]),
        ("table", Some(n)) => maintenance(c.names, ObjectKind::Relation, vec![n]),
        ("schema", Some(_)) | ("database" | "system", _) => maintenance(c.names, ObjectKind::Relation, vec![]),
        _ => Err(Reason::UnsupportedConstruct),
    }
}

fn cluster(c: &mut Cur<'_, '_>) -> Result<Analysis, Reason> {
    c.options(&["verbose"])?;
    let _ = c.eat("verbose");
    if c.done() {
        return maintenance(c.names, ObjectKind::Relation, vec![]);
    }
    let table = c.name().ok_or(Reason::UnsupportedConstruct)?;
    if c.eat("using") {
        c.name().ok_or(Reason::UnsupportedConstruct)?;
    }
    c.end()?;
    maintenance(c.names, ObjectKind::Relation, vec![table])
}

fn refresh(c: &mut Cur<'_, '_>) -> Result<Analysis, Reason> {
    if !(c.eat("materialized") && c.eat("view")) {
        return Err(Reason::UnsupportedConstruct);
    }
    let _ = c.eat("concurrently");
    let view = c.name().ok_or(Reason::UnsupportedConstruct)?;
    if c.eat("with") {
        let _ = c.eat("no");
        if !c.eat("data") {
            return Err(Reason::UnsupportedConstruct);
        }
    }
    c.end()?;
    maintenance(c.names, ObjectKind::Relation, vec![view])
}

/// `ALTER {SEQUENCE | VIEW | MATERIALIZED VIEW} [IF EXISTS] name …` whose
/// tail is only words, numbers and `. , = + -` (no expression, string or
/// parenthesis): `sql_alter` on it, `sql_admin` for `OWNER TO`, and
/// `sql_alter` on the table a sequence becomes `OWNED BY`.
fn alter_simple(c: &mut Cur<'_, '_>, kind: ObjectKind) -> Result<Analysis, Reason> {
    if c.eat("if") && !c.eat("exists") {
        return Err(Reason::UnsupportedConstruct);
    }
    let name = c.name().ok_or(Reason::UnsupportedConstruct)?;
    let mut a = Analysis::new(Kind::Alter);
    a.required.insert((Cap::Alter, SqlTarget::Object(c.names.existing_parts(kind, name)?)));
    while !c.done() {
        if c.eat("owner") {
            a.required.insert((Cap::Admin, SqlTarget::Server));
        } else if kind == ObjectKind::Sequence && c.eat("owned") {
            if !c.eat("by") {
                return Err(Reason::UnsupportedConstruct);
            }
            let owner = c.name().ok_or(Reason::UnsupportedConstruct)?;
            if owner.len() >= 2 {
                let table = c.names.existing_parts(ObjectKind::Relation, owner[..owner.len() - 1].to_vec())?;
                a.required.insert((Cap::Alter, SqlTarget::Object(table)));
            } else if owner != ["none"] {
                return Err(Reason::UnresolvableName);
            }
        } else if matches!(
            c.peek(),
            Some(T::Word(_) | T::Quoted(_) | T::Number | T::Punct(b'.' | b',' | b'=' | b'+' | b'-'))
        ) {
            c.i += 1;
        } else {
            return Err(Reason::UnsupportedConstruct);
        }
    }
    Ok(a)
}

/// `ALTER SYSTEM SET name …` / `RESET name` / `RESET ALL`: `sql_admin`,
/// except that a lexer or read-only-guard setting is refused. A reload makes
/// the change reach sessions that are already open.
fn alter_system(c: &mut Cur<'_, '_>) -> Result<Analysis, Reason> {
    let is_set = c.eat("set");
    if !is_set && !c.eat("reset") {
        return Err(Reason::UnsupportedConstruct);
    }
    if !is_set && c.eat("all") {
        return Err(Reason::LexerSettingChange);
    }
    let name = c.name().ok_or(Reason::UnsupportedConstruct)?.join(".");
    settings::requirement(&name)?;
    admin(Kind::Admin)
}
