//! Oracle statements classified from their tokens, before the parser sees
//! them: transaction control, `SET TRANSACTION / ROLE / CONSTRAINTS`,
//! `ALTER SESSION`, `CALL`, `LOCK TABLE`, `DROP`, `TRUNCATE`, `PURGE`,
//! `FLASHBACK TABLE`, `RENAME`, `COMMENT ON`, `ANALYZE`, sequence, synonym
//! and object DDL, the `sql_admin` families, and the PL/SQL unit headers.

// Oracle runs one statement per call, so a grammar here that stopped early
// could not let a second statement ride along; every grammar still ends
// with `end()`, so trailing text the grammar does not know is refused.
// A PL/SQL unit is read only up to its name: the body is stored or run
// whole, opaque, and only scanned for refused names (mod.rs).

use super::analyze::Analysis;
use super::lexer::{RawStatement, StrKind, TokKind};
use super::names::{reserved, Names, Part};
use super::settings;
use super::{routine_use, RoutineUse};
use crate::model::{ObjectKind, Reason, SqlCapability as Cap, SqlTarget, StatementKind as Kind};

#[derive(Debug, Clone, PartialEq, Eq)]
enum T {
    /// Unquoted word: lower-cased, and as written.
    Word(String, String),
    /// `"…"`, without the quotes.
    Ident(String),
    Str,
    Number,
    Punct(u8),
    Range,
}

struct Cur<'a, 'c> {
    toks: Vec<T>,
    i: usize,
    names: &'a Names<'c>,
}

type R<T> = Result<T, Reason>;

fn unsupported<T>() -> R<T> {
    Err(Reason::UnsupportedConstruct)
}

impl Cur<'_, '_> {
    fn peek(&self) -> Option<&T> {
        self.toks.get(self.i)
    }

    fn word_at(&self, k: usize) -> Option<&str> {
        match self.toks.get(self.i + k) {
            Some(T::Word(w, _)) => Some(w),
            _ => None,
        }
    }

    fn peek_word(&self) -> Option<&str> {
        self.word_at(0)
    }

    fn eat(&mut self, w: &str) -> bool {
        if self.peek_word() == Some(w) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_any(&mut self, ws: &[&str]) -> bool {
        match self.peek_word() {
            Some(w) if ws.contains(&w) => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }

    /// Any number of the words in `ws`, in any order.
    fn eat_all(&mut self, ws: &[&str]) {
        while self.eat_any(ws) {}
    }

    fn expect(&mut self, w: &str) -> R<()> {
        if self.eat(w) {
            Ok(())
        } else {
            unsupported()
        }
    }

    fn eat_punct(&mut self, c: u8) -> bool {
        if self.peek() == Some(&T::Punct(c)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, c: u8) -> R<()> {
        if self.eat_punct(c) {
            Ok(())
        } else {
            unsupported()
        }
    }

    fn expect_str(&mut self) -> R<()> {
        if self.peek() == Some(&T::Str) {
            self.i += 1;
            Ok(())
        } else {
            unsupported()
        }
    }

    fn done(&self) -> bool {
        self.i >= self.toks.len()
    }

    fn end(&self) -> R<()> {
        if self.done() {
            Ok(())
        } else {
            unsupported()
        }
    }

    /// One name part: an unquoted non-reserved word or a quoted identifier.
    fn part(&mut self) -> R<Part> {
        let p = match self.peek() {
            Some(T::Word(w, raw)) => {
                if reserved(w) {
                    return Err(Reason::ReservedWordAsName);
                }
                Part::unquoted(raw)
            }
            Some(T::Ident(s)) => Part::quoted(s),
            _ => return unsupported(),
        };
        self.i += 1;
        Ok(p)
    }

    /// `name [. name]…`, as written.
    fn raw_name(&mut self) -> R<Vec<Part>> {
        let mut parts = vec![self.part()?];
        while self.eat_punct(b'.') {
            parts.push(self.part()?);
        }
        Ok(parts)
    }

    fn existing(&mut self, kind: ObjectKind) -> R<SqlTarget> {
        let raw = self.raw_name()?;
        Ok(SqlTarget::Object(self.names.existing(kind, &raw)?))
    }

    fn new_object(&mut self, kind: ObjectKind) -> R<SqlTarget> {
        let raw = self.raw_name()?;
        Ok(SqlTarget::Object(self.names.new_object(kind, &raw)?))
    }

    /// `name {, name}`.
    fn objects(&mut self, kind: ObjectKind) -> R<Vec<SqlTarget>> {
        let mut out = vec![self.existing(kind)?];
        while self.eat_punct(b',') {
            out.push(self.existing(kind)?);
        }
        Ok(out)
    }

    fn if_exists(&mut self) {
        if self.word_at(0) == Some("if") && self.word_at(1) == Some("exists") {
            self.i += 2;
        }
    }

    fn if_not_exists(&mut self) {
        if self.word_at(0) == Some("if") && self.word_at(1) == Some("not") && self.word_at(2) == Some("exists") {
            self.i += 3;
        }
    }

    fn or_replace(&mut self) -> R<bool> {
        if self.eat("or") {
            self.expect("replace")?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The rest holds `w`.
    fn rest_has(&self, w: &str) -> bool {
        self.toks[self.i..].iter().any(|t| matches!(t, T::Word(x, _) if x == w))
    }
}

fn tokens(text: &str, raw: &RawStatement) -> Vec<T> {
    let mut out = Vec::new();
    for t in raw.tokens.iter().filter(|t| !t.is_comment()) {
        let s = &text[t.start..t.end];
        out.push(match t.kind {
            TokKind::Word => T::Word(s.to_ascii_lowercase(), s.to_string()),
            TokKind::QuotedIdent => T::Ident(s[1..s.len() - 1].to_string()),
            TokKind::Str(StrKind::Single | StrKind::National | StrKind::Q | StrKind::NationalQ) => T::Str,
            TokKind::Number => T::Number,
            TokKind::Range => T::Range,
            TokKind::Punct(c) => T::Punct(c),
            TokKind::LineComment | TokKind::BlockComment => continue,
        });
    }
    out
}

fn with(kind: Kind, req: &[(Cap, SqlTarget)]) -> Analysis {
    let mut a = Analysis::new(kind);
    a.required.extend(req.iter().cloned());
    a
}

fn server(kind: Kind, cap: Cap) -> R<Analysis> {
    Ok(with(kind, &[(cap, SqlTarget::Server)]))
}

fn admin() -> R<Analysis> {
    server(Kind::Admin, Cap::Admin)
}

fn tx(kind: Kind) -> R<Analysis> {
    let mut a = Analysis::new(kind);
    a.tx_control = true;
    Ok(a)
}

/// Words no option list may hold: a query or another statement.
fn is_statement_start(w: &str) -> bool {
    matches!(
        w,
        "select"
            | "insert"
            | "update"
            | "delete"
            | "merge"
            | "begin"
            | "declare"
            | "call"
            | "create"
            | "drop"
            | "grant"
            | "revoke"
            | "commit"
            | "rollback"
            | "savepoint"
            | "truncate"
            | "lock"
    )
}

/// Free option tokens after a statement's object (`ALTER INDEX … REBUILD`,
/// `CREATE SEQUENCE … CACHE 20`): no word that starts a statement and no
/// subquery.
fn options_only(c: &mut Cur<'_, '_>) -> R<()> {
    while let Some(t) = c.peek() {
        match t {
            T::Word(w, _) if is_statement_start(w) => return unsupported(),
            T::Punct(b'(') if matches!(c.toks.get(c.i + 1), Some(T::Word(w, _)) if w == "select" || w == "with") => {
                return unsupported()
            }
            _ => c.i += 1,
        }
    }
    Ok(())
}

/// Classify `raw` if it is a SQL statement this module owns; `None` hands it
/// to the parser.
pub(crate) fn classify(text: &str, raw: &RawStatement, names: &Names<'_>) -> Option<R<Analysis>> {
    let toks = tokens(text, raw);
    let first = match toks.first() {
        Some(T::Word(w, _)) => w.clone(),
        _ => return None,
    };
    let mut c = Cur { toks, i: 1, names };
    let result = match first.as_str() {
        "commit" => commit(&mut c),
        "rollback" => rollback(&mut c),
        "savepoint" => (|| {
            c.part()?;
            c.end()?;
            tx(Kind::TxSavepoint)
        })(),
        "set" => set(&mut c),
        "alter" => return alter(&mut c),
        "create" => return create(&mut c),
        "drop" => drop(&mut c),
        "truncate" => truncate(&mut c),
        "purge" => purge(&mut c),
        "flashback" => flashback(&mut c),
        "lock" => lock(&mut c),
        "rename" => rename(&mut c),
        "comment" => comment(&mut c),
        "analyze" => analyze(&mut c),
        "call" => call(&mut c),
        // The sql_admin families. Their arguments are not read further: a
        // statement that needs sql_admin is held to the bar `unclassified`
        // already is (§4.2).
        "grant" | "revoke" | "audit" | "noaudit" | "associate" | "disassociate" => admin(),
        // `EXPLAIN PLAN` writes the plan into a table (`PLAN_TABLE` or
        // `INTO t`): not classified.
        "explain" => Err(Reason::UnsupportedStatement),
        _ => return None,
    };
    Some(result)
}

/// `COMMIT [WORK] [COMMENT '…'] [WRITE …]`; `FORCE` resolves another
/// session's in-doubt distributed transaction (`sql_admin`).
fn commit(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.eat("work");
    if c.eat("force") {
        return admin();
    }
    if c.eat("comment") {
        c.expect_str()?;
    }
    if c.eat("write") {
        c.eat_any(&["wait", "nowait"]);
        c.eat_any(&["immediate", "batch"]);
    }
    c.end()?;
    tx(Kind::TxCommit)
}

/// `ROLLBACK [WORK] [TO [SAVEPOINT] name]`; `FORCE` as for `COMMIT`.
fn rollback(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.eat("work");
    if c.eat("force") {
        return admin();
    }
    if c.eat("to") {
        c.eat("savepoint");
        c.part()?;
        c.end()?;
        // The transaction stays open.
        return tx(Kind::TxSavepoint);
    }
    c.end()?;
    tx(Kind::TxRollback)
}

/// SQL `SET`: `TRANSACTION`, `ROLE`, `CONSTRAINT[S]`. Every other `SET` is
/// a SQL*Plus command and refused before it gets here.
fn set(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if c.eat("transaction") {
        return set_transaction(c);
    }
    if c.eat("role") {
        return admin();
    }
    if c.eat_any(&["constraint", "constraints"]) {
        // Deferral of constraint checks, for this transaction only.
        if !c.eat("all") {
            c.raw_name()?;
            while c.eat_punct(b',') {
                c.raw_name()?;
            }
        }
        if !c.eat_any(&["immediate", "deferred"]) {
            return unsupported();
        }
        c.end()?;
        return server(Kind::SetSession, Cap::Select);
    }
    Err(Reason::ClientCommand)
}

/// `SET TRANSACTION { READ ONLY | READ WRITE | ISOLATION LEVEL … | USE
/// ROLLBACK SEGMENT rs } [NAME '…'] | NAME '…'`.
fn set_transaction(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let mut clause = false;
    let mut rollback_segment = false;
    if c.eat("read") {
        if c.eat("write") {
            // Lifts the read-only guard (§5.3).
            return Err(Reason::ReadOnlyGuardChange);
        }
        c.expect("only")?;
        clause = true;
    } else if c.eat("isolation") {
        c.expect("level")?;
        if !(c.eat("serializable") || (c.eat("read") && c.eat("committed"))) {
            return unsupported();
        }
        clause = true;
    } else if c.eat("use") {
        c.expect("rollback")?;
        c.expect("segment")?;
        c.part()?;
        clause = true;
        rollback_segment = true;
    }
    if c.eat("name") {
        c.expect_str()?;
        clause = true;
    }
    if !clause {
        return unsupported();
    }
    c.end()?;
    if rollback_segment {
        return admin();
    }
    tx(Kind::TxBegin)
}

/// `ALTER SESSION`: `SET param = value …` per parameter (settings.rs);
/// every other form (`ENABLE / DISABLE / FORCE PARALLEL`, `COMMIT IN
/// PROCEDURE`, `RESUMABLE`, `ADVISE`, `CLOSE DATABASE LINK`, `SYNC WITH
/// PRIMARY`) is `sql_admin`.
fn alter_session(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if c.rest_has("container") {
        return Err(Reason::SessionScopeChange);
    }
    if !c.eat("set") {
        return server(Kind::SetSession, Cap::Admin);
    }
    let mut a = Analysis::new(Kind::SetSession);
    while !c.done() {
        let (name, quoted) = match c.peek() {
            Some(T::Word(w, _)) => (w.clone(), false),
            Some(T::Ident(s)) => (s.clone(), true),
            _ => return unsupported(),
        };
        c.i += 1;
        let cap = settings::requirement(&name, quoted)?;
        // `SET EVENTS '…'` takes no `=`.
        if !c.eat_punct(b'=') && (quoted || name != "events") {
            return unsupported();
        }
        if !quoted && name == "isolation_level" {
            if !(c.eat("serializable") || (c.eat("read") && c.eat("committed"))) {
                return unsupported();
            }
        } else {
            if !c.eat_punct(b'-') {
                c.eat_punct(b'+');
            }
            match c.peek() {
                Some(T::Word(w, _)) if is_statement_start(w) => return unsupported(),
                Some(T::Word(..) | T::Ident(_) | T::Str | T::Number) => c.i += 1,
                _ => return unsupported(),
            }
        }
        a.required.insert((cap, SqlTarget::Server));
    }
    if a.required.is_empty() {
        return unsupported();
    }
    Ok(a)
}

fn alter_object(c: &mut Cur<'_, '_>, kind: ObjectKind) -> R<Analysis> {
    let t = c.existing(kind)?;
    options_only(c)?;
    Ok(with(Kind::Alter, &[(Cap::Alter, t)]))
}

/// `ALTER …` other than `TABLE` (the parser's).
fn alter(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    let r = (|| -> R<Option<Analysis>> {
        let Some(w) = c.peek_word().map(str::to_string) else { return unsupported() };
        c.i += 1;
        let a = match w.as_str() {
            "table" => return Ok(None),
            "session" => alter_session(c)?,
            "view" => alter_object(c, ObjectKind::Relation)?,
            "synonym" => alter_object(c, ObjectKind::Relation)?,
            "sequence" => alter_object(c, ObjectKind::Sequence)?,
            "procedure" | "function" | "package" => alter_object(c, ObjectKind::Routine)?,
            "type" => alter_object(c, ObjectKind::Type)?,
            "materialized" => {
                c.expect("view")?;
                if c.eat("log") {
                    c.eat("force");
                    c.expect("on")?;
                }
                alter_object(c, ObjectKind::Relation)?
            }
            "index" => {
                let i = c.existing(ObjectKind::Index)?;
                let mut a = with(Kind::Alter, &[(Cap::Alter, i)]);
                if c.word_at(0) == Some("rename") && c.word_at(1) == Some("to") {
                    // The index moves to a new path.
                    c.i += 2;
                    a.required.insert((Cap::Create, c.new_object(ObjectKind::Index)?));
                    c.end()?;
                } else {
                    options_only(c)?;
                }
                a
            }
            "trigger" => {
                // Trigger names are per schema; the table is not named here.
                c.raw_name()?;
                options_only(c)?;
                with(Kind::Alter, &[(Cap::Alter, SqlTarget::Server)])
            }
            // Code loaded into the server (refused by name in mod.rs too).
            "java" | "library" | "mle" => return Err(Reason::ServerFileOrOsAccess),
            // SYSTEM, DATABASE, PLUGGABLE DATABASE, USER, ROLE, PROFILE,
            // TABLESPACE, PUBLIC SYNONYM, RESOURCE COST, AUDIT POLICY, …
            _ => admin()?,
        };
        Ok(Some(a))
    })();
    match r {
        Ok(Some(a)) => Some(Ok(a)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

/// `CREATE …` that is not a PL/SQL unit. Tables, views, materialized views
/// and indexes go to the parser.
fn create(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    let r = (|| -> R<Option<Analysis>> {
        let or_replace = c.or_replace()?;
        let Some(w) = c.peek_word().map(str::to_string) else { return unsupported() };
        let a = match w.as_str() {
            "sequence" => {
                c.i += 1;
                c.if_not_exists();
                let s = c.new_object(ObjectKind::Sequence)?;
                options_only(c)?;
                with(Kind::CreateSequence, &[(Cap::Create, s)])
            }
            "synonym" => {
                c.i += 1;
                c.if_not_exists();
                let s = c.new_object(ObjectKind::Relation)?;
                c.expect("for")?;
                let target = c.raw_name()?;
                if target.len() > 2 {
                    return Err(Reason::UnresolvableName);
                }
                c.end()?;
                let mut a = with(Kind::CreateView, &[(Cap::Create, s.clone())]);
                if or_replace {
                    a.required.insert((Cap::Alter, s));
                }
                a
            }
            // A PUBLIC synonym is visible to every user of the database.
            "public" => admin()?,
            // Several objects in one statement.
            "schema" => return Err(Reason::UnsupportedStatement),
            "user" | "role" | "profile" | "tablespace" | "temporary" | "undo" | "bigfile" | "smallfile"
            | "database" | "pluggable" | "context" | "edition" | "outline" | "restore" | "rollback" | "audit"
            | "lockdown" | "diskgroup" | "cluster" | "dimension" | "indextype" | "operator" | "flashback"
            | "attribute" | "hierarchy" | "analytic" | "domain" | "property" | "logical" => admin()?,
            _ => return Ok(None),
        };
        Ok(Some(a))
    })();
    match r {
        Ok(Some(a)) => Some(Ok(a)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

fn drops(c: &mut Cur<'_, '_>, kind: ObjectKind, options: &[&str]) -> R<Analysis> {
    c.if_exists();
    let t = c.existing(kind)?;
    c.eat_all(options);
    c.end()?;
    Ok(with(Kind::Drop, &[(Cap::Drop, t)]))
}

fn drop(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let Some(w) = c.peek_word().map(str::to_string) else { return unsupported() };
    c.i += 1;
    match w.as_str() {
        "table" | "view" => {
            c.if_exists();
            let t = c.existing(ObjectKind::Relation)?;
            let mut a = with(Kind::Drop, &[(Cap::Drop, t)]);
            if c.eat("cascade") {
                c.expect("constraints")?;
                // Drops other tables' foreign keys, which it does not name.
                a.required.insert((Cap::Drop, SqlTarget::Server));
            }
            c.eat("purge");
            c.end()?;
            Ok(a)
        }
        "materialized" => {
            c.expect("view")?;
            if c.eat("log") {
                c.expect("on")?;
                let t = c.existing(ObjectKind::Relation)?;
                c.end()?;
                return Ok(with(Kind::Alter, &[(Cap::Alter, t)]));
            }
            let t = c.existing(ObjectKind::Relation)?;
            if c.eat("preserve") {
                c.expect("table")?;
            }
            c.end()?;
            Ok(with(Kind::Drop, &[(Cap::Drop, t)]))
        }
        "index" => drops(c, ObjectKind::Index, &["online", "force", "deferred", "immediate", "invalidation"]),
        "sequence" => drops(c, ObjectKind::Sequence, &[]),
        "synonym" => drops(c, ObjectKind::Relation, &["force"]),
        "procedure" | "function" => drops(c, ObjectKind::Routine, &[]),
        "package" => {
            c.eat("body");
            drops(c, ObjectKind::Routine, &[])
        }
        "type" => {
            c.eat("body");
            drops(c, ObjectKind::Type, &["force", "validate"])
        }
        "trigger" => {
            c.if_exists();
            c.raw_name()?;
            c.end()?;
            // Trigger names are per schema; the table is not named here.
            server(Kind::Drop, Cap::Drop)
        }
        // PUBLIC SYNONYM, USER, ROLE, PROFILE, TABLESPACE, DIRECTORY,
        // LIBRARY, JAVA, CONTEXT, …
        _ => admin(),
    }
}

/// `TRUNCATE TABLE t [… STORAGE] [CASCADE]`.
fn truncate(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.expect("table")?;
    let t = c.existing(ObjectKind::Relation)?;
    c.eat_all(&["preserve", "purge", "materialized", "view", "log", "drop", "all", "reuse", "storage"]);
    let cascade = c.eat("cascade");
    c.end()?;
    let mut a = with(Kind::Truncate, &[(Cap::Drop, t)]);
    if cascade {
        // Empties child tables the statement does not name.
        a.required.insert((Cap::Drop, SqlTarget::Server));
    }
    Ok(a)
}

/// `PURGE { TABLE t | INDEX i | RECYCLEBIN | DBA_RECYCLEBIN | TABLESPACE … }`.
fn purge(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let Some(w) = c.peek_word().map(str::to_string) else { return unsupported() };
    c.i += 1;
    let target = match w.as_str() {
        "table" => c.existing(ObjectKind::Relation)?,
        "index" => c.existing(ObjectKind::Index)?,
        // The caller's own recycle bin: objects the statement does not name.
        "recyclebin" => SqlTarget::Server,
        "dba_recyclebin" | "tablespace" => return admin(),
        _ => return unsupported(),
    };
    c.end()?;
    Ok(with(Kind::Drop, &[(Cap::Drop, target)]))
}

/// Words a `FLASHBACK TABLE … TO {SCN | TIMESTAMP}` expression may use.
const FLASHBACK_WORDS: &[&str] = &[
    "systimestamp",
    "sysdate",
    "current_timestamp",
    "localtimestamp",
    "interval",
    "timestamp",
    "to_timestamp",
    "to_date",
    "timestamp_to_scn",
    "day",
    "hour",
    "minute",
    "second",
    "month",
    "year",
];

/// `FLASHBACK TABLE t {, t} TO { BEFORE DROP [RENAME TO n] | {SCN |
/// TIMESTAMP} expr | RESTORE POINT rp } [{ENABLE | DISABLE} TRIGGERS]`.
fn flashback(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if c.eat_any(&["database", "standby", "pluggable"]) {
        return admin();
    }
    c.expect("table")?;
    let tables = c.objects(ObjectKind::Relation)?;
    c.expect("to")?;
    let mut a = Analysis::new(Kind::Alter);
    if c.eat("before") {
        c.expect("drop")?;
        if c.eat("rename") {
            c.expect("to")?;
            a.required.insert((Cap::Create, c.new_object(ObjectKind::Relation)?));
        }
    } else if c.eat_any(&["scn", "timestamp"]) {
        // A constant expression only: nothing that reads a table or calls
        // user code.
        let start = c.i;
        while let Some(t) = c.peek() {
            match t {
                T::Word(w, _) if w == "enable" || w == "disable" => break,
                T::Word(w, _) if FLASHBACK_WORDS.contains(&w.as_str()) => c.i += 1,
                T::Str | T::Number | T::Punct(b'+' | b'-' | b'*' | b'/' | b'(' | b')' | b',') => c.i += 1,
                _ => return unsupported(),
            }
        }
        if c.i == start {
            return unsupported();
        }
    } else if c.eat("restore") {
        c.expect("point")?;
        c.part()?;
    } else {
        return unsupported();
    }
    if c.eat_any(&["enable", "disable"]) {
        c.expect("triggers")?;
    }
    c.end()?;
    for t in tables {
        a.required.insert((Cap::Alter, t));
    }
    Ok(a)
}

/// `LOCK TABLE t [PARTITION (p)] {, …} IN mode MODE [NOWAIT | WAIT n]`.
fn lock(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.expect("table")?;
    let mut a = Analysis::new(Kind::Lock);
    loop {
        let t = c.existing(ObjectKind::Relation)?;
        if c.eat_any(&["partition", "subpartition"]) {
            c.expect_punct(b'(')?;
            c.part()?;
            c.expect_punct(b')')?;
        }
        a.required.insert((Cap::Select, t.clone()));
        a.required.insert((Cap::Update, t));
        if !c.eat_punct(b',') {
            break;
        }
    }
    c.expect("in")?;
    let start = c.i;
    c.eat_all(&["row", "share", "exclusive", "update"]);
    if c.i == start {
        return unsupported();
    }
    c.expect("mode")?;
    if !c.eat("nowait") && c.eat("wait") {
        if c.peek() != Some(&T::Number) {
            return unsupported();
        }
        c.i += 1;
    }
    c.end()?;
    Ok(a)
}

/// `RENAME old TO new` (objects of the current schema only).
fn rename(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let old = c.raw_name()?;
    c.expect("to")?;
    let new = c.raw_name()?;
    c.end()?;
    if old.len() != 1 || new.len() != 1 {
        return unsupported();
    }
    let old = c.names.existing(ObjectKind::Relation, &old)?;
    let new = c.names.new_object(ObjectKind::Relation, &new)?;
    Ok(with(Kind::Alter, &[(Cap::Alter, SqlTarget::Object(old)), (Cap::Create, SqlTarget::Object(new))]))
}

/// `COMMENT ON { TABLE t | COLUMN t.c | MATERIALIZED VIEW mv } IS '…'`.
fn comment(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.expect("on")?;
    let t = if c.eat("table") {
        c.existing(ObjectKind::Relation)?
    } else if c.eat("column") {
        let name = c.raw_name()?;
        if name.len() < 2 {
            return unsupported();
        }
        SqlTarget::Object(c.names.existing(ObjectKind::Relation, &name[..name.len() - 1])?)
    } else if c.eat("materialized") {
        c.expect("view")?;
        c.existing(ObjectKind::Relation)?
    } else {
        return unsupported();
    };
    c.expect("is")?;
    c.expect_str()?;
    c.end()?;
    Ok(with(Kind::Comment, &[(Cap::Alter, t)]))
}

/// `ANALYZE { TABLE t | INDEX i } …`; `… INTO t` writes rows: refused.
fn analyze(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let t = if c.eat("table") {
        c.existing(ObjectKind::Relation)?
    } else if c.eat("index") {
        c.existing(ObjectKind::Index)?
    } else {
        return unsupported();
    };
    while let Some(tok) = c.peek() {
        match tok {
            T::Word(w, _) if w == "into" => return unsupported(),
            T::Word(..) | T::Number | T::Punct(b'(' | b')' | b',') => c.i += 1,
            _ => return unsupported(),
        }
    }
    Ok(with(Kind::Maintenance, &[(Cap::Alter, t)]))
}

/// `CALL [schema.][package.]routine(args)`: constants only (as T-SQL's
/// `EXEC`); `INTO :bind` is never bound by the caller and is refused.
fn call(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let parts = c.raw_name()?;
    c.expect_punct(b'(')?;
    if !c.eat_punct(b')') {
        loop {
            // `name => value`
            if matches!(c.peek(), Some(T::Word(..) | T::Ident(_)))
                && c.toks.get(c.i + 1) == Some(&T::Punct(b'='))
                && c.toks.get(c.i + 2) == Some(&T::Punct(b'>'))
            {
                c.i += 3;
            }
            if !c.eat_punct(b'-') {
                c.eat_punct(b'+');
            }
            match c.peek() {
                Some(T::Str | T::Number) => c.i += 1,
                Some(T::Word(w, _)) if w == "null" => c.i += 1,
                _ => return unsupported(),
            }
            if !c.eat_punct(b',') {
                break;
            }
        }
        c.expect_punct(b')')?;
    }
    c.end()?;
    let mut a = Analysis::new(Kind::Call);
    a.opaque = true;
    let usage = match parts.as_slice() {
        [_] => RoutineUse::Routines(vec![c.names.existing(ObjectKind::Routine, &parts)?]),
        [_, _] | [_, _, _] => routine_use(c.names, &parts)?,
        _ => return Err(Reason::UnresolvableName),
    };
    match usage {
        RoutineUse::Dynamic => {
            a.kind = Kind::Execute;
            a.required.insert((Cap::Execute, SqlTarget::Server));
        }
        RoutineUse::Routines(rs) => {
            for r in rs {
                a.required.insert((Cap::Execute, SqlTarget::Object(r)));
            }
        }
    }
    Ok(a)
}

/// DDL and database events: a trigger on them is schema- or database-wide.
const SYSTEM_EVENTS: &[&str] = &[
    "create",
    "alter",
    "drop",
    "analyze",
    "associate",
    "audit",
    "comment",
    "ddl",
    "disassociate",
    "grant",
    "noaudit",
    "rename",
    "revoke",
    "truncate",
    "startup",
    "shutdown",
    "servererror",
    "logon",
    "logoff",
    "suspend",
    "clone",
    "unplug",
    "db_role_change",
    "set",
];

/// `CREATE … TRIGGER name {BEFORE | AFTER | INSTEAD OF | FOR} events ON
/// {table | SCHEMA | DATABASE} …`. A DML trigger is `sql_create` on its
/// table plus opaque `sql_execute` on the server (its body runs on every
/// later write, T127 / T128 precedent); a system trigger is `sql_admin`.
fn trigger(c: &mut Cur<'_, '_>, or_replace: bool) -> R<Analysis> {
    c.if_not_exists();
    c.raw_name()?;
    let mut system = false;
    loop {
        match c.peek() {
            Some(T::Word(w, _)) if w == "on" => break,
            Some(T::Word(w, _)) => {
                system |= SYSTEM_EVENTS.contains(&w.as_str());
                c.i += 1;
            }
            Some(T::Ident(_) | T::Punct(b',')) => c.i += 1,
            _ => return unsupported(),
        }
    }
    c.expect("on")?;
    let opaque_admin = || -> R<Analysis> {
        let mut a = with(Kind::CreateTrigger, &[(Cap::Admin, SqlTarget::Server)]);
        a.opaque = true;
        Ok(a)
    };
    if system || c.eat_any(&["schema", "database", "pluggable"]) {
        return opaque_admin();
    }
    if c.peek_word() == Some("nested") {
        return unsupported();
    }
    let parts = c.raw_name()?;
    if parts.last().and_then(Part::keyword).as_deref() == Some("schema") {
        // `ON hr.SCHEMA`.
        return opaque_admin();
    }
    let t = SqlTarget::Object(c.names.existing(ObjectKind::Relation, &parts)?);
    let mut a = with(Kind::CreateTrigger, &[(Cap::Create, t.clone()), (Cap::Execute, SqlTarget::Server)]);
    a.opaque = true;
    if or_replace {
        a.required.insert((Cap::Alter, t));
    }
    Ok(a)
}

/// A PL/SQL unit, read up to its name. An anonymous block runs whole:
/// opaque `sql_execute` on the server (§4.2). A stored unit is compiled and
/// kept, not run: `sql_create` on it (and `sql_alter` when it replaces one
/// or adds a body to an existing package or type). Stored units run with
/// their owner's rights unless `AUTHID CURRENT_USER`: the path names that
/// owner's schema, so `sql_create` there is the grant of those rights.
pub(crate) fn unit(text: &str, raw: &RawStatement, names: &Names<'_>) -> R<Analysis> {
    let toks = tokens(text, raw);
    let mut c = Cur { toks, i: 0, names };
    let block = || -> R<Analysis> {
        let mut a = with(Kind::Do, &[(Cap::Execute, SqlTarget::Server)]);
        a.opaque = true;
        Ok(a)
    };
    match c.peek_word() {
        Some("begin" | "declare") => return block(),
        // Inline PL/SQL in a query: not classified.
        Some("with") => return unsupported(),
        Some("create") => c.i += 1,
        Some(_) => return Err(Reason::UnsupportedStatement),
        None => {
            // `<<label>> [<<label>>…] {BEGIN | DECLARE}`.
            while c.eat_punct(b'<') {
                c.expect_punct(b'<')?;
                c.part()?;
                c.expect_punct(b'>')?;
                c.expect_punct(b'>')?;
            }
            return match c.peek_word() {
                Some("begin" | "declare") if c.i > 0 => block(),
                _ => Err(Reason::UnsupportedStatement),
            };
        }
    }
    let or_replace = c.or_replace()?;
    c.eat_any(&["editionable", "noneditionable"]);
    let Some(w) = c.peek_word().map(str::to_string) else { return unsupported() };
    c.i += 1;
    let (kind, object, body) = match w.as_str() {
        "procedure" | "function" => (Kind::CreateRoutine, ObjectKind::Routine, false),
        "package" => (Kind::CreateRoutine, ObjectKind::Routine, c.eat("body")),
        "type" => (Kind::CreateType, ObjectKind::Type, c.eat("body")),
        "trigger" => return trigger(&mut c, or_replace),
        "library" | "java" | "mle" => return Err(Reason::ServerFileOrOsAccess),
        _ => return Err(Reason::UnsupportedStatement),
    };
    c.if_not_exists();
    let t = c.new_object(object)?;
    let mut a = with(kind, &[(Cap::Create, t.clone())]);
    if or_replace || body {
        a.required.insert((Cap::Alter, t));
    }
    Ok(a)
}
