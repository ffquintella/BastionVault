//! T-SQL statements classified from their tokens, before the parser sees
//! them: transaction control, `SET` options, `USE`, `EXEC` / `EXECUTE`
//! (procedures, dynamic SQL, `EXECUTE AS`), `REVERT`, `DROP`, `TRUNCATE`,
//! routine and trigger DDL, cursors and the `sql_admin` families.

// T-SQL needs no `;` between statements, so a grammar here that stopped
// early would let a second statement ride along. Every grammar therefore
// ends with `end()`: anything after the statement makes it unclassifiable.
// Routine and trigger definitions are the exception the server makes
// itself: their body is the rest of the batch, stored and not run.

// A statement this module does not route (`None`) goes to the parser,
// which reads T-SQL without requiring `;` and refuses a span holding two.

use super::analyze::Analysis;
use super::functions;
use super::lexer::{RawStatement, StrKind, TokKind};
use super::names::{reserved, Names};
use super::settings;
use crate::model::{ObjectKind, Reason, SqlCapability as Cap, SqlTarget, StatementKind as Kind};

#[derive(Debug, Clone, PartialEq, Eq)]
enum T {
    /// Unquoted word (incl. `@var`): lower-cased, and as written.
    Word(String, String),
    /// Bracketed or double-quoted identifier, unescaped.
    Ident(String),
    Str,
    Number,
    Punct(u8),
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

    /// One name part: an unquoted non-reserved word (not a variable) or a
    /// quoted identifier.
    fn part(&mut self) -> R<String> {
        let p = match self.peek() {
            Some(T::Word(w, raw)) => {
                if reserved(w) {
                    return Err(Reason::ReservedWordAsName);
                }
                if raw.starts_with('@') {
                    return unsupported();
                }
                raw.clone()
            }
            Some(T::Ident(s)) => s.clone(),
            _ => return unsupported(),
        };
        self.i += 1;
        Ok(p)
    }

    /// `name [. name]…`, as written; `db..name` keeps its empty part.
    fn raw_name(&mut self) -> R<Vec<String>> {
        let mut parts = vec![self.part()?];
        while self.eat_punct(b'.') {
            if self.peek() == Some(&T::Punct(b'.')) {
                parts.push(String::new());
                continue;
            }
            parts.push(self.part()?);
        }
        Ok(parts)
    }

    fn existing(&mut self, kind: ObjectKind) -> R<SqlTarget> {
        let raw = self.raw_name()?;
        let parts: Vec<&str> = raw.iter().map(String::as_str).collect();
        Ok(SqlTarget::Object(self.names.existing(kind, &parts)?))
    }

    fn new_object(&mut self, kind: ObjectKind) -> R<SqlTarget> {
        let raw = self.raw_name()?;
        let parts: Vec<&str> = raw.iter().map(String::as_str).collect();
        Ok(SqlTarget::Object(self.names.new_object(kind, &parts)?))
    }

    /// `name {, name}`.
    fn objects(&mut self, kind: ObjectKind) -> R<Vec<SqlTarget>> {
        let mut out = vec![self.existing(kind)?];
        while self.eat_punct(b',') {
            out.push(self.existing(kind)?);
        }
        Ok(out)
    }

    fn if_exists(&mut self) -> bool {
        if self.word_at(0) == Some("if") && self.word_at(1) == Some("exists") {
            self.i += 2;
            true
        } else {
            false
        }
    }

    /// A transaction or savepoint name: an identifier or `@variable`.
    fn tx_name(&mut self) -> bool {
        match self.peek() {
            Some(T::Word(w, _)) if !reserved(w) => {
                self.i += 1;
                true
            }
            Some(T::Ident(_)) => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }

    /// The rest holds `EXECUTE AS` / `EXEC AS` (definer rights).
    fn rest_has_execute_as(&self) -> bool {
        self.toks[self.i..].windows(2).any(|p| {
            matches!(&p[0], T::Word(w, _) if w == "execute" || w == "exec")
                && matches!(&p[1], T::Word(w, _) if w == "as")
        })
    }
}

fn tokens(text: &str, raw: &RawStatement) -> Vec<T> {
    let mut out = Vec::new();
    for t in raw.tokens.iter().filter(|t| !t.is_comment()) {
        let s = &text[t.start..t.end];
        out.push(match t.kind {
            TokKind::Word => T::Word(s.to_ascii_lowercase(), s.to_string()),
            TokKind::QuotedIdent(b'[') => T::Ident(s[1..s.len() - 1].replace("]]", "]")),
            TokKind::QuotedIdent(_) => T::Ident(s[1..s.len() - 1].replace("\"\"", "\"")),
            TokKind::Str(StrKind::Single | StrKind::National | StrKind::Double) => T::Str,
            TokKind::Number | TokKind::Binary => T::Number,
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

/// Classify `raw` if it is a statement this module owns; `None` hands it to
/// the parser.
pub(crate) fn classify(text: &str, raw: &RawStatement, names: &Names<'_>) -> Option<R<Analysis>> {
    let toks = tokens(text, raw);
    let first = match toks.first() {
        Some(T::Word(w, _)) => w.clone(),
        _ => return None,
    };
    let mut c = Cur { toks, i: 1, names };
    let result = match first.as_str() {
        "begin" => begin(&mut c),
        "commit" => (|| {
            c.eat_any(&["tran", "transaction", "work"]);
            c.tx_name();
            if c.eat("with") {
                // WITH ( DELAYED_DURABILITY = { OFF | ON } )
                let ok = c.eat_punct(b'(')
                    && c.eat("delayed_durability")
                    && c.eat_punct(b'=')
                    && c.eat_any(&["on", "off"])
                    && c.eat_punct(b')');
                if !ok {
                    return unsupported();
                }
            }
            c.end()?;
            tx(Kind::TxCommit)
        })(),
        "rollback" => (|| {
            let work = c.eat("work");
            if !work {
                c.eat_any(&["tran", "transaction"]);
            }
            let named = !work && c.tx_name();
            c.end()?;
            // `ROLLBACK TRAN name` may name a savepoint (the transaction
            // stays open) or the outer transaction; the caller re-reads it.
            tx(if named { Kind::TxSavepoint } else { Kind::TxRollback })
        })(),
        "save" => (|| {
            if !c.eat_any(&["tran", "transaction"]) || !c.tx_name() {
                return unsupported();
            }
            c.end()?;
            tx(Kind::TxSavepoint)
        })(),
        "set" => return set(&mut c),
        "use" => (|| {
            let db = c.part()?;
            c.names.database(&db)?;
            c.end()?;
            server(Kind::SetSession, Cap::Select)
        })(),
        "exec" | "execute" => exec(&mut c),
        "revert" => (|| {
            // REVERT [WITH COOKIE = @c]: back to the login's own context.
            if c.eat("with") {
                if !(c.eat("cookie") && c.eat_punct(b'=') && matches!(c.peek_word(), Some(w) if w.starts_with('@'))) {
                    return unsupported();
                }
                c.i += 1;
            }
            c.end()?;
            let mut a = with(Kind::Admin, &[(Cap::Admin, SqlTarget::Server)]);
            a.opaque = true;
            Ok(a)
        })(),
        "truncate" => (|| {
            c.expect("table")?;
            let t = c.existing(ObjectKind::Relation)?;
            c.end()?;
            Ok(with(Kind::Truncate, &[(Cap::Drop, t)]))
        })(),
        "drop" => drop(&mut c),
        "create" => return create(&mut c),
        "alter" => return alter(&mut c),
        "enable" | "disable" => toggle_trigger(&mut c),
        "update" if c.peek_word() == Some("statistics") => (|| {
            c.i += 1;
            let t = c.existing(ObjectKind::Relation)?;
            // Optional statistics names and WITH options: words only.
            while let Some(t) = c.peek() {
                match t {
                    T::Word(w, _) if is_statement_start(w) => return unsupported(),
                    T::Word(..) | T::Ident(_) | T::Number | T::Punct(b',' | b'(' | b')' | b'=') => c.i += 1,
                    _ => return unsupported(),
                }
            }
            Ok(with(Kind::Maintenance, &[(Cap::Alter, t)]))
        })(),
        "open" => cursor(&mut c, Kind::FetchCursor),
        "close" => cursor(&mut c, Kind::CloseCursor),
        "deallocate" => cursor(&mut c, Kind::CloseCursor),
        "fetch" => fetch(&mut c),
        // The sql_admin families. Their arguments are not read further: a
        // statement that needs sql_admin is held to the bar `unclassified`
        // already is (§4.2), so nothing is gained by smuggling into one.
        "grant" | "deny" | "revoke" | "dbcc" | "kill" | "shutdown" | "checkpoint" | "reconfigure" | "setuser" => {
            admin()
        }
        // Control flow and blocks: not classified (§4.2 opaque blocks would
        // need every branch read; refused instead).
        "if" | "while" | "goto" | "return" | "break" | "continue" | "end" | "else" | "try" | "catch" | "send"
        | "receive" | "move" | "get" | "readtext" | "writetext" | "updatetext" => Err(Reason::UnsupportedStatement),
        _ => return None,
    };
    Some(result)
}

/// Words that start a T-SQL statement. Where a grammar here accepts free
/// option tokens, none of these may appear among them. (`WITH` is left out:
/// sequence options use it, and a CTE must be followed by one of these.)
pub(crate) fn is_statement_start(w: &str) -> bool {
    matches!(
        w,
        "select"
            | "insert"
            | "update"
            | "delete"
            | "merge"
            | "exec"
            | "execute"
            | "drop"
            | "create"
            | "alter"
            | "truncate"
            | "grant"
            | "deny"
            | "revoke"
            | "begin"
            | "commit"
            | "rollback"
            | "save"
            | "declare"
            | "set"
            | "use"
            | "waitfor"
            | "print"
            | "raiserror"
            | "throw"
            | "if"
            | "while"
            | "return"
            | "goto"
            | "break"
            | "continue"
            | "backup"
            | "restore"
            | "dbcc"
            | "kill"
            | "shutdown"
            | "checkpoint"
            | "reconfigure"
            | "bulk"
            | "open"
            | "close"
            | "fetch"
            | "deallocate"
            | "readtext"
            | "writetext"
            | "updatetext"
            | "setuser"
            | "revert"
            | "enable"
            | "disable"
            | "send"
            | "receive"
            | "move"
            | "get"
            | "end"
    )
}

fn begin(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if c.eat("distributed") {
        // An MS DTC transaction spanning servers.
        return admin();
    }
    if !c.eat_any(&["tran", "transaction"]) {
        // A BEGIN … END block, TRY / CATCH, DIALOG, CONVERSATION TIMER.
        return Err(Reason::UnsupportedStatement);
    }
    if c.tx_name() && c.eat("with") {
        c.expect("mark")?;
        if c.peek() == Some(&T::Str) {
            c.i += 1;
        }
    }
    c.end()?;
    tx(Kind::TxBegin)
}

/// One `SET` value: a single token (a signed number counts as one).
fn set_value(c: &mut Cur<'_, '_>) -> R<()> {
    c.eat_punct(b'-');
    match c.peek() {
        Some(T::Word(w, _)) if is_statement_start(w) => unsupported(),
        Some(T::Word(..) | T::Ident(_) | T::Str | T::Number) => {
            c.i += 1;
            Ok(())
        }
        _ => unsupported(),
    }
}

/// `SET …`. Options that change the lexer never run, however the value is
/// written; every other option has a one-token value. `SET @var = …` goes
/// to the parser (its expression may read tables).
fn set(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    if matches!(c.peek_word(), Some(w) if w.starts_with('@')) {
        return None;
    }
    let r = (|| -> R<Analysis> {
        if c.eat("transaction") {
            c.expect("isolation")?;
            c.expect("level")?;
            let ok = (c.eat("read") && c.eat_any(&["uncommitted", "committed"]))
                || (c.eat("repeatable") && c.eat("read"))
                || c.eat_any(&["snapshot", "serializable"]);
            if !ok {
                return unsupported();
            }
            c.end()?;
            return server(Kind::SetSession, Cap::Select);
        }
        if c.eat("identity_insert") {
            // Explicit values into an identity column: ALTER on the table.
            let t = c.existing(ObjectKind::Relation)?;
            if !c.eat_any(&["on", "off"]) {
                return unsupported();
            }
            c.end()?;
            return Ok(with(Kind::SetSession, &[(Cap::Alter, t)]));
        }
        // Every option is judged before any value is looked at.
        let mut names = Vec::new();
        loop {
            let name = match c.peek() {
                Some(T::Word(w, _)) => w.clone(),
                _ => return unsupported(),
            };
            c.i += 1;
            names.push(name);
            if !c.eat_punct(b',') {
                break;
            }
        }
        let mut caps = Vec::new();
        for n in &names {
            caps.push(settings::requirement(n)?);
        }
        if names.len() > 1 {
            // SET opt, opt {ON | OFF}
            if !c.eat_any(&["on", "off"]) {
                return unsupported();
            }
        } else if names[0] == "statistics" {
            // SET STATISTICS {IO | TIME | XML | PROFILE} {ON | OFF}
            if !c.eat_any(&["io", "time", "xml", "profile"]) || !c.eat_any(&["on", "off"]) {
                return unsupported();
            }
        } else {
            set_value(c)?;
        }
        c.end()?;
        let mut a = Analysis::new(Kind::SetSession);
        for cap in caps {
            a.required.insert((cap, SqlTarget::Server));
        }
        Ok(a)
    })();
    Some(r)
}

/// `EXEC` / `EXECUTE`: a procedure call, dynamic SQL, or `EXECUTE AS`.
fn exec(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if c.eat("as") {
        // EXECUTE AS {CALLER | SELF | OWNER | USER = '…' | LOGIN = '…'}: the
        // session runs with another principal's rights (§4.2: sql_admin).
        if !(c.eat_any(&["caller", "self", "owner"])
            || (c.eat_any(&["user", "login"]) && c.eat_punct(b'=') && matches!(c.peek(), Some(T::Str)) && {
                c.i += 1;
                true
            }))
        {
            return unsupported();
        }
        if c.eat("with") {
            let ok = (c.eat("no") && c.eat("revert"))
                || (c.eat("cookie") && c.eat("into") && matches!(c.peek_word(), Some(w) if w.starts_with('@')) && {
                    c.i += 1;
                    true
                });
            if !ok {
                return unsupported();
            }
        }
        c.end()?;
        let mut a = with(Kind::Admin, &[(Cap::Admin, SqlTarget::Server)]);
        a.opaque = true;
        return Ok(a);
    }
    if c.eat_punct(b'(') {
        return dynamic_sql(c);
    }
    // [@status =] procedure
    if matches!(c.peek_word(), Some(w) if w.starts_with('@')) && c.toks.get(c.i + 1) == Some(&T::Punct(b'=')) {
        c.i += 2;
    }
    let mut a = Analysis::new(Kind::Call);
    a.opaque = true;
    if matches!(c.peek_word(), Some(w) if w.starts_with('@')) {
        // The procedure's name is in a variable: dynamic.
        c.i += 1;
        a.kind = Kind::Execute;
        a.required.insert((Cap::Execute, SqlTarget::Server));
    } else {
        let raw = c.raw_name()?;
        let last = raw.last().cloned().unwrap_or_default();
        let parts: Vec<&str> = raw.iter().map(String::as_str).collect();
        if functions::always_refused(&last) || raw.len() > 3 {
            return Err(Reason::ServerFileOrOsAccess);
        }
        if last.eq_ignore_ascii_case("sp_executesql") {
            a.kind = Kind::Execute;
            a.required.insert((Cap::Execute, SqlTarget::Server));
        } else if (raw.len() == 1 && functions::system_procedure(&last))
            || raw.iter().rev().nth(1).is_some_and(|s| s.eq_ignore_ascii_case("sys"))
        {
            // A system procedure: server code with server-wide effects.
            a.kind = Kind::Admin;
            a.required.insert((Cap::Admin, SqlTarget::Server));
        } else {
            let r = c.names.existing(ObjectKind::Routine, &parts)?;
            a.required.insert((Cap::Execute, SqlTarget::Object(r)));
        }
        // A numbered procedure (`p;2`) cannot be called: the splitter ends
        // the statement at its `;`, and the `2` alone is refused.
    }
    exec_params(c)?;
    if c.eat("with") {
        c.expect("recompile")?;
    }
    c.end()?;
    Ok(a)
}

/// `[@p =] value [OUTPUT] {, …}`: constants, variables, `DEFAULT` and bare
/// words only (T-SQL allows no expression here).
fn exec_params(c: &mut Cur<'_, '_>) -> R<()> {
    if c.done() || c.peek_word() == Some("with") {
        return Ok(());
    }
    loop {
        if matches!(c.peek_word(), Some(w) if w.starts_with('@')) && c.toks.get(c.i + 1) == Some(&T::Punct(b'=')) {
            c.i += 2;
        }
        c.eat_punct(b'-');
        match c.peek() {
            Some(T::Word(w, _)) if w.starts_with('@') || w == "default" || w == "null" => c.i += 1,
            Some(T::Word(w, _)) if reserved(w) || is_statement_start(w) => return unsupported(),
            Some(T::Word(..) | T::Ident(_) | T::Str | T::Number) => c.i += 1,
            _ => return unsupported(),
        }
        c.eat_any(&["output", "out"]);
        if !c.eat_punct(b',') {
            return Ok(());
        }
    }
}

/// `EXEC ( 'text' | @var [+ …] ) [AS {USER | LOGIN} = '…'] [AT server]`.
fn dynamic_sql(c: &mut Cur<'_, '_>) -> R<Analysis> {
    loop {
        match c.peek() {
            Some(T::Str) => c.i += 1,
            Some(T::Word(w, _)) if w.starts_with('@') => c.i += 1,
            _ => return unsupported(),
        }
        if !c.eat_punct(b'+') {
            break;
        }
    }
    if !c.eat_punct(b')') {
        return unsupported();
    }
    let mut a = with(Kind::Execute, &[(Cap::Execute, SqlTarget::Server)]);
    a.opaque = true;
    if c.eat("as") {
        if !(c.eat_any(&["user", "login"]) && c.eat_punct(b'=') && c.peek() == Some(&T::Str)) {
            return unsupported();
        }
        c.i += 1;
        a.required.insert((Cap::Admin, SqlTarget::Server));
    }
    if c.eat("at") {
        // Runs on a linked server or an external data source.
        return Err(Reason::ServerFileOrOsAccess);
    }
    c.end()?;
    Ok(a)
}

fn drop(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let Some(kind) = c.peek_word().map(str::to_string) else { return unsupported() };
    c.i += 1;
    let drops = |c: &mut Cur<'_, '_>, k: ObjectKind| -> R<Analysis> {
        c.if_exists();
        let objs = c.objects(k)?;
        c.end()?;
        let mut a = Analysis::new(Kind::Drop);
        for o in objs {
            a.required.insert((Cap::Drop, o));
        }
        Ok(a)
    };
    match kind.as_str() {
        "table" | "view" | "synonym" => drops(c, ObjectKind::Relation),
        "proc" | "procedure" | "function" => drops(c, ObjectKind::Routine),
        "sequence" => drops(c, ObjectKind::Sequence),
        "type" => drops(c, ObjectKind::Type),
        "index" => {
            c.if_exists();
            let mut a = Analysis::new(Kind::Drop);
            loop {
                let first = c.raw_name()?;
                let t = if c.eat("on") {
                    if first.len() != 1 {
                        return unsupported();
                    }
                    c.existing(ObjectKind::Relation)?
                } else {
                    // `table.index` (or `schema.table.index`).
                    if first.len() < 2 {
                        return unsupported();
                    }
                    let parts: Vec<&str> = first[..first.len() - 1].iter().map(String::as_str).collect();
                    SqlTarget::Object(c.names.existing(ObjectKind::Relation, &parts)?)
                };
                a.required.insert((Cap::Drop, t));
                if !c.eat_punct(b',') {
                    break;
                }
            }
            c.end()?;
            Ok(a)
        }
        "trigger" => {
            c.if_exists();
            c.raw_name()?;
            while c.eat_punct(b',') {
                c.raw_name()?;
            }
            if c.eat("on") {
                // DML triggers never take ON; DDL triggers are server-wide.
                return admin();
            }
            c.end()?;
            // Trigger names are per schema, not per table: the table they
            // belong to is not in the statement.
            server(Kind::Drop, Cap::Drop)
        }
        "statistics" => {
            let mut a = Analysis::new(Kind::Maintenance);
            loop {
                let name = c.raw_name()?;
                if name.len() < 2 {
                    return unsupported();
                }
                let parts: Vec<&str> = name[..name.len() - 1].iter().map(String::as_str).collect();
                a.required.insert((Cap::Alter, SqlTarget::Object(c.names.existing(ObjectKind::Relation, &parts)?)));
                if !c.eat_punct(b',') {
                    break;
                }
            }
            c.end()?;
            Ok(a)
        }
        "assembly" => Err(Reason::ServerFileOrOsAccess),
        _ => admin(),
    }
}

/// `{CREATE | ALTER} {PROC | FUNCTION} name …`: the body is the rest of the
/// batch and is stored, not run (it runs later under EXEC: `sql_execute`).
fn routine(c: &mut Cur<'_, '_>, alter: bool, or_alter: bool) -> R<Analysis> {
    let r = if alter { c.existing(ObjectKind::Routine)? } else { c.new_object(ObjectKind::Routine)? };
    let mut a = if alter {
        with(Kind::Alter, &[(Cap::Alter, r)])
    } else {
        let mut a = with(Kind::CreateRoutine, &[(Cap::Create, r.clone())]);
        if or_alter {
            a.required.insert((Cap::Alter, r));
        }
        a
    };
    if c.rest_has_execute_as() {
        // Definer rights: the routine runs as another principal.
        a.required.insert((Cap::Admin, SqlTarget::Server));
    }
    Ok(a)
}

/// `{CREATE | ALTER} TRIGGER name ON {table | DATABASE | ALL SERVER} …`.
fn trigger(c: &mut Cur<'_, '_>, alter: bool, or_alter: bool) -> R<Analysis> {
    c.raw_name()?;
    c.expect("on")?;
    if c.eat("database") || (c.eat("all") && c.eat("server")) {
        // A DDL or logon trigger: server or database wide.
        return admin();
    }
    let t = c.existing(ObjectKind::Relation)?;
    // The body runs on every later write to the table, with the trigger's
    // rights: opaque, `sql_execute` on the server (the MySQL precedent).
    let cap = if alter { Cap::Alter } else { Cap::Create };
    let mut a = with(
        if alter { Kind::Alter } else { Kind::CreateTrigger },
        &[(cap, t.clone()), (Cap::Execute, SqlTarget::Server)],
    );
    a.opaque = true;
    if or_alter {
        a.required.insert((Cap::Alter, t));
    }
    if c.rest_has_execute_as() {
        a.required.insert((Cap::Admin, SqlTarget::Server));
    }
    Ok(a)
}

/// Free option tokens after a statement's object (`CREATE SEQUENCE`,
/// `ALTER INDEX`, …): words, numbers, strings and punctuation, but no word
/// that could start another statement (`SET (…)` options excepted).
fn options_only(c: &mut Cur<'_, '_>) -> R<()> {
    while let Some(t) = c.peek() {
        match t {
            T::Word(w, _) if w == "set" && c.toks.get(c.i + 1) == Some(&T::Punct(b'(')) => c.i += 1,
            T::Word(w, _) if is_statement_start(w) => return unsupported(),
            _ => c.i += 1,
        }
    }
    Ok(())
}

/// `CREATE …` other than tables, views and indexes (those go to the parser).
fn create(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    let start = c.i;
    let or_alter = c.word_at(0) == Some("or") && c.word_at(1) == Some("alter");
    if or_alter {
        c.i += 2;
    }
    let r = (|| -> R<Option<Analysis>> {
        match c.peek_word() {
            Some("proc" | "procedure" | "function") => {
                c.i += 1;
                return routine(c, false, or_alter).map(Some);
            }
            Some("trigger") => {
                c.i += 1;
                return trigger(c, false, or_alter).map(Some);
            }
            Some("sequence") => {
                c.i += 1;
                let s = c.new_object(ObjectKind::Sequence)?;
                options_only(c)?;
                return Ok(Some(with(Kind::CreateSequence, &[(Cap::Create, s)])));
            }
            Some("synonym") => {
                c.i += 1;
                let s = c.new_object(ObjectKind::Relation)?;
                c.expect("for")?;
                let target = c.raw_name()?;
                if target.len() > 3 {
                    // A synonym for a linked-server object.
                    return Err(Reason::ServerFileOrOsAccess);
                }
                c.end()?;
                return Ok(Some(with(Kind::CreateView, &[(Cap::Create, s)])));
            }
            Some("type") => {
                c.i += 1;
                let t = c.new_object(ObjectKind::Type)?;
                options_only(c)?;
                return Ok(Some(with(Kind::CreateType, &[(Cap::Create, t)])));
            }
            Some("statistics") => {
                c.i += 1;
                c.part()?;
                c.expect("on")?;
                let t = c.existing(ObjectKind::Relation)?;
                options_only(c)?;
                return Ok(Some(with(Kind::Maintenance, &[(Cap::Alter, t)])));
            }
            Some("assembly") => return Err(Reason::ServerFileOrOsAccess),
            Some(
                "database" | "schema" | "login" | "user" | "role" | "application" | "certificate" | "asymmetric"
                | "symmetric" | "master" | "credential" | "endpoint" | "event" | "server" | "rule" | "default"
                | "partition" | "fulltext" | "queue" | "service" | "route" | "contract" | "message" | "workload"
                | "resource" | "security" | "column" | "availability" | "broker" | "cryptographic" | "xml"
                | "selective" | "remote" | "search",
            ) if !or_alter => return admin().map(Some),
            // Tables, views and indexes go to the parser; anything else is
            // not classified there either.
            Some(_) => {}
            None => return unsupported(),
        }
        c.i = start;
        Ok(None)
    })();
    match r {
        Ok(Some(a)) => Some(Ok(a)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

/// `ALTER …` other than tables and views (those go to the parser).
fn alter(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    let r = (|| -> R<Option<Analysis>> {
        match c.peek_word() {
            Some("table" | "view") => Ok(None),
            Some("proc" | "procedure" | "function") => {
                c.i += 1;
                routine(c, true, false).map(Some)
            }
            Some("trigger") => {
                c.i += 1;
                trigger(c, true, false).map(Some)
            }
            Some("index") => {
                c.i += 1;
                if !c.eat("all") {
                    c.part()?;
                }
                c.expect("on")?;
                let t = c.existing(ObjectKind::Relation)?;
                options_only(c)?;
                Ok(Some(with(Kind::Maintenance, &[(Cap::Alter, t)])))
            }
            Some("sequence") => {
                c.i += 1;
                let s = c.existing(ObjectKind::Sequence)?;
                options_only(c)?;
                Ok(Some(with(Kind::Alter, &[(Cap::Alter, s)])))
            }
            Some("assembly") => Err(Reason::ServerFileOrOsAccess),
            Some(_) => admin().map(Some),
            None => unsupported(),
        }
    })();
    match r {
        Ok(Some(a)) => Some(Ok(a)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

/// `{ENABLE | DISABLE} TRIGGER {name {, name} | ALL} ON {table | DATABASE |
/// ALL SERVER}`.
fn toggle_trigger(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.expect("trigger")?;
    if !c.eat("all") {
        c.raw_name()?;
        while c.eat_punct(b',') {
            c.raw_name()?;
        }
    }
    c.expect("on")?;
    if c.eat("database") || (c.eat("all") && c.eat("server")) {
        return admin();
    }
    let t = c.existing(ObjectKind::Relation)?;
    c.end()?;
    Ok(with(Kind::Alter, &[(Cap::Alter, t)]))
}

/// `OPEN` / `CLOSE` / `DEALLOCATE [GLOBAL] cursor`; the key forms of OPEN
/// and CLOSE are `sql_admin`.
fn cursor(c: &mut Cur<'_, '_>, kind: Kind) -> R<Analysis> {
    if matches!(c.peek_word(), Some("symmetric" | "master" | "all")) {
        return admin();
    }
    c.eat("global");
    match c.peek() {
        Some(T::Word(w, _)) if !reserved(w) => c.i += 1,
        Some(T::Ident(_)) => c.i += 1,
        _ => return unsupported(),
    }
    c.end()?;
    server(kind, Cap::Select)
}

/// `FETCH [NEXT | PRIOR | FIRST | LAST | ABSOLUTE n | RELATIVE n] [FROM]
/// [GLOBAL] cursor [INTO @v {, @v}]`. The rows were authorized when the
/// cursor's query was.
fn fetch(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if c.eat_any(&["absolute", "relative"]) {
        c.eat_punct(b'-');
        match c.peek() {
            Some(T::Number) => c.i += 1,
            Some(T::Word(w, _)) if w.starts_with('@') => c.i += 1,
            _ => return unsupported(),
        }
    } else {
        c.eat_any(&["next", "prior", "first", "last"]);
    }
    c.eat("from");
    c.eat("global");
    match c.peek() {
        Some(T::Word(w, _)) if !reserved(w) => c.i += 1,
        Some(T::Ident(_)) => c.i += 1,
        _ => return unsupported(),
    }
    if c.eat("into") {
        loop {
            match c.peek_word() {
                Some(w) if w.starts_with('@') => c.i += 1,
                _ => return unsupported(),
            }
            if !c.eat_punct(b',') {
                break;
            }
        }
    }
    c.end()?;
    server(Kind::FetchCursor, Cap::Select)
}
