//! MySQL / MariaDB statements classified from their tokens, before the
//! parser sees them: `SHOW`, `DESCRIBE`, `USE`, transaction control, `SET`,
//! `LOCK`, `RENAME`, `DROP`, `TRUNCATE`, routine and trigger DDL, the
//! maintenance commands and the `sql_admin` families.

// Each has a strict grammar; anything else in the statement makes it
// unclassifiable, never a guess. A statement this module does not route
// (`None`) goes to the parser.

use super::analyze::Analysis;
use super::lexer::{RawStatement, StrKind, TokKind};
use super::names::{reserved, Names};
use super::settings;
use crate::model::{ObjectKind, Reason, SqlCapability as Cap, SqlTarget, StatementKind as Kind};

#[derive(Debug, Clone, PartialEq, Eq)]
enum T {
    /// Unquoted word: lower-cased, and as written.
    Word(String, String),
    /// Backtick-quoted identifier, unescaped.
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

    fn eat_all(&mut self, ws: &[&str]) -> bool {
        if ws.iter().enumerate().all(|(k, w)| self.word_at(k) == Some(w)) {
            self.i += ws.len();
            true
        } else {
            false
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

    /// One name part: an unquoted non-reserved word or a quoted identifier.
    fn part(&mut self) -> R<String> {
        let p = match self.peek() {
            Some(T::Word(w, raw)) => {
                if reserved(w) {
                    return Err(Reason::ReservedWordAsName);
                }
                raw.clone()
            }
            Some(T::Ident(s)) => s.clone(),
            _ => return unsupported(),
        };
        self.i += 1;
        Ok(p)
    }

    /// `name [. name]`, as written.
    fn raw_name(&mut self) -> R<Vec<String>> {
        let mut parts = vec![self.part()?];
        while self.eat_punct(b'.') {
            parts.push(self.part()?);
        }
        Ok(parts)
    }

    fn object(&mut self, kind: ObjectKind) -> R<SqlTarget> {
        let raw = self.raw_name()?;
        let parts: Vec<&str> = raw.iter().map(String::as_str).collect();
        Ok(SqlTarget::Object(self.names.resolve_raw(kind, &parts)?))
    }

    /// `name {, name}`.
    fn objects(&mut self, kind: ObjectKind) -> R<Vec<SqlTarget>> {
        let mut out = vec![self.object(kind)?];
        while self.eat_punct(b',') {
            out.push(self.object(kind)?);
        }
        Ok(out)
    }

    fn if_exists(&mut self) -> bool {
        self.eat_all(&["if", "exists"])
    }

    fn if_not_exists(&mut self) -> bool {
        self.eat_all(&["if", "not", "exists"])
    }

    /// `LIKE 'pattern'` at the end, or nothing. `WHERE` is refused: its
    /// expression could read any table.
    fn like_tail(&mut self) -> R<()> {
        if self.eat("like") && !matches!(self.peek(), Some(T::Str)) {
            return unsupported();
        }
        if self.peek() == Some(&T::Str) {
            self.i += 1;
        }
        self.end()
    }

    /// `{FROM | IN} db`, optional.
    fn skip_from_db(&mut self) -> R<()> {
        if self.eat("from") || self.eat("in") {
            let db = self.part()?;
            self.names.database(&db)?;
        }
        Ok(())
    }

    /// Skip a `DEFINER = account` clause; returns whether there was one.
    fn definer(&mut self) -> R<bool> {
        if !self.eat("definer") {
            return Ok(false);
        }
        if !self.eat_punct(b'=') {
            return unsupported();
        }
        let stops = ["procedure", "function", "trigger", "event", "view", "sql", "aggregate", "algorithm"];
        let from = self.i;
        while let Some(t) = self.peek() {
            if matches!(t, T::Word(w, _) if stops.contains(&w.as_str())) {
                break;
            }
            self.i += 1;
        }
        if self.i == from {
            return unsupported();
        }
        Ok(true)
    }
}

fn tokens(text: &str, raw: &RawStatement) -> R<Vec<T>> {
    let mut out = Vec::new();
    for t in raw.tokens.iter().filter(|t| !t.is_comment()) {
        let s = &text[t.start..t.end];
        out.push(match t.kind {
            TokKind::Word => T::Word(s.to_ascii_lowercase(), s.to_string()),
            TokKind::QuotedIdent(q) => {
                T::Ident(s[1..s.len() - 1].replace(&format!("{0}{0}", q as char), &(q as char).to_string()))
            }
            TokKind::Str(StrKind::Single | StrKind::Double | StrKind::National | StrKind::Hex | StrKind::Bit) => T::Str,
            TokKind::Number => T::Number,
            TokKind::Punct(c) => T::Punct(c),
            TokKind::LineComment | TokKind::BlockComment | TokKind::ExecComment => continue,
        });
    }
    Ok(out)
}

fn with(kind: Kind, req: &[(Cap, SqlTarget)]) -> Analysis {
    let mut a = Analysis::new(kind);
    a.required.extend(req.iter().cloned());
    a
}

fn server(kind: Kind, cap: Cap) -> R<Analysis> {
    Ok(with(kind, &[(cap, SqlTarget::Server)]))
}

fn tx(kind: Kind) -> R<Analysis> {
    let mut a = Analysis::new(kind);
    a.tx_control = true;
    Ok(a)
}

/// Classify `raw` if it is a statement this module owns; `None` hands it to
/// the parser.
pub(crate) fn classify(text: &str, raw: &RawStatement, names: &Names<'_>) -> Option<R<Analysis>> {
    let toks = match tokens(text, raw) {
        Ok(t) => t,
        Err(e) => return Some(Err(e)),
    };
    let first = match toks.first() {
        Some(T::Word(w, _)) => w.clone(),
        _ => return None,
    };
    let mut c = Cur { toks, i: 1, names };
    let result = match first.as_str() {
        "show" => show(&mut c),
        "describe" | "desc" | "explain" => {
            // `EXPLAIN SELECT …` and its kin go to the parser.
            let next = c.peek_word().unwrap_or("");
            let statement = [
                "select",
                "insert",
                "update",
                "delete",
                "replace",
                "with",
                "table",
                "values",
                "format",
                "analyze",
                "extended",
                "partitions",
                "for",
            ];
            if statement.contains(&next) || c.peek() == Some(&T::Punct(b'(')) {
                return None;
            }
            describe(&mut c)
        }
        "use" => c.object_db().and_then(|_| c.end()).and_then(|_| server(Kind::SetSession, Cap::Select)),
        "begin" => {
            c.eat("work");
            c.end().and_then(|_| tx(Kind::TxBegin))
        }
        "start" => start(&mut c),
        "commit" => {
            c.eat("work");
            c.end().and_then(|_| tx(Kind::TxCommit))
        }
        "rollback" => rollback(&mut c),
        "savepoint" => c.part().and_then(|_| c.end()).and_then(|_| tx(Kind::TxSavepoint)),
        "release" => (|| {
            c.expect("savepoint")?;
            c.part()?;
            c.end()?;
            tx(Kind::TxReleaseSavepoint)
        })(),
        "set" => return set(&mut c),
        "lock" => lock(&mut c),
        "unlock" => {
            if c.eat("tables") || c.eat("table") {
                c.end().and_then(|_| server(Kind::Lock, Cap::Select))
            } else {
                server(Kind::Admin, Cap::Admin)
            }
        }
        "rename" => rename(&mut c),
        "drop" => drop(&mut c),
        "truncate" => (|| {
            c.eat("table");
            let t = c.object(ObjectKind::Relation)?;
            c.end()?;
            Ok(with(Kind::Truncate, &[(Cap::Drop, t)]))
        })(),
        "create" => return create(&mut c),
        "alter" => return alter(&mut c),
        "optimize" | "repair" => maintenance(&mut c, Cap::Alter),
        "analyze" => {
            // MariaDB's `ANALYZE <statement>` executes it: not classified.
            if !matches!(c.peek_word(), Some("table" | "tables" | "local" | "no_write_to_binlog")) {
                return Some(Err(Reason::UnsupportedStatement));
            }
            maintenance(&mut c, Cap::Alter)
        }
        "check" | "checksum" => maintenance(&mut c, Cap::Select),
        "prepare" => (|| {
            c.part()?;
            c.expect("from")?;
            match c.peek() {
                Some(T::Str) => c.i += 1,
                Some(T::Punct(b'@')) => {
                    c.i += 1;
                    c.part()?;
                }
                _ => return unsupported(),
            }
            c.end()?;
            let mut a = with(Kind::Prepare, &[(Cap::Execute, SqlTarget::Server)]);
            a.opaque = true;
            Ok(a)
        })(),
        "execute" => (|| {
            c.part()?;
            if c.eat("using") {
                loop {
                    if !c.eat_punct(b'@') {
                        return unsupported();
                    }
                    c.part()?;
                    if !c.eat_punct(b',') {
                        break;
                    }
                }
            }
            c.end()?;
            let mut a = with(Kind::Execute, &[(Cap::Execute, SqlTarget::Server)]);
            a.opaque = true;
            Ok(a)
        })(),
        "deallocate" => (|| {
            c.expect("prepare")?;
            c.part()?;
            c.end()?;
            server(Kind::Deallocate, Cap::Select)
        })(),
        "help" => (|| {
            if c.peek() != Some(&T::Str) {
                return unsupported();
            }
            c.i += 1;
            c.end()?;
            server(Kind::Show, Cap::Select)
        })(),
        "grant" | "revoke" | "kill" | "flush" | "reset" | "purge" | "shutdown" | "restart" | "binlog" | "change"
        | "cache" | "stop" => server(Kind::Admin, Cap::Admin),
        "load" if c.eat_all(&["index", "into", "cache"]) => server(Kind::Admin, Cap::Admin),
        _ => return None,
    };
    Some(result)
}

impl Cur<'_, '_> {
    /// A compound body (`BEGIN … END`) is not classified: the splitter
    /// cuts it at its first `;`, and the piece must not pass as a whole
    /// routine definition.
    fn no_compound_body(&self) -> R<()> {
        if self.toks[self.i..].iter().any(|t| matches!(t, T::Word(w, _) if w == "begin")) {
            return Err(Reason::UnsupportedStatement);
        }
        Ok(())
    }

    /// `USE db` / `{FROM|IN} db`: the database must have a canonical name.
    fn object_db(&mut self) -> R<()> {
        let db = self.part()?;
        self.names.database(&db).map(|_| ())
    }
}

fn describe(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let t = c.object(ObjectKind::Relation)?;
    // An optional column name or wildcard pattern.
    match c.peek() {
        None => {}
        Some(T::Str) | Some(T::Word(..)) | Some(T::Ident(_)) => c.i += 1,
        _ => return unsupported(),
    }
    c.end()?;
    Ok(with(Kind::Show, &[(Cap::Select, t)]))
}

fn show(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let sel = |c: &mut Cur<'_, '_>| -> R<Analysis> {
        c.like_tail()?;
        server(Kind::Show, Cap::Select)
    };
    let admin = || server(Kind::Show, Cap::Admin);
    let full = c.eat("full");
    match c.peek_word() {
        Some("tables") => {
            c.i += 1;
            c.skip_from_db()?;
            sel(c)
        }
        Some("columns" | "fields") => {
            c.i += 1;
            if !(c.eat("from") || c.eat("in")) {
                return unsupported();
            }
            let t = c.raw_name()?;
            let mut parts: Vec<String> = t;
            if c.eat("from") || c.eat("in") {
                if parts.len() != 1 {
                    return unsupported();
                }
                parts.insert(0, c.part()?);
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            let obj = SqlTarget::Object(c.names.resolve_raw(ObjectKind::Relation, &refs)?);
            c.like_tail()?;
            Ok(with(Kind::Show, &[(Cap::Select, obj)]))
        }
        Some("processlist") => {
            c.i += 1;
            c.end()?;
            admin()
        }
        _ if full => unsupported(),
        Some("index" | "indexes" | "keys") => {
            c.i += 1;
            if !(c.eat("from") || c.eat("in")) {
                return unsupported();
            }
            let mut parts = c.raw_name()?;
            if c.eat("from") || c.eat("in") {
                if parts.len() != 1 {
                    return unsupported();
                }
                parts.insert(0, c.part()?);
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            let obj = SqlTarget::Object(c.names.resolve_raw(ObjectKind::Relation, &refs)?);
            c.end()?;
            Ok(with(Kind::Show, &[(Cap::Select, obj)]))
        }
        Some("create") => {
            c.i += 1;
            let kind = match c.peek_word() {
                Some("table" | "view") => Some(ObjectKind::Relation),
                Some("procedure" | "function") => Some(ObjectKind::Routine),
                Some("sequence") if c.names.mariadb => Some(ObjectKind::Sequence),
                Some("trigger" | "event" | "database" | "schema" | "user") => None,
                _ => return unsupported(),
            };
            c.i += 1;
            match kind {
                Some(k) => {
                    let t = c.object(k)?;
                    c.end()?;
                    Ok(with(Kind::Show, &[(Cap::Select, t)]))
                }
                None => server(Kind::Show, Cap::Select),
            }
        }
        Some("table") => {
            c.i += 1;
            c.expect("status")?;
            c.skip_from_db()?;
            sel(c)
        }
        Some("open") => {
            c.i += 1;
            c.expect("tables")?;
            c.skip_from_db()?;
            sel(c)
        }
        Some("triggers" | "events") => {
            c.i += 1;
            c.skip_from_db()?;
            sel(c)
        }
        Some("databases" | "schemas" | "collation" | "engines" | "plugins" | "privileges" | "charset" | "profiles") => {
            c.i += 1;
            sel(c)
        }
        Some("character") => {
            c.i += 1;
            c.expect("set")?;
            sel(c)
        }
        Some("global") => {
            c.i += 1;
            if !(c.eat("variables") || c.eat("status")) {
                return unsupported();
            }
            sel(c)
        }
        Some("session" | "local") => {
            c.i += 1;
            if !(c.eat("variables") || c.eat("status")) {
                return unsupported();
            }
            sel(c)
        }
        Some("variables" | "status") => {
            c.i += 1;
            sel(c)
        }
        Some("warnings" | "errors") => {
            c.i += 1;
            if c.eat("limit") {
                while matches!(c.peek(), Some(T::Number | T::Punct(b','))) {
                    c.i += 1;
                }
            }
            c.end()?;
            server(Kind::Show, Cap::Select)
        }
        Some("procedure" | "function") => {
            c.i += 1;
            c.expect("status")?;
            sel(c)
        }
        Some("grants") => {
            c.i += 1;
            if c.eat("for") {
                // Only the session's own account; another's needs sql_admin.
                if c.eat("current_user") {
                    if c.eat_punct(b'(') && !c.eat_punct(b')') {
                        return unsupported();
                    }
                    c.end()?;
                    return server(Kind::Show, Cap::Select);
                }
                return admin();
            }
            c.end()?;
            server(Kind::Show, Cap::Select)
        }
        Some("engine" | "binary" | "master" | "binlog" | "relaylog" | "slave" | "replica" | "replicas" | "mutex") => {
            admin()
        }
        _ => unsupported(),
    }
}

fn start(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if !c.eat("transaction") {
        // START SLAVE / REPLICA / GROUP_REPLICATION.
        return server(Kind::Admin, Cap::Admin);
    }
    if c.done() {
        return tx(Kind::TxBegin);
    }
    loop {
        if c.eat_all(&["read", "write"]) {
            return Err(Reason::ReadOnlyGuardChange);
        }
        if !(c.eat_all(&["read", "only"]) || c.eat_all(&["with", "consistent", "snapshot"])) {
            return unsupported();
        }
        if !c.eat_punct(b',') {
            break;
        }
    }
    c.end()?;
    tx(Kind::TxBegin)
}

fn rollback(c: &mut Cur<'_, '_>) -> R<Analysis> {
    c.eat("work");
    if c.eat("to") {
        c.eat("savepoint");
        c.part()?;
        c.end()?;
        // Back to a savepoint: the transaction stays open.
        return tx(Kind::TxSavepoint);
    }
    c.end()?;
    tx(Kind::TxRollback)
}

/// One `SET` assignment target: a user variable, or a system variable with
/// its scope.
enum Target {
    User,
    System { name: String, global: bool },
}

fn set_target(c: &mut Cur<'_, '_>) -> R<Target> {
    let mut global = false;
    let mut scoped = false;
    match c.peek_word() {
        Some("global" | "persist" | "persist_only") => {
            c.i += 1;
            global = true;
            scoped = true;
        }
        Some("session" | "local") => {
            c.i += 1;
            scoped = true;
        }
        _ => {}
    }
    if c.eat_punct(b'@') {
        if c.eat_punct(b'@') {
            if scoped {
                return unsupported();
            }
            let parts = c.raw_name()?;
            let full = format!("@@{}", parts.join("."));
            return match settings::session_name(&full) {
                Some(name) if !name.contains('.') => Ok(Target::System { name, global: false }),
                Some(_) => unsupported(),
                None => Ok(Target::System { name: parts.last().cloned().unwrap_or_default(), global: true }),
            };
        }
        if scoped {
            return unsupported();
        }
        match c.peek() {
            Some(T::Word(..) | T::Ident(_) | T::Str) => c.i += 1,
            _ => return unsupported(),
        }
        return Ok(Target::User);
    }
    let parts = c.raw_name()?;
    if parts.len() != 1 {
        return unsupported();
    }
    Ok(Target::System { name: parts[0].to_ascii_lowercase(), global })
}

/// `SET …`. Session variables that change the lexer or the read-only guard
/// never run, however the value is written; the value of a system variable
/// must be one token. A `SET` of user variables only, with expressions, goes
/// to the parser (`None`).
fn set(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    let r = (|| -> R<Option<Analysis>> {
        match c.peek_word() {
            Some("names" | "charset") => return Err(Reason::LexerSettingChange),
            Some("character") if c.word_at(1) == Some("set") => return Err(Reason::LexerSettingChange),
            // MariaDB `SET STATEMENT var = … FOR stmt` overrides any variable,
            // the guards included, for one statement.
            Some("statement") => return Err(Reason::LexerSettingChange),
            Some("password" | "role" | "default" | "resource") => {
                return Ok(Some(with(Kind::Admin, &[(Cap::Admin, SqlTarget::Server)])))
            }
            _ => {}
        }
        // SET [GLOBAL | SESSION] TRANSACTION …
        let scope_then_tx = matches!(c.peek_word(), Some("global" | "session" | "local" | "persist" | "persist_only"))
            && c.word_at(1) == Some("transaction");
        if scope_then_tx || c.peek_word() == Some("transaction") {
            let global = matches!(c.peek_word(), Some("global" | "persist" | "persist_only"));
            if scope_then_tx {
                c.i += 1;
            }
            c.i += 1;
            loop {
                if c.eat_all(&["read", "write"]) {
                    return Err(Reason::ReadOnlyGuardChange);
                }
                if c.eat_all(&["read", "only"]) {
                } else if c.eat_all(&["isolation", "level"]) {
                    let ok = c.eat_all(&["read", "uncommitted"])
                        || c.eat_all(&["read", "committed"])
                        || c.eat_all(&["repeatable", "read"])
                        || c.eat("serializable");
                    if !ok {
                        return unsupported();
                    }
                } else {
                    return unsupported();
                }
                if !c.eat_punct(b',') {
                    break;
                }
            }
            c.end()?;
            let cap = if global { Cap::Admin } else { Cap::Select };
            return Ok(Some(with(Kind::SetSession, &[(cap, SqlTarget::Server)])));
        }
        // Assignments. Every target is judged before any value is looked at.
        let mut caps = Vec::new();
        let mut simple_values = true;
        let mut all_user = true;
        loop {
            match set_target(c)? {
                Target::User => caps.push(Cap::Select),
                Target::System { name, global } => {
                    all_user = false;
                    caps.push(settings::requirement(&name, global)?);
                }
            }
            if c.eat_punct(b':') {
                if !c.eat_punct(b'=') {
                    return unsupported();
                }
            } else if !c.eat_punct(b'=') {
                return unsupported();
            }
            // A value of one token (a signed number counts as one).
            let from = c.i;
            c.eat_punct(b'-');
            match c.peek() {
                Some(T::Word(..) | T::Ident(_) | T::Str | T::Number) => c.i += 1,
                _ => simple_values = false,
            }
            if !simple_values {
                // Skip to the next top-level `,` so later targets are judged.
                c.i = from;
                let mut depth = 0usize;
                while let Some(t) = c.peek() {
                    match t {
                        T::Punct(b'(') => depth += 1,
                        T::Punct(b')') => depth = depth.saturating_sub(1),
                        T::Punct(b',') if depth == 0 => break,
                        _ => {}
                    }
                    c.i += 1;
                }
            } else if !matches!(c.peek(), None | Some(T::Punct(b','))) {
                simple_values = false;
                let mut depth = 0usize;
                while let Some(t) = c.peek() {
                    match t {
                        T::Punct(b'(') => depth += 1,
                        T::Punct(b')') => depth = depth.saturating_sub(1),
                        T::Punct(b',') if depth == 0 => break,
                        _ => {}
                    }
                    c.i += 1;
                }
            }
            if !c.eat_punct(b',') {
                break;
            }
        }
        c.end()?;
        if !simple_values {
            // Expressions need the parser; only user variables may take one.
            return if all_user { Ok(None) } else { Err(Reason::UnsupportedConstruct) };
        }
        let mut a = Analysis::new(Kind::SetSession);
        for cap in caps {
            a.required.insert((cap, SqlTarget::Server));
        }
        Ok(Some(a))
    })();
    match r {
        Ok(Some(a)) => Some(Ok(a)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

fn lock(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if !(c.eat("tables") || c.eat("table")) {
        // LOCK INSTANCE FOR BACKUP.
        return server(Kind::Admin, Cap::Admin);
    }
    let mut a = Analysis::new(Kind::Lock);
    loop {
        let t = c.object(ObjectKind::Relation)?;
        let alias = c.eat("as")
            || matches!(c.peek(), Some(T::Ident(_)))
            || matches!(c.peek_word(), Some(w) if !matches!(w, "read" | "write" | "low_priority"));
        if alias {
            c.part()?;
        }
        a.required.insert((Cap::Select, t.clone()));
        if c.eat("read") {
            c.eat("local");
        } else {
            c.eat("low_priority");
            c.expect("write")?;
            a.required.insert((Cap::Update, t));
        }
        if !c.eat_punct(b',') {
            break;
        }
    }
    c.end()?;
    Ok(a)
}

fn rename(c: &mut Cur<'_, '_>) -> R<Analysis> {
    if !(c.eat("table") || c.eat("tables")) {
        // RENAME USER.
        return server(Kind::Admin, Cap::Admin);
    }
    let mut a = Analysis::new(Kind::Alter);
    loop {
        let from = c.object(ObjectKind::Relation)?;
        c.expect("to")?;
        let to = c.object(ObjectKind::Relation)?;
        a.required.insert((Cap::Alter, from));
        a.required.insert((Cap::Create, to));
        if !c.eat_punct(b',') {
            break;
        }
    }
    c.end()?;
    Ok(a)
}

fn drop(c: &mut Cur<'_, '_>) -> R<Analysis> {
    let temporary = c.eat("temporary");
    let kind = c.peek_word().map(str::to_string);
    let Some(kind) = kind else { return unsupported() };
    c.i += 1;
    if temporary && kind != "table" {
        return unsupported();
    }
    let drops = |c: &mut Cur<'_, '_>, k: ObjectKind| -> R<Analysis> {
        c.if_exists();
        let objs = c.objects(k)?;
        c.eat("restrict");
        c.eat("cascade");
        c.end()?;
        let mut a = Analysis::new(Kind::Drop);
        for o in objs {
            a.required.insert((Cap::Drop, o));
        }
        Ok(a)
    };
    match kind.as_str() {
        "table" | "tables" | "view" => drops(c, ObjectKind::Relation),
        "sequence" if c.names.mariadb => drops(c, ObjectKind::Sequence),
        "procedure" | "function" => drops(c, ObjectKind::Routine),
        "index" => {
            c.part()?;
            c.expect("on")?;
            let t = c.object(ObjectKind::Relation)?;
            // ALGORITHM / LOCK options only.
            while matches!(c.peek_word(), Some("algorithm" | "lock")) {
                c.i += 1;
                c.eat_punct(b'=');
                c.part()?;
            }
            c.end()?;
            Ok(with(Kind::Drop, &[(Cap::Drop, t)]))
        }
        "trigger" => {
            // Trigger names are per database, not per table: the table they
            // belong to is not in the statement.
            c.if_exists();
            c.raw_name()?;
            c.end()?;
            server(Kind::Drop, Cap::Drop)
        }
        "prepare" => {
            c.part()?;
            c.end()?;
            server(Kind::Deallocate, Cap::Select)
        }
        "database" | "schema" | "user" | "role" | "event" | "server" | "tablespace" | "logfile" | "resource"
        | "spatial" | "undo" => server(Kind::Admin, Cap::Admin),
        _ => unsupported(),
    }
}

/// `CREATE …` other than tables, views and indexes (those go to the parser).
fn create(c: &mut Cur<'_, '_>) -> Option<R<Analysis>> {
    let start = c.i;
    let or_replace = c.eat_all(&["or", "replace"]);
    let r = (|| -> R<Option<Analysis>> {
        let definer = c.definer()?;
        match c.peek_word() {
            Some(
                "database" | "schema" | "user" | "role" | "event" | "server" | "tablespace" | "logfile" | "resource"
                | "spatial" | "undo",
            ) => return Ok(Some(with(Kind::Admin, &[(Cap::Admin, SqlTarget::Server)]))),
            Some("procedure" | "function" | "aggregate") => {
                c.eat("aggregate");
                c.i += 1;
                c.if_not_exists();
                let r = c.object(ObjectKind::Routine)?;
                c.no_compound_body()?;
                // The body is not classified: it runs later, under CALL
                // (`sql_execute`) or as a function call in a query.
                let mut a = with(Kind::CreateRoutine, &[(Cap::Create, r.clone())]);
                if or_replace {
                    a.required.insert((Cap::Alter, r));
                }
                if definer {
                    a.required.insert((Cap::Admin, SqlTarget::Server));
                }
                return Ok(Some(a));
            }
            Some("trigger") => {
                c.i += 1;
                c.if_not_exists();
                c.raw_name()?;
                if !(c.eat("before") || c.eat("after")) {
                    return unsupported();
                }
                if !(c.eat("insert") || c.eat("update") || c.eat("delete")) {
                    return unsupported();
                }
                c.expect("on")?;
                let t = c.object(ObjectKind::Relation)?;
                c.no_compound_body()?;
                // The body runs on every later write to the table, with the
                // definer's rights: opaque, `sql_execute` on the server.
                let mut a = with(Kind::CreateTrigger, &[(Cap::Create, t.clone()), (Cap::Execute, SqlTarget::Server)]);
                a.opaque = true;
                if or_replace {
                    a.required.insert((Cap::Alter, t));
                }
                if definer {
                    a.required.insert((Cap::Admin, SqlTarget::Server));
                }
                return Ok(Some(a));
            }
            Some("sequence") if c.names.mariadb => {
                c.i += 1;
                c.if_not_exists();
                let s = c.object(ObjectKind::Sequence)?;
                let mut a = with(Kind::CreateSequence, &[(Cap::Create, s.clone())]);
                if or_replace {
                    a.required.insert((Cap::Drop, s));
                }
                return Ok(Some(a));
            }
            Some("temporary") if c.word_at(1) == Some("sequence") && c.names.mariadb => {
                c.i += 2;
                c.if_not_exists();
                let s = c.object(ObjectKind::Sequence)?;
                return Ok(Some(with(Kind::CreateSequence, &[(Cap::Create, s)])));
            }
            _ => {}
        }
        if definer {
            // `CREATE DEFINER = … VIEW` goes to the parser with its definer.
            c.i = start;
        }
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
        c.definer()?;
        match c.peek_word() {
            Some("table" | "online" | "ignore" | "view" | "algorithm" | "sql") => Ok(None),
            Some("procedure" | "function") => {
                c.i += 1;
                let r = c.object(ObjectKind::Routine)?;
                // Characteristics only (COMMENT, SQL SECURITY, …).
                Ok(Some(with(Kind::Alter, &[(Cap::Alter, r)])))
            }
            Some("sequence") if c.names.mariadb => {
                c.i += 1;
                c.if_exists();
                let s = c.object(ObjectKind::Sequence)?;
                Ok(Some(with(Kind::Alter, &[(Cap::Alter, s)])))
            }
            Some(_) => Ok(Some(with(Kind::Admin, &[(Cap::Admin, SqlTarget::Server)]))),
            None => unsupported(),
        }
    })();
    match r {
        Ok(Some(a)) => Some(Ok(a)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

/// `{OPTIMIZE | REPAIR | ANALYZE | CHECK | CHECKSUM} [NO_WRITE_TO_BINLOG |
/// LOCAL] TABLE t {, t} [options]`.
fn maintenance(c: &mut Cur<'_, '_>, cap: Cap) -> R<Analysis> {
    c.eat("no_write_to_binlog");
    c.eat("local");
    if !(c.eat("table") || c.eat("tables")) {
        return unsupported();
    }
    let objs = c.objects(ObjectKind::Relation)?;
    // Trailing options are keywords only (QUICK, EXTENDED, UPDATE HISTOGRAM
    // ON col, PERSISTENT FOR …): no expression, no string.
    while let Some(t) = c.peek() {
        match t {
            T::Word(..) | T::Ident(_) | T::Number | T::Punct(b',') | T::Punct(b'(') | T::Punct(b')') => c.i += 1,
            _ => return unsupported(),
        }
    }
    let mut a = Analysis::new(Kind::Maintenance);
    for o in objs {
        a.required.insert((cap, o));
    }
    Ok(a)
}
