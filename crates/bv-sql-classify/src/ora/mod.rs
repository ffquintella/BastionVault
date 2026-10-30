//! The Oracle dialect, Oracle Database 19c and later (T129, Phase 8): lex,
//! split at `;` and SQL*Plus `/` lines (PL/SQL units only at `/`), refuse
//! client commands, refuse file / OS / network / remote access from the
//! words alone, cross-check the lexers, then classify from tokens, from the
//! parsed statement, or, for a PL/SQL unit, from its header only.

// Oracle runs one statement or one PL/SQL block per call: a span holding
// two is an error at the server, never two statements run. What the
// classifier must get right is the reading of the one statement, which is
// why every opaque region is cross-checked against the parser's tokenizer.

// PL/SQL units are opaque. Their bodies are never parsed for safety: they
// are scanned word by word for the always-refused names, then classified by
// their header. Dynamic SQL can build any name at run time, so that scan is
// best effort; the database login is the backstop (§4.3).

mod analyze;
mod differential;
mod fallback;
mod functions;
mod lexer;
mod names;
mod settings;

use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Tokenizer;

use crate::model::{ClassifiedStatement, NameContext, ObjectKind, ObjectRef, Reason, Refusal, Unclassifiable};
use crate::{MAX_NESTING, MAX_STATEMENTS, MAX_TEXT_BYTES, PARSER_RECURSION_LIMIT};
use analyze::Analysis;
use lexer::{RawStatement, TokKind};
use names::{Names, Part};

pub(crate) fn classify_each(
    text: &str,
    ctx: &NameContext,
) -> Result<Vec<Result<ClassifiedStatement, Unclassifiable>>, Unclassifiable> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Unclassifiable::whole(Reason::InputTooLarge));
    }
    if ctx.current_catalog.is_empty() || ctx.current_schema.as_deref() == Some("") {
        return Err(Unclassifiable::whole(Reason::InvalidContext));
    }
    let tokens = lexer::lex(text).map_err(|e| Unclassifiable::whole(e.reason))?;
    let statements = lexer::split(text, &tokens).map_err(|e| Unclassifiable::whole(e.reason))?;
    if statements.iter().any(|raw| client_command(text, raw)) {
        // Written for SQL*Plus or SQLcl, which split lines their own way:
        // refused whole rather than split by guess (the T-SQL `GO` rule).
        return Err(Unclassifiable::whole(Reason::ClientCommand));
    }
    if statements.len() > MAX_STATEMENTS {
        return Err(Unclassifiable::whole(Reason::TooManyStatements));
    }
    let names = Names { ctx };
    Ok(statements.iter().enumerate().map(|(i, raw)| statement(text, i, raw, &names)).collect())
}

/// `text` with every string and number replaced by `?`, every comment by a
/// space, and every password (`IDENTIFIED BY pw`, its `REPLACE old`, the
/// rest of a `CONNECT` line) by `?`: Oracle passwords are identifiers, not
/// literals. Found by the same lexer that splits statements.
pub(crate) fn redact(text: &str) -> Result<String, Reason> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Reason::InputTooLarge);
    }
    let tokens = lexer::lex(text).map_err(|e| e.reason)?;
    let secret = secrets(text, &tokens);
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for (i, t) in tokens.iter().enumerate() {
        let replacement = match t.kind {
            _ if secret.contains(&i) => "?",
            TokKind::Str(_) | TokKind::Number => "?",
            TokKind::LineComment | TokKind::BlockComment => " ",
            _ => continue,
        };
        out.push_str(&text[pos..t.start]);
        out.push_str(replacement);
        pos = t.end;
    }
    out.push_str(&text[pos..]);
    Ok(out)
}

/// Indexes of the tokens that hold a password.
fn secrets(text: &str, tokens: &[lexer::Tok]) -> std::collections::HashSet<usize> {
    let code: Vec<usize> = (0..tokens.len()).filter(|&i| !tokens[i].is_comment()).collect();
    let word = |k: usize| code.get(k).and_then(|&i| lexer::word_lower(text, &tokens[i]));
    let lines = lexer::Lines::new(text);
    let mut out = std::collections::HashSet::new();
    let mut identified = false;
    // Tokens up to here are already marked as the rest of a CONNECT line.
    let mut connect_until = 0;
    for k in 0..code.len() {
        let t = tokens[code[k]];
        if t.kind == TokKind::Punct(b';') {
            identified = false;
        }
        match word(k).as_deref() {
            Some("identified") if word(k + 1).as_deref() == Some("by") => {
                identified = true;
                out.extend(code.get(k + 2));
            }
            Some("replace") if identified => out.extend(code.get(k + 1)),
            Some("connect" | "conn") if k >= connect_until && word(k + 1).as_deref() != Some("by") => {
                let line_end = lines.end(t.start);
                let rest = code[k + 1..].iter().take_while(|&&i| tokens[i].start < line_end);
                connect_until = k + 1 + rest.clone().count();
                out.extend(rest.copied());
            }
            _ => {}
        }
    }
    out
}

/// SQL*Plus and SQLcl commands, as the first word of a statement. None of
/// them is SQL; `SET` is SQL only for `TRANSACTION`, `ROLE` and
/// `CONSTRAINT[S]`.
const CLIENT_COMMANDS: &[&str] = &[
    "acc",
    "accept",
    "alias",
    "apex",
    "append",
    "archive",
    "attribute",
    "break",
    "bridge",
    "btitle",
    "cd",
    "change",
    "clear",
    "col",
    "column",
    "comp",
    "compute",
    "conn",
    "connect",
    "copy",
    "ctas",
    "ddl",
    "def",
    "define",
    "del",
    "desc",
    "describe",
    "disc",
    "disconnect",
    "ed",
    "edit",
    "exec",
    "execute",
    "exit",
    "format",
    "get",
    "help",
    "history",
    "ho",
    "host",
    "info",
    "information",
    "input",
    "l",
    "lb",
    "liquibase",
    "list",
    "load",
    "oerr",
    "password",
    "pause",
    "print",
    "pro",
    "prompt",
    "quit",
    "r",
    "recover",
    "rem",
    "remark",
    "repfooter",
    "repheader",
    "run",
    "save",
    "script",
    "sho",
    "show",
    "shutdown",
    "soda",
    "spo",
    "spool",
    "sshtunnel",
    "sta",
    "start",
    "startup",
    "store",
    "timing",
    "tnsping",
    "ttitle",
    "undefine",
    "var",
    "variable",
    "whenever",
    "xquery",
];

/// Whether a statement starts with a client command (`@script` included).
fn client_command(text: &str, raw: &RawStatement) -> bool {
    let code: Vec<&lexer::Tok> = raw.tokens.iter().filter(|t| !t.is_comment()).take(2).collect();
    let Some(first) = code.first() else { return false };
    if first.kind == TokKind::Punct(b'@') {
        return true;
    }
    let Some(w) = lexer::word_lower(text, first) else { return false };
    if w.starts_with('$') {
        return true;
    }
    if w == "set" {
        let second = code.get(1).and_then(|t| lexer::word_lower(text, t));
        return !matches!(second.as_deref(), Some("transaction" | "role" | "constraint" | "constraints"));
    }
    CLIENT_COMMANDS.contains(&w.as_str())
}

fn statement(
    text: &str,
    index: usize,
    raw: &RawStatement,
    names: &Names<'_>,
) -> Result<ClassifiedStatement, Unclassifiable> {
    let span = raw.span.clone();
    match classify_raw(text, raw, names) {
        Ok(a) if !a.tx_control && a.required.is_empty() => {
            Err(Unclassifiable::never(index, span, Reason::EmptyRequirementSet))
        }
        Ok(a) => Ok(ClassifiedStatement {
            span,
            kind: a.kind,
            required: a.required.into_iter().collect(),
            opaque: a.opaque,
            tx_control: a.tx_control,
        }),
        Err(reason) => {
            let mut u = Unclassifiable::at(index, span, reason);
            if u.refusal == Refusal::Unknown && (file_or_os_access(text, raw) || guard_change(text, raw).is_some()) {
                // An unread statement that names server files, remote
                // access or the session guards must not run as
                // `unclassified` either (§4.2, §4.3).
                u.refusal = Refusal::Never;
            }
            Err(u)
        }
    }
}

/// The unquoted words of a statement, lower-cased, comments left out.
fn words(text: &str, raw: &RawStatement) -> Vec<String> {
    raw.tokens.iter().filter_map(|t| lexer::word_lower(text, t)).collect()
}

/// Modifiers between `CREATE` / `ALTER` / `DROP` and the kind of object.
const DDL_MODIFIERS: &[&str] = &[
    "or",
    "replace",
    "public",
    "shared",
    "editionable",
    "noneditionable",
    "if",
    "not",
    "exists",
    "and",
    "resolve",
    "compile",
    "noforce",
];

/// Server file, OS, network, Java and remote access spelled in the
/// statement, whether or not it parses (§4.2's always-refused row): the
/// names in `functions::ALWAYS_REFUSED` as words or quoted identifiers, any
/// `@` (a database link, or a SQL*Plus script), DDL on a database link,
/// `CREATE / ALTER {DIRECTORY | LIBRARY | JAVA | MLE | PFILE | SPFILE}`,
/// `GRANT … ON DIRECTORY`, `ADMINISTER KEY MANAGEMENT`, and external code
/// in a routine (`LANGUAGE C / JAVA / JAVASCRIPT`, MLE modules).
fn file_or_os_access(text: &str, raw: &RawStatement) -> bool {
    let named = raw.tokens.iter().any(|t| match t.kind {
        TokKind::Word => functions::always_refused(&text[t.start..t.end]),
        TokKind::QuotedIdent => functions::always_refused(&text[t.start + 1..t.end - 1]),
        TokKind::Punct(b'@') => true,
        _ => false,
    });
    if named {
        return true;
    }
    let w = words(text, raw);
    let pair = |a: &str, b: &[&str]| w.windows(2).any(|p| p[0] == a && b.contains(&p[1].as_str()));
    let first = w.first().map(String::as_str);
    if let Some(verb @ ("create" | "alter" | "drop")) = first {
        let mut k = 1;
        while w.get(k).is_some_and(|x| DDL_MODIFIERS.contains(&x.as_str())) {
            k += 1;
        }
        let object = w.get(k).map(String::as_str);
        if object == Some("database") && w.get(k + 1).map(String::as_str) == Some("link") {
            return true;
        }
        let code_or_files = matches!(object, Some("directory" | "library" | "java" | "mle" | "pfile" | "spfile"));
        if verb != "drop" && code_or_files {
            return true;
        }
    }
    first == Some("administer")
        || pair("on", &["directory"])
        || pair("mle", &["module", "env", "environment", "language"])
        || (first == Some("create") && pair("language", &["c", "java", "javascript"]))
}

/// A change to a session guard spelled in the statement or unit: `SET
/// TRANSACTION READ WRITE` lifts the read-only guard (§5.3); `ALTER
/// SESSION SET CONTAINER` leaves the bound service.
fn guard_change(text: &str, raw: &RawStatement) -> Option<Reason> {
    let w = words(text, raw);
    if w.windows(4).any(|p| p == ["set", "transaction", "read", "write"]) {
        return Some(Reason::ReadOnlyGuardChange);
    }
    let alter_session = w.windows(2).any(|p| p == ["alter", "session"]);
    if alter_session && w.iter().any(|x| x == "container") {
        return Some(Reason::SessionScopeChange);
    }
    None
}

/// How a dotted routine reference is checked (§4.2).
pub(crate) enum RoutineUse {
    /// Dynamic SQL (`DBMS_SQL`, `DBMS_XMLGEN`, …): `sql_execute` on
    /// `sql/server`, opaque.
    Dynamic,
    /// `sql_execute` on every one of these.
    Routines(Vec<ObjectRef>),
}

/// A two- or three-part routine reference, `a.f` or `s.a.f`, not a column.
/// `a.f` is a function `f` in schema `a`, or function `f` of package `a`
/// (in the current schema or through a `PUBLIC` synonym): both are
/// checked, more and never less. A reviewed supplied package is `SYS`'s;
/// an unreviewed `DBMS_*` / `UTL_*` / `OWA_*` one is not classified.
pub(crate) fn routine_use(names: &Names<'_>, parts: &[Part]) -> Result<RoutineUse, Reason> {
    let supplied = |pkg: &Part, f: &Part| -> Result<Option<RoutineUse>, Reason> {
        let Some(p) = pkg.keyword() else { return Ok(None) };
        if functions::dynamic_package(&p) {
            return Ok(Some(RoutineUse::Dynamic));
        }
        if functions::harmless(&p, &f.keyword().unwrap_or_default()) {
            let r = names.in_schema(ObjectKind::Routine, "SYS", pkg)?;
            return Ok(Some(RoutineUse::Routines(vec![r])));
        }
        if functions::supplied_package(&p) {
            return Err(Reason::UnsupportedConstruct);
        }
        Ok(None)
    };
    match parts {
        [a, f] => {
            if let Some(u) = supplied(a, f)? {
                return Ok(u);
            }
            if a.keyword().as_deref() == Some("sys") {
                return Ok(RoutineUse::Routines(vec![names.in_schema(ObjectKind::Routine, "SYS", f)?]));
            }
            let in_schema = names.existing(ObjectKind::Routine, &[a.clone(), f.clone()])?;
            let package = names.existing(ObjectKind::Routine, std::slice::from_ref(a))?;
            Ok(RoutineUse::Routines(vec![in_schema, package]))
        }
        [s, a, f] => {
            if s.keyword().as_deref() == Some("sys") {
                if let Some(u) = supplied(a, f)? {
                    return Ok(u);
                }
            }
            Ok(RoutineUse::Routines(vec![names.existing(ObjectKind::Routine, &[s.clone(), a.clone()])?]))
        }
        _ => Err(Reason::UnresolvableName),
    }
}

/// Most operator tokens in a statement handed to the parser. The parser
/// builds `1 + 1 + …` as a left-deep tree in a loop its recursion limit does
/// not see, and walking or dropping 100,000 levels overflows the stack.
const MAX_OPERATORS: usize = 4096;

/// Operator tokens (`+ - * / | = < > ! ^ ~ [`, the infix and postfix
/// keywords, the set operators): an upper bound on how deep a chain the
/// parser builds in a loop can make the statement's tree.
fn operators(text: &str, raw: &RawStatement) -> usize {
    raw.tokens
        .iter()
        .filter(|t| match t.kind {
            TokKind::Punct(c) => b"+-*/|=<>!^~[".contains(&c),
            TokKind::Word => matches!(
                lexer::word_lower(text, t).as_deref(),
                Some(
                    "and"
                        | "or"
                        | "xor"
                        | "is"
                        | "like"
                        | "in"
                        | "between"
                        | "collate"
                        | "at"
                        | "member"
                        | "union"
                        | "intersect"
                        | "minus"
                        | "except"
                )
            ),
            _ => false,
        })
        .count()
}

fn classify_raw(text: &str, raw: &RawStatement, names: &Names<'_>) -> Result<Analysis, Reason> {
    if file_or_os_access(text, raw) {
        return Err(Reason::ServerFileOrOsAccess);
    }
    if let Some(reason) = guard_change(text, raw) {
        return Err(reason);
    }
    let span_text = &text[raw.span.clone()];
    let dialect = OracleDialect {};
    if raw.unit {
        // Nothing parses the unit, but the scan above relied on this
        // crate's lexer alone: an independent tokenizer must agree on every
        // literal and comment, or the unit is not classified.
        let tokens = Tokenizer::new(&dialect, span_text).tokenize_with_location().map_err(|_| Reason::ParseFailed)?;
        if !differential::agree(span_text, raw.span.start, &raw.tokens, &tokens) {
            return Err(Reason::LexerDisagreement);
        }
        return fallback::unit(text, raw, names);
    }
    if raw.max_depth > MAX_NESTING {
        return Err(Reason::NestingTooDeep);
    }
    if raw.tokens.iter().any(|t| t.is_hint(text)) {
        return Err(Reason::OptimizerHint);
    }
    if let Some(result) = fallback::classify(text, raw, names) {
        return result;
    }
    if operators(text, raw) > MAX_OPERATORS {
        return Err(Reason::NestingTooDeep);
    }
    let tokens = Tokenizer::new(&dialect, span_text).tokenize_with_location().map_err(|_| Reason::ParseFailed)?;
    if !differential::agree(span_text, raw.span.start, &raw.tokens, &tokens) {
        return Err(Reason::LexerDisagreement);
    }
    let w = words(text, raw);
    if w.first().map(String::as_str) == Some("insert") && matches!(w.get(1).map(String::as_str), Some("all" | "first"))
    {
        return analyze::multi_insert(tokens, names);
    }
    let statements = Parser::new(&dialect)
        .with_recursion_limit(PARSER_RECURSION_LIMIT)
        .with_tokens_with_locations(tokens)
        .parse_statements()
        .map_err(|_| Reason::ParseFailed)?;
    let [stmt] = statements.as_slice() else { return Err(Reason::NotOneStatement) };
    analyze::analyze(stmt, names)
}

#[cfg(test)]
mod tests;
