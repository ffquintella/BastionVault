//! The MySQL / MariaDB dialect (T127, Phase 6): lex, split, refuse what the
//! server executes from comments or reads per session setting, cross-check,
//! then classify from tokens or the parsed statement.

mod analyze;
mod differential;
mod fallback;
mod functions;
mod lexer;
mod names;
mod settings;

use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Tokenizer;

use crate::model::{ClassifiedStatement, Dialect, LexerSettings, NameContext, Reason, Refusal, Unclassifiable};
use crate::{MAX_NESTING, MAX_STATEMENTS, MAX_TEXT_BYTES, PARSER_RECURSION_LIMIT};
use analyze::Analysis;
use lexer::{RawStatement, StrKind, TokKind};
use names::Names;

/// The session settings the MySQL lexer and name rules follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settings {
    pub ansi_quotes: bool,
    pub no_backslash_escapes: bool,
    pub fold_table_names: bool,
    pub mariadb: bool,
}

impl Settings {
    pub(crate) fn from_lexer(lexer: LexerSettings, dialect: Dialect) -> Self {
        let mariadb = dialect == Dialect::MariaDb;
        match lexer {
            LexerSettings::MySql { ansi_quotes, no_backslash_escapes, fold_table_names } => {
                Self { ansi_quotes, no_backslash_escapes, fold_table_names, mariadb }
            }
            // The caller matched the dialect first; a mismatch reads as the
            // strictest settings, and the dialect check refuses it anyway.
            _ => Self { ansi_quotes: true, no_backslash_escapes: true, fold_table_names: false, mariadb },
        }
    }
}

pub(crate) fn classify_each(
    text: &str,
    s: Settings,
    ctx: &NameContext,
) -> Result<Vec<Result<ClassifiedStatement, Unclassifiable>>, Unclassifiable> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Unclassifiable::whole(Reason::InputTooLarge));
    }
    if ctx.current_catalog.is_empty() || ctx.current_schema.as_deref() == Some("") {
        return Err(Unclassifiable::whole(Reason::InvalidContext));
    }
    let tokens = lexer::lex(text, s).map_err(|e| Unclassifiable::whole(e.reason))?;
    if tokens.iter().any(|t| t.kind == TokKind::ExecComment) {
        // The server runs what an executable comment holds, even one that
        // stands alone between statements (`/*!40101 SET NAMES … */;`), which
        // the splitter would otherwise drop as a comment: nothing runs.
        return Err(Unclassifiable::whole(Reason::ExecutableComment));
    }
    let statements = lexer::split(&tokens);
    if statements.len() > MAX_STATEMENTS {
        return Err(Unclassifiable::whole(Reason::TooManyStatements));
    }
    let names = Names { ctx, fold_tables: s.fold_table_names, mariadb: s.mariadb };
    Ok(statements.iter().enumerate().map(|(i, raw)| statement(text, i, raw, s, &names)).collect())
}

/// `text` with every string and number replaced by `?` and every comment
/// (executable ones included) by a space, found by the same lexer that
/// splits statements.
pub(crate) fn redact(text: &str, s: Settings) -> Result<String, Reason> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Reason::InputTooLarge);
    }
    let tokens = lexer::lex(text, s).map_err(|e| e.reason)?;
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for t in &tokens {
        let replacement = match t.kind {
            TokKind::Str(_) | TokKind::Number => "?",
            TokKind::LineComment | TokKind::BlockComment | TokKind::ExecComment => " ",
            _ => continue,
        };
        out.push_str(&text[pos..t.start]);
        out.push_str(replacement);
        pos = t.end;
    }
    out.push_str(&text[pos..]);
    Ok(out)
}

fn statement(
    text: &str,
    index: usize,
    raw: &RawStatement,
    s: Settings,
    names: &Names<'_>,
) -> Result<ClassifiedStatement, Unclassifiable> {
    let span = raw.span.clone();
    match classify_raw(text, raw, s, names) {
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
            if u.refusal == Refusal::Unknown && touches_files_or_guards(text, raw) {
                // An unread statement that names server files, the lexer
                // settings or the read-only guard must not run as
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

/// Server file, OS or network access spelled in the statement's words:
/// `LOAD DATA / XML`, `INTO OUTFILE / DUMPFILE`, `LOAD_FILE`, `INFILE`,
/// loadable code (`SONAME`, `INSTALL`), table files (`DATA / INDEX
/// DIRECTORY`, `DISCARD / IMPORT TABLESPACE`), remote tables (`FEDERATED`,
/// `CONNECTION =`), `CLONE`, `IMPORT TABLE` and the shell-running UDFs.
fn file_or_os_access(text: &str, raw: &RawStatement) -> bool {
    let w = words(text, raw);
    let first = w.first().map(String::as_str);
    let has = |s: &str| w.iter().any(|x| x == s);
    let pair = |a: &str, b: &str| w.windows(2).any(|p| p[0] == a && p[1] == b);
    matches!(first, Some("install" | "uninstall" | "clone"))
        || (first == Some("load") && matches!(w.get(1).map(String::as_str), Some("data" | "xml")))
        || (first == Some("import") && w.get(1).map(String::as_str) == Some("table"))
        || has("outfile")
        || has("dumpfile")
        || has("infile")
        || has("soname")
        || has("federated")
        || pair("engine", "connect")
        || pair("data", "directory")
        || pair("index", "directory")
        || pair("discard", "tablespace")
        || pair("import", "tablespace")
        || w.iter().any(|x| functions::always_refused(x))
        || raw.tokens.windows(2).any(|p| {
            lexer::word_lower(text, &p[0]).as_deref() == Some("connection") && p[1].kind == TokKind::Punct(b'=')
        })
}

/// Words naming the lexer settings, the read-only guard or per-statement
/// overrides: an `Unknown` refusal that mentions one is raised to `Never`.
fn touches_files_or_guards(text: &str, raw: &RawStatement) -> bool {
    let w = words(text, raw);
    let guarded = [
        "sql_mode",
        "character_set_client",
        "character_set_connection",
        "character_set_results",
        "collation_connection",
        "transaction_read_only",
        "tx_read_only",
    ];
    file_or_os_access(text, raw)
        || w.iter().any(|x| guarded.iter().any(|g| x == g || x.ends_with(&format!(".{g}"))))
        || w.windows(2).any(|p| p[0] == "read" && p[1] == "write")
        || (w.first().map(String::as_str) == Some("set")
            && w.iter().any(|x| matches!(x.as_str(), "names" | "charset" | "character" | "statement")))
}

/// A built-in in `sql_functions[]` followed by whitespace or a comment and
/// then `(` (§4.3): without `IGNORE_SPACE` the server may resolve the name
/// to a stored function. A qualified name (`db.sum (…)`) is a stored
/// function either way and is classified as one.
fn space_before_parenthesis(text: &str, raw: &RawStatement) -> bool {
    let toks = &raw.tokens;
    toks.iter().enumerate().any(|(i, t)| {
        let Some(w) = lexer::word_lower(text, t) else { return false };
        if !functions::space_sensitive(&w) {
            return false;
        }
        let qualified =
            toks[..i].iter().rev().find(|p| !p.is_comment()).is_some_and(|p| p.kind == TokKind::Punct(b'.'));
        let next = toks[i + 1..].iter().find(|n| !n.is_comment());
        !qualified && next.is_some_and(|n| n.kind == TokKind::Punct(b'(') && n.start != t.end)
    })
}

fn classify_raw(text: &str, raw: &RawStatement, s: Settings, names: &Names<'_>) -> Result<Analysis, Reason> {
    if raw.max_depth > MAX_NESTING {
        return Err(Reason::NestingTooDeep);
    }
    if raw.tokens.iter().any(|t| t.kind == TokKind::ExecComment) {
        return Err(Reason::ExecutableComment);
    }
    if file_or_os_access(text, raw) {
        return Err(Reason::ServerFileOrOsAccess);
    }
    for t in &raw.tokens {
        // sqlparser's MySQL tokenizer always reads `"…"` as a string and
        // always takes backslash escapes: where the session differs, the
        // statement is not classified (the span itself is exact).
        if t.kind == TokKind::QuotedIdent(b'"') {
            return Err(Reason::LexerSettingUnsupported);
        }
        let escapable = matches!(t.kind, TokKind::Str(StrKind::Single | StrKind::Double | StrKind::National));
        if s.no_backslash_escapes && escapable && text[t.start..t.end].contains('\\') {
            return Err(Reason::LexerSettingUnsupported);
        }
    }
    if space_before_parenthesis(text, raw) {
        return Err(Reason::SpaceBeforeParenthesis);
    }
    if let Some(result) = fallback::classify(text, raw, names) {
        return result;
    }
    let span_text = &text[raw.span.clone()];
    let dialect = MySqlDialect {};
    let tokens = Tokenizer::new(&dialect, span_text).tokenize_with_location().map_err(|_| Reason::ParseFailed)?;
    if !differential::agree(span_text, raw.span.start, &raw.tokens, &tokens) {
        return Err(Reason::LexerDisagreement);
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
