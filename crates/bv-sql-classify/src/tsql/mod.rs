//! The T-SQL dialect, SQL Server 2022 and later (T128, Phase 7): lex,
//! split, refuse `GO` lines and server file / OS / remote access from the
//! words alone, cross-check the lexers, then classify from tokens or the
//! parsed statement.

// SQL Server runs a span as a batch and the batch protocol cannot be told
// to stop after one statement (§4.3's residual). So the parser reads each
// span without requiring `;`, and a span it finds two statements in is
// never run; what the parser cannot read is refused.

mod analyze;
mod differential;
mod fallback;
mod functions;
mod lexer;
mod names;
mod settings;

use sqlparser::dialect::MsSqlDialect;
use sqlparser::parser::{Parser, ParserOptions};
use sqlparser::tokenizer::Tokenizer;

use crate::model::{ClassifiedStatement, NameContext, NameMatch, Reason, Refusal, Unclassifiable};
use crate::{MAX_NESTING, MAX_STATEMENTS, MAX_TEXT_BYTES, PARSER_RECURSION_LIMIT};
use analyze::Analysis;
use lexer::{RawStatement, StrKind, TokKind};
use names::Names;

/// The session settings the T-SQL lexer and name rules follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settings {
    pub quoted_identifier: bool,
    pub names: NameMatch,
    pub catalogs: NameMatch,
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
    if lexer::batch_separator(text, &tokens).is_some() {
        // `GO` belongs to sqlcmd and SSMS, not to the server: a script that
        // holds one was written for a client that splits batches, and is
        // refused rather than split by guess (Phase 0 finding 3).
        return Err(Unclassifiable::whole(Reason::BatchSeparator));
    }
    let statements = lexer::split(&tokens);
    if statements.len() > MAX_STATEMENTS {
        return Err(Unclassifiable::whole(Reason::TooManyStatements));
    }
    let names = Names { ctx, names: s.names, catalogs: s.catalogs };
    Ok(statements.iter().enumerate().map(|(i, raw)| statement(text, i, raw, &names)).collect())
}

/// `text` with every string and number replaced by `?` and every comment by
/// a space, found by the same lexer that splits statements.
pub(crate) fn redact(text: &str, s: Settings) -> Result<String, Reason> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Reason::InputTooLarge);
    }
    let tokens = lexer::lex(text, s).map_err(|e| e.reason)?;
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for t in &tokens {
        let replacement = match t.kind {
            TokKind::Str(_) | TokKind::Number | TokKind::Binary => "?",
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
            if u.refusal == Refusal::Unknown && touches_files_or_guards(text, raw) {
                // An unread statement that names server files, remote
                // access or the pinned settings must not run as
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

/// Server file, OS, network and remote access spelled in the statement's
/// words (`functions::always_refused`: `xp_*`, `sp_OA*`, `OPENROWSET`,
/// `BULK`, `BACKUP`, `RESTORE`, `EXTERNAL` …), and `CREATE / ALTER
/// ASSEMBLY` (CLR code loaded into the server).
fn file_or_os_access(text: &str, raw: &RawStatement) -> bool {
    let w = words(text, raw);
    w.iter().any(|x| functions::always_refused(x))
        || w.windows(2).any(|p| matches!(p[0].as_str(), "create" | "alter") && p[1] == "assembly")
}

/// Words naming the pinned lexer settings: an `Unknown` refusal that
/// mentions one is raised to `Never`.
fn touches_files_or_guards(text: &str, raw: &RawStatement) -> bool {
    let w = words(text, raw);
    file_or_os_access(text, raw) || w.iter().any(|x| matches!(x.as_str(), "quoted_identifier" | "ansi_defaults"))
}

fn classify_raw(text: &str, raw: &RawStatement, names: &Names<'_>) -> Result<Analysis, Reason> {
    if raw.max_depth > MAX_NESTING {
        return Err(Reason::NestingTooDeep);
    }
    if file_or_os_access(text, raw) {
        return Err(Reason::ServerFileOrOsAccess);
    }
    // sqlparser's MS SQL tokenizer always reads `"…"` as an identifier:
    // under QUOTED_IDENTIFIER OFF the statement is not classified (the span
    // itself is exact).
    if raw.tokens.iter().any(|t| t.kind == TokKind::Str(StrKind::Double)) {
        return Err(Reason::LexerSettingUnsupported);
    }
    if let Some(result) = fallback::classify(text, raw, names) {
        return result;
    }
    let span_text = &text[raw.span.clone()];
    let dialect = MsSqlDialect {};
    let tokens = Tokenizer::new(&dialect, span_text).tokenize_with_location().map_err(|_| Reason::ParseFailed)?;
    if !differential::agree(span_text, raw.span.start, &raw.tokens, &tokens) {
        return Err(Reason::LexerDisagreement);
    }
    // T-SQL needs no `;` between statements: the parser is told so, and a
    // span it reads as two statements is refused (never run as one batch).
    let options = ParserOptions { require_semicolon_stmt_delimiter: false, ..ParserOptions::new() };
    let statements = Parser::new(&dialect)
        .with_options(options)
        .with_recursion_limit(PARSER_RECURSION_LIMIT)
        .with_tokens_with_locations(tokens)
        .parse_statements()
        .map_err(|_| Reason::ParseFailed)?;
    let [stmt] = statements.as_slice() else { return Err(Reason::NotOneStatement) };
    analyze::analyze(stmt, names)
}

#[cfg(test)]
mod tests;
