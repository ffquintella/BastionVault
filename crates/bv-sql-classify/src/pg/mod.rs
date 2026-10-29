//! The PostgreSQL dialect: lex, split, cross-check, parse, classify.

mod analyze;
mod differential;
mod fallback;
mod functions;
mod lexer;
mod names;
mod settings;

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Tokenizer;

use crate::model::{ClassifiedStatement, NameContext, Reason, Refusal, Unclassifiable};
use crate::{MAX_NESTING, MAX_STATEMENTS, MAX_TEXT_BYTES, PARSER_RECURSION_LIMIT};
use analyze::Analysis;
use lexer::{RawStatement, StrKind, TokKind};
use names::Names;

/// Longest identifier length accepted from a [`NameContext`]. PostgreSQL's
/// `NAMEDATALEN` is a compile-time constant, 64 by default.
const MAX_IDENTIFIER_LENGTH: usize = 1024;

pub(crate) fn classify_each(
    text: &str,
    standard_conforming_strings: bool,
    ctx: &NameContext,
) -> Result<Vec<Result<ClassifiedStatement, Unclassifiable>>, Unclassifiable> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Unclassifiable::whole(Reason::InputTooLarge));
    }
    if ctx.current_catalog.is_empty()
        || ctx.max_identifier_length == 0
        || ctx.max_identifier_length > MAX_IDENTIFIER_LENGTH
        || ctx.current_schema.as_deref() == Some("")
    {
        return Err(Unclassifiable::whole(Reason::InvalidContext));
    }
    let tokens = lexer::lex(text, standard_conforming_strings).map_err(|e| Unclassifiable::whole(e.reason))?;
    let statements = lexer::split(text, &tokens);
    if statements.len() > MAX_STATEMENTS {
        return Err(Unclassifiable::whole(Reason::TooManyStatements));
    }
    let names = Names { ctx };
    Ok(statements
        .iter()
        .enumerate()
        .map(|(i, raw)| statement(text, i, raw, standard_conforming_strings, &names))
        .collect())
}

/// `text` with every string, dollar-quoted and numeric literal replaced by
/// `?` and every comment by a space, found by the same lexer that splits
/// statements. Identifiers, keywords and `$n` parameters are kept.
pub(crate) fn redact(text: &str, standard_conforming_strings: bool) -> Result<String, Reason> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Reason::InputTooLarge);
    }
    let tokens = lexer::lex(text, standard_conforming_strings).map_err(|e| e.reason)?;
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for t in &tokens {
        let replacement = match t.kind {
            TokKind::Str(_) | TokKind::DollarStr | TokKind::Number => "?",
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
    scs: bool,
    names: &Names<'_>,
) -> Result<ClassifiedStatement, Unclassifiable> {
    let span = raw.span.clone();
    match classify_raw(text, raw, scs, names) {
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
            if u.refusal == Refusal::Unknown && looks_like_file_or_os_access(text, raw) {
                // An unparsed statement that may touch server files or the OS
                // must not run as `unclassified` either (§4.2).
                u.refusal = Refusal::Never;
            }
            Err(u)
        }
    }
}

fn classify_raw(text: &str, raw: &RawStatement, scs: bool, names: &Names<'_>) -> Result<Analysis, Reason> {
    if raw.max_depth > MAX_NESTING {
        return Err(Reason::NestingTooDeep);
    }
    for t in &raw.tokens {
        if t.continued {
            return Err(Reason::StringContinuation);
        }
        let plain = matches!(t.kind, TokKind::Str(StrKind::Plain | StrKind::National));
        if !scs && plain && text[t.start..t.end].contains('\\') {
            return Err(Reason::BackslashInPlainString);
        }
    }
    if let Some(result) = fallback::classify(text, raw, names) {
        return result;
    }
    let span_text = &text[raw.span.clone()];
    let dialect = PostgreSqlDialect {};
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

/// Words that mark server file, OS or network access in a statement the
/// classifier could not otherwise read: `COPY` (file and `PROGRAM` forms),
/// `LOAD`, `CREATE TABLESPACE`, the always-refused functions, and an
/// untrusted procedural language.
fn looks_like_file_or_os_access(text: &str, raw: &RawStatement) -> bool {
    let words: Vec<String> = raw
        .tokens
        .iter()
        .filter(|t| !t.is_comment())
        .map(|t| {
            let s = &text[t.start..t.end];
            match t.kind {
                TokKind::Word => s.to_ascii_lowercase(),
                TokKind::QuotedIdent | TokKind::Str(StrKind::Plain) => s[1..s.len() - 1].to_ascii_lowercase(),
                _ => String::new(),
            }
        })
        .collect();
    let first = words.first().map(String::as_str);
    if matches!(first, Some("copy" | "load")) {
        return true;
    }
    if first == Some("create") && words.iter().any(|w| w == "tablespace") {
        return true;
    }
    words.iter().enumerate().any(|(i, w)| {
        w == "program"
            || functions::always_refused(w)
            || (w == "language"
                && words.get(i + 1).is_some_and(|l| analyze::check_language(l) == Err(Reason::ServerFileOrOsAccess)))
    })
}

#[cfg(test)]
mod tests;
