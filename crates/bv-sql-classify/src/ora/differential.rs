//! The parser only sees code the server will see as code (Oracle).
//!
//! Every opaque region (string, q-quote, quoted identifier, comment) must
//! start and end at the same place in this crate's lexer and in sqlparser's
//! Oracle tokenizer; otherwise the classifier would judge text the server
//! reads differently (`x'1F'` is a word and a string to Oracle, a hex
//! literal to the parser; `"a""b"` is two identifiers to Oracle, one to it).

use sqlparser::tokenizer::{Location, Token, TokenWithSpan, Whitespace};

use super::lexer::{StrKind, Tok, TokKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opaque {
    Comment,
    Str(StrKind),
    QuotedIdent,
    /// A literal form Oracle does not have. Never matches.
    Foreign,
}

fn mine(t: &Tok) -> Option<Opaque> {
    match t.kind {
        TokKind::LineComment | TokKind::BlockComment => Some(Opaque::Comment),
        TokKind::Str(k) => Some(Opaque::Str(k)),
        TokKind::QuotedIdent => Some(Opaque::QuotedIdent),
        TokKind::Word | TokKind::Number | TokKind::Range | TokKind::Punct(_) => None,
    }
}

fn theirs(t: &Token) -> Option<Opaque> {
    Some(match t {
        Token::Whitespace(Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_)) => Opaque::Comment,
        Token::SingleQuotedString(_) => Opaque::Str(StrKind::Single),
        Token::NationalStringLiteral(_) => Opaque::Str(StrKind::National),
        Token::QuoteDelimitedStringLiteral(_) => Opaque::Str(StrKind::Q),
        Token::NationalQuoteDelimitedStringLiteral(_) => Opaque::Str(StrKind::NationalQ),
        Token::Word(w) => match w.quote_style {
            None => return None,
            Some('"') => Opaque::QuotedIdent,
            Some(_) => Opaque::Foreign,
        },
        Token::HexStringLiteral(_)
        | Token::DoubleQuotedString(_)
        | Token::EscapedStringLiteral(_)
        | Token::DollarQuotedString(_)
        | Token::TripleSingleQuotedString(_)
        | Token::TripleDoubleQuotedString(_)
        | Token::SingleQuotedByteStringLiteral(_)
        | Token::DoubleQuotedByteStringLiteral(_)
        | Token::TripleSingleQuotedByteStringLiteral(_)
        | Token::TripleDoubleQuotedByteStringLiteral(_)
        | Token::SingleQuotedRawStringLiteral(_)
        | Token::DoubleQuotedRawStringLiteral(_)
        | Token::TripleSingleQuotedRawStringLiteral(_)
        | Token::TripleDoubleQuotedRawStringLiteral(_)
        | Token::UnicodeStringLiteral(_) => Opaque::Foreign,
        _ => return None,
    })
}

/// sqlparser's locations: 1-based line and column, columns counted in
/// characters, and only `\n` starts a new line. `offsets` must be sorted.
fn locations(text: &str, offsets: &[usize]) -> Vec<Location> {
    let mut out = Vec::with_capacity(offsets.len());
    let (mut line, mut col) = (1u64, 1u64);
    let mut chars = text.char_indices().peekable();
    for &target in offsets {
        while let Some(&(i, c)) = chars.peek() {
            if i >= target {
                break;
            }
            if c == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            chars.next();
        }
        out.push(Location { line, column: col });
    }
    out
}

/// Do both lexers agree on every opaque region of `text`? `my_tokens` carry
/// offsets in the whole input; `base` is where `text` starts in it.
pub(crate) fn agree(text: &str, base: usize, my_tokens: &[Tok], their_tokens: &[TokenWithSpan]) -> bool {
    let my_opaque: Vec<(Opaque, usize, usize)> =
        my_tokens.iter().filter_map(|t| mine(t).map(|k| (k, t.start - base, t.end - base))).collect();
    let mut offsets: Vec<usize> = my_opaque.iter().flat_map(|&(_, s, e)| [s, e]).collect();
    offsets.sort_unstable();
    offsets.dedup();
    let locs = locations(text, &offsets);
    let loc_of = |o: usize| offsets.binary_search(&o).ok().map(|i| locs[i]);
    let mut theirs_iter = their_tokens.iter().filter_map(|t| theirs(&t.token).map(|k| (k, t.span.start, t.span.end)));
    for &(kind, s, e) in &my_opaque {
        let Some((their_kind, their_start, their_end)) = theirs_iter.next() else { return false };
        if kind != their_kind || loc_of(s) != Some(their_start) || loc_of(e) != Some(their_end) {
            return false;
        }
    }
    theirs_iter.next().is_none()
}
