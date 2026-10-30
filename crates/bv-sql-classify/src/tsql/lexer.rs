//! A T-SQL lexer that follows SQL Server's rules for where code ends and
//! opaque text begins: `'…'` and `N'…'` strings (`''` escapes, no
//! backslash escapes), `[…]` identifiers (`]]` escapes), `"…"` identifiers
//! under `QUOTED_IDENTIFIER ON` (strings when it is off), `--` comments
//! (no space needed) and nested `/* */` comments.

// It builds no AST: it splits the input into statements at `;` and is the
// reference the parser's tokenizer is checked against (`differential.rs`).
// T-SQL does not need `;` between statements; that boundary is the
// parser's to find, and a span holding two statements is refused there.

// What the server may read differently from the parser is refused: a lone
// `\r` (it might end a `--` comment), other line or page separators inside a
// `--` comment, control characters, `\` outside a literal, number junk
// (`1abc`, `1e`), non-ASCII digits and non-alphanumeric non-ASCII outside
// literals.

use crate::model::Reason;

use super::Settings;

/// Kind of a string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrKind {
    /// `'…'`.
    Single,
    /// `N'…'`: national; lexed like `'…'`.
    National,
    /// `"…"` with `QUOTED_IDENTIFIER OFF`.
    Double,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokKind {
    /// Unquoted identifier or keyword, including `@var`, `@@fn`, `#temp`,
    /// `##temp` and `$action`-style pseudo-columns.
    Word,
    /// `[…]`, or `"…"` under `QUOTED_IDENTIFIER ON` (the `u8` is the
    /// opening quote).
    QuotedIdent(u8),
    Str(StrKind),
    LineComment,
    BlockComment,
    /// Decimal, float or money (`$12.50`) constant.
    Number,
    /// `0x…`: a binary constant.
    Binary,
    /// Any other single character outside a literal.
    Punct(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tok {
    pub kind: TokKind,
    pub start: usize,
    pub end: usize,
}

impl Tok {
    pub fn is_comment(&self) -> bool {
        matches!(self.kind, TokKind::LineComment | TokKind::BlockComment)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LexError {
    pub reason: Reason,
    pub at: usize,
}

fn err<T>(reason: Reason, at: usize) -> Result<T, LexError> {
    Err(LexError { reason, at })
}

/// Identifier start: letters of the Basic Multilingual Plane, `_`, `@`,
/// `#`. (`$` continues an identifier but does not start one.)
fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic()
        || matches!(c, '_' | '@' | '#')
        || (!c.is_ascii() && c.is_alphabetic() && (c as u32) <= 0xFFFF)
}

fn ident_cont(c: char) -> bool {
    ident_start(c) || c.is_ascii_digit() || c == '$'
}

/// Whitespace outside literals. A `\r` counts only as part of `\r\n`.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n')
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    s: Settings,
    pos: usize,
}

impl Lexer<'_> {
    fn peek_char(&self, at: usize) -> Option<char> {
        self.text.get(at..).and_then(|s| s.chars().next())
    }

    fn byte(&self, at: usize) -> Option<u8> {
        self.bytes.get(at).copied()
    }

    fn char_len(&self, at: usize) -> usize {
        self.peek_char(at).map_or(1, char::len_utf8)
    }

    /// A body after the opening delimiter at `start`, closed by `close`;
    /// `close` doubled stands for itself. Returns the offset just past the
    /// closing delimiter.
    fn delimited(&self, start: usize, open_len: usize, close: u8) -> Result<usize, LexError> {
        let mut j = start + open_len;
        loop {
            match self.byte(j) {
                None => return err(Reason::UnterminatedLiteral, start),
                Some(b) if b == close => {
                    if self.byte(j + 1) == Some(close) {
                        j += 2;
                    } else {
                        return Ok(j + 1);
                    }
                }
                Some(_) => j += self.char_len(j),
            }
        }
    }

    /// `/* … */`, nested as SQL Server nests them.
    fn block_comment(&self, start: usize) -> Result<Tok, LexError> {
        let mut depth = 1usize;
        let mut j = start + 2;
        loop {
            match (self.byte(j), self.byte(j + 1)) {
                (None, _) => return err(Reason::UnterminatedLiteral, start),
                (Some(b'/'), Some(b'*')) => {
                    depth += 1;
                    j += 2;
                }
                (Some(b'*'), Some(b'/')) => {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        return Ok(tok(TokKind::BlockComment, start, j));
                    }
                }
                _ => j += self.char_len(j),
            }
        }
    }

    /// `--` up to (not including) the next `\n`. Any other character that
    /// some reader might take for a line end is refused, so the comment ends
    /// where every reader agrees.
    fn line_comment(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start + 2;
        while let Some(c) = self.peek_char(j) {
            match c {
                '\n' => break,
                '\r' if self.byte(j + 1) == Some(b'\n') => break,
                '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                    return err(Reason::ControlCharacter, j)
                }
                _ => j += c.len_utf8(),
            }
        }
        Ok(tok(TokKind::LineComment, start, j))
    }

    fn digits(&self, mut j: usize) -> usize {
        while self.byte(j).is_some_and(|c| c.is_ascii_digit()) {
            j += 1;
        }
        j
    }

    /// Decimal or float: `12`, `1.5`, `.5`, `1.`, `1e5`, `1.5E-3`.
    fn decimal(&self, start: usize) -> Result<usize, LexError> {
        let mut j = self.digits(start);
        if self.byte(j) == Some(b'.') {
            j = self.digits(j + 1);
        }
        if matches!(self.byte(j), Some(b'e' | b'E')) {
            let mut k = j + 1;
            if matches!(self.byte(k), Some(b'+' | b'-')) {
                k += 1;
            }
            if !self.byte(k).is_some_and(|c| c.is_ascii_digit()) {
                // `1e` is a float to the server and a number and a word to
                // the parser.
                return err(Reason::InvalidCharacter, j);
            }
            j = self.digits(k);
        }
        Ok(j)
    }

    /// No identifier character may follow a number: `1abc` is `1 AS abc` to
    /// the server, which is refused rather than read one way.
    fn number_end(&self, j: usize) -> Result<usize, LexError> {
        match self.peek_char(j) {
            Some(c) if ident_cont(c) || c == '.' => err(Reason::InvalidCharacter, j),
            Some(c) if !c.is_ascii() && c.is_numeric() => err(Reason::InvalidCharacter, j),
            _ => Ok(j),
        }
    }

    fn number(&self, start: usize) -> Result<Tok, LexError> {
        if self.byte(start) == Some(b'0') && matches!(self.byte(start + 1), Some(b'x' | b'X')) {
            let mut j = start + 2;
            while self.byte(j).is_some_and(|c| c.is_ascii_hexdigit()) {
                j += 1;
            }
            return Ok(tok(TokKind::Binary, start, self.number_end(j)?));
        }
        let end = self.decimal(start)?;
        Ok(tok(TokKind::Number, start, self.number_end(end)?))
    }

    fn word(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start;
        while let Some(c) = self.peek_char(j) {
            if !c.is_ascii() && !(c.is_alphabetic() && (c as u32) <= 0xFFFF) {
                // A national digit or a non-letter: the server's identifier
                // rules and the parser's differ there.
                return err(Reason::InvalidCharacter, j);
            }
            if !ident_cont(c) {
                break;
            }
            j += c.len_utf8();
        }
        Ok(tok(TokKind::Word, start, j))
    }

    fn next(&mut self) -> Result<Option<Tok>, LexError> {
        let b = self.bytes;
        loop {
            match b.get(self.pos) {
                Some(&c) if is_space(c) => self.pos += 1,
                Some(b'\r') if b.get(self.pos + 1) == Some(&b'\n') => self.pos += 2,
                _ => break,
            }
        }
        let i = self.pos;
        let Some(&c) = b.get(i) else { return Ok(None) };
        let next = b.get(i + 1).copied();
        let t = match c {
            b'-' if next == Some(b'-') => self.line_comment(i)?,
            b'/' if next == Some(b'*') => self.block_comment(i)?,
            b'\'' => tok(TokKind::Str(StrKind::Single), i, self.delimited(i, 1, b'\'')?),
            b'n' | b'N' if next == Some(b'\'') => tok(TokKind::Str(StrKind::National), i, self.delimited(i, 2, b'\'')?),
            b'"' if self.s.quoted_identifier => tok(TokKind::QuotedIdent(b'"'), i, self.delimited(i, 1, b'"')?),
            b'"' => tok(TokKind::Str(StrKind::Double), i, self.delimited(i, 1, b'"')?),
            b'[' => tok(TokKind::QuotedIdent(b'['), i, self.delimited(i, 1, b']')?),
            b'0'..=b'9' => self.number(i)?,
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => {
                let end = self.decimal(i)?;
                tok(TokKind::Number, i, self.number_end(end)?)
            }
            // Money constants: `$12`, `$.5`, `$12.50`.
            b'$' if next.is_some_and(|d| d.is_ascii_digit())
                || (next == Some(b'.') && b.get(i + 2).is_some_and(u8::is_ascii_digit)) =>
            {
                let end = self.decimal(i + 1)?;
                tok(TokKind::Number, i, self.number_end(end)?)
            }
            // `$action`, `$identity`, `$rowguid`: pseudo-columns.
            b'$' if next.is_some_and(|d| d.is_ascii_alphabetic()) => self.word(i)?,
            b'\\' => return err(Reason::InvalidCharacter, i),
            c if c < 0x20 || c == 0x7f => return err(Reason::ControlCharacter, i),
            c if c.is_ascii() && ident_start(c as char) => self.word(i)?,
            c if c.is_ascii() => tok(TokKind::Punct(c), i, i + 1),
            _ => {
                let ch = self.peek_char(i).unwrap_or('\u{fffd}');
                if ident_start(ch) {
                    self.word(i)?
                } else {
                    return err(Reason::InvalidCharacter, i);
                }
            }
        };
        self.pos = t.end;
        Ok(Some(t))
    }
}

fn tok(kind: TokKind, start: usize, end: usize) -> Tok {
    Tok { kind, start, end }
}

/// Lex the whole input. Fails on the first error, with its offset.
pub(crate) fn lex(text: &str, s: Settings) -> Result<Vec<Tok>, LexError> {
    if let Some(at) = text.bytes().position(|b| b == 0) {
        return err(Reason::ControlCharacter, at);
    }
    let mut lx = Lexer { text, bytes: text.as_bytes(), s, pos: 0 };
    let mut out = Vec::new();
    while let Some(t) = lx.next()? {
        out.push(t);
    }
    Ok(out)
}

/// A `GO` batch separator: the word `GO` first on its line (only
/// whitespace before it on that line). The offset of the first one.
pub(crate) fn batch_separator(text: &str, tokens: &[Tok]) -> Option<usize> {
    tokens.iter().find_map(|t| {
        if t.kind != TokKind::Word || !text[t.start..t.end].eq_ignore_ascii_case("go") {
            return None;
        }
        let line_start = text[..t.start].rfind('\n').map_or(0, |n| n + 1);
        text[line_start..t.start].bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r')).then_some(t.start)
    })
}

/// One statement as the splitter delimited it.
#[derive(Debug, Clone)]
pub(crate) struct RawStatement {
    /// From the first to the last non-comment token.
    pub span: std::ops::Range<usize>,
    /// Every token inside the span, comments included.
    pub tokens: Vec<Tok>,
    /// Deepest `(` nesting seen.
    pub max_depth: usize,
}

/// The lower-cased text of an unquoted word, for keyword checks.
pub(crate) fn word_lower(text: &str, t: &Tok) -> Option<String> {
    (t.kind == TokKind::Word).then(|| text[t.start..t.end].to_ascii_lowercase())
}

/// Split lexed tokens into statements at every `;` outside a literal or a
/// comment; statements with only comments are dropped. `BEGIN … END`
/// blocks are not kept together: their pieces do not parse and are refused.
pub(crate) fn split(tokens: &[Tok]) -> Vec<RawStatement> {
    fn flush(current: &mut Vec<Tok>, max_depth: usize, out: &mut Vec<RawStatement>) {
        let first = current.iter().position(|t| !t.is_comment());
        let last = current.iter().rposition(|t| !t.is_comment());
        if let (Some(f), Some(l)) = (first, last) {
            out.push(RawStatement {
                span: current[f].start..current[l].end,
                tokens: current[f..=l].to_vec(),
                max_depth,
            });
        }
        current.clear();
    }
    let mut out = Vec::new();
    let mut current: Vec<Tok> = Vec::new();
    let (mut depth, mut max_depth) = (0usize, 0usize);
    for t in tokens {
        match t.kind {
            TokKind::Punct(b';') => {
                flush(&mut current, max_depth, &mut out);
                depth = 0;
                max_depth = 0;
                continue;
            }
            TokKind::Punct(b'(') => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            TokKind::Punct(b')') => depth = depth.saturating_sub(1),
            _ => {}
        }
        current.push(*t);
    }
    flush(&mut current, max_depth, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NameMatch;

    fn s(quoted_identifier: bool) -> Settings {
        Settings {
            quoted_identifier,
            names: NameMatch::AsciiCaseInsensitive,
            catalogs: NameMatch::AsciiCaseInsensitive,
        }
    }

    fn spans(text: &str) -> Vec<&str> {
        let toks = lex(text, s(true)).unwrap();
        split(&toks).into_iter().map(|r| &text[r.span]).collect()
    }

    fn kinds(text: &str, qi: bool) -> Vec<TokKind> {
        lex(text, s(qi)).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn semicolons_inside_literals_and_comments_do_not_split() {
        let text = "SELECT 'a;b', N'c;d', [e;f], \"g;h\" /* i; /* j; */ k; */ -- l;\n; SELECT 2";
        assert_eq!(spans(text).len(), 2);
        assert_eq!(spans("SELECT 1;; ;SELECT 2;"), vec!["SELECT 1", "SELECT 2"]);
        assert!(spans("-- only\n/* comments */;").is_empty());
    }

    #[test]
    fn brackets_and_quotes_escape_by_doubling() {
        assert_eq!(kinds("[a]]b]", true), vec![TokKind::QuotedIdent(b'[')]);
        assert_eq!(kinds("[a]]];x", true), vec![TokKind::QuotedIdent(b'['), TokKind::Punct(b';'), TokKind::Word]);
        assert_eq!(kinds("\"a\"\"b\"", true), vec![TokKind::QuotedIdent(b'"')]);
        assert_eq!(kinds("\"a\"\"b\"", false), vec![TokKind::Str(StrKind::Double)]);
        assert_eq!(
            kinds("'a''b' N'c' n'd'", true),
            vec![TokKind::Str(StrKind::Single), TokKind::Str(StrKind::National), TokKind::Str(StrKind::National)]
        );
        // No backslash escapes in T-SQL: the string ends at the second quote.
        assert_eq!(spans(r"SELECT 'a\'; DELETE FROM t"), vec![r"SELECT 'a\'", "DELETE FROM t"]);
    }

    #[test]
    fn comments_dash_dash_and_nested_blocks() {
        // `--` needs no space in T-SQL.
        assert!(kinds("SELECT 1--1", true).contains(&TokKind::LineComment));
        assert_eq!(spans("SELECT 1 /* a /* b */ c */ ; SELECT 2").len(), 2);
        assert_eq!(lex("SELECT 1 /* a /* b */", s(true)).unwrap_err().reason, Reason::UnterminatedLiteral);
        // `\r\n` ends a line comment; a lone `\r` (or another separator) is
        // refused, never guessed.
        assert_eq!(spans("SELECT 1 -- c\r\n; DELETE FROM t").len(), 2);
        for text in ["SELECT 1 -- c\rDELETE FROM t", "SELECT 1 -- c\u{2028}DELETE FROM t", "SELECT\r1"] {
            assert_eq!(lex(text, s(true)).unwrap_err().reason, Reason::ControlCharacter, "{text:?}");
        }
    }

    #[test]
    fn numbers_binary_and_money() {
        assert_eq!(
            kinds("1 1.5 .5 1. 1e5 1.5E-3 0x1F 0x $12 $.5 $1.25", true),
            vec![TokKind::Number; 5]
                .into_iter()
                .chain([TokKind::Number, TokKind::Binary, TokKind::Binary])
                .chain([TokKind::Number; 3])
                .collect::<Vec<_>>()
        );
        assert_eq!(kinds("$action @x @@ROWCOUNT #t ##g a$b", true), vec![TokKind::Word; 6]);
        for text in ["SELECT 1abc", "SELECT 1e", "SELECT 0x1G", "SELECT 1.2.3", "SELECT 1\u{0663}"] {
            assert_eq!(lex(text, s(true)).unwrap_err().reason, Reason::InvalidCharacter, "{text:?}");
        }
    }

    #[test]
    fn go_lines_are_found() {
        let text = "SELECT 1\nGO\nSELECT 2";
        assert_eq!(batch_separator(text, &lex(text, s(true)).unwrap()), Some(9));
        let text = "SELECT 1\n  go 5\n";
        assert!(batch_separator(text, &lex(text, s(true)).unwrap()).is_some());
        // A column named go mid-line is not a separator.
        let text = "SELECT go FROM t";
        assert_eq!(batch_separator(text, &lex(text, s(true)).unwrap()), None);
    }

    #[test]
    fn refusals() {
        for (text, reason) in [
            ("SELECT 1\0", Reason::ControlCharacter),
            ("SELECT \u{0b}1", Reason::ControlCharacter),
            ("SELECT 1 \\ 2", Reason::InvalidCharacter),
            ("SELECT\u{a0}1", Reason::InvalidCharacter),
            ("SELECT £100", Reason::InvalidCharacter),
            ("SELECT 'abc", Reason::UnterminatedLiteral),
            ("SELECT [abc", Reason::UnterminatedLiteral),
            ("SELECT [a]]", Reason::UnterminatedLiteral),
            ("SELECT \"abc", Reason::UnterminatedLiteral),
            ("SELECT /* x", Reason::UnterminatedLiteral),
        ] {
            assert_eq!(lex(text, s(true)).unwrap_err().reason, reason, "{text:?}");
        }
        assert!(lex("SELECT ação FROM tabela", s(true)).is_ok());
    }
}
