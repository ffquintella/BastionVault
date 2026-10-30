//! A MySQL / MariaDB lexer that follows the server's rules (`sql_lex.cc`)
//! for where code ends and opaque text begins: `'…'` and `"…"` strings with
//! or without backslash escapes, backtick identifiers, `"…"` identifiers
//! under `ANSI_QUOTES`, `#`, `-- ` and `/* */` comments, and the comments the
//! server executes (`/*!`, `/*M!`) or interprets (`/*+`).

// It builds no AST: it splits the input into statements and is the
// reference the parser's tokenizer is checked against (`differential.rs`).

// What the server reads in a version-dependent way is refused: nested
// comments, `\v` / `\f`, `\` outside a literal, number junk (`1abc` is an
// identifier to the server), non-alphanumeric non-ASCII outside literals.

use crate::model::Reason;

use super::Settings;

/// Kind of a string literal, by its prefix or quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrKind {
    /// `'…'`.
    Single,
    /// `"…"` without `ANSI_QUOTES`.
    Double,
    /// `X'…'`: hex digits, no escapes.
    Hex,
    /// `B'…'`: binary digits, no escapes.
    Bit,
    /// `N'…'`: national; lexed like `'…'`.
    National,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokKind {
    /// Unquoted identifier or keyword.
    Word,
    /// `` `…` ``, or `"…"` under `ANSI_QUOTES` (the `u8` is the quote).
    QuotedIdent(u8),
    Str(StrKind),
    LineComment,
    BlockComment,
    /// `/*! … */`, `/*M! … */`, `/*+ … */`: never runs (§4.3).
    ExecComment,
    Number,
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
        matches!(self.kind, TokKind::LineComment | TokKind::BlockComment | TokKind::ExecComment)
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

/// Unquoted identifier start: ASCII letters, `_`, `$`, and alphanumeric
/// characters of the Basic Multilingual Plane (the server takes nothing
/// beyond U+FFFF in an unquoted identifier).
fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$' || (!c.is_ascii() && c.is_alphanumeric() && (c as u32) <= 0xFFFF)
}

fn ident_cont(c: char) -> bool {
    ident_start(c) || c.is_ascii_digit()
}

/// Whitespace outside literals. The server also takes `\v` and `\f`; the
/// parser does not, so they are refused as control characters.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
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

    /// A quoted body after the opening `quote` at `start`: the quote doubled
    /// stands for itself; with `backslash`, `\` takes the next character.
    /// Returns the offset just past the closing quote.
    fn quoted(&self, start: usize, quote: u8, backslash: bool) -> Result<usize, LexError> {
        let mut j = start + 1;
        loop {
            match self.byte(j) {
                None => return err(Reason::UnterminatedLiteral, start),
                Some(b) if b == quote => {
                    if self.byte(j + 1) == Some(quote) {
                        j += 2;
                    } else {
                        return Ok(j + 1);
                    }
                }
                Some(b'\\') if backslash => {
                    j += 1;
                    if j >= self.bytes.len() {
                        return err(Reason::UnterminatedLiteral, start);
                    }
                    j += self.char_len(j);
                }
                Some(_) => j += self.char_len(j),
            }
        }
    }

    /// `X'…'` / `B'…'`: the first `'` ends the literal.
    fn prefixed_raw(&self, start: usize, kind: StrKind) -> Result<Tok, LexError> {
        let quote = start + 1;
        match self.text[quote + 1..].find('\'') {
            Some(rel) => Ok(tok(TokKind::Str(kind), start, quote + 1 + rel + 1)),
            None => err(Reason::UnterminatedLiteral, start),
        }
    }

    fn block_comment(&self, start: usize) -> Result<Tok, LexError> {
        // `/*!`, `/*M!` (MariaDB; either case is refused), `/*+` (hints).
        let exec = matches!(
            (self.byte(start + 2), self.byte(start + 3)),
            (Some(b'!' | b'+'), _) | (Some(b'M' | b'm'), Some(b'!'))
        );
        let mut j = start + 2;
        loop {
            match (self.byte(j), self.byte(j + 1)) {
                (None, _) => return err(Reason::UnterminatedLiteral, start),
                // MySQL 8 does not nest comments; MariaDB nests one level.
                // Either reading may be the server's, so neither is guessed.
                (Some(b'/'), Some(b'*')) => return err(Reason::ExecutableComment, j),
                (Some(b'*'), Some(b'/')) => {
                    let kind = if exec { TokKind::ExecComment } else { TokKind::BlockComment };
                    return Ok(tok(kind, start, j + 2));
                }
                _ => j += self.char_len(j),
            }
        }
    }

    /// `#` or `-- `: up to (not including) the next `\n`. The server ends
    /// these at `\n` only.
    fn line_comment(&self, start: usize, prefix: usize) -> Tok {
        let mut j = start + prefix;
        while let Some(b) = self.byte(j) {
            if b == b'\n' {
                break;
            }
            j += self.char_len(j);
        }
        tok(TokKind::LineComment, start, j)
    }

    fn number(&self, start: usize) -> Result<Tok, LexError> {
        let b = self.bytes;
        let mut j = start;
        let radix: Option<fn(u8) -> bool> = if b.get(j) == Some(&b'0') {
            match b.get(j + 1) {
                Some(b'x') => Some(|c: u8| c.is_ascii_hexdigit()),
                Some(b'b') => Some(|c: u8| c == b'0' || c == b'1'),
                _ => None,
            }
        } else {
            None
        };
        if let Some(digit) = radix {
            j += 2;
            let from = j;
            while b.get(j).is_some_and(|&c| digit(c)) {
                j += 1;
            }
            if j == from {
                return err(Reason::InvalidCharacter, j);
            }
        } else {
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            if b.get(j) == Some(&b'.') {
                j += 1;
                while b.get(j).is_some_and(u8::is_ascii_digit) {
                    j += 1;
                }
            }
            if matches!(b.get(j), Some(b'e' | b'E')) {
                let mut k = j + 1;
                if matches!(b.get(k), Some(b'+' | b'-')) {
                    k += 1;
                }
                if b.get(k).is_some_and(u8::is_ascii_digit) {
                    j = k;
                    while b.get(j).is_some_and(u8::is_ascii_digit) {
                        j += 1;
                    }
                }
            }
        }
        // `1abc`, `0x1G`, `1e5x`: the server reads an identifier there, the
        // parser a number and a word. Refused rather than read one way.
        if self.peek_char(j).is_some_and(ident_cont) {
            return err(Reason::InvalidCharacter, j);
        }
        Ok(tok(TokKind::Number, start, j))
    }

    fn word(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start;
        while let Some(c) = self.peek_char(j) {
            if !c.is_ascii() && !(c.is_alphanumeric() && (c as u32) <= 0xFFFF) {
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
        while b.get(self.pos).is_some_and(|&c| is_space(c)) {
            self.pos += 1;
        }
        let i = self.pos;
        let Some(&c) = b.get(i) else { return Ok(None) };
        let next = b.get(i + 1).copied();
        let backslash = !self.s.no_backslash_escapes;
        let t = match c {
            0 => return err(Reason::ControlCharacter, i),
            b'#' => self.line_comment(i, 1),
            // `--` is a comment only when whitespace follows (or nothing).
            b'-' if next == Some(b'-') && b.get(i + 2).is_none_or(|&c| is_space(c)) => self.line_comment(i, 2),
            b'/' if next == Some(b'*') => self.block_comment(i)?,
            b'\'' => tok(TokKind::Str(StrKind::Single), i, self.quoted(i, b'\'', backslash)?),
            b'"' if self.s.ansi_quotes => tok(TokKind::QuotedIdent(b'"'), i, self.quoted(i, b'"', false)?),
            b'"' => tok(TokKind::Str(StrKind::Double), i, self.quoted(i, b'"', backslash)?),
            b'`' => tok(TokKind::QuotedIdent(b'`'), i, self.quoted(i, b'`', false)?),
            b'x' | b'X' if next == Some(b'\'') => self.prefixed_raw(i, StrKind::Hex)?,
            b'b' | b'B' if next == Some(b'\'') => self.prefixed_raw(i, StrKind::Bit)?,
            b'n' | b'N' if next == Some(b'\'') => {
                tok(TokKind::Str(StrKind::National), i, self.quoted(i + 1, b'\'', backslash)?)
            }
            b'0'..=b'9' => self.number(i)?,
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => self.number(i)?,
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
/// comment; statements with only comments are dropped. Compound statements
/// (`BEGIN … END` routine bodies) are not kept together: their pieces do
/// not parse and are refused.
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

    fn s(ansi_quotes: bool, no_backslash_escapes: bool) -> Settings {
        Settings { ansi_quotes, no_backslash_escapes, fold_table_names: false, mariadb: false }
    }

    fn spans(text: &str, st: Settings) -> Vec<&str> {
        let toks = lex(text, st).unwrap();
        split(&toks).into_iter().map(|r| &text[r.span]).collect()
    }

    fn kinds(text: &str) -> Vec<TokKind> {
        lex(text, s(false, false)).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn semicolons_inside_literals_and_comments_do_not_split() {
        let text = "SELECT 'a;b', \"c;d\", `e;f` /* g; */ # h;\n -- i;\n; SELECT 2";
        assert_eq!(spans(text, s(false, false)).len(), 2);
        assert_eq!(spans("SELECT 1;; ;SELECT 2;", s(false, false)), vec!["SELECT 1", "SELECT 2"]);
        assert!(spans("# only\n/* comments */;", s(false, false)).is_empty());
    }

    #[test]
    fn backslash_escapes_follow_sql_mode() {
        let text = r"SELECT 'a\'; DELETE FROM t; #'";
        // Escapes on (the default): `\'` is an escaped quote, one statement.
        assert_eq!(spans(text, s(false, false)).len(), 1);
        // NO_BACKSLASH_ESCAPES: the string ends after the backslash.
        assert_eq!(spans(text, s(false, true)).len(), 2);
    }

    #[test]
    fn double_quotes_follow_ansi_quotes() {
        assert_eq!(kinds("\"a\""), vec![TokKind::Str(StrKind::Double)]);
        let toks = lex("\"a\"\"b\"", s(true, false)).unwrap();
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].kind, TokKind::QuotedIdent(b'"'));
        // Under ANSI_QUOTES a backslash does not escape in an identifier.
        assert_eq!(spans(r#"SELECT "a\"; DELETE FROM t"#, s(true, false)).len(), 2);
    }

    #[test]
    fn dash_dash_needs_a_space() {
        // `1--1` is one minus a negative one, not a comment.
        assert!(!kinds("SELECT 1--1").contains(&TokKind::LineComment));
        assert!(kinds("SELECT 1 -- c").contains(&TokKind::LineComment));
        assert!(kinds("SELECT 1 --").contains(&TokKind::LineComment));
        // A `#` comment runs to `\n` only, not `\r`.
        let toks = lex("SELECT 1 # c\rDELETE FROM t", s(false, false)).unwrap();
        assert_eq!(toks.last().unwrap().kind, TokKind::LineComment);
    }

    #[test]
    fn executable_and_hint_comments_are_flagged() {
        for text in ["SELECT /*! 1 */", "SELECT /*!50001 1 */", "SELECT /*M! 1 */", "SELECT /*+ BKA(t) */ 1"] {
            assert!(kinds(text).contains(&TokKind::ExecComment), "{text}");
        }
        assert!(kinds("SELECT /* ! */ 1").contains(&TokKind::BlockComment));
        assert_eq!(lex("SELECT /* /* */ 1", s(false, false)).unwrap_err().reason, Reason::ExecutableComment);
    }

    #[test]
    fn prefixes_and_numbers() {
        assert_eq!(
            kinds("X'1F' b'01' N'a' 0x1F 0b01 1e5 .5 1.5"),
            vec![
                TokKind::Str(StrKind::Hex),
                TokKind::Str(StrKind::Bit),
                TokKind::Str(StrKind::National),
                TokKind::Number,
                TokKind::Number,
                TokKind::Number,
                TokKind::Number,
                TokKind::Number,
            ]
        );
        assert_eq!(kinds("`a``b`"), vec![TokKind::QuotedIdent(b'`')]);
    }

    #[test]
    fn refusals() {
        for (text, reason) in [
            ("SELECT 1\0", Reason::ControlCharacter),
            ("SELECT \u{0b}1", Reason::ControlCharacter),
            ("SELECT \u{0c}1", Reason::ControlCharacter),
            ("SELECT 1 \\ 2", Reason::InvalidCharacter),
            ("SELECT 1abc", Reason::InvalidCharacter),
            ("SELECT 0x1G", Reason::InvalidCharacter),
            ("SELECT\u{2003}1", Reason::InvalidCharacter),
            ("SELECT 'abc", Reason::UnterminatedLiteral),
            ("SELECT 'a\\'", Reason::UnterminatedLiteral),
            ("SELECT `abc", Reason::UnterminatedLiteral),
            ("SELECT /* x", Reason::UnterminatedLiteral),
            ("SELECT X'ab", Reason::UnterminatedLiteral),
        ] {
            assert_eq!(lex(text, s(false, false)).unwrap_err().reason, reason, "{text:?}");
        }
        assert!(lex("SELECT ação FROM tabela", s(false, false)).is_ok());
    }
}
