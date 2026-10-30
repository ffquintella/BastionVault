//! An Oracle lexer that follows the server's rules for where code ends and
//! opaque text begins: `'…'` and `N'…'` strings (`''` escapes, no backslash
//! escapes), q-quotes (`q'[…]'`, `Nq'…'`), `"…"` identifiers (no escape at
//! all), `--` comments and `/* */` comments, which do not nest.

// It builds no AST. It splits the input at `;` and at SQL*Plus `/` lines,
// except inside a PL/SQL unit, where only a `/` line or the end of input
// ends the unit, and it is the reference the parser's tokenizer is checked
// against (`differential.rs`).

// Refused, because the server or a client may read it differently: NUL,
// control characters (a lone `\r` too), `\`, `&` (SQL*Plus substitution),
// a lone `!` or `$`, number junk (`1abc`, `1e`, `1f`, `0x1F`), `_` or `#`
// starting a word, non-alphanumeric non-ASCII, empty `""`, a q-quote
// delimiter that is blank, `'`, non-ASCII or a closing bracket.

use crate::model::Reason;

/// Kind of a string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrKind {
    /// `'…'`.
    Single,
    /// `N'…'`.
    National,
    /// `q'…'`: the alternative quoting mechanism.
    Q,
    /// `Nq'…'`.
    NationalQ,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokKind {
    /// Unquoted identifier or keyword, including PL/SQL's `$IF` / `$$NAME`.
    Word,
    /// `"…"`.
    QuotedIdent,
    Str(StrKind),
    LineComment,
    BlockComment,
    Number,
    /// `..`, PL/SQL's range operator.
    Range,
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

    /// `/*+ … */` or `--+ …`: an optimizer hint, which the server reads.
    pub fn is_hint(&self, text: &str) -> bool {
        let s = &text[self.start..self.end];
        self.is_comment() && (s.starts_with("/*+") || s.starts_with("--+"))
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

/// Letters start an unquoted identifier (ASCII or not; the name rules
/// refuse non-ASCII later, the lexer only has to find the word's end).
fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || (!c.is_ascii() && c.is_alphabetic())
}

fn ident_cont(c: char) -> bool {
    ident_start(c) || c.is_ascii_digit() || matches!(c, '_' | '$' | '#')
}

/// Whitespace outside literals. A `\r` counts only as part of `\r\n`.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n')
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
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

    /// Only spaces and tabs between the start of the line and `at`.
    fn first_on_line(&self, at: usize) -> bool {
        let line_start = self.text[..at].rfind('\n').map_or(0, |n| n + 1);
        self.bytes[line_start..at].iter().all(|b| matches!(b, b' ' | b'\t'))
    }

    /// `'…'` after an `open_len`-byte prefix ending in the quote; `''`
    /// stands for a quote. Returns the offset just past the closing quote.
    fn quoted(&self, start: usize, open_len: usize) -> Result<usize, LexError> {
        let mut j = start + open_len;
        loop {
            match self.byte(j) {
                None => return err(Reason::UnterminatedLiteral, start),
                Some(b'\'') if self.byte(j + 1) == Some(b'\'') => j += 2,
                Some(b'\'') => return Ok(j + 1),
                Some(_) => j += self.char_len(j),
            }
        }
    }

    /// `q'<d>…<d>'` after an `open_len`-byte prefix ending in the quote: the
    /// literal ends at the first closing delimiter followed by `'`.
    fn q_quote(&self, start: usize, open_len: usize) -> Result<usize, LexError> {
        let at = start + open_len;
        let Some(open) = self.byte(at) else { return err(Reason::UnterminatedLiteral, start) };
        let close = match open {
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            b'(' => b')',
            // A blank, quote, control or non-ASCII delimiter, or a closing
            // bracket used to open, is read differently by some reader.
            b']' | b'}' | b'>' | b')' | b'\'' => return err(Reason::InvalidCharacter, at),
            b if (0x21..0x7f).contains(&b) => b,
            _ => return err(Reason::InvalidCharacter, at),
        };
        let mut j = at + 1;
        loop {
            match self.byte(j) {
                None => return err(Reason::UnterminatedLiteral, start),
                Some(b) if b == close && self.byte(j + 1) == Some(b'\'') => return Ok(j + 2),
                Some(_) => j += 1,
            }
        }
    }

    /// `"…"`: Oracle has no escape for `"`, and an empty name is an error.
    fn quoted_ident(&self, start: usize) -> Result<Tok, LexError> {
        let Some(len) = self.text[start + 1..].find('"') else { return err(Reason::UnterminatedLiteral, start) };
        if len == 0 {
            return err(Reason::InvalidCharacter, start);
        }
        Ok(tok(TokKind::QuotedIdent, start, start + 1 + len + 1))
    }

    /// `/* … */`. Oracle does not nest them.
    fn block_comment(&self, start: usize) -> Result<Tok, LexError> {
        match self.text[start + 2..].find("*/") {
            Some(n) => Ok(tok(TokKind::BlockComment, start, start + 2 + n + 2)),
            None => err(Reason::UnterminatedLiteral, start),
        }
    }

    /// `--` up to the next `\n` (a `\r` just before it belongs to the
    /// comment, as the parser's tokenizer reads it). Any other character
    /// some reader might take for a line end is refused.
    fn line_comment(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start + 2;
        while let Some(c) = self.peek_char(j) {
            match c {
                '\n' => break,
                '\r' if self.byte(j + 1) == Some(b'\n') => j += 1,
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

    /// `12`, `1.5`, `.5`, `1.`, `1e5`, `1.5E-3`. A `.` followed by another
    /// `.` is PL/SQL's range operator (`1..10`), not a decimal point.
    fn decimal(&self, start: usize) -> Result<usize, LexError> {
        let mut j = self.digits(start);
        if self.byte(j) == Some(b'.') && self.byte(j + 1) != Some(b'.') {
            j = self.digits(j + 1);
        }
        if matches!(self.byte(j), Some(b'e' | b'E')) {
            let mut k = j + 1;
            if matches!(self.byte(k), Some(b'+' | b'-')) {
                k += 1;
            }
            if !self.byte(k).is_some_and(|c| c.is_ascii_digit()) {
                return err(Reason::InvalidCharacter, j);
            }
            j = self.digits(k);
        }
        Ok(j)
    }

    /// No identifier character may follow a number: `1abc` is `1 abc` to
    /// the server, and `1f` / `1d` are binary float / double literals the
    /// parser reads as a number and an alias. Both are refused. The one
    /// exception is a size in DDL (`SIZE 10M`, `INITIAL 64K`): an integer
    /// and one of `K M G T P`, which every reader ends at the same place.
    fn number_end(&self, start: usize, j: usize) -> Result<usize, LexError> {
        let integer = self.bytes[start..j].iter().all(u8::is_ascii_digit);
        let size = matches!(self.byte(j), Some(b'k' | b'K' | b'm' | b'M' | b'g' | b'G' | b't' | b'T' | b'p' | b'P'));
        if integer && size && !self.peek_char(j + 1).is_some_and(|c| ident_cont(c) || c == '.') {
            return Ok(j + 1);
        }
        match self.peek_char(j) {
            Some('.') if self.byte(j + 1) == Some(b'.') => Ok(j),
            Some(c) if ident_cont(c) || c == '.' => err(Reason::InvalidCharacter, j),
            Some(c) if !c.is_ascii() && c.is_numeric() => err(Reason::InvalidCharacter, j),
            _ => Ok(j),
        }
    }

    fn word(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start;
        while let Some(c) = self.peek_char(j) {
            if !c.is_ascii() && !c.is_alphabetic() {
                // A national digit or a non-letter: the server's identifier
                // rules and the parser's may differ there.
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
        let after = b.get(i + 2).copied();
        let t = match c {
            b'-' if next == Some(b'-') => self.line_comment(i)?,
            b'/' if next == Some(b'*') => self.block_comment(i)?,
            b'\'' => tok(TokKind::Str(StrKind::Single), i, self.quoted(i, 1)?),
            b'n' | b'N' if next == Some(b'\'') => tok(TokKind::Str(StrKind::National), i, self.quoted(i, 2)?),
            b'n' | b'N' if matches!(next, Some(b'q' | b'Q')) && after == Some(b'\'') => {
                tok(TokKind::Str(StrKind::NationalQ), i, self.q_quote(i, 3)?)
            }
            b'q' | b'Q' if next == Some(b'\'') => tok(TokKind::Str(StrKind::Q), i, self.q_quote(i, 2)?),
            b'"' => self.quoted_ident(i)?,
            b'0'..=b'9' => {
                let end = self.decimal(i)?;
                tok(TokKind::Number, i, self.number_end(i, end)?)
            }
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => {
                let end = self.decimal(i)?;
                tok(TokKind::Number, i, self.number_end(i, end)?)
            }
            b'.' if next == Some(b'.') => tok(TokKind::Range, i, i + 2),
            // PL/SQL conditional compilation: `$IF`, `$THEN`, `$$PLSQL_UNIT`.
            b'$' if next.is_some_and(|d| d.is_ascii_alphabetic())
                || (next == Some(b'$') && after.is_some_and(|d| d.is_ascii_alphabetic())) =>
            {
                self.word(i)?
            }
            b'!' if next == Some(b'=') => tok(TokKind::Punct(c), i, i + 1),
            // `$ cmd` and `! cmd` run a host command in SQL*Plus.
            b'$' | b'!' if self.first_on_line(i) => return err(Reason::ClientCommand, i),
            b'$' | b'!' | b'\\' | b'&' | b'_' | b'#' => return err(Reason::InvalidCharacter, i),
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
pub(crate) fn lex(text: &str) -> Result<Vec<Tok>, LexError> {
    if let Some(at) = text.bytes().position(|b| b == 0) {
        return err(Reason::ControlCharacter, at);
    }
    let mut lx = Lexer { text, bytes: text.as_bytes(), pos: 0 };
    let mut out = Vec::new();
    while let Some(t) = lx.next()? {
        out.push(t);
    }
    Ok(out)
}

/// One statement or PL/SQL unit as the splitter delimited it.
#[derive(Debug, Clone)]
pub(crate) struct RawStatement {
    /// From the first to the last non-comment token.
    pub span: std::ops::Range<usize>,
    /// Every token inside the span, comments included.
    pub tokens: Vec<Tok>,
    /// Deepest `(` nesting seen.
    pub max_depth: usize,
    /// A PL/SQL unit: `;` did not end it.
    pub unit: bool,
}

/// The lower-cased text of an unquoted word, for keyword checks.
pub(crate) fn word_lower(text: &str, t: &Tok) -> Option<String> {
    (t.kind == TokKind::Word).then(|| text[t.start..t.end].to_ascii_lowercase())
}

/// The input's line boundaries, found once: per-token look-ups are a binary
/// search, so a 4 MiB single line costs no more than many short ones.
pub(crate) struct Lines {
    newlines: Vec<usize>,
    len: usize,
}

impl Lines {
    pub fn new(text: &str) -> Self {
        Self {
            newlines: text.bytes().enumerate().filter(|&(_, b)| b == b'\n').map(|(i, _)| i).collect(),
            len: text.len(),
        }
    }

    /// Offset of the first byte of the line holding `at`.
    pub fn start(&self, at: usize) -> usize {
        match self.newlines.partition_point(|&n| n < at) {
            0 => 0,
            k => self.newlines[k - 1] + 1,
        }
    }

    /// Offset of the `\n` ending the line holding `at`, or the input's end.
    pub fn end(&self, at: usize) -> usize {
        let k = self.newlines.partition_point(|&n| n < at);
        self.newlines.get(k).copied().unwrap_or(self.len)
    }
}

/// Where a `/` or `.` token sits on its line.
#[derive(Debug, PartialEq, Eq)]
enum LineRole {
    /// Alone on its line (spaces and tabs around it).
    Alone,
    /// First on its line, followed only by a comment: SQL*Plus and the
    /// server may disagree on what it is.
    BeforeComment,
    Inline,
}

fn line_role(text: &str, lines: &Lines, tokens: &[Tok], idx: usize) -> LineRole {
    let t = tokens[idx];
    let bytes = text.as_bytes();
    // Only the token before it on the same line needs looking at.
    let line_start = lines.start(t.start);
    let first = idx == 0 || tokens[idx - 1].end <= line_start;
    if !first || !bytes[line_start..t.start].iter().all(|b| matches!(b, b' ' | b'\t')) {
        return LineRole::Inline;
    }
    let line_end = lines.end(t.start);
    let next_on_line = tokens.get(idx + 1).is_some_and(|n| n.start < line_end);
    if !next_on_line && bytes[t.end..line_end].iter().all(|b| matches!(b, b' ' | b'\t' | b'\r')) {
        return LineRole::Alone;
    }
    match tokens.get(idx + 1) {
        Some(n) if n.is_comment() && n.start < line_end => LineRole::BeforeComment,
        _ => LineRole::Inline,
    }
}

/// Modifiers that may sit between `CREATE` and the kind of object.
const CREATE_MODIFIERS: &[&str] =
    &["or", "replace", "editionable", "noneditionable", "if", "not", "exists", "and", "resolve", "compile", "noforce"];

/// Object kinds whose `CREATE` SQL*Plus sends as PL/SQL: `;` inside them
/// does not end the statement.
const UNIT_KINDS: &[&str] = &["procedure", "function", "package", "trigger", "type", "library", "java", "mle"];

/// Whether the statement starting at `tokens[idx]` is a PL/SQL unit.
pub(crate) fn unit_start(text: &str, tokens: &[Tok], idx: usize) -> bool {
    let code: Vec<&Tok> = tokens[idx..].iter().filter(|t| !t.is_comment()).take(16).collect();
    let word = |k: usize| code.get(k).and_then(|t| word_lower(text, t));
    match word(0).as_deref() {
        Some("begin" | "declare") => true,
        Some("with") => matches!(word(1).as_deref(), Some("function" | "procedure")),
        Some("create") => {
            let mut k = 1;
            while word(k).is_some_and(|w| CREATE_MODIFIERS.contains(&w.as_str())) {
                k += 1;
            }
            word(k).is_some_and(|w| UNIT_KINDS.contains(&w.as_str()))
        }
        // `<<label>>` before a block.
        Some(_) => false,
        None => {
            code.first().is_some_and(|t| t.kind == TokKind::Punct(b'<'))
                && code.get(1).is_some_and(|t| t.kind == TokKind::Punct(b'<'))
        }
    }
}

/// Split lexed tokens into statements: at every `;` outside a literal or
/// comment, and at every `/` alone on its line; inside a PL/SQL unit only
/// at a `/` line. Statements with only comments are dropped, as is a `/`
/// line with nothing before it (SQL*Plus would run the last statement
/// again; nothing is run twice here).
pub(crate) fn split(text: &str, tokens: &[Tok]) -> Result<Vec<RawStatement>, LexError> {
    struct Current {
        toks: Vec<Tok>,
        unit: Option<bool>,
        depth: usize,
        max_depth: usize,
    }
    fn flush(c: &mut Current, out: &mut Vec<RawStatement>) {
        let first = c.toks.iter().position(|t| !t.is_comment());
        let last = c.toks.iter().rposition(|t| !t.is_comment());
        if let (Some(f), Some(l)) = (first, last) {
            out.push(RawStatement {
                span: c.toks[f].start..c.toks[l].end,
                tokens: c.toks[f..=l].to_vec(),
                max_depth: c.max_depth,
                unit: c.unit == Some(true),
            });
        }
        *c = Current { toks: Vec::new(), unit: None, depth: 0, max_depth: 0 };
    }
    let mut out = Vec::new();
    let lines = Lines::new(text);
    let mut c = Current { toks: Vec::new(), unit: None, depth: 0, max_depth: 0 };
    for (idx, t) in tokens.iter().enumerate() {
        if matches!(t.kind, TokKind::Punct(b'/' | b'.')) {
            match line_role(text, &lines, tokens, idx) {
                LineRole::Alone if t.kind == TokKind::Punct(b'/') => {
                    flush(&mut c, &mut out);
                    continue;
                }
                // `.` alone ends SQL*Plus input without running it.
                LineRole::Alone => return err(Reason::ClientCommand, t.start),
                LineRole::BeforeComment => return err(Reason::NotOneStatement, t.start),
                LineRole::Inline => {}
            }
        }
        if c.unit.is_none() && !t.is_comment() {
            c.unit = Some(unit_start(text, tokens, idx));
        }
        match t.kind {
            TokKind::Punct(b';') if c.unit != Some(true) => {
                flush(&mut c, &mut out);
                continue;
            }
            TokKind::Punct(b'(') => {
                c.depth += 1;
                c.max_depth = c.max_depth.max(c.depth);
            }
            TokKind::Punct(b')') => c.depth = c.depth.saturating_sub(1),
            _ => {}
        }
        c.toks.push(*t);
    }
    flush(&mut c, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(text: &str) -> Vec<&str> {
        let toks = lex(text).unwrap();
        split(text, &toks).unwrap().into_iter().map(|r| &text[r.span]).collect()
    }

    fn kinds(text: &str) -> Vec<TokKind> {
        lex(text).unwrap().into_iter().map(|t| t.kind).collect()
    }

    fn lex_err(text: &str) -> Reason {
        match lex(text) {
            Ok(toks) => split(text, &toks).unwrap_err().reason,
            Err(e) => e.reason,
        }
    }

    #[test]
    fn semicolons_inside_literals_and_comments_do_not_split() {
        let text = "SELECT 'a;b', N'c;d', q'[e;f]', nq'{g;}', \"h;i\" FROM t /* j; */ -- k;\n; SELECT 2";
        assert_eq!(spans(text).len(), 2);
        assert_eq!(
            spans("SELECT 1 FROM dual;; ;SELECT 2 FROM dual;"),
            vec!["SELECT 1 FROM dual", "SELECT 2 FROM dual"]
        );
        assert!(spans("-- only\n/* comments */;\n/\n").is_empty());
    }

    #[test]
    fn q_quotes_pair_brackets_or_repeat_the_delimiter() {
        for text in ["q'[a]b]'", "Q'{a}'", "q'<a>'", "q'(a)'", "q'!a'b!'", "q'xabcx'", "q'#it''s#'"] {
            assert_eq!(kinds(text), vec![TokKind::Str(StrKind::Q)], "{text:?}");
        }
        assert_eq!(kinds("nq'[x]' NQ'|y|'"), vec![TokKind::Str(StrKind::NationalQ); 2]);
        // The literal ends at the first closing delimiter followed by `'`.
        assert_eq!(spans("SELECT q'[a]'; DELETE FROM t"), vec!["SELECT q'[a]'", "DELETE FROM t"]);
        for text in ["q' a '", "q'\ta\t'", "q''a''", "q']a]'", "q')a)'", "q'\u{e9}a\u{e9}'"] {
            assert_eq!(lex(text).unwrap_err().reason, Reason::InvalidCharacter, "{text:?}");
        }
        assert_eq!(lex("q'[abc'").unwrap_err().reason, Reason::UnterminatedLiteral);
        // `q` and `nq` without a quote straight after are words.
        assert_eq!(kinds("q nq Q1"), vec![TokKind::Word; 3]);
    }

    #[test]
    fn strings_and_identifiers_have_no_backslash_and_no_quote_escape() {
        assert_eq!(
            kinds("'a''b' N'c' n'd'"),
            vec![TokKind::Str(StrKind::Single), TokKind::Str(StrKind::National), TokKind::Str(StrKind::National)]
        );
        assert_eq!(spans(r"SELECT 'a\'; DELETE FROM t"), vec![r"SELECT 'a\'", "DELETE FROM t"]);
        // `"a""b"` is two identifiers to Oracle.
        assert_eq!(kinds("\"a\"\"b\""), vec![TokKind::QuotedIdent; 2]);
        assert_eq!(lex("SELECT \"\" FROM t").unwrap_err().reason, Reason::InvalidCharacter);
    }

    #[test]
    fn comments_do_not_nest_and_end_at_newline() {
        assert_eq!(spans("SELECT 1 /* a /* b */ FROM dual; SELECT 2").len(), 2);
        assert_eq!(spans("SELECT 1 FROM dual -- c\r\n; DELETE FROM t").len(), 2);
        for text in ["SELECT 1 -- c\rDELETE FROM t", "SELECT 1 -- c\u{2028}x", "SELECT\r1"] {
            assert_eq!(lex(text).unwrap_err().reason, Reason::ControlCharacter, "{text:?}");
        }
        assert_eq!(lex("SELECT /* x").unwrap_err().reason, Reason::UnterminatedLiteral);
    }

    #[test]
    fn numbers_ranges_and_words() {
        assert_eq!(kinds("1 1.5 .5 1. 1e5 1.5E-3"), vec![TokKind::Number; 6]);
        assert_eq!(kinds("1..10"), vec![TokKind::Number, TokKind::Range, TokKind::Number]);
        assert_eq!(kinds("10M 64k 1G"), vec![TokKind::Number; 3]);
        assert_eq!(kinds("v$session a#b x_1 $IF $$PLSQL_UNIT"), vec![TokKind::Word; 5]);
        for text in [
            "SELECT 1abc",
            "SELECT 1e",
            "SELECT 0x1F",
            "SELECT 1.5f",
            "SELECT 2d",
            "SELECT 1.2.3",
            "SELECT 1.5M",
            "SELECT 10MB",
        ] {
            assert_eq!(lex(text).unwrap_err().reason, Reason::InvalidCharacter, "{text:?}");
        }
    }

    #[test]
    fn slash_lines_end_statements_and_units() {
        assert_eq!(
            spans("SELECT 1 FROM dual\n/\nSELECT 2 FROM dual\n  /  \n"),
            vec!["SELECT 1 FROM dual", "SELECT 2 FROM dual"]
        );
        // Division mid-line is not a terminator.
        assert_eq!(spans("SELECT 4 / 2 FROM dual\n/2"), vec!["SELECT 4 / 2 FROM dual\n/2"]);
        let text = "BEGIN\n  x := 1;\n  y := 2;\nEND;\n/\nSELECT 1 FROM dual;";
        let toks = lex(text).unwrap();
        let raws = split(text, &toks).unwrap();
        assert_eq!(
            raws.iter().map(|r| &text[r.span.clone()]).collect::<Vec<_>>(),
            vec!["BEGIN\n  x := 1;\n  y := 2;\nEND;", "SELECT 1 FROM dual"]
        );
        assert!(raws[0].unit && !raws[1].unit);
        // A unit with no `/` runs to the end of the input.
        assert_eq!(spans("CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;\nSELECT 1 FROM dual;").len(), 1);
        assert_eq!(lex_err("SELECT 1 FROM dual\n/ -- run it\n"), Reason::NotOneStatement);
        assert_eq!(lex_err("SELECT a\n.\nFROM t"), Reason::ClientCommand);
    }

    #[test]
    fn unit_starts() {
        for text in [
            "BEGIN NULL; END;",
            "declare x int; begin null; end;",
            "<<l>> BEGIN NULL; END;",
            "CREATE OR REPLACE EDITIONABLE PACKAGE BODY p AS END;",
            "create function f return number is begin return 1; end;",
            "CREATE TYPE t AS OBJECT (a NUMBER);",
            "CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED x AS class X {};",
            "WITH FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; SELECT f FROM dual",
            "/* c */ CREATE TRIGGER t BEFORE INSERT ON x BEGIN NULL; END;",
        ] {
            let toks = lex(text).unwrap();
            let raws = split(text, &toks).unwrap();
            assert_eq!(raws.len(), 1, "{text:?}");
            assert!(raws[0].unit, "{text:?}");
        }
        for text in ["CREATE OR REPLACE VIEW v AS SELECT 1 FROM dual", "WITH c AS (SELECT 1 FROM dual) SELECT * FROM c"]
        {
            let toks = lex(text).unwrap();
            assert!(!split(text, &toks).unwrap()[0].unit, "{text:?}");
        }
    }

    #[test]
    fn refusals() {
        for (text, reason) in [
            ("SELECT 1\0", Reason::ControlCharacter),
            ("SELECT \u{0b}1", Reason::ControlCharacter),
            ("SELECT 1 \\ 2", Reason::InvalidCharacter),
            ("SELECT &x FROM dual", Reason::InvalidCharacter),
            ("SELECT _x FROM dual", Reason::InvalidCharacter),
            ("SELECT #x FROM dual", Reason::InvalidCharacter),
            ("SELECT 1 ! 2", Reason::InvalidCharacter),
            ("SELECT\u{a0}1", Reason::InvalidCharacter),
            ("SELECT £100", Reason::InvalidCharacter),
            ("$ ls -l", Reason::ClientCommand),
            ("  !whoami", Reason::ClientCommand),
            ("SELECT 'abc", Reason::UnterminatedLiteral),
            ("SELECT \"abc", Reason::UnterminatedLiteral),
        ] {
            assert_eq!(lex(text).unwrap_err().reason, reason, "{text:?}");
        }
        assert!(lex("SELECT ação, a != b FROM tabela").is_ok());
    }
}
