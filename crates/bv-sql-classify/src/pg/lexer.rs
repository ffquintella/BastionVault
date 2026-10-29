//! A PostgreSQL lexer that follows the server's own rules (`scan.l`) for
//! what decides where code ends and opaque text begins: every string
//! flavour, quoted identifiers, dollar quotes, nested comments, and the
//! `standard_conforming_strings` switch. It builds no AST. It splits the
//! input into statements, and it is the reference the parser's tokenizer is
//! checked against (`differential.rs`).

// Anything the server reads in a version-dependent or surprising way is
// refused rather than guessed; see the `Reason` each path returns.

use crate::model::Reason;

/// Kind of a string literal, by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrKind {
    /// `'…'`: escapes only when `standard_conforming_strings` is off.
    Plain,
    /// `E'…'`: backslash escapes always.
    Escape,
    /// `B'…'`: bit string, no escapes at all.
    Bit,
    /// `X'…'`: hex bit string, no escapes at all.
    Hex,
    /// `N'…'`: national; lexed like a plain string.
    National,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokKind {
    /// Unquoted identifier or keyword.
    Word,
    QuotedIdent,
    Str(StrKind),
    DollarStr,
    LineComment,
    BlockComment,
    Number,
    /// `$1`.
    Param,
    /// Any other single character outside a literal.
    Punct(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tok {
    pub kind: TokKind,
    pub start: usize,
    pub end: usize,
    /// A string literal continued across a newline into another quoted part.
    pub continued: bool,
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

/// PostgreSQL `ident_start`: ASCII letters, `_`, and any non-ASCII character
/// (the server takes every byte >= 0x80). Non-ASCII characters that are not
/// alphanumeric are refused separately: the parser may read them as spaces.
fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || !c.is_ascii()
}

/// PostgreSQL `ident_cont`: `ident_start`, digits and `$`.
fn ident_cont(c: char) -> bool {
    ident_start(c) || c.is_ascii_digit() || c == '$'
}

/// `dolq_start` / `dolq_cont`: like identifiers, but never `$`.
fn dolq_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || !c.is_ascii()
}

fn dolq_cont(c: char) -> bool {
    dolq_start(c) || c.is_ascii_digit()
}

/// Whitespace outside literals. `\v` is left out on purpose: PostgreSQL 16
/// added it to `space`, older servers reject it, so it is refused.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    scs: bool,
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

    /// Scan a quoted string body starting just after the opening quote.
    /// Returns the offset just past the closing quote.
    fn scan_quoted(&self, mut j: usize, backslash_escapes: bool, doubled_quote: bool) -> Result<usize, LexError> {
        let start = j;
        loop {
            match self.byte(j) {
                None => return err(Reason::UnterminatedLiteral, start),
                Some(b'\'') => {
                    if doubled_quote && self.byte(j + 1) == Some(b'\'') {
                        j += 2;
                    } else {
                        return Ok(j + 1);
                    }
                }
                Some(b'\\') if backslash_escapes => {
                    // `\` takes the next character, whatever it is (octal and
                    // hex escapes never contain a quote).
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

    /// `quotecontinue`: whitespace containing a newline (and `--` comments
    /// ending in one), then a quote. Returns the offset of that quote.
    fn quote_continuation(&self, after: usize) -> Option<usize> {
        let mut j = after;
        let mut seen_newline = false;
        loop {
            match self.byte(j) {
                Some(b'\n') | Some(b'\r') => {
                    seen_newline = true;
                    j += 1;
                }
                Some(b' ') | Some(b'\t') | Some(0x0c) => j += 1,
                Some(b'-') if self.byte(j + 1) == Some(b'-') => {
                    j += 2;
                    while let Some(b) = self.byte(j) {
                        if b == b'\n' || b == b'\r' {
                            break;
                        }
                        j += 1;
                    }
                    self.byte(j)?;
                }
                Some(b'\'') if seen_newline => return Some(j),
                _ => return None,
            }
        }
    }

    /// A string literal whose opening quote is at `quote`; `start` is where
    /// the token starts (the prefix, if any).
    fn string(&self, start: usize, quote: usize, kind: StrKind) -> Result<Tok, LexError> {
        let (backslash, doubled) = match kind {
            StrKind::Plain | StrKind::National => (!self.scs, true),
            StrKind::Escape => (true, true),
            // xb / xh: `[^']*`, and a quote always ends the part.
            StrKind::Bit | StrKind::Hex => (false, false),
        };
        let mut end = self.scan_quoted(quote + 1, backslash, doubled)?;
        let mut continued = false;
        while let Some(next_quote) = self.quote_continuation(end) {
            continued = true;
            end = self.scan_quoted(next_quote + 1, backslash, doubled)?;
        }
        Ok(Tok { kind: TokKind::Str(kind), start, end, continued })
    }

    fn quoted_ident(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start + 1;
        loop {
            match self.byte(j) {
                None => return err(Reason::UnterminatedLiteral, start),
                Some(b'"') if self.byte(j + 1) == Some(b'"') => j += 2,
                Some(b'"') => return Ok(tok(TokKind::QuotedIdent, start, j + 1)),
                Some(_) => j += self.char_len(j),
            }
        }
    }

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

    fn line_comment(&self, start: usize) -> Tok {
        let mut j = start + 2;
        while let Some(b) = self.byte(j) {
            if b == b'\n' || b == b'\r' {
                break;
            }
            j += self.char_len(j);
        }
        tok(TokKind::LineComment, start, j)
    }

    /// `$` at a token start: a parameter, a dollar quote, or a lone `$`.
    fn dollar(&self, start: usize) -> Result<Tok, LexError> {
        if self.byte(start + 1).is_some_and(|b| b.is_ascii_digit()) {
            let mut j = start + 1;
            while self.byte(j).is_some_and(|b| b.is_ascii_digit()) {
                j += 1;
            }
            // `param_junk`, and `$1$`, which the parser's tokenizer would read
            // as the start of a dollar quote.
            if self.peek_char(j).is_some_and(ident_cont) {
                return err(Reason::InvalidCharacter, j);
            }
            return Ok(tok(TokKind::Param, start, j));
        }
        // `dolqdelim`: `$` [tag] `$`.
        let mut j = start + 1;
        if let Some(c) = self.peek_char(j) {
            if dolq_start(c) {
                j += c.len_utf8();
                while let Some(c) = self.peek_char(j) {
                    if !dolq_cont(c) {
                        break;
                    }
                    j += c.len_utf8();
                }
            }
        }
        if self.byte(j) != Some(b'$') {
            // `dolqfailed`: the server returns the lone `$` and fails to parse.
            return Ok(tok(TokKind::Punct(b'$'), start, start + 1));
        }
        let delim = &self.text[start..=j];
        let body = j + 1;
        match self.text[body..].find(delim) {
            Some(rel) => Ok(tok(TokKind::DollarStr, start, body + rel + delim.len())),
            None => err(Reason::UnterminatedLiteral, start),
        }
    }

    fn number(&self, start: usize) -> Result<Tok, LexError> {
        let b = self.bytes;
        let mut j = start;
        let radix_digit: Option<fn(u8) -> bool> = if b.get(j) == Some(&b'0') {
            match b.get(j + 1) {
                Some(b'x') | Some(b'X') => Some(|c: u8| c.is_ascii_hexdigit()),
                Some(b'o') | Some(b'O') => Some(|c: u8| (b'0'..=b'7').contains(&c)),
                Some(b'b') | Some(b'B') => Some(|c: u8| c == b'0' || c == b'1'),
                _ => None,
            }
        } else {
            None
        };
        if let Some(digit) = radix_digit {
            j += 2;
            let digits_start = j;
            while b.get(j).is_some_and(|&c| digit(c) || c == b'_') {
                j += 1;
            }
            if j == digits_start {
                return err(Reason::InvalidCharacter, j);
            }
        } else {
            while b.get(j).is_some_and(|&c| c.is_ascii_digit() || c == b'_') {
                j += 1;
            }
            // A fraction, but not `..`.
            if b.get(j) == Some(&b'.') && b.get(j + 1) != Some(&b'.') {
                j += 1;
                while b.get(j).is_some_and(|&c| c.is_ascii_digit() || c == b'_') {
                    j += 1;
                }
            }
            if matches!(b.get(j), Some(b'e') | Some(b'E')) {
                let mut k = j + 1;
                if matches!(b.get(k), Some(b'+') | Some(b'-')) {
                    k += 1;
                }
                if b.get(k).is_some_and(|c| c.is_ascii_digit()) {
                    j = k;
                    while b.get(j).is_some_and(|c| c.is_ascii_digit()) {
                        j += 1;
                    }
                }
            }
        }
        // `integer_junk` / `numeric_junk` / `realfail`: refused on every
        // server version rather than read one version's way.
        if self.peek_char(j).is_some_and(ident_start) {
            return err(Reason::InvalidCharacter, j);
        }
        Ok(tok(TokKind::Number, start, j))
    }

    fn word(&self, start: usize) -> Result<Tok, LexError> {
        let mut j = start;
        while let Some(c) = self.peek_char(j) {
            if !ident_cont(c) {
                break;
            }
            if !c.is_ascii() && !c.is_alphanumeric() {
                return err(Reason::InvalidCharacter, j);
            }
            j += c.len_utf8();
        }
        Ok(tok(TokKind::Word, start, j))
    }

    fn next(&mut self) -> Result<Option<Tok>, LexError> {
        let b = self.bytes;
        while let Some(&c) = b.get(self.pos) {
            if !is_space(c) {
                break;
            }
            self.pos += 1;
        }
        let i = self.pos;
        let Some(&c) = b.get(i) else { return Ok(None) };
        let next = b.get(i + 1).copied();
        let t = match c {
            0 => return err(Reason::ControlCharacter, i),
            b'-' if next == Some(b'-') => self.line_comment(i),
            b'/' if next == Some(b'*') => self.block_comment(i)?,
            b'\'' => self.string(i, i, StrKind::Plain)?,
            b'"' => self.quoted_ident(i)?,
            b'$' => self.dollar(i)?,
            b'e' | b'E' if next == Some(b'\'') => self.string(i, i + 1, StrKind::Escape)?,
            b'b' | b'B' if next == Some(b'\'') => self.string(i, i + 1, StrKind::Bit)?,
            b'x' | b'X' if next == Some(b'\'') => self.string(i, i + 1, StrKind::Hex)?,
            b'n' | b'N' if next == Some(b'\'') => self.string(i, i + 1, StrKind::National)?,
            b'u' | b'U' if next == Some(b'&') && matches!(b.get(i + 2), Some(b'\'') | Some(b'"')) => {
                return err(Reason::UnicodeEscape, i);
            }
            b'0'..=b'9' => self.number(i)?,
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => self.number(i)?,
            b'\\' => return err(Reason::InvalidCharacter, i),
            c if c < 0x20 || c == 0x7f => return err(Reason::ControlCharacter, i),
            c if c.is_ascii() && ident_start(c as char) => self.word(i)?,
            c if c.is_ascii() => tok(TokKind::Punct(c), i, i + 1),
            _ => {
                let ch = self.peek_char(i).unwrap_or('\u{fffd}');
                if ch.is_alphanumeric() {
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
    Tok { kind, start, end, continued: false }
}

/// Lex the whole input. Fails on the first error, with its offset.
pub(crate) fn lex(text: &str, standard_conforming_strings: bool) -> Result<Vec<Tok>, LexError> {
    if let Some(at) = text.bytes().position(|b| b == 0) {
        // The wire protocol ends a query string at the first NUL.
        return err(Reason::ControlCharacter, at);
    }
    let mut lx = Lexer { text, bytes: text.as_bytes(), scs: standard_conforming_strings, pos: 0 };
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
    /// Deepest `(` / `[` nesting seen.
    pub max_depth: usize,
}

/// The lower-cased text of an unquoted word, for keyword checks.
pub(crate) fn word_lower(text: &str, t: &Tok) -> Option<String> {
    (t.kind == TokKind::Word).then(|| text[t.start..t.end].to_ascii_lowercase())
}

/// psql's rule for `CREATE [OR REPLACE] {FUNCTION|PROCEDURE} … BEGIN ATOMIC
/// … END`: there, `;` between `BEGIN` and its `END` does not end the
/// statement. A wrong guess is harmless either way: a split body fails to
/// parse, and a joined span holds two statements, which the parser check and
/// the server's extended protocol both refuse.
#[derive(Default)]
struct BeginTracker {
    words: Vec<char>,
    word_count: usize,
    depth: usize,
}

impl BeginTracker {
    fn word(&mut self, w: &str, paren_depth: usize) {
        if self.word_count < 4 {
            let tracked = matches!(w, "create" | "function" | "procedure" | "or" | "replace");
            self.words.push(if tracked { w.chars().next().unwrap_or(' ') } else { ' ' });
        }
        self.word_count += 1;
        let at = |i: usize| self.words.get(i).copied().unwrap_or(' ');
        let routine = at(0) == 'c'
            && (at(1) == 'f' || at(1) == 'p' || (at(1) == 'o' && at(2) == 'r' && (at(3) == 'f' || at(3) == 'p')));
        if routine && paren_depth == 0 {
            match w {
                "begin" => self.depth += 1,
                "case" if self.depth >= 1 => self.depth += 1,
                "end" if self.depth > 0 => self.depth -= 1,
                _ => {}
            }
        }
    }
}

/// Split lexed tokens into statements at top-level `;`. Statements with no
/// code (only comments) are dropped.
pub(crate) fn split(text: &str, tokens: &[Tok]) -> Vec<RawStatement> {
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
    let mut tracker = BeginTracker::default();
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    for t in tokens {
        match t.kind {
            TokKind::Punct(b';') if tracker.depth == 0 => {
                flush(&mut current, max_depth, &mut out);
                tracker = BeginTracker::default();
                depth = 0;
                max_depth = 0;
                continue;
            }
            TokKind::Punct(b'(') | TokKind::Punct(b'[') => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            TokKind::Punct(b')') | TokKind::Punct(b']') => depth = depth.saturating_sub(1),
            TokKind::Word => {
                if let Some(w) = word_lower(text, t) {
                    tracker.word(&w, depth);
                }
            }
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

    fn kinds(text: &str, scs: bool) -> Vec<TokKind> {
        lex(text, scs).unwrap().into_iter().map(|t| t.kind).collect()
    }

    fn spans(text: &str) -> Vec<&str> {
        let toks = lex(text, true).unwrap();
        split(text, &toks).into_iter().map(|s| &text[s.span]).collect()
    }

    #[test]
    fn semicolons_inside_literals_and_comments_do_not_split() {
        let text = "SELECT 'a;b', \"c;d\", $$e;f$$, $t$g;$$;h$t$ /* i; /* j; */ k; */ -- l;\n; SELECT 2";
        assert_eq!(spans(text).len(), 2);
        assert_eq!(spans("SELECT 1;; ;SELECT 2;"), vec!["SELECT 1", "SELECT 2"]);
        assert!(spans("-- only a comment\n/* and another */;").is_empty());
    }

    #[test]
    fn standard_conforming_strings_changes_where_a_string_ends() {
        let text = r"SELECT 'a\'; DELETE FROM t; --'";
        // On: the backslash is a plain character, the string ends after it.
        assert_eq!(spans(text).len(), 2);
        // Off: `\'` is an escaped quote, so the whole rest is one string.
        let toks = lex(text, false).unwrap();
        assert_eq!(split(text, &toks).len(), 1);
    }

    #[test]
    fn line_comments_end_at_carriage_return() {
        let toks = lex("SELECT 1 -- c\rDELETE FROM t", true).unwrap();
        assert!(toks.iter().any(|t| t.kind == TokKind::Word && t.start == 14));
    }

    #[test]
    fn prefixes_and_escapes() {
        assert_eq!(kinds(r"E'\''", true), vec![TokKind::Str(StrKind::Escape)]);
        assert_eq!(kinds("B'01'", true), vec![TokKind::Str(StrKind::Bit)]);
        // In a bit string `''` is two literals, not an escaped quote.
        assert_eq!(kinds("B'01''10'", true), vec![TokKind::Str(StrKind::Bit), TokKind::Str(StrKind::Plain)]);
        assert_eq!(kinds("x'1F' n'a'", true), vec![TokKind::Str(StrKind::Hex), TokKind::Str(StrKind::National)]);
        assert_eq!(kinds("a$b$ $1", true), vec![TokKind::Word, TokKind::Param]);
        assert_eq!(kinds("0x1F 1e5 .5 1_000", true), vec![TokKind::Number; 4]);
    }

    #[test]
    fn continuation_is_one_token_and_flagged() {
        let toks = lex("SELECT 'a'\n  -- c\n 'b'", true).unwrap();
        let s: Vec<_> = toks.iter().filter(|t| matches!(t.kind, TokKind::Str(_))).collect();
        assert_eq!(s.len(), 1);
        assert!(s[0].continued);
        // Without a newline it is two literals and no continuation.
        let toks = lex("SELECT 'a' 'b'", true).unwrap();
        assert!(toks.iter().all(|t| !t.continued));
    }

    #[test]
    fn refusals() {
        for (text, reason) in [
            ("SELECT 1\0", Reason::ControlCharacter),
            ("SELECT \u{0b}1", Reason::ControlCharacter),
            ("SELECT 1 \\ 2", Reason::InvalidCharacter),
            ("SELECT 1abc", Reason::InvalidCharacter),
            ("SELECT $1abc", Reason::InvalidCharacter),
            ("SELECT\u{2003}1", Reason::InvalidCharacter),
            ("SELECT 'abc", Reason::UnterminatedLiteral),
            ("SELECT $x$abc$y$", Reason::UnterminatedLiteral),
            ("SELECT /* /* */", Reason::UnterminatedLiteral),
            ("SELECT U&'d\\0061t'", Reason::UnicodeEscape),
            ("SELECT u&\"x\"", Reason::UnicodeEscape),
        ] {
            assert_eq!(lex(text, true).unwrap_err().reason, reason, "{text:?}");
        }
        // Non-ASCII letters are identifiers.
        assert!(lex("SELECT ação FROM tabela", true).is_ok());
    }

    #[test]
    fn begin_atomic_bodies_stay_in_one_statement() {
        let text = "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT 2; END; SELECT 3";
        assert_eq!(spans(text).len(), 2);
        // Outside a routine definition, BEGIN is a transaction start.
        assert_eq!(spans("BEGIN; SELECT 1; END").len(), 3);
    }
}
