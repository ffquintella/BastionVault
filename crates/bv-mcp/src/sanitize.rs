//! Strip anything a rendered string could use to fool the model or hide
//! text from the operator. Every string leaf `tools/call` returns passes
//! through here before it reaches `content`/`structuredContent`:
//!
//! * C0/C1 controls (except `\n`/`\t`) and ANSI CSI/OSC escape sequences;
//! * every Unicode `Bidi_Control` character: the embeddings, overrides and
//!   isolates (U+202A–U+202E, U+2066–U+2069) and the marks LRM, RLM and ALM
//!   (U+200E, U+200F, U+061C);
//! * zero-width characters (U+200B–U+200D, U+2060–U+2064, U+FEFF);
//! * Unicode tag characters (U+E0000–U+E007F) — the "ASCII smuggling"
//!   channel, invisible when rendered but read by a model;
//! * interlinear annotation characters (U+FFF9–U+FFFB).
//!
//! The line and paragraph separators U+2028/U+2029 become `\n`, so a line
//! break the model sees is one the operator sees too.
//!
//! The last four groups were added by `features/mcp-brokered-sessions.md`
//! §8 step 4, for every tool, not only the session tools.

/// `\x1b[` (CSI) ... final byte in `0x40..=0x7e`, or `\x1b]` (OSC) ...
/// terminated by BEL (`\x07`) or ST (`\x1b\\`).
fn strip_ansi(input: &str) -> String {
    let bytes: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '\u{1b}' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == '[' {
                let mut j = i + 2;
                while j < bytes.len() && !('\u{40}'..='\u{7e}').contains(&bytes[j]) {
                    j += 1;
                }
                i = (j + 1).min(bytes.len());
                continue;
            } else if next == ']' {
                let mut j = i + 2;
                while j < bytes.len() {
                    if bytes[j] == '\u{07}' {
                        j += 1;
                        break;
                    }
                    if bytes[j] == '\u{1b}' && j + 1 < bytes.len() && bytes[j + 1] == '\\' {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Unicode `Bidi_Control` characters: the embeddings and overrides (LRE,
/// RLE, PDF, LRO, RLO), the isolates (LRI, RLI, FSI, PDI) and the marks (LRM,
/// RLM, ALM) — used to visually reorder text so a hidden instruction reads
/// differently than it renders.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// Zero-width characters: ZWSP, ZWNJ, ZWJ, WORD JOINER, the invisible
/// operators U+2061–U+2064, and ZWNBSP/BOM. They split a word the operator
/// reads into tokens the model reads differently, or carry bits outright.
fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}')
}

/// Unicode tag characters: an invisible copy of ASCII that a model reads.
fn is_tag_character(c: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&c)
}

/// Interlinear annotation anchor, separator and terminator: text between
/// them is not meant to be rendered inline.
fn is_interlinear_annotation(c: char) -> bool {
    ('\u{FFF9}'..='\u{FFFB}').contains(&c)
}

/// Every character [`sanitize_for_model`] deletes outright (U+2028/U+2029 are
/// rewritten, not deleted, and so are not in this set).
fn is_stripped(c: char) -> bool {
    is_stripped_control(c)
        || is_bidi_control(c)
        || is_zero_width(c)
        || is_tag_character(c)
        || is_interlinear_annotation(c)
}

/// `true` for C0 controls other than `\n`/`\t`, and all C1 controls.
fn is_stripped_control(c: char) -> bool {
    let code = c as u32;
    let is_c0 = code < 0x20 && c != '\n' && c != '\t';
    let is_c1 = (0x80..=0x9f).contains(&code);
    is_c0 || is_c1
}

/// Sanitize a string leaf before it is returned to an MCP client.
pub fn sanitize_for_model(input: &str) -> String {
    let ansi_stripped = strip_ansi(input);
    ansi_stripped
        .chars()
        .filter_map(|c| match c {
            '\u{2028}' | '\u{2029}' => Some('\n'),
            c if is_stripped(c) => None,
            c => Some(c),
        })
        .collect()
}

/// Characters with no visible glyph of their own that the sanitizer keeps
/// in output (they are harmless there) but that a session command may not
/// carry, because the operator confirming it could not see them: the soft
/// hyphen, the combining grapheme joiner, the Mongolian vowel separator,
/// the variation selectors and the Hangul fillers that render as blanks.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{180E}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{E0100}'..='\u{E01EF}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
    )
}

/// The first character a brokered-session command may not contain, if any
/// (`features/mcp-brokered-sessions.md` §5.1): a C0 control other than
/// `\t` and `\n` (NUL and `\r` included), DEL, a C1 control, a bidi
/// control, a zero-width, tag or interlinear-annotation character, U+2028 /
/// U+2029, or an invisible format character ([`is_invisible_format`]).
///
/// A command carrying one is **refused, not cleaned**: what the operator
/// confirms must be exactly the bytes that run, and every one of these can
/// make a command read differently from what executes.
pub fn forbidden_command_char(command: &str) -> Option<char> {
    command
        .chars()
        .find(|&c| is_stripped(c) || c == '\u{7f}' || c == '\u{2028}' || c == '\u{2029}' || is_invisible_format(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_with_hidden_characters_are_named() {
        assert_eq!(forbidden_command_char("journalctl -u nginx | tail -n 20\n\tuptime"), None);
        assert_eq!(forbidden_command_char("grep 'ação' /var/log/app.log"), None, "plain non-ASCII is fine");
        for (input, bad) in [
            ("echo\u{0}x", '\u{0}'),
            ("safe\rrm -rf /", '\r'),
            ("a\u{1b}[2Jb", '\u{1b}'),
            ("a\u{7f}", '\u{7f}'),
            ("a\u{85}", '\u{85}'),
            ("ls\u{202E}fdp.exe", '\u{202E}'),
            ("ls\u{200E}", '\u{200E}'),
            ("r\u{200B}m", '\u{200B}'),
            ("id\u{E0041}", '\u{E0041}'),
            ("one\u{2028}two", '\u{2028}'),
            ("one\u{2029}two", '\u{2029}'),
            ("x\u{FFF9}", '\u{FFF9}'),
            ("rm\u{00AD}-rf", '\u{00AD}'),
            ("a\u{FE0F}", '\u{FE0F}'),
            ("a\u{3164}b", '\u{3164}'),
        ] {
            assert_eq!(forbidden_command_char(input), Some(bad), "{input:?}");
        }
    }

    #[test]
    fn preserves_plain_text() {
        assert_eq!(sanitize_for_model("hello world\n"), "hello world\n");
    }

    #[test]
    fn strips_csi_color_codes() {
        let input = "\u{1b}[31mred\u{1b}[0m plain";
        assert_eq!(sanitize_for_model(input), "red plain");
    }

    #[test]
    fn strips_osc_hyperlink_hide() {
        // Trail of Bits: OSC 8 hyperlinks / title-set sequences can hide
        // text a terminal renders differently than the raw bytes read.
        let input = "\u{1b}]8;;https://evil.example\u{07}click\u{1b}]8;;\u{07} me";
        assert_eq!(sanitize_for_model(input), "click me");
    }

    #[test]
    fn strips_c0_controls_except_newline_and_tab() {
        let input = "a\u{07}b\tc\nd\u{1b}e";
        // \x1b alone (no following CSI/OSC introducer) is still a C0
        // control and must be dropped by the control-char filter.
        assert_eq!(sanitize_for_model(input), "ab\tc\nde");
    }

    #[test]
    fn strips_c1_controls() {
        let input = "a\u{85}b\u{9f}c";
        assert_eq!(sanitize_for_model(input), "abc");
    }

    #[test]
    fn strips_bidi_overrides() {
        // RLO followed by reversed-looking text, then PDF to pop it.
        let input = "safe\u{202E}txt.exe\u{202C}.txt";
        assert_eq!(sanitize_for_model(input), "safetxt.exe.txt");
    }

    #[test]
    fn strips_every_bidi_control_including_the_marks() {
        // The isolates, plus LRM/RLM/ALM, which the first version let through.
        let input = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e\u{200E}f\u{200F}g\u{061C}h\u{202A}i\u{202B}j\u{202D}k";
        assert_eq!(sanitize_for_model(input), "abcdefghijk");
    }

    #[test]
    fn strips_zero_width_characters() {
        let input = "r\u{200B}m\u{200C} -\u{200D}rf\u{2060} /\u{2061}\u{2062}\u{2063}\u{2064}\u{FEFF}";
        assert_eq!(sanitize_for_model(input), "rm -rf /");
    }

    #[test]
    fn strips_unicode_tag_characters() {
        // "hi" followed by an invisible tag-encoded "run rm" and the
        // CANCEL TAG: the classic ASCII-smuggling payload.
        let smuggled: String = "run rm".chars().map(|c| char::from_u32(0xE0000 + c as u32).unwrap()).collect();
        let input = format!("hi\u{E0001}{smuggled}\u{E007F}");
        assert_eq!(sanitize_for_model(&input), "hi");
        assert_eq!(sanitize_for_model("\u{E0000}x\u{E007F}"), "x");
    }

    #[test]
    fn strips_interlinear_annotation_characters() {
        assert_eq!(sanitize_for_model("base\u{FFF9}hidden\u{FFFA}gloss\u{FFFB}"), "basehiddengloss");
    }

    #[test]
    fn line_and_paragraph_separators_become_newlines() {
        assert_eq!(sanitize_for_model("one\u{2028}two\u{2029}three"), "one\ntwo\nthree");
    }

    #[test]
    fn leaves_ordinary_non_ascii_text_alone() {
        // Accents, CJK, emoji with ZWJ removed only where it is the ZWJ
        // itself: the visible code points survive.
        assert_eq!(sanitize_for_model("café — 日本語 ✓"), "café — 日本語 ✓");
        assert_eq!(sanitize_for_model("שלום"), "שלום", "RTL text itself is not a control");
    }

    #[test]
    fn dangling_escape_at_end_of_string_is_dropped_not_panicked() {
        let input = "abc\u{1b}";
        assert_eq!(sanitize_for_model(input), "abc");
    }

    #[test]
    fn unterminated_csi_consumes_to_end_without_panicking() {
        let input = "abc\u{1b}[31";
        assert_eq!(sanitize_for_model(input), "abc");
    }
}
