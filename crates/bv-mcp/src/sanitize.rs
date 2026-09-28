//! Strip anything a rendered string could use to fool the model or hide
//! text from the operator: C0/C1 controls (except `\n`/`\t`), ANSI CSI/OSC
//! escape sequences, and Unicode bidi override characters. Every string
//! leaf `tools/call` returns passes through here before it reaches
//! `content`/`structuredContent`.

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

/// Unicode bidi override / embedding control characters (RLO, LRO, RLE,
/// LRE, PDF, LRI, RLI, FSI, PDI) — used to visually reorder text so a
/// hidden instruction reads differently than it renders.
fn is_bidi_override(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
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
    ansi_stripped.chars().filter(|c| !is_stripped_control(*c) && !is_bidi_override(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
