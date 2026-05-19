//! WASM frame walker for Rustion `.rdp-rec` recordings.
//!
//! Phase 8.3 of `features/rustion-integration.md`. The crate ships a
//! single entrypoint, `parse_rdp_rec(bytes) -> Summary`, that walks
//! the binary frame stream produced by `rustion-recording::rdp_recorder`
//! and returns:
//!
//!   - The JSON header (so the GUI can show the operator + target metadata).
//!   - Event counts split by kind (graphics / keyboard / mouse).
//!   - Total duration in milliseconds.
//!
//! This crate explicitly does NOT include the MS-RDPBCGR slow-path
//! bitmap-update decoder — that codec (RLE + NSCodec + bitmap-cache
//! management) is its own multi-week engineering project tracked
//! separately. What's here is enough to surface a useful Recordings-page
//! summary without re-implementing the parser in TypeScript.
//!
//! Wire format (mirrors `crates/rustion-recording/src/rdp_recorder.rs`):
//!
//! ```text
//! magic        = "RREC"                        // 4 bytes
//! header_json  = "{\"version\":1,...}"         // JSON, newline-terminated
//! event_record = ts:u64_LE
//!              + type:u8                       // 0x01 graphics / 0x02 kb / 0x03 mouse
//!              + len:u32_LE
//!              + payload[len]
//! ```

#![deny(unsafe_code)]

use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAGIC: &[u8; 4] = b"RREC";
const EVENT_GRAPHICS: u8 = 0x01;
const EVENT_KEYBOARD: u8 = 0x02;
const EVENT_MOUSE: u8 = 0x03;

/// Frame-walker output. Serialised to a plain JS object via
/// `serde-wasm-bindgen`; `header_json` is the literal JSON string
/// from the recording so the caller can `JSON.parse` it as it sees
/// fit (the parser doesn't enforce a schema on the header — the
/// recorder might add fields without bumping the wasm crate).
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub ok: bool,
    pub error: Option<String>,
    pub header_json: Option<String>,
    pub graphics: u64,
    pub keyboard: u64,
    pub mouse: u64,
    pub duration_ms: u64,
    pub event_count: u64,
    pub bytes_parsed: u64,
}

#[wasm_bindgen]
pub fn parse_rdp_rec(bytes: &[u8]) -> JsValue {
    let summary = parse(bytes);
    serde_wasm_bindgen::to_value(&summary).unwrap_or(JsValue::NULL)
}

/// Native entrypoint — exposed so the wasm crate can be exercised
/// from a regular `cargo test` without spinning up wasm-bindgen.
pub fn parse(bytes: &[u8]) -> Summary {
    if bytes.len() < MAGIC.len() {
        return err("input shorter than the 4-byte magic prefix");
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return err("magic mismatch (expected RREC)");
    }
    // Find the newline that terminates the JSON header.
    let mut nl = None;
    for (i, b) in bytes.iter().enumerate().skip(MAGIC.len()) {
        if *b == 0x0a {
            nl = Some(i);
            break;
        }
    }
    let Some(nl) = nl else {
        return err("no newline after header");
    };
    let header = std::str::from_utf8(&bytes[MAGIC.len()..nl])
        .map(|s| s.to_string())
        .map_err(|e| format!("header is not utf-8: {e}"));
    let header_json = match header {
        Ok(s) => Some(s),
        Err(e) => return err(&e),
    };

    let mut pos = nl + 1;
    let mut graphics = 0u64;
    let mut keyboard = 0u64;
    let mut mouse = 0u64;
    let mut last_ts = 0u64;
    let mut event_count = 0u64;

    while pos + 13 <= bytes.len() {
        let ts = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        let kind = bytes[pos + 8];
        let len =
            u32::from_le_bytes(bytes[pos + 9..pos + 13].try_into().unwrap()) as usize;
        let next = pos + 13 + len;
        if next > bytes.len() {
            // Truncated payload — report what we have so far rather than
            // returning an error; SOC tooling can still join on the
            // events we did read.
            break;
        }
        match kind {
            EVENT_GRAPHICS => graphics += 1,
            EVENT_KEYBOARD => keyboard += 1,
            EVENT_MOUSE => mouse += 1,
            _ => {} // unknown kind → ignore but keep walking
        }
        last_ts = ts;
        event_count += 1;
        pos = next;
    }

    Summary {
        ok: true,
        error: None,
        header_json,
        graphics,
        keyboard,
        mouse,
        duration_ms: last_ts,
        event_count,
        bytes_parsed: pos as u64,
    }
}

fn err(msg: &str) -> Summary {
    Summary {
        ok: false,
        error: Some(msg.to_string()),
        header_json: None,
        graphics: 0,
        keyboard: 0,
        mouse: 0,
        duration_ms: 0,
        event_count: 0,
        bytes_parsed: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests — pure native, no wasm-bindgen dance required.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_record(events: &[(u64, u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(b"{\"version\":1,\"target\":\"prod-rdp\"}\n");
        for (ts, kind, payload) in events {
            out.extend_from_slice(&ts.to_le_bytes());
            out.push(*kind);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn happy_path_counts_events() {
        let bytes = build_record(&[
            (100, EVENT_GRAPHICS, &[0; 64]),
            (200, EVENT_KEYBOARD, &[0; 3]),
            (300, EVENT_MOUSE, &[0; 5]),
            (400, EVENT_GRAPHICS, &[0; 16]),
        ]);
        let s = parse(&bytes);
        assert!(s.ok);
        assert_eq!(s.graphics, 2);
        assert_eq!(s.keyboard, 1);
        assert_eq!(s.mouse, 1);
        assert_eq!(s.event_count, 4);
        assert_eq!(s.duration_ms, 400);
        assert!(s.header_json.as_ref().unwrap().contains("prod-rdp"));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = build_record(&[]);
        bytes[0..4].copy_from_slice(b"XXXX");
        let s = parse(&bytes);
        assert!(!s.ok);
        assert!(s.error.unwrap().contains("magic"));
    }

    #[test]
    fn rejects_short_input() {
        let s = parse(b"RRE");
        assert!(!s.ok);
    }

    #[test]
    fn truncated_event_stops_cleanly() {
        // Header + 8 bytes of ts + 1 byte of kind + 4 bytes of len, but
        // claim 1000 bytes of payload when none follow.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(b"{}\n");
        bytes.extend_from_slice(&50u64.to_le_bytes());
        bytes.push(EVENT_GRAPHICS);
        bytes.extend_from_slice(&1000u32.to_le_bytes());
        let s = parse(&bytes);
        assert!(s.ok);
        assert_eq!(s.graphics, 0); // didn't count the truncated event
        assert_eq!(s.event_count, 0);
    }

    #[test]
    fn empty_record_just_header_is_ok() {
        let bytes = build_record(&[]);
        let s = parse(&bytes);
        assert!(s.ok);
        assert_eq!(s.event_count, 0);
        assert_eq!(s.duration_ms, 0);
    }
}
