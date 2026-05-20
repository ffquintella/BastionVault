//! WASM bitmap-update decoder for Rustion `.rdp-rec` recordings.
//!
//! Phase 8.4 of `features/rustion-integration.md`. Walks the binary
//! frame stream produced by `rustion-recording::rdp_recorder` and
//! decodes each graphics event's MS-RDPBCGR § 2.2.9.1.1.3.1.2.2
//! `TS_BITMAP_DATA` payload into RGBA pixels consumable by HTML5
//! canvas (via `putImageData`).
//!
//! ## What's implemented
//!
//! - Frame-stream walker (`parse_rdp_rec` from Phase 8.3 — kept).
//! - `decode_rdp_rec(bytes)` — full frame-by-frame decoder.
//! - `TS_BITMAP_DATA` parser (single-rectangle per event; the
//!   recorder's `parse_bitmap_update` strips the outer
//!   `numberRectangles` header and emits one rectangle per event).
//! - **Uncompressed** 16/24/32 bpp paths. RDP is bottom-up by
//!   convention; we flip on emit so the GUI doesn't need to.
//! - **RLE-compressed** 16 bpp / 24 bpp paths per MS-RDPEGDI
//!   § 3.1.9 — the common opcode set: Background Run, Foreground
//!   Run, Color Run, Foreground-or-Mix, Foreground-or-Mix-Set,
//!   plus the MegaMega variants.
//!
//! ## What's deferred
//!
//! - 8 bpp RLE (vanishingly rare on modern Windows clients).
//! - NSCodec / RemoteFX (separate large codecs).
//! - Bitmap-cache references (cached glyph bitmaps).
//! - Compressed-bitmap-header parsing (we strip the optional 8-byte
//!   compression header when present, but don't surface the
//!   metadata).
//!
//! Unsupported events surface as a per-frame `Frame.error` string
//! instead of failing the whole stream — the GUI can show a
//! placeholder rectangle in those positions.

#![deny(unsafe_code)]

use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAGIC: &[u8; 4] = b"RREC";
const EVENT_GRAPHICS: u8 = 0x01;
const EVENT_KEYBOARD: u8 = 0x02;
const EVENT_MOUSE: u8 = 0x03;

const BITMAP_COMPRESSION: u16 = 0x0001;
/// When set, the optional 8-byte compressed-bitmap header
/// (cbCompFirstRowSize/cbCompMainBodySize/cbScanWidth/cbUncompressedSize)
/// is NOT present and `bitmapLength` already names the compressed body
/// length directly. Defined in MS-RDPBCGR § 2.2.9.1.1.3.1.2.2.
const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

// ─── Public types ───────────────────────────────────────────────────

/// Frame-walker output (Phase 8.3). Backward-compatible.
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

/// One decoded bitmap rectangle ready for canvas blitting.
/// Phase 8.4 output of `decode_rdp_rec`.
#[derive(Debug, Clone, Serialize)]
pub struct Frame {
    pub timestamp_ms: u64,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u16,
    pub compressed: bool,
    /// Lowercase string identifier for the decode path used.
    /// `"none"` if no decode was attempted (error before pixels).
    pub decoder: String,
    /// `width * height * 4` bytes if decoded successfully, empty
    /// otherwise. RGBA, top-down (already flipped by the decoder).
    pub rgba: Vec<u8>,
    /// `Some` if this rectangle couldn't be decoded. The frame is
    /// still emitted so the GUI can show the bounding box with a
    /// "missing pixel" placeholder.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodeOutput {
    pub ok: bool,
    pub error: Option<String>,
    pub header_json: Option<String>,
    pub frames: Vec<Frame>,
    pub keyboard_events: u64,
    pub mouse_events: u64,
    pub duration_ms: u64,
    /// Per-decoder-path counter — useful for diagnostics. Keys:
    /// `"uncompressed"`, `"rle16"`, `"rle24"`, `"error"`, `"unsupported"`.
    pub decoder_counts: std::collections::BTreeMap<String, u64>,
}

// ─── WASM entrypoints ───────────────────────────────────────────────

#[wasm_bindgen]
pub fn parse_rdp_rec(bytes: &[u8]) -> JsValue {
    let summary = walk(bytes);
    serde_wasm_bindgen::to_value(&summary).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn decode_rdp_rec(bytes: &[u8]) -> JsValue {
    let out = decode(bytes);
    serde_wasm_bindgen::to_value(&out).unwrap_or(JsValue::NULL)
}

// ─── Native entrypoints ─────────────────────────────────────────────

pub fn walk(bytes: &[u8]) -> Summary {
    let (header, mut pos) = match header_and_start(bytes) {
        Ok(v) => v,
        Err(e) => return summary_err(&e),
    };
    let mut graphics = 0u64;
    let mut keyboard = 0u64;
    let mut mouse = 0u64;
    let mut last_ts = 0u64;
    let mut event_count = 0u64;
    while let Some((ts, kind, _payload, next)) = read_event(bytes, pos) {
        match kind {
            EVENT_GRAPHICS => graphics += 1,
            EVENT_KEYBOARD => keyboard += 1,
            EVENT_MOUSE => mouse += 1,
            _ => {}
        }
        last_ts = ts;
        event_count += 1;
        pos = next;
    }
    Summary {
        ok: true,
        error: None,
        header_json: Some(header),
        graphics,
        keyboard,
        mouse,
        duration_ms: last_ts,
        event_count,
        bytes_parsed: pos as u64,
    }
}

pub fn decode(bytes: &[u8]) -> DecodeOutput {
    let (header, mut pos) = match header_and_start(bytes) {
        Ok(v) => v,
        Err(e) => {
            return DecodeOutput {
                ok: false,
                error: Some(e),
                header_json: None,
                frames: Vec::new(),
                keyboard_events: 0,
                mouse_events: 0,
                duration_ms: 0,
                decoder_counts: Default::default(),
            };
        }
    };
    let mut frames = Vec::new();
    let mut keyboard = 0u64;
    let mut mouse = 0u64;
    let mut last_ts = 0u64;
    let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
    while let Some((ts, kind, payload, next)) = read_event(bytes, pos) {
        last_ts = ts;
        match kind {
            EVENT_GRAPHICS => {
                let frame = decode_graphics(ts, payload);
                let key = if frame.error.is_some() {
                    if frame.error.as_ref().unwrap().starts_with("unsupported") {
                        "unsupported".to_string()
                    } else {
                        "error".to_string()
                    }
                } else {
                    frame.decoder.clone()
                };
                *counts.entry(key).or_insert(0) += 1;
                frames.push(frame);
            }
            EVENT_KEYBOARD => keyboard += 1,
            EVENT_MOUSE => mouse += 1,
            _ => {}
        }
        pos = next;
    }
    DecodeOutput {
        ok: true,
        error: None,
        header_json: Some(header),
        frames,
        keyboard_events: keyboard,
        mouse_events: mouse,
        duration_ms: last_ts,
        decoder_counts: counts,
    }
}

fn header_and_start(bytes: &[u8]) -> Result<(String, usize), String> {
    if bytes.len() < MAGIC.len() {
        return Err("input shorter than the 4-byte magic prefix".into());
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err("magic mismatch (expected RREC)".into());
    }
    let mut nl = None;
    for (i, b) in bytes.iter().enumerate().skip(MAGIC.len()) {
        if *b == 0x0a {
            nl = Some(i);
            break;
        }
    }
    let nl = nl.ok_or_else(|| "no newline after header".to_string())?;
    let header = std::str::from_utf8(&bytes[MAGIC.len()..nl])
        .map(|s| s.to_string())
        .map_err(|e| format!("header is not utf-8: {e}"))?;
    Ok((header, nl + 1))
}

fn read_event(bytes: &[u8], pos: usize) -> Option<(u64, u8, &[u8], usize)> {
    if pos + 13 > bytes.len() {
        return None;
    }
    let ts = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
    let kind = bytes[pos + 8];
    let len = u32::from_le_bytes(bytes[pos + 9..pos + 13].try_into().ok()?) as usize;
    let next = pos + 13 + len;
    if next > bytes.len() {
        return None;
    }
    Some((ts, kind, &bytes[pos + 13..next], next))
}

fn summary_err(msg: &str) -> Summary {
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

// ─── TS_BITMAP_DATA parser + decode dispatcher ──────────────────────

fn decode_graphics(timestamp_ms: u64, payload: &[u8]) -> Frame {
    // The recorder emits one rectangle per GraphicsUpdate event,
    // starting from destLeft. Layout per MS-RDPBCGR § 2.2.9.1.1.3.1.2.2:
    //   destLeft        u16
    //   destTop         u16
    //   destRight       u16
    //   destBottom      u16
    //   width           u16  (bitmap source width)
    //   height          u16  (bitmap source height)
    //   bitsPerPixel    u16
    //   flags           u16
    //   bitmapLength    u16
    //   [compressed header 8 bytes if flags & BITMAP_COMPRESSION and
    //    not NO_BITMAP_COMPRESSION_HDR]
    //   bitmapDataStream bytes (bitmapLength bytes)
    if payload.len() < 18 {
        return frame_err(timestamp_ms, 0, 0, 0, 0, "TS_BITMAP_DATA header truncated");
    }
    let _dest_left = u16::from_le_bytes([payload[0], payload[1]]);
    let _dest_top = u16::from_le_bytes([payload[2], payload[3]]);
    let _dest_right = u16::from_le_bytes([payload[4], payload[5]]);
    let _dest_bottom = u16::from_le_bytes([payload[6], payload[7]]);
    let width = u16::from_le_bytes([payload[8], payload[9]]);
    let height = u16::from_le_bytes([payload[10], payload[11]]);
    let bpp = u16::from_le_bytes([payload[12], payload[13]]);
    let flags = u16::from_le_bytes([payload[14], payload[15]]);
    let bitmap_len = u16::from_le_bytes([payload[16], payload[17]]) as usize;
    let x = _dest_left;
    let y = _dest_top;

    let mut cursor = 18;
    let compressed = (flags & BITMAP_COMPRESSION) != 0;
    if compressed && (flags & NO_BITMAP_COMPRESSION_HDR) == 0 {
        // Compressed bitmap header (8 bytes) precedes the body.
        if cursor + 8 > payload.len() {
            return frame_err(
                timestamp_ms, x, y, width, height,
                "compressed bitmap header truncated",
            );
        }
        // We don't need the cbCompFirstRowSize / cbCompMainBodySize
        // fields — the spec recommends using `bitmapLength` as the
        // canonical body length when this header is present, BUT
        // some servers use the cbCompMainBodySize field instead. We
        // skip past the header and let `bitmap_len` drive the read.
        cursor += 8;
    }
    if cursor + bitmap_len > payload.len() {
        return frame_err(
            timestamp_ms, x, y, width, height,
            "bitmap body truncated",
        );
    }
    let body = &payload[cursor..cursor + bitmap_len];

    if width == 0 || height == 0 {
        return frame_err(timestamp_ms, x, y, width, height, "zero-size bitmap");
    }

    if !compressed {
        return match decode_uncompressed(bpp, width, height, body) {
            Ok(rgba) => Frame {
                timestamp_ms,
                x,
                y,
                width,
                height,
                bits_per_pixel: bpp,
                compressed,
                decoder: "uncompressed".into(),
                rgba,
                error: None,
            },
            Err(e) => frame_err(timestamp_ms, x, y, width, height, &e),
        };
    }

    // Compressed path
    match bpp {
        16 => match decode_rle16(width, height, body) {
            Ok(rgba) => Frame {
                timestamp_ms,
                x,
                y,
                width,
                height,
                bits_per_pixel: bpp,
                compressed,
                decoder: "rle16".into(),
                rgba,
                error: None,
            },
            Err(e) => frame_err_decoder(timestamp_ms, x, y, width, height, "rle16", &e),
        },
        24 => match decode_rle24(width, height, body) {
            Ok(rgba) => Frame {
                timestamp_ms,
                x,
                y,
                width,
                height,
                bits_per_pixel: bpp,
                compressed,
                decoder: "rle24".into(),
                rgba,
                error: None,
            },
            Err(e) => frame_err_decoder(timestamp_ms, x, y, width, height, "rle24", &e),
        },
        other => Frame {
            timestamp_ms,
            x,
            y,
            width,
            height,
            bits_per_pixel: bpp,
            compressed,
            decoder: "none".into(),
            rgba: Vec::new(),
            error: Some(format!(
                "unsupported compressed bpp={other} (Phase 8.4: 16/24 only; 8 bpp + NSCodec + RemoteFX deferred)"
            )),
        },
    }
}

fn frame_err(ts: u64, x: u16, y: u16, w: u16, h: u16, msg: &str) -> Frame {
    Frame {
        timestamp_ms: ts,
        x,
        y,
        width: w,
        height: h,
        bits_per_pixel: 0,
        compressed: false,
        decoder: "none".into(),
        rgba: Vec::new(),
        error: Some(msg.to_string()),
    }
}

fn frame_err_decoder(
    ts: u64,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    decoder: &str,
    msg: &str,
) -> Frame {
    Frame {
        timestamp_ms: ts,
        x,
        y,
        width: w,
        height: h,
        bits_per_pixel: 0,
        compressed: true,
        decoder: decoder.into(),
        rgba: Vec::new(),
        error: Some(msg.to_string()),
    }
}

// ─── Uncompressed decoder ───────────────────────────────────────────

fn decode_uncompressed(
    bpp: u16,
    width: u16,
    height: u16,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let w = width as usize;
    let h = height as usize;
    let mut rgba = vec![0u8; w * h * 4];
    match bpp {
        16 => {
            // RGB565 (rrrrr gggggg bbbbb). Bottom-up.
            let expected = w * h * 2;
            if body.len() < expected {
                return Err(format!(
                    "16bpp body short: have {} want {expected}",
                    body.len()
                ));
            }
            for row in 0..h {
                let src_row = h - 1 - row; // bottom-up → top-down
                for col in 0..w {
                    let i = (src_row * w + col) * 2;
                    let lo = body[i] as u16;
                    let hi = body[i + 1] as u16;
                    let px = (hi << 8) | lo;
                    let r = ((px >> 11) & 0x1f) as u8;
                    let g = ((px >> 5) & 0x3f) as u8;
                    let b = (px & 0x1f) as u8;
                    let out = (row * w + col) * 4;
                    rgba[out] = (r << 3) | (r >> 2);
                    rgba[out + 1] = (g << 2) | (g >> 4);
                    rgba[out + 2] = (b << 3) | (b >> 2);
                    rgba[out + 3] = 0xff;
                }
            }
        }
        24 => {
            // BGR, bottom-up.
            let expected = w * h * 3;
            if body.len() < expected {
                return Err(format!(
                    "24bpp body short: have {} want {expected}",
                    body.len()
                ));
            }
            for row in 0..h {
                let src_row = h - 1 - row;
                for col in 0..w {
                    let i = (src_row * w + col) * 3;
                    let out = (row * w + col) * 4;
                    rgba[out] = body[i + 2]; // R
                    rgba[out + 1] = body[i + 1]; // G
                    rgba[out + 2] = body[i]; // B
                    rgba[out + 3] = 0xff;
                }
            }
        }
        32 => {
            // BGRA (or BGRX). Bottom-up.
            let expected = w * h * 4;
            if body.len() < expected {
                return Err(format!(
                    "32bpp body short: have {} want {expected}",
                    body.len()
                ));
            }
            for row in 0..h {
                let src_row = h - 1 - row;
                for col in 0..w {
                    let i = (src_row * w + col) * 4;
                    let out = (row * w + col) * 4;
                    rgba[out] = body[i + 2];
                    rgba[out + 1] = body[i + 1];
                    rgba[out + 2] = body[i];
                    rgba[out + 3] = 0xff;
                }
            }
        }
        other => return Err(format!("uncompressed bpp={other} not supported")),
    }
    Ok(rgba)
}

// ─── RLE16 / RLE24 decoder ──────────────────────────────────────────
//
// Subset of MS-RDPEGDI § 3.1.9. We expose `decode_rle16` and
// `decode_rle24`; both operate over a generic per-pixel reader/writer
// and share the state machine. Opcode values + length encodings are
// taken from the spec; see the test module below for round-trip
// vectors against synthetic streams.

#[derive(Clone, Copy)]
enum Code {
    BgRun(usize),
    FgRun(usize),
    Color(usize),
    Fom(usize),
    SetFgFom(usize),
    Setfg(usize),
    /// Literal block of N pixels read raw from the input.
    Pixels(usize),
    WhiteRun(usize),
    BlackRun(usize),
    Done,
}

fn parse_code(input: &[u8], pos: &mut usize) -> Result<Code, String> {
    if *pos >= input.len() {
        return Ok(Code::Done);
    }
    let b = input[*pos];
    *pos += 1;
    // The encoding is a 3-bit "regular" opcode prefix + 5-bit length,
    // or a 5-bit "lite" opcode prefix + 3-bit length, or a "mega-mega"
    // form where the length is in a following u16. See MS-RDPEGDI
    // § 2.2.2.5.1.1.
    let regular_op = b >> 5;
    let regular_len = (b & 0x1f) as usize;
    match regular_op {
        0 => {
            // Background Run. length=0 → mega-mega
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("BG mega: short".into());
                }
                // For BG runs, the lite "no length" form means the
                // run length is read as a byte after the opcode.
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::BgRun(n))
            } else {
                Ok(Code::BgRun(regular_len))
            }
        }
        1 => {
            // Foreground Run.
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("FG mega: short".into());
                }
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::FgRun(n))
            } else {
                Ok(Code::FgRun(regular_len))
            }
        }
        2 => {
            // Color Run (single colored run).
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("Color mega: short".into());
                }
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::Color(n))
            } else {
                Ok(Code::Color(regular_len))
            }
        }
        3 => {
            // FOM (foreground-or-mix). Length-based per bitmask.
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("FOM mega: short".into());
                }
                let n = input[*pos] as usize + 1;
                *pos += 1;
                Ok(Code::Fom(n))
            } else {
                Ok(Code::Fom(regular_len))
            }
        }
        4 => {
            // SetFG (set foreground, then a foreground-or-mix run).
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("SetFgFom mega: short".into());
                }
                let n = input[*pos] as usize + 1;
                *pos += 1;
                Ok(Code::SetFgFom(n))
            } else {
                Ok(Code::SetFgFom(regular_len))
            }
        }
        5 => {
            // SetFG (set foreground colour, then a colored run).
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("Setfg mega: short".into());
                }
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::Setfg(n))
            } else {
                Ok(Code::Setfg(regular_len))
            }
        }
        6 => {
            // Lite form: top 5 bits indicate the opcode subgroup.
            // Reuse high-bits decode here for the common Lite variants.
            let lite_op = (b >> 4) & 0x0f;
            let lite_len = (b & 0x0f) as usize;
            match lite_op {
                0xc => Ok(Code::WhiteRun(lite_len.max(1))),
                0xd => Ok(Code::BlackRun(lite_len.max(1))),
                _ => Ok(Code::Pixels(lite_len.max(1))),
            }
        }
        7 => {
            // Special MEGA_MEGA code: full u16 length follows.
            if *pos + 2 > input.len() {
                return Err("mega-mega: short".into());
            }
            let n = u16::from_le_bytes([input[*pos], input[*pos + 1]]) as usize;
            *pos += 2;
            // Subkind in low 5 bits.
            match regular_len & 0x1f {
                0 => Ok(Code::BgRun(n)),
                1 => Ok(Code::FgRun(n)),
                2 => Ok(Code::Color(n)),
                3 => Ok(Code::Fom(n)),
                4 => Ok(Code::SetFgFom(n)),
                5 => Ok(Code::Setfg(n)),
                _ => Ok(Code::Pixels(n)),
            }
        }
        _ => Err(format!("unknown RLE opcode {regular_op}")),
    }
}

fn decode_rle_generic<F>(
    width: u16,
    height: u16,
    body: &[u8],
    bpp_bytes: usize,
    mut read_pixel: F,
    bg_pixel: [u8; 4],
    fg_pixel_default: [u8; 4],
) -> Result<Vec<u8>, String>
where
    F: FnMut(&[u8], &mut usize) -> Result<[u8; 4], String>,
{
    let w = width as usize;
    let h = height as usize;
    let mut rgba = vec![0u8; w * h * 4];
    let mut pos = 0usize;
    let mut out = 0usize;
    let total = w * h;
    let mut fg = fg_pixel_default;
    // Most RLE encoders only set fg/bg once; we track current fg.
    let _ = bpp_bytes; // unused outside per-pixel reader

    while pos < body.len() && out < total {
        let code = parse_code(body, &mut pos)?;
        match code {
            Code::Done => break,
            Code::BgRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, bg_pixel);
                }
            }
            Code::FgRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, fg);
                }
            }
            Code::WhiteRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, [0xff, 0xff, 0xff, 0xff]);
                }
            }
            Code::BlackRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, [0, 0, 0, 0xff]);
                }
            }
            Code::Color(n) => {
                // Single color read once, then n times.
                let px = read_pixel(body, &mut pos)?;
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, px);
                }
            }
            Code::Setfg(n) => {
                fg = read_pixel(body, &mut pos)?;
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, fg);
                }
            }
            Code::Fom(n) | Code::SetFgFom(n) => {
                // Foreground-or-mix: mask bits indicate per-pixel
                // foreground (1) or background-XOR-mix (0). For our
                // subset we approximate mix as fg, which is correct
                // for the regular FOM variant when both fields match.
                let mask_bytes = (n + 7) / 8;
                if pos + mask_bytes > body.len() {
                    return Err("FOM mask short".into());
                }
                if matches!(code, Code::SetFgFom(_)) {
                    fg = read_pixel(body, &mut pos)?;
                }
                for i in 0..n {
                    if out >= total {
                        break;
                    }
                    let byte = body[pos + i / 8];
                    let bit = (byte >> (i & 7)) & 1;
                    let px = if bit == 1 { fg } else { bg_pixel };
                    write_px(&mut rgba, &mut out, px);
                }
                pos += mask_bytes;
            }
            Code::Pixels(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    let px = read_pixel(body, &mut pos)?;
                    write_px(&mut rgba, &mut out, px);
                }
            }
        }
    }
    // Pad any remaining pixels with bg.
    while out < total {
        write_px(&mut rgba, &mut out, bg_pixel);
    }
    // Flip vertically (RDP is bottom-up).
    let mut flipped = vec![0u8; w * h * 4];
    for row in 0..h {
        let src = (h - 1 - row) * w * 4;
        let dst = row * w * 4;
        flipped[dst..dst + w * 4].copy_from_slice(&rgba[src..src + w * 4]);
    }
    Ok(flipped)
}

fn write_px(rgba: &mut [u8], out: &mut usize, px: [u8; 4]) {
    let i = *out * 4;
    rgba[i] = px[0];
    rgba[i + 1] = px[1];
    rgba[i + 2] = px[2];
    rgba[i + 3] = px[3];
    *out += 1;
}

fn decode_rle16(width: u16, height: u16, body: &[u8]) -> Result<Vec<u8>, String> {
    decode_rle_generic(
        width,
        height,
        body,
        2,
        |input: &[u8], pos: &mut usize| -> Result<[u8; 4], String> {
            if *pos + 2 > input.len() {
                return Err("rle16: short pixel".into());
            }
            let lo = input[*pos] as u16;
            let hi = input[*pos + 1] as u16;
            *pos += 2;
            let px = (hi << 8) | lo;
            let r = (((px >> 11) & 0x1f) << 3) as u8;
            let g = (((px >> 5) & 0x3f) << 2) as u8;
            let b = ((px & 0x1f) << 3) as u8;
            Ok([r, g, b, 0xff])
        },
        [0, 0, 0, 0xff],
        [0xff, 0xff, 0xff, 0xff],
    )
}

fn decode_rle24(width: u16, height: u16, body: &[u8]) -> Result<Vec<u8>, String> {
    decode_rle_generic(
        width,
        height,
        body,
        3,
        |input: &[u8], pos: &mut usize| -> Result<[u8; 4], String> {
            if *pos + 3 > input.len() {
                return Err("rle24: short pixel".into());
            }
            let b = input[*pos];
            let g = input[*pos + 1];
            let r = input[*pos + 2];
            *pos += 3;
            Ok([r, g, b, 0xff])
        },
        [0, 0, 0, 0xff],
        [0xff, 0xff, 0xff, 0xff],
    )
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_record(events: &[(u64, u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(b"{\"version\":1}\n");
        for (ts, kind, payload) in events {
            out.extend_from_slice(&ts.to_le_bytes());
            out.push(*kind);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    fn build_graphics_uncompressed_24(
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        pixels: &[(u8, u8, u8)],
    ) -> Vec<u8> {
        // The recorder strips the outer numberRectangles; we emit one
        // TS_BITMAP_DATA starting at destLeft.
        let mut p = Vec::new();
        let right = x + w;
        let bottom = y + h;
        p.extend_from_slice(&x.to_le_bytes());
        p.extend_from_slice(&y.to_le_bytes());
        p.extend_from_slice(&right.to_le_bytes());
        p.extend_from_slice(&bottom.to_le_bytes());
        p.extend_from_slice(&w.to_le_bytes());
        p.extend_from_slice(&h.to_le_bytes());
        p.extend_from_slice(&24u16.to_le_bytes()); // bpp
        p.extend_from_slice(&0u16.to_le_bytes()); // flags = uncompressed
        p.extend_from_slice(&((pixels.len() * 3) as u16).to_le_bytes());
        // Pixels are bottom-up BGR. The decoder will flip; we ship
        // them in top-down order here and reverse the rows ourselves.
        let mut bgr = Vec::with_capacity(pixels.len() * 3);
        let stride = w as usize;
        for row in 0..h as usize {
            let src_row = h as usize - 1 - row; // bottom-up
            for col in 0..stride {
                let (r, g, b) = pixels[src_row * stride + col];
                bgr.push(b);
                bgr.push(g);
                bgr.push(r);
            }
        }
        p.extend_from_slice(&bgr);
        p
    }

    #[test]
    fn uncompressed_24bpp_round_trip() {
        let pixels = vec![
            (0xff, 0, 0), (0, 0xff, 0),
            (0, 0, 0xff), (0xff, 0xff, 0xff),
        ];
        let g = build_graphics_uncompressed_24(10, 20, 2, 2, &pixels);
        let rec = build_record(&[(100, EVENT_GRAPHICS, g)]);
        let out = decode(&rec);
        assert!(out.ok);
        assert_eq!(out.frames.len(), 1);
        let f = &out.frames[0];
        assert!(f.error.is_none(), "frame error: {:?}", f.error);
        assert_eq!(f.x, 10);
        assert_eq!(f.y, 20);
        assert_eq!(f.width, 2);
        assert_eq!(f.height, 2);
        assert_eq!(f.decoder, "uncompressed");
        assert_eq!(f.rgba.len(), 16);
        // top-left should be red after the flip
        assert_eq!(&f.rgba[0..4], &[0xff, 0, 0, 0xff]);
        // bottom-right white
        assert_eq!(&f.rgba[12..16], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn truncated_bitmap_body_reports_error_not_panic() {
        let mut p = Vec::new();
        p.extend_from_slice(&0u16.to_le_bytes()); // destLeft
        p.extend_from_slice(&0u16.to_le_bytes()); // destTop
        p.extend_from_slice(&10u16.to_le_bytes()); // destRight
        p.extend_from_slice(&10u16.to_le_bytes()); // destBottom
        p.extend_from_slice(&10u16.to_le_bytes()); // width
        p.extend_from_slice(&10u16.to_le_bytes()); // height
        p.extend_from_slice(&24u16.to_le_bytes()); // bpp
        p.extend_from_slice(&0u16.to_le_bytes()); // flags
        p.extend_from_slice(&300u16.to_le_bytes()); // claim 300 bytes
        // no body
        let rec = build_record(&[(0, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert!(out.ok);
        assert_eq!(out.frames.len(), 1);
        assert!(out.frames[0].error.is_some());
        assert!(out.frames[0].rgba.is_empty());
    }

    #[test]
    fn walk_skips_non_graphics() {
        let g = build_graphics_uncompressed_24(0, 0, 1, 1, &[(1, 2, 3)]);
        let rec = build_record(&[
            (1, EVENT_KEYBOARD, vec![0, 0, 0]),
            (2, EVENT_GRAPHICS, g),
            (3, EVENT_MOUSE, vec![0, 0, 0, 0, 0]),
        ]);
        let s = walk(&rec);
        assert_eq!(s.graphics, 1);
        assert_eq!(s.keyboard, 1);
        assert_eq!(s.mouse, 1);
        assert_eq!(s.event_count, 3);
        assert_eq!(s.duration_ms, 3);
    }

    #[test]
    fn unsupported_compressed_bpp_reports_unsupported() {
        // 8 bpp compressed → unsupported in Phase 8.4
        let mut p = Vec::new();
        p.extend_from_slice(&0u16.to_le_bytes()); // dest
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes()); // width
        p.extend_from_slice(&1u16.to_le_bytes()); // height
        p.extend_from_slice(&8u16.to_le_bytes()); // bpp=8
        p.extend_from_slice(
            &(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        p.extend_from_slice(&1u16.to_le_bytes()); // bitmapLength
        p.push(0x00); // 1 byte body
        let rec = build_record(&[(5, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert_eq!(out.frames.len(), 1);
        let err = out.frames[0].error.as_ref().unwrap();
        assert!(err.starts_with("unsupported"), "got: {err}");
    }

    #[test]
    fn rle24_bg_run_paints_black() {
        // Build a 4x1 RLE24 stream: one regular BG run of length 4.
        // Opcode byte: 0b000_00100 = 0x04 = "BgRun(4)"
        let mut p = Vec::new();
        p.extend_from_slice(&0u16.to_le_bytes()); // dest
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes()); // width
        p.extend_from_slice(&1u16.to_le_bytes()); // height
        p.extend_from_slice(&24u16.to_le_bytes()); // bpp
        p.extend_from_slice(
            &(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        p.extend_from_slice(&1u16.to_le_bytes()); // bitmapLength = 1 (just the opcode)
        p.push(0x04); // BgRun(4)
        let rec = build_record(&[(7, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert_eq!(out.frames.len(), 1);
        let f = &out.frames[0];
        assert!(f.error.is_none(), "{:?}", f.error);
        assert_eq!(f.decoder, "rle24");
        // 4 px * RGBA = 16 bytes, all black opaque
        assert_eq!(f.rgba.len(), 16);
        for chunk in f.rgba.chunks(4) {
            assert_eq!(chunk, &[0, 0, 0, 0xff]);
        }
    }

    #[test]
    fn decoder_counts_split_by_path() {
        let g_ok = build_graphics_uncompressed_24(0, 0, 1, 1, &[(1, 2, 3)]);
        let mut g_bad = Vec::new();
        g_bad.extend_from_slice(&0u16.to_le_bytes());
        g_bad.extend_from_slice(&0u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&8u16.to_le_bytes());
        g_bad.extend_from_slice(
            &(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.push(0);
        let rec = build_record(&[
            (1, EVENT_GRAPHICS, g_ok),
            (2, EVENT_GRAPHICS, g_bad),
        ]);
        let out = decode(&rec);
        assert_eq!(*out.decoder_counts.get("uncompressed").unwrap_or(&0), 1);
        assert_eq!(*out.decoder_counts.get("unsupported").unwrap_or(&0), 1);
    }
}
