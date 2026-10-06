//! `CF_DIB` / `CF_DIBV5` ⇄ RGBA, for RDP clipboard images (T35 Phase 2).
//!
//! The decoder is the one place a *remote* image is parsed, so it is strict
//! by construction: a closed set of header sizes, bit depths, compressions
//! and channel masks, every length and offset checked with overflow-safe
//! arithmetic before a byte is read, and an explicit [`DibError`] for every
//! refusal. Anything outside the set is refused rather than "best-effort"
//! decoded — the operator gets a counted, audited refusal instead of a
//! codec running on attacker-shaped input. Palette (1/4/8 bpp), 16 bpp, RLE,
//! embedded JPEG/PNG and colour tables are all refused: a modern Windows
//! clipboard synthesises a 24- or 32-bit `CF_DIB` for every bitmap anyway.
//!
//! Only the output — validated straight-alpha RGBA — is handed to `arboard`,
//! which *encodes* it for the host pasteboard. No image codec ever sees bytes
//! from the session.
//!
//! The encoder writes the two shapes every Windows application reads: a
//! 32-bit `BI_RGB` `BITMAPINFOHEADER` (`CF_DIB`) and a 32-bit `BI_BITFIELDS`
//! `BITMAPV5HEADER` with an alpha mask and `LCS_sRGB` (`CF_DIBV5`), both
//! bottom-up.

use zeroize::Zeroizing;

/// Largest DIB accepted on the wire, either direction. A 3840x2160 32-bit
/// screenshot is 33,177,600 bytes of pixels, so 4K fits; anything larger is
/// dropped and counted, never truncated.
pub const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
/// Largest decoded RGBA buffer the host side will hold for one image. Wider
/// than [`MAX_IMAGE_BYTES`] because a 24-bit DIB expands by a third.
pub const MAX_DECODED_BYTES: usize = 48 * 1024 * 1024;
/// Largest width or height accepted, matching GDI's own practical ceiling.
pub const MAX_IMAGE_DIMENSION: u32 = 16_384;

const BITMAPINFOHEADER: usize = 40;
const BITMAPV4HEADER: usize = 108;
const BITMAPV5HEADER: usize = 124;

const BI_RGB: u32 = 0;
const BI_BITFIELDS: u32 = 3;

const RED_MASK: u32 = 0x00FF_0000;
const GREEN_MASK: u32 = 0x0000_FF00;
const BLUE_MASK: u32 = 0x0000_00FF;
const ALPHA_MASK: u32 = 0xFF00_0000;

const LCS_CALIBRATED_RGB: u32 = 0;
const LCS_SRGB: u32 = 0x7352_4742; // 'sRGB'
const LCS_WINDOWS_COLOR_SPACE: u32 = 0x5769_6E20; // 'Win '
const PROFILE_LINKED: u32 = 0x4C49_4E4B; // 'LINK'
const PROFILE_EMBEDDED: u32 = 0x4D42_4544; // 'MBED'

/// A decoded image: `width * height` pixels, rows top-down, four bytes per
/// pixel (R, G, B, A), straight alpha. Zeroized on drop — clipboard content
/// is operator data and this is the copy we own.
#[derive(Debug)]
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Zeroizing<Vec<u8>>,
}

/// Why a DIB was refused. Carries numbers only, never pixel data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DibError {
    /// Shorter than its header, its masks, its colour profile or its pixels.
    Truncated,
    /// `biSize` is not 40, 108 or 124.
    UnsupportedHeader(u32),
    BadPlanes(u16),
    UnsupportedBitCount(u16),
    UnsupportedCompression(u32),
    /// `BI_BITFIELDS` with anything but the standard 8-bit channel masks.
    UnsupportedMasks,
    /// A colour table on a true-colour image.
    ColorTable,
    UnsupportedColorSpace(u32),
    /// Zero or negative width, zero height, `i32::MIN`, or over the ceiling.
    BadDimensions,
    /// Over [`MAX_IMAGE_BYTES`] on the wire or [`MAX_DECODED_BYTES`] decoded.
    TooLarge,
    /// An RGBA buffer whose length does not match its dimensions.
    BadPixelBuffer,
}

impl DibError {
    /// Whether this refusal is a size cap (audited as `oversize`) rather
    /// than a malformed payload (`malformed`).
    pub fn is_oversize(self) -> bool {
        matches!(self, Self::TooLarge)
    }
}

impl std::fmt::Display for DibError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated DIB"),
            Self::UnsupportedHeader(n) => write!(f, "unsupported DIB header size {n}"),
            Self::BadPlanes(n) => write!(f, "DIB planes must be 1, got {n}"),
            Self::UnsupportedBitCount(n) => write!(f, "unsupported DIB bit depth {n} (24 and 32 only)"),
            Self::UnsupportedCompression(n) => {
                write!(f, "unsupported DIB compression {n} (BI_RGB and BI_BITFIELDS only)")
            }
            Self::UnsupportedMasks => write!(f, "unsupported DIB channel masks"),
            Self::ColorTable => write!(f, "colour table on a true-colour DIB"),
            Self::UnsupportedColorSpace(n) => write!(f, "unsupported DIB colour space {n:#010x}"),
            Self::BadDimensions => write!(f, "DIB dimensions out of range"),
            Self::TooLarge => write!(f, "DIB over the size cap"),
            Self::BadPixelBuffer => write!(f, "pixel buffer does not match the image dimensions"),
        }
    }
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, DibError> {
    let s = b.get(at..at + 2).ok_or(DibError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, DibError> {
    let s = b.get(at..at + 4).ok_or(DibError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn i32_at(b: &[u8], at: usize) -> Result<i32, DibError> {
    Ok(u32_at(b, at)? as i32)
}

/// Row stride in bytes: rows are padded to a 4-byte boundary.
fn stride(width: u32, bit_count: u16) -> Option<usize> {
    let bits = u64::from(width).checked_mul(u64::from(bit_count))?;
    let bytes = bits.checked_add(31)? / 32 * 4;
    usize::try_from(bytes).ok()
}

/// Decode a `CF_DIB` or `CF_DIBV5` payload (a `BITMAPINFO` header followed
/// by pixels — no `BITMAPFILEHEADER`).
pub fn decode(payload: &[u8]) -> Result<RgbaImage, DibError> {
    if payload.len() > MAX_IMAGE_BYTES {
        return Err(DibError::TooLarge);
    }
    let header_size = u32_at(payload, 0)?;
    let header = match header_size as usize {
        BITMAPINFOHEADER | BITMAPV4HEADER | BITMAPV5HEADER => header_size as usize,
        _ => return Err(DibError::UnsupportedHeader(header_size)),
    };
    if payload.len() < header {
        return Err(DibError::Truncated);
    }

    let width = i32_at(payload, 4)?;
    let height = i32_at(payload, 8)?;
    let planes = u16_at(payload, 12)?;
    let bit_count = u16_at(payload, 14)?;
    let compression = u32_at(payload, 16)?;
    let colors_used = u32_at(payload, 32)?;

    if planes != 1 {
        return Err(DibError::BadPlanes(planes));
    }
    if width <= 0 || height == 0 || height == i32::MIN {
        return Err(DibError::BadDimensions);
    }
    let top_down = height < 0;
    let width = width as u32;
    let height = height.unsigned_abs();
    if width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
        return Err(DibError::BadDimensions);
    }
    if bit_count != 24 && bit_count != 32 {
        return Err(DibError::UnsupportedBitCount(bit_count));
    }
    if colors_used != 0 {
        return Err(DibError::ColorTable);
    }

    // Channel masks: inline for V4/V5, three DWORDs after a 40-byte header.
    let mut pixel_offset = header;
    let alpha_in_pixels = match compression {
        BI_RGB => {
            // For 32-bit BI_RGB the fourth byte is "reserved"; a V4/V5
            // header may still declare it as alpha.
            bit_count == 32 && header >= BITMAPV4HEADER && u32_at(payload, 52)? == ALPHA_MASK
        }
        BI_BITFIELDS => {
            if bit_count != 32 {
                return Err(DibError::UnsupportedMasks);
            }
            let (masks_at, alpha) = if header == BITMAPINFOHEADER {
                pixel_offset = pixel_offset.checked_add(12).ok_or(DibError::Truncated)?;
                (BITMAPINFOHEADER, 0)
            } else {
                (40, u32_at(payload, 52)?)
            };
            let (r, g, b) =
                (u32_at(payload, masks_at)?, u32_at(payload, masks_at + 4)?, u32_at(payload, masks_at + 8)?);
            if (r, g, b) != (RED_MASK, GREEN_MASK, BLUE_MASK) || (alpha != 0 && alpha != ALPHA_MASK) {
                return Err(DibError::UnsupportedMasks);
            }
            alpha == ALPHA_MASK
        }
        other => return Err(DibError::UnsupportedCompression(other)),
    };

    if header >= BITMAPV4HEADER {
        let cs_type = u32_at(payload, 56)?;
        match cs_type {
            LCS_CALIBRATED_RGB | LCS_SRGB | LCS_WINDOWS_COLOR_SPACE => {}
            PROFILE_LINKED | PROFILE_EMBEDDED if header == BITMAPV5HEADER => {
                // Never read, but a declared profile must lie inside the
                // payload: an out-of-range offset is a malformed header.
                let at = u32_at(payload, 112)? as usize;
                let len = u32_at(payload, 116)? as usize;
                let end = at.checked_add(len).ok_or(DibError::Truncated)?;
                if at < header || end > payload.len() {
                    return Err(DibError::Truncated);
                }
            }
            other => return Err(DibError::UnsupportedColorSpace(other)),
        }
    }

    let row_bytes = stride(width, bit_count).ok_or(DibError::BadDimensions)?;
    let pixel_bytes = row_bytes.checked_mul(height as usize).ok_or(DibError::BadDimensions)?;
    let pixel_end = pixel_offset.checked_add(pixel_bytes).ok_or(DibError::Truncated)?;
    if payload.len() < pixel_end {
        return Err(DibError::Truncated);
    }
    let decoded_len =
        (width as usize).checked_mul(height as usize).and_then(|p| p.checked_mul(4)).ok_or(DibError::BadDimensions)?;
    if decoded_len > MAX_DECODED_BYTES {
        return Err(DibError::TooLarge);
    }

    let pixels = &payload[pixel_offset..pixel_end];
    let bpp = usize::from(bit_count / 8);
    let mut rgba = Zeroizing::new(vec![0u8; decoded_len]);
    let mut any_alpha = false;
    for y in 0..height as usize {
        let src_row = if top_down { y } else { height as usize - 1 - y };
        let src = &pixels[src_row * row_bytes..src_row * row_bytes + width as usize * bpp];
        let dst = &mut rgba[y * width as usize * 4..(y + 1) * width as usize * 4];
        for (s, d) in src.chunks_exact(bpp).zip(dst.as_chunks_mut::<4>().0.iter_mut()) {
            d[0] = s[2];
            d[1] = s[1];
            d[2] = s[0];
            d[3] = if alpha_in_pixels { s[3] } else { 0xFF };
            any_alpha |= alpha_in_pixels && s[3] != 0;
        }
    }
    // A 32-bit DIB that declares alpha but leaves every pixel at zero is an
    // opaque image written by an application that never set the channel —
    // rendering it fully transparent would be the wrong reading.
    if alpha_in_pixels && !any_alpha {
        for px in rgba.as_chunks_mut::<4>().0 {
            px[3] = 0xFF;
        }
    }
    Ok(RgbaImage { width, height, rgba })
}

fn check_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<(), DibError> {
    if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
        return Err(DibError::BadDimensions);
    }
    let want =
        (width as usize).checked_mul(height as usize).and_then(|p| p.checked_mul(4)).ok_or(DibError::BadDimensions)?;
    if rgba.len() != want {
        return Err(DibError::BadPixelBuffer);
    }
    Ok(())
}

fn encode_with_header(width: u32, height: u32, rgba: &[u8], header: &[u8]) -> Result<Vec<u8>, DibError> {
    check_rgba(width, height, rgba)?;
    let row = width as usize * 4;
    let total = header
        .len()
        .checked_add(row.checked_mul(height as usize).ok_or(DibError::TooLarge)?)
        .ok_or(DibError::TooLarge)?;
    if total > MAX_IMAGE_BYTES {
        return Err(DibError::TooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(header);
    // Bottom-up: the last image row first.
    for y in (0..height as usize).rev() {
        for px in rgba[y * row..(y + 1) * row].as_chunks::<4>().0 {
            out.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
    }
    Ok(out)
}

fn base_header(size: usize, width: u32, height: u32, compression: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(size);
    h.extend_from_slice(&(size as u32).to_le_bytes());
    h.extend_from_slice(&(width as i32).to_le_bytes());
    h.extend_from_slice(&(height as i32).to_le_bytes()); // positive: bottom-up
    h.extend_from_slice(&1u16.to_le_bytes()); // planes
    h.extend_from_slice(&32u16.to_le_bytes()); // bit count
    h.extend_from_slice(&compression.to_le_bytes());
    let image_size = (width as u64 * 4 * height as u64).min(u64::from(u32::MAX)) as u32;
    h.extend_from_slice(&image_size.to_le_bytes());
    h.extend_from_slice(&2835i32.to_le_bytes()); // 72 DPI
    h.extend_from_slice(&2835i32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // colours used
    h.extend_from_slice(&0u32.to_le_bytes()); // colours important
    h
}

/// Encode as `CF_DIB`: 32-bit `BI_RGB`, alpha in the reserved byte.
pub fn encode_dib(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, DibError> {
    let header = base_header(BITMAPINFOHEADER, width, height, BI_RGB);
    encode_with_header(width, height, rgba, &header)
}

/// Encode as `CF_DIBV5`: 32-bit `BI_BITFIELDS` with an alpha mask, sRGB.
pub fn encode_dibv5(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, DibError> {
    let mut header = base_header(BITMAPV5HEADER, width, height, BI_BITFIELDS);
    for mask in [RED_MASK, GREEN_MASK, BLUE_MASK, ALPHA_MASK, LCS_SRGB] {
        header.extend_from_slice(&mask.to_le_bytes());
    }
    header.extend_from_slice(&[0u8; 36]); // CIEXYZTRIPLE endpoints
    header.extend_from_slice(&[0u8; 12]); // gamma red / green / blue
    header.extend_from_slice(&4u32.to_le_bytes()); // LCS_GM_IMAGES
    header.extend_from_slice(&[0u8; 12]); // profile data, profile size, reserved
    debug_assert_eq!(header.len(), BITMAPV5HEADER);
    encode_with_header(width, height, rgba, &header)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 3x2 image with a distinct colour per pixel and partial alpha.
    fn sample() -> (u32, u32, Vec<u8>) {
        let px: [[u8; 4]; 6] = [
            [255, 0, 0, 255],
            [0, 255, 0, 255],
            [0, 0, 255, 128],
            [10, 20, 30, 255],
            [40, 50, 60, 0],
            [70, 80, 90, 255],
        ];
        (3, 2, px.concat())
    }

    /// Hand-built `BITMAPINFOHEADER` DIB, for the decoder tests that need a
    /// shape the encoder does not produce.
    fn header40(width: i32, height: i32, bit_count: u16, compression: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&40u32.to_le_bytes());
        h.extend_from_slice(&width.to_le_bytes());
        h.extend_from_slice(&height.to_le_bytes());
        h.extend_from_slice(&1u16.to_le_bytes());
        h.extend_from_slice(&bit_count.to_le_bytes());
        h.extend_from_slice(&compression.to_le_bytes());
        h.extend_from_slice(&[0u8; 20]);
        h
    }

    #[test]
    fn dibv5_round_trips_including_alpha() {
        let (w, h, rgba) = sample();
        let wire = encode_dibv5(w, h, &rgba).unwrap();
        let back = decode(&wire).unwrap();
        assert_eq!((back.width, back.height), (w, h));
        assert_eq!(&back.rgba[..], &rgba[..]);
    }

    #[test]
    fn dib_round_trips_and_reads_32_bit_bi_rgb_as_opaque() {
        // `BI_RGB` with a 40-byte header has no alpha channel by
        // definition; the reserved byte we wrote is not read back as one.
        let (w, h, rgba) = sample();
        let back = decode(&encode_dib(w, h, &rgba).unwrap()).unwrap();
        let mut opaque = rgba.clone();
        for px in opaque.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        assert_eq!(&back.rgba[..], &opaque[..]);
    }

    #[test]
    fn top_down_and_bottom_up_both_decode_to_top_down_rows() {
        // 1x2, 24-bit: row padding makes each row 4 bytes.
        let top = [0x01u8, 0x02, 0x03, 0x00];
        let bottom = [0x04u8, 0x05, 0x06, 0x00];
        let mut bottom_up = header40(1, 2, 24, BI_RGB);
        bottom_up.extend_from_slice(&bottom);
        bottom_up.extend_from_slice(&top);
        let mut top_down = header40(1, -2, 24, BI_RGB);
        top_down.extend_from_slice(&top);
        top_down.extend_from_slice(&bottom);
        let want = vec![0x03, 0x02, 0x01, 0xFF, 0x06, 0x05, 0x04, 0xFF];
        assert_eq!(&decode(&bottom_up).unwrap().rgba[..], &want[..]);
        assert_eq!(&decode(&top_down).unwrap().rgba[..], &want[..]);
    }

    #[test]
    fn row_padding_is_honoured_for_24_bit() {
        // Width 3 at 24 bpp is 9 bytes of pixels, padded to a 12-byte row.
        let mut dib = header40(3, 1, 24, BI_RGB);
        dib.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0xEE, 0xEE, 0xEE]);
        let img = decode(&dib).unwrap();
        assert_eq!(&img.rgba[..], &[3, 2, 1, 255, 6, 5, 4, 255, 9, 8, 7, 255]);
        // One padding byte short is truncated, not read past.
        dib.pop();
        assert_eq!(decode(&dib).unwrap_err(), DibError::Truncated);
    }

    #[test]
    fn an_all_zero_alpha_channel_reads_as_opaque() {
        let (w, h, mut rgba) = sample();
        for px in rgba.chunks_exact_mut(4) {
            px[3] = 0;
        }
        let back = decode(&encode_dibv5(w, h, &rgba).unwrap()).unwrap();
        assert!(back.rgba.chunks_exact(4).all(|px| px[3] == 0xFF));
    }

    #[test]
    fn bitfields_after_a_40_byte_header_are_read_from_the_mask_dwords() {
        let mut dib = header40(1, 1, 32, BI_BITFIELDS);
        for m in [RED_MASK, GREEN_MASK, BLUE_MASK] {
            dib.extend_from_slice(&m.to_le_bytes());
        }
        dib.extend_from_slice(&[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(&decode(&dib).unwrap().rgba[..], &[0x30, 0x20, 0x10, 0xFF]);
    }

    #[test]
    fn malformed_headers_are_refused() {
        let ok = encode_dibv5(2, 2, &[0u8; 16]).unwrap();
        let patch = |at: usize, bytes: &[u8]| {
            let mut v = ok.clone();
            v[at..at + bytes.len()].copy_from_slice(bytes);
            v
        };
        let cases: Vec<(&str, Vec<u8>, DibError)> = vec![
            ("empty", vec![], DibError::Truncated),
            ("three bytes", vec![40, 0, 0], DibError::Truncated),
            ("core header", patch(0, &12u32.to_le_bytes()), DibError::UnsupportedHeader(12)),
            ("os/2 v2 header", patch(0, &64u32.to_le_bytes()), DibError::UnsupportedHeader(64)),
            ("huge header", patch(0, &u32::MAX.to_le_bytes()), DibError::UnsupportedHeader(u32::MAX)),
            ("planes 0", patch(12, &0u16.to_le_bytes()), DibError::BadPlanes(0)),
            ("planes 2", patch(12, &2u16.to_le_bytes()), DibError::BadPlanes(2)),
            ("8 bpp", patch(14, &8u16.to_le_bytes()), DibError::UnsupportedBitCount(8)),
            ("16 bpp", patch(14, &16u16.to_le_bytes()), DibError::UnsupportedBitCount(16)),
            ("0 bpp", patch(14, &0u16.to_le_bytes()), DibError::UnsupportedBitCount(0)),
            ("RLE8", patch(16, &1u32.to_le_bytes()), DibError::UnsupportedCompression(1)),
            ("JPEG", patch(16, &4u32.to_le_bytes()), DibError::UnsupportedCompression(4)),
            ("PNG", patch(16, &5u32.to_le_bytes()), DibError::UnsupportedCompression(5)),
            ("odd red mask", patch(40, &0x0000_00FFu32.to_le_bytes()), DibError::UnsupportedMasks),
            ("odd alpha mask", patch(52, &0x0F00_0000u32.to_le_bytes()), DibError::UnsupportedMasks),
            ("colour table", patch(32, &4u32.to_le_bytes()), DibError::ColorTable),
            ("width 0", patch(4, &0i32.to_le_bytes()), DibError::BadDimensions),
            ("negative width", patch(4, &(-2i32).to_le_bytes()), DibError::BadDimensions),
            ("height 0", patch(8, &0i32.to_le_bytes()), DibError::BadDimensions),
            ("height i32::MIN", patch(8, &i32::MIN.to_le_bytes()), DibError::BadDimensions),
            ("width over ceiling", patch(4, &(MAX_IMAGE_DIMENSION as i32 + 1).to_le_bytes()), DibError::BadDimensions),
            (
                "unknown colour space",
                patch(56, &0x1234_5678u32.to_le_bytes()),
                DibError::UnsupportedColorSpace(0x1234_5678),
            ),
            (
                "embedded profile outside the payload",
                {
                    let mut v = patch(56, &PROFILE_EMBEDDED.to_le_bytes());
                    v[112..116].copy_from_slice(&124u32.to_le_bytes());
                    v[116..120].copy_from_slice(&4096u32.to_le_bytes());
                    v
                },
                DibError::Truncated,
            ),
            ("pixels cut short", ok[..ok.len() - 1].to_vec(), DibError::Truncated),
            ("header only", ok[..124].to_vec(), DibError::Truncated),
        ];
        for (what, payload, want) in cases {
            assert_eq!(decode(&payload).unwrap_err(), want, "{what}");
        }
    }

    #[test]
    fn bitfields_on_24_bit_is_refused() {
        let dib = header40(1, 1, 24, BI_BITFIELDS);
        assert_eq!(decode(&dib).unwrap_err(), DibError::UnsupportedMasks);
    }

    #[test]
    fn dimensions_that_would_overflow_never_allocate() {
        // Within the per-axis ceiling, but the payload is a few bytes: the
        // length check refuses it before any buffer is sized.
        let mut dib = header40(MAX_IMAGE_DIMENSION as i32, MAX_IMAGE_DIMENSION as i32, 32, BI_RGB);
        dib.extend_from_slice(&[0u8; 16]);
        assert_eq!(decode(&dib).unwrap_err(), DibError::Truncated);
    }

    #[test]
    fn the_wire_cap_drops_rather_than_truncates() {
        assert_eq!(decode(&vec![0u8; MAX_IMAGE_BYTES + 1]).unwrap_err(), DibError::TooLarge);
        // An image whose encoding would exceed the cap is refused whole.
        let side = 4096u32; // 4096^2 * 4 = 64 MiB
        let rgba = vec![0u8; (side * side * 4) as usize];
        assert_eq!(encode_dib(side, side, &rgba).unwrap_err(), DibError::TooLarge);
        assert_eq!(encode_dibv5(side, side, &rgba).unwrap_err(), DibError::TooLarge);
    }

    #[test]
    fn a_4k_screenshot_fits() {
        assert!(3840usize * 2160 * 4 + BITMAPV5HEADER <= MAX_IMAGE_BYTES);
        assert!(3840usize * 2160 * 4 <= MAX_DECODED_BYTES);
    }

    #[test]
    fn the_encoder_refuses_a_buffer_that_does_not_match_its_dimensions() {
        assert_eq!(encode_dib(2, 2, &[0u8; 15]).unwrap_err(), DibError::BadPixelBuffer);
        assert_eq!(encode_dibv5(0, 2, &[]).unwrap_err(), DibError::BadDimensions);
    }
}
