//! QR PNG rendering for `otpauth://` URLs (Phase 2).
//!
//! Pure-Rust pipeline: `qrcode` produces an `image::ImageBuffer`, the
//! `image` crate writes PNG bytes, base64 wraps the bytes for JSON
//! transport. No filesystem I/O — the buffer lives only as long as
//! the response body.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use image::Luma;
use qrcode::QrCode;

use crate::errors::RvError;

/// Render `text` to a PNG QR sized to roughly `pixel_size` pixels on
/// the long edge. Returns base64-encoded PNG bytes.
///
/// `pixel_size = 0` is the documented "do not render" sentinel; the
/// caller checks for it and skips this function entirely. We keep the
/// guard here too so a forgotten check upstream doesn't panic on a
/// zero-sized image.
pub fn render_png_b64(text: &str, pixel_size: u32) -> Result<String, RvError> {
    if pixel_size == 0 {
        return Err(RvError::ErrString(
            "qr_size = 0 disables rendering; do not call render_png_b64".into(),
        ));
    }

    let code = QrCode::new(text.as_bytes())
        .map_err(|e| RvError::ErrString(format!("qr encode failed: {e}")))?;

    // `qrcode` lays out modules; render to a Luma8 buffer scaled so
    // the *image* (not the module count) lands near `pixel_size`. The
    // builder picks a per-module pixel count internally given
    // min_dimensions; supplying both axes keeps it square.
    let img = code
        .render::<Luma<u8>>()
        .min_dimensions(pixel_size, pixel_size)
        .build();

    let mut png = Vec::<u8>::new();
    let mut cur = std::io::Cursor::new(&mut png);
    img.write_to(&mut cur, image::ImageFormat::Png)
        .map_err(|e| RvError::ErrString(format!("png encode failed: {e}")))?;

    Ok(B64.encode(&png))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_non_empty_png() {
        let b64 = render_png_b64("otpauth://totp/Foo:bar?secret=JBSWY3DPEHPK3PXP", 200).unwrap();
        let bytes = B64.decode(&b64).unwrap();
        // PNG magic.
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn zero_size_is_an_error() {
        assert!(render_png_b64("foo", 0).is_err());
    }
}
