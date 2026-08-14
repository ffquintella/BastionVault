//! Base64url-no-pad helpers used throughout the WebAuthn RP module.
//!
//! WebAuthn wire format uses RFC4648 §5 base64url *without* padding; both
//! the browser and our stored JSON follow that convention. Keep these
//! helpers in one place so we don't get padding/charset drift.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}
