//! Example: client-side form-hook WASM for the TOTP plugin.
//!
//! Pair with `examples/totp_surface.rs`. Build as a wasm artifact:
//!
//! ```text
//! cargo build --release --target wasm32-unknown-unknown \
//!     --example totp_form_hook \
//!     --features surface,json -p bastion-plugin-sdk
//! ```
//!
//! Ship the resulting `.wasm` as `totp-form-hooks.wasm` next to
//! `surface.json` inside the `.bvplugin` bundle.
//!
//! The matching `SurfaceForm.hook` reference is
//! `"totp-form-hooks.wasm#validate_create"`.
//!
//! ## What this hook does
//!
//! Refuses non-base32 `secret` values before the form even hits
//! the server. Server-side validation still runs as the source of
//! truth — the hook is purely UX (faster feedback, no round-trip).
//!
//! Plugin Extensibility v1 / Phase 7.

#[cfg(feature = "surface")]
use serde_json::{json, Value};

#[cfg(feature = "surface")]
fn validate_create(input: Value) -> Value {
    let name = input.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return json!({
            "ok": false,
            "errors": { "name": "Required." },
        });
    }
    let secret = input.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    if secret.is_empty() {
        return json!({
            "ok": false,
            "errors": { "secret": "Required." },
        });
    }
    // Allow ASCII space + dash so users pasting QR-derived secrets
    // with their built-in formatting don't have to clean them up.
    let normalised: String = secret
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect();
    let valid_b32 = !normalised.is_empty()
        && normalised
            .chars()
            .all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '='));
    if !valid_b32 {
        return json!({
            "ok": false,
            "errors": {
                "secret": "Must be base32 (A–Z, 2–7); spaces and dashes are stripped."
            },
        });
    }
    // Hand the normalised secret back so the form submits the
    // cleaned-up value rather than the user's pasted one.
    json!({
        "ok": true,
        "values": {
            "name": name,
            "issuer": input.get("issuer").cloned().unwrap_or(Value::Null),
            "secret": normalised,
        }
    })
}

#[cfg(feature = "surface")]
bastion_plugin_sdk::form_hook!(validate_create);

// `cargo build --example` requires a `main` even for examples
// targeting wasm. Empty for non-wasm hosts; the WASM target
// produces a `cdylib`-style export with no entry point.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn main() {}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(all(test, feature = "surface"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_name() {
        let r = validate_create(json!({ "secret": "JBSWY3DPEHPK3PXP" }));
        assert_eq!(r["ok"], false);
        assert!(r["errors"]["name"].is_string());
    }

    #[test]
    fn rejects_non_base32_secret() {
        let r = validate_create(json!({ "name": "x", "secret": "abc!" }));
        assert_eq!(r["ok"], false);
        assert!(r["errors"]["secret"].is_string());
    }

    #[test]
    fn strips_spaces_and_dashes_from_valid_secret() {
        let r = validate_create(json!({
            "name": "x",
            "secret": "JBSW Y3DP-EHPK 3PXP",
        }));
        assert_eq!(r["ok"], true);
        assert_eq!(r["values"]["secret"], "JBSWY3DPEHPK3PXP");
    }
}
