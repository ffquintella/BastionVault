//! Small helpers shared across logical-request entry points.
//!
//! The KV-v2 per-environment feature lets a read carry an `?env=<name>`
//! selector. That selector must reach the ACL check (which runs in the
//! pre-route phase and reads `req.data`/`req.body` directly) and the KV
//! handler — through *two* different entry boundaries: the HTTP handler
//! (`src/http/logical.rs`, where the query is separate from the path) and the
//! GUI's embedded backend (`gui/src-tauri/src/backend.rs`, which receives the
//! query glued onto the path string). Both seed `req.data` using the helpers
//! here so behaviour stays identical.

use serde_json::{Map, Number, Value};

/// Query keys we are willing to lift into `req.data`. Deliberately tiny: only
/// parameters the logical layer understands. Everything else is dropped so a
/// client can't smuggle arbitrary fields past the policy parameter checks.
const ALLOWED_QUERY_KEYS: &[&str] = &["env", "version"];

/// Split a raw logical path that may carry a query string
/// (`secret/data/app?env=prod`) into the clean path and an allowlisted
/// parameter map. The clean path must be query-free before it reaches the
/// router, whose mount lookup and `data/` regex would otherwise absorb the
/// `?env=...` into the secret name.
pub fn split_path_query(raw: &str) -> (String, Option<Map<String, Value>>) {
    match raw.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_query_allowlist(query)),
        None => (raw.to_string(), None),
    }
}

/// Parse a URL query string (no leading `?`), keeping only the allowlisted
/// keys. `version` is coerced to a number when numeric so it matches the
/// body-based read path (which calls `Value::as_u64`); a non-numeric `version`
/// is dropped. Returns `None` when nothing allowlisted matched.
pub fn parse_query_allowlist(query: &str) -> Option<Map<String, Value>> {
    let mut out = Map::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(k).to_ascii_lowercase();
        if !ALLOWED_QUERY_KEYS.contains(&key.as_str()) {
            continue;
        }
        let raw_val = percent_decode(v);
        let value = if key == "version" {
            match raw_val.parse::<u64>() {
                Ok(n) => Value::Number(Number::from(n)),
                Err(_) => continue,
            }
        } else {
            Value::String(raw_val)
        };
        out.insert(key, value);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Minimal `application/x-www-form-urlencoded` value decoder: `+` → space and
/// `%XX` → byte. Kept dependency-free on purpose (the `form_urlencoded` crate
/// is only a transitive dep). Invalid escapes are passed through verbatim.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_path_and_lifts_env() {
        let (path, data) = split_path_query("secret/data/app?env=prod");
        assert_eq!(path, "secret/data/app");
        let data = data.unwrap();
        assert_eq!(data.get("env").unwrap(), "prod");
    }

    #[test]
    fn no_query_yields_none() {
        let (path, data) = split_path_query("secret/data/app");
        assert_eq!(path, "secret/data/app");
        assert!(data.is_none());
    }

    #[test]
    fn version_is_numeric_and_unknown_keys_dropped() {
        let data = parse_query_allowlist("version=3&secret=leak&env=staging").unwrap();
        assert_eq!(data.get("version").unwrap().as_u64(), Some(3));
        assert_eq!(data.get("env").unwrap(), "staging");
        assert!(data.get("secret").is_none());
    }

    #[test]
    fn non_numeric_version_dropped() {
        assert!(parse_query_allowlist("version=latest").is_none());
    }

    #[test]
    fn percent_and_plus_decoded() {
        let data = parse_query_allowlist("env=us%2Dwest+1").unwrap();
        assert_eq!(data.get("env").unwrap(), "us-west 1");
    }
}
