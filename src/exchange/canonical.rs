//! Canonical JSON encoder: sorted keys, LF newlines, no trailing whitespace.
//!
//! Two encodes of the same value must produce byte-identical output across
//! runs and across platforms. We deliberately do not depend on `serde_json`'s
//! default object emit order because `serde_json::Map` preserves insertion
//! order, not sort order, when the `preserve_order` feature is enabled.
//!
//! The encoder walks the `serde_json::Value` tree manually and writes a
//! minimal-form JSON: no whitespace, sorted object keys, integer-or-float
//! number rendering matching `serde_json`'s standard serializer.

use serde::Serialize;
use serde_json::Value;

use crate::errors::RvError;

/// Serialize any `Serialize` value to canonical JSON bytes.
///
/// This is the byte representation we feed into AEAD as plaintext. Two calls
/// with the same `value` produce byte-identical output.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, RvError> {
    let v = serde_json::to_value(value)?;
    let mut out = Vec::with_capacity(256);
    write_value(&v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), RvError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // serde_json's Number Display matches the standard JSON serializer.
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sorted-key emit. BTreeMap rebuild keeps the canonical order
            // independent of whatever order `serde_json` parsed in.
            let sorted: std::collections::BTreeMap<&String, &Value> = map.iter().collect();
            out.push(b'{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0c' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn determinism_across_two_runs() {
        let a = json!({
            "z": 1,
            "a": [1, 2, 3],
            "m": { "y": "y", "x": "x" },
        });
        let b = json!({
            "a": [1, 2, 3],
            "m": { "x": "x", "y": "y" },
            "z": 1,
        });
        let a_canon = to_canonical_vec(&a).unwrap();
        let b_canon = to_canonical_vec(&b).unwrap();
        assert_eq!(a_canon, b_canon);
        // Sorted-key form starts with `{"a":...`.
        assert!(a_canon.starts_with(b"{\"a\":"));
    }

    #[test]
    fn escapes_control_chars() {
        let v = json!({"k": "a\nb\tc\"d\\e"});
        let bytes = to_canonical_vec(&v).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"k":"a\nb\tc\"d\\e"}"#);
    }

    #[test]
    fn nested_object_keys_sorted_recursively() {
        let v = json!({"o": {"z": 1, "a": 2}});
        let bytes = to_canonical_vec(&v).unwrap();
        assert_eq!(&bytes, br#"{"o":{"a":2,"z":1}}"#);
    }
}
