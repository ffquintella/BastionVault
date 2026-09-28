//! The read-only tool catalogue (spec §7, v1 — write tools are Phase 6 and
//! not built here). Descriptions and schemas are constants: nothing here is
//! ever built from stored data, which is what makes tool descriptions
//! immune to tool-poisoning via a renamed secret or a crafted resource
//! note.

use serde_json::{json, Value};

/// A single catalogue entry as `tools/list` reports it.
pub struct ToolMeta {
    pub name: &'static str,
    pub description: &'static str,
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    /// This tool can return a secret/plaintext value gated by an explicit
    /// `reveal: true` argument (spec §6 "Reveal gate").
    pub is_reveal: bool,
    pub input_schema: fn() -> Value,
    pub output_schema: fn() -> Value,
}

fn empty_output_schema() -> Value {
    json!({ "type": "object" })
}

fn path_args_schema(extra: Value) -> Value {
    let mut base = json!({
        "type": "object",
        "properties": {
            "mount": { "type": "string" },
            "path": { "type": "string" },
        },
        "required": ["mount", "path"],
    });
    if let (Some(base_props), Some(extra_props)) = (base.get_mut("properties"), extra.get("properties")) {
        if let (Value::Object(bp), Value::Object(ep)) = (base_props, extra_props) {
            for (k, v) in ep {
                bp.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(Value::Array(extra_req)) = extra.get("required") {
        if let Some(Value::Array(req)) = base.get_mut("required") {
            req.extend(extra_req.clone());
        }
    }
    base
}

/// Fixed serialization order — `tools/list` and the catalogue hash both
/// depend on this never silently reordering.
pub fn catalogue() -> &'static [ToolMeta] {
    &[
        ToolMeta {
            name: "bv_whoami",
            description: "Return the calling principal's token accessor, display name and policies. Answered from the token entry directly; never routes to auth/token/lookup-self.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({ "type": "object", "properties": {} }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_capabilities",
            description: "Return this principal's effective capabilities on a given path.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_kv_list",
            description: "List the keys under a KV path.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || path_args_schema(json!({})),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_kv_read_metadata",
            description: "Read a KV secret's metadata (versions, timestamps) without its value.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || path_args_schema(json!({})),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_kv_read",
            description: "Read a KV secret. Returns metadata and a redacted value sentinel unless `reveal: true` is set and this principal's binding allows reveal.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: true,
            input_schema: || path_args_schema(json!({
                "properties": { "reveal": { "type": "boolean", "default": false } },
            })),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_resource_list",
            description: "List generic resources under a path.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_resource_describe",
            description: "Describe a generic resource (never a secret value without reveal).",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_transit_encrypt",
            description: "Encrypt plaintext (base64) under a Transit key. Does not require reveal.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "plaintext": { "type": "string", "description": "base64" },
                    "context": { "type": "string", "description": "base64, optional" },
                },
                "required": ["key", "plaintext"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_transit_decrypt",
            description: "Decrypt ciphertext under a Transit key. The output is plaintext, so this is treated as a reveal.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: true,
            input_schema: || json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "ciphertext": { "type": "string" },
                    "reveal": { "type": "boolean", "default": false },
                },
                "required": ["key", "ciphertext"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_transit_sign",
            description: "Sign input (base64) with a Transit key.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "input": { "type": "string", "description": "base64" },
                },
                "required": ["key", "input"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_transit_verify",
            description: "Verify a signature against input (base64) with a Transit key.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "input": { "type": "string", "description": "base64" },
                    "signature": { "type": "string" },
                },
                "required": ["key", "input", "signature"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_totp_code",
            description: "Read the current TOTP code for a named generator. The code is a secret, so this is treated as a reveal.",
            read_only: true,
            destructive: false,
            idempotent: false,
            is_reveal: true,
            input_schema: || json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "reveal": { "type": "boolean", "default": false },
                },
                "required": ["name"],
            }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_pki_list_certs",
            description: "List issued certificate serial numbers.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({ "type": "object", "properties": {} }),
            output_schema: empty_output_schema,
        },
        ToolMeta {
            name: "bv_pki_read_cert",
            description: "Read a certificate's public material by serial number. Never returns a stored private key.",
            read_only: true,
            destructive: false,
            idempotent: true,
            is_reveal: false,
            input_schema: || json!({
                "type": "object",
                "properties": { "serial": { "type": "string" } },
                "required": ["serial"],
            }),
            output_schema: empty_output_schema,
        },
    ]
}

pub fn find(name: &str) -> Option<&'static ToolMeta> {
    catalogue().iter().find(|t| t.name == name)
}

/// `tools/list`'s JSON body, in catalogue order — the exact bytes
/// `catalogue_hash` is computed over.
pub fn tools_list_json() -> Value {
    let tools: Vec<Value> = catalogue()
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": (t.input_schema)(),
                "outputSchema": (t.output_schema)(),
                "annotations": {
                    "readOnlyHint": t.read_only,
                    "destructiveHint": t.destructive,
                    "idempotentHint": t.idempotent,
                    "openWorldHint": false,
                },
            })
        })
        .collect();
    json!({ "tools": tools })
}

/// BLAKE3 hash over the canonical JSON of `tools_list_json()`. `serde_json`
/// serializes object keys via `BTreeMap` ordering in this workspace (no
/// crate enables the `preserve_order` feature), so this is stable across
/// runs and platforms as long as the catalogue's own field order above is
/// unchanged.
pub fn catalogue_hash() -> String {
    let bytes = serde_json::to_vec(&tools_list_json()).expect("catalogue always serializes");
    blake3::hash(&bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_across_calls() {
        assert_eq!(catalogue_hash(), catalogue_hash());
    }

    #[test]
    fn no_tool_sets_open_world_hint() {
        let list = tools_list_json();
        for tool in list["tools"].as_array().unwrap() {
            assert_eq!(tool["annotations"]["openWorldHint"], json!(false));
        }
    }

    #[test]
    fn every_tool_has_a_valid_schema_object() {
        for t in catalogue() {
            let schema = (t.input_schema)();
            assert_eq!(schema["type"], json!("object"), "{} input schema", t.name);
        }
    }

    #[test]
    fn find_locates_a_known_tool_and_rejects_unknown() {
        assert!(find("bv_whoami").is_some());
        assert!(find("bv_kv_write").is_none());
    }

    #[test]
    fn reveal_tools_match_spec_table() {
        let reveal_tools: Vec<&str> = catalogue().iter().filter(|t| t.is_reveal).map(|t| t.name).collect();
        assert_eq!(reveal_tools, vec!["bv_kv_read", "bv_transit_decrypt", "bv_totp_code"]);
    }
}
