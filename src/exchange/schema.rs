//! `bvx.v1` JSON schema.
//!
//! The schema is intentionally narrow in v1: KV-mount items only. Resources,
//! file blobs, and asset / resource groups land in later phases and add new
//! variants under `ExchangeItems`.
//!
//! Canonical encoding is enforced by `canonical::to_canonical_vec` so two
//! exports of the same scope produce byte-identical JSON. That property is
//! what lets the AEAD authentication be meaningful: a tampered field flips
//! the tag.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_TAG: &str = "bvx.v1";

/// Top-level export document. Wrapped by `Envelope` when encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExchangeDocument {
    pub schema: String,
    pub exported_at: String,
    pub exporter: ExporterInfo,
    pub scope: ScopeSpec,
    pub items: ExchangeItems,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ExchangeDocument {
    pub fn new(exporter: ExporterInfo, scope: ScopeSpec, items: ExchangeItems) -> Self {
        Self {
            schema: SCHEMA_TAG.to_string(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            exporter,
            scope,
            items,
            warnings: Vec::new(),
        }
    }

    pub fn validate_schema_tag(&self) -> Result<(), &'static str> {
        if self.schema != SCHEMA_TAG {
            return Err("unsupported bvx schema tag");
        }
        Ok(())
    }
}

/// Who produced the document. The `vault_fingerprint_b64` is a non-secret
/// identity hash so the importer can warn on cross-vault imports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExporterInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault_fingerprint_b64: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_display_name: Option<String>,
}

impl Default for ExporterInfo {
    fn default() -> Self {
        Self {
            vault_fingerprint_b64: String::new(),
            namespace: String::new(),
            actor_display_name: None,
        }
    }
}

/// What was selected for export. The `include` list is replayable; an
/// importer with the right ACL can recompute which items the exporter
/// intended to ship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeSpec {
    pub kind: ScopeKind,
    pub include: Vec<ScopeSelector>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Caller hand-picked the items.
    Selective,
    /// Caller asked for everything they can read.
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScopeSelector {
    /// All keys under `mount`+`path` (inclusive of `path`, recursive).
    KvPath { mount: String, path: String },
    /// A single resource by id, including its file blobs.
    Resource { id: String },
    /// An asset group; expands to every member the actor can read.
    AssetGroup { id: String },
    /// A resource group; expands to every member resource.
    ResourceGroup { id: String },
}

/// The actual exported data. Each variant is independently optional so a
/// document carrying only KV items still parses against an importer that
/// supports more variants, and vice versa.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ExchangeItems {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kv: Vec<KvItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_groups: Vec<AssetGroupItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_groups: Vec<ResourceGroupItem>,
}

/// A single KV entry. `value` is the parsed JSON body if the storage entry
/// parsed as JSON; otherwise a base64-encoded blob (`{"_base64": "..."}`)
/// to keep the document self-describing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KvItem {
    pub mount: String,
    pub path: String,
    pub value: Value,
}

/// A resource record — typed inventory entry (e.g. "server", "ssh-key").
/// The wire shape mirrors the resource module's storage record so an
/// importer can reconstitute it without parsing application-level fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceItem {
    pub id: String,
    pub data: Value,
}

/// A file resource — binary blob plus metadata. `content_b64` is the raw
/// bytes; `metadata` carries name / sha256 / size / type-id / etc. exactly
/// as the file engine's storage record stored them. The importer is
/// responsible for SHA-256 verification on read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileItem {
    pub id: String,
    pub metadata: Value,
    pub content_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetGroupItem {
    pub id: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceGroupItem {
    pub id: String,
    pub data: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_tag_round_trip() {
        let doc = ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec {
                kind: ScopeKind::Selective,
                include: vec![ScopeSelector::KvPath {
                    mount: "secret/".to_string(),
                    path: "myapp/".to_string(),
                }],
            },
            ExchangeItems::default(),
        );
        assert_eq!(doc.schema, SCHEMA_TAG);
        assert!(doc.validate_schema_tag().is_ok());
    }

    #[test]
    fn rejects_unknown_schema_tag() {
        let doc = ExchangeDocument {
            schema: "bvx.v999".to_string(),
            exported_at: "2026-04-25T00:00:00Z".to_string(),
            exporter: ExporterInfo::default(),
            scope: ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            items: ExchangeItems::default(),
            warnings: vec![],
        };
        assert!(doc.validate_schema_tag().is_err());
    }
}
