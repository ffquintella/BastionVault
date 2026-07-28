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
#[derive(Default)]
pub struct ExporterInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault_fingerprint_b64: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_display_name: Option<String>,
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
    /// Caller asked for everything they can read **in the namespace the
    /// request targets** (the root namespace for a root-scoped call).
    Full,
    /// Caller asked for everything in *every* namespace of the deployment.
    /// Root-only: the resulting document carries the root namespace's items
    /// at the top level and one [`NamespaceBundle`] per child namespace.
    AllNamespaces,
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
    /// Opaque barrier-subtree entries for secret engines that have no
    /// structured exporter (pki, ssh, ssh-broker, transit, totp, openldap,
    /// rustion, …). Captured verbatim under the mount's barrier prefix so a
    /// full-vault backup round-trips every engine, not just KV. See
    /// `scope::read_raw_mount`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<RawEntry>,
    /// ACL policy documents belonging to the namespace this item set describes.
    /// A vault's secrets are unusable without the policies that grant access to
    /// them, so a full-vault export carries both. See `scope::read_policies`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyItem>,
    /// Per-namespace item sets, one bundle per **non-root** namespace, present
    /// only in an `all_namespaces` export. The root namespace's items stay in
    /// the fields above so a single-namespace document (every document written
    /// before this field existed) parses and imports unchanged.
    ///
    /// Bundles never nest: a bundle's own `namespaces` list is always empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<NamespaceBundle>,
}

impl ExchangeItems {
    /// Items in this set, not counting nested namespace bundles.
    pub fn local_len(&self) -> usize {
        self.kv.len()
            + self.resources.len()
            + self.files.len()
            + self.asset_groups.len()
            + self.resource_groups.len()
            + self.raw.len()
            + self.policies.len()
    }
}

/// Everything exported from one non-root namespace. `path` is the canonical
/// namespace path (`engineering`, `engineering/platform`) — no leading or
/// trailing slash — which is what the importer resolves back to a namespace
/// UUID and, from there, to that namespace's barrier prefix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NamespaceBundle {
    pub path: String,
    pub items: ExchangeItems,
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

/// A single opaque barrier-storage entry for a non-KV secret engine. `mount`
/// is the engine's mount path (e.g. `pki/`); `path` is the key **relative to
/// the mount's barrier prefix**; `value` is the parsed JSON body, or a
/// `{"_base64": "..."}` wrapper when the stored bytes are not JSON — exactly
/// like [`KvItem`]. The importer writes it straight back under the destination
/// mount's barrier prefix via `MountIndex::resolve_raw_key`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RawEntry {
    pub mount: String,
    pub path: String,
    pub value: Value,
}

/// A single ACL policy. `name` is the policy name as the operator addresses it
/// through `sys/policy/<name>`; `value` is the stored policy document (the
/// `PolicyEntry` JSON carrying the raw HCL, `templated`, and `type`), or a
/// `{"_base64": …}` wrapper when the stored bytes are not JSON — same encoding
/// as [`KvItem`].
///
/// `tests` carries the policy's saved effectivity test cases (the graphical
/// builder's regression gate, stored in its own keyspace) when the policy has
/// any, so a restore brings back the policy *and* the assertions that guard it.
/// Absent for policies with no saved tests.
///
/// Which namespace a policy belongs to is implied by where it sits in the
/// document: top-level items are the root namespace's, and a
/// [`NamespaceBundle`]'s items are that namespace's — exactly as for KV.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyItem {
    pub name: String,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests: Option<Value>,
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
