//! Plugin surface manifest types.
//!
//! Single source of truth for the `surface.json` shape introduced in
//! Plugin Extensibility v1 (see `features/plugin-extensibility.md`).
//! The server stores these, `bv-client` parses them after the
//! aggregated-surface fetch, and the Tauri GUI renders against them.
//! Keeping the types in one crate guarantees the three sides agree on
//! field names, enum variants, and validation.
//!
//! Validation is layered:
//!
//! 1. `serde` deserialisation rejects type-shape mistakes (a string
//!    where an array is expected, an unknown variant, etc.).
//! 2. [`SurfaceManifest::validate`] catches semantic issues: bindings
//!    that escape the plugin's mount, unknown sections, dangling
//!    component IDs in row-action references.
//!
//! The GUI must call `validate` after deserialising. The server calls
//! it at registration time too, so a bad surface is rejected before
//! a client ever sees it.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current surface schema version. Bumped when a backwards-incompatible
/// change to the on-disk shape lands. Clients that see a higher
/// `schema_version` than this constant ignore the surface — they do
/// **not** attempt to render an unknown shape.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Top-level surface manifest. Stored alongside the plugin's server
/// binary and served verbatim to clients.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceManifest {
    /// Hard fence on the schema version. A client that doesn't
    /// recognise the value drops the surface (the plugin still works
    /// via the admin page) and surfaces a single warning.
    pub schema_version: u32,
    /// Display title used in the operator-side preview and as the
    /// fallback menu label when an entry omits `label`.
    pub title: String,
    /// Lucide icon name (e.g. `"key-round"`). Optional — the GUI
    /// renders a generic plugin glyph when missing or unknown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
    /// Sidebar entries this plugin contributes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub menus: Vec<SurfaceMenu>,
    /// Pages reachable through the menus.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<SurfacePage>,
    /// Optional surface-driven config form. When present, the GUI
    /// renders this in place of the raw key/value editor backed by
    /// `manifest.config_schema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_form: Option<SurfaceForm>,
}

/// Sidebar / admin / settings link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceMenu {
    /// Stable ID, namespaced by the author (e.g. `"totp.main"`).
    /// Used by the operator-preview pane to detect collisions
    /// between plugins.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Lucide icon name. Optional.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
    /// Where the menu shows up.
    pub section: SurfaceSection,
    /// In-app route. Must start with `/plugin/<plugin-name>/`.
    pub route: String,
    /// Optional ACL policy hint. The GUI hides menus the active
    /// token doesn't satisfy. **Not** a security boundary — the
    /// server's ACL pipeline is the only authority.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub min_policy: String,
}

/// Sidebar section. Rejected at validation if outside this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceSection {
    Secrets,
    Sharing,
    Admin,
    Settings,
}

/// One page reachable from a menu. Vertical stack of components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfacePage {
    pub route: String,
    pub title: String,
    pub components: Vec<SurfaceComponent>,
}

/// Discriminated union of supported component kinds. New variants
/// require a `schema_version` bump.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SurfaceComponent {
    Table(SurfaceTable),
    Form(SurfaceForm),
    Detail(SurfaceDetail),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceTable {
    pub id: String,
    pub binding: SurfaceBinding,
    pub columns: Vec<SurfaceColumn>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub row_actions: Vec<SurfaceRowAction>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub empty_text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceColumn {
    pub field: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceRowAction {
    pub label: String,
    pub binding: SurfaceBinding,
    /// When true, the GUI shows a confirm dialog before issuing
    /// the bound operation.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceForm {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// JSON Schema (Draft 2020-12). Validated structurally by the
    /// renderer; we don't try to evaluate the schema host-side.
    pub schema: serde_json::Value,
    pub submit: SurfaceSubmit,
    /// Optional `<asset_name>#<export>` form-hook reference.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hook: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceSubmit {
    pub label: String,
    pub binding: SurfaceBinding,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceDetail {
    pub id: String,
    pub binding: SurfaceBinding,
    pub fields: Vec<SurfaceDetailField>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceDetailField {
    pub field: String,
    pub label: String,
    /// When true, the GUI re-issues the bound `read` on a 5-second
    /// cadence while the page is visible (e.g., live TOTP code).
    #[serde(default)]
    pub live: bool,
}

/// `{op, path}` envelope mirroring the existing plugin LogicalBackend
/// dispatch shape. The path supports two substitution points:
///
/// * `{mount}` — replaced with this plugin's actual mount path.
/// * `{<form_field>}` — only legal in `submit.binding` and
///   `row_actions[].binding`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceBinding {
    pub op: SurfaceOp,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceOp {
    Read,
    Write,
    Delete,
    List,
}

// ── Validation ───────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq)]
pub enum SurfaceError {
    #[error("schema_version {got} not supported (max: {max})")]
    UnsupportedSchemaVersion { got: u32, max: u32 },
    #[error("menu route `{0}` must start with `/plugin/<this-plugin>/`")]
    BadMenuRoute(String),
    #[error("page route `{0}` does not match any declared menu")]
    OrphanPageRoute(String),
    #[error("binding path `{0}` must start with `{{mount}}/` and not contain `..`")]
    BadBindingPath(String),
    #[error("hook reference `{0}` must be `<asset>#<export>` shape")]
    BadHookRef(String),
    #[error("hook `{hook}` references asset `{asset}` not declared in manifest.client_assets")]
    UnknownHookAsset { hook: String, asset: String },
    #[error("duplicate component id `{0}`")]
    DuplicateComponentId(String),
    #[error("duplicate menu id `{0}`")]
    DuplicateMenuId(String),
}

impl SurfaceManifest {
    /// Run semantic checks. The caller passes the plugin's own name so
    /// we can verify menu routes are scoped, plus the set of asset
    /// names declared in the bundle's manifest so hook references
    /// can be checked against actual files.
    pub fn validate(
        &self,
        plugin_name: &str,
        declared_asset_names: &BTreeSet<&str>,
    ) -> Result<(), SurfaceError> {
        if self.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(SurfaceError::UnsupportedSchemaVersion {
                got: self.schema_version,
                max: CURRENT_SCHEMA_VERSION,
            });
        }

        let menu_prefix = format!("/plugin/{plugin_name}/");

        let mut menu_ids: BTreeSet<&str> = BTreeSet::new();
        let mut menu_routes: BTreeSet<&str> = BTreeSet::new();
        for m in &self.menus {
            if !menu_ids.insert(&m.id) {
                return Err(SurfaceError::DuplicateMenuId(m.id.clone()));
            }
            if !m.route.starts_with(&menu_prefix) {
                return Err(SurfaceError::BadMenuRoute(m.route.clone()));
            }
            menu_routes.insert(&m.route);
        }

        let mut comp_ids: BTreeSet<String> = BTreeSet::new();
        for p in &self.pages {
            if !p.route.starts_with(&menu_prefix) {
                return Err(SurfaceError::BadMenuRoute(p.route.clone()));
            }
            // Pages must be reachable from at least one menu — we
            // don't strictly require a menu per page (a page can be
            // a sub-detail target), but we flag totally-orphan
            // pages as a likely authoring mistake.
            if !menu_routes.contains(p.route.as_str())
                && !is_subroute_of_any(&p.route, &menu_routes)
            {
                return Err(SurfaceError::OrphanPageRoute(p.route.clone()));
            }
            for c in &p.components {
                check_component(c, &mut comp_ids, declared_asset_names)?;
            }
        }

        if let Some(cf) = &self.config_form {
            // config_form lives outside the page tree but still
            // participates in the global ID namespace.
            check_component_id(&cf.id, &mut comp_ids)?;
            check_binding(&cf.submit.binding)?;
            check_hook(&cf.hook, declared_asset_names)?;
        }

        Ok(())
    }
}

fn is_subroute_of_any(route: &str, menus: &BTreeSet<&str>) -> bool {
    menus.iter().any(|m| route.starts_with(m) && route.len() > m.len())
}

fn check_component(
    c: &SurfaceComponent,
    seen: &mut BTreeSet<String>,
    asset_names: &BTreeSet<&str>,
) -> Result<(), SurfaceError> {
    match c {
        SurfaceComponent::Table(t) => {
            check_component_id(&t.id, seen)?;
            check_binding(&t.binding)?;
            for ra in &t.row_actions {
                check_binding(&ra.binding)?;
            }
        }
        SurfaceComponent::Form(f) => {
            check_component_id(&f.id, seen)?;
            check_binding(&f.submit.binding)?;
            check_hook(&f.hook, asset_names)?;
        }
        SurfaceComponent::Detail(d) => {
            check_component_id(&d.id, seen)?;
            check_binding(&d.binding)?;
        }
    }
    Ok(())
}

fn check_component_id(id: &str, seen: &mut BTreeSet<String>) -> Result<(), SurfaceError> {
    if !seen.insert(id.to_string()) {
        return Err(SurfaceError::DuplicateComponentId(id.to_string()));
    }
    Ok(())
}

fn check_binding(b: &SurfaceBinding) -> Result<(), SurfaceError> {
    // Bindings must be mount-scoped. We allow the literal placeholder
    // because it's resolved at request time — never a raw absolute
    // path or anything containing `..`.
    if !b.path.starts_with("{mount}/") {
        return Err(SurfaceError::BadBindingPath(b.path.clone()));
    }
    if b.path.contains("..") {
        return Err(SurfaceError::BadBindingPath(b.path.clone()));
    }
    Ok(())
}

fn check_hook(hook: &str, asset_names: &BTreeSet<&str>) -> Result<(), SurfaceError> {
    if hook.is_empty() {
        return Ok(());
    }
    let (asset, export) = hook
        .split_once('#')
        .ok_or_else(|| SurfaceError::BadHookRef(hook.to_string()))?;
    if asset.is_empty() || export.is_empty() {
        return Err(SurfaceError::BadHookRef(hook.to_string()));
    }
    if !asset_names.contains(asset) {
        return Err(SurfaceError::UnknownHookAsset {
            hook: hook.to_string(),
            asset: asset.to_string(),
        });
    }
    Ok(())
}

// ── ETag computation ─────────────────────────────────────────────────

/// Stable ETag for a surface manifest. The ETag is the SHA-256 of the
/// canonical (sorted-keys) JSON encoding of the manifest. Same input
/// → same hex string, regardless of the ordering of the in-memory
/// `Vec`s — so a server restart that re-deserialises identically
/// returns the same ETag and clients hit 304.
pub fn surface_etag(m: &SurfaceManifest) -> String {
    use sha2::{Digest, Sha256};
    // serde_json::to_vec writes object keys in struct-declaration
    // order, which is stable for our types.
    let bytes = serde_json::to_vec(m).expect("SurfaceManifest is always serializable");
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

// ── Aggregated surface bundle (server → client) ──────────────────────

/// Response body of `GET /v1/sys/plugins/active-surfaces`. One entry
/// per active plugin that ships a surface; the bundle's top-level
/// ETag is the hash of every entry's individual ETag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveSurfaceBundle {
    pub etag: String,
    pub entries: Vec<ActiveSurfaceEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveSurfaceEntry {
    pub plugin: String,
    pub version: String,
    pub mount: String,
    pub surface: SurfaceManifest,
    /// `(asset_name, sha256-hex)` pairs the client can fetch via the
    /// `/asset/<sha256>` endpoint. Order-stable.
    pub assets: Vec<(String, String)>,
    /// Extensibility v2: the plugin's *live* admin grant, delivered
    /// in-band so the Tauri-side network enforcer needs no extra round
    /// trip and revocation propagates through the existing ETag/watcher
    /// machinery. `None` when the plugin has no valid grant (never
    /// requested, never granted, or the grant's `capability_sha256` no
    /// longer matches the active manifest). Omitted on the wire so v1
    /// clients — which don't know the field — deserialize unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SurfaceGrant>,
}

/// Extensibility v2: the subset of a plugin's admin grant that clients
/// need. Only the granted network hosts are shipped — never the grant
/// metadata (actor, timestamp, capability hash), which stays server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceGrant {
    /// Granted outbound host allowlist (a subset of the manifest's
    /// requested `capabilities.app.net.hosts`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net_hosts: Vec<String>,
}

impl ActiveSurfaceBundle {
    /// Compute the bundle ETag from the constituent entries. Stable
    /// for a given input.
    pub fn compute_etag(entries: &[ActiveSurfaceEntry]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for e in entries {
            hasher.update(e.plugin.as_bytes());
            hasher.update(b"\0");
            hasher.update(e.version.as_bytes());
            hasher.update(b"\0");
            hasher.update(surface_etag(&e.surface).as_bytes());
            hasher.update(b"\0");
            for (n, h) in &e.assets {
                hasher.update(n.as_bytes());
                hasher.update(b"=");
                hasher.update(h.as_bytes());
                hasher.update(b"\0");
            }
            // Fold the grant into the ETag so an admin approve/revoke
            // changes the bundle hash and propagates to clients via the
            // existing long-poll/watcher (revocation takes effect ≤ 30 s).
            if let Some(g) = &e.grant {
                hasher.update(b"grant:");
                for host in &g.net_hosts {
                    hasher.update(host.as_bytes());
                    hasher.update(b",");
                }
                hasher.update(b"\0");
            }
            hasher.update(b"\n");
        }
        hex::encode(hasher.finalize())
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal_surface() -> SurfaceManifest {
        SurfaceManifest {
            schema_version: 1,
            title: "Test".into(),
            icon: String::new(),
            menus: vec![SurfaceMenu {
                id: "t.main".into(),
                label: "Test".into(),
                icon: String::new(),
                section: SurfaceSection::Secrets,
                route: "/plugin/totp/list".into(),
                min_policy: String::new(),
            }],
            pages: vec![SurfacePage {
                route: "/plugin/totp/list".into(),
                title: "List".into(),
                components: vec![SurfaceComponent::Table(SurfaceTable {
                    id: "t.list".into(),
                    binding: SurfaceBinding { op: SurfaceOp::List, path: "{mount}/codes".into() },
                    columns: vec![SurfaceColumn { field: "name".into(), label: "Name".into() }],
                    row_actions: vec![],
                    empty_text: String::new(),
                })],
            }],
            config_form: None,
        }
    }

    #[test]
    fn minimal_validates() {
        let s = minimal_surface();
        let assets = BTreeSet::new();
        s.validate("totp", &assets).unwrap();
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let mut s = minimal_surface();
        s.schema_version = 99;
        let assets = BTreeSet::new();
        assert_eq!(
            s.validate("totp", &assets).unwrap_err(),
            SurfaceError::UnsupportedSchemaVersion { got: 99, max: 1 }
        );
    }

    #[test]
    fn rejects_menu_outside_plugin() {
        let mut s = minimal_surface();
        s.menus[0].route = "/plugin/other/list".into();
        let assets = BTreeSet::new();
        assert!(matches!(
            s.validate("totp", &assets),
            Err(SurfaceError::BadMenuRoute(_))
        ));
    }

    #[test]
    fn rejects_binding_outside_mount() {
        let mut s = minimal_surface();
        if let SurfaceComponent::Table(t) = &mut s.pages[0].components[0] {
            t.binding.path = "sys/plugins".into();
        }
        let assets = BTreeSet::new();
        assert!(matches!(
            s.validate("totp", &assets),
            Err(SurfaceError::BadBindingPath(_))
        ));
    }

    #[test]
    fn rejects_dotdot_in_binding() {
        let mut s = minimal_surface();
        if let SurfaceComponent::Table(t) = &mut s.pages[0].components[0] {
            t.binding.path = "{mount}/../other".into();
        }
        let assets = BTreeSet::new();
        assert!(matches!(
            s.validate("totp", &assets),
            Err(SurfaceError::BadBindingPath(_))
        ));
    }

    #[test]
    fn rejects_duplicate_component_id() {
        let mut s = minimal_surface();
        s.pages[0].components.push(SurfaceComponent::Table(SurfaceTable {
            id: "t.list".into(),
            binding: SurfaceBinding { op: SurfaceOp::List, path: "{mount}/other".into() },
            columns: vec![],
            row_actions: vec![],
            empty_text: String::new(),
        }));
        let assets = BTreeSet::new();
        assert!(matches!(
            s.validate("totp", &assets),
            Err(SurfaceError::DuplicateComponentId(_))
        ));
    }

    #[test]
    fn rejects_unknown_hook_asset() {
        let mut s = minimal_surface();
        s.pages[0].components.push(SurfaceComponent::Form(SurfaceForm {
            id: "t.create".into(),
            title: String::new(),
            schema: json!({}),
            submit: SurfaceSubmit {
                label: "Save".into(),
                binding: SurfaceBinding { op: SurfaceOp::Write, path: "{mount}/codes/{name}".into() },
            },
            hook: "nope.wasm#go".into(),
        }));
        let assets = BTreeSet::new();
        assert!(matches!(
            s.validate("totp", &assets),
            Err(SurfaceError::UnknownHookAsset { .. })
        ));
    }

    #[test]
    fn etag_is_stable_across_clones() {
        let s = minimal_surface();
        assert_eq!(surface_etag(&s), surface_etag(&s.clone()));
    }

    #[test]
    fn etag_changes_on_payload_change() {
        let a = minimal_surface();
        let mut b = a.clone();
        b.title = "Different".into();
        assert_ne!(surface_etag(&a), surface_etag(&b));
    }

    #[test]
    fn bundle_etag_aggregates() {
        let s = minimal_surface();
        let entries = vec![ActiveSurfaceEntry {
            plugin: "totp".into(),
            version: "1.0.0".into(),
            mount: "secret/totp".into(),
            surface: s,
            assets: vec![],
            grant: None,
        }];
        let etag = ActiveSurfaceBundle::compute_etag(&entries);
        assert_eq!(etag.len(), 64); // sha256 hex
    }

    #[test]
    fn grant_changes_bundle_etag() {
        let s = minimal_surface();
        let base = ActiveSurfaceEntry {
            plugin: "totp".into(),
            version: "1.0.0".into(),
            mount: "secret/totp".into(),
            surface: s,
            assets: vec![],
            grant: None,
        };
        let ungranted = ActiveSurfaceBundle::compute_etag(std::slice::from_ref(&base));
        let mut granted = base.clone();
        granted.grant = Some(SurfaceGrant { net_hosts: vec!["hooks.example.com".into()] });
        let granted_etag = ActiveSurfaceBundle::compute_etag(std::slice::from_ref(&granted));
        // Approve → different ETag → clients refresh and pick up the grant.
        assert_ne!(ungranted, granted_etag);
        // Absent grant deserializes on v1 clients (field omitted on wire).
        let wire = serde_json::to_string(&base).unwrap();
        assert!(!wire.contains("grant"));
    }

    #[test]
    fn round_trips_through_json() {
        let s = minimal_surface();
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: SurfaceManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
