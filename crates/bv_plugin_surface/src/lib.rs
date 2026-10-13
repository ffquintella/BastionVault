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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current surface schema version. Bumped when a change lands that an
/// older host or client would otherwise mis-render. Clients that see a
/// higher `schema_version` than this constant ignore the surface — they
/// do **not** attempt to render an unknown shape.
///
/// * `1` — menus, pages, inline tables / forms / details.
/// * `2` — adds modal forms ([`SurfacePresentation::Modal`]), table
///   toolbar actions ([`SurfaceTable::actions`]) and row actions that open
///   a prefilled form ([`SurfaceRowAction::open_form`]). A v1 surface is
///   still a valid v2 surface and renders exactly as before.
///
/// The bump is what makes the new keys fail loudly on an older host: the
/// structs here do not deny unknown fields and the server re-serialises
/// the parsed manifest, so a host that predates v2 would silently drop
/// them (rendering every modal form inline and turning an *Edit* row
/// action into a bare `read`). Declaring `schema_version = 2` instead
/// gets the bundle refused at registration by such a host.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// First schema version that may use modal forms, table actions and
/// row actions that open a form. [`SurfaceManifest::validate`] refuses
/// those features in a surface declaring anything lower.
pub const MODAL_FORMS_SCHEMA_VERSION: u32 = 2;

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
    /// Schema v2: buttons shown with the table (also when it is empty)
    /// that open modal forms, e.g. *Add account*.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SurfaceTableAction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceColumn {
    pub field: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceRowAction {
    pub label: String,
    /// The operation the action issues with the row's string fields
    /// as `{<field>}` substitutions. When [`Self::open_form`] is set
    /// this must be a `read`: its response prefills the form.
    pub binding: SurfaceBinding,
    /// When true, the GUI shows a confirm dialog before issuing
    /// the bound operation. Not allowed together with `open_form`.
    #[serde(default)]
    pub confirm: bool,
    /// Schema v2: open a modal form for this row instead of issuing
    /// `binding` as the action. The renderer reads `binding`, prefills
    /// the form from the response (never a secret-format field), and
    /// submits the form's own `submit.binding` with the row's fields
    /// taking precedence for path placeholders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_form: Option<SurfaceOpenForm>,
}

/// Schema v2: a toolbar button on a table that opens a modal form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceTableAction {
    pub label: String,
    /// Ids of modal forms on the same page. With one, the button opens
    /// it directly; with more, the modal first asks which one, listing
    /// each form's `title` (a "choose the kind" step).
    pub forms: Vec<String>,
    /// Shown above the choices when `forms` has more than one entry.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prompt: String,
}

/// Schema v2: which modal form a row action opens. Exactly one of the
/// two shapes is allowed:
///
/// * `form` — the same form for every row;
/// * `select_by` + `forms_by_value` — the row's string field
///   `select_by` picks the form, e.g. `secret_kind` → `password` /
///   `ssh-key`. A row whose value has no entry gets an explicit error,
///   never a fallback form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceOpenForm {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub form: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub select_by: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub forms_by_value: BTreeMap<String, String>,
}

impl SurfaceOpenForm {
    /// Every form id this reference can open.
    pub fn form_ids(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.form.as_str())
            .filter(|f| !f.is_empty())
            .chain(self.forms_by_value.values().map(String::as_str))
    }
}

/// Schema v2: how a form is presented.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfacePresentation {
    /// Rendered in place on its page (the v1 behaviour).
    #[default]
    Inline,
    /// Not rendered on the page; opened in a modal by a table action or
    /// a row action on the same page.
    Modal,
}

impl SurfacePresentation {
    fn is_inline(&self) -> bool {
        *self == SurfacePresentation::Inline
    }
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
    /// Schema v2: `modal` keeps the form off the page until an action
    /// opens it. Omitted (inline) on the wire, so a v1 form serialises
    /// byte-for-byte as before and its ETag does not move.
    #[serde(default, skip_serializing_if = "SurfacePresentation::is_inline")]
    pub presentation: SurfacePresentation,
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
///   `row_actions[].binding`. A row action substitutes the row's string
///   fields; a form opened by a row action substitutes the row's fields
///   first and its own values only for placeholders the row lacks.
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
    #[error("{feature} needs schema_version {min} or later, but the surface declares {got}")]
    FeatureNeedsSchemaVersion { feature: &'static str, min: u32, got: u32 },
    #[error("`{component}` references form `{form}`, which is not a modal form on the same page")]
    UnknownModalForm { component: String, form: String },
    #[error("modal form `{0}` is not opened by any table action or row action on its page")]
    UnreachableModalForm(String),
    #[error("config_form `{0}` cannot be a modal form")]
    ModalConfigForm(String),
    #[error("table `{table}` action `{label}`: {reason}")]
    BadTableAction { table: String, label: String, reason: &'static str },
    #[error("table `{table}` row action `{label}`: {reason}")]
    BadOpenForm { table: String, label: String, reason: &'static str },
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
                check_component(c, self.schema_version, &mut comp_ids, declared_asset_names)?;
            }
            check_modal_forms(p)?;
        }

        if let Some(cf) = &self.config_form {
            // config_form lives outside the page tree but still
            // participates in the global ID namespace.
            check_component_id(&cf.id, &mut comp_ids)?;
            // The admin panel renders it in place; nothing could open it.
            if cf.presentation == SurfacePresentation::Modal {
                return Err(SurfaceError::ModalConfigForm(cf.id.clone()));
            }
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
    schema_version: u32,
    seen: &mut BTreeSet<String>,
    asset_names: &BTreeSet<&str>,
) -> Result<(), SurfaceError> {
    match c {
        SurfaceComponent::Table(t) => {
            check_component_id(&t.id, seen)?;
            check_binding(&t.binding)?;
            if !t.actions.is_empty() {
                require_schema_version("table actions", schema_version)?;
            }
            for ra in &t.row_actions {
                check_binding(&ra.binding)?;
                if ra.open_form.is_some() {
                    require_schema_version("row actions that open a form", schema_version)?;
                }
            }
        }
        SurfaceComponent::Form(f) => {
            check_component_id(&f.id, seen)?;
            check_binding(&f.submit.binding)?;
            check_hook(&f.hook, asset_names)?;
            if f.presentation == SurfacePresentation::Modal {
                require_schema_version("modal forms", schema_version)?;
            }
        }
        SurfaceComponent::Detail(d) => {
            check_component_id(&d.id, seen)?;
            check_binding(&d.binding)?;
        }
    }
    Ok(())
}

fn require_schema_version(feature: &'static str, got: u32) -> Result<(), SurfaceError> {
    if got < MODAL_FORMS_SCHEMA_VERSION {
        return Err(SurfaceError::FeatureNeedsSchemaVersion {
            feature,
            min: MODAL_FORMS_SCHEMA_VERSION,
            got,
        });
    }
    Ok(())
}

/// Every form a table action or row action names must be a modal form
/// on the same page, and every modal form must be opened by something
/// (an unreachable form is an authoring mistake, like an orphan page).
fn check_modal_forms(page: &SurfacePage) -> Result<(), SurfaceError> {
    let modal: BTreeSet<&str> = page
        .components
        .iter()
        .filter_map(|c| match c {
            SurfaceComponent::Form(f) if f.presentation == SurfacePresentation::Modal => Some(f.id.as_str()),
            _ => None,
        })
        .collect();
    let require_modal = |component: &str, form: &str| -> Result<(), SurfaceError> {
        if modal.contains(form) {
            Ok(())
        } else {
            Err(SurfaceError::UnknownModalForm { component: component.to_string(), form: form.to_string() })
        }
    };

    let mut opened: BTreeSet<&str> = BTreeSet::new();
    for c in &page.components {
        let SurfaceComponent::Table(t) = c else { continue };
        for a in &t.actions {
            let bad = |reason| SurfaceError::BadTableAction { table: t.id.clone(), label: a.label.clone(), reason };
            if a.label.trim().is_empty() {
                return Err(bad("label is empty"));
            }
            if a.forms.is_empty() {
                return Err(bad("lists no forms"));
            }
            let mut listed: BTreeSet<&str> = BTreeSet::new();
            for f in &a.forms {
                if !listed.insert(f.as_str()) {
                    return Err(bad("lists the same form twice"));
                }
                require_modal(&t.id, f)?;
                opened.insert(f.as_str());
            }
        }
        for ra in &t.row_actions {
            let Some(of) = &ra.open_form else { continue };
            let bad = |reason| SurfaceError::BadOpenForm { table: t.id.clone(), label: ra.label.clone(), reason };
            if ra.binding.op != SurfaceOp::Read {
                return Err(bad("an action that opens a form must bind a `read`, which prefills the form"));
            }
            if ra.confirm {
                return Err(bad("`confirm` does not apply to an action that opens a form"));
            }
            match (of.form.is_empty(), of.select_by.is_empty(), of.forms_by_value.is_empty()) {
                (false, true, true) | (true, false, false) => {}
                _ => return Err(bad("open_form needs either `form`, or `select_by` with `forms_by_value`")),
            }
            if of.forms_by_value.keys().any(|k| k.is_empty()) {
                return Err(bad("forms_by_value has an empty value"));
            }
            for f in of.form_ids() {
                require_modal(&t.id, f)?;
                opened.insert(f);
            }
        }
    }
    if let Some(unreached) = modal.difference(&opened).next() {
        return Err(SurfaceError::UnreachableModalForm(unreached.to_string()));
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
    /// Extensibility v2 (Phase 2): descriptor for the plugin's app
    /// module, when it ships one (a `client_assets` entry with
    /// `kind = "app-module"`). Carries the content-addressed asset ref
    /// plus the app-capability gates the Tauri-backend runtime needs to
    /// register/deny `bvx.*` imports per call. `None` when the plugin
    /// declares no app module. Omitted on the wire for v1 compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_module: Option<AppModuleRef>,
}

/// Extensibility v2: everything a client needs to instantiate and gate
/// a plugin's app module without re-fetching the manifest. The network
/// hosts are *not* here — they ride the separately-gated [`SurfaceGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppModuleRef {
    /// `client_assets` name of the app-module WASM (fetched via the
    /// per-version asset endpoint, like any other client asset).
    pub asset_name: String,
    /// SHA-256 (hex) of the WASM bytes — content-addressed, verified on
    /// fetch.
    pub sha256: String,
    /// `capabilities.app.dynamic_menus` — gates `bvx.menu_*`.
    #[serde(default)]
    pub dynamic_menus: bool,
    /// `capabilities.app.windows.max_open` — gates `bvx.window_*` and
    /// caps concurrent plugin windows (0 = windows disabled).
    #[serde(default)]
    pub windows_max_open: u32,
    /// `capabilities.app.api_paths` — the mount-scoped prefixes
    /// `bvx.api_request` may target (enforced host-side per call).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_paths: Vec<String>,
    /// `capabilities.app.net.https_only` — governs the client enforcer's
    /// cleartext-`http` exception. Defaults `true`. (The granted host
    /// list itself rides the separately-gated [`SurfaceGrant`].)
    #[serde(default = "default_true_bool")]
    pub net_https_only: bool,
}

fn default_true_bool() -> bool {
    true
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
            // Mounts are namespace-local and can change independently of a
            // plugin version. Include the resolved path so mount, unmount and
            // remount operations invalidate clients' active-surface bundles.
            hasher.update(e.mount.as_bytes());
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
            // Fold the app-module descriptor so a new module sha or a
            // capability change re-instantiates the runtime on refresh.
            if let Some(am) = &e.app_module {
                hasher.update(b"app:");
                hasher.update(am.sha256.as_bytes());
                hasher.update(b":");
                hasher.update([am.dynamic_menus as u8]);
                hasher.update(am.windows_max_open.to_le_bytes());
                for p in &am.api_paths {
                    hasher.update(p.as_bytes());
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
                    actions: vec![],
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
            SurfaceError::UnsupportedSchemaVersion { got: 99, max: CURRENT_SCHEMA_VERSION }
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
            actions: vec![],
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
            presentation: SurfacePresentation::Inline,
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
            app_module: None,
        }];
        let etag = ActiveSurfaceBundle::compute_etag(&entries);
        assert_eq!(etag.len(), 64); // sha256 hex
    }

    #[test]
    fn mount_changes_bundle_etag() {
        let base = ActiveSurfaceEntry {
            plugin: "self-accounts".into(),
            version: "0.1.1".into(),
            mount: String::new(),
            surface: minimal_surface(),
            assets: vec![],
            grant: None,
            app_module: None,
        };
        let unmounted = ActiveSurfaceBundle::compute_etag(std::slice::from_ref(&base));
        let mut mounted = base;
        mounted.mount = "self-accounts/".into();

        assert_ne!(
            unmounted,
            ActiveSurfaceBundle::compute_etag(std::slice::from_ref(&mounted)),
            "mounting a plugin must wake active-surface watchers"
        );
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
            app_module: None,
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

    // ── Schema v2: modal forms, table actions, row actions opening a form ──

    fn form(id: &str, submit_path: &str, modal: bool) -> serde_json::Value {
        let mut f = json!({
            "kind": "form",
            "id": id,
            "title": id,
            "schema": { "type": "object", "properties": { "label": { "type": "string" } } },
            "submit": { "label": "Save", "binding": { "op": "write", "path": submit_path } },
        });
        if modal {
            f["presentation"] = json!("modal");
        }
        f
    }

    /// The self-accounts shape: an *Add* button with a kind chooser and an
    /// *Edit* row action that picks the edit form by `secret_kind`.
    fn v2_json() -> serde_json::Value {
        json!({
            "schema_version": 2,
            "title": "Accounts",
            "menus": [{ "id": "a.main", "label": "Accounts", "section": "secrets", "route": "/plugin/acc/list" }],
            "pages": [{
                "route": "/plugin/acc/list",
                "title": "Accounts",
                "components": [
                    {
                        "kind": "table",
                        "id": "accounts",
                        "binding": { "op": "list", "path": "{mount}/v2/accounts" },
                        "columns": [{ "field": "label", "label": "Label" }],
                        "actions": [{ "label": "Add account", "prompt": "Kind?", "forms": ["add-pw", "add-key"] }],
                        "row_actions": [
                            {
                                "label": "Edit",
                                "binding": { "op": "read", "path": "{mount}/v2/accounts/{id}" },
                                "open_form": {
                                    "select_by": "secret_kind",
                                    "forms_by_value": { "password": "edit-pw", "ssh-key": "edit-key" }
                                }
                            },
                            {
                                "label": "Delete",
                                "binding": { "op": "delete", "path": "{mount}/v2/accounts/{id}" },
                                "confirm": true
                            }
                        ]
                    },
                    form("add-pw", "{mount}/v2/accounts", true),
                    form("add-key", "{mount}/v2/accounts", true),
                    form("edit-pw", "{mount}/v2/accounts/{id}", true),
                    form("edit-key", "{mount}/v2/accounts/{id}", true),
                ]
            }]
        })
    }

    fn parse(v: &serde_json::Value) -> SurfaceManifest {
        serde_json::from_value(v.clone()).expect("fixture deserialises")
    }

    fn check(v: &serde_json::Value) -> Result<(), SurfaceError> {
        parse(v).validate("acc", &BTreeSet::new())
    }

    fn table_mut(v: &mut serde_json::Value) -> &mut serde_json::Value {
        &mut v["pages"][0]["components"][0]
    }

    /// Drop a key (a JSON `null` would not hit the `serde(default)`).
    fn remove(v: &mut serde_json::Value, key: &str) {
        v.as_object_mut().expect("object").remove(key);
    }

    #[test]
    fn v2_modal_forms_validate_and_round_trip() {
        let v = v2_json();
        check(&v).unwrap();
        let s = parse(&v);
        let SurfaceComponent::Table(t) = &s.pages[0].components[0] else { panic!("table") };
        assert_eq!(t.actions[0].forms, ["add-pw", "add-key"]);
        let of = t.row_actions[0].open_form.as_ref().unwrap();
        assert_eq!(of.select_by, "secret_kind");
        assert_eq!(of.forms_by_value["ssh-key"], "edit-key");
        assert!(t.row_actions[1].open_form.is_none());
        let SurfaceComponent::Form(f) = &s.pages[0].components[1] else { panic!("form") };
        assert_eq!(f.presentation, SurfacePresentation::Modal);
        // The server re-serialises the parsed manifest: the new keys must survive.
        let back: SurfaceManifest = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn single_form_open_form_validates() {
        let mut v = v2_json();
        table_mut(&mut v)["row_actions"][0]["open_form"] = json!({ "form": "edit-pw" });
        // `edit-key` is now opened by nothing.
        assert_eq!(check(&v).unwrap_err(), SurfaceError::UnreachableModalForm("edit-key".into()));
        v["pages"][0]["components"].as_array_mut().unwrap().pop();
        check(&v).unwrap();
    }

    #[test]
    fn v1_surface_is_unchanged_on_the_wire_and_still_valid() {
        // A v1 surface: inline forms, delete row action. Same bytes out,
        // same ETag as before the v2 fields existed.
        let v1 = json!({
            "schema_version": 1,
            "title": "Accounts",
            "menus": [{ "id": "a.main", "label": "Accounts", "section": "secrets", "route": "/plugin/acc/list" }],
            "pages": [{
                "route": "/plugin/acc/list",
                "title": "Accounts",
                "components": [
                    {
                        "kind": "table",
                        "id": "accounts",
                        "binding": { "op": "list", "path": "{mount}/v2/accounts" },
                        "columns": [{ "field": "label", "label": "Label" }],
                        "row_actions": [{
                            "label": "Delete",
                            "binding": { "op": "delete", "path": "{mount}/v2/accounts/{id}" },
                            "confirm": true
                        }]
                    },
                    form("add", "{mount}/v2/accounts", false),
                ]
            }]
        });
        check(&v1).unwrap();
        let wire = serde_json::to_value(parse(&v1)).unwrap();
        assert_eq!(wire, v1, "no v2 key is emitted for a v1 surface");
    }

    #[test]
    fn v2_features_need_schema_version_2() {
        for (mutate, feature) in [
            (
                (|v: &mut serde_json::Value| {
                    remove(&mut table_mut(v)["row_actions"][0], "open_form");
                    remove(table_mut(v), "actions");
                }) as fn(&mut serde_json::Value),
                "modal forms",
            ),
            (
                |v: &mut serde_json::Value| remove(&mut table_mut(v)["row_actions"][0], "open_form"),
                "table actions",
            ),
            (|v: &mut serde_json::Value| remove(table_mut(v), "actions"), "row actions that open a form"),
        ] {
            let mut v = v2_json();
            v["schema_version"] = json!(1);
            mutate(&mut v);
            let err = check(&v).unwrap_err();
            assert!(
                matches!(&err, SurfaceError::FeatureNeedsSchemaVersion { feature: f, min: 2, got: 1 } if *f == feature),
                "{feature}: {err}"
            );
        }
    }

    #[test]
    fn rejects_dangling_form_references() {
        let mut v = v2_json();
        table_mut(&mut v)["actions"][0]["forms"][1] = json!("nope");
        assert_eq!(
            check(&v).unwrap_err(),
            SurfaceError::UnknownModalForm { component: "accounts".into(), form: "nope".into() }
        );

        let mut v = v2_json();
        table_mut(&mut v)["row_actions"][0]["open_form"]["forms_by_value"]["ssh-key"] = json!("missing");
        assert_eq!(
            check(&v).unwrap_err(),
            SurfaceError::UnknownModalForm { component: "accounts".into(), form: "missing".into() }
        );

        // An inline form is not something an action can open.
        let mut v = v2_json();
        remove(&mut v["pages"][0]["components"][3], "presentation");
        assert!(matches!(check(&v), Err(SurfaceError::UnknownModalForm { form, .. }) if form == "edit-pw"));
    }

    #[test]
    fn rejects_a_form_on_another_page() {
        let mut v = v2_json();
        let moved = v["pages"][0]["components"].as_array_mut().unwrap().remove(4);
        v["pages"].as_array_mut().unwrap().push(json!({
            "route": "/plugin/acc/list/other",
            "title": "Other",
            "components": [moved],
        }));
        assert!(matches!(check(&v), Err(SurfaceError::UnknownModalForm { form, .. }) if form == "edit-key"));
    }

    #[test]
    fn rejects_unreachable_modal_form() {
        let mut v = v2_json();
        v["pages"][0]["components"].as_array_mut().unwrap().push(form("orphan", "{mount}/v2/x", true));
        assert_eq!(check(&v).unwrap_err(), SurfaceError::UnreachableModalForm("orphan".into()));
    }

    #[test]
    fn rejects_bad_bindings_in_modal_forms_and_form_opening_actions() {
        let mut v = v2_json();
        v["pages"][0]["components"][3]["submit"]["binding"]["path"] = json!("sys/policies/acl/x");
        assert!(matches!(check(&v), Err(SurfaceError::BadBindingPath(_))));

        let mut v = v2_json();
        table_mut(&mut v)["row_actions"][0]["binding"]["path"] = json!("{mount}/../other/{id}");
        assert!(matches!(check(&v), Err(SurfaceError::BadBindingPath(_))));
    }

    #[test]
    fn rejects_malformed_actions() {
        type Mutation = fn(&mut serde_json::Value);
        let cases: [(Mutation, &str); 7] = [
            (|v| table_mut(v)["actions"][0]["forms"] = json!([]), "lists no forms"),
            (|v| table_mut(v)["actions"][0]["forms"] = json!(["add-pw", "add-pw", "add-key"]), "twice"),
            (|v| table_mut(v)["actions"][0]["label"] = json!(" "), "label is empty"),
            (|v| table_mut(v)["row_actions"][0]["binding"]["op"] = json!("write"), "must bind a `read`"),
            (|v| table_mut(v)["row_actions"][0]["confirm"] = json!(true), "`confirm`"),
            (|v| table_mut(v)["row_actions"][0]["open_form"]["form"] = json!("edit-pw"), "either `form`"),
            (
                |v| table_mut(v)["row_actions"][0]["open_form"]["forms_by_value"][""] = json!("edit-pw"),
                "empty value",
            ),
        ];
        for (mutate, needle) in cases {
            let mut v = v2_json();
            mutate(&mut v);
            let err = check(&v).unwrap_err();
            assert!(
                matches!(err, SurfaceError::BadTableAction { .. } | SurfaceError::BadOpenForm { .. }),
                "{needle}: {err}"
            );
            assert!(err.to_string().contains(needle), "{needle}: {err}");
        }

        let mut v = v2_json();
        table_mut(&mut v)["row_actions"][0]["open_form"] = json!({});
        assert!(check(&v).unwrap_err().to_string().contains("either `form`"));
    }

    #[test]
    fn rejects_modal_config_form() {
        let mut v = v2_json();
        v["config_form"] = form("cfg", "{mount}/config", true);
        assert_eq!(check(&v).unwrap_err(), SurfaceError::ModalConfigForm("cfg".into()));
    }

    #[test]
    fn unknown_presentation_is_a_parse_error() {
        let mut v = v2_json();
        v["pages"][0]["components"][1]["presentation"] = json!("drawer");
        assert!(serde_json::from_value::<SurfaceManifest>(v).is_err());
    }
}
