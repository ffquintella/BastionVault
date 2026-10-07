//! Saved Session Workspace layouts (features/session-workspace.md §5, T38
//! Phase 5).
//!
//! A saved layout is a *skeleton*: the tab order, each tab's split tree and
//! ratios, and per pane the `{resource_name, profile_id, protocol}` it was
//! opened from plus the namespace it was opened in. It holds no token, no
//! credential and no session output — the host builds it from the
//! attachment registry's descriptors, so a token sent by the workspace to
//! name a pane never reaches the file.
//!
//! Restoring never resumes anything: the workspace re-opens every pane
//! through the normal `session_open_*` path (connect gate, transport tier,
//! connect-time MFA), and only on an explicit operator action.
//!
//! Stored in its own file next to the GUI preferences file
//! (`session_layouts.json`), not inside it as the spec first proposed: the
//! layout is rewritten on every (debounced) layout change, and the
//! preferences file is read-modified-written by many commands without a
//! common lock, so a frequent writer there could drop a concurrent vault
//! profile edit. This file has one writer path, behind [`FILE_LOCK`].
//!
//! The format is versioned ([`LAYOUT_FILE_VERSION`]). A file of another
//! version is refused — named, not read and not overwritten — so a
//! downgrade never destroys what a newer build saved.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::ProfileProtocol;

/// On-disk format version this build reads and writes.
pub const LAYOUT_FILE_VERSION: u32 = 1;
/// Bounds on one saved layout. Far past any real workspace; a layout over
/// them is not one this GUI produced.
pub const MAX_TABS: usize = 32;
pub const MAX_PANES: usize = 64;
pub const MAX_DEPTH: usize = 16;
/// Longest resource name / profile id / namespace kept.
pub const MAX_NAME: usize = 256;
/// Saved layouts kept — one per vault profile.
pub const MAX_LAYOUTS: usize = 64;
/// Same clamp as the workspace's reducer (`gui/src/lib/sessionLayout.ts`).
pub const MIN_RATIO: f64 = 0.1;
pub const MAX_RATIO: f64 = 0.9;

const FILE_NAME: &str = "session_layouts.json";

/// Serialises every read-modify-write of the layouts file in this process.
static FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutFile {
    pub version: u32,
    /// Vault profile id → that vault's last layout.
    #[serde(default)]
    pub layouts: BTreeMap<String, SavedLayout>,
}

impl Default for LayoutFile {
    fn default() -> Self {
        Self { version: LAYOUT_FILE_VERSION, layouts: BTreeMap::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SavedLayout {
    /// RFC 3339, UTC.
    pub saved_at: String,
    pub tabs: Vec<SavedTab>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SavedTab {
    pub root: SavedNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitDir {
    Row,
    Col,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaneProtocol {
    Ssh,
    Rdp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SavedPane {
    pub resource_name: String,
    pub profile_id: String,
    pub protocol: PaneProtocol,
    /// Namespace the session was opened in; `""` is root.
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SavedNode {
    Pane(SavedPane),
    Split { dir: SplitDir, ratio: f64, a: Box<SavedNode>, b: Box<SavedNode> },
}

/// The tree shape the workspace sends: leaves name a live session by
/// token, which the host resolves against its own registry.
#[derive(Debug, Clone, Deserialize)]
pub struct LayoutInput {
    pub tabs: Vec<TabInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TabInput {
    pub root: NodeInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum NodeInput {
    Pane { token: String },
    Split { dir: SplitDir, ratio: f64, a: Box<NodeInput>, b: Box<NodeInput> },
}

/// What the registry knows about one live session, as a layout needs it.
#[derive(Debug, Clone)]
pub struct PaneSource {
    pub resource_name: String,
    pub profile_id: String,
    pub protocol: ProfileProtocol,
    pub namespace: String,
    pub vault_id: String,
}

fn clamp_ratio(ratio: f64) -> f64 {
    if ratio.is_finite() {
        ratio.clamp(MIN_RATIO, MAX_RATIO)
    } else {
        0.5
    }
}

/// Build the skeleton for `input`, resolving each token with `lookup`.
///
/// A token the registry no longer knows (a session stopped while the save
/// was in flight) is dropped and its split collapses onto the survivor, as
/// the workspace's own close does; a tab left with nothing is dropped.
/// Returns `Ok(None)` when nothing is left — a save never replaces a layout
/// with an empty one — and the vault the panes belong to otherwise.
///
/// Refused: a layout whose sessions come from more than one vault profile
/// (the operator switched vault with sessions open). It has no single
/// owner, and saving it under either vault would later re-open the other
/// vault's resource names there.
pub fn build_saved_layout(
    input: &LayoutInput,
    lookup: impl Fn(&str) -> Option<PaneSource>,
    saved_at: String,
) -> Result<Option<(String, SavedLayout)>, String> {
    if input.tabs.len() > MAX_TABS {
        return Err(format!("layout has {} tabs; at most {MAX_TABS} are saved", input.tabs.len()));
    }
    let mut vaults: BTreeSet<String> = BTreeSet::new();
    let mut tabs = Vec::new();
    for tab in &input.tabs {
        if let Some(root) = convert(&tab.root, &lookup, &mut vaults, 0)? {
            tabs.push(SavedTab { root });
        }
    }
    if tabs.is_empty() {
        return Ok(None);
    }
    if vaults.len() > 1 {
        return Err(format!(
            "the workspace holds sessions from more than one vault ({}); its layout is not saved",
            vaults.into_iter().map(|v| format!("`{v}`")).collect::<Vec<_>>().join(", ")
        ));
    }
    let layout = SavedLayout { saved_at, tabs };
    validate_saved(&layout)?;
    let vault = vaults.into_iter().next().unwrap_or_default();
    Ok(Some((vault, layout)))
}

fn convert(
    node: &NodeInput,
    lookup: &impl Fn(&str) -> Option<PaneSource>,
    vaults: &mut BTreeSet<String>,
    depth: usize,
) -> Result<Option<SavedNode>, String> {
    if depth > MAX_DEPTH {
        return Err(format!("layout is nested deeper than {MAX_DEPTH} splits"));
    }
    match node {
        NodeInput::Pane { token } => {
            let Some(src) = lookup(token) else { return Ok(None) };
            let protocol = match src.protocol {
                ProfileProtocol::Ssh => PaneProtocol::Ssh,
                ProfileProtocol::Rdp => PaneProtocol::Rdp,
                ProfileProtocol::Web => return Ok(None),
            };
            vaults.insert(src.vault_id);
            Ok(Some(SavedNode::Pane(SavedPane {
                resource_name: src.resource_name,
                profile_id: src.profile_id,
                protocol,
                namespace: src.namespace,
            })))
        }
        NodeInput::Split { dir, ratio, a, b } => {
            let a = convert(a, lookup, vaults, depth + 1)?;
            let b = convert(b, lookup, vaults, depth + 1)?;
            Ok(match (a, b) {
                (Some(a), Some(b)) => {
                    Some(SavedNode::Split { dir: *dir, ratio: clamp_ratio(*ratio), a: Box::new(a), b: Box::new(b) })
                }
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            })
        }
    }
}

fn name_ok(s: &str, allow_empty: bool) -> bool {
    (allow_empty || !s.is_empty()) && s.len() <= MAX_NAME && !s.chars().any(char::is_control)
}

/// Check a layout against the bounds — on save, and on read, since the
/// file can be edited by hand.
pub fn validate_saved(layout: &SavedLayout) -> Result<(), String> {
    if layout.tabs.is_empty() {
        return Err("saved layout has no tabs".into());
    }
    if layout.tabs.len() > MAX_TABS {
        return Err(format!("saved layout has {} tabs; at most {MAX_TABS}", layout.tabs.len()));
    }
    let mut panes = 0usize;
    for tab in &layout.tabs {
        check_node(&tab.root, 0, &mut panes)?;
    }
    if panes > MAX_PANES {
        return Err(format!("saved layout has {panes} panes; at most {MAX_PANES}"));
    }
    Ok(())
}

fn check_node(node: &SavedNode, depth: usize, panes: &mut usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("saved layout is nested deeper than {MAX_DEPTH} splits"));
    }
    match node {
        SavedNode::Pane(p) => {
            *panes += 1;
            if !name_ok(&p.resource_name, false) || !name_ok(&p.profile_id, false) || !name_ok(&p.namespace, true) {
                return Err("saved layout has a pane with an empty, over-long or non-printable name".into());
            }
            Ok(())
        }
        SavedNode::Split { ratio, a, b, .. } => {
            if !ratio.is_finite() || *ratio < MIN_RATIO || *ratio > MAX_RATIO {
                return Err(format!("saved layout has a split ratio outside [{MIN_RATIO}, {MAX_RATIO}]"));
            }
            check_node(a, depth + 1, panes)?;
            check_node(b, depth + 1, panes)
        }
    }
}

/// Every pane in reading order.
pub fn panes(layout: &SavedLayout) -> Vec<&SavedPane> {
    fn walk<'a>(n: &'a SavedNode, out: &mut Vec<&'a SavedPane>) {
        match n {
            SavedNode::Pane(p) => out.push(p),
            SavedNode::Split { a, b, .. } => {
                walk(a, out);
                walk(b, out);
            }
        }
    }
    let mut out = Vec::new();
    for t in &layout.tabs {
        walk(&t.root, &mut out);
    }
    out
}

/// Normalise a namespace path the way `set_active_namespace` stores it:
/// trimmed, no surrounding slashes, `""` for root.
pub fn normalize_namespace(ns: &str) -> String {
    ns.trim().trim_matches('/').to_string()
}

fn show_namespace(ns: &str) -> String {
    if ns.is_empty() {
        "root".to_string()
    } else {
        format!("`{ns}`")
    }
}

/// The per-pane enforcement of the cross-namespace rule: a restore's open
/// names the namespace its pane was saved in, and is refused before
/// anything is read when the session's active namespace is another —
/// rather than resolving a same-named resource in the wrong namespace.
pub fn check_restore_namespace(saved: &str, active: &str) -> Result<(), String> {
    let (saved, active) = (normalize_namespace(saved), normalize_namespace(active));
    if saved == active {
        return Ok(());
    }
    Err(format!(
        "restore refused: this pane was saved in namespace {} but the active namespace is {}; switch namespace \
         before restoring",
        show_namespace(&saved),
        show_namespace(&active)
    ))
}

/// A restore placeholder id: short, printable, no separators that could be
/// mistaken for anything else. Opaque to the host.
pub fn pane_ref_ok(r: &str) -> bool {
    !r.is_empty() && r.len() <= 32 && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── File ──────────────────────────────────────────────────────────────

pub fn layouts_path() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir().or_else(dirs::home_dir).ok_or("cannot determine the home directory")?;
    Ok(base.join(".bastion_vault_gui").join(FILE_NAME))
}

/// Read the layouts file. Absent → empty. Another version → refused,
/// naming it.
pub fn load_from(path: &Path) -> Result<LayoutFile, String> {
    if !path.exists() {
        return Ok(LayoutFile::default());
    }
    let data = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let version = raw.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(LAYOUT_FILE_VERSION as u64) {
        return Err(format!(
            "{} has format version {}, this build reads version {LAYOUT_FILE_VERSION}; it is left untouched",
            path.display(),
            version.map_or_else(|| "(none)".to_string(), |v| v.to_string())
        ));
    }
    serde_json::from_value(raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Read-modify-write under [`FILE_LOCK`], written atomically (temp file +
/// rename) and owner-only on Unix: the file is a list of the hosts an
/// operator connects to.
pub fn update_at(path: &Path, f: impl FnOnce(&mut LayoutFile) -> Result<(), String>) -> Result<(), String> {
    let _guard = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut file = load_from(path)?;
    f(&mut file)?;
    file.version = LAYOUT_FILE_VERSION;
    let data = serde_json::to_string_pretty(&file).map_err(|e| format!("serialise layouts: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.write_all(data.as_bytes()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("sync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

/// Store `layout` as `vault_id`'s last layout.
pub fn save_at(path: &Path, vault_id: &str, layout: SavedLayout) -> Result<(), String> {
    validate_saved(&layout)?;
    update_at(path, |file| {
        if !file.layouts.contains_key(vault_id) && file.layouts.len() >= MAX_LAYOUTS {
            return Err(format!("{MAX_LAYOUTS} vault layouts are already saved; forget one first"));
        }
        file.layouts.insert(vault_id.to_string(), layout);
        Ok(())
    })
}

/// `vault_id`'s saved layout, checked against the bounds.
pub fn get_at(path: &Path, vault_id: &str) -> Result<Option<SavedLayout>, String> {
    let _guard = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let file = load_from(path)?;
    match file.layouts.get(vault_id) {
        None => Ok(None),
        Some(l) => {
            validate_saved(l).map_err(|e| format!("{} for vault `{vault_id}`: {e}", path.display()))?;
            Ok(Some(l.clone()))
        }
    }
}

/// Forget `vault_id`'s saved layout. Returns whether there was one.
pub fn forget_at(path: &Path, vault_id: &str) -> Result<bool, String> {
    let mut removed = false;
    update_at(path, |file| {
        removed = file.layouts.remove(vault_id).is_some();
        Ok(())
    })?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(name: &str, ns: &str, vault: &str) -> PaneSource {
        PaneSource {
            resource_name: name.into(),
            profile_id: format!("cp_{name}"),
            protocol: if name.starts_with("rdp") { ProfileProtocol::Rdp } else { ProfileProtocol::Ssh },
            namespace: ns.into(),
            vault_id: vault.into(),
        }
    }

    fn input(json: serde_json::Value) -> LayoutInput {
        serde_json::from_value(json).unwrap()
    }

    fn lookup(token: &str) -> Option<PaneSource> {
        match token {
            "sess_web" => Some(src("web01", "", "v1")),
            "sess_db" => Some(src("db01", "", "v1")),
            "rdp_win" => Some(src("rdp-win01", "", "v1")),
            "sess_other_vault" => Some(src("web01", "", "v2")),
            _ => None,
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("bv-layouts-test-{}-{nanos}-{name}", std::process::id())).join(FILE_NAME)
    }

    #[test]
    fn a_skeleton_carries_targets_and_shape_but_never_a_token() {
        let i = input(serde_json::json!({ "tabs": [
            { "root": { "kind": "split", "dir": "row", "ratio": 0.3,
                        "a": { "kind": "pane", "token": "sess_web" },
                        "b": { "kind": "split", "dir": "col", "ratio": 0.5,
                               "a": { "kind": "pane", "token": "sess_db" },
                               "b": { "kind": "pane", "token": "rdp_win" } } } },
            { "root": { "kind": "pane", "token": "sess_db" } }
        ]}));
        let (vault, layout) = build_saved_layout(&i, lookup, "2026-10-07T00:00:00Z".into()).unwrap().unwrap();
        assert_eq!(vault, "v1");
        assert_eq!(layout.tabs.len(), 2);
        let names: Vec<&str> = panes(&layout).iter().map(|p| p.resource_name.as_str()).collect();
        assert_eq!(names, vec!["web01", "db01", "rdp-win01", "db01"]);
        assert_eq!(panes(&layout)[2].protocol, PaneProtocol::Rdp);
        match &layout.tabs[0].root {
            SavedNode::Split { dir, ratio, .. } => {
                assert_eq!(*dir, SplitDir::Row);
                assert!((ratio - 0.3).abs() < 1e-9);
            }
            other => panic!("{other:?}"),
        }
        let json = serde_json::to_string(&layout).unwrap();
        assert!(!json.contains("sess_") && !json.contains("rdp_win") && !json.contains("token"), "{json}");
    }

    /// A pane whose session is gone collapses its split; a tab left empty
    /// goes; nothing left at all saves nothing.
    #[test]
    fn unknown_tokens_collapse_and_an_empty_result_saves_nothing() {
        let i = input(serde_json::json!({ "tabs": [
            { "root": { "kind": "split", "dir": "row", "ratio": 0.5,
                        "a": { "kind": "pane", "token": "sess_gone" },
                        "b": { "kind": "pane", "token": "sess_web" } } },
            { "root": { "kind": "pane", "token": "sess_gone_too" } }
        ]}));
        let (_, layout) = build_saved_layout(&i, lookup, String::new()).unwrap().unwrap();
        assert_eq!(layout.tabs.len(), 1);
        assert!(matches!(&layout.tabs[0].root, SavedNode::Pane(p) if p.resource_name == "web01"));

        let none = input(serde_json::json!({ "tabs": [{ "root": { "kind": "pane", "token": "sess_gone" } }] }));
        assert_eq!(build_saved_layout(&none, lookup, String::new()).unwrap(), None);
        assert_eq!(build_saved_layout(&input(serde_json::json!({ "tabs": [] })), lookup, String::new()).unwrap(), None);
    }

    #[test]
    fn a_layout_spanning_two_vaults_is_refused() {
        let i = input(serde_json::json!({ "tabs": [
            { "root": { "kind": "pane", "token": "sess_web" } },
            { "root": { "kind": "pane", "token": "sess_other_vault" } }
        ]}));
        let err = build_saved_layout(&i, lookup, String::new()).unwrap_err();
        assert!(err.contains("more than one vault") && err.contains("`v1`") && err.contains("`v2`"), "{err}");
    }

    #[test]
    fn ratios_are_clamped_and_bounds_enforced() {
        let i = input(serde_json::json!({ "tabs": [
            { "root": { "kind": "split", "dir": "col", "ratio": 7.0,
                        "a": { "kind": "pane", "token": "sess_web" },
                        "b": { "kind": "pane", "token": "sess_db" } } }
        ]}));
        let (_, layout) = build_saved_layout(&i, lookup, String::new()).unwrap().unwrap();
        assert!(matches!(layout.tabs[0].root, SavedNode::Split { ratio, .. } if ratio == MAX_RATIO));

        let many = LayoutInput {
            tabs: (0..=MAX_TABS).map(|_| TabInput { root: NodeInput::Pane { token: "sess_web".into() } }).collect(),
        };
        assert!(build_saved_layout(&many, lookup, String::new()).unwrap_err().contains("tabs"));

        let mut deep = NodeInput::Pane { token: "sess_web".into() };
        for _ in 0..=MAX_DEPTH {
            deep = NodeInput::Split {
                dir: SplitDir::Row,
                ratio: 0.5,
                a: Box::new(deep),
                b: Box::new(NodeInput::Pane { token: "sess_db".into() }),
            };
        }
        let deep = LayoutInput { tabs: vec![TabInput { root: deep }] };
        assert!(build_saved_layout(&deep, lookup, String::new()).unwrap_err().contains("deeper"));
    }

    /// A hand-edited file is checked on read too.
    #[test]
    fn validation_refuses_malformed_saved_layouts() {
        let pane = |name: &str| {
            SavedNode::Pane(SavedPane {
                resource_name: name.into(),
                profile_id: "cp".into(),
                protocol: PaneProtocol::Ssh,
                namespace: String::new(),
            })
        };
        assert!(validate_saved(&SavedLayout { saved_at: String::new(), tabs: vec![] }).is_err());
        assert!(
            validate_saved(&SavedLayout { saved_at: String::new(), tabs: vec![SavedTab { root: pane("") }] }).is_err()
        );
        assert!(validate_saved(&SavedLayout {
            saved_at: String::new(),
            tabs: vec![SavedTab { root: pane("web\u{1b}[31m") }]
        })
        .is_err());
        let bad_ratio =
            SavedNode::Split { dir: SplitDir::Row, ratio: 0.01, a: Box::new(pane("a")), b: Box::new(pane("b")) };
        assert!(
            validate_saved(&SavedLayout { saved_at: String::new(), tabs: vec![SavedTab { root: bad_ratio }] }).is_err()
        );
        assert!(
            validate_saved(&SavedLayout { saved_at: String::new(), tabs: vec![SavedTab { root: pane("ok") }] }).is_ok()
        );
    }

    /// The spec's rule: a pane saved in one namespace is not opened in
    /// another, and the refusal names both.
    #[test]
    fn a_restore_into_another_namespace_is_refused_naming_both() {
        assert!(check_restore_namespace("tenant-a", "tenant-a").is_ok());
        assert!(check_restore_namespace("/tenant-a/", "tenant-a").is_ok());
        assert!(check_restore_namespace("", "").is_ok());
        let err = check_restore_namespace("tenant-a", "tenant-b").unwrap_err();
        assert!(err.contains("`tenant-a`") && err.contains("`tenant-b`"), "{err}");
        let err = check_restore_namespace("tenant-a", "").unwrap_err();
        assert!(err.contains("`tenant-a`") && err.contains("root"), "{err}");
    }

    #[test]
    fn pane_refs_are_short_opaque_ids() {
        for ok in ["r1", "p12_restore", "a-b"] {
            assert!(pane_ref_ok(ok), "{ok}");
        }
        for bad in ["", "r 1", "r/1", "sess_..", &"r".repeat(33), "r\u{0}"] {
            assert!(!pane_ref_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_file_round_trips_per_vault_and_forgets() {
        let path = temp_path("roundtrip");
        assert_eq!(get_at(&path, "v1").unwrap(), None);
        let i = input(serde_json::json!({ "tabs": [{ "root": { "kind": "pane", "token": "sess_web" } }] }));
        let (vault, layout) = build_saved_layout(&i, lookup, "t".into()).unwrap().unwrap();
        save_at(&path, &vault, layout.clone()).unwrap();
        assert_eq!(get_at(&path, "v1").unwrap(), Some(layout));
        assert_eq!(get_at(&path, "v2").unwrap(), None);
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], LAYOUT_FILE_VERSION);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(forget_at(&path, "v1").unwrap());
        assert!(!forget_at(&path, "v1").unwrap());
        assert_eq!(get_at(&path, "v1").unwrap(), None);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A file written by another format version is neither read nor
    /// overwritten.
    #[test]
    fn another_format_version_is_refused_and_left_untouched() {
        let path = temp_path("version");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let future = r#"{ "version": 2, "layouts": { "v1": { "something": "new" } } }"#;
        std::fs::write(&path, future).unwrap();
        let err = get_at(&path, "v1").unwrap_err();
        assert!(err.contains("version 2"), "{err}");
        let i = input(serde_json::json!({ "tabs": [{ "root": { "kind": "pane", "token": "sess_web" } }] }));
        let (vault, layout) = build_saved_layout(&i, lookup, "t".into()).unwrap().unwrap();
        assert!(save_at(&path, &vault, layout).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), future);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
