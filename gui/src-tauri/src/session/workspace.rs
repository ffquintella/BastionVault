//! Session layout: where a Resource Connect session is rendered
//! (features/session-workspace.md, T38).
//!
//! Placement decides *where* a session is drawn, never *whether* it may
//! open: every open still goes through the same resolver, connect gate,
//! transport tier and MFA ticket check. That is why it is resolved first
//! in `session_open_{ssh,rdp}` — a placement this build cannot honour is
//! refused before anything is resolved or dialled.
//!
//! Every value here is parsed strictly. An unknown placement or layout mode
//! is an error naming the value, not a fallback: the two layout modes have
//! different isolation properties (one webview per session vs. a shared
//! workspace realm), so guessing between them is not a UX detail.

use serde::{Deserialize, Serialize};

use crate::preferences::SessionWorkspacePrefs;

/// Label of the singleton Session Workspace window (Phase 3).
pub const WORKSPACE_WINDOW_LABEL: &str = "session-workspace";

/// Route the workspace window loads (`HashRouter` fragment).
pub const WORKSPACE_WINDOW_URL: &str = "index.html#/workspace";

/// Event the host sends the workspace window when a session has been
/// registered as attached to it. It carries **no payload**: a Tauri
/// `listen()` registered with the default `Any` target receives an
/// `emit_to` event in every webview, so anything in the payload — a token
/// above all — would reach every webview that subscribes to the name. The
/// workspace answers it by calling `session_list_open`, which only `main`
/// and the workspace may call.
pub const PLACED_EVENT: &str = "session://placed";

/// macOS native window-tab group for per-session windows in `windows`
/// layout mode (Phase 0). Distinct from the main window, which carries no
/// identifier, so a session window is never merged into the admin window.
pub const SESSION_TABBING_IDENTIFIER: &str = "bv-session";

/// Whether this build ships the Session Workspace window (T38 Phase 3:
/// the `/workspace` route, its capability entry and the
/// `session://placed` hand-off). Kept as a constant so the refusal path
/// below stays tested and can be switched back on for a build that has to
/// ship without the window.
pub const WORKSPACE_WINDOW_AVAILABLE: bool = true;

/// Where an open request asks for its session to be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Placement {
    /// A new tab in the Session Workspace window.
    WorkspaceTab,
    /// Split the workspace's focused pane; the new session on the right.
    WorkspaceSplitRight,
    /// Split the workspace's focused pane; the new session below.
    WorkspaceSplitDown,
    /// A dedicated `WebviewWindow` for this session — the pre-T38 model.
    OwnWindow,
}

impl Placement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceTab => "workspace-tab",
            Self::WorkspaceSplitRight => "workspace-split-right",
            Self::WorkspaceSplitDown => "workspace-split-down",
            Self::OwnWindow => "own-window",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "workspace-tab" => Ok(Self::WorkspaceTab),
            "workspace-split-right" => Ok(Self::WorkspaceSplitRight),
            "workspace-split-down" => Ok(Self::WorkspaceSplitDown),
            "own-window" => Ok(Self::OwnWindow),
            other => Err(format!(
                "unknown session placement `{other}` (expected own-window, workspace-tab, workspace-split-right \
                 or workspace-split-down)"
            )),
        }
    }

    pub fn is_workspace(self) -> bool {
        !matches!(self, Self::OwnWindow)
    }
}

/// The operator's layout mode preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// Sessions may share the Session Workspace window.
    Workspace,
    /// One `WebviewWindow` per session, always; native tabs on macOS.
    Windows,
}

impl LayoutMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "workspace" => Ok(Self::Workspace),
            "windows" => Ok(Self::Windows),
            other => Err(format!("unknown session layout mode `{other}` (expected workspace or windows)")),
        }
    }
}

/// Most chord overrides a preferences file may carry. The reserved-chord
/// table has a few dozen actions; anything far past that is not a file
/// the GUI wrote.
pub const MAX_CHORD_OVERRIDES: usize = 64;
/// Longest action id / chord string accepted in an override.
pub const MAX_CHORD_TEXT: usize = 64;

/// Validate a preferences value before it is written. Refuses anything a
/// later open could not honour, so a GUI-written file never makes every
/// Connect fail.
///
/// Chord overrides are checked for shape only (bounded count and length,
/// printable ASCII). What a chord *means* — which actions exist, how a
/// chord string parses, whether two actions collide or one shadows a
/// terminal control character — is owned by the reserved-chord table in
/// `gui/src/lib/reservedChords.ts`, which refuses such an override before
/// it is saved and ignores (and names) one a hand-edited file carries.
/// Duplicating that table here would let the two drift.
pub fn validate_prefs(prefs: &SessionWorkspacePrefs) -> Result<(), String> {
    LayoutMode::parse(&prefs.layout_mode)?;
    let default = Placement::parse(&prefs.default_placement)?;
    if default.is_workspace() && !WORKSPACE_WINDOW_AVAILABLE {
        return Err(workspace_unavailable(default));
    }
    if prefs.chord_overrides.len() > MAX_CHORD_OVERRIDES {
        return Err(format!(
            "too many chord overrides ({}; at most {MAX_CHORD_OVERRIDES})",
            prefs.chord_overrides.len()
        ));
    }
    for (action, chord) in &prefs.chord_overrides {
        let action_ok = !action.is_empty()
            && action.len() <= MAX_CHORD_TEXT
            && action.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !action_ok {
            return Err(format!("chord override has an invalid action id `{}`", action.escape_debug()));
        }
        let chord_ok =
            !chord.is_empty() && chord.len() <= MAX_CHORD_TEXT && chord.chars().all(|c| c.is_ascii_graphic());
        if !chord_ok {
            return Err(format!("chord override for `{action}` is not a chord: `{}`", chord.escape_debug()));
        }
    }
    Ok(())
}

/// The placement an open request resolves to.
///
/// * An explicit placement wins, except that `windows` layout mode refuses
///   a `workspace-*` one: the operator chose per-session webview isolation,
///   and no caller gets to pool a session into a shared realm past that.
/// * An absent placement takes the preference default (`workspace-tab`
///   unless the operator chose otherwise); in `windows` mode that is
///   always `own-window`.
/// * A `workspace-*` result is refused in a build without the workspace
///   window ([`WORKSPACE_WINDOW_AVAILABLE`]).
pub fn resolve_placement(requested: Option<Placement>, prefs: &SessionWorkspacePrefs) -> Result<Placement, String> {
    let mode = LayoutMode::parse(&prefs.layout_mode).map_err(|e| format!("preferences: {e}"))?;
    let placement = match (requested, mode) {
        (Some(p), LayoutMode::Windows) if p.is_workspace() => {
            return Err(format!(
                "session placement `{}` refused: the session layout mode is `windows`, so every session opens in its \
                 own window (Settings → General → Session layout)",
                p.as_str()
            ))
        }
        (Some(p), _) => p,
        (None, LayoutMode::Windows) => Placement::OwnWindow,
        (None, LayoutMode::Workspace) => {
            Placement::parse(&prefs.default_placement).map_err(|e| format!("preferences: default {e}"))?
        }
    };
    if placement.is_workspace() && !WORKSPACE_WINDOW_AVAILABLE {
        return Err(workspace_unavailable(placement));
    }
    Ok(placement)
}

fn workspace_unavailable(placement: Placement) -> String {
    format!(
        "session placement `{}` is not available in this build: it ships without the Session Workspace window; \
         use `own-window`",
        placement.as_str()
    )
}

/// Whether a per-session window should join the macOS native tab group.
/// Only in `windows` mode (Phase 0); an unreadable mode joins nothing.
pub fn wants_native_tabs(prefs: &SessionWorkspacePrefs) -> bool {
    matches!(LayoutMode::parse(&prefs.layout_mode), Ok(LayoutMode::Windows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs(mode: &str, default: &str) -> SessionWorkspacePrefs {
        SessionWorkspacePrefs { layout_mode: mode.into(), default_placement: default.into(), ..Default::default() }
    }

    #[test]
    fn placement_wire_values_round_trip_and_unknown_is_refused() {
        for p in [
            Placement::WorkspaceTab,
            Placement::WorkspaceSplitRight,
            Placement::WorkspaceSplitDown,
            Placement::OwnWindow,
        ] {
            assert_eq!(Placement::parse(p.as_str()), Ok(p));
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.as_str()));
            assert_eq!(serde_json::from_str::<Placement>(&json).unwrap(), p);
        }
        for bad in ["", "own_window", "OwnWindow", "workspace", "tab"] {
            assert!(Placement::parse(bad).is_err(), "{bad}");
            assert!(serde_json::from_str::<Placement>(&format!("\"{bad}\"")).is_err(), "{bad}");
        }
    }

    /// Phase 3 flipped the default: a caller that sends no placement gets
    /// a workspace tab, unless the operator chose own windows — by the
    /// default placement or by the `windows` layout mode.
    #[test]
    fn absent_placement_takes_the_preference_default() {
        assert_eq!(SessionWorkspacePrefs::default().default_placement, "workspace-tab");
        assert_eq!(resolve_placement(None, &SessionWorkspacePrefs::default()), Ok(Placement::WorkspaceTab));
        assert_eq!(resolve_placement(None, &prefs("workspace", "own-window")), Ok(Placement::OwnWindow));
        assert_eq!(
            resolve_placement(None, &prefs("workspace", "workspace-split-down")),
            Ok(Placement::WorkspaceSplitDown)
        );
        assert_eq!(resolve_placement(None, &prefs("windows", "own-window")), Ok(Placement::OwnWindow));
        // `windows` mode ignores the default entirely.
        assert_eq!(resolve_placement(None, &prefs("windows", "workspace-tab")), Ok(Placement::OwnWindow));
    }

    #[test]
    fn explicit_workspace_placements_are_honoured_in_workspace_mode() {
        const { assert!(WORKSPACE_WINDOW_AVAILABLE) };
        for p in [Placement::WorkspaceTab, Placement::WorkspaceSplitRight, Placement::WorkspaceSplitDown] {
            assert_eq!(resolve_placement(Some(p), &prefs("workspace", "own-window")), Ok(p));
        }
    }

    #[test]
    fn explicit_own_window_is_honoured_in_both_modes() {
        assert_eq!(
            resolve_placement(Some(Placement::OwnWindow), &prefs("workspace", "own-window")),
            Ok(Placement::OwnWindow)
        );
        assert_eq!(
            resolve_placement(Some(Placement::OwnWindow), &prefs("windows", "own-window")),
            Ok(Placement::OwnWindow)
        );
    }

    /// `windows` mode is the operator's isolation choice; an explicit
    /// workspace placement is refused, and the message says why.
    #[test]
    fn windows_mode_refuses_workspace_placements() {
        for p in [Placement::WorkspaceTab, Placement::WorkspaceSplitRight, Placement::WorkspaceSplitDown] {
            let err = resolve_placement(Some(p), &prefs("windows", "own-window")).unwrap_err();
            assert!(err.contains("layout mode is `windows`"), "{err}");
            assert!(err.contains(p.as_str()), "{err}");
        }
    }

    /// The refusal a build without the window gives, kept honest even
    /// though this build ships it.
    #[test]
    fn the_unavailable_message_names_the_placement_and_the_way_out() {
        let err = workspace_unavailable(Placement::WorkspaceSplitDown);
        assert!(err.contains("workspace-split-down"), "{err}");
        assert!(err.contains("own-window"), "{err}");
    }

    #[test]
    fn unreadable_preferences_are_named_not_guessed() {
        let err = resolve_placement(None, &prefs("tiles", "own-window")).unwrap_err();
        assert!(err.contains("`tiles`"), "{err}");
        let err = resolve_placement(None, &prefs("workspace", "floating")).unwrap_err();
        assert!(err.contains("`floating`"), "{err}");
        // An explicit placement does not paper over a broken mode either.
        assert!(resolve_placement(Some(Placement::OwnWindow), &prefs("tiles", "own-window")).is_err());
    }

    #[test]
    fn validate_refuses_what_an_open_could_not_honour() {
        assert!(validate_prefs(&SessionWorkspacePrefs::default()).is_ok());
        assert!(validate_prefs(&prefs("windows", "own-window")).is_ok());
        assert!(validate_prefs(&prefs("workspace", "workspace-tab")).is_ok());
        assert!(validate_prefs(&prefs("workspace", "workspace-split-right")).is_ok());
        assert!(validate_prefs(&prefs("tiles", "own-window")).is_err());
        assert!(validate_prefs(&prefs("workspace", "nowhere")).is_err());
    }

    /// Chord overrides are checked for shape here; meaning is the
    /// frontend table's job.
    #[test]
    fn validate_bounds_chord_overrides() {
        let mut p = SessionWorkspacePrefs::default();
        p.chord_overrides.insert("splitRight".into(), "Ctrl+Shift+R".into());
        assert!(validate_prefs(&p).is_ok());

        for (action, chord) in [
            ("", "Ctrl+Shift+R"),
            ("split right", "Ctrl+Shift+R"),
            ("splitRight", ""),
            ("splitRight", "Ctrl + Shift + R"),
            ("splitRight", "Ctrl+Shift+\u{7}"),
        ] {
            let mut bad = SessionWorkspacePrefs::default();
            bad.chord_overrides.insert(action.into(), chord.into());
            assert!(validate_prefs(&bad).is_err(), "{action:?} => {chord:?}");
        }
        let mut long = SessionWorkspacePrefs::default();
        long.chord_overrides.insert("a".repeat(MAX_CHORD_TEXT + 1), "Ctrl+Shift+R".into());
        assert!(validate_prefs(&long).is_err());

        let mut many = SessionWorkspacePrefs::default();
        for i in 0..=MAX_CHORD_OVERRIDES {
            many.chord_overrides.insert(format!("a{i}"), "Ctrl+Shift+R".into());
        }
        assert!(validate_prefs(&many).unwrap_err().contains("too many"));
    }

    #[test]
    fn native_tabs_only_in_windows_mode() {
        assert!(wants_native_tabs(&prefs("windows", "own-window")));
        assert!(!wants_native_tabs(&prefs("workspace", "own-window")));
        assert!(!wants_native_tabs(&prefs("tiles", "own-window")));
    }
}
