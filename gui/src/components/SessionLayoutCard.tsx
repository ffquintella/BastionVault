/**
 * Settings → General → Session layout (T38, features/session-workspace.md).
 *
 * Chooses between the two layout modes, and — in workspace mode — where a
 * new session opens. The modes differ in isolation, not just looks:
 * `windows` keeps one window — and one webview realm — per session;
 * `workspace` puts sessions in tabs and splits of one shared window. The
 * copy says which is which.
 *
 * Also here (T38 Phases 5–6): opening the workspace on its own — whose
 * empty state offers to restore the last layout — forgetting the saved
 * layout, and the opt-in output replay buffer for moving sessions.
 */

import { useEffect, useState } from "react";

import { Card, useToast } from "./ui";
import {
  sessionLayoutForget,
  sessionWorkspaceOpen,
  type SessionLayoutMode,
  type SessionPlacement,
} from "../lib/api";
import { extractError } from "../lib/error";
import { useSessionPrefsStore } from "../stores/sessionPrefsStore";

const OPTIONS: { mode: SessionLayoutMode; title: string; detail: string }[] = [
  {
    mode: "workspace",
    title: "Session workspace",
    detail:
      "Sessions open as tabs and splits in one Session Workspace window. They share that window's webview, so a compromised page in one pane could read another pane's screen.",
  },
  {
    mode: "windows",
    title: "Separate windows",
    detail:
      "Every session keeps its own window and its own webview, the most isolated layout. On macOS, session windows group as native window tabs (by your “Prefer tabs” system setting, or Window → Merge All Windows).",
  },
];

const PLACEMENTS: { value: SessionPlacement; label: string }[] = [
  { value: "workspace-tab", label: "A new tab in the workspace" },
  { value: "workspace-split-right", label: "A split to the right of the focused pane" },
  { value: "workspace-split-down", label: "A split below the focused pane" },
  { value: "own-window", label: "Its own window" },
];

export function SessionLayoutCard() {
  const { toast } = useToast();
  const prefs = useSessionPrefsStore((s) => s.prefs);
  const loadError = useSessionPrefsStore((s) => s.loadError);
  const load = useSessionPrefsStore((s) => s.load);
  const update = useSessionPrefsStore((s) => s.update);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(patch: {
    layout_mode?: SessionLayoutMode;
    default_placement?: SessionPlacement;
    replay_buffer?: boolean;
  }) {
    setSaving(true);
    try {
      await update(patch);
      toast("success", "Session layout saved. It applies to sessions you open from now on.");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card title="Session layout">
      {loadError ? (
        <p className="text-sm text-[var(--color-danger)] break-words">{loadError}</p>
      ) : !prefs ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : (
        <fieldset className="space-y-3" disabled={saving}>
          <legend className="sr-only">Session layout</legend>
          {OPTIONS.map((o) => (
            <label key={o.mode} className="flex items-start gap-3 cursor-pointer min-w-0">
              <input
                type="radio"
                name="session-layout-mode"
                value={o.mode}
                checked={prefs.layout_mode === o.mode}
                onChange={() => {
                  if (prefs.layout_mode !== o.mode) void save({ layout_mode: o.mode });
                }}
                className="mt-1 accent-[var(--color-primary)]"
              />
              <span className="min-w-0">
                <span className="block text-sm font-medium text-[var(--color-text)]">{o.title}</span>
                <span className="block text-xs text-[var(--color-text-muted)]">{o.detail}</span>
              </span>
            </label>
          ))}
          {prefs.layout_mode === "workspace" && (
            <div className="grid grid-cols-2 gap-3">
              <label className="col-span-2 min-w-0 text-sm">
                <span className="block font-medium text-[var(--color-text)]">A new session opens in</span>
                <select
                  value={prefs.default_placement}
                  onChange={(e) => void save({ default_placement: e.target.value as SessionPlacement })}
                  className="mt-1 w-full min-w-0 rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-sm"
                >
                  {PLACEMENTS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}
          {prefs.layout_mode === "workspace" && (
            <>
              <label className="flex items-start gap-3 cursor-pointer min-w-0">
                <input
                  type="checkbox"
                  checked={prefs.replay_buffer}
                  onChange={(e) => void save({ replay_buffer: e.target.checked })}
                  className="mt-1 accent-[var(--color-primary)]"
                />
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-[var(--color-text)]">
                    Keep recent terminal output
                  </span>
                  <span className="block text-xs text-[var(--color-text-muted)]">
                    Holds the last 256 KiB of each SSH session&apos;s output in this app&apos;s memory, so a session you
                    move between the workspace and its own window redraws it. That output can include anything you
                    printed, secrets too; it is never written to disk and is wiped when the session closes. Off: a
                    moved session starts with an empty screen.
                  </span>
                </span>
              </label>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => void sessionWorkspaceOpen().catch((e: unknown) => toast("error", extractError(e)))}
                  className="rounded border border-[var(--color-border)] px-3 py-1 text-sm"
                >
                  Open the Session Workspace
                </button>
                <button
                  type="button"
                  onClick={() =>
                    void sessionLayoutForget().then(
                      (had) =>
                        toast("success", had ? "Saved session layout forgotten." : "There was no saved session layout."),
                      (e: unknown) => toast("error", extractError(e)),
                    )
                  }
                  className="rounded border border-[var(--color-border)] px-3 py-1 text-sm"
                >
                  Forget the saved layout
                </button>
              </div>
              <p className="text-xs text-[var(--color-text-muted)]">
                The workspace remembers its last layout for this vault — which resources and profiles, never a
                credential or session output — and offers to restore it, re-connecting each session through the
                normal connect path.
              </p>
            </>
          )}
        </fieldset>
      )}
    </Card>
  );
}
