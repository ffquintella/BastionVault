/**
 * Settings → General → Session keyboard & paste (T38 Phase 4,
 * features/session-workspace.md §4).
 *
 * The operator-visible list of the workspace's reserved chords — the one
 * table both the terminal and the RDP pane consult before forwarding a
 * key — with an override per action, and the multi-line paste guard.
 *
 * An override is checked before it can be saved: it must parse, must not
 * be a key the remote shell needs (a C0 control character such as Ctrl+C,
 * or a readline Meta key), must not be a chord the app or the OS already
 * owns, and must not collide with another action. Overrides already in the
 * file that fail those checks (a hand edit) are listed as not applied.
 */

import { useEffect, useMemo, useState } from "react";

import { Card, useToast } from "./ui";
import { extractError } from "../lib/error";
import {
  RESERVED_CHORDS,
  detectPlatform,
  effectiveBindings,
  formatChord,
  parseChord,
  setChordOverrides,
  validateOverrides,
  type WorkspaceAction,
} from "../lib/reservedChords";
import { useSessionPrefsStore } from "../stores/sessionPrefsStore";

export function SessionKeyboardCard() {
  const { toast } = useToast();
  const platform = useMemo(() => detectPlatform(), []);
  const prefs = useSessionPrefsStore((s) => s.prefs);
  const loadError = useSessionPrefsStore((s) => s.loadError);
  const load = useSessionPrefsStore((s) => s.load);
  const update = useSessionPrefsStore((s) => s.update);
  const [draft, setDraft] = useState<Partial<Record<WorkspaceAction, string>>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void load();
  }, [load]);

  const stored = prefs?.chord_overrides;
  useEffect(() => {
    if (!stored) return;
    const next: Partial<Record<WorkspaceAction, string>> = {};
    for (const row of RESERVED_CHORDS) if (stored[row.action]) next[row.action] = stored[row.action];
    setDraft(next);
  }, [stored]);

  const storedProblems = useMemo(() => effectiveBindings(platform, stored ?? {}).problems, [platform, stored]);
  const validation = useMemo(() => validateOverrides(platform, draft), [platform, draft]);
  const hasErrors = Object.keys(validation.errors).length > 0;
  const dirty = useMemo(() => {
    const a = JSON.stringify(Object.entries(validation.normalized).sort());
    const b = JSON.stringify(Object.entries(stored ?? {}).sort());
    return a !== b;
  }, [validation.normalized, stored]);

  async function saveChords() {
    setSaving(true);
    try {
      await update({ chord_overrides: validation.normalized });
      // This window's own bindings; session windows read theirs on open.
      setChordOverrides(validation.normalized);
      toast("success", "Session chords saved. Session windows opened from now on use them.");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  async function savePasteGuard(on: boolean) {
    setSaving(true);
    try {
      await update({ confirm_multiline_paste: on });
      toast(
        "success",
        on
          ? "Multi-line paste confirmation is on."
          : "Multi-line paste confirmation is off. A paste with line breaks now runs as it arrives.",
      );
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card title="Session keyboard & paste">
      {loadError ? (
        <p className="text-sm text-[var(--color-danger)] break-words">{loadError}</p>
      ) : !prefs ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : (
        <fieldset className="space-y-4" disabled={saving}>
          <legend className="sr-only">Session keyboard and paste</legend>
          <label className="flex items-start gap-3 cursor-pointer min-w-0">
            <input
              type="checkbox"
              checked={prefs.confirm_multiline_paste}
              onChange={(e) => void savePasteGuard(e.target.checked)}
              className="mt-1 accent-[var(--color-primary)]"
            />
            <span className="min-w-0">
              <span className="block text-sm font-medium text-[var(--color-text)]">
                Ask before pasting text with line breaks into a terminal
              </span>
              <span className="block text-xs text-[var(--color-text-muted)]">
                Each line break runs a command. The confirmation names the session the paste would go to.
              </span>
            </span>
          </label>

          <div className="min-w-0">
            <p className="text-sm font-medium text-[var(--color-text)]">Workspace chords</p>
            <p className="text-xs text-[var(--color-text-muted)]">
              These keys belong to the session workspace and are never sent to a remote host, in a terminal or an
              RDP desktop. Leave an override empty to keep the default. Keys a remote shell needs (Ctrl+C, Ctrl+D,
              Ctrl+Z, Alt+B, …) cannot be chosen.
            </p>
          </div>

          {storedProblems.length > 0 && (
            <div role="alert" className="text-xs text-[var(--color-danger)] space-y-1">
              {storedProblems.map((p) => (
                <p key={`${p.action}:${p.value}`} className="break-words">
                  Not applied: {p.action} = {p.value} — {p.reason}. The default is in force.
                </p>
              ))}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-[var(--color-text-muted)]">
                  <th className="py-1 pr-3 font-medium">Action</th>
                  <th className="py-1 pr-3 font-medium">Default</th>
                  <th className="py-1 font-medium">Override</th>
                </tr>
              </thead>
              <tbody>
                {RESERVED_CHORDS.map((row) => {
                  const def = parseChord(platform === "mac" ? row.mac : row.other)!;
                  const error = validation.errors[row.action];
                  return (
                    <tr key={row.action} className="align-top border-t border-[var(--color-border)]">
                      <td className="py-1 pr-3 min-w-0">{row.label}</td>
                      <td className="py-1 pr-3 font-mono whitespace-nowrap">{formatChord(def, platform)}</td>
                      <td className="py-1 min-w-0">
                        <input
                          aria-label={`Override for ${row.label}`}
                          value={draft[row.action] ?? ""}
                          placeholder="default"
                          onChange={(e) => setDraft((d) => ({ ...d, [row.action]: e.target.value }))}
                          className="w-full min-w-0 rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-0.5 font-mono text-sm"
                        />
                        {error && <p className="text-xs text-[var(--color-danger)] break-words">{error}</p>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={() => setDraft({})}
              className="rounded border border-[var(--color-border)] px-3 py-1 text-sm"
            >
              Reset all to defaults
            </button>
            <button
              type="button"
              onClick={() => void saveChords()}
              disabled={hasErrors || !dirty}
              className="rounded bg-[var(--color-primary)] px-3 py-1 text-sm text-white disabled:opacity-50"
            >
              Save chords
            </button>
          </div>
        </fieldset>
      )}
    </Card>
  );
}
