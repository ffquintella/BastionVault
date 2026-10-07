/**
 * Multi-line paste guard for terminal panes (T38 Phase 4,
 * features/session-workspace.md §Scope).
 *
 * A paste that contains a line break runs commands the moment it lands in
 * a shell — and with six visible production shells, the one it lands in
 * may not be the one the operator meant. Such a paste is held until the
 * operator confirms it, naming the target. Single-line pastes pass
 * through untouched. On by default; `confirm_multiline_paste` in the
 * session-workspace preferences turns it off.
 */

/** Lines and characters shown in the confirmation. */
export const PREVIEW_LINES = 5;
export const PREVIEW_LINE_CHARS = 200;

/** True when `text` would execute on paste: it holds a CR or LF. A single
 *  command with a trailing newline counts — it runs on arrival too. */
export function needsPasteConfirmation(text: string): boolean {
  return /[\r\n]/.test(text);
}

export interface PasteSummary {
  /** Number of lines, counting a final unterminated one. */
  lines: number;
  chars: number;
  /** The first few lines, each cut to a fixed width — enough to spot the
   *  wrong clipboard, not a full copy. Rendered as text, never HTML. */
  preview: string[];
  /** Lines beyond the preview. */
  more: number;
}

export function summarisePaste(text: string): PasteSummary {
  const all = text.replace(/\r\n?/g, "\n").split("\n");
  if (all.length > 1 && all[all.length - 1] === "") all.pop();
  const preview = all
    .slice(0, PREVIEW_LINES)
    .map((l) => (l.length > PREVIEW_LINE_CHARS ? `${l.slice(0, PREVIEW_LINE_CHARS)}…` : l));
  return { lines: all.length, chars: text.length, preview, more: Math.max(0, all.length - PREVIEW_LINES) };
}
