/**
 * The Session Workspace's reserved chords (T38 Phase 4,
 * features/session-workspace.md §4) — the only place a workspace chord is
 * defined.
 *
 * Two consumers read it: the SSH pane's xterm
 * `attachCustomKeyEventHandler` and the RDP pane's keydown filter. Both
 * ask {@link matchChord} before forwarding a key, so a chord the workspace
 * owns is never typed into a remote host — in a terminal pane, in a
 * Windows desktop, or in a session's own window. Deriving both from this
 * one table is what stops a chord working in one pane type and silently
 * reaching the remote host in the other.
 *
 * Chords match on `KeyboardEvent.code` (the physical key) plus the four
 * modifiers, never on `key`: `code` is what the RDP pane forwards as a
 * scancode, and it does not change with Shift or Option. On a non-QWERTY
 * layout a letter chord is the key in the QWERTY position.
 *
 * `Ctrl` with a plain key belongs to the remote shell: every chord that
 * produces a C0 control character, or that readline reads as a Meta key,
 * is in {@link TERMINAL_CHORDS} and can be neither a default nor an
 * override.
 */

export type ChordPlatform = "mac" | "other";

export type WorkspaceAction =
  | "newTab"
  | "closePane"
  | "splitRight"
  | "splitDown"
  | "focusLeft"
  | "focusRight"
  | "focusUp"
  | "focusDown"
  | "resizeLeft"
  | "resizeRight"
  | "resizeUp"
  | "resizeDown"
  | "toggleZoom"
  | "selectTab1"
  | "selectTab2"
  | "selectTab3"
  | "selectTab4"
  | "selectTab5"
  | "selectTab6"
  | "selectTab7"
  | "selectTab8"
  | "selectTab9"
  | "prevTab"
  | "nextTab"
  | "releaseKeyboard";

export interface Chord {
  meta: boolean;
  ctrl: boolean;
  alt: boolean;
  shift: boolean;
  /** `KeyboardEvent.code`, e.g. `KeyD`, `Digit1`, `ArrowLeft`. */
  code: string;
}

export interface ReservedChord {
  action: WorkspaceAction;
  label: string;
  /** Default binding on macOS, in the canonical string form. */
  mac: string;
  /** Default binding on Linux and Windows. */
  other: string;
}

const tabSelect = (n: number): ReservedChord => ({
  action: `selectTab${n}` as WorkspaceAction,
  label: `Select tab ${n}`,
  mac: `Meta+Digit${n}`,
  other: `Alt+Digit${n}`,
});

/**
 * Defaults, matching Ghostty where Ghostty has an opinion. On Linux and
 * Windows the modifier is `Ctrl+Shift`, which every terminal there uses.
 *
 * Prev / next tab is `Ctrl+Shift+PageUp/PageDown` there, not the spec's
 * `Ctrl+PageUp/PageDown`: the spec's own rule is that `Ctrl` alone is never
 * bound, and full-screen terminal programs read `Ctrl+PageUp` (`CSI 5;5~`).
 */
export const RESERVED_CHORDS: readonly ReservedChord[] = [
  { action: "newTab", label: "New tab (opens the Connect palette)", mac: "Meta+KeyT", other: "Ctrl+Shift+KeyT" },
  { action: "closePane", label: "Close pane (the tab, if it is the last pane)", mac: "Meta+KeyW", other: "Ctrl+Shift+KeyW" },
  { action: "splitRight", label: "Split right (opens the Connect palette)", mac: "Meta+KeyD", other: "Ctrl+Shift+KeyE" },
  { action: "splitDown", label: "Split down (opens the Connect palette)", mac: "Meta+Shift+KeyD", other: "Ctrl+Shift+KeyO" },
  { action: "focusLeft", label: "Focus the pane to the left", mac: "Meta+Alt+ArrowLeft", other: "Ctrl+Shift+ArrowLeft" },
  { action: "focusRight", label: "Focus the pane to the right", mac: "Meta+Alt+ArrowRight", other: "Ctrl+Shift+ArrowRight" },
  { action: "focusUp", label: "Focus the pane above", mac: "Meta+Alt+ArrowUp", other: "Ctrl+Shift+ArrowUp" },
  { action: "focusDown", label: "Focus the pane below", mac: "Meta+Alt+ArrowDown", other: "Ctrl+Shift+ArrowDown" },
  { action: "resizeLeft", label: "Move the focused divider left", mac: "Meta+Ctrl+ArrowLeft", other: "Ctrl+Alt+ArrowLeft" },
  { action: "resizeRight", label: "Move the focused divider right", mac: "Meta+Ctrl+ArrowRight", other: "Ctrl+Alt+ArrowRight" },
  { action: "resizeUp", label: "Move the focused divider up", mac: "Meta+Ctrl+ArrowUp", other: "Ctrl+Alt+ArrowUp" },
  { action: "resizeDown", label: "Move the focused divider down", mac: "Meta+Ctrl+ArrowDown", other: "Ctrl+Alt+ArrowDown" },
  { action: "toggleZoom", label: "Zoom / un-zoom the focused pane", mac: "Meta+Shift+Enter", other: "Ctrl+Shift+Enter" },
  tabSelect(1),
  tabSelect(2),
  tabSelect(3),
  tabSelect(4),
  tabSelect(5),
  tabSelect(6),
  tabSelect(7),
  tabSelect(8),
  tabSelect(9),
  { action: "prevTab", label: "Previous tab", mac: "Meta+Shift+BracketLeft", other: "Ctrl+Shift+PageUp" },
  { action: "nextTab", label: "Next tab", mac: "Meta+Shift+BracketRight", other: "Ctrl+Shift+PageDown" },
  {
    action: "releaseKeyboard",
    label: "Release the keyboard from an RDP pane",
    mac: "Meta+Alt+Ctrl+KeyK",
    other: "Ctrl+Alt+Shift+KeyK",
  },
];

export const WORKSPACE_ACTIONS: readonly WorkspaceAction[] = RESERVED_CHORDS.map((c) => c.action);

export function isWorkspaceAction(value: string): value is WorkspaceAction {
  return (WORKSPACE_ACTIONS as readonly string[]).includes(value);
}

// ── Chords a remote host needs ──────────────────────────────────────

const chord = (code: string, mods: Partial<Omit<Chord, "code">> = {}): Chord => ({
  meta: false,
  ctrl: false,
  alt: false,
  shift: false,
  ...mods,
  code,
});

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");

/**
 * Chords an operator needs to reach the remote shell. A binding equal to
 * one of these is refused, default or override.
 *
 * - `Ctrl+<key>` for every key that produces a C0 control character in a
 *   terminal: `Ctrl+A`…`Ctrl+Z` (`^C`, `^D`, `^Z`, …), `Ctrl+[` (ESC),
 *   `Ctrl+\` (`^\`), `Ctrl+]`, `Ctrl+Space` / `Ctrl+2` (NUL), `Ctrl+3`…`8`,
 *   `Ctrl+-` / `Ctrl+/` (`^_`, readline undo), `Ctrl+` backquote.
 * - The shifted spellings of `^@`, `^^` and `^_` (`Ctrl+Shift+2/6/-`).
 * - `Alt+<letter>` (and `Alt+.`, `Alt+Backspace`): readline and emacs read
 *   these as Meta keys — word movement, word delete, last argument.
 */
export const TERMINAL_CHORDS: readonly { chord: Chord; why: string }[] = [
  ...LETTERS.map((l) => ({ chord: chord(`Key${l}`, { ctrl: true }), why: `control character ^${l}` })),
  { chord: chord("BracketLeft", { ctrl: true }), why: "control character ^[ (Escape)" },
  { chord: chord("Backslash", { ctrl: true }), why: "control character ^\\ (quit)" },
  { chord: chord("BracketRight", { ctrl: true }), why: "control character ^]" },
  { chord: chord("Space", { ctrl: true }), why: "control character ^@ (NUL)" },
  { chord: chord("Backquote", { ctrl: true }), why: "control character ^@ (NUL)" },
  ...[2, 3, 4, 5, 6, 7, 8].map((n) => ({
    chord: chord(`Digit${n}`, { ctrl: true }),
    why: `control character sent by Ctrl+${n}`,
  })),
  { chord: chord("Minus", { ctrl: true }), why: "control character ^_ (undo)" },
  { chord: chord("Slash", { ctrl: true }), why: "control character ^_ (undo)" },
  { chord: chord("Digit2", { ctrl: true, shift: true }), why: "control character ^@ (NUL)" },
  { chord: chord("Digit6", { ctrl: true, shift: true }), why: "control character ^^" },
  { chord: chord("Minus", { ctrl: true, shift: true }), why: "control character ^_ (undo)" },
  ...LETTERS.map((l) => ({ chord: chord(`Key${l}`, { alt: true }), why: `Meta-${l.toLowerCase()} in readline / emacs` })),
  { chord: chord("Period", { alt: true }), why: "Meta-. (last argument) in readline" },
  { chord: chord("Backspace", { alt: true }), why: "Meta-Backspace (delete word) in readline" },
];

/** Chords the app or the OS already owns, refused as overrides. */
export const APP_CHORDS: Readonly<Record<ChordPlatform, readonly { chord: Chord; why: string }[]>> = {
  mac: [
    { chord: chord("KeyK", { meta: true }), why: "opens the Connect palette" },
    { chord: chord("KeyC", { meta: true }), why: "Copy" },
    { chord: chord("KeyV", { meta: true }), why: "Paste" },
    { chord: chord("KeyX", { meta: true }), why: "Cut" },
    { chord: chord("KeyA", { meta: true }), why: "Select all" },
    { chord: chord("KeyQ", { meta: true }), why: "Quit" },
    { chord: chord("KeyH", { meta: true }), why: "Hide" },
    { chord: chord("KeyM", { meta: true }), why: "Minimise" },
    { chord: chord("Tab", { meta: true }), why: "the macOS app switcher" },
    { chord: chord("Space", { meta: true }), why: "Spotlight" },
  ],
  other: [
    { chord: chord("KeyC", { ctrl: true, shift: true }), why: "terminal Copy" },
    { chord: chord("KeyV", { ctrl: true, shift: true }), why: "terminal Paste" },
    { chord: chord("F4", { alt: true }), why: "closes the window" },
    { chord: chord("Tab", { alt: true }), why: "the window switcher" },
  ],
};

// ── Parse / format ──────────────────────────────────────────────────

const MODIFIER_ALIASES: Record<string, keyof Omit<Chord, "code">> = {
  meta: "meta",
  cmd: "meta",
  command: "meta",
  "⌘": "meta",
  super: "meta",
  win: "meta",
  ctrl: "ctrl",
  control: "ctrl",
  "⌃": "ctrl",
  alt: "alt",
  option: "alt",
  opt: "alt",
  "⌥": "alt",
  shift: "shift",
  "⇧": "shift",
};

const KEY_ALIASES: Record<string, string> = {
  enter: "Enter",
  return: "Enter",
  escape: "Escape",
  esc: "Escape",
  tab: "Tab",
  space: "Space",
  backspace: "Backspace",
  delete: "Delete",
  insert: "Insert",
  home: "Home",
  end: "End",
  pageup: "PageUp",
  pgup: "PageUp",
  pagedown: "PageDown",
  pgdn: "PageDown",
  left: "ArrowLeft",
  right: "ArrowRight",
  up: "ArrowUp",
  down: "ArrowDown",
  "[": "BracketLeft",
  "]": "BracketRight",
  "\\": "Backslash",
  "-": "Minus",
  "=": "Equal",
  ",": "Comma",
  ".": "Period",
  "/": "Slash",
  ";": "Semicolon",
  "'": "Quote",
  "`": "Backquote",
};

const NAMED_CODES = [
  "Enter",
  "Escape",
  "Tab",
  "Space",
  "Backspace",
  "Delete",
  "Insert",
  "Home",
  "End",
  "PageUp",
  "PageDown",
  "ArrowLeft",
  "ArrowRight",
  "ArrowUp",
  "ArrowDown",
  "BracketLeft",
  "BracketRight",
  "Backslash",
  "Minus",
  "Equal",
  "Comma",
  "Period",
  "Slash",
  "Semicolon",
  "Quote",
  "Backquote",
];

/** Every code a chord may use, keyed by its lower-case spelling. */
const CODES_BY_LOWER: ReadonlyMap<string, string> = new Map(
  [
    ...LETTERS.map((l) => `Key${l}`),
    ..."0123456789".split("").map((d) => `Digit${d}`),
    ...Array.from({ length: 12 }, (_, i) => `F${i + 1}`),
    ...NAMED_CODES,
  ].map((code) => [code.toLowerCase(), code]),
);

function parseKey(token: string): string | null {
  const lower = token.toLowerCase();
  if (KEY_ALIASES[lower]) return KEY_ALIASES[lower];
  if (/^[a-z]$/i.test(token)) return `Key${token.toUpperCase()}`;
  if (/^[0-9]$/.test(token)) return `Digit${token}`;
  return CODES_BY_LOWER.get(lower) ?? null;
}

/** Parse a chord string (`Ctrl+Shift+E`, `Meta+Alt+ArrowLeft`, `⌘⇧D` is
 *  not accepted — use `+`). Strict: unknown tokens, a repeated modifier or
 *  anything other than exactly one key is `null`. */
export function parseChord(text: string): Chord | null {
  const tokens = text
    .split("+")
    .map((t) => t.trim())
    .filter((t) => t !== "");
  if (tokens.length === 0) return null;
  const result: Chord = { meta: false, ctrl: false, alt: false, shift: false, code: "" };
  for (const token of tokens.slice(0, -1)) {
    const mod = MODIFIER_ALIASES[token.toLowerCase()];
    if (!mod || result[mod]) return null;
    result[mod] = true;
  }
  const key = parseKey(tokens[tokens.length - 1]);
  if (!key) return null;
  result.code = key;
  return result;
}

/** Canonical stored form: modifiers in a fixed order, then the code. */
export function chordToString(c: Chord): string {
  const parts: string[] = [];
  if (c.meta) parts.push("Meta");
  if (c.ctrl) parts.push("Ctrl");
  if (c.alt) parts.push("Alt");
  if (c.shift) parts.push("Shift");
  parts.push(c.code);
  return parts.join("+");
}

function keyLabel(code: string, platform: ChordPlatform): string {
  if (code.startsWith("Key")) return code.slice(3);
  if (code.startsWith("Digit")) return code.slice(5);
  const arrows: Record<string, [string, string]> = {
    ArrowLeft: ["←", "Left"],
    ArrowRight: ["→", "Right"],
    ArrowUp: ["↑", "Up"],
    ArrowDown: ["↓", "Down"],
  };
  if (arrows[code]) return platform === "mac" ? arrows[code][0] : arrows[code][1];
  const symbols: Record<string, string> = {
    BracketLeft: "[",
    BracketRight: "]",
    Backslash: "\\",
    Minus: "-",
    Equal: "=",
    Comma: ",",
    Period: ".",
    Slash: "/",
    Semicolon: ";",
    Quote: "'",
    Backquote: "`",
  };
  if (symbols[code]) return symbols[code];
  if (code === "Enter") return platform === "mac" ? "↵" : "Enter";
  if (code === "PageUp") return "PgUp";
  if (code === "PageDown") return "PgDn";
  return code;
}

/** Operator-facing form: `⌃⌥⇧⌘D` on macOS (Apple's modifier order),
 *  `Ctrl+Alt+Shift+D` elsewhere. */
export function formatChord(c: Chord, platform: ChordPlatform): string {
  const key = keyLabel(c.code, platform);
  if (platform === "mac") {
    return `${c.ctrl ? "⌃" : ""}${c.alt ? "⌥" : ""}${c.shift ? "⇧" : ""}${c.meta ? "⌘" : ""}${key}`;
  }
  const parts: string[] = [];
  if (c.ctrl) parts.push("Ctrl");
  if (c.alt) parts.push("Alt");
  if (c.shift) parts.push("Shift");
  if (c.meta) parts.push("Win");
  parts.push(key);
  return parts.join("+");
}

export function chordsEqual(a: Chord, b: Chord): boolean {
  return a.code === b.code && a.meta === b.meta && a.ctrl === b.ctrl && a.alt === b.alt && a.shift === b.shift;
}

/** Why `c` cannot be a workspace chord, or `null` if it can. */
export function chordProblem(c: Chord, platform: ChordPlatform): string | null {
  if (!c.meta && !c.ctrl && !c.alt) {
    return "needs Ctrl, Alt or ⌘/Win — a key with no modifier (or Shift alone) is typing";
  }
  const terminal = TERMINAL_CHORDS.find((t) => chordsEqual(t.chord, c));
  if (terminal) return `the remote shell needs it (${terminal.why})`;
  const app = APP_CHORDS[platform].find((t) => chordsEqual(t.chord, c));
  if (app) return `already used: ${app.why}`;
  return null;
}

// ── Effective bindings ──────────────────────────────────────────────

export interface BindingProblem {
  action: string;
  value: string;
  reason: string;
}

export interface ChordBindings {
  platform: ChordPlatform;
  byAction: ReadonlyMap<WorkspaceAction, Chord>;
  /** Overrides that were not applied, and why. The default stays bound. */
  problems: readonly BindingProblem[];
}

export function defaultChordString(action: WorkspaceAction, platform: ChordPlatform): string {
  const row = RESERVED_CHORDS.find((r) => r.action === action);
  if (!row) throw new Error(`unknown workspace action ${action}`);
  return platform === "mac" ? row.mac : row.other;
}

/**
 * The bindings in force: the platform defaults with `overrides` applied.
 * An override that names no action, does not parse, is refused by
 * {@link chordProblem}, or collides with another action's chord is not
 * applied — the default stays — and is reported in `problems`, so a
 * hand-edited preferences file can never unbind a chord silently or bind
 * one twice.
 */
export function effectiveBindings(
  platform: ChordPlatform,
  overrides: Readonly<Record<string, string>> = {},
): ChordBindings {
  const byAction = new Map<WorkspaceAction, Chord>();
  for (const row of RESERVED_CHORDS) {
    const parsed = parseChord(platform === "mac" ? row.mac : row.other);
    if (!parsed) throw new Error(`reserved chord table: ${row.action} does not parse`);
    byAction.set(row.action, parsed);
  }
  const problems: BindingProblem[] = [];
  const applied = new Set<WorkspaceAction>();
  for (const [action, value] of Object.entries(overrides).sort(([a], [b]) => a.localeCompare(b))) {
    if (!isWorkspaceAction(action)) {
      problems.push({ action, value, reason: "no such workspace action" });
      continue;
    }
    const parsed = parseChord(value);
    if (!parsed) {
      problems.push({ action, value, reason: "not a chord this build understands" });
      continue;
    }
    const problem = chordProblem(parsed, platform);
    if (problem) {
      problems.push({ action, value, reason: problem });
      continue;
    }
    byAction.set(action, parsed);
    applied.add(action);
  }
  // Conflicts: revert every applied override that shares a chord with
  // another action. Defaults never conflict (pinned by a test), so after
  // one pass the table is conflict-free.
  for (const action of [...applied]) {
    const mine = byAction.get(action)!;
    const clash = [...byAction.entries()].find(([other, c]) => other !== action && chordsEqual(c, mine));
    if (clash) {
      problems.push({
        action,
        value: chordToString(mine),
        reason: `conflicts with “${RESERVED_CHORDS.find((r) => r.action === clash[0])?.label ?? clash[0]}”`,
      });
      byAction.set(action, parseChord(defaultChordString(action, platform))!);
      applied.delete(action);
    }
  }
  return { platform, byAction, problems };
}

export function detectPlatform(): ChordPlatform {
  if (typeof navigator === "undefined") return "other";
  const hint = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`;
  return /Mac|iPhone|iPad/i.test(hint) ? "mac" : "other";
}

const MODIFIER_CODES = new Set([
  "ShiftLeft",
  "ShiftRight",
  "ControlLeft",
  "ControlRight",
  "AltLeft",
  "AltRight",
  "MetaLeft",
  "MetaRight",
  "OSLeft",
  "OSRight",
]);

let active: ChordBindings = effectiveBindings(detectPlatform());

/** Bindings every pane and the workspace consult. */
export function activeChordBindings(): ChordBindings {
  return active;
}

/** Apply the operator's overrides (from the preferences file). Returns
 *  the problems with them. */
export function setChordOverrides(overrides: Readonly<Record<string, string>>): readonly BindingProblem[] {
  active = effectiveBindings(detectPlatform(), overrides);
  return active.problems;
}

type KeyLike = Pick<KeyboardEvent, "code" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey"> & {
  isComposing?: boolean;
};

/** The workspace action `e` is bound to, or `null` for everything that
 *  belongs to the remote host. */
export function matchChord(e: KeyLike, bindings: ChordBindings = active): WorkspaceAction | null {
  if (e.isComposing || !e.code || MODIFIER_CODES.has(e.code)) return null;
  for (const [action, c] of bindings.byAction) {
    if (
      c.code === e.code &&
      c.meta === e.metaKey &&
      c.ctrl === e.ctrlKey &&
      c.alt === e.altKey &&
      c.shift === e.shiftKey
    ) {
      return action;
    }
  }
  return null;
}

// ── Settings: validating overrides before they are saved ─────────────

export interface OverrideValidation {
  /** action → canonical chord string, for every override that differs
   *  from its default. What Settings saves when `errors` is empty. */
  normalized: Record<string, string>;
  /** action → why its override cannot be saved. */
  errors: Partial<Record<WorkspaceAction, string>>;
}

/**
 * Validate the override text an operator typed (action → text; empty
 * means "use the default"). Every refusal {@link effectiveBindings} would
 * make at load time is made here first, with a message, so Settings never
 * saves an override that would be ignored.
 */
export function validateOverrides(
  platform: ChordPlatform,
  draft: Readonly<Partial<Record<WorkspaceAction, string>>>,
): OverrideValidation {
  const normalized: Record<string, string> = {};
  const errors: Partial<Record<WorkspaceAction, string>> = {};
  const bound = new Map<WorkspaceAction, Chord>();
  for (const row of RESERVED_CHORDS) bound.set(row.action, parseChord(platform === "mac" ? row.mac : row.other)!);

  const overridden: WorkspaceAction[] = [];
  for (const row of RESERVED_CHORDS) {
    const text = (draft[row.action] ?? "").trim();
    if (text === "") continue;
    const parsed = parseChord(text);
    if (!parsed) {
      errors[row.action] = "not a chord — write it like Ctrl+Shift+E or Meta+Alt+Left";
      continue;
    }
    const problem = chordProblem(parsed, platform);
    if (problem) {
      errors[row.action] = problem;
      continue;
    }
    if (chordsEqual(parsed, bound.get(row.action)!)) continue; // same as the default
    bound.set(row.action, parsed);
    normalized[row.action] = chordToString(parsed);
    overridden.push(row.action);
  }
  for (const action of overridden) {
    const mine = bound.get(action)!;
    const clash = RESERVED_CHORDS.find((r) => r.action !== action && chordsEqual(bound.get(r.action)!, mine));
    if (clash) {
      errors[action] = `conflicts with “${clash.label}”`;
      delete normalized[action];
    }
  }
  return { normalized, errors };
}
