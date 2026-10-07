/**
 * T38 Phase 4 — the reserved-chord table (features/session-workspace.md §4)
 * and the multi-line paste guard.
 */

import { describe, it, expect } from "vitest";

import {
  RESERVED_CHORDS,
  TERMINAL_CHORDS,
  WORKSPACE_ACTIONS,
  chordProblem,
  chordToString,
  effectiveBindings,
  formatChord,
  matchChord,
  parseChord,
  validateOverrides,
  type ChordPlatform,
} from "../lib/reservedChords";
import { needsPasteConfirmation, summarisePaste } from "../lib/pasteGuard";

const PLATFORMS: ChordPlatform[] = ["mac", "other"];

function key(code: string, mods: { meta?: boolean; ctrl?: boolean; alt?: boolean; shift?: boolean } = {}) {
  return {
    code,
    metaKey: !!mods.meta,
    ctrlKey: !!mods.ctrl,
    altKey: !!mods.alt,
    shiftKey: !!mods.shift,
  };
}

describe("the default table", () => {
  it("binds every action on both platforms, and every binding parses", () => {
    expect(new Set(WORKSPACE_ACTIONS).size).toBe(RESERVED_CHORDS.length);
    for (const row of RESERVED_CHORDS) {
      expect(parseChord(row.mac), `${row.action} mac`).not.toBeNull();
      expect(parseChord(row.other), `${row.action} other`).not.toBeNull();
    }
    for (const p of PLATFORMS) {
      const b = effectiveBindings(p);
      expect(b.problems).toEqual([]);
      expect(b.byAction.size).toBe(RESERVED_CHORDS.length);
    }
  });

  it("no default collides with another, or with a key the remote shell needs", () => {
    for (const p of PLATFORMS) {
      const seen = new Map<string, string>();
      for (const [action, c] of effectiveBindings(p).byAction) {
        const s = chordToString(c);
        expect(seen.get(s), `${p}: ${action} and ${seen.get(s)} share ${s}`).toBeUndefined();
        seen.set(s, action);
        expect(chordProblem(c, p), `${p}: ${action} = ${s}`).toBeNull();
      }
    }
  });

  it("the terminal list covers the control characters an operator needs", () => {
    const names = TERMINAL_CHORDS.map((t) => chordToString(t.chord));
    for (const needed of ["Ctrl+KeyC", "Ctrl+KeyD", "Ctrl+KeyZ", "Ctrl+BracketLeft", "Ctrl+Backslash", "Ctrl+Shift+Minus", "Alt+KeyB"]) {
      expect(names).toContain(needed);
    }
  });

  it("`Ctrl` alone is never bound to a workspace action", () => {
    for (const p of PLATFORMS) {
      for (const [action, c] of effectiveBindings(p).byAction) {
        const ctrlOnly = c.ctrl && !c.shift && !c.alt && !c.meta;
        expect(ctrlOnly, `${p}: ${action}`).toBe(false);
      }
    }
  });
});

describe("matchChord", () => {
  const mac = effectiveBindings("mac");
  const other = effectiveBindings("other");

  it("returns null for plain typing and the shell's control keys", () => {
    for (const b of [mac, other]) {
      expect(matchChord(key("KeyA"), b)).toBeNull();
      expect(matchChord(key("KeyA", { shift: true }), b)).toBeNull();
      expect(matchChord(key("KeyC", { ctrl: true }), b)).toBeNull();
      expect(matchChord(key("KeyD", { ctrl: true }), b)).toBeNull();
      expect(matchChord(key("KeyZ", { ctrl: true }), b)).toBeNull();
      expect(matchChord(key("BracketLeft", { ctrl: true }), b)).toBeNull();
      expect(matchChord(key("Enter"), b)).toBeNull();
      expect(matchChord(key("ArrowLeft"), b)).toBeNull();
    }
  });

  it("maps the platform defaults to their actions", () => {
    expect(matchChord(key("KeyD", { meta: true }), mac)).toBe("splitRight");
    expect(matchChord(key("KeyD", { meta: true, shift: true }), mac)).toBe("splitDown");
    expect(matchChord(key("ArrowLeft", { meta: true, alt: true }), mac)).toBe("focusLeft");
    expect(matchChord(key("Digit3", { meta: true }), mac)).toBe("selectTab3");
    expect(matchChord(key("KeyK", { meta: true, alt: true, ctrl: true }), mac)).toBe("releaseKeyboard");
    expect(matchChord(key("KeyE", { ctrl: true, shift: true }), other)).toBe("splitRight");
    expect(matchChord(key("KeyO", { ctrl: true, shift: true }), other)).toBe("splitDown");
    expect(matchChord(key("Digit3", { alt: true }), other)).toBe("selectTab3");
    expect(matchChord(key("KeyK", { ctrl: true, alt: true, shift: true }), other)).toBe("releaseKeyboard");
    // The other platform's chord is just a key there.
    expect(matchChord(key("KeyD", { meta: true }), other)).toBeNull();
  });

  it("ignores modifier presses and IME composition", () => {
    expect(matchChord(key("MetaLeft", { meta: true }), mac)).toBeNull();
    expect(matchChord({ ...key("KeyD", { meta: true }), isComposing: true }, mac)).toBeNull();
  });
});

describe("parsing and formatting", () => {
  it("accepts the common spellings and refuses the rest", () => {
    expect(chordToString(parseChord("ctrl+shift+e")!)).toBe("Ctrl+Shift+KeyE");
    expect(chordToString(parseChord("Cmd + Option + Left")!)).toBe("Meta+Alt+ArrowLeft");
    expect(chordToString(parseChord("Ctrl+Shift+PgUp")!)).toBe("Ctrl+Shift+PageUp");
    expect(chordToString(parseChord("Meta+Shift+[")!)).toBe("Meta+Shift+BracketLeft");
    expect(chordToString(parseChord("Alt+F4")!)).toBe("Alt+F4");
    for (const bad of ["", "Ctrl+", "Ctrl+Ctrl+E", "Hyper+E", "Ctrl+Shift+E+F", "Ctrl+Shift+Banana"]) {
      expect(parseChord(bad), bad).toBeNull();
    }
  });

  it("formats with glyphs on macOS and words elsewhere", () => {
    expect(formatChord(parseChord("Meta+Shift+Enter")!, "mac")).toBe("⇧⌘↵");
    expect(formatChord(parseChord("Meta+Alt+Ctrl+KeyK")!, "mac")).toBe("⌃⌥⌘K");
    expect(formatChord(parseChord("Ctrl+Alt+Shift+KeyK")!, "other")).toBe("Ctrl+Alt+Shift+K");
  });
});

describe("overrides", () => {
  it("apply when valid, and are reported and ignored when not", () => {
    const b = effectiveBindings("other", {
      splitRight: "Ctrl+Shift+R",
      splitDown: "Ctrl+C",
      bogus: "Ctrl+Shift+Y",
      newTab: "Ctrl+Shift+nonsense",
      nextTab: "Ctrl+Shift+V",
    });
    expect(chordToString(b.byAction.get("splitRight")!)).toBe("Ctrl+Shift+KeyR");
    expect(chordToString(b.byAction.get("splitDown")!)).toBe("Ctrl+Shift+KeyO");
    expect(chordToString(b.byAction.get("newTab")!)).toBe("Ctrl+Shift+KeyT");
    expect(chordToString(b.byAction.get("nextTab")!)).toBe("Ctrl+Shift+PageDown");
    const reasons = Object.fromEntries(b.problems.map((p) => [p.action, p.reason]));
    expect(reasons.splitDown).toMatch(/remote shell needs it/);
    expect(reasons.bogus).toMatch(/no such workspace action/);
    expect(reasons.newTab).toMatch(/not a chord/);
    expect(reasons.nextTab).toMatch(/already used/);
  });

  it("an override that lands on another action's chord is reverted, never bound twice", () => {
    const b = effectiveBindings("mac", { newTab: "Meta+KeyD" });
    expect(chordToString(b.byAction.get("newTab")!)).toBe("Meta+KeyT");
    expect(chordToString(b.byAction.get("splitRight")!)).toBe("Meta+KeyD");
    expect(b.problems[0].reason).toMatch(/conflicts with/);
  });

  it("Settings validation names the problem per action and normalises the rest", () => {
    const v = validateOverrides("other", {
      splitRight: "ctrl+shift+r",
      splitDown: "Ctrl+Shift+R",
      newTab: "Ctrl+Shift+T",
      closePane: "Shift+W",
      focusLeft: "Ctrl+Alt+H",
      toggleZoom: "Alt+B",
    });
    // splitRight and splitDown collide; both are refused.
    expect(v.errors.splitRight).toMatch(/conflicts/);
    expect(v.errors.splitDown).toMatch(/conflicts/);
    expect(v.errors.closePane).toMatch(/needs Ctrl, Alt/);
    expect(v.errors.toggleZoom).toMatch(/Meta-b/);
    // Same as the default: no override is stored.
    expect(v.normalized.newTab).toBeUndefined();
    expect(v.normalized).toEqual({ focusLeft: "Ctrl+Alt+KeyH" });
  });
});

describe("paste guard", () => {
  it("passes a single line through and holds anything with a line break", () => {
    expect(needsPasteConfirmation("ls -la")).toBe(false);
    expect(needsPasteConfirmation("")).toBe(false);
    expect(needsPasteConfirmation("ls -la\n")).toBe(true);
    expect(needsPasteConfirmation("a\r\nb")).toBe(true);
    expect(needsPasteConfirmation("a\rb")).toBe(true);
  });

  it("summarises without reproducing the whole paste", () => {
    const text = Array.from({ length: 8 }, (_, i) => `line ${i} ${"x".repeat(i === 0 ? 300 : 3)}`).join("\n") + "\n";
    const s = summarisePaste(text);
    expect(s.lines).toBe(8);
    expect(s.chars).toBe(text.length);
    expect(s.preview).toHaveLength(5);
    expect(s.preview[0].endsWith("…")).toBe(true);
    expect(s.preview[0].length).toBe(201);
    expect(s.more).toBe(3);
  });
});
