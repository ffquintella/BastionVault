// Keystroke transcript pane for `.rdp-rec` version-4 recordings —
// Phase 8.6 of `features/rustion-integration.md`.
//
// Reads the transcript straight out of the artifact bytes the player
// already holds (`gui/src/lib/rdpKeystrokes.ts`), so a recording opens
// with its transcript whether or not the server has indexed it yet.
// The server-side index exists for *search*; this pane exists for
// *reading one session*.
//
// ## What this component is careful about
//
// A keystroke transcript is the highest-value artifact in a recording.
// Four rules shape every branch below, and none of them is cosmetic:
//
//  1. **A redacted run is rendered as withheld** — a masked
//     placeholder, its rule, and its character count. There is no
//     code path here that reconstructs one, infers one from its
//     neighbours, or hides that it exists.
//  2. **"Not enabled" is not "nothing was typed".** A version <= 3
//     file, and a version-4 file with `keystroke_metadata: false`,
//     get an explicit notice. An empty transcript that reads as
//     silence would be a false negative on an audit surface.
//  3. **Every caveat is visible.** `text_decoding` other than
//     `exact`, a `rebuilt` trailer, and a transcript recovered by
//     scanning `0x08` records each raise a banner, because each means
//     the transcript is approximate or incomplete in a specific way.
//  4. **Redaction upstream is best-effort** and this pane says so. It
//     must never read as "verified free of secrets".
//
// `field_epoch` is used only to draw a separator between runs. It is
// a correlation hint — a pass-through RDP proxy has no access to the
// remote UI's focus — so it is never labelled "field".

import { useMemo, useState } from "react";

import { Badge, Button } from "./ui";
import {
  readTranscript,
  type KeystrokeRun,
  type Transcript,
} from "../lib/rdpKeystrokes";

interface Props {
  /// The whole `.rdp-rec` buffer.
  bytes: Uint8Array;
  /// Current playback position in ms, so the pane can highlight the
  /// run the video is inside.
  positionMs?: number;
  /// Called when the operator clicks a run's timestamp. Wire it to
  /// the player's seek.
  onSeek?: (ms: number) => void;
}

/// Human-readable form of a redaction rule. The rules come from
/// Rustion's §6.2; anything unrecognised is shown verbatim rather
/// than swallowed, so a new upstream rule is visible rather than
/// silently rendered as "unknown".
const REASON_LABELS: Record<string, string> = {
  known_secret:
    "R1 known secret — matched a credential the bastion brokered for this session",
  masked_field:
    "R2 masked field — consecutive keystrokes painted the same glyph, so the field was masked",
  deny_pattern: "R3 deny pattern — matched a configured redaction regex",
  credential_pair:
    "R4 credential-shaped — an Enter-terminated run just after a Tab-terminated one",
  unknown:
    "rule not recorded — this transcript was rebuilt from 0x08 records, which carry no reason",
};

export function RdpTranscriptPane({ bytes, positionMs, onSeek }: Props) {
  const state = useMemo(() => readTranscript(bytes), [bytes]);
  const [showApplied, setShowApplied] = useState(false);
  const [showCensus, setShowCensus] = useState(false);

  if (state.kind === "not-enabled") {
    return <NotEnabledNotice version={state.header.version} />;
  }

  const t = state.transcript;
  const redacted = t.runs.filter((r) => r.redacted).length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold text-[var(--color-text)]">
          Keystroke transcript
        </span>
        <span className="text-[var(--color-text-muted)]">
          {t.runs.length} run{t.runs.length === 1 ? "" : "s"} ·{" "}
          {t.charsIndexed} character{t.charsIndexed === 1 ? "" : "s"}
        </span>
        {redacted > 0 && (
          <Badge variant="warning" label={`${redacted} withheld`} />
        )}
        {t.textDecoding !== "exact" && (
          <Badge variant="warning" label={`decoding: ${t.textDecoding || "unset"}`} />
        )}
        {t.rebuilt && <Badge variant="warning" label="trailer rebuilt" />}
        {t.source === "text-record-scan" && (
          <Badge variant="warning" label="recovered by scan" />
        )}
        {t.keyboardLayout && (
          <span className="text-[var(--color-text-muted)] font-mono">
            {t.keyboardLayout}
            {t.keyboardLayoutSource ? ` (${t.keyboardLayoutSource})` : ""}
          </span>
        )}
      </div>

      <Caveats transcript={t} />

      {t.runs.length === 0 ? (
        <div className="p-3 text-sm text-[var(--color-text-muted)] bg-[var(--color-surface)] border border-[var(--color-border)] rounded">
          Keystroke recording was enabled for this session and the transcript
          holds no runs. Every run the recorder closed is listed here, so this
          means nothing was typed after the point the recorder started — not
          that the transcript is missing.
        </div>
      ) : (
        <ol className="space-y-1 max-h-[420px] overflow-auto pr-1">
          {t.runs.map((run, i) => (
            <RunRow
              key={`${run.t}-${i}`}
              run={run}
              previous={i > 0 ? t.runs[i - 1] : null}
              active={
                positionMs !== undefined &&
                positionMs >= run.t &&
                positionMs < run.t + Math.max(run.d, 1)
              }
              onSeek={onSeek}
            />
          ))}
        </ol>
      )}

      {t.textApplied !== null && (
        <div>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => setShowApplied((v) => !v)}
          >
            {showApplied ? "Hide edited view" : "Show edited view"}
          </Button>
          {showApplied && (
            <div className="mt-2 space-y-1">
              <div className="text-xs text-amber-200/90">
                <strong>Derived and lossy.</strong> This is the bastion&apos;s
                own rendering with <code>[Backspace]</code> /{" "}
                <code>[Delete]</code> applied and other named keys stripped. It
                is a convenience view, <em>not</em> the record of what was
                pressed — the list above is. It is deliberately not what the
                keystroke search matches against.
              </div>
              <pre className="bg-neutral-950 border border-neutral-800 rounded p-2 text-[11px] max-h-48 overflow-auto whitespace-pre-wrap break-all">
                {t.textApplied}
              </pre>
            </div>
          )}
        </div>
      )}

      <div>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => setShowCensus((v) => !v)}
        >
          {showCensus ? "Hide recorder census" : "Show recorder census"}
        </Button>
        {showCensus && <Census census={t.census} />}
      </div>

      <div className="text-xs text-[var(--color-text-muted)]">
        Redaction is <strong>best-effort</strong> on the recording bastion. A
        transcript with no withheld runs has <em>not</em> been verified free of
        secrets — it means no redaction rule fired.
      </div>
    </div>
  );
}

/// The state a version <= 3 file, and a version-4 file recorded with
/// the feature off, land in. Deliberately loud: an empty transcript
/// here would read as "nobody typed", which is a different and
/// unsupported claim.
export function NotEnabledNotice({ version }: { version: number }) {
  return (
    <div className="p-3 text-sm text-sky-200 bg-sky-950/40 border border-sky-900 rounded space-y-1">
      <div className="font-semibold">
        Keystroke recording was not enabled for this session.
      </div>
      <div className="text-xs text-sky-200/80">
        {version >= 4
          ? "This is a format version-4 recording, but its header says keystroke_metadata is false — the bastion had the feature switched off when the session ran."
          : `This is a format version-${version || "?"} recording, which predates the keystroke track (added in version 4).`}
      </div>
      <div className="text-xs text-sky-200/80">
        <strong>This is not a statement that nothing was typed.</strong> There
        is no keystroke evidence in this artifact either way. Enable{" "}
        <code>recording.rdp_record_keystrokes</code> on the bastion to record
        it for future sessions.
      </div>
    </div>
  );
}

function Caveats({ transcript: t }: { transcript: Transcript }) {
  const notes: Array<{ title: string; body: string }> = [];

  if (t.source === "text-record-scan") {
    notes.push({
      title: "This transcript was recovered, not read.",
      body:
        "The keystroke trailer at the end of the artifact could not be read, so the transcript " +
        "was rebuilt by walking the 0x08 text-input records. Every run listed was already " +
        "adjudicated by the recorder before it was written, so nothing here is unredacted by " +
        "accident — but the session's final unclosed run is missing, per-run durations are " +
        "absent, and the redaction rule for each withheld run was not recorded.",
    });
  }
  if (t.rebuilt) {
    notes.push({
      title: "The bastion rebuilt this trailer after a crash.",
      body:
        "The trailer was reconstructed by the bastion's orphan reconciler rather than written " +
        "live at session end. Treat it as incomplete: the session's final unclosed run is not " +
        "in it.",
    });
  }
  if (t.textDecoding === "approximate") {
    notes.push({
      title: "Text is approximate.",
      body:
        "The session's keyboard layout had no built-in table on the bastion, so the scancodes " +
        "were decoded through a fallback layout. Characters that differ between the two layouts " +
        "are wrong. Punctuation and AltGr characters are the usual casualties.",
    });
  }
  if (t.textDecoding === "none") {
    notes.push({
      title: "Keystrokes were captured but not decoded.",
      body:
        "The recorder wrote a keystroke track without decoding it to text. Run counts and " +
        "timings are meaningful; the text is not present.",
    });
  }
  if (t.textDecoding === "unknown") {
    notes.push({
      title: "Decoding fidelity is unknown.",
      body:
        "This transcript came from a 0x08 scan, and only the trailer records whether a layout " +
        "table matched the session's own keyboard layout. The text may be approximate.",
    });
  }
  if (t.runs.some((r) => r.truncated)) {
    notes.push({
      title: "At least one run was truncated.",
      body:
        "A run hit the recorder's per-run character cap and was cut. The characters past the " +
        "cap were never written.",
    });
  }

  const other = t.warnings.filter(
    (w) =>
      !w.includes("rebuilt") &&
      !w.includes("text_decoding") &&
      !w.includes("scanning the 0x08"),
  );

  if (notes.length === 0 && other.length === 0) return null;
  return (
    <div className="space-y-2">
      {notes.map((n) => (
        <div
          key={n.title}
          className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded space-y-1"
        >
          <div className="font-semibold">{n.title}</div>
          <div className="text-xs text-amber-200/80">{n.body}</div>
        </div>
      ))}
      {other.length > 0 && (
        <details className="text-xs text-[var(--color-text-muted)]">
          <summary className="cursor-pointer">
            Parser notes ({other.length})
          </summary>
          <ul className="mt-1 ml-4 space-y-0.5">
            {other.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

function RunRow({
  run,
  previous,
  active,
  onSeek,
}: {
  run: KeystrokeRun;
  previous: KeystrokeRun | null;
  active: boolean;
  onSeek?: (ms: number) => void;
}) {
  // The epoch changed, so the recorder saw something that *might*
  // have been an input-context change. A visual separator and nothing
  // more — it is a hint, not a field identity.
  const newGroup = previous !== null && previous.epoch !== run.epoch;
  return (
    <li
      className={
        "rounded border px-2 py-1.5 min-w-0 " +
        (newGroup ? "mt-2 " : "") +
        (active
          ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
          : "border-[var(--color-border)] bg-[var(--color-surface)]")
      }
    >
      <div className="flex items-start gap-2 min-w-0">
        <button
          onClick={() => onSeek?.(run.t)}
          disabled={!onSeek}
          title={onSeek ? "Seek the player here" : undefined}
          className={
            "shrink-0 font-mono text-[11px] tabular-nums " +
            (onSeek
              ? "text-[var(--color-accent)] hover:underline cursor-pointer"
              : "text-[var(--color-text-muted)] cursor-default")
          }
        >
          {formatOffset(run.t)}
        </button>
        <div className="min-w-0 flex-1">
          {run.redacted ? (
            <Withheld run={run} />
          ) : (
            <div className="font-mono text-xs whitespace-pre-wrap break-all">
              {run.text ?? ""}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 mt-0.5 text-[10px] text-[var(--color-text-muted)]">
            <span>
              {run.n} char{run.n === 1 ? "" : "s"}
            </span>
            {run.d > 0 && <span>{(run.d / 1000).toFixed(1)}s</span>}
            {run.approximate && (
              <span className="text-amber-300">approximate</span>
            )}
            {run.composed && <span>dead-key composition</span>}
            {run.truncated && (
              <span className="text-amber-300">truncated at the run cap</span>
            )}
          </div>
        </div>
      </div>
    </li>
  );
}

/// A withheld run. The placeholder is sized from `n` so an auditor
/// sees how much was suppressed — which is the one thing the recorder
/// deliberately retains about a redacted run — and nothing here
/// attempts to say what it was.
function Withheld({ run }: { run: KeystrokeRun }) {
  const label = REASON_LABELS[run.reason ?? "unknown"] ?? run.reason ?? "unknown rule";
  return (
    <div className="min-w-0">
      <div
        className="font-mono text-xs text-amber-300/90 break-all"
        aria-label={`${run.n} characters withheld`}
      >
        {"•".repeat(Math.min(run.n, 48))}
        {run.n > 48 ? "…" : ""}
      </div>
      <div className="text-[10px] text-amber-200/80">withheld — {label}</div>
    </div>
  );
}

function Census({
  census,
}: {
  census: import("../lib/rdpKeystrokes").KeystrokeCensus;
}) {
  const rows: Array<[string, number]> = [
    ["Keys total", census.keysTotal],
    ["Characters decoded", census.charsDecoded],
    ["Unicode events", census.unicodeEvents],
    ["Named keys", census.namedKeys],
    ["Dead-key compositions", census.composed],
    ["Undecodable scancodes", census.undecodableScancodes],
    ["Redacted runs", census.redactedRuns],
    ["Redacted characters", census.redactedChars],
    ["Slow-path input PDUs", census.slowpathInputPdus],
    ["Truncated runs", census.truncatedRuns],
  ];
  return (
    <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
      {rows.map(([label, value]) => (
        <div
          key={label}
          className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-2 py-1 min-w-0 flex justify-between gap-2"
        >
          <span className="text-[var(--color-text-muted)] truncate">
            {label}
          </span>
          <span className="font-mono tabular-nums">{value}</span>
        </div>
      ))}
    </div>
  );
}

export function formatOffset(ms: number): string {
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = `${m}`.padStart(2, "0");
  const ss = `${s}`.padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}
