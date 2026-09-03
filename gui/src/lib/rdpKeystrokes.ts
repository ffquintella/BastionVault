// `.rdp-rec` version-4 keystroke transcript reader — TypeScript port
// of `crates/bv-engine-rustion/src/rdp_keystrokes.rs`.
//
// The Rust module is the canonical, unit-tested reference and the one
// the server indexes with. This file mirrors it so the player can
// render a transcript straight out of the artifact bytes it already
// holds — no second fetch, and a recording opened before the server
// has indexed it still shows its transcript. **If you change one,
// change the other; the Rust tests are the spec.** The authoritative
// format specification is Rustion's `docs/rdp-keystroke-metadata.md`.
//
// ## Two records, both additive
//
//   `0x08` text input:
//       flags:u8  field_epoch:u32 LE  char_count:u16 LE
//       text_len:u16 LE  text[text_len] (UTF-8)
//     The record's `timestamp_ms` is the run's **first** keystroke.
//
//   `0x7F` keystroke trailer: the whole transcript as JSON, always the
//     last record, ending in a self-locating 8-byte footer
//     (`record_len:u32 LE` + `"RKTR"`).
//
// A version <= 3 player skips both by `payload_len`, which is the
// container's forward-compatibility contract — that is what makes
// version 4 additive.
//
// ## The fast path
//
// `readTrailer` reads the last 8 bytes, checks the magic, seeks back
// `record_len` from EOF and parses exactly that one record. It touches
// no graphics byte and its cost does not scale with the artifact;
// `bytesExamined` records what it looked at so that stays testable.
// **Do not scan the file looking for the trailer.**
//
// `readTranscript` adds the degradation path: when the magic or the
// JSON fails — a file truncated mid-trailer, or one whose bastion died
// before writing it — it falls back to `scanTextRecords`, which walks
// the `0x08` records and yields every *completed* run. Sound because a
// `0x08` is only written after its run's redaction verdict, so
// everything in a crashed file is already adjudicated; what is lost is
// the final unclosed run, which is the safe direction to fail.
//
// ## Security rules this module enforces
//
// 1. **Redacted runs are never reconstructed.** A redacted run has no
//    `0x02` scancode records and no per-key timestamps — the recorder
//    drops both deliberately, because inter-keystroke timing is itself
//    a password-recovery channel. Nothing here infers a redacted run's
//    content from anything.
// 2. **`searchText` is rebuilt from the runs whose `redacted` flag is
//    false**, never taken on trust from the producer's own field, so a
//    producer bug cannot surface withheld text as searchable.
// 3. **`textApplied` is display-only.** The trailer carries a derived,
//    lossy rendering with `[Backspace]`/`[Delete]` applied. It is
//    parsed here for a readable pane and is explicitly never indexed
//    and never presented as the record of what was pressed.
// 4. **No transcript text in a URL, a log line or an error.** Every
//    error here carries offsets, lengths and counts only.
//
// ## Ordering
//
// From version 4 `timestamp_ms` is **not monotonic across records**:
// `0x02` and `0x08` are buffered until their run closes, so they are
// written after graphics records bearing later timestamps. The header
// declares the bound as `max_reorder_ms`. Nothing here assumes
// monotonicity, and `runs` is sorted by `t` before it is returned.

/// `event_type` of a version-4 text-input record.
export const EVENT_TEXT_INPUT = 0x08;
/// `event_type` of the keystroke trailer.
export const EVENT_KEYSTROKE_TRAILER = 0x7f;
/// Trailing magic of the trailer's self-locating footer: "RKTR".
export const TRAILER_MAGIC = [0x52, 0x4b, 0x54, 0x52] as const;
/// `record_len:u32 LE` + `"RKTR"`.
export const TRAILER_FOOTER_LEN = 8;
/// `timestamp_ms:u64 LE` + `event_type:u8` + `payload_len:u32 LE`.
export const RECORD_HEADER_LEN = 13;
/// `0x08` fixed prefix: `flags:u8 field_epoch:u32 char_count:u16 text_len:u16`.
export const TEXT_INPUT_PREFIX_LEN = 9;
/// First container version that can carry a keystroke track.
export const FIRST_KEYSTROKE_VERSION = 4;

// `0x08` `flags` bits.
export const FLAG_REDACTED = 0x01;
export const FLAG_COMPOSED = 0x02;
export const FLAG_APPROXIMATE = 0x04;
export const FLAG_RUN_END = 0x08;
export const FLAG_TRUNCATED = 0x10;

/// Ceiling on the trailer record we are willing to parse. The footer's
/// `record_len` is attacker-influenced input — recording bytes come
/// from the bastion — and a JSON document this large is a malformed
/// file, not a session transcript.
export const MAX_TRAILER_RECORD_BYTES = 32 * 1024 * 1024;

/// Ceiling on how many runs the fallback scan will accumulate.
export const MAX_SCANNED_RUNS = 200_000;

/// How the transcript was obtained. A scanned transcript is missing
/// the session's final unclosed run and has no per-run durations, so
/// the source is surfaced rather than hidden.
export type TranscriptSource = "trailer-footer" | "text-record-scan";

/// `exact` — a layout table matched the session's own KLID.
/// `approximate` — a fallback table was used.
/// `none` — keystrokes were captured but not decoded.
/// `unknown` — a scanned transcript, which cannot prove exactness.
export type TextDecoding = "exact" | "approximate" | "none" | "unknown" | "";

export interface KeystrokeHeader {
  /// Container `version`. `0` when the header carries no version.
  version: number;
  /// Whether a keystroke track and trailer are present.
  ///
  /// **`false` does not mean nobody typed.** It means the feature was
  /// off on that bastion. Never render it as "no keyboard activity".
  keystrokeMetadata: boolean;
  /// Resolved Windows KLID as a hex string, or `null`.
  keyboardLayout: string | null;
  /// `client_core` | `config` | `fallback`.
  keyboardLayoutSource: string | null;
  /// Bound on how far out of order a keystroke record may appear.
  /// `0` when `keystrokeMetadata` is false.
  maxReorderMs: number;
}

/// One keystroke run. `text` is `null` exactly when `redacted` is
/// true — there is no path here that tries to recover it.
export interface KeystrokeRun {
  /// Elapsed ms of the run's first keystroke — the player's seek
  /// offset.
  t: number;
  /// Run duration in ms. `0` on a scanned transcript.
  d: number;
  /// Character count (Unicode scalar values). Retained for a redacted
  /// run: an auditor sees that N characters were withheld.
  n: number;
  /// Typed text, with non-character keys as bracketed tokens
  /// (`[Enter]`, `[Ctrl+C]`, `[F5]`). `null` when redacted.
  text: string | null;
  redacted: boolean;
  /// `known_secret` | `masked_field` | `deny_pattern` |
  /// `credential_pair`, on a redacted run.
  reason: string | null;
  /// The `field_epoch` correlation **hint**. A pass-through RDP proxy
  /// has no access to the remote UI's focus, so this groups runs
  /// visually. Do not label it "field" and do not depend on it.
  epoch: number;
  composed: boolean;
  approximate: boolean;
  truncated: boolean;
}

/// The recorder's own account of what it dropped. Counts only.
export interface KeystrokeCensus {
  keysTotal: number;
  charsDecoded: number;
  unicodeEvents: number;
  namedKeys: number;
  composed: number;
  undecodableScancodes: number;
  redactedRuns: number;
  redactedChars: number;
  slowpathInputPdus: number;
  truncatedRuns: number;
}

export interface Transcript {
  source: TranscriptSource;
  /// True only for a trailer the live recorder wrote. False for a
  /// rebuilt trailer and for a scanned fallback, both of which are
  /// missing the session's final unclosed run and must not be
  /// presented as a complete transcript.
  complete: boolean;
  trailerVersion: number;
  /// The bastion rebuilt the trailer after a crash rather than
  /// writing it live.
  rebuilt: boolean;
  keyboardLayout: string | null;
  keyboardLayoutSource: string | null;
  textDecoding: TextDecoding;
  /// Sorted by `t`, because version 4's records are not monotonic.
  runs: KeystrokeRun[];
  /// Newline join of every **non-redacted** run's text, rebuilt from
  /// `runs`. A substring hit against it can never be a hit on
  /// withheld text.
  searchText: string;
  /// The trailer's derived `text_applied`: the same content with
  /// `[Backspace]`/`[Delete]` applied and other named keys stripped.
  /// **Derived and lossy — display only.** Never index it and never
  /// present it as the record of what was pressed. `null` when the
  /// producer did not supply one (every scanned transcript).
  textApplied: string | null;
  census: KeystrokeCensus;
  /// Non-redacted characters, i.e. what `searchText` covers.
  charsIndexed: number;
  /// Bytes of the artifact this parse examined. The trailer fast path
  /// is bounded by the trailer's own size; the fallback scan is not.
  bytesExamined: number;
  warnings: string[];
}

export type TrailerErrorKind =
  | "too-short"
  | "no-magic"
  | "bad-record-len"
  | "not-trailer-record"
  | "length-mismatch"
  | "not-utf8"
  | "bad-json";

export interface TrailerError {
  kind: TrailerErrorKind;
  /// Offsets, lengths and counts only. Never transcript content.
  message: string;
}

const emptyCensus = (): KeystrokeCensus => ({
  keysTotal: 0,
  charsDecoded: 0,
  unicodeEvents: 0,
  namedKeys: 0,
  composed: 0,
  undecodableScancodes: 0,
  redactedRuns: 0,
  redactedChars: 0,
  slowpathInputPdus: 0,
  truncatedRuns: 0,
});

// ─── Header ─────────────────────────────────────────────────────────

/// Split a `.rdp-rec` into its JSON header line and the offset of the
/// first event record. Mirrors the graphics decoder's `parseHeader`.
export function headerAndStart(
  bytes: Uint8Array,
): { header: string; start: number } | null {
  if (bytes.length < 4) return null;
  if (
    bytes[0] !== 0x52 ||
    bytes[1] !== 0x52 ||
    bytes[2] !== 0x45 ||
    bytes[3] !== 0x43
  ) {
    return null; // not "RREC"
  }
  let nl = -1;
  for (let i = 4; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) {
      nl = i;
      break;
    }
  }
  if (nl < 0) return null;
  const header = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.subarray(4, nl),
  );
  return { header, start: nl + 1 };
}

/// Read the version-4 keystroke fields off a `.rdp-rec` JSON header.
///
/// A missing `keystroke_metadata` reads as `false`, which is how every
/// version <= 3 header reads — that is the whole compatibility story
/// and it needs no version gate.
export function parseKeystrokeHeader(headerJson: string): KeystrokeHeader {
  const fallback: KeystrokeHeader = {
    version: 0,
    keystrokeMetadata: false,
    keyboardLayout: null,
    keyboardLayoutSource: null,
    maxReorderMs: 0,
  };
  let h: Record<string, unknown>;
  try {
    const parsed = JSON.parse(headerJson);
    if (typeof parsed !== "object" || parsed === null) return fallback;
    h = parsed as Record<string, unknown>;
  } catch {
    return fallback;
  }
  const num = (v: unknown) => (typeof v === "number" && v >= 0 ? v : 0);
  const str = (v: unknown) => (typeof v === "string" ? v : null);
  return {
    version: num(h.version),
    keystrokeMetadata: h.keystroke_metadata === true,
    keyboardLayout: str(h.keyboard_layout),
    keyboardLayoutSource: str(h.keyboard_layout_source),
    maxReorderMs: num(h.max_reorder_ms),
  };
}

// ─── The trailer fast path ──────────────────────────────────────────

/// Locate and parse the `0x7F` trailer by seeking from EOF.
///
/// Reads the last 8 bytes, checks the magic, seeks back `record_len`
/// and parses that one record. **The cost is the trailer's size, not
/// the artifact's** — see `Transcript.bytesExamined`.
export function readTrailer(
  bytes: Uint8Array,
): { ok: true; transcript: Transcript } | { ok: false; error: TrailerError } {
  const fileLen = bytes.length;
  if (fileLen < TRAILER_FOOTER_LEN) {
    return err(
      "too-short",
      `artifact is ${fileLen} bytes, shorter than the ${TRAILER_FOOTER_LEN}-byte keystroke-trailer footer`,
    );
  }
  const fo = fileLen - TRAILER_FOOTER_LEN;
  for (let i = 0; i < 4; i++) {
    if (bytes[fo + 4 + i] !== TRAILER_MAGIC[i]) {
      return err("no-magic", "no `RKTR` keystroke-trailer footer at end of file");
    }
  }
  const recordLen = readU32Le(bytes, fo);
  // A trailer record is at minimum its 13-byte header plus a payload
  // big enough to hold the 8-byte footer it ends with.
  const min = RECORD_HEADER_LEN + TRAILER_FOOTER_LEN;
  if (
    recordLen < min ||
    recordLen > fileLen ||
    recordLen > MAX_TRAILER_RECORD_BYTES
  ) {
    return err(
      "bad-record-len",
      `keystroke-trailer footer claims record_len=${recordLen}, which does not fit a ${fileLen}-byte artifact`,
    );
  }
  const start = fileLen - recordLen;
  const eventType = bytes[start + 8];
  if (eventType !== EVENT_KEYSTROKE_TRAILER) {
    return err(
      "not-trailer-record",
      `record at EOF-record_len has event_type 0x${eventType.toString(16).padStart(2, "0")}, expected 0x7f`,
    );
  }
  const payloadLen = readU32Le(bytes, start + 9);
  if (payloadLen !== recordLen - RECORD_HEADER_LEN) {
    return err(
      "length-mismatch",
      `keystroke trailer payload_len=${payloadLen} disagrees with footer record_len=${recordLen}`,
    );
  }
  const jsonLen = payloadLen - TRAILER_FOOTER_LEN;
  const jsonStart = start + RECORD_HEADER_LEN;
  let json: string;
  try {
    json = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(jsonStart, jsonStart + jsonLen),
    );
  } catch {
    return err("not-utf8", "keystroke trailer JSON is not valid UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    // The thrown `SyntaxError` is *not* forwarded. V8's message
    // quotes the offending source — `Unexpected token 'o', "{"runs":
    // [ oops" is not valid JSON` — which on this input would put
    // transcript bytes into an error string, and from there into a
    // toast or a log. Rule 4 in this module's header forbids exactly
    // that, so the report is a length and nothing else. A test
    // asserts the message does not contain the content.
    return err(
      "bad-json",
      `keystroke trailer JSON did not parse (${jsonLen} bytes of JSON in the 0x7F record)`,
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    return err("bad-json", "keystroke trailer JSON is not an object");
  }
  return {
    ok: true,
    transcript: transcriptFromTrailer(
      parsed as Record<string, unknown>,
      TRAILER_FOOTER_LEN + recordLen,
    ),
  };
}

function err(kind: TrailerErrorKind, message: string) {
  return { ok: false as const, error: { kind, message } };
}

function transcriptFromTrailer(
  t: Record<string, unknown>,
  bytesExamined: number,
): Transcript {
  const warnings: string[] = [];
  const trailerVersion = typeof t.trailer_version === "number" ? t.trailer_version : 0;
  const rebuilt = t.rebuilt === true;
  const textDecoding = (typeof t.text_decoding === "string"
    ? t.text_decoding
    : "") as TextDecoding;

  if (trailerVersion !== 1) {
    warnings.push(
      `trailer_version ${trailerVersion} is not the version 1 this reader was written against; unknown fields were ignored`,
    );
  }
  if (rebuilt) {
    warnings.push(
      "the bastion rebuilt this trailer after a crash rather than writing it live — the session's final unclosed run is missing",
    );
  }
  if (textDecoding !== "exact") {
    warnings.push(
      `text_decoding is \`${textDecoding || "unset"}\`, not \`exact\` — the transcript was not decoded through a layout table matching the session's own keyboard layout`,
    );
  }

  const runs = parseRuns(t.runs);
  // Rule 2: the searchable text is *ours*, rebuilt from the runs whose
  // `redacted` flag is false, never the producer's `search_text` taken
  // on trust.
  const { searchText, charsIndexed } = deriveSearchText(runs);
  const producerSearchText =
    typeof t.search_text === "string" ? t.search_text : "";
  if (producerSearchText !== searchText) {
    warnings.push(
      `the trailer's own search_text (${producerSearchText.length} chars) differs from the newline join of its non-redacted runs (${searchText.length} chars); using the join`,
    );
  }

  return {
    source: "trailer-footer",
    complete: !rebuilt,
    trailerVersion,
    rebuilt,
    keyboardLayout:
      typeof t.keyboard_layout === "string" ? t.keyboard_layout : null,
    keyboardLayoutSource:
      typeof t.keyboard_layout_source === "string"
        ? t.keyboard_layout_source
        : null,
    textDecoding,
    runs,
    searchText,
    // Display-only, and only if the producer supplied it.
    textApplied: typeof t.text_applied === "string" ? t.text_applied : null,
    census: parseCensus(t.census),
    charsIndexed,
    bytesExamined,
    warnings,
  };
}

function parseRuns(raw: unknown): KeystrokeRun[] {
  if (!Array.isArray(raw)) return [];
  const out: KeystrokeRun[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) continue;
    const o = item as Record<string, unknown>;
    const redacted = o.redacted === true;
    const num = (v: unknown) => (typeof v === "number" && v >= 0 ? v : 0);
    out.push({
      t: num(o.t),
      d: num(o.d),
      n: num(o.n),
      // A run flagged redacted whose `text` is nevertheless populated
      // (a producer bug) has that text dropped here rather than shown.
      text: redacted ? null : typeof o.text === "string" ? o.text : null,
      redacted,
      reason: typeof o.reason === "string" ? o.reason : redacted ? "unknown" : null,
      epoch: num(o.epoch),
      composed: o.composed === true,
      approximate: o.approximate === true,
      truncated: o.truncated === true,
    });
  }
  // Version 4's records are not monotonic; anchor the pane on `t`.
  out.sort((a, b) => a.t - b.t);
  return out;
}

function parseCensus(raw: unknown): KeystrokeCensus {
  const c = emptyCensus();
  if (typeof raw !== "object" || raw === null) return c;
  const o = raw as Record<string, unknown>;
  const num = (k: string) => (typeof o[k] === "number" ? (o[k] as number) : 0);
  return {
    keysTotal: num("keys_total"),
    charsDecoded: num("chars_decoded"),
    unicodeEvents: num("unicode_events"),
    namedKeys: num("named_keys"),
    composed: num("composed"),
    undecodableScancodes: num("undecodable_scancodes"),
    redactedRuns: num("redacted_runs"),
    redactedChars: num("redacted_chars"),
    slowpathInputPdus: num("slowpath_input_pdus"),
    truncatedRuns: num("truncated_runs"),
  };
}

/// Newline-join every non-redacted run's text.
///
/// A redacted run contributes **nothing** — not even a placeholder —
/// so a substring hit against the result is never a hit on withheld
/// text.
export function deriveSearchText(runs: KeystrokeRun[]): {
  searchText: string;
  charsIndexed: number;
} {
  const parts: string[] = [];
  let chars = 0;
  for (const r of runs) {
    if (r.redacted || r.text === null) continue;
    parts.push(r.text);
    chars += [...r.text].length;
  }
  return { searchText: parts.join("\n"), charsIndexed: chars };
}

// ─── The degradation path ───────────────────────────────────────────

/// Walk the `0x08` records and rebuild whatever runs completed.
///
/// Used when the trailer is unreadable. Unknown `event_type` values
/// are skipped by `payload_len`, exactly as the graphics path does.
export function scanTextRecords(bytes: Uint8Array): Transcript {
  const runs: KeystrokeRun[] = [];
  const census = emptyCensus();
  const warnings: string[] = [];
  let anyApproximate = false;
  let trailerSeen = false;

  const head = headerAndStart(bytes);
  if (head === null) {
    return {
      source: "text-record-scan",
      complete: false,
      trailerVersion: 0,
      rebuilt: false,
      keyboardLayout: null,
      keyboardLayoutSource: null,
      textDecoding: "unknown",
      runs,
      searchText: "",
      textApplied: null,
      census,
      charsIndexed: 0,
      bytesExamined: bytes.length,
      warnings: ["artifact has no readable `RREC` header"],
    };
  }

  // The run currently being accumulated across fragments. A run may
  // span several `0x08` records; only the one with `RUN_END` closes
  // it. An unterminated tail is dropped rather than guessed at.
  let open: KeystrokeRun | null = null;
  let pos = head.start;
  let hitCap = false;

  while (pos + RECORD_HEADER_LEN <= bytes.length) {
    const ts = readU64Le(bytes, pos);
    const kind = bytes[pos + 8];
    const len = readU32Le(bytes, pos + 9);
    const dataStart = pos + RECORD_HEADER_LEN;
    const next = dataStart + len;
    if (next > bytes.length) {
      warnings.push(
        `artifact ends mid-record: ${bytes.length - pos} trailing bytes do not form a complete record`,
      );
      break;
    }
    if (kind === EVENT_KEYSTROKE_TRAILER) trailerSeen = true;
    if (kind === EVENT_TEXT_INPUT) {
      const frag = parseTextInput(ts, bytes.subarray(dataStart, next));
      if (frag === null) {
        warnings.push(
          `skipped a malformed 0x08 text-input record (${len} payload bytes)`,
        );
      } else {
        if (frag.approximate) anyApproximate = true;
        if (open === null) {
          open = {
            t: frag.timestampMs,
            d: 0,
            n: 0,
            text: null,
            redacted: false,
            reason: null,
            epoch: frag.epoch,
            composed: false,
            approximate: false,
            truncated: false,
          };
        }
        mergeFragment(open, frag);
        if (frag.runEnd) {
          if (runs.length >= MAX_SCANNED_RUNS) {
            hitCap = true;
            open = null;
            break;
          }
          if (open.redacted) {
            census.redactedRuns += 1;
            census.redactedChars += open.n;
          } else {
            census.charsDecoded += open.n;
          }
          if (open.composed) census.composed += 1;
          if (open.truncated) census.truncatedRuns += 1;
          runs.push(open);
          open = null;
        }
      }
    }
    pos = next;
  }

  if (open !== null) {
    warnings.push(
      "the artifact's final keystroke run was never closed by a RUN_END record and was dropped — an un-adjudicated run is not written out",
    );
  }
  if (hitCap) {
    warnings.push(
      `stopped after ${MAX_SCANNED_RUNS} runs; the artifact declares more than this reader will accumulate`,
    );
  }
  warnings.push(
    trailerSeen
      ? "the keystroke trailer could not be read, so this transcript was rebuilt by scanning the 0x08 text-input records. It is missing per-run durations and any run the recorder had not closed."
      : "this artifact carries no keystroke trailer, so the transcript was rebuilt by scanning the 0x08 text-input records. It is missing per-run durations and any run the recorder had not closed.",
  );

  runs.sort((a, b) => a.t - b.t);
  const { searchText, charsIndexed } = deriveSearchText(runs);
  return {
    source: "text-record-scan",
    complete: false,
    trailerVersion: 0,
    rebuilt: false,
    keyboardLayout: null,
    keyboardLayoutSource: null,
    // A scan can prove "approximate" from a flag but can never prove
    // "exact" — the layout match is a fact only the trailer carries.
    textDecoding: anyApproximate ? "approximate" : "unknown",
    runs,
    searchText,
    // `text_applied` is the producer's derivation. A scan does not
    // invent one: doing so would put a lossy, edited reconstruction on
    // screen with nothing upstream vouching for it.
    textApplied: null,
    census,
    charsIndexed,
    bytesExamined: bytes.length,
    warnings,
  };
}

interface TextInputFragment {
  timestampMs: number;
  redacted: boolean;
  composed: boolean;
  approximate: boolean;
  runEnd: boolean;
  truncated: boolean;
  epoch: number;
  charCount: number;
  text: string | null;
}

/// Decode one `0x08` payload. `null` when the payload is too short for
/// its own declared fields — skipped and counted, never guessed at.
function parseTextInput(
  timestampMs: number,
  payload: Uint8Array,
): TextInputFragment | null {
  if (payload.length < TEXT_INPUT_PREFIX_LEN) return null;
  const flags = payload[0];
  const epoch = readU32Le(payload, 1);
  const charCount = readU16Le(payload, 5);
  const textLen = readU16Le(payload, 7);
  if (payload.length < TEXT_INPUT_PREFIX_LEN + textLen) return null;
  const redacted = (flags & FLAG_REDACTED) !== 0;
  // A redacted record carries `text_len == 0` by specification. If a
  // producer bug puts bytes there anyway we drop them: this reader
  // does not surface text from a run the recorder said to withhold.
  const text = redacted
    ? null
    : new TextDecoder("utf-8", { fatal: false }).decode(
        payload.subarray(
          TEXT_INPUT_PREFIX_LEN,
          TEXT_INPUT_PREFIX_LEN + textLen,
        ),
      );
  return {
    timestampMs,
    redacted,
    composed: (flags & FLAG_COMPOSED) !== 0,
    approximate: (flags & FLAG_APPROXIMATE) !== 0,
    runEnd: (flags & FLAG_RUN_END) !== 0,
    truncated: (flags & FLAG_TRUNCATED) !== 0,
    epoch,
    charCount,
    text,
  };
}

function mergeFragment(acc: KeystrokeRun, frag: TextInputFragment): void {
  acc.n += frag.charCount;
  acc.epoch = frag.epoch;
  acc.composed = acc.composed || frag.composed;
  acc.approximate = acc.approximate || frag.approximate;
  acc.truncated = acc.truncated || frag.truncated;
  if (frag.redacted) {
    // Redaction is a property of the whole run: once any fragment says
    // withheld, the run is withheld and whatever text earlier
    // fragments carried is discarded rather than half-published.
    acc.redacted = true;
    acc.text = null;
    // `0x08` carries no reason; the trailer does. Name the gap rather
    // than inventing a rule.
    if (acc.reason === null) acc.reason = "unknown";
    return;
  }
  if (acc.redacted) return;
  if (frag.text !== null) {
    acc.text = acc.text === null ? frag.text : acc.text + frag.text;
  }
}

// ─── The path callers should use ────────────────────────────────────

export type TranscriptState =
  /// A transcript was read.
  | { kind: "transcript"; transcript: Transcript; header: KeystrokeHeader }
  /// The artifact genuinely carries no keystroke track: a version <= 3
  /// file, or a version-4 file recorded with `keystroke_metadata:
  /// false`. A real state — render it as "keystroke recording was not
  /// enabled for this session", **never** as an empty transcript.
  | { kind: "not-enabled"; header: KeystrokeHeader };

/// Read a `.rdp-rec`'s keystroke transcript: trailer fast path, then
/// the `0x08` scan when the trailer cannot be read.
export function readTranscript(bytes: Uint8Array): TranscriptState {
  const head = headerAndStart(bytes);
  const header = head
    ? parseKeystrokeHeader(head.header)
    : {
        version: 0,
        keystrokeMetadata: false,
        keyboardLayout: null,
        keyboardLayoutSource: null,
        maxReorderMs: 0,
      };

  const attempt = readTrailer(bytes);
  if (attempt.ok) {
    return { kind: "transcript", transcript: attempt.transcript, header };
  }
  if (attempt.error.kind === "no-magic") {
    // No footer. Either there was never a keystroke track, or the tail
    // was lost. The header settles which.
    if (!header.keystrokeMetadata) return { kind: "not-enabled", header };
    return { kind: "transcript", transcript: scanTextRecords(bytes), header };
  }
  // A footer that is present but unusable is a damaged tail, not an
  // absent feature: fall back and say why.
  const transcript = scanTextRecords(bytes);
  transcript.warnings.unshift(attempt.error.message);
  return { kind: "transcript", transcript, header };
}

// ─── Little-endian readers (mirroring rdpDecoder.ts) ────────────────

function readU64Le(b: Uint8Array, p: number): number {
  const lo = b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] * 0x1000000);
  const hi =
    b[p + 4] | (b[p + 5] << 8) | (b[p + 6] << 16) | (b[p + 7] * 0x1000000);
  return lo + hi * 0x100000000;
}

function readU32Le(b: Uint8Array, p: number): number {
  return b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] * 0x1000000);
}

function readU16Le(b: Uint8Array, p: number): number {
  return b[p] | (b[p + 1] << 8);
}
