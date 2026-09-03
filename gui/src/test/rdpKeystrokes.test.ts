// Tests for the `.rdp-rec` version-4 keystroke transcript reader.
//
// Mirrors the Rust tests in
// `crates/bv-engine-rustion/src/rdp_keystrokes.rs`, which are the
// spec. Fixtures are built from the format specification (Rustion's
// `docs/rdp-keystroke-metadata.md` §5), not captured from a recorder,
// so a producer bug cannot silently become the expectation.

import { describe, expect, it } from "vitest";

import {
  EVENT_KEYSTROKE_TRAILER,
  EVENT_TEXT_INPUT,
  FLAG_APPROXIMATE,
  FLAG_COMPOSED,
  FLAG_REDACTED,
  FLAG_RUN_END,
  MAX_TRAILER_RECORD_BYTES,
  RECORD_HEADER_LEN,
  TRAILER_FOOTER_LEN,
  headerAndStart,
  parseKeystrokeHeader,
  readTrailer,
  readTranscript,
  scanTextRecords,
} from "../lib/rdpKeystrokes";

// ─── Fixture builders ──────────────────────────────────────────────

function le16(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff];
}
function le32(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
}
function le64(n: number): number[] {
  const lo = n % 0x100000000;
  const hi = Math.floor(n / 0x100000000);
  return [...le32(lo), ...le32(hi)];
}

interface Ev {
  ts: number;
  kind: number;
  payload: number[];
}

function record(e: Ev): number[] {
  return [...le64(e.ts), e.kind, ...le32(e.payload.length), ...e.payload];
}

function textInput(
  ts: number,
  flags: number,
  epoch: number,
  charCount: number,
  text: string,
): number[] {
  const bytes = Array.from(new TextEncoder().encode(text));
  return record({
    ts,
    kind: EVENT_TEXT_INPUT,
    payload: [
      flags,
      ...le32(epoch),
      ...le16(charCount),
      ...le16(bytes.length),
      ...bytes,
    ],
  });
}

/// Build a `0x7F` record with the self-locating footer, exactly as
/// §5.3 lays it out: JSON, then `record_len:u32 LE`, then `"RKTR"`.
function trailerRecord(ts: number, json: string): number[] {
  const jsonBytes = Array.from(new TextEncoder().encode(json));
  const payloadLen = jsonBytes.length + TRAILER_FOOTER_LEN;
  const recordLen = RECORD_HEADER_LEN + payloadLen;
  const out = [
    ...le64(ts),
    EVENT_KEYSTROKE_TRAILER,
    ...le32(payloadLen),
    ...jsonBytes,
    ...le32(recordLen),
    0x52,
    0x4b,
    0x54,
    0x52, // "RKTR"
  ];
  expect(out.length).toBe(recordLen);
  return out;
}

/// Assembles into a `Uint8Array` rather than spreading into a
/// `number[]`: one fixture below is a 4 MiB artifact, and
/// `out.push(...r)` on that overflows the argument limit.
function file(header: string, records: number[][]): Uint8Array {
  const prefix = [0x52, 0x52, 0x45, 0x43]; // "RREC"
  const headerBytes = Array.from(new TextEncoder().encode(header));
  const total =
    prefix.length +
    headerBytes.length +
    1 +
    records.reduce((n, r) => n + r.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  out.set(prefix, at);
  at += prefix.length;
  out.set(headerBytes, at);
  at += headerBytes.length;
  out[at++] = 0x0a;
  for (const r of records) {
    out.set(r, at);
    at += r.length;
  }
  return out;
}

function graphics(ts: number, bytes: number): number[] {
  return record({ ts, kind: 0x07, payload: new Array(bytes).fill(0) });
}

const V4_HEADER = JSON.stringify({
  version: 4,
  screen_width: 1920,
  screen_height: 1080,
  keystroke_metadata: true,
  keyboard_layout: "0x00000416",
  keyboard_layout_source: "client_core",
  max_reorder_ms: 2000,
});

const TRAILER_JSON = JSON.stringify({
  trailer_version: 1,
  rebuilt: false,
  keyboard_layout: "0x00000416",
  keyboard_layout_source: "client_core",
  text_decoding: "exact",
  runs: [
    { t: 4120, d: 2310, n: 11, text: "notepad.exe[Enter]", redacted: false, epoch: 3 },
    { t: 20100, d: 1490, n: 14, text: null, redacted: true, reason: "known_secret", epoch: 4 },
  ],
  search_text: "notepad.exe[Enter]",
  text_applied: "notepad.exe\n",
  census: {
    keys_total: 412,
    chars_decoded: 388,
    unicode_events: 3,
    named_keys: 21,
    composed: 4,
    undecodable_scancodes: 0,
    redacted_runs: 1,
    redacted_chars: 14,
    slowpath_input_pdus: 0,
    truncated_runs: 0,
  },
});

// ─── Header ────────────────────────────────────────────────────────

describe("rdpKeystrokes — header", () => {
  it("reads the version-4 keystroke fields", () => {
    const h = parseKeystrokeHeader(V4_HEADER);
    expect(h.version).toBe(4);
    expect(h.keystrokeMetadata).toBe(true);
    expect(h.keyboardLayout).toBe("0x00000416");
    expect(h.keyboardLayoutSource).toBe("client_core");
    expect(h.maxReorderMs).toBe(2000);
  });

  it("reads a version-3 header as keystroke_metadata false", () => {
    // The compatibility contract: version <= 3 has no
    // `keystroke_metadata` key, and absent must read as false.
    const h = parseKeystrokeHeader(
      '{"version":3,"screen_width":1920,"screen_height":1080}',
    );
    expect(h.version).toBe(3);
    expect(h.keystrokeMetadata).toBe(false);
    expect(h.maxReorderMs).toBe(0);
    expect(h.keyboardLayout).toBeNull();
  });

  it("reads a malformed header as no keystrokes rather than throwing", () => {
    const h = parseKeystrokeHeader("not json at all");
    expect(h.version).toBe(0);
    expect(h.keystrokeMetadata).toBe(false);
  });

  it("rejects a foreign magic and a header with no newline", () => {
    expect(headerAndStart(new TextEncoder().encode("XXXX{}\n"))).toBeNull();
    expect(headerAndStart(new TextEncoder().encode("RREC{}"))).toBeNull();
    const got = headerAndStart(new TextEncoder().encode('RREC{"version":4}\nrest'));
    expect(got?.header).toBe('{"version":4}');
    expect(got?.start).toBe(4 + 13 + 1);
  });
});

// ─── Trailer fast path ─────────────────────────────────────────────

describe("rdpKeystrokes — trailer fast path", () => {
  it("locates the trailer by tail-seek and parses it", () => {
    const bytes = file(V4_HEADER, [trailerRecord(30_000, TRAILER_JSON)]);
    const out = readTrailer(bytes);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const t = out.transcript;
    expect(t.source).toBe("trailer-footer");
    expect(t.trailerVersion).toBe(1);
    expect(t.rebuilt).toBe(false);
    expect(t.complete).toBe(true);
    expect(t.textDecoding).toBe("exact");
    expect(t.runs.length).toBe(2);
    expect(t.census.keysTotal).toBe(412);
    expect(t.census.redactedChars).toBe(14);
    expect(t.warnings).toEqual([]);
  });

  it("reads a bounded number of bytes regardless of artifact size", () => {
    // The acceptance criterion for the fast path: growing the graphics
    // ahead of the trailer must not grow what a trailer read examines.
    const small = file(V4_HEADER, [
      graphics(1, 1024),
      trailerRecord(30_000, TRAILER_JSON),
    ]);
    const large = file(V4_HEADER, [
      graphics(1, 4 * 1024 * 1024),
      trailerRecord(30_000, TRAILER_JSON),
    ]);
    const a = readTrailer(small);
    const b = readTrailer(large);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.transcript.bytesExamined).toBe(b.transcript.bytesExamined);
    expect(b.transcript.bytesExamined).toBeLessThan(2048);
    expect(large.length).toBeGreaterThan(4 * 1024 * 1024);
  });

  it("keeps a redacted run's reason and count and gives it no text", () => {
    const bytes = file(V4_HEADER, [trailerRecord(30_000, TRAILER_JSON)]);
    const out = readTrailer(bytes);
    if (!out.ok) throw new Error("expected a trailer");
    const r = out.transcript.runs[1];
    expect(r.redacted).toBe(true);
    expect(r.text).toBeNull();
    expect(r.reason).toBe("known_secret");
    expect(r.n).toBe(14);
    expect(r.t).toBe(20100);
  });

  it("rebuilds searchText from non-redacted runs only", () => {
    const bytes = file(V4_HEADER, [trailerRecord(30_000, TRAILER_JSON)]);
    const out = readTrailer(bytes);
    if (!out.ok) throw new Error("expected a trailer");
    expect(out.transcript.searchText).toBe("notepad.exe[Enter]");
    expect(out.transcript.charsIndexed).toBe("notepad.exe[Enter]".length);
  });

  it("does not surface a producer search_text carrying redacted content", () => {
    // The defence for rule 2: a producer bug that leaks a withheld run
    // into `search_text` must not reach anything searchable.
    const json = JSON.stringify({
      trailer_version: 1,
      text_decoding: "exact",
      runs: [
        { t: 10, d: 5, n: 5, text: "ls -l", redacted: false, epoch: 1 },
        { t: 50, d: 9, n: 8, text: null, redacted: true, reason: "known_secret", epoch: 2 },
      ],
      search_text: "ls -l\nhunter22",
      census: {},
    });
    const out = readTrailer(file(V4_HEADER, [trailerRecord(9, json)]));
    if (!out.ok) throw new Error("expected a trailer");
    expect(out.transcript.searchText).toBe("ls -l");
    expect(out.transcript.searchText).not.toContain("hunter22");
    expect(out.transcript.warnings.some((w) => w.includes("differs from"))).toBe(true);
  });

  it("drops text from a run flagged redacted anyway", () => {
    const json = JSON.stringify({
      trailer_version: 1,
      text_decoding: "exact",
      runs: [
        { t: 50, d: 9, n: 8, text: "hunter22", redacted: true, reason: "known_secret", epoch: 2 },
      ],
      search_text: "",
      census: {},
    });
    const out = readTrailer(file(V4_HEADER, [trailerRecord(9, json)]));
    if (!out.ok) throw new Error("expected a trailer");
    expect(out.transcript.runs[0].text).toBeNull();
    expect(out.transcript.searchText).toBe("");
    expect(out.transcript.charsIndexed).toBe(0);
  });

  it("warns for rebuilt and for inexact decoding", () => {
    const json = JSON.stringify({
      trailer_version: 1,
      rebuilt: true,
      text_decoding: "approximate",
      runs: [],
      search_text: "",
      census: {},
    });
    const out = readTrailer(file(V4_HEADER, [trailerRecord(9, json)]));
    if (!out.ok) throw new Error("expected a trailer");
    expect(out.transcript.rebuilt).toBe(true);
    expect(out.transcript.complete).toBe(false);
    expect(out.transcript.warnings.some((w) => w.includes("rebuilt"))).toBe(true);
    expect(out.transcript.warnings.some((w) => w.includes("approximate"))).toBe(true);
  });

  it("sorts runs by t, because version-4 records are not monotonic", () => {
    const json = JSON.stringify({
      trailer_version: 1,
      text_decoding: "exact",
      runs: [
        { t: 900, d: 1, n: 1, text: "late", redacted: false, epoch: 2 },
        { t: 100, d: 1, n: 1, text: "early", redacted: false, epoch: 1 },
      ],
      search_text: "late\nearly",
      census: {},
    });
    const out = readTrailer(file(V4_HEADER, [trailerRecord(9, json)]));
    if (!out.ok) throw new Error("expected a trailer");
    expect(out.transcript.runs.map((r) => r.t)).toEqual([100, 900]);
    expect(out.transcript.searchText).toBe("early\nlate");
  });

  it("parses text_applied for display but keeps it out of searchText", () => {
    const bytes = file(V4_HEADER, [trailerRecord(30_000, TRAILER_JSON)]);
    const out = readTrailer(bytes);
    if (!out.ok) throw new Error("expected a trailer");
    expect(out.transcript.textApplied).toBe("notepad.exe\n");
    // Derived and lossy: it is not what `searchText` indexes.
    expect(out.transcript.searchText).not.toBe(out.transcript.textApplied);
  });
});

// ─── Trailer rejections ────────────────────────────────────────────

describe("rdpKeystrokes — trailer rejections", () => {
  it("reports no magic for a version-3 file", () => {
    const bytes = file('{"version":3,"screen_width":800,"screen_height":600}', [
      record({ ts: 1, kind: 0x01, payload: [1, 2, 3] }),
    ]);
    const out = readTrailer(bytes);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.error.kind).toBe("no-magic");
  });

  it("rejects a record_len past the end of the file", () => {
    const bytes = file(V4_HEADER, [trailerRecord(9, TRAILER_JSON)]);
    const n = bytes.length;
    bytes.set([0xff, 0xff, 0xff, 0xff], n - 8);
    const out = readTrailer(bytes);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.error.kind).toBe("bad-record-len");
  });

  it("rejects a record_len pointing at a non-trailer record", () => {
    const g = graphics(1, 64);
    const tr = trailerRecord(9, TRAILER_JSON);
    const bytes = file(V4_HEADER, [g, tr]);
    const n = bytes.length;
    bytes.set(le32(g.length + tr.length), n - 8);
    const out = readTrailer(bytes);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.error.kind).toBe("not-trailer-record");
  });

  it("caps an absurd record_len before touching the buffer", () => {
    const bytes = new Uint8Array(64);
    bytes.set(le32(MAX_TRAILER_RECORD_BYTES + 32), 64 - 8);
    bytes.set([0x52, 0x4b, 0x54, 0x52], 64 - 4);
    const out = readTrailer(bytes);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.error.kind).toBe("bad-record-len");
  });

  it("rejects an artifact shorter than the footer", () => {
    const out = readTrailer(new Uint8Array([0x52, 0x52, 0x45, 0x43]));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.error.kind).toBe("too-short");
  });

  it("reports broken trailer JSON without echoing its content", () => {
    const out = readTrailer(file(V4_HEADER, [trailerRecord(9, '{"runs": [ oops')]));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.error.kind).toBe("bad-json");
    // V8's SyntaxError quotes the offending source. Forwarding it
    // would turn a parse failure into a channel for transcript
    // content, so the message carries a length and nothing else.
    expect(out.error.message).not.toContain("oops");
    expect(out.error.message).not.toContain("runs");
  });
});

// ─── The 0x08 scan fallback ────────────────────────────────────────

describe("rdpKeystrokes — 0x08 scan fallback", () => {
  it("yields every completed run from a file truncated mid-trailer", () => {
    const full = file(V4_HEADER, [
      textInput(4120, FLAG_RUN_END, 3, 18, "notepad.exe[Enter]"),
      textInput(20100, FLAG_REDACTED | FLAG_RUN_END, 4, 14, ""),
      textInput(31000, FLAG_RUN_END, 5, 10, "dir[Enter]"),
      trailerRecord(40_000, TRAILER_JSON),
    ]);
    // Cut inside the trailer's JSON, losing the footer.
    const truncated = full.subarray(0, full.length - 40);
    const state = readTranscript(truncated);
    expect(state.kind).toBe("transcript");
    if (state.kind !== "transcript") return;
    const t = state.transcript;
    expect(t.source).toBe("text-record-scan");
    expect(t.complete).toBe(false);
    expect(t.runs.length).toBe(3);
    expect(t.runs[0].text).toBe("notepad.exe[Enter]");
    expect(t.runs[1].redacted).toBe(true);
    expect(t.runs[1].text).toBeNull();
    expect(t.runs[1].n).toBe(14);
    expect(t.runs[2].text).toBe("dir[Enter]");
    expect(t.searchText).toBe("notepad.exe[Enter]\ndir[Enter]");
  });

  it("concatenates fragments until RUN_END", () => {
    const bytes = file(V4_HEADER, [
      textInput(1000, 0, 1, 3, "net"),
      textInput(1100, 0, 1, 5, " user"),
      textInput(1200, FLAG_RUN_END | FLAG_COMPOSED, 1, 5, " /add"),
    ]);
    const t = scanTextRecords(bytes);
    expect(t.runs.length).toBe(1);
    expect(t.runs[0].text).toBe("net user /add");
    // The run's timestamp is its *first* keystroke, not its last.
    expect(t.runs[0].t).toBe(1000);
    expect(t.runs[0].n).toBe(13);
    expect(t.runs[0].composed).toBe(true);
  });

  it("drops the final unclosed run", () => {
    const bytes = file(V4_HEADER, [
      textInput(10, FLAG_RUN_END, 1, 2, "ok"),
      textInput(20, 0, 2, 6, "unterm"),
    ]);
    const t = scanTextRecords(bytes);
    expect(t.runs.length).toBe(1);
    expect(t.searchText).toBe("ok");
    expect(t.warnings.some((w) => w.includes("never closed"))).toBe(true);
  });

  it("lets a redacted fragment withhold the whole run", () => {
    // A run whose verdict lands on a later fragment must not publish
    // the text its earlier fragments carried.
    const bytes = file(V4_HEADER, [
      textInput(10, 0, 1, 4, "pass"),
      textInput(20, FLAG_REDACTED | FLAG_RUN_END, 1, 4, ""),
    ]);
    const t = scanTextRecords(bytes);
    expect(t.runs.length).toBe(1);
    expect(t.runs[0].redacted).toBe(true);
    expect(t.runs[0].text).toBeNull();
    expect(t.searchText).toBe("");
    expect(t.runs[0].n).toBe(8);
  });

  it("marks approximate but never claims exact", () => {
    const approx = file(V4_HEADER, [
      textInput(10, FLAG_RUN_END | FLAG_APPROXIMATE, 1, 2, "ab"),
    ]);
    expect(scanTextRecords(approx).textDecoding).toBe("approximate");
    const plain = file(V4_HEADER, [textInput(10, FLAG_RUN_END, 1, 2, "ab")]);
    expect(scanTextRecords(plain).textDecoding).toBe("unknown");
  });

  it("skips a malformed 0x08 record without giving up on the file", () => {
    const bytes = file(V4_HEADER, [
      record({ ts: 10, kind: EVENT_TEXT_INPUT, payload: [0x08, 0x00, 0x00] }),
      textInput(20, FLAG_RUN_END, 1, 2, "ok"),
    ]);
    const t = scanTextRecords(bytes);
    expect(t.runs.length).toBe(1);
    expect(t.warnings.some((w) => w.includes("malformed 0x08"))).toBe(true);
  });

  it("skips unknown event types by payload_len during a scan", () => {
    const bytes = file(V4_HEADER, [
      record({ ts: 1, kind: 0x5a, payload: new Array(300).fill(0xaa) }),
      textInput(10, FLAG_RUN_END, 1, 2, "ok"),
      record({ ts: 11, kind: 0x5b, payload: new Array(7).fill(0xbb) }),
    ]);
    const t = scanTextRecords(bytes);
    expect(t.runs.length).toBe(1);
    expect(t.searchText).toBe("ok");
  });

  it("survives non-monotonic timestamps and orders runs by t", () => {
    // Version 4's one behavioural break: a keystroke record is written
    // after graphics bearing a later timestamp.
    const bytes = file(V4_HEADER, [
      graphics(9_000, 16),
      textInput(4_000, FLAG_RUN_END, 2, 2, "yo"),
      graphics(9_500, 16),
      textInput(1_000, FLAG_RUN_END, 1, 2, "hi"),
    ]);
    const t = scanTextRecords(bytes);
    expect(t.runs.map((r) => r.t)).toEqual([1_000, 4_000]);
    expect(t.searchText).toBe("hi\nyo");
  });

  it("does not invent a text_applied on the scan path", () => {
    const bytes = file(V4_HEADER, [
      textInput(10, FLAG_RUN_END, 1, 12, "cd \\[Backspace]x"),
    ]);
    // A lossy, edited reconstruction with nothing upstream vouching
    // for it would be a guess presented as evidence.
    expect(scanTextRecords(bytes).textApplied).toBeNull();
  });
});

// ─── readTranscript: the path callers use ──────────────────────────

describe("rdpKeystrokes — readTranscript", () => {
  it("reports not-enabled for a version-3 file", () => {
    const bytes = file('{"version":3,"screen_width":800,"screen_height":600}', [
      record({ ts: 1, kind: 0x01, payload: [1, 2, 3] }),
      record({ ts: 2, kind: 0x02, payload: [0x1e, 0x01] }),
    ]);
    const state = readTranscript(bytes);
    // Not an empty transcript: a distinct state the UI renders as
    // "keystroke recording was not enabled for this session".
    expect(state.kind).toBe("not-enabled");
    expect(state.header.version).toBe(3);
  });

  it("reports not-enabled for a version-4 file with the feature off", () => {
    const bytes = file(
      '{"version":4,"keystroke_metadata":false,"max_reorder_ms":0}',
      [graphics(10, 32)],
    );
    const state = readTranscript(bytes);
    expect(state.kind).toBe("not-enabled");
    expect(state.header.version).toBe(4);
    expect(state.header.keystrokeMetadata).toBe(false);
  });

  it("prefers the trailer over the scan when both are available", () => {
    const bytes = file(V4_HEADER, [
      textInput(4120, FLAG_RUN_END, 3, 18, "notepad.exe[Enter]"),
      trailerRecord(40_000, TRAILER_JSON),
    ]);
    const state = readTranscript(bytes);
    if (state.kind !== "transcript") throw new Error("expected a transcript");
    expect(state.transcript.source).toBe("trailer-footer");
    // The trailer carries durations; a scan cannot.
    expect(state.transcript.runs[0].d).toBe(2310);
  });

  it("falls back when a version-4 trailer was never written", () => {
    const bytes = file(V4_HEADER, [
      textInput(4120, FLAG_RUN_END, 3, 18, "notepad.exe[Enter]"),
    ]);
    const state = readTranscript(bytes);
    if (state.kind !== "transcript") throw new Error("expected a transcript");
    expect(state.transcript.source).toBe("text-record-scan");
    expect(state.transcript.searchText).toBe("notepad.exe[Enter]");
    expect(
      state.transcript.warnings.some((w) => w.includes("no keystroke trailer")),
    ).toBe(true);
  });

  it("keeps the trailer error at the head of the warnings on a damaged tail", () => {
    const bytes = file(V4_HEADER, [
      textInput(10, FLAG_RUN_END, 1, 2, "ok"),
      trailerRecord(99, TRAILER_JSON),
    ]);
    // Corrupt `record_len` but leave the magic: a present-but-unusable
    // footer is a damaged tail, not an absent feature.
    bytes.set([0xff, 0xff, 0xff, 0xff], bytes.length - 8);
    const state = readTranscript(bytes);
    if (state.kind !== "transcript") throw new Error("expected a transcript");
    expect(state.transcript.source).toBe("text-record-scan");
    expect(state.transcript.warnings[0]).toContain("record_len");
    expect(state.transcript.runs.length).toBe(1);
  });
});
