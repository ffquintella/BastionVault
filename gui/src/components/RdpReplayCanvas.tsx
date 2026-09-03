// Canvas-based RDP replay for Rustion `.rdp-rec` recordings.
//
// Decodes the byte stream via `gui/src/lib/rdpDecoder.ts` (the TS port
// of `gui/wasm/rdp-replay`) and walks the recording's ordered timeline,
// blitting each paint at its (x, y) destination on the schedule the
// per-event timestamps describe.
//
// Two paint paths, picked by the recording's header version:
//
//   - `0x01` wire bitmaps (version >= 2) — decoded up front by the
//     decoder's `TS_BITMAP_DATA` path.
//   - `0x07` surface updates (version >= 3) — decoded *pixels*, which
//     the bastion produced by running a full client-side graphics
//     decode over a copy of the relayed stream. Each event is the
//     coalesced dirty region of the desktop at that moment; there is
//     no key-frame/delta distinction and no full-frame event at the
//     start, so the canvas begins blank and fills in as regions
//     arrive. Showing a correct canvas at time T means replaying every
//     region from the beginning — which is why Restart clears and
//     replays rather than seeking.
//
// Surface pixels are inflated one region at a time, at the moment of
// the blit, and dropped straight after: eagerly inflating a 454 s
// session's ~450 full-desktop regions would retain gigabytes.
//
// Controls: Play / Pause / Restart / Seek / 1x / 2x / 4x / 8x.
// The rendered/skipped report names *which* rejection bucket a skipped
// event landed in — that reporting is what made the black-canvas bug
// diagnosable, so it must not regress into a bare count.
//
// ## Seeking, and why it replays rather than jumps
//
// A `0x07` region is the coalesced dirty rectangle of the desktop at
// that moment — there is no key frame and no full-frame event at the
// start. A correct canvas at time T therefore requires every region
// from the beginning, so `seekTo(T)` clears the canvas and replays
// every timeline event up to T as fast as it can decode them, then
// resumes normal-speed playback. That is not an optimisation to fix
// later; it is what the format allows.
//
// ## Version 4: the keystroke transcript
//
// Version 4 adds `0x08` text-input records and a `0x7F` keystroke
// trailer. Both are invisible to everything above: they are not
// graphics, they are not in `timeline`, and `rdpDecoder` skips their
// payloads. The transcript pane below the canvas reads them through
// `rdpKeystrokes.ts`, anchors each run at its own `t`, and the
// operator can click a run to seek the video to it.
//
// The one thing version 4 changes for a player is that
// `timestamp_ms` is **not monotonic across records** — keystroke
// records are buffered until their run closes, bounded by the
// header's `max_reorder_ms`. `timeline` holds only graphics and
// desktop-size events, which remain monotonic among themselves, so
// the playback loop needs no change. Do not add a monotonicity
// assertion; it would fire on a valid version-4 file.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Button, Badge } from "./ui";
import { RdpTranscriptPane } from "./RdpTranscriptPane";
import {
  COUNT_RLE16,
  COUNT_RLE24,
  COUNT_SURFACE,
  COUNT_UNCOMPRESSED,
  COUNT_KEYSTROKE_BAD_VERSION,
  COUNT_UNKNOWN_EVENT,
  MAX_SUPPORTED_VERSION,
  decodeRdpRec,
  renderSurfaceUpdate,
  type DecodeResult,
  type SurfaceUpdate,
} from "../lib/rdpDecoder";

interface Props {
  bytes: Uint8Array;
  /// Offset in ms to seek to on mount. Set from a keystroke-search
  /// hit's `t` so an operator lands on the moment the text was typed
  /// instead of scrubbing for it.
  initialSeekMs?: number;
}

const SPEEDS = [1, 2, 4, 8] as const;

/// Buckets that mean "this event reached the canvas".
const PAINTED_KEYS = [
  COUNT_UNCOMPRESSED,
  COUNT_RLE16,
  COUNT_RLE24,
  COUNT_SURFACE,
] as const;

/// Fallback canvas size when the recording carries no desktop geometry
/// at all (header `0x0`, no `0x06`, nothing paintable to infer from).
const FALLBACK_W = 1024;
const FALLBACK_H = 768;

export function RdpReplayCanvas({ bytes, initialSeekMs }: Props) {
  const decoded: DecodeResult = useMemo(() => decodeRdpRec(bytes), [bytes]);

  // Initial canvas size: the header's negotiated desktop, else the
  // bounding box of everything we could actually paint, else a
  // default. A rejected event's rect gets no vote — that geometry is
  // exactly what we refused to trust, and letting it size the canvas
  // turns a bad recording into a multi-gigabyte backing store.
  const { canvasW, canvasH } = useMemo(() => {
    let w = decoded.screenWidth;
    let h = decoded.screenHeight;
    if (w === 0 || h === 0) {
      for (const f of decoded.frames) {
        if (f.error !== null) continue;
        w = Math.max(w, f.x + f.width);
        h = Math.max(h, f.y + f.height);
      }
      for (const u of decoded.surfaceUpdates) {
        if (u.error !== null) continue;
        w = Math.max(w, u.x + u.width);
        h = Math.max(h, u.y + u.height);
      }
      for (const d of decoded.desktopSizes) {
        w = Math.max(w, d.width);
        h = Math.max(h, d.height);
      }
    }
    if (w === 0) w = FALLBACK_W;
    if (h === 0) h = FALLBACK_H;
    return { canvasW: w, canvasH: h };
  }, [decoded]);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(1);
  const [position, setPosition] = useState(0); // ms played
  const [done, setDone] = useState(false);
  const [surfaceSize, setSurfaceSize] = useState({ w: canvasW, h: canvasH });

  // Counts discovered while painting: a surface region's zlib stream is
  // only inflated when the player reaches it, so inflate failures and
  // inflated-length mismatches cannot be known up front. They land
  // here and are merged into the static counts for display.
  const liveCountsRef = useRef<Record<string, number>>({});
  const [liveCounts, setLiveCounts] = useState<Record<string, number>>({});

  // Elapsed-ms position *within the recording*, as opposed to
  // `position`, which is time played since the current start/seek
  // base. The transcript pane anchors its runs on recording offsets,
  // so it needs the former.
  const [absPosition, setAbsPosition] = useState(0);
  const absPositionRef = useRef(0);

  const cursorRef = useRef(0);
  const startedAtRef = useRef<number | null>(null);
  const baseTsRef = useRef(0);
  const rafRef = useRef<number | null>(null);

  /// Size + clear the backing store. Setting `width`/`height` clears a
  /// canvas by definition, which is exactly the semantics a `0x06`
  /// desktop change calls for.
  const applySurface = useCallback((w: number, h: number) => {
    const c = canvasRef.current;
    if (!c) return;
    if (c.width !== w || c.height !== h) {
      c.width = w;
      c.height = h;
    }
    const ctx = c.getContext("2d");
    if (!ctx) return;
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
  }, []);

  const blit = useCallback(
    (rgba: Uint8ClampedArray, x: number, y: number, width: number, height: number) => {
      const c = canvasRef.current;
      if (!c) return;
      const ctx = c.getContext("2d");
      if (!ctx) return;
      // The region was already bounds-checked against the recording's
      // desktop. This clamp only bites when the canvas is smaller than
      // that desktop, which can only happen on the inferred-size
      // fallback path above.
      const w = Math.min(width, c.width - x);
      const h = Math.min(height, c.height - y);
      if (w <= 0 || h <= 0) return;
      if (w === width && h === height) {
        ctx.putImageData(
          new ImageData(rgba as unknown as Uint8ClampedArray<ArrayBuffer>, width, height),
          x,
          y,
        );
        return;
      }
      const sliced = new Uint8ClampedArray(w * h * 4);
      for (let row = 0; row < h; row++) {
        const src = row * width * 4;
        sliced.set(rgba.subarray(src, src + w * 4), row * w * 4);
      }
      ctx.putImageData(
        new ImageData(sliced as unknown as Uint8ClampedArray<ArrayBuffer>, w, h),
        x,
        y,
      );
    },
    [],
  );

  const paintSurface = useCallback(
    (u: SurfaceUpdate) => {
      const out = renderSurfaceUpdate(bytes, u);
      // Statically-rejected updates were already counted by the
      // decoder; only count what the render itself decided.
      if (u.error === null) {
        const counts = liveCountsRef.current;
        counts[out.countKey] = (counts[out.countKey] ?? 0) + 1;
      }
      if (out.rgba !== null) blit(out.rgba, u.x, u.y, u.width, u.height);
    },
    [bytes, blit],
  );

  // Reset playback when the input changes, and on mount.
  useEffect(() => {
    cursorRef.current = 0;
    startedAtRef.current = null;
    baseTsRef.current = 0;
    liveCountsRef.current = {};
    setLiveCounts({});
    setPosition(0);
    absPositionRef.current = 0;
    setAbsPosition(0);
    setDone(false);
    setSurfaceSize({ w: canvasW, h: canvasH });
    applySurface(canvasW, canvasH);
  }, [bytes, canvasW, canvasH, applySurface]);

  // Playback loop.
  useEffect(() => {
    if (!playing || done) return;
    const timeline = decoded.timeline;
    if (timeline.length === 0) {
      setDone(true);
      return;
    }
    if (cursorRef.current >= timeline.length) {
      setDone(true);
      return;
    }
    if (startedAtRef.current === null) {
      startedAtRef.current = performance.now();
      // `baseTsRef` is already set when a seek put us here; only a
      // fresh start (or a restart) takes its base from the first
      // event, which is what skips a recording's leading dead time.
      if (baseTsRef.current === 0) {
        baseTsRef.current = timeline[cursorRef.current].timestampMs;
      }
    }
    const tick = () => {
      if (startedAtRef.current === null) return;
      const elapsed = (performance.now() - startedAtRef.current) * speed;
      const targetTs = baseTsRef.current + elapsed;
      while (
        cursorRef.current < timeline.length &&
        timeline[cursorRef.current].timestampMs <= targetTs
      ) {
        const ev = timeline[cursorRef.current];
        cursorRef.current += 1;
        if (ev.kind === "bitmap") {
          if (ev.frame.error === null && ev.frame.rgba.length > 0) {
            blit(ev.frame.rgba, ev.frame.x, ev.frame.y, ev.frame.width, ev.frame.height);
          }
        } else if (ev.kind === "surface") {
          paintSurface(ev.update);
        } else {
          // A `0x06` whose size differs from the current canvas resizes
          // it and clears it — the desktop renegotiated, so nothing
          // painted against the old one is still valid.
          applySurface(ev.desktop.width, ev.desktop.height);
          setSurfaceSize({ w: ev.desktop.width, h: ev.desktop.height });
        }
      }
      setLiveCounts({ ...liveCountsRef.current });
      setPosition(targetTs - baseTsRef.current);
      absPositionRef.current = targetTs;
      setAbsPosition(targetTs);
      if (cursorRef.current >= timeline.length) {
        setDone(true);
        return;
      }
      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
      startedAtRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing, done, speed, decoded.timeline, applySurface, blit, paintSurface]);

  const restart = useCallback(() => {
    cursorRef.current = 0;
    startedAtRef.current = null;
    baseTsRef.current = 0;
    liveCountsRef.current = {};
    setLiveCounts({});
    setPosition(0);
    absPositionRef.current = 0;
    setAbsPosition(0);
    setDone(false);
    setPlaying(true);
    setSurfaceSize({ w: canvasW, h: canvasH });
    applySurface(canvasW, canvasH);
  }, [applySurface, canvasW, canvasH]);

  /// Seek to `targetMs`.
  ///
  /// A `0x07` region is the coalesced dirty rectangle at its moment —
  /// no key frames, no full-frame event at the start — so a correct
  /// canvas at T is "every region from the beginning, applied in
  /// order". This clears and replays them as fast as they decode,
  /// then hands the timeline back to the rAF loop from T. There is no
  /// cheaper correct seek in this format.
  const seekTo = useCallback(
    (targetMs: number) => {
      const timeline = decoded.timeline;
      cursorRef.current = 0;
      liveCountsRef.current = {};
      let w = canvasW;
      let h = canvasH;
      applySurface(w, h);
      while (
        cursorRef.current < timeline.length &&
        timeline[cursorRef.current].timestampMs <= targetMs
      ) {
        const ev = timeline[cursorRef.current];
        cursorRef.current += 1;
        if (ev.kind === "bitmap") {
          if (ev.frame.error === null && ev.frame.rgba.length > 0) {
            blit(ev.frame.rgba, ev.frame.x, ev.frame.y, ev.frame.width, ev.frame.height);
          }
        } else if (ev.kind === "surface") {
          paintSurface(ev.update);
        } else {
          w = ev.desktop.width;
          h = ev.desktop.height;
          applySurface(w, h);
        }
      }
      setSurfaceSize({ w, h });
      setLiveCounts({ ...liveCountsRef.current });
      absPositionRef.current = targetMs;
      setAbsPosition(targetMs);
      // Re-base the clock on the seek target rather than on the next
      // event's timestamp: a gap between regions is real dead time in
      // the session and swallowing it would desynchronise the
      // transcript pane's highlight from the video.
      startedAtRef.current = null;
      baseTsRef.current = targetMs;
      setPosition(0);
      setDone(cursorRef.current >= timeline.length);
      setPlaying(cursorRef.current < timeline.length);
    },
    [applySurface, blit, paintSurface, decoded.timeline, canvasW, canvasH],
  );

  // Land on a keystroke-search hit's offset when the caller asked for
  // one. Deliberately keyed on `bytes` too, so re-opening the same
  // recording at a different hit seeks again.
  useEffect(() => {
    if (initialSeekMs === undefined || initialSeekMs <= 0) return;
    seekTo(initialSeekMs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bytes, initialSeekMs]);

  if (!decoded.ok) {
    return (
      <div className="p-3 text-sm text-red-300 bg-red-950/40 border border-red-900 rounded">
        Failed to decode recording: {decoded.error}
      </div>
    );
  }

  const counts: Record<string, number> = { ...decoded.decoderCounts };
  for (const [k, v] of Object.entries(liveCounts)) {
    counts[k] = (counts[k] ?? 0) + v;
  }

  const totalGraphics = decoded.frames.length + decoded.surfaceUpdates.length;
  const rendered = PAINTED_KEYS.reduce((n, k) => n + (counts[k] ?? 0), 0);
  const unknownEvents = counts[COUNT_UNKNOWN_EVENT] ?? 0;
  // Everything counted that is neither a paint nor a non-graphics
  // event type we skipped on purpose.
  const skipped = Object.entries(counts).reduce(
    (n, [k, v]) =>
      (PAINTED_KEYS as readonly string[]).includes(k) || k === COUNT_UNKNOWN_EVENT
        ? n
        : n + v,
    0,
  );
  const pending = totalGraphics - rendered - skipped;

  const dominantFailure =
    Object.entries(counts)
      .filter(
        ([k]) =>
          !(PAINTED_KEYS as readonly string[]).includes(k) &&
          k !== COUNT_UNKNOWN_EVENT,
      )
      .sort((a, b) => b[1] - a[1])[0] ?? null;
  const firstError =
    decoded.frames.find((f) => f.error !== null)?.error ??
    decoded.surfaceUpdates.find((u) => u.error !== null)?.error ??
    null;

  // Nothing decodable at all, and nothing left to try. The canvas would
  // otherwise sit black with no indication that this is a failure
  // rather than a session that happened to start on a dark screen — a
  // silent downgrade on an audit surface.
  const nothingRendered =
    totalGraphics > 0 && rendered === 0 && (pending === 0 || done);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Button size="sm" onClick={() => setPlaying((p) => !p)} disabled={done}>
          {playing ? "Pause" : "Play"}
        </Button>
        <Button size="sm" variant="secondary" onClick={restart}>
          Restart
        </Button>
        <div className="flex items-center gap-1 ml-2">
          {SPEEDS.map((s) => (
            <button
              key={s}
              onClick={() => setSpeed(s)}
              className={
                "px-2 py-0.5 text-xs rounded border " +
                (speed === s
                  ? "bg-[var(--color-accent)] text-white border-[var(--color-accent)]"
                  : "border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]")
              }
            >
              {s}×
            </button>
          ))}
        </div>
        <span className="ml-2 text-[var(--color-text-muted)]">
          {(absPosition / 1000).toFixed(1)}s /{" "}
          {(decoded.durationMs / 1000).toFixed(1)}s
        </span>
        {position > 0 && absPosition !== position && (
          <span className="text-[var(--color-text-muted)]">
            ({(position / 1000).toFixed(1)}s played)
          </span>
        )}
        {done && <Badge variant="success" label="complete" />}
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--color-text-muted)]">
        <span>
          <strong className="text-[var(--color-text)]">{rendered}</strong>{" "}
          rendered
        </span>
        <span>·</span>
        <span>
          <strong className="text-[var(--color-text)]">{skipped}</strong> skipped
        </span>
        <span>·</span>
        <span>
          <strong className="text-[var(--color-text)]">{totalGraphics}</strong>{" "}
          total
        </span>
        <span>·</span>
        <span>
          {surfaceSize.w}×{surfaceSize.h}
        </span>
        <span>·</span>
        <span>v{decoded.version || "?"}</span>
        {decoded.version >= 4 && (
          <>
            <span>·</span>
            <span>
              {decoded.keystrokeMetadata
                ? `${decoded.textInputEvents} keystroke run record${decoded.textInputEvents === 1 ? "" : "s"}`
                : "keystrokes not recorded"}
            </span>
            {decoded.maxReorderMs > 0 && (
              <>
                <span>·</span>
                <span title="Keystroke records may appear up to this far out of order; graphics records stay monotonic among themselves, so the video is unaffected.">
                  reorder bound {decoded.maxReorderMs} ms
                </span>
              </>
            )}
          </>
        )}
        {unknownEvents > 0 && (
          <>
            <span>·</span>
            <span>
              {unknownEvents} unknown event{unknownEvents === 1 ? "" : "s"}{" "}
              skipped
            </span>
          </>
        )}
        {skipped > 0 && dominantFailure && (
          <Badge
            variant="warning"
            label={`lossy: ${dominantFailure[0]} ×${dominantFailure[1]}`}
          />
        )}
      </div>

      {skipped > 0 && (
        <details className="text-xs text-[var(--color-text-muted)]">
          <summary className="cursor-pointer">
            Skip reasons ({skipped})
          </summary>
          <ul className="mt-1 ml-4 space-y-0.5 font-mono">
            {Object.entries(counts)
              .filter(
                ([k]) =>
                  !(PAINTED_KEYS as readonly string[]).includes(k) &&
                  k !== COUNT_UNKNOWN_EVENT,
              )
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => (
                <li key={k}>
                  {k}: {v}
                </li>
              ))}
          </ul>
        </details>
      )}

      {decoded.truncated && (
        <div className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded">
          <div className="font-semibold">Recording is truncated.</div>
          <div className="text-xs text-amber-200/80 font-mono break-all">
            {decoded.truncated}
          </div>
          <div className="text-xs text-amber-200/80">
            Everything before the incomplete record is replayed as normal.
            Compare the artifact against the sidecar&apos;s{" "}
            <code>size_bytes</code> and SHA-256.
          </div>
        </div>
      )}

      {(counts[COUNT_KEYSTROKE_BAD_VERSION] ?? 0) > 0 && (
        <div className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded space-y-1">
          <div className="font-semibold">
            This recording contradicts its own header.
          </div>
          <div className="text-xs text-amber-200/80">
            It declares format version {decoded.version || "?"} but carries{" "}
            {counts[COUNT_KEYSTROKE_BAD_VERSION]} keystroke record(s), which
            were added in version 4. They were skipped by their declared
            length rather than read: a file that misdescribes itself is not one
            to trust on an audit surface, and silently accepting the records
            would be a fallback. The graphics above are unaffected.
          </div>
        </div>
      )}

      {decoded.newerFormat && (
        <div className="p-3 text-sm text-sky-200 bg-sky-950/40 border border-sky-900 rounded">
          <div className="font-semibold">
            Produced by a newer bastion (format version {decoded.version}).
          </div>
          <div className="text-xs text-sky-200/80">
            This player understands version {MAX_SUPPORTED_VERSION}. Known event
            types are decoded and the rest are skipped by their declared
            length, so the replay may be incomplete — upgrade BastionVault to
            see everything this recording holds.
          </div>
        </div>
      )}

      {decoded.graphicsUndecodable && totalGraphics > 0 && (
        <div className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded space-y-1">
          <div className="font-semibold">
            Metadata only: this is a version-{decoded.version || "?"} recording
            and its {totalGraphics} graphics events are not decodable.
          </div>
          <div className="text-xs text-amber-200/80">
            Version-1 graphics events are undelimited slices of the raw byte
            stream, captured by a recording tap that accepted roughly a quarter
            of all bytes as frames. They are not pixels in any encoding, so
            nothing is rendered rather than painting noise. Keyboard, mouse,
            timing and session metadata below are still accurate.
          </div>
          <div className="text-xs text-amber-200/80">
            Only sessions recorded after the bastion&apos;s recording upgrade
            (format version 3) carry decodable pixels.
          </div>
        </div>
      )}

      {decoded.graphicsNotRecordable && (
        <div className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded space-y-1">
          <div className="font-semibold">
            This session&apos;s graphics were not recordable.
          </div>
          <div className="text-xs text-amber-200/80">
            The recording is format version {decoded.version} and contains no
            graphics events at all — neither wire bitmaps nor decoded surface
            updates. That is a real state, not a decode failure: the bastion
            could not represent this session&apos;s graphics. The remaining
            known cause is AVC420 / AVC444 (H.264) over EGFX, which the bastion
            counts but does not decode.
          </div>
          <div className="text-xs text-amber-200/80">
            Check the bastion audit chain for a{" "}
            <code>recording_graphics_unrepresentable</code> entry, or its{" "}
            <code>RECORDING_GRAPHICS_CENSUS</code> log event, for the reason and
            counts. That signal is not yet carried in the recording sidecar
            BastionVault imports.
          </div>
          {decoded.graphicsEncodings.length > 0 && (
            <div className="text-xs font-mono text-amber-200/70">
              header advertised: {decoded.graphicsEncodings.join(", ")}
            </div>
          )}
        </div>
      )}

      {nothingRendered && !decoded.graphicsUndecodable && (
        <div className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded space-y-1">
          <div className="font-semibold">
            No video: none of the {totalGraphics} graphics events could be
            decoded.
          </div>
          <div className="text-xs text-amber-200/80">
            The canvas below stays black because nothing was drawn — this is a
            decode failure, not a dark session.
            {dominantFailure &&
              ` Dominant reason: ${dominantFailure[0]} (${dominantFailure[1]} of ${totalGraphics}).`}
          </div>
          {firstError && (
            <div className="text-xs font-mono break-all text-amber-200/70">
              first: {firstError}
            </div>
          )}
          <div className="text-xs text-amber-200/80">
            Download the raw <code>.rdp-rec</code> and check the recorder on the
            bastion.
          </div>
        </div>
      )}

      <div className="bg-black rounded border border-[var(--color-border)] overflow-auto">
        <canvas
          ref={canvasRef}
          style={{
            display: "block",
            maxWidth: "100%",
            imageRendering: "pixelated",
          }}
        />
      </div>

      {/* The keystroke transcript, anchored on recording offsets and
          wired to the seek above. Rendered for every recording — a
          version <= 3 file and a version-4 file with the feature off
          get an explicit "not enabled" notice from the pane, because
          an absent pane would read as "nothing was typed". */}
      <RdpTranscriptPane
        bytes={bytes}
        positionMs={absPosition}
        onSeek={seekTo}
      />
    </div>
  );
}
