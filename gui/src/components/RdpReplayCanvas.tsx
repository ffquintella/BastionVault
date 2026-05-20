// Phase 8.4 — canvas-based RDP replay.
//
// Decodes the `.rdp-rec` byte stream via the TS port of the BVRG WASM
// crate (see `gui/src/lib/rdpDecoder.ts` + `gui/wasm/rdp-replay`) and
// blits each decoded TS_BITMAP_DATA rectangle onto an HTML5 canvas at
// its (x, y, w, h) destination, scheduled by the per-event timestamps
// embedded in the recording.
//
// Controls: Play / Pause / Restart / 1× / 2× / 4× / 8× / scrub bar.
// The "skipped" counter surfaces frames the decoder couldn't render
// (unsupported codec / truncated body) so the operator knows the view
// isn't lossless when those show up.

import { useEffect, useMemo, useRef, useState } from "react";

import { Button, Badge } from "./ui";
import {
  decodeRdpRec,
  type DecodedFrame,
  type DecodeResult,
} from "../lib/rdpDecoder";

interface Props {
  bytes: Uint8Array;
}

interface RdpHeader {
  width?: number;
  height?: number;
  // tolerate other fields without typing them
  [k: string]: unknown;
}

const SPEEDS = [1, 2, 4, 8] as const;

export function RdpReplayCanvas({ bytes }: Props) {
  const decoded: DecodeResult = useMemo(() => decodeRdpRec(bytes), [bytes]);
  const header = useMemo<RdpHeader | null>(() => {
    if (!decoded.headerJson) return null;
    try {
      return JSON.parse(decoded.headerJson) as RdpHeader;
    } catch {
      return null;
    }
  }, [decoded.headerJson]);

  // Canvas size: prefer header width/height; otherwise infer the
  // bounding box from the union of all rectangles.
  const { canvasW, canvasH } = useMemo(() => {
    let w = typeof header?.width === "number" ? header.width : 0;
    let h = typeof header?.height === "number" ? header.height : 0;
    if (w === 0 || h === 0) {
      for (const f of decoded.frames) {
        w = Math.max(w, f.x + f.width);
        h = Math.max(h, f.y + f.height);
      }
    }
    // Sensible defaults if recording lacks size info
    if (w === 0) w = 1024;
    if (h === 0) h = 768;
    return { canvasW: w, canvasH: h };
  }, [decoded.frames, header]);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(1);
  const [position, setPosition] = useState(0); // ms played
  const [done, setDone] = useState(false);

  // Frame cursor (index of next frame to draw); kept in a ref so the
  // animation loop can mutate without re-renders.
  const cursorRef = useRef(0);
  const startedAtRef = useRef<number | null>(null);
  const baseTsRef = useRef(0);
  const rafRef = useRef<number | null>(null);

  // Black-fill the canvas once on first mount (RDP servers send an
  // initial paint as part of the connection sequence; if the recording
  // started mid-session we still want a clean background).
  useEffect(() => {
    const c = canvasRef.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, c.width, c.height);
  }, [canvasW, canvasH]);

  const drawFrame = (frame: DecodedFrame) => {
    const c = canvasRef.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    if (frame.error || frame.rgba.length === 0) return; // skip
    // Clamp blit to canvas to be defensive against bogus rects.
    const w = Math.min(frame.width, c.width - frame.x);
    const h = Math.min(frame.height, c.height - frame.y);
    if (w <= 0 || h <= 0) return;
    if (w === frame.width && h === frame.height) {
      const img = new ImageData(
        frame.rgba as unknown as Uint8ClampedArray<ArrayBuffer>,
        frame.width,
        frame.height,
      );
      ctx.putImageData(img, frame.x, frame.y);
    } else {
      // Partial blit — extract the visible slice. Rare; tolerate it
      // rather than dropping the frame.
      const sliced = new Uint8ClampedArray(w * h * 4);
      for (let row = 0; row < h; row++) {
        const src = row * frame.width * 4;
        sliced.set(
          frame.rgba.subarray(src, src + w * 4),
          row * w * 4,
        );
      }
      const img = new ImageData(
        sliced as unknown as Uint8ClampedArray<ArrayBuffer>,
        w,
        h,
      );
      ctx.putImageData(img, frame.x, frame.y);
    }
  };

  // Reset playback when input changes.
  useEffect(() => {
    cursorRef.current = 0;
    startedAtRef.current = null;
    baseTsRef.current = 0;
    setPosition(0);
    setDone(false);
    // Repaint background.
    const c = canvasRef.current;
    if (c) {
      const ctx = c.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#000";
        ctx.fillRect(0, 0, c.width, c.height);
      }
    }
  }, [bytes]);

  // Animation loop.
  useEffect(() => {
    if (!playing || done) return;
    const frames = decoded.frames;
    if (frames.length === 0) {
      setDone(true);
      return;
    }
    if (cursorRef.current >= frames.length) {
      setDone(true);
      return;
    }
    if (startedAtRef.current === null) {
      startedAtRef.current = performance.now();
      baseTsRef.current = frames[cursorRef.current].timestampMs;
    }
    const tick = () => {
      if (!startedAtRef.current) return;
      const elapsed = (performance.now() - startedAtRef.current) * speed;
      const targetTs = baseTsRef.current + elapsed;
      while (
        cursorRef.current < frames.length &&
        frames[cursorRef.current].timestampMs <= targetTs
      ) {
        drawFrame(frames[cursorRef.current]);
        cursorRef.current += 1;
      }
      setPosition(targetTs - baseTsRef.current);
      if (cursorRef.current >= frames.length) {
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
  }, [playing, done, speed, decoded.frames]);

  const restart = () => {
    cursorRef.current = 0;
    startedAtRef.current = null;
    baseTsRef.current = 0;
    setPosition(0);
    setDone(false);
    setPlaying(true);
    const c = canvasRef.current;
    if (c) {
      const ctx = c.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#000";
        ctx.fillRect(0, 0, c.width, c.height);
      }
    }
  };

  if (!decoded.ok) {
    return (
      <div className="p-3 text-sm text-red-300 bg-red-950/40 border border-red-900 rounded">
        Failed to decode recording: {decoded.error}
      </div>
    );
  }

  const drawn =
    (decoded.decoderCounts["uncompressed"] ?? 0) +
    (decoded.decoderCounts["rle16"] ?? 0) +
    (decoded.decoderCounts["rle24"] ?? 0);
  const skipped =
    (decoded.decoderCounts["unsupported"] ?? 0) +
    (decoded.decoderCounts["error"] ?? 0);
  const totalGraphics = decoded.frames.length;

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
          {(position / 1000).toFixed(1)}s /{" "}
          {(decoded.durationMs / 1000).toFixed(1)}s
        </span>
        {done && (
          <Badge variant="success" label="complete" />
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--color-text-muted)]">
        <span>
          <strong className="text-[var(--color-text)]">{drawn}</strong> rendered
        </span>
        <span>·</span>
        <span>
          <strong className="text-[var(--color-text)]">{skipped}</strong>{" "}
          skipped
        </span>
        <span>·</span>
        <span>
          <strong className="text-[var(--color-text)]">{totalGraphics}</strong>{" "}
          total
        </span>
        <span>·</span>
        <span>
          {canvasW}×{canvasH}
        </span>
        {skipped > 0 && (
          <Badge
            variant="warning"
            label="lossy: NSCodec/RemoteFX/8bpp out of scope"
          />
        )}
      </div>

      <div className="bg-black rounded border border-[var(--color-border)] overflow-auto">
        <canvas
          ref={canvasRef}
          width={canvasW}
          height={canvasH}
          style={{
            display: "block",
            maxWidth: "100%",
            imageRendering: "pixelated",
          }}
        />
      </div>
    </div>
  );
}
