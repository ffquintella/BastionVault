// Phase 8.3 — full-screen replay in a separate Tauri WebviewWindow.
// Spawned from the Recordings page via `rustionOpenReplayWindow`.
//
// Reads the recording id from the URL query (HashRouter), fetches
// the sidecar metadata + bytes via the same Tauri commands the modal
// uses, then routes to the format-specific renderer. No Layout chrome
// — this window is meant for operators to scrub a recording without
// the main app's sidebar in the way.

import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";

import { Badge, Button } from "../components/ui";
import { RdpReplayCanvas } from "../components/RdpReplayCanvas";
import { decodeRdpRec } from "../lib/rdpDecoder";
import { extractError } from "../lib/error";
import {
  fetchRecordingBytes,
  rustionRecordingRead,
  rustionRecordingReplayLog,
  type RecordingBytes,
  type RustionRecordingEntry,
} from "../lib/rustion";

export function SessionReplayWindow() {
  const [params] = useSearchParams();
  const recordingId = params.get("recording") ?? "";
  // Phase 8.6 — `?at=<ms>` seeks the player, set from a
  // keystroke-search hit. A numeric offset and nothing else: the
  // query and the matched text never travel in a URL.
  const seekMs = Number.parseInt(params.get("at") ?? "", 10);
  const initialSeekMs = Number.isFinite(seekMs) && seekMs > 0 ? seekMs : undefined;
  const [entry, setEntry] = useState<RustionRecordingEntry | null>(null);
  const [blob, setBlob] = useState<RecordingBytes | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [progress, setProgress] = useState<{ received: number; total: number } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const abort = new AbortController();
    document.title = `BastionVault — Replay ${recordingId}`;
    (async () => {
      try {
        const e = await rustionRecordingRead(recordingId);
        if (cancelled) return;
        setEntry(e);
        // Chunked fetch: playback must not depend on the whole
        // artifact fitting in one response.
        const b = await fetchRecordingBytes(recordingId, {
          signal: abort.signal,
          onProgress: (received, total) => {
            if (!cancelled) setProgress({ received, total });
          },
        });
        if (cancelled) return;
        setBlob(b);
        const arr = b.bytes;
        setBytes(arr);
        // Phase 8.2 audit-log emission with sha256 integrity check.
        try {
          let mismatch = false;
          const expected = (b.sha256 || e.sha256 || "").toLowerCase();
          if (expected && typeof crypto.subtle?.digest === "function") {
            const digest = await crypto.subtle.digest(
              "SHA-256",
              arr.buffer as ArrayBuffer,
            );
            const got = Array.from(new Uint8Array(digest))
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
            mismatch = got !== expected;
          }
          await rustionRecordingReplayLog(recordingId, mismatch);
        } catch (logErr) {
          console.warn("replay-log failed:", logErr);
        }
      } catch (e) {
        if (!cancelled) setError(extractError(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
      abort.abort();
    };
  }, [recordingId]);

  if (!recordingId) {
    return (
      <div className="p-6 text-sm text-red-300">
        Missing <code>?recording=</code> parameter.
      </div>
    );
  }
  if (loading) {
    return (
      <div className="p-6 text-sm text-[var(--color-text-muted)]">
        {progress && progress.total > 0
          ? `Loading recording… ${Math.floor((progress.received / progress.total) * 100)}%`
          : "Loading recording…"}
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-6 text-sm text-red-300">
        <div className="font-semibold mb-2">Failed to load recording</div>
        <div>{error}</div>
      </div>
    );
  }
  if (!entry || !blob || !bytes) {
    return (
      <div className="p-6 text-sm text-[var(--color-text-muted)]">
        Recording unavailable.
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="px-4 py-3 border-b border-[var(--color-border)] flex items-center justify-between">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold font-mono truncate">
            {entry.recordingId}
          </h1>
          <div className="text-xs text-[var(--color-text-muted)] truncate">
            <span className="font-mono">{entry.targetUser}</span>
            <span> @ </span>
            <span className="font-mono">{entry.targetHost}</span>
            <span className="mx-2">·</span>
            <span>{entry.authority || "—"}</span>
            <span className="mx-2">·</span>
            <span>{entry.format}</span>
          </div>
        </div>
        <Badge variant="info" label={blob.format} />
      </header>
      <main className="p-4">
        {blob.format === "asciicast" && <ReplayAsciicast bytes={bytes} />}
        {blob.format === "rdp-rec" && (
          <ReplayRdp bytes={bytes} initialSeekMs={initialSeekMs} />
        )}
        {blob.format === "smb-log" && <ReplaySmbSummary bytes={bytes} />}
      </main>
      <footer className="px-4 py-2 border-t border-[var(--color-border)] flex justify-between items-center text-xs text-[var(--color-text-muted)]">
        <div>
          sha256: <span className="font-mono">{entry.sha256}</span>
        </div>
        <Button size="sm" onClick={() => window.close()}>
          Close
        </Button>
      </footer>
    </div>
  );
}

// ─── Asciicast (full screen) ────────────────────────────────────────

function ReplayAsciicast({ bytes }: { bytes: Uint8Array }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let cancelled = false;
    // We can't import @xterm types statically (they're loaded
    // lazily below); using `any` here keeps the lazy-import shape
    // and avoids a top-level type dep.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let terminal: any = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    (async () => {
      const text = new TextDecoder().decode(bytes);
      const lines = text.split("\n").filter((l) => l.length > 0);
      if (lines.length === 0) {
        setError("Empty asciicast");
        return;
      }
      let header: { width?: number; height?: number };
      try {
        header = JSON.parse(lines[0]);
      } catch (e) {
        setError(`Invalid asciicast header: ${e}`);
        return;
      }
      const events: Array<[number, string, string]> = [];
      for (let i = 1; i < lines.length; i++) {
        try {
          const ev = JSON.parse(lines[i]);
          if (Array.isArray(ev) && ev.length >= 3) {
            events.push([ev[0], ev[1], ev[2]]);
          }
        } catch {
          // skip
        }
      }
      if (cancelled || !containerRef.current) return;
      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      await import("@xterm/xterm/css/xterm.css");
      terminal = new Terminal({
        cols: header.width ?? 100,
        rows: header.height ?? 30,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: 13,
        theme: { background: "#000000", foreground: "#e5e7eb" },
        convertEol: true,
        disableStdin: true,
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.open(containerRef.current);
      try {
        fitAddon.fit();
      } catch {
        /* ignore */
      }
      let idx = 0;
      const startedAt = performance.now();
      const tick = () => {
        if (cancelled || !terminal) return;
        const now = (performance.now() - startedAt) / 1000;
        while (idx < events.length && events[idx][0] <= now) {
          if (events[idx][1] === "o") {
            terminal.write(events[idx][2]);
          }
          idx++;
        }
        if (idx < events.length) {
          const wait = Math.max(0, (events[idx][0] - now) * 1000);
          timer = setTimeout(tick, Math.min(wait, 200));
        } else {
          setDone(true);
        }
      };
      tick();
    })();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      if (terminal) terminal.dispose();
    };
  }, [bytes]);

  if (error) {
    return (
      <div className="bg-red-950/40 border border-red-800 rounded p-3 text-sm text-red-200">
        {error}
      </div>
    );
  }
  return (
    <div>
      <div className="text-xs text-[var(--color-text-muted)] mb-1">
        {done ? "Playback complete" : "Playing…"}
      </div>
      <div
        ref={containerRef}
        className="bg-black rounded p-2"
        style={{ minHeight: "70vh" }}
      />
    </div>
  );
}

// ─── RDP playback (full screen) ─────────────────────────────────────

function ReplayRdp({
  bytes,
  initialSeekMs,
}: {
  bytes: Uint8Array;
  initialSeekMs?: number;
}) {
  const [showDetails, setShowDetails] = useState(false);
  return (
    <div className="space-y-4 max-w-[1600px] mx-auto">
      <RdpReplayCanvas bytes={bytes} initialSeekMs={initialSeekMs} />
      <div>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => setShowDetails((v) => !v)}
        >
          {showDetails ? "Hide details" : "Show details"}
        </Button>
      </div>
      {showDetails && <ReplayRdpSummary bytes={bytes} />}
    </div>
  );
}

function ReplayRdpSummary({ bytes }: { bytes: Uint8Array }) {
  // The same decoder the canvas above uses. Indexing only — no 0x07
  // pixels are inflated to render a summary.
  const decoded = useMemo(() => decodeRdpRec(bytes), [bytes]);
  const header = useMemo(() => {
    if (!decoded.headerJson) return null;
    try {
      return JSON.parse(decoded.headerJson) as unknown;
    } catch {
      return null;
    }
  }, [decoded.headerJson]);
  const graphics = decoded.frames.length + decoded.surfaceUpdates.length;
  return (
    <div className="space-y-4">
      <div className="bg-neutral-900/60 border border-neutral-800 rounded p-3 text-xs text-[var(--color-text-muted)]">
        <strong>Keystroke track:</strong> version-4 recordings add a{" "}
        <code>0x08</code> text-input record per keystroke run and a{" "}
        <code>0x7F</code> trailer holding the whole transcript, located by
        reading the last 8 bytes of the artifact rather than scanning it.
        Neither touches the graphics, and both are skipped by their declared
        length on older players. From version 4 the record stream is no longer
        monotonic in <code>timestamp_ms</code> — keystroke records are buffered
        until their run closes, bounded by the header&apos;s{" "}
        <code>max_reorder_ms</code> — but graphics records stay monotonic among
        themselves, so the video is unaffected.
      </div>
      <div className="bg-neutral-900/60 border border-neutral-800 rounded p-3 text-xs text-[var(--color-text-muted)]">
        <strong>Graphics paths:</strong> version-3 recordings carry{" "}
        <code>0x07</code> surface updates — pixels the bastion decoded
        client-side over a copy of the relayed stream — which are inflated and
        blitted directly. Version-2 recordings carry <code>0x01</code> wire
        bitmaps, decoded here for uncompressed 16/24/32 bpp and RLE16/RLE24;
        8 bpp RLE, NSCodec, RemoteFX and bitmap-cache references are not
        decoded on that path. Version-1 recordings carry no decodable graphics
        at all. Anything not painted is named in the skip-reason breakdown
        above.
      </div>
      <div className="bg-neutral-900/60 border border-neutral-800 rounded p-3 text-xs">
        <div className="font-semibold mb-2 text-neutral-300">Header</div>
        {header ? (
          <pre className="text-[10px] overflow-x-auto">
            {JSON.stringify(header, null, 2)}
          </pre>
        ) : (
          <div className="text-red-300">{decoded.error ?? "no header"}</div>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3 min-w-0">
          <div className="text-[var(--color-text-muted)] text-xs">
            Surface updates (0x07)
          </div>
          <div className="text-2xl font-semibold">
            {decoded.surfaceUpdates.length}
          </div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3 min-w-0">
          <div className="text-[var(--color-text-muted)] text-xs">
            Wire bitmaps (0x01)
          </div>
          <div className="text-2xl font-semibold">{decoded.frames.length}</div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3 min-w-0">
          <div className="text-[var(--color-text-muted)] text-xs">
            Keyboard events
          </div>
          <div className="text-2xl font-semibold">
            {decoded.keyboardEvents}
          </div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3 min-w-0">
          <div className="text-[var(--color-text-muted)] text-xs">
            Mouse events
          </div>
          <div className="text-2xl font-semibold">{decoded.mouseEvents}</div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3 min-w-0">
          <div className="text-[var(--color-text-muted)] text-xs">
            Keystroke runs (0x08)
          </div>
          <div className="text-2xl font-semibold">
            {decoded.version >= 4 && decoded.keystrokeMetadata
              ? decoded.textInputEvents
              : "—"}
          </div>
          <div className="text-[var(--color-text-muted)] text-xs">
            {decoded.version < 4
              ? "predates the keystroke track"
              : !decoded.keystrokeMetadata
                ? "not enabled for this session"
                : decoded.keystrokeTrailer
                  ? "trailer present"
                  : "no trailer — recovered by scan"}
          </div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3 min-w-0">
          <div className="text-[var(--color-text-muted)] text-xs">
            Keyboard layout
          </div>
          <div className="text-sm font-semibold font-mono truncate">
            {decoded.keyboardLayout ?? "—"}
          </div>
          <div className="text-[var(--color-text-muted)] text-xs truncate">
            {decoded.keyboardLayoutSource ?? "not recorded"}
          </div>
        </div>
      </div>
      <div className="text-xs text-[var(--color-text-muted)]">
        Format version {decoded.version || "?"} · Duration:{" "}
        {(decoded.durationMs / 1000).toFixed(1)}s · Total events:{" "}
        {graphics +
          decoded.keyboardEvents +
          decoded.mouseEvents +
          decoded.desktopSizes.length +
          decoded.unknownEvents}
        {decoded.unknownEvents > 0 &&
          ` · ${decoded.unknownEvents} unknown event type(s) skipped by declared length`}
        {decoded.desktopSizes.length > 0 &&
          ` · ${decoded.desktopSizes.length} desktop-size change(s)`}
      </div>
    </div>
  );
}

// ─── SMB log (full screen) ──────────────────────────────────────────

function ReplaySmbSummary({ bytes }: { bytes: Uint8Array }) {
  const text = useMemo(() => new TextDecoder().decode(bytes), [bytes]);
  const lines = useMemo(
    () => text.split("\n").filter((l) => l.length > 0),
    [text],
  );
  return (
    <div className="max-w-5xl mx-auto">
      <div className="text-xs text-[var(--color-text-muted)] mb-1">
        {lines.length} operations recorded
      </div>
      <pre className="bg-neutral-950 border border-neutral-800 rounded p-3 text-[11px] max-h-[70vh] overflow-auto">
        {lines.join("\n")}
      </pre>
    </div>
  );
}
