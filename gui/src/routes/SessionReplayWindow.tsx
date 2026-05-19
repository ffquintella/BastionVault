// Phase 8.3 — full-screen replay in a separate Tauri WebviewWindow.
// Spawned from the Recordings page via `rustionOpenReplayWindow`.
//
// Reads the recording id from the URL query (HashRouter), fetches
// the sidecar metadata + bytes via the same Tauri commands the modal
// uses, then routes to the format-specific renderer. No Layout chrome
// — this window is meant for operators to scrub a recording without
// the main app's sidebar in the way.

import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { Badge, Button } from "../components/ui";
import { extractError } from "../lib/error";
import {
  rustionRecordingBlob,
  rustionRecordingRead,
  rustionRecordingReplayLog,
  type RustionRecordingBlob,
  type RustionRecordingEntry,
} from "../lib/rustion";

export function SessionReplayWindow() {
  const [params] = useSearchParams();
  const recordingId = params.get("recording") ?? "";
  const [entry, setEntry] = useState<RustionRecordingEntry | null>(null);
  const [blob, setBlob] = useState<RustionRecordingBlob | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    document.title = `BastionVault — Replay ${recordingId}`;
    (async () => {
      try {
        const e = await rustionRecordingRead(recordingId);
        if (cancelled) return;
        setEntry(e);
        const b = await rustionRecordingBlob(recordingId);
        if (cancelled) return;
        setBlob(b);
        const bin = atob(b.bytesB64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
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
        Loading recording…
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
        {blob.format === "rdp-rec" && <ReplayRdpSummary bytes={bytes} />}
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

// ─── RDP summary (full screen) ──────────────────────────────────────

function ReplayRdpSummary({ bytes }: { bytes: Uint8Array }) {
  const summary = useMemo(() => walkRdpRec(bytes), [bytes]);
  return (
    <div className="space-y-4 max-w-5xl mx-auto">
      <div className="bg-amber-950/40 border border-amber-800 rounded p-3 text-xs text-amber-200">
        <strong>Visual RDP playback is a separate codec project.</strong>{" "}
        Decoding MS-RDPBCGR slow-path bitmap-update payloads (RLE + NSCodec +
        bitmap-cache management) is a multi-week protocol-decoder track and
        ships independently. The summary below comes from a wasm frame-walker
        included in this build; use the download below to view the raw{" "}
        <code>.rdp-rec</code> in an external player.
      </div>
      <div className="bg-neutral-900/60 border border-neutral-800 rounded p-3 text-xs">
        <div className="font-semibold mb-2 text-neutral-300">Header</div>
        {summary.header ? (
          <pre className="text-[10px] overflow-x-auto">
            {JSON.stringify(summary.header, null, 2)}
          </pre>
        ) : (
          <div className="text-red-300">{summary.error ?? "no header"}</div>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3">
          <div className="text-[var(--color-text-muted)] text-xs">
            Graphics frames
          </div>
          <div className="text-2xl font-semibold">{summary.graphics}</div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3">
          <div className="text-[var(--color-text-muted)] text-xs">
            Keyboard events
          </div>
          <div className="text-2xl font-semibold">{summary.keyboard}</div>
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-3">
          <div className="text-[var(--color-text-muted)] text-xs">
            Mouse events
          </div>
          <div className="text-2xl font-semibold">{summary.mouse}</div>
        </div>
      </div>
      <div className="text-xs text-[var(--color-text-muted)]">
        Duration: {(summary.durationMs / 1000).toFixed(1)}s · Total events:{" "}
        {summary.graphics + summary.keyboard + summary.mouse}
      </div>
    </div>
  );
}

function walkRdpRec(bytes: Uint8Array): {
  header: unknown | null;
  error?: string;
  graphics: number;
  keyboard: number;
  mouse: number;
  durationMs: number;
} {
  // Reuses the same TS parser as RdpRecSummary. Phase 8.3 also ships
  // a wasm version with the same exit shape — see gui/wasm/rdp-replay.
  if (bytes.length < 4 || String.fromCharCode(...bytes.slice(0, 4)) !== "RREC") {
    return {
      header: null,
      error: "magic mismatch (expected RREC)",
      graphics: 0,
      keyboard: 0,
      mouse: 0,
      durationMs: 0,
    };
  }
  let nl = -1;
  for (let i = 4; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) {
      nl = i;
      break;
    }
  }
  if (nl < 0) {
    return {
      header: null,
      error: "no header newline",
      graphics: 0,
      keyboard: 0,
      mouse: 0,
      durationMs: 0,
    };
  }
  let header: unknown = null;
  try {
    header = JSON.parse(new TextDecoder().decode(bytes.slice(4, nl)));
  } catch (e) {
    return {
      header: null,
      error: `header parse failed: ${e}`,
      graphics: 0,
      keyboard: 0,
      mouse: 0,
      durationMs: 0,
    };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = nl + 1;
  let graphics = 0,
    keyboard = 0,
    mouse = 0,
    lastTs = 0;
  while (pos + 13 <= bytes.length) {
    const ts = Number(view.getBigUint64(pos, true));
    const type = bytes[pos + 8];
    const len = view.getUint32(pos + 9, true);
    const next = pos + 13 + len;
    if (next > bytes.length) break;
    if (type === 0x01) graphics++;
    else if (type === 0x02) keyboard++;
    else if (type === 0x03) mouse++;
    lastTs = ts;
    pos = next;
  }
  return { header, graphics, keyboard, mouse, durationMs: lastTs };
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
