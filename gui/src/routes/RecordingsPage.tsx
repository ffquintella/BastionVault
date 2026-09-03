// Phase 6.5 — Recordings page.
//
// Lists every recording entry BV knows about (either via the
// `recording.ready` webhook receiver or via the 24h pull-fallback)
// and lets the operator open the artifact inline.
//
// Playback fan-out:
//   - format=asciicast → AsciicastPlayer (xterm.js + a tiny native
//     scheduler we ship in this file). No third-party player dep.
//   - format=rdp-rec   → RdpRecSummary (frame walker showing event
//     counts + screen dimensions + download button). The full RDP
//     bitmap-codec decoder is a separate engineering project.
//   - format=smb-log   → SmbLogSummary (header + download).
//
// Common controls live in RecordingPlayer; the protocol-specific
// renderers are mounted underneath it.
//
// Phase 8.6 adds keystroke search over `.rdp-rec` version-4
// transcripts. Three things about that card are deliberate:
//
//   - The query goes over the Tauri IPC in a request *body* and then
//     into a POST body. It never lands in a URL, a query string, a
//     log line or an error message — it is user-supplied text
//     describing a secret-bearing corpus.
//   - The server matches per run over non-redacted text, so a hit can
//     never come from a withheld run. This page does not filter for
//     that; the data model guarantees it.
//   - An empty result is reported alongside how many recordings were
//     actually searched and how many have no transcript index yet.
//     "No hits" over an unindexed corpus is not a negative finding
//     and must not read as one.

import { useEffect, useMemo, useRef, useState } from "react";

import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  Select,
  Table,
  useToast,
} from "../components/ui";
import { RdpTranscriptPane, formatOffset } from "../components/RdpTranscriptPane";
import { decodeRdpRec } from "../lib/rdpDecoder";
import { extractError } from "../lib/error";
import {
  rustionKeystrokeSearch,
  rustionKeystrokesIndex,
  rustionOpenReplayWindow,
  fetchRecordingBytes,
  rustionRecordingPull,
  rustionRecordingsReconcile,
  rustionRecordingRead,
  rustionRecordingReplayLog,
  rustionRecordingsList,
  rustionTargetList,
  type RustionKeystrokeHit,
  type RustionKeystrokeSearchReport,
  type RecordingBytes,
  type RustionRecordingEntry,
  type RustionTargetSummary,
} from "../lib/rustion";
import { useNamespaceStore } from "../stores/namespaceStore";

export function RecordingsPage() {
  const toast = useToast();
  // Recordings are a deployment-global index, but the server scopes the list
  // to the active namespace: in a child namespace it returns only recordings
  // whose target host matches a resource that namespace owns. Root sees all.
  const activeNamespace = useNamespaceStore((s) => s.active);
  const inNamespace =
    activeNamespace.trim() !== "" && activeNamespace.trim() !== "root";
  const [loading, setLoading] = useState(true);
  const [entries, setEntries] = useState<RustionRecordingEntry[]>([]);
  const [search, setSearch] = useState("");
  const [filterFormat, setFilterFormat] = useState<string>("");
  const [filterDelivery, setFilterDelivery] = useState<string>("");
  const [selected, setSelected] = useState<RustionRecordingEntry | null>(null);
  const [pullInput, setPullInput] = useState({ bastionId: "", sessionId: "" });
  const [pulling, setPulling] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  // Enrolled bastions for the Force-pull dropdown. Loaded once on
  // mount; the operator picks by friendly name and we submit the id.
  // Avoids the previous freeform text input that let the operator
  // type the bastion *name* (`dev-1`) when the API wants the id
  // (`rt_<hex>`), which surfaced as `HTTP 500: Logical backend
  // operation not supported` from the per-target route resolver.
  const [bastions, setBastions] = useState<RustionTargetSummary[]>([]);
  const [bastionsLoading, setBastionsLoading] = useState(true);

  const reload = async () => {
    setLoading(true);
    try {
      const ids = await rustionRecordingsList();
      const rows = await Promise.all(
        ids.map((id) => rustionRecordingRead(id).catch(() => null)),
      );
      setEntries(rows.filter((r): r is RustionRecordingEntry => r !== null));
    } catch (e) {
      toast.toast("error", `Failed to load recordings: ${extractError(e)}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void reload();
    // Load enrolled bastions for the Force-pull dropdown. Failures
    // here are non-fatal — the dropdown just renders "No bastions
    // enrolled" and the operator can refresh from Settings.
    (async () => {
      try {
        const list = await rustionTargetList();
        setBastions(list);
        if (list.length > 0) {
          setPullInput((p) => (p.bastionId ? p : { ...p, bastionId: list[0].id }));
        }
      } catch (e) {
        toast.toast("error", `Failed to load bastions: ${extractError(e)}`);
      } finally {
        setBastionsLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter((r) => {
      if (filterFormat && r.format !== filterFormat) return false;
      if (filterDelivery && r.deliveryMode !== filterDelivery) return false;
      if (!q) return true;
      return (
        r.recordingId.toLowerCase().includes(q) ||
        r.sessionId.toLowerCase().includes(q) ||
        r.authority.toLowerCase().includes(q) ||
        r.targetHost.toLowerCase().includes(q) ||
        r.targetUser.toLowerCase().includes(q)
      );
    });
  }, [entries, search, filterFormat, filterDelivery]);

  const handlePull = async () => {
    if (!pullInput.bastionId || !pullInput.sessionId) {
      toast.toast("error", "Both bastion ID and session ID are required");
      return;
    }
    setPulling(true);
    try {
      const entry = await rustionRecordingPull(pullInput);
      toast.toast("success", `Pulled recording ${entry.recordingId}`);
      // Keep the selected bastion (operator likely wants to pull
      // another session from the same one); only clear the session id.
      setPullInput((p) => ({ ...p, sessionId: "" }));
      await reload();
    } catch (e) {
      toast.toast("error", `Pull failed: ${extractError(e)}`);
    } finally {
      setPulling(false);
    }
  };

  // Active reconcile: ask each enrolled bastion for its full recording
  // index and import anything we're missing. Recovers terminated
  // sessions and missed webhooks that the per-session pull can't reach.
  const handleReconcile = async () => {
    setReconciling(true);
    try {
      const rep = await rustionRecordingsReconcile(
        pullInput.bastionId || undefined,
      );
      toast.toast(
        rep.imported > 0 ? "success" : "info",
        `Reconcile: ${rep.imported} imported, ${rep.skippedExisting} already present (${rep.found} found)`,
      );
      await reload();
    } catch (e) {
      toast.toast("error", `Reconcile failed: ${extractError(e)}`);
    } finally {
      setReconciling(false);
    }
  };

  return (
    <Layout>
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-semibold">Recordings</h1>
          <p className="text-sm text-neutral-400 mt-1">
            Session recordings handed off by enrolled Rustion bastions. Webhook
            deliveries land here automatically; the 24h fallback poller and the
            manual pull below cover the edge cases.
          </p>
          {inNamespace && (
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              Scoped to <span className="font-mono">{activeNamespace}</span> —
              showing recordings whose target host matches a resource in this
              namespace. Switch to the root namespace to see every recording.
            </p>
          )}
        </div>

        <Card className="p-4">
          <h2 className="text-sm font-semibold mb-3">Force-pull a recording</h2>
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Bastion"
              value={pullInput.bastionId}
              onChange={(e) =>
                setPullInput({ ...pullInput, bastionId: e.target.value })
              }
              disabled={bastionsLoading || bastions.length === 0}
              options={
                bastions.length === 0
                  ? [
                      {
                        value: "",
                        label: bastionsLoading
                          ? "Loading…"
                          : "No bastions enrolled",
                      },
                    ]
                  : bastions.map((b) => ({
                      value: b.id,
                      label: `${b.name} (${b.id})`,
                    }))
              }
            />
            <Input
              label="Session ID"
              value={pullInput.sessionId}
              onChange={(e) =>
                setPullInput({ ...pullInput, sessionId: e.target.value })
              }
              placeholder="sess_<32 hex>"
            />
          </div>
          <div className="mt-3 flex items-center gap-2">
            <Button
              onClick={handlePull}
              loading={pulling}
              variant="primary"
              disabled={
                bastions.length === 0 || !pullInput.bastionId || !pullInput.sessionId
              }
            >
              Pull from bastion
            </Button>
            <Button
              onClick={handleReconcile}
              loading={reconciling}
              variant="secondary"
              disabled={bastions.length === 0}
            >
              {pullInput.bastionId ? "Sync this bastion" : "Sync all bastions"}
            </Button>
            <span className="text-xs text-neutral-500 min-w-0">
              Pulls the bastion's full recording index and imports anything
              missing — recovers closed sessions and missed webhooks.
            </span>
          </div>
        </Card>

        <KeystrokeSearchCard />

        <Card className="p-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
            <Input
              label="Metadata search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="recording id, session id, host, user…"
            />
            <Select
              label="Format"
              value={filterFormat}
              onChange={(e) => setFilterFormat(e.target.value)}
              options={[
                { value: "", label: "All formats" },
                { value: "asciicast", label: "asciicast (SSH)" },
                { value: "rdp-rec", label: "rdp-rec (RDP)" },
                { value: "smb-log", label: "smb-log (SMB)" },
              ]}
            />
            <Select
              label="Delivery"
              value={filterDelivery}
              onChange={(e) => setFilterDelivery(e.target.value)}
              options={[
                { value: "", label: "All deliveries" },
                { value: "webhook", label: "Webhook" },
                { value: "pull", label: "Pull-fallback" },
              ]}
            />
          </div>

          {loading ? (
            <div className="py-8 text-center text-neutral-400 text-sm">
              Loading recordings…
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState
              title={
                entries.length === 0
                  ? "No recordings yet"
                  : "No recordings match these filters"
              }
              description={
                entries.length === 0
                  ? inNamespace
                    ? `No recordings match a resource in ${activeNamespace}. Recordings appear here once a session targets one of this namespace's resources; switch to the root namespace to see every recording.`
                    : "Once an enrolled bastion finishes a session, its recording.ready webhook will land here."
                  : "Adjust the filters above to widen the view."
              }
            />
          ) : (
            <Table
              data={filtered}
              rowKey={(r) => r.recordingId}
              columns={[
                {
                  key: "recordingId",
                  header: "Recording",
                  render: (r) => (
                    <span className="font-mono text-xs">{r.recordingId}</span>
                  ),
                },
                {
                  key: "sessionId",
                  header: "Session",
                  render: (r) => (
                    <span className="font-mono text-xs">{r.sessionId}</span>
                  ),
                },
                {
                  key: "format",
                  header: "Format",
                  render: (r) => <Badge variant="info" label={r.format} />,
                },
                {
                  key: "authority",
                  header: "Authority",
                  render: (r) => r.authority || "—",
                },
                {
                  key: "target",
                  header: "Target",
                  render: (r) => (
                    <>
                      <span className="font-mono text-xs">{r.targetUser}</span>
                      <span className="text-neutral-500"> @ </span>
                      <span className="font-mono text-xs">{r.targetHost}</span>
                    </>
                  ),
                },
                {
                  key: "size",
                  header: "Size",
                  render: (r) => formatBytes(r.sizeBytes),
                },
                {
                  key: "delivery",
                  header: "Delivery",
                  render: (r) => (
                    <Badge
                      variant={
                        r.deliveryMode === "webhook" ? "success" : "neutral"
                      }
                      label={r.deliveryMode}
                    />
                  ),
                },
                {
                  key: "typed",
                  header: "Typed",
                  render: (r) => <KeystrokeBadge entry={r} />,
                },
                {
                  key: "received",
                  header: "Received",
                  render: (r) => (
                    <span className="text-xs text-[var(--color-text-muted)]">
                      {formatDate(r.receivedAt)}
                    </span>
                  ),
                },
                {
                  key: "actions",
                  header: "",
                  render: (r) => (
                    <Button size="sm" onClick={() => setSelected(r)}>
                      Open
                    </Button>
                  ),
                },
              ]}
            />
          )}
        </Card>
      </div>

      {selected && (
        <RecordingPlayerModal
          entry={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </Layout>
  );
}

// ─── Recording Player Modal ─────────────────────────────────────────

function RecordingPlayerModal({
  entry,
  onClose,
}: {
  entry: RustionRecordingEntry;
  onClose: () => void;
}) {
  const toast = useToast();
  const [blob, setBlob] = useState<RecordingBytes | null>(null);
  const [loading, setLoading] = useState(true);
  const [progress, setProgress] = useState<{ received: number; total: number } | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);

  useEffect(() => {
    let cancelled = false;
    const abort = new AbortController();
    (async () => {
      setLoading(true);
      setProgress(null);
      try {
        // Chunked: a recording is fetched in fixed slices, so a large
        // one is not rejected for being a single oversized response.
        const b = await fetchRecordingBytes(entry.recordingId, {
          signal: abort.signal,
          onProgress: (received, total) => {
            if (!cancelled) setProgress({ received, total });
          },
        });
        if (cancelled) return;
        setBlob(b);
        const arr = b.bytes;
        setBytes(arr);
        // Phase 8.2 — sha256 integrity check + recording.replayed
        // audit event. Hash the bytes locally and report a mismatch
        // to the audit chain if they don't match the sidecar.
        try {
          const expectedHex = (b.sha256 || entry.sha256 || "").toLowerCase();
          let mismatch = false;
          if (expectedHex && typeof crypto.subtle?.digest === "function") {
            const digest = await crypto.subtle.digest(
              "SHA-256",
              arr.buffer as ArrayBuffer,
            );
            const got = Array.from(new Uint8Array(digest))
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
            mismatch = got !== expectedHex;
            if (mismatch) {
              toast.toast(
                "error",
                `Recording sha256 mismatch — got ${got.slice(0, 12)}…, expected ${expectedHex.slice(0, 12)}…`,
              );
            }
          }
          await rustionRecordingReplayLog(entry.recordingId, mismatch);
        } catch (e) {
          // Best-effort: a missing crypto.subtle (older webviews) or
          // a network blip on the replay-log post should not break
          // playback.
          console.warn("recording replay-log failed:", e);
        }
      } catch (e) {
        // An abort is the modal closing mid-fetch, not a failure.
        if (!cancelled) {
          toast.toast("error", `Failed to fetch recording: ${extractError(e)}`);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
      abort.abort();
    };
  }, [entry.recordingId]);

  const handleDownload = () => {
    if (!bytes || !blob) return;
    const ext =
      blob.format === "rdp-rec"
        ? "rdp-rec"
        : blob.format === "smb-log"
          ? "smb-log"
          : "cast";
    const blobObj = new Blob([new Uint8Array(bytes)], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blobObj);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${entry.recordingId}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal open onClose={onClose} title={`Recording ${entry.recordingId}`} size="lg">
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <div className="text-neutral-500">Session</div>
            <div className="font-mono">{entry.sessionId}</div>
          </div>
          <div>
            <div className="text-neutral-500">Authority</div>
            <div className="font-mono">{entry.authority || "—"}</div>
          </div>
          <div>
            <div className="text-neutral-500">Target</div>
            <div className="font-mono">
              {entry.targetUser}@{entry.targetHost}
            </div>
          </div>
          <div>
            <div className="text-neutral-500">Format</div>
            <div className="font-mono">{entry.format}</div>
          </div>
          <div>
            <div className="text-neutral-500">Size</div>
            <div className="font-mono">{formatBytes(entry.sizeBytes)}</div>
          </div>
          <div>
            <div className="text-neutral-500">SHA-256</div>
            <div className="font-mono text-[10px] truncate">{entry.sha256}</div>
          </div>
        </div>

        {loading ? (
          <div className="py-8 text-center text-neutral-400 text-sm">
            {progress && progress.total > 0
              ? `Loading recording bytes… ${formatBytes(progress.received)} of ${formatBytes(progress.total)} (${Math.floor((progress.received / progress.total) * 100)}%)`
              : "Loading recording bytes…"}
          </div>
        ) : bytes && blob ? (
          <>
            {blob.format === "asciicast" && (
              <AsciicastPlayer bytes={bytes} />
            )}
            {blob.format === "rdp-rec" && (
              <>
                <RdpRecSummary bytes={bytes} />
                {/* Read straight out of the artifact bytes above, so
                    the transcript is here whether or not the server
                    has indexed this recording for search yet. The
                    pane renders its own explicit "not enabled"
                    notice for a version <= 3 file — an absent pane
                    would read as "nothing was typed". */}
                <RdpTranscriptPane bytes={bytes} />
              </>
            )}
            {blob.format === "smb-log" && <SmbLogSummary bytes={bytes} />}
            <div className="flex justify-end gap-2">
              <Button
                onClick={async () => {
                  try {
                    await rustionOpenReplayWindow(entry.recordingId);
                  } catch (e) {
                    toast.toast("error", `Open replay window: ${extractError(e)}`);
                  }
                }}
                variant="secondary"
              >
                Open in window
              </Button>
              <Button onClick={handleDownload} variant="secondary">
                Download {blob.format === "rdp-rec" ? "(.rdp-rec)" : ""}
              </Button>
            </div>
          </>
        ) : (
          <div className="py-4 text-neutral-400 text-sm">
            Recording bytes unavailable.
          </div>
        )}
      </div>
    </Modal>
  );
}

// ─── Asciicast player (xterm.js + native scheduler) ────────────────

function AsciicastPlayer({ bytes }: { bytes: Uint8Array }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    let cancelled = false;
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
          // skip malformed lines
        }
      }

      if (cancelled || !containerRef.current) return;
      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      await import("@xterm/xterm/css/xterm.css");
      terminal = new Terminal({
        cols: header.width ?? 80,
        rows: header.height ?? 24,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: 12,
        theme: { background: "#000000", foreground: "#cbd5e1" },
        convertEol: true,
        disableStdin: true,
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.open(containerRef.current);
      try {
        fitAddon.fit();
      } catch {
        // ignore — small containers may throw before layout
      }

      setPlaying(true);
      let idx = 0;
      const startedAt = performance.now();
      const tick = () => {
        if (cancelled || !terminal) return;
        const now = (performance.now() - startedAt) / 1000;
        while (idx < events.length && events[idx][0] <= now) {
          const [, type, data] = events[idx];
          if (type === "o") {
            terminal.write(data);
          }
          idx++;
        }
        if (idx < events.length) {
          const wait = Math.max(0, (events[idx][0] - now) * 1000);
          timer = setTimeout(tick, Math.min(wait, 200));
        } else {
          setPlaying(false);
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
      <div className="text-xs text-neutral-500 mb-1">
        {playing ? "Playing…" : "Finished"}
      </div>
      <div
        ref={containerRef}
        className="bg-black rounded p-2"
        style={{ minHeight: 300 }}
      />
    </div>
  );
}

// ─── RDP-rec summary (no inline visual replay) ─────────────────────

function RdpRecSummary({ bytes }: { bytes: Uint8Array }) {
  // Same decoder the canvas player uses, so the counts here and the
  // counts there cannot disagree. `decodeRdpRec` only *indexes* the
  // 0x07 surface updates — no pixels are inflated for a summary.
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
    <div className="space-y-3">
      <div className="bg-neutral-900/60 border border-neutral-800 rounded p-3 text-xs">
        <div className="font-semibold mb-2 text-neutral-300">
          RDP recording header
        </div>
        {header ? (
          <pre className="text-[10px] overflow-x-auto">
            {JSON.stringify(header, null, 2)}
          </pre>
        ) : (
          <div className="text-red-300">{decoded.error ?? "no header"}</div>
        )}
      </div>
      <div className="grid grid-cols-3 gap-3 text-xs">
        <Card className="p-3">
          <div className="text-neutral-500">Graphics events</div>
          <div className="text-lg font-semibold">{graphics}</div>
          <div className="text-neutral-500">
            {decoded.frames.length} bitmap · {decoded.surfaceUpdates.length}{" "}
            surface
          </div>
        </Card>
        <Card className="p-3">
          <div className="text-neutral-500">Keyboard events</div>
          <div className="text-lg font-semibold">{decoded.keyboardEvents}</div>
        </Card>
        <Card className="p-3">
          <div className="text-neutral-500">Mouse events</div>
          <div className="text-lg font-semibold">{decoded.mouseEvents}</div>
        </Card>
      </div>
      <div className="text-xs text-neutral-400">
        Format version {decoded.version || "?"} · Duration:{" "}
        {(decoded.durationMs / 1000).toFixed(1)}s · Events:{" "}
        {graphics +
          decoded.keyboardEvents +
          decoded.mouseEvents +
          decoded.unknownEvents}
        {decoded.screenWidth > 0 &&
          ` · ${decoded.screenWidth}×${decoded.screenHeight}`}
      </div>
      {decoded.truncated && (
        <div className="text-xs text-amber-300">{decoded.truncated}</div>
      )}
      <div className="text-xs text-neutral-500 leading-relaxed">
        {decoded.graphicsUndecodable
          ? "This is a version-1 recording: its graphics events are undelimited slices of the raw byte stream and cannot be rendered. Open in a window for the full explanation, or download the artifact."
          : decoded.graphicsNotRecordable
            ? "This version-3 recording contains no graphics events — the bastion could not represent this session's graphics. Check the bastion audit chain for recording_graphics_unrepresentable."
            : "Open in a window to replay this recording on a canvas. Version-3 recordings carry pixels the bastion decoded client-side; version-2 recordings carry wire bitmaps decoded here."}
      </div>
    </div>
  );
}

// ─── SMB-log summary ───────────────────────────────────────────────

function SmbLogSummary({ bytes }: { bytes: Uint8Array }) {
  const text = useMemo(() => new TextDecoder().decode(bytes), [bytes]);
  const lines = useMemo(() => text.split("\n").filter((l) => l.length > 0), [
    text,
  ]);
  return (
    <div>
      <div className="text-xs text-neutral-500 mb-1">
        {lines.length} operations recorded
      </div>
      <pre className="bg-neutral-950 border border-neutral-800 rounded p-2 text-[10px] max-h-72 overflow-auto">
        {lines.slice(0, 200).join("\n")}
        {lines.length > 200 ? `\n… (${lines.length - 200} more)` : ""}
      </pre>
    </div>
  );
}

// ─── Keystroke search (Phase 8.6) ──────────────────────────────────

/// Search recordings by what was typed in them.
///
/// The query is sent in a request body, never a URL, and the server
/// does not log it. Matching happens per keystroke run over
/// non-redacted text, so a hit can never come from a withheld run.
function KeystrokeSearchCard() {
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [indexing, setIndexing] = useState(false);
  const [report, setReport] = useState<RustionKeystrokeSearchReport | null>(
    null,
  );

  const run = async () => {
    const q = query.trim();
    if (!q) {
      toast.toast("error", "Enter some text to search for");
      return;
    }
    setSearching(true);
    try {
      setReport(await rustionKeystrokeSearch(q));
    } catch (e) {
      // `extractError` surfaces the server's message, which by
      // design never echoes the query back.
      toast.toast("error", `Keystroke search failed: ${extractError(e)}`);
    } finally {
      setSearching(false);
    }
  };

  const buildIndex = async () => {
    setIndexing(true);
    try {
      const rep = await rustionKeystrokesIndex();
      toast.toast(
        rep.indexed > 0 ? "success" : "info",
        `Transcript index: ${rep.indexed} indexed, ${rep.notEnabled} without keystroke recording, ` +
          `${rep.unchanged} already current, ${rep.failed} failed` +
          (rep.remaining > 0
            ? ` — ${rep.remaining} still queued (each costs a full artifact fetch, so the sweep is batched)`
            : ""),
      );
    } catch (e) {
      toast.toast("error", `Indexing failed: ${extractError(e)}`);
    } finally {
      setIndexing(false);
    }
  };

  return (
    <Card className="p-4">
      <h2 className="text-sm font-semibold mb-1">Search keystrokes</h2>
      <p className="text-xs text-neutral-500 mb-3">
        Finds RDP sessions by the text typed in them, from the keystroke
        transcript inside each <code>.rdp-rec</code> version-4 artifact.
        Non-character keys appear as bracketed tokens — search{" "}
        <code>[Enter]</code>, <code>[Ctrl+C]</code>, <code>[F5]</code>.
      </p>
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="Typed text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void run();
          }}
          placeholder="net user /add"
        />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button onClick={run} loading={searching} variant="primary">
          Search
        </Button>
        <Button onClick={buildIndex} loading={indexing} variant="secondary">
          Build transcript index
        </Button>
        <span className="text-xs text-neutral-500 min-w-0">
          Transcripts are indexed in the background as recordings arrive; this
          forces a batch now.
        </span>
      </div>

      {report && <KeystrokeResults report={report} />}
    </Card>
  );
}

function KeystrokeResults({
  report,
}: {
  report: RustionKeystrokeSearchReport;
}) {
  return (
    <div className="mt-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold">
          {report.hits.length} match{report.hits.length === 1 ? "" : "es"}
        </span>
        <span className="text-neutral-500">
          in {report.scanned} indexed recording
          {report.scanned === 1 ? "" : "s"}
        </span>
        {report.truncated && (
          <Badge variant="warning" label="results truncated" />
        )}
      </div>

      {report.unindexed > 0 && (
        <div className="p-3 text-sm text-amber-200 bg-amber-950/40 border border-amber-900 rounded space-y-1">
          <div className="font-semibold">
            This search did not cover every recording.
          </div>
          <div className="text-xs text-amber-200/80">
            {report.unindexed} recording
            {report.unindexed === 1 ? " has" : "s have"} no transcript index
            yet, so {report.hits.length === 0 ? "this empty result" : "these results"}{" "}
            {report.hits.length === 0 ? "is" : "are"} not a complete answer.
            Run <strong>Build transcript index</strong> and search again.
          </div>
        </div>
      )}

      {report.hits.length === 0 ? (
        <div className="text-xs text-neutral-500">
          No run in an indexed transcript contains that text. Redacted runs
          carry no text and are unmatchable by design, so a secret that was
          withheld will never appear here.
        </div>
      ) : (
        <ul className="space-y-2 max-h-96 overflow-auto pr-1">
          {report.hits.map((h) => (
            <KeystrokeHitRow key={`${h.recordingId}-${h.runIndex}`} hit={h} />
          ))}
        </ul>
      )}

      {report.redactionDisclaimer && (
        <div className="text-xs text-neutral-500">
          {report.redactionDisclaimer}
        </div>
      )}
    </div>
  );
}

function KeystrokeHitRow({ hit }: { hit: RustionKeystrokeHit }) {
  const toast = useToast();
  return (
    <li className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 min-w-0">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-xs min-w-0">
        <span className="font-mono truncate">{hit.recordingId}</span>
        <span className="text-neutral-500">·</span>
        <span className="font-mono truncate">
          {hit.targetUser}@{hit.targetHost}
        </span>
        <span className="text-neutral-500">·</span>
        <span className="font-mono tabular-nums">{formatOffset(hit.tMs)}</span>
        <span className="text-neutral-500">
          {hit.n} char{hit.n === 1 ? "" : "s"}
        </span>
        {hit.approximate && (
          <Badge variant="warning" label="approximate" />
        )}
        {hit.textDecoding !== "exact" && (
          <Badge variant="warning" label={`decoding: ${hit.textDecoding}`} />
        )}
        {hit.rebuilt && <Badge variant="warning" label="trailer rebuilt" />}
        {!hit.complete && !hit.rebuilt && (
          <Badge variant="warning" label="transcript incomplete" />
        )}
      </div>
      <div className="mt-1 font-mono text-xs whitespace-pre-wrap break-all">
        {hit.excerpt}
      </div>
      <div className="mt-1">
        <Button
          size="sm"
          variant="secondary"
          onClick={async () => {
            try {
              // Only the offset travels in the replay window's URL —
              // never the query or the matched text.
              await rustionOpenReplayWindow(hit.recordingId, hit.tMs);
            } catch (e) {
              toast.toast("error", `Open replay window: ${extractError(e)}`);
            }
          }}
        >
          Open replay at {formatOffset(hit.tMs)}
        </Button>
      </div>
    </li>
  );
}

/// The Recordings list's per-row transcript state.
///
/// Four distinct states, and collapsing any two of them would be a
/// false statement on an audit surface:
///   - not an `.rdp-rec`: no keystroke track is possible at all;
///   - not indexed: BastionVault has not looked yet;
///   - not enabled: the bastion had keystroke recording off;
///   - indexed: N characters, M of them withheld.
function KeystrokeBadge({ entry }: { entry: RustionRecordingEntry }) {
  if (entry.format !== "rdp-rec") {
    return <span className="text-neutral-600 text-xs">n/a</span>;
  }
  if (entry.keystrokeState === "") {
    return (
      <span
        className="text-neutral-500 text-xs"
        title="No transcript index yet. This says nothing about whether anything was typed — run Build transcript index."
      >
        not indexed
      </span>
    );
  }
  if (entry.keystrokeState === "not-enabled") {
    return (
      <span
        className="text-neutral-400 text-xs"
        title="Keystroke recording was not enabled for this session (version <= 3, or version 4 with keystroke_metadata false). Not a statement that nothing was typed."
      >
        not recorded
      </span>
    );
  }
  if (entry.keystrokeState !== "indexed") {
    return (
      <Badge
        variant="warning"
        label={entry.keystrokeState}
      />
    );
  }
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="text-xs">
        {entry.keystrokeChars} char{entry.keystrokeChars === 1 ? "" : "s"}
        {entry.keystrokeRedactedRuns > 0 && (
          <span className="text-amber-300">
            {" "}
            · {entry.keystrokeRedactedRuns} withheld
          </span>
        )}
      </span>
      {(entry.keystrokeDecoding !== "exact" ||
        entry.keystrokeRebuilt ||
        !entry.keystrokeComplete) && (
        <span
          className="text-[10px] text-amber-300/90"
          title="Anything other than an exact, live-written trailer means the transcript is approximate or incomplete."
        >
          {entry.keystrokeRebuilt
            ? "rebuilt"
            : !entry.keystrokeComplete
              ? "incomplete"
              : entry.keystrokeDecoding}
        </span>
      )}
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDate(iso: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
