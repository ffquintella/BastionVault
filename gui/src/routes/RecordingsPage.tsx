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
import { extractError } from "../lib/error";
import {
  rustionRecordingBlob,
  rustionRecordingPull,
  rustionRecordingRead,
  rustionRecordingsList,
  type RustionRecordingBlob,
  type RustionRecordingEntry,
} from "../lib/rustion";

export function RecordingsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [entries, setEntries] = useState<RustionRecordingEntry[]>([]);
  const [search, setSearch] = useState("");
  const [filterFormat, setFilterFormat] = useState<string>("");
  const [filterDelivery, setFilterDelivery] = useState<string>("");
  const [selected, setSelected] = useState<RustionRecordingEntry | null>(null);
  const [pullInput, setPullInput] = useState({ bastionId: "", sessionId: "" });
  const [pulling, setPulling] = useState(false);

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
      setPullInput({ bastionId: "", sessionId: "" });
      await reload();
    } catch (e) {
      toast.toast("error", `Pull failed: ${extractError(e)}`);
    } finally {
      setPulling(false);
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
        </div>

        <Card className="p-4">
          <h2 className="text-sm font-semibold mb-3">Force-pull a recording</h2>
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Bastion ID"
              value={pullInput.bastionId}
              onChange={(e) =>
                setPullInput({ ...pullInput, bastionId: e.target.value })
              }
              placeholder="rt_<16 hex>"
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
          <div className="mt-3">
            <Button onClick={handlePull} loading={pulling} variant="primary">
              Pull from bastion
            </Button>
          </div>
        </Card>

        <Card className="p-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
            <Input
              label="Search"
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
                  ? "Once an enrolled bastion finishes a session, its recording.ready webhook will land here."
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
  const [blob, setBlob] = useState<RustionRecordingBlob | null>(null);
  const [loading, setLoading] = useState(true);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const b = await rustionRecordingBlob(entry.recordingId);
        if (cancelled) return;
        setBlob(b);
        // base64 → Uint8Array
        const bin = atob(b.bytesB64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        setBytes(arr);
      } catch (e) {
        toast.toast("error", `Failed to fetch recording: ${extractError(e)}`);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
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
            Loading recording bytes…
          </div>
        ) : bytes && blob ? (
          <>
            {blob.format === "asciicast" && (
              <AsciicastPlayer bytes={bytes} />
            )}
            {blob.format === "rdp-rec" && <RdpRecSummary bytes={bytes} />}
            {blob.format === "smb-log" && <SmbLogSummary bytes={bytes} />}
            <div className="flex justify-end">
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
  const summary = useMemo(() => parseRdpRec(bytes), [bytes]);
  return (
    <div className="space-y-3">
      <div className="bg-neutral-900/60 border border-neutral-800 rounded p-3 text-xs">
        <div className="font-semibold mb-2 text-neutral-300">
          RDP recording header
        </div>
        {summary.header ? (
          <pre className="text-[10px] overflow-x-auto">
            {JSON.stringify(summary.header, null, 2)}
          </pre>
        ) : (
          <div className="text-red-300">{summary.error ?? "no header"}</div>
        )}
      </div>
      <div className="grid grid-cols-3 gap-3 text-xs">
        <Card className="p-3">
          <div className="text-neutral-500">Graphics frames</div>
          <div className="text-lg font-semibold">{summary.graphics}</div>
        </Card>
        <Card className="p-3">
          <div className="text-neutral-500">Keyboard events</div>
          <div className="text-lg font-semibold">{summary.keyboard}</div>
        </Card>
        <Card className="p-3">
          <div className="text-neutral-500">Mouse events</div>
          <div className="text-lg font-semibold">{summary.mouse}</div>
        </Card>
      </div>
      <div className="text-xs text-neutral-400">
        Duration: {(summary.durationMs / 1000).toFixed(1)}s · Events:{" "}
        {summary.graphics + summary.keyboard + summary.mouse}
      </div>
      <div className="text-xs text-neutral-500 leading-relaxed">
        Inline visual playback of RDP recordings requires decoding the upstream's
        raw RDP bitmap-update payloads (MS-RDPBCGR). The downloaded{" "}
        <code className="font-mono">.rdp-rec</code> file can be opened in an
        external player; a native in-GUI replayer is tracked as a future
        enhancement (it's a multi-week protocol-decoder engineering task on its
        own track).
      </div>
    </div>
  );
}

function parseRdpRec(bytes: Uint8Array): {
  header: any | null;
  error?: string;
  graphics: number;
  keyboard: number;
  mouse: number;
  durationMs: number;
} {
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
  // Find the newline after the JSON header.
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
  let header: any = null;
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
  // Walk events: timestamp:u64le + type:u8 + len:u32le + payload[len]
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
