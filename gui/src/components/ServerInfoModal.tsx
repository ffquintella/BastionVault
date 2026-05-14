import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Modal, Badge, Button } from "./ui";
import * as api from "../lib/api";
import type { ServerInfo } from "../lib/api";
import { extractError } from "../lib/error";

/**
 * Global modal mounted at the App root. The Tauri window menu's
 * "Server Info..." item emits `open-server-info` (see
 * `gui/src-tauri/src/lib.rs::on_menu_event`); this component listens
 * once at mount, fetches the latest info each time the event fires,
 * and renders a read-only summary.
 *
 * Stateless w.r.t. the connection itself — we always re-query, so
 * stale data after disconnect/reconnect is not a concern.
 */
export function ServerInfoModal() {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<ServerInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const unlisten = listen("open-server-info", async () => {
      if (cancelled) return;
      setOpen(true);
      setLoading(true);
      setError(null);
      setInfo(null);
      try {
        const result = await api.getServerInfo();
        if (!cancelled) setInfo(result);
      } catch (e: unknown) {
        if (!cancelled) setError(extractError(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    });
    return () => {
      cancelled = true;
      void unlisten.then((u) => u());
    };
  }, []);

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Server info"
      size="md"
      actions={
        <Button variant="ghost" onClick={() => setOpen(false)}>
          Close
        </Button>
      }
    >
      {loading && (
        <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
      )}
      {error && (
        <p className="text-sm text-[var(--color-danger)]">{error}</p>
      )}
      {info && (
        <div className="space-y-2 text-sm">
          <InfoRow
            label="Connection"
            value={
              <span className="flex items-center gap-2">
                <Badge
                  label={info.connection_kind}
                  variant={
                    info.connection_kind === "embedded" ? "info" : "success"
                  }
                />
                <span className="font-mono text-xs">{info.endpoint}</span>
              </span>
            }
          />
          <InfoRow label="Version" value={<code className="font-mono">{info.version}</code>} />
          <InfoRow
            label="Status"
            value={
              <span className="flex items-center gap-1">
                <Badge
                  label={info.sealed ? "sealed" : "unsealed"}
                  variant={info.sealed ? "error" : "success"}
                />
                <Badge
                  label={info.initialized ? "initialized" : "uninitialized"}
                  variant={info.initialized ? "success" : "warning"}
                />
              </span>
            }
          />
          <InfoRow
            label="Storage"
            value={<span className="font-mono text-xs">{info.storage_type || "unknown"}</span>}
          />
          <InfoRow
            label="Started at"
            value={
              <span className="font-mono text-xs">
                {info.started_at
                  ? new Date(info.started_at).toLocaleString()
                  : "-"}
              </span>
            }
          />
          <InfoRow label="Uptime" value={formatUptime(info.uptime_seconds)} />
        </div>
      )}
    </Modal>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 items-start">
      <span className="text-xs text-[var(--color-text-muted)] pt-0.5">{label}</span>
      <div>{value}</div>
    </div>
  );
}

function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "less than 1 second";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (mins) parts.push(`${mins}m`);
  parts.push(`${secs}s`);
  return parts.join(" ");
}
