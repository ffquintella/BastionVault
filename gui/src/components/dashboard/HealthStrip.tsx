import { StatusBadge } from "../StatusBadge";
import type { ServerInfo } from "../../lib/api";

function formatUptime(seconds: number): string {
  if (!seconds || seconds < 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

interface HealthStripProps {
  sealed: boolean | null;
  server: ServerInfo | null;
}

/** Header health badges: seal state plus storage / version / uptime
 *  drawn from the server-info call. Renders what it has and quietly
 *  omits the rest. */
export function HealthStrip({ sealed, server }: HealthStripProps) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {sealed !== null && (
        <StatusBadge
          status={sealed ? "error" : "ok"}
          label={sealed ? "Sealed" : "Unsealed"}
        />
      )}
      {server && (
        <>
          {/* Version / storage / uptime belong to `/sys/info`'s
              authenticated disclosure tier, so they arrive empty (and
              uptime as 0) if the caller ever loses its token. Omit those
              pills rather than rendering a bare "v" and "up —", which
              reads as a broken server instead of a missing credential. */}
          {server.storage_type && (
            <Pill icon="🗄" text={server.storage_type} />
          )}
          {server.uptime_seconds > 0 && (
            <Pill icon="◴" text={`up ${formatUptime(server.uptime_seconds)}`} />
          )}
          {server.version && <Pill icon="" text={`v${server.version}`} />}
          <Pill
            icon=""
            text={server.connection_kind === "remote" ? "remote" : "embedded"}
          />
        </>
      )}
    </div>
  );
}

function Pill({ icon, text }: { icon: string; text: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-muted)]">
      {icon && <span aria-hidden>{icon}</span>}
      <span className="truncate max-w-[12rem]">{text}</span>
    </span>
  );
}
