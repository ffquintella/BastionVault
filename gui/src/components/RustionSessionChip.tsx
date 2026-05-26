/**
 * Phase 7.4 — lifecycle chip for Rustion-mediated session windows.
 *
 * Drops into the header of the spawned SSH / RDP session window. On
 * mount it calls `session_rustion_info(token)`:
 *   - null  → the session was dialed direct; the chip renders nothing.
 *   - bundle → drives [[useRustionSessionLifecycle]] so the session
 *     auto-renews at expiry − 60s and the operator can press Renew /
 *     Terminate manually. The chip surfaces the bastion name, the
 *     time remaining, and the renewal-budget counter.
 *
 * The hook expects a [[RustionSessionOpenResult]]-shaped object; we
 * synthesise one from the smaller bundle the host returns. Only the
 * fields the hook actually reads are filled — the rest stay empty so
 * we don't accidentally shadow values the host already validated.
 */

import { useEffect, useMemo, useState } from "react";

import {
  sessionRustionInfo,
  type SessionRustionInfo,
} from "../lib/api";
import { type RustionSessionOpenResult } from "../lib/rustion";
import { useRustionSessionLifecycle } from "../hooks/useRustionSessionLifecycle";

interface RustionSessionChipProps {
  /** The local SSH/RDP session token surfaced by the spawned window's
   *  URL params. Used as the key the host stashed the bundle under. */
  token: string;
  /** Optional inline color override so the chip blends with the host
   *  window's palette (RDP window has a darker header than SSH). */
  background?: string;
}

function formatTtl(expiresAt: string | null): string {
  if (!expiresAt) return "—";
  const ms = Date.parse(expiresAt) - Date.now();
  if (Number.isNaN(ms)) return "—";
  if (ms <= 0) return "expired";
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m === 0) return `${s}s`;
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

export function RustionSessionChip({ token, background }: RustionSessionChipProps) {
  const [info, setInfo] = useState<SessionRustionInfo | null>(null);
  // Tick once a second so the countdown moves. We keep it scoped to
  // the chip so the host window's render isn't dragged along.
  const [, setTick] = useState(0);

  useEffect(() => {
    if (!token) return;
    let alive = true;
    void sessionRustionInfo(token).then((res) => {
      if (alive) setInfo(res);
    });
    return () => {
      alive = false;
    };
  }, [token]);

  useEffect(() => {
    if (!info) return;
    const id = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [info]);

  // Synthesise the shape `useRustionSessionLifecycle` consumes. The
  // hook only reads bastion_id / session_id / correlation_id /
  // expires_at, but TypeScript wants the full interface — fill the
  // unused fields with empty defaults rather than `as any`.
  const sessionShim: RustionSessionOpenResult | null = useMemo(() => {
    if (!info) return null;
    return {
      session_id: info.session_id,
      host: "",
      port: 0,
      ticket: "",
      expires_at: info.expires_at,
      protocol: info.protocol,
      recording_id: "",
      bastion_id: info.bastion_id,
      bastion_name: info.bastion_name,
      bastion_selection: "",
      bastion_candidates_tried: [],
      correlation_id: info.correlation_id,
    };
  }, [info]);

  const lifecycle = useRustionSessionLifecycle({
    session: sessionShim,
    // Auto-renew while the chip is mounted — there is no idle
    // detection at this layer; renewals are cheap and the
    // server-side `max_renewals` budget bounds them.
    isIdle: false,
    autoRenewEnabled: true,
  });

  if (!info) return null;

  const ttl = formatTtl(lifecycle.expiresAt);
  const budgetTotal = info.max_renewals || lifecycle.maxRenewals;
  const budgetUsed = lifecycle.renewalsUsed;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        padding: "2px 8px",
        borderRadius: 999,
        background: background ?? "#1f2030",
        color: "#e6e6e6",
        fontSize: 11,
        whiteSpace: "nowrap",
      }}
      title={`bastion ${info.bastion_name} (${info.bastion_id}) · session ${info.session_id}`}
    >
      <span style={{ opacity: 0.7 }}>via</span>
      <span style={{ fontWeight: 600 }}>{info.bastion_name || info.bastion_id}</span>
      <span style={{ opacity: 0.5 }}>·</span>
      <span>{ttl}</span>
      {budgetTotal > 0 && (
        <>
          <span style={{ opacity: 0.5 }}>·</span>
          <span>
            renew {budgetUsed}/{budgetTotal}
          </span>
        </>
      )}
      <button
        type="button"
        onClick={() => void lifecycle.renew()}
        disabled={
          lifecycle.renewing ||
          lifecycle.terminated ||
          (budgetTotal > 0 && budgetUsed >= budgetTotal)
        }
        style={{
          background: "#2a2f5e",
          color: "#e6e6e6",
          border: "1px solid #3a3f6e",
          padding: "1px 6px",
          borderRadius: 4,
          cursor: "pointer",
          fontSize: 11,
        }}
      >
        {lifecycle.renewing ? "Renewing…" : "Renew"}
      </button>
      <button
        type="button"
        onClick={() => void lifecycle.kill()}
        disabled={lifecycle.killing || lifecycle.terminated}
        style={{
          background: "#5e1f1f",
          color: "#e6e6e6",
          border: "1px solid #7a2a2a",
          padding: "1px 6px",
          borderRadius: 4,
          cursor: "pointer",
          fontSize: 11,
        }}
      >
        {lifecycle.killing ? "Terminating…" : "Terminate"}
      </button>
      {lifecycle.lastError && (
        <span style={{ color: "#ff6e6e" }} title={lifecycle.lastError}>
          ⚠
        </span>
      )}
    </span>
  );
}
