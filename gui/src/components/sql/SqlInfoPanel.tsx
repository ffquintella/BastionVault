import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import type { SqlSessionStatus } from "../../lib/api";
import { SQL_CAPABILITIES, SQL_CAPABILITY_HINTS, type SqlCapability } from "../../lib/sqlPrivileges";
import { CapChip } from "./SqlDialog";

function duration(secs: number): string {
  if (secs < 60) return `${secs} s`;
  if (secs < 3600) return `${Math.floor(secs / 60)} min ${secs % 60} s`;
  return `${Math.floor(secs / 3600)} h ${Math.floor((secs % 3600) / 60)} min`;
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 gap-2">
      <dt className="w-24 shrink-0 text-[var(--color-text-muted)]">{k}</dt>
      <dd className="min-w-0 flex-1 truncate">{children}</dd>
    </div>
  );
}

const ordered = (caps: readonly string[]) => SQL_CAPABILITIES.filter((c) => caps.includes(c));

/**
 * The right-hand panel (§10): resource and profile, the caller's effective
 * SQL privileges as chips, enforcement (what the database enforces and
 * what only the vault does), transport, TLS and the session's timers.
 * Display only: nothing is enforced from it.
 */
export function SqlInfoPanel({
  status,
  effective,
  readAt,
}: {
  status: SqlSessionStatus | null;
  /** Effective privileges (server ∪ resource-wide); null when unknown. */
  effective: string[] | null;
  /** When `status` was read (ms), so the timers keep counting between reads. */
  readAt: number;
}) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const elapsed = Math.max(0, Math.floor((now - readAt) / 1000));
  if (!status) {
    return <aside className="p-2 text-xs text-[var(--color-text-muted)]">Reading the session…</aside>;
  }
  const privileges = effective ?? status.privileges;
  const tx = status.transaction;
  return (
    <aside aria-label="Session information" className="min-w-0 space-y-3 overflow-auto p-2 text-xs">
      <section>
        <h3 className="mb-1 font-semibold">Session</h3>
        <dl className="space-y-0.5">
          <Row k="Resource">
            <span title={status.resource}>{status.resource}</span>
          </Row>
          <Row k="Profile">
            <span title={status.profile}>{status.profile}</span>
          </Row>
          <Row k="Database">
            <span title={status.catalog}>{status.catalog}</span>
          </Row>
          <Row k="Engine">
            {status.engine} {status.server_version}
          </Row>
          <Row k="Transport">{status.transport}</Row>
          <Row k="TLS">{status.tls_mode}</Row>
          <Row k="Open for">{duration(status.age_secs + elapsed)}</Row>
          <Row k="Idle">{duration(status.active_run ? 0 : status.idle_secs + elapsed)}</Row>
          <Row k="Rows read">{status.rows_read}</Row>
          {status.search_path && (
            <Row k="search_path">
              <span title={status.search_path}>{status.search_path}</span>
            </Row>
          )}
        </dl>
        {tx.open && (
          <p
            data-testid="sql-tx-badge"
            className={`mt-1 inline-block rounded px-1.5 py-0.5 ${tx.failed ? "bg-red-900/60 text-red-200" : "bg-yellow-900/50 text-yellow-200"}`}
          >
            {tx.failed ? "transaction failed" : "transaction open"} · {tx.statements} statements
            {tx.open_secs !== null ? ` · ${duration(tx.open_secs + elapsed)}` : ""}
          </p>
        )}
      </section>

      <section aria-label="Your SQL privileges">
        <h3 className="mb-1 font-semibold">Your SQL privileges</h3>
        <div className="flex flex-wrap gap-1" data-testid="sql-privilege-chips">
          {ordered(privileges).length === 0 && <span className="text-[var(--color-text-muted)]">none</span>}
          {ordered(privileges).map((c) => (
            <CapChip key={c} cap={c} title={SQL_CAPABILITY_HINTS[c as SqlCapability]} />
          ))}
        </div>
        <p className="mt-1 text-[10px] text-[var(--color-text-muted)]">
          Buttons follow these as a convenience; the vault checks every statement.
        </p>
      </section>

      <section aria-label="Enforcement" data-testid="sql-enforcement">
        <h3 className="mb-1 font-semibold">Enforcement</h3>
        <dl className="space-y-0.5">
          <Row k="Mode">{status.enforcement}</Row>
          <Row k="Database">{status.db_enforced ? "enforces the grant" : "can do more than the grant"}</Row>
          <Row k="Read-only">{status.read_only ? "yes (the database refuses writes)" : "no"}</Row>
        </dl>
        <div className="mt-1 flex flex-wrap items-center gap-1">
          <span className="text-[var(--color-text-muted)]">Login ceiling</span>
          {ordered(status.ceiling).map((c) => (
            <CapChip key={c} cap={c} />
          ))}
        </div>
        {status.vault_only.length > 0 && (
          <div className="mt-1 flex flex-wrap items-center gap-1" data-testid="sql-vault-only">
            <span className="text-yellow-300">Vault only</span>
            {ordered(status.vault_only).map((c) => (
              <CapChip key={c} cap={c} tone="warn" title="The login can do this; only BastionVault refuses it" />
            ))}
          </div>
        )}
        {!status.db_enforced && (
          <p className="mt-1 text-[10px] text-yellow-300">
            The database login can do more than you are granted: BastionVault alone refuses the excess, and every
            audit event of this session carries <code>db_enforced: false</code>.
          </p>
        )}
        {status.taint && <p className="mt-1 text-red-400">Session tainted: {status.taint}</p>}
      </section>
    </aside>
  );
}
