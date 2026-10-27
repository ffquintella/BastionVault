import { useEffect, useState } from "react";
import { Badge } from "./ui";
import { parsePolicyHcl } from "../lib/policyHcl";
import { namesSql, type PolicySchemaStatus } from "../lib/sqlPrivileges";
import * as api from "../lib/api";

/**
 * Warns, while a draft names `sql_*` capabilities, that the server will refuse
 * to store it yet (features/sql-browser.md §13): an older cluster node could
 * not parse the policy, so the write gate stays closed until every node
 * reports a build that does. Reads `GET v2/sys/policy-schema`, which never
 * opens the gate. Renders nothing when the draft names no SQL capability, the
 * gate is open, or the status cannot be read: the save itself still reports
 * the refusal in full, and this notice only explains it earlier.
 */
export function PolicySqlGateNotice({ hcl }: { hcl: string }) {
  const parsed = parsePolicyHcl(hcl);
  return <SqlGateNotice active={parsed.ok && parsed.model.blocks.some((b) => namesSql(b.capabilities))} />;
}

/** The same notice for any write that is about to name `sql_*` (a share, say). */
export function SqlGateNotice({ active: names }: { active: boolean }) {
  const [status, setStatus] = useState<PolicySchemaStatus | null>(null);

  useEffect(() => {
    if (!names) return;
    let live = true;
    api
      .policySchemaStatus()
      .then((s) => live && setStatus(s))
      .catch(() => live && setStatus(null));
    return () => {
      live = false;
    };
  }, [names]);

  if (!names || !status || status.sql_capabilities_writable) return null;
  const blockers = (status.nodes ?? []).filter((n) => n.member !== false && !n.qualifies);
  return (
    <div
      role="alert"
      className="rounded border border-yellow-700 bg-yellow-950/40 px-3 py-2 text-sm text-yellow-200"
      data-testid="sql-gate-notice"
    >
      <div className="flex flex-wrap items-center gap-2">
        <strong>SQL privileges cannot be saved yet.</strong>
        <Badge variant="warning" label="write gate closed" />
      </div>
      <p className="mt-1">
        This policy names <code>sql_*</code> capabilities. The server stores them only once every cluster node runs a
        build that understands them (policy schema 2, plugin host ABI 1.4); until then it refuses the save with a 409,
        so that an older node can still unseal.
      </p>
      {status.reason && <p className="mt-1 min-w-0 break-words">Blocking: {status.reason}</p>}
      {blockers.length > 0 && (
        <ul className="mt-1 list-disc pl-5 text-xs">
          {blockers.map((n) => (
            <li key={n.node} className="min-w-0 break-words">
              node {n.node}: {n.problem ?? "does not qualify yet"}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
