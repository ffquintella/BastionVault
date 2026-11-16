import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge, Button, Card, useToast } from "../ui";
import { IdpEnvironmentsCard } from "./IdpEnvironmentsCard";
import { EntitlementModal, type EntitlementTarget } from "./EntitlementModal";
import { StateBadge } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

/** Rows per page: one entitlement read per row, kept well under the request gate. */
const PAGE = 20;

export function IdpEntitlementsTab({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [page, setPage] = useState(0);
  const [grants, setGrants] = useState<Record<string, Record<string, idp.IdpEntitlement>>>({});
  const [error, setError] = useState<string | null>(null);
  const [target, setTarget] = useState<EntitlementTarget | null>(null);

  const people = useMemo(() => directory.identities.filter((i) => i.info.state !== "removed"), [directory.identities]);
  const environments = useMemo(
    () => directory.environments.filter((e) => e.info.state === "active"),
    [directory.environments],
  );
  const pages = Math.max(1, Math.ceil(people.length / PAGE));
  const rows = people.slice(page * PAGE, page * PAGE + PAGE);

  const load = useCallback(async () => {
    setError(null);
    const visible = people.slice(page * PAGE, page * PAGE + PAGE);
    try {
      const sets = await Promise.all(visible.map((r) => idp.idpListEntitlements(r.entity_id)));
      setGrants((prev) => {
        const next = { ...prev };
        sets.forEach((s, i) => {
          next[visible[i].entity_id] = s.data?.entitlements ?? {};
        });
        return next;
      });
    } catch (e) {
      setError(idp.describeIdpError(e));
    }
  }, [page, people]);

  useEffect(() => {
    void load();
  }, [load]);

  const now = Date.now();

  return (
    <div className="space-y-4">
      <IdpEnvironmentsCard directory={directory} />
      <Card title="Entitlements: identity × environment × roles">
        {error && (
          <p className="mb-2 text-sm text-[var(--color-danger)]" role="alert">
            {error}
          </p>
        )}
        {people.length === 0 || environments.length === 0 ? (
          <p className="py-6 text-center text-sm text-[var(--color-text-muted)]">
            Entitlements need at least one identity that is not removed and one active environment.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[var(--color-text-muted)]">
                  <th className="pb-2 pr-3 font-medium">Identity</th>
                  {environments.map((e) => (
                    <th key={e.name} className="pb-2 pr-3 font-medium">
                      <span className="block w-40 truncate" title={e.name}>
                        {e.name}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.entity_id} className="border-t border-[var(--color-border)] align-top">
                    <td className="py-2 pr-3">
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="truncate font-medium" title={r.info.login}>
                          {r.info.login}
                        </span>
                        {r.info.state !== "active" && <StateBadge state={r.info.state} />}
                      </div>
                    </td>
                    {environments.map((e) => {
                      const g = grants[r.entity_id]?.[e.name] ?? null;
                      const expired = g?.not_after ? new Date(g.not_after).getTime() <= now : false;
                      return (
                        <td key={e.name} className="py-2 pr-3">
                          <button
                            type="button"
                            aria-label={`Entitlement of ${r.info.login} in ${e.name}`}
                            onClick={() =>
                              setTarget({
                                entity_id: r.entity_id,
                                login: r.info.login,
                                environment: e.name,
                                roles: e.info.roles,
                                existing: g,
                              })
                            }
                            className="flex min-w-0 flex-col items-start gap-1 rounded px-1 py-0.5 text-left hover:bg-[var(--color-surface-hover)]"
                          >
                            {g ? (
                              <>
                                <span className="flex flex-wrap gap-1">
                                  {g.roles.map((role) => (
                                    <Badge key={role} variant="info" label={role} />
                                  ))}
                                </span>
                                {g.not_after && (
                                  <span className={`text-xs ${expired ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"}`}>
                                    {expired ? "expired " : "until "}
                                    {idp.formatTime(g.not_after)}
                                  </span>
                                )}
                              </>
                            ) : (
                              <span className="text-xs text-[var(--color-text-muted)]">+ grant</span>
                            )}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {pages > 1 && (
          <div className="mt-3 flex items-center justify-end gap-2 text-xs">
            <Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Previous
            </Button>
            <span>
              Page {page + 1} of {pages}
            </span>
            <Button size="sm" variant="ghost" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>
              Next
            </Button>
          </div>
        )}
        <p className="mt-3 text-xs text-[var(--color-text-muted)]">
          A disabled identity keeps its grants, but the gate refuses every issue until it is reinstated.
        </p>
      </Card>
      {target && (
        <EntitlementModal
          target={target}
          onClose={() => setTarget(null)}
          onChanged={(message) => {
            toast("success", message);
            setTarget(null);
            void load();
          }}
        />
      )}
    </div>
  );
}
