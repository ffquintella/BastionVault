import { useEffect, useMemo, useState } from "react";
import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  EntityLabel,
  Input,
  Select,
  Table,
  useToast,
} from "../components/ui";
import type { AuditEvent } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const CATEGORY_LABELS: Record<string, string> = {
  policy: "Policy",
  "identity-group-user": "Identity group (user)",
  "identity-group-app": "Identity group (app)",
  "asset-group": "Asset group",
};

const CATEGORY_VARIANTS: Record<
  string,
  "info" | "success" | "warning" | "error" | "neutral"
> = {
  policy: "warning",
  "identity-group-user": "info",
  "identity-group-app": "info",
  "asset-group": "success",
};

const OP_VARIANTS: Record<string, "info" | "success" | "warning" | "error" | "neutral"> = {
  create: "success",
  update: "info",
  delete: "error",
};

/**
 * Admin → Audit. Pulls the unified trail from
 * `/v2/sys/audit/events` and renders it as a searchable table.
 * Filters are applied client-side against the already-loaded page;
 * the `from` / `to` date inputs are pushed to the server to bound
 * large vaults.
 */
export function AuditPage() {
  const { toast } = useToast();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [limit, setLimit] = useState<number>(500);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [opFilter, setOpFilter] = useState("");

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function load() {
    setLoading(true);
    try {
      const list = await api.listAuditEvents(from.trim(), to.trim(), limit);
      setEvents(list);
    } catch (e: unknown) {
      toast("error", extractError(e));
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter((e) => {
      if (categoryFilter && e.category !== categoryFilter) return false;
      if (opFilter && e.op !== opFilter) return false;
      if (q) {
        const hay = `${e.user} ${e.target} ${e.category} ${e.op} ${(e.changed_fields || []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [events, search, categoryFilter, opFilter]);

  // Distinct category values present in the current page — drives the
  // filter dropdown options so operators don't see labels for a kind
  // with zero matches.
  const categoriesPresent = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) s.add(e.category);
    return Array.from(s).sort();
  }, [events]);

  const columns = [
    {
      key: "ts",
      header: "Time",
      className: "whitespace-nowrap",
      render: (e: AuditEvent) => (
        <span className="text-xs text-[var(--color-text-muted)]">
          {e.ts ? new Date(e.ts).toLocaleString() : "-"}
        </span>
      ),
    },
    {
      key: "user",
      header: "Who",
      render: (e: AuditEvent) =>
        looksLikeEntityId(e.user) ? (
          <EntityLabel entityId={e.user} />
        ) : (
          <span className="text-sm">{e.user || "(unknown)"}</span>
        ),
    },
    {
      key: "op",
      header: "Op",
      render: (e: AuditEvent) => (
        <Badge label={e.op} variant={OP_VARIANTS[e.op] ?? "neutral"} />
      ),
    },
    {
      key: "category",
      header: "Where",
      render: (e: AuditEvent) => (
        <Badge
          label={CATEGORY_LABELS[e.category] ?? e.category}
          variant={CATEGORY_VARIANTS[e.category] ?? "neutral"}
        />
      ),
    },
    {
      key: "target",
      header: "Target",
      render: (e: AuditEvent) => (
        <span className="font-mono text-xs truncate">{e.target || "-"}</span>
      ),
    },
    {
      key: "changed_fields",
      header: "Fields",
      render: (e: AuditEvent) =>
        e.changed_fields && e.changed_fields.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {e.changed_fields.map((f) => (
              <span
                key={f}
                className="px-1.5 py-0.5 bg-[var(--color-bg)] rounded text-[10px] font-mono text-[var(--color-text-muted)] border border-[var(--color-border)]"
              >
                {f}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-xs text-[var(--color-text-muted)] italic">—</span>
        ),
    },
  ];

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Audit</h1>
          <div className="flex gap-2 items-center text-xs text-[var(--color-text-muted)]">
            {loading ? "Loading..." : `${filtered.length} of ${events.length} events`}
          </div>
        </div>

        <Card>
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <Input
                label="From (RFC3339)"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
                placeholder="2026-01-01T00:00:00Z"
              />
              <Input
                label="To (RFC3339)"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                placeholder="2026-12-31T23:59:59Z"
              />
              <Input
                label="Max rows"
                value={String(limit)}
                onChange={(e) => {
                  const n = parseInt(e.target.value, 10);
                  if (!Number.isNaN(n) && n > 0) setLimit(n);
                  else if (e.target.value === "") setLimit(500);
                }}
                placeholder="500"
                type="number"
              />
              <div className="flex items-end">
                <Button onClick={load} className="w-full" loading={loading}>
                  Refresh
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <Input
                label="Search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="username, target, field..."
              />
              <Select
                label="Category"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                options={[
                  { value: "", label: "All" },
                  ...categoriesPresent.map((c) => ({
                    value: c,
                    label: CATEGORY_LABELS[c] ?? c,
                  })),
                ]}
              />
              <Select
                label="Operation"
                value={opFilter}
                onChange={(e) => setOpFilter(e.target.value)}
                options={[
                  { value: "", label: "All" },
                  { value: "create", label: "Create" },
                  { value: "update", label: "Update" },
                  { value: "delete", label: "Delete" },
                ]}
              />
            </div>
          </div>
        </Card>

        <Card>
          {loading ? (
            <p className="text-sm text-[var(--color-text-muted)] py-4">
              Loading events...
            </p>
          ) : filtered.length === 0 ? (
            <EmptyState
              title={events.length === 0 ? "No events recorded" : "No matches"}
              description={
                events.length === 0
                  ? "Once policies, groups, or asset groups change, their history entries show up here."
                  : "Adjust the filters or clear the search box."
              }
            />
          ) : (
            <Table
              columns={columns}
              data={filtered}
              rowKey={(e) => `${e.ts}|${e.category}|${e.target}|${e.op}|${e.user}`}
            />
          )}
        </Card>
      </div>
    </Layout>
  );
}

/** Cheap heuristic: Vault-style entity IDs are UUID-like. */
function looksLikeEntityId(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}
