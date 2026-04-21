import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  EntityPicker,
  Input,
  Modal,
  Select,
  Tabs,
  Table,
  useToast,
} from "../components/ui";
import type {
  ShareEntry,
  SharePointer,
  ShareTargetKind,
} from "../lib/types";
import { useAuthStore } from "../stores/authStore";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

/**
 * Per-user sharing surface:
 *   - **Shared with me**: everything pointing at the caller's
 *     entity_id (via `list_shares_for_grantee`). Each row links
 *     directly to the referenced KV path or resource.
 *   - **Manage**: look up shares on a specific target (kind + path)
 *     and add/revoke. We don't have a "shares I granted" reverse
 *     index today, so this tab is target-oriented.
 */
export function SharingPage() {
  const { toast } = useToast();
  const [tab, setTab] = useState<"received" | "manage">("received");
  const entityId = useAuthStore((s) => s.entityId);
  const loadEntity = useAuthStore((s) => s.loadEntity);

  // Received (shared with me)
  const [received, setReceived] = useState<SharePointer[]>([]);
  const [receivedLoading, setReceivedLoading] = useState(false);

  // Manage (per-target)
  const [manageKind, setManageKind] = useState<ShareTargetKind>("resource");
  const [managePath, setManagePath] = useState("");
  const [shares, setShares] = useState<ShareEntry[]>([]);
  const [sharesLoading, setSharesLoading] = useState(false);

  // Add-share modal state
  const [showAdd, setShowAdd] = useState(false);
  const [newGrantee, setNewGrantee] = useState("");
  const [newCaps, setNewCaps] = useState<string[]>(["read"]);
  const [newExpires, setNewExpires] = useState("");

  useEffect(() => {
    if (!entityId) {
      loadEntity().catch(() => {});
    }
  }, [entityId, loadEntity]);

  useEffect(() => {
    if (tab === "received" && entityId) {
      loadReceived();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, entityId]);

  async function loadReceived() {
    if (!entityId) return;
    setReceivedLoading(true);
    try {
      setReceived(await api.listSharesForGrantee(entityId));
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setReceivedLoading(false);
    }
  }

  async function loadSharesForTarget() {
    if (!managePath.trim()) return;
    setSharesLoading(true);
    try {
      setShares(await api.listSharesForTarget(manageKind, managePath.trim()));
    } catch (e: unknown) {
      toast("error", extractError(e));
      setShares([]);
    } finally {
      setSharesLoading(false);
    }
  }

  async function handleAdd() {
    try {
      await api.putShare(
        manageKind,
        managePath.trim(),
        newGrantee.trim(),
        newCaps,
        newExpires.trim(),
      );
      toast("success", "Share granted");
      setShowAdd(false);
      setNewGrantee("");
      setNewCaps(["read"]);
      setNewExpires("");
      loadSharesForTarget();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleRevoke(share: ShareEntry) {
    try {
      await api.deleteShare(
        share.target_kind as ShareTargetKind,
        share.target_path,
        share.grantee_entity_id,
      );
      toast("success", "Share revoked");
      loadSharesForTarget();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function toggleCap(cap: string) {
    setNewCaps((prev) =>
      prev.includes(cap) ? prev.filter((c) => c !== cap) : [...prev, cap],
    );
  }

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Sharing</h1>
        </div>

        <Tabs
          tabs={[
            { id: "received", label: "Shared with me" },
            { id: "manage", label: "Manage target" },
          ]}
          active={tab}
          onChange={(id) => setTab(id as "received" | "manage")}
        />

        {tab === "received" && (
          <Card>
            {!entityId ? (
              <EmptyState
                title="No entity_id on this token"
                description="Sharing is only visible when the token carries an entity_id. Re-login to provision one."
              />
            ) : receivedLoading ? (
              <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
            ) : received.length === 0 ? (
              <EmptyState
                title="Nothing shared with you"
                description="When someone grants you access, it shows up here."
              />
            ) : (
              <ReceivedTable entries={received} />
            )}
          </Card>
        )}

        {tab === "manage" && (
          <Card title="Shares on a target">
            <div className="flex gap-2 items-end mb-4">
              <Select
                label="Kind"
                value={manageKind}
                onChange={(e) => setManageKind(e.target.value as ShareTargetKind)}
                options={[
                  { value: "resource", label: "Resource" },
                  { value: "kv-secret", label: "KV secret" },
                ]}
              />
              <Input
                label={manageKind === "resource" ? "Resource name" : "KV path"}
                value={managePath}
                onChange={(e) => setManagePath(e.target.value)}
                placeholder={
                  manageKind === "resource" ? "server-01" : "secret/foo/bar"
                }
                className="flex-1"
              />
              <Button onClick={loadSharesForTarget} disabled={!managePath.trim()}>
                Load
              </Button>
              <Button
                variant="secondary"
                onClick={() => setShowAdd(true)}
                disabled={!managePath.trim()}
              >
                Add share
              </Button>
            </div>

            {sharesLoading ? (
              <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
            ) : shares.length === 0 ? (
              <EmptyState
                title="No shares on this target"
                description="Pick a target and click Load, or use Add share to grant access."
              />
            ) : (
              <ShareTable entries={shares} onRevoke={handleRevoke} />
            )}
          </Card>
        )}

        <Modal
          open={showAdd}
          onClose={() => setShowAdd(false)}
          title="Grant access"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowAdd(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleAdd}
                disabled={!newGrantee.trim() || newCaps.length === 0}
              >
                Grant
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <EntityPicker
              label="Grantee"
              value={newGrantee}
              onChange={(id) => setNewGrantee(id)}
              placeholder="Search by login or paste entity_id"
              hint="Type part of a username, mount, or UUID."
            />
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                Capabilities
              </label>
              <div className="flex flex-wrap gap-2">
                {(["read", "list", "update", "delete", "create"] as const).map(
                  (c) => {
                    const selected = newCaps.includes(c);
                    return (
                      <button
                        key={c}
                        type="button"
                        onClick={() => toggleCap(c)}
                        className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                          selected
                            ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                            : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                        }`}
                      >
                        {c}
                      </button>
                    );
                  },
                )}
              </div>
            </div>
            <Input
              label="Expires at (optional)"
              value={newExpires}
              onChange={(e) => setNewExpires(e.target.value)}
              placeholder="2026-12-31T23:59:59Z"
              hint="RFC3339 timestamp. Leave empty for no expiry."
            />
          </div>
        </Modal>
      </div>
    </Layout>
  );
}

function ReceivedTable({ entries }: { entries: SharePointer[] }) {
  const columns = [
    {
      key: "kind",
      header: "Kind",
      render: (p: SharePointer) => (
        <Badge
          label={p.target_kind}
          variant={p.target_kind === "resource" ? "info" : "neutral"}
        />
      ),
    },
    {
      key: "target",
      header: "Target",
      render: (p: SharePointer) => (
        <span className="font-mono text-xs truncate">{p.target_path}</span>
      ),
    },
    {
      key: "open",
      header: "",
      className: "text-right w-24",
      render: (p: SharePointer) => {
        if (p.target_kind === "resource") {
          return (
            <Link
              to={`/resources/${encodeURIComponent(p.target_path)}`}
              className="text-xs text-[var(--color-primary)] hover:underline"
            >
              Open
            </Link>
          );
        }
        // KV: navigate to the parent prefix so the list view opens
        // on the right page. The leaf name is the last segment.
        return (
          <Link
            to={`/secrets/${p.target_path}`}
            className="text-xs text-[var(--color-primary)] hover:underline"
          >
            Open
          </Link>
        );
      },
    },
  ];
  return <Table columns={columns} data={entries} rowKey={(p) => `${p.target_kind}|${p.target_path}`} />;
}

function ShareTable({
  entries,
  onRevoke,
}: {
  entries: ShareEntry[];
  onRevoke: (s: ShareEntry) => void;
}) {
  const columns = [
    {
      key: "grantee",
      header: "Grantee",
      render: (s: ShareEntry) => (
        <span className="font-mono text-xs truncate">{s.grantee_entity_id}</span>
      ),
    },
    {
      key: "caps",
      header: "Capabilities",
      render: (s: ShareEntry) => (
        <div className="flex flex-wrap gap-1">
          {s.capabilities.map((c) => (
            <Badge key={c} label={c} variant="info" />
          ))}
        </div>
      ),
    },
    {
      key: "granted_at",
      header: "Granted",
      render: (s: ShareEntry) => (
        <span className="text-xs text-[var(--color-text-muted)]">
          {s.granted_at || "-"}
        </span>
      ),
    },
    {
      key: "expires",
      header: "Expires",
      render: (s: ShareEntry) =>
        s.expires_at ? (
          <span
            className={`text-xs ${
              s.expired ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"
            }`}
          >
            {s.expires_at}
            {s.expired && " (expired)"}
          </span>
        ) : (
          <span className="text-xs text-[var(--color-text-muted)]">never</span>
        ),
    },
    {
      key: "revoke",
      header: "",
      className: "text-right w-24",
      render: (s: ShareEntry) => (
        <Button variant="danger" size="sm" onClick={() => onRevoke(s)}>
          Revoke
        </Button>
      ),
    },
  ];
  return (
    <Table
      columns={columns}
      data={entries}
      rowKey={(s) => `${s.target_kind}|${s.target_path}|${s.grantee_entity_id}`}
    />
  );
}
