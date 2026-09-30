import { useState, useEffect, useCallback } from "react";

import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Textarea,
  Badge,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import type { McpApp, McpCatalogue, McpCatalogueTool, McpConfig, McpToken } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const APP_NAME_RE = /^[a-z0-9-]+$/;
const MIN_TTL = 60;
const MAX_TTL = 86_400;

function fmtTime(unix: number): string {
  if (!unix) return "—";
  try {
    return new Date(unix * 1000).toLocaleString();
  } catch {
    return String(unix);
  }
}

function kindVariant(kind: string): "neutral" | "warning" | "error" {
  if (kind === "read") return "neutral";
  if (kind === "reveal") return "warning";
  return "error";
}

/** One path glob per line (or comma) → trimmed, non-empty list. */
function parseLines(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function waiverBadge(app: McpApp) {
  const w = app.machine_waiver;
  if (!w) return <Badge variant="success" label="Attested" />;
  const active = w.expires_at * 1000 > Date.now();
  return active ? (
    <Badge variant="warning" label={`Waived until ${fmtTime(w.expires_at)}`} />
  ) : (
    <Badge variant="error" label="Waiver expired" />
  );
}

export function McpAppsPage() {
  const [apps, setApps] = useState<McpApp[]>([]);
  const [tokens, setTokens] = useState<McpToken[]>([]);
  const [config, setConfig] = useState<McpConfig | null>(null);
  const [catalogue, setCatalogue] = useState<McpCatalogue | null>(null);
  const [tab, setTab] = useState("apps");
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  // App editor.
  const [editing, setEditing] = useState<McpApp | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [fName, setFName] = useState("");
  const [fRole, setFRole] = useState("");
  const [fDesc, setFDesc] = useState("");
  const [fTools, setFTools] = useState<string[]>([]);
  const [fScope, setFScope] = useState("");
  const [fReveal, setFReveal] = useState(false);
  const [fDestructive, setFDestructive] = useState(false);
  const [fTtl, setFTtl] = useState("3600");

  const [deleteTarget, setDeleteTarget] = useState<McpApp | null>(null);
  const [waiverTarget, setWaiverTarget] = useState<McpApp | null>(null);
  const [waiverReason, setWaiverReason] = useState("");
  const [waiverDays, setWaiverDays] = useState("7");
  const [revokeWaiverTarget, setRevokeWaiverTarget] = useState<McpApp | null>(null);
  const [revokeTokenTarget, setRevokeTokenTarget] = useState<McpToken | null>(null);

  // Config form.
  const [cDefaultTtl, setCDefaultTtl] = useState("3600");
  const [cMaxTtl, setCMaxTtl] = useState("86400");
  const [cWaiverDays, setCWaiverDays] = useState("90");
  const [cPin, setCPin] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [a, t, c, cat] = await Promise.all([
        api.mcpListApps(),
        api.mcpListTokens(),
        api.mcpReadConfig(),
        api.mcpCatalogue(),
      ]);
      setApps(a);
      setTokens(t);
      setConfig(c);
      setCatalogue(cat);
      setCDefaultTtl(String(c.default_ttl_secs || 3600));
      setCMaxTtl(String(c.max_ttl_secs || 86_400));
      setCWaiverDays(String(c.waiver_max_days || 90));
      setCPin(c.catalogue_pin ?? "");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  function openNew() {
    setEditing({
      name: "",
      approle_role: "",
      entity_id: "",
      description: "",
      tool_allowlist: [],
      path_scope: [],
      reveal_allowed: false,
      destructive_allowed: false,
      ttl_secs: 3600,
      machine_waiver: null,
      created_at: 0,
      updated_at: 0,
    });
    setIsNew(true);
    setFName("");
    setFRole("");
    setFDesc("");
    setFTools([]);
    setFScope("");
    setFReveal(false);
    setFDestructive(false);
    setFTtl("3600");
  }

  function openEdit(app: McpApp) {
    setEditing(app);
    setIsNew(false);
    setFName(app.name);
    setFRole(app.approle_role);
    setFDesc(app.description);
    setFTools(app.tool_allowlist);
    setFScope(app.path_scope.join("\n"));
    setFReveal(app.reveal_allowed);
    setFDestructive(app.destructive_allowed);
    setFTtl(String(app.ttl_secs || 3600));
  }

  function toggleTool(name: string) {
    setFTools((prev) => (prev.includes(name) ? prev.filter((t) => t !== name) : [...prev, name]));
  }

  async function saveApp() {
    const name = fName.trim();
    const ttl = Number(fTtl);
    if (isNew && !APP_NAME_RE.test(name)) {
      toast("error", "App name may only contain lowercase letters, digits and dashes");
      return;
    }
    if (!fRole.trim()) {
      toast("error", "An AppID role is required");
      return;
    }
    if (!Number.isInteger(ttl) || ttl < MIN_TTL || ttl > MAX_TTL) {
      toast("error", `Token lifetime must be between ${MIN_TTL} and ${MAX_TTL} seconds`);
      return;
    }
    try {
      await api.mcpWriteApp({
        name,
        approleRole: fRole.trim(),
        description: fDesc.trim(),
        toolAllowlist: fTools,
        pathScope: parseLines(fScope),
        revealAllowed: fReveal,
        destructiveAllowed: fDestructive,
        ttlSecs: ttl,
      });
      toast("success", isNew ? `Created ${name}` : `Saved ${name}`);
      setEditing(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doDelete() {
    if (!deleteTarget) return;
    try {
      await api.mcpDeleteApp(deleteTarget.name);
      toast("success", `Deleted ${deleteTarget.name}; its tokens were revoked`);
      setDeleteTarget(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doGrantWaiver() {
    if (!waiverTarget) return;
    const days = Number(waiverDays);
    const maxDays = config?.waiver_max_days || 90;
    if (!waiverReason.trim()) {
      toast("error", "A reason is required for a machine-identity waiver");
      return;
    }
    if (!Number.isInteger(days) || days < 1 || days > maxDays) {
      toast("error", `A waiver must last between 1 and ${maxDays} days`);
      return;
    }
    try {
      await api.mcpGrantWaiver(waiverTarget.name, waiverReason.trim(), days);
      toast("success", `Waiver granted to ${waiverTarget.name} for ${days} day(s)`);
      setWaiverTarget(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doRevokeWaiver() {
    if (!revokeWaiverTarget) return;
    try {
      await api.mcpRevokeWaiver(revokeWaiverTarget.name);
      toast("success", `Waiver revoked for ${revokeWaiverTarget.name}`);
      setRevokeWaiverTarget(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doRevokeToken() {
    if (!revokeTokenTarget) return;
    try {
      await api.mcpRevokeToken(revokeTokenTarget.accessor);
      toast("success", "Token revoked");
      setRevokeTokenTarget(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function saveConfig(pinOverride?: string) {
    const d = Number(cDefaultTtl);
    const m = Number(cMaxTtl);
    const w = Number(cWaiverDays);
    if (![d, m, w].every((n) => Number.isInteger(n) && n > 0)) {
      toast("error", "TTLs and the waiver limit must be whole numbers greater than zero");
      return;
    }
    if (d > m) {
      toast("error", "The default lifetime cannot exceed the maximum");
      return;
    }
    const pin = (pinOverride ?? cPin).trim();
    try {
      await api.mcpWriteConfig({ defaultTtlSecs: d, maxTtlSecs: m, waiverMaxDays: w, cataloguePin: pin });
      toast("success", "MCP settings saved");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  const pin = config?.catalogue_pin ?? "";
  const pinState: "none" | "match" | "mismatch" = !pin
    ? "none"
    : catalogue && pin === catalogue.hash
      ? "match"
      : "mismatch";

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold">MCP Apps</h1>
            <p className="text-sm text-[var(--color-text-muted)]">
              Applications allowed to call the vault through the Model Context Protocol, each with an explicit tool
              allow-list and path scope.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <Button variant="secondary" size="sm" onClick={() => void load()} disabled={loading}>
              Refresh
            </Button>
            <Button size="sm" onClick={openNew}>
              New app
            </Button>
          </div>
        </div>

        <Tabs
          tabs={[
            { id: "apps", label: `Apps${apps.length ? ` (${apps.length})` : ""}` },
            { id: "tokens", label: `Tokens${tokens.length ? ` (${tokens.length})` : ""}` },
            { id: "catalogue", label: "Catalogue" },
            { id: "config", label: "Settings" },
          ]}
          active={tab}
          onChange={setTab}
        />

        {tab === "apps" && (
          <Card>
            {apps.length === 0 && loading ? (
              <p className="py-8 text-center text-sm text-[var(--color-text-muted)]">Loading…</p>
            ) : apps.length === 0 ? (
              <EmptyState
                title="No MCP apps"
                description="Register an app to let an application call the vault over MCP. It signs in through its AppID role and receives a short-lived MCP-bound token that works nowhere else."
                action={<Button onClick={openNew}>New app</Button>}
              />
            ) : (
              <Table
                columns={[
                  {
                    key: "name",
                    header: "Name",
                    render: (a: McpApp) => <span className="block min-w-0 truncate font-mono text-xs">{a.name}</span>,
                  },
                  {
                    key: "role",
                    header: "AppID role",
                    render: (a: McpApp) => <span className="block min-w-0 truncate font-mono text-xs">{a.approle_role}</span>,
                  },
                  {
                    key: "tools",
                    header: "Tools",
                    render: (a: McpApp) => (
                      <span title={a.tool_allowlist.join(", ")}>{a.tool_allowlist.length}</span>
                    ),
                  },
                  {
                    key: "scope",
                    header: "Path scope",
                    render: (a: McpApp) => (
                      <span className="block min-w-0 max-w-xs truncate font-mono text-xs" title={a.path_scope.join("\n")}>
                        {a.path_scope.length ? a.path_scope.join(", ") : "none (denies all)"}
                      </span>
                    ),
                  },
                  {
                    key: "reveal",
                    header: "Reveal",
                    render: (a: McpApp) => (
                      <Badge variant={a.reveal_allowed ? "warning" : "neutral"} label={a.reveal_allowed ? "allowed" : "off"} />
                    ),
                  },
                  {
                    key: "destructive",
                    header: "Writes",
                    render: (a: McpApp) => (
                      <Badge
                        variant={a.destructive_allowed ? "error" : "neutral"}
                        label={a.destructive_allowed ? "allowed" : "off"}
                      />
                    ),
                  },
                  { key: "machine", header: "Machine identity", render: (a: McpApp) => waiverBadge(a) },
                  {
                    key: "actions",
                    header: "",
                    render: (a: McpApp) => (
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="secondary" onClick={() => openEdit(a)}>
                          Edit
                        </Button>
                        {a.machine_waiver ? (
                          <Button size="sm" variant="secondary" onClick={() => setRevokeWaiverTarget(a)}>
                            Revoke waiver
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => {
                              setWaiverTarget(a);
                              setWaiverReason("");
                              setWaiverDays("7");
                            }}
                          >
                            Waive attestation
                          </Button>
                        )}
                        <Button size="sm" variant="danger" onClick={() => setDeleteTarget(a)}>
                          Delete
                        </Button>
                      </div>
                    ),
                  },
                ]}
                data={apps}
                rowKey={(a: McpApp) => a.name}
                emptyMessage="No MCP apps"
              />
            )}
          </Card>
        )}

        {tab === "tokens" && (
          <Card>
            <Table
              columns={[
                {
                  key: "kind",
                  header: "Kind",
                  render: (t: McpToken) => (
                    <Badge variant={t.kind === "pairing" ? "info" : "neutral"} label={t.kind || "app"} />
                  ),
                },
                {
                  key: "app",
                  header: "App / pairing",
                  render: (t: McpToken) => <span className="block min-w-0 truncate font-mono text-xs">{t.app}</span>,
                },
                {
                  key: "client",
                  header: "Client",
                  render: (t: McpToken) => (
                    <span className="block min-w-0 truncate text-sm">
                      {t.client_name ? `${t.client_name} ${t.client_version}`.trim() : "—"}
                    </span>
                  ),
                },
                { key: "issued", header: "Issued", render: (t: McpToken) => fmtTime(t.issued_at) },
                { key: "expires", header: "Expires", render: (t: McpToken) => fmtTime(t.expires_at) },
                {
                  key: "accessor",
                  header: "Accessor",
                  render: (t: McpToken) => (
                    <span className="block min-w-0 max-w-[10rem] truncate font-mono text-xs" title={t.accessor}>
                      {t.accessor}
                    </span>
                  ),
                },
                {
                  key: "actions",
                  header: "",
                  render: (t: McpToken) => (
                    <div className="flex justify-end">
                      <Button size="sm" variant="danger" onClick={() => setRevokeTokenTarget(t)}>
                        Revoke
                      </Button>
                    </div>
                  ),
                },
              ]}
              data={tokens}
              rowKey={(t: McpToken) => t.accessor}
              emptyMessage="No active MCP tokens"
            />
          </Card>
        )}

        {tab === "catalogue" && catalogue && (
          <div className="space-y-4">
            <Card title="Catalogue hash">
              <div className="space-y-3 text-sm">
                <p className="text-[var(--color-text-muted)]">
                  The tool descriptions and schemas are fixed in the software; this hash changes whenever any of them
                  does. Pin it to turn such a change into a deliberate upgrade step. The hash shown is this
                  application&apos;s own build, which matches the server only when both are the same release.
                </p>
                <p className="break-all font-mono text-xs" data-testid="catalogue-hash">
                  {catalogue.hash}
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  {pinState === "none" && <Badge variant="neutral" label="Not pinned" />}
                  {pinState === "match" && <Badge variant="success" label="Pinned, matches this build" />}
                  {pinState === "mismatch" && <Badge variant="error" label="Pinned to a different catalogue" />}
                  <Button size="sm" variant="secondary" onClick={() => void saveConfig(catalogue.hash)}>
                    Pin this hash
                  </Button>
                  {pin && (
                    <Button size="sm" variant="secondary" onClick={() => void saveConfig("")}>
                      Clear pin
                    </Button>
                  )}
                </div>
              </div>
            </Card>
            <Card title="Tools">
              <Table
                columns={[
                  {
                    key: "name",
                    header: "Tool",
                    render: (t: McpCatalogueTool) => <span className="font-mono text-xs">{t.name}</span>,
                  },
                  {
                    key: "kind",
                    header: "Kind",
                    render: (t: McpCatalogueTool) => <Badge variant={kindVariant(t.kind)} label={t.kind} />,
                  },
                  {
                    key: "desc",
                    header: "Description",
                    render: (t: McpCatalogueTool) => (
                      <span className="text-sm text-[var(--color-text-muted)]">{t.description}</span>
                    ),
                  },
                ]}
                data={catalogue.tools}
                rowKey={(t: McpCatalogueTool) => t.name}
              />
            </Card>
          </div>
        )}

        {tab === "config" && (
          <Card title="Settings">
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <Input
                  label="Default token lifetime (seconds)"
                  value={cDefaultTtl}
                  onChange={(e) => setCDefaultTtl(e.target.value)}
                />
                <Input
                  label="Maximum token lifetime (seconds)"
                  value={cMaxTtl}
                  onChange={(e) => setCMaxTtl(e.target.value)}
                />
                <Input
                  label="Longest machine-identity waiver (days)"
                  value={cWaiverDays}
                  onChange={(e) => setCWaiverDays(e.target.value)}
                />
                <div className="col-span-2">
                  <Input
                    label="Catalogue pin (blank for none)"
                    value={cPin}
                    onChange={(e) => setCPin(e.target.value)}
                    placeholder="hash from the Catalogue tab"
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <Button onClick={() => void saveConfig()}>Save settings</Button>
              </div>
            </div>
          </Card>
        )}
      </div>

      {/* Create / edit */}
      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={isNew ? "New MCP app" : `Edit ${editing?.name ?? ""}`}
        size="lg"
      >
        {editing && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Name"
                value={fName}
                onChange={(e) => setFName(e.target.value)}
                disabled={!isNew}
                placeholder="ci-secrets-reader"
              />
              <Input
                label="AppID role"
                value={fRole}
                onChange={(e) => setFRole(e.target.value)}
                placeholder="reader-role"
              />
              <div className="col-span-2">
                <Input label="Description" value={fDesc} onChange={(e) => setFDesc(e.target.value)} />
              </div>
              <div className="col-span-2">
                <label className="mb-1 block text-sm text-[var(--color-text-muted)]">
                  Tools this app may call (none selected denies everything)
                </label>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                  {(catalogue?.tools ?? []).map((t) => (
                    <label key={t.name} className="flex min-w-0 items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={fTools.includes(t.name)}
                        onChange={() => toggleTool(t.name)}
                        aria-label={t.name}
                      />
                      <span className="min-w-0 truncate font-mono text-xs">{t.name}</span>
                      {t.kind !== "read" && <Badge variant={kindVariant(t.kind)} label={t.kind} />}
                    </label>
                  ))}
                </div>
              </div>
              <div className="col-span-2">
                <Textarea
                  label="Path scope — one glob per line (empty denies every path)"
                  value={fScope}
                  onChange={(e) => setFScope(e.target.value)}
                  placeholder={"secret/metadata/ai/*\ntransit/encrypt/ai-*"}
                />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={fReveal}
                  onChange={(e) => setFReveal(e.target.checked)}
                  aria-label="Allow revealing secret values"
                />
                Allow revealing secret values
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={fDestructive}
                  onChange={(e) => setFDestructive(e.target.checked)}
                  aria-label="Allow write and delete tools"
                />
                Allow write and delete tools
              </label>
              <Input label="Token lifetime (seconds)" value={fTtl} onChange={(e) => setFTtl(e.target.value)} />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setEditing(null)}>
                Cancel
              </Button>
              <Button onClick={() => void saveApp()}>{isNew ? "Create" : "Save"}</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Waiver */}
      <Modal
        open={!!waiverTarget}
        onClose={() => setWaiverTarget(null)}
        title="Waive machine attestation"
        size="md"
      >
        {waiverTarget && (
          <div className="space-y-3">
            <p className="text-sm text-[var(--color-text-muted)]">
              {waiverTarget.name} will be allowed to obtain MCP tokens from a host without FerroGate attestation. This
              needs sudo, is time-boxed, and the app&apos;s AppID role must also allow bypassing machine binding.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Textarea
                  label="Reason (required)"
                  value={waiverReason}
                  onChange={(e) => setWaiverReason(e.target.value)}
                  placeholder="no FerroGate agent on this CI runner"
                />
              </div>
              <Input
                label={`Expires in (days, 1 to ${config?.waiver_max_days || 90})`}
                value={waiverDays}
                onChange={(e) => setWaiverDays(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setWaiverTarget(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={() => void doGrantWaiver()}>
                Grant waiver
              </Button>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => void doDelete()}
        title="Delete MCP app"
        message={`Delete ${deleteTarget?.name ?? ""}? Every token it has been issued is revoked immediately.`}
        confirmLabel="Delete"
        variant="danger"
      />

      <ConfirmModal
        open={!!revokeWaiverTarget}
        onClose={() => setRevokeWaiverTarget(null)}
        onConfirm={() => void doRevokeWaiver()}
        title="Revoke waiver"
        message={`Revoke the waiver for ${revokeWaiverTarget?.name ?? ""}? Its existing tokens stop working at their next call.`}
        confirmLabel="Revoke waiver"
        variant="danger"
      />

      <ConfirmModal
        open={!!revokeTokenTarget}
        onClose={() => setRevokeTokenTarget(null)}
        onConfirm={() => void doRevokeToken()}
        title="Revoke token"
        message="Revoke this MCP token? The client using it is cut off immediately."
        confirmLabel="Revoke"
        variant="danger"
      />
    </Layout>
  );
}
