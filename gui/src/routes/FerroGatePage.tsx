import { useState, useEffect, useCallback } from "react";

import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Textarea,
  Select,
  Badge,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import type { FerroGateConfig, FerroGateMachine, FerroGateLoginResult } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const MOUNT = "ferrogate/";

function fmtTime(unix: number): string {
  if (!unix) return "—";
  try {
    return new Date(unix * 1000).toLocaleString();
  } catch {
    return String(unix);
  }
}

function shortId(spiffe: string): string {
  // Show the trailing host segment of a SPIFFE id when present.
  const tail = spiffe.split("/").pop() || spiffe;
  return tail.length > 20 ? `${tail.slice(0, 20)}…` : tail;
}

function statusBadge(status: string) {
  const variant: "success" | "warning" | "error" | "neutral" =
    status === "approved" ? "success" : status === "pending" ? "warning" : status === "revoked" ? "error" : "neutral";
  return <Badge variant={variant} label={status} />;
}

export function FerroGatePage() {
  const [machines, setMachines] = useState<FerroGateMachine[]>([]);
  const [config, setConfig] = useState<FerroGateConfig | null>(null);
  const [tab, setTab] = useState("pending");
  const [loading, setLoading] = useState(true);
  const [mountEnabled, setMountEnabled] = useState(true);
  const { toast } = useToast();

  const [approveTarget, setApproveTarget] = useState<FerroGateMachine | null>(null);
  const [approvePolicies, setApprovePolicies] = useState("default");
  const [approveTtl, setApproveTtl] = useState("3600");
  const [approveComment, setApproveComment] = useState("");

  const [rejectTarget, setRejectTarget] = useState<FerroGateMachine | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const [revokeTarget, setRevokeTarget] = useState<FerroGateMachine | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.ferrogateListMachines();
      setMachines(list);
      setMountEnabled(true);
      try {
        setConfig(await api.ferrogateReadConfig());
      } catch {
        /* config read may fail independently; leave as-is */
      }
    } catch (e) {
      // A missing mount surfaces as an error here.
      setMountEnabled(false);
      setMachines([]);
      void extractError(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function enableMount() {
    try {
      await api.enableAuthMethod(MOUNT, "ferrogate", "FerroGate machine identity");
      toast("success", "FerroGate auth method enabled");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doApprove() {
    if (!approveTarget) return;
    try {
      await api.ferrogateApprove(
        approveTarget.id,
        approvePolicies,
        parseInt(approveTtl || "0", 10) || 0,
        approveComment,
      );
      toast("success", `Approved ${shortId(approveTarget.spiffe_id)}`);
      setApproveTarget(null);
      setApproveComment("");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doReject() {
    if (!rejectTarget) return;
    try {
      await api.ferrogateReject(rejectTarget.id, rejectReason);
      toast("success", `Rejected ${shortId(rejectTarget.spiffe_id)}`);
      setRejectTarget(null);
      setRejectReason("");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function doRevoke() {
    if (!revokeTarget) return;
    try {
      await api.ferrogateRevoke(revokeTarget.id);
      toast("success", `Revoked ${shortId(revokeTarget.spiffe_id)}`);
      setRevokeTarget(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  const pending = machines.filter((m) => m.status === "pending");
  const approved = machines.filter((m) => m.status === "approved");
  const history = machines.filter((m) => m.status === "rejected" || m.status === "revoked");

  const spiffeCol = {
    key: "spiffe",
    header: "Machine (SPIFFE ID)",
    render: (m: FerroGateMachine) => (
      <div className="min-w-0">
        <div className="truncate font-medium" title={m.spiffe_id}>
          {m.spiffe_id || "(unknown)"}
        </div>
        <div className="truncate font-mono text-xs text-[var(--color-text-muted)]" title={m.id}>
          {m.id.slice(0, 16)}…
        </div>
      </div>
    ),
  };

  const attestCol = {
    key: "attest",
    header: "Attestation",
    render: (m: FerroGateMachine) => (
      <div className="min-w-0 font-mono text-xs text-[var(--color-text-muted)]">
        {m.ek_cert_sha384 ? (
          <span title={m.ek_cert_sha384}>ek:{m.ek_cert_sha384.slice(0, 12)}…</span>
        ) : m.parent_svid ? (
          <span title={m.parent_svid}>svid:{m.parent_svid.slice(0, 12)}…</span>
        ) : (
          "—"
        )}
        {m.policy_id ? <span className="ml-2">pol:{m.policy_id}</span> : null}
      </div>
    ),
  };

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">Machines (FerroGate)</h1>
            <p className="text-sm text-[var(--color-text-muted)]">
              Admit only FerroGate-attested machines, gated by your approval.
            </p>
          </div>
          <Button variant="secondary" size="sm" onClick={() => void load()} disabled={loading}>
            Refresh
          </Button>
        </div>

        {!mountEnabled ? (
          <Card>
            <EmptyState
              title="FerroGate auth method not enabled"
              description="Enable the ferrogate auth method to start admitting attested machines."
              action={<Button onClick={() => void enableMount()}>Enable FerroGate</Button>}
            />
          </Card>
        ) : (
          <>
            <Tabs
              tabs={[
                { id: "pending", label: `Pending${pending.length ? ` (${pending.length})` : ""}` },
                { id: "approved", label: `Approved${approved.length ? ` (${approved.length})` : ""}` },
                { id: "history", label: "History" },
                { id: "self", label: "Machine Login" },
                { id: "config", label: "Config" },
              ]}
              active={tab}
              onChange={setTab}
            />

            {tab === "pending" && (
              <Card>
                <Table
                  columns={[
                    spiffeCol,
                    attestCol,
                    { key: "seen", header: "First seen", render: (m: FerroGateMachine) => fmtTime(m.first_seen_at) },
                    {
                      key: "actions",
                      header: "",
                      render: (m: FerroGateMachine) => (
                        <div className="flex justify-end gap-2">
                          <Button size="sm" onClick={() => setApproveTarget(m)}>
                            Approve
                          </Button>
                          <Button size="sm" variant="danger" onClick={() => setRejectTarget(m)}>
                            Reject
                          </Button>
                        </div>
                      ),
                    },
                  ]}
                  data={pending}
                  rowKey={(m: FerroGateMachine) => m.id}
                  emptyMessage="No machines awaiting approval"
                />
              </Card>
            )}

            {tab === "approved" && (
              <Card>
                <Table
                  columns={[
                    spiffeCol,
                    {
                      key: "policies",
                      header: "Policies",
                      render: (m: FerroGateMachine) => (
                        <div className="flex flex-wrap gap-1">
                          {m.policies.map((p) => (
                            <Badge key={p} variant="info" label={p} />
                          ))}
                        </div>
                      ),
                    },
                    { key: "login", header: "Last login", render: (m: FerroGateMachine) => fmtTime(m.last_login_at) },
                    {
                      key: "ip",
                      header: "Source IP",
                      render: (m: FerroGateMachine) => (
                        <span className="font-mono text-xs">{m.last_login_ip || "—"}</span>
                      ),
                    },
                    {
                      key: "actions",
                      header: "",
                      render: (m: FerroGateMachine) => (
                        <div className="flex justify-end">
                          <Button size="sm" variant="danger" onClick={() => setRevokeTarget(m)}>
                            Revoke
                          </Button>
                        </div>
                      ),
                    },
                  ]}
                  data={approved}
                  rowKey={(m: FerroGateMachine) => m.id}
                  emptyMessage="No approved machines"
                />
              </Card>
            )}

            {tab === "history" && (
              <Card>
                <Table
                  columns={[
                    spiffeCol,
                    { key: "status", header: "Status", render: (m: FerroGateMachine) => statusBadge(m.status) },
                    {
                      key: "reason",
                      header: "Reason",
                      render: (m: FerroGateMachine) => (
                        <span className="text-sm text-[var(--color-text-muted)]">{m.reject_reason || "—"}</span>
                      ),
                    },
                    { key: "when", header: "Approved at", render: (m: FerroGateMachine) => fmtTime(m.approved_at) },
                  ]}
                  data={history}
                  rowKey={(m: FerroGateMachine) => m.id}
                  emptyMessage="No rejected or revoked machines"
                />
              </Card>
            )}

            {tab === "self" && <MachineLoginPanel expectedAudience={config?.expected_audience || ""} toast={toast} />}

            {tab === "config" && config && <ConfigPanel config={config} onSaved={load} toast={toast} />}
          </>
        )}
      </div>

      {/* Approve modal */}
      <Modal open={!!approveTarget} onClose={() => setApproveTarget(null)} title="Approve machine" size="md">
        {approveTarget && (
          <div className="space-y-3">
            <p className="break-all text-sm text-[var(--color-text-muted)]">{approveTarget.spiffe_id}</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Input
                  label="Policies (comma-separated)"
                  value={approvePolicies}
                  onChange={(e) => setApprovePolicies(e.target.value)}
                  placeholder="default,reader"
                />
              </div>
              <Input
                label="Token TTL (seconds)"
                type="number"
                value={approveTtl}
                onChange={(e) => setApproveTtl(e.target.value)}
              />
              <div className="col-span-2">
                <Input
                  label="Comment (optional)"
                  value={approveComment}
                  onChange={(e) => setApproveComment(e.target.value)}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setApproveTarget(null)}>
                Cancel
              </Button>
              <Button onClick={() => void doApprove()}>Approve</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Reject modal */}
      <Modal open={!!rejectTarget} onClose={() => setRejectTarget(null)} title="Reject machine" size="md">
        {rejectTarget && (
          <div className="space-y-3">
            <p className="break-all text-sm text-[var(--color-text-muted)]">{rejectTarget.spiffe_id}</p>
            <Textarea
              label="Reason"
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="unknown host"
            />
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setRejectTarget(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={() => void doReject()}>
                Reject
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Revoke confirm */}
      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => void doRevoke()}
        title="Revoke machine"
        message={`Revoke ${revokeTarget ? shortId(revokeTarget.spiffe_id) : ""}? Active tokens for it will be invalidated.`}
        confirmLabel="Revoke"
        variant="danger"
      />
    </Layout>
  );
}

function MachineLoginPanel({
  expectedAudience,
  toast,
}: {
  expectedAudience: string;
  toast: (type: "success" | "error" | "info", message: string) => void;
}) {
  const [socket, setSocket] = useState("");
  const [audience, setAudience] = useState(expectedAudience);
  const [mount, setMount] = useState("ferrogate");
  const [ttl, setTtl] = useState("300");
  const [busy, setBusy] = useState<"" | "whoami" | "status" | "login">("");
  const [spiffe, setSpiffe] = useState("");
  const [statusJson, setStatusJson] = useState("");
  const [result, setResult] = useState<FerroGateLoginResult | null>(null);

  // Prefill the socket field with this platform's default MIA path so the
  // operator does not have to know whether it is /run or /var/run.
  useEffect(() => {
    void api.ferrogateDefaultSocket().then(setSocket).catch(() => {});
  }, []);
  // Keep the audience in sync with the mount's configured expected_audience
  // until the operator edits it.
  useEffect(() => {
    setAudience((a) => (a ? a : expectedAudience));
  }, [expectedAudience]);

  const ttlNum = parseInt(ttl || "0", 10) || 300;

  async function doWhoami() {
    setBusy("whoami");
    try {
      const id = await api.ferrogateWhoami(socket);
      setSpiffe(id);
      toast("success", "MIA reachable");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy("");
    }
  }

  async function doStatus() {
    setBusy("status");
    try {
      const s = await api.ferrogateMachineStatus(audience, socket, mount, ttlNum);
      setStatusJson(JSON.stringify(s, null, 2));
    } catch (e) {
      setStatusJson("");
      toast("error", extractError(e));
    } finally {
      setBusy("");
    }
  }

  async function doLogin() {
    setBusy("login");
    try {
      const r = await api.ferrogateMachineLogin(audience, socket, mount, ttlNum);
      setResult(r);
      setSpiffe(r.spiffe_id || spiffe);
      if (r.authenticated) {
        toast("success", "Machine authenticated — token issued");
      } else if (r.enrolment === "rejected" || r.enrolment === "revoked") {
        toast("error", r.message || `Machine ${r.enrolment}`);
      } else {
        toast("info", r.message || "Awaiting operator approval");
      }
    } catch (e) {
      setResult(null);
      toast("error", extractError(e));
    } finally {
      setBusy("");
    }
  }

  async function copyToken() {
    if (!result?.client_token) return;
    try {
      await navigator.clipboard.writeText(result.client_token);
      toast("success", "Token copied");
    } catch {
      toast("error", "Could not copy token");
    }
  }

  return (
    <Card>
      <div className="space-y-4">
        <div>
          <h2 className="text-base font-semibold">Self-enroll this host via the MIA</h2>
          <p className="text-sm text-[var(--color-text-muted)]">
            Dials the local FerroGate Machine Identity Agent over its helper socket, mints a
            short-lived DPoP-bound child token, and exchanges it at <code className="font-mono">auth/{mount.trim() || "ferrogate"}/login</code>.
            A running MIA on this machine is required. This does not change your current admin session.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <Input
              label="MIA helper socket"
              value={socket}
              onChange={(e) => setSocket(e.target.value)}
              placeholder="resolved from the installed MIA's config…"
            />
          </div>
          <Input
            label="Audience"
            value={audience}
            onChange={(e) => setAudience(e.target.value)}
            placeholder="https://vault.example.com"
          />
          <Input label="Mount" value={mount} onChange={(e) => setMount(e.target.value)} placeholder="ferrogate" />
          <Input
            label="Child-token TTL (seconds)"
            type="number"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
          />
        </div>

        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => void doWhoami()} disabled={!!busy}>
            {busy === "whoami" ? "Checking…" : "Whoami"}
          </Button>
          <Button variant="secondary" onClick={() => void doStatus()} disabled={!!busy || !audience}>
            {busy === "status" ? "Checking…" : "Check status"}
          </Button>
          <Button onClick={() => void doLogin()} disabled={!!busy || !audience}>
            {busy === "login" ? "Logging in…" : "Log in"}
          </Button>
        </div>

        {spiffe && (
          <div className="text-sm">
            <span className="text-[var(--color-text-muted)]">This host&apos;s SPIFFE ID: </span>
            <span className="break-all font-mono">{spiffe}</span>
          </div>
        )}

        {statusJson && (
          <div>
            <div className="mb-1 text-sm text-[var(--color-text-muted)]">Enrolment status</div>
            <pre className="overflow-x-auto rounded bg-[var(--color-bg-subtle)] p-3 text-xs">{statusJson}</pre>
          </div>
        )}

        {result?.authenticated && (
          <Card>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Badge variant="success" label="authenticated" />
                {result.policies.map((p) => (
                  <Badge key={p} variant="info" label={p} />
                ))}
                {result.lease_duration ? (
                  <span className="text-xs text-[var(--color-text-muted)]">lease {result.lease_duration}s</span>
                ) : null}
              </div>
              <Input label="Vault token" value={result.client_token} readOnly className="font-mono" />
              <div className="flex justify-end">
                <Button variant="secondary" size="sm" onClick={() => void copyToken()}>
                  Copy token
                </Button>
              </div>
            </div>
          </Card>
        )}

        {result && !result.authenticated && (
          <Card>
            <div className="flex items-center gap-2">
              {statusBadge(result.enrolment)}
              <span className="text-sm text-[var(--color-text-muted)]">
                {result.message ||
                  (result.enrolment === "pending"
                    ? "Awaiting operator approval."
                    : "This machine is not authorized.")}
              </span>
            </div>
          </Card>
        )}
      </div>
    </Card>
  );
}

function ConfigPanel({
  config,
  onSaved,
  toast,
}: {
  config: FerroGateConfig;
  onSaved: () => Promise<void>;
  toast: (type: "success" | "error" | "info", message: string) => void;
}) {
  const [trustDomain, setTrustDomain] = useState(config.trust_domain);
  const [expectedAudience, setExpectedAudience] = useState(config.expected_audience);
  const [jwksSource, setJwksSource] = useState(config.jwks_source || "static_jwks");
  const [cmisEndpoint, setCmisEndpoint] = useState(config.cmis_endpoint);
  const [cmisSpkiPins, setCmisSpkiPins] = useState((config.cmis_spki_pins || []).join(","));
  const [staticJwks, setStaticJwks] = useState(config.static_jwks);
  const [acceptSvid, setAcceptSvid] = useState(config.accept_svid);
  const [cmisTlsEnable, setCmisTlsEnable] = useState(config.cmis_tls_enable);
  const [cmisSameHost, setCmisSameHost] = useState(config.cmis_same_host);
  const [bootstrap, setBootstrap] = useState(config.bootstrap_root_auto_approve);
  const [bootstrapPolicies, setBootstrapPolicies] = useState((config.bootstrap_policies || []).join(","));
  const [requireUserToken, setRequireUserToken] = useState(config.require_user_token);
  const [requireMachineIdentity, setRequireMachineIdentity] = useState(config.require_machine_identity);
  const [saving, setSaving] = useState(false);
  const [autofilling, setAutofilling] = useState(false);

  // Prefill trust domain + CMIS coordinates from the FerroGate MIA installed on
  // this host (mia.toml + signed allowlist) and verify CMIS is reachable by
  // fetching its live JWKS. Fills the form only — the operator reviews and Saves.
  async function autofill() {
    setAutofilling(true);
    try {
      const r = await api.ferrogateAutoconfig(expectedAudience.trim());
      if (r.trust_domain) setTrustDomain(r.trust_domain);
      setJwksSource(r.jwks_source || "cmis_grpc");
      setCmisEndpoint(r.cmis_endpoint);
      setCmisSpkiPins((r.cmis_spki_pins || []).join(","));
      setCmisTlsEnable(r.cmis_tls_enable);
      if (r.fetched_jwks) setStaticJwks(r.fetched_jwks);
      (r.warnings || []).forEach((w) => toast("info", w));
      toast(
        "success",
        `Filled from local MIA: CMIS ${r.cmis_endpoint}, ${(r.jwks_kids || []).length} key(s). Review and Save.`,
      );
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setAutofilling(false);
    }
  }

  async function save() {
    setSaving(true);
    try {
      await api.ferrogateWriteConfig({
        trustDomain,
        expectedAudience,
        jwksSource,
        cmisEndpoint,
        cmisSpkiPins,
        staticJwks,
        acceptSvid,
        cmisTlsEnable,
        cmisSameHost,
        bootstrapRootAutoApprove: bootstrap,
        bootstrapPolicies,
        requireUserToken,
        requireMachineIdentity,
      });
      toast("success", "Configuration saved");
      await onSaved();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <div className="grid grid-cols-2 gap-3">
        <Input label="Trust domain" value={trustDomain} onChange={(e) => setTrustDomain(e.target.value)} placeholder="ferrogate.prod" />
        <Input label="Expected audience" value={expectedAudience} onChange={(e) => setExpectedAudience(e.target.value)} placeholder="https://vault.example.com" />
        <Select
          label="JWKS source"
          value={jwksSource}
          onChange={(e) => setJwksSource(e.target.value)}
          options={[
            { value: "static_jwks", label: "static_jwks" },
            { value: "cmis_grpc", label: "cmis_grpc" },
          ]}
        />
        <Input label="CMIS endpoint" value={cmisEndpoint} onChange={(e) => setCmisEndpoint(e.target.value)} placeholder="cmis.example.com:8443" />
        <div className="col-span-2">
          <Input label="CMIS SPKI pins (comma-separated SHA-384 hex)" value={cmisSpkiPins} onChange={(e) => setCmisSpkiPins(e.target.value)} />
        </div>
        <div className="col-span-2">
          <Textarea label="Static JWKS (JSON)" value={staticJwks} onChange={(e) => setStaticJwks(e.target.value)} rows={4} />
        </div>
        <Input label="Bootstrap policies (comma-separated)" value={bootstrapPolicies} onChange={(e) => setBootstrapPolicies(e.target.value)} placeholder="default" />
        <div className="flex flex-col justify-end gap-2 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={cmisTlsEnable} onChange={(e) => setCmisTlsEnable(e.target.checked)} />
            Use PQ-TLS to reach CMIS
          </label>
          <label className="flex items-center gap-2" title="The endpoint above may not be reachable from the server's own vantage point (e.g. a containerised server). Tries host.containers.internal and loopback first, then the configured endpoint. The SPKI pin still authenticates the peer.">
            <input type="checkbox" checked={cmisSameHost} onChange={(e) => setCmisSameHost(e.target.checked)} />
            CMIS is on the same host as the server
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={bootstrap} onChange={(e) => setBootstrap(e.target.checked)} />
            First-machine root bootstrap
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={acceptSvid} onChange={(e) => setAcceptSvid(e.target.checked)} />
            Accept direct SVID (weaker)
          </label>
          <label className="flex items-center gap-2" title="Require a user token on every machine login and mint a token whose policies are the intersection of the machine's and the user's. Enforces combined machine+user auth server-side.">
            <input type="checkbox" checked={requireUserToken} onChange={(e) => setRequireUserToken(e.target.checked)} />
            Require user token (machine + user)
          </label>
          <label className="flex items-center gap-2" title="Server-enforced: every authenticated request to this server must present a FerroGate machine-bound token (or a root token). Clients discover this on connect and cannot bypass it.">
            <input type="checkbox" checked={requireMachineIdentity} onChange={(e) => setRequireMachineIdentity(e.target.checked)} />
            Require machine identity (all sessions)
          </label>
        </div>
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
        <Button variant="secondary" onClick={() => void autofill()} disabled={autofilling || saving}>
          {autofilling ? "Reading MIA…" : "Autofill from local MIA"}
        </Button>
        <Button onClick={() => void save()} disabled={saving || autofilling}>
          {saving ? "Saving…" : "Save configuration"}
        </Button>
      </div>
    </Card>
  );
}
