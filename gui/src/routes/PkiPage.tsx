import { useState, useEffect, useCallback } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Textarea,
  Badge,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import type {
  PkiMountInfo,
  PkiIssuerSummary,
  PkiIssuerDetail,
  PkiRoleConfig,
  PkiIssueResult,
  PkiTidyStatus,
  PkiAutoTidyConfig,
  PkiManagedKey,
  PkiCertRecord,
} from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type TabId = "issuers" | "roles" | "keys" | "issue" | "certs" | "tidy" | "xca";

const KEY_TYPE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "ec", label: "ECDSA P-256 (default)" },
  { value: "rsa", label: "RSA" },
  { value: "ed25519", label: "Ed25519" },
  { value: "ml-dsa-44", label: "ML-DSA-44 (PQC)" },
  { value: "ml-dsa-65", label: "ML-DSA-65 (PQC)" },
  { value: "ml-dsa-87", label: "ML-DSA-87 (PQC)" },
];

const RSA_BITS = [
  { value: "2048", label: "2048" },
  { value: "3072", label: "3072" },
  { value: "4096", label: "4096" },
];
const EC_BITS = [
  { value: "256", label: "256 (P-256)" },
  { value: "384", label: "384 (P-384)" },
];

const ALL_USAGES = ["issuing-certificates", "crl-signing", "ocsp-signing"] as const;

// `humantime::parse_duration` (the parser the PKI engine runs on the
// backend) accepts these unit suffixes. Validate against this list at
// submit time so a user who types bare digits gets immediate feedback
// instead of a server round-trip with a generic error.
const DURATION_UNIT_RE = /^\s*(\d+\s*(ns|us|µs|ms|s|m|h|d|w|y))(\s*\d+\s*(ns|us|µs|ms|s|m|h|d|w|y))*\s*$/;

function defaultRoleConfig(): PkiRoleConfig {
  return {
    // Pre-fill with sensible defaults that are valid duration strings.
    // Empty is also accepted by the backend (falls back to engine defaults),
    // but a no-touch submit with valid units beats a no-touch submit that
    // round-trips an error.
    ttl: "720h",
    max_ttl: "2160h",
    key_type: "ec",
    key_bits: 0,
    allow_localhost: true,
    allow_any_name: true,
    allow_subdomains: false,
    allow_bare_domains: false,
    allow_ip_sans: true,
    server_flag: true,
    client_flag: true,
    use_csr_sans: true,
    use_csr_common_name: true,
    key_usage: ["DigitalSignature", "KeyEncipherment"],
    ext_key_usage: [],
    country: "",
    province: "",
    locality: "",
    organization: "",
    ou: "",
    no_store: false,
    generate_lease: false,
    issuer_ref: "",
    allow_key_reuse: false,
    allowed_key_refs: [],
    allowed_domains: [],
    allow_glob_domains: false,
    acme_enabled: true,
  };
}

/// Validate a duration string the way the backend's `humantime::parse_duration`
/// would. Empty is allowed (the backend falls back to engine defaults).
/// Returns a human-readable error message on rejection, or `null` on accept.
function validateDurationField(label: string, value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!DURATION_UNIT_RE.test(trimmed)) {
    return `${label} '${value}' needs a unit suffix — try '720h', '5m', or '8760h'`;
  }
  return null;
}

function fmtUnix(t: number | null | undefined): string {
  if (!t || t === 0) return "—";
  return new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/** Pull the CN attribute out of an RFC 4514-style DN string. Returns
 *  empty when no CN= component is present so the caller can fall
 *  back to the full DN. Handles `CN=foo,O=bar` and the variant
 *  produced by `x509-cert`'s `Display` (which separates RDNs with
 *  `,` and unescapes nothing). */
function extractCn(dn: string): string {
  for (const piece of dn.split(",")) {
    const t = piece.trim();
    if (t.toUpperCase().startsWith("CN=")) {
      return t.slice(3);
    }
  }
  return "";
}

export function PkiPage() {
  const { toast } = useToast();
  const [mounts, setMounts] = useState<PkiMountInfo[]>([]);
  const [activeMount, setActiveMount] = useState<string>("");
  const [tab, setTab] = useState<TabId>("issuers");
  const [showEnable, setShowEnable] = useState(false);
  const [newMountPath, setNewMountPath] = useState("pki/");
  const [enabling, setEnabling] = useState(false);
  // The XCA importer ships as an external plugin; the tab only appears
  // when the plugin (named `xca-import`) is registered on this vault.
  const [xcaPluginPresent, setXcaPluginPresent] = useState(false);
  const [xcaPluginVersion, setXcaPluginVersion] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.pluginsList();
        if (!cancelled) {
          const found = list.find((p) => p.name === "xca-import");
          setXcaPluginPresent(!!found);
          setXcaPluginVersion(found?.version ?? null);
        }
      } catch {
        /* plugin admin may be gated; treat as absent */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshMounts = useCallback(async () => {
    try {
      const list = await api.pkiListMounts();
      setMounts(list);
      if (list.length > 0 && !activeMount) {
        setActiveMount(list[0].path.replace(/\/$/, ""));
      }
    } catch (e) {
      toast("error", extractError(e));
    }
  }, [activeMount, toast]);

  useEffect(() => {
    refreshMounts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleEnableMount() {
    if (!newMountPath.trim()) return;
    setEnabling(true);
    try {
      await api.pkiEnableMount(newMountPath.trim());
      toast("success", `Mounted PKI engine at ${newMountPath}`);
      setShowEnable(false);
      setNewMountPath("pki/");
      await refreshMounts();
      setActiveMount(newMountPath.trim().replace(/\/$/, ""));
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setEnabling(false);
    }
  }

  const mountOptions = mounts.length === 0
    ? [{ value: "", label: "No PKI mounts" }]
    : mounts.map((m) => ({
        value: m.path.replace(/\/$/, ""),
        label: m.path,
      }));

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h1 className="text-xl font-semibold">PKI</h1>
          <Button onClick={() => setShowEnable(true)}>+ Mount PKI engine</Button>
        </div>

        <Card>
          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-sm text-[var(--color-text-muted)]">Mount</label>
            <Select
              label=""
              value={activeMount}
              onChange={(e) => setActiveMount(e.target.value)}
              disabled={mounts.length === 0}
              options={mountOptions}
              className="min-w-[200px]"
            />
            <Button variant="ghost" onClick={refreshMounts}>
              Refresh
            </Button>
          </div>
        </Card>

        {!activeMount ? (
          <Card>
            <EmptyState
              title="No PKI engine mounted"
              description="Mount the PKI engine on a path (typically `pki/`) to manage CAs, roles, and certificate issuance."
              action={
                <Button onClick={() => setShowEnable(true)}>Mount PKI engine</Button>
              }
            />
          </Card>
        ) : (
          <>
            <Card>
              <Tabs
                tabs={[
                  { id: "issuers", label: "Issuers" },
                  { id: "roles", label: "Roles" },
                  { id: "keys", label: "Keys" },
                  { id: "issue", label: "Issue" },
                  { id: "certs", label: "Certificates" },
                  { id: "tidy", label: "Tidy" },
                  ...(xcaPluginPresent
                    ? [{ id: "xca", label: "Import XCA" }]
                    : []),
                ]}
                active={tab}
                onChange={(t) => setTab(t as TabId)}
              />
            </Card>

            {tab === "issuers" && <IssuersTab mount={activeMount} />}
            {tab === "roles" && <RolesTab mount={activeMount} />}
            {tab === "keys" && <KeysTab mount={activeMount} />}
            {tab === "issue" && <IssueTab mount={activeMount} />}
            {tab === "certs" && <CertsTab mount={activeMount} />}
            {tab === "tidy" && <TidyTab mount={activeMount} />}
            {tab === "xca" && xcaPluginPresent && (
              <XcaImportTab mount={activeMount} pluginVersion={xcaPluginVersion} />
            )}
          </>
        )}
      </div>

      <Modal
        open={showEnable}
        onClose={() => setShowEnable(false)}
        title="Mount PKI engine"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowEnable(false)}>
              Cancel
            </Button>
            <Button onClick={handleEnableMount} disabled={enabling || !newMountPath.trim()}>
              {enabling ? "Mounting..." : "Mount"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input
            label="Mount path"
            value={newMountPath}
            onChange={(e) => setNewMountPath(e.target.value)}
            placeholder="pki/"
            autoFocus
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            The engine is mounted at <code>/v1/&lt;path&gt;/*</code>. Common choices:{" "}
            <code>pki/</code> for the default mount, <code>pki-int/</code> for an intermediate
            mount.
          </p>
        </div>
      </Modal>
    </Layout>
  );
}

// ── Issuers Tab ───────────────────────────────────────────────────

function IssuersTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [issuers, setIssuers] = useState<PkiIssuerSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<PkiIssuerDetail | null>(null);
  const [showGenerate, setShowGenerate] = useState(false);
  const [showImportCa, setShowImportCa] = useState(false);
  const [showRename, setShowRename] = useState(false);
  const [showUsages, setShowUsages] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<PkiIssuerSummary | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [usageValues, setUsageValues] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.pkiListIssuers(mount);
      setIssuers(result.issuers);
      if (result.issuers.length > 0) {
        const first = detail
          ? result.issuers.find((i) => i.id === detail.id) ?? result.issuers[0]
          : result.issuers[0];
        const d = await api.pkiReadIssuer(mount, first.id);
        setDetail(d);
      } else {
        setDetail(null);
      }
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function selectIssuer(id: string) {
    try {
      const d = await api.pkiReadIssuer(mount, id);
      setDetail(d);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function setAsDefault(id: string) {
    try {
      await api.pkiSetDefaultIssuer(mount, id);
      toast("success", "Default issuer updated");
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleRename() {
    if (!detail || !renameValue.trim()) return;
    try {
      await api.pkiRenameIssuer(mount, detail.id, renameValue.trim());
      toast("success", "Issuer renamed");
      setShowRename(false);
      setRenameValue("");
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleSetUsages() {
    if (!detail) return;
    try {
      await api.pkiSetIssuerUsages(mount, detail.id, usageValues);
      toast("success", "Usages updated");
      setShowUsages(false);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.pkiDeleteIssuer(mount, deleteTarget.id);
      toast("success", `Issuer ${deleteTarget.name} deleted`);
      setDeleteTarget(null);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card
      title="Issuers"
      actions={
        <>
          <Button variant="ghost" onClick={() => setShowImportCa(true)}>
            Import root CA
          </Button>
          <Button onClick={() => setShowGenerate(true)}>+ Generate root CA</Button>
        </>
      }
    >
      {loading ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : issuers.length === 0 ? (
        <EmptyState
          title="No issuers configured"
          description="Generate a root CA to start issuing certificates. The first issuer becomes the mount default automatically."
          action={
            <div className="flex items-center gap-2">
              <Button variant="ghost" onClick={() => setShowImportCa(true)}>
                Import root CA
              </Button>
              <Button onClick={() => setShowGenerate(true)}>Generate root CA</Button>
            </div>
          }
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div>
            <div className="space-y-1">
              {issuers.map((i) => (
                <button
                  key={i.id}
                  onClick={() => selectIssuer(i.id)}
                  className={`block w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                    detail?.id === i.id
                      ? "bg-[var(--color-surface-hover)] font-semibold"
                      : "hover:bg-[var(--color-surface-hover)]"
                  }`}
                >
                  <span className="truncate">{i.name}</span>
                  {i.is_default && (
                    <Badge label="default" variant="success" />
                  )}
                </button>
              ))}
            </div>
          </div>

          {detail && (
            <div className="lg:col-span-2 space-y-3 min-w-0">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Name" value={detail.name} />
                <Field label="Kind" value={detail.ca_kind} />
                <Field label="Common Name" value={detail.common_name} />
                <Field label="Key Type" value={detail.key_type} />
                <Field label="Not After" value={fmtUnix(detail.not_after)} />
                <Field label="Default" value={detail.is_default ? "yes" : "no"} />
                <Field label="Issuer ID" value={detail.id} mono />
                <Field label="Usages" value={detail.usage.join(", ") || "(none)"} />
                {detail.key_id && (
                  <Field
                    label="Backing key (managed-key UUID)"
                    value={detail.key_id}
                    mono
                  />
                )}
              </div>
              <div className="flex gap-2 flex-wrap">
                {!detail.is_default && (
                  <Button variant="ghost" onClick={() => setAsDefault(detail.id)}>
                    Set as default
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={() => {
                    setRenameValue(detail.name);
                    setShowRename(true);
                  }}
                >
                  Rename
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setUsageValues(detail.usage);
                    setShowUsages(true);
                  }}
                >
                  Edit usages
                </Button>
                <Button
                  variant="ghost"
                  onClick={() =>
                    setDeleteTarget({
                      id: detail.id,
                      name: detail.name,
                      is_default: detail.is_default,
                    })
                  }
                >
                  Delete
                </Button>
              </div>
              <Textarea
                label="Certificate (PEM)"
                value={detail.certificate}
                readOnly
                rows={8}
                className="font-mono text-xs"
              />
            </div>
          )}
        </div>
      )}

      <GenerateRootModal
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
        mount={mount}
        onSuccess={refresh}
      />

      <ImportRootCaModal
        open={showImportCa}
        onClose={() => setShowImportCa(false)}
        mount={mount}
        onSuccess={refresh}
      />

      <Modal
        open={showRename}
        onClose={() => setShowRename(false)}
        title="Rename issuer"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowRename(false)}>
              Cancel
            </Button>
            <Button onClick={handleRename} disabled={!renameValue.trim()}>
              Rename
            </Button>
          </>
        }
      >
        <Input
          label="New name"
          value={renameValue}
          onChange={(e) => setRenameValue(e.target.value)}
          autoFocus
        />
      </Modal>

      <Modal
        open={showUsages}
        onClose={() => setShowUsages(false)}
        title="Edit issuer usages"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowUsages(false)}>
              Cancel
            </Button>
            <Button onClick={handleSetUsages} disabled={usageValues.length === 0}>
              Save
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {ALL_USAGES.map((u) => (
            <label key={u} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={usageValues.includes(u)}
                onChange={(e) => {
                  if (e.target.checked) {
                    setUsageValues((prev) => Array.from(new Set([...prev, u])));
                  } else {
                    setUsageValues((prev) => prev.filter((v) => v !== u));
                  }
                }}
              />
              <code>{u}</code>
            </label>
          ))}
          <p className="text-xs text-[var(--color-text-muted)]">
            At least one usage must be enabled. An issuer with no usages can never be invoked.
          </p>
        </div>
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete issuer?"
        message={
          deleteTarget
            ? `Delete issuer "${deleteTarget.name}"? Certs already issued by this issuer remain in the cert store and tidy will sweep them after expiry.`
            : ""
        }
        confirmLabel="Delete"
        variant="danger"
      />
    </Card>
  );
}

// ── Generate Root Modal ──────────────────────────────────────────

function GenerateRootModal({
  open,
  onClose,
  mount,
  onSuccess,
}: {
  open: boolean;
  onClose: () => void;
  mount: string;
  onSuccess: () => void;
}) {
  const { toast } = useToast();
  const [commonName, setCommonName] = useState("");
  const [organization, setOrganization] = useState("");
  const [keyType, setKeyType] = useState("ec");
  const [keyBits, setKeyBits] = useState("0");
  const [ttl, setTtl] = useState("87600h");
  const [issuerName, setIssuerName] = useState("");
  const [exported, setExported] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ private_key?: string } | null>(null);

  function reset() {
    setCommonName("");
    setOrganization("");
    setKeyType("ec");
    setKeyBits("0");
    setTtl("87600h");
    setIssuerName("");
    setExported(false);
    setResult(null);
  }

  async function submit() {
    if (!commonName.trim()) return;
    setBusy(true);
    try {
      const r = await api.pkiGenerateRoot({
        mount,
        mode: exported ? "exported" : "internal",
        common_name: commonName.trim(),
        organization: organization.trim() || undefined,
        key_type: keyType,
        key_bits: Number(keyBits) || undefined,
        ttl: ttl.trim() || undefined,
        issuer_name: issuerName.trim() || undefined,
      });
      toast("success", `Root CA generated as issuer "${r.issuer_name}"`);
      setResult({ private_key: r.private_key });
      onSuccess();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  function handleClose() {
    reset();
    onClose();
  }

  const bitsOptions = keyType === "rsa" ? RSA_BITS : keyType === "ec" ? EC_BITS : [];

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Generate root CA"
      size="md"
      actions={
        result ? (
          <Button onClick={handleClose}>Close</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={handleClose}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={busy || !commonName.trim()}>
              {busy ? "Generating…" : "Generate"}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="space-y-3">
          <p className="text-sm text-green-500">Root CA generated.</p>
          {result.private_key && (
            <Textarea
              label="Private key (PKCS#8 PEM) — store this securely; it will not be shown again"
              value={result.private_key}
              readOnly
              rows={8}
              className="font-mono text-xs"
            />
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Common Name"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
              placeholder="My Internal Root"
              autoFocus
            />
            <Input
              label="Organization (optional)"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
            />
            <Select
              label="Key type"
              value={keyType}
              onChange={(e) => {
                setKeyType(e.target.value);
                setKeyBits("0");
              }}
              options={KEY_TYPE_OPTIONS}
            />
            {bitsOptions.length > 0 && (
              <Select
                label="Key bits"
                value={keyBits === "0" ? bitsOptions[0].value : keyBits}
                onChange={(e) => setKeyBits(e.target.value)}
                options={bitsOptions}
              />
            )}
            <Input
              label="TTL"
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              placeholder="87600h (10 years)"
            />
            <Input
              label="Issuer name (optional)"
              value={issuerName}
              onChange={(e) => setIssuerName(e.target.value)}
              placeholder="default | issuer-2 | …"
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={exported}
              onChange={(e) => setExported(e.target.checked)}
            />
            Export private key (returns the key in the response — copy it before closing)
          </label>
        </div>
      )}
    </Modal>
  );
}

// ── Import root CA Modal ──────────────────────────────────────────

/** Two-mode root CA importer:
 *  - **PEM bundle**: textarea, accepts a single string with the cert
 *    PEM block(s) and the unencrypted private-key PEM concatenated.
 *  - **PKCS#12**: file picker (`.p12` / `.pfx`) + passphrase. The
 *    file is read in the renderer, base64-encoded, and unwrapped on
 *    the Tauri side; the passphrase never leaves the local process.
 *
 *  Both modes go through `pki/config/ca`, so the freshly imported
 *  cert + key land as a normal issuer (with a shadow managed-key
 *  entry so the Keys tab can manage it like any other key). */
function ImportRootCaModal({
  open,
  onClose,
  mount,
  onSuccess,
}: {
  open: boolean;
  onClose: () => void;
  mount: string;
  onSuccess: () => void;
}) {
  const { toast } = useToast();
  const [mode, setMode] = useState<"pem" | "pkcs12">("pem");
  const [issuerName, setIssuerName] = useState("");
  const [pemBundle, setPemBundle] = useState("");
  const [pkcs12Name, setPkcs12Name] = useState("");
  const [pkcs12B64, setPkcs12B64] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);

  function reset() {
    setMode("pem");
    setIssuerName("");
    setPemBundle("");
    setPkcs12Name("");
    setPkcs12B64("");
    setPassphrase("");
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setPkcs12Name(file.name);
    const buf = await file.arrayBuffer();
    // Encode as base64 — chunked to dodge the call-stack limit on
    // large containers (>~50 KB) when fanning the byte array into
    // String.fromCharCode in one shot.
    const bytes = new Uint8Array(buf);
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    setPkcs12B64(btoa(binary));
  }

  async function submit() {
    setBusy(true);
    try {
      if (mode === "pem") {
        if (!pemBundle.trim()) {
          toast("error", "Paste a PEM bundle (cert + private key).");
          return;
        }
        const r = await api.pkiImportCaBundle({
          mount,
          pem_bundle: pemBundle.trim(),
          issuer_name: issuerName.trim() || undefined,
        });
        toast("success", `Imported as issuer "${r.issuer_name}"`);
      } else {
        if (!pkcs12B64) {
          toast("error", "Select a .p12 / .pfx file first.");
          return;
        }
        const r = await api.pkiImportCaPkcs12({
          mount,
          pkcs12_b64: pkcs12B64,
          passphrase,
          issuer_name: issuerName.trim() || undefined,
        });
        toast("success", `Imported as issuer "${r.issuer_name}"`);
      }
      onSuccess();
      handleClose();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  const canSubmit =
    !busy &&
    (mode === "pem" ? pemBundle.trim().length > 0 : pkcs12B64.length > 0);

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Import root CA"
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {busy ? "Importing…" : "Import"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-sm">
          <button
            type="button"
            className={`px-3 py-1.5 rounded-lg border ${
              mode === "pem"
                ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                : "border-[var(--color-border)] text-[var(--color-text-muted)]"
            }`}
            onClick={() => setMode("pem")}
          >
            PEM bundle
          </button>
          <button
            type="button"
            className={`px-3 py-1.5 rounded-lg border ${
              mode === "pkcs12"
                ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                : "border-[var(--color-border)] text-[var(--color-text-muted)]"
            }`}
            onClick={() => setMode("pkcs12")}
          >
            PKCS#12 (.p12 / .pfx)
          </button>
        </div>

        <Input
          label="Issuer name (optional)"
          value={issuerName}
          onChange={(e) => setIssuerName(e.target.value)}
          placeholder="Defaults to the cert's CN"
        />

        {mode === "pem" ? (
          <>
            <Textarea
              label="PEM bundle"
              value={pemBundle}
              onChange={(e) => setPemBundle(e.target.value)}
              rows={12}
              placeholder={
                "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n" +
                "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----"
              }
            />
            <p className="text-xs text-[var(--color-text-muted)]">
              Paste the CA certificate and its unencrypted private key
              (PKCS#8 / RSA / EC) concatenated. Optional intermediate certs
              may be appended; they go through the same import path.
            </p>
          </>
        ) : (
          <>
            <div className="space-y-1">
              <label className="text-xs text-[var(--color-text-muted)]">
                PKCS#12 file
              </label>
              <input
                type="file"
                accept=".p12,.pfx,application/x-pkcs12"
                onChange={onFile}
                className="block text-sm w-full"
              />
              {pkcs12Name && (
                <div className="text-xs text-[var(--color-text-muted)]">
                  Selected: <code>{pkcs12Name}</code>
                </div>
              )}
            </div>
            <Input
              label="Passphrase"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Leave blank for password-less containers"
            />
            <p className="text-xs text-[var(--color-text-muted)]">
              The container is unwrapped locally inside the Tauri process —
              the passphrase is not sent over the network. Encrypted private
              keys are re-emitted as unencrypted PKCS#8 before being handed
              to the engine, which seals them with the mount's barrier.
            </p>
          </>
        )}
      </div>
    </Modal>
  );
}

// ── Roles Tab ─────────────────────────────────────────────────────

function RolesTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [config, setConfig] = useState<PkiRoleConfig | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [draft, setDraft] = useState<PkiRoleConfig>(defaultRoleConfig());
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const list = await api.pkiListRoles(mount);
      setRoles(list);
      if (selected && !list.includes(selected)) setSelected(null);
      if (selected && list.includes(selected)) {
        const c = await api.pkiReadRole(mount, selected);
        setConfig(c);
      }
    } catch (e) {
      toast("error", extractError(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount, selected]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function selectRole(name: string) {
    try {
      const c = await api.pkiReadRole(mount, name);
      setSelected(name);
      setConfig(c);
      setEditing(false);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newName.trim()) return;
    const ttlError = validateDurationField("TTL", draft.ttl);
    if (ttlError) {
      toast("error", ttlError);
      return;
    }
    const maxTtlError = validateDurationField("Max TTL", draft.max_ttl);
    if (maxTtlError) {
      toast("error", maxTtlError);
      return;
    }
    try {
      await api.pkiWriteRole(mount, newName.trim(), draft);
      toast("success", `Role ${newName} created`);
      setShowCreate(false);
      setNewName("");
      setDraft(defaultRoleConfig());
      await refresh();
      const created = newName.trim();
      setSelected(created);
      const c = await api.pkiReadRole(mount, created);
      setConfig(c);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleSaveEdit() {
    if (!selected || !config) return;
    const ttlError = validateDurationField("TTL", config.ttl);
    if (ttlError) {
      toast("error", ttlError);
      return;
    }
    const maxTtlError = validateDurationField("Max TTL", config.max_ttl);
    if (maxTtlError) {
      toast("error", maxTtlError);
      return;
    }
    try {
      await api.pkiWriteRole(mount, selected, config);
      toast("success", "Role updated");
      setEditing(false);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.pkiDeleteRole(mount, deleteTarget);
      toast("success", `Role ${deleteTarget} deleted`);
      setDeleteTarget(null);
      if (selected === deleteTarget) {
        setSelected(null);
        setConfig(null);
      }
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card title="Roles" actions={<Button onClick={() => setShowCreate(true)}>+ Create role</Button>}>
      {roles.length === 0 ? (
        <EmptyState
          title="No roles configured"
          description="Create a role to define which CN, SANs, and TTLs are allowed when issuing certificates."
          action={<Button onClick={() => setShowCreate(true)}>Create role</Button>}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-1">
            {roles.map((r) => (
              <button
                key={r}
                onClick={() => selectRole(r)}
                className={`block w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  selected === r
                    ? "bg-[var(--color-surface-hover)] font-semibold"
                    : "hover:bg-[var(--color-surface-hover)]"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          <div className="lg:col-span-2 min-w-0">
            {config ? (
              <RoleEditor
                config={config}
                editing={editing}
                onChange={setConfig}
                onEdit={() => setEditing(true)}
                onSave={handleSaveEdit}
                onCancel={() => {
                  setEditing(false);
                  if (selected) selectRole(selected);
                }}
                onDelete={() => selected && setDeleteTarget(selected)}
              />
            ) : (
              <p className="text-sm text-[var(--color-text-muted)]">
                Select a role to view its configuration.
              </p>
            )}
          </div>
        </div>
      )}

      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title="Create role"
        size="lg"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={!newName.trim()}>
              Create
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input
            label="Role name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="web-server"
            autoFocus
          />
          <RoleEditor config={draft} editing={true} onChange={setDraft} compact />
        </div>
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete role?"
        message={`Delete role "${deleteTarget}"? Existing certs issued under this role keep working until they expire or are revoked.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </Card>
  );
}

function RoleEditor({
  config,
  editing,
  onChange,
  onEdit,
  onSave,
  onCancel,
  onDelete,
  compact,
}: {
  config: PkiRoleConfig;
  editing: boolean;
  onChange: (c: PkiRoleConfig) => void;
  onEdit?: () => void;
  onSave?: () => void;
  onCancel?: () => void;
  onDelete?: () => void;
  compact?: boolean;
}) {
  const set = (patch: Partial<PkiRoleConfig>) => onChange({ ...config, ...patch });

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="TTL"
          value={config.ttl}
          onChange={(e) => set({ ttl: e.target.value })}
          disabled={!editing}
          placeholder="720h"
        />
        <Input
          label="Max TTL"
          value={config.max_ttl}
          onChange={(e) => set({ max_ttl: e.target.value })}
          disabled={!editing}
          placeholder="2160h"
        />
        <Select
          label="Key type"
          value={config.key_type}
          onChange={(e) => set({ key_type: e.target.value })}
          disabled={!editing}
          options={KEY_TYPE_OPTIONS}
        />
        <Input
          label="Key bits (0 = default)"
          type="number"
          value={config.key_bits}
          onChange={(e) => set({ key_bits: Number(e.target.value) })}
          disabled={!editing}
        />
        <Input
          label="Issuer ref (empty = mount default)"
          value={config.issuer_ref}
          onChange={(e) => set({ issuer_ref: e.target.value })}
          disabled={!editing}
          placeholder="default | uuid"
        />
        <Input
          label="Organization"
          value={config.organization}
          onChange={(e) => set({ organization: e.target.value })}
          disabled={!editing}
        />
      </div>

      {!compact && (
        <div className="grid grid-cols-2 gap-2">
          <Toggle
            label="allow_any_name"
            checked={config.allow_any_name}
            onChange={(b) => set({ allow_any_name: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_localhost"
            checked={config.allow_localhost}
            onChange={(b) => set({ allow_localhost: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_subdomains"
            checked={config.allow_subdomains}
            onChange={(b) => set({ allow_subdomains: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_bare_domains"
            checked={config.allow_bare_domains}
            onChange={(b) => set({ allow_bare_domains: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_ip_sans"
            checked={config.allow_ip_sans}
            onChange={(b) => set({ allow_ip_sans: b })}
            disabled={!editing}
          />
          <Toggle
            label="server_flag (ServerAuth EKU)"
            checked={config.server_flag}
            onChange={(b) => set({ server_flag: b })}
            disabled={!editing}
          />
          <Toggle
            label="client_flag (ClientAuth EKU)"
            checked={config.client_flag}
            onChange={(b) => set({ client_flag: b })}
            disabled={!editing}
          />
          <Toggle
            label="no_store"
            checked={config.no_store}
            onChange={(b) => set({ no_store: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_glob_domains"
            checked={config.allow_glob_domains}
            onChange={(b) => set({ allow_glob_domains: b })}
            disabled={!editing}
          />
          <Toggle
            label="acme_enabled"
            checked={config.acme_enabled}
            onChange={(b) => set({ acme_enabled: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_key_reuse"
            checked={config.allow_key_reuse}
            onChange={(b) => set({ allow_key_reuse: b })}
            disabled={!editing}
          />
        </div>
      )}

      {!compact && (
        <div className="grid grid-cols-1 gap-3">
          <Input
            label="allowed_domains (comma-separated)"
            value={config.allowed_domains.join(",")}
            onChange={(e) =>
              set({
                allowed_domains: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter((s) => s.length > 0),
              })
            }
            disabled={!editing}
            placeholder="example.com,*.svc.cluster.local"
          />
          <Input
            label="allowed_key_refs (comma-separated; needs allow_key_reuse)"
            value={config.allowed_key_refs.join(",")}
            onChange={(e) =>
              set({
                allowed_key_refs: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter((s) => s.length > 0),
              })
            }
            disabled={!editing || !config.allow_key_reuse}
            placeholder="key-name | uuid"
          />
        </div>
      )}

      {!compact && (onEdit || onSave) && (
        <div className="flex gap-2 justify-end">
          {editing ? (
            <>
              <Button variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
              <Button onClick={onSave}>Save</Button>
            </>
          ) : (
            <>
              {onDelete && (
                <Button variant="ghost" onClick={onDelete}>
                  Delete
                </Button>
              )}
              <Button onClick={onEdit}>Edit</Button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (b: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
      />
      <code className="text-xs">{label}</code>
    </label>
  );
}

// ── Issue Tab ────────────────────────────────────────────────────

// ── Keys tab — managed key store (Phase L1 + reuse from L2/L3) ────

function KeysTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [ids, setIds] = useState<string[]>([]);
  const [details, setDetails] = useState<Record<string, PkiManagedKey>>({});
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [showExportedKey, setShowExportedKey] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{
    id: string;
    name: string;
    issuerRefs: number;
    certRefs: number;
  } | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.pkiListKeys(mount);
      setIds(list);
      const map: Record<string, PkiManagedKey> = {};
      for (const id of list) {
        try {
          map[id] = await api.pkiReadKey(mount, id);
        } catch {
          /* skip rows that fail to read */
        }
      }
      setDetails(map);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }, [mount, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function deleteKey(id: string, force: boolean) {
    try {
      await api.pkiDeleteKey(mount, id, force);
      toast("success", force ? "Key force-deleted" : "Key deleted");
      await reload();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card title="Managed keys">
      <div className="flex justify-between items-center mb-3">
        <div className="text-sm text-[var(--color-text-muted)]">
          Generate or import private keys, then pin them on root /
          intermediate generation or on issue / sign with{" "}
          <code>key_ref</code>.
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => setShowImport(true)}>
            Import
          </Button>
          <Button onClick={() => setShowCreate(true)}>Generate</Button>
        </div>
      </div>
      {loading ? (
        <div className="text-sm text-[var(--color-text-muted)]">Loading…</div>
      ) : ids.length === 0 ? (
        <EmptyState
          title="No managed keys"
          description="Generate one or import a PEM-encoded private key."
        />
      ) : (
        <Table<{ id: string }>
          columns={[
            {
              key: "name",
              header: "Name",
              render: ({ id }) => (
                <span className="text-sm">{details[id]?.name || "—"}</span>
              ),
            },
            {
              key: "id",
              header: "ID",
              render: ({ id }) => (
                <code className="text-xs break-all">{id}</code>
              ),
            },
            {
              key: "alg",
              header: "Algorithm",
              render: ({ id }) => {
                const k = details[id];
                return (
                  <span className="text-sm">
                    {k
                      ? `${k.key_type}${k.key_bits > 0 ? `-${k.key_bits}` : ""}`
                      : "?"}
                  </span>
                );
              },
            },
            {
              key: "source",
              header: "Source",
              render: ({ id }) => (
                <Badge
                  label={details[id]?.source || "?"}
                  variant={details[id]?.source === "imported" ? "warning" : "neutral"}
                />
              ),
            },
            {
              key: "issuers",
              header: "Issuers",
              render: ({ id }) => (
                <span className="text-sm">
                  {details[id]?.issuer_ref_count ?? 0}
                </span>
              ),
            },
            {
              key: "certs",
              header: "Certs",
              render: ({ id }) => (
                <span className="text-sm">
                  {details[id]?.cert_ref_count ?? 0}
                </span>
              ),
            },
            {
              key: "actions",
              header: "",
              render: ({ id }) => {
                const k = details[id];
                return (
                  <Button
                    variant="ghost"
                    onClick={() =>
                      setConfirmDelete({
                        id,
                        name: k?.name || id,
                        issuerRefs: k?.issuer_ref_count ?? 0,
                        certRefs: k?.cert_ref_count ?? 0,
                      })
                    }
                    disabled={!k}
                  >
                    Delete
                  </Button>
                );
              },
            },
          ]}
          data={ids.map((id) => ({ id }))}
          rowKey={(r) => r.id}
        />
      )}
      <GenerateKeyModal
        open={showCreate}
        mount={mount}
        onClose={() => setShowCreate(false)}
        onGenerated={(pkcs8) => {
          void reload();
          if (pkcs8) setShowExportedKey(pkcs8);
        }}
      />
      <ImportKeyModal
        open={showImport}
        mount={mount}
        onClose={() => setShowImport(false)}
        onImported={() => {
          setShowImport(false);
          void reload();
        }}
      />
      {showExportedKey && (
        <Modal
          open
          onClose={() => setShowExportedKey(null)}
          title="Generated key (exported mode)"
          size="lg"
        >
          <div className="space-y-3">
            <div className="text-sm text-[var(--color-text-muted)]">
              The engine returns the PKCS#8 PEM exactly once. Save it
              now if you need to deliver it to a consumer; the engine
              keeps a copy under the barrier so future renewals can
              reuse it via <code>key_ref</code>.
            </div>
            <Textarea
              label="Private key"
              value={showExportedKey}
              readOnly
              rows={14}
            />
            <div className="flex justify-end gap-2">
              <Button
                variant="ghost"
                onClick={() => {
                  navigator.clipboard.writeText(showExportedKey);
                  toast("success", "Private key copied");
                }}
              >
                Copy
              </Button>
              <Button onClick={() => setShowExportedKey(null)}>Close</Button>
            </div>
          </div>
        </Modal>
      )}
      <ConfirmModal
        open={confirmDelete !== null}
        onClose={() => setConfirmDelete(null)}
        onConfirm={async () => {
          if (!confirmDelete) return;
          const { id, issuerRefs, certRefs } = confirmDelete;
          const force = issuerRefs > 0 || certRefs > 0;
          setConfirmDelete(null);
          await deleteKey(id, force);
        }}
        title={
          confirmDelete && (confirmDelete.issuerRefs > 0 || confirmDelete.certRefs > 0)
            ? "Force-delete managed key"
            : "Delete managed key"
        }
        message={
          confirmDelete
            ? confirmDelete.issuerRefs > 0 || confirmDelete.certRefs > 0
              ? `Key \`${confirmDelete.name}\` is bound to ${confirmDelete.issuerRefs} issuer(s) and ${confirmDelete.certRefs} cert(s). ` +
                `Each bound issuer keeps its own private-key copy at issuers/<id>/key, so the issuer keeps signing — ` +
                `but the audit trail linking this managed-key entry to those issuers and certs is dropped. Continue?`
              : `Delete key \`${confirmDelete.name}\`?`
            : ""
        }
        confirmLabel={
          confirmDelete && (confirmDelete.issuerRefs > 0 || confirmDelete.certRefs > 0)
            ? "Force delete"
            : "Delete"
        }
        variant="danger"
      />
    </Card>
  );
}

function GenerateKeyModal({
  open,
  mount,
  onClose,
  onGenerated,
}: {
  open: boolean;
  mount: string;
  onClose: () => void;
  onGenerated: (pkcs8: string | null) => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [keyType, setKeyType] = useState("ec");
  const [keyBits, setKeyBits] = useState(0);
  const [mode, setMode] = useState<"internal" | "exported">("internal");
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    try {
      const r = await api.pkiGenerateKey({
        mount,
        mode,
        key_type: keyType,
        key_bits: keyBits || undefined,
        name: name.trim() || undefined,
      });
      toast("success", `Key ${r.key_id} generated`);
      onGenerated(r.private_key ?? null);
      onClose();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Generate managed key" size="md">
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="Name (optional)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="svc-key"
        />
        <Select
          label="Mode"
          value={mode}
          onChange={(e) => setMode(e.target.value as "internal" | "exported")}
          options={[
            { value: "internal", label: "internal (private not echoed)" },
            { value: "exported", label: "exported (PKCS#8 returned once)" },
          ]}
        />
        <Select
          label="Key type"
          value={keyType}
          onChange={(e) => setKeyType(e.target.value)}
          options={KEY_TYPE_OPTIONS}
        />
        <Input
          label="Key bits (0 = default)"
          type="number"
          value={keyBits}
          onChange={(e) => setKeyBits(Number(e.target.value))}
        />
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button onClick={submit} disabled={busy}>
          {busy ? "Generating…" : "Generate"}
        </Button>
      </div>
    </Modal>
  );
}

function ImportKeyModal({
  open,
  mount,
  onClose,
  onImported,
}: {
  open: boolean;
  mount: string;
  onClose: () => void;
  onImported: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!pem.trim()) return;
    setBusy(true);
    try {
      const r = await api.pkiImportKey({
        mount,
        private_key: pem.trim(),
        name: name.trim() || undefined,
      });
      toast("success", `Key ${r.key_id} imported`);
      onImported();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Import managed key" size="lg">
      <div className="space-y-3">
        <Input
          label="Name (optional)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="svc-key"
        />
        <Textarea
          label="Private key (PEM)"
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          rows={12}
          placeholder="-----BEGIN PRIVATE KEY-----"
        />
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button onClick={submit} disabled={busy || !pem.trim()}>
          {busy ? "Importing…" : "Import"}
        </Button>
      </div>
    </Modal>
  );
}

function IssueTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [role, setRole] = useState("");
  const [commonName, setCommonName] = useState("");
  const [altNames, setAltNames] = useState("");
  const [ipSans, setIpSans] = useState("");
  const [ttl, setTtl] = useState("");
  const [issuerRef, setIssuerRef] = useState("");
  const [keyRef, setKeyRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PkiIssueResult | null>(null);

  useEffect(() => {
    api
      .pkiListRoles(mount)
      .then((list) => {
        setRoles(list);
        if (list.length > 0 && !role) setRole(list[0]);
      })
      .catch((e) => toast("error", extractError(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  async function submit() {
    if (!role || !commonName.trim()) return;
    setBusy(true);
    try {
      const r = await api.pkiIssueCert({
        mount,
        role,
        common_name: commonName.trim(),
        alt_names: altNames.trim() || undefined,
        ip_sans: ipSans.trim() || undefined,
        ttl: ttl.trim() || undefined,
        issuer_ref: issuerRef.trim() || undefined,
        key_ref: keyRef.trim() || undefined,
      });
      setResult(r);
      toast("success", `Certificate issued (serial ${r.serial_number})`);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  function copy(text: string, label: string) {
    navigator.clipboard.writeText(text).then(
      () => toast("success", `${label} copied`),
      () => toast("error", `Failed to copy ${label}`),
    );
  }

  if (roles.length === 0) {
    return (
      <Card>
        <EmptyState
          title="No roles configured"
          description="Create a role on the Roles tab before issuing a certificate."
        />
      </Card>
    );
  }

  return (
    <Card title="Issue a certificate">
      <div className="grid grid-cols-2 gap-3">
        <Select
          label="Role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          options={roles.map((r) => ({ value: r, label: r }))}
        />
        <Input
          label="Common Name"
          value={commonName}
          onChange={(e) => setCommonName(e.target.value)}
          placeholder="api.example.com"
        />
        <Input
          label="DNS / IP SANs (comma-separated)"
          value={altNames}
          onChange={(e) => setAltNames(e.target.value)}
          placeholder="api-alt.example.com, 127.0.0.1"
        />
        <Input
          label="Extra IP SANs (comma-separated)"
          value={ipSans}
          onChange={(e) => setIpSans(e.target.value)}
        />
        <Input
          label="TTL (optional)"
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          placeholder="720h"
        />
        <Input
          label="Issuer override (optional)"
          value={issuerRef}
          onChange={(e) => setIssuerRef(e.target.value)}
          placeholder="default | uuid"
        />
        <Input
          label="Pin managed key (optional, requires role.allow_key_reuse)"
          value={keyRef}
          onChange={(e) => setKeyRef(e.target.value)}
          placeholder="key-name | uuid"
        />
      </div>
      <div className="mt-4">
        <Button onClick={submit} disabled={busy || !role || !commonName.trim()}>
          {busy ? "Issuing…" : "Issue"}
        </Button>
      </div>

      {result && (
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge label="issued" variant="success" />
            <code className="text-sm break-all">{result.serial_number}</code>
            <span className="text-xs text-[var(--color-text-muted)]">
              issuer {result.issuer_id}
            </span>
            {result.key_id && (
              <span className="text-xs text-[var(--color-text-muted)]">
                key {result.key_id}
              </span>
            )}
            {result.ca_chain && result.ca_chain.length > 1 && (
              <span className="text-xs text-[var(--color-text-muted)]">
                chain depth {result.ca_chain.length}
              </span>
            )}
          </div>
          <PemBlock
            label="Certificate"
            value={result.certificate}
            onCopy={() => copy(result.certificate, "certificate")}
          />
          <PemBlock
            label="Private key (PKCS#8)"
            value={result.private_key}
            onCopy={() => copy(result.private_key, "private key")}
          />
          <PemBlock
            label="Issuing CA"
            value={result.issuing_ca}
            onCopy={() => copy(result.issuing_ca, "issuing CA")}
          />
        </div>
      )}
    </Card>
  );
}

function PemBlock({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: () => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium text-[var(--color-text-muted)]">{label}</span>
        <Button variant="ghost" onClick={onCopy}>
          Copy
        </Button>
      </div>
      <Textarea label="" value={value} readOnly rows={6} className="font-mono text-xs" />
    </div>
  );
}

// ── Certificates Tab ──────────────────────────────────────────────

interface CertSummary {
  serial: string;
  common_name: string;
  not_after: number;
  revoked_at: number | null;
  is_orphaned: boolean;
  source: string;
  /** UUID of the signing issuer when known (engine-issued certs and
   *  intermediates imported via `pki/config/ca`). Empty for orphan
   *  imports — the engine has no record of who signed those. */
  issuer_id: string;
  /** Issuer DN parsed from the cert PEM. Always populated; used as
   *  the Emitter cell text. */
  issuer_dn: string;
}

/** Right-pane detail view for a selected cert. Renders the structured
 *  fields the operator needs at a glance (Status / Emitter / Expires /
 *  Source / Key Usages / EKU / SANs) and keeps the full PEM block in a
 *  scrollable section below. Designed to fit a 1/3-width column. */
function CertDetail({
  serial,
  cert,
  summary,
  issuerName,
  onRevoke,
  onDelete,
  onCopyPem,
}: {
  serial: string;
  cert: PkiCertRecord;
  summary: CertSummary | null;
  issuerName: string;
  onRevoke: () => void;
  onDelete: () => void;
  onCopyPem: () => void;
}) {
  const expired = cert.not_after > 0 && cert.not_after * 1000 < Date.now();
  const emitterText = issuerName
    ? issuerName
    : summary?.issuer_dn
      ? extractCn(summary.issuer_dn) || summary.issuer_dn
      : "external";
  const emitterIcon = issuerName ? "🔒" : "🌐";

  const sanRows: Array<[string, string[]]> = [
    ["DNS", cert.san_dns ?? []],
    ["IP", cert.san_ip ?? []],
    ["Email", cert.san_email ?? []],
    ["URI", cert.san_uri ?? []],
  ].filter(([, v]) => v.length > 0) as Array<[string, string[]]>;

  return (
    <div className="space-y-3 min-w-0">
      <div className="flex items-center gap-2 flex-wrap">
        <code className="text-xs break-all">{serial}</code>
        {cert.revoked_at ? (
          <Badge label={`revoked ${fmtUnix(cert.revoked_at)}`} variant="error" />
        ) : expired ? (
          <Badge label="expired" variant="warning" />
        ) : (
          <Badge label="active" variant="success" />
        )}
      </div>

      <Field
        label="Common Name"
        value={cert.common_name || "—"}
      />
      <div className="space-y-1">
        <div className="text-xs text-[var(--color-text-muted)]">Emitter</div>
        <div className="flex items-center gap-1 min-w-0 text-sm" title={summary?.issuer_dn || ""}>
          <span aria-hidden>{emitterIcon}</span>
          <span className="truncate">{emitterText}</span>
        </div>
      </div>
      <Field label="Issued at" value={fmtUnix(cert.issued_at)} />
      <Field
        label="Expires"
        value={cert.not_after ? fmtUnix(cert.not_after) : "—"}
      />
      {cert.is_orphaned && (
        <Field
          label="Source"
          value={cert.source ? `orphan (${cert.source})` : "orphan"}
        />
      )}

      {(cert.key_usages?.length ?? 0) > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-[var(--color-text-muted)]">Key usages</div>
          <div className="flex flex-wrap gap-1">
            {cert.key_usages!.map((u) => (
              <Badge key={`ku-${u}`} label={u} variant="neutral" />
            ))}
          </div>
        </div>
      )}
      {(cert.ext_key_usages?.length ?? 0) > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-[var(--color-text-muted)]">Extended key usages</div>
          <div className="flex flex-wrap gap-1">
            {cert.ext_key_usages!.map((u) => (
              <Badge key={`eku-${u}`} label={u} variant="neutral" />
            ))}
          </div>
        </div>
      )}

      {sanRows.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-[var(--color-text-muted)]">
            Subject alternative names
          </div>
          <div className="space-y-1">
            {sanRows.map(([kind, values]) => (
              <div key={`san-${kind}`} className="text-xs flex gap-2 min-w-0">
                <span className="text-[var(--color-text-muted)] w-12 shrink-0">{kind}</span>
                <div className="flex flex-wrap gap-1 min-w-0">
                  {values.map((v) => (
                    <code
                      key={`${kind}-${v}`}
                      className="font-mono text-[11px] break-all"
                      title={v}
                    >
                      {v}
                    </code>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <PemBlock
        label="Certificate (PEM)"
        value={cert.certificate}
        onCopy={onCopyPem}
      />
      <div className="flex items-center gap-2 flex-wrap">
        {!cert.revoked_at && (
          <Button variant="ghost" onClick={onRevoke}>
            Revoke
          </Button>
        )}
        <Button variant="ghost" onClick={onDelete}>
          Delete
        </Button>
      </div>
    </div>
  );
}

function CertsTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [summaries, setSummaries] = useState<CertSummary[]>([]);
  /** issuer UUID → human-readable name, used for the Emitter column.
   *  Loaded once per refresh alongside the cert list so the column
   *  can render names instead of UUIDs (and so an unknown issuer_id
   *  signals "external" — i.e. an orphan-imported cert). */
  const [issuerNames, setIssuerNames] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [cert, setCert] = useState<PkiCertRecord | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    serial: string;
    active: boolean;
  } | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      // Load issuers + cert list in parallel. We use the issuers map
      // to label engine-owned emitters in the table.
      const [issuers, list] = await Promise.all([
        api.pkiListIssuers(mount).catch(() => null),
        api.pkiListCerts(mount),
      ]);
      const nameMap: Record<string, string> = {};
      if (issuers) {
        for (const it of issuers.issuers ?? []) {
          nameMap[it.id] = it.name || it.id;
        }
      }
      setIssuerNames(nameMap);

      const sorted = [...list].sort();
      // Fetch each cert's metadata in parallel. Each `pkiReadCert`
      // call returns CN + not_after parsed server-side from the PEM,
      // so the list view can show identity + expiration without the
      // user having to click into each row.
      const records = await Promise.all(
        sorted.map(async (s) => {
          try {
            const c = await api.pkiReadCert(mount, s);
            return {
              serial: s,
              common_name: c.common_name || "",
              not_after: c.not_after || 0,
              revoked_at: c.revoked_at ?? null,
              is_orphaned: c.is_orphaned ?? false,
              source: c.source ?? "",
              issuer_id: c.issuer_id ?? "",
              issuer_dn: c.issuer_dn ?? "",
            } satisfies CertSummary;
          } catch {
            // A single read failure shouldn't blank the whole list —
            // surface the serial with empty meta so the operator can
            // still drill in to investigate.
            return {
              serial: s,
              common_name: "",
              not_after: 0,
              revoked_at: null,
              is_orphaned: false,
              source: "",
              issuer_id: "",
              issuer_dn: "",
            };
          }
        }),
      );
      setSummaries(records);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function selectSerial(serial: string) {
    try {
      const c = await api.pkiReadCert(mount, serial);
      setSelected(serial);
      setCert(c);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleRevoke() {
    if (!revokeTarget) return;
    try {
      await api.pkiRevokeCert(mount, revokeTarget);
      toast("success", `Certificate ${revokeTarget} revoked`);
      setRevokeTarget(null);
      if (selected === revokeTarget) await selectSerial(revokeTarget);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleDeleteCert() {
    if (!deleteTarget) return;
    const { serial, active } = deleteTarget;
    try {
      await api.pkiDeleteCert(mount, serial, active);
      toast("success", `Certificate ${serial} deleted`);
      setDeleteTarget(null);
      if (selected === serial) {
        setSelected(null);
        setCert(null);
      }
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function rotateCrl() {
    try {
      const r = await api.pkiRotateCrl(mount);
      toast("success", `CRL rotated (number ${r.crl_number})`);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  const filtered = filter
    ? summaries.filter((s) => {
        const f = filter.toLowerCase();
        return (
          s.serial.toLowerCase().includes(f) ||
          s.common_name.toLowerCase().includes(f)
        );
      })
    : summaries;

  return (
    <Card
      title="Issued certificates"
      actions={
        <>
          <Input
            label=""
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter…"
            className="w-48"
          />
          <Button variant="ghost" onClick={refresh}>
            Refresh
          </Button>
          <Button variant="ghost" onClick={rotateCrl}>
            Rotate CRL
          </Button>
        </>
      }
    >
      {summaries.length === 0 && !loading ? (
        <EmptyState
          title="No certificates issued yet"
          description="Issued certificates appear here. Roles with `no_store = true` skip persistence."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 max-h-[32rem] overflow-auto min-w-0">
            <Table<CertSummary>
              tableClassName="table-fixed"
              columns={[
                {
                  key: "serial",
                  header: "Serial",
                  className: "w-[35%]",
                  render: (s) => (
                    <button
                      onClick={() => selectSerial(s.serial)}
                      className={`text-left w-full block min-w-0 ${
                        selected === s.serial
                          ? "font-semibold text-[var(--color-primary)]"
                          : ""
                      }`}
                      title={s.serial}
                    >
                      <div className="font-mono text-xs truncate">{s.serial}</div>
                    </button>
                  ),
                },
                {
                  key: "common_name",
                  header: "Common Name",
                  className: "w-[25%]",
                  render: (s) => (
                    <button
                      onClick={() => selectSerial(s.serial)}
                      className={`text-left w-full block min-w-0 ${
                        selected === s.serial
                          ? "font-semibold text-[var(--color-primary)]"
                          : ""
                      }`}
                      title={
                        s.is_orphaned
                          ? `${s.common_name || "—"}\nOrphan cert${s.source ? ` (source: ${s.source})` : ""}`
                          : s.common_name
                      }
                    >
                      <div className="text-xs truncate flex items-center gap-1 min-w-0">
                        <span className="truncate min-w-0">{s.common_name || "—"}</span>
                        {s.is_orphaned && (
                          <Badge variant="warning" label="orphan" />
                        )}
                      </div>
                    </button>
                  ),
                },
                {
                  key: "emitter",
                  header: "Emitter",
                  className: "w-[25%]",
                  render: (s) => {
                    // Engine-owned emitter: cert's `issuer_id` resolves
                    // to a known issuer on this mount → render the
                    // issuer name and a green "owned" badge with a
                    // lock glyph. Anything else (orphan import,
                    // unknown issuer_id, no issuer recorded) is
                    // surfaced as "external" with the cert's Issuer
                    // DN as the label.
                    const ownedName =
                      s.issuer_id && issuerNames[s.issuer_id];
                    if (ownedName) {
                      return (
                        <div
                          className="flex items-center gap-1 min-w-0"
                          title={`Owned issuer (id ${s.issuer_id})\n${s.issuer_dn || ""}`}
                        >
                          <span aria-label="owned" title="Owned by this PKI mount">🔒</span>
                          <span className="text-xs truncate">{ownedName}</span>
                        </div>
                      );
                    }
                    return (
                      <div
                        className="flex items-center gap-1 min-w-0"
                        title={s.issuer_dn || "External CA"}
                      >
                        <span aria-label="external" title="External CA — not on this mount">🌐</span>
                        <span className="text-xs truncate text-[var(--color-text-muted)]">
                          {s.issuer_dn
                            ? extractCn(s.issuer_dn) || s.issuer_dn
                            : "external"}
                        </span>
                      </div>
                    );
                  },
                },
                {
                  key: "expires",
                  header: "Expires",
                  className: "w-[15%]",
                  render: (s) => {
                    if (s.revoked_at) {
                      return (
                        <span className="text-xs text-[var(--color-danger)]">
                          revoked
                        </span>
                      );
                    }
                    if (!s.not_after) return <span className="text-xs">—</span>;
                    const expired = s.not_after * 1000 < Date.now();
                    return (
                      <span
                        className={`text-xs ${
                          expired ? "text-[var(--color-danger)]" : ""
                        }`}
                        title={fmtUnix(s.not_after)}
                      >
                        {fmtUnix(s.not_after).slice(0, 10)}
                        {expired ? " (expired)" : ""}
                      </span>
                    );
                  },
                },
              ]}
              data={filtered}
              rowKey={(r) => r.serial}
              emptyMessage={loading ? "Loading…" : "No matching serials"}
            />
          </div>
          {cert && selected && (
            <CertDetail
              serial={selected}
              cert={cert}
              summary={summaries.find((s) => s.serial === selected) ?? null}
              issuerName={(() => {
                const summary = summaries.find((s) => s.serial === selected);
                if (!summary) return "";
                return summary.issuer_id && issuerNames[summary.issuer_id]
                  ? issuerNames[summary.issuer_id]
                  : "";
              })()}
              onRevoke={() => setRevokeTarget(selected)}
              onDelete={() =>
                setDeleteTarget({
                  serial: selected,
                  active: !cert.revoked_at,
                })
              }
              onCopyPem={() =>
                navigator.clipboard.writeText(cert.certificate).then(
                  () => toast("success", "certificate copied"),
                  () => toast("error", "Failed to copy"),
                )
              }
            />
          )}
        </div>
      )}

      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
        title="Revoke certificate?"
        message={`Revoke ${revokeTarget}? The CRL will rebuild immediately.`}
        confirmLabel="Revoke"
        variant="danger"
      />
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteCert}
        title={
          deleteTarget?.active ? "Force-delete active certificate?" : "Delete certificate?"
        }
        message={
          deleteTarget
            ? deleteTarget.active
              ? `Serial ${deleteTarget.serial} is still active (not revoked, not expired). ` +
                `Deleting drops the cert record from this mount but does NOT revoke it — relying parties may still trust it until it expires. ` +
                `Prefer Revoke unless you know what you're doing.`
              : `Delete the cert record for ${deleteTarget.serial}? Any matching CRL entry will be pulled and the CRL rebuilt.`
            : ""
        }
        confirmLabel={deleteTarget?.active ? "Force delete" : "Delete"}
        variant="danger"
      />
    </Card>
  );
}

// ── Tidy Tab ──────────────────────────────────────────────────────

function TidyTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [status, setStatus] = useState<PkiTidyStatus | null>(null);
  const [autoTidy, setAutoTidy] = useState<PkiAutoTidyConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [safetyBuffer, setSafetyBuffer] = useState("72h");
  const [tidyCertStore, setTidyCertStore] = useState(true);
  const [tidyRevoked, setTidyRevoked] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([
        api.pkiReadTidyStatus(mount),
        api.pkiReadAutoTidy(mount),
      ]);
      setStatus(s);
      setAutoTidy(a);
    } catch (e) {
      toast("error", extractError(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function runTidy() {
    setBusy(true);
    try {
      const r = await api.pkiRunTidy({
        mount,
        tidy_cert_store: tidyCertStore,
        tidy_revoked_certs: tidyRevoked,
        safety_buffer: safetyBuffer,
      });
      toast(
        "success",
        `Tidy: ${r.certs_deleted} certs, ${r.revoked_entries_deleted} revoked entries removed (${r.duration_ms}ms)`,
      );
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveAutoTidy() {
    if (!autoTidy) return;
    try {
      await api.pkiWriteAutoTidy(mount, autoTidy);
      toast("success", "Auto-tidy configuration saved");
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <div className="space-y-4">
      <Card title="Run tidy on demand">
        <div className="grid grid-cols-2 gap-3 mb-3">
          <Input
            label="Safety buffer"
            value={safetyBuffer}
            onChange={(e) => setSafetyBuffer(e.target.value)}
            placeholder="72h"
          />
          <div className="flex items-end gap-3">
            <Toggle label="cert_store" checked={tidyCertStore} onChange={setTidyCertStore} />
            <Toggle label="revoked_certs" checked={tidyRevoked} onChange={setTidyRevoked} />
          </div>
        </div>
        <Button onClick={runTidy} disabled={busy}>
          {busy ? "Running…" : "Run tidy"}
        </Button>
      </Card>

      <Card title="Last tidy run">
        {status && status.last_run_at_unix > 0 ? (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Last run at" value={fmtUnix(status.last_run_at_unix)} />
            <Field label="Source" value={status.source} />
            <Field label="Certs deleted" value={String(status.certs_deleted)} />
            <Field
              label="Revoked entries deleted"
              value={String(status.revoked_entries_deleted)}
            />
            <Field label="Duration (ms)" value={String(status.last_run_duration_ms)} />
            <Field label="Safety buffer (s)" value={String(status.safety_buffer_seconds)} />
          </div>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            Tidy has not run yet on this mount.
          </p>
        )}
      </Card>

      <Card
        title="Auto-tidy"
        actions={autoTidy ? <Button onClick={saveAutoTidy}>Save</Button> : null}
      >
        {autoTidy && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Interval"
                value={autoTidy.interval}
                onChange={(e) => setAutoTidy({ ...autoTidy, interval: e.target.value })}
                placeholder="12h"
              />
              <Input
                label="Safety buffer"
                value={autoTidy.safety_buffer}
                onChange={(e) =>
                  setAutoTidy({ ...autoTidy, safety_buffer: e.target.value })
                }
                placeholder="72h"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 mt-3">
              <Toggle
                label="enabled"
                checked={autoTidy.enabled}
                onChange={(b) => setAutoTidy({ ...autoTidy, enabled: b })}
              />
              <Toggle
                label="tidy_cert_store"
                checked={autoTidy.tidy_cert_store}
                onChange={(b) => setAutoTidy({ ...autoTidy, tidy_cert_store: b })}
              />
              <Toggle
                label="tidy_revoked_certs"
                checked={autoTidy.tidy_revoked_certs}
                onChange={(b) => setAutoTidy({ ...autoTidy, tidy_revoked_certs: b })}
              />
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

// ── Shared atom ───────────────────────────────────────────────────

// ── Import XCA Tab (gated on the `xca-import` plugin being registered) ──

interface XcaPreviewItem {
  meta: {
    id: number;
    item_type:
      | "private_key"
      | "cert"
      | "request"
      | "crl"
      | "template"
      | "public_key"
      | "authority"
      | "other";
    parent: number;
    name: string;
    comment: string;
  };
  pem: string | null;
  subject?: string;
  serial_hex?: string;
  not_after_unix?: number | null;
  decrypt:
    | "not_encrypted"
    | "ok"
    | "missing_password"
    | "wrong_password"
    | "unsupported";
  has_own_pass: boolean;
  /** `items.id` of the cert/key counterpart matched by the plugin
   * via public-key fingerprint. Plugin v0.1.5+. */
  paired_item_id?: number | null;
  /** Cert only: BasicConstraints `cA=true` (or XCA's `certs.ca` flag).
   * Plugin v0.1.7+; absent on older plugins, in which case the GUI
   * treats the cert as a CA candidate to preserve old behavior. */
  is_ca?: boolean;
  /** Cert only (plugin v0.1.9+): true when the cert signed at least
   *  one *other* cert in the same import set, OR when this is a
   *  self-signed CA (a stand-alone trust anchor). The GUI's Apply
   *  step routes by this rather than `is_ca` so CA-flagged certs
   *  that never actually signed anything in the file land on the
   *  certificates tab instead of the issuers tab. */
  signs_others?: boolean;
  /** Cert only (plugin v0.1.9+): when the cert's parent is also in
   *  the import set, the parent's `items.id`. Lets the GUI tag the
   *  cert's emitter as "owned" (parent we're importing) vs
   *  "external". */
  signer_item_id?: number | null;
  /** Cert only (plugin v0.1.9+): the cert's Issuer DN as text.
   *  Always populated, even when the issuer isn't on the XCA file. */
  signer_subject?: string;
}

interface XcaPreview {
  summary: {
    format_version: string;
    issuer_count: number;
    leaf_count: number;
    csr_count: number;
    crl_count: number;
    template_count: number;
    key_count: number;
    skipped: string[];
  };
  items: XcaPreviewItem[];
  decryption_failures: Array<{ name: string; reason: string }>;
  ownpass_keys: string[];
}

function XcaImportTab({
  mount,
  pluginVersion,
}: {
  mount: string;
  pluginVersion: string | null;
}) {
  const { toast } = useToast();
  const [filePath, setFilePath] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [preview, setPreview] = useState<XcaPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Record<number, boolean>>({});

  function decode(b64: string): string {
    // base64 → utf-8 string
    return new TextDecoder().decode(
      Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)),
    );
  }
  function encode(s: string): string {
    // utf-8 string → base64
    const bytes = new TextEncoder().encode(s);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  async function pickFile() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const picked = await open({
        title: "Select XCA database",
        multiple: false,
        directory: false,
        filters: [
          { name: "XCA database", extensions: ["xdb"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof picked === "string" && picked.length > 0) {
        setFilePath(picked);
        setPreview(null);
      }
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function invokeXca(input: object): Promise<unknown> {
    const inputB64 = encode(JSON.stringify(input));
    const result = await api.pluginsInvoke("xca-import", inputB64);
    let parsed: unknown = null;
    if (result.response_b64) {
      try {
        parsed = JSON.parse(decode(result.response_b64));
      } catch {
        // fall through — we'll surface the raw status below
      }
    }
    if (parsed && typeof parsed === "object" && "error" in parsed) {
      throw new Error(String((parsed as { error: unknown }).error));
    }
    if (result.status !== "success") {
      throw new Error(
        `xca-import plugin returned status ${result.status} (code ${result.plugin_status_code})`,
      );
    }
    return parsed;
  }

  async function handlePreview() {
    if (!filePath) {
      toast("error", "Pick an XCA file first.");
      return;
    }
    setBusy(true);
    try {
      const out = (await invokeXca({
        op: "preview",
        file_path: filePath,
        master_password: password || undefined,
      })) as XcaPreview;
      setPreview(out);
      // Default-select every item that has usable content. CA certs
      // get imported as issuers (with their paired key); leaf certs
      // get indexed via `pki/certs/import` as orphan certs.
      const next: Record<number, boolean> = {};
      for (const it of out.items) {
        next[it.meta.id] =
          it.pem !== null &&
          (it.meta.item_type === "cert" ||
            it.meta.item_type === "private_key");
      }
      setSelected(next);
      if (out.decryption_failures.length > 0) {
        toast(
          "info",
          `${out.decryption_failures.length} key(s) couldn't be decrypted — supply the password and re-preview.`,
        );
      }
    } catch (e) {
      toast("error", extractError(e));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  /** Decide whether a cert preview row should land on the issuers
   *  tab (returns true) or the certificates tab (returns false).
   *
   *  Plugin v0.1.9+ exposes `signs_others`: true iff the cert signed
   *  at least one other cert in the import set OR is a self-signed
   *  CA. That's the authoritative routing signal.
   *
   *  On older plugins (`signs_others === undefined`) we fall back
   *  to the v0.1.7+ `is_ca` flag; on plugins older still
   *  (`is_ca === undefined`) we treat the cert as a CA candidate to
   *  preserve pre-v0.1.7 behaviour and avoid hard-failing an import
   *  that worked on the old GUI build.
   */
  function isEmitter(item: XcaPreviewItem): boolean {
    if (item.signs_others === true) return true;
    if (item.signs_others === false) return false;
    if (item.is_ca === false) return false;
    return true;
  }

  /** Pair every selected CA cert with its `parent` private key and
   * import as a CA bundle. Leaf certs / CSRs / CRLs / templates are
   * v2 work — for now they're listed but skipped on Apply. */
  async function handleApply() {
    if (!preview) return;
    if (!mount) {
      toast("error", "No PKI mount selected.");
      return;
    }
    setBusy(true);
    let imported = 0;
    let skipped = 0;
    const errors: string[] = [];
    try {
      const byId = new Map(preview.items.map((it) => [it.meta.id, it]));
      // Plugin v0.1.5+ does the authoritative cert↔key pairing by
      // public-key fingerprint and returns it as `paired_item_id`.
      // We trust ONLY that signal: name-stem heuristics produced wrong
      // pairs (the host's PKI engine then rejected them with
      // "public key of certificate does not match private key").
      // If the plugin couldn't fingerprint a key (decryption failed,
      // unsupported algorithm), we'd rather skip the row with a clear
      // message than guess wrong.
      const findCertForKey = (key: XcaPreviewItem): XcaPreviewItem | null => {
        if (key.paired_item_id == null) return null;
        const paired = byId.get(key.paired_item_id);
        if (paired && paired.meta.item_type === "cert" && paired.pem) return paired;
        return null;
      };
      const findKeyForCert = (cert: XcaPreviewItem): XcaPreviewItem | null => {
        if (cert.paired_item_id == null) return null;
        const paired = byId.get(cert.paired_item_id);
        if (paired && paired.meta.item_type === "private_key" && paired.pem) return paired;
        return null;
      };
      // Track imported pairs so a selected cert + its selected key only
      // result in a single import.
      const importedPairs = new Set<string>();
      const importBundle = async (
        cert: XcaPreviewItem,
        key: XcaPreviewItem,
      ) => {
        const pairKey = `${cert.meta.id}:${key.meta.id}`;
        if (importedPairs.has(pairKey)) return;
        importedPairs.add(pairKey);
        const bundle = `${key.pem!.trim()}\n${cert.pem!.trim()}\n`;
        const baseName = cert.meta.name || "imported-ca";
        // .xdb files often contain the same logical CA across renewals
        // (same name, different cert), and re-running Apply attempts
        // the same names again. Auto-suffix `_2`, `_3`, … on name
        // collision so the operator gets every cert imported and can
        // sort out which to keep afterward.
        const MAX_ATTEMPTS = 50;
        let lastErr: unknown = null;
        for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
          const name = attempt === 0 ? baseName : `${baseName}_${attempt + 1}`;
          try {
            await api.pkiImportCaBundle({
              mount,
              pem_bundle: bundle,
              issuer_name: name,
            });
            imported++;
            return;
          } catch (e) {
            lastErr = e;
            if (!/already exists/i.test(extractError(e))) break;
          }
        }
        errors.push(`${cert.meta.name}: ${extractError(lastErr)}`);
        skipped++;
      };
      // Leaf certs land in the orphan-cert index via `pki/certs/import`
      // — they get listed in the Certificates tab without being treated
      // as issuers (no key, no CRL participation). Track the imported
      // serials so a leaf that's also reachable via its paired key
      // doesn't get imported twice.
      const importedLeafSerials = new Set<string>();
      const importLeaf = async (cert: XcaPreviewItem) => {
        try {
          const result = await api.pkiImportCert({
            mount,
            certificate: cert.pem!,
            source: "xca-import",
          });
          importedLeafSerials.add(result.serial_number);
          imported++;
        } catch (e) {
          const msg = extractError(e);
          // A second import attempt for a serial we already wrote in
          // this same Apply pass shouldn't surface as a failure.
          if (/already indexed/i.test(msg)) {
            return;
          }
          errors.push(`${cert.meta.name}: ${msg}`);
          skipped++;
        }
      };

      // Managed-key imports (Phase L8). Standalone private keys and
      // leaf-cert paired keys both land in `pki/keys/*` so the
      // operator can pin them via `key_ref` on later issuance.
      // Tracks already-imported xdb item ids so a leaf and its
      // paired key — both selected — only result in one key import.
      const importedKeyIds = new Set<number>();
      const importStandaloneKey = async (
        key: XcaPreviewItem,
        nameHint: string,
      ): Promise<string | null> => {
        if (importedKeyIds.has(key.meta.id)) return null;
        importedKeyIds.add(key.meta.id);
        const baseName = (nameHint || key.meta.name || "imported-key")
          .replace(/[^\w-]/g, "-")
          .slice(0, 60) || "imported-key";
        const MAX_ATTEMPTS = 50;
        let lastErr: unknown = null;
        for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
          const name = attempt === 0 ? baseName : `${baseName}-${attempt + 1}`;
          try {
            const r = await api.pkiImportKey({
              mount,
              private_key: key.pem!,
              name,
            });
            imported++;
            return r.key_id;
          } catch (e) {
            lastErr = e;
            if (!/already (exist|registered)/i.test(extractError(e))) break;
          }
        }
        errors.push(`${key.meta.name}: ${extractError(lastErr)}`);
        skipped++;
        return null;
      };

      for (const item of preview.items) {
        if (!selected[item.meta.id]) continue;
        if (item.meta.item_type === "cert") {
          if (!item.pem) {
            skipped++;
            continue;
          }
          // Leaf cert → orphan-cert index + paired key (if any) into
          // the managed key store. Phase L8: leaves with keys no
          // longer drop the key on the floor — the operator can pin
          // it later via `key_ref`. Plugin v0.1.9+ uses chain-driven
          // `signs_others`; older plugins fall back via `isEmitter`.
          if (!isEmitter(item)) {
            const key = findKeyForCert(item);
            if (key && key.pem) {
              const cn = (item.subject || "").split(",").find((p) => p.trim().toUpperCase().startsWith("CN="))?.slice(3).trim();
              await importStandaloneKey(key, cn || item.meta.name);
            }
            await importLeaf(item);
            continue;
          }
          const key = findKeyForCert(item);
          if (!key) {
            skipped++;
            continue;
          }
          await importBundle(item, key);
        } else if (item.meta.item_type === "private_key") {
          if (!item.pem) {
            skipped++;
            continue;
          }
          const cert = findCertForKey(item);
          if (!cert) {
            // Phase L8: standalone keys are no longer skipped. They
            // land in `pki/keys/*` directly so the operator can use
            // them as `key_ref` on a later issuance call.
            await importStandaloneKey(item, item.meta.name);
            continue;
          }
          // Paired cert: route by emitter classification. Leaves
          // get the key into the managed store + the cert as orphan;
          // CAs go through `pki/config/ca`.
          if (!isEmitter(cert)) {
            const cn = (cert.subject || "").split(",").find((p) => p.trim().toUpperCase().startsWith("CN="))?.slice(3).trim();
            await importStandaloneKey(item, cn || cert.meta.name);
            await importLeaf(cert);
            continue;
          }
          await importBundle(cert, item);
        } else {
          // CSRs / CRLs / templates land in v2; selecting them today is
          // informational only.
          skipped++;
        }
      }
      if (errors.length > 0) {
        toast(
          "error",
          `Imported ${imported} cert(s); ${errors.length} failed:\n` +
            errors.join("\n"),
        );
      } else {
        toast(
          "success",
          `Imported ${imported} cert(s). ${skipped} item(s) skipped (out of v1 scope or no matching key).`,
        );
      }
      setPreview(null);
      setSelected({});
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <Card
        title="Import XCA database"
        actions={
          pluginVersion ? (
            <Badge label={`xca-import v${pluginVersion}`} variant="info" />
          ) : null
        }
      >
        <p className="text-sm text-[var(--color-text-muted)] mb-3">
          Reads an XCA <code className="font-mono">.xdb</code> file via the{" "}
          <code className="font-mono">xca-import</code> plugin and imports
          selected CA + key pairs as PKI issuers on{" "}
          <code className="font-mono">{mount || "(no mount)"}</code>. Leaf
          certs, CSRs, CRLs, and templates are listed but not yet imported in
          v1.
        </p>

        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2 flex items-end gap-2">
            <Input
              label="XCA file"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder="Click Browse…"
              readOnly
            />
            <Button onClick={pickFile} variant="secondary" disabled={busy}>
              Browse…
            </Button>
          </div>
          <Input
            label="Master password (optional)"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            hint="Leave blank for unencrypted databases."
          />
        </div>

        <div className="flex gap-2 mt-3">
          <Button onClick={handlePreview} loading={busy && !preview} disabled={!filePath}>
            Preview
          </Button>
          {preview && (
            <Button
              onClick={() => {
                setPreview(null);
                setSelected({});
              }}
              variant="secondary"
              disabled={busy}
            >
              Cancel preview
            </Button>
          )}
        </div>
      </Card>

      {preview && (
        <Card title="Preview">
          <div className="text-sm mb-3">
            <strong>Format:</strong> {preview.summary.format_version} —{" "}
            <span className="text-emerald-500">
              {preview.summary.issuer_count} CA(s)
            </span>{" "}
            /{" "}
            <span className="text-[var(--color-text-muted)]">
              {preview.summary.leaf_count} leaf
            </span>{" "}
            / {preview.summary.csr_count} CSR / {preview.summary.crl_count} CRL
            / {preview.summary.template_count} template /{" "}
            {preview.summary.key_count} key
          </div>

          {preview.decryption_failures.length > 0 && (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-xs mb-3">
              <strong>Decryption failures:</strong>
              <ul className="mt-1 ml-4 list-disc">
                {preview.decryption_failures.map((f, i) => (
                  <li key={i}>
                    {f.name}: {f.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <Table
            columns={[
              {
                key: "select",
                header: "",
                render: (it: XcaPreviewItem) => (
                  <input
                    type="checkbox"
                    checked={!!selected[it.meta.id]}
                    onChange={(e) =>
                      setSelected((s) => ({
                        ...s,
                        [it.meta.id]: e.target.checked,
                      }))
                    }
                  />
                ),
              },
              { key: "name", header: "Name", render: (it) => it.meta.name },
              {
                key: "type",
                header: "Type",
                render: (it) =>
                  it.meta.item_type === "cert"
                    ? isEmitter(it)
                      ? "cert (issuer)"
                      : "cert (leaf)"
                    : it.meta.item_type,
              },
              {
                key: "subject",
                header: "Subject / detail",
                render: (it) =>
                  it.subject || it.meta.comment || "—",
              },
              { key: "decrypt", header: "Decrypt", render: (it) => it.decrypt },
            ]}
            data={preview.items}
            rowKey={(it) => String(it.meta.id)}
          />

          <div className="flex justify-end mt-3">
            <Button
              onClick={handleApply}
              loading={busy}
              disabled={!Object.values(selected).some(Boolean)}
            >
              Import selected
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
        {label}
      </label>
      <div
        className={`bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm truncate ${
          mono ? "font-mono text-xs" : ""
        }`}
      >
        {value || "—"}
      </div>
    </div>
  );
}
