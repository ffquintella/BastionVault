import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Tabs,
  Modal,
  ConfirmModal,
  EmptyState,
  Badge,
  MaskedValue,
  useToast,
} from "../components/ui";
import type {
  TotpMountInfo,
  TotpKeyInfo,
  TotpCreateKeyResult,
} from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type TabId = "keys" | "code" | "validate";

export function TotpPage() {
  const { toast } = useToast();
  const [mounts, setMounts] = useState<TotpMountInfo[]>([]);
  const [activeMount, setActiveMount] = useState<string>("");
  const [tab, setTab] = useState<TabId>("keys");
  const [showEnable, setShowEnable] = useState(false);
  const [enablePath, setEnablePath] = useState("totp");

  const refreshMounts = useCallback(async () => {
    try {
      const list = await api.totpListMounts();
      setMounts(list);
      setActiveMount((prev) => {
        if (prev && list.some((m) => m.path === prev)) return prev;
        return list[0]?.path ?? "";
      });
    } catch (err) {
      toast("error", extractError(err));
    }
  }, [toast]);

  useEffect(() => {
    refreshMounts();
  }, [refreshMounts]);

  const mountOptions = useMemo(
    () => mounts.map((m) => ({ value: m.path, label: m.path })),
    [mounts],
  );

  const onEnable = async () => {
    try {
      await api.totpEnableMount(enablePath);
      toast("success", `Mounted TOTP engine at ${enablePath}`);
      setShowEnable(false);
      await refreshMounts();
      setActiveMount(enablePath.replace(/\/+$/, "") + "/");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h1 className="text-xl font-semibold">TOTP</h1>
          <Button onClick={() => setShowEnable(true)}>+ Mount TOTP engine</Button>
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
              title="No TOTP engine mounted"
              description="Mount the TOTP engine on a path (typically `totp/`) to manage seeds and issue codes."
              action={
                <Button onClick={() => setShowEnable(true)}>Mount TOTP engine</Button>
              }
            />
          </Card>
        ) : (
          <>
            <Card>
              <Tabs
                tabs={[
                  { id: "keys", label: "Keys" },
                  { id: "code", label: "Live Code" },
                  { id: "validate", label: "Validate" },
                ]}
                active={tab}
                onChange={(t) => setTab(t as TabId)}
              />
            </Card>

            {tab === "keys" && <KeysTab mount={activeMount} />}
            {tab === "code" && <LiveCodeTab mount={activeMount} />}
            {tab === "validate" && <ValidateTab mount={activeMount} />}
          </>
        )}

        <Modal
          open={showEnable}
          onClose={() => setShowEnable(false)}
          title="Mount TOTP engine"
          size="sm"
        >
          <div className="space-y-3">
            <Input
              label="Mount path"
              value={enablePath}
              onChange={(e) => setEnablePath(e.target.value)}
              placeholder="totp"
              hint="Typically `totp`. Operators with multiple environments can mount at custom paths like `totp-prod`."
            />
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setShowEnable(false)}>
                Cancel
              </Button>
              <Button onClick={onEnable}>Mount</Button>
            </div>
          </div>
        </Modal>
      </div>
    </Layout>
  );
}

// ── Keys Tab ──────────────────────────────────────────────────────

function KeysTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [keys, setKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [createResult, setCreateResult] = useState<TotpCreateKeyResult | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, TotpKeyInfo | null>>({});

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.totpListKeys(mount);
      setKeys(list);
    } catch {
      // LIST against an empty key set throws on some storage backends —
      // treat as an empty list rather than an error so the operator
      // sees the empty state, not a toast they can't act on.
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }, [mount]);

  useEffect(() => {
    refresh();
    setDetails({});
  }, [refresh]);

  const expand = async (name: string) => {
    if (details[name] !== undefined) {
      // Already loaded — collapse on a second click.
      setDetails((d) => {
        const next = { ...d };
        delete next[name];
        return next;
      });
      return;
    }
    try {
      const info = await api.totpReadKey(mount, name);
      setDetails((d) => ({ ...d, [name]: info }));
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onDelete = async (name: string) => {
    try {
      await api.totpDeleteKey(mount, name);
      toast("success", `Deleted ${name}`);
      setConfirmDelete(null);
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading keys…</p>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
          <h2 className="text-lg font-medium">Keys</h2>
          <Button onClick={() => setShowCreate(true)}>+ Create key</Button>
        </div>

        {keys.length === 0 ? (
          <EmptyState
            title="No TOTP keys"
            description="Create a key in `generate` mode to enroll a new authenticator, or in `provider` mode to import an existing TOTP seed."
            action={<Button onClick={() => setShowCreate(true)}>Create key</Button>}
          />
        ) : (
          <ul className="divide-y divide-[var(--color-border)]">
            {keys.map((name) => {
              const info = details[name];
              return (
                <li key={name} className="py-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <button
                      type="button"
                      className="text-left font-mono text-sm hover:underline min-w-0 truncate"
                      onClick={() => expand(name)}
                    >
                      {name}
                    </button>
                    <div className="flex gap-2">
                      <Button variant="ghost" onClick={() => expand(name)}>
                        {info !== undefined ? "Hide" : "Details"}
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() => setConfirmDelete(name)}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                  {info && (
                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-[var(--color-text-muted)]">
                      <div>
                        Mode:{" "}
                        <Badge
                          label={info.generate ? "generate" : "provider"}
                        />
                      </div>
                      <div>Algorithm: {info.algorithm}</div>
                      <div>Issuer: {info.issuer || "—"}</div>
                      <div>Account: {info.account_name}</div>
                      <div>Digits: {info.digits}</div>
                      <div>Period: {info.period}s</div>
                      <div>Skew: ±{info.skew}</div>
                      <div>
                        Replay check: {info.replay_check ? "on" : "off"}
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {showCreate && (
        <CreateKeyModal
          mount={mount}
          onClose={() => setShowCreate(false)}
          onCreated={(res) => {
            setShowCreate(false);
            setCreateResult(res);
            refresh();
          }}
        />
      )}

      {createResult && (
        <CreateResultModal
          result={createResult}
          onClose={() => setCreateResult(null)}
        />
      )}

      <ConfirmModal
        open={!!confirmDelete}
        title="Delete TOTP key"
        message={
          confirmDelete
            ? `Delete \`${confirmDelete}\`? Any authenticator already enrolled with this seed will keep generating codes, but the engine will no longer accept or emit them.`
            : ""
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => confirmDelete && onDelete(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
      />
    </>
  );
}

// ── Create Key Modal ──────────────────────────────────────────────

function CreateKeyModal({
  mount,
  onClose,
  onCreated,
}: {
  mount: string;
  onClose: () => void;
  onCreated: (r: TotpCreateKeyResult) => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [generate, setGenerate] = useState(true);
  const [issuer, setIssuer] = useState("");
  const [accountName, setAccountName] = useState("");
  const [algorithm, setAlgorithm] = useState("SHA1");
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);
  const [skew, setSkew] = useState(1);
  const [keySize, setKeySize] = useState(20);
  const [qrSize, setQrSize] = useState(200);
  const [importMode, setImportMode] = useState<"key" | "url">("key");
  const [importedKey, setImportedKey] = useState("");
  const [importedUrl, setImportedUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async () => {
    if (!name.trim()) {
      toast("error", "Key name is required");
      return;
    }
    setSubmitting(true);
    try {
      const result = await api.totpCreateKey({
        mount,
        name: name.trim(),
        generate,
        issuer: issuer.trim() || undefined,
        account_name: accountName.trim() || undefined,
        algorithm,
        digits,
        period,
        skew,
        key_size: generate ? keySize : undefined,
        qr_size: generate ? qrSize : undefined,
        exported: generate ? true : undefined,
        key: !generate && importMode === "key" ? importedKey.trim() : undefined,
        url: !generate && importMode === "url" ? importedUrl.trim() : undefined,
      });
      onCreated(result);
    } catch (err) {
      toast("error", extractError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal open={true} onClose={onClose} title="Create TOTP key" size="lg">
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Key name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="alice-google"
          />
          <Select
            label="Mode"
            value={generate ? "generate" : "provider"}
            onChange={(e) => setGenerate(e.target.value === "generate")}
            options={[
              { value: "generate", label: "Generate (engine picks the seed)" },
              { value: "provider", label: "Provider (import existing seed)" },
            ]}
          />
          <Input
            label="Issuer"
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            placeholder="ACME Co"
          />
          <Input
            label="Account name"
            value={accountName}
            onChange={(e) => setAccountName(e.target.value)}
            placeholder="alice@example.com"
          />
          <Select
            label="Algorithm"
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
            options={[
              { value: "SHA1", label: "SHA1 (default — best app support)" },
              { value: "SHA256", label: "SHA256" },
              { value: "SHA512", label: "SHA512" },
            ]}
          />
          <Select
            label="Digits"
            value={String(digits)}
            onChange={(e) => setDigits(Number(e.target.value))}
            options={[
              { value: "6", label: "6 (default)" },
              { value: "8", label: "8" },
            ]}
          />
          <Input
            label="Period (seconds)"
            type="number"
            value={String(period)}
            onChange={(e) => setPeriod(Number(e.target.value) || 30)}
          />
          <Input
            label="Skew (steps)"
            type="number"
            value={String(skew)}
            onChange={(e) => setSkew(Number(e.target.value) || 0)}
            hint="±N steps accepted on validate."
          />
        </div>

        {generate ? (
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Seed size (bytes)"
              type="number"
              value={String(keySize)}
              onChange={(e) => setKeySize(Number(e.target.value) || 20)}
              hint="20 = RFC 4226 recommendation."
            />
            <Input
              label="QR pixel size"
              type="number"
              value={String(qrSize)}
              onChange={(e) => setQrSize(Number(e.target.value) || 0)}
              hint="0 disables QR rendering."
            />
          </div>
        ) : (
          <div className="space-y-3">
            <Select
              label="Import via"
              value={importMode}
              onChange={(e) => setImportMode(e.target.value as "key" | "url")}
              options={[
                { value: "key", label: "Base32 seed" },
                { value: "url", label: "otpauth:// URL" },
              ]}
            />
            {importMode === "key" ? (
              <Input
                label="Base32 seed"
                value={importedKey}
                onChange={(e) => setImportedKey(e.target.value)}
                placeholder="JBSWY3DPEHPK3PXP"
                hint="RFC 4648 alphabet. Whitespace and case are tolerated; padding optional."
              />
            ) : (
              <Input
                label="otpauth:// URL"
                value={importedUrl}
                onChange={(e) => setImportedUrl(e.target.value)}
                placeholder="otpauth://totp/ACME:alice?secret=...&issuer=ACME"
              />
            )}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={submitting}>
            {submitting ? "Creating…" : "Create"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ── Create-result Modal ───────────────────────────────────────────
//
// One-shot disclosure: the seed and QR appear here exactly once and
// then live in the host's clipboard / authenticator. Closing the
// modal drops the result from React state — there is no second-look
// button.

function CreateResultModal({
  result,
  onClose,
}: {
  result: TotpCreateKeyResult;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const hasSeed = result.generate && result.key.length > 0;

  return (
    <Modal open={true} onClose={onClose} title={`Created ${result.name}`} size="lg">
      <div className="space-y-3">
        {hasSeed ? (
          <>
            <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-xs text-[var(--color-text-muted)]">
              <strong className="text-[var(--color-warning)]">
                One-shot disclosure:
              </strong>{" "}
              the seed and QR are returned exactly once. Scan the QR into
              an authenticator now or copy the seed; closing this dialog
              drops it from view.
            </div>

            {result.barcode && (
              <div className="flex justify-center">
                <img
                  src={`data:image/png;base64,${result.barcode}`}
                  alt={`QR for ${result.name}`}
                  className="border border-[var(--color-border)] bg-white p-2"
                  style={{ imageRendering: "pixelated" }}
                />
              </div>
            )}

            <div>
              <label className="text-sm font-medium">Base32 seed</label>
              <MaskedValue value={result.key} />
            </div>

            <div>
              <label className="text-sm font-medium">otpauth URL</label>
              <div className="flex items-center gap-2">
                <code className="flex-1 min-w-0 truncate text-xs bg-[var(--color-surface-2)] px-2 py-1 rounded">
                  {result.url}
                </code>
                <Button
                  variant="ghost"
                  onClick={() => {
                    navigator.clipboard.writeText(result.url);
                    toast("success", "URL copied");
                  }}
                >
                  Copy
                </Button>
              </div>
            </div>
          </>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            Provider-mode keys never re-export the seed. The key is stored
            and ready to validate codes via the Validate tab.
          </p>
        )}

        <div className="flex justify-end">
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>
    </Modal>
  );
}

// ── Live-code Tab ─────────────────────────────────────────────────
//
// Generate-mode keys serve their current code via GET /code/:name.
// We poll once per second so the operator sees the digits the
// authenticator app would show; the circular timer is driven from
// `Date.now()` rather than from any server response so a stalled
// network doesn't lie about the remaining window.

function LiveCodeTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [keys, setKeys] = useState<string[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [info, setInfo] = useState<TotpKeyInfo | null>(null);
  const [code, setCode] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));

  // Refresh the key list when the mount changes.
  useEffect(() => {
    (async () => {
      try {
        setKeys(await api.totpListKeys(mount));
      } catch {
        setKeys([]);
      }
    })();
    setSelected("");
    setInfo(null);
    setCode("");
    setError("");
  }, [mount]);

  // Load metadata for the selected key (need `period` for the timer).
  useEffect(() => {
    if (!selected) {
      setInfo(null);
      return;
    }
    (async () => {
      try {
        setInfo(await api.totpReadKey(mount, selected));
      } catch (err) {
        toast("error", extractError(err));
      }
    })();
  }, [mount, selected, toast]);

  // 1-Hz tick. We only fetch a new code when the step boundary is
  // crossed, but the timer ring updates every second.
  const lastStepRef = useRef<number>(-1);
  useEffect(() => {
    const id = window.setInterval(() => {
      setNow(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (!selected || !info) return;
    const step = Math.floor(now / info.period);
    if (step === lastStepRef.current) return;
    lastStepRef.current = step;
    (async () => {
      try {
        const r = await api.totpGetCode(mount, selected);
        setCode(r.code);
        setError("");
      } catch (err) {
        setCode("");
        setError(extractError(err));
      }
    })();
  }, [mount, selected, info, now]);

  const period = info?.period ?? 30;
  const remaining = period - (now % period);
  const fraction = remaining / period;

  const keyOptions = useMemo(
    () => [
      { value: "", label: keys.length === 0 ? "(no keys)" : "Select a key…" },
      ...keys.map((k) => ({ value: k, label: k })),
    ],
    [keys],
  );

  return (
    <Card>
      <div className="space-y-4">
        <Select
          label="Key"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          options={keyOptions}
          disabled={keys.length === 0}
        />

        {selected && info && !info.generate && (
          <p className="text-sm text-[var(--color-warning)]">
            `{selected}` is a provider-mode key. Use the Validate tab
            instead — provider-mode keys do not emit codes here.
          </p>
        )}

        {selected && info?.generate && (
          <div className="flex items-center gap-6">
            <div
              className="font-mono text-4xl tracking-widest"
              aria-live="polite"
            >
              {error
                ? "—"
                : code
                ? code.replace(/(\d{3})(\d+)/, "$1 $2")
                : "······"}
            </div>
            <div className="relative h-16 w-16">
              <svg viewBox="0 0 36 36" className="h-16 w-16 -rotate-90">
                <circle
                  cx="18"
                  cy="18"
                  r="16"
                  fill="none"
                  stroke="var(--color-border)"
                  strokeWidth="3"
                />
                <circle
                  cx="18"
                  cy="18"
                  r="16"
                  fill="none"
                  stroke="var(--color-primary)"
                  strokeWidth="3"
                  strokeDasharray={`${fraction * 100.53} 100.53`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center text-xs">
                {remaining}s
              </div>
            </div>
          </div>
        )}

        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}
      </div>
    </Card>
  );
}

// ── Validate Tab ──────────────────────────────────────────────────

function ValidateTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [keys, setKeys] = useState<string[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [code, setCode] = useState<string>("");
  const [result, setResult] = useState<boolean | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        setKeys(await api.totpListKeys(mount));
      } catch {
        setKeys([]);
      }
    })();
    setSelected("");
    setCode("");
    setResult(null);
  }, [mount]);

  const onValidate = async () => {
    if (!selected || !code.trim()) {
      toast("error", "Select a key and enter a code");
      return;
    }
    setSubmitting(true);
    setResult(null);
    try {
      const r = await api.totpValidateCode(mount, selected, code.trim());
      setResult(r.valid);
    } catch (err) {
      toast("error", extractError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const keyOptions = useMemo(
    () => [
      { value: "", label: keys.length === 0 ? "(no keys)" : "Select a key…" },
      ...keys.map((k) => ({ value: k, label: k })),
    ],
    [keys],
  );

  return (
    <Card>
      <div className="space-y-3">
        <Select
          label="Provider-mode key"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          options={keyOptions}
          disabled={keys.length === 0}
        />
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\s+/g, ""))}
            placeholder="123456"
            inputMode="numeric"
          />
          <div className="flex items-end">
            <Button onClick={onValidate} disabled={submitting}>
              {submitting ? "Validating…" : "Validate"}
            </Button>
          </div>
        </div>
        {result !== null && (
          <p
            className={
              result
                ? "text-sm text-[var(--color-success)]"
                : "text-sm text-[var(--color-danger)]"
            }
          >
            {result ? "✓ Valid" : "✗ Invalid (or replay-rejected)"}
          </p>
        )}
        <p className="text-xs text-[var(--color-text-muted)]">
          Replay protection is on by default — a successfully validated
          code cannot be re-validated within the same step window.
        </p>
      </div>
    </Card>
  );
}
