import { useEffect, useState } from "react";
import { Badge, Button, Card, Input, Modal, Select, Textarea } from "./ui";
import type { ResourceMetadata, ResourceTypeDef } from "../lib/types";
import { profilesForWrite, readProfiles, readUnknownProfiles } from "../lib/connectionProfiles";
import {
  SQL_ENGINES,
  SQL_TLS_MODES,
  blankSqlProfile,
  connectWithSql,
  isSqlProfileEntry,
  readSqlEnforcement,
  readSqlProfile,
  resolveSqlEndpoint,
  serializeSqlProfile,
  sqlEngineOf,
  sqlOfferedByType,
  validateSqlProfile,
  withSqlEnforcement,
  type SqlEnforcement,
  type SqlEngineInfo,
  type SqlProfileForm,
  type SqlTlsMode,
} from "../lib/sqlProfile";
import {
  SQL_CAPABILITIES,
  SQL_CAPABILITY_HINTS,
  SQL_PRESETS,
  activeSqlPreset,
  applySqlPreset,
  type SqlCapability,
  type SqlPrivileges,
} from "../lib/sqlPrivileges";
import { useCanWriteResource } from "../hooks/useCanWriteResource";
import type { SqlLaunchProfile } from "../lib/sqlLaunch";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type Toast = (type: "success" | "error" | "info", msg: string) => void;

const TLS_LABELS: Record<SqlTlsMode, string> = {
  "verify-full": "verify-full: check the certificate chain and the server name",
  "verify-ca": "verify-ca: check the certificate chain only",
  require: "require: encrypt, do not verify",
  disable: "disable: no TLS",
};

const TYPE_GATE_TEXT = {
  disabled: "Connect is disabled for the Database type, which turns the SQL browser off too.",
  "missing-from-list":
    "The saved Database type lists its Connect protocols without `sql`, so the SQL browser is off for every database resource.",
  "not-a-list": "The saved Database type's `connect.protocols` is not a list, which offers no protocol at all.",
  unreadable: "The saved Database type's `connect` block cannot be read, which refuses the SQL browser.",
} as const;

/**
 * The SQL browser's part of a database resource's Connection tab
 * (features/sql-browser.md §5, §10): `sql` profiles, enforcement mode, and
 * the type-level switch that offers `sql`. The launcher's profile panel does
 * not know the protocol, so these entries reach it as "unknown" ones that
 * every save re-appends untouched (T102); this card does the same in reverse.
 */
export function SqlProfilesCard({
  resource,
  typeDef,
  onUpdated,
  onTypeUpdated,
  onOpenSql,
  toast,
}: {
  resource: ResourceMetadata;
  /** The effective `database` type definition. */
  typeDef: ResourceTypeDef;
  onUpdated: () => void;
  /** Called after the type configuration was changed from here. */
  onTypeUpdated?: () => void;
  /** Open the SQL browser: with a profile, or (null) letting the plugin pick. */
  onOpenSql?: (profile: SqlLaunchProfile | null) => void;
  toast: Toast;
}) {
  const name = String(resource.name ?? "");
  const meta = resource as Record<string, unknown>;
  const engine = sqlEngineOf(meta);
  const gate = sqlOfferedByType(typeDef);
  const canWrite = useCanWriteResource(name);
  const readOnly = canWrite === false;

  const known = readProfiles(meta);
  const unknown = readUnknownProfiles(meta);
  const sqlEntries = unknown.filter(isSqlProfileEntry);
  const enforcement = readSqlEnforcement(meta);

  const [editing, setEditing] = useState<{ form: SqlProfileForm; isNew: boolean; problems: string[] } | null>(null);
  const [deleting, setDeleting] = useState<SqlProfileForm | null>(null);
  const [enforcementDraft, setEnforcementDraft] = useState<SqlEnforcement>(enforcement.value);
  const [busy, setBusy] = useState(false);
  const [privileges, setPrivileges] = useState<SqlPrivileges | null>(null);

  useEffect(() => setEnforcementDraft(enforcement.value), [enforcement.value]);

  // The caller's own effective SQL privileges: informational chips only.
  useEffect(() => {
    let live = true;
    api
      .resourceSqlPrivileges(name)
      .then((p) => live && setPrivileges(p))
      .catch(() => live && setPrivileges(null));
    return () => {
      live = false;
    };
  }, [name]);

  /** Write the record with `connection_profiles` rebuilt around `nextUnknown`. */
  async function persist(nextUnknown: unknown[], ok: string) {
    setBusy(true);
    try {
      const toWrite = profilesForWrite(known, nextUnknown);
      await api.writeResource(name, { ...meta, connection_profiles: toWrite } as unknown as ResourceMetadata);
      toast("success", ok);
      onUpdated();
      return true;
    } catch (e: unknown) {
      toast("error", extractError(e));
      return false;
    } finally {
      setBusy(false);
    }
  }

  const sameId = (p: unknown, id: string) => isSqlProfileEntry(p) && (p as Record<string, unknown>)["id"] === id;

  async function saveProfile(form: SqlProfileForm, isNew: boolean) {
    const written = serializeSqlProfile(form);
    const next = isNew ? [...unknown, written] : unknown.map((p) => (sameId(p, form.id) ? written : p));
    if (await persist(next, "SQL profile saved")) setEditing(null);
  }

  async function deleteProfile(form: SqlProfileForm) {
    if (await persist(unknown.filter((p) => !sameId(p, form.id)), "SQL profile deleted")) setDeleting(null);
  }

  async function saveEnforcement() {
    setBusy(true);
    try {
      await api.writeResource(name, withSqlEnforcement(meta, enforcementDraft) as unknown as ResourceMetadata);
      toast("success", "SQL enforcement saved");
      onUpdated();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  // Offer `sql` on the saved type. Only where this namespace saved the type
  // configuration itself: writing it from a namespace that inherits the
  // root's would fork every type into a partial local copy.
  const [typeNote, setTypeNote] = useState<string | null>(null);
  async function addSqlToType() {
    setBusy(true);
    try {
      const eff = await api.resourceTypesReadEffective();
      const types = eff.types as Record<string, Record<string, unknown>> | null;
      if (eff.source !== "mount" || !types || !types[typeDef.id]) {
        setTypeNote(
          eff.source === "root"
            ? "This namespace inherits the root namespace's type configuration. Add sql to the Database type there (Settings, Resource types)."
            : "The Database type is not saved in this namespace's type configuration.",
        );
        return;
      }
      const def = types[typeDef.id];
      const connect = (def["connect"] ?? {}) as Record<string, unknown>;
      await api.resourceTypesWrite({ ...types, [typeDef.id]: { ...def, connect: connectWithSql(connect) } });
      toast("success", "The Database type now offers sql");
      setTypeNote(null);
      onTypeUpdated?.();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  const newDisabled = readOnly || !engine || !gate.offered;
  const newTitle = readOnly
    ? "You don't have permission to modify this resource."
    : !engine
      ? "Set the resource's Engine (Info tab) to PostgreSQL, MySQL, MariaDB, SQL Server or Oracle first."
      : !gate.offered
        ? "The SQL browser is off for the Database type."
        : undefined;

  return (
    <Card>
      <div className="space-y-3" data-testid="sql-profiles-card">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <h2 className="text-lg font-medium">SQL browser</h2>
            <p className="text-xs text-[var(--color-text-muted)]">
              Connection profiles the SQL browser opens sessions with. Each states the privileges its database login can
              use (its ceiling) and where the login comes from.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            {onOpenSql && (
              <Button
                variant="secondary"
                onClick={() => onOpenSql(null)}
                disabled={!engine || !gate.offered || sqlEntries.length === 0}
                title="Open a SQL session; BastionVault picks the smallest profile that covers your grant"
              >
                Open SQL browser
              </Button>
            )}
            <Button
              onClick={() => engine && setEditing({ form: blankSqlProfile(), isNew: true, problems: [] })}
              disabled={newDisabled}
              title={newTitle}
            >
              + Add SQL profile
            </Button>
          </div>
        </div>

        {!gate.offered && (
          <div role="alert" className="rounded border border-yellow-700 bg-yellow-950/40 px-3 py-2 text-sm text-yellow-200">
            <p>{TYPE_GATE_TEXT[gate.reason]}</p>
            {gate.reason === "missing-from-list" && (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button size="sm" variant="secondary" loading={busy} onClick={() => void addSqlToType()}>
                  Add sql to the Database type
                </Button>
                <span className="text-xs">Needs permission to edit the resource types.</span>
              </div>
            )}
            {typeNote && <p className="mt-1 text-xs">{typeNote}</p>}
          </div>
        )}

        {!engine && (
          <p className="text-sm text-[var(--color-text-muted)]">
            The SQL browser supports {SQL_ENGINES.map((e) => e.label).join(", ")}. Set this resource&apos;s{" "}
            <strong>Engine</strong> on the Info tab to one of them.
          </p>
        )}

        {privileges && (privileges.server.length > 0 || privileges.resource_wide.length > 0) && (
          <div
            className="flex flex-wrap items-center gap-1.5 text-xs text-[var(--color-text-muted)]"
            data-testid="sql-my-privileges"
          >
            <span className="text-[var(--color-text)]">Your SQL privileges</span>
            {SQL_CAPABILITIES.filter((c) => privileges.resource_wide.includes(c) || privileges.server.includes(c)).map(
              (c) => (
                <Badge key={c} variant="info" label={c} />
              ),
            )}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-end">
          <div className="min-w-0">
            <Select
              label="Enforcement"
              value={enforcementDraft}
              disabled={readOnly || busy}
              onChange={(e) => setEnforcementDraft(e.target.value as SqlEnforcement)}
              options={[
                { value: "database-first", label: "database-first: the database enforces the ceiling (default)" },
                { value: "classifier-only", label: "classifier-only: BastionVault alone holds the line" },
              ]}
            />
          </div>
          <div>
            <Button
              size="sm"
              variant="secondary"
              loading={busy}
              disabled={readOnly || enforcementDraft === enforcement.value}
              onClick={() => void saveEnforcement()}
            >
              Save enforcement
            </Button>
          </div>
        </div>
        {enforcement.problem && (
          <p role="alert" className="text-xs text-red-400">
            {enforcement.problem}. The server refuses SQL sessions on this resource until it is fixed; saving a value
            here rewrites the block.
          </p>
        )}
        {enforcementDraft === "classifier-only" ? (
          <p className="text-xs text-yellow-400" data-testid="classifier-only-note">
            SQL grants on this database are enforced by BastionVault only; the database login can do more. Every audit
            event of such a session carries <code>db_enforced: false</code>.
          </p>
        ) : (
          <p className="text-xs text-[var(--color-text-muted)]">
            A read-only grant needs a profile whose ceiling is exactly <code>sql_select</code>; without one it is
            refused, and an administrator must add a read-only login.
          </p>
        )}

        {sqlEntries.length === 0 && <p className="text-sm text-[var(--color-text-muted)]">No SQL profiles yet.</p>}
        <div className="space-y-2">
          {sqlEntries.map((raw, i) => (
            <SqlProfileRow
              key={String((raw as Record<string, unknown>)["id"] ?? i)}
              raw={raw}
              engine={engine}
              disabled={readOnly || !engine}
              onEdit={(form, problems) => setEditing({ form, isNew: false, problems })}
              onDelete={(form) => setDeleting(form)}
              onOpen={
                onOpenSql && engine && gate.offered
                  ? (form) => onOpenSql({ id: form.id, name: form.name || form.id, requireMfa: form.requireMfa })
                  : undefined
              }
            />
          ))}
        </div>
      </div>

      {editing && engine && (
        <SqlProfileEditor
          initial={editing.form}
          isNew={editing.isNew}
          storedProblems={editing.problems}
          engine={engine}
          resource={meta}
          resourceName={name}
          otherIds={[...known.map((p) => p.id), ...sqlEntries.map((p) => String((p as Record<string, unknown>)["id"]))]}
          saving={busy}
          onClose={() => setEditing(null)}
          onSave={(f) => void saveProfile(f, editing.isNew)}
        />
      )}

      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete SQL profile"
        actions={
          <>
            <Button variant="ghost" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button variant="danger" loading={busy} onClick={() => deleting && void deleteProfile(deleting)}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm">
          Delete the SQL profile <strong>{deleting?.name || deleting?.id}</strong>? Sessions that use it stop working.
          The resource&apos;s other profiles are kept as they are.
        </p>
      </Modal>
    </Card>
  );
}

function SqlProfileRow({
  raw,
  engine,
  disabled,
  onEdit,
  onDelete,
  onOpen,
}: {
  raw: unknown;
  engine: SqlEngineInfo | null;
  disabled: boolean;
  onEdit: (form: SqlProfileForm, problems: string[]) => void;
  onDelete: (form: SqlProfileForm) => void;
  /** Open the SQL browser with this profile (valid profiles only). */
  onOpen?: (form: SqlProfileForm) => void;
}) {
  const { form, problems } = readSqlProfile(raw, engine?.id ?? "postgresql");
  return (
    <div className="flex items-start justify-between gap-3 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <strong className="truncate">{form.name || form.id || "(unnamed)"}</strong>
          <Badge label="SQL" />
          {form.requireMfa && <Badge variant="info" label="MFA required" />}
          <Badge variant="neutral" label={`TLS ${form.tlsMode}`} />
          {problems.length > 0 && <Badge variant="error" label="invalid" />}
        </div>
        {problems.length > 0 ? (
          <ul className="list-disc pl-5 text-xs text-red-400">
            {problems.map((p, i) => (
              <li key={i} className="min-w-0 break-words">
                {p}
              </li>
            ))}
          </ul>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-[var(--color-text-muted)]">ceiling</span>
              {form.ceiling.map((c) => (
                <Badge key={c} variant="info" label={c} />
              ))}
            </div>
            <p className="text-xs text-[var(--color-text-muted)] min-w-0 truncate">
              {form.credential.kind === "secret"
                ? `login from secret ${form.credential.secretId}`
                : `dynamic credentials ${form.credential.mount} / ${form.credential.role} (not available yet)`}
              {form.catalog ? ` · ${form.catalog}` : ""}
              {form.targetHost ? ` · ${form.targetHost}${form.targetPort ? `:${form.targetPort}` : ""}` : ""}
            </p>
          </>
        )}
      </div>
      <div className="flex shrink-0 gap-1">
        {onOpen && problems.length === 0 && form.id && (
          <Button size="sm" variant="secondary" onClick={() => onOpen(form)} aria-label={`Open SQL browser with ${form.name || form.id}`}>
            Open
          </Button>
        )}
        <Button size="sm" variant="ghost" disabled={disabled} onClick={() => onEdit(form, problems)}>
          Edit
        </Button>
        <Button size="sm" variant="danger" disabled={disabled} onClick={() => onDelete(form)}>
          Delete
        </Button>
      </div>
    </div>
  );
}

function CapabilityChips({
  value,
  onChange,
  label,
}: {
  value: SqlCapability[];
  onChange: (next: SqlCapability[]) => void;
  label: string;
}) {
  const toggle = (c: SqlCapability) => {
    const next = value.includes(c) ? value.filter((x) => x !== c) : [...value, c];
    onChange(SQL_CAPABILITIES.filter((x) => next.includes(x)));
  };
  return (
    <div className="flex flex-wrap gap-2" role="group" aria-label={label}>
      {SQL_CAPABILITIES.map((c) => {
        const on = value.includes(c);
        return (
          <button
            key={c}
            type="button"
            aria-pressed={on}
            title={SQL_CAPABILITY_HINTS[c]}
            onClick={() => toggle(c)}
            className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
              on
                ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
            }`}
          >
            {c}
          </button>
        );
      })}
    </div>
  );
}

function SqlProfileEditor({
  initial,
  isNew,
  storedProblems,
  engine,
  resource,
  resourceName,
  otherIds,
  saving,
  onClose,
  onSave,
}: {
  initial: SqlProfileForm;
  isNew: boolean;
  /** Why the stored profile does not parse, when editing one that does not. */
  storedProblems: string[];
  engine: SqlEngineInfo;
  resource: Record<string, unknown>;
  resourceName: string;
  /** Ids of every stored profile, so a new one cannot reuse one. */
  otherIds: string[];
  saving: boolean;
  onClose: () => void;
  onSave: (form: SqlProfileForm) => void;
}) {
  const [f, setF] = useState<SqlProfileForm>(initial);
  const [secretKeys, setSecretKeys] = useState<string[]>([]);
  const set = <K extends keyof SqlProfileForm>(k: K, v: SqlProfileForm[K]) => setF((p) => ({ ...p, [k]: v }));

  // The resource's secrets, as suggestions for the credential picker. A
  // caller that may not list them just types the id.
  useEffect(() => {
    let live = true;
    api
      .listResourceSecrets(resourceName)
      .then((r) => live && setSecretKeys(r.keys ?? []))
      .catch(() => live && setSecretKeys([]));
    return () => {
      live = false;
    };
  }, [resourceName]);

  const errors = validateSqlProfile(f, engine.id);
  if (isNew && otherIds.includes(f.id)) errors.push("The profile id is already used on this resource");
  const endpoint = resolveSqlEndpoint(f, resource, engine);
  const preset = activeSqlPreset(f.ceiling);
  const cred = f.credential;

  return (
    <Modal
      open
      onClose={onClose}
      title={isNew ? "Add SQL profile" : "Edit SQL profile"}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={saving} disabled={errors.length > 0} onClick={() => onSave(f)}>
            Save profile
          </Button>
        </>
      }
    >
      <div className="space-y-3" data-testid="sql-profile-editor">
        {storedProblems.length > 0 && (
          <div role="alert" className="rounded border border-red-700 bg-red-950/40 px-3 py-2 text-xs text-red-300">
            The server refuses this stored profile:
            <ul className="list-disc pl-5">
              {storedProblems.map((p, i) => (
                <li key={i} className="min-w-0 break-words">
                  {p}
                </li>
              ))}
            </ul>
            Saving writes it back in the accepted shape; a key the server does not accept is dropped.
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2 min-w-0">
            <Input
              label="Name"
              value={f.name}
              onChange={(e) => set("name", e.target.value)}
              placeholder="Read-only (svc_app_ro)"
            />
          </div>
          <div className="min-w-0">
            <Input
              label="Host (optional)"
              value={f.targetHost}
              onChange={(e) => set("targetHost", e.target.value)}
              placeholder="the resource's hostname"
            />
          </div>
          <div className="min-w-0">
            <Input
              label="Port (optional)"
              inputMode="numeric"
              value={f.targetPort}
              onChange={(e) => set("targetPort", e.target.value)}
              placeholder={String(engine.port)}
            />
          </div>
          <div className="min-w-0">
            <Input
              label={engine.catalogLabel}
              value={f.catalog}
              onChange={(e) => set("catalog", e.target.value)}
              placeholder={engine.id === "oracle" ? "ORCLPDB1" : "app_production"}
            />
          </div>
          {engine.id === "mssql" && (
            <div className="min-w-0">
              <Input
                label="Named instance (optional)"
                value={f.instance}
                onChange={(e) => set("instance", e.target.value)}
                placeholder="SQLEXPRESS"
              />
            </div>
          )}

          <div className="col-span-2 min-w-0">
            <Select
              label="TLS"
              value={f.tlsMode}
              onChange={(e) => set("tlsMode", e.target.value as SqlTlsMode)}
              options={SQL_TLS_MODES.map((m) => ({ value: m, label: TLS_LABELS[m] }))}
            />
          </div>
          {f.tlsMode !== "disable" && (
            <>
              <div className="col-span-2 min-w-0">
                <Input
                  label="TLS server name (optional)"
                  value={f.tlsServerName}
                  onChange={(e) => set("tlsServerName", e.target.value)}
                  placeholder="the name on the server's certificate"
                />
              </div>
              <div className="col-span-2 min-w-0">
                <Textarea
                  label="Trusted CA (PEM, optional)"
                  value={f.tlsCaPem}
                  onChange={(e) => set("tlsCaPem", e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  spellCheck={false}
                />
              </div>
            </>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--color-text-muted)] mb-1">Ceiling</label>
          <div className="flex flex-wrap gap-2 mb-2" role="group" aria-label="Ceiling presets">
            {SQL_PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                aria-pressed={preset === p.id}
                onClick={() => set("ceiling", applySqlPreset(f.ceiling, p) as SqlCapability[])}
                className={`px-2.5 py-1 rounded-md text-xs border transition-colors ${
                  preset === p.id
                    ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                    : "border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
          <CapabilityChips label="Ceiling" value={f.ceiling} onChange={(v) => set("ceiling", v)} />
          <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
            What this profile&apos;s database login can do at the database, as you state it. It must name at least one
            capability. A read-only grant is served only by a profile whose ceiling is exactly <code>sql_select</code>.
          </p>
        </div>

        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" checked={f.requireMfa} onChange={(e) => set("requireMfa", e.target.checked)} />
          <span>
            Require MFA before a session opens with this profile{" "}
            <span className="text-xs text-[var(--color-text-muted)]">
              (<code>sql.require_mfa</code>)
            </span>
          </span>
        </label>

        <div>
          <label className="block text-sm font-medium text-[var(--color-text-muted)] mb-1">Step-up (optional)</label>
          <CapabilityChips label="Step-up" value={f.stepUp} onChange={(v) => set("stepUp", v)} />
          <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
            Capabilities whose use will need a fresh MFA ticket. Stored now; it takes effect with the step-up phase
            (T126), until then it is not enforced.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2 min-w-0">
            <Select
              label="Credential source"
              value={cred.kind}
              onChange={(e) => {
                if (e.target.value === "secret") set("credential", { kind: "secret", secretId: "" });
              }}
              options={[
                { value: "secret", label: "Stored secret on this resource" },
                { value: "dynamic", label: "Dynamic credentials (later: not available yet)" },
              ]}
            />
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              Dynamic database credentials arrive with a later phase; the server refuses to release one until then, so
              they cannot be chosen here.
            </p>
          </div>
          {cred.kind === "secret" ? (
            <div className="col-span-2 min-w-0">
              <Input
                label="Secret"
                list="sql-profile-secrets"
                value={cred.secretId}
                onChange={(e) => set("credential", { kind: "secret", secretId: e.target.value })}
                placeholder="svc_app_ro"
                hint={`A secret of this resource with string "username" and "password" fields.`}
              />
              <datalist id="sql-profile-secrets">
                {secretKeys.map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
            </div>
          ) : (
            <p className="col-span-2 text-xs text-[var(--color-text-muted)]">
              This profile uses dynamic credentials ({cred.mount} / {cred.role}), which the server parses but cannot
              release yet. Switch to a stored secret to make it usable.
            </p>
          )}
        </div>

        {cred.kind === "secret" && (
          <div
            className="rounded border border-[var(--color-border)] px-3 py-2 text-xs text-[var(--color-text-muted)]"
            data-testid="sql-endpoint-hint"
          >
            The secret&apos;s login is released only to the endpoints its <code>sql_endpoint</code> field names, so set
            that field on the secret to{" "}
            {endpoint ? (
              <code className="font-mono break-all">{endpoint}</code>
            ) : (
              <>
                this profile&apos;s <code>host:port</code> (give the resource a hostname, or enter a host above)
              </>
            )}{" "}
            (<code>host:port</code>, <code>[v6]:port</code>, or a list of them). The key is reserved: a malformed value
            is refused when the secret is saved, and a secret without it is never released to a SQL session.
          </div>
        )}

        {errors.length > 0 && (
          <ul role="alert" className="list-disc pl-5 text-xs text-red-400" data-testid="sql-profile-errors">
            {errors.map((e, i) => (
              <li key={i} className="min-w-0 break-words">
                {e}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Modal>
  );
}
