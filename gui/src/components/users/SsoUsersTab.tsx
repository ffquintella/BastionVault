import { useEffect, useState } from "react";
import {
  Badge,
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  Input,
  Modal,
  Table,
  useToast,
} from "../ui";
import * as api from "../../lib/api";
import type { SsoUserInfo } from "../../lib/types";
import { extractError, isRouteUnsupported } from "../../lib/error";
import { NamespaceAccessSelector } from "./NamespaceAccessSelector";

/** `oidc/alice` — the directory's own key for a record. */
const rowKey = (u: SsoUserInfo) => `${u.mount}${u.username}`;

/** A login timestamp in the viewer's locale, or a dash when there is none. */
export function formatLoginTime(ts: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

/** `OIDC · default`: how the user signs in and through which role. */
export function providerLabel(u: SsoUserInfo): string {
  const method = (u.auth_method || u.mount.replace(/\/$/, "")).toUpperCase();
  return u.role ? `${method} · ${u.role}` : method;
}

function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x) => b.includes(x));
}

type LoadState =
  | { kind: "loading" }
  | { kind: "ok" }
  | { kind: "unsupported" }
  | { kind: "error"; message: string };

/**
 * The Users page's "SSO Users" tab: people who signed in through an OIDC or
 * SAML provider (`v2/sys/sso/users`). Records are created by the sign-in
 * itself; here an admin sets the namespaces each may reach and an e-mail.
 */
export function SsoUsersTab({ availableNamespaces }: { availableNamespaces: string[] }) {
  const { toast } = useToast();
  const [users, setUsers] = useState<SsoUserInfo[]>([]);
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [editing, setEditing] = useState<SsoUserInfo | null>(null);
  const [email, setEmail] = useState("");
  const [namespaces, setNamespaces] = useState<string[]>([]);
  // `null`: the assignment could not be read, so saving must not write one
  // (an empty write clears it, which would widen where the user may log in).
  const [loadedNamespaces, setLoadedNamespaces] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<SsoUserInfo | null>(null);

  async function load() {
    setState({ kind: "loading" });
    try {
      setUsers(await api.listSsoUsers());
      setState({ kind: "ok" });
    } catch (e) {
      setUsers([]);
      setState(isRouteUnsupported(e) ? { kind: "unsupported" } : { kind: "error", message: extractError(e) });
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function openEdit(u: SsoUserInfo) {
    let assigned: string[] | null = null;
    try {
      assigned = (await api.getNsAssignment(u.mount, u.username)).namespaces;
    } catch (e) {
      toast("error", `Could not read namespace access: ${extractError(e)}`);
    }
    setEmail(u.email);
    setNamespaces(assigned ?? []);
    setLoadedNamespaces(assigned);
    setEditing(u);
  }

  function toggleNamespace(ns: string) {
    setNamespaces((prev) => (prev.includes(ns) ? prev.filter((p) => p !== ns) : [...prev, ns]));
  }

  async function handleSave() {
    if (!editing) return;
    setSaving(true);
    try {
      if (email.trim() !== editing.email) {
        await api.updateSsoUser(editing.mount, editing.username, email.trim());
      }
      if (loadedNamespaces !== null && !sameSet(namespaces, loadedNamespaces)) {
        await api.setNsAssignment(editing.mount, editing.username, namespaces);
      }
      toast("success", `SSO user ${editing.username} updated`);
      setEditing(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    if (!removing) return;
    try {
      await api.deleteSsoUser(removing.mount, removing.username);
      toast("success", `SSO user ${removing.username} removed from the directory`);
      setRemoving(null);
      await load();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  const columns = [
    {
      key: "username",
      header: "User",
      className: "w-1/3",
      render: (u: SsoUserInfo) => (
        <span className="flex items-center gap-2 min-w-0">
          <span className="truncate font-mono text-[var(--color-primary)]" title={u.username}>
            {u.username}
          </span>
          <Badge label="SSO" variant="info" />
        </span>
      ),
    },
    {
      key: "provider",
      header: "Provider",
      render: (u: SsoUserInfo) => <span className="truncate">{providerLabel(u)}</span>,
    },
    {
      key: "email",
      header: "Email",
      render: (u: SsoUserInfo) => (
        <span className="block truncate text-[var(--color-text-muted)]" title={u.email}>
          {u.email || "—"}
        </span>
      ),
    },
    {
      key: "last_login",
      header: "Last login",
      render: (u: SsoUserInfo) => (
        <span className="whitespace-nowrap" title={`${u.login_count} sign-in(s)`}>
          {formatLoginTime(u.last_login)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-32",
      render: (u: SsoUserInfo) => (
        <div className="flex gap-1 justify-end">
          <Button variant="ghost" size="sm" onClick={() => openEdit(u)}>
            Edit
          </Button>
          <Button variant="danger" size="sm" onClick={() => setRemoving(u)}>
            Remove
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <Card>
        <div className="flex items-center justify-between gap-3 mb-3">
          <p className="text-sm text-[var(--color-text-muted)] min-w-0">
            People who signed in through an SSO provider (OIDC or SAML). A record is
            created by the first successful sign-in; it holds no password, and access
            still comes from the provider and the SSO role.
          </p>
          <Button size="sm" variant="ghost" onClick={() => void load()}>
            Refresh
          </Button>
        </div>
        {state.kind === "loading" ? (
          <p className="text-sm text-[var(--color-text-muted)] py-4">Loading...</p>
        ) : state.kind === "unsupported" ? (
          <p className="text-sm text-[var(--color-text-muted)] py-4">
            This server has no SSO user directory yet. Upgrade it to list SSO users here.
          </p>
        ) : state.kind === "error" ? (
          <p className="text-sm text-[var(--color-danger)] py-4">
            Could not load SSO users: {state.message}
          </p>
        ) : users.length === 0 ? (
          <EmptyState
            title="No SSO users yet"
            description="Users appear here after their first successful OIDC or SAML sign-in."
          />
        ) : (
          <Table columns={columns} data={users} rowKey={rowKey} tableClassName="table-fixed" />
        )}
      </Card>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={`Edit SSO User: ${editing?.username ?? ""}`}
        size="lg"
        actions={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)}>
              Cancel
            </Button>
            <Button onClick={handleSave} loading={saving}>
              Save
            </Button>
          </>
        }
      >
        {editing && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="min-w-0">
                <p className="text-[var(--color-text-muted)]">Provider</p>
                <p className="truncate">{providerLabel(editing)}</p>
              </div>
              <div className="min-w-0">
                <p className="text-[var(--color-text-muted)]">Subject</p>
                <p className="truncate font-mono" title={editing.subject}>
                  {editing.subject || "—"}
                </p>
              </div>
              <div className="min-w-0">
                <p className="text-[var(--color-text-muted)]">First login</p>
                <p className="truncate">{formatLoginTime(editing.first_login)}</p>
              </div>
              <div className="min-w-0">
                <p className="text-[var(--color-text-muted)]">Last login</p>
                <p className="truncate">
                  {formatLoginTime(editing.last_login)} ({editing.login_count} sign-in
                  {editing.login_count === 1 ? "" : "s"})
                </p>
              </div>
            </div>

            <p className="text-xs text-[var(--color-text-muted)]">
              SSO users have no password here. Their policies come from the SSO role;
              this dialog sets where they may sign in and how to reach them.
            </p>

            {loadedNamespaces === null ? (
              <p className="text-xs text-[var(--color-danger)]">
                Namespace access could not be read, so it is left unchanged.
              </p>
            ) : availableNamespaces.length === 0 ? (
              <p className="text-xs text-[var(--color-text-muted)]">
                No child namespaces exist, so there is no namespace access to restrict.
              </p>
            ) : (
              <NamespaceAccessSelector
                label="Namespace access"
                available={availableNamespaces}
                selected={namespaces}
                onToggle={toggleNamespace}
              />
            )}

            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Input
                  label="Email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="e.g. user@example.com"
                />
                <p className="text-xs text-[var(--color-text-muted)] mt-1">
                  {editing.email_source === "admin"
                    ? "Set by an administrator and kept across sign-ins. Clear it to let the provider supply one."
                    : "Supplied by the identity provider at sign-in. Editing it keeps your value from then on."}
                </p>
              </div>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmModal
        open={removing !== null}
        onClose={() => setRemoving(null)}
        onConfirm={handleRemove}
        title="Remove SSO User"
        message={`Remove "${removing?.username ?? ""}" from the SSO user directory? They can still sign in through the identity provider, which recreates the record. Their namespace access and shares are kept.`}
        confirmLabel="Remove"
      />
    </>
  );
}
