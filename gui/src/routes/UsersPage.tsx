import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

export function UsersPage() {
  const { toast } = useToast();
  const [users, setUsers] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [mountPath] = useState("userpass/");
  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<string | null>(null);
  const [deleteUser, setDeleteUser] = useState<string | null>(null);

  // Available policies (fetched from vault, excluding "root")
  const [availablePolicies, setAvailablePolicies] = useState<string[]>([]);

  // Form state
  const [formUsername, setFormUsername] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formSelectedPolicies, setFormSelectedPolicies] = useState<string[]>([]);

  useEffect(() => {
    ensureMountAndLoad();
  }, [mountPath]);

  async function ensureMountAndLoad() {
    setLoading(true);
    try {
      const methods = await api.listAuthMethods();
      const mounted = methods.some((m) => m.path === mountPath);
      if (!mounted) {
        await api.enableAuthMethod("userpass/", "userpass", "Username & password authentication");
      }
    } catch {
      // fall through
    }
    await Promise.all([loadUsers(), loadPolicies()]);
  }

  async function loadUsers() {
    setLoading(true);
    try {
      const result = await api.listUsers(mountPath);
      setUsers(result.users);
    } catch {
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }

  async function loadPolicies() {
    try {
      const result = await api.listPolicies();
      // Filter out "root" — auth methods cannot create root tokens
      setAvailablePolicies(result.policies.filter((p) => p !== "root"));
    } catch {
      setAvailablePolicies([]);
    }
  }

  function togglePolicy(policy: string) {
    setFormSelectedPolicies((prev) =>
      prev.includes(policy)
        ? prev.filter((p) => p !== policy)
        : [...prev, policy],
    );
  }

  async function handleCreate() {
    try {
      const policies = formSelectedPolicies.join(",");
      await api.createUser(mountPath, formUsername, formPassword, policies);
      toast("success", `User ${formUsername} created`);
      setShowCreate(false);
      resetForm();
      loadUsers();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleEdit() {
    if (!editUser) return;
    try {
      const policies = formSelectedPolicies.join(",");
      await api.updateUser(mountPath, editUser, formPassword, policies);
      toast("success", `User ${editUser} updated`);
      setEditUser(null);
      resetForm();
      loadUsers();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteUser) return;
    try {
      await api.deleteUser(mountPath, deleteUser);
      toast("success", `User ${deleteUser} deleted`);
      setDeleteUser(null);
      loadUsers();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openEdit(username: string) {
    try {
      const info = await api.getUser(mountPath, username);
      setEditUser(username);
      setFormPassword("");
      setFormSelectedPolicies(info.policies);
      // Refresh policies in case new ones were added
      await loadPolicies();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openCreate() {
    setShowCreate(true);
    await loadPolicies();
  }

  function resetForm() {
    setFormUsername("");
    setFormPassword("");
    setFormSelectedPolicies([]);
  }

  function PolicySelector() {
    if (availablePolicies.length === 0) {
      return (
        <div>
          <label className="block text-sm text-[var(--color-text-muted)] mb-1">
            Policies
          </label>
          <p className="text-xs text-[var(--color-text-muted)]">
            No policies available. Create policies first from the Policies page.
          </p>
        </div>
      );
    }

    return (
      <div>
        <label className="block text-sm text-[var(--color-text-muted)] mb-1">
          Policies
        </label>
        <div className="flex flex-wrap gap-2">
          {availablePolicies.map((policy) => {
            const selected = formSelectedPolicies.includes(policy);
            return (
              <button
                key={policy}
                type="button"
                onClick={() => togglePolicy(policy)}
                className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                  selected
                    ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                    : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                }`}
              >
                {policy}
              </button>
            );
          })}
        </div>
        {formSelectedPolicies.length > 0 && (
          <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
            Selected: {formSelectedPolicies.join(", ")}
          </p>
        )}
      </div>
    );
  }

  const columns = [
    {
      key: "username",
      header: "Username",
      className: "font-mono text-[var(--color-primary)]",
      render: (user: string) => user,
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-32",
      render: (user: string) => (
        <div className="flex gap-1 justify-end">
          <Button variant="ghost" size="sm" onClick={() => openEdit(user)}>
            Edit
          </Button>
          <Button variant="danger" size="sm" onClick={() => setDeleteUser(user)}>
            Delete
          </Button>
        </div>
      ),
    },
  ];

  return (
    <Layout>
      <div className="max-w-4xl space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Users</h1>
          <Button size="sm" onClick={openCreate}>
            Create User
          </Button>
        </div>

        <Card>
          {loading ? (
            <p className="text-sm text-[var(--color-text-muted)] py-4">Loading...</p>
          ) : users.length === 0 ? (
            <EmptyState
              title="No users"
              description="Create your first user to enable username/password authentication"
              action={
                <Button size="sm" onClick={openCreate}>
                  Create User
                </Button>
              }
            />
          ) : (
            <Table
              columns={columns}
              data={users}
              rowKey={(u) => u}
            />
          )}
        </Card>

        {/* Create user modal */}
        <Modal
          open={showCreate}
          onClose={() => {
            setShowCreate(false);
            resetForm();
          }}
          title="Create User"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={!formUsername || !formPassword}>
                Create
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input
              label="Username"
              value={formUsername}
              onChange={(e) => setFormUsername(e.target.value)}
            />
            <Input
              label="Password"
              type="password"
              value={formPassword}
              onChange={(e) => setFormPassword(e.target.value)}
            />
            <PolicySelector />
          </div>
        </Modal>

        {/* Edit user modal */}
        <Modal
          open={editUser !== null}
          onClose={() => {
            setEditUser(null);
            resetForm();
          }}
          title={`Edit User: ${editUser}`}
          actions={
            <>
              <Button variant="ghost" onClick={() => setEditUser(null)}>
                Cancel
              </Button>
              <Button onClick={handleEdit}>Save</Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input
              label="New Password"
              type="password"
              value={formPassword}
              onChange={(e) => setFormPassword(e.target.value)}
              hint="Leave empty to keep current password"
            />
            <PolicySelector />
          </div>
        </Modal>

        {/* Delete confirmation */}
        <ConfirmModal
          open={deleteUser !== null}
          onClose={() => setDeleteUser(null)}
          onConfirm={handleDelete}
          title="Delete User"
          message={`Are you sure you want to delete user "${deleteUser}"? This action cannot be undone.`}
          confirmLabel="Delete"
        />
      </div>
    </Layout>
  );
}
