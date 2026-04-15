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

export function UsersPage() {
  const { toast } = useToast();
  const [users, setUsers] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [mountPath] = useState("userpass/");
  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<string | null>(null);
  const [deleteUser, setDeleteUser] = useState<string | null>(null);

  // Form state
  const [formUsername, setFormUsername] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formPolicies, setFormPolicies] = useState("");

  useEffect(() => {
    loadUsers();
  }, [mountPath]);

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

  async function handleCreate() {
    try {
      await api.createUser(mountPath, formUsername, formPassword, formPolicies);
      toast("success", `User ${formUsername} created`);
      setShowCreate(false);
      resetForm();
      loadUsers();
    } catch (e: unknown) {
      toast("error", String(e));
    }
  }

  async function handleEdit() {
    if (!editUser) return;
    try {
      await api.updateUser(mountPath, editUser, formPassword, formPolicies);
      toast("success", `User ${editUser} updated`);
      setEditUser(null);
      resetForm();
      loadUsers();
    } catch (e: unknown) {
      toast("error", String(e));
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
      toast("error", String(e));
    }
  }

  async function openEdit(username: string) {
    try {
      const info = await api.getUser(mountPath, username);
      setEditUser(username);
      setFormPassword("");
      setFormPolicies(info.policies.join(", "));
    } catch (e: unknown) {
      toast("error", String(e));
    }
  }

  function resetForm() {
    setFormUsername("");
    setFormPassword("");
    setFormPolicies("");
  }

  const columns = [
    {
      key: "username",
      header: "Username",
      className: "font-mono text-[var(--color-primary)]",
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
          <Button size="sm" onClick={() => setShowCreate(true)}>
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
                <Button size="sm" onClick={() => setShowCreate(true)}>
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
            <Input
              label="Policies"
              value={formPolicies}
              onChange={(e) => setFormPolicies(e.target.value)}
              hint="Comma-separated list of policy names"
            />
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
            <Input
              label="Policies"
              value={formPolicies}
              onChange={(e) => setFormPolicies(e.target.value)}
              hint="Comma-separated list of policy names"
            />
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
