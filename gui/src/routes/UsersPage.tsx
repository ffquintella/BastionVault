import { useState, useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Badge,
  Input,
  SecretInput,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import { useWebAuthn } from "../hooks/useWebAuthn";
import { usePasswordPolicyStore } from "../stores/passwordPolicyStore";
import { useEntityDirectoryStore } from "../stores/entityDirectoryStore";
import { checkPasswordPolicy, describePolicy } from "../lib/password";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

export function UsersPage() {
  const { toast } = useToast();
  const { register: registerFido2 } = useWebAuthn();
  const [users, setUsers] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [mountPath] = useState("userpass/");
  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<string | null>(null);
  const [deleteUser, setDeleteUser] = useState<string | null>(null);

  // Available policies (fetched from vault, excluding "root")
  const [availablePolicies, setAvailablePolicies] = useState<string[]>([]);
  // Available child namespaces (multi-tenancy). Empty on single-tenant installs.
  const [availableNamespaces, setAvailableNamespaces] = useState<string[]>([]);

  // Form state
  const [formUsername, setFormUsername] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formSelectedPolicies, setFormSelectedPolicies] = useState<string[]>([]);
  // Allowed namespaces (login-restriction). Empty ⇒ unrestricted (any namespace).
  const [formSelectedNamespaces, setFormSelectedNamespaces] = useState<string[]>([]);
  // Per-OS default resource accounts (Resource Connect). Empty ⇒ unconfigured
  // for that OS family. Only consumed by `default-account` connection profiles.
  const [formDefaultAccountLinux, setFormDefaultAccountLinux] = useState("");
  const [formDefaultAccountMacos, setFormDefaultAccountMacos] = useState("");
  const [formDefaultAccountWindows, setFormDefaultAccountWindows] = useState("");
  // Windows RDP password for the default account. The stored value is never
  // read back (write-only from the admin's view); `…HasWinPw` reflects whether
  // one is on file, `…WinPw` is a new value to set, `…ClearWinPw` clears it.
  const [formDefaultAccountWinPw, setFormDefaultAccountWinPw] = useState("");
  const [formDefaultAccountHasWinPw, setFormDefaultAccountHasWinPw] = useState(false);
  const [formDefaultAccountClearWinPw, setFormDefaultAccountClearWinPw] = useState(false);

  // FIDO2 state for the edit modal
  const [editFido2Keys, setEditFido2Keys] = useState(0);
  const [editFido2Enabled, setEditFido2Enabled] = useState(false);

  // Account-state + TOTP MFA state for the edit modal
  const [editDisabled, setEditDisabled] = useState(false);
  const [editLocked, setEditLocked] = useState(false);
  const [editFailedCount, setEditFailedCount] = useState(0);
  const [editTotpMfaEnabled, setEditTotpMfaEnabled] = useState(false);
  const [editTotpMount, setEditTotpMount] = useState("");
  const [editTotpKey, setEditTotpKey] = useState("");

  // Mount-level account-security config (lockout + TOTP MFA).
  const [lockoutEnabled, setLockoutEnabled] = useState(true);
  const [lockoutMaxAttempts, setLockoutMaxAttempts] = useState(5);
  const [lockoutDurationSecs, setLockoutDurationSecs] = useState(900);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [mfaDefaultMount, setMfaDefaultMount] = useState("totp/");
  const [savingSecurity, setSavingSecurity] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [fido2Status, setFido2Status] = useState<string | null>(null);
  const [showDeleteKeys, setShowDeleteKeys] = useState(false);

  // PIN modal state
  const [pinModalOpen, setPinModalOpen] = useState(false);
  const [pinValue, setPinValue] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const pinInputRef = useRef<HTMLInputElement>(null);

  // Per-user FIDO2 key counts for the list display
  const [userFido2Info, setUserFido2Info] = useState<Record<string, number>>({});
  // Per-user status flags for the list display (disabled / locked / MFA).
  const [userFlags, setUserFlags] = useState<
    Record<string, { disabled: boolean; locked: boolean; mfa: boolean }>
  >({});

  // Minimum-password-composition policy.
  const passwordPolicy = usePasswordPolicyStore((s) => s.policy);
  const loadPasswordPolicy = usePasswordPolicyStore((s) => s.load);
  useEffect(() => {
    loadPasswordPolicy();
  }, [loadPasswordPolicy]);

  const policyDescription = describePolicy(passwordPolicy);
  // Live policy check for the create modal (password is always required).
  const createPasswordCheck = checkPasswordPolicy(formPassword, passwordPolicy);
  // Live policy check for the edit modal (blank = keep current, so blank is OK).
  const editPasswordEntered = formPassword.length > 0;
  const editPasswordCheck = editPasswordEntered
    ? checkPasswordPolicy(formPassword, passwordPolicy)
    : { ok: true, failures: [] };

  useEffect(() => {
    ensureMountAndLoad();
  }, [mountPath]);

  // Listen for FIDO2 status/PIN events
  useEffect(() => {
    if (!registering) {
      setFido2Status(null);
      setPinModalOpen(false);
      return;
    }
    const unlisten = listen<string>("fido2-status", (event) => {
      const s = event.payload;
      if (s === "insert-key") setFido2Status("Insert your security key...");
      else if (s === "tap-key") setFido2Status("Tap your security key now...");
      else if (s === "pin-required") setFido2Status("PIN required...");
      else if (s.startsWith("invalid-pin")) setFido2Status("Wrong PIN...");
      else if (s === "processing") { setFido2Status("Processing..."); setPinModalOpen(false); }
      else if (s === "complete") { setFido2Status(null); setPinModalOpen(false); }
      else setFido2Status(null);
    });
    return () => { unlisten.then(fn => fn()); };
  }, [registering]);

  useEffect(() => {
    const unlisten = listen<string>("fido2-pin-request", (event) => {
      const payload = event.payload;
      setPinValue("");
      setPinError(payload.startsWith("invalid-pin")
        ? `Wrong PIN. ${payload.split(":")[1] ? payload.split(":")[1] + " attempts remaining." : "Try again."}`
        : null);
      setPinModalOpen(true);
      setTimeout(() => pinInputRef.current?.focus(), 50);
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  async function handlePinSubmit() {
    if (!pinValue) return;
    setPinModalOpen(false);
    setPinError(null);
    try { await api.fido2SubmitPin(pinValue); } catch { /* */ }
    setPinValue("");
  }

  async function handlePinCancel() {
    setPinModalOpen(false);
    setPinError(null);
    setPinValue("");
    try { await api.fido2SubmitPin(""); } catch { /* */ }
  }

  async function ensureMountAndLoad() {
    setLoading(true);
    try {
      const methods = await api.listAuthMethods();
      const mounted = methods.some((m) => m.path === mountPath);
      if (!mounted) {
        try {
          await api.enableAuthMethod("userpass/", "userpass", "Username & password authentication");
        } catch (e) {
          toast(
            "error",
            `Could not enable userpass auth at ${mountPath}: ${extractError(e)}. ` +
              `Your token may lack permission on sys/auth/userpass.`,
          );
        }
      }
    } catch (e) {
      toast("error", `Could not list auth methods: ${extractError(e)}`);
    }
    await Promise.all([loadUsers(), loadPolicies(), loadNamespaces(), loadSecurityConfig()]);
  }

  async function loadSecurityConfig() {
    try {
      const [lockout, mfa] = await Promise.all([
        api.getLockoutConfig(mountPath),
        api.getMfaConfig(mountPath),
      ]);
      setLockoutEnabled(lockout.enabled);
      setLockoutMaxAttempts(lockout.max_failed_attempts);
      setLockoutDurationSecs(lockout.lockout_duration_secs);
      setMfaEnabled(mfa.enabled);
      setMfaDefaultMount(mfa.default_mount || "totp/");
    } catch {
      /* Non-admin tokens may lack read on config/*; leave defaults. */
    }
  }

  async function handleSaveSecurity() {
    setSavingSecurity(true);
    try {
      await api.setLockoutConfig(
        mountPath,
        lockoutEnabled,
        lockoutMaxAttempts,
        lockoutDurationSecs,
      );
      await api.setMfaConfig(mountPath, mfaEnabled, mfaDefaultMount);
      toast("success", "Account security settings saved");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSavingSecurity(false);
    }
  }

  async function handleUnlock() {
    if (!editUser) return;
    try {
      await api.unlockUser(mountPath, editUser);
      toast("success", `User ${editUser} unlocked`);
      setEditLocked(false);
      setEditFailedCount(0);
      loadUsers();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function loadUsers() {
    setLoading(true);
    try {
      const result = await api.listUsers(mountPath);
      setUsers(result.users);
      // Load FIDO2 info and status flags for each user.
      const info: Record<string, number> = {};
      const flags: Record<string, { disabled: boolean; locked: boolean; mfa: boolean }> = {};
      await Promise.all(
        result.users.map(async (u) => {
          try {
            const cred = await api.fido2ListCredentials(u);
            if (cred) info[u] = cred.registered_keys;
          } catch { /* */ }
          try {
            const ui = await api.getUser(mountPath, u);
            flags[u] = { disabled: ui.disabled, locked: ui.locked, mfa: ui.totp_mfa_enabled };
          } catch { /* */ }
        }),
      );
      setUserFido2Info(info);
      setUserFlags(flags);
    } catch {
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }

  async function loadPolicies() {
    try {
      const result = await api.listPolicies();
      setAvailablePolicies(result.policies.filter((p) => p !== "root"));
    } catch {
      setAvailablePolicies([]);
    }
  }

  async function loadNamespaces() {
    try {
      const result = await api.listNamespaces();
      setAvailableNamespaces(result.namespaces);
    } catch {
      setAvailableNamespaces([]);
    }
  }

  function togglePolicy(policy: string) {
    setFormSelectedPolicies((prev) =>
      prev.includes(policy)
        ? prev.filter((p) => p !== policy)
        : [...prev, policy],
    );
  }

  function toggleNamespace(ns: string) {
    setFormSelectedNamespaces((prev) =>
      prev.includes(ns) ? prev.filter((p) => p !== ns) : [...prev, ns],
    );
  }

  async function handleCreate() {
    // Enforce the minimum-password-composition policy at create time. The
    // backend does not know about this policy (it is a GUI-only UX rule),
    // so we block client-side.
    const check = checkPasswordPolicy(formPassword, passwordPolicy);
    if (!check.ok) {
      toast("error", `Password must include ${check.failures.join(", ")}.`);
      return;
    }
    try {
      const policies = formSelectedPolicies.join(",");
      await api.createUser(mountPath, formUsername, formPassword, policies);
      // Persist the namespace login-restriction (empty ⇒ unrestricted).
      await api.setNsAssignment(mountPath, formUsername, formSelectedNamespaces);
      toast("success", `User ${formUsername} created`);
      setShowCreate(false);
      resetForm();
      loadUsers();
      // The userpass create handler pre-provisions the entity alias
      // so the new login appears in share pickers without a relogin.
      // Refresh the cache so already-mounted EntityPickers / labels
      // pick it up immediately.
      useEntityDirectoryStore.getState().refresh().catch(() => {});
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleEdit() {
    if (!editUser) return;
    // If the password field is non-empty the user is actively changing the
    // password -- enforce the policy. A blank field means "keep current",
    // which bypasses the policy (since we are not writing a new password).
    if (formPassword.length > 0) {
      const check = checkPasswordPolicy(formPassword, passwordPolicy);
      if (!check.ok) {
        toast("error", `Password must include ${check.failures.join(", ")}.`);
        return;
      }
    }
    // A user with a TOTP second factor must have a key bound, or the backend
    // rejects the write. Block client-side with a clear message.
    if (editTotpMfaEnabled && !editTotpKey.trim()) {
      toast("error", "Enter a TOTP key name to require MFA for this user.");
      return;
    }
    try {
      const policies = formSelectedPolicies.join(",");
      await api.updateUser(mountPath, editUser, formPassword, policies, {
        disabled: editDisabled,
        totpMfaEnabled: editTotpMfaEnabled,
        totpMount: editTotpMount,
        totpKey: editTotpKey,
      });
      // Persist the namespace login-restriction (empty ⇒ clears it).
      await api.setNsAssignment(mountPath, editUser, formSelectedNamespaces);
      // Persist the per-OS default resource accounts (all-empty ⇒ clears them).
      // Password: a typed value sets it, the clear checkbox wipes it, otherwise
      // it is left untouched (undefined ⇒ the command omits the field).
      const windowsPassword =
        formDefaultAccountWinPw.length > 0
          ? formDefaultAccountWinPw
          : formDefaultAccountClearWinPw
            ? ""
            : undefined;
      await api.setDefaultAccount(
        mountPath,
        editUser,
        formDefaultAccountLinux,
        formDefaultAccountMacos,
        formDefaultAccountWindows,
        windowsPassword,
      );
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
      // Drop the deleted user from the picker cache.
      useEntityDirectoryStore.getState().refresh().catch(() => {});
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openEdit(username: string) {
    try {
      const [info, fido2Info, assignment, defaultAccount] = await Promise.all([
        api.getUser(mountPath, username),
        api.fido2ListCredentials(username).catch(() => null),
        api.getNsAssignment(mountPath, username).catch(() => ({ namespaces: [] })),
        api
          .getDefaultAccount(mountPath, username)
          .catch(() => ({
            linux: "",
            macos: "",
            windows: "",
            has_windows_password: false,
          })),
      ]);
      setEditUser(username);
      setFormPassword("");
      setFormSelectedPolicies(info.policies);
      setFormSelectedNamespaces(assignment.namespaces);
      setFormDefaultAccountLinux(defaultAccount.linux);
      setFormDefaultAccountMacos(defaultAccount.macos);
      setFormDefaultAccountWindows(defaultAccount.windows);
      setFormDefaultAccountWinPw("");
      setFormDefaultAccountHasWinPw(defaultAccount.has_windows_password);
      setFormDefaultAccountClearWinPw(false);
      setEditFido2Keys(fido2Info?.registered_keys ?? 0);
      setEditFido2Enabled(fido2Info?.fido2_enabled ?? false);
      setEditDisabled(info.disabled);
      setEditLocked(info.locked);
      setEditFailedCount(info.failed_login_count);
      setEditTotpMfaEnabled(info.totp_mfa_enabled);
      setEditTotpMount(info.totp_mount);
      setEditTotpKey(info.totp_key);
      await Promise.all([loadPolicies(), loadNamespaces()]);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openCreate() {
    setShowCreate(true);
    setFormSelectedNamespaces([]);
    await Promise.all([loadPolicies(), loadNamespaces()]);
  }

  function resetForm() {
    setFormUsername("");
    setFormPassword("");
    setFormSelectedPolicies([]);
    setFormSelectedNamespaces([]);
    setFormDefaultAccountLinux("");
    setFormDefaultAccountMacos("");
    setFormDefaultAccountWindows("");
    setFormDefaultAccountWinPw("");
    setFormDefaultAccountHasWinPw(false);
    setFormDefaultAccountClearWinPw(false);
    setEditFido2Keys(0);
    setEditFido2Enabled(false);
    setEditDisabled(false);
    setEditLocked(false);
    setEditFailedCount(0);
    setEditTotpMfaEnabled(false);
    setEditTotpMount("");
    setEditTotpKey("");
  }

  async function handleRegisterKey() {
    if (!editUser) return;
    setRegistering(true);
    try {
      await registerFido2(editUser);
      toast("success", "Security key registered");
      // Refresh FIDO2 info
      const cred = await api.fido2ListCredentials(editUser).catch(() => null);
      setEditFido2Keys(cred?.registered_keys ?? 0);
      setEditFido2Enabled(cred?.fido2_enabled ?? false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setRegistering(false);
    }
  }

  async function handleDeleteKeys() {
    if (!editUser) return;
    try {
      await api.fido2DeleteCredential(editUser);
      toast("success", "All security keys removed. Password login re-enabled.");
      setShowDeleteKeys(false);
      setEditFido2Keys(0);
      setEditFido2Enabled(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function PolicySelector() {
    if (availablePolicies.length === 0) {
      return (
        <div>
          <label className="block text-sm text-[var(--color-text-muted)] mb-1">Policies</label>
          <p className="text-xs text-[var(--color-text-muted)]">
            No policies available. Create policies first from the Policies page.
          </p>
        </div>
      );
    }

    return (
      <div>
        <label className="block text-sm text-[var(--color-text-muted)] mb-1">Policies</label>
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

  // Namespace login-restriction picker. Hidden on single-tenant installs (no
  // child namespaces). An empty selection means the user may authenticate into
  // any namespace; selecting one or more restricts login to those (and their
  // descendants). The root namespace is offered as the "root" chip (value "").
  function NamespaceSelector() {
    if (availableNamespaces.length === 0) return null;
    const options = ["", ...availableNamespaces];
    return (
      <div>
        <label className="block text-sm text-[var(--color-text-muted)] mb-1">
          Allowed namespaces
        </label>
        <div className="flex flex-wrap gap-2">
          {options.map((ns) => {
            const selected = formSelectedNamespaces.includes(ns);
            return (
              <button
                key={ns || "__root__"}
                type="button"
                onClick={() => toggleNamespace(ns)}
                className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                  selected
                    ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                    : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                }`}
              >
                {ns === "" ? "root" : ns}
              </button>
            );
          })}
        </div>
        <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
          {formSelectedNamespaces.length === 0
            ? "No restriction — this user may log in to any namespace."
            : `Login restricted to: ${formSelectedNamespaces.map((n) => n || "root").join(", ")} (and descendants).`}
        </p>
      </div>
    );
  }

  const columns = [
    {
      key: "username",
      header: "Username",
      className: "font-mono text-[var(--color-primary)]",
      render: (user: string) => (
        <span className="flex items-center gap-2">
          {user}
          {(userFido2Info[user] ?? 0) > 0 && (
            <Badge label={`${userFido2Info[user]} key${userFido2Info[user] > 1 ? "s" : ""}`} variant="info" />
          )}
          {userFlags[user]?.disabled && <Badge label="Disabled" variant="error" />}
          {userFlags[user]?.locked && <Badge label="Locked" variant="warning" />}
          {userFlags[user]?.mfa && <Badge label="MFA" variant="success" />}
        </span>
      ),
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
      <div className="space-y-4">
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
            <Table columns={columns} data={users} rowKey={(u) => u} />
          )}
        </Card>

        {/* Mount-level account-security policy (lockout + TOTP MFA). */}
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold">Account Security</h2>
            <Button size="sm" onClick={handleSaveSecurity} loading={savingSecurity}>
              Save
            </Button>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Lockout */}
            <div className="space-y-3">
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  checked={lockoutEnabled}
                  onChange={(e) => setLockoutEnabled(e.target.checked)}
                />
                Temporary account lockout
              </label>
              <p className="text-xs text-[var(--color-text-muted)]">
                Lock an account after too many consecutive failed password attempts.
              </p>
              <div className="grid grid-cols-2 gap-3">
                <Input
                  label="Max failed attempts"
                  type="number"
                  min={0}
                  value={String(lockoutMaxAttempts)}
                  onChange={(e) => setLockoutMaxAttempts(Number(e.target.value) || 0)}
                  disabled={!lockoutEnabled}
                />
                <Input
                  label="Lockout duration (seconds)"
                  type="number"
                  min={0}
                  value={String(lockoutDurationSecs)}
                  onChange={(e) => setLockoutDurationSecs(Number(e.target.value) || 0)}
                  disabled={!lockoutEnabled}
                />
              </div>
            </div>
            {/* TOTP MFA */}
            <div className="space-y-3">
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  checked={mfaEnabled}
                  onChange={(e) => setMfaEnabled(e.target.checked)}
                />
                TOTP multi-factor authentication
              </label>
              <p className="text-xs text-[var(--color-text-muted)]">
                Master switch. When on, users with MFA enabled must present a TOTP code
                at login. When off, TOTP is not required for anyone.
              </p>
              <Input
                label="Default TOTP engine mount"
                value={mfaDefaultMount}
                onChange={(e) => setMfaDefaultMount(e.target.value)}
                placeholder="totp/"
                disabled={!mfaEnabled}
              />
            </div>
          </div>
        </Card>

        {/* Create user modal */}
        <Modal
          open={showCreate}
          onClose={() => { setShowCreate(false); resetForm(); }}
          title="Create User"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button
                onClick={handleCreate}
                disabled={!formUsername || !formPassword || !createPasswordCheck.ok}
              >
                Create
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input label="Username" value={formUsername} onChange={(e) => setFormUsername(e.target.value)} />
            <SecretInput
              label="Password"
              value={formPassword}
              onChange={(e) => setFormPassword(e.target.value)}
              showGenerator
              onGenerate={(v) => setFormPassword(v)}
              hint={policyDescription}
              error={
                formPassword && !createPasswordCheck.ok
                  ? `Missing: ${createPasswordCheck.failures.join(", ")}`
                  : undefined
              }
            />
            <PolicySelector />
            <NamespaceSelector />
          </div>
        </Modal>

        {/* Edit user modal */}
        <Modal
          open={editUser !== null}
          onClose={() => { setEditUser(null); resetForm(); }}
          title={`Edit User: ${editUser}`}
          size="lg"
          actions={
            <>
              <Button variant="ghost" onClick={() => setEditUser(null)}>Cancel</Button>
              <Button onClick={handleEdit} disabled={!editPasswordCheck.ok}>
                Save
              </Button>
            </>
          }
        >
          <div className="space-y-4">
            {editFido2Enabled ? (
              <div>
                <label className="block text-sm text-[var(--color-text-muted)] mb-1">Password</label>
                <p className="text-xs text-[var(--color-text-muted)]">
                  Password login is disabled because this user has FIDO2 security keys. Remove all keys to re-enable password login.
                </p>
              </div>
            ) : (
              <SecretInput
                label="New Password"
                value={formPassword}
                onChange={(e) => setFormPassword(e.target.value)}
                showGenerator
                onGenerate={(v) => setFormPassword(v)}
                hint={
                  editPasswordEntered
                    ? policyDescription
                    : `Leave empty to keep current password. ${policyDescription}.`
                }
                error={
                  editPasswordEntered && !editPasswordCheck.ok
                    ? `Missing: ${editPasswordCheck.failures.join(", ")}`
                    : undefined
                }
              />
            )}
            <PolicySelector />
            <NamespaceSelector />

            {/* Account status: enable/disable + lockout. */}
            <div className="pt-3 border-t border-[var(--color-border)]">
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-[var(--color-text)]">Account Status</label>
                <div className="flex items-center gap-2">
                  {editDisabled && <Badge label="Disabled" variant="error" />}
                  {editLocked && <Badge label="Locked" variant="warning" />}
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm text-[var(--color-text)]">
                <input
                  type="checkbox"
                  checked={editDisabled}
                  onChange={(e) => setEditDisabled(e.target.checked)}
                />
                Disable this account (blocks all login, password and FIDO2)
              </label>
              <div className="mt-2 flex items-center gap-3">
                <p className="text-xs text-[var(--color-text-muted)]">
                  {editLocked
                    ? "Account is temporarily locked after repeated failed password attempts."
                    : `Failed attempts since last success: ${editFailedCount}.`}
                </p>
                {editLocked && (
                  <Button size="sm" variant="ghost" onClick={handleUnlock}>
                    Unlock now
                  </Button>
                )}
              </div>
            </div>

            {/* TOTP multi-factor authentication (per-user). */}
            <div className="pt-3 border-t border-[var(--color-border)]">
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-[var(--color-text)]">
                  TOTP Multi-Factor
                </label>
                {editTotpMfaEnabled && !mfaEnabled && (
                  <Badge label="MFA off globally" variant="warning" />
                )}
              </div>
              <label className="flex items-center gap-2 text-sm text-[var(--color-text)]">
                <input
                  type="checkbox"
                  checked={editTotpMfaEnabled}
                  onChange={(e) => setEditTotpMfaEnabled(e.target.checked)}
                />
                Require a TOTP code for this user
              </label>
              {editTotpMfaEnabled && (
                <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <Input
                    label="TOTP key name"
                    value={editTotpKey}
                    onChange={(e) => setEditTotpKey(e.target.value)}
                    placeholder="e.g. alice-mfa"
                  />
                  <Input
                    label={`TOTP engine mount (default ${mfaDefaultMount})`}
                    value={editTotpMount}
                    onChange={(e) => setEditTotpMount(e.target.value)}
                    placeholder={mfaDefaultMount}
                  />
                </div>
              )}
              <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
                Create the key in the TOTP secret engine and enroll it in the user's
                authenticator app.{" "}
                {mfaEnabled
                  ? "MFA is enabled globally, so this takes effect at next login."
                  : "MFA is disabled globally — enable it under Account Security below for this to apply."}
              </p>
            </div>

            {/* Default Resource Account section (Resource Connect). */}
            <div className="pt-3 border-t border-[var(--color-border)]">
              <label className="text-sm font-medium text-[var(--color-text)]">
                Default Resource Account
              </label>
              <p className="text-xs text-[var(--color-text-muted)] mt-1 mb-2">
                Optional. The login name this user connects with on resources
                whose connection profile uses the{" "}
                <em>connecting user's default account</em> credential source.
                One per OS family; leave blank to leave an OS unconfigured.
                Resources not using that source are unaffected.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <Input
                  label="Linux / Unix"
                  value={formDefaultAccountLinux}
                  onChange={(e) => setFormDefaultAccountLinux(e.target.value)}
                  placeholder="e.g. felipe-admin"
                />
                <Input
                  label="macOS"
                  value={formDefaultAccountMacos}
                  onChange={(e) => setFormDefaultAccountMacos(e.target.value)}
                  placeholder="e.g. felipe"
                />
                <Input
                  label="Windows"
                  value={formDefaultAccountWindows}
                  onChange={(e) => setFormDefaultAccountWindows(e.target.value)}
                  placeholder="e.g. CORP\\felipe"
                />
              </div>
              <div className="mt-3">
                <SecretInput
                  label="Windows account password (optional)"
                  value={formDefaultAccountWinPw}
                  onChange={(e) => {
                    setFormDefaultAccountWinPw(e.target.value);
                    if (e.target.value) setFormDefaultAccountClearWinPw(false);
                  }}
                  showGenerator
                  onGenerate={(v) => setFormDefaultAccountWinPw(v)}
                  disabled={formDefaultAccountClearWinPw}
                  hint={
                    formDefaultAccountHasWinPw
                      ? "A password is stored. Leave blank to keep it; type a new one to replace it. Used only for RDP default-account connections (SSH is always brokered)."
                      : "Optional. If set, RDP default-account connections use it instead of prompting at connect. Leave blank to prompt each time."
                  }
                />
                {formDefaultAccountHasWinPw && (
                  <label className="mt-1 flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
                    <input
                      type="checkbox"
                      checked={formDefaultAccountClearWinPw}
                      onChange={(e) => {
                        setFormDefaultAccountClearWinPw(e.target.checked);
                        if (e.target.checked) setFormDefaultAccountWinPw("");
                      }}
                    />
                    Clear the stored Windows password (revert to prompting at connect)
                  </label>
                )}
              </div>
            </div>

            {/* FIDO2 Security Keys section */}
            <div className="pt-3 border-t border-[var(--color-border)]">
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-[var(--color-text)]">Security Keys (FIDO2)</label>
                {editFido2Enabled && (
                  <Badge label="Password login disabled" variant="warning" />
                )}
              </div>

              {editFido2Keys > 0 ? (
                <div className="space-y-2">
                  <p className="text-sm text-[var(--color-text-muted)]">
                    {editFido2Keys} key{editFido2Keys > 1 ? "s" : ""} registered.
                    {editFido2Enabled && " Password login is disabled for this user."}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" onClick={handleRegisterKey} loading={registering}>
                      Register Another Key
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => setShowDeleteKeys(true)}>
                      Remove All Keys
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-sm text-[var(--color-text-muted)]">
                    No security keys registered. Register a key to enable passwordless FIDO2 authentication.
                  </p>
                  <Button size="sm" onClick={handleRegisterKey} loading={registering}>
                    Register Security Key
                  </Button>
                </div>
              )}

              {registering && fido2Status && (
                <div className="flex items-center gap-2 mt-2 text-sm text-[var(--color-text-muted)]">
                  <span className="w-4 h-4 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin" />
                  {fido2Status}
                </div>
              )}
            </div>
          </div>
        </Modal>

        {/* Delete user confirmation */}
        <ConfirmModal
          open={deleteUser !== null}
          onClose={() => setDeleteUser(null)}
          onConfirm={handleDelete}
          title="Delete User"
          message={`Are you sure you want to delete user "${deleteUser}"? This action cannot be undone.`}
          confirmLabel="Delete"
        />

        {/* Delete FIDO2 keys confirmation */}
        <ConfirmModal
          open={showDeleteKeys}
          onClose={() => setShowDeleteKeys(false)}
          onConfirm={handleDeleteKeys}
          title="Remove All Security Keys"
          message={`This will remove all FIDO2 security keys for "${editUser}" and re-enable password login.`}
          confirmLabel="Remove Keys"
        />

        {/* PIN Entry Modal */}
        <Modal
          open={pinModalOpen}
          onClose={handlePinCancel}
          title="Security Key PIN"
          size="sm"
          actions={
            <>
              <Button variant="ghost" onClick={handlePinCancel}>Cancel</Button>
              <Button onClick={handlePinSubmit} disabled={!pinValue}>Submit</Button>
            </>
          }
        >
          <div className="space-y-3">
            <p className="text-sm text-[var(--color-text-muted)]">
              Your security key requires a PIN to continue.
            </p>
            {pinError && <p className="text-sm text-[var(--color-danger)] font-medium">{pinError}</p>}
            <input
              ref={pinInputRef}
              type="password"
              value={pinValue}
              onChange={(e) => setPinValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && pinValue) handlePinSubmit(); }}
              placeholder="Enter PIN"
              className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
              autoComplete="off"
            />
          </div>
        </Modal>
      </div>
    </Layout>
  );
}
