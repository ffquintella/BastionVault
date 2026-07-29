import { useCallback, useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Badge, Button, Card, Input, SecretInput, useToast } from "../components/ui";
import * as api from "../lib/api";
import type { MyProfile } from "../lib/api";
import { extractError } from "../lib/error";
import { checkPasswordPolicy, describePolicy } from "../lib/password";
import { usePasswordPolicyStore } from "../stores/passwordPolicyStore";

/**
 * My Profile — everything the signed-in operator can change about their own
 * account without an administrator.
 *
 * Three independent sections, each saving on its own so a failure in one does
 * not roll back another:
 *
 *  1. **Contact details** — email / phone. Informational only; the server
 *     never uses them for authentication or account recovery.
 *  2. **Password** — requires the current password. Only rendered when the
 *     server says the account has one to change (`can_change_password`):
 *     FIDO2-only accounts, disabled accounts, and non-userpass logins
 *     (AppRole / OIDC / root token) have no password here.
 *  3. **Default resource accounts** — the per-OS login names used by
 *     connection profiles whose credential source is "connecting user's
 *     default account", plus the optional stored Windows RDP password.
 *
 * Every call is caller-scoped server-side (`sys/identity/…/self`), so this
 * page cannot reach anyone else's record — it takes no username anywhere.
 * See `features/self-service-profile.md`.
 */
export function ProfilePage() {
  const { toast } = useToast();
  const [profile, setProfile] = useState<MyProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Contact form
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [savingContact, setSavingContact] = useState(false);

  // Password form
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [savingPassword, setSavingPassword] = useState(false);

  // Default resource accounts
  const [linux, setLinux] = useState("");
  const [macos, setMacos] = useState("");
  const [windows, setWindows] = useState("");
  const [winPassword, setWinPassword] = useState("");
  const [clearWinPassword, setClearWinPassword] = useState(false);
  const [savingAccounts, setSavingAccounts] = useState(false);

  const passwordPolicy = usePasswordPolicyStore((s) => s.policy);
  const loadPasswordPolicy = usePasswordPolicyStore((s) => s.load);
  useEffect(() => {
    loadPasswordPolicy();
  }, [loadPasswordPolicy]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const p = await api.getMyProfile();
      setProfile(p);
      setEmail(p.email);
      setPhone(p.phone);
      setLinux(p.default_account.linux);
      setMacos(p.default_account.macos);
      setWindows(p.default_account.windows);
      setWinPassword("");
      setClearWinPassword(false);
    } catch (e) {
      setError(extractError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function saveContact() {
    setSavingContact(true);
    try {
      await api.updateMyContact(email.trim(), phone.trim());
      toast("success", "Contact details updated");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSavingContact(false);
    }
  }

  async function savePassword() {
    if (newPassword !== confirmPassword) {
      toast("error", "The new password and its confirmation do not match");
      return;
    }
    setSavingPassword(true);
    try {
      await api.changeMyPassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      toast(
        "success",
        "Password changed. Sessions opened before this change keep working until they expire.",
      );
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSavingPassword(false);
    }
  }

  async function saveAccounts() {
    setSavingAccounts(true);
    try {
      // `undefined` keeps the stored password (the operator never sees it);
      // `""` clears it; a typed value replaces it.
      const pw = clearWinPassword ? "" : winPassword || undefined;
      await api.setMyDefaultAccount(linux.trim(), macos.trim(), windows.trim(), pw);
      toast("success", "Default resource accounts saved");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSavingAccounts(false);
    }
  }

  const policyDescription = describePolicy(passwordPolicy);
  const newPasswordCheck =
    newPassword.length > 0
      ? checkPasswordPolicy(newPassword, passwordPolicy)
      : { ok: false, failures: [] };
  const confirmMismatch =
    confirmPassword.length > 0 && confirmPassword !== newPassword;
  const passwordFormReady =
    currentPassword.length > 0 &&
    newPassword.length > 0 &&
    newPasswordCheck.ok &&
    !confirmMismatch &&
    confirmPassword === newPassword;

  const contactDirty =
    !!profile && (email.trim() !== profile.email || phone.trim() !== profile.phone);
  const accountsDirty =
    !!profile &&
    (linux.trim() !== profile.default_account.linux ||
      macos.trim() !== profile.default_account.macos ||
      windows.trim() !== profile.default_account.windows ||
      winPassword.length > 0 ||
      clearWinPassword);

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-xl font-semibold">My Profile</h2>
            <p className="text-sm text-[var(--color-text-muted)] mt-1">
              Your own account. Changes here affect only you — administrators
              manage other users under Admin → Users.
            </p>
          </div>
          <Button variant="secondary" size="sm" onClick={() => void load()} loading={loading}>
            Refresh
          </Button>
        </div>

        {error && (
          <Card>
            <p className="text-sm text-[var(--color-danger)]">{error}</p>
          </Card>
        )}

        {profile && (
          <>
            {/* Identity summary — read-only. */}
            <Card title="Signed in as">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <Field label="Username" value={profile.username || "—"} mono />
                <Field
                  label="Auth method"
                  value={profile.auth_mount || profile.auth_method || "—"}
                  mono
                />
                <Field
                  label="Policies"
                  value={
                    profile.policies.length > 0 ? (
                      <span className="flex flex-wrap gap-1">
                        {profile.policies.map((p) => (
                          <Badge key={p} label={p} variant="neutral" />
                        ))}
                      </span>
                    ) : (
                      "—"
                    )
                  }
                />
                <Field
                  label="Second factor"
                  value={
                    profile.fido2_enabled ? (
                      <Badge label="FIDO2 security key" variant="info" />
                    ) : profile.totp_mfa_enabled ? (
                      <Badge label="TOTP" variant="info" />
                    ) : (
                      "None"
                    )
                  }
                />
              </div>
            </Card>

            {/* 1. Contact details. */}
            <Card
              title="Contact details"
              actions={
                <Button
                  size="sm"
                  onClick={() => void saveContact()}
                  loading={savingContact}
                  disabled={!profile.can_edit_contact || !contactDirty}
                >
                  Save
                </Button>
              }
            >
              <p className="text-xs text-[var(--color-text-muted)] mb-3">
                How an administrator can reach you out-of-band. Informational
                only — never used for authentication, notifications, or account
                recovery.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <Input
                  label="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  disabled={!profile.can_edit_contact}
                />
                <Input
                  label="Phone"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="+55 21 0000-0000"
                  disabled={!profile.can_edit_contact}
                />
              </div>
            </Card>

            {/* 2. Password — only when this account actually has one. */}
            <Card
              title="Password"
              actions={
                profile.can_change_password ? (
                  <Button
                    size="sm"
                    onClick={() => void savePassword()}
                    loading={savingPassword}
                    disabled={!passwordFormReady}
                  >
                    Change password
                  </Button>
                ) : undefined
              }
            >
              {profile.can_change_password ? (
                <>
                  <p className="text-xs text-[var(--color-text-muted)] mb-3">
                    {policyDescription}. Your current password is required.
                    Sessions opened before the change keep working until they
                    expire.
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <SecretInput
                      label="Current password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                    />
                    <SecretInput
                      label="New password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      showGenerator
                      onGenerate={(v) => {
                        setNewPassword(v);
                        setConfirmPassword(v);
                      }}
                      error={
                        newPassword.length > 0 && !newPasswordCheck.ok
                          ? `Needs ${newPasswordCheck.failures.join(", ")}`
                          : undefined
                      }
                    />
                    <SecretInput
                      label="Confirm new password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      error={confirmMismatch ? "Does not match" : undefined}
                    />
                  </div>
                </>
              ) : (
                <p className="text-sm text-[var(--color-text-muted)]">
                  {profile.fido2_enabled
                    ? "This account signs in with a FIDO2 security key, so it has no password to change."
                    : profile.disabled
                      ? "This account is disabled. Contact an administrator."
                      : "This session was not opened with a username and password, so there is no password to change here."}
                </p>
              )}
            </Card>

            {/* 3. Default resource accounts. */}
            <Card
              title="Default resource accounts"
              actions={
                <Button
                  size="sm"
                  onClick={() => void saveAccounts()}
                  loading={savingAccounts}
                  disabled={!profile.can_edit_default_account || !accountsDirty}
                >
                  Save
                </Button>
              }
            >
              <p className="text-xs text-[var(--color-text-muted)] mb-3">
                The login name you use on target hosts, one per OS family. Used
                by resources whose connection profile picks the{" "}
                <em>connecting user's default account</em> credential source;
                every other profile is unaffected. Leave a field blank to leave
                that OS unconfigured.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <Input
                  label="Linux / Unix"
                  value={linux}
                  onChange={(e) => setLinux(e.target.value)}
                  placeholder="e.g. felipe-admin"
                  disabled={!profile.can_edit_default_account}
                />
                <Input
                  label="macOS"
                  value={macos}
                  onChange={(e) => setMacos(e.target.value)}
                  placeholder="e.g. felipe"
                  disabled={!profile.can_edit_default_account}
                />
                <Input
                  label="Windows"
                  value={windows}
                  onChange={(e) => setWindows(e.target.value)}
                  placeholder="e.g. CORP\felipe"
                  disabled={!profile.can_edit_default_account}
                />
              </div>
              <div className="mt-3">
                <SecretInput
                  label="Windows account password (optional)"
                  value={winPassword}
                  onChange={(e) => {
                    setWinPassword(e.target.value);
                    if (e.target.value) setClearWinPassword(false);
                  }}
                  showGenerator
                  onGenerate={(v) => setWinPassword(v)}
                  disabled={!profile.can_edit_default_account || clearWinPassword}
                  hint={
                    profile.default_account.has_windows_password
                      ? "A password is stored. Leave blank to keep it; type a new one to replace it. Used only for RDP default-account connections (SSH logins are always brokered)."
                      : "Optional. If set, RDP default-account connections use it instead of prompting. Leave blank to be prompted each time."
                  }
                />
                {profile.default_account.has_windows_password && (
                  <label className="mt-1 flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
                    <input
                      type="checkbox"
                      checked={clearWinPassword}
                      onChange={(e) => {
                        setClearWinPassword(e.target.checked);
                        if (e.target.checked) setWinPassword("");
                      }}
                    />
                    Clear the stored Windows password (revert to prompting at connect)
                  </label>
                )}
              </div>
            </Card>
          </>
        )}
      </div>
    </Layout>
  );
}

/** One read-only label/value row in the identity summary. */
function Field({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-[var(--color-text-muted)] mb-0.5">{label}</div>
      <div
        className={`text-sm text-[var(--color-text)] ${mono ? "font-mono truncate" : ""}`}
        title={mono && typeof value === "string" ? value : undefined}
      >
        {value}
      </div>
    </div>
  );
}
