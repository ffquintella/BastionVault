import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { listen } from "@tauri-apps/api/event";
import { open as shellOpen } from "@tauri-apps/plugin-shell";
import { AuthLayout } from "../components/AuthLayout";
import { Modal } from "../components/ui";
import { useAuthStore } from "../stores/authStore";
import { useVaultStore } from "../stores/vaultStore";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type Tab = "token" | "login" | "oidc";
type LoginStep = "username" | "password";

interface SsoProviderOption {
  mount: string;
  name: string;
  kind: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
  const loadEntity = useAuthStore((s) => s.loadEntity);
  const rememberSession = useAuthStore((s) => s.rememberSession);

  /**
   * Run after every successful login (Token, UserPass, FIDO2, SSO).
   * Updates the auth store, kicks off the best-effort entity-self
   * fetch, AND stashes the session under the current vault's
   * `last_used_id` so the Switch-vault flow can resume without a
   * re-login next time. Silent failure to resolve the vault id
   * just means the session isn't cached — login still works.
   */
  async function finalizeLogin(token: string, policies: string[]) {
    setAuth(token, policies);
    try {
      const list = await api.listVaultProfiles();
      if (list.lastUsedId) {
        // Wait for loadEntity so the entity_id also makes it into
        // the cached session — otherwise the first Switch-back
        // loses ownership attribution until the next loadEntity
        // round-trip.
        await loadEntity();
        rememberSession(list.lastUsedId);
      } else {
        loadEntity().catch(() => {});
      }
    } catch {
      loadEntity().catch(() => {});
    }
  }
  const mode = useVaultStore((s) => s.mode);
  const [tab, setTab] = useState<Tab>("login");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Token form
  const [token, setToken] = useState("");

  // Unified login form
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginStep, setLoginStep] = useState<LoginStep>("username");
  const [fido2Status, setFido2Status] = useState<string | null>(null);

  // PIN modal state
  const [pinModalOpen, setPinModalOpen] = useState(false);
  const [pinValue, setPinValue] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const pinInputRef = useRef<HTMLInputElement>(null);

  // Reset vault state
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [resetConfirmText, setResetConfirmText] = useState("");
  const [resetting, setResetting] = useState(false);

  // SSO state. The login page never asks the user for mount/role —
  // an admin configures those once via the Settings page + the per-
  // mount auth backend, and the user just picks a provider by name.
  // Providers come from the unauth `sys/sso/providers` endpoint,
  // which returns the empty list when SSO is globally disabled
  // (→ the SSO tab is hidden entirely).
  const [ssoProviders, setSsoProviders] = useState<SsoProviderOption[]>([]);
  const [ssoLoaded, setSsoLoaded] = useState(false);
  const [oidcPhase, setOidcPhase] = useState<"idle" | "consent">("idle");
  const [pendingMount, setPendingMount] = useState<string | null>(null);

  // Fetch the SSO provider list on mount. Failure is silent — we
  // just end up with an empty list, the SSO tab hides, and the user
  // falls back to token/password. Backend returns `{enabled, providers}`
  // but a disabled toggle also produces an empty list, so we only
  // need to check the array.
  useEffect(() => {
    let cancelled = false;
    api
      .listSsoProviders()
      .then((result) => {
        if (cancelled) return;
        setSsoProviders(result.enabled ? result.providers : []);
        setSsoLoaded(true);
      })
      .catch(() => {
        if (cancelled) return;
        setSsoProviders([]);
        setSsoLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // If the active tab is SSO but providers disappeared (admin
  // disabled it between loads, or mount was removed), bounce the
  // user back to the default login tab.
  useEffect(() => {
    if (ssoLoaded && tab === "oidc" && ssoProviders.length === 0) {
      setTab("login");
    }
  }, [ssoLoaded, tab, ssoProviders.length]);

  // Listen for FIDO2 status and PIN events
  useEffect(() => {
    const unlistenStatus = listen<string>("fido2-status", (event) => {
      const status = event.payload;
      if (status === "insert-key") setFido2Status("Insert your security key...");
      else if (status === "tap-key") setFido2Status("Tap your security key now...");
      else if (status === "pin-required") setFido2Status("PIN required...");
      else if (status.startsWith("invalid-pin")) setFido2Status("Wrong PIN...");
      else if (status === "pin-auth-blocked") setFido2Status("Too many failed attempts. Unplug and re-insert your key.");
      else if (status === "pin-blocked") setFido2Status("PIN is blocked. Reset your security key.");
      else if (status === "processing") { setFido2Status("Processing..."); setPinModalOpen(false); }
      else if (status === "complete") { setFido2Status(null); setPinModalOpen(false); }
      else setFido2Status(null);
    });
    const unlistenPin = listen<string>("fido2-pin-request", (event) => {
      const payload = event.payload;
      setPinValue("");
      if (payload.startsWith("invalid-pin")) {
        const attempts = payload.split(":")[1];
        setPinError(attempts ? `Wrong PIN. ${attempts} attempts remaining.` : "Wrong PIN. Try again.");
      } else {
        setPinError(null);
      }
      setPinModalOpen(true);
      setTimeout(() => pinInputRef.current?.focus(), 50);
    });
    return () => {
      unlistenStatus.then(fn => fn());
      unlistenPin.then(fn => fn());
    };
  }, []);

  async function handlePinSubmit() {
    if (!pinValue) return;
    setPinModalOpen(false);
    setPinError(null);
    try { await api.fido2SubmitPin(pinValue); } catch { /* ceremony handles */ }
    setPinValue("");
  }

  async function handlePinCancel() {
    setPinModalOpen(false);
    setPinError(null);
    setPinValue("");
    try { await api.fido2SubmitPin(""); } catch { /* ignore */ }
  }

  /**
   * Run the OIDC consent flow in three steps:
   *   1. `oidcLoginStart` binds a loopback listener and asks the
   *      vault's `auth/<mount>/auth_url` endpoint for the IdP URL.
   *   2. Open that URL in the user's real system browser via the
   *      Tauri shell plugin — gets them the familiar IdP consent
   *      page with their existing signed-in session rather than
   *      a blank Tauri popup.
   *   3. `oidcLoginComplete` blocks on the loopback accept loop,
   *      POSTs the returned `code` + `state` to the vault's
   *      `callback`, and returns the minted vault token.
   *
   * Cancellation / transient errors release the loopback listener
   * via `oidcLoginCancel` so the OS port isn't held open for the
   * 5-minute default timeout. The phase state drives the in-flight
   * status text ("Waiting for browser callback…").
   */
  async function handleSsoLogin(provider: SsoProviderOption) {
    setLoading(true);
    setError(null);
    setPendingMount(provider.mount);
    let sessionId: string | null = null;
    try {
      // Role is deliberately omitted — the vault resolves it via
      // `OidcConfig.default_role` on the mount. Admin-side config
      // is the single source of truth for what role an SSO login
      // maps to.
      const start = await api.oidcLoginStart({ mount: provider.mount });
      sessionId = start.sessionId;
      setOidcPhase("consent");
      await shellOpen(start.authUrl);
      const result = await api.oidcLoginComplete({ sessionId });
      await finalizeLogin(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(extractError(err));
      if (sessionId) {
        try {
          await api.oidcLoginCancel(sessionId);
        } catch {
          /* best-effort cleanup */
        }
      }
    } finally {
      setOidcPhase("idle");
      setPendingMount(null);
      setLoading(false);
    }
  }

  async function handleTokenLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.loginToken(token);
      await finalizeLogin(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(extractError(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleContinue(e: React.FormEvent) {
    e.preventDefault();
    if (!username) return;
    setLoading(true);
    setError(null);
    try {
      // Try to start FIDO2 login — if user has keys, this succeeds
      await api.fido2NativeLogin(username).then(async (result) => {
        await finalizeLogin(result.token, result.policies);
        navigate("/dashboard");
      });
    } catch (fido2Err: unknown) {
      const errMsg = extractError(fido2Err);
      // If the error indicates no FIDO2 keys or FIDO2 not set up, fall back to password
      const lower = errMsg.toLowerCase();
      if (lower.includes("credential not found") || lower.includes("not configured") || lower.includes("no credentials") || lower.includes("no security key")) {
        setLoginStep("password");
        setLoading(false);
        return;
      }
      // Real FIDO2 error (cancelled, PIN blocked, etc.)
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  }

  async function handlePasswordLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.loginUserpass(username, password);
      await finalizeLogin(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(extractError(err));
    } finally {
      setLoading(false);
    }
  }

  function handleBack() {
    setLoginStep("username");
    setPassword("");
    setError(null);
  }

  function handleSwitchVault() {
    navigate("/connect?choose=1");
  }

  async function handleReset() {
    setResetting(true);
    setError(null);
    try {
      await api.resetVault();
      setShowResetConfirm(false);
      setResetConfirmText("");
      navigate("/init");
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setResetting(false);
    }
  }

  // The SSO tab only surfaces when the admin toggle is on AND at
  // least one SSO-capable auth mount is configured. Zero providers
  // ⇒ hide entirely — the login page should never advertise a
  // feature the user can't actually use.
  const tabs: { id: Tab; label: string }[] = [
    { id: "login", label: "Login" },
    { id: "token", label: "Token" },
    ...(ssoProviders.length > 0
      ? [{ id: "oidc" as const, label: "SSO" }]
      : []),
  ];

  return (
    <AuthLayout title="Sign In" subtitle="Authenticate to your vault">
      {/* Tabs */}
      <div className="flex border-b border-[var(--color-border)] mb-4 -mx-6 px-6">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => {
              setTab(t.id);
              setError(null);
              setLoginStep("username");
              setPassword("");
            }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === t.id
                ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                : "border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {tab === "token" && (
        <form onSubmit={handleTokenLogin} className="space-y-4">
          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Token
            </label>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="hvs.xxxxx..."
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--color-primary)]"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !token}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      )}

      {tab === "oidc" && (
        <div className="space-y-3">
          <p className="text-xs text-[var(--color-text-muted)]">
            Sign in through your organization's identity provider. A new
            browser window will open for consent; come back here once
            you've approved.
          </p>
          <div className="space-y-2">
            {ssoProviders.map((p) => {
              const isPending = pendingMount === p.mount;
              return (
                <button
                  key={p.mount}
                  type="button"
                  onClick={() => handleSsoLogin(p)}
                  disabled={loading}
                  className="w-full py-2.5 px-4 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors text-left flex items-center justify-between gap-2"
                >
                  <span>
                    {isPending
                      ? oidcPhase === "consent"
                        ? `Waiting for ${p.name}…`
                        : `Opening ${p.name}…`
                      : `Sign in with ${p.name}`}
                  </span>
                  {isPending && (
                    <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin shrink-0" />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {tab === "login" && loginStep === "username" && (
        <form onSubmit={handleContinue} className="space-y-4">
          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="alice"
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--color-primary)]"
              autoFocus
            />
          </div>
          <p className="text-xs text-[var(--color-text-muted)]">
            If your account has a security key, you'll be prompted to use it. Otherwise, you'll enter your password.
          </p>
          <button
            type="submit"
            disabled={loading || !username}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                {fido2Status || "Checking for security key..."}
              </>
            ) : (
              "Continue"
            )}
          </button>
        </form>
      )}

      {tab === "login" && loginStep === "password" && (
        <form onSubmit={handlePasswordLogin} className="space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <button
              type="button"
              onClick={handleBack}
              className="text-[var(--color-text-muted)] hover:text-[var(--color-text)] text-sm"
            >
              &larr;
            </button>
            <span className="text-sm text-[var(--color-text-muted)]">
              Signing in as <span className="text-[var(--color-text)] font-medium">{username}</span>
            </span>
          </div>
          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--color-primary)]"
              autoFocus
            />
          </div>
          <button
            type="submit"
            disabled={loading || !password}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      )}

      {/* Footer actions */}
      <div className="mt-6 pt-4 border-t border-[var(--color-border)] flex items-center justify-between">
        <button
          onClick={handleSwitchVault}
          className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
        >
          Switch vault
        </button>

        {mode === "Embedded" && (
          <>
            {!showResetConfirm ? (
              <button
                onClick={() => setShowResetConfirm(true)}
                className="text-xs text-red-400/60 hover:text-red-400 transition-colors"
              >
                Reset vault
              </button>
            ) : null}
          </>
        )}
      </div>

      {/* Reset confirmation */}
      {showResetConfirm && (
        <div className="mt-3 p-4 bg-red-500/10 border border-red-500/30 rounded-lg space-y-3">
          <div className="flex items-start gap-2">
            <span className="text-red-400 text-lg leading-none mt-0.5">!</span>
            <div>
              <p className="text-red-400 font-medium text-sm">
                This will permanently destroy all vault data
              </p>
              <p className="text-red-400/70 text-xs mt-1">
                All secrets, keys, users, policies, and configuration will be
                irreversibly deleted. This cannot be undone.
              </p>
            </div>
          </div>

          <div>
            <label className="block text-xs text-red-400/70 mb-1">
              Type <span className="font-mono font-bold">RESET</span> to confirm
            </label>
            <input
              type="text"
              value={resetConfirmText}
              onChange={(e) => setResetConfirmText(e.target.value)}
              placeholder="RESET"
              className="w-full bg-[var(--color-bg)] border border-red-500/30 rounded-lg px-3 py-2 text-sm font-mono text-red-400 placeholder:text-red-400/30"
            />
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => {
                setShowResetConfirm(false);
                setResetConfirmText("");
              }}
              className="flex-1 py-2 bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] rounded-lg text-sm transition-colors hover:bg-[var(--color-border)]"
            >
              Cancel
            </button>
            <button
              onClick={handleReset}
              disabled={resetConfirmText !== "RESET" || resetting}
              className="flex-1 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              {resetting ? "Resetting..." : "Destroy & Reset"}
            </button>
          </div>
        </div>
      )}

      {/* PIN Entry Modal */}
      <Modal
        open={pinModalOpen}
        onClose={handlePinCancel}
        title="Security Key PIN"
        size="sm"
        actions={
          <>
            <button
              onClick={handlePinCancel}
              className="px-4 py-2 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handlePinSubmit}
              disabled={!pinValue}
              className="px-4 py-2 text-sm bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
            >
              Submit
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            Your security key requires a PIN to continue.
          </p>
          {pinError && (
            <p className="text-sm text-red-400 font-medium">
              {pinError}
            </p>
          )}
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
    </AuthLayout>
  );
}
