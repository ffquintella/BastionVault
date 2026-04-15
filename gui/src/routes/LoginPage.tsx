import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import { useAuthStore } from "../stores/authStore";
import { useVaultStore } from "../stores/vaultStore";
import { useWebAuthn } from "../hooks/useWebAuthn";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type Tab = "token" | "userpass" | "fido2";

export function LoginPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
  const mode = useVaultStore((s) => s.mode);
  const { authenticate } = useWebAuthn();
  const [tab, setTab] = useState<Tab>("token");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Token form
  const [token, setToken] = useState("");

  // Userpass form
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  // FIDO2 form
  const [fido2Username, setFido2Username] = useState("");

  // Reset vault state
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [resetConfirmText, setResetConfirmText] = useState("");
  const [resetting, setResetting] = useState(false);

  async function handleTokenLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.loginToken(token);
      setAuth(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(extractError(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleUserpassLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.loginUserpass(username, password);
      setAuth(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(extractError(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleFido2Login(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await authenticate(fido2Username);
      setAuth(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(extractError(err));
    } finally {
      setLoading(false);
    }
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

  const tabs: { id: Tab; label: string }[] = [
    { id: "token", label: "Token" },
    { id: "userpass", label: "UserPass" },
    { id: "fido2", label: "FIDO2" },
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

      {tab === "userpass" && (
        <form onSubmit={handleUserpassLogin} className="space-y-4">
          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--color-primary)]"
            />
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
            />
          </div>
          <button
            type="submit"
            disabled={loading || !username || !password}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      )}

      {tab === "fido2" && (
        <form onSubmit={handleFido2Login} className="space-y-4">
          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Username
            </label>
            <input
              type="text"
              value={fido2Username}
              onChange={(e) => setFido2Username(e.target.value)}
              placeholder="alice"
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--color-primary)]"
            />
          </div>
          <p className="text-xs text-[var(--color-text-muted)]">
            Insert your security key and click the button below. Your browser will prompt you to tap your key.
          </p>
          <button
            type="submit"
            disabled={loading || !fido2Username}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Waiting for security key...
              </>
            ) : (
              "Authenticate with Security Key"
            )}
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
    </AuthLayout>
  );
}
