import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import { useAuthStore } from "../stores/authStore";
import { useWebAuthn } from "../hooks/useWebAuthn";
import * as api from "../lib/api";

type Tab = "token" | "userpass" | "fido2";

export function LoginPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
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

  async function handleTokenLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.loginToken(token);
      setAuth(result.token, result.policies);
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(String(err));
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
      setError(String(err));
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
      setError(String(err));
    } finally {
      setLoading(false);
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
    </AuthLayout>
  );
}
