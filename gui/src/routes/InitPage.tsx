import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import { useAuthStore } from "../stores/authStore";
import * as api from "../lib/api";

export function InitPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
  const [loading, setLoading] = useState(false);
  const [rootToken, setRootToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleInit() {
    setLoading(true);
    setError(null);
    try {
      const result = await api.initVault();
      setRootToken(result.root_token);
    } catch (e: unknown) {
      setError(String(e));
      setLoading(false);
    }
  }

  function handleContinue() {
    if (rootToken) {
      setAuth(rootToken, ["root"]);
      navigate("/dashboard");
    }
  }

  if (rootToken) {
    return (
      <AuthLayout
        title="Vault Initialized"
        subtitle="Save your root token securely"
      >
        <div className="space-y-4">
          <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
            Your root token has been saved to the OS keychain. You can also copy
            it below for safekeeping.
          </div>

          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Root Token
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                readOnly
                value={rootToken}
                className="flex-1 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono"
              />
              <button
                onClick={() => navigator.clipboard.writeText(rootToken)}
                className="px-3 py-2 bg-[var(--color-surface-hover)] border border-[var(--color-border)] rounded-lg text-sm hover:bg-[var(--color-border)] transition-colors"
              >
                Copy
              </button>
            </div>
          </div>

          <button
            onClick={handleContinue}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white rounded-lg font-medium transition-colors"
          >
            Continue to Dashboard
          </button>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Initialize Vault"
      subtitle="First-time setup for your local vault"
    >
      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <p className="text-sm text-[var(--color-text-muted)]">
          This will create an encrypted vault on your device. The unseal key and
          root token will be stored securely in your OS keychain.
        </p>

        <button
          onClick={handleInit}
          disabled={loading}
          className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? "Initializing..." : "Initialize Vault"}
        </button>
      </div>
    </AuthLayout>
  );
}
