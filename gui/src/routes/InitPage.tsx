import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import { useAuthStore } from "../stores/authStore";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

export function InitPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
  const [loading, setLoading] = useState(true);
  const [initializing, setInitializing] = useState(false);
  const [rootToken, setRootToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [alreadyInitialized, setAlreadyInitialized] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [resetConfirmText, setResetConfirmText] = useState("");
  const [resetting, setResetting] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    checkIfInitialized();
  }, []);

  async function checkIfInitialized() {
    try {
      const initialized = await api.isVaultInitialized();
      if (initialized) {
        setAlreadyInitialized(true);
      } else {
        // Double-check by trying to get vault status — the _barrier file
        // check can be stale if the vault was initialized via a different
        // storage backend.
        try {
          const status = await api.getVaultStatus();
          if (status.initialized) {
            setAlreadyInitialized(true);
          }
        } catch {
          // ignore — vault not open yet
        }
      }
    } catch {
      // If check fails, allow initialization
    } finally {
      setLoading(false);
    }
  }

  async function handleGoToLogin() {
    try {
      await api.openVault();
      navigate("/login");
    } catch (e: unknown) {
      setError(extractError(e));
    }
  }

  async function handleInit() {
    setInitializing(true);
    setError(null);
    try {
      const result = await api.initVault();
      await api.savePreferences("Embedded");
      setRootToken(result.root_token);
    } catch (e: unknown) {
      const msg = extractError(e);
      // If the vault is already initialized, switch to the already-initialized view
      if (msg.toLowerCase().includes("already initialized")) {
        setAlreadyInitialized(true);
      } else {
        setError(msg);
      }
      setInitializing(false);
    }
  }

  async function handleReset() {
    setResetting(true);
    setError(null);
    try {
      await api.resetVault();
      setAlreadyInitialized(false);
      setShowResetConfirm(false);
      setResetConfirmText("");
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setResetting(false);
    }
  }

  function handleContinue() {
    if (rootToken) {
      setAuth(rootToken, ["root"]);
      navigate("/dashboard");
    }
  }

  if (loading) {
    return (
      <AuthLayout title="Loading..." subtitle="Checking vault state">
        <div className="text-center text-[var(--color-text-muted)] py-8">
          <div className="inline-block w-6 h-6 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin mb-3" />
          <p>Checking vault state...</p>
        </div>
      </AuthLayout>
    );
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
                onClick={() => {
                  navigator.clipboard.writeText(rootToken);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className={`px-3 py-2 border rounded-lg text-sm transition-colors ${
                  copied
                    ? "bg-green-500/20 border-green-500/40 text-green-400"
                    : "bg-[var(--color-surface-hover)] border-[var(--color-border)] hover:bg-[var(--color-border)]"
                }`}
              >
                {copied ? "Copied!" : "Copy"}
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

  if (alreadyInitialized) {
    return (
      <AuthLayout
        title="Vault Already Initialized"
        subtitle="Your local vault is ready"
      >
        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text-muted)]">
            An encrypted vault already exists on this device. You can log in to
            access it, or reset the vault to start fresh.
          </p>

          <button
            onClick={handleGoToLogin}
            className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white rounded-lg font-medium transition-colors"
          >
            Go to Login
          </button>

          {!showResetConfirm ? (
            <button
              onClick={() => setShowResetConfirm(true)}
              className="w-full py-2.5 bg-transparent border border-red-500/40 text-red-400 hover:bg-red-500/10 rounded-lg font-medium transition-colors text-sm"
            >
              Reset Vault...
            </button>
          ) : (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg space-y-3">
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
          disabled={initializing}
          className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
        >
          {initializing ? "Initializing..." : "Initialize Vault"}
        </button>
      </div>
    </AuthLayout>
  );
}
