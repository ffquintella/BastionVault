import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { listen } from "@tauri-apps/api/event";
import { AuthLayout } from "../components/AuthLayout";
import { Modal } from "../components/ui";
import { useAuthStore } from "../stores/authStore";
import { useVaultStore } from "../stores/vaultStore";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type Tab = "token" | "login";
type LoginStep = "username" | "password";

export function LoginPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
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

  async function handleContinue(e: React.FormEvent) {
    e.preventDefault();
    if (!username) return;
    setLoading(true);
    setError(null);
    try {
      // Try to start FIDO2 login — if user has keys, this succeeds
      await api.fido2NativeLogin(username).then((result) => {
        setAuth(result.token, result.policies);
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
      setAuth(result.token, result.policies);
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

  const tabs: { id: Tab; label: string }[] = [
    { id: "login", label: "Login" },
    { id: "token", label: "Token" },
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
