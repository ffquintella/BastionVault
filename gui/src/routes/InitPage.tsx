import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import { Button, Input, Modal, useToast } from "../components/ui";
import { useAuthStore } from "../stores/authStore";
import type { VaultProfile } from "../lib/api";
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
  // "local" | "cloud" — drives the copy so the init page correctly
  // describes what the user is about to create. Pulled from the
  // current default vault profile; remote profiles never reach
  // this page (the remote-connect path goes straight to /login).
  const [vaultKind, setVaultKind] = useState<"local" | "cloud">("local");
  const [cloudProvider, setCloudProvider] = useState<string>("");
  // Full current default profile — gives the bottom-right icon row
  // (gear / trash / change) access to the id + spec it needs to
  // operate on. Null until the async lookup completes.
  const [defaultProfile, setDefaultProfile] = useState<VaultProfile | null>(null);
  // Confirm-before-remove state.
  const [showTrashConfirm, setShowTrashConfirm] = useState(false);
  // Settings modal (gear). For cloud vaults today it re-pastes the
  // credential token via `save_pasted_token`, which is the most
  // common reason an init fails ("refresh token is malformed" ==
  // the on-disk credentials file is in an older format).
  const [showSettings, setShowSettings] = useState(false);
  const [pastedToken, setPastedToken] = useState("");
  const [savingToken, setSavingToken] = useState(false);

  // Local-keystore recovery. Surfaced when an open fails with the
  // "aead unwrap" / "local keystore" signature — the on-disk vault
  // is fine, only the cached unseal key is unreadable. The operator
  // pastes the unseal key they stashed at init time; we clear the
  // bad cache + re-seed it, then retry the open. Distinct from
  // "Destroy & Reset" which nukes vault data.
  const [showKeystoreRecovery, setShowKeystoreRecovery] = useState(false);
  const [recoveryUnsealKey, setRecoveryUnsealKey] = useState("");
  const [recovering, setRecovering] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    checkIfInitialized();
    // Determine whether we're initializing a Local or Cloud vault
    // so the page copy stays truthful. Runs in parallel with the
    // already-initialized check; errors fall through silently and
    // we default to "local" which was the historical behavior.
    api
      .listVaultProfiles()
      .then((list) => {
        const def = list.vaults.find((v) => v.id === list.lastUsedId) ?? null;
        setDefaultProfile(def);
        if (def?.spec.kind === "cloud") {
          setVaultKind("cloud");
          setCloudProvider(String(def.spec.config.target ?? ""));
        }
      })
      .catch(() => {
        /* default vaultKind stays "local" */
      });
  }, []);

  /**
   * Switch to a different saved vault — just clears `last_used_id`
   * and punts back to the chooser with `?choose=1` so auto-resume
   * doesn't fire.
   */
  async function handleChangeVault() {
    try {
      await api.clearLastUsedVault();
    } catch {
      /* best effort — even if this fails, the chooser still works */
    }
    navigate("/?choose=1", { replace: true });
  }

  /**
   * Remove the current default vault from the saved list and go
   * back to the chooser. Only edits the preferences file; the
   * underlying storage (cloud bucket, local data dir) is not
   * touched, so a user who forgets by accident can re-add the
   * same profile later without losing data.
   */
  async function handleTrashVault() {
    setShowTrashConfirm(false);
    if (!defaultProfile) {
      navigate("/?choose=1", { replace: true });
      return;
    }
    try {
      await api.removeVaultProfile(defaultProfile.id);
      toast("success", `Removed "${defaultProfile.name}"`);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
    navigate("/?choose=1", { replace: true });
  }

  /**
   * Re-write the credential file for the current cloud vault. Reads
   * the current `credentials_ref` out of the saved profile spec so
   * the new content lands at the same path the target is already
   * configured to read. Uses the JSON-envelope writer which is what
   * `DropboxTarget::ensure_access_token` expects for long-lived
   * tokens from the provider's dev console.
   */
  async function handleReSavePastedToken() {
    if (!defaultProfile || defaultProfile.spec.kind !== "cloud") return;
    const target = String(defaultProfile.spec.config.target ?? "");
    if (!["onedrive", "gdrive", "dropbox"].includes(target)) {
      toast("error", "Re-pasting a token is only supported for OAuth providers");
      return;
    }
    if (!pastedToken.trim()) {
      toast("error", "Paste the token first");
      return;
    }
    setSavingToken(true);
    try {
      await api.savePastedToken({
        target: target as "onedrive" | "gdrive" | "dropbox",
        token: pastedToken,
      });
      toast("success", "Token saved — try Initialize Vault again");
      setPastedToken("");
      setShowSettings(false);
      setError(null);
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSavingToken(false);
    }
  }

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
      const msg = extractError(e);
      setError(msg);
      // Surface the safer recovery path automatically when the
      // failure is a keystore-unwrap mismatch — the destructive
      // "Destroy & Reset" below would nuke vault data the operator
      // probably doesn't want to lose for a cache-mismatch bug.
      const lower = msg.toLowerCase();
      if (
        lower.includes("local keystore") ||
        lower.includes("unwrap") ||
        lower.includes("no unseal key found")
      ) {
        setShowKeystoreRecovery(true);
      }
    }
  }

  async function handleKeystoreRecovery() {
    const key = recoveryUnsealKey.trim();
    if (!key) {
      toast("error", "Paste the unseal key to continue.");
      return;
    }
    setRecovering(true);
    try {
      await api.recoverUnsealKey(key);
      toast("success", "Unseal key restored. Opening the vault…");
      setRecoveryUnsealKey("");
      setShowKeystoreRecovery(false);
      setError(null);
      // Retry the open path the operator originally intended to
      // take — succeeds now that the cache is re-seeded with a
      // working key. Failure surfaces a real unseal error
      // (e.g. wrong key pasted) on the InitPage.
      try {
        await api.openVault();
        navigate("/login");
      } catch (openErr: unknown) {
        setError(extractError(openErr));
      }
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setRecovering(false);
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

          {/* Safer recovery path for the keystore-unwrap failure
              mode. Vault data stays intact; operator pastes their
              unseal key, we clear the bad cache + re-seed it, and
              retry the open. Surfaced EITHER when the handler
              explicitly opened it OR when the current error
              message carries the keystore-unwrap signature — the
              error can arrive via more than one code path (eg an
              upstream Tauri command called by a different handler)
              and we want the panel to show regardless of which
              route set the error state. */}
          {(showKeystoreRecovery ||
            (error !== null &&
              (error.toLowerCase().includes("local keystore") ||
                error.toLowerCase().includes("unwrap") ||
                error.toLowerCase().includes("no unseal key found")))) && (
            <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg space-y-3">
              <p className="text-amber-400 font-medium text-sm">
                Recover with your unseal key
              </p>
              <p className="text-amber-400/80 text-xs">
                The cached unseal key on this machine is unreadable, but
                your vault data is safe. Paste the unseal key you saved
                at init time to re-seed the cache and continue. This does
                not touch the vault's stored secrets.
              </p>
              <div>
                <label className="block text-xs text-amber-400/70 mb-1">
                  Unseal key (hex, 64 characters)
                </label>
                <input
                  type="password"
                  value={recoveryUnsealKey}
                  onChange={(e) => setRecoveryUnsealKey(e.target.value)}
                  placeholder="e.g. a1b2…"
                  spellCheck={false}
                  autoComplete="off"
                  className="w-full bg-[var(--color-bg)] border border-amber-500/30 rounded-lg px-3 py-2 text-sm font-mono text-amber-300 placeholder:text-amber-500/30"
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setShowKeystoreRecovery(false);
                    setRecoveryUnsealKey("");
                  }}
                  disabled={recovering}
                  className="flex-1 py-2 bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] rounded-lg text-sm transition-colors hover:bg-[var(--color-border)] disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleKeystoreRecovery}
                  disabled={recovering || !recoveryUnsealKey.trim()}
                  className="flex-1 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
                >
                  {recovering ? "Recovering…" : "Restore & open"}
                </button>
              </div>
            </div>
          )}

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

  const kindLabel =
    vaultKind === "cloud"
      ? cloudProvider
        ? `cloud vault (${cloudProvider})`
        : "cloud vault"
      : "local vault";
  const subtitle =
    vaultKind === "cloud"
      ? `First-time setup for your ${kindLabel}`
      : "First-time setup for your local vault";
  const body =
    vaultKind === "cloud"
      ? "This will create an encrypted vault in the cloud storage target you just configured. The unseal key and root token will be stored securely in your OS keychain; your vault contents are encrypted before being written to the provider, so only this device can read them."
      : "This will create an encrypted vault on your device. The unseal key and root token will be stored securely in your OS keychain.";

  const isCloudVault = vaultKind === "cloud";
  const hasOAuthProvider =
    isCloudVault && ["onedrive", "gdrive", "dropbox"].includes(cloudProvider);

  return (
    <AuthLayout title="Initialize Vault" subtitle={subtitle}>
      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <p className="text-sm text-[var(--color-text-muted)]">{body}</p>

        <button
          onClick={handleInit}
          disabled={initializing}
          className="w-full py-2.5 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] disabled:opacity-50 text-white rounded-lg font-medium transition-colors"
        >
          {initializing ? "Initializing..." : "Initialize Vault"}
        </button>

        {/* Icon row: change vault / edit settings / forget vault.
            Only shown once we've resolved which profile is active —
            before that, there's nothing to act on. */}
        {defaultProfile && (
          <div className="flex items-center justify-end gap-1 pt-1">
            <IconButton
              title="Switch to a different saved vault"
              ariaLabel="Change vault"
              onClick={handleChangeVault}
            >
              {/* arrows-swap */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M17 1l4 4-4 4" />
                <path d="M3 11V9a4 4 0 0 1 4-4h14" />
                <path d="M7 23l-4-4 4-4" />
                <path d="M21 13v2a4 4 0 0 1-4 4H3" />
              </svg>
            </IconButton>
            <IconButton
              title={
                isCloudVault
                  ? "Adjust vault connection parameters (credentials, etc.)"
                  : "Adjust vault settings"
              }
              ariaLabel="Vault settings"
              onClick={() => {
                if (isCloudVault) {
                  setShowSettings(true);
                } else {
                  // For non-cloud vaults we don't have an inline
                  // editor yet; shunt the user to the chooser where
                  // they can Remove + Re-add.
                  handleChangeVault();
                }
              }}
            >
              {/* gear */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
              </svg>
            </IconButton>
            <IconButton
              title="Forget this vault (does not delete data)"
              ariaLabel="Remove vault"
              onClick={() => setShowTrashConfirm(true)}
              danger
            >
              {/* trash */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polyline points="3 6 5 6 21 6" />
                <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                <path d="M10 11v6" />
                <path d="M14 11v6" />
                <path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2" />
              </svg>
            </IconButton>
          </div>
        )}
      </div>

      {/* Settings modal (gear). Cloud vaults get an inline token
          re-paste form — the most common reason init fails here is
          that the on-disk credential file is stale, and this lets
          the user fix it without going back to the chooser. */}
      <Modal
        open={showSettings}
        onClose={() => setShowSettings(false)}
        title="Vault connection settings"
        size="md"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowSettings(false)}>
              Close
            </Button>
            {hasOAuthProvider && (
              <Button
                onClick={handleReSavePastedToken}
                loading={savingToken}
                disabled={!pastedToken.trim()}
              >
                Save token
              </Button>
            )}
          </>
        }
      >
        <div className="space-y-3">
          {defaultProfile && (
            <>
              <div className="text-sm">
                <div className="text-[var(--color-text-muted)] text-xs mb-0.5">
                  Profile
                </div>
                <div className="font-mono">{defaultProfile.name}</div>
              </div>
              {isCloudVault && (
                <div className="text-sm">
                  <div className="text-[var(--color-text-muted)] text-xs mb-0.5">
                    Credentials file
                  </div>
                  <div className="font-mono break-all text-xs">
                    {String(defaultProfile.spec.kind === "cloud"
                      ? defaultProfile.spec.config.credentials_ref ?? ""
                      : "")}
                  </div>
                </div>
              )}
            </>
          )}

          {hasOAuthProvider ? (
            <div className="rounded-md border border-[var(--color-border)] p-3 space-y-2">
              <p className="text-sm">
                Re-paste the access token generated at{" "}
                <span className="font-medium capitalize">{cloudProvider}</span>'s
                developer console. This rewrites the credentials file in the
                current long-lived-token format — useful if the init is failing
                with "refresh token is malformed" because the file was written
                in an older format.
              </p>
              <Input
                label="Token"
                type="password"
                value={pastedToken}
                onChange={(e) => setPastedToken(e.target.value)}
                placeholder="Paste the token string (no URL, no JSON)"
              />
            </div>
          ) : isCloudVault ? (
            <p className="text-sm text-[var(--color-text-muted)]">
              Editing connection fields for S3 vaults is not yet supported
              inline — use the vault chooser to forget and re-add.
            </p>
          ) : (
            <p className="text-sm text-[var(--color-text-muted)]">
              Local vaults have no connection parameters to adjust.
            </p>
          )}
        </div>
      </Modal>

      {/* Trash confirm — avoids an accidental click wiping the
          default-vault pointer. Underlying storage is not touched
          regardless. */}
      <Modal
        open={showTrashConfirm}
        onClose={() => setShowTrashConfirm(false)}
        title="Forget this vault?"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowTrashConfirm(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleTrashVault}>
              Forget
            </Button>
          </>
        }
      >
        <p className="text-sm text-[var(--color-text-muted)]">
          Removes{" "}
          <span className="font-medium text-[var(--color-text)]">
            {defaultProfile?.name ?? "the current vault"}
          </span>{" "}
          from your saved list. The underlying data
          {isCloudVault ? " in the cloud bucket/folder" : " on disk"} is not
          touched — you can re-add the same profile later without losing
          anything.
        </p>
      </Modal>
    </AuthLayout>
  );
}

/**
 * Small icon button used in the init-page footer row. Local to
 * this file because the icon set + hover treatment is specific to
 * this one use; if another page ever needs the same thing, lift
 * it to `components/ui/`.
 */
function IconButton({
  title,
  ariaLabel,
  onClick,
  danger,
  children,
}: {
  title: string;
  ariaLabel: string;
  onClick: () => void;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={ariaLabel}
      className={`p-2 rounded-md text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] transition-colors ${
        danger ? "hover:text-red-400" : "hover:text-[var(--color-text)]"
      }`}
    >
      {children}
    </button>
  );
}
