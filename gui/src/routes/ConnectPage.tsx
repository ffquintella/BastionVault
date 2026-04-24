import { useState, useEffect, useCallback } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import {
  Button,
  CollapsibleSection,
  Input,
  Modal,
  Select,
  useToast,
} from "../components/ui";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import type { RemoteProfile } from "../lib/types";
import type { VaultProfile, VaultSpec } from "../lib/api";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { open as shellOpen } from "@tauri-apps/plugin-shell";

type CloudProvider = "s3" | "onedrive" | "gdrive" | "dropbox";
const CLOUD_PROVIDER_LABELS: Record<CloudProvider, string> = {
  s3: "AWS S3 / MinIO",
  onedrive: "Microsoft OneDrive",
  gdrive: "Google Drive",
  dropbox: "Dropbox",
};

/**
 * Developer-console URLs where operators register their own OAuth
 * application / generate S3 access keys. Rendered as a "Get client
 * id ↗" link next to the relevant form field. BastionVault never
 * ships pre-registered consumer-drive client ids (per the feature
 * spec) so every deployment creates its own app; the link removes
 * the "where do I click?" friction.
 */
const CLOUD_DEV_CONSOLES: Record<CloudProvider, { url: string; label: string }> = {
  s3: {
    url: "https://console.aws.amazon.com/iam/home#/security_credentials",
    label: "AWS IAM → generate an access key",
  },
  onedrive: {
    url: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
    label: "Azure → register an application",
  },
  gdrive: {
    url: "https://console.cloud.google.com/apis/credentials",
    label: "Google Cloud → OAuth 2.0 client IDs",
  },
  dropbox: {
    url: "https://www.dropbox.com/developers/apps",
    label: "Dropbox → App Console",
  },
};

type AddKind = "local" | "remote" | "cloud" | null;

/**
 * Get Started / vault chooser.
 *
 * Loads the saved vault profiles list from preferences. If one is
 * marked as the default (`last_used_id`) and the `choose` query
 * param is not set, tries to auto-resume it. Otherwise renders:
 *
 *   * A card for every saved profile (click to open, Remove to
 *     drop from the list, "Set default" to pin for next launch).
 *   * An "Add new vault" section with three buttons (Local / Server
 *     / Cloud) that open type-specific modals and persist the new
 *     profile on save.
 *
 * Removing a profile only edits the preferences file — the
 * underlying storage (local directory / server / cloud bucket) is
 * not touched.
 */
export function ConnectPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const forceChoose = searchParams.get("choose") === "1";
  const { toast } = useToast();
  const setMode = useVaultStore((s) => s.setMode);
  const setRemoteProfile = useVaultStore((s) => s.setRemoteProfile);
  const rememberSession = useAuthStore((s) => s.rememberSession);
  const restoreSession = useAuthStore((s) => s.restoreSession);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const currentToken = useAuthStore((s) => s.token);
  const loadEntity = useAuthStore((s) => s.loadEntity);
  const clearAuth = useAuthStore((s) => s.clearAuth);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<VaultProfile[]>([]);
  const [lastUsedId, setLastUsedId] = useState<string | null>(null);
  const [opening, setOpening] = useState<string | null>(null);

  // Reset-vault panel state (unseal-key mismatch recovery).
  const [showReset, setShowReset] = useState(false);
  const [resetText, setResetText] = useState("");
  const [resetting, setResetting] = useState(false);

  // Local-keystore mismatch recovery. Distinct from `showReset`
  // because the remediation is different: this wipes the GUI's
  // cached unseal keys (the encrypted vault-keys.enc file +
  // keychain entry) while leaving every vault's actual data
  // intact. Triggered when an open fails with the keystore-unwrap
  // error signature.
  const [showLocalKeystoreReset, setShowLocalKeystoreReset] = useState(false);
  const [resettingLocalKeystore, setResettingLocalKeystore] = useState(false);

  // Add-vault modal state.
  const [addKind, setAddKind] = useState<AddKind>(null);
  const [addBusy, setAddBusy] = useState(false);
  const [newName, setNewName] = useState("");

  // Remote add-form fields.
  const [remoteAddr, setRemoteAddr] = useState("https://127.0.0.1:8200");
  const [tlsSkipVerify, setTlsSkipVerify] = useState(false);
  const [caCertPath, setCaCertPath] = useState("");

  // Cloud add-form fields.
  const [cloudProvider, setCloudProvider] = useState<CloudProvider>("s3");
  const [cloudBucket, setCloudBucket] = useState("");
  const [cloudRegion, setCloudRegion] = useState("us-east-1");
  const [cloudEndpointUrl, setCloudEndpointUrl] = useState("");
  const [cloudClientId, setCloudClientId] = useState("");
  const [cloudCredentialsRef, setCloudCredentialsRef] = useState("");
  const [cloudPrefix, setCloudPrefix] = useState("");
  const [cloudObfuscate, setCloudObfuscate] = useState(false);
  // S3-only inline credential fields. Filled by the user and
  // written to disk by `saveS3Credentials` which returns the
  // credentials_ref to prefill the shared field above.
  const [s3AccessKeyId, setS3AccessKeyId] = useState("");
  const [s3SecretAccessKey, setS3SecretAccessKey] = useState("");
  const [s3SessionToken, setS3SessionToken] = useState("");
  // True once credentials_ref has been populated via the inline
  // Connect / Save-credentials flow — drives the status badge on
  // the modal so the user knows Save & Open will work.
  const [cloudCredsReady, setCloudCredsReady] = useState(false);
  // "connect | save-s3 | save-token | none" — identifies which
  // inline action is currently in flight so the disabled-button UX
  // is precise.
  const [cloudAction, setCloudAction] = useState<
    "connect" | "save-s3" | "save-token" | null
  >(null);
  // OAuth redirect URI and "paste existing token" alternative for
  // users who don't want to run the consent flow (typical for
  // Dropbox, where the dev console has a "Generate" button that
  // mints a long-lived token without needing a redirect URI at all).
  const [oauthRedirectUri, setOauthRedirectUri] = useState("");
  const [pastedToken, setPastedToken] = useState("");
  const [showPasteToken, setShowPasteToken] = useState(false);

  // Local add-form fields. `localDataDir` is initialised to the
  // canonical default per storage kind; the user can edit it or hit
  // "Reset to default" to re-fill. Empty string means "use default",
  // so we translate to `undefined` on the way into the VaultSpec.
  // YubiKey-at-init preference for the new Local Vault. When on, the
  // InitPage registers the picked YubiKey as an additional unlock
  // slot on the machine-wide keystore after the vault's init step
  // succeeds. Stored transiently via `localStorage` keyed by the
  // new profile's id so the preference survives the navigation
  // from ConnectPage → InitPage without polluting the saved
  // profile schema. PIN is NEVER persisted — InitPage prompts for
  // it at register time and clears immediately after.
  const [localRequireYubiKey, setLocalRequireYubiKey] = useState(false);
  const [localYubiKeyDevices, setLocalYubiKeyDevices] = useState<
    import("../lib/api").YubiKeyDeviceInfo[]
  >([]);
  const [localYubiKeySerial, setLocalYubiKeySerial] = useState<number | null>(
    null,
  );
  const [localYubiKeyLoading, setLocalYubiKeyLoading] = useState(false);

  const [localStorageKind, setLocalStorageKind] = useState<
    "file" | "hiqlite"
  >("file");
  const [localDataDir, setLocalDataDir] = useState("");
  const [localDefaultDir, setLocalDefaultDir] = useState("");

  const refreshProfiles = useCallback(async () => {
    const list = await api.listVaultProfiles();
    setProfiles(list.vaults);
    setLastUsedId(list.lastUsedId);
  }, []);

  useEffect(() => {
    checkSavedPreferences();
    // One-shot fetch of the stable OAuth redirect URI so we can
    // display it in the Add Cloud Vault modal's OAuth section.
    api
      .getOAuthRedirectUri()
      .then(setOauthRedirectUri)
      .catch(() => setOauthRedirectUri(""));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * Save an access / refresh token the user generated at the
   * provider's dev console (e.g. Dropbox's "Generate" button).
   * Fast path for users who don't want to run the full consent
   * flow — skips the redirect URI round-trip entirely.
   */
  async function handleSavePastedToken() {
    if (cloudProvider === "s3") return;
    const oauthTarget: "onedrive" | "gdrive" | "dropbox" = cloudProvider;
    if (!pastedToken.trim()) {
      setError("Paste the token string first");
      return;
    }
    setCloudAction("save-token");
    setError(null);
    try {
      const ref = await api.savePastedToken({
        target: oauthTarget,
        token: pastedToken,
      });
      setCloudCredentialsRef(ref);
      setCloudCredsReady(true);
      setPastedToken("");
      setShowPasteToken(false);
      toast("success", `Token saved to ${ref}`);
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setCloudAction(null);
    }
  }

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast("success", `${label} copied to clipboard`);
    } catch {
      toast("error", "Clipboard access denied");
    }
  }

  async function checkSavedPreferences() {
    try {
      const list = await api.listVaultProfiles();
      setProfiles(list.vaults);
      setLastUsedId(list.lastUsedId);

      if (!forceChoose && list.lastUsedId) {
        const def = list.vaults.find((v) => v.id === list.lastUsedId);
        if (def) {
          // Attempt to auto-resume. On failure we fall through to
          // the chooser, leaving the profile in the list so the user
          // can re-try or remove.
          try {
            await openProfile(def, /*recordDefault=*/ false);
            return;
          } catch {
            // Swallow; render chooser below so the user can pick
            // another profile or fix the failed one.
          }
        }
      }
    } catch {
      // Preferences file missing / unreadable → show empty chooser.
    }
    setLoading(false);
  }

  /**
   * Core open routine shared by auto-resume on boot and click-to-open
   * on a saved profile. Dispatches on the profile kind:
   *
   *   Local  → set mode=Embedded, open+unseal the local vault; if
   *            not initialized, navigate to /init.
   *   Remote → connect to the server, validate health, navigate to
   *            /login.
   *   Cloud  → open (falls back to /init if the bucket is empty or
   *            contains an un-seedable blob); keys come from the OS
   *            keychain same as Local.
   *
   * `recordDefault` flips `last_used_id` to this profile so the next
   * launch picks it. The auto-resume path passes `false` because the
   * default is already set.
   */
  /**
   * Try to re-hydrate the auth store from a cached per-vault
   * session, skipping the /login round-trip. Returns `true` when
   * the cached token validated against the newly-opened vault and
   * we've navigated straight to the dashboard; `false` otherwise
   * (no cache for this vault, or the cached token was rejected).
   */
  async function tryResumeSession(vaultId: string): Promise<boolean> {
    const ok = await restoreSession(vaultId);
    if (!ok) return false;
    // Best-effort entity reload — mirrors the post-login code path in
    // LoginPage so ownership / sharing UI still has the principal on hand.
    loadEntity().catch(() => {});
    navigate("/dashboard");
    return true;
  }

  async function openProfile(profile: VaultProfile, recordDefault = true) {
    setOpening(profile.id);
    setError(null);
    try {
      const targetId = profile.id;
      const currentId = lastUsedId;

      // Switching AWAY from a different vault? Stash its session
      // and close the handle so the target can take the AppState
      // slot. When the operator comes back later the cached token
      // is restored without a re-login. Same-vault re-open is
      // handled below (idempotent, no disconnect).
      const switchingAwayFromAnother =
        currentId !== null && currentId !== targetId;
      if (switchingAwayFromAnother && isAuthenticated && currentToken) {
        rememberSession(currentId!);
      }
      if (switchingAwayFromAnother) {
        // Disconnect regardless of embedded/remote — the backend
        // commands are no-ops if nothing is bound, so running both
        // in sequence is cheap and correct.
        try {
          await api.disconnectVault();
        } catch {
          /* nothing bound → fine */
        }
        try {
          await api.disconnectRemote();
        } catch {
          /* nothing bound → fine */
        }
        // Drop the now-stale auth state; restoreSession will re-hydrate
        // it post-open when a cached token exists.
        clearAuth();
      }

      switch (profile.spec.kind) {
        case "local": {
          const initialized = await api.isVaultInitialized();
          if (!initialized) {
            if (recordDefault) await api.setLastUsedVault(profile.id);
            navigate("/init");
            return;
          }
          await api.openVault();
          setMode("Embedded");
          if (recordDefault) await api.setLastUsedVault(profile.id);
          if (await tryResumeSession(targetId)) return;
          navigate("/login");
          return;
        }
        case "remote": {
          await api.connectRemote(profile.spec.profile);
          setMode("Remote");
          setRemoteProfile(profile.spec.profile);
          if (recordDefault) await api.setLastUsedVault(profile.id);
          if (await tryResumeSession(targetId)) return;
          navigate("/login");
          return;
        }
        case "cloud": {
          // Flip default *before* the open attempt so
          // `embedded::build_backend` picks up the right profile on
          // this boot — the Rust side reads `last_used_id` directly.
          await api.setLastUsedVault(profile.id);
          const initialized = await api.isVaultInitialized();
          if (!initialized) {
            navigate("/init");
            return;
          }
          try {
            await api.openVault();
            setMode("Embedded");
            if (await tryResumeSession(targetId)) return;
            navigate("/login");
          } catch (err) {
            const msg = extractError(err);
            // Fresh bucket: surface as "needs init" rather than a
            // cryptic unseal error.
            if (
              msg.toLowerCase().includes("unseal") ||
              msg.toLowerCase().includes("barrier") ||
              msg.toLowerCase().includes("decrypt")
            ) {
              navigate("/init");
            } else {
              throw err;
            }
          }
          return;
        }
      }
    } catch (e: unknown) {
      const msg = extractError(e);
      setError(msg);
      const lower = msg.toLowerCase();
      // Local-keystore mismatch takes precedence over the
      // wipe-the-vault-data recovery because it's the safer
      // remediation (vault data stays untouched).
      if (lower.includes("local keystore") || lower.includes("unwrap")) {
        setShowLocalKeystoreReset(true);
      } else if (
        profile.spec.kind !== "remote" &&
        (lower.includes("unseal") ||
          lower.includes("invalid") ||
          lower.includes("decrypt"))
      ) {
        setShowReset(true);
      }
      throw e;
    } finally {
      setOpening(null);
    }
  }

  async function handleResetLocalKeystore() {
    setResettingLocalKeystore(true);
    try {
      await api.resetLocalKeystore();
      toast(
        "success",
        "Local key cache cleared. Re-open the vault and re-enter its unseal key.",
      );
      setShowLocalKeystoreReset(false);
      setError(null);
      // Re-list so the cards re-render (nothing visibly changes,
      // but the error badge disappears).
      await refreshProfiles();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setResettingLocalKeystore(false);
    }
  }

  async function handleReset() {
    setResetting(true);
    try {
      await api.resetVault();
      toast("success", "Vault data cleared. You can now create a new vault.");
      setShowReset(false);
      setResetText("");
      setError(null);
      navigate("/init");
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setResetting(false);
    }
  }

  async function handleRemove(id: string, name: string) {
    if (!confirm(`Forget "${name}"? The underlying data is not touched.`)) return;
    try {
      await api.removeVaultProfile(id);
      toast("success", `Removed "${name}"`);
      await refreshProfiles();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleSetDefault(id: string) {
    try {
      await api.setLastUsedVault(id);
      toast("success", "Default updated");
      await refreshProfiles();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function resetAddForm(kind: AddKind) {
    setAddKind(kind);
    setError(null);
    setCloudCredsReady(false);
    setS3AccessKeyId("");
    setS3SecretAccessKey("");
    setS3SessionToken("");
    setNewName(
      kind === "local"
        ? "Local Vault"
        : kind === "remote"
          ? "My Server"
          : kind === "cloud"
            ? `Cloud (${CLOUD_PROVIDER_LABELS[cloudProvider]})`
            : "",
    );
    // Prefill the credentials_ref field with a suggested per-user
    // path so the user doesn't have to invent one. Ignore failure —
    // on error the field stays blank and the user types their own.
    if (kind === "cloud") {
      api
        .suggestCredentialsRefPath(cloudProvider)
        .then((p) => setCloudCredentialsRef(p))
        .catch(() => {});
    }
    // Prefill the local data directory with the canonical default
    // for the current storage engine. The user can edit or clear it;
    // an empty value persists as "use default" (the backend picks
    // `data_dir_for(storage_kind)` at open time).
    if (kind === "local") {
      api
        .getDefaultLocalDataDir(localStorageKind)
        .then((p) => {
          setLocalDefaultDir(p);
          setLocalDataDir(p);
        })
        .catch(() => {
          setLocalDefaultDir("");
          setLocalDataDir("");
        });
    }
  }

  /**
   * Run the OAuth consent flow inline from inside the Add Cloud
   * Vault modal. Reuses the existing `cloud_target_*` Tauri
   * commands — same flow as `bvault operator cloud-target connect`
   * but started from the form the user is currently filling out,
   * so on success the `credentials_ref` field is already set and
   * the user can click Save & Open immediately.
   */
  async function handleInlineOAuthConnect() {
    if (cloudProvider === "s3") {
      // Button only renders in the OAuth branch, but guard anyway.
      return;
    }
    const oauthTarget: "onedrive" | "gdrive" | "dropbox" = cloudProvider;
    if (!cloudClientId.trim()) {
      setError("Enter the OAuth client id first");
      return;
    }
    let refToUse = cloudCredentialsRef.trim();
    if (!refToUse) {
      try {
        refToUse = await api.suggestCredentialsRefPath(oauthTarget);
        setCloudCredentialsRef(refToUse);
      } catch (e) {
        setError(extractError(e));
        return;
      }
    }
    setCloudAction("connect");
    setError(null);
    let sessionId: string | null = null;
    try {
      const start = await api.cloudTargetStartConnect({
        target: oauthTarget,
        clientId: cloudClientId.trim(),
        credentialsRef: refToUse,
      });
      sessionId = start.sessionId;
      await shellOpen(start.consentUrl);
      toast("info", "Opened consent page in your browser — waiting for callback…");
      await api.cloudTargetCompleteConnect({ sessionId });
      setCloudCredsReady(true);
      toast("success", `Connected — refresh token saved to ${refToUse}`);
    } catch (e: unknown) {
      setError(extractError(e));
      if (sessionId) {
        try {
          await api.cloudTargetCancelConnect(sessionId);
        } catch {
          /* best-effort */
        }
      }
    } finally {
      setCloudAction(null);
    }
  }

  /**
   * Save entered S3 access keys to a fresh file under the user's
   * cloud-creds directory, and fill in `credentials_ref` with the
   * returned path. Replaces the "paste a JSON file path and
   * pre-populate it" workflow with a single in-modal step.
   */
  async function handleSaveS3Credentials() {
    if (!s3AccessKeyId.trim() || !s3SecretAccessKey.trim()) {
      setError("Access key ID and secret access key are required");
      return;
    }
    setCloudAction("save-s3");
    setError(null);
    try {
      const ref = await api.saveS3Credentials({
        accessKeyId: s3AccessKeyId.trim(),
        secretAccessKey: s3SecretAccessKey.trim(),
        sessionToken: s3SessionToken.trim() || undefined,
      });
      setCloudCredentialsRef(ref);
      setCloudCredsReady(true);
      toast("success", `Credentials saved to ${ref}`);
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setCloudAction(null);
    }
  }

  async function handleAddAndOpen() {
    setAddBusy(true);
    setError(null);
    try {
      let spec: VaultSpec;
      if (addKind === "local") {
        // Persist the custom dir only if it differs from the
        // default — that way a user who left the field untouched
        // still gets the canonical platform path at open time
        // (and it continues to follow future default changes).
        const trimmedDir = localDataDir.trim();
        const dataDir =
          trimmedDir && trimmedDir !== localDefaultDir ? trimmedDir : undefined;
        spec = {
          kind: "local",
          storage_kind: localStorageKind,
          data_dir: dataDir,
        };
      } else if (addKind === "remote") {
        if (!remoteAddr.trim()) throw new Error("Server address is required");
        const profile: RemoteProfile = {
          name: newName.trim(),
          address: remoteAddr.trim(),
          tls_skip_verify: tlsSkipVerify,
          ca_cert_path: caCertPath || undefined,
        };
        spec = { kind: "remote", profile };
      } else if (addKind === "cloud") {
        const config: Record<string, unknown> = {
          credentials_ref: cloudCredentialsRef.trim(),
          obfuscate_keys: cloudObfuscate,
        };
        if (cloudPrefix.trim()) config.prefix = cloudPrefix.trim();
        if (cloudProvider === "s3") {
          if (!cloudBucket.trim())
            throw new Error("Bucket is required for S3");
          config.bucket = cloudBucket.trim();
          config.region = cloudRegion.trim() || "us-east-1";
          if (cloudEndpointUrl.trim()) {
            config.endpoint_url = cloudEndpointUrl.trim();
            config.url_style = "path";
          }
        } else {
          if (!cloudClientId.trim())
            throw new Error(
              "Client ID is required for OAuth-based providers",
            );
          config.client_id = cloudClientId.trim();
        }
        if (!cloudCredentialsRef.trim())
          throw new Error("credentials_ref is required");
        spec = {
          kind: "cloud",
          config: { target: cloudProvider, ...config },
        };
      } else {
        return;
      }

      const id = await api.addVaultProfile({
        name: newName.trim() || "Untitled vault",
        spec,
        setDefault: true,
      });
      // Stash the Local-Vault YubiKey preference for the InitPage to
      // consume post-init. Key is per-profile-id so multi-vault
      // operators don't cross-contaminate. No PIN here — InitPage
      // prompts for it at register time.
      if (addKind === "local" && localRequireYubiKey && localYubiKeySerial) {
        try {
          window.localStorage.setItem(
            `bv.init.yubikey.${id}`,
            String(localYubiKeySerial),
          );
        } catch {
          /* storage full / disabled — fall back to no-yubikey init */
        }
      }
      setAddKind(null);
      await refreshProfiles();
      // Immediately open the newly-added profile so the user doesn't
      // have to click again.
      const added = (await api.listVaultProfiles()).vaults.find(
        (v) => v.id === id,
      );
      if (added) {
        try {
          await openProfile(added, /*recordDefault=*/ false);
        } catch {
          /* openProfile already surfaced the error */
        }
      }
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setAddBusy(false);
    }
  }

  if (loading) {
    return (
      <AuthLayout
        title="BastionVault"
        subtitle="Identity-based secrets management"
      >
        <div className="text-center text-[var(--color-text-muted)] py-8">
          <div className="inline-block w-6 h-6 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin mb-3" />
          <p>Connecting to vault...</p>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Get Started"
      subtitle="Identity-based secrets management"
    >
      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {(showLocalKeystoreReset ||
        (error !== null &&
          (error.toLowerCase().includes("local keystore") ||
            error.toLowerCase().includes("unwrap")))) && (
        <div className="mb-4 p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg space-y-3">
          <p className="text-amber-400 font-medium text-sm">
            The local key cache cannot be unwrapped on this machine.
          </p>
          <p className="text-amber-400/80 text-xs">
            This usually means the OS keychain entry that sealed the cached
            unseal keys was regenerated (reinstall, keychain cleanup, moved
            the GUI between user accounts). <span className="font-medium">Your vault data is safe</span> — only
            the local copy of the unseal key is. Clearing the cache lets
            you re-open the vault; you'll just need to enter the unseal
            key once on next open.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setShowLocalKeystoreReset(false)}
              className="flex-1 py-2 bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] rounded-lg text-sm transition-colors hover:bg-[var(--color-border)]"
            >
              Cancel
            </button>
            <button
              onClick={handleResetLocalKeystore}
              disabled={resettingLocalKeystore}
              className="flex-1 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              {resettingLocalKeystore ? "Clearing..." : "Clear local key cache"}
            </button>
          </div>
        </div>
      )}

      {showReset && (
        <div className="mb-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg space-y-3">
          <p className="text-red-400 font-medium text-sm">
            The vault data cannot be decrypted. This usually means the unseal key in your keychain no longer matches.
          </p>
          <p className="text-red-400/70 text-xs">
            You can reset the local vault data to start fresh. This only affects the Local Vault at the default path.
          </p>
          <div>
            <label className="block text-xs text-red-400/70 mb-1">
              Type <span className="font-mono font-bold">RESET</span> to confirm
            </label>
            <input
              type="text"
              value={resetText}
              onChange={(e) => setResetText(e.target.value)}
              placeholder="RESET"
              className="w-full bg-[var(--color-bg)] border border-red-500/30 rounded-lg px-3 py-2 text-sm font-mono text-red-400 placeholder:text-red-400/30"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => { setShowReset(false); setResetText(""); }}
              className="flex-1 py-2 bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] rounded-lg text-sm transition-colors hover:bg-[var(--color-border)]"
            >
              Cancel
            </button>
            <button
              onClick={handleReset}
              disabled={resetText !== "RESET" || resetting}
              className="flex-1 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              {resetting ? "Resetting..." : "Destroy & Reset"}
            </button>
          </div>
        </div>
      )}

      {/* Saved profiles */}
      <div className="space-y-2 mb-4">
        {profiles.length === 0 && (
          <p className="text-sm text-[var(--color-text-muted)] text-center py-2">
            No vaults saved yet — add one below.
          </p>
        )}
        {profiles.map((p) => (
          <VaultProfileCard
            key={p.id}
            profile={p}
            isDefault={p.id === lastUsedId}
            opening={opening === p.id}
            onOpen={() => openProfile(p).catch(() => {})}
            onSetDefault={() => handleSetDefault(p.id)}
            onRemove={() => handleRemove(p.id, p.name)}
          />
        ))}
      </div>

      {/* Add-new section */}
      <div className="pt-3 border-t border-[var(--color-border)] space-y-2">
        <p className="text-xs uppercase tracking-wide text-[var(--color-text-muted)] font-medium">
          Add new vault
        </p>
        <div className="grid grid-cols-3 gap-2">
          <AddKindButton label="Local" description="This device" onClick={() => resetAddForm("local")} />
          <AddKindButton label="Server" description="Remote BV" onClick={() => resetAddForm("remote")} />
          <AddKindButton label="Cloud" description="S3 / Drive" onClick={() => resetAddForm("cloud")} />
        </div>
      </div>

      {/* Add-vault modal */}
      <Modal
        open={addKind !== null}
        onClose={() => setAddKind(null)}
        title={
          addKind === "local"
            ? "Add Local Vault"
            : addKind === "remote"
              ? "Add Server"
              : addKind === "cloud"
                ? "Add Cloud Vault"
                : ""
        }
        size="md"
        actions={
          <>
            <Button variant="ghost" onClick={() => setAddKind(null)}>Cancel</Button>
            <Button onClick={handleAddAndOpen} loading={addBusy}>
              {addBusy ? "Saving…" : "Save & Open"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}
          <Input
            label="Name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Give this vault a short label"
          />

          {addKind === "local" && (
            <>
              <Select
                label="Storage engine"
                value={localStorageKind}
                onChange={(e) => {
                  const kind = e.target.value as "file" | "hiqlite";
                  setLocalStorageKind(kind);
                  // Re-fetch the default path for the new engine so
                  // the Location field stays truthful when the user
                  // hadn't customized it. If they had, keep their
                  // custom value and update only the "default" hint.
                  const wasAtDefault = localDataDir === localDefaultDir;
                  api
                    .getDefaultLocalDataDir(kind)
                    .then((p) => {
                      setLocalDefaultDir(p);
                      if (wasAtDefault) setLocalDataDir(p);
                    })
                    .catch(() => {});
                }}
                options={[
                  { value: "file", label: "File (simple, one file per key)" },
                  { value: "hiqlite", label: "Hiqlite (embedded SQLite)" },
                ]}
              />
              <div>
                <div className="flex gap-2 items-end">
                  <div className="flex-1 min-w-0">
                    <Input
                      label="Location"
                      value={localDataDir}
                      onChange={(e) => setLocalDataDir(e.target.value)}
                      placeholder={localDefaultDir}
                      hint="Directory that will hold the encrypted vault files. Empty = use the default below."
                    />
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={async () => {
                      // Dialog plugin is async-imported so plain-browser
                      // vitest runs (where `@tauri-apps/plugin-dialog` is
                      // not available at module resolution time) don't
                      // crash on page import. The button is only visible
                      // inside Tauri anyway.
                      try {
                        const { open } = await import(
                          "@tauri-apps/plugin-dialog"
                        );
                        const picked = await open({
                          directory: true,
                          defaultPath: localDataDir || localDefaultDir,
                          title: "Select vault data directory",
                        });
                        if (typeof picked === "string" && picked.length > 0) {
                          setLocalDataDir(picked);
                        }
                      } catch (e) {
                        toast("error", extractError(e));
                      }
                    }}
                  >
                    Browse…
                  </Button>
                </div>
                <div className="flex items-center justify-between mt-1 text-xs text-[var(--color-text-muted)]">
                  <span className="font-mono truncate mr-2" title={localDefaultDir}>
                    Default: {localDefaultDir || "(resolving…)"}
                  </span>
                  {localDataDir !== localDefaultDir && localDefaultDir && (
                    <button
                      type="button"
                      onClick={() => setLocalDataDir(localDefaultDir)}
                      className="text-[var(--color-primary)] hover:underline shrink-0"
                    >
                      Reset to default
                    </button>
                  )}
                </div>
              </div>

              {/* YubiKey-at-init toggle. When on, InitPage prompts
                  for the PIV PIN after the vault's init step and
                  registers the selected device as an additional
                  unlock slot on the machine-wide keystore. The
                  OS-keychain slot stays enrolled too, so the
                  YubiKey is a FAILSAFE (either path unlocks), not
                  a hard requirement that would brick the vault
                  if the card is lost. */}
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] p-3 space-y-2">
                <label className="flex items-center justify-between gap-3 cursor-pointer select-none">
                  <div className="min-w-0">
                    <p className="text-sm text-[var(--color-text)] font-medium">
                      Require a YubiKey for unlock
                    </p>
                    <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                      Registers a YubiKey as an additional unlock path for
                      the machine-wide keystore right after init. Either
                      the OS keychain OR the card unlocks the file — losing
                      the card doesn't brick the vault.
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={localRequireYubiKey}
                    onChange={async (e) => {
                      const on = e.target.checked;
                      setLocalRequireYubiKey(on);
                      if (on && localYubiKeyDevices.length === 0) {
                        setLocalYubiKeyLoading(true);
                        try {
                          const devices = await api.yubikeyListDevices();
                          setLocalYubiKeyDevices(devices);
                          if (
                            devices.length > 0 &&
                            localYubiKeySerial === null
                          ) {
                            setLocalYubiKeySerial(devices[0].serial);
                          }
                        } catch {
                          setLocalYubiKeyDevices([]);
                        } finally {
                          setLocalYubiKeyLoading(false);
                        }
                      }
                    }}
                    className="accent-[var(--color-primary)] w-4 h-4 shrink-0"
                  />
                </label>

                {localRequireYubiKey && (
                  <div className="pt-2 border-t border-[var(--color-border)]">
                    {localYubiKeyLoading ? (
                      <p className="text-xs text-[var(--color-text-muted)]">
                        Scanning for connected YubiKeys…
                      </p>
                    ) : localYubiKeyDevices.length === 0 ? (
                      <div className="space-y-2">
                        <p className="text-xs text-[var(--color-warning)]">
                          No YubiKey detected. Plug one in and click
                          Refresh.
                        </p>
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          onClick={async () => {
                            setLocalYubiKeyLoading(true);
                            try {
                              const devices = await api.yubikeyListDevices();
                              setLocalYubiKeyDevices(devices);
                              if (
                                devices.length > 0 &&
                                localYubiKeySerial === null
                              ) {
                                setLocalYubiKeySerial(devices[0].serial);
                              }
                            } finally {
                              setLocalYubiKeyLoading(false);
                            }
                          }}
                        >
                          Refresh
                        </Button>
                      </div>
                    ) : (
                      <Select
                        label="YubiKey to register"
                        value={
                          localYubiKeySerial !== null
                            ? String(localYubiKeySerial)
                            : ""
                        }
                        onChange={(e) => {
                          const n = Number(e.target.value);
                          setLocalYubiKeySerial(
                            Number.isFinite(n) ? n : null,
                          );
                        }}
                        options={localYubiKeyDevices.map((d) => ({
                          value: String(d.serial),
                          label: `#${d.serial}${d.slot_occupied ? "" : " (slot 9a empty)"}`,
                        }))}
                      />
                    )}
                  </div>
                )}
              </div>
            </>
          )}

          {addKind === "remote" && (
            <>
              <Input
                label="Server Address"
                value={remoteAddr}
                onChange={(e) => setRemoteAddr(e.target.value)}
                placeholder="https://vault.example.com:8200"
                hint="Full URL including protocol and port"
              />
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={tlsSkipVerify}
                  onChange={(e) => setTlsSkipVerify(e.target.checked)}
                  className="rounded"
                />
                <span className="text-[var(--color-text-muted)]">
                  Skip TLS certificate verification (insecure)
                </span>
              </label>
              <Input
                label="CA Certificate Path"
                value={caCertPath}
                onChange={(e) => setCaCertPath(e.target.value)}
                placeholder="/path/to/ca.pem"
                hint="Optional: path to PEM-encoded CA certificate"
              />
            </>
          )}

          {addKind === "cloud" && (
            <>
              <Select
                label="Provider"
                value={cloudProvider}
                onChange={(e) => {
                  const v = e.target.value as CloudProvider;
                  setCloudProvider(v);
                  // Reset connect-state on provider change — the
                  // old credentials_ref doesn't apply to the new
                  // provider, and the user needs to re-authenticate.
                  setCloudCredsReady(false);
                  api
                    .suggestCredentialsRefPath(v)
                    .then((p) => setCloudCredentialsRef(p))
                    .catch(() => {});
                }}
                options={(Object.keys(CLOUD_PROVIDER_LABELS) as CloudProvider[]).map(
                  (v) => ({ value: v, label: CLOUD_PROVIDER_LABELS[v] }),
                )}
              />

              {/* Storage location — collapsed by default for OAuth
                  providers (nothing extra to configure beyond the
                  app-folder) but open for S3 where bucket/region are
                  required. */}
              {cloudProvider === "s3" && (
                <CollapsibleSection
                  title="Storage location"
                  defaultOpen={true}
                  description="Where the backend stores its objects."
                >
                  <div className="grid grid-cols-2 gap-3">
                    <Input
                      label="Bucket"
                      value={cloudBucket}
                      onChange={(e) => setCloudBucket(e.target.value)}
                      placeholder="my-bastionvault-bucket"
                    />
                    <Input
                      label="Region"
                      value={cloudRegion}
                      onChange={(e) => setCloudRegion(e.target.value)}
                      placeholder="us-east-1"
                    />
                  </div>
                  <Input
                    label="Endpoint URL (optional)"
                    value={cloudEndpointUrl}
                    onChange={(e) => setCloudEndpointUrl(e.target.value)}
                    placeholder="http://localhost:9000  (MinIO)"
                    hint="Leave blank for AWS; path-style addressing enabled automatically."
                  />
                </CollapsibleSection>
              )}

              {/* Credentials section — the primary action the user
                  came to the modal for. Stays expanded by default,
                  contents differ per provider. */}
              <CollapsibleSection
                title={cloudProvider === "s3" ? "AWS Credentials" : "OAuth Application"}
                defaultOpen={true}
                headerRight={
                  <button
                    type="button"
                    onClick={() => shellOpen(CLOUD_DEV_CONSOLES[cloudProvider].url)}
                    className="text-xs text-[var(--color-primary)] hover:underline"
                  >
                    {CLOUD_DEV_CONSOLES[cloudProvider].label} ↗
                  </button>
                }
              >
                {cloudProvider === "s3" ? (
                  <>
                    <Input
                      label="Access Key ID"
                      value={s3AccessKeyId}
                      onChange={(e) => setS3AccessKeyId(e.target.value)}
                      placeholder="AKIA…"
                    />
                    <Input
                      label="Secret Access Key"
                      type="password"
                      value={s3SecretAccessKey}
                      onChange={(e) => setS3SecretAccessKey(e.target.value)}
                      placeholder="secret"
                    />
                    <Input
                      label="Session Token (optional)"
                      type="password"
                      value={s3SessionToken}
                      onChange={(e) => setS3SessionToken(e.target.value)}
                      placeholder="for AWS STS temporary credentials"
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={handleSaveS3Credentials}
                      loading={cloudAction === "save-s3"}
                      disabled={cloudAction !== null}
                    >
                      {cloudCredsReady ? "✓ Credentials saved" : "Save credentials"}
                    </Button>
                  </>
                ) : (
                  <>
                    {/* Redirect URI display — providers like Dropbox
                        require this to exactly match what's pre-
                        registered in the app console. Showing it
                        here with a copy button removes the guesswork. */}
                    {oauthRedirectUri && (
                      <div className="rounded-md bg-[var(--color-surface)] p-2 border border-[var(--color-border)]">
                        <div className="flex items-center justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-medium text-[var(--color-text-muted)] mb-0.5">
                              Redirect URI to register
                            </p>
                            <p className="text-xs font-mono truncate">
                              {oauthRedirectUri}
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={() =>
                              copyToClipboard(oauthRedirectUri, "Redirect URI")
                            }
                            className="text-xs px-2 py-1 rounded bg-[var(--color-surface-hover)] hover:bg-[var(--color-border)] text-[var(--color-text-muted)] shrink-0"
                          >
                            Copy
                          </button>
                        </div>
                        <p className="text-xs text-[var(--color-text-muted)] mt-1">
                          Paste this exact URL into your{" "}
                          {CLOUD_PROVIDER_LABELS[cloudProvider]} app's "Redirect
                          URIs" list before clicking Connect.
                        </p>
                      </div>
                    )}

                    <Input
                      label="Client ID"
                      value={cloudClientId}
                      onChange={(e) => setCloudClientId(e.target.value)}
                      placeholder="Registered OAuth application client id"
                      hint="BastionVault doesn't ship shared client ids — register your own app at the provider's dev console."
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={handleInlineOAuthConnect}
                      loading={cloudAction === "connect"}
                      disabled={cloudAction !== null || !cloudClientId.trim()}
                    >
                      {cloudCredsReady
                        ? "✓ Connected"
                        : `Connect with ${CLOUD_PROVIDER_LABELS[cloudProvider]}`}
                    </Button>
                    <p className="text-xs text-[var(--color-text-muted)]">
                      Opens the provider's consent page in your browser, then writes
                      the returned refresh token to the path below.
                    </p>

                    {/* Alternative: paste a token the user generated
                        directly at the provider's dev console. Dropbox
                        has a "Generate" button that mints a long-lived
                        access token with no redirect URI required. */}
                    {!showPasteToken ? (
                      <button
                        type="button"
                        onClick={() => setShowPasteToken(true)}
                        className="text-xs text-[var(--color-primary)] hover:underline self-start"
                      >
                        Or paste an existing token (generated at the dev console) ↓
                      </button>
                    ) : (
                      <div className="rounded-md border border-[var(--color-border)] p-2 space-y-2">
                        <p className="text-xs text-[var(--color-text-muted)]">
                          If you already generated a token at the provider's dev
                          console (Dropbox has a "Generate" button, for example),
                          paste it here to skip the OAuth consent round-trip.
                        </p>
                        <Input
                          label="Token"
                          type="password"
                          value={pastedToken}
                          onChange={(e) => setPastedToken(e.target.value)}
                          placeholder="Paste the token string (no URL, no JSON)"
                        />
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={handleSavePastedToken}
                            loading={cloudAction === "save-token"}
                            disabled={cloudAction !== null || !pastedToken.trim()}
                          >
                            Save token
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              setShowPasteToken(false);
                              setPastedToken("");
                            }}
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </CollapsibleSection>

              {/* Advanced section — credentials-ref path, vault
                  prefix, obfuscation. Collapsed by default; the
                  common case is "accept the suggested ref and skip
                  the rest". */}
              <CollapsibleSection
                title="Advanced"
                defaultOpen={false}
                description="Override the auto-generated credentials path, scope the vault to a sub-path, or obfuscate object keys."
              >
                <Input
                  label="Credentials ref"
                  value={cloudCredentialsRef}
                  onChange={(e) => {
                    setCloudCredentialsRef(e.target.value);
                    // Editing the ref invalidates the "ready" flag —
                    // we don't know if the new target is populated.
                    setCloudCredsReady(false);
                  }}
                  placeholder={
                    cloudProvider === "s3"
                      ? "file:/etc/bvault/aws.json"
                      : "file:/etc/bvault/oauth-refresh"
                  }
                  hint="Where the credential file lives. The buttons above populate it for you; you can also point at an existing file."
                />
                <Input
                  label="Path prefix (optional)"
                  value={cloudPrefix}
                  onChange={(e) => setCloudPrefix(e.target.value)}
                  placeholder="bastionvault"
                />
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={cloudObfuscate}
                    onChange={(e) => setCloudObfuscate(e.target.checked)}
                    className="mt-1 rounded"
                  />
                  <span className="text-[var(--color-text-muted)]">
                    <span className="font-medium text-[var(--color-text)]">
                      Obfuscate key names
                    </span>{" "}
                    — HMAC every object key. Breaks prefix-based listing; leave off if unsure.
                  </span>
                </label>
              </CollapsibleSection>
            </>
          )}
        </div>
      </Modal>
    </AuthLayout>
  );
}

// ── Subcomponents ─────────────────────────────────────────────────

function AddKindButton({
  label,
  description,
  onClick,
}: {
  label: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="p-3 bg-[var(--color-surface-hover)] hover:bg-[var(--color-border)] text-[var(--color-text)] rounded-lg text-left transition-colors"
    >
      <div className="font-medium text-sm">{label}</div>
      <div className="text-xs text-[var(--color-text-muted)] mt-0.5">
        {description}
      </div>
    </button>
  );
}

function VaultProfileCard({
  profile,
  isDefault,
  opening,
  onOpen,
  onSetDefault,
  onRemove,
}: {
  profile: VaultProfile;
  isDefault: boolean;
  opening: boolean;
  onOpen: () => void;
  onSetDefault: () => void;
  onRemove: () => void;
}) {
  const kindLabel =
    profile.spec.kind === "local"
      ? "Local"
      : profile.spec.kind === "remote"
        ? "Server"
        : "Cloud";
  const subtitle =
    profile.spec.kind === "local"
      ? `Embedded (${(profile.spec as { storage_kind: string }).storage_kind})`
      : profile.spec.kind === "remote"
        ? (profile.spec as { profile: RemoteProfile }).profile.address
        : `${
            (profile.spec as { config: { target: string } }).config.target
          } — cloud-backed`;
  return (
    <div
      className={`p-3 rounded-lg border transition-colors ${
        isDefault
          ? "border-[var(--color-primary)] bg-[var(--color-primary)]/10"
          : "border-[var(--color-border)] bg-[var(--color-surface)]"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <button
          onClick={onOpen}
          disabled={opening}
          className="flex-1 text-left min-w-0 disabled:opacity-60"
        >
          <div className="flex items-center gap-2">
            <span className="font-medium truncate">{profile.name}</span>
            <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]">
              {kindLabel}
            </span>
            {isDefault && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--color-primary)]/30 text-[var(--color-primary)]">
                default
              </span>
            )}
          </div>
          <div className="text-xs text-[var(--color-text-muted)] mt-0.5 truncate">
            {subtitle}
          </div>
        </button>
        <div className="flex items-center gap-1 shrink-0">
          {!isDefault && (
            <button
              onClick={onSetDefault}
              className="text-xs px-2 py-1 text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
              title="Set as default (opens on next app launch)"
            >
              Pin
            </button>
          )}
          <button
            onClick={onRemove}
            className="text-xs px-2 py-1 text-[var(--color-text-muted)] hover:text-red-400 transition-colors"
            title="Forget this vault (does not delete data)"
          >
            Remove
          </button>
        </div>
      </div>
    </div>
  );
}
