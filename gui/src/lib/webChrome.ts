/**
 * Web session toolbar ("session chrome") — pure logic
 * (features/web-application-connect.md Phase 5, T96).
 *
 * The toolbar is a separate, bundled page (`web-chrome.html`) loaded in its
 * own webview above a web session's remote content. It holds no capability
 * and calls only the three host commands below; the host derives the
 * session from the calling webview, so no command takes a token.
 *
 * Everything shown comes from the host (`session::web_chrome::ChromeState`
 * in `gui/src-tauri`): the origin the host saw loading, never the page's own
 * claims. It is rendered as text only.
 */

/** Host commands. Must match `commands/connect_web_chrome.rs`. */
export const WEB_CHROME_COMMANDS = {
  state: "web_chrome_state",
  disconnect: "web_chrome_disconnect",
  relogin: "web_chrome_relogin",
} as const;

/** How often the toolbar asks the host for its state. */
export const WEB_CHROME_POLL_MS = 1000;

export type WebChromeLock = "none" | "secure" | "pinned" | "insecure";
export type WebChromeRelogin = "available" | "running" | "unavailable";
export type WebChromeLoginMode = "open" | "form" | "http-auth" | "recipe_test";

/** Mirror of `session::web_chrome::ChromeState`. */
export interface WebChromeState {
  resource: string;
  origin: string;
  lock: WebChromeLock;
  notice: string | null;
  login: string | null;
  login_mode: WebChromeLoginMode;
  /** Seconds left in the sign-in window (credential held), or null. */
  login_window_secs: number | null;
  elapsed_secs: number;
  relogin: WebChromeRelogin;
  relogin_reason: string | null;
}

const LOCKS: readonly WebChromeLock[] = ["none", "secure", "pinned", "insecure"];
const RELOGINS: readonly WebChromeRelogin[] = ["available", "running", "unavailable"];
const MODES: readonly WebChromeLoginMode[] = ["open", "form", "http-auth", "recipe_test"];

function str(v: unknown): v is string {
  return typeof v === "string";
}

function nullableStr(v: unknown): v is string | null {
  return v === null || typeof v === "string";
}

function count(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

/**
 * Strictly read the host's reply. Anything unexpected is `null`, which the
 * toolbar shows as "state unavailable" rather than guessing.
 */
export function parseChromeState(v: unknown): WebChromeState | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  if (
    !str(o.resource) ||
    !str(o.origin) ||
    !LOCKS.includes(o.lock as WebChromeLock) ||
    !nullableStr(o.notice) ||
    !nullableStr(o.login) ||
    !MODES.includes(o.login_mode as WebChromeLoginMode) ||
    !(o.login_window_secs === null || count(o.login_window_secs)) ||
    !count(o.elapsed_secs) ||
    !RELOGINS.includes(o.relogin as WebChromeRelogin) ||
    !nullableStr(o.relogin_reason)
  ) {
    return null;
  }
  return {
    resource: o.resource,
    origin: o.origin,
    lock: o.lock as WebChromeLock,
    notice: o.notice,
    login: o.login,
    login_mode: o.login_mode as WebChromeLoginMode,
    login_window_secs: o.login_window_secs as number | null,
    elapsed_secs: o.elapsed_secs,
    relogin: o.relogin as WebChromeRelogin,
    relogin_reason: o.relogin_reason,
  };
}

/** `m:ss`, or `h:mm:ss` from an hour. */
export function formatClock(totalSecs: number): string {
  const s = Math.max(0, Math.floor(totalSecs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
}

/** The lock indicator's short label and its explanation. */
export function lockLabel(lock: WebChromeLock): { text: string; title: string } {
  switch (lock) {
    case "secure":
      return { text: "Secure", title: "HTTPS; the certificate was accepted by the system" };
    case "pinned":
      return {
        text: "Pinned",
        title: "HTTPS; the system rejected the certificate and a pin on this profile accepted it",
      };
    case "insecure":
      return { text: "Not secure", title: "Plain HTTP, allowed by this profile" };
    default:
      return { text: "—", title: "No page loaded yet" };
  }
}

/**
 * The timer: while the host may still hold a released credential, the time
 * left in the sign-in window; otherwise how long the session has been open.
 */
export function timerText(state: WebChromeState): { text: string; title: string } {
  if (state.login_window_secs !== null) {
    return {
      text: `Sign-in ${formatClock(state.login_window_secs)}`,
      title: "Time left in the sign-in window; the credential is dropped when it ends",
    };
  }
  return { text: `Session ${formatClock(state.elapsed_secs)}`, title: "Time since the session opened" };
}

/** The middle text: a notice (blocked navigation) wins over the login state. */
export function statusText(state: WebChromeState): string {
  return state.notice ?? state.login ?? "";
}

/** How the Re-run login button looks. Hidden when it can never apply. */
export function reloginButton(
  state: WebChromeState,
  pending: boolean,
): { visible: boolean; disabled: boolean; title: string } {
  if (state.relogin === "unavailable") {
    return { visible: state.login_mode === "http-auth", disabled: true, title: state.relogin_reason ?? "" };
  }
  if (state.relogin === "running" || pending) {
    return { visible: true, disabled: true, title: "A sign-in re-run is in progress" };
  }
  return {
    visible: true,
    disabled: false,
    title: "Sign in again with a new launch and a fresh credential (the server authorises it again)",
  };
}
