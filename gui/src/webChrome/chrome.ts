/**
 * The web session toolbar's view: builds its DOM, polls the host for state
 * and wires Disconnect / Re-run login (features/web-application-connect.md
 * Phase 5, T96). Logic shared with tests lives in `lib/webChrome.ts`.
 *
 * Every value is written with `textContent` / `title` — never as markup —
 * so nothing the host relays (a blocked origin, a resource name) can turn
 * into script in this local, IPC-capable page.
 */
import { extractError } from "../lib/error";
import {
  WEB_CHROME_COMMANDS,
  WEB_CHROME_POLL_MS,
  lockLabel,
  parseChromeState,
  reloginButton,
  statusText,
  timerText,
  type WebChromeState,
} from "../lib/webChrome";

export interface ChromeDeps {
  invoke: (cmd: string) => Promise<unknown>;
  setInterval?: (fn: () => void, ms: number) => unknown;
  clearInterval?: (id: unknown) => void;
}

export interface ChromeHandle {
  /** Ask the host for the current state and render it. */
  refresh: () => Promise<void>;
  /** Stop polling. */
  stop: () => void;
}

/** How long an error from a button stays in the status line. */
const MESSAGE_MS = 8000;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  e.className = className;
  return e;
}

export function mountChrome(root: HTMLElement, deps: ChromeDeps): ChromeHandle {
  const setIntervalFn = deps.setInterval ?? ((fn: () => void, ms: number) => window.setInterval(fn, ms));
  const clearIntervalFn = deps.clearInterval ?? ((id: unknown) => window.clearInterval(id as number));

  root.replaceChildren();
  const lock = el("span", "wc-lock");
  lock.dataset.testid = "wc-lock";
  const origin = el("span", "wc-origin");
  origin.dataset.testid = "wc-origin";
  const resource = el("span", "wc-resource");
  resource.dataset.testid = "wc-resource";
  const status = el("span", "wc-status");
  status.dataset.testid = "wc-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const timer = el("span", "wc-timer");
  timer.dataset.testid = "wc-timer";
  const relogin = el("button", "wc-button");
  relogin.type = "button";
  relogin.textContent = "Re-run login";
  relogin.dataset.testid = "wc-relogin";
  const disconnect = el("button", "wc-button wc-danger");
  disconnect.type = "button";
  disconnect.textContent = "Disconnect";
  disconnect.dataset.testid = "wc-disconnect";

  const where = el("div", "wc-where");
  where.append(lock, origin);
  const what = el("div", "wc-what");
  what.append(resource, status);
  const actions = el("div", "wc-actions");
  actions.append(timer, relogin, disconnect);
  root.append(where, what, actions);

  let state: WebChromeState | null = null;
  let reloginPending = false;
  let ended = false;
  let message: { text: string; until: number } | null = null;
  let timerId: unknown = null;

  const stop = () => {
    if (timerId !== null) {
      clearIntervalFn(timerId);
      timerId = null;
    }
  };

  const showMessage = (text: string) => {
    message = { text, until: Date.now() + MESSAGE_MS };
    render();
  };

  function render() {
    if (ended) {
      status.textContent = "Session ended";
      relogin.disabled = true;
      disconnect.disabled = true;
      return;
    }
    const msg = message && message.until > Date.now() ? message.text : null;
    if (!state) {
      lock.textContent = lockLabel("none").text;
      lock.dataset.lock = "none";
      status.textContent = msg ?? "Waiting for the session…";
      relogin.hidden = true;
      return;
    }
    const l = lockLabel(state.lock);
    lock.textContent = l.text;
    lock.title = l.title;
    lock.dataset.lock = state.lock;
    origin.textContent = state.origin;
    origin.title = state.origin;
    resource.textContent = state.resource;
    status.textContent = msg ?? statusText(state);
    const t = timerText(state);
    timer.textContent = t.text;
    timer.title = t.title;
    const r = reloginButton(state, reloginPending);
    relogin.hidden = !r.visible;
    relogin.disabled = r.disabled;
    relogin.title = r.title;
  }

  async function refresh() {
    if (ended) return;
    try {
      const next = parseChromeState(await deps.invoke(WEB_CHROME_COMMANDS.state));
      state = next;
      if (!next) message = { text: "The host sent a state this toolbar cannot read", until: Date.now() + MESSAGE_MS };
    } catch (e) {
      // The host refuses once the session is gone; nothing more to poll.
      ended = true;
      stop();
      status.title = extractError(e);
    }
    render();
  }

  relogin.addEventListener("click", async () => {
    if (reloginPending || ended) return;
    reloginPending = true;
    render();
    try {
      await deps.invoke(WEB_CHROME_COMMANDS.relogin);
      message = null;
    } catch (e) {
      showMessage(`Re-run refused: ${extractError(e)}`);
    } finally {
      reloginPending = false;
      await refresh();
    }
  });

  disconnect.addEventListener("click", async () => {
    if (ended) return;
    disconnect.disabled = true;
    try {
      await deps.invoke(WEB_CHROME_COMMANDS.disconnect);
    } catch (e) {
      disconnect.disabled = false;
      showMessage(`Disconnect failed: ${extractError(e)}`);
    }
  });

  render();
  timerId = setIntervalFn(() => {
    void refresh();
  }, WEB_CHROME_POLL_MS);
  void refresh();
  return { refresh, stop };
}
