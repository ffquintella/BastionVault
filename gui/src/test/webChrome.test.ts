import { describe, expect, it, vi } from "vitest";
import {
  WEB_CHROME_COMMANDS,
  formatClock,
  lockLabel,
  parseChromeState,
  reloginButton,
  statusText,
  timerText,
  type WebChromeState,
} from "../lib/webChrome";
import { mountChrome } from "../webChrome/chrome";

function state(over: Partial<WebChromeState> = {}): WebChromeState {
  return {
    resource: "fw01",
    origin: "https://fw01.example.com",
    lock: "secure",
    notice: null,
    login: "signed in",
    login_mode: "form",
    login_window_secs: null,
    elapsed_secs: 65,
    relogin: "available",
    relogin_reason: null,
    ...over,
  };
}

describe("web session toolbar — pure logic", () => {
  it("reads the host's state strictly", () => {
    expect(parseChromeState(state())).toEqual(state());
    expect(parseChromeState(null)).toBeNull();
    expect(parseChromeState("x")).toBeNull();
    expect(parseChromeState({ ...state(), lock: "green" })).toBeNull();
    expect(parseChromeState({ ...state(), relogin: "yes" })).toBeNull();
    expect(parseChromeState({ ...state(), login_mode: "sso" })).toBeNull();
    expect(parseChromeState({ ...state(), elapsed_secs: -1 })).toBeNull();
    expect(parseChromeState({ ...state(), elapsed_secs: 1.5 })).toBeNull();
    expect(parseChromeState({ ...state(), login_window_secs: "30" })).toBeNull();
    expect(parseChromeState({ ...state(), origin: 42 })).toBeNull();
    const missing: Record<string, unknown> = { ...state() };
    delete missing.notice;
    expect(parseChromeState(missing)).toBeNull();
  });

  it("formats clocks", () => {
    expect(formatClock(0)).toBe("0:00");
    expect(formatClock(42)).toBe("0:42");
    expect(formatClock(65)).toBe("1:05");
    expect(formatClock(3600)).toBe("1:00:00");
    expect(formatClock(3725)).toBe("1:02:05");
    expect(formatClock(-3)).toBe("0:00");
  });

  it("labels every lock state", () => {
    expect(lockLabel("secure").text).toBe("Secure");
    expect(lockLabel("pinned").text).toBe("Pinned");
    expect(lockLabel("pinned").title).toMatch(/pin/);
    expect(lockLabel("insecure").text).toBe("Not secure");
    expect(lockLabel("none").text).toBe("—");
  });

  it("shows the sign-in window while a credential is held, the session age otherwise", () => {
    expect(timerText(state({ login_window_secs: 42 })).text).toBe("Sign-in 0:42");
    expect(timerText(state()).text).toBe("Session 1:05");
  });

  it("puts a notice before the login state", () => {
    expect(statusText(state())).toBe("signed in");
    expect(statusText(state({ notice: "blocked: https://evil.example" }))).toBe("blocked: https://evil.example");
    expect(statusText(state({ login: null }))).toBe("");
  });

  it("offers Re-run login for form sessions and explains it for http-auth", () => {
    expect(reloginButton(state(), false)).toMatchObject({ visible: true, disabled: false });
    expect(reloginButton(state(), true)).toMatchObject({ visible: true, disabled: true });
    expect(reloginButton(state({ relogin: "running" }), false)).toMatchObject({ visible: true, disabled: true });
    const http = reloginButton(
      state({ login_mode: "http-auth", relogin: "unavailable", relogin_reason: "answered once per window" }),
      false,
    );
    expect(http).toEqual({ visible: true, disabled: true, title: "answered once per window" });
    expect(reloginButton(state({ login_mode: "open", relogin: "unavailable" }), false).visible).toBe(false);
    expect(reloginButton(state({ login_mode: "recipe_test", relogin: "unavailable" }), false).visible).toBe(false);
  });
});

function harness(reply: (cmd: string) => unknown | Promise<unknown>) {
  const root = document.createElement("div");
  const calls: string[] = [];
  let tick: (() => void) | null = null;
  const clearInterval = vi.fn();
  const handle = mountChrome(root, {
    invoke: async (cmd) => {
      calls.push(cmd);
      return reply(cmd);
    },
    setInterval: (fn) => {
      tick = fn;
      return 7;
    },
    clearInterval,
  });
  const q = (id: string) => root.querySelector(`[data-testid="${id}"]`) as HTMLElement;
  const flush = () => new Promise((r) => setTimeout(r, 0));
  return { root, calls, handle, q, flush, tick: () => tick?.(), clearInterval };
}

describe("web session toolbar — view", () => {
  it("renders the host's state as text only", async () => {
    const hostile = "<img src=x onerror=alert(1)>";
    const h = harness(() => state({ resource: hostile, notice: `blocked: ${hostile}` }));
    await h.flush();
    expect(h.calls).toEqual([WEB_CHROME_COMMANDS.state]);
    expect(h.q("wc-resource").textContent).toBe(hostile);
    expect(h.q("wc-status").textContent).toBe(`blocked: ${hostile}`);
    expect(h.root.querySelector("img")).toBeNull();
    expect(h.q("wc-origin").textContent).toBe("https://fw01.example.com");
    expect(h.q("wc-lock").textContent).toBe("Secure");
    expect(h.q("wc-lock").dataset.lock).toBe("secure");
    expect(h.q("wc-timer").textContent).toBe("Session 1:05");
  });

  it("polls through the interval and stops once the session has ended", async () => {
    let alive = true;
    const h = harness(() => {
      if (!alive) throw { message: "this web session has ended" };
      return state();
    });
    await h.flush();
    h.tick();
    await h.flush();
    expect(h.calls.length).toBe(2);
    alive = false;
    h.tick();
    await h.flush();
    expect(h.q("wc-status").textContent).toBe("Session ended");
    expect(h.clearInterval).toHaveBeenCalledWith(7);
    expect((h.q("wc-relogin") as HTMLButtonElement).disabled).toBe(true);
    expect((h.q("wc-disconnect") as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows a placeholder for a state it cannot read", async () => {
    const h = harness(() => ({ resource: "fw01" }));
    await h.flush();
    expect(h.q("wc-status").textContent).toMatch(/cannot read/);
    expect(h.q("wc-relogin").hidden).toBe(true);
  });

  it("re-runs the login through the host and shows a refusal", async () => {
    const h = harness((cmd) => {
      if (cmd === WEB_CHROME_COMMANDS.relogin) {
        throw { message: "launch refused: connect MFA required" };
      }
      return state();
    });
    await h.flush();
    const button = h.q("wc-relogin") as HTMLButtonElement;
    expect(button.hidden).toBe(false);
    button.click();
    expect(button.disabled).toBe(true);
    await h.flush();
    await h.flush();
    expect(h.calls).toContain(WEB_CHROME_COMMANDS.relogin);
    expect(h.q("wc-status").textContent).toBe("Re-run refused: launch refused: connect MFA required");
    expect(button.disabled).toBe(false);
  });

  it("hides Re-run login for an open session and disconnects through the host", async () => {
    const h = harness(() => state({ login_mode: "open", relogin: "unavailable", relogin_reason: "no credential" }));
    await h.flush();
    expect(h.q("wc-relogin").hidden).toBe(true);
    (h.q("wc-disconnect") as HTMLButtonElement).click();
    await h.flush();
    expect(h.calls).toContain(WEB_CHROME_COMMANDS.disconnect);
    expect((h.q("wc-disconnect") as HTMLButtonElement).disabled).toBe(true);
  });

  it("never sends a token or any argument", async () => {
    const invoke = vi.fn(async (cmd: string) => (cmd === WEB_CHROME_COMMANDS.state ? state() : undefined));
    const root = document.createElement("div");
    mountChrome(root, { invoke, setInterval: () => 1, clearInterval: () => {} });
    await new Promise((r) => setTimeout(r, 0));
    (root.querySelector('[data-testid="wc-relogin"]') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    for (const call of invoke.mock.calls) {
      expect(call).toHaveLength(1);
    }
  });
});
