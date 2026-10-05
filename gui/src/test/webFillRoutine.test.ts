/**
 * The fixed fill routine of Web Application Connect form mode
 * (features/web-application-connect.md §5, T96 Phase 2), executed against a
 * jsdom page. The routine ships inside the desktop host
 * (`gui/src-tauri/src/session/web_fill_routine.js`); the host evaluates
 * `(<routine>)(<JSON args>)` in the session window. jsdom has no layout, so
 * each test gives the fields it needs a box and a hit-test result.
 */
import { describe, it, expect, beforeEach } from "vitest";
import routineSource from "../../src-tauri/src/session/web_fill_routine.js?raw";

type Reply = {
  v: number;
  origin: string;
  status: string;
  matches?: number;
  success?: number;
  failure?: number;
  scan?: Record<string, number>;
};

const ORIGIN = window.location.origin;

/** Evaluate the routine the way the host does: one expression, JSON args. */
function run(args: Record<string, unknown>): Reply {
  const script = `(${routineSource.trimEnd()})(${JSON.stringify({ origin: ORIGIN, fill_origins: [ORIGIN], ...args })})`;
  const raw = (0, eval)(script) as unknown;
  expect(typeof raw).toBe("string");
  return JSON.parse(raw as string) as Reply;
}

function fill(selector: string, expectKind: string, value: string, extra: Record<string, unknown> = {}) {
  return run({ op: "action", mode: "act", kind: "fill", selector, expect: expectKind, value, ...extra });
}

/** Give an element a visible box and make it the hit-test winner. */
function layout(el: Element, box = { left: 10, top: 10, width: 200, height: 24 }) {
  Object.defineProperty(el, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ ...box, right: box.left + box.width, bottom: box.top + box.height, x: box.left, y: box.top }),
  });
}

function hitTest(winner: () => Element | null) {
  Object.defineProperty(document, "elementFromPoint", { configurable: true, value: winner });
}

function el<T extends Element>(sel: string): T {
  const e = document.querySelector(sel);
  if (!e) throw new Error(`missing ${sel}`);
  return e as T;
}

beforeEach(() => {
  document.body.innerHTML = `
    <form id="login" action="/session">
      <input id="u" name="username" type="text">
      <input id="p" name="password" type="password">
      <button id="go" type="submit">Sign in</button>
    </form>`;
  for (const s of ["#u", "#p", "#go"]) layout(el(s));
  hitTest(() => null);
  Object.defineProperty(Element.prototype, "scrollIntoView", { configurable: true, value: () => {} });
});

describe("fill routine — fill", () => {
  it("sets the value through the native setter and fires input/change", () => {
    const u = el<HTMLInputElement>("#u");
    hitTest(() => u);
    const events: string[] = [];
    u.addEventListener("input", () => events.push("input"));
    u.addEventListener("change", () => events.push("change"));
    // A React-style instance override must be bypassed, not called.
    let ownSetterCalls = 0;
    Object.defineProperty(u, "value", {
      configurable: true,
      get: () => "",
      set: () => {
        ownSetterCalls += 1;
      },
    });
    const r = fill("#u", "username", "admin");
    expect(r).toEqual({ v: 1, origin: ORIGIN, status: "ok", matches: 1 });
    expect(ownSetterCalls).toBe(0);
    expect(events).toEqual(["input", "change"]);
    delete (u as unknown as Record<string, unknown>).value;
    expect(u.value).toBe("admin");
  });

  it("writes hostile values literally and never echoes them", () => {
    const p = el<HTMLInputElement>("#p");
    hitTest(() => p);
    for (const v of ['";alert(1)//', "</script><script>alert(1)</script>", "a b\\c`${x}`"]) {
      const r = fill("#p", "password", v);
      expect(r.status).toBe("ok");
      expect(JSON.stringify(r)).not.toContain(v);
      expect(p.value).toBe(v);
    }
  });

  it("check mode runs every check and changes nothing", () => {
    const p = el<HTMLInputElement>("#p");
    hitTest(() => p);
    const r = run({ op: "action", mode: "check", kind: "fill", selector: "#p", expect: "password" });
    expect(r.status).toBe("ok");
    expect(p.value).toBe("");
  });

  it("refuses to run on another origin than the host checked", () => {
    hitTest(() => el("#u"));
    const r = fill("#u", "username", "admin", { origin: "https://fw01.example.com" });
    expect(r.status).toBe("origin");
    expect(el<HTMLInputElement>("#u").value).toBe("");
  });

  it("requires exactly one match and a parseable selector", () => {
    expect(fill("#nope", "username", "x").status).toBe("no_match");
    expect(fill("input", "username", "x").status).toBe("ambiguous");
    expect(fill("input[", "username", "x").status).toBe("bad_selector");
  });

  it("requires an input of the expected type", () => {
    hitTest(() => el("#p"));
    expect(fill("#p", "username", "admin").status).toBe("wrong_type");
    hitTest(() => el("#u"));
    expect(fill("#u", "password", "pw").status).toBe("wrong_type");
    expect(fill("#go", "username", "x").status).toBe("not_input");
  });

  it("refuses an opacity-0 decoy, a zero box and hidden fields", () => {
    const u = el<HTMLInputElement>("#u");
    hitTest(() => u);
    el<HTMLFormElement>("#login").style.opacity = "0";
    expect(fill("#u", "username", "x").status).toBe("not_visible");
    el<HTMLFormElement>("#login").style.opacity = "1";
    u.style.visibility = "hidden";
    expect(fill("#u", "username", "x").status).toBe("not_visible");
    u.style.visibility = "";
    layout(u, { left: 10, top: 10, width: 1, height: 1 });
    expect(fill("#u", "username", "x").status).toBe("not_visible");
    layout(u, { left: -5000, top: -5000, width: 200, height: 24 });
    expect(fill("#u", "username", "x").status).toBe("not_visible");
    expect(u.value).toBe("");
  });

  it("refuses a field covered at its centre, but accepts its own label", () => {
    const overlay = document.createElement("div");
    document.body.appendChild(overlay);
    hitTest(() => overlay);
    expect(fill("#u", "username", "x").status).toBe("occluded");
    const label = document.createElement("label");
    label.htmlFor = "u";
    const span = document.createElement("span");
    label.appendChild(span);
    document.body.appendChild(label);
    hitTest(() => span);
    expect(fill("#u", "username", "x").status).toBe("ok");
  });

  it("refuses a form that posts off-origin, even when DOM clobbering hides it", () => {
    hitTest(() => el("#u"));
    const form = el<HTMLFormElement>("#login");
    form.setAttribute("action", "https://evil.example/collect");
    // `form.action` / `form.elements` are shadowed by these named controls.
    form.insertAdjacentHTML("beforeend", '<input name="action" value="/session"><input name="elements">');
    expect(fill("#u", "username", "x").status).toBe("form_action");
    form.setAttribute("action", "/session");
    expect(fill("#u", "username", "x").status).toBe("ok");
    // A submitter's formaction counts too.
    el("#go").setAttribute("formaction", "https://evil.example/collect");
    expect(fill("#u", "username", "x").status).toBe("form_action");
    el("#go").setAttribute("formaction", "javascript:alert(1)");
    expect(fill("#u", "username", "x").status).toBe("form_action");
  });

  it("checks image submits, which form.elements leaves out, and the click target's own formaction", () => {
    const form = el<HTMLFormElement>("#login");
    form.insertAdjacentHTML("beforeend", '<input id="img" type="image" alt="go" formaction="https://evil.example/c">');
    const img = el<HTMLInputElement>("#img");
    layout(img);
    expect(Array.from(form.elements)).not.toContain(img);
    hitTest(() => img);
    // Clicking the image submit itself...
    expect(run({ op: "action", mode: "check", kind: "click", selector: "#img" }).status).toBe("form_action");
    expect(run({ op: "action", mode: "act", kind: "click", selector: "#img" }).status).toBe("form_action");
    // ...and filling any field of a form it can submit.
    hitTest(() => el("#u"));
    expect(fill("#u", "username", "x").status).toBe("form_action");
    expect(el<HTMLInputElement>("#u").value).toBe("");
    // An image submit attached from outside with `form=` counts too.
    img.remove();
    document.body.insertAdjacentHTML(
      "beforeend",
      '<input id="img2" type="image" form="login" alt="go" formaction="https://evil.example/c">',
    );
    expect(fill("#u", "username", "x").status).toBe("form_action");
    el("#img2").setAttribute("formaction", "/session");
    expect(fill("#u", "username", "x").status).toBe("ok");
  });

  it("refuses a form that submits into a named frame", () => {
    document.body.insertAdjacentHTML("beforeend", '<iframe name="sink"></iframe>');
    const form = el<HTMLFormElement>("#login");
    hitTest(() => el("#u"));
    form.setAttribute("target", "sink");
    // A control named `target` cannot hide the attribute.
    form.insertAdjacentHTML("beforeend", '<input name="target" value="_self">');
    expect(fill("#u", "username", "x").status).toBe("form_target");
    expect(el<HTMLInputElement>("#u").value).toBe("");
    for (const ok of ["", "_self", "_TOP", "_parent", "_blank"]) {
      form.setAttribute("target", ok);
      expect(fill("#u", "username", "x").status).toBe("ok");
    }
    // A submitter's formtarget, and a document-wide <base target>.
    form.removeAttribute("target");
    el("#go").setAttribute("formtarget", "sink");
    hitTest(() => el("#go"));
    expect(run({ op: "action", mode: "act", kind: "click", selector: "#go" }).status).toBe("form_target");
    expect(run({ op: "action", mode: "act", kind: "submit", selector: "form" }).status).toBe("form_target");
    el("#go").removeAttribute("formtarget");
    document.head.insertAdjacentHTML("beforeend", '<base target="sink">');
    hitTest(() => el("#u"));
    expect(fill("#u", "username", "x").status).toBe("form_target");
    document.head.querySelector("base")?.remove();
  });

  it("treats a disabled field as not ready", () => {
    hitTest(() => el("#u"));
    el<HTMLInputElement>("#u").disabled = true;
    expect(fill("#u", "username", "x").status).toBe("disabled");
  });
});

describe("fill routine — click, submit, wait", () => {
  it("clicks a visible control and submits through requestSubmit", () => {
    const go = el<HTMLButtonElement>("#go");
    hitTest(() => go);
    let submits = 0;
    el("#login").addEventListener("submit", (e) => {
      e.preventDefault();
      submits += 1;
    });
    expect(run({ op: "action", mode: "act", kind: "click", selector: "#go" }).status).toBe("ok");
    expect(run({ op: "action", mode: "act", kind: "submit", selector: "form" }).status).toBe("ok");
    expect(submits).toBe(2);
    // Check mode never clicks or submits.
    expect(run({ op: "action", mode: "check", kind: "click", selector: "#go" }).status).toBe("ok");
    expect(run({ op: "action", mode: "check", kind: "submit", selector: "form" }).status).toBe("ok");
    expect(submits).toBe(2);
  });

  it("refuses to submit a field outside any form", () => {
    document.body.insertAdjacentHTML("beforeend", '<input id="loose" type="text">');
    expect(run({ op: "action", mode: "act", kind: "submit", selector: "#loose" }).status).toBe("no_form");
  });

  it("waits for presence, not uniqueness", () => {
    expect(run({ op: "action", mode: "act", kind: "wait", selector: "input" }).status).toBe("ok");
    expect(run({ op: "action", mode: "act", kind: "wait", selector: ".later" }).status).toBe("no_match");
  });
});

describe("fill routine — probe, scan, clear", () => {
  it("counts the outcome selectors", () => {
    document.body.insertAdjacentHTML("beforeend", '<div class="error">bad password</div>');
    const r = run({ op: "probe", mode: "check", success_selector: "#dashboard", failure_selector: ".error" });
    expect(r).toMatchObject({ status: "ok", success: 0, failure: 1 });
    expect(run({ op: "probe", mode: "check", failure_selector: "[" }).status).toBe("bad_selector");
  });

  it("counts heuristic candidates with the host's selectors", () => {
    el("#u").setAttribute("autocomplete", "section-a username");
    const r = run({
      op: "scan",
      mode: "check",
      scan: {
        username: 'input[autocomplete~="username" i]',
        current_password: 'input[autocomplete~="current-password" i]',
        password: 'input[type="password" i]',
        otp: 'input[autocomplete~="one-time-code" i]',
      },
    });
    expect(r.scan).toEqual({ username: 1, current_password: 0, password: 1, otp: 0 });
  });

  it("clears every password field after the outcome", () => {
    el<HTMLInputElement>("#p").value = "hunter2";
    const r = run({ op: "clear", mode: "act" });
    expect(r).toMatchObject({ status: "ok", matches: 1 });
    expect(el<HTMLInputElement>("#p").value).toBe("");
  });

  it("an unknown op is an error, not a no-op", () => {
    expect(run({ op: "exfiltrate", mode: "act" }).status).toBe("script_error");
  });
});
