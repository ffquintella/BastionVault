// The fixed fill routine of Web Application Connect, form mode
// (features/web-application-connect.md §5). It ships with the binary and is
// the only JavaScript the host ever runs in a web session window.
//
// The host evaluates `(<this function>)(<args>)` in the window's top frame
// through the webview's native script evaluation (WKWebView
// evaluateJavaScript, WebView2 ExecuteScript, WebKitGTK run_javascript). That
// path is not Tauri IPC: the page gets no channel, and the only thing that
// travels back is this function's return value. `<args>` is a JSON object
// literal the host serialises (`session::web_script::render`); selectors and
// values are data in it, never code.
//
// It returns one JSON string `{v, origin, status, ...}`. It never returns,
// stores or logs a filled value. Every check that fails returns a status and
// changes nothing; `mode: "check"` (the recipe dry run) runs every check and
// never sets a value, clicks or submits.
function (A) {
  "use strict";
  var R = { v: 1, origin: "", status: "script_error" };
  var D = window.document;
  // A cumulative opacity below this is treated as invisible (decoy fields).
  var MIN_OPACITY = 0.5;
  // Smallest field box, in CSS pixels, that counts as visible.
  var MIN_SIDE = 4;
  var TYPES = {
    username: ["text", "email", "tel"],
    password: ["password"],
    totp: ["text", "tel", "number", "password"],
    literal: ["text", "email", "tel", "number", "search", "url"]
  };

  function out(status) {
    R.status = status;
    return JSON.stringify(R);
  }
  // Native accessors from the prototypes, so a form control named `form`,
  // `elements` or `value` cannot shadow them (DOM clobbering).
  function getter(C, p) {
    return Object.getOwnPropertyDescriptor(C.prototype, p).get;
  }
  function setter(C, p) {
    return Object.getOwnPropertyDescriptor(C.prototype, p).set;
  }
  // Every match of `sel` in the top document; null for an unparseable selector.
  function query(sel) {
    try {
      return D.querySelectorAll(sel);
    } catch (e) {
      return null;
    }
  }
  function originOf(raw) {
    try {
      return new URL(raw, D.baseURI).origin;
    } catch (e) {
      return "null";
    }
  }
  function allowed(origin) {
    return A.fill_origins.indexOf(origin) >= 0;
  }
  function formOf(el) {
    if (el instanceof HTMLFormElement) return el;
    if (el instanceof HTMLInputElement) return getter(HTMLInputElement, "form").call(el);
    if (el instanceof HTMLButtonElement) return getter(HTMLButtonElement, "form").call(el);
    return null;
  }
  // The form's action and every submitter's formaction must resolve to an
  // origin of the fill scope. An empty or missing action is the document URL.
  function formTargetsOk(form) {
    if (form === null) return true;
    var action = Element.prototype.getAttribute.call(form, "action");
    var targets = [action === null || action === "" ? D.URL : action];
    var els = getter(HTMLFormElement, "elements").call(form);
    for (var i = 0; i < els.length; i++) {
      var fa = Element.prototype.getAttribute.call(els[i], "formaction");
      if (fa !== null) targets.push(fa === "" ? D.URL : fa);
    }
    for (var j = 0; j < targets.length; j++) {
      if (!allowed(originOf(targets[j]))) return false;
    }
    return true;
  }
  function centre(el) {
    var r = el.getBoundingClientRect();
    return { w: r.width, h: r.height, x: r.left + r.width / 2, y: r.top + r.height / 2 };
  }
  function inViewport(c) {
    return c.x >= 0 && c.y >= 0 && c.x < window.innerWidth && c.y < window.innerHeight;
  }
  // null when `el` is visible and not covered at its centre point;
  // otherwise the failed check.
  function visibility(el) {
    var c = centre(el);
    if (!(c.w >= MIN_SIDE && c.h >= MIN_SIDE)) return "not_visible";
    if (window.getComputedStyle(el).visibility !== "visible") return "not_visible";
    var opacity = 1;
    for (var n = el; n !== null && n.nodeType === 1; n = n.parentElement) {
      var s = window.getComputedStyle(n);
      if (s.display === "none") return "not_visible";
      opacity *= parseFloat(s.opacity);
    }
    if (!(opacity >= MIN_OPACITY)) return "not_visible";
    if (!inViewport(c)) {
      el.scrollIntoView({ block: "center", inline: "center" });
      c = centre(el);
      if (!inViewport(c)) return "not_visible";
    }
    var hit = D.elementFromPoint(c.x, c.y);
    if (hit === el || (hit !== null && el.contains(hit))) return null;
    // A <label> for this very field drawn over it (floating labels).
    var label = hit === null ? null : hit.closest("label");
    if (label !== null && label.control === el) return null;
    return "occluded";
  }
  function fire(el, type) {
    EventTarget.prototype.dispatchEvent.call(el, new Event(type, { bubbles: true }));
  }

  function fill(el) {
    if (!(el instanceof HTMLInputElement)) return out("not_input");
    if (!Object.prototype.hasOwnProperty.call(TYPES, A.expect)) return out("script_error");
    var allowedTypes = TYPES[A.expect];
    if (allowedTypes.indexOf(getter(HTMLInputElement, "type").call(el)) < 0) return out("wrong_type");
    if (getter(HTMLInputElement, "disabled").call(el) || getter(HTMLInputElement, "readOnly").call(el)) {
      return out("disabled");
    }
    var v = visibility(el);
    if (v !== null) return out(v);
    if (!formTargetsOk(formOf(el))) return out("form_action");
    if (A.mode !== "act") return out("ok");
    HTMLElement.prototype.focus.call(el);
    // The native setter, so React / Vue value tracking sees the change.
    setter(HTMLInputElement, "value").call(el, A.value);
    fire(el, "input");
    fire(el, "change");
    return out("ok");
  }
  function click(el) {
    if (!(el instanceof HTMLElement)) return out("not_input");
    if ((el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.disabled === true) {
      return out("disabled");
    }
    var v = visibility(el);
    if (v !== null) return out(v);
    if (!formTargetsOk(formOf(el))) return out("form_action");
    if (A.mode !== "act") return out("ok");
    HTMLElement.prototype.click.call(el);
    return out("ok");
  }
  function submit(el) {
    var form = formOf(el);
    if (form === null) return out("no_form");
    if (!formTargetsOk(form)) return out("form_action");
    if (typeof HTMLFormElement.prototype.requestSubmit !== "function") return out("unsupported");
    if (A.mode !== "act") return out("ok");
    HTMLFormElement.prototype.requestSubmit.call(form);
    return out("ok");
  }
  function action() {
    var m = query(A.selector);
    if (m === null) return out("bad_selector");
    R.matches = m.length;
    if (A.kind === "wait") return out(m.length > 0 ? "ok" : "no_match");
    if (m.length === 0) return out("no_match");
    if (m.length > 1) return out("ambiguous");
    if (A.kind === "fill") return fill(m[0]);
    if (A.kind === "click") return click(m[0]);
    if (A.kind === "submit") return submit(m[0]);
    return out("script_error");
  }
  // Presence counts for the recipe's success_when / failure_when selectors.
  function probe() {
    var m;
    if (typeof A.success_selector === "string") {
      m = query(A.success_selector);
      if (m === null) return out("bad_selector");
      R.success = m.length;
    }
    if (typeof A.failure_selector === "string") {
      m = query(A.failure_selector);
      if (m === null) return out("bad_selector");
      R.failure = m.length;
    }
    return out("ok");
  }
  // Heuristic mode: how many candidates each fixed selector finds.
  function scan() {
    var keys = ["username", "current_password", "password", "otp"];
    var S = {};
    for (var i = 0; i < keys.length; i++) {
      var m = query(A.scan[keys[i]]);
      if (m === null) return out("bad_selector");
      S[keys[i]] = m.length;
    }
    R.scan = S;
    return out("ok");
  }
  // After the outcome: empty every password field still in the document.
  function clear() {
    if (A.mode !== "act") return out("ok");
    var m = query('input[type="password" i]');
    if (m === null) return out("bad_selector");
    var set = setter(HTMLInputElement, "value");
    for (var i = 0; i < m.length; i++) {
      set.call(m[i], "");
      fire(m[i], "input");
    }
    R.matches = m.length;
    return out("ok");
  }

  try {
    R.origin = window.location.origin;
    // `window.top` and `location` are unforgeable; the page cannot fake
    // either. The host passes the origin it observed and checked.
    if (window.top !== window) return out("not_top");
    if (R.origin !== A.origin) return out("origin");
    if (A.op === "action") return action();
    if (A.op === "probe") return probe();
    if (A.op === "scan") return scan();
    if (A.op === "clear") return clear();
    return out("script_error");
  } catch (e) {
    return out("script_error");
  }
}
