/**
 * The main window's view of a form-mode web session's sign-in outcome
 * (features/web-application-connect.md, T96): the payload the host sends
 * with `emit_to` the main window, read strictly.
 */
import { describe, it, expect } from "vitest";
import {
  WEB_SESSION_OUTCOME_EVENT,
  describeWebSessionOutcome,
  parseWebSessionOutcome,
} from "../lib/webSessionOutcome";

const base = { token: "sess_t", resource: "fw01", profile_id: "p_web", outcome: "success", step: 1 };

describe("web session outcome event", () => {
  it("uses the host's event name", () => {
    expect(WEB_SESSION_OUTCOME_EVENT).toBe("web-session-outcome");
  });

  it("reads the host's payload", () => {
    expect(parseWebSessionOutcome(base)).toEqual(base);
    expect(parseWebSessionOutcome({ ...base, step: null })?.step).toBeNull();
    expect(parseWebSessionOutcome({ ...base, outcome: "aborted:form_action" })?.outcome).toBe("aborted:form_action");
  });

  it("ignores malformed payloads", () => {
    for (const bad of [
      null,
      "success",
      { ...base, outcome: "pwned" },
      { ...base, outcome: "aborted:Bad Check" },
      { ...base, step: -1 },
      { ...base, step: "1" },
      { ...base, token: 5 },
      { resource: "fw01", outcome: "success" },
    ]) {
      expect(parseWebSessionOutcome(bad)).toBeNull();
    }
  });

  it("describes each outcome", () => {
    expect(describeWebSessionOutcome({ ...base, outcome: "success" })).toEqual({
      type: "success",
      message: "Signed in to fw01.",
    });
    expect(describeWebSessionOutcome({ ...base, outcome: "failure" }).type).toBe("error");
    expect(describeWebSessionOutcome({ ...base, outcome: "timeout" }).message).toMatch(/timed out \(step 2\)/);
    expect(describeWebSessionOutcome({ ...base, outcome: "aborted:window_closed" }).type).toBe("info");
    const aborted = describeWebSessionOutcome({ ...base, outcome: "aborted:form_target", step: 0 });
    expect(aborted).toEqual({
      type: "error",
      message: "Sign-in to fw01 stopped (step 1): form target. Nothing more was filled.",
    });
  });
});
