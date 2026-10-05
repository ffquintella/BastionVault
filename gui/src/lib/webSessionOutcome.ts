/**
 * Web Application Connect, form mode (features/web-application-connect.md,
 * T96): the desktop host tells the main window how a session's sign-in
 * ended. The event is sent to the main window only and carries names and the
 * outcome — never a credential, a TOTP code or a URL.
 */

/** Must match `WEB_SESSION_OUTCOME_EVENT` in `session/web_recipe.rs`. */
export const WEB_SESSION_OUTCOME_EVENT = "web-session-outcome";

export interface WebSessionOutcome {
  token: string;
  resource: string;
  profile_id: string;
  /** `success` | `failure` | `timeout` | `aborted:<check>`. */
  outcome: string;
  step: number | null;
}

const OUTCOME_RE = /^(success|failure|timeout|aborted:[a-z0-9_]{1,32})$/;

/** Strictly read an event payload; anything malformed is ignored. */
export function parseWebSessionOutcome(payload: unknown): WebSessionOutcome | null {
  if (typeof payload !== "object" || payload === null) return null;
  const p = payload as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : null);
  const token = str(p.token);
  const resource = str(p.resource);
  const profileId = str(p.profile_id);
  const outcome = str(p.outcome);
  if (token === null || resource === null || profileId === null || outcome === null) return null;
  if (!OUTCOME_RE.test(outcome)) return null;
  const step = p.step === null || p.step === undefined ? null : p.step;
  if (step !== null && (typeof step !== "number" || !Number.isInteger(step) || step < 0)) return null;
  return { token, resource, profile_id: profileId, outcome, step };
}

/** The toast for an outcome. */
export function describeWebSessionOutcome(e: WebSessionOutcome): {
  type: "success" | "error" | "info";
  message: string;
} {
  const step = e.step === null ? "" : ` (step ${e.step + 1})`;
  if (e.outcome === "success") return { type: "success", message: `Signed in to ${e.resource}.` };
  if (e.outcome === "failure") {
    return { type: "error", message: `Sign-in to ${e.resource} failed${step}: the application reported an error.` };
  }
  if (e.outcome === "timeout") {
    return { type: "error", message: `Sign-in to ${e.resource} timed out${step}.` };
  }
  const check = e.outcome.slice("aborted:".length);
  if (check === "window_closed" || check === "session_closed") {
    return { type: "info", message: `Sign-in to ${e.resource} stopped: the session was closed.` };
  }
  return {
    type: "error",
    message: `Sign-in to ${e.resource} stopped${step}: ${check.replace(/_/g, " ")}. Nothing more was filled.`,
  };
}
