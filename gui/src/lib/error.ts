/**
 * Extract a human-readable error message from a Tauri command error.
 *
 * Tauri serialises `CommandError { message }` as a plain JS object,
 * so `String(e)` produces the useless "[object Object]".  This helper
 * checks for the `.message` field first.
 */
export function extractError(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "object" && e !== null && "message" in e)
    return String((e as { message: unknown }).message);
  return String(e);
}

/**
 * Recognise the bv-client `ClientError::NodeUnavailable` wrapped by
 * the command layer. The cluster-discovery feature surfaces this
 * shape — `node \`<host>\` is unavailable: <reason>` — when the
 * pinned remote node fails mid-session. Frontend uses it to show a
 * "Reconnect" CTA instead of a generic error toast.
 */
export function isNodeUnavailable(e: unknown): boolean {
  return extractError(e).includes("is unavailable:");
}

/**
 * True when the backend returned 404 because the targeted mount or
 * route is not registered on this server — e.g. an older server build
 * that predates a newer GUI's Phase 7 Rustion policy routes. Lets the
 * UI render an "unavailable on this server" empty state instead of a
 * generic error toast.
 */
export function isMountNotFound(e: unknown): boolean {
  const msg = extractError(e);
  return msg.includes("404") && /mount not found|no handler for route/i.test(msg);
}

/**
 * True when the server rejected the request *body* — HTTP 400 carrying
 * either a serde parse error (`unknown variant`, `unknown field`) or the
 * generic `Request is invalid.` older builds returned in its place.
 *
 * In practice this is version skew rather than a malformed request: the
 * GUI named an enum value or field the connected server's build does not
 * know, so its deserializer refused the whole body. Callers pair this
 * with the feature they just asked for to add an "upgrade the server"
 * hint instead of surfacing a dead-end 400.
 */
export function isUnsupportedRequestShape(e: unknown): boolean {
  const msg = extractError(e);
  return (
    msg.includes("400") &&
    (/request is invalid/i.test(msg) || /unknown (variant|field)/i.test(msg))
  );
}

/**
 * True when the failure was caused by the vault being sealed — the
 * barrier is locked so no auth backend can mint a token. Surfaced on
 * the login page (e.g. `node \`<host>\` is unavailable: BastionVault is
 * sealed.`) so the operator can be offered an unseal action instead of
 * a dead-end error. The `\b` anchors keep this from matching the
 * opposite "unsealed" wording.
 */
export function isVaultSealed(e: unknown): boolean {
  return /\bsealed\b/i.test(extractError(e));
}

/**
 * True when the backend denied the request for lack of capability —
 * HTTP 403. Read-only share-grantees and non-admin users hit this on
 * routes they can't read (e.g. the Rustion dispatcher preview). Lets a
 * purely informational panel stay out of the way instead of rendering
 * a red "unavailable" error for an expected permission boundary.
 */
export function isPermissionDenied(e: unknown): boolean {
  const msg = extractError(e);
  return msg.includes("403") || /permission denied/i.test(msg);
}


/**
 * True when the server does not have the route the GUI just asked for
 * — the logical router matched the mount but no path pattern, which
 * both the HTTP and embedded backends report as "Logical backend path
 * not supported." (`RvError::ErrLogicalPathUnsupported`).
 *
 * This is version skew, not a malformed request: a newer GUI reaching
 * an older server build. Distinct from `isMountNotFound`, where the
 * whole mount is absent. Callers use it to fall back to the older
 * route they know the server has.
 */
export function isRouteUnsupported(e: unknown): boolean {
  return /path not supported/i.test(extractError(e));
}
