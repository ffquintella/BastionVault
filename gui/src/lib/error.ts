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

