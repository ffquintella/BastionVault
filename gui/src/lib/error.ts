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
