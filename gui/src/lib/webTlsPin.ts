/**
 * TLS SPKI pins for `web` connection profiles
 * (features/web-application-connect.md §8, T96 Phase 4).
 *
 * Mirrors the host's `SpkiPin::parse` (`gui/src-tauri/src/session/web_tls_pin.rs`)
 * so the editor refuses at save time exactly what the host would refuse at
 * connect time. A pin is the SHA-256 of a certificate's DER
 * SubjectPublicKeyInfo. Accepted forms:
 *
 * - `sha256:<64 hex digits>` — canonical; prefix optional and
 *   case-insensitive, hex any case, `:` between byte pairs tolerated;
 * - `sha256/<base64>` or curl's `sha256//<base64>` — standard, padded base64
 *   of the 32 bytes (RFC 7469 / `curl --pinnedpubkey`); also accepted bare.
 */

/** Most pins one profile may carry (the host's `MAX_PINS`). */
export const MAX_TLS_PINS = 16;

export type TlsPinResult = { pin: string } | { error: string };

function fromHex(h: string): string | null {
  let compact = h;
  if (h.includes(":")) {
    const parts = h.split(":");
    if (parts.length !== 32 || parts.some((p) => p.length !== 2)) return null;
    compact = parts.join("");
  }
  return /^[0-9a-f]{64}$/.test(compact) ? compact : null;
}

function fromBase64(b: string, shown: string): TlsPinResult {
  // 32 bytes in standard, padded base64: 43 characters and one "=".
  if (!/^[A-Za-z0-9+/]{43}=$/.test(b)) {
    return { error: `“${shown}” is not a base64 SHA-256 pin (44 characters, standard alphabet, padded).` };
  }
  const bin = atob(b);
  // The host's decoder refuses non-canonical trailing bits; so does this.
  if (btoa(bin) !== b) {
    return { error: `“${shown}” is not canonical base64.` };
  }
  const hex = Array.from(bin, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  return { pin: `sha256:${hex}` };
}

/** Parse one pin into its canonical `sha256:<hex>` form. */
export function normalizeTlsPin(raw: string): TlsPinResult {
  const s = raw.trim();
  if (!s) return { error: "A TLS pin is empty." };
  const lower = s.toLowerCase();
  if (lower.startsWith("sha256//")) return fromBase64(s.slice(8), s);
  if (lower.startsWith("sha256/")) return fromBase64(s.slice(7), s);
  const prefixed = lower.startsWith("sha256:");
  const hex = fromHex(prefixed ? lower.slice(7) : lower);
  if (hex) return { pin: `sha256:${hex}` };
  if (!prefixed && s.length === 44) return fromBase64(s, s);
  return {
    error: `“${s}” is not a SHA-256 public-key pin — give sha256:<64 hex digits> or sha256/<base64>.`,
  };
}

/**
 * Save-time check of `web.tls_pin_sha256`. Every entry must parse: one that
 * does not refuses the profile (the host refuses it too), never a silently
 * smaller pin set.
 */
export function validateTlsPins(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value)) return "TLS pins must be a list.";
  if (value.length > MAX_TLS_PINS) return `At most ${MAX_TLS_PINS} TLS pins are allowed (this profile has ${value.length}).`;
  for (const entry of value) {
    if (typeof entry !== "string") return "Every TLS pin must be text.";
    const r = normalizeTlsPin(entry);
    if ("error" in r) return r.error;
  }
  return null;
}

/** The canonical pins of a list, deduplicated; unreadable entries are left out. */
export function canonicalTlsPins(list: readonly string[]): string[] {
  const out: string[] = [];
  for (const entry of list) {
    const r = normalizeTlsPin(entry);
    if ("pin" in r && !out.includes(r.pin)) out.push(r.pin);
  }
  return out;
}
