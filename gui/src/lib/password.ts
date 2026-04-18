/**
 * Cryptographically-secure password generator.
 *
 * Uses `crypto.getRandomValues` (WebCrypto) -- NOT `Math.random`, which is
 * predictable. WebView2 / modern browsers always expose WebCrypto.
 */

export interface PasswordOptions {
  /** Total password length. Clamped to [1, 512]. */
  length: number;
  /** Include a-z. */
  lowercase: boolean;
  /** Include A-Z. */
  uppercase: boolean;
  /** Include 0-9. */
  digits: boolean;
  /** Include !@#$%^&* and friends. */
  symbols: boolean;
  /** Exclude visually confusable characters (0/O, 1/l/I, |, backtick, quotes). */
  excludeAmbiguous?: boolean;
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
// Keep to printable ASCII, avoid space (which trims oddly) and backslash
// (which needs escaping everywhere).
const SYMBOLS = "!@#$%^&*()-_=+[]{}<>?/.,;:";
const AMBIGUOUS = "0O1lI|`'\"";

function stripAmbiguous(s: string): string {
  let out = "";
  for (const c of s) if (!AMBIGUOUS.includes(c)) out += c;
  return out;
}

/**
 * Draw `count` uniformly-random indices in the range `[0, max)` using
 * rejection sampling to avoid modulo bias. `max` must be > 0 and <= 2**32.
 */
function randomIndices(count: number, max: number): number[] {
  if (max <= 0) throw new Error("max must be positive");
  if (count <= 0) return [];
  // Largest multiple of `max` that fits in 2**32; values above this are rejected.
  const limit = Math.floor(0x100000000 / max) * max;
  const out: number[] = [];
  // Over-sample to reduce round-trips to the RNG on rejection.
  const batch = Math.max(count * 2, 32);
  const buf = new Uint32Array(batch);
  while (out.length < count) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < count; i++) {
      if (buf[i] < limit) out.push(buf[i] % max);
    }
  }
  return out;
}

/** Shape of the stored password policy. Kept loose so this file does not
 *  have to import the store/types module (which imports React). */
export interface PasswordPolicyShape {
  min_length: number;
  require_lowercase: boolean;
  require_uppercase: boolean;
  require_digits: boolean;
  require_symbols: boolean;
}

export interface PasswordPolicyCheck {
  ok: boolean;
  /** Human-readable list of missing criteria, e.g. ["a digit", "at least 16 characters"]. */
  failures: string[];
}

/**
 * Validate a candidate password against the configured policy. Returns the
 * set of failing criteria. An empty string is treated as any other short
 * password (it fails the length check) -- callers that want to allow
 * "blank = no change" should branch on that themselves before calling.
 */
export function checkPasswordPolicy(
  password: string,
  policy: PasswordPolicyShape,
): PasswordPolicyCheck {
  const failures: string[] = [];
  if (password.length < policy.min_length) {
    failures.push(`at least ${policy.min_length} characters`);
  }
  if (policy.require_lowercase && !/[a-z]/.test(password)) {
    failures.push("a lowercase letter");
  }
  if (policy.require_uppercase && !/[A-Z]/.test(password)) {
    failures.push("an uppercase letter");
  }
  if (policy.require_digits && !/[0-9]/.test(password)) {
    failures.push("a digit");
  }
  if (policy.require_symbols && !/[^A-Za-z0-9]/.test(password)) {
    failures.push("a symbol");
  }
  return { ok: failures.length === 0, failures };
}

/** Render a policy as a short one-line summary, e.g.
 *  "Min 16 chars, requires lowercase, uppercase, digits". */
export function describePolicy(policy: PasswordPolicyShape): string {
  const parts: string[] = [`Min ${policy.min_length} chars`];
  const groups: string[] = [];
  if (policy.require_lowercase) groups.push("lowercase");
  if (policy.require_uppercase) groups.push("uppercase");
  if (policy.require_digits) groups.push("digits");
  if (policy.require_symbols) groups.push("symbols");
  if (groups.length) parts.push(`requires ${groups.join(", ")}`);
  return parts.join(", ");
}

/**
 * Generate a password matching `opts`. Guarantees at least one character
 * from each selected group (as long as `length` is at least the number of
 * selected groups). Returns the empty string if no character groups are
 * selected or `length <= 0`.
 */
export function generatePassword(opts: PasswordOptions): string {
  const length = Math.max(0, Math.min(512, Math.floor(opts.length)));
  if (length === 0) return "";

  const groups: string[] = [];
  if (opts.lowercase) groups.push(opts.excludeAmbiguous ? stripAmbiguous(LOWER) : LOWER);
  if (opts.uppercase) groups.push(opts.excludeAmbiguous ? stripAmbiguous(UPPER) : UPPER);
  if (opts.digits) groups.push(opts.excludeAmbiguous ? stripAmbiguous(DIGITS) : DIGITS);
  if (opts.symbols) groups.push(opts.excludeAmbiguous ? stripAmbiguous(SYMBOLS) : SYMBOLS);
  const usable = groups.filter((g) => g.length > 0);
  if (usable.length === 0) return "";

  const pool = usable.join("");

  // Pick one character from each required group first (up to `length`).
  const required: string[] = [];
  for (const group of usable) {
    if (required.length >= length) break;
    const [idx] = randomIndices(1, group.length);
    required.push(group[idx]);
  }
  // Fill the remainder from the combined pool.
  const remaining = length - required.length;
  const poolIndices = randomIndices(remaining, pool.length);
  const chars = [...required, ...poolIndices.map((i) => pool[i])];

  // Fisher-Yates shuffle with crypto RNG so the required-group chars are
  // not always clustered at the start.
  for (let i = chars.length - 1; i > 0; i--) {
    const [j] = randomIndices(1, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
