/**
 * Shared admin-detection used by the sidebar (Layout) and the dashboard
 * so they agree on who gets the operator experience versus the
 * cropped-down user experience.
 *
 * GUI gating ONLY — the API still enforces authorization per request
 * server-side. A user who is not "admin" here simply sees a smaller UI;
 * they are never granted access they don't have.
 */

// Well-known full-admin policy names. Any of these grants the same nav
// as `root` — both the workspace engine links and the Admin section —
// and the full operator dashboard. Operators can assign one of these to
// delegate full GUI access without issuing a root token.
export const SUPER_ADMIN = ["root", "super-admin", "administrator", "admin"] as const;

// Policies that unlock the admin experience as a whole. `root`,
// `super-admin`, `administrator`, and `admin` are the well-known
// super-administrator keywords; `exchange-admin` / `plugin-admin`
// delegate specific admin sub-features. `pki-admin` is intentionally
// absent — PKI is a workspace feature, not an admin one.
export const ADMIN_POLICIES = new Set<string>([
  ...SUPER_ADMIN,
  "exchange-admin",
  "plugin-admin",
]);

/** True when the token carries any policy that grants the admin GUI. */
export function isAdminUser(policies: readonly string[]): boolean {
  return policies.some((p) => ADMIN_POLICIES.has(p));
}
