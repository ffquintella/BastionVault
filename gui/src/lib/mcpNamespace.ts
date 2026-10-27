/**
 * How the AI-assistant views name and offer namespaces
 * (features/mcp-namespace-selection.md). The vault is the authority on
 * where a token may be bound; these only present it.
 */

/** A namespace as an operator reads it: `root` for `""`. */
export function namespaceLabel(ns: string): string {
  return ns === "" ? "root" : ns;
}

/** True when `ns` is `parent` itself or lies beneath it. */
function isSelfOrDescendant(ns: string, parent: string): boolean {
  if (ns === parent) return true;
  return parent === "" ? ns !== "" : ns.startsWith(`${parent}/`);
}

/**
 * The namespaces a pairing may be narrowed to, as the pairing dialog offers
 * them: the operator's own first, then the operable namespaces beneath it,
 * sorted. Never a parent, a sibling or an unrelated namespace — the vault
 * would refuse those (`mcp_namespace_not_permitted`), so they are not offered.
 */
export function narrowingOptions(own: string, operable: readonly string[]): string[] {
  const below = Array.from(new Set(operable.filter((ns) => ns !== own && isSelfOrDescendant(ns, own)))).sort();
  return [own, ...below];
}
