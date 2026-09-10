/**
 * Cache topics, and how they map onto the server's change epochs.
 *
 * Two different granularities meet here, and conflating them is the mistake:
 *
 * * **The server's epoch granularity is the mount.** `Core::record_change_epoch`
 *   files every mutation under `<namespace>` + `<mount>`, so the finest signal
 *   a client can ever receive is "something under `pki/` changed".
 * * **A client's cache granularity is the page.** Three PKI tabs cache three
 *   different listings off one mount, and a certificate write should not make
 *   this client throw away its own pending-CSR list.
 *
 * So a topic is `<kind>|<mount>`: fine enough that a local write drops only
 * what it affects, while several topics can subscribe to the same mount and
 * all be invalidated when its epoch moves (`changeWatcher` maps one mount
 * epoch onto every topic watching it).
 *
 * The namespace is deliberately *not* in the client topic. The whole cache is
 * dropped on a namespace switch (`namespaceStore.setActive`), so a topic can
 * only ever hold entries for the active namespace, and the server scopes its
 * epoch answer to the namespace the request is made in.
 */

/** A cache topic for one page's listing on one mount. */
export function topicFor(kind: string, mount: string): string {
  return `${kind}|${mount}`;
}

/**
 * The mount path the server keys epochs by, for an auth mount.
 *
 * The GUI carries userpass-style mounts as `userpass/` and builds request
 * paths as `auth/<mount>...`; the server files the epoch under the full
 * `auth/userpass/`. Getting this wrong is silent — the watcher would ask
 * about a mount that never moves and simply never invalidate.
 */
export function authMount(mountPath: string): string {
  const trimmed = mountPath.replace(/^\/+/, "");
  const withSlash = trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
  return withSlash.startsWith("auth/") ? withSlash : `auth/${withSlash}`;
}

/**
 * The mount the `sys/` backend's listings live under — policies, mounts,
 * namespaces and the rest all file their epochs here, because `sys` is the
 * first path segment of every one of them.
 */
export const SYS_MOUNT = "sys/";
