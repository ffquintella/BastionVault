#!/usr/bin/env bash
#
# Which crates changed since they were last published, and in what order they
# would go out.
#
#   scripts/crates-plan.sh                # human-readable table
#   scripts/crates-plan.sh --json         # the same, machine-readable
#   scripts/crates-plan.sh --offline      # no registry lookups (tags only)
#   scripts/crates-plan.sh --publishable  # just the names, in publish order
#
# ── The model ─────────────────────────────────────────────────────
#
# Every library crate carries its OWN version and is released on its OWN
# schedule. The product version — what `bvault --version` prints and what the
# installers are named after — belongs to `bastion_vault`, `bv-server`,
# `bvault-cli` and the GUI, and is what `make bump-*` moves in lockstep. The
# two are deliberately unrelated: `bv-shamir` has not changed since it was
# extracted and should not be republished 40 times because the GUI shipped.
#
# So "what needs publishing?" is a question about CONTENT, not about the
# product release, and it is answered per crate:
#
#   1. the last release tag for the crate, `<name>-v<version>`, written by
#      scripts/publish-crates.sh when a publish succeeds;
#   2. `git diff <that tag> HEAD -- <the crate's directory>` — did anything in
#      the crate actually change;
#   3. the registry's sparse index — is the version in the manifest already
#      published, in which case the change needs a bump before it can ship.
#
# ── Why a patch bump does not cascade ─────────────────────────────
#
# Internal dependencies are declared `version = "0.1.0"`, which is a CARET
# requirement: it matches every 0.1.x. So bumping `bv-errors` 0.1.0 -> 0.1.1
# needs no edit in the 32 crates that depend on it, their packaged tarballs do
# not change, and they do not need republishing — a consumer resolving them
# picks up 0.1.1 on its own. Only a breaking bump (0.1 -> 0.2) invalidates the
# requirement, and scripts/crates-bump.sh rewrites dependents only then.
#
# That property is the whole point of per-crate versions, and it is easy to
# destroy by accident: pinning internal deps with `=` , or moving them to
# `[workspace.dependencies]`, both turn every release into a whole-workspace
# release. See AGENTS.md § Per-crate versioning.
#
# ── Where the crate list comes from ───────────────────────────────
#
# `cargo metadata`, not a hand-maintained list. The list this replaced had
# already drifted: `bv-core` and `bv-kernel` were created in Phase 4.5 with
# `publish = ["uox-bastionvault"]` and were never added to it, so they would
# have been silently omitted from every release. Publishability and publish
# ORDER are both properties of the graph, and the graph is in the manifests.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

REGISTRY="${REGISTRY:-uox-bastionvault}"
FORMAT="table"
OFFLINE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)        FORMAT="json"; shift ;;
    --publishable) FORMAT="names"; shift ;;
    --offline)     OFFLINE=1; shift ;;
    --registry)    REGISTRY="${2:?--registry needs a name}"; shift 2 ;;
    -h|--help)     sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "crates-plan: unknown argument '$1'" >&2; exit 64 ;;
  esac
done

# The sparse index base, read out of .cargo/config.toml rather than hardcoded,
# so this can never disagree with what cargo itself resolves against. One
# `sed` and not a TOML parse: the file is ours, the line has one shape, and
# tomllib would put a Python 3.11 floor on a script that otherwise needs only
# json.
INDEX=$(sed -n "s|^${REGISTRY} = { index = \"sparse+\(.*\)\" }.*|\1|p" .cargo/config.toml)
if [[ -z "$INDEX" ]]; then
  echo "crates-plan: no sparse index for registry '$REGISTRY' in .cargo/config.toml" >&2
  exit 1
fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

cargo metadata --format-version 1 >"$WORK/meta.json"
git tag --list >"$WORK/tags"

python3 - "$WORK" "$OFFLINE" "$INDEX" "$FORMAT" <<'PY'
import concurrent.futures
import json, os, subprocess, sys, urllib.error, urllib.request

work, offline, index, fmt = sys.argv[1:5]
offline = offline == "1"

with open(os.path.join(work, "meta.json")) as fh:
    md = json.load(fh)

root = md["workspace_root"]
member_ids = set(md["workspace_members"])
by_id = {p["id"]: p for p in md["packages"]}
members = {i: by_id[i] for i in member_ids if i in by_id}
name_of = {i: p["name"] for i, p in members.items()}
pkg_of = {p["name"]: p for p in members.values()}

# `publish` in cargo metadata: None means "any registry" (no key in the
# manifest), a list means exactly those, and `publish = false` shows up as the
# empty list. Every crate here is meant to carry an explicit allowlist, so an
# empty list is "not publishable" and None would be a manifest bug — flagged
# below rather than silently treated as either.
def publish_field(p):
    return p.get("publish")


unguarded = sorted(n for n, p in pkg_of.items() if publish_field(p) is None)
self_publishable = {n for n, p in pkg_of.items() if publish_field(p)}


# ── Edges that survive `cargo publish` ────────────────────────────
#
# A dev-dependency declared with a path and NO version is stripped from the
# published manifest, so it constrains neither publishability nor order. One
# declared with a version is kept and must resolve. cargo metadata reports the
# difference as the requirement: "*" for path-only, "^0.1.0" otherwise.
#
# This matters concretely here: `bv-kernel` dev-depends on `bastion_vault` and
# `bv-server`, neither of which is publishable. Treating that as a real edge
# would wrongly exclude the entire kernel from every release.
def real_deps(p):
    out = set()
    for d in p["dependencies"]:
        if d["name"] not in pkg_of:
            continue
        if d["kind"] == "dev" and d.get("req") == "*":
            continue
        out.add(d["name"])
    return out


deps = {n: real_deps(p) for n, p in pkg_of.items()}

# A crate can only be published if every crate it depends on can be. Computed
# as a fixpoint rather than assumed, so `bv-server` and `bvault-cli` drop out
# on their own from `bastion_vault` being unpublishable — and rejoin on their
# own the day it is not.
publishable = set(self_publishable)
changed = True
while changed:
    changed = False
    for n in sorted(publishable):
        blocked = deps[n] - publishable
        if blocked:
            publishable.discard(n)
            changed = True

blocked_by = {
    n: sorted(deps[n] - publishable)
    for n in self_publishable - publishable
}

# ── Publish order ─────────────────────────────────────────────────
#
# Topological, ties broken by name so the order is stable between runs and a
# diff of two plans is readable. A registry rejects a crate whose dependencies
# it cannot resolve, so this is load-bearing.
order, seen, visiting = [], set(), set()


def visit(n):
    if n in seen:
        return
    if n in visiting:
        sys.exit(f"crates-plan: dependency cycle through '{n}' among publishable crates")
    visiting.add(n)
    for d in sorted(deps[n] & publishable):
        visit(d)
    visiting.discard(n)
    seen.add(n)
    order.append(n)


for n in sorted(publishable):
    visit(n)

if fmt == "names":
    print("\n".join(order))
    raise SystemExit(0)

with open(os.path.join(work, "tags")) as fh:
    all_tags = {t.strip() for t in fh if t.strip()}


def parse_ver(v):
    """(0, 1, 12) from "0.1.12". Sorts numerically, unlike the string."""
    parts = []
    for part in v.split("."):
        num = ""
        for ch in part:
            if not ch.isdigit():
                break
            num += ch
        parts.append(int(num or 0))
    return tuple(parts + [0, 0, 0])[:3]


def last_release_tag(crate):
    """The highest `<crate>-v<version>` tag that exists, or None.

    By version rather than by commit date: tags are written at publish time and
    a rebase can reorder their commits, but the version ordering is what the
    registry sees.
    """
    prefix = f"{crate}-v"
    versions = [t[len(prefix):] for t in all_tags if t.startswith(prefix)]
    if not versions:
        return None, None
    best = max(versions, key=parse_ver)
    return f"{prefix}{best}", best


def dir_of(crate):
    d = os.path.relpath(os.path.dirname(pkg_of[crate]["manifest_path"]), root)
    return "." if d == "." else d


def changed_since(tag, path):
    """Did anything in the crate's directory change since the tag?

    Three sources, because no single git command covers them and missing one
    means a stale crate on the registry:

      committed    `git diff --quiet <tag> HEAD -- <dir>`
      modified     tracked files differing from the index
      untracked    a brand new source file, which `git diff` never sees

    The last two matter because the question people actually ask is "I have
    been editing — what will I need to bump?", and they ask it before they
    commit. Answering "nothing changed" there is worse than useless.

    `git diff <tag> HEAD` is tree-to-tree and `git ls-files` only reads the
    index, so none of this takes the index lock — deliberately, because this
    script runs inside `publish-crates.sh` and a plan that can be blocked by
    an editor's background `git status` would be a bad failure mode.
    """
    r = subprocess.run(
        ["git", "diff", "--quiet", tag, "HEAD", "--", path],
        capture_output=True,
    )
    if r.returncode not in (0, 1):
        sys.exit(f"crates-plan: git diff {tag}..HEAD -- {path} failed: "
                 f"{r.stderr.decode().strip()}")
    if r.returncode == 1:
        return True

    dirty = subprocess.run(
        ["git", "ls-files", "--modified", "--others", "--exclude-standard",
         "--", path],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return bool(dirty)


def index_path(crate):
    """Sparse-index path for a crate name, per cargo's layout.

    1 char -> 1/n, 2 -> 2/nn, 3 -> 3/n/nnn, 4+ -> nn/nn/name. Names are used
    as written; cargo does not fold `-` and `_` in the path.
    """
    n = crate.lower()
    if len(n) == 1:
        return f"1/{n}"
    if len(n) == 2:
        return f"2/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def _fetch_versions(crate):
    """Versions already on the registry. Empty set if the crate is unknown.

    None means "could not tell" — a network failure or an auth wall — which is
    reported rather than guessed at, because guessing "not published" would
    make a publish attempt fail late and guessing "published" would skip a
    crate that needs shipping.
    """
    url = index.rstrip("/") + "/" + index_path(crate)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            body = resp.read().decode()
        return {json.loads(l)["vers"] for l in body.splitlines() if l.strip()}
    except urllib.error.HTTPError as e:
        return set() if e.code == 404 else None
    except Exception:
        return None


# Prefetched concurrently rather than one at a time inside the loop below.
# The sparse index has no bulk endpoint, so this is 38 separate HTTPS round
# trips; sequentially that measured 14.9s, which is most of the runtime of a
# command that otherwise reads local files. It is also paid three times over
# in a release, because crates-bump and publish-crates both ask for a plan.
#
# Eight workers, not more: this is someone else's registry and the point is to
# stop being slow, not to open 38 sockets at once.
_index_cache = {}
if not offline:
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        _index_cache = dict(
            zip(order, pool.map(_fetch_versions, order))
        )


def published_versions(crate):
    return None if offline else _index_cache.get(crate)


rows = []
for crate in order:
    version = pkg_of[crate]["version"]
    path = dir_of(crate)
    tag, tag_version = last_release_tag(crate)
    on_registry = published_versions(crate)

    if on_registry is None:
        # Fall back to the tag: it is what this repo wrote when it last
        # published, and it is the only evidence available offline.
        is_published = tag_version == version
        source = "tag"
    else:
        is_published = version in on_registry
        source = "index"

    # No tag at all means the crate has never been released from this repo, so
    # everything in it is new by definition.
    content_changed = True if tag is None else changed_since(tag, path)

    if not is_published:
        action, why = "publish", ("never released" if tag is None
                                  else f"{version} not on the registry")
    elif content_changed:
        action, why = "bump", f"{version} is published and {path} has changed since {tag}"
    else:
        action, why = "skip", f"{version} published, unchanged since {tag}"

    rows.append({
        "name": crate,
        "dir": path,
        "version": version,
        "tag": f"{crate}-v{version}",
        "last_tag": tag,
        "changed": content_changed,
        "published": is_published,
        "published_source": source,
        "action": action,
        "why": why,
    })

plan = {
    "registry_index": index,
    "order": order,
    "crates": rows,
    "not_publishable": blocked_by,
    "unguarded": unguarded,
    "counts": {
        "publish": sum(1 for r in rows if r["action"] == "publish"),
        "bump": sum(1 for r in rows if r["action"] == "bump"),
        "skip": sum(1 for r in rows if r["action"] == "skip"),
    },
}

if fmt == "json":
    print(json.dumps(plan, indent=2))
    raise SystemExit(0)

w = max(len(r["name"]) for r in rows)
print(f"==> {len(rows)} publishable crate(s), in publish order")
print(f"    registry index: {index}")
if offline:
    print("    offline — 'published' is inferred from git tags, not the index")
print()
print(f"    {'crate'.ljust(w)}  version   action   why")
print(f"    {'-' * w}  --------  -------  ---")
for r in rows:
    print(f"    {r['name'].ljust(w)}  {r['version']:<8}  {r['action']:<7}  {r['why']}")
print()
c = plan["counts"]
print(f"    publish {c['publish']}   bump {c['bump']}   skip {c['skip']}")

if c["bump"]:
    print()
    print("    Crates marked 'bump' have changed since their published version.")
    print("    Run:  make crates-bump          # patch-bump just those")
    print("          make crates-bump MINOR=<crate>   # if the change is breaking")

if blocked_by:
    print()
    print("    Not publishable (a dependency is not):")
    for n, b in sorted(blocked_by.items()):
        print(f"      {n} — blocked by {', '.join(b)}")

if unguarded:
    print()
    print("    WARNING: no `publish` key, so a bare `cargo publish` would target")
    print("             crates.io. Add `publish = [\"uox-bastionvault\"]` or `false`:")
    for n in unguarded:
        print(f"      {n}")
PY
