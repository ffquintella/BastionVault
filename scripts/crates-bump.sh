#!/usr/bin/env bash
#
# Bump the version of each crate that changed since it was last published —
# and only those.
#
#   scripts/crates-bump.sh                     # patch-bump every 'bump' crate
#   scripts/crates-bump.sh --dry-run           # show the edits, write nothing
#   scripts/crates-bump.sh --minor bv-errors   # breaking change in one crate
#   scripts/crates-bump.sh --crate bv-engine-pki   # bump one, changed or not
#
# The set comes from scripts/crates-plan.sh, so "changed" means the same thing
# here as it does everywhere else: the crate's directory differs from its last
# `<name>-v<version>` release tag.
#
# ── Patch bumps do not cascade. Minor bumps do. ───────────────────
#
# Internal dependencies are declared as `version = "0.1.0"`, a CARET
# requirement matching every 0.1.x. So:
#
#   0.1.0 -> 0.1.1   nothing else is touched. The 32 crates that depend on
#                    bv-errors keep `version = "0.1.0"`, their tarballs are
#                    byte-identical, and they do not need republishing.
#                    A consumer resolving them picks up 0.1.1 by itself.
#
#   0.1.x -> 0.2.0   `^0.1.0` no longer matches, so every dependent's
#                    requirement is rewritten — which changes those manifests,
#                    which makes those crates 'changed', which means the next
#                    plan wants to bump and republish them too. That cascade
#                    is correct: a breaking change in a dependency IS a change
#                    in its dependents.
#
# This is why internal deps must never be pinned with `=` and must never move
# to `[workspace.dependencies]`: both would make every release a
# whole-workspace release. See AGENTS.md § Per-crate versioning.
#
# ── What this does not do ─────────────────────────────────────────
#
# It does not decide whether your change is breaking. Nothing can: that is a
# judgement about the crate's public API, and getting it wrong is a broken
# downstream build rather than a failing test here. Patch is the default
# because it is the safe default for a private registry; pass --minor when you
# removed or changed a public item.
#
# It does not touch the PRODUCT version. `bastion_vault`, `bv-server`,
# `bvault-cli` and the GUI move together under `make bump-*`, because
# `bvault --version` and the installer filenames are one number that operators
# read. Library crates are versioned by content; the product is versioned by
# release. See docs/publishing-crates.md.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

DRY=0
MINOR=()
ONLY=()
# Reuse a plan computed earlier rather than making ~38 more requests to the
# registry index. Same flag, same meaning, as scripts/publish-crates.sh.
PLAN_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|-n) DRY=1; shift ;;
    --minor)      MINOR+=("${2:?--minor needs a crate name}"); shift 2 ;;
    --crate)      ONLY+=("${2:?--crate needs a crate name}"); shift 2 ;;
    --plan-file)  PLAN_FILE="${2:?--plan-file needs a path}"; shift 2 ;;
    -h|--help)    sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "crates-bump: unknown argument '$1'" >&2; exit 64 ;;
  esac
done

if [[ -n "$PLAN_FILE" ]]; then
  CRATES_BUMP_PLAN=$(cat "$PLAN_FILE")
else
  CRATES_BUMP_PLAN=$(scripts/crates-plan.sh --json)
fi
export CRATES_BUMP_PLAN

python3 - "$DRY" "${#MINOR[@]}" ${MINOR[@]+"${MINOR[@]}"} ${ONLY[@]+"${ONLY[@]}"} <<'PY'
import json, os, re, subprocess, sys

dry = sys.argv[1] == "1"
n_minor = int(sys.argv[2])
rest = sys.argv[3:]
minor = set(rest[:n_minor])
only = set(rest[n_minor:])

plan = json.loads(os.environ["CRATES_BUMP_PLAN"])
rows = {r["name"]: r for r in plan["crates"]}

unknown = (minor | only) - set(rows)
if unknown:
    sys.exit("crates-bump: not a publishable crate: " + ", ".join(sorted(unknown)))

# --crate is an explicit override: bump it whether or not the plan says it
# changed. That exists for the case the plan cannot see — you know the change
# is breaking for a reason that is not in the diff, or you need to re-cut a
# version that was yanked.
if only:
    targets = sorted(only | minor)
else:
    targets = sorted(
        {n for n, r in rows.items() if r["action"] == "bump"} | minor
    )

if not targets:
    print("==> nothing to bump: no crate has changed since its published version.")
    print("    (`scripts/crates-plan.sh` shows why for each crate.)")
    raise SystemExit(0)


def parse(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", v)
    if not m:
        sys.exit(f"crates-bump: cannot parse version '{v}' — expected MAJOR.MINOR.PATCH")
    return int(m[1]), int(m[2]), int(m[3]), m[4]


def bumped(v, breaking):
    """Next version, using the 0.x rule that minor is the breaking position.

    For 0.x, cargo treats 0.MINOR as the compatibility boundary: ^0.1.0 matches
    0.1.9 but not 0.2.0. So a breaking change is a minor bump while the crates
    are pre-1.0, and would be a major bump after. Encoded rather than assumed,
    because the day a crate reaches 1.0 the wrong rule silently stops
    protecting dependents.
    """
    ma, mi, pa, suffix = parse(v)
    if not breaking:
        return f"{ma}.{mi}.{pa + 1}{suffix}"
    if ma == 0:
        return f"0.{mi + 1}.0{suffix}"
    return f"{ma + 1}.0.0{suffix}"


def read(path):
    with open(path) as fh:
        return fh.read()


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def set_package_version(path, old, new):
    """Rewrite the [package] version only.

    Anchored to the first `version = ` line in the file, which is inside
    [package] in every manifest here. A blanket substitution would also rewrite
    a dependency's `version = "0.1.0"` — the exact bug the Makefile's
    `_bump-write` comment records having hit once already.
    """
    text = read(path)
    pat = re.compile(r'^version = "' + re.escape(old) + r'"$', re.M)
    m = pat.search(text)
    if not m:
        sys.exit(f"crates-bump: no `version = \"{old}\"` line in {path}")
    return text[:m.start()] + f'version = "{new}"' + text[m.end():]


def caret_matches(req_version, new_version):
    """Does a `version = "<req>"` requirement still accept <new>?

    Cargo's default operator is caret. For 0.x the compatibility range is
    0.MINOR.*, above that it is MAJOR.*. Only asked about a bump of the same
    crate, so <new> is always >= <req>.
    """
    rma, rmi, _, _ = parse(req_version)
    nma, nmi, _, _ = parse(new_version)
    if rma != nma:
        return False
    return rma != 0 or rmi == nmi


# Every manifest in the workspace, so a dependent is found wherever it lives —
# including the two Tier 4 crates and the GUI, which are not publishable but
# still have to resolve.
manifests = subprocess.run(
    ["git", "ls-files", "*Cargo.toml"], capture_output=True, text=True, check=True
).stdout.split()

edits = {}          # path -> text
summary = []
cascaded = set()

for crate in targets:
    row = rows[crate]
    old = row["version"]
    breaking = crate in minor
    new = bumped(old, breaking)
    manifest = os.path.join(row["dir"], "Cargo.toml") if row["dir"] != "." else "Cargo.toml"

    edits[manifest] = set_package_version(
        manifest, old, new
    ) if manifest not in edits else None
    if edits[manifest] is None:
        sys.exit(f"crates-bump: {manifest} targeted twice")

    summary.append((crate, old, new, "minor" if breaking else "patch"))

    if caret_matches(old, new):
        continue

    # Breaking: every dependent's requirement has to move, or the workspace
    # stops resolving on the very next build.
    dep_pat = re.compile(
        r'(^' + re.escape(crate) + r'\s*=\s*\{[^}]*?version\s*=\s*")'
        + re.escape(old) + r'(")',
        re.M | re.S,
    )
    for path in manifests:
        text = edits.get(path, read(path))
        new_text, n = dep_pat.subn(r"\g<1>" + new + r"\g<2>", text)
        if n:
            edits[path] = new_text
            cascaded.add((crate, path, n))

print(f"==> bumping {len(summary)} crate(s)")
for crate, old, new, kind in summary:
    print(f"    {crate:<26} {old} -> {new}   ({kind})")

if cascaded:
    print()
    print("    Breaking bump — dependents' requirements rewritten:")
    for crate, path, n in sorted(cascaded):
        print(f"      {path}  ({n} × {crate})")
    print()
    print("    Those manifests are now 'changed', so the next plan will want to")
    print("    bump and republish them too. That is correct: a breaking change")
    print("    in a dependency is a change in its dependents.")

if dry:
    print()
    print("==> --dry-run: nothing written.")
    raise SystemExit(0)

for path, text in sorted(edits.items()):
    write(path, text)

print()
print(f"==> wrote {len(edits)} manifest(s).")
print("    Next:  cargo check --workspace --exclude bastion-vault-gui   # refresh Cargo.lock")
print("           git commit")
print("           make crates-publish-changed-dry")
PY
