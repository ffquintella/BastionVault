#!/usr/bin/env python3
"""Verification tiers for BastionVault — T31 Phase 4.

    scripts/verify.py step NAME [--note K=V]... [--skip REASON] -- CMD...
    scripts/verify.py inventory
    scripts/verify.py kani --set fast|full [--verbose] [--playback-on-failure]
    scripts/verify.py kani-check --set fast|full LOG [--exit-code N]
    scripts/verify.py pin kani|cbmc
    scripts/verify.py selftest
    scripts/verify.py report [--tag TAG] [--out FILE] [--require-tier N]

The Makefile's `verify*` targets and .github/workflows/verify.yml both call
this, so a tier means the same thing on a laptop and in CI. Read
roadmaps/formal-verification-and-type-driven-security.md § Phase 4 for the
tiers and docs/verification.md for what the proofs say.

EVIDENCE. Every step writes a JSON record to target/verify/ (VERIFY_DIR
overrides) carrying its result and the exact tree it ran on — the commit plus,
for a dirty tree, a fingerprint of the diff and of every untracked file.
`report` states only what those records show: a step with no record is NOT
RUN, a record from another tree is STALE, and neither ever reads as a pass.
A step deletes its old record before it starts, so an interrupted run leaves
NOT RUN behind, never the previous result.

THE KANI GATE (`kani`, `kani-check`). `cargo kani` exits 0 when a cover is
UNSATISFIABLE — covers do not affect its verdict — so its exit status alone
would let a vacuous proof through. The gate parses the regular output and
fails on, per harness of the set:

  * no result for an expected harness, or a result for an unexpected one
  * VERIFICATION not SUCCESSFUL — a real counterexample
  * any check UNDETERMINED — an undischarged proof is not a pass
  * an assertion inside the harness function itself UNREACHABLE
  * a cover count different from scripts/kani-harnesses.txt
  * theorem: any cover not SATISFIED — the harness proves nothing
  * witness: any cover not SATISFIED — the defect no longer reproduces, which
    is the documented signal to turn the cover into an assert (proofs.rs,
    docs/verification.md § Defect witnesses). A witness whose covers are all
    SATISFIED is a KNOWN OPEN FINDING: reported, and not a failure.

and, for the run: a Kani or CBMC version other than the pinned one, no final
harness summary (crash, timeout, compile error) or a non-zero exit.

`selftest` drives every one of those rules against synthetic logs, so the gate
is itself exercised on every `make verify-gates` — an unexercised gate is not
a gate.

Python 3.9+ and the standard library only: it runs on the stock macOS python3
and on the CI runner without an install step.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.environ.get("VERIFY_DIR") or os.path.join(ROOT, "target", "verify")
MANIFEST = os.path.join(ROOT, "scripts", "kani-harnesses.txt")
CORE_DIR = os.path.join(ROOT, "crates", "bv-policy-core")
PROOFS = os.path.join(CORE_DIR, "src", "proofs.rs")
KANI_PACKAGE = "bv-policy-core"
PROOF_MODULE = "proofs::"

KINDS = ("theorem", "witness")
SETS = ("fast", "slow")

# Steps each tier requires. The names are the `step` names the Makefile uses;
# keep the two in step (`make verify-fast` is the reference).
TIER0_STEPS = (
    "sql-gate",
    "semgrep",
    "core-lint",
    "core-tests",
    "kani-inventory",
    "gate-selftest",
    "routes",
    "witness-doctests",
)
TIER1_CASES = 10_000
TIER2_CASES = 1_000_000

# What to tell someone whose step failed because a tool is missing, instead of
# a bare "No such file or directory".
HINTS = {
    "semgrep": "install it (`pipx install semgrep` or `pip install semgrep`), or "
    "pass SEMGREP=0 to record the step as explicitly SKIPPED. CI's sql-guard job "
    "(tests.yml) always runs it.",
    "cargo": "install a Rust toolchain (rustup).",
}


class GateError(Exception):
    """A malformed manifest, proof source or log: never judged as a pass."""


# ── Small helpers ───────────────────────────────────────────────────


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def git(args, binary=False):
    out = subprocess.run(
        ["git"] + list(args), cwd=ROOT, check=True, stdout=subprocess.PIPE
    ).stdout
    return out if binary else out.decode("utf-8", "replace")


def tree_state():
    """The commit, and for a dirty tree a fingerprint of exactly what differs.

    Two records with the same fingerprint ran on the same bytes. A clean tree's
    fingerprint is its commit.
    """
    commit = git(["rev-parse", "HEAD"]).strip()
    status = [
        line
        for line in git(["status", "--porcelain=v1", "--untracked-files=all"]).splitlines()
        if line.strip()
    ]
    if not status:
        return {"commit": commit, "dirty": False, "changed_files": 0, "fingerprint": commit}
    digest = hashlib.sha256()
    digest.update(git(["diff", "HEAD", "--binary"], binary=True))
    untracked = git(["ls-files", "--others", "--exclude-standard", "-z"]).split("\0")
    for path in sorted(p for p in untracked if p):
        digest.update(path.encode("utf-8") + b"\0")
        try:
            with open(os.path.join(ROOT, path), "rb") as fh:
                digest.update(hashlib.sha256(fh.read()).digest())
        except OSError:
            digest.update(b"<unreadable>")
    return {
        "commit": commit,
        "dirty": True,
        "changed_files": len(status),
        "fingerprint": "dirty-" + digest.hexdigest()[:16],
    }


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def remove(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def step_path(name):
    return os.path.join(EVIDENCE, "step-%s.json" % name)


def kani_paths(kani_set):
    base = os.path.join(EVIDENCE, "kani-%s" % kani_set)
    return base + ".log", base + ".json"


# ── The manifest ────────────────────────────────────────────────────


def parse_manifest(text):
    """(pins, harnesses) from scripts/kani-harnesses.txt. Strict: a row the
    parser does not understand is an error, never skipped."""
    pins, harnesses, seen = {}, [], set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        where = "scripts/kani-harnesses.txt:%d" % number
        if fields[0] == "pin":
            if len(fields) != 3 or fields[1] not in ("kani", "cbmc"):
                raise GateError("%s: expected `pin kani|cbmc <version>`" % where)
            pins[fields[1]] = fields[2]
        elif fields[0] == "harness":
            if len(fields) < 7:
                raise GateError(
                    "%s: expected `harness <name> <kind> <set> <covers> <secs> <label...>`" % where
                )
            name, kind, hset, covers, secs = fields[1:6]
            if kind not in KINDS:
                raise GateError("%s: kind must be one of %s, got %r" % (where, KINDS, kind))
            if hset not in SETS:
                raise GateError("%s: set must be one of %s, got %r" % (where, SETS, hset))
            if not covers.isdigit() or int(covers) < 1:
                raise GateError("%s: every harness needs at least one cover (a vacuity guard)" % where)
            if name in seen:
                raise GateError("%s: duplicate harness %r" % (where, name))
            try:
                secs_value = float(secs)
            except ValueError:
                raise GateError("%s: secs must be a number, got %r" % (where, secs))
            seen.add(name)
            harnesses.append(
                {
                    "name": name,
                    "kind": kind,
                    "set": hset,
                    "covers": int(covers),
                    "secs": secs_value,
                    "label": " ".join(fields[6:]),
                }
            )
        else:
            raise GateError("%s: unknown row type %r" % (where, fields[0]))
    for tool in ("kani", "cbmc"):
        if tool not in pins:
            raise GateError("scripts/kani-harnesses.txt: no `pin %s` row" % tool)
    if not harnesses:
        raise GateError("scripts/kani-harnesses.txt: no harnesses")
    return pins, harnesses


def load_manifest():
    with open(MANIFEST) as fh:
        return parse_manifest(fh.read())


def in_set(harness, kani_set):
    return kani_set == "full" or harness["set"] == "fast"


# ── The proof source ────────────────────────────────────────────────

ATTR_BLOCK_FN = re.compile(r"((?:#\[[^\]]*\]\s*)+)fn\s+(\w+)\s*\(")


def parse_proofs(text):
    """{harness: {"unwind": int|None, "solver": str|None}} for every
    #[kani::proof] function. Errors when a `#[kani::proof]` is found that the
    parser could not tie to a function, rather than silently missing it."""
    found = {}
    for match in ATTR_BLOCK_FN.finditer(text):
        attrs, name = match.group(1), match.group(2)
        if "kani::proof" not in attrs:
            continue
        unwind = re.search(r"#\[kani::unwind\((\d+)\)\]", attrs)
        solver = re.search(r"#\[kani::solver\((\w+)\)\]", attrs)
        found[name] = {
            "unwind": int(unwind.group(1)) if unwind else None,
            "solver": solver.group(1) if solver else None,
        }
    declared = len(re.findall(r"#\[kani::proof\]", text))
    if declared != len(found):
        raise GateError(
            "proofs.rs declares %d #[kani::proof] but %d could be tied to a function "
            "(attributes and `fn` must be adjacent)" % (declared, len(found))
        )
    return found


def inventory_problems(harnesses, proofs, stray_files):
    problems = []
    listed = {h["name"] for h in harnesses}
    for name in sorted(set(proofs) - listed):
        problems.append(
            "harness %s is in proofs.rs but not in scripts/kani-harnesses.txt — "
            "list it (kind, set, covers) and describe it in docs/verification.md" % name
        )
    for name in sorted(listed - set(proofs)):
        problems.append(
            "harness %s is in scripts/kani-harnesses.txt but not in proofs.rs — a proof "
            "disappeared; restore it or remove it from the manifest and the docs together" % name
        )
    for name, info in sorted(proofs.items()):
        if info["unwind"] is None:
            problems.append(
                "harness %s has no explicit #[kani::unwind(n)] — no harness may rely on a "
                "default bound (docs/verification.md § Bounds)" % name
            )
    for path in stray_files:
        problems.append(
            "%s declares a #[kani::proof] outside src/proofs.rs — the inventory only "
            "covers proofs.rs" % os.path.relpath(path, ROOT)
        )
    return problems


def stray_proof_files():
    stray = []
    for dirpath, _, files in os.walk(os.path.join(CORE_DIR, "src")):
        for f in files:
            path = os.path.join(dirpath, f)
            if f.endswith(".rs") and path != PROOFS:
                with open(path) as fh:
                    if "kani::proof" in fh.read():
                        stray.append(path)
    return sorted(stray)


def read_proofs():
    with open(PROOFS) as fh:
        return parse_proofs(fh.read())


# ── Parsing a Kani log ──────────────────────────────────────────────

RE_KANI = re.compile(r"^Kani Rust Verifier (\S+)")
RE_CBMC = re.compile(r"^CBMC (\d\S*)\s*$")
RE_HARNESS = re.compile(r"^Checking harness (\S+)\.\.\.\s*$")
RE_CHECK = re.compile(r"^Check \d+: (\S.*?)\s*$")
RE_FIELD = re.compile(r"^\t - (Status|Description|Location): (.*)$")
RE_VERIFICATION = re.compile(r"^VERIFICATION:- (\w+)")
RE_TIME = re.compile(r"^Verification Time: ([0-9.]+)s")
RE_COMPLETE = re.compile(
    r"^Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\."
)


def parse_log(text):
    log = {"kani": None, "cbmc": None, "harnesses": {}, "order": [], "complete": None}
    current = None
    check = None
    for line in text.splitlines():
        if log["kani"] is None:
            m = RE_KANI.match(line)
            if m:
                log["kani"] = m.group(1)
                continue
        if log["cbmc"] is None:
            m = RE_CBMC.match(line)
            if m:
                log["cbmc"] = m.group(1)
                continue
        m = RE_HARNESS.match(line)
        if m:
            current = {"checks": [], "verification": None, "time": None}
            log["harnesses"][m.group(1)] = current
            log["order"].append(m.group(1))
            check = None
            continue
        m = RE_COMPLETE.match(line)
        if m:
            log["complete"] = tuple(int(g) for g in m.groups())
            current = None
            continue
        if current is None:
            continue
        m = RE_CHECK.match(line)
        if m:
            check = {"name": m.group(1), "status": None, "description": "", "location": ""}
            current["checks"].append(check)
            continue
        m = RE_FIELD.match(line)
        if m and check is not None:
            key, value = m.group(1).lower(), m.group(2).strip()
            if key == "description" and len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            check[key] = value
            continue
        m = RE_VERIFICATION.match(line)
        if m:
            current["verification"] = m.group(1)
            check = None
            continue
        m = RE_TIME.match(line)
        if m:
            current["time"] = float(m.group(1))
    return log


def is_cover(check):
    return ".cover." in check["name"]


# ── Judging a Kani log ──────────────────────────────────────────────


def judge(text, pins, harnesses, kani_set, exit_code, proofs=None):
    """The gate. Returns a result dict; result["verdict"] is "pass" or "fail"
    and result["problems"] says why, one line per violated rule."""
    log = parse_log(text)
    problems = []
    proofs = proofs or {}

    if exit_code != 0:
        problems.append("cargo kani exited %d (log: see above)" % exit_code)
    for tool in ("kani", "cbmc"):
        seen = log[tool]
        if seen is None:
            problems.append("the log names no %s version — not a Kani run log" % tool.upper())
        elif seen != pins[tool]:
            problems.append(
                "%s %s is not the pinned %s (scripts/kani-harnesses.txt). A verifier bump is "
                "its own change, with a full tier-2 run green before merge"
                % (tool.upper() if tool == "cbmc" else "Kani", seen, pins[tool])
            )

    expected = [h for h in harnesses if in_set(h, kani_set)]
    expected_names = {PROOF_MODULE + h["name"] for h in expected}
    if log["complete"] is None:
        problems.append(
            "Kani printed no final harness summary — the run did not finish "
            "(compile error, crash, timeout or interruption)"
        )
    elif log["complete"][2] != len(expected):
        problems.append(
            "Kani verified %d harnesses; the %s set has %d"
            % (log["complete"][2], kani_set, len(expected))
        )
    for name in log["order"]:
        if name not in expected_names:
            problems.append(
                "unexpected harness %s in the %s run — list it in scripts/kani-harnesses.txt"
                % (name, kani_set)
            )

    rows = []
    for h in expected:
        full_name = PROOF_MODULE + h["name"]
        got = log["harnesses"].get(full_name)
        row = {
            "name": h["name"],
            "kind": h["kind"],
            "set": h["set"],
            "label": h["label"],
            "unwind": proofs.get(h["name"], {}).get("unwind"),
            "expected_covers": h["covers"],
            "verification": None,
            "time_s": None,
            "covers": [],
            "checks": 0,
            "failed": [],
            "undetermined": 0,
            "unreachable_in_harness": [],
            "problems": [],
        }
        rows.append(row)
        mine = row["problems"]
        if got is None:
            mine.append(
                "%s: no result — the harness did not run (renamed, filtered out, or the run "
                "stopped before it)" % h["name"]
            )
            row["outcome"] = "failed"
            continue
        row["verification"] = got["verification"]
        row["time_s"] = got["time"]
        row["checks"] = len(got["checks"])
        covers = [c for c in got["checks"] if is_cover(c)]
        row["covers"] = [{"description": c["description"], "status": c["status"]} for c in covers]
        for c in got["checks"]:
            if c["status"] == "FAILURE":
                row["failed"].append(
                    {"name": c["name"], "description": c["description"], "location": c["location"]}
                )
            elif c["status"] == "UNDETERMINED":
                row["undetermined"] += 1
            elif (
                c["status"] == "UNREACHABLE"
                and not is_cover(c)
                and c["name"].startswith(full_name + ".")
            ):
                row["unreachable_in_harness"].append(
                    {"name": c["name"], "description": c["description"], "location": c["location"]}
                )
            elif c["status"] is None:
                mine.append("%s: check %s has no status — malformed log" % (h["name"], c["name"]))

        if got["verification"] is None:
            mine.append("%s: no VERIFICATION line — the harness did not finish" % h["name"])
        elif got["verification"] != "SUCCESSFUL":
            mine.append(
                "%s: VERIFICATION:- %s — a property does not hold; this is a real "
                "counterexample (failing checks below; `--playback-on-failure` prints the input)"
                % (h["name"], got["verification"])
            )
        for f in row["failed"]:
            mine.append("%s:   FAILURE %s — %s (%s)" % (h["name"], f["name"], f["description"], f["location"]))
        if row["undetermined"]:
            mine.append(
                "%s: %d check(s) UNDETERMINED — an undischarged proof is not a pass"
                % (h["name"], row["undetermined"])
            )
        for u in row["unreachable_in_harness"]:
            mine.append(
                "%s: %s (%s) is UNREACHABLE — an assertion that cannot be reached proves nothing"
                % (h["name"], u["name"], u["location"])
            )
        if len(covers) != h["covers"]:
            mine.append(
                "%s: %d cover(s) in the run, %d in scripts/kani-harnesses.txt — a vacuity guard "
                "was added or removed; update the manifest and docs/verification.md together"
                % (h["name"], len(covers), h["covers"])
            )
        for c in covers:
            if c["status"] == "SATISFIED":
                continue
            if c["status"] not in ("UNSATISFIABLE", "UNREACHABLE"):
                mine.append(
                    '%s: cover "%s" is %s — undischarged, which is not a pass'
                    % (h["name"], c["description"], c["status"])
                )
            elif h["kind"] == "theorem":
                mine.append(
                    '%s: cover "%s" is %s — the harness\'s interesting case is unreachable, so '
                    "the theorem is vacuous" % (h["name"], c["description"], c["status"])
                )
            else:
                finding = h["label"].split()
                mine.append(
                    '%s: defect witness for %s: cover "%s" is %s, so the defect no longer '
                    "reproduces. If %s landed, replace the cover with the assert in the harness's "
                    "doc comment and make it a theorem in scripts/kani-harnesses.txt. Failing on "
                    "purpose (docs/verification.md § Defect witnesses)"
                    % (
                        h["name"],
                        finding[0] if finding else "?",
                        c["description"],
                        c["status"],
                        finding[1] if len(finding) > 1 else "its fix",
                    )
                )
        if mine:
            row["outcome"] = "failed"
        elif h["kind"] == "witness":
            row["outcome"] = "open-finding"
        else:
            row["outcome"] = "proved"

    for row in rows:
        problems.extend(row["problems"])

    return {
        "schema": 1,
        "set": kani_set,
        "exit_code": exit_code,
        "kani_version": log["kani"],
        "cbmc_version": log["cbmc"],
        "pinned": dict(pins),
        "harnesses": rows,
        "open_findings": [
            {"harness": r["name"], "label": r["label"], "covers": r["covers"]}
            for r in rows
            if r["outcome"] == "open-finding"
        ],
        "problems": problems,
        "verdict": "fail" if problems else "pass",
    }


def print_summary(result, wall=None):
    rows = result["harnesses"]
    head = "Kani gate — %s set, %d harnesses, Kani %s / CBMC %s" % (
        result["set"],
        len(rows),
        result["kani_version"],
        result["cbmc_version"],
    )
    if wall is not None:
        head += ", %.0f s wall" % wall
    print("")
    print(head)
    print("  %-56s %-8s %-22s %-7s %s" % ("harness", "kind", "outcome", "covers", "time"))
    for r in rows:
        sat = sum(1 for c in r["covers"] if c["status"] == "SATISFIED")
        outcome = {
            "proved": "PROVED",
            "open-finding": "OPEN FINDING " + r["label"],
            "failed": "FAILED",
        }[r["outcome"]]
        t = "%.1fs" % r["time_s"] if r["time_s"] is not None else "-"
        print("  %-56s %-8s %-22s %-7s %s" % (r["name"], r["kind"], outcome, "%d/%d" % (sat, len(r["covers"])), t))
    if result["open_findings"]:
        print("")
        print("Known open findings (the defect is present; tracked, not a gate failure):")
        for f in result["open_findings"]:
            print("  %-10s %s: %s" % (f["label"], f["harness"], "; ".join(c["description"] for c in f["covers"])))
    print("")
    if result["verdict"] == "pass":
        print("KANI GATE: PASS")
    else:
        print("KANI GATE: FAIL — %d problem(s):" % len(result["problems"]))
        for p in result["problems"]:
            print("  - " + p)


# ── Subcommands ─────────────────────────────────────────────────────


def cmd_pin(args):
    pins, _ = load_manifest()
    print(pins[args.tool])
    return 0


def cmd_cases(args):
    """The differential case count a tier requires — one number, read by the
    Makefile, verify.yml and the report's tier check alike."""
    print(TIER1_CASES if args.tier == 1 else TIER2_CASES)
    return 0


def cmd_inventory(args):
    _, harnesses = load_manifest()
    proofs = read_proofs()
    problems = inventory_problems(harnesses, proofs, stray_proof_files())
    if problems:
        print("kani inventory: FAIL")
        for p in problems:
            print("  - " + p)
        return 1
    fast = sum(1 for h in harnesses if h["set"] == "fast")
    witnesses = sum(1 for h in harnesses if h["kind"] == "witness")
    print(
        "kani inventory: %d harnesses in proofs.rs match scripts/kani-harnesses.txt "
        "(%d fast, %d slow; %d defect witnesses)" % (len(harnesses), fast, len(harnesses) - fast, witnesses)
    )
    return 0


def kani_command(harnesses, kani_set):
    cmd = ["cargo", "kani", "-p", KANI_PACKAGE, "--output-format", "regular"]
    if kani_set == "fast":
        cmd.append("--exact")
        for h in harnesses:
            if h["set"] == "fast":
                cmd += ["--harness", PROOF_MODULE + h["name"]]
    return cmd


PROGRESS = re.compile(
    r"^(Kani Rust Verifier|CBMC \d|Checking harness|VERIFICATION:-|Verification Time|Complete -|"
    r"Manual Harness Summary|error|warning: unused|\s+Compiling|\s+Finished)"
)


def run_streaming(cmd, log_path, verbose):
    with open(log_path, "w") as fh:
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
        )
        for line in proc.stdout:
            fh.write(line)
            if verbose or PROGRESS.match(line):
                sys.stdout.write(line)
                sys.stdout.flush()
        return proc.wait()


def failing_playback_blocks(text):
    """The concrete-playback tests in a Kani log that reproduce a failure.

    Kani prints each test as a header line and a fenced block, and also emits
    one per SATISFIED cover — a witness of reachability, not of the failure —
    so those are dropped."""
    blocks, block, fences = [], None, 0
    for line in text.splitlines(keepends=True):
        if line.startswith("Concrete playback unit test for"):
            block, fences = [line], 0
            continue
        if block is None:
            continue
        block.append(line)
        if line.strip() == "```":
            fences += 1
            if fences == 2:
                blocks.append("".join(block))
                block = None
    return [b for b in blocks if "/// Check for `cover`" not in b]


def print_playback(result, kani_set):
    """Diagnostics only: re-run each failed harness with concrete playback so
    the job log carries the input that breaks it. The verdict is already
    decided and is not changed by this."""
    for row in result["harnesses"]:
        if row["verification"] != "FAILED":
            continue
        log_path = os.path.join(EVIDENCE, "kani-%s-playback-%s.log" % (kani_set, row["name"]))
        cmd = [
            "cargo", "kani", "-p", KANI_PACKAGE, "--exact", "--harness", PROOF_MODULE + row["name"],
            "-Z", "concrete-playback", "--concrete-playback=print",
        ]
        print("\n==> counterexample for %s: %s" % (row["name"], " ".join(cmd)))
        run_streaming(cmd, log_path, verbose=False)
        with open(log_path) as fh:
            failing = failing_playback_blocks(fh.read())
        for b in failing:
            sys.stdout.write(b)
        if not failing:
            # Measured with Kani 0.68.0: an `assert_eq!` whose message is
            # formatted at runtime fails inside core::panicking and gets no
            # playback test. Say so rather than print nothing.
            print(
                "    Kani produced no concrete playback for the failing check (it does not for "
                "every failure — e.g. an assert_eq! with a runtime-formatted message). The harness "
                "and failing check are listed above; the full output is in the log."
            )
        print("    (full output: %s)" % os.path.relpath(log_path, ROOT))


def cmd_kani(args):
    pins, harnesses = load_manifest()
    proofs = read_proofs()
    log_path, json_path = kani_paths(args.set)
    remove(log_path)
    remove(json_path)
    problems = inventory_problems(harnesses, proofs, stray_proof_files())
    if problems:
        print("kani inventory: FAIL — not running Kani against a manifest that does not match")
        for p in problems:
            print("  - " + p)
        return 1
    if shutil.which("cargo-kani") is None:
        print(
            "error: cargo-kani is not installed. `make bootstrap` installs it; CI pins "
            "kani-verifier %s (scripts/kani-harnesses.txt)." % pins["kani"]
        )
        return 127
    os.makedirs(EVIDENCE, exist_ok=True)
    cmd = kani_command(harnesses, args.set)
    print("==> " + " ".join(cmd))
    print("    full log: %s" % os.path.relpath(log_path, ROOT))
    started = now_utc()
    t0 = time.time()
    rc = run_streaming(cmd, log_path, args.verbose)
    wall = time.time() - t0
    with open(log_path) as fh:
        result = judge(fh.read(), pins, harnesses, args.set, rc, proofs)
    solvers = sorted({i["solver"] for i in proofs.values() if i["solver"]})
    result.update(
        {
            "command": cmd,
            "started": started,
            "finished": now_utc(),
            "wall_seconds": round(wall, 1),
            "tree": tree_state(),
            "solver": (
                "per-harness: " + ", ".join(solvers)
                if solvers
                else "CaDiCaL (the Kani %s default; no harness sets kani::solver, none passed)" % pins["kani"]
            ),
            "log": os.path.relpath(log_path, ROOT),
        }
    )
    write_json(json_path, result)
    print_summary(result, wall)
    if result["verdict"] != "pass" and args.playback_on_failure:
        print_playback(result, args.set)
    return 0 if result["verdict"] == "pass" else 1


def cmd_kani_check(args):
    pins, harnesses = load_manifest()
    with open(args.log) as fh:
        result = judge(fh.read(), pins, harnesses, args.set, args.exit_code, read_proofs())
    print_summary(result)
    return 0 if result["verdict"] == "pass" else 1


def cmd_step(args):
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", args.name):
        print("verify step: bad step name %r" % args.name)
        return 2
    notes = {}
    for note in args.note or []:
        if "=" not in note:
            print("verify step: --note expects KEY=VALUE, got %r" % note)
            return 2
        k, v = note.split("=", 1)
        notes[k] = v
    cmd = list(args.cmd)
    path = step_path(args.name)
    remove(path)
    record = {"schema": 1, "step": args.name, "notes": notes, "command": cmd, "started": now_utc()}
    if args.skip:
        record.update({"result": "skipped", "reason": args.skip, "exit": None, "seconds": 0})
        record["tree"] = tree_state()
        record["finished"] = now_utc()
        write_json(path, record)
        print("==> verify %s: SKIPPED — %s" % (args.name, args.skip))
        return 0
    if not cmd:
        print("verify step: no command given after --")
        return 2
    print("==> verify %s: %s" % (args.name, " ".join(cmd)))
    t0 = time.time()
    if shutil.which(cmd[0]) is None:
        print("error: %s is not installed — %s" % (cmd[0], HINTS.get(cmd[0], "install it.")))
        rc = 127
    else:
        rc = subprocess.call(cmd, cwd=ROOT)
    seconds = round(time.time() - t0, 1)
    record.update(
        {
            "result": "pass" if rc == 0 else "fail",
            "exit": rc,
            "seconds": seconds,
            "tree": tree_state(),
            "finished": now_utc(),
        }
    )
    write_json(path, record)
    print("==> verify %s: %s (%.1f s)" % (args.name, "PASS" if rc == 0 else "FAIL, exit %d" % rc, seconds))
    return rc


# ── selftest: the gate's own regression suite ───────────────────────


def _fake_log(runs, kani="0.68.0", cbmc="6.11.0", complete=True):
    """A Kani regular-format log. `runs` is a list of
    (harness, verification, covers=[(status, description)], extra=[(name, status)])."""
    out = ["Kani Rust Verifier %s (cargo plugin)" % kani, "CBMC %s" % cbmc,
           "   Compiling bv-policy-core v0.0.0", "    Finished `dev` profile"]
    ok = bad = 0
    for harness, verification, covers, extra in runs:
        out.append("Checking harness proofs::%s..." % harness)
        out.append("CBMC %s (cbmc-%s)" % (cbmc, cbmc))
        out.append("")
        out.append("RESULTS:")
        n = 0
        for name, status in extra:
            n += 1
            out += ["Check %d: %s" % (n, name), "\t - Status: %s" % status,
                    '\t - Description: "an assertion"', "\t - Location: x.rs:1:1 in function f", ""]
        for i, (status, desc) in enumerate(covers, 1):
            n += 1
            out += ["Check %d: proofs::%s.cover.%d" % (n, harness, i), "\t - Status: %s" % status,
                    '\t - Description: "%s"' % desc,
                    "\t - Location: crates/bv-policy-core/src/proofs.rs:1:5 in function proofs::%s" % harness, ""]
        out += ["", "SUMMARY:", " ** 0 of %d failed" % n, "",
                " ** %d of %d cover properties satisfied" % (sum(1 for s, _ in covers if s == "SATISFIED"), len(covers)),
                "", "", "VERIFICATION:- %s" % verification, "Verification Time: 0.5s", ""]
        if verification == "SUCCESSFUL":
            ok += 1
        else:
            bad += 1
    if complete:
        out += ["Manual Harness Summary:",
                "Complete - %d successfully verified harnesses, %d failures, %d total." % (ok, bad, ok + bad)]
    return "\n".join(out) + "\n"


_SELFTEST_MANIFEST = """
pin kani 0.68.0
pin cbmc 6.11.0
harness t_ok     theorem fast 2 1.0 T1
harness w_bug    witness fast 1 1.0 F9 T999
harness t_slow   theorem slow 1 99.0 T2
"""

_SAT = ("SATISFIED", "a case")
_GOOD = [
    ("t_ok", "SUCCESSFUL", [_SAT, ("SATISFIED", "another case")], [("proofs::t_ok.assertion.1", "SUCCESS")]),
    ("w_bug", "SUCCESSFUL", [("SATISFIED", "F9: the bug")], []),
]


def _replace(runs, harness, **kw):
    out = []
    for name, verification, covers, extra in runs:
        if name == harness:
            verification = kw.get("verification", verification)
            covers = kw.get("covers", covers)
            extra = kw.get("extra", extra)
        out.append((name, verification, covers, extra))
    return out


def cmd_selftest(args):
    pins, hs = parse_manifest(_SELFTEST_MANIFEST)
    full_good = _GOOD + [("t_slow", "SUCCESSFUL", [_SAT], [])]
    # (description, log text, set, exit code, expected verdict, substring a problem must contain)
    cases = [
        ("a clean fast run passes", _fake_log(_GOOD), "fast", 0, "pass", None),
        ("a clean full run passes", _fake_log(full_good), "full", 0, "pass", None),
        ("a theorem with an UNSATISFIABLE cover is vacuous",
         _fake_log(_replace(_GOOD, "t_ok", covers=[_SAT, ("UNSATISFIABLE", "another case")])),
         "fast", 0, "fail", "vacuous"),
        ("a theorem with an UNREACHABLE cover is vacuous",
         _fake_log(_replace(_GOOD, "t_ok", covers=[_SAT, ("UNREACHABLE", "another case")])),
         "fast", 0, "fail", "vacuous"),
        ("a witness whose cover turns UNSATISFIABLE fails on purpose",
         _fake_log(_replace(_GOOD, "w_bug", covers=[("UNSATISFIABLE", "F9: the bug")])),
         "fast", 0, "fail", "no longer reproduces"),
        ("a witness whose cover is UNDETERMINED fails",
         _fake_log(_replace(_GOOD, "w_bug", covers=[("UNDETERMINED", "F9: the bug")])),
         "fast", 0, "fail", "UNDETERMINED"),
        ("a failed property is a counterexample",
         _fake_log(_replace(_GOOD, "t_ok", verification="FAILED", extra=[("proofs::t_ok.assertion.1", "FAILURE")])),
         "fast", 0, "fail", "counterexample"),
        ("an UNDETERMINED check blocks",
         _fake_log(_replace(_GOOD, "t_ok", extra=[("core::x.assertion.1", "UNDETERMINED")])),
         "fast", 0, "fail", "UNDETERMINED"),
        ("an UNREACHABLE assertion inside the harness blocks",
         _fake_log(_replace(_GOOD, "t_ok", extra=[("proofs::t_ok.assertion.1", "UNREACHABLE")])),
         "fast", 0, "fail", "UNREACHABLE"),
        ("an UNREACHABLE check in library code does not block",
         _fake_log(_replace(_GOOD, "t_ok", extra=[("core::panicking::x.assertion.1", "UNREACHABLE")])),
         "fast", 0, "pass", None),
        ("a missing harness has no result",
         _fake_log([r for r in _GOOD if r[0] != "w_bug"]), "fast", 0, "fail", "no result"),
        ("the full set requires the slow harnesses",
         _fake_log(_GOOD), "full", 0, "fail", "t_slow: no result"),
        ("an unlisted harness is unexpected",
         _fake_log(_GOOD + [("t_new", "SUCCESSFUL", [_SAT], [])]), "fast", 0, "fail", "unexpected harness"),
        ("a removed cover is caught",
         _fake_log(_replace(_GOOD, "t_ok", covers=[_SAT])), "fast", 0, "fail", "vacuity guard"),
        ("another Kani version is refused",
         _fake_log(_GOOD, kani="0.69.0"), "fast", 0, "fail", "not the pinned"),
        ("another CBMC version is refused",
         _fake_log(_GOOD, cbmc="6.12.0"), "fast", 0, "fail", "not the pinned"),
        ("a run without a final summary did not finish",
         _fake_log(_GOOD, complete=False), "fast", 0, "fail", "did not finish"),
        ("a non-zero exit fails a clean-looking log",
         _fake_log(_GOOD), "fast", 101, "fail", "exited 101"),
        ("an empty log is not a pass", "", "fast", 0, "fail", "not a Kani run log"),
    ]
    failures = []
    for desc, text, kani_set, rc, want, needle in cases:
        result = judge(text, pins, hs, kani_set, rc)
        joined = "\n".join(result["problems"])
        if result["verdict"] != want:
            failures.append("%s: verdict %s, wanted %s\n      %s" % (desc, result["verdict"], want, joined))
        elif needle and needle not in joined:
            failures.append("%s: no problem mentions %r\n      %s" % (desc, needle, joined))
    # The witness of a clean run is reported as a known open finding, not dropped.
    clean = judge(_fake_log(_GOOD), pins, hs, "fast", 0)
    outcomes = {r["name"]: r["outcome"] for r in clean["harnesses"]}
    if outcomes != {"t_ok": "proved", "w_bug": "open-finding"}:
        failures.append("clean run outcomes: %r" % outcomes)
    if [f["label"] for f in clean["open_findings"]] != ["F9 T999"]:
        failures.append("clean run open findings: %r" % clean["open_findings"])

    # The manifest parser is strict.
    bad_manifests = [
        ("duplicate harness", _SELFTEST_MANIFEST + "harness t_ok theorem fast 1 1.0 T1\n"),
        ("unknown kind", "pin kani 1\npin cbmc 1\nharness a lemma fast 1 1.0 T1\n"),
        ("unknown set", "pin kani 1\npin cbmc 1\nharness a theorem nightly 1 1.0 T1\n"),
        ("zero covers", "pin kani 1\npin cbmc 1\nharness a theorem fast 0 1.0 T1\n"),
        ("no pin", "pin kani 1\nharness a theorem fast 1 1.0 T1\n"),
        ("unknown row", "pin kani 1\npin cbmc 1\nharnes a theorem fast 1 1.0 T1\n"),
    ]
    for desc, text in bad_manifests:
        try:
            parse_manifest(text)
            failures.append("manifest with %s was accepted" % desc)
        except GateError:
            pass

    # The inventory catches drift in both directions and a missing bound.
    src = (
        "#[kani::proof]\n#[kani::unwind(5)]\nfn t_ok() {}\n"
        "#[kani::proof]\n#[kani::unwind(5)]\nfn w_bug() {}\n"
        "#[kani::proof]\nfn t_new() {}\n"
    )
    found = parse_proofs(src)
    inv = "\n".join(inventory_problems(hs, found, []))
    for needle in ("t_new is in proofs.rs but not", "t_slow is in scripts/kani-harnesses.txt but not",
                   "t_new has no explicit #[kani::unwind"):
        if needle not in inv:
            failures.append("inventory did not report %r:\n      %s" % (needle, inv))
    try:
        parse_proofs("#[kani::proof]\n/// a doc comment in the way\nfn t_ok() {}\n")
        failures.append("a #[kani::proof] that could not be tied to a function was accepted")
    except GateError:
        pass

    # Playback extraction keeps the failure's test and drops the covers'.
    def _pb(check):
        return ("Concrete playback unit test for `proofs::t_ok`:\n```\n"
                "/// Test generated for harness `proofs::t_ok`\n///\n/// %s\n#[test]\nfn t() {}\n```\n" % check)
    pb = _pb('Check for `cover`: "a case"') + "noise\n" + _pb("Check for `assertion`: \"a deny produced a grant\"")
    got = failing_playback_blocks(pb)
    if len(got) != 1 or "a deny produced a grant" not in got[0]:
        failures.append("playback extraction returned %r" % got)
    if failing_playback_blocks(_pb('Check for `cover`: "a case"')):
        failures.append("a cover's playback test was taken for a counterexample")

    total = len(cases) + 2 + len(bad_manifests) + 4 + 2
    if failures:
        print("gate selftest: FAIL — %d of %d checks" % (len(failures), total))
        for f in failures:
            print("  - " + f)
        return 1
    print("gate selftest: %d checks of the Kani gate's failure policy pass" % total)
    return 0


# ── report: the tier-3 release artifact ─────────────────────────────


def read_text(rel):
    with open(os.path.join(ROOT, rel)) as fh:
        return fh.read()


def load_evidence():
    steps, kani = {}, {}
    if not os.path.isdir(EVIDENCE):
        return steps, kani
    for f in sorted(os.listdir(EVIDENCE)):
        path = os.path.join(EVIDENCE, f)
        if f.startswith("step-") and f.endswith(".json"):
            with open(path) as fh:
                rec = json.load(fh)
            steps[rec["step"]] = rec
        elif re.match(r"^kani-(fast|full)\.json$", f):
            with open(path) as fh:
                rec = json.load(fh)
            kani[rec["set"]] = rec
    return steps, kani


def evidence_state(rec, tree):
    """PASS / FAIL / SKIPPED / STALE / NOT RUN for one record."""
    if rec is None:
        return "NOT RUN"
    if rec.get("tree", {}).get("fingerprint") != tree["fingerprint"]:
        return "STALE"
    result = rec.get("result") or rec.get("verdict")
    return {"pass": "PASS", "fail": "FAIL", "skipped": "SKIPPED"}.get(result, "FAIL")


def product_version():
    in_package = False
    for line in read_text("Cargo.toml").splitlines():
        if line.strip().startswith("["):
            in_package = line.strip() == "[package]"
        elif in_package:
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    return "unknown"


def route_facts():
    classes = {}
    rows = 0
    for line in read_text("crates/bv-server/tests/golden/route-inventory.txt").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        rows += 1
        m = re.match(r"^\S+\s+\S+\s+\[([a-z-]+)\]", line)
        cls = m.group(1) if m else "UNPARSED"
        classes[cls] = classes.get(cls, 0) + 1
    anonymous = sum(
        1
        for line in read_text("crates/bv-server/tests/golden/anonymous-routes.txt").splitlines()
        if line.strip() and not line.startswith("#")
    )
    compile_fail = len(re.findall(r"```compile_fail", read_text("crates/bv-server/src/authz.rs")))
    return rows, classes, anonymous, compile_fail


def sql_facts():
    ui_dir = os.path.join(ROOT, "crates", "bv-sql-guard", "tests", "ui")
    trybuild = len([f for f in os.listdir(ui_dir) if f.endswith(".rs")]) if os.path.isdir(ui_dir) else 0
    sites = 0
    for top in ("src", "crates", os.path.join("gui", "src-tauri", "src")):
        for dirpath, _, files in os.walk(os.path.join(ROOT, top)):
            rel = os.path.relpath(dirpath, ROOT)
            if rel.startswith(os.path.join("crates", "bv-sql-guard")):
                continue
            for f in files:
                if f.endswith(".rs"):
                    with open(os.path.join(dirpath, f), errors="replace") as fh:
                        sites += fh.read().count("escape_hatch_reviewed(")
    return trybuild, sites


def bound_facts():
    lib = read_text("crates/bv-policy-core/src/lib.rs")
    model = read_text("crates/bv-policy-core/src/model.rs")

    def const(name):
        m = re.search(r"pub const %s: usize = (\d+);" % name, lib)
        return m.group(1) if m else "?"

    m = re.search(r"pub enum Seg\s*\{([^}]*)\}", model)
    alphabet = re.findall(r"^\s*(\w+)\s*,", m.group(1), re.M) if m else []
    return const("MAX_RULES"), const("MAX_SEGMENTS"), alphabet


def reached_tier(steps, kani, tree):
    """(tier, what is missing for the next one). -1 = tier 0 incomplete."""

    def ok(rec):
        return evidence_state(rec, tree) == "PASS"

    def cases():
        rec = steps.get("differential")
        try:
            return int(rec["notes"].get("cases", "0")) if ok(rec) else 0
        except (TypeError, ValueError):
            return 0

    missing0 = ["%s %s" % (s, evidence_state(steps.get(s), tree)) for s in TIER0_STEPS if not ok(steps.get(s))]
    if missing0:
        return -1, missing0
    if ok(kani.get("full")) and cases() >= TIER2_CASES:
        return 2, []
    missing2 = []
    if not ok(kani.get("full")):
        missing2.append("Kani full set " + evidence_state(kani.get("full"), tree))
    if cases() < TIER2_CASES:
        missing2.append("differential at %d cases (have %d)" % (TIER2_CASES, cases()))
    if (ok(kani.get("fast")) or ok(kani.get("full"))) and cases() >= TIER1_CASES:
        return 1, missing2
    return 0, missing2


def cmd_report(args):
    tree = tree_state()
    steps, kani = load_evidence()
    tier, missing = reached_tier(steps, kani, tree)
    failed = [n for n, r in steps.items() if evidence_state(r, tree) == "FAIL"]
    failed += ["kani-" + s for s, r in kani.items() if evidence_state(r, tree) == "FAIL"]
    version = product_version()
    # A release tag binds the report to a version (`02` §7–8). A tag that
    # names another version than the tree is the "tagged but forgot
    # `make bump-patch`" mistake, and the report must not paper over it.
    if args.tag and args.tag.startswith("releases/") and args.tag[len("releases/"):].lstrip("v") != version:
        failed.append("tag `%s` vs Cargo.toml version %s" % (args.tag, version))
    if failed:
        verdict = "FAIL"
    elif args.require_tier is not None and tier < args.require_tier:
        verdict = "INCOMPLETE"
    elif tier < 0:
        verdict = "INCOMPLETE"
    else:
        verdict = "PASS"

    tags = [t for t in git(["tag", "--points-at", "HEAD"]).split() if t]
    tag = args.tag or (", ".join(tags) if tags else "untagged")
    commit_date = git(["show", "-s", "--format=%cI", "HEAD"]).strip()
    pins, _ = load_manifest()
    # Harness detail comes only from a record of THIS tree: a stale table of
    # SUCCESSFUL rows would read as evidence it is not.
    current = {s: r for s, r in kani.items() if evidence_state(r, tree) in ("PASS", "FAIL")}
    k = current.get("full") or current.get("fast")

    def st(name):
        return evidence_state(steps.get(name), tree)

    def secs(name):
        rec = steps.get(name)
        return " (%.1f s)" % rec["seconds"] if rec and rec.get("seconds") else ""

    out = []
    w = out.append
    w("# Verification Report — BastionVault v%s" % version)
    w("")
    w("| | |")
    w("|---|---|")
    w("| Commit | `%s` (%s) |" % (tree["commit"], commit_date))
    w("| Tag | `%s`%s |" % (tag, " — names HEAD, not this dirty tree" if tree["dirty"] and not args.tag else ""))
    if tree["dirty"]:
        w("| Working tree | **DIRTY — %d changed file(s), fingerprint `%s`. Not a release artifact.** |"
          % (tree["changed_files"], tree["fingerprint"]))
    else:
        w("| Working tree | clean |")
    w("| Generated | %s |" % now_utc())
    if k:
        w("| Verifier | Kani %s · CBMC %s · solver: %s |" % (k["kani_version"], k["cbmc_version"], k.get("solver", "?")))
    else:
        w("| Verifier | pinned Kani %s · CBMC %s — **no Kani run recorded for this tree** |" % (pins["kani"], pins["cbmc"]))
    tier_text = {-1: "none — tier 0 incomplete", 0: "0 (gates)", 1: "1 (per-PR)", 2: "2 (nightly / release)"}[tier]
    w("| Tier reached | %s%s |" % (tier_text, " — missing: " + ", ".join(missing) if missing else ""))
    w("| **Verdict** | **%s** |" % verdict)
    w("")
    w("This report states only what the evidence records in `target/verify/` show for this exact tree. "
      "A check with no record is NOT RUN and a record from another tree is STALE; neither is counted "
      "as a pass. Generated by `make verification-report` (`scripts/verify.py report`).")
    if failed:
        w("")
        w("Failed: " + ", ".join("`%s`" % f for f in sorted(failed)))

    rows, classes, anonymous, compile_fail = route_facts()
    w("")
    w("## Structural (Phase 1)")
    w("")
    w("Routes served: **%d** — %s." % (rows, " · ".join("%s %d" % (c, n) for c, n in sorted(classes.items(), key=lambda kv: -kv[1]))))
    w("Anonymous surface: **%d** routes (`crates/bv-server/tests/golden/anonymous-routes.txt`)." % anonymous)
    w("")
    w("| Check | Result |")
    w("|---|---|")
    w("| Golden files, registration gate, witness tests (`cargo nextest run -p bv-server --lib routes:: authz::`) | %s%s |" % (st("routes"), secs("routes")))
    w("| `Authorized<R>` doctests in `authz.rs`: %d `compile_fail` + a compiling control (`cargo test --doc -p bv-server authz`) | %s%s |"
      % (compile_fail, st("witness-doctests"), secs("witness-doctests")))

    trybuild, hatch_sites = sql_facts()
    w("")
    w("## SQL (Phase 2)")
    w("")
    w("| Check | Result |")
    w("|---|---|")
    w("| Text gate (`scripts/check-sql-guard.sh`) | %s%s |" % (st("sql-gate"), secs("sql-gate")))
    sem = steps.get("semgrep")
    sem_state = st("semgrep")
    if sem_state == "SKIPPED" and sem:
        sem_state += " — " + sem.get("reason", "")
    w("| Semgrep `bv-unguarded-sql-statement` (`.semgrep/sql-guard.yml`) | %s%s |" % (sem_state, secs("semgrep")))
    w("| `bv-sql-guard` + `bv-policy-core` unit and `trybuild` compile-fail tests (%d cases) | %s%s |" % (trybuild, st("core-tests"), secs("core-tests")))
    w("| `cargo clippy -D warnings` on both crates | %s%s |" % (st("core-lint"), secs("core-lint")))
    w("| `escape_hatch_reviewed` call sites outside the guard crate | %d |" % hatch_sites)

    w("")
    w("## Formal (Phase 3)")
    w("")
    w("| Check | Result |")
    w("|---|---|")
    w("| Harness inventory (proofs.rs vs `scripts/kani-harnesses.txt`) | %s |" % st("kani-inventory"))
    w("| Kani gate self-test | %s |" % st("gate-selftest"))
    for s in ("full", "fast"):
        if s in kani:
            rec = kani[s]
            w("| Kani, %s set (%d harnesses, %.0f s wall) | %s |" % (s, len(rec["harnesses"]), rec.get("wall_seconds", 0), evidence_state(rec, tree)))
    if not kani:
        w("| Kani | NOT RUN |")
    diff = steps.get("differential")
    cases_text = diff["notes"].get("cases", "?") if diff else "-"
    w("| Differential suite vs. the frozen evaluator (`bv-kernel` `policy::differential`, %s cases) | %s%s |" % (cases_text, st("differential"), secs("differential")))
    if k:
        w("")
        w("Harnesses (%s set):" % k["set"])
        w("")
        w("| Harness | Proves | Result | Covers | Unwind | Time |")
        w("|---|---|---|---|---|---|")
        for r in k["harnesses"]:
            sat = sum(1 for c in r["covers"] if c["status"] == "SATISFIED")
            result = {"proved": "SUCCESSFUL", "open-finding": "OPEN FINDING (defect present)", "failed": "**FAILED**"}[r["outcome"]]
            w("| `%s` | %s | %s | %d/%d SATISFIED | %s | %s |" % (
                r["name"], r["label"] if r["kind"] == "theorem" else "witness " + r["label"], result,
                sat, len(r["covers"]), r["unwind"] if r["unwind"] is not None else "?",
                "%.1f s" % r["time_s"] if r["time_s"] is not None else "-"))
        w("")
        if k["open_findings"]:
            w("### Known open findings")
            w("")
            w("Defect witnesses whose covers are `SATISFIED`: the defect is present in this build. "
              "They are tracked, not hidden, and the gate fails the day one stops reproducing.")
            w("")
            for f in k["open_findings"]:
                label = f["label"].split()
                w("- **%s** (%s) — `%s`: %s." % (
                    label[0], label[1] if len(label) > 1 else "untracked", f["harness"],
                    "; ".join('"%s"' % c["description"] for c in f["covers"])))
            w("")
        if k["problems"]:
            w("### Kani gate problems")
            w("")
            for p in k["problems"]:
                w("- " + p)
            w("")
    else:
        w("")
        w("No Kani record of this tree, so no harness results are reported.")
        w("")
    max_rules, max_segments, alphabet = bound_facts()
    w("Bounds: `MAX_RULES = %s` per layer, `MAX_SEGMENTS = %s`, path alphabet {%s} (%d symbols); "
      "every harness's unwind bound is in the table above." % (max_rules, max_segments, ", ".join(alphabet), len(alphabet)))
    w("")
    w("## Not covered")
    w("")
    w("What these checks do **not** establish is in `docs/verification.md` § What is not proved "
      "(bounds, the index's real string matching, the asynchronous inputs, everything upstream "
      "of the evaluator, concurrency). Read it before quoting this report.")
    w("")

    out_path = args.out or os.path.join(EVIDENCE, "verification-report.md")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write("\n".join(out))
    shown = os.path.relpath(out_path, ROOT) if os.path.abspath(out_path).startswith(ROOT + os.sep) else out_path
    print("verification report: %s — verdict %s, tier %s" % (shown, verdict, tier_text))
    if verdict == "FAIL":
        return 1
    if args.require_tier is not None and tier < args.require_tier:
        print("error: tier %d required, reached %s" % (args.require_tier, tier_text))
        return 1
    return 0


def main(argv):
    # Our banners must interleave correctly with the output of the commands we
    # run, which write straight to the inherited descriptor; under a pipe (CI,
    # `| tee`) stdout would otherwise be block-buffered.
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command")
    sub.required = True

    p = sub.add_parser("step", help="run one verification step and record its outcome")
    p.add_argument("name")
    p.add_argument("--note", action="append", help="KEY=VALUE stored with the record")
    p.add_argument("--skip", metavar="REASON", help="record the step as explicitly SKIPPED")
    p.set_defaults(func=cmd_step)

    p = sub.add_parser("inventory", help="proofs.rs harnesses == scripts/kani-harnesses.txt")
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("kani", help="run cargo kani over a harness set and gate the result")
    p.add_argument("--set", choices=("fast", "full"), required=True)
    p.add_argument("--verbose", action="store_true", help="stream Kani's full output")
    p.add_argument("--playback-on-failure", action="store_true",
                   help="re-run failed harnesses with concrete playback to print the counterexample")
    p.set_defaults(func=cmd_kani)

    p = sub.add_parser("kani-check", help="gate an existing Kani log")
    p.add_argument("--set", choices=("fast", "full"), required=True)
    p.add_argument("--exit-code", type=int, default=0)
    p.add_argument("log")
    p.set_defaults(func=cmd_kani_check)

    p = sub.add_parser("pin", help="print a pinned verifier version")
    p.add_argument("tool", choices=("kani", "cbmc"))
    p.set_defaults(func=cmd_pin)

    p = sub.add_parser("cases", help="print the differential case count a tier requires")
    p.add_argument("tier", type=int, choices=(1, 2))
    p.set_defaults(func=cmd_cases)

    p = sub.add_parser("selftest", help="exercise the gate's failure policy on synthetic logs")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("report", help="write verification-report.md from the recorded evidence")
    p.add_argument("--tag")
    p.add_argument("--out")
    p.add_argument("--require-tier", type=int, choices=(0, 1, 2))
    p.set_defaults(func=cmd_report)

    # `step NAME [options] -- CMD...`: the command is split off here, before
    # argparse, so an option-looking word in it is never read as ours.
    cmd = []
    if "--" in argv:
        split = argv.index("--")
        argv, cmd = argv[:split], argv[split + 1:]
    args = parser.parse_args(argv)
    args.cmd = cmd
    if cmd and args.command != "step":
        parser.error("`--` is only meaningful for `step`")
    try:
        return args.func(args)
    except GateError as e:
        print("error: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
