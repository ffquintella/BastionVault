#!/usr/bin/env python3
"""Cross-session recall with brain-like decay — the memory an agent carries between sessions.

Instructions given in one coding session are lost when it ends. This keeps the small,
durable ones and injects the most relevant into every later session, in any assistant that
reads a markdown instruction file.

Relevance is ACT-R base-level activation, the standard formalization of "recent and frequent
wins":

    activation(m) = ln( SUM_j (now - t_j) ** -d )      d = 0.5, t_j = each past use

Every use of a memory leaves a decaying trace; the traces sum. One use yesterday beats ten
uses a year ago, and ten uses this month beat one use yesterday. Nothing is deleted on a
schedule — memories that fall under the floor are archived, so the history stays available
for retuning `d` later.

Two rules keep the system honest, and both matter more than the arithmetic:

  * Rendering a memory does NOT reinforce it. Only an explicit `use`, or a `touch` on a file
    the memory is anchored to, counts as a use. Counting injections would make whatever is
    already in the prompt reinforce itself into a permanent fixture.
  * A stale instruction with high activation is worse than no memory at all. `add` reports
    candidate conflicts in the same scope so they can be resolved with `supersede`, which
    retires the loser instead of leaving two contradictory lines competing.

Storage is one SQLite file (default `~/.claude/memory/recall.db`, override with
`RECALL_DB`). `scope` is either `global` or a repository root, so a project's conventions
stay in that project while preferences about how to work follow you everywhere.

Injection is deliberately a file, not a protocol: `render` writes a managed block into any
markdown file, so Claude Code, Codex, Cline, and Cursor all pick the same memories up
without a server between them.

Usage:
    recall.py add "Prefer sqlx query! over the query builder" --kind convention
    recall.py add "Never touch migrations/ without asking" --scope . --anchor migrations/
    recall.py use 12                       # reinforce — a real use, not an injection
    recall.py touch --file src/dal/user.rs # reinforce every memory anchored to that path
    recall.py render --scope . --max-lines 40
    recall.py render --into ~/.claude/CLAUDE.md --scope global
    recall.py list --scope . --json
    recall.py supersede 7 --by 12
    recall.py forget 7
    recall.py decay                        # archive whatever fell under the floor
    recall.py stats

    recall.py hook session-start           # Claude Code hooks; JSON in, JSON out
    recall.py hook prompt-submit
    recall.py hook post-edit

Exit status: 0 fine, 1 nothing matched the request, 2 the store could not be opened.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

# --- tuning -----------------------------------------------------------------
#
# `DECAY` is the ACT-R d parameter. 0.5 is the value the psychology literature
# settles on for human declarative memory and it behaves well here: half the
# activation of a single trace is gone after four times the elapsed time.
DECAY = 0.5

# Traces closer than this are clamped, so a memory added a second ago has a
# large-but-finite activation instead of dividing by zero.
MIN_ELAPSED_DAYS = 1.0 / 24.0

# Below this, a memory is a candidate for archiving. A single use 180 days ago
# sits at about -2.6; a single use 30 days ago at about -1.7.
ARCHIVE_FLOOR = -2.5

# Per-memory trace cap. Activation is dominated by the newest traces, so
# keeping every use of a memory used daily for two years buys nothing.
MAX_TRACES = 48

# The render budget. This is the point of the whole exercise: instructions get
# less effective as they get longer, so the cap is what forces activation to
# actually decide anything.
MAX_LINES = 40
MAX_CHARS = 6000

# Space held back from the budget for the two lines `render` appends at the end.
FOOTER_RESERVE = 240

KINDS = ("preference", "convention", "gotcha", "fact")

BEGIN = "<!-- recall:begin -->"
END = "<!-- recall:end -->"

DAY = 86400.0

STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "do", "dont", "for", "from",
    "in", "is", "it", "its", "never", "no", "not", "of", "on", "or", "should", "so",
    "than", "that", "the", "then", "this", "to", "use", "used", "using", "was", "when",
    "with", "you", "your",
}


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    id            INTEGER PRIMARY KEY,
    scope         TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    text          TEXT    NOT NULL,
    anchors       TEXT    NOT NULL DEFAULT '',
    pinned        INTEGER NOT NULL DEFAULT 0,
    created_at    REAL    NOT NULL,
    archived_at   REAL,
    superseded_by INTEGER REFERENCES memory(id)
);

CREATE TABLE IF NOT EXISTS trace (
    id        INTEGER PRIMARY KEY,
    memory_id INTEGER NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    used_at   REAL    NOT NULL,
    reason    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS trace_memory ON trace(memory_id, used_at DESC);
CREATE INDEX IF NOT EXISTS memory_scope ON memory(scope, archived_at);
CREATE UNIQUE INDEX IF NOT EXISTS memory_unique ON memory(scope, text);
"""


def db_path() -> Path:
    env = os.environ.get("RECALL_DB")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".claude" / "memory" / "recall.db"


def connect() -> sqlite3.Connection:
    path = db_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=10.0)
    except (OSError, sqlite3.Error) as exc:
        sys.exit(f"recall: cannot open {path}: {exc}")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript(SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------

def resolve_scope(raw: str | None) -> str:
    """`global`, or the repository root a path belongs to.

    Scoping on the git root rather than the working directory means a memory added
    from `crates/dal` is still there when the next session starts in the repo root.
    """
    if raw is None or raw == "global":
        return "global"
    start = Path(raw).expanduser().resolve()
    if not start.is_dir():
        start = start.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return str(start)


def scope_label(scope: str) -> str:
    return "everywhere" if scope == "global" else Path(scope).name


# ---------------------------------------------------------------------------
# activation
# ---------------------------------------------------------------------------

def activation(traces: list[float], now: float) -> float:
    """ACT-R base-level activation over a memory's use times, in days."""
    total = 0.0
    for used_at in traces:
        elapsed = max((now - used_at) / DAY, MIN_ELAPSED_DAYS)
        total += elapsed ** -DECAY
    if total <= 0.0:
        return float("-inf")
    return math.log(total)


def load(conn: sqlite3.Connection, scopes: list[str], include_archived: bool = False) -> list[dict]:
    now = time.time()
    placeholders = ",".join("?" for _ in scopes)
    sql = f"""
        SELECT m.*, t.used_at
          FROM memory m
          LEFT JOIN trace t ON t.memory_id = m.id
         WHERE m.scope IN ({placeholders})
           AND m.superseded_by IS NULL
    """
    if not include_archived:
        sql += " AND m.archived_at IS NULL"
    sql += " ORDER BY m.id, t.used_at DESC"

    rows: dict[int, dict] = {}
    for row in conn.execute(sql, scopes):
        entry = rows.get(row["id"])
        if entry is None:
            entry = {
                "id": row["id"],
                "scope": row["scope"],
                "kind": row["kind"],
                "text": row["text"],
                "anchors": [a for a in row["anchors"].split(",") if a],
                "pinned": bool(row["pinned"]),
                "created_at": row["created_at"],
                "archived_at": row["archived_at"],
                "traces": [],
            }
            rows[row["id"]] = entry
        if row["used_at"] is not None and len(entry["traces"]) < MAX_TRACES:
            entry["traces"].append(row["used_at"])

    out = list(rows.values())
    for entry in out:
        entry["uses"] = len(entry["traces"])
        entry["last_used"] = max(entry["traces"]) if entry["traces"] else entry["created_at"]
        entry["activation"] = activation(entry["traces"] or [entry["created_at"]], now)
    out.sort(key=lambda e: (e["pinned"], e["activation"]), reverse=True)
    return out


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9_]{3,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def conflicts(conn: sqlite3.Connection, scope: str, kind: str, text: str) -> list[dict]:
    """Existing memories that talk about the same things as `text`.

    Cheap on purpose: shared significant tokens, not semantics. It only has to be
    good enough to put the candidates in front of a reader who can judge them.
    """
    wanted = tokens(text)
    if len(wanted) < 2:
        return []
    hits = []
    for row in conn.execute(
        "SELECT id, kind, text FROM memory"
        " WHERE scope = ? AND archived_at IS NULL AND superseded_by IS NULL",
        (scope,),
    ):
        shared = wanted & tokens(row["text"])
        if len(shared) >= 2 or (row["kind"] == kind and len(shared) >= 1 and len(wanted) <= 3):
            hits.append({"id": row["id"], "text": row["text"], "shared": sorted(shared)})
    return hits


def cmd_add(conn: sqlite3.Connection, args) -> int:
    text = " ".join(args.text).strip()
    if not text:
        sys.exit("recall: refusing to store an empty memory")
    text = re.sub(r"\s+", " ", text)
    if len(text) > 300:
        sys.exit(f"recall: {len(text)} chars is a document, not a memory — keep it under 300")

    scope = resolve_scope(args.scope)
    now = time.time()
    anchors = ",".join(a.strip() for a in args.anchor if a.strip())

    found = conflicts(conn, scope, args.kind, text)

    row = conn.execute(
        "SELECT id, archived_at FROM memory WHERE scope = ? AND text = ?", (scope, text)
    ).fetchone()
    if row is not None:
        # Saying the same thing twice is itself a use, and un-archives it.
        conn.execute(
            "UPDATE memory SET archived_at = NULL, superseded_by = NULL, pinned = ?,"
            " anchors = CASE WHEN ? = '' THEN anchors ELSE ? END WHERE id = ?",
            (int(args.pin), anchors, anchors, row["id"]),
        )
        conn.execute(
            "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, 'restated')",
            (row["id"], now),
        )
        conn.commit()
        mid = row["id"]
        print(f"reinforced #{mid} ({scope_label(scope)}) {text}")
    else:
        cur = conn.execute(
            "INSERT INTO memory (scope, kind, text, anchors, pinned, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (scope, args.kind, text, anchors, int(args.pin), now),
        )
        mid = cur.lastrowid
        conn.execute(
            "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, 'added')",
            (mid, now),
        )
        conn.commit()
        print(f"remembered #{mid} ({args.kind}, {scope_label(scope)}) {text}")

    if args.supersedes:
        for old in args.supersedes:
            _supersede(conn, old, mid)
        conn.commit()
        print(f"  superseded {', '.join('#' + str(o) for o in args.supersedes)}")

    for hit in found:
        if hit["id"] in (args.supersedes or []) or hit["id"] == mid:
            continue
        print(
            f"  possible conflict with #{hit['id']}: {hit['text']}\n"
            f"    -> if it contradicts this, run: recall.py supersede {hit['id']} --by {mid}",
            file=sys.stderr,
        )
    return 0


def cmd_use(conn: sqlite3.Connection, args) -> int:
    now = time.time()
    hit = 0
    for mid in args.ids:
        row = conn.execute("SELECT id FROM memory WHERE id = ?", (mid,)).fetchone()
        if row is None:
            print(f"recall: no memory #{mid}", file=sys.stderr)
            continue
        conn.execute(
            "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, ?)",
            (mid, now, args.reason),
        )
        conn.execute("UPDATE memory SET archived_at = NULL WHERE id = ?", (mid,))
        hit += 1
    conn.commit()
    if not args.quiet:
        print(f"reinforced {hit} memor{'y' if hit == 1 else 'ies'}")
    return 0 if hit else 1


def matches_anchor(anchors: list[str], path: str) -> bool:
    norm = path.replace(os.sep, "/")
    name = norm.rsplit("/", 1)[-1]
    for anchor in anchors:
        a = anchor.replace(os.sep, "/")
        if any(ch in a for ch in "*?["):
            if fnmatch.fnmatch(norm, a) or fnmatch.fnmatch(norm, f"*/{a}") or fnmatch.fnmatch(name, a):
                return True
        elif a in norm or a == name:
            return True
    return False


def cmd_touch(conn: sqlite3.Connection, args) -> int:
    """Reinforce memories anchored to the files this session actually worked on.

    This is the frequency signal that cannot be gamed by injection: the memory about
    the migrations directory gets stronger when someone edits a migration, and stays
    where it is otherwise.
    """
    scopes = ["global", resolve_scope(args.scope)]
    now = time.time()
    touched: list[dict] = []
    for entry in load(conn, scopes):
        if not entry["anchors"]:
            continue
        if any(matches_anchor(entry["anchors"], f) for f in args.file):
            conn.execute(
                "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, 'touched')",
                (entry["id"], now),
            )
            touched.append(entry)
    conn.commit()
    if args.json:
        print(json.dumps([{"id": e["id"], "text": e["text"]} for e in touched]))
    elif touched:
        for entry in touched:
            print(f"reinforced #{entry['id']} {entry['text']}")
    return 0 if touched else 1


def _supersede(conn: sqlite3.Connection, old: int, new: int) -> None:
    conn.execute(
        "UPDATE memory SET superseded_by = ?, archived_at = COALESCE(archived_at, ?)"
        " WHERE id = ?",
        (new, time.time(), old),
    )


def cmd_supersede(conn: sqlite3.Connection, args) -> int:
    for mid in (args.old, args.by):
        if conn.execute("SELECT 1 FROM memory WHERE id = ?", (mid,)).fetchone() is None:
            sys.exit(f"recall: no memory #{mid}")
    _supersede(conn, args.old, args.by)
    conn.commit()
    print(f"#{args.old} retired in favour of #{args.by}")
    return 0


def cmd_forget(conn: sqlite3.Connection, args) -> int:
    gone = 0
    for mid in args.ids:
        if args.purge:
            cur = conn.execute("DELETE FROM memory WHERE id = ?", (mid,))
        else:
            cur = conn.execute(
                "UPDATE memory SET archived_at = ? WHERE id = ? AND archived_at IS NULL",
                (time.time(), mid),
            )
        if cur.rowcount:
            gone += 1
        else:
            print(f"recall: nothing to do for #{mid}", file=sys.stderr)
    conn.commit()
    verb = "purged" if args.purge else "archived"
    print(f"{verb} {gone}")
    return 0 if gone else 1


def cmd_decay(conn: sqlite3.Connection, args) -> int:
    """Archive what has faded. Nothing is deleted — `d` may want retuning later."""
    now = time.time()
    archived = []
    for entry in load(conn, [s for (s,) in conn.execute("SELECT DISTINCT scope FROM memory")] or ["global"]):
        if entry["pinned"]:
            continue
        age_days = (now - entry["created_at"]) / DAY
        if age_days < args.grace_days:
            continue
        if entry["activation"] >= args.floor:
            continue
        archived.append(entry)
        if not args.dry_run:
            conn.execute("UPDATE memory SET archived_at = ? WHERE id = ?", (now, entry["id"]))
    conn.commit()
    for entry in archived:
        print(f"{'would archive' if args.dry_run else 'archived'} "
              f"#{entry['id']} (a={entry['activation']:+.2f}) {entry['text']}")
    if not archived:
        print("nothing has faded")
    return 0


def cmd_list(conn: sqlite3.Connection, args) -> int:
    scopes = ["global"] if args.scope in (None, "global") else ["global", resolve_scope(args.scope)]
    entries = load(conn, scopes, include_archived=args.archived)
    if args.kind:
        entries = [e for e in entries if e["kind"] == args.kind]
    if args.json:
        print(json.dumps([
            {k: e[k] for k in
             ("id", "scope", "kind", "text", "anchors", "pinned", "uses", "activation")}
            for e in entries
        ], indent=2))
        return 0 if entries else 1
    if not entries:
        print("nothing remembered yet")
        return 1
    now = time.time()
    for e in entries:
        age = (now - e["last_used"]) / DAY
        flags = "".join(("*" if e["pinned"] else "", "~" if e["archived_at"] else ""))
        print(f"#{e['id']:<4} a={e['activation']:+.2f} n={e['uses']:<3} {age:6.1f}d "
              f"{e['kind'][:10]:<10} {scope_label(e['scope'])[:14]:<14} {flags}{e['text']}")
    return 0


def cmd_stats(conn: sqlite3.Connection, args) -> int:
    total = conn.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
    live = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE archived_at IS NULL AND superseded_by IS NULL"
    ).fetchone()[0]
    traces = conn.execute("SELECT COUNT(*) FROM trace").fetchone()[0]
    print(f"store       {db_path()}")
    print(f"memories    {live} live, {total - live} archived or superseded")
    print(f"traces      {traces}")
    for row in conn.execute(
        "SELECT scope, COUNT(*) n FROM memory WHERE archived_at IS NULL"
        " AND superseded_by IS NULL GROUP BY scope ORDER BY n DESC"
    ):
        print(f"  {row['n']:>4}  {row['scope']}")
    return 0


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

def render(conn: sqlite3.Connection, scope: str, max_lines: int, max_chars: int) -> str:
    scopes = ["global"] if scope == "global" else ["global", scope]
    entries = load(conn, scopes)
    if not entries:
        return ""

    lines = ["## Recalled context",
             "",
             "Carried over from earlier sessions, ordered by how recently and often each one"
             " mattered. Apply them; when one turns out to be wrong or obsolete, say so —"
             " do not work around it silently.",
             ""]

    def spent(ls: list[str]) -> int:
        return sum(len(line) + 1 for line in ls)

    # The two closing lines are written after the loop, so their cost has to be
    # reserved before it — otherwise a full budget overshoots by exactly the footer.
    reserved = max_chars - FOOTER_RESERVE
    shown = 0
    for kind in KINDS:
        group = [e for e in entries if e["kind"] == kind]
        if not group:
            continue
        pending = [f"**{kind}**"]
        for entry in group:
            if shown >= max_lines:
                break
            line = f"- [{entry['id']}] {entry['text']}"
            if entry["anchors"]:
                line += f"  _({', '.join(entry['anchors'])})_"
            if spent(lines) + spent(pending) + len(line) + 1 > reserved:
                break
            pending.append(line)
            shown += 1
        if len(pending) > 1:
            lines.extend(pending)
            lines.append("")

    if shown == 0:
        return ""

    dropped = len(entries) - shown
    if dropped > 0:
        lines.append(f"_{dropped} weaker memor{'y' if dropped == 1 else 'ies'} withheld;"
                     f" `recall.py list --scope .` shows everything._")
    lines.append("_Applied one of these? `recall.py use <id>` — that is what keeps it alive._")

    block = "\n".join(lines).rstrip() + "\n"
    if len(block) > max_chars:
        # Only reachable if max_chars is smaller than the footer itself. Drop whole
        # lines from the end rather than handing back a truncated instruction.
        while lines and len("\n".join(lines).rstrip()) + 1 > max_chars:
            lines.pop()
        block = "\n".join(lines).rstrip() + "\n" if lines else ""
    return block


def splice(existing: str, block: str) -> str:
    """Replace the managed block in `existing`, leaving everything else untouched."""
    managed = f"{BEGIN}\n{block}{END}\n" if block else ""
    start = existing.find(BEGIN)
    end = existing.find(END)
    if start != -1 and end != -1 and end > start:
        head = existing[:start]
        tail = existing[end + len(END):].lstrip("\n")
        if managed and tail:
            return f"{head}{managed}\n{tail}"
        return f"{head}{managed}{tail}"
    if not managed:
        return existing
    if existing and not existing.endswith("\n\n"):
        existing = existing.rstrip("\n") + "\n\n"
    return f"{existing}{managed}"


def cmd_render(conn: sqlite3.Connection, args) -> int:
    scope = resolve_scope(args.scope)
    block = render(conn, scope, args.max_lines, args.max_chars)
    if not args.into:
        sys.stdout.write(block)
        return 0 if block else 1

    target = Path(args.into).expanduser()
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    updated = splice(existing, block)
    if updated != existing:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".recall-tmp")
        tmp.write_text(updated, encoding="utf-8")
        tmp.replace(target)
        print(f"wrote {len(block.splitlines())} lines into {target}")
    else:
        print(f"{target} already current")
    return 0


# ---------------------------------------------------------------------------
# hooks
# ---------------------------------------------------------------------------

# An explicit directive, and only that. Anything else in the prompt is data: this hook
# never infers a memory from what it happens to read.
REMEMBER = re.compile(
    r"(?:^|\n|[.;!?]\s+)\s*(?:remember|recall|lembrar|lembre)"
    r"(?:\s+(?:that|this|isso|que))?\s*[:,]\s*(?P<text>[^\n]+)",
    re.IGNORECASE,
)


def hook_input() -> dict:
    try:
        raw = sys.stdin.read()
    except (OSError, ValueError):
        return {}
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def emit(event: str, context: str = "", message: str = "") -> None:
    out: dict = {"suppressOutput": True}
    if context:
        out["hookSpecificOutput"] = {"hookEventName": event, "additionalContext": context}
    if message:
        out["systemMessage"] = message
    print(json.dumps(out))


def cmd_hook(conn: sqlite3.Connection, args) -> int:
    payload = hook_input()
    cwd = payload.get("cwd") or os.getcwd()

    if args.event == "session-start":
        block = render(conn, resolve_scope(cwd), args.max_lines, args.max_chars)
        emit("SessionStart", context=block)
        return 0

    if args.event == "prompt-submit":
        # A prompt is data, not a command: the only thing acted on here is the
        # explicit `remember:` directive the user typed themselves.
        prompt = payload.get("prompt") or ""
        stored = []
        for match in REMEMBER.finditer(prompt):
            text = re.sub(r"\s+", " ", match.group("text")).strip().rstrip(".")
            if not text or len(text) > 300:
                continue
            scope = resolve_scope(cwd)
            now = time.time()
            try:
                cur = conn.execute(
                    "INSERT INTO memory (scope, kind, text, created_at) VALUES (?, ?, ?, ?)",
                    (scope, "preference", text, now),
                )
                mid = cur.lastrowid
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT id FROM memory WHERE scope = ? AND text = ?", (scope, text)
                ).fetchone()
                mid = row["id"]
                conn.execute("UPDATE memory SET archived_at = NULL WHERE id = ?", (mid,))
            conn.execute(
                "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, 'directive')",
                (mid, now),
            )
            stored.append((mid, text))
        conn.commit()
        if stored:
            ids = ", ".join(f"#{m}" for m, _ in stored)
            emit(
                "UserPromptSubmit",
                context=(
                    f"Stored {len(stored)} memor{'y' if len(stored) == 1 else 'ies'} for later"
                    f" sessions ({ids}). Classify each one now if `preference` is wrong:"
                    " `recall.py list --scope . --json`, then re-add with the right --kind,"
                    " --anchor, or --scope global. Check the conflict warnings."
                ),
                message=f"recall: remembered {ids}",
            )
        else:
            print(json.dumps({"suppressOutput": True}))
        return 0

    if args.event == "post-edit":
        path = (payload.get("tool_input") or {}).get("file_path")
        if not path:
            path = (payload.get("tool_response") or {}).get("filePath")
        if not path:
            print(json.dumps({"suppressOutput": True}))
            return 0
        scopes = ["global", resolve_scope(cwd)]
        now = time.time()
        for entry in load(conn, scopes):
            if entry["anchors"] and matches_anchor(entry["anchors"], str(path)):
                conn.execute(
                    "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, 'touched')",
                    (entry["id"], now),
                )
        conn.commit()
        print(json.dumps({"suppressOutput": True}))
        return 0

    sys.exit(f"recall: unknown hook event {args.event}")


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recall.py",
        description="Cross-session memory ranked by recency and frequency.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="store a memory (or reinforce an identical one)")
    a.add_argument("text", nargs="+")
    a.add_argument("--kind", choices=KINDS, default="fact")
    a.add_argument("--scope", default="global",
                   help="'global', or a path whose repository root scopes the memory ('.')")
    a.add_argument("--anchor", action="append", default=[],
                   help="path or glob; editing it reinforces this memory (repeatable)")
    a.add_argument("--pin", action="store_true", help="always render, never decay")
    a.add_argument("--supersedes", type=int, action="append",
                   help="retire an older memory this one replaces (repeatable)")
    a.set_defaults(fn=cmd_add)

    u = sub.add_parser("use", help="record a real use — the only thing that reinforces")
    u.add_argument("ids", nargs="+", type=int)
    u.add_argument("--reason", default="applied")
    u.add_argument("--quiet", action="store_true")
    u.set_defaults(fn=cmd_use)

    t = sub.add_parser("touch", help="reinforce every memory anchored to these files")
    t.add_argument("--file", action="append", required=True)
    t.add_argument("--scope", default=".")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=cmd_touch)

    r = sub.add_parser("render", help="render the top memories as a markdown block")
    r.add_argument("--scope", default=".")
    r.add_argument("--into", help="file to splice the managed block into")
    r.add_argument("--max-lines", type=int, default=MAX_LINES)
    r.add_argument("--max-chars", type=int, default=MAX_CHARS)
    r.set_defaults(fn=cmd_render)

    l = sub.add_parser("list", help="show memories with their activation")
    l.add_argument("--scope", default=".")
    l.add_argument("--kind", choices=KINDS)
    l.add_argument("--archived", action="store_true")
    l.add_argument("--json", action="store_true")
    l.set_defaults(fn=cmd_list)

    s = sub.add_parser("supersede", help="retire a memory in favour of a newer one")
    s.add_argument("old", type=int)
    s.add_argument("--by", type=int, required=True)
    s.set_defaults(fn=cmd_supersede)

    f = sub.add_parser("forget", help="archive a memory (--purge to delete it outright)")
    f.add_argument("ids", nargs="+", type=int)
    f.add_argument("--purge", action="store_true")
    f.set_defaults(fn=cmd_forget)

    d = sub.add_parser("decay", help="archive whatever has fallen under the floor")
    d.add_argument("--floor", type=float, default=ARCHIVE_FLOOR)
    d.add_argument("--grace-days", type=float, default=14.0)
    d.add_argument("--dry-run", action="store_true")
    d.set_defaults(fn=cmd_decay)

    st = sub.add_parser("stats", help="where the store is and what is in it")
    st.set_defaults(fn=cmd_stats)

    h = sub.add_parser("hook", help="Claude Code hook entry points (JSON in, JSON out)")
    h.add_argument("event", choices=("session-start", "prompt-submit", "post-edit"))
    h.add_argument("--max-lines", type=int, default=MAX_LINES)
    h.add_argument("--max-chars", type=int, default=MAX_CHARS)
    h.set_defaults(fn=cmd_hook)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    conn = connect()
    try:
        return args.fn(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
