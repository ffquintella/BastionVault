#!/usr/bin/env python3
"""Tests for `recall.py` — the ranking, the two honesty rules, and the render budget.

    python3 ai/memory/test_recall.py                 # or: make test-memory

The scoring is the part where a bug is invisible: a wrong exponent still produces a
plausible-looking ordered list. So the ranking cases below are stated as the claims the
design makes ("ten uses this month beats one use yesterday"), not as expected floats.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DAY = 86400.0


def load_module():
    spec = importlib.util.spec_from_file_location("recall", HERE / "recall.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recall = load_module()


@contextlib.contextmanager
def quiet():
    """Run a CLI entry point without its progress output landing in the test log."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "recall.db"
        os.environ["RECALL_DB"] = str(self.db)
        self.conn = recall.connect()

    def tearDown(self) -> None:
        self.conn.close()
        os.environ.pop("RECALL_DB", None)
        self.tmp.cleanup()

    def add(self, text: str, kind: str = "fact", scope: str = "global", **kw) -> int:
        cur = self.conn.execute(
            "INSERT INTO memory (scope, kind, text, anchors, pinned, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (scope, kind, text, kw.get("anchors", ""), int(kw.get("pinned", False)),
             time.time()),
        )
        return cur.lastrowid

    def use(self, mid: int, days_ago: float) -> None:
        self.conn.execute(
            "INSERT INTO trace (memory_id, used_at, reason) VALUES (?, ?, 'test')",
            (mid, time.time() - days_ago * DAY),
        )


class TestActivation(Base):
    """Recent and frequent both count — that is the whole claim being made."""

    def rank(self) -> list[str]:
        self.conn.commit()
        return [e["text"] for e in recall.load(self.conn, ["global"])]

    def test_recent_beats_old_at_equal_frequency(self):
        old = self.add("old")
        new = self.add("new")
        for m, d in ((old, 200.0), (new, 1.0)):
            self.use(m, d)
        self.assertEqual(self.rank()[0], "new")

    def test_frequent_beats_recent_when_frequent_enough(self):
        once = self.add("once yesterday")
        often = self.add("ten times this month")
        self.use(once, 1.0)
        for d in (1, 3, 5, 7, 9, 11, 14, 18, 22, 28):
            self.use(often, float(d))
        self.assertEqual(self.rank()[0], "ten times this month")

    def test_frequency_does_not_outlive_decay(self):
        """Ten uses a year ago must not outrank one use yesterday."""
        stale = self.add("ten times a year ago")
        fresh = self.add("once yesterday")
        for d in range(350, 360):
            self.use(stale, float(d))
        self.use(fresh, 1.0)
        self.assertEqual(self.rank()[0], "once yesterday")

    def test_pinned_outranks_everything(self):
        pinned = self.add("pinned", pinned=True)
        hot = self.add("hot")
        self.use(pinned, 400.0)
        for d in range(1, 20):
            self.use(hot, float(d))
        self.assertEqual(self.rank()[0], "pinned")

    def test_a_memory_never_used_still_scores(self):
        """`created_at` stands in for a first use, so a fresh memory is not -inf."""
        self.add("never used")
        self.conn.commit()
        entry = recall.load(self.conn, ["global"])[0]
        self.assertGreater(entry["activation"], float("-inf"))
        self.assertEqual(entry["uses"], 0)

    def test_simultaneous_traces_do_not_divide_by_zero(self):
        mid = self.add("now")
        self.use(mid, 0.0)
        self.conn.commit()
        entry = recall.load(self.conn, ["global"])[0]
        self.assertTrue(entry["activation"] < float("inf"))


class TestRenderingIsNotUsing(Base):
    """The rule that stops injected memories from reinforcing themselves."""

    def test_render_adds_no_trace(self):
        mid = self.add("do the thing", kind="preference")
        self.conn.commit()
        before = self.conn.execute(
            "SELECT COUNT(*) FROM trace WHERE memory_id = ?", (mid,)).fetchone()[0]
        for _ in range(5):
            self.assertIn("do the thing", recall.render(self.conn, "global", 40, 6000))
        after = self.conn.execute(
            "SELECT COUNT(*) FROM trace WHERE memory_id = ?", (mid,)).fetchone()[0]
        self.assertEqual(before, after)

    def test_use_adds_a_trace(self):
        mid = self.add("do the thing")
        self.conn.commit()
        with quiet():
            recall.main(["use", str(mid), "--quiet"])
        conn = recall.connect()
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM trace WHERE memory_id = ?",
                             (mid,)).fetchone()[0], 1)
        finally:
            conn.close()


class TestAnchors(Base):
    def test_matching(self):
        cases = [
            (["migrations/"], "db/migrations/001.sql", True),
            (["migrations/"], "src/main.rs", False),
            (["*.sql"], "db/migrations/001.sql", True),
            (["*.sql"], "db/schema.rs", False),
            (["src/dal/*.rs"], "src/dal/user.rs", True),
            (["Cargo.toml"], "crates/core/Cargo.toml", True),
            (["lib.rs"], "src/lib.rs", True),
        ]
        for anchors, path, expected in cases:
            with self.subTest(anchors=anchors, path=path):
                self.assertEqual(recall.matches_anchor(anchors, path), expected)

    def test_touch_reinforces_only_the_anchored_memory(self):
        anchored = self.add("about migrations", anchors="migrations/")
        other = self.add("about nothing in particular")
        self.conn.commit()
        with quiet():
            recall.main(["touch", "--file", "db/migrations/007.sql",
                         "--scope", "global", "--json"])
        conn = recall.connect()
        try:
            counts = {
                mid: conn.execute("SELECT COUNT(*) FROM trace WHERE memory_id = ?",
                                  (mid,)).fetchone()[0]
                for mid in (anchored, other)
            }
        finally:
            conn.close()
        self.assertEqual(counts[anchored], 1)
        self.assertEqual(counts[other], 0)


class TestSupersedeAndDecay(Base):
    def test_superseded_memory_leaves_the_render(self):
        old = self.add("use the builder", kind="convention")
        new = self.add("use the macros", kind="convention")
        self.conn.commit()
        with quiet():
            recall.main(["supersede", str(old), "--by", str(new)])
        block = recall.render(recall.connect(), "global", 40, 6000)
        self.assertIn("use the macros", block)
        self.assertNotIn("use the builder", block)

    def test_decay_archives_below_the_floor_but_spares_the_pinned(self):
        faded = self.add("faded")
        pinned = self.add("pinned", pinned=True)
        for mid in (faded, pinned):
            self.use(mid, 180.0)
        self.conn.execute("UPDATE memory SET created_at = ?", (time.time() - 200 * DAY,))
        self.conn.commit()
        with quiet():
            recall.main(["decay", "--grace-days", "0"])
        conn = recall.connect()
        try:
            rows = dict(conn.execute("SELECT id, archived_at IS NOT NULL FROM memory"))
        finally:
            conn.close()
        self.assertTrue(rows[faded])
        self.assertFalse(rows[pinned])

    def test_decay_never_deletes(self):
        mid = self.add("faded")
        self.use(mid, 400.0)
        self.conn.execute("UPDATE memory SET created_at = ?", (time.time() - 400 * DAY,))
        self.conn.commit()
        with quiet():
            recall.main(["decay", "--grace-days", "0"])
        conn = recall.connect()
        try:
            self.assertIsNotNone(
                conn.execute("SELECT 1 FROM memory WHERE id = ?", (mid,)).fetchone())
        finally:
            conn.close()

    def test_decay_respects_the_grace_period(self):
        mid = self.add("young but unused")
        self.use(mid, 400.0)  # activation is low, but the memory itself is new
        self.conn.commit()
        with quiet():
            recall.main(["decay"])
        conn = recall.connect()
        try:
            archived = conn.execute(
                "SELECT archived_at FROM memory WHERE id = ?", (mid,)).fetchone()[0]
        finally:
            conn.close()
        self.assertIsNone(archived)


class TestBudget(Base):
    def test_render_honours_both_caps(self):
        for i in range(200):
            self.add(f"memory number {i} " + "x" * 60)
        self.conn.commit()
        block = recall.render(self.conn, "global", 10, 6000)
        self.assertLessEqual(sum(1 for l in block.splitlines() if l.startswith("- ")), 10)

        block = recall.render(self.conn, "global", 500, 1200)
        self.assertLessEqual(len(block), 1200)
        self.assertIn("withheld", block)

    def test_a_budget_smaller_than_the_footer_yields_whole_lines_or_nothing(self):
        self.add("something", kind="preference")
        self.conn.commit()
        for cap in (0, 40, 120, 300):
            with self.subTest(cap=cap):
                block = recall.render(self.conn, "global", 40, cap)
                self.assertLessEqual(len(block), max(cap, 1))
                self.assertFalse(block.endswith("..."))

    def test_empty_store_renders_nothing(self):
        self.assertEqual(recall.render(self.conn, "global", 40, 6000), "")


class TestSplice(Base):
    def test_is_idempotent_and_preserves_the_rest(self):
        original = "# Title\n\nhand-written, keep me\n"
        once = recall.splice(original, "BLOCK\n")
        twice = recall.splice(once, "BLOCK\n")
        self.assertEqual(once, twice)
        self.assertIn("hand-written, keep me", twice)
        self.assertEqual(twice.count(recall.BEGIN), 1)

    def test_replaces_rather_than_appends(self):
        first = recall.splice("# Title\n", "OLD\n")
        second = recall.splice(first, "NEW\n")
        self.assertIn("NEW", second)
        self.assertNotIn("OLD", second)
        self.assertEqual(second.count(recall.END), 1)

    def test_an_empty_block_removes_the_managed_section(self):
        spliced = recall.splice("# Title\n\nkeep\n", "BLOCK\n")
        cleared = recall.splice(spliced, "")
        self.assertNotIn(recall.BEGIN, cleared)
        self.assertIn("keep", cleared)


class TestDirective(Base):
    """`remember:` is a directive. Nothing else in a prompt may become a memory."""

    def test_recognised_forms(self):
        for prompt in (
            "remember: always run clippy",
            "Remember that: always run clippy",
            "fix the parser. remember: always run clippy",
            "do it.\nremember: always run clippy",
            "lembrar: always run clippy",
        ):
            with self.subTest(prompt=prompt):
                m = recall.REMEMBER.search(prompt)
                self.assertIsNotNone(m)
                self.assertEqual(m.group("text").strip(), "always run clippy")

    def test_prose_is_not_a_directive(self):
        for prompt in (
            "I remember we discussed this last week",
            "please remember to be careful",
            "the user will remember nothing",
            "add a memory feature",
        ):
            with self.subTest(prompt=prompt):
                self.assertIsNone(recall.REMEMBER.search(prompt))


class TestConflicts(Base):
    def test_overlapping_memories_are_reported(self):
        self.add("prefer sqlx query macros over the builder", kind="convention")
        self.conn.commit()
        hits = recall.conflicts(
            self.conn, "global", "convention", "use the sqlx builder, not query macros")
        self.assertEqual(len(hits), 1)

    def test_unrelated_memories_are_not(self):
        self.add("prefer sqlx query macros over the builder", kind="convention")
        self.conn.commit()
        hits = recall.conflicts(
            self.conn, "global", "preference", "write commit bodies in Portuguese")
        self.assertEqual(hits, [])


class TestScope(Base):
    def test_global_memories_reach_every_project(self):
        self.add("everywhere", scope="global")
        self.add("here only", scope="/some/repo")
        self.conn.commit()
        both = {e["text"] for e in recall.load(self.conn, ["global", "/some/repo"])}
        self.assertEqual(both, {"everywhere", "here only"})
        self.assertEqual({e["text"] for e in recall.load(self.conn, ["global"])},
                         {"everywhere"})

    def test_add_refuses_a_duplicate_and_reinforces_instead(self):
        with quiet():
            recall.main(["add", "one", "line", "--kind", "fact"])
        with quiet():
            recall.main(["add", "one", "line", "--kind", "fact"])
        conn = recall.connect()
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM memory").fetchone()[0], 1)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM trace").fetchone()[0], 2)
        finally:
            conn.close()


class TestHooks(Base):
    def run_hook(self, event: str, payload: dict) -> dict:
        import sys
        stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(payload))
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                recall.main(["hook", event])
            return json.loads(out.getvalue())
        finally:
            sys.stdin = stdin

    def test_session_start_emits_the_block_as_context(self):
        self.add("do the thing", kind="preference")
        self.conn.commit()
        out = self.run_hook("session-start", {"cwd": str(HERE)})
        self.assertIn("do the thing",
                      out["hookSpecificOutput"]["additionalContext"])

    def test_session_start_on_an_empty_store_emits_no_context(self):
        out = self.run_hook("session-start", {"cwd": str(HERE)})
        self.assertNotIn("hookSpecificOutput", out)

    def test_prompt_submit_stores_only_the_directive(self):
        out = self.run_hook("prompt-submit", {
            "cwd": str(HERE),
            "prompt": "fix the parser. remember: always run clippy first",
        })
        self.assertIn("hookSpecificOutput", out)
        conn = recall.connect()
        try:
            rows = [r[0] for r in conn.execute("SELECT text FROM memory")]
        finally:
            conn.close()
        self.assertEqual(rows, ["always run clippy first"])

    def test_prompt_submit_stores_nothing_from_prose(self):
        out = self.run_hook("prompt-submit", {
            "cwd": str(HERE),
            "prompt": "I remember you said the parser was fine. please fix it anyway",
        })
        self.assertNotIn("hookSpecificOutput", out)
        conn = recall.connect()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM memory").fetchone()[0], 0)
        finally:
            conn.close()

    def test_prompt_submit_survives_a_repeated_directive(self):
        payload = {"cwd": str(HERE), "prompt": "remember: be brief"}
        self.run_hook("prompt-submit", payload)
        self.run_hook("prompt-submit", payload)
        conn = recall.connect()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM memory").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM trace").fetchone()[0], 2)
        finally:
            conn.close()

    def test_post_edit_without_a_path_is_a_no_op(self):
        out = self.run_hook("post-edit", {"cwd": str(HERE)})
        self.assertEqual(out, {"suppressOutput": True})

    def test_hooks_emit_valid_json_on_an_empty_payload(self):
        for event in ("session-start", "prompt-submit", "post-edit"):
            with self.subTest(event=event):
                self.assertIsInstance(self.run_hook(event, {}), dict)


if __name__ == "__main__":
    unittest.main()
