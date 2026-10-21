#!/usr/bin/env python3
"""PreToolUse reminder: query the graphify graph before grepping the tree.

AGENTS.md §1 ("Looking up references") orders lookups as memory -> graph ->
source. This hook only adds context; it never blocks the tool call.
"""
import json
import os
import re
import sys

GREP_WORD = re.compile(r"(^|[\s;&|(])(grep|rg)(\s|$)")

NUDGE = (
    "graphify-out/graph.json exists. AGENTS.md §1 asks to query the graph "
    "before grepping: `graphify query \"<question>\"`, `graphify explain \"X\"`, "
    "`graphify affected \"X\" --depth 1` or `graphify path \"A\" \"B\"`. Open only "
    "the `src=... loc=L...` ranges it returns, then confirm with a targeted rg. "
    "If the question is about a spec or design doc, read ROADMAP.md's ## Specs "
    "table and features/*.md first."
)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or "."
    if not os.path.isfile(os.path.join(project, "graphify-out", "graph.json")):
        return 0

    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    if tool == "Grep":
        triggered = True
    elif tool == "Bash":
        triggered = bool(GREP_WORD.search(tool_input.get("command", "")))
    else:
        triggered = False
    if not triggered:
        return 0

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": NUDGE,
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
