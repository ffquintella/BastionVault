#!/usr/bin/env bash
#
# Dependency-free half of the SQL gate (see .semgrep/sql-guard.yml for the
# AST-ish half). Fails if a SQL verb is spliced into a `format!` anywhere in
# production source, or if `Sql::escape_hatch_reviewed` is called anywhere that
# docs/sql-escape-hatches.md does not account for.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# DoD from roadmaps/formal-verification-and-type-driven-security.md § Phase 2.
if grep -rnE 'format!\(\s*"\s*(SELECT|INSERT|DELETE|UPDATE|CREATE|DROP|ALTER|TRUNCATE)\b' \
     --include='*.rs' src crates gui/src-tauri/src 2>/dev/null; then
  echo "error: SQL statement built with format! — use bv_sql_guard::sql!" >&2
  fail=1
fi

# Every escape-hatch call site (outside the defining crate) must be listed.
sites=$(grep -rn 'escape_hatch_reviewed(' --include='*.rs' src crates gui/src-tauri/src 2>/dev/null \
          | grep -v '^crates/bv-sql-guard/' || true)
if [ -n "$sites" ]; then
  while IFS= read -r line; do
    file=${line%%:*}
    if ! grep -qF "$file" docs/sql-escape-hatches.md; then
      echo "error: escape hatch in $file is not recorded in docs/sql-escape-hatches.md" >&2
      fail=1
    fi
  done <<< "$sites"
fi

exit $fail
