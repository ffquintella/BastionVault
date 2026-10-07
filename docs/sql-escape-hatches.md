# SQL escape hatches

Every call to `bv_sql_guard::Sql::escape_hatch_reviewed` outside the guard crate
must be listed here with the file, a justification, a reviewer and a date.
`scripts/check-sql-guard.sh` fails CI if a call site's file is not mentioned.

The target is an empty table. Prefer `sql!("...")` with `SqlIdent` holes.

| File | Justification | Reviewer | Date |
|---|---|---|---|
| _none_ | | | |
