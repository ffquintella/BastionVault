//! The MySQL / MariaDB function table (§4.3, side-effecting functions).
//!
//! An unqualified name the server treats as a built-in never resolves to a
//! stored function (a stored function with a built-in's name must be called
//! qualified). So a name in this table, unqualified, is the built-in; any
//! other unqualified name may be a loadable (native) function or a stored
//! function of the current database, and is user code on `sql/server`.

// The table lists built-ins present in both MySQL 8.0 and MariaDB 10.6
// unless marked otherwise; a name missing from one server would let a stored
// function of that name pass as built-in there. Incompleteness costs
// usability (an unlisted built-in needs `sql_execute`), never safety.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FnClass {
    /// Reviewed built-in with no side effect beyond reading its arguments.
    Pure,
    /// Window function: the built-in only with an `OVER` clause.
    Window,
    /// `sql_admin` on `sql/server`.
    Admin,
    /// `GET_LOCK` / `RELEASE_LOCK` / `RELEASE_ALL_LOCKS`: `sql_update` on
    /// `sql/server`.
    AdvisoryLock,
    /// MariaDB `NEXTVAL(s)` / `SETVAL(s, …)`: `sql_update` on the sequence.
    SequenceWrite,
    /// MariaDB `LASTVAL(s)`: `sql_select` on the sequence.
    SequenceRead,
    /// Not in the table: user code.
    Unknown,
}

/// Server file and OS access (§4.2's always-refused row), matched on the
/// name whatever qualifies it: `LOAD_FILE`, and the `lib_mysqludf_sys`
/// loadable functions that run shell commands.
const ALWAYS_REFUSED: &[&str] = &["load_file", "sys_exec", "sys_eval", "sys_get", "sys_set", "sys_bineval"];

/// `sql_functions[]` in the server's `lex.h`: built-ins whose call must touch
/// its `(`. Written with a space or a comment before `(` (and without
/// `IGNORE_SPACE`), the name is an identifier and the call may reach a
/// stored function of the same name.
const SPACE_SENSITIVE: &[&str] = &[
    "adddate",
    "bit_and",
    "bit_or",
    "bit_xor",
    "cast",
    "count",
    "curdate",
    "curtime",
    "date_add",
    "date_sub",
    "extract",
    "group_concat",
    "json_arrayagg",
    "json_objectagg",
    "max",
    "mid",
    "min",
    "now",
    "position",
    "session_user",
    "std",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "st_collect",
    "subdate",
    "substr",
    "substring",
    "sum",
    "sysdate",
    "system_user",
    "trim",
    "variance",
    "var_pop",
    "var_samp",
];

const PURE: &[&str] = &[
    // Control flow and comparison.
    "coalesce",
    "nullif",
    "ifnull",
    "if",
    "greatest",
    "least",
    "isnull",
    "interval",
    "strcmp",
    "field",
    "find_in_set",
    "elt",
    // Mathematics.
    "abs",
    "acos",
    "asin",
    "atan",
    "atan2",
    "ceil",
    "ceiling",
    "conv",
    "cos",
    "cot",
    "crc32",
    "degrees",
    "exp",
    "floor",
    "ln",
    "log",
    "log10",
    "log2",
    "mod",
    "pi",
    "pow",
    "power",
    "radians",
    "rand",
    "round",
    "sign",
    "sin",
    "sqrt",
    "tan",
    "truncate",
    "format",
    "bit_count",
    // Strings.
    "ascii",
    "bin",
    "bit_length",
    "char",
    "char_length",
    "character_length",
    "concat",
    "concat_ws",
    "export_set",
    "from_base64",
    "hex",
    "insert",
    "instr",
    "lcase",
    "left",
    "length",
    "locate",
    "lower",
    "lpad",
    "ltrim",
    "make_set",
    "mid",
    "oct",
    "octet_length",
    "ord",
    "position",
    "quote",
    "repeat",
    "replace",
    "reverse",
    "right",
    "rpad",
    "rtrim",
    "soundex",
    "space",
    "substr",
    "substring",
    "substring_index",
    "to_base64",
    "trim",
    "ucase",
    "unhex",
    "upper",
    "weight_string",
    "regexp_replace",
    "regexp_instr",
    "regexp_substr",
    // Dates and times.
    "adddate",
    "addtime",
    "convert_tz",
    "curdate",
    "current_date",
    "current_time",
    "current_timestamp",
    "curtime",
    "date",
    "date_add",
    "date_format",
    "date_sub",
    "datediff",
    "day",
    "dayname",
    "dayofmonth",
    "dayofweek",
    "dayofyear",
    "extract",
    "from_days",
    "from_unixtime",
    "get_format",
    "hour",
    "last_day",
    "localtime",
    "localtimestamp",
    "makedate",
    "maketime",
    "microsecond",
    "minute",
    "month",
    "monthname",
    "now",
    "period_add",
    "period_diff",
    "quarter",
    "sec_to_time",
    "second",
    "str_to_date",
    "subdate",
    "subtime",
    "sysdate",
    "time",
    "time_format",
    "time_to_sec",
    "timediff",
    "timestamp",
    "timestampadd",
    "timestampdiff",
    "to_days",
    "to_seconds",
    "unix_timestamp",
    "utc_date",
    "utc_time",
    "utc_timestamp",
    "week",
    "weekday",
    "weekofyear",
    "year",
    "yearweek",
    // Aggregates.
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "count",
    "group_concat",
    "max",
    "min",
    "std",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    // Casts.
    "cast",
    "convert",
    // Session information.
    "benchmark",
    "charset",
    "coercibility",
    "collation",
    "connection_id",
    "current_user",
    "database",
    "found_rows",
    "last_insert_id",
    "row_count",
    "schema",
    "session_user",
    "system_user",
    "user",
    "version",
    // Hashes, compression, encryption with caller-supplied keys.
    "md5",
    "sha",
    "sha1",
    "sha2",
    "aes_encrypt",
    "aes_decrypt",
    "compress",
    "uncompress",
    "uncompressed_length",
    // Miscellaneous.
    "uuid",
    "uuid_short",
    "inet_aton",
    "inet_ntoa",
    "inet6_aton",
    "inet6_ntoa",
    "is_ipv4",
    "is_ipv6",
    "is_ipv4_compat",
    "is_ipv4_mapped",
    "sleep",
    "name_const",
    "values",
    "is_free_lock",
    "is_used_lock",
    // JSON.
    "json_array",
    "json_object",
    "json_quote",
    "json_contains",
    "json_contains_path",
    "json_extract",
    "json_keys",
    "json_search",
    "json_unquote",
    "json_depth",
    "json_length",
    "json_type",
    "json_valid",
    "json_array_append",
    "json_array_insert",
    "json_insert",
    "json_merge_patch",
    "json_merge_preserve",
    "json_remove",
    "json_replace",
    "json_set",
];

/// Built-ins of MySQL 8.0 that MariaDB does not have.
const PURE_MYSQL_ONLY: &[&str] = &["regexp_like", "any_value", "uuid_to_bin", "bin_to_uuid", "is_uuid"];

/// Built-ins of MariaDB 10.6 that MySQL does not have.
const PURE_MARIADB_ONLY: &[&str] = &["json_detailed", "json_compact", "json_loose"];

const WINDOW: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "nth_value",
];

const ADMIN: &[&str] =
    &["master_pos_wait", "source_pos_wait", "wait_for_executed_gtid_set", "wait_until_sql_thread_after_gtids"];

const ADVISORY_LOCKS: &[&str] = &["get_lock", "release_lock", "release_all_locks"];

pub(crate) fn always_refused(name: &str) -> bool {
    ALWAYS_REFUSED.contains(&name.to_ascii_lowercase().as_str())
}

pub(crate) fn space_sensitive(name: &str) -> bool {
    SPACE_SENSITIVE.contains(&name.to_ascii_lowercase().as_str())
}

/// The class of an unqualified function name on this server flavor.
pub(crate) fn class(name: &str, mariadb: bool) -> FnClass {
    let n = name.to_ascii_lowercase();
    let n = n.as_str();
    if PURE.contains(&n) || (!mariadb && PURE_MYSQL_ONLY.contains(&n)) || (mariadb && PURE_MARIADB_ONLY.contains(&n)) {
        FnClass::Pure
    } else if WINDOW.contains(&n) {
        FnClass::Window
    } else if ADMIN.contains(&n) {
        FnClass::Admin
    } else if ADVISORY_LOCKS.contains(&n) {
        FnClass::AdvisoryLock
    } else if mariadb && matches!(n, "nextval" | "setval") {
        FnClass::SequenceWrite
    } else if mariadb && n == "lastval" {
        FnClass::SequenceRead
    } else {
        FnClass::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(class("COUNT", false), FnClass::Pure);
        assert_eq!(class("regexp_like", false), FnClass::Pure);
        assert_eq!(class("regexp_like", true), FnClass::Unknown, "not a MariaDB built-in");
        assert_eq!(class("json_detailed", true), FnClass::Pure);
        assert_eq!(class("json_detailed", false), FnClass::Unknown);
        assert_eq!(class("row_number", false), FnClass::Window);
        assert_eq!(class("get_lock", true), FnClass::AdvisoryLock);
        assert_eq!(class("nextval", true), FnClass::SequenceWrite);
        assert_eq!(class("nextval", false), FnClass::Unknown);
        assert_eq!(class("my_func", false), FnClass::Unknown);
        assert!(always_refused("LOAD_FILE") && always_refused("sys_exec"));
        assert!(space_sensitive("Sum") && !space_sensitive("abs"));
    }
}
