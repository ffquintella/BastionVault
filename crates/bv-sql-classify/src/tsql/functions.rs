//! The T-SQL function and procedure tables (§4.2, §4.3 side-effecting
//! functions). A user-defined scalar function must be called with its
//! schema, so an unqualified scalar call is a built-in; one this table does
//! not list still needs `sql_execute` on `sql/server` (usability, never
//! safety, pays for an incomplete table).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FnClass {
    /// Reviewed built-in with no side effect beyond reading its arguments.
    Pure,
    /// Window function: the built-in only with an `OVER` clause.
    Window,
    /// Not in the table: an unlisted built-in, treated as user code.
    Unknown,
}

/// Server file, OS, network and remote-server access (§4.2's always-refused
/// row), matched on any unquoted word whatever qualifies it. The extended
/// stored procedures (`xp_*`) and OLE automation (`sp_OA*`) match by prefix.
const ALWAYS_REFUSED: &[&str] = &[
    // Remote rowsets and linked servers.
    "openrowset",
    "opendatasource",
    "openquery",
    "sp_addlinkedserver",
    "sp_addlinkedsrvlogin",
    "sp_serveroption",
    // Files: bulk load, backups, dumps, attach / detach, audit and trace files.
    "bulk",
    "backup",
    "restore",
    "dump",
    "load",
    "sp_attach_db",
    "sp_attach_single_file_db",
    "sp_detach_db",
    "fn_get_audit_file",
    "fn_xe_file_target_read_file",
    "fn_trace_gettable",
    "fn_dump_dblog",
    "sp_makewebtask",
    // OS code and processes: extended procedures, external scripts, agent
    // jobs (a job step can run a shell command), CLR and external objects.
    "sp_execute_external_script",
    "sp_addextendedproc",
    "addextendedproc",
    "sp_add_job",
    "sp_add_jobstep",
    "sp_update_jobstep",
    "sp_start_job",
    // `CREATE EXTERNAL …`, `EXTERNAL NAME` (CLR); `external` is reserved,
    // so it is never a plain name. `ASSEMBLY` is matched with its verb.
    "external",
    // Network egress.
    "sp_send_dbmail",
    "sp_invoke_external_rest_endpoint",
];

/// Built-ins reviewed as pure, lower case.
const PURE: &[&str] = &[
    // Logical and comparison.
    "coalesce",
    "nullif",
    "isnull",
    "iif",
    "choose",
    "greatest",
    "least",
    // Conversion.
    "cast",
    "convert",
    "try_cast",
    "try_convert",
    "parse",
    "try_parse",
    // Mathematics.
    "abs",
    "acos",
    "asin",
    "atan",
    "atn2",
    "ceiling",
    "cos",
    "cot",
    "degrees",
    "exp",
    "floor",
    "log",
    "log10",
    "pi",
    "power",
    "radians",
    "rand",
    "round",
    "sign",
    "sin",
    "sqrt",
    "square",
    "tan",
    // Strings.
    "ascii",
    "char",
    "charindex",
    "concat",
    "concat_ws",
    "difference",
    "format",
    "left",
    "len",
    "lower",
    "ltrim",
    "nchar",
    "patindex",
    "quotename",
    "replace",
    "replicate",
    "reverse",
    "right",
    "rtrim",
    "soundex",
    "space",
    "str",
    "string_escape",
    "stuff",
    "substring",
    "translate",
    "trim",
    "unicode",
    "upper",
    "datalength",
    // Dates and times.
    "current_timestamp",
    "dateadd",
    "datediff",
    "datediff_big",
    "datefromparts",
    "datename",
    "datepart",
    "datetime2fromparts",
    "datetimefromparts",
    "datetimeoffsetfromparts",
    "smalldatetimefromparts",
    "timefromparts",
    "date_bucket",
    "datetrunc",
    "day",
    "eomonth",
    "getdate",
    "getutcdate",
    "isdate",
    "month",
    "switchoffset",
    "sysdatetime",
    "sysdatetimeoffset",
    "sysutcdatetime",
    "todatetimeoffset",
    "year",
    // Aggregates.
    "approx_count_distinct",
    "avg",
    "checksum_agg",
    "count",
    "count_big",
    "grouping",
    "grouping_id",
    "max",
    "min",
    "stdev",
    "stdevp",
    "string_agg",
    "sum",
    "var",
    "varp",
    // JSON.
    "isjson",
    "json_array",
    "json_modify",
    "json_object",
    "json_query",
    "json_value",
    // Hashes and the like.
    "binary_checksum",
    "checksum",
    "compress",
    "decompress",
    "crypt_gen_random",
    "hashbytes",
    "newid",
    "isnumeric",
    // Session and metadata, read only.
    "app_name",
    "col_length",
    "col_name",
    "columnproperty",
    "connectionproperty",
    "context_info",
    "current_user",
    "session_user",
    "system_user",
    "user",
    "current_request_id",
    "current_transaction_id",
    "databasepropertyex",
    "db_id",
    "db_name",
    "error_line",
    "error_message",
    "error_number",
    "error_procedure",
    "error_severity",
    "error_state",
    "has_perms_by_name",
    "host_id",
    "host_name",
    "ident_current",
    "ident_incr",
    "ident_seed",
    "indexproperty",
    "is_member",
    "is_rolemember",
    "is_srvrolemember",
    "object_definition",
    "object_id",
    "object_name",
    "object_schema_name",
    "objectproperty",
    "objectpropertyex",
    "original_login",
    "schema_id",
    "schema_name",
    "scope_identity",
    "serverproperty",
    "session_context",
    "sessionproperty",
    "suser_id",
    "suser_name",
    "suser_sid",
    "suser_sname",
    "type_id",
    "type_name",
    "user_id",
    "user_name",
    "xact_state",
];

const WINDOW: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "cume_dist",
    "percent_rank",
    "percentile_cont",
    "percentile_disc",
];

/// Built-in table-valued functions reviewed as pure.
const PURE_TABLE: &[&str] = &["string_split", "openjson", "generate_series"];

/// Whether an unquoted word names server file, OS, network or remote access.
pub(crate) fn always_refused(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    ALWAYS_REFUSED.contains(&w.as_str()) || w.starts_with("xp_") || w.starts_with("sp_oa")
}

/// The class of an unqualified scalar function name.
pub(crate) fn class(name: &str) -> FnClass {
    let n = name.to_ascii_lowercase();
    if PURE.contains(&n.as_str()) {
        FnClass::Pure
    } else if WINDOW.contains(&n.as_str()) {
        FnClass::Window
    } else {
        FnClass::Unknown
    }
}

pub(crate) fn pure_table_function(name: &str) -> bool {
    PURE_TABLE.contains(&name.to_ascii_lowercase().as_str())
}

/// A system procedure name: `sp_…` resolves to the `sys` schema before the
/// current database, so an unqualified one is server code, not a user
/// routine.
pub(crate) fn system_procedure(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("sp_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(class("GETDATE"), FnClass::Pure);
        assert_eq!(class("row_number"), FnClass::Window);
        assert_eq!(class("my_func"), FnClass::Unknown);
        for w in ["xp_cmdshell", "XP_DIRTREE", "sp_OACreate", "OPENROWSET", "bulk", "sp_send_dbmail"] {
            assert!(always_refused(w), "{w}");
        }
        assert!(!always_refused("sp_executesql") && !always_refused("openjson"));
        assert!(system_procedure("SP_who") && !system_procedure("usp_x"));
        assert!(pure_table_function("STRING_SPLIT"));
    }
}
