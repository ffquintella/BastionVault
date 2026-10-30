//! The Oracle function and package tables (§4.2, §4.3 side-effecting
//! functions). Built-in SQL functions win over a schema function of the
//! same name when called unqualified, so the table below is trusted for
//! unqualified calls; one it does not list is user code, `sql_execute` on
//! `sql/server`. Usability, never safety, pays for an incomplete table.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FnClass {
    /// Reviewed built-in with no side effect beyond reading its arguments.
    Pure,
    /// Analytic-only: the built-in only with `OVER (…)`.
    Window,
    /// Not in the table: treated as user code.
    Unknown,
}

/// Server file, OS, network, scheduler, Java and remote access (§4.2's
/// always-refused row), matched on any unquoted word or quoted identifier
/// whatever qualifies it. Dynamic SQL can build these names at run time, so
/// the match is best effort; the database login is the backstop.
const ALWAYS_REFUSED: &[&str] = &[
    // Files.
    "utl_file",
    "bfilename",
    "loadfromfile",
    "loadblobfromfile",
    "loadclobfromfile",
    "fileopen",
    "fileclose",
    "filecloseall",
    "fileexists",
    "filegetname",
    "fileisopen",
    "writetofile",
    "dbms_xslprocessor",
    "dbms_advisor",
    "dbms_file_transfer",
    "dbms_file_group",
    "dbms_datapump",
    "dbms_backup_restore",
    "dbms_logmnr",
    "dbms_logmnr_d",
    "dbms_hprof",
    "dbms_system",
    "controlfile",
    "unplug",
    // External tables, external procedures and inline external data.
    "external",
    // Network.
    "utl_http",
    "utl_tcp",
    "utl_smtp",
    "utl_mail",
    "utl_inaddr",
    "utl_dbws",
    "httpuritype",
    "dburitype",
    "xdburitype",
    "dbms_ldap",
    "dbms_network_acl_admin",
    "dbms_hs_passthrough",
    "dbms_debug_jdwp",
    "dbms_aqelm",
    "dbms_xdb",
    "dbms_xdb_config",
    "dbms_xdb_repos",
    "dbms_epg",
    // OS processes and jobs (a job can run an executable), pipes, Java.
    "dbms_scheduler",
    "dbms_isched",
    "dbms_job",
    "dbms_ijob",
    "dbms_pipe",
    "dbms_credential",
    "dbms_java",
    "dbms_java_test",
    "loadjava",
    // SQL run as another user.
    "dbms_sys_sql",
];

/// Prefixes refused like the words above (`DBMS_CLOUD`, `DBMS_CLOUD_AI`, …).
const ALWAYS_REFUSED_PREFIXES: &[&str] = &["dbms_cloud"];

/// Built-ins reviewed as pure, lower case (Oracle 19c SQL Language
/// Reference, "Functions"). `TO_CLOB` / `TO_BLOB` and `XMLTYPE` are left
/// out: given a `BFILE` they read a server file.
const PURE: &[&str] = &[
    // Numeric.
    "abs",
    "acos",
    "asin",
    "atan",
    "atan2",
    "bitand",
    "ceil",
    "cos",
    "cosh",
    "exp",
    "floor",
    "ln",
    "log",
    "mod",
    "nanvl",
    "power",
    "remainder",
    "round",
    "sign",
    "sin",
    "sinh",
    "sqrt",
    "tan",
    "tanh",
    "trunc",
    "width_bucket",
    // Character.
    "ascii",
    "asciistr",
    "chr",
    "concat",
    "initcap",
    "instr",
    "instrb",
    "instrc",
    "instr2",
    "instr4",
    "length",
    "lengthb",
    "lengthc",
    "length2",
    "length4",
    "lower",
    "lpad",
    "ltrim",
    "nchr",
    "nls_initcap",
    "nls_lower",
    "nls_upper",
    "nlssort",
    "nls_charset_decl_len",
    "nls_charset_id",
    "nls_charset_name",
    "regexp_count",
    "regexp_instr",
    "regexp_like",
    "regexp_replace",
    "regexp_substr",
    "replace",
    "rpad",
    "rtrim",
    "soundex",
    "substr",
    "substrb",
    "substrc",
    "substr2",
    "substr4",
    "translate",
    "trim",
    "unistr",
    "upper",
    // Date and time.
    "add_months",
    "current_date",
    "current_timestamp",
    "dbtimezone",
    "extract",
    "from_tz",
    "last_day",
    "localtimestamp",
    "months_between",
    "new_time",
    "next_day",
    "numtodsinterval",
    "numtoyminterval",
    "sessiontimezone",
    "sys_extract_utc",
    "sysdate",
    "systimestamp",
    "to_dsinterval",
    "to_yminterval",
    "tz_offset",
    // Conversion.
    "bin_to_num",
    "cast",
    "chartorowid",
    "compose",
    "convert",
    "decompose",
    "hextoraw",
    "rawtohex",
    "rawtonhex",
    "rowidtochar",
    "rowidtonchar",
    "scn_to_timestamp",
    "timestamp_to_scn",
    "to_binary_double",
    "to_binary_float",
    "to_char",
    "to_date",
    "to_multi_byte",
    "to_nchar",
    "to_number",
    "to_single_byte",
    "to_timestamp",
    "to_timestamp_tz",
    "validate_conversion",
    // Comparison, NULL handling, encoding.
    "coalesce",
    "decode",
    "greatest",
    "least",
    "lnnvl",
    "nullif",
    "nvl",
    "nvl2",
    "dump",
    "ora_hash",
    "standard_hash",
    "vsize",
    "empty_blob",
    "empty_clob",
    "cardinality",
    // Environment (read only).
    "sys_context",
    "sys_guid",
    "uid",
    "user",
    "userenv",
    // Aggregates (also analytic with OVER).
    "any_value",
    "approx_count",
    "approx_count_distinct",
    "approx_median",
    "approx_percentile",
    "avg",
    "collect",
    "corr",
    "count",
    "covar_pop",
    "covar_samp",
    "cume_dist",
    "dense_rank",
    "group_id",
    "grouping",
    "grouping_id",
    "listagg",
    "max",
    "median",
    "min",
    "percent_rank",
    "percentile_cont",
    "percentile_disc",
    "rank",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "stats_mode",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    // JSON.
    "json_array",
    "json_arrayagg",
    "json_exists",
    "json_mergepatch",
    "json_object",
    "json_objectagg",
    "json_query",
    "json_scalar",
    "json_serialize",
    "json_value",
    // XML built from values (no query, no URI, no file).
    "existsnode",
    "extractvalue",
    "xmlagg",
    "xmlcast",
    "xmlcdata",
    "xmlcomment",
    "xmlconcat",
    "xmlelement",
    "xmlforest",
    "xmlparse",
    "xmlpi",
    "xmlroot",
    "xmlserialize",
];

/// Analytic-only functions: built-ins only with `OVER (…)`.
const WINDOW: &[&str] =
    &["row_number", "ntile", "lag", "lead", "first_value", "last_value", "nth_value", "ratio_to_report"];

/// Names that read without parentheses: pseudo-columns and the built-ins
/// Oracle calls bare. Anything else bare, where no table is in scope, is a
/// parameterless function call.
const BARE: &[&str] = &[
    "sysdate",
    "systimestamp",
    "current_date",
    "current_timestamp",
    "localtimestamp",
    "dbtimezone",
    "sessiontimezone",
    "user",
    "uid",
    "rownum",
    "rowid",
    "level",
    "ora_rowscn",
    "connect_by_isleaf",
    "connect_by_iscycle",
    "column_value",
    "object_value",
    "object_id",
    "dummy",
    "null",
    "true",
    "false",
    "default",
];

/// Functions that run a query held in a string (`ora:view` in XQuery, the
/// XML generators): opaque `sql_execute` on `sql/server`, as dynamic SQL.
const DYNAMIC_FUNCTIONS: &[&str] = &["xmlquery", "xmlexists", "xmltable", "sys_xmlgen", "xmltransform"];

/// Supplied packages that run SQL built at run time (§4.2 dynamic SQL).
const DYNAMIC_PACKAGES: &[&str] = &["dbms_sql", "dbms_xmlgen", "dbms_xmlquery", "dbms_xmlstore"];

/// Supplied packages reviewed as harmless, reached through their `PUBLIC`
/// synonym and owned by `SYS`. `None`: every function; `Some`: only those.
const HARMLESS_PACKAGES: &[(&str, Option<&[&str]>)] = &[
    ("dbms_random", None),
    ("dbms_output", None),
    ("dbms_lock", None),
    ("dbms_crypto", None),
    ("dbms_application_info", None),
    ("dbms_metadata", None),
    // Its file functions are refused by name above.
    ("dbms_lob", None),
    (
        "dbms_utility",
        Some(&[
            "get_time",
            "get_cpu_time",
            "get_hash_value",
            "format_error_backtrace",
            "format_error_stack",
            "format_call_stack",
            "current_instance",
            "get_endianness",
            "port_string",
        ]),
    ),
];

/// Whether a word (lower case) names server file, OS, network or remote
/// access.
pub(crate) fn always_refused(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    ALWAYS_REFUSED.contains(&w.as_str()) || ALWAYS_REFUSED_PREFIXES.iter().any(|p| w.starts_with(p))
}

/// The class of an unqualified function name (lower case).
pub(crate) fn class(name: &str) -> FnClass {
    if PURE.contains(&name) {
        FnClass::Pure
    } else if WINDOW.contains(&name) {
        FnClass::Window
    } else {
        FnClass::Unknown
    }
}

pub(crate) fn bare_builtin(name: &str) -> bool {
    BARE.contains(&name)
}

pub(crate) fn dynamic_function(name: &str) -> bool {
    DYNAMIC_FUNCTIONS.contains(&name)
}

pub(crate) fn dynamic_package(name: &str) -> bool {
    DYNAMIC_PACKAGES.contains(&name)
}

/// Whether `package.function` (lower case) is a reviewed supplied call.
pub(crate) fn harmless(package: &str, function: &str) -> bool {
    HARMLESS_PACKAGES.iter().any(|(p, only)| *p == package && only.is_none_or(|fs| fs.contains(&function)))
}

/// A supplied-package prefix this table does not review: `Unknown`.
pub(crate) fn supplied_package(name: &str) -> bool {
    ["dbms_", "utl_", "owa_"].iter().any(|p| name.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables() {
        assert_eq!(class("nvl"), FnClass::Pure);
        assert_eq!(class("row_number"), FnClass::Window);
        assert_eq!(class("my_func"), FnClass::Unknown);
        for w in ["UTL_FILE", "utl_http", "BFILENAME", "dbms_scheduler", "DBMS_CLOUD_AI", "external", "loadjava"] {
            assert!(always_refused(w), "{w}");
        }
        assert!(!always_refused("dbms_sql") && !always_refused("dbms_random") && !always_refused("utl_raw"));
        assert!(harmless("dbms_random", "value") && harmless("dbms_utility", "get_time"));
        assert!(!harmless("dbms_utility", "exec_ddl_statement") && !harmless("dbms_session", "set_role"));
        assert!(dynamic_package("dbms_sql") && dynamic_function("xmlquery"));
        assert!(supplied_package("owa_util") && !supplied_package("hr_pkg"));
        for list in [PURE, WINDOW, BARE, ALWAYS_REFUSED] {
            assert!(list.iter().all(|w| w.chars().all(|c| !c.is_ascii_uppercase())));
        }
    }
}
