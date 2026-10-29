//! The classifier's public vocabulary (features/sql-browser.md §4.1).
//!
//! [`SqlCapability`] mirrors `bv_kernel_api::policy::sql::SqlCapability` by
//! name and spelling. It is a copy, not an import, so this crate never depends
//! on a kernel tier; the `names_match_the_policy_vocabulary` test pins the
//! spellings.

use std::fmt;
use std::ops::Range;

/// One of the eleven SQL capabilities (features/sql-browser.md §3.1).
///
/// The classifier only ever *requires* the first nine. `Export` and `Script`
/// belong to endpoints (§8), not to statements, and are listed so the plugin
/// can map this type onto the kernel's one to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SqlCapability {
    Select,
    Insert,
    Update,
    Delete,
    Alter,
    Create,
    Drop,
    Execute,
    Admin,
    Export,
    Script,
}

impl SqlCapability {
    /// Every SQL capability, in policy-language order.
    pub const ALL: [SqlCapability; 11] = [
        SqlCapability::Select,
        SqlCapability::Insert,
        SqlCapability::Update,
        SqlCapability::Delete,
        SqlCapability::Alter,
        SqlCapability::Create,
        SqlCapability::Drop,
        SqlCapability::Execute,
        SqlCapability::Admin,
        SqlCapability::Export,
        SqlCapability::Script,
    ];

    /// The name as policies and shares spell it (`sql_select`, …).
    pub const fn as_str(self) -> &'static str {
        match self {
            SqlCapability::Select => "sql_select",
            SqlCapability::Insert => "sql_insert",
            SqlCapability::Update => "sql_update",
            SqlCapability::Delete => "sql_delete",
            SqlCapability::Alter => "sql_alter",
            SqlCapability::Create => "sql_create",
            SqlCapability::Drop => "sql_drop",
            SqlCapability::Execute => "sql_execute",
            SqlCapability::Admin => "sql_admin",
            SqlCapability::Export => "sql_export",
            SqlCapability::Script => "sql_script",
        }
    }

    /// The capability spelled exactly `s`, or `None`. Case-sensitive.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl fmt::Display for SqlCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of database object a name refers to. It tells the caller which
/// catalog resolves an unqualified name (§4.4): `pg_class` for relations,
/// sequences and indexes, `pg_proc` for routines, `pg_type` for types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjectKind {
    /// Table, view, materialized view or foreign table.
    Relation,
    Sequence,
    Index,
    /// Function or procedure. Overloads share one path: a policy addresses
    /// the name, not the signature.
    Routine,
    /// Type or domain.
    Type,
    Collation,
}

/// A referenced object, every name already in the engine's canonical case
/// (PostgreSQL: unquoted names folded to lower case, quoted names kept, both
/// truncated to `max_identifier_length` bytes, as the server does).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectRef {
    pub kind: ObjectKind,
    /// The database: `current_database()` unless the statement names one.
    pub catalog: String,
    /// `Some` when written, or when the classifier knows it (a new
    /// unqualified object goes to [`NameContext::current_schema`], a
    /// temporary one to `pg_temp`). `None` for an unqualified reference to
    /// an existing object: the caller resolves it through the catalog with
    /// the session's search path (§4.4). A name that does not resolve to
    /// exactly one schema is checked as unaddressable (fail closed, §3.2).
    pub schema: Option<String>,
    pub name: String,
}

/// What a requirement is about (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SqlTarget {
    /// `…/sql/server`: statements that reference no object, server-level
    /// administration, and effects on objects the statement does not name
    /// (for example `TRUNCATE … CASCADE`).
    Server,
    /// `…/sql/objects/<catalog>/<schema>/<object>` once resolved.
    Object(ObjectRef),
}

/// What a statement is, for display, audit and the plugin's bookkeeping. It
/// never decides authorization; [`ClassifiedStatement::required`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatementKind {
    Select,
    SelectInto,
    Values,
    Explain,
    ExplainAnalyze,
    Show,
    Insert,
    Update,
    Delete,
    Merge,
    CopyTo,
    CopyFrom,
    Lock,
    CreateTable,
    CreateView,
    CreateIndex,
    CreateSequence,
    CreateSchema,
    CreateRoutine,
    CreateTrigger,
    CreateType,
    CreatePolicy,
    Alter,
    Comment,
    Drop,
    Truncate,
    /// `VACUUM`, `ANALYZE`, `REINDEX`, `CLUSTER`, `REFRESH MATERIALIZED VIEW`.
    Maintenance,
    Call,
    /// `DO`: an anonymous code block.
    Do,
    Prepare,
    Execute,
    Deallocate,
    DeclareCursor,
    FetchCursor,
    CloseCursor,
    Listen,
    Notify,
    /// Grants, roles, databases, extensions, server configuration, two-phase
    /// commit and the other `sql_admin` statements.
    Admin,
    TxBegin,
    TxCommit,
    TxRollback,
    TxSavepoint,
    TxReleaseSavepoint,
    /// `SET` / `RESET` / `DISCARD` of a session setting. The caller re-reads
    /// the search path and current schema after one runs (§4.4).
    SetSession,
}

/// One statement of the input, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedStatement {
    /// Byte range in the input, without the terminating `;` and without
    /// leading or trailing comments and whitespace. The caller executes
    /// exactly `&text[span]`, one span per protocol round trip, and never
    /// the original multi-statement text (§4.3).
    pub span: Range<usize>,
    pub kind: StatementKind,
    /// Every privilege the statement uses, deduplicated and sorted. Never
    /// empty unless [`Self::tx_control`] is set.
    pub required: Vec<(SqlCapability, SqlTarget)>,
    /// The effect is not statically known (`CALL`, `DO`, `EXECUTE`, dynamic
    /// SQL, user functions outside a database-enforced read-only session).
    pub opaque: bool,
    /// `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`: needs only an
    /// open session and is not counted as a statement by `execute` (§8.2).
    pub tx_control: bool,
}

/// Whether a refused statement may still run as `unclassified` (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Unparseable or unknown. A caller holding `sql_admin` may run the span
    /// as `unclassified`, audited and subject to step-up. Only returned with
    /// a span the engine-faithful lexer established.
    Unknown,
    /// Never runs: server file and OS access, changes to the lexer or the
    /// read-only guard, and anything where the statement boundaries are in
    /// doubt. `sql_admin` does not unlock it.
    Never,
}

/// Why a statement, or the whole input, was not classified. It carries no
/// statement text, which may hold secrets or personal data, so it is safe to
/// log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// The lexer settings are for another dialect.
    DialectMismatch,
    /// The [`NameContext`] is unusable (empty catalog, bad identifier length).
    InvalidContext,
    InputTooLarge,
    TooManyStatements,
    NestingTooDeep,
    /// A NUL byte anywhere, or a control character outside a literal.
    ControlCharacter,
    /// A character outside a literal that the server's lexer would reject or
    /// read differently from the parser: `\`, non-alphanumeric non-ASCII,
    /// or trailing junk after a number.
    InvalidCharacter,
    UnterminatedLiteral,
    /// The engine-faithful lexer and the parser's tokenizer disagree on
    /// where a string, quoted identifier or comment starts or ends.
    LexerDisagreement,
    /// The parser found more or fewer than one statement in a span the lexer
    /// delimited.
    NotOneStatement,
    /// `U&'…'` / `U&"…"`: the escapes cannot be decoded the way the server
    /// does, so names and literals inside them cannot be trusted.
    UnicodeEscape,
    /// `standard_conforming_strings` is off and a plain string literal holds
    /// a backslash, which the parser cannot read the way the server does.
    BackslashInPlainString,
    /// String literals continued across a newline (`'a'` newline `'b'`).
    StringContinuation,
    ParseFailed,
    UnsupportedStatement,
    UnsupportedConstruct,
    /// No canonical object reference: too many name parts, a sequence chosen
    /// at run time, a case-ambiguous name, or a new unqualified object with
    /// no schema selected.
    UnresolvableName,
    /// Server file or OS access, always refused in v1 (§4.2).
    ServerFileOrOsAccess,
    /// Changes a lexer-affecting setting (§4.3).
    LexerSettingChange,
    /// Changes or resets the read-only transaction guard (§5.3).
    ReadOnlyGuardChange,
    /// Internal invariant: a non-transaction-control statement ended up with
    /// no requirement. Refused rather than allowed.
    EmptyRequirementSet,
    /// An unquoted PostgreSQL reserved keyword where the parser put an object
    /// name (`DELETE FROM ONLY t` read as table `only`): the parser and the
    /// server read the statement differently.
    ReservedWordAsName,
    /// The classifier itself failed (a parser panic, no thread to run on).
    InternalError,
}

impl Reason {
    /// The refusal class of this reason.
    pub fn refusal(self) -> Refusal {
        match self {
            Reason::UnicodeEscape
            | Reason::BackslashInPlainString
            | Reason::StringContinuation
            | Reason::ParseFailed
            | Reason::UnsupportedStatement
            | Reason::UnsupportedConstruct
            | Reason::UnresolvableName
            | Reason::ReservedWordAsName => Refusal::Unknown,
            Reason::DialectMismatch
            | Reason::InvalidContext
            | Reason::InputTooLarge
            | Reason::TooManyStatements
            | Reason::NestingTooDeep
            | Reason::ControlCharacter
            | Reason::InvalidCharacter
            | Reason::UnterminatedLiteral
            | Reason::LexerDisagreement
            | Reason::NotOneStatement
            | Reason::ServerFileOrOsAccess
            | Reason::LexerSettingChange
            | Reason::ReadOnlyGuardChange
            | Reason::EmptyRequirementSet
            | Reason::InternalError => Refusal::Never,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::DialectMismatch => "lexer settings do not match the dialect",
            Reason::InvalidContext => "invalid name context",
            Reason::InputTooLarge => "input too large",
            Reason::TooManyStatements => "too many statements",
            Reason::NestingTooDeep => "nesting too deep",
            Reason::ControlCharacter => "control character",
            Reason::InvalidCharacter => "invalid character outside a literal",
            Reason::UnterminatedLiteral => "unterminated literal or comment",
            Reason::LexerDisagreement => "lexer and parser disagree on literal boundaries",
            Reason::NotOneStatement => "statement boundaries disagree",
            Reason::UnicodeEscape => "unicode-escaped literal or identifier",
            Reason::BackslashInPlainString => "backslash in a string with standard_conforming_strings off",
            Reason::StringContinuation => "string literal continued across lines",
            Reason::ParseFailed => "statement could not be parsed",
            Reason::UnsupportedStatement => "statement type is not classified",
            Reason::UnsupportedConstruct => "construct is not classified",
            Reason::UnresolvableName => "name cannot be resolved",
            Reason::ServerFileOrOsAccess => "server file or OS access is always refused",
            Reason::LexerSettingChange => "changes a lexer-affecting setting",
            Reason::ReadOnlyGuardChange => "changes the read-only guard",
            Reason::EmptyRequirementSet => "no requirement could be derived",
            Reason::ReservedWordAsName => "a reserved keyword was parsed as an object name",
            Reason::InternalError => "the classifier failed internally",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused statement, or refused input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclassifiable {
    /// Zero-based index of the statement, when the input could be split.
    pub statement_index: Option<usize>,
    /// The statement's byte range, when the lexer established it.
    pub span: Option<Range<usize>>,
    pub reason: Reason,
    pub refusal: Refusal,
}

impl Unclassifiable {
    /// The whole input. Without a span nothing can run, whatever the reason.
    pub(crate) fn whole(reason: Reason) -> Self {
        Self { statement_index: None, span: None, reason, refusal: Refusal::Never }
    }

    pub(crate) fn at(index: usize, span: Range<usize>, reason: Reason) -> Self {
        Self { statement_index: Some(index), span: Some(span), reason, refusal: reason.refusal() }
    }

    pub(crate) fn never(index: usize, span: Range<usize>, reason: Reason) -> Self {
        Self { statement_index: Some(index), span: Some(span), reason, refusal: Refusal::Never }
    }
}

impl fmt::Display for Unclassifiable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.statement_index, &self.span) {
            (Some(i), Some(s)) => write!(f, "statement {} (bytes {}..{}): {}", i + 1, s.start, s.end, self.reason),
            _ => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for Unclassifiable {}

/// The SQL dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dialect {
    PostgreSql,
}

/// The session's lexer-affecting settings, read by the caller at session
/// start (§4.3). Statements that change one are refused, so they stay valid
/// for the session, provided the caller also watches the server's reports of
/// them (PostgreSQL `ParameterStatus`) and stops when one changes anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LexerSettings {
    PostgreSql {
        /// `standard_conforming_strings`. When off, `'…'` strings treat a
        /// backslash as an escape character.
        standard_conforming_strings: bool,
    },
}

/// Session state that decides what a name means (§4.4) and whether user
/// functions are confined by the database (§4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameContext {
    /// `current_database()`. Must not be empty.
    pub current_catalog: String,
    /// `current_schema()`: where a new unqualified object is created. `None`
    /// when no schema on the search path exists; creating an unqualified
    /// object is then refused, as the server would refuse it.
    pub current_schema: Option<String>,
    /// `current_schemas(true)`: the effective search path, implicit schemas
    /// included, in order. An unqualified function or operator is trusted as
    /// a built-in only when `pg_catalog` comes first (temporary schemas are
    /// skipped; functions are never looked up there). Otherwise a user schema
    /// could shadow it, and every unqualified call counts as user code.
    pub search_path: Vec<String>,
    /// `max_identifier_length` (PostgreSQL default 63). Longer identifiers
    /// are truncated, as the server truncates them.
    pub max_identifier_length: usize,
    /// The session is read-only *as enforced by the database* (§5.3). User
    /// functions then need `sql_select` on the function, not `sql_execute`.
    pub database_read_only: bool,
}

impl NameContext {
    /// A PostgreSQL context with the default identifier length, not read-only.
    pub fn postgres(
        current_catalog: impl Into<String>,
        current_schema: Option<String>,
        search_path: Vec<String>,
    ) -> Self {
        Self {
            current_catalog: current_catalog.into(),
            current_schema,
            search_path,
            max_identifier_length: 63,
            database_read_only: false,
        }
    }
}
