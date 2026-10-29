//! Statement → required privileges, PostgreSQL (§4.2, §4.3).
//!
//! The statement table decides each statement's own targets; a full AST walk
//! then visits every node, so a data-modifying CTE, a subquery or a function
//! call anywhere is classified too. Unknown statements, clauses, table
//! factors and expressions refuse; nothing defaults to `sql_select`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;

use sqlparser::ast::{
    AccessExpr, AlterTableOperation, BinaryOperator, CascadeOption, ColumnOption, CommentObject, CopySource,
    CopyTarget, CreateFunctionBody, DataType, DeclareType, DescribeAlias, DiscardObject, DropBehavior, Expr, FromTable,
    Function, FunctionArg, FunctionArgExpr, FunctionArguments, MergeAction, ObjectName, ObjectType, OnConflictAction,
    OnInsert, Query, ReferentialAction, Reset, Select, Set, SetExpr, Statement, TableConstraint, TableFactor,
    TableObject, TransactionAccessMode, TransactionMode, Value, Visit, Visitor,
};

use super::functions::{self, FnClass};
use super::names::Names;
use super::settings;
use crate::model::{ObjectKind, ObjectRef, Reason, SqlCapability as Cap, SqlTarget, StatementKind as Kind};

pub(crate) type Requirements = BTreeSet<(Cap, SqlTarget)>;

/// The classification of one statement, before the span is attached.
#[derive(Debug)]
pub(crate) struct Analysis {
    pub kind: Kind,
    pub required: Requirements,
    pub opaque: bool,
    pub tx_control: bool,
}

impl Analysis {
    pub fn new(kind: Kind) -> Self {
        Self { kind, required: BTreeSet::new(), opaque: false, tx_control: false }
    }

    pub fn with(kind: Kind, cap: Cap, target: SqlTarget) -> Self {
        let mut a = Self::new(kind);
        a.required.insert((cap, target));
        a
    }
}

type Flow = ControlFlow<Reason>;

fn brk<T>(r: Reason) -> ControlFlow<Reason, T> {
    ControlFlow::Break(r)
}

fn addr<T>(t: &T) -> usize {
    t as *const T as usize
}

/// Untrusted procedural languages and C: a function in one is server OS
/// access (§4.2, always refused).
fn language_is_untrusted(lang: &str) -> bool {
    matches!(
        lang,
        "c" | "internal" | "plsh" | "plr" | "javau" | "plperlu" | "pltclu" | "plpythonu" | "plpython2u" | "plpython3u"
    ) || (lang.starts_with("pl") && lang.ends_with('u'))
}

fn language_is_trusted(lang: &str) -> bool {
    matches!(lang, "sql" | "plpgsql" | "plperl" | "pltcl" | "pllua" | "plv8" | "plrust" | "java")
}

/// `Ok` for a trusted language, `ServerFileOrOsAccess` for an untrusted one,
/// `UnsupportedConstruct` for one the table does not know.
pub(crate) fn check_language(lang: &str) -> Result<(), Reason> {
    let lang = lang.to_ascii_lowercase();
    if language_is_untrusted(&lang) {
        Err(Reason::ServerFileOrOsAccess)
    } else if language_is_trusted(&lang) {
        Ok(())
    } else {
        Err(Reason::UnsupportedConstruct)
    }
}

/// Classify one parsed statement.
pub(crate) fn analyze(stmt: &Statement, names: &Names<'_>) -> Result<Analysis, Reason> {
    match stmt {
        Statement::Explain {
            describe_alias,
            analyze: explain_analyze,
            query_plan,
            estimate,
            statement,
            format: _,
            options,
            verbose: _,
        } => {
            if *describe_alias != DescribeAlias::Explain || *query_plan || *estimate {
                return Err(Reason::UnsupportedStatement);
            }
            let mut executes = *explain_analyze;
            for opt in options.iter().flatten() {
                let name = opt.name.value.to_ascii_lowercase();
                match name.as_str() {
                    // Any spelling of ANALYZE, even `ANALYZE false`, is taken as
                    // executing: the stricter reading.
                    "analyze" | "analyse" => executes = true,
                    "verbose" | "costs" | "settings" | "generic_plan" | "buffers" | "serialize" | "wal" | "timing"
                    | "summary" | "memory" | "format" => {}
                    _ => return Err(Reason::UnsupportedConstruct),
                }
            }
            let inner = analyze(statement, names)?;
            if inner.tx_control {
                return Err(Reason::UnsupportedStatement);
            }
            if executes {
                return Ok(Analysis { kind: Kind::ExplainAnalyze, ..inner });
            }
            // Plan only: reading the plan reveals every object the inner
            // statement touches. The planner may still run user functions
            // declared IMMUTABLE, so `sql_execute` is kept as it is.
            let mut a = Analysis::new(Kind::Explain);
            for (cap, target) in inner.required {
                let cap = if cap == Cap::Execute { Cap::Execute } else { Cap::Select };
                a.opaque |= cap == Cap::Execute;
                a.required.insert((cap, target));
            }
            if a.required.is_empty() {
                a.required.insert((Cap::Select, SqlTarget::Server));
            }
            Ok(a)
        }
        Statement::Prepare { statement, .. } => {
            // The statement is stored and later run by EXECUTE, which cannot
            // be tied back to it: opaque, and the caller must already hold
            // what the stored statement needs.
            let inner = analyze(statement, names)?;
            if inner.tx_control {
                return Err(Reason::UnsupportedStatement);
            }
            let mut a = Analysis { kind: Kind::Prepare, required: inner.required, opaque: true, tx_control: false };
            a.required.insert((Cap::Execute, SqlTarget::Server));
            Ok(a)
        }
        _ => {
            let mut w = Walker::new(names, stmt);
            match stmt.visit(&mut w) {
                ControlFlow::Break(r) => Err(r),
                ControlFlow::Continue(()) => w.finish(),
            }
        }
    }
}

struct Walker<'n, 'c> {
    names: &'n Names<'c>,
    root: usize,
    kind: Option<Kind>,
    read_family: bool,
    session_change: bool,
    required: Requirements,
    opaque: bool,
    tx_control: bool,
    /// Name nodes the statement table consumed as targets; not reads.
    excluded: HashSet<usize>,
    /// CTE names visible at each query level (absolute, not incremental).
    scopes: Vec<Vec<String>>,
    /// Scope precomputed for a CTE body, keyed by its `Query` node.
    cte_scope: HashMap<usize, Vec<String>>,
    /// Per query level: whether it takes row locks (`FOR UPDATE/SHARE`).
    locks: Vec<bool>,
}

impl<'n, 'c> Walker<'n, 'c> {
    fn new(names: &'n Names<'c>, root: &Statement) -> Self {
        Self {
            names,
            root: addr(root),
            kind: None,
            read_family: false,
            session_change: false,
            required: BTreeSet::new(),
            opaque: false,
            tx_control: false,
            excluded: HashSet::new(),
            scopes: Vec::new(),
            cte_scope: HashMap::new(),
            locks: Vec::new(),
        }
    }

    fn finish(mut self) -> Result<Analysis, Reason> {
        let mut kind = self.kind.ok_or(Reason::UnsupportedStatement)?;
        if self.read_family && self.required.is_empty() {
            self.required.insert((Cap::Select, SqlTarget::Server));
        }
        if self.session_change && matches!(kind, Kind::Select | Kind::Values) {
            kind = Kind::SetSession;
        }
        Ok(Analysis { kind, required: self.required, opaque: self.opaque, tx_control: self.tx_control })
    }

    fn need(&mut self, cap: Cap, target: SqlTarget) {
        self.required.insert((cap, target));
    }

    fn need_obj(&mut self, cap: Cap, obj: ObjectRef) {
        self.required.insert((cap, SqlTarget::Object(obj)));
    }

    fn exclude(&mut self, name: &ObjectName) {
        self.excluded.insert(addr(name));
    }

    fn existing(&self, kind: ObjectKind, name: &ObjectName) -> ControlFlow<Reason, ObjectRef> {
        match self.names.existing(kind, name) {
            Ok(r) => ControlFlow::Continue(r),
            Err(e) => brk(e),
        }
    }

    fn created(&self, kind: ObjectKind, name: &ObjectName, temporary: bool) -> ControlFlow<Reason, ObjectRef> {
        match self.names.new_object(kind, name, temporary) {
            Ok(r) => ControlFlow::Continue(r),
            Err(e) => brk(e),
        }
    }

    fn lock_level(&self) -> bool {
        self.locks.iter().any(|&l| l)
    }

    fn is_cte(&self, name: &ObjectName) -> bool {
        let Ok(parts) = self.names.parts(name) else { return false };
        parts.len() == 1 && self.scopes.last().is_some_and(|s| s.contains(&parts[0]))
    }

    fn read(&mut self, obj: ObjectRef) {
        if self.lock_level() {
            self.need_obj(Cap::Update, obj.clone());
        }
        self.need_obj(Cap::Select, obj);
    }

    /// User code: `sql_execute` on the routine, or `sql_select` when the
    /// database keeps the session read-only (§4.2).
    fn user_code(&mut self, target: SqlTarget) {
        if self.names.ctx.database_read_only {
            self.need(Cap::Select, target);
        } else {
            self.need(Cap::Execute, target);
            self.opaque = true;
        }
    }

    /// An operator that may resolve to user code: custom operators, and every
    /// operator when a user schema precedes `pg_catalog` on the search path.
    fn user_operator(&mut self) {
        self.user_code(SqlTarget::Server);
    }

    fn foreign_key(&mut self, c: &TableConstraint) -> Flow {
        if let TableConstraint::ForeignKey(fk) = c {
            let r = self.existing(ObjectKind::Relation, &fk.foreign_table)?;
            // Adding a foreign key constrains writes to the referenced table.
            self.need_obj(Cap::Alter, r);
        }
        ControlFlow::Continue(())
    }

    fn column_foreign_keys(&mut self, options: &[sqlparser::ast::ColumnOptionDef]) -> Flow {
        for o in options {
            if let ColumnOption::ForeignKey(fk) = &o.option {
                let r = self.existing(ObjectKind::Relation, &fk.foreign_table)?;
                self.need_obj(Cap::Alter, r);
            }
        }
        ControlFlow::Continue(())
    }

    /// A string literal argument exactly as the server reads it. Only plain
    /// and dollar-quoted strings qualify: other forms are decoded by the
    /// parser in ways that may differ from the server.
    fn literal(e: &Expr) -> Option<&str> {
        match e {
            Expr::Value(v) => match &v.value {
                Value::SingleQuotedString(s) => Some(s),
                Value::DollarQuotedString(d) => Some(&d.value),
                _ => None,
            },
            Expr::Nested(inner) => Self::literal(inner),
            Expr::Cast { expr, data_type: DataType::Regclass | DataType::Text, format: None, .. } => {
                Self::literal(expr)
            }
            _ => None,
        }
    }

    fn first_arg(args: &[FunctionArg]) -> Option<&Expr> {
        match args.first()? {
            FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => Some(e),
            _ => None,
        }
    }

    fn sequence_arg(&self, args: &[FunctionArg]) -> ControlFlow<Reason, ObjectRef> {
        let Some(s) = Self::first_arg(args).and_then(Self::literal) else {
            // The sequence is chosen at run time: no object to check.
            return brk(Reason::UnresolvableName);
        };
        match self.names.in_string(ObjectKind::Sequence, s) {
            Ok(r) => ControlFlow::Continue(r),
            Err(e) => brk(e),
        }
    }

    fn apply_class(&mut self, class: FnClass, args: &[FunctionArg]) -> Flow {
        match class {
            FnClass::Pure | FnClass::Unknown => {}
            FnClass::Admin => self.need(Cap::Admin, SqlTarget::Server),
            FnClass::SequenceWrite => {
                let s = self.sequence_arg(args)?;
                self.need_obj(Cap::Update, s);
            }
            FnClass::SequenceRead => {
                let s = self.sequence_arg(args)?;
                self.need_obj(Cap::Select, s);
            }
            FnClass::LastValue => self.need(Cap::Select, SqlTarget::Server),
            FnClass::AdvisoryLock => self.need(Cap::Update, SqlTarget::Server),
            FnClass::Notify => self.need(Cap::Execute, SqlTarget::Server),
            FnClass::SetConfig => {
                let Some(name) = Self::first_arg(args).and_then(Self::literal) else {
                    return brk(Reason::UnresolvableName);
                };
                match settings::requirement(name.trim()) {
                    Ok(cap) => self.need(cap, SqlTarget::Server),
                    Err(r) => return brk(r),
                }
                self.session_change = true;
            }
        }
        ControlFlow::Continue(())
    }

    /// A function call, in an expression or in `FROM`.
    fn function(&mut self, name: &ObjectName, args: &[FunctionArg]) -> Flow {
        let parts = match self.names.parts(name) {
            Ok(p) => p,
            Err(e) => return brk(e),
        };
        let (schema, fname) = match parts.as_slice() {
            [f] => (None, f.as_str()),
            [s, f] => (Some(s.as_str()), f.as_str()),
            [_, s, f] => (Some(s.as_str()), f.as_str()),
            _ => return brk(Reason::UnresolvableName),
        };
        if functions::always_refused(fname) {
            return brk(Reason::ServerFileOrOsAccess);
        }
        if functions::dynamic_sql(fname) {
            self.need(Cap::Execute, SqlTarget::Server);
            self.opaque = true;
            return ControlFlow::Continue(());
        }
        let class = functions::class(fname);
        let builtin = schema == Some("pg_catalog") || (schema.is_none() && self.names.catalog_first());
        if builtin {
            if class == FnClass::Unknown {
                let r = self.existing(ObjectKind::Routine, name)?;
                self.user_code(SqlTarget::Object(r));
            } else {
                self.apply_class(class, args)?;
            }
            return ControlFlow::Continue(());
        }
        // A user schema is searched first, or the name is qualified with
        // one: user code, plus whatever the built-in of that name needs.
        if schema.is_none() {
            self.apply_class(class, args)?;
        }
        let r = self.existing(ObjectKind::Routine, name)?;
        self.user_code(SqlTarget::Object(r));
        ControlFlow::Continue(())
    }

    fn call(&mut self, f: &Function) -> Flow {
        if f.uses_odbc_syntax || !matches!(f.parameters, FunctionArguments::None) {
            return brk(Reason::UnsupportedConstruct);
        }
        match &f.args {
            FunctionArguments::List(l) => self.function(&f.name, &l.args),
            FunctionArguments::None | FunctionArguments::Subquery(_) => self.function(&f.name, &[]),
        }
    }

    fn binary_op(&mut self, op: &BinaryOperator) -> Flow {
        match op {
            BinaryOperator::Spaceship
            | BinaryOperator::Xor
            | BinaryOperator::DuckIntegerDivide
            | BinaryOperator::MyIntegerDivide
            | BinaryOperator::Match
            | BinaryOperator::Regexp
            | BinaryOperator::Glob
            | BinaryOperator::Assignment => return brk(Reason::UnsupportedConstruct),
            BinaryOperator::PGCustomBinaryOperator(parts) => {
                if !(parts.len() == 2 && parts[0].eq_ignore_ascii_case("pg_catalog")) || !self.names.catalog_first() {
                    self.user_operator();
                }
            }
            BinaryOperator::Custom(_) => self.user_operator(),
            _ if !self.names.catalog_first() => self.user_operator(),
            _ => {}
        }
        ControlFlow::Continue(())
    }

    /// The statement table: each statement's own targets.
    fn primary(&mut self, s: &Statement, is_root: bool) -> Flow {
        let kind = self.primary_inner(s)?;
        if is_root {
            self.kind = Some(kind);
        }
        ControlFlow::Continue(())
    }

    fn primary_inner(&mut self, s: &Statement) -> ControlFlow<Reason, Kind> {
        use ObjectKind as K;
        let server = SqlTarget::Server;
        let kind = match s {
            Statement::Query(q) => {
                self.read_family = true;
                query_kind(&q.body)
            }
            Statement::Insert(ins) => {
                if ins.or.is_some()
                    || ins.ignore
                    || ins.overwrite
                    || ins.partitioned.is_some()
                    || !ins.after_columns.is_empty()
                    || !ins.assignments.is_empty()
                    || ins.output.is_some()
                    || ins.replace_into
                    || ins.priority.is_some()
                    || ins.insert_alias.is_some()
                    || ins.settings.is_some()
                    || ins.format_clause.is_some()
                    || ins.multi_table_insert_type.is_some()
                    || !ins.multi_table_into_clauses.is_empty()
                    || !ins.multi_table_when_clauses.is_empty()
                    || ins.multi_table_else_clause.is_some()
                    || ins.has_table_keyword
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                let TableObject::TableName(target) = &ins.table else { return brk(Reason::UnsupportedConstruct) };
                self.exclude(target);
                let t = self.existing(K::Relation, target)?;
                self.need_obj(Cap::Insert, t.clone());
                if ins.returning.is_some() {
                    self.need_obj(Cap::Select, t.clone());
                }
                match &ins.on {
                    None => {}
                    Some(OnInsert::OnConflict(oc)) => {
                        // The arbiter and any DO UPDATE expressions read the target.
                        self.need_obj(Cap::Select, t.clone());
                        if matches!(oc.action, OnConflictAction::DoUpdate(_)) {
                            self.need_obj(Cap::Update, t);
                        }
                    }
                    Some(_) => return brk(Reason::UnsupportedConstruct),
                }
                Kind::Insert
            }
            Statement::Update(up) => {
                if up.or.is_some() || up.output.is_some() || !up.order_by.is_empty() || up.limit.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                if !up.table.joins.is_empty() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let TableFactor::Table { name, args: None, .. } = &up.table.relation else {
                    return brk(Reason::UnsupportedConstruct);
                };
                self.exclude(name);
                let t = self.existing(K::Relation, name)?;
                self.need_obj(Cap::Update, t.clone());
                let reads_target = up.selection.is_some()
                    || up.returning.is_some()
                    || up.from.is_some()
                    || up.assignments.iter().any(|a| !matches!(a.value, Expr::Value(_)));
                if reads_target {
                    self.need_obj(Cap::Select, t);
                }
                Kind::Update
            }
            Statement::Delete(d) => {
                if !d.tables.is_empty() || d.output.is_some() || !d.order_by.is_empty() || d.limit.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) = &d.from;
                let [twj] = from.as_slice() else { return brk(Reason::UnsupportedConstruct) };
                if !twj.joins.is_empty() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let TableFactor::Table { name, args: None, .. } = &twj.relation else {
                    return brk(Reason::UnsupportedConstruct);
                };
                self.exclude(name);
                let t = self.existing(K::Relation, name)?;
                self.need_obj(Cap::Delete, t.clone());
                if d.selection.is_some() || d.returning.is_some() || d.using.is_some() {
                    self.need_obj(Cap::Select, t);
                }
                Kind::Delete
            }
            Statement::Merge(m) => {
                if m.output.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let TableFactor::Table { name, args: None, .. } = &m.table else {
                    return brk(Reason::UnsupportedConstruct);
                };
                self.exclude(name);
                let t = self.existing(K::Relation, name)?;
                // The join condition reads the target.
                self.need_obj(Cap::Select, t.clone());
                for clause in &m.clauses {
                    match &clause.action {
                        MergeAction::Insert(_) => self.need_obj(Cap::Insert, t.clone()),
                        MergeAction::Update(_) => self.need_obj(Cap::Update, t.clone()),
                        MergeAction::Delete { .. } => self.need_obj(Cap::Delete, t.clone()),
                        MergeAction::DoNothing { .. } => {}
                    }
                }
                Kind::Merge
            }
            Statement::Copy { source, to, target, values, .. } => {
                if !values.is_empty() {
                    return brk(Reason::UnsupportedConstruct);
                }
                match target {
                    CopyTarget::Stdin | CopyTarget::Stdout => {}
                    CopyTarget::File { .. } | CopyTarget::Program { .. } => return brk(Reason::ServerFileOrOsAccess),
                }
                if *to != matches!(target, CopyTarget::Stdout) {
                    return brk(Reason::UnsupportedConstruct);
                }
                match source {
                    CopySource::Table { table_name, .. } => {
                        let t = self.existing(K::Relation, table_name)?;
                        if *to {
                            self.need_obj(Cap::Select, t);
                        } else {
                            self.need_obj(Cap::Insert, t);
                        }
                    }
                    CopySource::Query(_) if *to => self.read_family = true,
                    CopySource::Query(_) => return brk(Reason::UnsupportedConstruct),
                }
                if *to {
                    Kind::CopyTo
                } else {
                    Kind::CopyFrom
                }
            }
            Statement::Lock(l) => {
                for t in &l.tables {
                    self.exclude(&t.name);
                    let r = self.existing(K::Relation, &t.name)?;
                    self.need_obj(Cap::Select, r.clone());
                    self.need_obj(Cap::Update, r);
                }
                Kind::Lock
            }
            Statement::Truncate(tr) => {
                if tr.partitions.is_some() || tr.on_cluster.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                for t in &tr.table_names {
                    self.exclude(&t.name);
                    let r = self.existing(K::Relation, &t.name)?;
                    self.need_obj(Cap::Drop, r);
                }
                if matches!(tr.cascade, Some(CascadeOption::Cascade)) {
                    // CASCADE empties tables the statement does not name.
                    self.need(Cap::Drop, server.clone());
                }
                Kind::Truncate
            }
            Statement::Drop { object_type, names, cascade, table, .. } => {
                if table.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let object_kind = match object_type {
                    ObjectType::Table | ObjectType::View | ObjectType::MaterializedView => Some(K::Relation),
                    ObjectType::Index => Some(K::Index),
                    ObjectType::Sequence => Some(K::Sequence),
                    ObjectType::Type => Some(K::Type),
                    ObjectType::Collation => Some(K::Collation),
                    ObjectType::Schema => None,
                    ObjectType::Database | ObjectType::Role | ObjectType::User => {
                        self.need(Cap::Admin, server.clone());
                        return ControlFlow::Continue(Kind::Admin);
                    }
                    _ => return brk(Reason::UnsupportedStatement),
                };
                for n in names {
                    match object_kind {
                        Some(k) => {
                            let r = self.existing(k, n)?;
                            self.need_obj(Cap::Drop, r);
                        }
                        None => self.need(Cap::Drop, server.clone()),
                    }
                }
                if *cascade {
                    // CASCADE drops dependent objects the statement does not name.
                    self.need(Cap::Drop, server.clone());
                }
                Kind::Drop
            }
            Statement::DropFunction(df) => {
                for d in &df.func_desc {
                    let r = self.existing(K::Routine, &d.name)?;
                    self.need_obj(Cap::Drop, r);
                }
                if matches!(df.drop_behavior, Some(DropBehavior::Cascade)) {
                    self.need(Cap::Drop, server.clone());
                }
                Kind::Drop
            }
            Statement::DropProcedure { proc_desc, drop_behavior, .. } => {
                for d in proc_desc {
                    let r = self.existing(K::Routine, &d.name)?;
                    self.need_obj(Cap::Drop, r);
                }
                if matches!(drop_behavior, Some(DropBehavior::Cascade)) {
                    self.need(Cap::Drop, server.clone());
                }
                Kind::Drop
            }
            Statement::DropTrigger(dt) => {
                // Triggers are named per table; the table is the object.
                let Some(table) = &dt.table_name else { return brk(Reason::UnsupportedConstruct) };
                let r = self.existing(K::Relation, table)?;
                self.need_obj(Cap::Drop, r);
                if matches!(dt.option, Some(ReferentialAction::Cascade)) {
                    self.need(Cap::Drop, server.clone());
                }
                Kind::Drop
            }
            Statement::DropDomain(dd) => {
                let r = self.existing(K::Type, &dd.name)?;
                self.need_obj(Cap::Drop, r);
                if matches!(dd.drop_behavior, Some(DropBehavior::Cascade)) {
                    self.need(Cap::Drop, server.clone());
                }
                Kind::Drop
            }
            Statement::DropPolicy(dp) => {
                self.exclude(&dp.table_name);
                let r = self.existing(K::Relation, &dp.table_name)?;
                self.need_obj(Cap::Drop, r);
                Kind::Drop
            }
            Statement::CreateTable(ct) => {
                if ct.or_replace
                    || ct.external
                    || ct.dynamic
                    || ct.iceberg
                    || ct.snapshot
                    || ct.transient
                    || ct.volatile
                    || ct.without_rowid
                    || ct.strict
                    || ct.copy_grants
                    || ct.clone.is_some()
                    || ct.version.is_some()
                    || ct.with_aggregation_policy.is_some()
                    || ct.with_row_access_policy.is_some()
                    || ct.with_storage_lifecycle_policy.is_some()
                    || ct.with_connection.is_some()
                    || ct.location.is_some()
                    || ct.file_format.is_some()
                    || ct.hive_formats.is_some()
                    || ct.on_cluster.is_some()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ct.name);
                let t = self.created(K::Relation, &ct.name, ct.temporary)?;
                self.need_obj(Cap::Create, t.clone());
                if ct.query.is_some() {
                    self.need_obj(Cap::Insert, t);
                }
                if let Some(like) = &ct.like {
                    let (sqlparser::ast::CreateTableLikeKind::Parenthesized(l)
                    | sqlparser::ast::CreateTableLikeKind::Plain(l)) = like;
                    let src = self.existing(K::Relation, &l.name)?;
                    self.need_obj(Cap::Select, src);
                }
                for parent in ct.inherits.iter().flatten() {
                    let p = self.existing(K::Relation, parent)?;
                    self.need_obj(Cap::Alter, p);
                }
                if let Some(parent) = &ct.partition_of {
                    self.exclude(parent);
                    let p = self.existing(K::Relation, parent)?;
                    self.need_obj(Cap::Alter, p);
                }
                for c in &ct.columns {
                    self.column_foreign_keys(&c.options)?;
                }
                for c in &ct.constraints {
                    self.foreign_key(c)?;
                }
                Kind::CreateTable
            }
            Statement::CreateView(cv) => {
                if cv.secure || cv.to.is_some() || cv.params.is_some() || cv.copy_grants || cv.with_no_schema_binding {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&cv.name);
                let v = self.created(K::Relation, &cv.name, cv.temporary)?;
                self.need_obj(Cap::Create, v.clone());
                if cv.or_replace || cv.or_alter {
                    self.need_obj(Cap::Alter, v.clone());
                }
                if cv.materialized {
                    self.need_obj(Cap::Insert, v);
                }
                // The view's query is walked: its creator must be able to read
                // what the view exposes, or the view would launder access.
                Kind::CreateView
            }
            Statement::CreateIndex(ci) => {
                if !ci.index_options.is_empty() || !ci.alter_options.is_empty() || ci.r#async {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ci.table_name);
                let t = self.existing(K::Relation, &ci.table_name)?;
                self.need_obj(Cap::Create, t);
                Kind::CreateIndex
            }
            Statement::CreateSequence { temporary, name, owned_by, .. } => {
                let seq = self.created(K::Sequence, name, *temporary)?;
                self.need_obj(Cap::Create, seq);
                if let Some(owner) = owned_by {
                    let parts = match self.names.parts(owner) {
                        Ok(p) => p,
                        Err(e) => return brk(e),
                    };
                    // `OWNED BY t.col` ties the sequence to a table; `OWNED BY NONE` does not.
                    if parts.len() >= 2 {
                        let table = match self.names.existing_parts(K::Relation, parts[..parts.len() - 1].to_vec()) {
                            Ok(r) => r,
                            Err(e) => return brk(e),
                        };
                        self.need_obj(Cap::Alter, table);
                    } else if parts != ["none"] {
                        return brk(Reason::UnresolvableName);
                    }
                }
                Kind::CreateSequence
            }
            Statement::CreateSchema { schema_name, with, options, default_collate_spec, clone, .. } => {
                if with.is_some() || options.is_some() || default_collate_spec.is_some() || clone.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.need(Cap::Create, server.clone());
                if !matches!(schema_name, sqlparser::ast::SchemaName::Simple(_)) {
                    // AUTHORIZATION creates the schema owned by another role.
                    self.need(Cap::Admin, server.clone());
                }
                Kind::CreateSchema
            }
            Statement::CreateFunction(cf) => {
                if cf.using.is_some() || cf.remote_connection.is_some() || cf.options.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                if let Some(lang) = &cf.language {
                    if let Err(r) = check_language(&lang.value) {
                        return brk(r);
                    }
                }
                if matches!(cf.function_body, Some(CreateFunctionBody::AsBeginEnd(_))) && cf.language.is_none() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let f = self.created(K::Routine, &cf.name, cf.temporary)?;
                self.need_obj(Cap::Create, f.clone());
                if cf.or_replace || cf.or_alter {
                    self.need_obj(Cap::Alter, f);
                }
                Kind::CreateRoutine
            }
            Statement::CreateProcedure { or_alter, name, language, .. } => {
                if let Some(lang) = language {
                    if let Err(r) = check_language(&lang.value) {
                        return brk(r);
                    }
                }
                let p = self.created(K::Routine, name, false)?;
                self.need_obj(Cap::Create, p.clone());
                if *or_alter {
                    self.need_obj(Cap::Alter, p);
                }
                Kind::CreateRoutine
            }
            Statement::CreateTrigger(ct) => {
                if ct.or_alter || ct.statements.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let t = self.existing(K::Relation, &ct.table_name)?;
                self.need_obj(Cap::Create, t.clone());
                if ct.or_replace {
                    self.need_obj(Cap::Alter, t);
                }
                if let Some(r) = &ct.referenced_table_name {
                    let r = self.existing(K::Relation, r)?;
                    self.need_obj(Cap::Select, r);
                }
                let Some(body) = &ct.exec_body else { return brk(Reason::UnsupportedConstruct) };
                let f = self.existing(K::Routine, &body.func_desc.name)?;
                self.need_obj(Cap::Execute, f);
                Kind::CreateTrigger
            }
            Statement::CreateType { name, .. } => {
                let t = self.created(K::Type, name, false)?;
                self.need_obj(Cap::Create, t);
                Kind::CreateType
            }
            Statement::CreateDomain(cd) => {
                let t = self.created(K::Type, &cd.name, false)?;
                self.need_obj(Cap::Create, t);
                Kind::CreateType
            }
            Statement::CreateCollation(cc) => {
                let c = self.created(K::Collation, &cc.name, false)?;
                self.need_obj(Cap::Create, c);
                Kind::CreateType
            }
            Statement::CreatePolicy(cp) => {
                self.exclude(&cp.table_name);
                let t = self.existing(K::Relation, &cp.table_name)?;
                self.need_obj(Cap::Create, t);
                Kind::CreatePolicy
            }
            Statement::AlterPolicy(ap) => {
                self.exclude(&ap.table_name);
                let t = self.existing(K::Relation, &ap.table_name)?;
                self.need_obj(Cap::Alter, t);
                Kind::Alter
            }
            Statement::AlterTable(at) => {
                if at.location.is_some() || at.on_cluster.is_some() || at.table_type.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&at.name);
                let t = self.existing(K::Relation, &at.name)?;
                self.need_obj(Cap::Alter, t);
                for op in &at.operations {
                    match op {
                        AlterTableOperation::AddConstraint { constraint, .. } => self.foreign_key(constraint)?,
                        AlterTableOperation::AddColumn { column_def, .. } => {
                            self.column_foreign_keys(&column_def.options)?
                        }
                        AlterTableOperation::OwnerTo { .. } => self.need(Cap::Admin, server.clone()),
                        AlterTableOperation::DisableRowLevelSecurity
                        | AlterTableOperation::DisableRule { .. }
                        | AlterTableOperation::DisableTrigger { .. }
                        | AlterTableOperation::DropConstraint { .. }
                        | AlterTableOperation::DropColumn { .. }
                        | AlterTableOperation::EnableAlwaysRule { .. }
                        | AlterTableOperation::EnableAlwaysTrigger { .. }
                        | AlterTableOperation::EnableReplicaRule { .. }
                        | AlterTableOperation::EnableReplicaTrigger { .. }
                        | AlterTableOperation::EnableRowLevelSecurity
                        | AlterTableOperation::ForceRowLevelSecurity
                        | AlterTableOperation::NoForceRowLevelSecurity
                        | AlterTableOperation::EnableRule { .. }
                        | AlterTableOperation::EnableTrigger { .. }
                        | AlterTableOperation::ReplicaIdentity { .. }
                        | AlterTableOperation::RenameColumn { .. }
                        | AlterTableOperation::RenameTable { .. }
                        | AlterTableOperation::RenameConstraint { .. }
                        | AlterTableOperation::AlterColumn { .. }
                        | AlterTableOperation::SetLogged
                        | AlterTableOperation::SetUnlogged
                        | AlterTableOperation::ValidateConstraint { .. }
                        | AlterTableOperation::SetOptionsParens { .. } => {}
                        _ => return brk(Reason::UnsupportedConstruct),
                    }
                }
                Kind::Alter
            }
            Statement::AlterIndex { name, .. } => {
                let i = self.existing(K::Index, name)?;
                self.need_obj(Cap::Alter, i);
                Kind::Alter
            }
            Statement::AlterView { name, .. } => {
                self.exclude(name);
                let v = self.existing(K::Relation, name)?;
                self.need_obj(Cap::Alter, v);
                Kind::Alter
            }
            Statement::AlterSchema(a) => {
                self.need(Cap::Alter, server.clone());
                if a.operations.iter().any(|o| matches!(o, sqlparser::ast::AlterSchemaOperation::OwnerTo { .. })) {
                    self.need(Cap::Admin, server.clone());
                }
                Kind::Alter
            }
            Statement::AlterType(a) => {
                let t = self.existing(K::Type, &a.name)?;
                self.need_obj(Cap::Alter, t);
                Kind::Alter
            }
            Statement::AlterFunction(a) => {
                let f = self.existing(K::Routine, &a.function.name)?;
                self.need_obj(Cap::Alter, f);
                if matches!(a.operation, sqlparser::ast::AlterFunctionOperation::OwnerTo(_)) {
                    self.need(Cap::Admin, server.clone());
                }
                Kind::Alter
            }
            Statement::Comment { object_type, object_name, .. } => {
                let parts = match self.names.parts(object_name) {
                    Ok(p) => p,
                    Err(e) => return brk(e),
                };
                let target = |k: K, parts: Vec<String>| self.names.existing_parts(k, parts);
                let r = match object_type {
                    CommentObject::Column if parts.len() >= 2 => target(K::Relation, parts[..parts.len() - 1].to_vec()),
                    CommentObject::Column => Err(Reason::UnresolvableName),
                    CommentObject::Table | CommentObject::View | CommentObject::MaterializedView => {
                        target(K::Relation, parts)
                    }
                    CommentObject::Index => target(K::Index, parts),
                    CommentObject::Sequence => target(K::Sequence, parts),
                    CommentObject::Function | CommentObject::Procedure => target(K::Routine, parts),
                    CommentObject::Type | CommentObject::Domain => target(K::Type, parts),
                    CommentObject::Collation => target(K::Collation, parts),
                    CommentObject::Schema
                    | CommentObject::Database
                    | CommentObject::Extension
                    | CommentObject::Role
                    | CommentObject::User => {
                        self.need(Cap::Alter, server.clone());
                        return ControlFlow::Continue(Kind::Comment);
                    }
                };
                match r {
                    Ok(r) => self.need_obj(Cap::Alter, r),
                    Err(e) => return brk(e),
                }
                Kind::Comment
            }
            Statement::Grant(_)
            | Statement::Revoke(_)
            | Statement::CreateRole(_)
            | Statement::CreateUser(_)
            | Statement::AlterRole { .. }
            | Statement::AlterUser(_)
            | Statement::CreateDatabase { .. }
            | Statement::CreateExtension(_)
            | Statement::DropExtension(_)
            | Statement::CreateServer(_)
            | Statement::CreateOperator(_)
            | Statement::CreateOperatorFamily(_)
            | Statement::CreateOperatorClass(_)
            | Statement::DropOperator(_)
            | Statement::DropOperatorFamily(_)
            | Statement::DropOperatorClass(_) => {
                self.need(Cap::Admin, server.clone());
                Kind::Admin
            }
            Statement::Call(f) => {
                if f.uses_odbc_syntax || !matches!(f.parameters, FunctionArguments::None) {
                    return brk(Reason::UnsupportedConstruct);
                }
                let r = self.existing(K::Routine, &f.name)?;
                self.need_obj(Cap::Execute, r);
                self.opaque = true;
                Kind::Call
            }
            Statement::Execute { name, immediate, into, using, output, default, .. } => {
                if *immediate || !into.is_empty() || !using.is_empty() || *output || *default || name.is_none() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.need(Cap::Execute, server.clone());
                self.opaque = true;
                Kind::Execute
            }
            Statement::Deallocate { .. } => {
                self.need(Cap::Select, server.clone());
                Kind::Deallocate
            }
            Statement::Declare { stmts } => {
                for d in stmts {
                    if d.declare_type != Some(DeclareType::Cursor) || d.for_query.is_none() || d.assignment.is_some() {
                        return brk(Reason::UnsupportedConstruct);
                    }
                }
                self.read_family = true;
                Kind::DeclareCursor
            }
            Statement::Fetch { into, .. } => {
                if into.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.need(Cap::Select, server.clone());
                Kind::FetchCursor
            }
            Statement::Close { .. } => {
                self.need(Cap::Select, server.clone());
                Kind::CloseCursor
            }
            Statement::LISTEN { .. } | Statement::UNLISTEN { .. } => {
                self.need(Cap::Select, server.clone());
                Kind::Listen
            }
            Statement::NOTIFY { .. } => {
                self.need(Cap::Execute, server.clone());
                Kind::Notify
            }
            Statement::StartTransaction { modes, statements, exception, has_end_keyword, modifier, .. } => {
                if !statements.is_empty() || exception.is_some() || *has_end_keyword || modifier.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                check_modes(modes)?;
                self.tx_control = true;
                Kind::TxBegin
            }
            Statement::Commit { modifier, .. } => {
                if modifier.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.tx_control = true;
                Kind::TxCommit
            }
            Statement::Rollback { .. } => {
                self.tx_control = true;
                Kind::TxRollback
            }
            Statement::Savepoint { .. } => {
                self.tx_control = true;
                Kind::TxSavepoint
            }
            Statement::ReleaseSavepoint { .. } => {
                self.tx_control = true;
                Kind::TxReleaseSavepoint
            }
            Statement::Set(set) => {
                let cap = match set {
                    Set::SingleAssignment { scope, hivevar, variable, .. } => {
                        if *hivevar || matches!(scope, Some(sqlparser::ast::ContextModifier::Global)) {
                            return brk(Reason::UnsupportedConstruct);
                        }
                        match settings::requirement(&setting_name(variable)) {
                            Ok(c) => c,
                            Err(r) => return brk(r),
                        }
                    }
                    Set::SetTimeZone { .. } => Cap::Select,
                    Set::SetNames { .. } | Set::SetNamesDefault {} => return brk(Reason::LexerSettingChange),
                    Set::SetTransaction { modes, .. } => {
                        check_modes(modes)?;
                        Cap::Select
                    }
                    Set::SetRole { .. } | Set::SetSessionAuthorization(_) => Cap::Admin,
                    _ => return brk(Reason::UnsupportedConstruct),
                };
                self.need(cap, server.clone());
                Kind::SetSession
            }
            Statement::Reset(r) => {
                let cap = match &r.reset {
                    // RESET ALL also resets standard_conforming_strings and the
                    // read-only guard to their configured defaults.
                    Reset::ALL => return brk(Reason::LexerSettingChange),
                    Reset::SessionAuthorization => Cap::Admin,
                    Reset::ConfigurationParameter(name) => match settings::requirement(&setting_name(name)) {
                        Ok(c) => c,
                        Err(r) => return brk(r),
                    },
                };
                self.need(cap, server.clone());
                Kind::SetSession
            }
            Statement::ShowVariable { .. } => {
                self.need(Cap::Select, server.clone());
                Kind::Show
            }
            Statement::Discard { object_type } => {
                if matches!(object_type, DiscardObject::ALL) {
                    // DISCARD ALL includes RESET ALL.
                    return brk(Reason::LexerSettingChange);
                }
                self.need(Cap::Select, server.clone());
                Kind::SetSession
            }
            Statement::Load { .. }
            | Statement::LoadData { .. }
            | Statement::Directory { .. }
            | Statement::Unload { .. } => return brk(Reason::ServerFileOrOsAccess),
            Statement::Explain { .. } | Statement::Prepare { .. } => {
                // Only valid at the top, where `analyze` handles them.
                return brk(Reason::UnsupportedStatement);
            }
            _ => return brk(Reason::UnsupportedStatement),
        };
        ControlFlow::Continue(kind)
    }
}

/// `READ WRITE` would lift the read-only guard of the session (§5.3).
fn check_modes(modes: &[TransactionMode]) -> Flow {
    if modes.iter().any(|m| matches!(m, TransactionMode::AccessMode(TransactionAccessMode::ReadWrite))) {
        return brk(Reason::ReadOnlyGuardChange);
    }
    ControlFlow::Continue(())
}

/// A setting name as the server looks it up: dotted parts, case-insensitive.
fn setting_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|p| match p {
            sqlparser::ast::ObjectNamePart::Identifier(id) => id.value.to_ascii_lowercase(),
            // Never a valid setting name; it then needs sql_admin at least.
            sqlparser::ast::ObjectNamePart::Function(_) => "\u{fffd}".to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn query_kind(body: &SetExpr) -> Kind {
    match body {
        SetExpr::Values(_) => Kind::Values,
        SetExpr::Insert(_) => Kind::Insert,
        SetExpr::Update(_) => Kind::Update,
        SetExpr::Delete(_) => Kind::Delete,
        SetExpr::Merge(_) => Kind::Merge,
        SetExpr::Query(q) => query_kind(&q.body),
        SetExpr::Select(_) | SetExpr::SetOperation { .. } | SetExpr::Table(_) => Kind::Select,
    }
}

impl Visitor for Walker<'_, '_> {
    type Break = Reason;

    fn pre_visit_statement(&mut self, s: &Statement) -> Flow {
        let is_root = addr(s) == self.root;
        self.primary(s, is_root)
    }

    fn pre_visit_query(&mut self, q: &Query) -> Flow {
        if q.for_clause.is_some() || q.settings.is_some() || q.format_clause.is_some() || !q.pipe_operators.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let mut visible = match self.cte_scope.remove(&addr(q)) {
            Some(s) => s,
            None => self.scopes.last().cloned().unwrap_or_default(),
        };
        if let Some(with) = &q.with {
            let mut cte_names = Vec::with_capacity(with.cte_tables.len());
            for cte in &with.cte_tables {
                if cte.from.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                match self.names.ident(&cte.alias.name) {
                    Ok(n) => cte_names.push(n),
                    Err(e) => return brk(e),
                }
            }
            for (i, cte) in with.cte_tables.iter().enumerate() {
                // A non-recursive CTE sees only the ones before it; its own
                // name inside its body is the real table of that name.
                let mut scope = visible.clone();
                let upto = if with.recursive { cte_names.len() } else { i };
                scope.extend(cte_names[..upto].iter().cloned());
                self.cte_scope.insert(addr(&*cte.query), scope);
            }
            visible.extend(cte_names);
        }
        self.scopes.push(visible);
        self.locks.push(!q.locks.is_empty());
        self.table_set_exprs(&q.body)
    }

    fn post_visit_query(&mut self, _q: &Query) -> Flow {
        self.scopes.pop();
        self.locks.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> Flow {
        if s.top.is_some()
            || s.select_modifiers.is_some()
            || s.exclude.is_some()
            || !s.lateral_views.is_empty()
            || s.prewhere.is_some()
            || !s.connect_by.is_empty()
            || !s.cluster_by.is_empty()
            || !s.distribute_by.is_empty()
            || !s.sort_by.is_empty()
            || s.qualify.is_some()
            || s.value_table_mode.is_some()
            || s.flavor != sqlparser::ast::SelectFlavor::Standard
        {
            return brk(Reason::UnsupportedConstruct);
        }
        if let Some(into) = &s.into {
            // `SELECT … INTO new_table` creates and fills a table (§4.2).
            let [target] = into.targets.as_slice() else { return brk(Reason::UnsupportedConstruct) };
            let name = match target {
                Expr::Identifier(id) => ObjectName::from(vec![id.clone()]),
                Expr::CompoundIdentifier(ids) => ObjectName::from(ids.clone()),
                _ => return brk(Reason::UnsupportedConstruct),
            };
            let t = self.created(ObjectKind::Relation, &name, into.temporary)?;
            self.need_obj(Cap::Create, t.clone());
            self.need_obj(Cap::Insert, t);
            if self.kind == Some(Kind::Select) {
                self.kind = Some(Kind::SelectInto);
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, name: &ObjectName) -> Flow {
        if self.excluded.contains(&addr(name)) || self.is_cte(name) {
            return ControlFlow::Continue(());
        }
        let r = self.existing(ObjectKind::Relation, name)?;
        self.read(r);
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> Flow {
        match tf {
            TableFactor::Table { name, args, with_hints, version, partitions, json_path, index_hints, .. } => {
                if !with_hints.is_empty()
                    || version.is_some()
                    || !partitions.is_empty()
                    || json_path.is_some()
                    || !index_hints.is_empty()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                if let Some(a) = args {
                    // `FROM f(…)`: a function, not a relation.
                    if a.settings.is_some() {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    self.exclude(name);
                    self.function(name, &a.args)?;
                }
            }
            TableFactor::Function { name, args, .. } => self.function(name, args)?,
            TableFactor::UNNEST { with_offset, .. } => {
                if *with_offset {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
            TableFactor::Derived { .. }
            | TableFactor::NestedJoin { .. }
            | TableFactor::TableFunction { .. }
            | TableFactor::JsonTable { .. }
            | TableFactor::XmlTable { .. } => {}
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> Flow {
        match e {
            Expr::Function(f) => self.call(f)?,
            Expr::BinaryOp { op, .. } => self.binary_op(op)?,
            Expr::AnyOp { compare_op, .. } | Expr::AllOp { compare_op, .. } => self.binary_op(compare_op)?,
            Expr::UnaryOp { .. }
            | Expr::Like { .. }
            | Expr::ILike { .. }
            | Expr::SimilarTo { .. }
            | Expr::Between { .. }
            | Expr::InList { .. }
            | Expr::InSubquery { .. }
            | Expr::IsDistinctFrom(..)
            | Expr::IsNotDistinctFrom(..) => {
                if !self.names.catalog_first() {
                    self.user_operator();
                }
            }
            Expr::CompoundFieldAccess { access_chain, .. } => {
                if access_chain.iter().any(|a| !matches!(a, AccessExpr::Dot(_) | AccessExpr::Subscript(_))) {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
            Expr::Identifier(_)
            | Expr::CompoundIdentifier(_)
            | Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::IsNormalized { .. }
            | Expr::IsJson { .. }
            | Expr::Cast { .. }
            | Expr::AtTimeZone { .. }
            | Expr::Extract { .. }
            | Expr::Ceil { .. }
            | Expr::Floor { .. }
            | Expr::Position { .. }
            | Expr::Substring { .. }
            | Expr::Trim { .. }
            | Expr::Overlay { .. }
            | Expr::Collate { .. }
            | Expr::Nested(_)
            | Expr::Value(_)
            | Expr::TypedString(_)
            | Expr::Case { .. }
            | Expr::Exists { .. }
            | Expr::Subquery(_)
            | Expr::GroupingSets(_)
            | Expr::Cube(_)
            | Expr::Rollup(_)
            | Expr::Tuple(_)
            | Expr::Array(_)
            | Expr::Interval(_)
            | Expr::Wildcard(_)
            | Expr::QualifiedWildcard(..) => {}
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }
}

impl Walker<'_, '_> {
    /// `TABLE name` carries its name as bare strings, quoting lost. It is
    /// accepted only when no case folding could change it.
    fn table_set_exprs(&mut self, body: &SetExpr) -> Flow {
        match body {
            SetExpr::SetOperation { left, right, .. } => {
                self.table_set_exprs(left)?;
                self.table_set_exprs(right)
            }
            SetExpr::Table(t) => {
                let Some(table) = &t.table_name else { return brk(Reason::UnsupportedConstruct) };
                let mut parts = Vec::new();
                for p in t.schema_name.iter().chain(std::iter::once(table)) {
                    if p.is_empty() || p.chars().any(|c| c.is_ascii_uppercase()) {
                        return brk(Reason::UnresolvableName);
                    }
                    parts.push(self.names.truncate(p.clone()));
                }
                if parts.len() == 1 && self.scopes.last().is_some_and(|s| s.contains(&parts[0])) {
                    return ControlFlow::Continue(());
                }
                match self.names.existing_parts(ObjectKind::Relation, parts) {
                    Ok(r) => self.read(r),
                    Err(e) => return brk(e),
                }
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Continue(()),
        }
    }
}
