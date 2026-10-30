//! Statement → required privileges, T-SQL (§4.2, §4.3), for the statements
//! the parser reads: queries (`SELECT … INTO`, `FOR XML / JSON`, lock
//! hints, table-valued functions), `INSERT` / `UPDATE` / `DELETE` / `MERGE`
//! with `OUTPUT [INTO]` and data-modifying CTEs, `CREATE TABLE / VIEW /
//! INDEX`, `ALTER TABLE / VIEW`, `DECLARE`, `SET @var`, `PRINT`,
//! `RAISERROR`, `THROW` and `WAITFOR`.

// The statement table decides each statement's own targets; a full AST walk
// then visits every node, so a subquery, a hint or a function call anywhere
// is classified too. Unknown statements, clauses, table factors and
// expressions refuse; nothing defaults to `sql_select`.

// An unquoted reserved keyword in a name or alias position is refused: the
// parser took it for a name where the server would start the next
// statement (`SELECT * FROM t checkpoint`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;

use sqlparser::ast::{
    AlterTableOperation, ColumnOption, Delete, Expr, ForClause, FromTable, Function, FunctionArg, FunctionArgExpr,
    FunctionArguments, Insert, Merge, MergeAction, ObjectName, ObjectNamePart, OutputClause, Query, RaisErrorOption,
    Select, SelectInto, SelectItem, Set, SetExpr, Statement, TableConstraint, TableFactor, TableObject, TableWithJoins,
    Update, Value, Visit, Visitor,
};

use super::functions::{self, FnClass};
use super::names::{raw_ident, reserved_ident, Names, Resolved};
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
}

type Flow = ControlFlow<Reason>;

fn brk<T>(r: Reason) -> ControlFlow<Reason, T> {
    ControlFlow::Break(r)
}

fn addr<T>(t: &T) -> usize {
    t as *const T as usize
}

fn ok<T>(r: Result<T, Reason>) -> ControlFlow<Reason, T> {
    match r {
        Ok(v) => ControlFlow::Continue(v),
        Err(e) => brk(e),
    }
}

/// Table hints that take or hold locks beyond a plain read (§4.2: lock
/// hints need `sql_update` too).
const LOCKING_HINTS: &[&str] =
    &["updlock", "xlock", "holdlock", "serializable", "repeatableread", "tablock", "tablockx"];

/// Table hints that change only how the read is done.
const READ_HINTS: &[&str] = &[
    "nolock",
    "readuncommitted",
    "readcommitted",
    "readcommittedlock",
    "readpast",
    "nowait",
    "rowlock",
    "paglock",
    "noexpand",
    "forceseek",
    "forcescan",
    "snapshot",
];

/// Reserved keywords the parser legitimately reads as an expression.
const RESERVED_EXPRESSIONS: &[&str] = &[
    "current_timestamp",
    "current_user",
    "session_user",
    "system_user",
    "user",
    "current_date",
    "current_time",
    "default",
    "null",
    "identitycol",
    "rowguidcol",
];

/// Classify one parsed statement.
pub(crate) fn analyze(stmt: &Statement, names: &Names<'_>) -> Result<Analysis, Reason> {
    let mut w = Walker::new(names, stmt);
    match stmt.visit(&mut w) {
        ControlFlow::Break(r) => Err(r),
        ControlFlow::Continue(()) => w.finish(),
    }
}

struct Walker<'n, 'c> {
    names: &'n Names<'c>,
    root: usize,
    /// The DML statement a root `WITH … {INSERT | UPDATE | DELETE | MERGE}`
    /// carries; the only nested statement accepted.
    dml_body: Option<usize>,
    kind: Option<Kind>,
    read_family: bool,
    required: Requirements,
    opaque: bool,
    /// Name nodes the statement table consumed as targets; not reads.
    excluded: HashSet<usize>,
    /// Expressions that are not expressions to the server (table hints,
    /// `OUTPUT INTO` targets): skipped by the expression rules.
    skipped: HashSet<usize>,
    /// Table names read under a locking hint.
    locked: HashSet<usize>,
    /// CTE names visible at each query level, as written.
    scopes: Vec<Vec<String>>,
    cte_scope: HashMap<usize, Vec<String>>,
}

impl<'n, 'c> Walker<'n, 'c> {
    fn new(names: &'n Names<'c>, root: &Statement) -> Self {
        let dml_body = match root {
            Statement::Query(q) if q.with.is_some() => match &*q.body {
                SetExpr::Insert(s) | SetExpr::Update(s) | SetExpr::Delete(s) | SetExpr::Merge(s) => Some(addr(s)),
                _ => None,
            },
            _ => None,
        };
        Self {
            names,
            root: addr(root),
            dml_body,
            kind: None,
            read_family: false,
            required: BTreeSet::new(),
            opaque: false,
            excluded: HashSet::new(),
            skipped: HashSet::new(),
            locked: HashSet::new(),
            scopes: Vec::new(),
            cte_scope: HashMap::new(),
        }
    }

    fn finish(mut self) -> Result<Analysis, Reason> {
        let kind = self.kind.ok_or(Reason::UnsupportedStatement)?;
        if self.read_family && self.required.is_empty() {
            self.required.insert((Cap::Select, SqlTarget::Server));
        }
        Ok(Analysis { kind, required: self.required, opaque: self.opaque, tx_control: false })
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

    fn is_cte(&self, name: &ObjectName) -> bool {
        let [ObjectNamePart::Identifier(id)] = name.0.as_slice() else { return false };
        self.scopes.last().is_some_and(|s| s.iter().any(|c| c.eq_ignore_ascii_case(&id.value)))
    }

    /// An existing relation; `None` for a table variable.
    fn relation(&self, name: &ObjectName) -> ControlFlow<Reason, Option<ObjectRef>> {
        match ok(self.names.object(ObjectKind::Relation, name))? {
            Resolved::Object(o) => ControlFlow::Continue(Some(o)),
            Resolved::Variable => ControlFlow::Continue(None),
        }
    }

    /// The target of a write: never a CTE (the write would reach the CTE's
    /// base tables, which the statement does not name).
    fn write_target(&mut self, name: &ObjectName) -> ControlFlow<Reason, Option<ObjectRef>> {
        if self.is_cte(name) {
            return brk(Reason::UnsupportedConstruct);
        }
        self.exclude(name);
        self.relation(name)
    }

    /// A stored or system function: `sql_execute` on it (SQL Server has no
    /// database-enforced read-only session, §5.3).
    fn stored_function(&mut self, r: ObjectRef) {
        if self.names.ctx.database_read_only {
            self.need_obj(Cap::Select, r);
        } else {
            self.need_obj(Cap::Execute, r);
            self.opaque = true;
        }
    }

    /// Code the table does not know: `sql_execute` on the server.
    fn unknown_function(&mut self) {
        self.need(Cap::Execute, SqlTarget::Server);
        self.opaque = true;
    }

    fn function_parts<'a>(&self, name: &'a ObjectName) -> ControlFlow<Reason, Vec<&'a str>> {
        let mut parts = Vec::new();
        for p in &name.0 {
            match p {
                ObjectNamePart::Identifier(id) => parts.push(ok(raw_ident(id))?),
                ObjectNamePart::Function(_) => return brk(Reason::UnresolvableName),
            }
        }
        ControlFlow::Continue(parts)
    }

    fn function(&mut self, name: &ObjectName, over: bool) -> Flow {
        let parts = self.function_parts(name)?;
        if parts.iter().any(|p| functions::always_refused(p)) {
            return brk(Reason::ServerFileOrOsAccess);
        }
        match parts.as_slice() {
            [f] => match functions::class(f) {
                FnClass::Pure => {}
                FnClass::Window if over => {}
                FnClass::Window | FnClass::Unknown => self.unknown_function(),
            },
            [s, _] | [_, s, _] if s.eq_ignore_ascii_case("sys") => self.unknown_function(),
            [_, _] | [_, _, _] => {
                let r = ok(self.names.existing(ObjectKind::Routine, &parts))?;
                self.stored_function(r);
            }
            [_, _, _, _] => return brk(Reason::ServerFileOrOsAccess),
            _ => return brk(Reason::UnresolvableName),
        }
        ControlFlow::Continue(())
    }

    fn call(&mut self, f: &Function) -> Flow {
        if f.uses_odbc_syntax || !matches!(f.parameters, FunctionArguments::None) || f.null_treatment.is_some() {
            return brk(Reason::UnsupportedConstruct);
        }
        self.function(&f.name, f.over.is_some())
    }

    fn foreign_key(&mut self, c: &TableConstraint) -> Flow {
        if let TableConstraint::ForeignKey(fk) = c {
            if let Some(r) = self.relation(&fk.foreign_table)? {
                // A foreign key constrains writes to the referenced table.
                self.need_obj(Cap::Alter, r);
            }
        }
        ControlFlow::Continue(())
    }

    fn column_foreign_keys(&mut self, options: &[sqlparser::ast::ColumnOptionDef]) -> Flow {
        for o in options {
            if let ColumnOption::ForeignKey(fk) = &o.option {
                if let Some(r) = self.relation(&fk.foreign_table)? {
                    self.need_obj(Cap::Alter, r);
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// `OUTPUT … [INTO target]`: the returned rows read the target; `INTO`
    /// inserts them into another table (DML hidden in the clause).
    fn output(&mut self, out: &Option<OutputClause>, target: &Option<ObjectRef>) -> Flow {
        match out {
            None => {}
            Some(OutputClause::Returning { .. }) => return brk(Reason::UnsupportedConstruct),
            Some(OutputClause::Output { into_table, .. }) => {
                if let Some(t) = target {
                    self.need_obj(Cap::Select, t.clone());
                }
                if let Some(into) = into_table {
                    self.output_into(into)?;
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn output_into(&mut self, into: &SelectInto) -> Flow {
        if into.temporary || into.unlogged || into.table || into.targets.len() != 1 {
            return brk(Reason::UnsupportedConstruct);
        }
        let target = &into.targets[0];
        self.skipped.insert(addr(target));
        let parts: Vec<&str> = match target {
            Expr::Identifier(id) => vec![ok(raw_ident(id))?],
            Expr::CompoundIdentifier(ids) => {
                let mut v = Vec::new();
                for id in ids {
                    v.push(ok(raw_ident(id))?);
                }
                v
            }
            // `INTO t (a, b)`: the parser reads a call; the name is the table.
            Expr::Function(f) => self.function_parts(&f.name)?,
            _ => return brk(Reason::UnsupportedConstruct),
        };
        if let Resolved::Object(o) = ok(self.names.resolve_raw(ObjectKind::Relation, &parts))? {
            self.need_obj(Cap::Insert, o);
        }
        ControlFlow::Continue(())
    }

    /// Every base table of a `FROM` list (joins and nested joins included),
    /// excluded from the read walk because the caller requires them. A
    /// derived table, CTE or function there may be what the statement
    /// writes through, so it is refused. Returns the aliases seen.
    fn base_tables(&mut self, from: &[TableWithJoins], out: &mut Vec<ObjectRef>, aliases: &mut Vec<String>) -> Flow {
        fn factor(
            w: &mut Walker<'_, '_>,
            tf: &TableFactor,
            out: &mut Vec<ObjectRef>,
            aliases: &mut Vec<String>,
        ) -> Flow {
            match tf {
                TableFactor::Table { name, args: None, alias, .. } => {
                    if w.is_cte(name) {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    w.exclude(name);
                    if let Some(o) = w.relation(name)? {
                        out.push(o);
                    }
                    if let Some(a) = alias {
                        aliases.push(a.name.value.clone());
                    }
                }
                TableFactor::NestedJoin { table_with_joins, alias: None } => {
                    w.base_tables(std::slice::from_ref(table_with_joins), out, aliases)?
                }
                _ => return brk(Reason::UnsupportedConstruct),
            }
            ControlFlow::Continue(())
        }
        for twj in from {
            factor(self, &twj.relation, out, aliases)?;
            for j in &twj.joins {
                factor(self, &j.relation, out, aliases)?;
            }
        }
        ControlFlow::Continue(())
    }

    fn insert(&mut self, ins: &Insert) -> ControlFlow<Reason, Kind> {
        if ins.or.is_some()
            || ins.ignore
            || ins.overwrite
            || ins.partitioned.is_some()
            || !ins.after_columns.is_empty()
            || ins.settings.is_some()
            || ins.format_clause.is_some()
            || ins.multi_table_insert_type.is_some()
            || !ins.multi_table_into_clauses.is_empty()
            || !ins.multi_table_when_clauses.is_empty()
            || ins.multi_table_else_clause.is_some()
            || ins.has_table_keyword
            || ins.table_alias.is_some()
            || !ins.optimizer_hints.is_empty()
            || ins.on.is_some()
            || ins.returning.is_some()
        {
            return brk(Reason::UnsupportedConstruct);
        }
        let TableObject::TableName(target) = &ins.table else { return brk(Reason::UnsupportedConstruct) };
        let t = self.write_target(target)?;
        if let Some(t) = &t {
            self.need_obj(Cap::Insert, t.clone());
        }
        self.output(&ins.output, &t)?;
        ControlFlow::Continue(Kind::Insert)
    }

    fn update(&mut self, up: &Update) -> ControlFlow<Reason, Kind> {
        if up.or.is_some() || !up.optimizer_hints.is_empty() || up.returning.is_some() || up.limit.is_some() {
            return brk(Reason::UnsupportedConstruct);
        }
        if up.from.is_none() && up.table.joins.is_empty() {
            let TableFactor::Table { name, args: None, with_hints, .. } = &up.table.relation else {
                return brk(Reason::UnsupportedConstruct);
            };
            if !with_hints.is_empty() {
                return brk(Reason::UnsupportedConstruct);
            }
            let t = self.write_target(name)?;
            if let Some(t) = &t {
                self.need_obj(Cap::Update, t.clone());
                let reads = up.selection.is_some()
                    || up.output.is_some()
                    || !up.order_by.is_empty()
                    || up.assignments.iter().any(|a| !matches!(a.value, Expr::Value(_)));
                if reads {
                    self.need_obj(Cap::Select, t.clone());
                }
            }
            self.output(&up.output, &t)?;
            return ControlFlow::Continue(Kind::Update);
        }
        // `UPDATE x SET … FROM t AS x JOIN u …`: which table the SET writes
        // is decided by aliases. Every joined table is checked for update
        // and read (more, never less).
        if !up.order_by.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let mut tables = Vec::new();
        let mut aliases = Vec::new();
        if let Some(from) = &up.from {
            let (sqlparser::ast::UpdateTableFromKind::BeforeSet(f) | sqlparser::ast::UpdateTableFromKind::AfterSet(f)) =
                from;
            self.base_tables(f, &mut tables, &mut aliases)?;
        }
        let target_is_alias = matches!(&up.table.relation, TableFactor::Table { name, args: None, alias: None, .. }
            if up.table.joins.is_empty()
                && matches!(name.0.as_slice(), [ObjectNamePart::Identifier(id)]
                    if aliases.iter().any(|a| a.eq_ignore_ascii_case(&id.value))));
        if target_is_alias {
            if let TableFactor::Table { name, .. } = &up.table.relation {
                self.exclude(name);
            }
        } else {
            self.base_tables(std::slice::from_ref(&up.table), &mut tables, &mut aliases)?;
        }
        for t in &tables {
            self.need_obj(Cap::Update, t.clone());
            self.need_obj(Cap::Select, t.clone());
        }
        // OUTPUT reads what the join wrote; every table is read already.
        self.output(&up.output, &None)?;
        ControlFlow::Continue(Kind::Update)
    }

    fn delete(&mut self, d: &Delete) -> ControlFlow<Reason, Kind> {
        if !d.optimizer_hints.is_empty() || d.returning.is_some() || d.using.is_some() || d.limit.is_some() {
            return brk(Reason::UnsupportedConstruct);
        }
        let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) = &d.from;
        let single = d.tables.is_empty()
            && matches!(from.as_slice(), [twj] if twj.joins.is_empty()
                && matches!(twj.relation, TableFactor::Table { args: None, .. }));
        if single {
            let TableFactor::Table { name, with_hints, .. } = &from[0].relation else {
                return brk(Reason::UnsupportedConstruct);
            };
            if !with_hints.is_empty() {
                return brk(Reason::UnsupportedConstruct);
            }
            let t = self.write_target(name)?;
            if let Some(t) = &t {
                self.need_obj(Cap::Delete, t.clone());
                if d.selection.is_some() || d.output.is_some() || !d.order_by.is_empty() {
                    self.need_obj(Cap::Select, t.clone());
                }
            }
            self.output(&d.output, &t)?;
            return ControlFlow::Continue(Kind::Delete);
        }
        // `DELETE x FROM t AS x JOIN u …`: the target may be an alias. Every
        // table of FROM is checked for delete and read.
        if !d.order_by.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let mut tables = Vec::new();
        let mut aliases = Vec::new();
        self.base_tables(from, &mut tables, &mut aliases)?;
        for n in &d.tables {
            let alias = matches!(n.0.as_slice(), [ObjectNamePart::Identifier(id)]
                if aliases.iter().any(|a| a.eq_ignore_ascii_case(&id.value)));
            if alias {
                self.exclude(n);
            } else if let Some(t) = self.write_target(n)? {
                tables.push(t);
            }
        }
        if tables.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        for t in &tables {
            self.need_obj(Cap::Delete, t.clone());
            self.need_obj(Cap::Select, t.clone());
        }
        self.output(&d.output, &None)?;
        ControlFlow::Continue(Kind::Delete)
    }

    fn merge(&mut self, m: &Merge) -> ControlFlow<Reason, Kind> {
        if !m.optimizer_hints.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let TableFactor::Table { name, args: None, with_hints, .. } = &m.table else {
            return brk(Reason::UnsupportedConstruct);
        };
        if !with_hints.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let t = self.write_target(name)?;
        if let Some(t) = &t {
            // MERGE reads the target to match it.
            self.need_obj(Cap::Select, t.clone());
            for c in &m.clauses {
                let cap = match c.action {
                    MergeAction::Insert(_) => Cap::Insert,
                    MergeAction::Update(_) => Cap::Update,
                    MergeAction::Delete { .. } => Cap::Delete,
                    MergeAction::DoNothing { .. } => return brk(Reason::UnsupportedConstruct),
                };
                self.need_obj(cap, t.clone());
            }
        }
        self.output(&m.output, &t)?;
        ControlFlow::Continue(Kind::Merge)
    }

    /// The statement table: each statement's own targets.
    fn primary(&mut self, s: &Statement) -> ControlFlow<Reason, Kind> {
        use ObjectKind as K;
        let kind = match s {
            Statement::Query(q) => match &*q.body {
                // `WITH … DML`: the DML body is the statement.
                SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_) => {
                    return ControlFlow::Continue(Kind::Select)
                }
                body => {
                    self.read_family = true;
                    query_kind(body)
                }
            },
            Statement::Insert(ins) => self.insert(ins)?,
            Statement::Update(up) => self.update(up)?,
            Statement::Delete(d) => self.delete(d)?,
            Statement::Merge(m) => self.merge(m)?,
            Statement::CreateTable(ct) => {
                if ct.external
                    || ct.global.is_some()
                    || ct.dynamic
                    || ct.iceberg
                    || ct.snapshot
                    || ct.transient
                    || ct.volatile
                    || ct.without_rowid
                    || ct.strict
                    || ct.copy_grants
                    || ct.or_replace
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
                    || ct.inherits.is_some()
                    || ct.partition_of.is_some()
                    || ct.like.is_some()
                    || ct.query.is_some()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ct.name);
                let parts = ok(self.names.raw_parts(&ct.name))?;
                let t = ok(self.names.new_object(K::Relation, &parts))?;
                self.need_obj(Cap::Create, t);
                for c in &ct.columns {
                    self.column_foreign_keys(&c.options)?;
                }
                for c in &ct.constraints {
                    self.foreign_key(c)?;
                }
                Kind::CreateTable
            }
            Statement::CreateView(cv) => {
                if cv.secure || cv.to.is_some() || cv.copy_grants || cv.with_no_schema_binding || cv.materialized {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&cv.name);
                let parts = ok(self.names.raw_parts(&cv.name))?;
                let v = ok(self.names.new_object(K::Relation, &parts))?;
                self.need_obj(Cap::Create, v.clone());
                if cv.or_replace || cv.or_alter {
                    self.need_obj(Cap::Alter, v);
                }
                // The view's query is walked: its creator must be able to
                // read what it exposes, or the view would launder access.
                Kind::CreateView
            }
            Statement::CreateIndex(ci) => {
                if ci.r#async {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ci.table_name);
                let t = self.relation(&ci.table_name)?.ok_or(Reason::UnsupportedConstruct);
                self.need_obj(Cap::Create, ok(t)?);
                Kind::CreateIndex
            }
            Statement::AlterTable(at) => {
                if at.location.is_some() || at.on_cluster.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&at.name);
                let t = ok(self.relation(&at.name)?.ok_or(Reason::UnsupportedConstruct))?;
                self.need_obj(Cap::Alter, t);
                for op in &at.operations {
                    match op {
                        AlterTableOperation::AddConstraint { constraint, .. } => self.foreign_key(constraint)?,
                        AlterTableOperation::AddColumn { column_def, .. } => {
                            self.column_foreign_keys(&column_def.options)?
                        }
                        AlterTableOperation::DropConstraint { .. }
                        | AlterTableOperation::DropColumn { .. }
                        | AlterTableOperation::DropPrimaryKey { .. }
                        | AlterTableOperation::DropForeignKey { .. }
                        | AlterTableOperation::AlterColumn { .. }
                        | AlterTableOperation::EnableTrigger { .. }
                        | AlterTableOperation::DisableTrigger { .. } => {}
                        _ => return brk(Reason::UnsupportedConstruct),
                    }
                }
                Kind::Alter
            }
            Statement::AlterView { name, .. } => {
                self.exclude(name);
                let v = ok(self.relation(name)?.ok_or(Reason::UnsupportedConstruct))?;
                self.need_obj(Cap::Alter, v);
                Kind::Alter
            }
            Statement::Set(set) => {
                // Only variables reach the parser (options are read from
                // tokens first, fallback.rs).
                let targets: Vec<&ObjectName> = match set {
                    Set::SingleAssignment { scope: None, hivevar: false, variable, .. } => vec![variable],
                    _ => return brk(Reason::UnsupportedConstruct),
                };
                for n in targets {
                    self.exclude(n);
                    let var = matches!(n.0.as_slice(), [ObjectNamePart::Identifier(id)]
                        if id.quote_style.is_none() && id.value.starts_with('@') && !id.value.starts_with("@@"));
                    if !var {
                        return brk(Reason::UnsupportedConstruct);
                    }
                }
                self.need(Cap::Select, SqlTarget::Server);
                Kind::SetSession
            }
            Statement::Declare { stmts } => {
                let mut kind = Kind::Declare;
                for d in stmts {
                    if d.binary.is_some() || d.hold.is_some() {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    match d.declare_type {
                        None => {}
                        Some(sqlparser::ast::DeclareType::Cursor) => kind = Kind::DeclareCursor,
                        Some(_) => return brk(Reason::UnsupportedConstruct),
                    }
                    if let Some(sqlparser::ast::DeclareAssignment::DuckAssignment(_)) = d.assignment {
                        return brk(Reason::UnsupportedConstruct);
                    }
                }
                self.read_family = true;
                kind
            }
            Statement::Print(_) | Statement::Throw(_) => {
                self.read_family = true;
                Kind::Message
            }
            Statement::RaisError { options, .. } => {
                self.read_family = true;
                if options.iter().any(|o| matches!(o, RaisErrorOption::Log)) {
                    // Writes to the server's error log.
                    self.need(Cap::Admin, SqlTarget::Server);
                }
                Kind::Message
            }
            Statement::WaitFor(_) => {
                self.read_family = true;
                Kind::WaitFor
            }
            _ => return brk(Reason::UnsupportedStatement),
        };
        ControlFlow::Continue(kind)
    }

    fn check_alias(&self, alias: &Option<sqlparser::ast::TableAlias>) -> Flow {
        if let Some(a) = alias {
            if reserved_ident(&a.name) {
                return brk(Reason::ReservedWordAsName);
            }
        }
        ControlFlow::Continue(())
    }
}

fn query_kind(body: &SetExpr) -> Kind {
    match body {
        SetExpr::Values(_) => Kind::Values,
        SetExpr::Insert(_) => Kind::Insert,
        SetExpr::Update(_) => Kind::Update,
        SetExpr::Delete(_) => Kind::Delete,
        SetExpr::Merge(_) => Kind::Merge,
        SetExpr::Query(q) => query_kind(&q.body),
        SetExpr::Select(s) if s.into.is_some() => Kind::SelectInto,
        SetExpr::Select(_) | SetExpr::SetOperation { .. } | SetExpr::Table(_) => Kind::Select,
    }
}

/// Whether a table function's arguments are the legacy hint form
/// `FROM t (NOLOCK)`, which the parser reads as a function call.
fn legacy_hints(args: &[FunctionArg]) -> bool {
    args.iter().any(|a| {
        matches!(a, FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(id)))
        if id.quote_style.is_none() && {
            let w = id.value.to_ascii_lowercase();
            LOCKING_HINTS.contains(&w.as_str()) || READ_HINTS.contains(&w.as_str())
        })
    })
}

impl Visitor for Walker<'_, '_> {
    type Break = Reason;

    fn pre_visit_statement(&mut self, s: &Statement) -> Flow {
        let a = addr(s);
        if a == self.root {
            let kind = self.primary(s)?;
            self.kind = Some(kind);
            return ControlFlow::Continue(());
        }
        if Some(a) == self.dml_body {
            let kind = self.primary(s)?;
            self.kind = Some(kind);
            return ControlFlow::Continue(());
        }
        // Any other statement nested in one: refused rather than read.
        brk(Reason::UnsupportedConstruct)
    }

    fn pre_visit_query(&mut self, q: &Query) -> Flow {
        if q.settings.is_some() || q.format_clause.is_some() || !q.pipe_operators.is_empty() || !q.locks.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        if matches!(q.for_clause, Some(ForClause::Browse)) {
            return brk(Reason::UnsupportedConstruct);
        }
        let dml_body =
            matches!(&*q.body, SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_));
        let is_root_query = self.dml_body.is_some() && dml_body;
        if matches!(*q.body, SetExpr::Table(_)) || (dml_body && !is_root_query) {
            return brk(Reason::UnsupportedConstruct);
        }
        let mut visible = match self.cte_scope.remove(&addr(q)) {
            Some(s) => s,
            None => self.scopes.last().cloned().unwrap_or_default(),
        };
        if let Some(with) = &q.with {
            let mut cte_names = Vec::with_capacity(with.cte_tables.len());
            for cte in &with.cte_tables {
                if cte.from.is_some() || cte.materialized.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                if reserved_ident(&cte.alias.name) {
                    return brk(Reason::ReservedWordAsName);
                }
                cte_names.push(cte.alias.name.value.clone());
            }
            for (i, cte) in with.cte_tables.iter().enumerate() {
                // A T-SQL CTE sees the ones before it and itself (recursion
                // needs no keyword); a later name is the real table.
                let mut scope = visible.clone();
                scope.extend(cte_names[..=i].iter().cloned());
                self.cte_scope.insert(addr(&*cte.query), scope);
            }
            visible.extend(cte_names);
        }
        self.scopes.push(visible);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _q: &Query) -> Flow {
        self.scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> Flow {
        if s.exclude.is_some()
            || !s.lateral_views.is_empty()
            || s.prewhere.is_some()
            || !s.connect_by.is_empty()
            || !s.cluster_by.is_empty()
            || !s.distribute_by.is_empty()
            || !s.sort_by.is_empty()
            || s.qualify.is_some()
            || s.value_table_mode.is_some()
            || s.flavor != sqlparser::ast::SelectFlavor::Standard
            || !s.optimizer_hints.is_empty()
        {
            return brk(Reason::UnsupportedConstruct);
        }
        for item in &s.projection {
            if let SelectItem::ExprWithAlias { alias, .. } = item {
                if reserved_ident(alias) {
                    return brk(Reason::ReservedWordAsName);
                }
            }
        }
        if let Some(into) = &s.into {
            // `SELECT … INTO new_table`: creates and fills it (§4.2).
            if into.temporary || into.unlogged || into.table || into.targets.len() != 1 {
                return brk(Reason::UnsupportedConstruct);
            }
            let target = &into.targets[0];
            self.skipped.insert(addr(target));
            let ids: Vec<&sqlparser::ast::Ident> = match target {
                Expr::Identifier(id) => vec![id],
                Expr::CompoundIdentifier(ids) => ids.iter().collect(),
                _ => return brk(Reason::UnsupportedConstruct),
            };
            let mut parts = Vec::with_capacity(ids.len());
            for id in ids {
                if reserved_ident(id) {
                    return brk(Reason::ReservedWordAsName);
                }
                parts.push(ok(raw_ident(id))?);
            }
            let t = ok(self.names.new_object(ObjectKind::Relation, &parts))?;
            self.need_obj(Cap::Create, t.clone());
            self.need_obj(Cap::Insert, t);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, name: &ObjectName) -> Flow {
        if self.excluded.contains(&addr(name)) || self.is_cte(name) {
            return ControlFlow::Continue(());
        }
        if let Some(r) = self.relation(name)? {
            if self.locked.contains(&addr(name)) {
                self.need_obj(Cap::Update, r.clone());
            }
            self.need_obj(Cap::Select, r);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> Flow {
        match tf {
            TableFactor::Table {
                name,
                alias,
                args,
                with_hints,
                version,
                json_path,
                sample,
                partitions,
                index_hints,
                with_ordinality,
            } => {
                if version.is_some()
                    || json_path.is_some()
                    || sample.is_some()
                    || !partitions.is_empty()
                    || !index_hints.is_empty()
                    || *with_ordinality
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.check_alias(alias)?;
                let mut locking = false;
                for h in with_hints {
                    self.skipped.insert(addr(h));
                    let word = match h {
                        Expr::Identifier(id) if id.quote_style.is_none() => id.value.to_ascii_lowercase(),
                        // INDEX (i) / INDEX = i: which index to use.
                        Expr::Function(f) if matches!(f.name.0.as_slice(), [ObjectNamePart::Identifier(id)] if id.value.eq_ignore_ascii_case("index")) => {
                            continue
                        }
                        _ => return brk(Reason::UnsupportedConstruct),
                    };
                    if LOCKING_HINTS.contains(&word.as_str()) {
                        locking = true;
                    } else if !READ_HINTS.contains(&word.as_str()) {
                        return brk(Reason::UnsupportedConstruct);
                    }
                }
                if locking {
                    self.locked.insert(addr(name));
                }
                if let Some(a) = args {
                    if a.settings.is_some() || legacy_hints(&a.args) {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    // A table-valued function: its rows are read, and its
                    // code runs (`sql_execute`), unless it is a reviewed
                    // built-in.
                    self.exclude(name);
                    let parts = self.function_parts(name)?;
                    if parts.iter().any(|p| functions::always_refused(p)) {
                        return brk(Reason::ServerFileOrOsAccess);
                    }
                    match parts.as_slice() {
                        [f] if functions::pure_table_function(f) => {}
                        [s, _] | [_, s, _] if s.eq_ignore_ascii_case("sys") => self.unknown_function(),
                        _ => {
                            let r = ok(self.names.existing(ObjectKind::Routine, &parts))?;
                            self.need_obj(Cap::Select, r.clone());
                            self.stored_function(r);
                        }
                    }
                }
            }
            TableFactor::Derived { alias, .. } | TableFactor::NestedJoin { alias, .. } => self.check_alias(alias)?,
            TableFactor::OpenJsonTable { alias, .. } => self.check_alias(alias)?,
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> Flow {
        if self.skipped.contains(&addr(e)) {
            return ControlFlow::Continue(());
        }
        let reserved_name = |id: &sqlparser::ast::Ident| {
            reserved_ident(id) && !RESERVED_EXPRESSIONS.contains(&id.value.to_ascii_lowercase().as_str())
        };
        match e {
            Expr::Function(f) => self.call(f)?,
            Expr::Identifier(id) => {
                if reserved_name(id) {
                    return brk(Reason::ReservedWordAsName);
                }
            }
            Expr::CompoundIdentifier(ids) => {
                if ids.iter().any(reserved_name) {
                    return brk(Reason::ReservedWordAsName);
                }
                if ids.len() > 4 {
                    return brk(Reason::UnresolvableName);
                }
            }
            Expr::BinaryOp { op, .. } => {
                if matches!(
                    op,
                    sqlparser::ast::BinaryOperator::Custom(_)
                        | sqlparser::ast::BinaryOperator::PGCustomBinaryOperator(_)
                ) {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
            Expr::Value(v) => {
                if let Value::Placeholder(p) = &v.value {
                    // `$12.50` money and the `$action` / `$identity` /
                    // `$rowguid` pseudo-columns; never a bind placeholder.
                    let rest = p.strip_prefix('$').unwrap_or("");
                    let money = !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.');
                    let pseudo = matches!(rest.to_ascii_lowercase().as_str(), "action" | "identity" | "rowguid");
                    if !(money || pseudo) {
                        return brk(Reason::UnsupportedConstruct);
                    }
                }
            }
            Expr::UnaryOp { .. }
            | Expr::Like { .. }
            | Expr::Between { .. }
            | Expr::InList { .. }
            | Expr::InSubquery { .. }
            | Expr::IsDistinctFrom(..)
            | Expr::IsNotDistinctFrom(..)
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::Cast { .. }
            | Expr::Convert { .. }
            | Expr::AtTimeZone { .. }
            | Expr::Ceil { .. }
            | Expr::Floor { .. }
            | Expr::Substring { .. }
            | Expr::Trim { .. }
            | Expr::Collate { .. }
            | Expr::Nested(_)
            | Expr::Case { .. }
            | Expr::Exists { .. }
            | Expr::Subquery(_)
            | Expr::Wildcard(_)
            | Expr::QualifiedWildcard(..) => {}
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }
}
