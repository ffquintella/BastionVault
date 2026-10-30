//! Statement → required privileges, MySQL / MariaDB (§4.2, §4.3), for the
//! statements the parser reads: queries, `INSERT` / `REPLACE`, `UPDATE`,
//! `DELETE` (single- and multi-table), `EXPLAIN`, `CALL`, `CREATE TABLE /
//! VIEW / INDEX`, `ALTER TABLE / VIEW` and `SET` of user variables.

// The statement table decides each statement's own targets; a full AST walk
// then visits every node, so a subquery or a function call anywhere is
// classified too. Unknown statements, clauses, table factors and
// expressions refuse; nothing defaults to `sql_select`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;

use sqlparser::ast::{
    AlterTableOperation, ColumnOption, DescribeAlias, Expr, FromTable, Function, FunctionArg, FunctionArgExpr,
    FunctionArguments, ObjectName, ObjectNamePart, OnInsert, Query, Select, Set, SetExpr, Statement, TableConstraint,
    TableFactor, TableObject, TableWithJoins, Value, Visit, Visitor,
};

use super::functions::{self, FnClass};
use super::names::{raw_ident, Names};
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

/// Classify one parsed statement.
pub(crate) fn analyze(stmt: &Statement, names: &Names<'_>) -> Result<Analysis, Reason> {
    if let Statement::Explain {
        describe_alias,
        analyze: explain_analyze,
        query_plan,
        estimate,
        statement,
        options,
        ..
    } = stmt
    {
        if !matches!(describe_alias, DescribeAlias::Explain | DescribeAlias::Describe | DescribeAlias::Desc)
            || *query_plan
            || *estimate
            || options.is_some()
        {
            return Err(Reason::UnsupportedStatement);
        }
        let inner = analyze(statement, names)?;
        if inner.tx_control || !matches!(inner.kind, Kind::Select | Kind::Insert | Kind::Update | Kind::Delete) {
            return Err(Reason::UnsupportedStatement);
        }
        if *explain_analyze {
            // EXPLAIN ANALYZE runs the statement (MySQL 8.0.18+).
            return Ok(Analysis { kind: Kind::ExplainAnalyze, ..inner });
        }
        // Plan only: the plan reveals every object the statement touches.
        let mut a = Analysis::new(Kind::Explain);
        for (cap, target) in inner.required {
            let cap = if cap == Cap::Execute { Cap::Execute } else { Cap::Select };
            a.opaque |= cap == Cap::Execute;
            a.required.insert((cap, target));
        }
        if a.required.is_empty() {
            a.required.insert((Cap::Select, SqlTarget::Server));
        }
        return Ok(a);
    }
    let mut w = Walker::new(names, stmt);
    match stmt.visit(&mut w) {
        ControlFlow::Break(r) => Err(r),
        ControlFlow::Continue(()) => w.finish(),
    }
}

struct Walker<'n, 'c> {
    names: &'n Names<'c>,
    root: usize,
    kind: Option<Kind>,
    read_family: bool,
    required: Requirements,
    opaque: bool,
    /// Name nodes the statement table consumed as targets; not reads.
    excluded: HashSet<usize>,
    /// CTE names visible at each query level, as written (exact match only:
    /// a reference spelled differently is read as the table, which asks for
    /// more, never less).
    scopes: Vec<Vec<String>>,
    cte_scope: HashMap<usize, Vec<String>>,
    /// Per query level: whether it takes row locks.
    locks: Vec<bool>,
}

impl<'n, 'c> Walker<'n, 'c> {
    fn new(names: &'n Names<'c>, root: &Statement) -> Self {
        Self {
            names,
            root: addr(root),
            kind: None,
            read_family: false,
            required: BTreeSet::new(),
            opaque: false,
            excluded: HashSet::new(),
            scopes: Vec::new(),
            cte_scope: HashMap::new(),
            locks: Vec::new(),
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

    fn object(&self, kind: ObjectKind, name: &ObjectName) -> ControlFlow<Reason, ObjectRef> {
        ok(self.names.object(kind, name))
    }

    fn is_cte(&self, name: &ObjectName) -> bool {
        let [ObjectNamePart::Identifier(id)] = name.0.as_slice() else { return false };
        self.scopes.last().is_some_and(|s| s.contains(&id.value))
    }

    fn lock_level(&self) -> bool {
        self.locks.iter().any(|&l| l)
    }

    fn read(&mut self, obj: ObjectRef) {
        if self.lock_level() {
            self.need_obj(Cap::Update, obj.clone());
        }
        self.need_obj(Cap::Select, obj);
    }

    /// A stored routine named with its database: `sql_execute` on it, or
    /// `sql_select` when the database keeps the session read-only (§4.2).
    fn stored_function(&mut self, r: ObjectRef) {
        if self.names.ctx.database_read_only {
            self.need_obj(Cap::Select, r);
        } else {
            self.need_obj(Cap::Execute, r);
            self.opaque = true;
        }
    }

    /// An unqualified name the table does not know: a loadable (native)
    /// function or a stored function of the current database. Native code
    /// can do anything, so this is never downgraded in a read-only session.
    fn unknown_function(&mut self) {
        self.need(Cap::Execute, SqlTarget::Server);
        self.opaque = true;
    }

    fn sequence_arg(&self, args: &[FunctionArg]) -> ControlFlow<Reason, ObjectRef> {
        let parts: Vec<&str> = match args.first() {
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(id)))) => vec![ok(raw_ident(id))?],
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::CompoundIdentifier(ids)))) => {
                let mut v = Vec::new();
                for id in ids {
                    v.push(ok(raw_ident(id))?);
                }
                v
            }
            // A sequence chosen at run time cannot be checked.
            _ => return brk(Reason::UnresolvableName),
        };
        ok(self.names.resolve_raw(ObjectKind::Sequence, &parts))
    }

    fn function(&mut self, name: &ObjectName, args: &[FunctionArg], over: bool) -> Flow {
        let mut parts = Vec::new();
        for p in &name.0 {
            match p {
                ObjectNamePart::Identifier(id) => parts.push(ok(raw_ident(id))?),
                ObjectNamePart::Function(_) => return brk(Reason::UnresolvableName),
            }
        }
        match parts.as_slice() {
            [f] => {
                if functions::always_refused(f) {
                    return brk(Reason::ServerFileOrOsAccess);
                }
                match functions::class(f, self.names.mariadb) {
                    FnClass::Pure => {}
                    FnClass::Window if over => {}
                    FnClass::Window | FnClass::Unknown => self.unknown_function(),
                    FnClass::Admin => self.need(Cap::Admin, SqlTarget::Server),
                    FnClass::AdvisoryLock => self.need(Cap::Update, SqlTarget::Server),
                    FnClass::SequenceWrite => {
                        let s = self.sequence_arg(args)?;
                        self.need_obj(Cap::Update, s);
                    }
                    FnClass::SequenceRead => {
                        let s = self.sequence_arg(args)?;
                        self.need_obj(Cap::Select, s);
                    }
                }
            }
            [_, f] => {
                if functions::always_refused(f) {
                    return brk(Reason::ServerFileOrOsAccess);
                }
                let r = ok(self.names.resolve_raw(ObjectKind::Routine, &parts))?;
                self.stored_function(r);
            }
            _ => return brk(Reason::UnresolvableName),
        }
        ControlFlow::Continue(())
    }

    fn call(&mut self, f: &Function) -> Flow {
        if f.uses_odbc_syntax || !matches!(f.parameters, FunctionArguments::None) {
            return brk(Reason::UnsupportedConstruct);
        }
        let over = f.over.is_some();
        match &f.args {
            FunctionArguments::List(l) => self.function(&f.name, &l.args, over),
            FunctionArguments::None | FunctionArguments::Subquery(_) => self.function(&f.name, &[], over),
        }
    }

    fn foreign_key(&mut self, c: &TableConstraint) -> Flow {
        if let TableConstraint::ForeignKey(fk) = c {
            let r = self.object(ObjectKind::Relation, &fk.foreign_table)?;
            // A foreign key constrains writes to the referenced table.
            self.need_obj(Cap::Alter, r);
        }
        ControlFlow::Continue(())
    }

    fn column_foreign_keys(&mut self, options: &[sqlparser::ast::ColumnOptionDef]) -> Flow {
        for o in options {
            if let ColumnOption::ForeignKey(fk) = &o.option {
                let r = self.object(ObjectKind::Relation, &fk.foreign_table)?;
                self.need_obj(Cap::Alter, r);
            }
        }
        ControlFlow::Continue(())
    }

    /// Every base table of a `FROM` list (joins and nested joins included),
    /// excluded from the read walk because the caller requires them itself.
    fn base_tables(&mut self, from: &[TableWithJoins], out: &mut Vec<ObjectRef>) -> Flow {
        fn factor(w: &mut Walker<'_, '_>, tf: &TableFactor, out: &mut Vec<ObjectRef>) -> Flow {
            match tf {
                TableFactor::Table { name, args: None, .. } => {
                    w.exclude(name);
                    out.push(w.object(ObjectKind::Relation, name)?);
                }
                TableFactor::NestedJoin { table_with_joins, .. } => {
                    w.base_tables(std::slice::from_ref(table_with_joins), out)?
                }
                // A derived table is read through the normal walk.
                TableFactor::Derived { .. } => {}
                _ => return brk(Reason::UnsupportedConstruct),
            }
            ControlFlow::Continue(())
        }
        for twj in from {
            factor(self, &twj.relation, out)?;
            for j in &twj.joins {
                factor(self, &j.relation, out)?;
            }
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
        let kind = match s {
            Statement::Query(q) => {
                self.read_family = true;
                query_kind(&q.body)
            }
            Statement::Insert(ins) => {
                if ins.or.is_some()
                    || ins.overwrite
                    || ins.partitioned.is_some()
                    || !ins.after_columns.is_empty()
                    || ins.output.is_some()
                    || ins.settings.is_some()
                    || ins.format_clause.is_some()
                    || ins.multi_table_insert_type.is_some()
                    || !ins.multi_table_into_clauses.is_empty()
                    || !ins.multi_table_when_clauses.is_empty()
                    || ins.multi_table_else_clause.is_some()
                    || ins.has_table_keyword
                    || ins.table_alias.is_some()
                    || !ins.optimizer_hints.is_empty()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                let TableObject::TableName(target) = &ins.table else { return brk(Reason::UnsupportedConstruct) };
                self.exclude(target);
                let t = self.object(K::Relation, target)?;
                self.need_obj(Cap::Insert, t.clone());
                if ins.replace_into {
                    // REPLACE deletes the row it collides with.
                    self.need_obj(Cap::Delete, t.clone());
                }
                if ins.returning.is_some() {
                    self.need_obj(Cap::Select, t.clone());
                }
                match &ins.on {
                    None => {}
                    Some(OnInsert::DuplicateKeyUpdate(_)) => {
                        // The update reads the existing row.
                        self.need_obj(Cap::Select, t.clone());
                        self.need_obj(Cap::Update, t);
                    }
                    Some(_) => return brk(Reason::UnsupportedConstruct),
                }
                Kind::Insert
            }
            Statement::Update(up) => {
                if up.or.is_some() || up.output.is_some() || !up.optimizer_hints.is_empty() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let single = up.table.joins.is_empty()
                    && up.from.is_none()
                    && matches!(up.table.relation, TableFactor::Table { args: None, .. });
                if single {
                    let TableFactor::Table { name, .. } = &up.table.relation else {
                        return brk(Reason::UnsupportedConstruct);
                    };
                    self.exclude(name);
                    let t = self.object(K::Relation, name)?;
                    self.need_obj(Cap::Update, t.clone());
                    let reads = up.selection.is_some()
                        || up.returning.is_some()
                        || !up.order_by.is_empty()
                        || up.assignments.iter().any(|a| !matches!(a.value, Expr::Value(_)));
                    if reads {
                        self.need_obj(Cap::Select, t);
                    }
                } else {
                    // Multi-table UPDATE: which tables the SET list writes is
                    // decided by column qualifiers and aliases. Every joined
                    // table is checked for update and read (more, never less).
                    if !up.order_by.is_empty() || up.limit.is_some() {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    let mut tables = Vec::new();
                    self.base_tables(std::slice::from_ref(&up.table), &mut tables)?;
                    if let Some(from) = &up.from {
                        let (sqlparser::ast::UpdateTableFromKind::BeforeSet(f)
                        | sqlparser::ast::UpdateTableFromKind::AfterSet(f)) = from;
                        self.base_tables(f, &mut tables)?;
                    }
                    for t in tables {
                        self.need_obj(Cap::Update, t.clone());
                        self.need_obj(Cap::Select, t);
                    }
                }
                Kind::Update
            }
            Statement::Delete(d) => {
                if d.output.is_some() || !d.optimizer_hints.is_empty() {
                    return brk(Reason::UnsupportedConstruct);
                }
                let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) = &d.from;
                let single = d.tables.is_empty()
                    && d.using.is_none()
                    && matches!(from.as_slice(), [twj] if twj.joins.is_empty()
                        && matches!(twj.relation, TableFactor::Table { args: None, .. }));
                if single {
                    let TableFactor::Table { name, .. } = &from[0].relation else {
                        return brk(Reason::UnsupportedConstruct);
                    };
                    self.exclude(name);
                    let t = self.object(K::Relation, name)?;
                    self.need_obj(Cap::Delete, t.clone());
                    if d.selection.is_some() || d.returning.is_some() || !d.order_by.is_empty() {
                        self.need_obj(Cap::Select, t);
                    }
                } else {
                    // Multi-table DELETE: the targets may be aliases. Every
                    // table of FROM and USING is checked for delete and read.
                    if !d.order_by.is_empty() || d.limit.is_some() || d.returning.is_some() {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    for n in &d.tables {
                        self.exclude(n);
                    }
                    let mut tables = Vec::new();
                    self.base_tables(from, &mut tables)?;
                    if let Some(using) = &d.using {
                        self.base_tables(using, &mut tables)?;
                    }
                    if tables.is_empty() {
                        return brk(Reason::UnsupportedConstruct);
                    }
                    for t in tables {
                        self.need_obj(Cap::Delete, t.clone());
                        self.need_obj(Cap::Select, t);
                    }
                }
                Kind::Delete
            }
            Statement::Call(f) => {
                if f.uses_odbc_syntax || !matches!(f.parameters, FunctionArguments::None) {
                    return brk(Reason::UnsupportedConstruct);
                }
                let r = self.object(K::Routine, &f.name)?;
                self.need_obj(Cap::Execute, r);
                self.opaque = true;
                Kind::Call
            }
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
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ct.name);
                let t = self.object(K::Relation, &ct.name)?;
                self.need_obj(Cap::Create, t.clone());
                if ct.or_replace {
                    // MariaDB CREATE OR REPLACE TABLE drops the old table.
                    self.need_obj(Cap::Drop, t.clone());
                }
                if ct.query.is_some() {
                    self.need_obj(Cap::Insert, t);
                }
                if let Some(like) = &ct.like {
                    let (sqlparser::ast::CreateTableLikeKind::Parenthesized(l)
                    | sqlparser::ast::CreateTableLikeKind::Plain(l)) = like;
                    self.exclude(&l.name);
                    let src = self.object(K::Relation, &l.name)?;
                    self.need_obj(Cap::Select, src);
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
                if cv.secure || cv.to.is_some() || cv.copy_grants || cv.with_no_schema_binding || cv.materialized {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&cv.name);
                let v = self.object(K::Relation, &cv.name)?;
                self.need_obj(Cap::Create, v.clone());
                if cv.or_replace || cv.or_alter {
                    self.need_obj(Cap::Alter, v);
                }
                if cv.params.as_ref().is_some_and(|p| p.definer.is_some()) {
                    // A view running as another account.
                    self.need(Cap::Admin, SqlTarget::Server);
                }
                // The view's query is walked: its creator must be able to read
                // what it exposes, or the view would launder access.
                Kind::CreateView
            }
            Statement::CreateIndex(ci) => {
                if ci.r#async {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ci.table_name);
                let t = self.object(K::Relation, &ci.table_name)?;
                self.need_obj(Cap::Create, t);
                Kind::CreateIndex
            }
            Statement::AlterTable(at) => {
                if at.location.is_some() || at.on_cluster.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&at.name);
                let t = self.object(K::Relation, &at.name)?;
                self.need_obj(Cap::Alter, t);
                for op in &at.operations {
                    match op {
                        AlterTableOperation::AddConstraint { constraint, .. } => self.foreign_key(constraint)?,
                        AlterTableOperation::AddColumn { column_def, .. } => {
                            self.column_foreign_keys(&column_def.options)?
                        }
                        AlterTableOperation::ChangeColumn { options, .. } => {
                            for o in options {
                                if let ColumnOption::ForeignKey(fk) = o {
                                    let r = self.object(K::Relation, &fk.foreign_table)?;
                                    self.need_obj(Cap::Alter, r);
                                }
                            }
                        }
                        AlterTableOperation::RenameTable { table_name } => {
                            let to = match table_name {
                                sqlparser::ast::RenameTableNameKind::As(n)
                                | sqlparser::ast::RenameTableNameKind::To(n) => n,
                            };
                            self.exclude(to);
                            let n = self.object(K::Relation, to)?;
                            self.need_obj(Cap::Create, n);
                        }
                        AlterTableOperation::DropConstraint { .. }
                        | AlterTableOperation::DropColumn { .. }
                        | AlterTableOperation::DropPrimaryKey { .. }
                        | AlterTableOperation::DropForeignKey { .. }
                        | AlterTableOperation::DropIndex { .. }
                        | AlterTableOperation::RenameColumn { .. }
                        | AlterTableOperation::AlterColumn { .. }
                        | AlterTableOperation::ModifyColumn { .. }
                        | AlterTableOperation::Algorithm { .. }
                        | AlterTableOperation::Lock { .. }
                        | AlterTableOperation::AutoIncrement { .. }
                        | AlterTableOperation::EnableTrigger { .. }
                        | AlterTableOperation::DisableTrigger { .. } => {}
                        _ => return brk(Reason::UnsupportedConstruct),
                    }
                }
                Kind::Alter
            }
            Statement::AlterView { name, .. } => {
                self.exclude(name);
                let v = self.object(K::Relation, name)?;
                self.need_obj(Cap::Alter, v);
                Kind::Alter
            }
            Statement::Set(set) => {
                // Only user variables reach the parser (system variables are
                // judged from tokens first, fallback.rs).
                let names: Vec<&ObjectName> = match set {
                    Set::SingleAssignment { scope: None, hivevar: false, variable, .. } => vec![variable],
                    Set::MultipleAssignments { assignments } => {
                        let mut v = Vec::new();
                        for a in assignments {
                            if a.scope.is_some() {
                                return brk(Reason::UnsupportedConstruct);
                            }
                            v.push(&a.name);
                        }
                        v
                    }
                    _ => return brk(Reason::UnsupportedConstruct),
                };
                for n in names {
                    self.exclude(n);
                    let user_var = matches!(n.0.as_slice(), [ObjectNamePart::Identifier(id)]
                        if id.quote_style.is_none() && id.value.starts_with('@') && !id.value.starts_with("@@"));
                    if !user_var {
                        return brk(Reason::UnsupportedConstruct);
                    }
                }
                self.need(Cap::Select, SqlTarget::Server);
                Kind::SetSession
            }
            Statement::Explain { .. } => return brk(Reason::UnsupportedStatement),
            _ => return brk(Reason::UnsupportedStatement),
        };
        ControlFlow::Continue(kind)
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
        SetExpr::Select(_) | SetExpr::SetOperation { .. } | SetExpr::Table(_) => Kind::Select,
    }
}

impl Visitor for Walker<'_, '_> {
    type Break = Reason;

    fn pre_visit_statement(&mut self, s: &Statement) -> Flow {
        let is_root = addr(s) == self.root;
        if !is_root {
            // A statement nested in another (a data-modifying CTE body is not
            // MySQL syntax): refused rather than read.
            return brk(Reason::UnsupportedConstruct);
        }
        self.primary(s, is_root)
    }

    fn pre_visit_query(&mut self, q: &Query) -> Flow {
        if q.for_clause.is_some() || q.settings.is_some() || q.format_clause.is_some() || !q.pipe_operators.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        if matches!(*q.body, SetExpr::Table(_) | SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_))
            || matches!(*q.body, SetExpr::Merge(_))
        {
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
                cte_names.push(cte.alias.name.value.clone());
            }
            for (i, cte) in with.cte_tables.iter().enumerate() {
                // A non-recursive CTE sees only the ones before it.
                let mut scope = visible.clone();
                let upto = if with.recursive { cte_names.len() } else { i };
                scope.extend(cte_names[..upto].iter().cloned());
                self.cte_scope.insert(addr(&*cte.query), scope);
            }
            visible.extend(cte_names);
        }
        self.scopes.push(visible);
        self.locks.push(!q.locks.is_empty());
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _q: &Query) -> Flow {
        self.scopes.pop();
        self.locks.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> Flow {
        if s.top.is_some()
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
            || !s.optimizer_hints.is_empty()
        {
            return brk(Reason::UnsupportedConstruct);
        }
        if let Some(into) = &s.into {
            // `SELECT … INTO @var` only. INTO OUTFILE / DUMPFILE never reach
            // the parser (refused from tokens, §4.2).
            if into.temporary || into.unlogged || into.table {
                return brk(Reason::UnsupportedConstruct);
            }
            for t in &into.targets {
                let user_var = matches!(t, Expr::Identifier(id) if id.quote_style.is_none() && id.value.starts_with('@') && !id.value.starts_with("@@"));
                if !user_var {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, name: &ObjectName) -> Flow {
        if self.excluded.contains(&addr(name)) || self.is_cte(name) {
            return ControlFlow::Continue(());
        }
        let r = self.object(ObjectKind::Relation, name)?;
        self.read(r);
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> Flow {
        match tf {
            TableFactor::Table { args, with_hints, version, json_path, sample, .. } => {
                if args.is_some()
                    || !with_hints.is_empty()
                    || version.is_some()
                    || json_path.is_some()
                    || sample.is_some()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
            TableFactor::Derived { .. } | TableFactor::NestedJoin { .. } | TableFactor::JsonTable { .. } => {}
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> Flow {
        match e {
            Expr::Function(f) => self.call(f)?,
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
                // `?` placeholders: the browser binds no parameters.
                if matches!(v.value, Value::Placeholder(_)) {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
            Expr::Identifier(_)
            | Expr::CompoundIdentifier(_)
            | Expr::UnaryOp { .. }
            | Expr::Like { .. }
            | Expr::RLike { .. }
            | Expr::Between { .. }
            | Expr::InList { .. }
            | Expr::InSubquery { .. }
            | Expr::IsDistinctFrom(..)
            | Expr::IsNotDistinctFrom(..)
            | Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::Cast { .. }
            | Expr::Convert { .. }
            | Expr::AtTimeZone { .. }
            | Expr::Extract { .. }
            | Expr::Ceil { .. }
            | Expr::Floor { .. }
            | Expr::Position { .. }
            | Expr::Substring { .. }
            | Expr::Trim { .. }
            | Expr::Collate { .. }
            | Expr::Prefixed { .. }
            | Expr::Nested(_)
            | Expr::TypedString(_)
            | Expr::Case { .. }
            | Expr::Exists { .. }
            | Expr::Subquery(_)
            | Expr::Tuple(_)
            | Expr::Interval(_)
            | Expr::MatchAgainst { .. }
            | Expr::MemberOf(_)
            | Expr::Rollup(_)
            | Expr::Wildcard(_)
            | Expr::QualifiedWildcard(..) => {}
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }
}
