//! Statement → required privileges, Oracle (§4.2, §4.3), for the
//! statements the parser reads: queries (`FOR UPDATE`, hierarchical
//! queries, `seq.NEXTVAL`), `INSERT`, multi-table `INSERT ALL / FIRST`,
//! `UPDATE`, `DELETE`, `MERGE`, `CREATE TABLE / VIEW / INDEX` and `ALTER
//! TABLE`.

// The statement table decides each statement's own targets; a full AST walk
// then visits every node, so a subquery or a function call anywhere is
// classified too. Unknown statements, clauses, table factors and
// expressions refuse; nothing defaults to `sql_select`.

// Oracle calls a parameterless function without parentheses: a bare name
// is a column only when a table it could belong to is in scope (columns win
// over functions). Where none is (`SELECT f FROM dual`, `VALUES (f)`), it
// is a function call: opaque `sql_execute` on `sql/server`. A dotted name
// whose qualifier is not a table or alias in scope is a routine call.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;

use sqlparser::ast::{
    AlterTableOperation, ColumnOption, Delete, Expr, FromTable, Function, FunctionArguments, Ident, Insert,
    JoinOperator, LockType, Merge, MergeAction, ObjectName, ObjectNamePart, OrderBy, Query, RenameTableNameKind,
    Select, SelectItem, SelectItemQualifiedWildcardKind, SetExpr, Statement, TableAlias, TableConstraint, TableFactor,
    TableObject, TableWithJoins, Update, Value, Visit, Visitor,
};
use sqlparser::dialect::OracleDialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::{IsOptional, Parser, ParserError};
use sqlparser::tokenizer::{Token, TokenWithSpan};

use super::functions::{self, FnClass};
use super::names::{ident_part, is_dual, reserved_ident, Names, Part};
use super::{routine_use, RoutineUse};
use crate::model::{ObjectKind, ObjectRef, Reason, SqlCapability as Cap, SqlTarget, StatementKind as Kind};
use crate::PARSER_RECURSION_LIMIT;

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

/// Most CTE names visible at once.
const MAX_VISIBLE_CTES: usize = 64;

/// Reserved words the parser legitimately reads as an expression.
const RESERVED_EXPRESSIONS: &[&str] = &["level", "rowid", "rownum", "sysdate", "uid", "user", "null", "default"];

/// What a bare name may be in one query block.
#[derive(Debug, Clone, Default)]
struct Frame {
    /// A table, view, derived table, CTE or table function is read here.
    has_relation: bool,
    /// Aliases, table names (`T` and `S.T`) and, for `ORDER BY`, the
    /// select-list aliases: canonical.
    names: HashSet<String>,
    /// Hides the frames below it (an uncorrelated subquery).
    barrier: bool,
}

fn canon_ident(id: &Ident) -> Option<String> {
    ident_part(id).ok()?.canon().ok()
}

fn add_alias(frame: &mut Frame, alias: &Option<TableAlias>) -> bool {
    if let Some(a) = alias {
        if let Some(n) = canon_ident(&a.name) {
            frame.names.insert(n);
        }
        true
    } else {
        false
    }
}

/// The names a `FROM` item brings into scope.
fn factor_frame(names: &Names<'_>, tf: &TableFactor, frame: &mut Frame) {
    match tf {
        TableFactor::Table { name, alias, .. } => {
            let parts = names.parts(name).unwrap_or_default();
            if !is_dual(&parts) {
                frame.has_relation = true;
            }
            if !add_alias(frame, alias) {
                let canon: Vec<String> = parts.iter().filter_map(|p| p.canon().ok()).collect();
                if let Some(last) = canon.last() {
                    frame.names.insert(last.clone());
                }
                if canon.len() == 2 {
                    frame.names.insert(canon.join("."));
                }
            }
        }
        TableFactor::NestedJoin { table_with_joins, alias } => {
            from_frame(names, std::slice::from_ref(&**table_with_joins), frame);
            add_alias(frame, alias);
        }
        TableFactor::Derived { alias, .. }
        | TableFactor::TableFunction { alias, .. }
        | TableFactor::JsonTable { alias, .. }
        | TableFactor::XmlTable { alias, .. }
        | TableFactor::Pivot { alias, .. }
        | TableFactor::Unpivot { alias, .. } => {
            frame.has_relation = true;
            add_alias(frame, alias);
        }
        _ => frame.has_relation = true,
    }
}

fn from_frame(names: &Names<'_>, from: &[TableWithJoins], frame: &mut Frame) {
    for twj in from {
        factor_frame(names, &twj.relation, frame);
        for j in &twj.joins {
            factor_frame(names, &j.relation, frame);
        }
    }
}

/// Everything the body of `q` reads, plus its select-list aliases: what
/// its `ORDER BY` (or a multi-table insert's `VALUES`) may name.
fn query_frame(names: &Names<'_>, body: &SetExpr, frame: &mut Frame) {
    match body {
        SetExpr::Select(s) => {
            from_frame(names, &s.from, frame);
            for item in &s.projection {
                if let SelectItem::ExprWithAlias { alias, .. } = item {
                    if let Some(n) = canon_ident(alias) {
                        frame.names.insert(n);
                    }
                }
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            query_frame(names, left, frame);
            query_frame(names, right, frame);
        }
        SetExpr::Query(q) => query_frame(names, &q.body, frame),
        _ => {}
    }
}

/// Classify one parsed statement.
pub(crate) fn analyze(stmt: &Statement, names: &Names<'_>) -> Result<Analysis, Reason> {
    let mut w = Walker::new(names, Some(stmt));
    match stmt.visit(&mut w) {
        ControlFlow::Break(r) => Err(r),
        ControlFlow::Continue(()) => w.finish(),
    }
}

struct Walker<'n, 'c> {
    names: &'n Names<'c>,
    root: usize,
    /// The `Query` of a root `SELECT`: the only one `FOR UPDATE` may sit on.
    root_query: usize,
    kind: Option<Kind>,
    read_family: bool,
    required: Requirements,
    opaque: bool,
    /// Name nodes the statement table consumed as targets; not reads.
    excluded: HashSet<usize>,
    /// `SELECT … FOR UPDATE`: every table read is locked.
    lock_all: bool,
    /// CTE names visible at each query level, canonical.
    scopes: Vec<Vec<String>>,
    cte_scope: HashMap<usize, Vec<String>>,
    /// What a bare or dotted name may refer to, innermost last.
    frames: Vec<Frame>,
    /// Queries that see no outer column (uncorrelated derived tables, CTEs).
    barriers: HashSet<usize>,
    /// Derived tables joined by `CROSS / OUTER APPLY`: correlated.
    lateral: HashSet<usize>,
    /// Whether each query being visited pushed a barrier frame.
    query_marks: Vec<bool>,
    /// The frame each `ORDER BY` sees, by address, until it is visited.
    order_frames: HashMap<usize, Frame>,
    pushed_order: Vec<usize>,
}

impl<'n, 'c> Walker<'n, 'c> {
    fn new(names: &'n Names<'c>, root: Option<&Statement>) -> Self {
        let root_query = match root {
            Some(Statement::Query(q)) => addr(&**q),
            _ => 0,
        };
        Self {
            names,
            root: root.map_or(0, addr),
            root_query,
            kind: None,
            read_family: false,
            required: BTreeSet::new(),
            opaque: false,
            excluded: HashSet::new(),
            lock_all: false,
            scopes: Vec::new(),
            cte_scope: HashMap::new(),
            frames: Vec::new(),
            barriers: HashSet::new(),
            lateral: HashSet::new(),
            query_marks: Vec::new(),
            order_frames: HashMap::new(),
            pushed_order: Vec::new(),
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

    fn parts(&self, name: &ObjectName) -> ControlFlow<Reason, Vec<Part>> {
        ok(self.names.parts(name))
    }

    fn is_cte(&self, name: &ObjectName) -> bool {
        let [ObjectNamePart::Identifier(id)] = name.0.as_slice() else { return false };
        let Some(n) = canon_ident(id) else { return false };
        self.scopes.last().is_some_and(|s| s.contains(&n))
    }

    /// An existing relation; `None` for `DUAL`.
    fn relation(&self, name: &ObjectName) -> ControlFlow<Reason, Option<ObjectRef>> {
        let parts = self.parts(name)?;
        if is_dual(&parts) {
            return ControlFlow::Continue(None);
        }
        let r = ok(self.names.existing(ObjectKind::Relation, &parts))?;
        ControlFlow::Continue(Some(r))
    }

    /// The target of a write: never a CTE (the write would reach the CTE's
    /// base tables, which the statement does not name), never `DUAL`.
    fn write_target(&mut self, name: &ObjectName) -> ControlFlow<Reason, ObjectRef> {
        if self.is_cte(name) {
            return brk(Reason::UnsupportedConstruct);
        }
        self.exclude(name);
        match self.relation(name)? {
            Some(o) => ControlFlow::Continue(o),
            None => brk(Reason::UnsupportedConstruct),
        }
    }

    /// Code the table does not know: `sql_execute` on the server.
    fn unknown_function(&mut self) {
        self.need(Cap::Execute, SqlTarget::Server);
        self.opaque = true;
    }

    /// A stored routine: `sql_execute` on it. Oracle has no read-only
    /// session the database enforces against an autonomous transaction
    /// (§5.3), so this never downgrades to `sql_select`.
    fn routine(&mut self, r: ObjectRef) {
        self.need_obj(Cap::Execute, r);
        self.opaque = true;
    }

    /// Whether `n` (canonical) is a table, alias or CTE in scope.
    fn visible(&self, n: &str) -> bool {
        for f in self.frames.iter().rev() {
            if f.names.contains(n) {
                return true;
            }
            if f.barrier {
                break;
            }
        }
        false
    }

    /// Whether a bare name may be a column here.
    fn column_in_scope(&self, n: Option<&str>) -> bool {
        for f in self.frames.iter().rev() {
            if f.has_relation || n.is_some_and(|n| f.names.contains(n)) {
                return true;
            }
            if f.barrier {
                break;
            }
        }
        false
    }

    fn push_frame(&mut self, frame: Frame) {
        self.frames.push(frame);
    }

    /// A dotted call or a dotted name that is not a column.
    fn qualified_routine(&mut self, parts: &[Part]) -> Flow {
        let first = ok(parts[0].canon())?;
        if self.visible(&first) {
            // `alias.method(…)` / `alias.col.method`: object methods.
            return brk(Reason::UnsupportedConstruct);
        }
        match ok(routine_use(self.names, parts))? {
            RoutineUse::Dynamic => self.unknown_function(),
            RoutineUse::Routines(rs) => {
                for r in rs {
                    self.routine(r);
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn ident_parts(&self, ids: &[Ident]) -> ControlFlow<Reason, Vec<Part>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(ok(ident_part(id))?);
        }
        ControlFlow::Continue(out)
    }

    fn function_parts(&self, name: &ObjectName) -> ControlFlow<Reason, Vec<Part>> {
        let mut out = Vec::new();
        for p in &name.0 {
            match p {
                ObjectNamePart::Identifier(id) => out.push(ok(ident_part(id))?),
                ObjectNamePart::Function(_) => return brk(Reason::UnresolvableName),
            }
        }
        ControlFlow::Continue(out)
    }

    fn call(&mut self, f: &Function) -> Flow {
        if f.uses_odbc_syntax || !matches!(f.parameters, FunctionArguments::None) || f.filter.is_some() {
            return brk(Reason::UnsupportedConstruct);
        }
        let parts = self.function_parts(&f.name)?;
        if parts.iter().any(|p| functions::always_refused(&p.text)) {
            return brk(Reason::ServerFileOrOsAccess);
        }
        let analytic = f.over.is_some() || !f.within_group.is_empty();
        match parts.as_slice() {
            [p] => match p.keyword() {
                Some(name) if functions::dynamic_function(&name) => self.unknown_function(),
                Some(name) => match functions::class(&name) {
                    FnClass::Pure => {}
                    FnClass::Window if analytic => {}
                    FnClass::Window | FnClass::Unknown => self.unknown_function(),
                },
                // A quoted name is never the built-in.
                None => self.unknown_function(),
            },
            [_, _] | [_, _, _] => self.qualified_routine(&parts)?,
            _ => return brk(Reason::UnresolvableName),
        }
        ControlFlow::Continue(())
    }

    /// A bare name: a column, a pseudo-column, or a parameterless call.
    fn bare(&mut self, id: &Ident) -> Flow {
        let part = ok(ident_part(id))?;
        if part.keyword().is_some_and(|k| functions::bare_builtin(&k)) {
            return ControlFlow::Continue(());
        }
        let canon = part.canon().ok();
        if self.column_in_scope(canon.as_deref()) {
            return ControlFlow::Continue(());
        }
        if canon.is_none() {
            return brk(Reason::UnresolvableName);
        }
        self.unknown_function();
        ControlFlow::Continue(())
    }

    /// `a.b`, `a.b.c`: a column, `seq.NEXTVAL / CURRVAL`, or a routine.
    fn compound(&mut self, ids: &[Ident]) -> Flow {
        let parts = self.ident_parts(ids)?;
        let last = parts.last().and_then(Part::keyword);
        if let Some(pseudo @ ("nextval" | "currval")) = last.as_deref() {
            let seq = &parts[..parts.len() - 1];
            if seq.is_empty() || self.visible(&ok(seq[0].canon())?) {
                return brk(Reason::UnsupportedConstruct);
            }
            let s = ok(self.names.existing(ObjectKind::Sequence, seq))?;
            // NEXTVAL advances the sequence (§4.2); CURRVAL only reads it.
            self.need_obj(if pseudo == "nextval" { Cap::Update } else { Cap::Select }, s);
            return ControlFlow::Continue(());
        }
        let first = ok(parts[0].canon())?;
        match parts.len() {
            2 if self.visible(&first) => {}
            3 if self.visible(&first) || self.visible(&format!("{first}.{}", ok(parts[1].canon())?)) => {}
            2 | 3 => self.qualified_routine(&parts)?,
            _ => return brk(Reason::UnresolvableName),
        }
        ControlFlow::Continue(())
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

    /// The frame of a single-table write: the table, under its alias.
    fn target_frame(&self, name: &ObjectName, alias: Option<&Ident>, has_relation: bool) -> Frame {
        let mut frame = Frame { has_relation, ..Frame::default() };
        match alias.and_then(canon_ident) {
            Some(a) => {
                frame.names.insert(a);
            }
            None => {
                let canon: Vec<String> =
                    self.names.parts(name).unwrap_or_default().iter().filter_map(|p| p.canon().ok()).collect();
                if let Some(last) = canon.last() {
                    frame.names.insert(last.clone());
                }
                if canon.len() == 2 {
                    frame.names.insert(canon.join("."));
                }
            }
        }
        frame
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
            || !ins.optimizer_hints.is_empty()
            || ins.on.is_some()
            || ins.returning.is_some()
            || ins.output.is_some()
            || ins.replace_into
            || ins.priority.is_some()
            || ins.insert_alias.is_some()
            || !ins.assignments.is_empty()
            || ins.source.is_none()
        {
            return brk(Reason::UnsupportedConstruct);
        }
        let TableObject::TableName(target) = &ins.table else { return brk(Reason::UnsupportedConstruct) };
        if let Some(a) = &ins.table_alias {
            if reserved_ident(&a.alias) {
                return brk(Reason::ReservedWordAsName);
            }
        }
        let t = self.write_target(target)?;
        self.need_obj(Cap::Insert, t);
        // `VALUES` cannot name the target's columns: a bare name there is a
        // function call.
        let frame = self.target_frame(target, ins.table_alias.as_ref().map(|a| &a.alias), false);
        self.push_frame(frame);
        ControlFlow::Continue(Kind::Insert)
    }

    fn update(&mut self, up: &Update) -> ControlFlow<Reason, Kind> {
        if up.or.is_some()
            || !up.optimizer_hints.is_empty()
            || up.returning.is_some()
            || up.output.is_some()
            || up.limit.is_some()
            || up.from.is_some()
            || !up.table.joins.is_empty()
            || !up.order_by.is_empty()
        {
            return brk(Reason::UnsupportedConstruct);
        }
        let TableFactor::Table { name, args: None, with_hints, alias, .. } = &up.table.relation else {
            return brk(Reason::UnsupportedConstruct);
        };
        if !with_hints.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let t = self.write_target(name)?;
        self.need_obj(Cap::Update, t.clone());
        let reads = up.selection.is_some() || up.assignments.iter().any(|a| !matches!(a.value, Expr::Value(_)));
        if reads {
            self.need_obj(Cap::Select, t);
        }
        let frame = self.target_frame(name, alias.as_ref().map(|a| &a.name), true);
        self.push_frame(frame);
        ControlFlow::Continue(Kind::Update)
    }

    fn delete(&mut self, d: &Delete) -> ControlFlow<Reason, Kind> {
        if !d.optimizer_hints.is_empty()
            || d.returning.is_some()
            || d.output.is_some()
            || d.using.is_some()
            || d.limit.is_some()
            || !d.order_by.is_empty()
            || !d.tables.is_empty()
        {
            return brk(Reason::UnsupportedConstruct);
        }
        let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) = &d.from;
        let [twj] = from.as_slice() else { return brk(Reason::UnsupportedConstruct) };
        let TableFactor::Table { name, args: None, with_hints, alias, .. } = &twj.relation else {
            return brk(Reason::UnsupportedConstruct);
        };
        if !twj.joins.is_empty() || !with_hints.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let t = self.write_target(name)?;
        self.need_obj(Cap::Delete, t.clone());
        if d.selection.is_some() {
            self.need_obj(Cap::Select, t);
        }
        let frame = self.target_frame(name, alias.as_ref().map(|a| &a.name), true);
        self.push_frame(frame);
        ControlFlow::Continue(Kind::Delete)
    }

    fn merge(&mut self, m: &Merge) -> ControlFlow<Reason, Kind> {
        if !m.optimizer_hints.is_empty() || m.output.is_some() {
            return brk(Reason::UnsupportedConstruct);
        }
        let TableFactor::Table { name, args: None, with_hints, alias, .. } = &m.table else {
            return brk(Reason::UnsupportedConstruct);
        };
        if !with_hints.is_empty() {
            return brk(Reason::UnsupportedConstruct);
        }
        let t = self.write_target(name)?;
        // MERGE reads the target to match it.
        self.need_obj(Cap::Select, t.clone());
        for c in &m.clauses {
            let cap = match &c.action {
                MergeAction::Insert(_) => Cap::Insert,
                MergeAction::Update(u) => {
                    if u.delete_predicate.is_some() {
                        // `UPDATE SET … DELETE WHERE …` deletes the rows it
                        // has just updated.
                        self.need_obj(Cap::Delete, t.clone());
                    }
                    Cap::Update
                }
                MergeAction::Delete { .. } => Cap::Delete,
                MergeAction::DoNothing { .. } => return brk(Reason::UnsupportedConstruct),
            };
            self.need_obj(cap, t.clone());
        }
        let mut frame = self.target_frame(name, alias.as_ref().map(|a| &a.name), true);
        factor_frame(self.names, &m.source, &mut frame);
        self.push_frame(frame);
        ControlFlow::Continue(Kind::Merge)
    }

    /// The statement table: each statement's own targets.
    fn primary(&mut self, s: &Statement) -> ControlFlow<Reason, Kind> {
        use ObjectKind as K;
        let kind = match s {
            Statement::Query(q) => {
                self.read_family = true;
                query_kind(&q.body)
            }
            Statement::Insert(ins) => self.insert(ins)?,
            Statement::Update(up) => self.update(up)?,
            Statement::Delete(d) => self.delete(d)?,
            Statement::Merge(m) => self.merge(m)?,
            Statement::CreateTable(ct) => {
                let global_temporary = ct.temporary && ct.global == Some(true);
                if (ct.temporary && !global_temporary)
                    || ct.unlogged
                    || ct.external
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
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&ct.name);
                let parts = self.parts(&ct.name)?;
                let t = ok(self.names.new_object(K::Relation, &parts))?;
                self.need_obj(Cap::Create, t.clone());
                if ct.query.is_some() {
                    // CREATE TABLE … AS SELECT fills the new table.
                    self.need_obj(Cap::Insert, t);
                }
                for c in &ct.columns {
                    self.column_foreign_keys(&c.options)?;
                }
                for c in &ct.constraints {
                    self.foreign_key(c)?;
                }
                let frame = self.target_frame(&ct.name, None, true);
                self.push_frame(frame);
                Kind::CreateTable
            }
            Statement::CreateView(cv) => {
                if cv.secure
                    || cv.to.is_some()
                    || cv.copy_grants
                    || cv.with_no_schema_binding
                    || cv.or_alter
                    || cv.temporary
                    || cv.params.is_some()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.exclude(&cv.name);
                let parts = self.parts(&cv.name)?;
                let v = ok(self.names.new_object(K::Relation, &parts))?;
                self.need_obj(Cap::Create, v.clone());
                if cv.or_replace {
                    self.need_obj(Cap::Alter, v);
                }
                // The view's query is walked: its creator must be able to
                // read what it exposes, or the view would launder access.
                Kind::CreateView
            }
            Statement::CreateIndex(ci) => {
                if ci.concurrently
                    || ci.r#async
                    || ci.using.is_some()
                    || !ci.include.is_empty()
                    || ci.nulls_distinct.is_some()
                    || !ci.with.is_empty()
                    || ci.predicate.is_some()
                    || !ci.index_options.is_empty()
                    || !ci.alter_options.is_empty()
                {
                    return brk(Reason::UnsupportedConstruct);
                }
                let Some(index_name) = &ci.name else { return brk(Reason::UnsupportedConstruct) };
                self.exclude(index_name);
                self.exclude(&ci.table_name);
                let t = ok(self.relation(&ci.table_name)?.ok_or(Reason::UnsupportedConstruct))?;
                self.need_obj(Cap::Create, t);
                // An index is a schema object of its own in Oracle, with
                // its own path (it may even sit in another schema).
                let parts = self.parts(index_name)?;
                let i = ok(self.names.new_object(K::Index, &parts))?;
                self.need_obj(Cap::Create, i);
                let frame = self.target_frame(&ci.table_name, None, true);
                self.push_frame(frame);
                Kind::CreateIndex
            }
            Statement::AlterTable(at) => {
                if at.only || at.location.is_some() || at.on_cluster.is_some() || at.table_type.is_some() {
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
                        AlterTableOperation::RenameTable {
                            table_name: RenameTableNameKind::To(new) | RenameTableNameKind::As(new),
                        } => {
                            // The table moves to a new path.
                            let parts = self.parts(new)?;
                            let n = ok(self.names.new_object(K::Relation, &parts))?;
                            self.need_obj(Cap::Create, n);
                            self.exclude(new);
                        }
                        AlterTableOperation::DropConstraint { .. }
                        | AlterTableOperation::DropColumn { .. }
                        | AlterTableOperation::DropPrimaryKey { .. }
                        | AlterTableOperation::DropForeignKey { .. }
                        | AlterTableOperation::AlterColumn { .. }
                        | AlterTableOperation::ModifyColumn { .. }
                        | AlterTableOperation::RenameColumn { .. }
                        | AlterTableOperation::RenameConstraint { .. }
                        | AlterTableOperation::ValidateConstraint { .. } => {}
                        _ => return brk(Reason::UnsupportedConstruct),
                    }
                }
                let frame = self.target_frame(&at.name, None, true);
                self.push_frame(frame);
                Kind::Alter
            }
            _ => return brk(Reason::UnsupportedStatement),
        };
        ControlFlow::Continue(kind)
    }

    fn check_alias(&self, alias: &Option<TableAlias>) -> Flow {
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
        SetExpr::Query(q) => query_kind(&q.body),
        _ => Kind::Select,
    }
}

impl Visitor for Walker<'_, '_> {
    type Break = Reason;

    fn pre_visit_statement(&mut self, s: &Statement) -> Flow {
        if addr(s) == self.root {
            let kind = self.primary(s)?;
            self.kind = Some(kind);
            return ControlFlow::Continue(());
        }
        // Any statement nested in another (`WITH … DELETE`, which Oracle
        // does not have anyway): refused rather than read.
        brk(Reason::UnsupportedConstruct)
    }

    fn pre_visit_query(&mut self, q: &Query) -> Flow {
        if q.settings.is_some()
            || q.format_clause.is_some()
            || !q.pipe_operators.is_empty()
            || q.for_clause.is_some()
            || matches!(*q.body, SetExpr::Table(_))
        {
            return brk(Reason::UnsupportedConstruct);
        }
        if !q.locks.is_empty() {
            // `FOR UPDATE` locks rows of the tables a root query reads
            // (§4.2: `sql_select` + `sql_update`). Anywhere else, refused.
            if addr(q) != self.root_query || q.locks.iter().any(|l| l.lock_type != LockType::Update) {
                return brk(Reason::UnsupportedConstruct);
            }
            self.lock_all = true;
        }
        let barrier = self.barriers.remove(&addr(q));
        if barrier {
            self.frames.push(Frame { barrier: true, ..Frame::default() });
        }
        self.query_marks.push(barrier);
        let mut visible = match self.cte_scope.remove(&addr(q)) {
            Some(s) => s,
            None => self.scopes.last().cloned().unwrap_or_default(),
        };
        if let Some(with) = &q.with {
            if visible.len() + with.cte_tables.len() > MAX_VISIBLE_CTES {
                // Each CTE gets its own copy of the scope: bounded, so the
                // walk stays linear in the input.
                return brk(Reason::UnsupportedConstruct);
            }
            let mut cte_names = Vec::with_capacity(with.cte_tables.len());
            for cte in &with.cte_tables {
                if cte.from.is_some() || cte.materialized.is_some() {
                    return brk(Reason::UnsupportedConstruct);
                }
                if reserved_ident(&cte.alias.name) {
                    return brk(Reason::ReservedWordAsName);
                }
                cte_names.push(ok(ok(ident_part(&cte.alias.name))?.canon())?);
            }
            for (i, cte) in with.cte_tables.iter().enumerate() {
                // An Oracle CTE sees the ones before it and itself (a
                // recursive one needs no keyword); a later name is the real
                // table. It sees no column of the query that uses it.
                let mut scope = visible.clone();
                scope.extend(cte_names[..=i].iter().cloned());
                self.cte_scope.insert(addr(&*cte.query), scope);
                self.barriers.insert(addr(&*cte.query));
            }
            visible.extend(cte_names);
        }
        if let Some(ob) = &q.order_by {
            let mut frame = Frame::default();
            query_frame(self.names, &q.body, &mut frame);
            self.order_frames.insert(addr(ob), frame);
        }
        self.scopes.push(visible);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _q: &Query) -> Flow {
        self.scopes.pop();
        if self.query_marks.pop() == Some(true) {
            self.frames.pop();
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_order_by(&mut self, ob: &OrderBy) -> Flow {
        if let Some(frame) = self.order_frames.remove(&addr(ob)) {
            self.frames.push(frame);
            self.pushed_order.push(addr(ob));
        }
        ControlFlow::Continue(())
    }

    fn post_visit_order_by(&mut self, ob: &OrderBy) -> Flow {
        if self.pushed_order.last() == Some(&addr(ob)) {
            self.pushed_order.pop();
            self.frames.pop();
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> Flow {
        if s.exclude.is_some()
            || s.top.is_some()
            || s.into.is_some()
            || s.select_modifiers.is_some()
            || !s.lateral_views.is_empty()
            || s.prewhere.is_some()
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
            match item {
                SelectItem::ExprWithAlias { alias, .. } if reserved_ident(alias) => {
                    return brk(Reason::ReservedWordAsName)
                }
                SelectItem::ExprWithAliases { .. } => return brk(Reason::UnsupportedConstruct),
                _ => {}
            }
        }
        let mut frame = Frame::default();
        from_frame(self.names, &s.from, &mut frame);
        self.frames.push(frame);
        for twj in &s.from {
            for j in &twj.joins {
                // `CROSS / OUTER APPLY (subquery)` sees the tables before it.
                if let (JoinOperator::CrossApply | JoinOperator::OuterApply, TableFactor::Derived { subquery, .. }) =
                    (&j.join_operator, &j.relation)
                {
                    self.lateral.insert(addr(&**subquery));
                }
            }
        }
        for item in &s.projection {
            if let SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::ObjectName(name), _) = item {
                let parts = self.parts(name)?;
                let joined: Result<Vec<String>, Reason> = parts.iter().map(Part::canon).collect();
                if !self.visible(&ok(joined)?.join(".")) {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, _s: &Select) -> Flow {
        self.frames.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, name: &ObjectName) -> Flow {
        if self.excluded.contains(&addr(name)) || self.is_cte(name) {
            return ControlFlow::Continue(());
        }
        if let Some(r) = self.relation(name)? {
            if self.lock_all {
                self.need_obj(Cap::Update, r.clone());
            }
            self.need_obj(Cap::Select, r);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> Flow {
        match tf {
            TableFactor::Table { alias, args, with_hints, json_path, index_hints, with_ordinality, .. } => {
                if args.is_some() || !with_hints.is_empty() || json_path.is_some() || !index_hints.is_empty() {
                    // `FROM f(…)` (SQL macros, polymorphic table functions)
                    // and other dialects' hints: not classified.
                    return brk(Reason::UnsupportedConstruct);
                }
                if *with_ordinality {
                    return brk(Reason::UnsupportedConstruct);
                }
                self.check_alias(alias)?;
            }
            TableFactor::Derived { lateral, subquery, alias, .. } => {
                self.check_alias(alias)?;
                if !lateral && !self.lateral.remove(&addr(&**subquery)) {
                    self.barriers.insert(addr(&**subquery));
                }
            }
            TableFactor::XmlTable { alias, .. } => {
                // XQuery can read tables named in a string (`ora:view`).
                self.check_alias(alias)?;
                self.unknown_function();
            }
            TableFactor::TableFunction { alias, .. }
            | TableFactor::JsonTable { alias, .. }
            | TableFactor::NestedJoin { alias, .. }
            | TableFactor::Pivot { alias, .. }
            | TableFactor::Unpivot { alias, .. } => self.check_alias(alias)?,
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> Flow {
        let reserved_name =
            |id: &Ident| reserved_ident(id) && !RESERVED_EXPRESSIONS.contains(&id.value.to_ascii_lowercase().as_str());
        match e {
            Expr::Function(f) => self.call(f)?,
            Expr::Identifier(id) => {
                if reserved_name(id) {
                    return brk(Reason::ReservedWordAsName);
                }
                self.bare(id)?;
            }
            Expr::CompoundIdentifier(ids) => {
                if ids.iter().any(reserved_name) {
                    return brk(Reason::ReservedWordAsName);
                }
                self.compound(ids)?;
            }
            Expr::QualifiedWildcard(name, _) => {
                let parts = self.parts(name)?;
                let joined: Result<Vec<String>, Reason> = parts.iter().map(Part::canon).collect();
                if !self.visible(&ok(joined)?.join(".")) {
                    return brk(Reason::UnsupportedConstruct);
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
                // Bind variables (`:x`, `?`) are never bound by the caller.
                if matches!(v.value, Value::Placeholder(_)) {
                    return brk(Reason::UnsupportedConstruct);
                }
            }
            Expr::UnaryOp { .. }
            | Expr::Like { .. }
            | Expr::Between { .. }
            | Expr::InList { .. }
            | Expr::InSubquery { .. }
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::Cast { .. }
            | Expr::Extract { .. }
            | Expr::AtTimeZone { .. }
            | Expr::Ceil { .. }
            | Expr::Floor { .. }
            | Expr::Substring { .. }
            | Expr::Convert { .. }
            | Expr::AnyOp { .. }
            | Expr::AllOp { .. }
            | Expr::Rollup(_)
            | Expr::Cube(_)
            | Expr::GroupingSets(_)
            | Expr::Trim { .. }
            | Expr::Collate { .. }
            | Expr::Nested(_)
            | Expr::Tuple(_)
            | Expr::Case { .. }
            | Expr::Exists { .. }
            | Expr::Subquery(_)
            | Expr::TypedString(_)
            | Expr::Interval(_)
            | Expr::OuterJoin(_)
            | Expr::Prior(_)
            | Expr::Wildcard(_) => {}
            _ => return brk(Reason::UnsupportedConstruct),
        }
        ControlFlow::Continue(())
    }
}

/// `INSERT { ALL | FIRST } … subquery`, which sqlparser 0.63 reads only in
/// its Snowflake dialect: parsed here with the Oracle grammar for each
/// piece (names, expressions, the query).
struct MultiInsert {
    targets: Vec<ObjectName>,
    exprs: Vec<Expr>,
    source: Box<Query>,
}

fn parse_failed() -> ParserError {
    ParserError::ParserError("not a multi-table insert".into())
}

fn into_clauses(p: &mut Parser<'_>, m: &mut Vec<ObjectName>, exprs: &mut Vec<Expr>) -> Result<(), ParserError> {
    let before = m.len();
    while p.parse_keyword(Keyword::INTO) {
        m.push(p.parse_object_name(false)?);
        p.maybe_parse(|p| p.parse_parenthesized_column_list(IsOptional::Mandatory, false))?;
        if p.parse_keyword(Keyword::VALUES) {
            p.expect_token(&Token::LParen)?;
            loop {
                if !p.parse_keyword(Keyword::DEFAULT) {
                    exprs.push(p.parse_expr()?);
                }
                if !p.consume_token(&Token::Comma) {
                    break;
                }
            }
            p.expect_token(&Token::RParen)?;
        }
    }
    if m.len() == before {
        return Err(parse_failed());
    }
    Ok(())
}

fn parse_multi_insert(p: &mut Parser<'_>) -> Result<MultiInsert, ParserError> {
    p.expect_keyword_is(Keyword::INSERT)?;
    p.parse_one_of_keywords(&[Keyword::ALL, Keyword::FIRST]).ok_or_else(parse_failed)?;
    let (mut targets, mut exprs) = (Vec::new(), Vec::new());
    if p.peek_keyword(Keyword::WHEN) {
        while p.parse_keyword(Keyword::WHEN) {
            exprs.push(p.parse_expr()?);
            p.expect_keyword_is(Keyword::THEN)?;
            into_clauses(p, &mut targets, &mut exprs)?;
        }
        if p.parse_keyword(Keyword::ELSE) {
            into_clauses(p, &mut targets, &mut exprs)?;
        }
    } else {
        into_clauses(p, &mut targets, &mut exprs)?;
    }
    let source = p.parse_query()?;
    if p.peek_token().token != Token::EOF {
        return Err(parse_failed());
    }
    Ok(MultiInsert { targets, exprs, source })
}

/// Classify `INSERT ALL / FIRST`: `sql_insert` on every target, and every
/// read of the conditions, the values and the source query.
pub(crate) fn multi_insert(tokens: Vec<TokenWithSpan>, names: &Names<'_>) -> Result<Analysis, Reason> {
    let dialect = OracleDialect {};
    let mut p = Parser::new(&dialect).with_recursion_limit(PARSER_RECURSION_LIMIT).with_tokens_with_locations(tokens);
    let m = parse_multi_insert(&mut p).map_err(|_| Reason::ParseFailed)?;
    let mut w = Walker::new(names, None);
    let run = |w: &mut Walker<'_, '_>| -> Flow {
        for t in &m.targets {
            let r = w.write_target(t)?;
            w.need_obj(Cap::Insert, r);
        }
        // The values and conditions name the source query's columns.
        let mut frame = Frame::default();
        query_frame(names, &m.source.body, &mut frame);
        w.frames.push(frame);
        for e in &m.exprs {
            e.visit(w)?;
        }
        w.frames.pop();
        m.source.visit(w)
    };
    if let ControlFlow::Break(r) = run(&mut w) {
        return Err(r);
    }
    w.kind = Some(Kind::Insert);
    w.finish()
}
